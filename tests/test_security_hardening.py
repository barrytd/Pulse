# test_security_hardening.py
# --------------------------
# Sprint 8+ security hardening — regression tests for the audit fixes.
#
# Covers:
#   H1. Path traversal: GET /api/firewall/log?path= rejects non-.log
#       extensions and traversal sequences; refuses any custom path in
#       production mode (PULSE_ENV=production).
#   M1. Login lockout: 10 failed attempts per IP in 15 min returns 423
#       Locked. Successful login does NOT consume failure budget.
#   M2. /api/scan is rate-limited to 20/hour per IP.
#   M3. /api/firewall blocker errors return a generic message, not raw
#       SQL exception text.
#   M4. /api/health redacts is_admin in production mode.
#   L2. /verify is rate-limited (60 / 15 min per IP).

import os

import pytest
from fastapi.testclient import TestClient

from pulse import rate_limit
from pulse.api import create_app


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Each security test gets a clean rate-limit bucket — multiple
    tests in the same session would otherwise share state and false-
    fail when one test bumps a counter the next test expects empty."""
    rate_limit.reset_all_for_tests()
    yield
    rate_limit.reset_all_for_tests()


@pytest.fixture
def auth_client(tmp_path):
    db_path = tmp_path / "test.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(cfg))
    client = TestClient(app)
    # First-signup → admin, fully logged in.
    client.post("/api/auth/signup", json={
        "email": "admin@example.com",
        "password": "correct-horse-battery",
    })
    return client


# NB: we deliberately do NOT have a "production_client" fixture that goes
# through real prod signup. TestClient drops Secure cookies over HTTP, so
# the session is lost. Tests that need the prod branch toggle
# ``app.state.is_production`` after the auth fixture has set the session.


# ---------------------------------------------------------------------------
# H1 — Firewall log path traversal
# ---------------------------------------------------------------------------

def test_firewall_log_rejects_non_log_extension(auth_client):
    """A .txt / .conf / .ini path is not a firewall log. Reject with
    400 instead of attempting to read it."""
    r = auth_client.get("/api/firewall/log?path=/etc/passwd")
    assert r.status_code == 400
    assert ".log" in r.json().get("detail", "").lower()


def test_firewall_log_rejects_parent_traversal(auth_client):
    """A path containing `..` could escape a permitted directory.
    Reject regardless of extension."""
    r = auth_client.get("/api/firewall/log?path=../etc/foo.log")
    assert r.status_code == 400
    r2 = auth_client.get("/api/firewall/log?path=..\\Windows\\foo.log")
    assert r2.status_code == 400


def test_firewall_log_rejects_null_byte(auth_client):
    """Null bytes can truncate paths in some libraries. Reject."""
    r = auth_client.get("/api/firewall/log?path=ok.log%00.txt")
    assert r.status_code == 400


def test_firewall_log_blocks_custom_path_in_production(auth_client):
    """Hosted multi-tenant deploy: a tenant-admin must not be able to
    point the server at arbitrary paths. Custom path is disabled in
    production; the upload endpoint stays.

    We flip is_production after the auth fixture sets up the session —
    going through the full prod-signup flow would lose the cookie
    because TestClient drops Secure cookies over HTTP."""
    auth_client.app.state.is_production = True
    try:
        r = auth_client.get("/api/firewall/log?path=/var/log/anything.log")
        assert r.status_code == 400
        assert "production" in r.json().get("detail", "").lower()
    finally:
        auth_client.app.state.is_production = False


def test_firewall_log_default_path_still_works(auth_client):
    """No custom path → returns the empty-payload shape (the default
    pfirewall.log doesn't exist in test environment)."""
    r = auth_client.get("/api/firewall/log")
    assert r.status_code == 200
    body = r.json()
    assert "available" in body
    assert "entries" in body


# ---------------------------------------------------------------------------
# M1 — Login lockout (10 failures / 15 min → 423)
# ---------------------------------------------------------------------------

def test_login_lockout_after_ten_failures(tmp_path):
    """10 failed login attempts from the same IP within 15 min returns
    423 Locked. Successful login bypasses the burst limit if budget is
    available."""
    db_path = tmp_path / "test.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(cfg))
    client = TestClient(app)
    client.post("/api/auth/signup", json={
        "email": "admin@example.com",
        "password": "correct-horse-battery",
    })
    client.post("/api/auth/logout")

    # 10 fails → still 401 (last one fills the bucket).
    for _ in range(10):
        r = client.post("/api/auth/login", json={
            "email": "admin@example.com", "password": "WRONG",
        })
        assert r.status_code == 401

    # 11th attempt is rejected with 423 before the credential check.
    r = client.post("/api/auth/login", json={
        "email": "admin@example.com", "password": "WRONG",
    })
    assert r.status_code == 423
    assert "locked" in r.json().get("detail", "").lower()

    # Even with the CORRECT password, lockout still blocks.
    r = client.post("/api/auth/login", json={
        "email": "admin@example.com", "password": "correct-horse-battery",
    })
    assert r.status_code == 423


def test_login_success_does_not_consume_failure_budget(tmp_path):
    """Typo once, type correctly the second time. The successful login
    must not trigger lockout on subsequent attempts."""
    db_path = tmp_path / "test.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(cfg))
    client = TestClient(app)
    client.post("/api/auth/signup", json={
        "email": "admin@example.com", "password": "correct-horse-battery",
    })
    client.post("/api/auth/logout")

    # Alternate fail/success — 5 failures + 5 successes should never
    # trip the 10-failure lockout because successes don't tick the
    # failure bucket.
    for _ in range(5):
        rf = client.post("/api/auth/login", json={
            "email": "admin@example.com", "password": "WRONG",
        })
        assert rf.status_code == 401
        rs = client.post("/api/auth/login", json={
            "email": "admin@example.com",
            "password": "correct-horse-battery",
        })
        assert rs.status_code == 200
        client.post("/api/auth/logout")


# ---------------------------------------------------------------------------
# M2 — /api/scan rate limit
# ---------------------------------------------------------------------------

def test_scan_endpoint_rate_limited(auth_client):
    """Issue 21 .evtx uploads in a row — the 21st must 429."""
    # We don't need a real .evtx for the rate-limit check; the limiter
    # runs BEFORE the magic-byte check, so a 400 from the magic byte
    # check is the "passed rate limit, hit validation" signal.
    payload = ("PK", b"not a real evtx", "application/octet-stream")
    files = {"file": ("test.evtx", b"not a real evtx", "application/octet-stream")}

    # 20 should each return 400 (validation failure) — they passed the
    # rate limiter and hit the magic-byte check.
    for i in range(20):
        r = auth_client.post("/api/scan", files=files)
        assert r.status_code == 400, f"call {i + 1} unexpectedly returned {r.status_code}"

    # 21st should be 429 from the limiter.
    r = auth_client.post("/api/scan", files=files)
    assert r.status_code == 429
    assert "retry-after" in {k.lower() for k in r.headers.keys()}


# ---------------------------------------------------------------------------
# M3 — Blocker error messages don't leak raw SQL exceptions
# ---------------------------------------------------------------------------

def test_blocker_db_error_does_not_leak_schema(tmp_path):
    """Hand the blocker a path that can't be opened as SQLite — the
    error message must NOT mention the table name or driver
    type."""
    from pulse.firewall import blocker
    # Pass a directory as a DB path so any execute() raises.
    bad_db = str(tmp_path)  # directory, not a file
    result = blocker.stage_ip(bad_db, "8.8.8.8")
    assert result["ok"] is False
    msg = result["message"]
    assert "ip_block_list" not in msg  # table name not leaked
    assert "sqlite3" not in msg.lower()
    assert "operationalerror" not in msg.lower()
    # Should be the generic friendly message.
    assert "Database error" in msg or "server log" in msg.lower()


# ---------------------------------------------------------------------------
# M4 — /api/health redacts is_admin in production
# ---------------------------------------------------------------------------

def test_health_redacts_is_admin_in_production(auth_client):
    # /api/health is auth-exempt anyway; flip is_production to exercise
    # the prod redaction branch without going through prod signup.
    auth_client.app.state.is_production = True
    try:
        body = auth_client.get("/api/health").json()
        assert body["status"] == "ok"
        assert "platform_windows" in body  # OS hint is fine
        assert "is_admin" not in body      # privilege state is redacted
    finally:
        auth_client.app.state.is_production = False


def test_health_exposes_is_admin_in_dev(auth_client):
    """Local single-user mode: is_admin powers the 'run as administrator'
    banner. Keep it exposed."""
    body = auth_client.get("/api/health").json()
    assert "is_admin" in body


# ---------------------------------------------------------------------------
# L2 — /verify rate limit
# ---------------------------------------------------------------------------

def test_verify_endpoint_rate_limited(tmp_path):
    db_path = tmp_path / "test.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(cfg))
    client = TestClient(app)

    # 60 attempts allowed; 61st must 429. Each bad token redirects to
    # /login?verified=0 (302).
    for i in range(60):
        r = client.get(
            f"/verify?token=pv_nope_{i}",
            follow_redirects=False,
        )
        assert r.status_code in (302, 200), f"call {i + 1}: {r.status_code}"
    r = client.get("/verify?token=pv_nope_overflow", follow_redirects=False)
    assert r.status_code == 429
