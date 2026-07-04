# tests/test_2fa.py
# -----------------
# Authenticator-app 2FA (TOTP, RFC 6238): enrollment, the login second step,
# recovery codes, clock-drift + replay handling, the admin org-scoped reset,
# and the org "require 2FA" policy gate.

import time

import pyotp
import pytest
from fastapi.testclient import TestClient

from pulse import auth, database
from pulse.api import create_app


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "t.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")   # no SMTP -> signup auto-verifies
    app = create_app(db_path=str(db_path), config_path=str(cfg))
    c = TestClient(app)
    c.post("/api/auth/signup", json={"email": "admin@example.com",
                                     "password": "correct-horse-battery"})
    return c


def _enroll_2fa(client):
    """Run the real setup+confirm flow; return (secret, recovery_codes)."""
    setup = client.post("/api/2fa/setup").json()
    secret = setup["secret"]
    assert setup["otpauth_uri"].startswith("otpauth://totp/")
    assert setup["qr"].startswith("data:image/png;base64,")
    code = pyotp.TOTP(secret).now()
    conf = client.post("/api/2fa/confirm", json={"code": code})
    assert conf.status_code == 200
    return secret, conf.json()["recovery_codes"]


# ---------------------------------------------------------------------------
# Enrollment
# ---------------------------------------------------------------------------

def test_setup_requires_valid_confirm_code(client):
    """A wrong confirm code does NOT activate 2FA; a valid one does and hands
    back 8 single-use recovery codes."""
    secret = client.post("/api/2fa/setup").json()["secret"]
    bad = client.post("/api/2fa/confirm", json={"code": "000000"})
    assert bad.status_code == 400
    assert client.get("/api/2fa/status").json()["enabled"] is False

    good = client.post("/api/2fa/confirm", json={"code": pyotp.TOTP(secret).now()})
    assert good.status_code == 200
    body = good.json()
    assert body["status"] == "enabled"
    assert len(body["recovery_codes"]) == 8
    st = client.get("/api/2fa/status").json()
    assert st["enabled"] is True and st["recovery_codes_remaining"] == 8


# ---------------------------------------------------------------------------
# Login second step
# ---------------------------------------------------------------------------

def test_login_requires_second_factor_and_rejects_wrong_code(client):
    secret, _ = _enroll_2fa(client)
    client.post("/api/auth/logout")
    # Correct password alone -> mfa_required, NO session.
    r = client.post("/api/auth/login", json={"email": "admin@example.com",
                                             "password": "correct-horse-battery"})
    assert r.status_code == 200 and r.json()["status"] == "mfa_required"
    assert "pulse_session" not in r.cookies
    # Wrong second factor.
    assert client.post("/api/auth/2fa/verify", json={"code": "000000"}).status_code == 400
    # Correct TOTP -> session.
    v = client.post("/api/auth/2fa/verify", json={"code": pyotp.TOTP(secret).now()})
    assert v.status_code == 200 and "pulse_session" in v.cookies
    assert client.get("/api/me").json()["email"] == "admin@example.com"


def test_totp_replay_is_rejected(tmp_path):
    """A TOTP step can be consumed once; the same step presented again is a
    replay and is rejected."""
    db_path = str(tmp_path / "t.db")
    database.init_db(db_path)
    u = database.create_user(db_path, "a@b.com", "h")
    assert database.totp_step_is_fresh(db_path, u, 1000) is True
    assert database.totp_step_is_fresh(db_path, u, 1000) is False   # replay
    assert database.totp_step_is_fresh(db_path, u, 999) is False    # older
    assert database.totp_step_is_fresh(db_path, u, 1001) is True    # newer step ok


def test_recovery_code_is_single_use(client):
    secret, recovery = _enroll_2fa(client)
    code = recovery[0]
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"email": "admin@example.com",
                                         "password": "correct-horse-battery"})
    # First use of the recovery code works and logs in; one code is now spent.
    assert client.post("/api/auth/2fa/verify", json={"code": code}).status_code == 200
    assert client.get("/api/2fa/status").json()["recovery_codes_remaining"] == 7
    # Second time that same code is presented, it's rejected (single-use).
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"email": "admin@example.com",
                                         "password": "correct-horse-battery"})
    assert client.post("/api/auth/2fa/verify", json={"code": code}).status_code == 400


def test_drift_window_accepts_adjacent_step(tmp_path):
    """±1 step tolerance: the previous window's code still verifies with
    valid_window=1, but not with valid_window=0."""
    secret = pyotp.random_base32()
    now = int(time.time())
    prev_code = pyotp.TOTP(secret).at(now - 30)   # previous 30s step
    assert auth.verify_totp(secret, prev_code, valid_window=1) is True
    assert auth.verify_totp(secret, prev_code, valid_window=0) is False


# ---------------------------------------------------------------------------
# Admin force-disable — org-scoped + audited
# ---------------------------------------------------------------------------

@pytest.fixture
def hosted(tmp_path, monkeypatch):
    monkeypatch.setenv("PULSE_HOSTED_SIGNUP", "1")
    db_path = tmp_path / "mt.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(cfg))

    def signup(email):
        c = TestClient(app)
        c.post("/api/auth/signup", json={"email": email, "password": "correct-horse-battery"})
        return c, c.get("/api/me").json()

    ca, me_a = signup("admin-a@acme.test")   # org A
    cb, me_b = signup("admin-b@init.test")   # org B
    # A member inside org A, with 2FA enabled directly in the DB.
    ca.post("/api/users", json={"email": "member-a@acme.test",
                                "password": "correct-horse-battery", "role": "analyst"})
    member_a = next(u["id"] for u in ca.get("/api/users").json()["users"]
                    if u["email"] == "member-a@acme.test")
    database.set_totp_secret(str(db_path), member_a, pyotp.random_base32())
    database.enable_totp(str(db_path), member_a)
    return {"ca": ca, "cb": cb, "db": str(db_path),
            "member_a": member_a, "admin_b": me_b["id"]}


def test_admin_reset_2fa_is_org_scoped_and_audited(hosted):
    ca, db_path = hosted["ca"], hosted["db"]
    # Cross-org target -> 404 (existence doesn't leak).
    assert ca.post(f"/api/users/{hosted['admin_b']}/2fa/reset").status_code == 404
    # Own-org member -> reset works.
    r = ca.post(f"/api/users/{hosted['member_a']}/2fa/reset")
    assert r.status_code == 200
    assert database.is_totp_enabled(db_path, hosted["member_a"]) is False
    # And it was audit-logged.
    audit = ca.get("/api/audit").json()
    rows = audit.get("entries") or audit.get("rows") or audit.get("audit") or []
    assert any("admin_reset_2fa" in str(row) for row in rows), \
        "the reset must be recorded in the audit log"


# ---------------------------------------------------------------------------
# Org "require 2FA" policy gate
# ---------------------------------------------------------------------------

def test_require_2fa_org_policy_blocks_until_enabled(client):
    # Turn the org policy on (admin has no PIN, so elevation passes).
    assert client.put("/api/org/require-2fa", json={"enabled": True}).status_code == 200
    # The admin has no 2FA yet -> blocked from normal endpoints...
    blocked = client.get("/api/history")
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["code"] == "2fa_setup_required"
    # ...but the 2FA setup surface + profile are still reachable.
    assert client.get("/api/2fa/status").status_code == 200
    assert client.post("/api/2fa/setup").status_code == 200
    assert client.get("/api/me").status_code == 200
    # Enable 2FA -> access is restored.
    secret = client.get("/api/2fa/status")  # noqa: F841 (touch endpoint)
    # Re-run setup to get a fresh secret we control, then confirm.
    s = client.post("/api/2fa/setup").json()["secret"]
    client.post("/api/2fa/confirm", json={"code": pyotp.TOTP(s).now()})
    assert client.get("/api/history").status_code == 200
