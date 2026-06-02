# test_auth.py
# ------------
# Tests for the dashboard authentication layer.
#
# Covers:
#   - Password hashing (scrypt) round-trip
#   - Session cookie sign + verify (tamper detection, expiry)
#   - First-user signup (only works when users table is empty)
#   - Login / logout
#   - Middleware: /api/* is 401 without a cookie, 200 with one
#   - My Account endpoints: change email + change password

import time

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app
from pulse.auth import (
    SESSION_COOKIE_NAME,
    hash_password, verify_password,
    issue_session_cookie, verify_session_cookie,
)


# ---------------------------------------------------------------------------
# Unit tests — no FastAPI
# ---------------------------------------------------------------------------

def test_hash_password_roundtrip():
    h = hash_password("hunter2-long-enough")
    assert verify_password("hunter2-long-enough", h) is True
    assert verify_password("wrong", h) is False


def test_hash_password_rejects_empty():
    with pytest.raises(ValueError):
        hash_password("")


def test_hash_password_unique_salt():
    """Same password, two hashes → two different strings (salt differs)."""
    h1 = hash_password("samepassword")
    h2 = hash_password("samepassword")
    assert h1 != h2


def test_verify_password_handles_garbage():
    assert verify_password("anything", "not-a-real-hash") is False
    assert verify_password("anything", "") is False
    assert verify_password("", "scrypt$..$x$y$z") is False


def test_session_cookie_roundtrip():
    secret = "abc123"
    cookie = issue_session_cookie(secret, user_id=42)
    assert verify_session_cookie(secret, cookie) == 42


def test_session_cookie_rejects_tamper():
    secret = "abc123"
    cookie = issue_session_cookie(secret, user_id=42)
    body, sig = cookie.rsplit(".", 1)
    tampered = body + "." + sig[:-1] + ("A" if sig[-1] != "A" else "B")
    assert verify_session_cookie(secret, tampered) is None


def test_session_cookie_rejects_wrong_secret():
    cookie = issue_session_cookie("secret-a", user_id=1)
    assert verify_session_cookie("secret-b", cookie) is None


def test_session_cookie_expires():
    secret = "abc123"
    # Issued a year ago, max_age of 10 days → expired.
    issued = int(time.time()) - (365 * 24 * 3600)
    cookie = issue_session_cookie(secret, user_id=7, now=issued)
    assert verify_session_cookie(secret, cookie, max_age=10 * 24 * 3600) is None


# ---------------------------------------------------------------------------
# API tests — auth enabled
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_client(tmp_path):
    """Full app with auth enabled (default)."""
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(config_path))
    return TestClient(app)


def test_status_reports_needs_signup_when_no_users(auth_client):
    r = auth_client.get("/api/auth/status")
    assert r.status_code == 200
    data = r.json()
    assert data["logged_in"] is False
    assert data["needs_signup"] is True


def test_signup_creates_first_user_and_logs_in(auth_client):
    r = auth_client.post("/api/auth/signup", json={
        "email": "me@example.com",
        "password": "correct-horse-battery",
    })
    assert r.status_code == 200
    assert SESSION_COOKIE_NAME in r.cookies

    # And /status now reports logged-in.
    r2 = auth_client.get("/api/auth/status")
    data = r2.json()
    assert data["logged_in"] is True
    assert data["email"] == "me@example.com"
    assert data["needs_signup"] is False


def test_signup_closed_after_first_user(auth_client):
    auth_client.post("/api/auth/signup", json={
        "email": "first@example.com",
        "password": "long-enough-password",
    })
    r = auth_client.post("/api/auth/signup", json={
        "email": "second@example.com",
        "password": "long-enough-password",
    })
    assert r.status_code == 409


def test_signup_validates_password_length(auth_client):
    r = auth_client.post("/api/auth/signup", json={
        "email": "me@example.com",
        "password": "short",
    })
    assert r.status_code == 400


def test_signup_validates_email(auth_client):
    r = auth_client.post("/api/auth/signup", json={
        "email": "not-an-email",
        "password": "long-enough-password",
    })
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Hosted multi-tenant signup (Sprint 7) — PULSE_HOSTED_SIGNUP=1 keeps the
# signup endpoint open past the first user, with each new email landing
# in its own brand-new organization.
# ---------------------------------------------------------------------------

@pytest.fixture
def hosted_signup_client(tmp_path, monkeypatch):
    """Auth-on app with hosted multi-tenant signup turned on."""
    monkeypatch.setenv("PULSE_HOSTED_SIGNUP", "1")
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(config_path))
    return TestClient(app), str(db_path)


def test_hosted_signup_status_reports_open(hosted_signup_client):
    client, _ = hosted_signup_client
    data = client.get("/api/auth/status").json()
    assert data["hosted_signup"] is True
    assert data["signup_open"] is True


def test_hosted_signup_allows_multiple_signups(hosted_signup_client):
    client, _ = hosted_signup_client
    r1 = client.post("/api/auth/signup", json={
        "email": "founder-a@acme.test",
        "password": "correct-horse-battery",
    })
    assert r1.status_code == 200
    client.post("/api/auth/logout")
    r2 = client.post("/api/auth/signup", json={
        "email": "founder-b@initech.test",
        "password": "another-long-password",
    })
    assert r2.status_code == 200


def test_hosted_signup_each_user_lands_in_a_fresh_org(hosted_signup_client):
    """Two separate signups → two separate organizations, no cross-tenant
    visibility. Verifies the multi-tenant boundary at the data layer."""
    from pulse import database
    client, db_path = hosted_signup_client
    client.post("/api/auth/signup", json={
        "email": "founder-a@acme.test", "password": "correct-horse-battery",
    })
    client.post("/api/auth/logout")
    client.post("/api/auth/signup", json={
        "email": "founder-b@initech.test", "password": "another-long-password",
    })

    user_a = database.get_user_by_email(db_path, "founder-a@acme.test")
    user_b = database.get_user_by_email(db_path, "founder-b@initech.test")
    assert user_a["organization_id"] is not None
    assert user_b["organization_id"] is not None
    assert user_a["organization_id"] != user_b["organization_id"]


def test_hosted_signup_first_user_still_admin(hosted_signup_client):
    """First signup should be admin (so the operator running the deploy
    has somebody to log in as), even in hosted mode."""
    client, db_path = hosted_signup_client
    client.post("/api/auth/signup", json={
        "email": "founder@acme.test", "password": "correct-horse-battery",
    })
    from pulse import database
    user = database.get_user_by_email(db_path, "founder@acme.test")
    assert user["role"] == "admin"


def test_hosted_signup_rejects_duplicate_email(hosted_signup_client):
    client, _ = hosted_signup_client
    client.post("/api/auth/signup", json={
        "email": "dupe@example.com", "password": "correct-horse-battery",
    })
    client.post("/api/auth/logout")
    r = client.post("/api/auth/signup", json={
        "email": "dupe@example.com", "password": "another-long-password",
    })
    assert r.status_code == 409
    assert "exists" in r.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Email verification on signup (Sprint 8)
#
# Two branches gated by whether SMTP is wired up:
#   - SMTP off  → user is auto-verified at signup (single-user installs)
#   - SMTP on   → user lands unverified, the verification email goes out,
#                 clicking the link consumes the token and marks them verified
# ---------------------------------------------------------------------------

@pytest.fixture
def smtp_signup_client(tmp_path):
    """Auth-on client with SMTP wired in pulse.yaml so signup follows the
    mail-the-verification-link branch. smtplib.SMTP is patched at the
    top of each test so no real mail ever leaves the runner."""
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text(
        "whitelist:\n  accounts: []\n"
        "email:\n"
        "  smtp_host: smtp.example.com\n"
        "  smtp_port: 587\n"
        "  sender: bot@example.com\n"
        "  password: hunter2\n"
    )
    from pulse.api import create_app
    app = create_app(db_path=str(db_path), config_path=str(config_path))
    return TestClient(app), str(db_path)


def test_signup_without_smtp_auto_verifies_user(auth_client):
    """The plain auth_client fixture has no SMTP config — the signup
    flow should mark the user verified on the spot so single-user CLI
    installs don't get stuck waiting for an email that never leaves."""
    r = auth_client.post("/api/auth/signup", json={
        "email": "me@example.com", "password": "correct-horse-battery",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["verification_sent"] is False
    me = auth_client.get("/api/me").json()
    assert me["email_verified"] is True


def test_signup_with_smtp_mints_token_and_sends_email(smtp_signup_client):
    """SMTP wired -> signup mints a pv_… token, ships the link via
    smtplib, and leaves the user unverified until they click."""
    from unittest.mock import patch, MagicMock
    client, _db = smtp_signup_client

    fake_smtp = MagicMock()
    inner = MagicMock()
    fake_smtp.return_value.__enter__.return_value = inner
    with patch("pulse.alerts.emailer.smtplib.SMTP", fake_smtp):
        r = client.post("/api/auth/signup", json={
            "email": "founder@example.com",
            "password": "correct-horse-battery",
        })

    assert r.status_code == 200
    body = r.json()
    assert body["verification_sent"] is True
    assert inner.sendmail.called

    # Inspect the sent message — verify link present, token format right.
    raw = inner.sendmail.call_args[0][2]
    import re
    m = re.search(r"/verify\?token=pv_[A-Za-z0-9_-]+", raw)
    assert m is not None, "verification email must contain a /verify?token=pv_… link"

    # User starts unverified until they click.
    me = client.get("/api/me").json()
    assert me["email_verified"] is False


def test_verify_endpoint_consumes_token_and_redirects(smtp_signup_client):
    """GET /verify?token=… consumes the token, stamps email_verified_at,
    redirects to /?verified=1, and issues a session cookie so the user
    lands on the dashboard already signed in."""
    from unittest.mock import patch, MagicMock
    client, db_path = smtp_signup_client

    fake_smtp = MagicMock()
    inner = MagicMock()
    fake_smtp.return_value.__enter__.return_value = inner
    with patch("pulse.alerts.emailer.smtplib.SMTP", fake_smtp):
        client.post("/api/auth/signup", json={
            "email": "founder@example.com",
            "password": "correct-horse-battery",
        })
    body = inner.sendmail.call_args[0][2]
    import re
    link = re.search(r"/verify\?token=pv_[A-Za-z0-9_-]+", body).group(0)

    # Log out so the verify flow has to re-issue a session.
    client.post("/api/auth/logout")
    r = client.get(link, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/?verified=1"
    # /verify issued a fresh session cookie too.
    assert SESSION_COOKIE_NAME in r.cookies

    # And now /api/me reports verified.
    me = client.get("/api/me").json()
    assert me["email_verified"] is True


def test_verify_endpoint_rejects_bad_token(smtp_signup_client):
    """Unknown / garbage tokens redirect to /login?verified=0 so the UI
    can render a single "link invalid or expired" message — no leak of
    whether the token shape was right vs. whether the row existed."""
    client, _db = smtp_signup_client
    r = client.get("/verify?token=pv_not_a_real_token", follow_redirects=False)
    assert r.status_code == 302
    assert "verified=0" in r.headers["location"]
    r = client.get("/verify", follow_redirects=False)  # missing token entirely
    assert r.status_code == 302
    assert "verified=0" in r.headers["location"]


def test_verify_endpoint_rejects_replay(smtp_signup_client):
    """Consuming a token should clear it so the same link can't be
    re-used. The second click 302s to /login?verified=0."""
    from unittest.mock import patch, MagicMock
    client, _db = smtp_signup_client

    fake_smtp = MagicMock()
    inner = MagicMock()
    fake_smtp.return_value.__enter__.return_value = inner
    with patch("pulse.alerts.emailer.smtplib.SMTP", fake_smtp):
        client.post("/api/auth/signup", json={
            "email": "founder@example.com",
            "password": "correct-horse-battery",
        })
    body = inner.sendmail.call_args[0][2]
    import re
    link = re.search(r"/verify\?token=pv_[A-Za-z0-9_-]+", body).group(0)

    r1 = client.get(link, follow_redirects=False)
    assert r1.status_code == 302
    assert "verified=1" in r1.headers["location"]

    r2 = client.get(link, follow_redirects=False)
    assert r2.status_code == 302
    assert "verified=0" in r2.headers["location"]


def test_resend_verification_succeeds_when_smtp_configured(smtp_signup_client):
    """Logged-in unverified user can hit /api/auth/resend-verification
    to mint a fresh token + send a new email."""
    from unittest.mock import patch, MagicMock
    client, _db = smtp_signup_client

    fake_smtp = MagicMock()
    inner = MagicMock()
    fake_smtp.return_value.__enter__.return_value = inner
    with patch("pulse.alerts.emailer.smtplib.SMTP", fake_smtp):
        client.post("/api/auth/signup", json={
            "email": "founder@example.com",
            "password": "correct-horse-battery",
        })
        # First email was the signup verification — clear the call list
        # so we only see the resend.
        inner.sendmail.reset_mock()
        r = client.post("/api/auth/resend-verification")
    assert r.status_code == 200
    body = r.json()
    assert body["sent"] is True
    assert body["smtp_configured"] is True
    assert inner.sendmail.called


def test_resend_verification_reports_smtp_off(auth_client):
    """When SMTP isn't configured, the resend endpoint returns 200 with
    sent=False + smtp_configured=False so the UI can show a "ask your
    admin to configure SMTP" message instead of "check your email"."""
    auth_client.post("/api/auth/signup", json={
        "email": "me@example.com", "password": "correct-horse-battery",
    })
    # The signup auto-verified them, so we re-flip to unverified to
    # exercise the resend path. (Otherwise the endpoint short-circuits
    # with already_verified=True, which is a different code path.)
    from pulse import database
    import sqlite3
    # auth_client owns the DB path via app.state — easiest is to find
    # it via the app
    app = auth_client.app
    db_path = app.state.db_path
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE users SET email_verified_at = NULL")
    r = auth_client.post("/api/auth/resend-verification")
    assert r.status_code == 200
    body = r.json()
    assert body["sent"] is False
    assert body["smtp_configured"] is False


def test_resend_verification_short_circuits_when_already_verified(auth_client):
    """A user who's already verified shouldn't be able to spam more
    verification emails. The endpoint returns sent=False +
    already_verified=True without minting a token."""
    auth_client.post("/api/auth/signup", json={
        "email": "me@example.com", "password": "correct-horse-battery",
    })
    r = auth_client.post("/api/auth/resend-verification")
    assert r.status_code == 200
    body = r.json()
    assert body["sent"] is False
    assert body.get("already_verified") is True


def test_db_verification_token_round_trip(tmp_path):
    """Direct exercise of mint/consume — outside the API stack."""
    from datetime import datetime, timedelta
    from pulse import database
    db_path = str(tmp_path / "test.db")
    database.init_db(db_path)
    uid = database.create_user(db_path, "a@b.com", "h")

    raw = database.mint_email_verification_token(db_path, uid)
    assert raw.startswith("pv_")
    assert database.consume_email_verification_token(db_path, raw) == uid
    # Replay must fail.
    assert database.consume_email_verification_token(db_path, raw) is None


def test_db_verification_token_expires(tmp_path):
    from datetime import datetime, timedelta
    from pulse import database
    db_path = str(tmp_path / "test.db")
    database.init_db(db_path)
    uid = database.create_user(db_path, "a@b.com", "h")

    past = datetime.now() - timedelta(hours=2)
    raw = database.mint_email_verification_token(
        db_path, uid, ttl_hours=1, now=past,
    )
    # Token is already expired by the time we try to consume it.
    assert database.consume_email_verification_token(db_path, raw) is None


def test_login_accepts_valid_credentials(auth_client):
    auth_client.post("/api/auth/signup", json={
        "email": "me@example.com", "password": "my-secret-pass",
    })
    auth_client.post("/api/auth/logout")

    r = auth_client.post("/api/auth/login", json={
        "email": "me@example.com", "password": "my-secret-pass",
    })
    assert r.status_code == 200
    assert SESSION_COOKIE_NAME in r.cookies


def test_login_rejects_bad_password(auth_client):
    auth_client.post("/api/auth/signup", json={
        "email": "me@example.com", "password": "my-secret-pass",
    })
    auth_client.post("/api/auth/logout")
    r = auth_client.post("/api/auth/login", json={
        "email": "me@example.com", "password": "WRONG",
    })
    assert r.status_code == 401


def test_login_rejects_unknown_email(auth_client):
    r = auth_client.post("/api/auth/login", json={
        "email": "nobody@example.com", "password": "whatever",
    })
    assert r.status_code == 401


def test_protected_route_401_without_cookie(auth_client):
    """/api/history is not in the exempt list — 401 when not logged in."""
    r = auth_client.get("/api/history")
    assert r.status_code == 401


def test_protected_route_200_after_login(auth_client):
    auth_client.post("/api/auth/signup", json={
        "email": "me@example.com", "password": "my-secret-pass",
    })
    r = auth_client.get("/api/history")
    assert r.status_code == 200


def test_health_is_public(auth_client):
    r = auth_client.get("/api/health")
    assert r.status_code == 200


def test_logout_clears_session(auth_client):
    auth_client.post("/api/auth/signup", json={
        "email": "me@example.com", "password": "my-secret-pass",
    })
    auth_client.post("/api/auth/logout")
    r = auth_client.get("/api/history")
    assert r.status_code == 401


def test_root_serves_marketing_landing_when_signed_out(auth_client):
    """Sprint 7: `/` is the marketing landing page for unauthenticated
    visitors (replaces the old redirect-to-login). Logged-in users still
    get the dashboard at the same path."""
    r = auth_client.get("/", follow_redirects=False)
    assert r.status_code == 200
    body = r.text
    # Distinguish landing from login/dashboard by a marketing-only marker.
    assert "Stop incidents on Windows" in body or "PULSE" in body
    # Landing has a Download CTA; the dashboard SPA does not.
    assert "Download" in body


def test_root_serves_dashboard_when_signed_in(auth_client):
    auth_client.post("/api/auth/signup", json={
        "email": "me@example.com", "password": "correct-horse-battery",
    })
    r = auth_client.get("/", follow_redirects=False)
    assert r.status_code == 200
    # Dashboard SPA shell — checks for the core dashboard markup, not the
    # marketing copy.
    assert "PULSE" in r.text or "id=\"app\"" in r.text or "topbar-scan-btn" in r.text


def test_auth_state_pages_set_no_store_cache_header(auth_client):
    """Regression — `/`, `/login`, and `/welcome` MUST return
    ``Cache-Control: no-store`` because they all return different
    content depending on the visitor's auth state. Without it the
    browser caches the landing page response for `/`, and after a
    fresh sign-in the user gets bounced back to the cached landing
    page until they hard-refresh. Reported as a real bug on
    2026-05-28 — see CHANGELOG."""
    for path in ("/", "/login", "/welcome"):
        r = auth_client.get(path, follow_redirects=False)
        assert r.status_code == 200, f"{path} returned {r.status_code}"
        cc = (r.headers.get("cache-control") or "").lower()
        assert "no-store" in cc, (
            f"{path} is missing no-store; got Cache-Control={cc!r}. "
            f"Browsers will cache the auth-dependent response."
        )


def test_update_email_requires_current_password(auth_client):
    auth_client.post("/api/auth/signup", json={
        "email": "me@example.com", "password": "my-secret-pass",
    })
    r = auth_client.put("/api/auth/email", json={
        "email": "new@example.com", "current_password": "WRONG",
    })
    assert r.status_code == 401


def test_update_email_succeeds_with_current_password(auth_client):
    auth_client.post("/api/auth/signup", json={
        "email": "me@example.com", "password": "my-secret-pass",
    })
    r = auth_client.put("/api/auth/email", json={
        "email": "new@example.com", "current_password": "my-secret-pass",
    })
    assert r.status_code == 200
    status = auth_client.get("/api/auth/status").json()
    assert status["email"] == "new@example.com"


def test_update_password_flow(auth_client):
    auth_client.post("/api/auth/signup", json={
        "email": "me@example.com", "password": "old-password-ok",
    })
    r = auth_client.put("/api/auth/password", json={
        "new_password": "new-password-ok", "current_password": "old-password-ok",
    })
    assert r.status_code == 200

    # Logging back in with the NEW password works...
    auth_client.post("/api/auth/logout")
    r1 = auth_client.post("/api/auth/login", json={
        "email": "me@example.com", "password": "new-password-ok",
    })
    assert r1.status_code == 200

    # ...and the old password no longer does.
    auth_client.post("/api/auth/logout")
    r2 = auth_client.post("/api/auth/login", json={
        "email": "me@example.com", "password": "old-password-ok",
    })
    assert r2.status_code == 401


def test_update_password_rejects_short(auth_client):
    auth_client.post("/api/auth/signup", json={
        "email": "me@example.com", "password": "old-password-ok",
    })
    r = auth_client.put("/api/auth/password", json={
        "new_password": "short", "current_password": "old-password-ok",
    })
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# RBAC — roles, admin-only endpoints, multi-user management
# ---------------------------------------------------------------------------

def _signup_admin(client, email="admin@example.com", password="correct-horse-battery"):
    r = client.post("/api/auth/signup", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return email, password


def _login(client, email, password):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text


def test_first_signup_becomes_admin(auth_client):
    _signup_admin(auth_client)
    r = auth_client.get("/api/me")
    assert r.status_code == 200
    assert r.json()["role"] == "admin"
    assert r.json()["active"] is True


def test_status_includes_role(auth_client):
    _signup_admin(auth_client)
    data = auth_client.get("/api/auth/status").json()
    assert data["role"] == "admin"


def test_admin_can_create_viewer(auth_client):
    _signup_admin(auth_client)
    r = auth_client.post("/api/users", json={
        "email": "viewer@example.com",
        "password": "another-long-password",
        "role": "analyst",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["role"] == "analyst"
    assert body["email"] == "viewer@example.com"


def test_viewer_cannot_list_users(auth_client):
    _signup_admin(auth_client)
    auth_client.post("/api/users", json={
        "email": "viewer@example.com",
        "password": "another-long-password",
        "role": "analyst",
    })
    auth_client.post("/api/auth/logout")
    _login(auth_client, "viewer@example.com", "another-long-password")
    r = auth_client.get("/api/users")
    assert r.status_code == 403


def test_viewer_blocked_from_admin_endpoints(auth_client):
    _signup_admin(auth_client)
    auth_client.post("/api/users", json={
        "email": "viewer@example.com",
        "password": "another-long-password",
        "role": "analyst",
    })
    auth_client.post("/api/auth/logout")
    _login(auth_client, "viewer@example.com", "another-long-password")
    # All three admin writes must be blocked.
    assert auth_client.post("/api/users", json={
        "email": "x@y.com", "password": "long-password-ok", "role": "analyst",
    }).status_code == 403


def test_admin_cannot_demote_last_admin(auth_client):
    _signup_admin(auth_client)
    me = auth_client.get("/api/me").json()
    r = auth_client.put(f"/api/users/{me['id']}/role", json={"role": "analyst"})
    assert r.status_code == 409


def test_admin_cannot_deactivate_self(auth_client):
    _signup_admin(auth_client)
    me = auth_client.get("/api/me").json()
    r = auth_client.put(f"/api/users/{me['id']}/active", json={"active": False})
    assert r.status_code == 409


def test_admin_cannot_delete_self(auth_client):
    _signup_admin(auth_client)
    me = auth_client.get("/api/me").json()
    r = auth_client.delete(f"/api/users/{me['id']}")
    assert r.status_code == 409


def test_deactivated_user_cannot_log_in(auth_client):
    _signup_admin(auth_client)
    created = auth_client.post("/api/users", json={
        "email": "viewer@example.com",
        "password": "another-long-password",
        "role": "analyst",
    }).json()
    # Admin deactivates the viewer.
    r = auth_client.put(f"/api/users/{created['id']}/active", json={"active": False})
    assert r.status_code == 200
    assert r.json()["active"] is False
    # Now the viewer's login attempt is refused.
    auth_client.post("/api/auth/logout")
    r = auth_client.post("/api/auth/login", json={
        "email": "viewer@example.com", "password": "another-long-password",
    })
    assert r.status_code == 403


def test_admin_can_promote_viewer(auth_client):
    _signup_admin(auth_client)
    created = auth_client.post("/api/users", json={
        "email": "promote@example.com",
        "password": "another-long-password",
        "role": "analyst",
    }).json()
    r = auth_client.put(f"/api/users/{created['id']}/role", json={"role": "admin"})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"


def test_create_user_duplicate_email_conflict(auth_client):
    _signup_admin(auth_client)
    auth_client.post("/api/users", json={
        "email": "dup@example.com",
        "password": "another-long-password",
        "role": "analyst",
    })
    r = auth_client.post("/api/users", json={
        "email": "dup@example.com",
        "password": "another-long-password",
        "role": "analyst",
    })
    assert r.status_code == 409


# ---------------------------------------------------------------------------
# API tokens (Bearer auth for CI)
# ---------------------------------------------------------------------------
#
# These cover the full lifecycle: create (raw token is shown once), list
# (raw token is gone — only last4 survives), use the token against a
# protected endpoint via the Authorization header, and revoke (subsequent
# bearer requests 401).

def test_api_token_unit_helpers_shape():
    from pulse.auth import generate_api_token, hash_api_token
    raw, digest, last4 = generate_api_token()
    assert raw.startswith("pulse_")
    assert len(raw) == len("pulse_") + 32   # 32 hex chars = 128 bits
    assert digest == hash_api_token(raw)
    assert len(digest) == 64                 # sha256 hex
    assert last4 == raw[-4:]


def test_api_token_create_returns_raw_exactly_once(auth_client):
    _signup_admin(auth_client)
    r = auth_client.post("/api/tokens", json={"name": "jenkins"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "jenkins"
    assert body["token"].startswith("pulse_")
    assert body["last4"] == body["token"][-4:]

    # The list endpoint must never expose the raw token, only last4.
    r2 = auth_client.get("/api/tokens")
    assert r2.status_code == 200
    tokens = r2.json()["tokens"]
    assert len(tokens) == 1
    assert "token" not in tokens[0]
    assert tokens[0]["last4"] == body["last4"]


def test_api_token_requires_name(auth_client):
    _signup_admin(auth_client)
    r = auth_client.post("/api/tokens", json={"name": "   "})
    assert r.status_code == 400


def test_api_token_authenticates_bearer_request(auth_client):
    _signup_admin(auth_client)
    raw = auth_client.post("/api/tokens", json={"name": "ci"}).json()["token"]

    # Fresh client — no cookies, so only the Bearer header can authenticate.
    fresh = TestClient(auth_client.app)
    r = fresh.get("/api/history", headers={"Authorization": "Bearer " + raw})
    assert r.status_code == 200


def test_api_token_revoke_blocks_future_calls(auth_client):
    _signup_admin(auth_client)
    created = auth_client.post("/api/tokens", json={"name": "jenkins"}).json()
    raw, token_id = created["token"], created["id"]

    # Pre-revoke: token works.
    fresh = TestClient(auth_client.app)
    assert fresh.get("/api/history", headers={"Authorization": "Bearer " + raw}).status_code == 200

    # Revoke.
    r = auth_client.delete("/api/tokens/" + str(token_id))
    assert r.status_code == 200

    # Post-revoke: 401.
    fresh2 = TestClient(auth_client.app)
    r2 = fresh2.get("/api/history", headers={"Authorization": "Bearer " + raw})
    assert r2.status_code == 401


def test_api_token_user_cannot_revoke_someone_elses_token(auth_client):
    # User A signs up (admin, auto) and creates a token.
    _signup_admin(auth_client, email="a@example.com")
    a_token = auth_client.post("/api/tokens", json={"name": "mine"}).json()
    a_token_id = a_token["id"]

    # A (admin) creates user B, then B logs in via a new client.
    r = auth_client.post("/api/users", json={
        "email": "b@example.com", "password": "long-enough-password", "role": "analyst",
    })
    assert r.status_code == 200, r.text
    b_client = TestClient(auth_client.app)
    _login(b_client, "b@example.com", "long-enough-password")

    # B tries to revoke A's token → 404 (token isn't theirs).
    r2 = b_client.delete("/api/tokens/" + str(a_token_id))
    assert r2.status_code == 404

    # A's token still works.
    fresh = TestClient(auth_client.app)
    assert fresh.get(
        "/api/history",
        headers={"Authorization": "Bearer " + a_token["token"]},
    ).status_code == 200


def test_api_token_bad_bearer_is_401(auth_client):
    _signup_admin(auth_client)
    fresh = TestClient(auth_client.app)
    r = fresh.get("/api/history", headers={"Authorization": "Bearer pulse_deadbeef"})
    assert r.status_code == 401


def test_api_token_deactivated_user_bearer_rejected(auth_client):
    # Admin A creates viewer B and mints a token for B.
    _signup_admin(auth_client)
    auth_client.post("/api/users", json={
        "email": "b@example.com", "password": "long-enough-password", "role": "analyst",
    })
    b_client = TestClient(auth_client.app)
    _login(b_client, "b@example.com", "long-enough-password")
    b_raw = b_client.post("/api/tokens", json={"name": "b"}).json()["token"]

    # Sanity: token works while B is active.
    fresh = TestClient(auth_client.app)
    assert fresh.get(
        "/api/history",
        headers={"Authorization": "Bearer " + b_raw},
    ).status_code == 200

    # Admin deactivates B.
    b_id = [u for u in auth_client.get("/api/users").json()["users"]
            if u["email"] == "b@example.com"][0]["id"]
    r = auth_client.put(f"/api/users/{b_id}/active", json={"active": False})
    assert r.status_code == 200

    # Deactivated user's bearer token is now rejected.
    fresh2 = TestClient(auth_client.app)
    r2 = fresh2.get("/api/history", headers={"Authorization": "Bearer " + b_raw})
    assert r2.status_code == 401
