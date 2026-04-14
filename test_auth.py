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


def test_root_redirects_to_login_when_signed_out(auth_client):
    r = auth_client.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert "/login" in r.headers["location"]


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
