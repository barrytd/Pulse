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
        "role": "viewer",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["role"] == "viewer"
    assert body["email"] == "viewer@example.com"


def test_viewer_cannot_list_users(auth_client):
    _signup_admin(auth_client)
    auth_client.post("/api/users", json={
        "email": "viewer@example.com",
        "password": "another-long-password",
        "role": "viewer",
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
        "role": "viewer",
    })
    auth_client.post("/api/auth/logout")
    _login(auth_client, "viewer@example.com", "another-long-password")
    # All three admin writes must be blocked.
    assert auth_client.post("/api/users", json={
        "email": "x@y.com", "password": "long-password-ok", "role": "viewer",
    }).status_code == 403


def test_admin_cannot_demote_last_admin(auth_client):
    _signup_admin(auth_client)
    me = auth_client.get("/api/me").json()
    r = auth_client.put(f"/api/users/{me['id']}/role", json={"role": "viewer"})
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
        "role": "viewer",
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
        "role": "viewer",
    }).json()
    r = auth_client.put(f"/api/users/{created['id']}/role", json={"role": "admin"})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"


def test_create_user_duplicate_email_conflict(auth_client):
    _signup_admin(auth_client)
    auth_client.post("/api/users", json={
        "email": "dup@example.com",
        "password": "another-long-password",
        "role": "viewer",
    })
    r = auth_client.post("/api/users", json={
        "email": "dup@example.com",
        "password": "another-long-password",
        "role": "viewer",
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
        "email": "b@example.com", "password": "long-enough-password", "role": "viewer",
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
        "email": "b@example.com", "password": "long-enough-password", "role": "viewer",
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
