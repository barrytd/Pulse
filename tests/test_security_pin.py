# test_security_pin.py
# --------------------
# Security PIN — step-up auth for destructive actions. Covers PIN set/clear
# (password-gated), verify + lockout, the elevation gate on a sensitive
# action, and that pin_hash never leaks.

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app
from pulse.auth import hash_pin, verify_pin, validate_pin_format


PW = "correct-horse-battery"


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "t.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db), config_path=str(cfg))
    c = TestClient(app)
    c.post("/api/auth/signup", json={"email": "a@x.com", "password": PW})
    return c, str(db)


# --- auth-layer units -------------------------------------------------------

def test_pin_format_validation():
    assert validate_pin_format("1234")
    assert validate_pin_format("123456789012")
    assert not validate_pin_format("123")        # too short
    assert not validate_pin_format("1234567890123")  # too long
    assert not validate_pin_format("12ab")       # non-digit
    assert not validate_pin_format("")


def test_pin_hash_roundtrip():
    h = hash_pin("135790")
    assert h != "135790"
    assert verify_pin("135790", h)
    assert not verify_pin("000000", h)


# --- set / clear (password-gated) -------------------------------------------

def test_set_pin_requires_password(client):
    c, _ = client
    r = c.post("/api/me/pin", json={"pin": "135790", "current_password": "wrong"})
    assert r.status_code == 403
    assert c.get("/api/me/pin").json()["pin_set"] is False


def test_set_pin_validates_format(client):
    c, _ = client
    r = c.post("/api/me/pin", json={"pin": "12", "current_password": PW})
    assert r.status_code == 400


def test_set_and_status_and_clear(client):
    c, _ = client
    assert c.post("/api/me/pin", json={"pin": "135790", "current_password": PW}).status_code == 200
    assert c.get("/api/me/pin").json()["pin_set"] is True
    # Clearing also needs the password.
    assert c.request("DELETE", "/api/me/pin", json={"current_password": "nope"}).status_code == 403
    assert c.request("DELETE", "/api/me/pin", json={"current_password": PW}).status_code == 200
    assert c.get("/api/me/pin").json()["pin_set"] is False


# --- verify + lockout -------------------------------------------------------

def test_verify_wrong_then_lockout(client):
    c, _ = client
    c.post("/api/me/pin", json={"pin": "135790", "current_password": PW})
    # First four wrong attempts → 401 with a decreasing counter.
    for expected_left in (4, 3, 2, 1):
        r = c.post("/api/me/pin/verify", json={"pin": "000000"})
        assert r.status_code == 401
        assert r.json()["detail"]["attempts_left"] == expected_left
    # Fifth wrong attempt trips the lockout.
    r = c.post("/api/me/pin/verify", json={"pin": "000000"})
    assert r.status_code == 423
    # Even the CORRECT pin is refused while locked.
    r = c.post("/api/me/pin/verify", json={"pin": "135790"})
    assert r.status_code == 423


def test_verify_correct_grants_elevation(client):
    c, _ = client
    c.post("/api/me/pin", json={"pin": "135790", "current_password": PW})
    r = c.post("/api/me/pin/verify", json={"pin": "135790"})
    assert r.status_code == 200
    assert "pulse_elev" in c.cookies


# --- the gate on a sensitive action -----------------------------------------

def test_sensitive_action_open_when_no_pin(client):
    """Opt-in: with no PIN set, the gated action proceeds."""
    c, _ = client
    r = c.post("/api/block-ip", json={"ip": "8.8.8.8"})
    assert r.status_code == 200


def test_sensitive_action_blocked_without_elevation(client):
    c, _ = client
    c.post("/api/me/pin", json={"pin": "135790", "current_password": PW})
    r = c.post("/api/block-ip", json={"ip": "8.8.4.4"})
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "pin_required"


def test_sensitive_action_allowed_after_elevation(client):
    c, _ = client
    c.post("/api/me/pin", json={"pin": "135790", "current_password": PW})
    c.post("/api/me/pin/verify", json={"pin": "135790"})
    r = c.post("/api/block-ip", json={"ip": "8.8.4.4"})
    assert r.status_code == 200


# --- no secret leakage ------------------------------------------------------

def test_pin_hash_never_returned(client):
    c, _ = client
    c.post("/api/me/pin", json={"pin": "135790", "current_password": PW})
    me = c.get("/api/me").json()
    assert "pin_hash" not in me
    users = c.get("/api/users").json().get("users", [])
    for u in users:
        assert "pin_hash" not in u
        assert "password_hash" not in u
