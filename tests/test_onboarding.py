# test_onboarding.py
# ------------------
# Getting Started checklist — Dashboard's 5-step onboarding card.
#
# Covers:
#   - GET /api/me/onboarding returns the right completion flags as the
#     install matures (zero scans -> first scan -> first finding viewed)
#   - POST /api/me/onboarding/dismiss flips `dismissed` to true and
#     persists across requests
#   - POST /api/me/onboarding/finding-viewed marks step 2 done and is
#     idempotent (the column uses COALESCE so the timestamp stays)
#   - SMTP detection only counts a host configured in pulse.yaml
#   - Whitelist detection counts any of accounts/services/ips/rules

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from pulse import database
from pulse.api import create_app


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(config_path))
    c = TestClient(app)
    c.post("/api/auth/signup", json={
        "email": "admin@example.com",
        "password": "correct-horse-battery",
    })
    return c, str(db_path), config_path


def test_fresh_user_has_nothing_done(client):
    c, _db, _cfg = client
    body = c.get("/api/me/onboarding").json()
    assert body["dismissed"] is False
    comp = body["complete"]
    assert comp == {
        "scans": False, "finding_viewed": False, "smtp": False,
        "users": False, "whitelist": False,
    }


def test_first_scan_flips_scans_step(client):
    c, db_path, _cfg = client
    me = c.get("/api/me").json()
    database.save_scan(
        db_path,
        [{"rule": "RDP Logon Detected", "severity": "HIGH", "hostname": "H"}],
        user_id=me["id"],
    )
    body = c.get("/api/me/onboarding").json()
    assert body["complete"]["scans"] is True
    # Other steps still pending.
    assert body["complete"]["finding_viewed"] is False


def test_finding_viewed_endpoint(client):
    c, _db, _cfg = client
    assert c.get("/api/me/onboarding").json()["complete"]["finding_viewed"] is False
    r = c.post("/api/me/onboarding/finding-viewed")
    assert r.status_code == 200
    assert c.get("/api/me/onboarding").json()["complete"]["finding_viewed"] is True
    # Idempotent — calling again doesn't break anything.
    c.post("/api/me/onboarding/finding-viewed")
    assert c.get("/api/me/onboarding").json()["complete"]["finding_viewed"] is True


def test_dismiss_endpoint_persists(client):
    c, _db, _cfg = client
    assert c.get("/api/me/onboarding").json()["dismissed"] is False
    r = c.post("/api/me/onboarding/dismiss")
    assert r.status_code == 200
    assert c.get("/api/me/onboarding").json()["dismissed"] is True


def test_invite_user_flips_users_step(client):
    c, _db, _cfg = client
    body = c.get("/api/me/onboarding").json()
    assert body["complete"]["users"] is False
    c.post("/api/users", json={
        "email": "viewer@example.com",
        "password": "another-long-password",
        "role": "viewer",
    })
    body = c.get("/api/me/onboarding").json()
    assert body["complete"]["users"] is True


def test_whitelist_step_reads_yaml(client, tmp_path):
    c, _db, cfg_path = client
    cfg_path.write_text(
        "whitelist:\n"
        "  accounts: [SYSTEM]\n"
        "  services: []\n"
        "  ips: []\n"
        "  rules: []\n"
    )
    body = c.get("/api/me/onboarding").json()
    assert body["complete"]["whitelist"] is True


def test_smtp_step_requires_host(client, tmp_path):
    c, _db, cfg_path = client
    # Only a recipient set — smtp not done yet.
    cfg_path.write_text(
        "email:\n  recipient: alerts@example.com\n"
        "whitelist:\n  accounts: []\n"
    )
    assert c.get("/api/me/onboarding").json()["complete"]["smtp"] is False
    # Host added — now done.
    cfg_path.write_text(
        "email:\n  host: smtp.gmail.com\n  recipient: alerts@example.com\n"
        "whitelist:\n  accounts: []\n"
    )
    assert c.get("/api/me/onboarding").json()["complete"]["smtp"] is True


def test_endpoints_require_login(client):
    c, _db, _cfg = client
    c.post("/api/auth/logout")
    assert c.get("/api/me/onboarding").status_code == 401
    assert c.post("/api/me/onboarding/dismiss").status_code == 401
    assert c.post("/api/me/onboarding/finding-viewed").status_code == 401
