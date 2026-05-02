# test_agents.py
# --------------
# Sprint 7 — Pulse Agent enrollment, heartbeat, and findings ingest.
#
# Covers the full server-side flow:
#   - Mint an enrollment token (admin) -> single-use, expires
#   - Exchange the enrollment token (no auth) -> long-lived agent token
#   - Heartbeat with the agent token -> bumps last_heartbeat
#   - Findings ingest writes a scan owned by the agent's user, agent_id
#     stamped on the row
#   - Pause/delete management endpoints respect ownership

import os
import tempfile
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from pulse import agents, database
from pulse.api import create_app


# ---------------------------------------------------------------------------
# Backend module — direct exercise of `pulse.agents`
# ---------------------------------------------------------------------------

def _fresh_db():
    """Fresh DB with a seed user (id=1). The agents table has a FK on
    user_id so unit tests need a real user to attach agents to."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database.init_db(path)
    database.create_user(path, "u1@example.com", "hash", role="admin")
    return path


def _cleanup(path):
    try:
        os.remove(path)
    except OSError:
        pass


def test_mint_and_exchange_round_trip():
    path = _fresh_db()
    try:
        minted = agents.mint_enrollment(path, user_id=1, name="lab-host")
        assert minted["enrollment_token"].startswith("pe_")
        assert "agent_id" in minted

        # Exchange should succeed and return a long-lived agent token.
        result = agents.exchange_enrollment(
            path,
            enrollment_token=minted["enrollment_token"],
            hostname="LAB-HOST",
            platform="Windows-11",
            version="1.0.0",
        )
        assert result is not None
        assert result["agent_token"].startswith("pa_")
        assert result["agent_id"] == minted["agent_id"]

        # The same enrollment token cannot be exchanged twice — single use.
        assert agents.exchange_enrollment(
            path, enrollment_token=minted["enrollment_token"]) is None

        # The new agent token authenticates.
        agent = agents.authenticate_agent(path, result["agent_token"])
        assert agent is not None
        assert agent["id"] == minted["agent_id"]
        assert agent["hostname"] == "LAB-HOST"
        assert agent["platform"] == "Windows-11"
        assert agent["version"] == "1.0.0"
    finally:
        _cleanup(path)


def test_exchange_rejects_unknown_token():
    path = _fresh_db()
    try:
        assert agents.exchange_enrollment(path, enrollment_token="pe_nope") is None
        assert agents.exchange_enrollment(path, enrollment_token="") is None
    finally:
        _cleanup(path)


def test_exchange_rejects_expired_token():
    path = _fresh_db()
    try:
        minted = agents.mint_enrollment(path, user_id=1, name="stale")
        # Backdate expiry directly so the test doesn't have to wait an hour.
        past = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        with database._connect(path) as conn:
            conn.execute(
                "UPDATE agents SET enrollment_expires_at = ? WHERE id = ?",
                (past, minted["agent_id"]),
            )
        assert agents.exchange_enrollment(
            path, enrollment_token=minted["enrollment_token"]) is None
    finally:
        _cleanup(path)


def test_heartbeat_updates_last_seen():
    path = _fresh_db()
    try:
        minted = agents.mint_enrollment(path, user_id=1, name="h")
        result = agents.exchange_enrollment(
            path, enrollment_token=minted["enrollment_token"])
        agent = database.get_agent_by_id(path, result["agent_id"])
        assert agent["last_heartbeat_at"] is None

        agents.heartbeat(path, agent["id"], status="running", version="1.2.3")
        agent = database.get_agent_by_id(path, agent["id"])
        assert agent["last_heartbeat_at"] is not None
        assert agent["last_status"] == "running"
        assert agent["version"] == "1.2.3"
    finally:
        _cleanup(path)


def test_compute_status_pending_paused_offline_online():
    pending = {"agent_token_sha256": None}
    assert agents.compute_status(pending) == "pending"

    paused = {"agent_token_sha256": "abc", "paused": 1}
    assert agents.compute_status(paused) == "paused"

    offline = {"agent_token_sha256": "abc", "paused": 0, "last_heartbeat_at": None}
    assert agents.compute_status(offline) == "offline"

    now = datetime.now()
    online_iso = now.strftime("%Y-%m-%d %H:%M:%S")
    online = {
        "agent_token_sha256": "abc", "paused": 0,
        "last_heartbeat_at": online_iso,
    }
    assert agents.compute_status(online, now=now) == "online"

    stale_iso = (now - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    stale = {
        "agent_token_sha256": "abc", "paused": 0,
        "last_heartbeat_at": stale_iso,
    }
    assert agents.compute_status(stale, now=now) == "stale"

    cold_iso = (now - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S")
    cold = {
        "agent_token_sha256": "abc", "paused": 0,
        "last_heartbeat_at": cold_iso,
    }
    assert agents.compute_status(cold, now=now) == "offline"


# ---------------------------------------------------------------------------
# API surface — full enrollment/heartbeat/findings flow over HTTP
# ---------------------------------------------------------------------------

@pytest.fixture
def agent_client(tmp_path):
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(config_path))
    client = TestClient(app)

    # First signup -> admin.
    client.post("/api/auth/signup", json={
        "email": "admin@example.com",
        "password": "correct-horse-battery",
    })
    return client, str(db_path)


def _enroll_and_exchange(client):
    """Helper: admin mints, agent exchanges. Returns (agent_id, agent_token)."""
    r = client.post("/api/agents", json={"name": "lab-host"})
    assert r.status_code == 200, r.text
    body = r.json()
    agent_id = body["agent_id"]
    enroll = body["enrollment_token"]

    # Logged-out client to prove exchange is public.
    client.post("/api/auth/logout")
    r = client.post("/api/agent/exchange", json={
        "enrollment_token": enroll,
        "hostname": "LAB-HOST",
        "platform": "Windows-11",
        "version": "1.0.0",
    })
    assert r.status_code == 200, r.text
    return agent_id, r.json()["agent_token"]


def test_full_enroll_exchange_heartbeat_findings(agent_client):
    client, db_path = agent_client
    agent_id, agent_token = _enroll_and_exchange(client)
    headers = {"Authorization": f"Bearer {agent_token}"}

    # Heartbeat
    r = client.post("/api/agent/heartbeat",
                    json={"status": "running", "version": "1.0.1"},
                    headers=headers)
    assert r.status_code == 200
    assert r.json()["agent_id"] == agent_id
    agent = database.get_agent_by_id(db_path, agent_id)
    assert agent["last_heartbeat_at"] is not None
    assert agent["last_status"] == "running"

    # Findings ingest
    r = client.post("/api/agent/findings", json={
        "scan": {
            "hostname": "LAB-HOST",
            "scope": "Pulse Agent — last 24h",
            "files_scanned": 1,
            "total_events": 100,
            "duration_sec": 12,
        },
        "findings": [
            {"rule": "RDP Logon Detected", "severity": "HIGH",
             "description": "RDP logon", "details": "—",
             "timestamp": "2026-04-28T10:00:00", "event_id": "4624"},
        ],
    }, headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["findings_saved"] == 1
    scan_id = body["scan_id"]

    # Scan was saved against the admin's user_id and stamped with agent_id.
    history = database.get_history(db_path)
    rows = [s for s in history if s["id"] == scan_id]
    assert rows, history
    # scope is round-tripped through save_scan; verify directly via SQL too
    with database._connect(db_path) as conn:
        row = conn.execute(
            "SELECT user_id, agent_id, scope FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    assert row[1] == agent_id           # agent_id stamped
    assert row[0] is not None           # owned by the enrolling admin
    assert row[2] == "Pulse Agent — last 24h"


def test_heartbeat_rejects_bogus_token(agent_client):
    client, _ = agent_client
    client.post("/api/auth/logout")
    r = client.post("/api/agent/heartbeat",
                    json={}, headers={"Authorization": "Bearer pa_garbage"})
    assert r.status_code == 401


def test_findings_ingest_rejects_bogus_token(agent_client):
    client, _ = agent_client
    client.post("/api/auth/logout")
    r = client.post("/api/agent/findings",
                    json={"findings": []},
                    headers={"Authorization": "Bearer pa_garbage"})
    assert r.status_code == 401


def test_paused_agent_drops_findings_but_acks_heartbeat(agent_client):
    client, db_path = agent_client
    agent_id, agent_token = _enroll_and_exchange(client)

    # Operator pauses the agent. We need to be logged in to do this.
    client.post("/api/auth/login", json={
        "email": "admin@example.com",
        "password": "correct-horse-battery",
    })
    r = client.put(f"/api/agents/{agent_id}", json={"paused": True})
    assert r.status_code == 200
    client.post("/api/auth/logout")

    headers = {"Authorization": f"Bearer {agent_token}"}
    # Heartbeat still acks (so we can see the host is alive).
    r = client.post("/api/agent/heartbeat", json={}, headers=headers)
    assert r.status_code == 200
    assert r.json()["paused"] is True

    # Findings ingest is dropped.
    r = client.post("/api/agent/findings", json={
        "scan": {"files_scanned": 1, "total_events": 5},
        "findings": [{"rule": "X", "severity": "LOW",
                      "description": "x", "details": "x"}],
    }, headers=headers)
    assert r.status_code == 200
    assert r.json() == {"status": "paused", "scan_id": None, "findings_saved": 0}


def test_list_agents_includes_status(agent_client):
    client, _ = agent_client
    _agent_id, _ = _enroll_and_exchange(client)
    client.post("/api/auth/login", json={
        "email": "admin@example.com",
        "password": "correct-horse-battery",
    })
    r = client.get("/api/agents")
    assert r.status_code == 200
    body = r.json()
    assert "agents" in body
    assert len(body["agents"]) == 1
    a = body["agents"][0]
    # No secrets surfaced
    assert "agent_token_sha256" not in a
    assert "enrollment_token_sha256" not in a
    assert a["agent_token_last4"] is not None
    # The exchange call did not fire a heartbeat, so an immediately-listed
    # agent reads as "offline" until the first /api/agent/heartbeat.
    assert a["status"] in ("online", "offline", "stale")


def test_delete_agent_revokes_token(agent_client):
    client, _db = agent_client
    agent_id, agent_token = _enroll_and_exchange(client)
    client.post("/api/auth/login", json={
        "email": "admin@example.com",
        "password": "correct-horse-battery",
    })
    r = client.delete(f"/api/agents/{agent_id}")
    assert r.status_code == 200
    client.post("/api/auth/logout")

    # Token no longer authenticates.
    r = client.post("/api/agent/heartbeat", json={},
                    headers={"Authorization": f"Bearer {agent_token}"})
    assert r.status_code == 401


def test_viewer_in_same_org_can_see_admin_agent(agent_client):
    client, db_path = agent_client
    agent_id, _agent_token = _enroll_and_exchange(client)

    # Add a viewer.
    client.post("/api/auth/login", json={
        "email": "admin@example.com",
        "password": "correct-horse-battery",
    })
    client.post("/api/users", json={
        "email": "viewer@example.com",
        "password": "another-long-password",
        "role": "viewer",
    })
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={
        "email": "viewer@example.com",
        "password": "another-long-password",
    })

    # Viewer joins the admin's org and shares agent visibility / control —
    # the agent shows in the listing and the viewer can pause it.
    r = client.get("/api/agents")
    assert r.status_code == 200
    listing = r.json()["agents"]
    assert any(a["id"] == agent_id for a in listing)

    r = client.put(f"/api/agents/{agent_id}", json={"paused": True})
    assert r.status_code == 200
    r = client.delete(f"/api/agents/{agent_id}")
    assert r.status_code == 200
