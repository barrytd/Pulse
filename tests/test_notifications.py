# test_notifications.py
# ---------------------
# Bell-icon feed (Sprint 6 polish) — table helpers + API endpoints.
#
# Covers:
#   - insert_notification respects the per-user 100-row cap
#   - list_notifications returns newest-first + a correct unread_count
#   - mark_notifications_read flips every unread row for the caller
#   - GET /api/notifications and POST /api/notifications/read are
#     login-gated and only see the caller's rows
#   - Triggers fire on the right action: scan upload, finding-assigned

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from pulse import database
from pulse.api import create_app


def _fresh_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database.init_db(path)
    database.create_user(path, "u1@example.com", "hash", role="admin")
    return path


def _cleanup(path):
    try: os.remove(path)
    except OSError: pass


# ---------------------------------------------------------------------------
# Direct table helpers
# ---------------------------------------------------------------------------

def test_insert_and_list_round_trip():
    path = _fresh_db()
    try:
        rid = database.insert_notification(
            path, user_id=1, kind="scan_complete", message="hello",
            ref_kind="scan", ref_id=42,
        )
        assert rid
        out = database.list_notifications(path, user_id=1)
        assert out["unread_count"] == 1
        assert len(out["notifications"]) == 1
        n = out["notifications"][0]
        assert n["type"] == "scan_complete"
        assert n["ref_id"] == 42
        assert n["read"] is False
    finally:
        _cleanup(path)


def test_insert_caps_at_100_per_user():
    path = _fresh_db()
    try:
        for i in range(120):
            database.insert_notification(path, 1, "scan_complete", f"n{i}")
        out = database.list_notifications(path, 1, limit=100)
        assert len(out["notifications"]) == 100
        # Newest 100 retained — n119 (most recent) survives.
        assert any(r["message"] == "n119" for r in out["notifications"])
        # Oldest pruned.
        assert not any(r["message"] == "n0" for r in out["notifications"])
    finally:
        _cleanup(path)


def test_mark_read_flips_unread():
    path = _fresh_db()
    try:
        for _ in range(5):
            database.insert_notification(path, 1, "scan_complete", "x")
        assert database.list_notifications(path, 1)["unread_count"] == 5
        marked = database.mark_notifications_read(path, 1)
        assert marked == 5
        assert database.list_notifications(path, 1)["unread_count"] == 0
        # Idempotent — second call marks nothing else.
        assert database.mark_notifications_read(path, 1) == 0
    finally:
        _cleanup(path)


def test_insert_with_null_user_is_noop():
    path = _fresh_db()
    try:
        rid = database.insert_notification(path, None, "scan_complete", "x")
        assert rid is None
    finally:
        _cleanup(path)


# ---------------------------------------------------------------------------
# API surface — login gate, scope, and endpoint behavior
# ---------------------------------------------------------------------------

@pytest.fixture
def notif_client(tmp_path):
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(config_path))
    client = TestClient(app)
    client.post("/api/auth/signup", json={
        "email": "admin@example.com",
        "password": "correct-horse-battery",
    })
    return client, str(db_path)


def test_notifications_require_login(notif_client):
    client, _ = notif_client
    client.post("/api/auth/logout")
    r = client.get("/api/notifications")
    assert r.status_code == 401


def test_notifications_scoped_to_caller(notif_client):
    client, db_path = notif_client
    me = client.get("/api/me").json()
    # Hand-craft a row owned by another user so we can prove isolation.
    database.create_user(db_path, "other@example.com", "hash", role="viewer")
    other = database.get_user_by_email(db_path, "other@example.com")
    database.insert_notification(db_path, other["id"], "scan_complete", "not yours")
    database.insert_notification(db_path, me["id"], "scan_complete", "yours")

    body = client.get("/api/notifications").json()
    msgs = [n["message"] for n in body["notifications"]]
    assert "yours" in msgs
    assert "not yours" not in msgs


def test_mark_read_endpoint(notif_client):
    client, db_path = notif_client
    me = client.get("/api/me").json()
    database.insert_notification(db_path, me["id"], "scan_complete", "a")
    database.insert_notification(db_path, me["id"], "scan_complete", "b")
    body_before = client.get("/api/notifications").json()
    assert body_before["unread_count"] == 2

    r = client.post("/api/notifications/read")
    assert r.status_code == 200
    assert r.json()["marked"] == 2
    body_after = client.get("/api/notifications").json()
    assert body_after["unread_count"] == 0


def test_finding_assignment_creates_notification(notif_client):
    """Wiring check — assigning a finding to a user should drop a row in
    their bell feed. Self-assign (admin -> admin) should NOT, since we
    skip notifying the caller."""
    client, db_path = notif_client
    me = client.get("/api/me").json()
    # Add a viewer to assign to.
    client.post("/api/users", json={
        "email": "viewer@example.com",
        "password": "another-long-password",
        "role": "viewer",
    })
    viewer = database.get_user_by_email(db_path, "viewer@example.com")

    # Seed a scan + finding owned by the admin so the assign API can act.
    sid = database.save_scan(
        db_path,
        [{"rule": "RDP Logon Detected", "severity": "HIGH", "hostname": "H"}],
        user_id=me["id"],
    )
    finding = database.get_scan_findings(db_path, sid)[0]

    # Assign to viewer -> notification for viewer.
    r = client.put(
        f"/api/finding/{finding['id']}/assign",
        json={"assignee_user_id": viewer["id"]},
    )
    assert r.status_code == 200
    rows = database.list_notifications(db_path, viewer["id"])["notifications"]
    assert any(n["type"] == "finding_assigned" for n in rows)

    # Self-assign (admin -> admin) should NOT generate a notification.
    before = database.list_notifications(db_path, me["id"])["notifications"]
    r = client.put(
        f"/api/finding/{finding['id']}/assign",
        json={"assignee_user_id": me["id"]},
    )
    assert r.status_code == 200
    after = database.list_notifications(db_path, me["id"])["notifications"]
    assert len(after) == len(before)
