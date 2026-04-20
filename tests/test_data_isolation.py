# test_data_isolation.py
# ----------------------
# Sprint 5 — data isolation tests.
#
# Covers:
#   - Scans carry their originator's user_id
#   - get_history / get_fleet_summary / get_scan_findings / get_scans_since
#     / get_findings_since / get_scan_number / delete_scans honor the
#     user_id filter
#   - API layer: viewers only see their own scans; admins see every scan
#     (including CLI / NULL-owned rows)

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from pulse import database
from pulse.api import create_app


# ---------------------------------------------------------------------------
# Unit tests — hit the DB helpers directly
# ---------------------------------------------------------------------------

def _fresh_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database.init_db(path)
    return path


def _cleanup(path):
    try:
        os.remove(path)
    except OSError:
        pass


def test_save_scan_records_user_id():
    path = _fresh_db()
    try:
        sid = database.save_scan(
            path,
            [{"rule": "RDP Logon Detected", "severity": "HIGH", "hostname": "HOST-A"}],
            filename="a.evtx",
            user_id=7,
        )
        history = database.get_history(path, user_id=7)
        assert len(history) == 1
        assert history[0]["id"] == sid
    finally:
        _cleanup(path)


def test_get_history_no_filter_returns_every_scan():
    """user_id=None is the admin / CLI view — sees everything."""
    path = _fresh_db()
    try:
        database.save_scan(path, [{"rule": "A", "severity": "LOW", "hostname": "H"}], user_id=1)
        database.save_scan(path, [{"rule": "B", "severity": "LOW", "hostname": "H"}], user_id=2)
        database.save_scan(path, [{"rule": "C", "severity": "LOW", "hostname": "H"}])  # CLI
        assert len(database.get_history(path)) == 3
    finally:
        _cleanup(path)


def test_get_history_user_filter_isolates():
    path = _fresh_db()
    try:
        database.save_scan(path, [{"rule": "A", "severity": "LOW", "hostname": "H"}], user_id=1)
        database.save_scan(path, [{"rule": "B", "severity": "LOW", "hostname": "H"}], user_id=2)
        database.save_scan(path, [{"rule": "C", "severity": "LOW", "hostname": "H"}])  # CLI

        one = database.get_history(path, user_id=1)
        two = database.get_history(path, user_id=2)
        assert len(one) == 1
        assert len(two) == 1
        assert one[0]["id"] != two[0]["id"]
    finally:
        _cleanup(path)


def test_get_scan_findings_respects_ownership():
    path = _fresh_db()
    try:
        sid = database.save_scan(
            path,
            [{"rule": "A", "severity": "LOW", "hostname": "H"}],
            user_id=1,
        )
        # Owner sees the findings.
        assert len(database.get_scan_findings(path, sid, user_id=1)) == 1
        # Another viewer sees an empty list.
        assert database.get_scan_findings(path, sid, user_id=2) == []
        # Admin / CLI (user_id=None) bypasses the check.
        assert len(database.get_scan_findings(path, sid)) == 1
    finally:
        _cleanup(path)


def test_get_fleet_summary_filters_by_user():
    path = _fresh_db()
    try:
        database.save_scan(
            path,
            [{"rule": "RDP Logon Detected", "severity": "HIGH", "hostname": "HOST-A"}],
            filename="a.evtx",
            user_id=1,
        )
        database.save_scan(
            path,
            [{"rule": "RDP Logon Detected", "severity": "HIGH", "hostname": "HOST-B"}],
            filename="b.evtx",
            user_id=2,
        )

        full = {row["hostname"] for row in database.get_fleet_summary(path)}
        assert full == {"HOST-A", "HOST-B"}

        only_one = {row["hostname"] for row in database.get_fleet_summary(path, user_id=1)}
        assert only_one == {"HOST-A"}
    finally:
        _cleanup(path)


def test_delete_scans_only_touches_owned_rows():
    path = _fresh_db()
    try:
        owned = database.save_scan(
            path, [{"rule": "A", "severity": "LOW", "hostname": "H"}], user_id=1,
        )
        other = database.save_scan(
            path, [{"rule": "B", "severity": "LOW", "hostname": "H"}], user_id=2,
        )

        # Viewer 1 tries to wipe both ids — only their own row goes.
        deleted = database.delete_scans(path, [owned, other], user_id=1)
        assert deleted == 1
        remaining = {r["id"] for r in database.get_history(path)}
        assert owned not in remaining
        assert other in remaining
    finally:
        _cleanup(path)


def test_get_scans_since_and_findings_since_filter_by_user():
    path = _fresh_db()
    try:
        database.save_scan(path, [{"rule": "A", "severity": "LOW", "hostname": "H"}], user_id=1)
        database.save_scan(path, [{"rule": "B", "severity": "LOW", "hostname": "H"}], user_id=2)

        assert len(database.get_scans_since(path, 30)) == 2
        assert len(database.get_scans_since(path, 30, user_id=1)) == 1
        assert len(database.get_findings_since(path, 30)) == 2
        assert len(database.get_findings_since(path, 30, user_id=1)) == 1
    finally:
        _cleanup(path)


# ---------------------------------------------------------------------------
# End-to-end API tests — admin vs viewer via the dashboard surface
# ---------------------------------------------------------------------------

@pytest.fixture
def isolation_client(tmp_path):
    """Auth-on app seeded with an admin and a viewer plus one scan each."""
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(config_path))
    client = TestClient(app)

    # First signup always becomes admin.
    client.post("/api/auth/signup", json={
        "email": "admin@example.com", "password": "correct-horse-battery",
    })
    me_admin = client.get("/api/me").json()

    client.post("/api/users", json={
        "email": "viewer@example.com",
        "password": "another-long-password",
        "role": "viewer",
    })
    # Viewer id: fetch from the users list while we're still the admin.
    users = client.get("/api/users").json()
    viewer_id = next(u["id"] for u in users["users"] if u["email"] == "viewer@example.com")

    # Seed three scans covering every ownership case: admin-owned, viewer-owned,
    # and an unowned CLI-style row. Go through the DB helper because we don't
    # need the full upload path to verify isolation.
    database.save_scan(
        str(db_path),
        [{"rule": "RDP Logon Detected", "severity": "HIGH", "hostname": "ADMIN-PC"}],
        filename="admin.evtx", user_id=me_admin["id"],
    )
    database.save_scan(
        str(db_path),
        [{"rule": "User Account Created", "severity": "MEDIUM", "hostname": "VIEWER-PC"}],
        filename="viewer.evtx", user_id=viewer_id,
    )
    database.save_scan(
        str(db_path),
        [{"rule": "Audit Log Cleared", "severity": "CRITICAL", "hostname": "CLI-PC"}],
        filename="cli.evtx",
    )

    return client, me_admin["id"], viewer_id


def test_admin_history_sees_every_scan(isolation_client):
    client, _admin_id, _viewer_id = isolation_client
    scans = client.get("/api/history").json()["scans"]
    files = {s.get("filename") for s in scans}
    assert {"admin.evtx", "viewer.evtx", "cli.evtx"} == files


def test_viewer_history_sees_only_own_scans(isolation_client):
    client, _admin_id, _viewer_id = isolation_client
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={
        "email": "viewer@example.com", "password": "another-long-password",
    })
    scans = client.get("/api/history").json()["scans"]
    files = {s.get("filename") for s in scans}
    assert files == {"viewer.evtx"}


def test_viewer_cannot_read_other_users_report(isolation_client):
    client, _admin_id, _viewer_id = isolation_client
    # Grab the admin-owned scan id while logged in as admin.
    scans = client.get("/api/history").json()["scans"]
    admin_scan_id = next(s["id"] for s in scans if s["filename"] == "admin.evtx")

    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={
        "email": "viewer@example.com", "password": "another-long-password",
    })
    r = client.get(f"/api/report/{admin_scan_id}")
    # The scan is invisible to the viewer, so the lookup 404s exactly as if
    # the row didn't exist — no "forbidden" leak that would confirm it's there.
    assert r.status_code == 404


def test_viewer_fleet_only_shows_their_hosts(isolation_client):
    client, _admin_id, _viewer_id = isolation_client
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={
        "email": "viewer@example.com", "password": "another-long-password",
    })
    hosts = {h["hostname"] for h in client.get("/api/fleet").json()["hosts"]}
    assert hosts == {"VIEWER-PC"}


def test_viewer_delete_cannot_reach_admin_scans(isolation_client):
    client, _admin_id, _viewer_id = isolation_client
    scans = client.get("/api/history").json()["scans"]
    admin_scan_id = next(s["id"] for s in scans if s["filename"] == "admin.evtx")

    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={
        "email": "viewer@example.com", "password": "another-long-password",
    })
    r = client.request("DELETE", "/api/scans", json={"ids": [admin_scan_id]})
    assert r.status_code == 200
    assert r.json()["deleted"] == 0

    # Log back in as admin and confirm the admin scan is untouched.
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={
        "email": "admin@example.com", "password": "correct-horse-battery",
    })
    still_there = {s["id"] for s in client.get("/api/history").json()["scans"]}
    assert admin_scan_id in still_there
