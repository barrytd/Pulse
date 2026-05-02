# test_data_isolation.py
# ----------------------
# Sprint 5 — data isolation tests, extended in Sprint 7 for multi-tenant.
#
# Single-tenant covers (legacy single-user installs):
#   - Scans carry their originator's user_id
#   - get_history / get_fleet_summary / get_scan_findings / get_scans_since
#     / get_findings_since / get_scan_number / delete_scans honor the
#     user_id filter
#
# Multi-tenant covers (Sprint 7 hosted mode):
#   - Admin creates teammates -> they join the admin's org (shared scope)
#   - Self-signup -> new org auto-created (isolated tenant)
#   - Cross-org reads / writes return 404 / no-op

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


def test_viewer_history_sees_org_mates_scans(isolation_client):
    """A viewer created by the admin joins the admin's org, so the viewer
    sees both admin-owned and viewer-owned scans (same tenant) but not the
    unowned CLI row (no organization_id)."""
    client, _admin_id, _viewer_id = isolation_client
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={
        "email": "viewer@example.com", "password": "another-long-password",
    })
    scans = client.get("/api/history").json()["scans"]
    files = {s.get("filename") for s in scans}
    assert files == {"admin.evtx", "viewer.evtx"}


def test_viewer_can_read_org_mate_report(isolation_client):
    """Org members share scan visibility — the viewer can fetch the
    admin's report because they're in the same tenant."""
    client, _admin_id, _viewer_id = isolation_client
    scans = client.get("/api/history").json()["scans"]
    admin_scan_id = next(s["id"] for s in scans if s["filename"] == "admin.evtx")

    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={
        "email": "viewer@example.com", "password": "another-long-password",
    })
    r = client.get(f"/api/report/{admin_scan_id}")
    assert r.status_code == 200


def test_viewer_fleet_shows_org_hosts(isolation_client):
    """Fleet rollup is org-scoped — viewer sees every host inside the
    org (admin's + their own), but never the unowned CLI host."""
    client, _admin_id, _viewer_id = isolation_client
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={
        "email": "viewer@example.com", "password": "another-long-password",
    })
    hosts = {h["hostname"] for h in client.get("/api/fleet").json()["hosts"]}
    assert hosts == {"ADMIN-PC", "VIEWER-PC"}


def test_viewer_can_delete_org_mate_scans(isolation_client):
    """In multi-tenant mode any org member can clean up shared scans.
    Admin owns scan, viewer (same org) deletes it -> success."""
    client, _admin_id, _viewer_id = isolation_client
    scans = client.get("/api/history").json()["scans"]
    admin_scan_id = next(s["id"] for s in scans if s["filename"] == "admin.evtx")

    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={
        "email": "viewer@example.com", "password": "another-long-password",
    })
    r = client.request("DELETE", "/api/scans", json={"ids": [admin_scan_id]})
    assert r.status_code == 200
    assert r.json()["deleted"] == 1

    # Confirm it's gone for the admin too.
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={
        "email": "admin@example.com", "password": "correct-horse-battery",
    })
    still_there = {s["id"] for s in client.get("/api/history").json()["scans"]}
    assert admin_scan_id not in still_there


# ---------------------------------------------------------------------------
# Multi-tenant — cross-org isolation (Sprint 7)
# ---------------------------------------------------------------------------

def test_create_organization_and_lookup():
    path = _fresh_db()
    try:
        oid_a = database.create_organization(path, name="Acme")
        oid_b = database.create_organization(path, name="Initech")
        assert oid_a != oid_b
        org_a = database.get_organization(path, oid_a)
        assert org_a["name"] == "Acme"
        # Slugs are unique even when the names collide.
        oid_c = database.create_organization(path, name="Acme")
        org_c = database.get_organization(path, oid_c)
        assert org_a["slug"] != org_c["slug"]
    finally:
        _cleanup(path)


def test_create_user_auto_creates_organization_for_self_signup():
    path = _fresh_db()
    try:
        uid = database.create_user(path, "founder@acme.test", "x", role="admin")
        org_id = database.get_user_organization_id(path, uid)
        assert org_id is not None
        org = database.get_organization(path, org_id)
        # Slug seeds from the email local-part when no display_name is set.
        assert (org.get("slug") or "").startswith("founder")
    finally:
        _cleanup(path)


def test_create_user_with_explicit_org_joins_that_org():
    path = _fresh_db()
    try:
        org_id = database.create_organization(path, name="Acme")
        uid = database.create_user(
            path, "joiner@acme.test", "x", role="viewer",
            organization_id=org_id,
        )
        assert database.get_user_organization_id(path, uid) == org_id
    finally:
        _cleanup(path)


def test_save_scan_stamps_organization_id_from_user():
    path = _fresh_db()
    try:
        uid = database.create_user(path, "a@x.test", "x")
        org_id = database.get_user_organization_id(path, uid)
        sid = database.save_scan(
            path, [{"rule": "A", "severity": "LOW", "hostname": "H"}],
            user_id=uid,
        )
        # Read back the org column directly.
        from pulse import db_backend
        with db_backend.connect(path) as conn:
            row = conn.execute(
                "SELECT organization_id FROM scans WHERE id = ?", (sid,)
            ).fetchone()
        stamped = row[0] if not isinstance(row, dict) else row.get("organization_id")
        assert stamped == org_id
    finally:
        _cleanup(path)


def test_get_history_organization_scope_isolates_tenants():
    path = _fresh_db()
    try:
        org_a = database.create_organization(path, name="Acme")
        org_b = database.create_organization(path, name="Initech")
        uid_a = database.create_user(path, "a@acme.test", "x", organization_id=org_a)
        uid_b = database.create_user(path, "b@init.test", "x", organization_id=org_b)
        database.save_scan(path, [{"rule": "A", "severity": "LOW", "hostname": "HA"}],
                           filename="acme.evtx", user_id=uid_a)
        database.save_scan(path, [{"rule": "B", "severity": "LOW", "hostname": "HB"}],
                           filename="init.evtx", user_id=uid_b)
        a_only = database.get_history(path, organization_id=org_a)
        b_only = database.get_history(path, organization_id=org_b)
        assert {s["filename"] for s in a_only} == {"acme.evtx"}
        assert {s["filename"] for s in b_only} == {"init.evtx"}
    finally:
        _cleanup(path)


def test_backfill_orphaned_users_get_organizations():
    """A DB created before the migration has users/scans with NULL
    organization_id. init_db should backfill an org per user and stamp
    every owned scan/agent/notification."""
    path = _fresh_db()
    try:
        # Simulate legacy state: user + scan exist but organization_id was
        # left NULL (e.g. pre-Sprint-7 install). Force the columns back to
        # NULL so we can observe the backfill in isolation.
        uid = database.create_user(path, "legacy@x.test", "x")
        sid = database.save_scan(
            path, [{"rule": "A", "severity": "LOW", "hostname": "H"}],
            user_id=uid,
        )
        from pulse import db_backend
        with db_backend.connect(path) as conn:
            conn.execute("UPDATE users SET organization_id = NULL WHERE id = ?",
                         (uid,))
            conn.execute("UPDATE scans SET organization_id = NULL WHERE id = ?",
                         (sid,))
        database._backfill_organizations(path)
        with db_backend.connect(path) as conn:
            urow = conn.execute(
                "SELECT organization_id FROM users WHERE id = ?", (uid,)
            ).fetchone()
            srow = conn.execute(
                "SELECT organization_id FROM scans WHERE id = ?", (sid,)
            ).fetchone()
        u_org = urow[0] if not isinstance(urow, dict) else urow.get("organization_id")
        s_org = srow[0] if not isinstance(srow, dict) else srow.get("organization_id")
        assert u_org is not None
        assert s_org == u_org
    finally:
        _cleanup(path)


@pytest.fixture
def two_tenant_client(tmp_path):
    """Two separate orgs each with their own viewer + scan.

    We can't go through /api/auth/signup twice because that endpoint is
    self-closing after the first user (single-instance bootstrap). Hosted
    multi-tenant signup is a separate Sprint 7 deliverable; this fixture
    builds the equivalent state via DB helpers so the cross-org isolation
    boundary can be exercised end-to-end at the API surface today."""
    from pulse.auth import hash_password
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(config_path))
    client = TestClient(app)

    # Two completely separate organizations.
    org_a = database.create_organization(str(db_path), name="Acme")
    org_b = database.create_organization(str(db_path), name="Initech")

    # One viewer per org. Email/password lets each one log in.
    uid_a = database.create_user(
        str(db_path), "viewer-a@acme.test",
        hash_password("correct-horse-battery"),
        role="viewer", organization_id=org_a,
    )
    uid_b = database.create_user(
        str(db_path), "viewer-b@initech.test",
        hash_password("another-long-password"),
        role="viewer", organization_id=org_b,
    )

    sid_a = database.save_scan(
        str(db_path),
        [{"rule": "RDP Logon Detected", "severity": "HIGH", "hostname": "ACME-PC"}],
        filename="acme.evtx", user_id=uid_a,
    )
    sid_b = database.save_scan(
        str(db_path),
        [{"rule": "Audit Log Cleared", "severity": "CRITICAL", "hostname": "INIT-PC"}],
        filename="init.evtx", user_id=uid_b,
    )
    return client, sid_a, sid_b


def test_cross_tenant_history_is_invisible(two_tenant_client):
    client, _sid_a, _sid_b = two_tenant_client
    # Tenant B (a viewer in their own org) should not see tenant A's scan.
    client.post("/api/auth/login", json={
        "email": "viewer-b@initech.test", "password": "another-long-password",
    })
    files = {s.get("filename") for s in client.get("/api/history").json()["scans"]}
    assert files == {"init.evtx"}


def test_cross_tenant_report_is_404(two_tenant_client):
    client, sid_a, _sid_b = two_tenant_client
    client.post("/api/auth/login", json={
        "email": "viewer-b@initech.test", "password": "another-long-password",
    })
    r = client.get(f"/api/report/{sid_a}")
    assert r.status_code == 404


def test_cross_tenant_delete_is_noop(two_tenant_client):
    client, sid_a, _sid_b = two_tenant_client
    client.post("/api/auth/login", json={
        "email": "viewer-b@initech.test", "password": "another-long-password",
    })
    r = client.request("DELETE", "/api/scans", json={"ids": [sid_a]})
    assert r.status_code == 200
    assert r.json()["deleted"] == 0
