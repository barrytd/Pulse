# test_assignment_visibility.py
# -----------------------------
# Sprint 8 bug fix (2026-05-28): a viewer assigned to a finding must be
# able to see it on /api/history + /api/report/{id} + /api/score/daily
# even when the parent scan is outside their org scope. Reported live by
# the user: 25 findings assigned to "kwame.asante" rendered as "No
# findings" on his Findings page because his org didn't own the scans.
#
# Root cause: get_history/get_scan_findings only filtered by scope.
# Fix: both helpers gained an `assignee_user_id` parameter that ORs into
# the WHERE clause via an EXISTS sub-query; the API layer plumbs it via
# the new `_findings_scope_kwargs` helper.

import os
import pytest
from fastapi.testclient import TestClient

from pulse import database
from pulse.api import create_app


@pytest.fixture
def two_user_app(tmp_path):
    """Auth-on app with a signed-up admin + a freshly invited viewer in
    a *different* org. Returns (admin_client, viewer_client, db_path)
    where each client carries its own session cookie. Mimics the real
    "Kwame Asante" repro from 2026-05-28."""
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(config_path))

    admin = TestClient(app)
    admin.post("/api/auth/signup", json={
        "email": "admin@example.com", "password": "correct-horse-battery",
    })

    # Hand-create a viewer in a *separate* org so the scope filter
    # excludes them by default — exactly the broken state Kwame was in.
    other_org = database.create_organization(str(db_path), name="Other Co")
    from pulse.auth import hash_password
    viewer_id = database.create_user(
        str(db_path), "kwame@example.com",
        hash_password("correct-horse-battery"),
        role="analyst", organization_id=other_org,
    )
    # The seeded viewer needs `email_verified_at` so the API treats them
    # as a real account (Sprint 8 verification gating).
    database.mark_user_email_verified(str(db_path), viewer_id)

    viewer = TestClient(app)
    viewer.post("/api/auth/login", json={
        "email": "kwame@example.com", "password": "correct-horse-battery",
    })
    return admin, viewer, str(db_path), viewer_id


def _save_finding(db_path, admin_user_id, *, severity="HIGH", rule="Test Rule"):
    """Stamp one scan + one finding owned by ``admin_user_id``. Returns
    (scan_id, finding_id)."""
    scan_id = database.save_scan(
        db_path,
        [{"rule": rule, "severity": severity, "description": "synthetic",
          "details": "synthetic", "hostname": "TEST-HOST"}],
        filename="seed.evtx", user_id=admin_user_id,
    )
    findings = database.get_scan_findings(db_path, scan_id)
    return scan_id, findings[0]["id"]


def test_viewer_sees_scan_in_history_after_assignment(two_user_app):
    """Repro: admin creates a scan in their org, assigns one of its
    findings to a viewer in a different org. The viewer's /api/history
    must include that scan even though their org scope would otherwise
    exclude it. Before the fix, /api/history returned ``{"scans": []}``."""
    admin, viewer, db_path, viewer_id = two_user_app

    me = admin.get("/api/me").json()
    scan_id, finding_id = _save_finding(db_path, me["id"])

    # Viewer doesn't see it yet — scope-filtered out.
    body = viewer.get("/api/history").json()
    assert all(s["id"] != scan_id for s in body["scans"]), (
        "viewer should NOT see the scan before assignment (sanity)"
    )

    # Admin assigns the finding to the viewer.
    r = admin.put(f"/api/finding/{finding_id}/assign", json={
        "assignee_user_id": viewer_id,
    })
    assert r.status_code == 200, r.text

    # Now the viewer's /api/history includes the scan.
    body = viewer.get("/api/history").json()
    scan_ids = [s["id"] for s in body["scans"]]
    assert scan_id in scan_ids, (
        f"after assignment, viewer should see scan {scan_id} in their "
        f"history. Got: {scan_ids}"
    )


def test_viewer_can_fetch_report_for_assigned_finding(two_user_app):
    """/api/report/{scan_id} must succeed for a viewer when the scan
    contains a finding assigned to them. Before the fix it returned 404
    ('Scan not found') because the scope filter rejected the scan."""
    admin, viewer, db_path, viewer_id = two_user_app
    me = admin.get("/api/me").json()
    scan_id, finding_id = _save_finding(db_path, me["id"])

    # Pre-assignment: viewer gets 404.
    r = viewer.get(f"/api/report/{scan_id}")
    assert r.status_code == 404

    admin.put(f"/api/finding/{finding_id}/assign", json={
        "assignee_user_id": viewer_id,
    })

    # Post-assignment: viewer gets the findings array.
    r = viewer.get(f"/api/report/{scan_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    findings = body.get("findings") if isinstance(body, dict) else body
    assert findings, "viewer should see at least the assigned finding"
    assigned = [f for f in findings if f.get("id") == finding_id]
    assert assigned, f"finding {finding_id} not present in {findings}"


def test_viewer_does_not_see_unassigned_findings(two_user_app):
    """Tighten the contract: assignment widens visibility to the SPECIFIC
    scan-with-assignment, but other out-of-scope scans stay invisible.
    Otherwise the widening becomes a privilege-escalation vector."""
    admin, viewer, db_path, viewer_id = two_user_app
    me = admin.get("/api/me").json()

    # Two separate scans owned by admin.
    assigned_scan, assigned_finding = _save_finding(db_path, me["id"], rule="Assigned")
    other_scan,    _other_finding   = _save_finding(db_path, me["id"], rule="Other")

    # Assign one finding from the first scan only.
    admin.put(f"/api/finding/{assigned_finding}/assign", json={
        "assignee_user_id": viewer_id,
    })

    body = viewer.get("/api/history").json()
    scan_ids = [s["id"] for s in body["scans"]]
    assert assigned_scan in scan_ids, "assigned scan visible — fix working"
    assert other_scan not in scan_ids, (
        f"viewer should NOT see {other_scan} (no assignment on it). "
        f"Got: {scan_ids}"
    )


def test_admin_visibility_unchanged_by_widening(two_user_app):
    """Admin scope is ``{}`` (no filter). Adding ``assignee_user_id``
    must be a no-op for admins — they already see everything."""
    admin, _viewer, db_path, _ = two_user_app
    me = admin.get("/api/me").json()
    scan_id, _ = _save_finding(db_path, me["id"])

    body = admin.get("/api/history").json()
    assert scan_id in [s["id"] for s in body["scans"]]
