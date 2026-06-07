# test_team_queue.py
# ------------------
# Team role hierarchy Phase 3: findings priority/due-date schema,
# analyst My Queue, and manager Team Workload.

import os
import tempfile
from datetime import datetime, timedelta

import pytest

from pulse import database as db
from pulse.database import (
    set_finding_assignee, set_finding_priority, get_user_queue,
    count_resolved_today, get_team_workload,
    FINDING_PRIORITIES, SEVERITY_DEFAULT_PRIORITY,
)


# ---------------------------------------------------------------------------
# DB-layer fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def seeded():
    """Admin + one analyst + a scan with three findings (CRIT/HIGH/MED),
    all assigned to the analyst. Returns (db_path, analyst_id, finding_ids)."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db.init_db(path)
    import sqlite3
    with sqlite3.connect(path) as c:
        c.execute("INSERT INTO users (email,password_hash,created_at,role,active) "
                  "VALUES ('admin@x.com','h','2026-01-01','admin',1)")
        c.execute("INSERT INTO users (email,password_hash,created_at,role,active,display_name) "
                  "VALUES ('kwame@x.com','h','2026-01-01','analyst',1,'Kwame')")
        analyst = c.execute("SELECT id FROM users WHERE email='kwame@x.com'").fetchone()[0]
        c.execute("INSERT INTO scans (scanned_at,files_scanned,score,score_label,filename,hostname) "
                  "VALUES ('2026-06-07 10:00:00',1,40,'High','x.evtx','DC01')")
        sid = c.execute("SELECT MAX(id) FROM scans").fetchone()[0]
        for sev in ("CRITICAL", "HIGH", "MEDIUM"):
            c.execute("INSERT INTO findings (scan_id,severity,rule,hostname,timestamp,workflow_status) "
                      "VALUES (?,?,?,?,?,?)",
                      (sid, sev, "Brute Force Attempt", "DC01",
                       "2026-06-07T09:00:00Z", "new"))
        fids = [r[0] for r in c.execute("SELECT id FROM findings ORDER BY id").fetchall()]
        c.commit()
    for fid in fids:
        set_finding_assignee(path, fid, analyst, assigned_by=1)
    yield path, analyst, fids
    try:
        os.unlink(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Priority schema
# ---------------------------------------------------------------------------

def test_priorities_constant():
    assert FINDING_PRIORITIES == ("P1", "P2", "P3", "P4")
    assert SEVERITY_DEFAULT_PRIORITY["CRITICAL"] == "P1"
    assert SEVERITY_DEFAULT_PRIORITY["LOW"] == "P4"


def test_set_priority_and_due(seeded):
    path, analyst, fids = seeded
    assert set_finding_priority(path, fids[0], priority="P1", due_date="2026-06-08") is True
    q = get_user_queue(path, analyst)
    row = next(r for r in q if r["id"] == fids[0])
    assert row["priority"] == "P1"
    assert row["due_date"] == "2026-06-08"


def test_set_priority_rejects_bad_value(seeded):
    path, _, fids = seeded
    with pytest.raises(ValueError):
        set_finding_priority(path, fids[0], priority="URGENT")


def test_set_priority_only_due(seeded):
    path, analyst, fids = seeded
    set_finding_priority(path, fids[1], due_date="2026-06-09")
    row = next(r for r in get_user_queue(path, analyst) if r["id"] == fids[1])
    assert row["due_date"] == "2026-06-09"
    assert row["priority"] is None


def test_assigned_by_recorded(seeded):
    path, analyst, fids = seeded
    row = get_user_queue(path, analyst)[0]
    assert row["assigned_by"] == 1


# ---------------------------------------------------------------------------
# Queue ordering + scoping
# ---------------------------------------------------------------------------

def test_queue_orders_priority_over_severity(seeded):
    path, analyst, fids = seeded
    # Give the MEDIUM finding P1 — it must sort above the unset CRITICAL.
    set_finding_priority(path, fids[2], priority="P1")
    q = get_user_queue(path, analyst)
    assert q[0]["id"] == fids[2]               # P1 medium leads
    assert q[0]["severity"] == "MEDIUM"
    # Remaining unset findings fall back to severity order.
    assert [r["severity"] for r in q[1:]] == ["CRITICAL", "HIGH"]


def test_queue_excludes_resolved(seeded):
    path, analyst, fids = seeded
    db.set_finding_workflow(path, fids[0], "resolved")
    q = get_user_queue(path, analyst)
    assert all(r["id"] != fids[0] for r in q)
    assert len(q) == 2


def test_queue_excludes_false_positive(seeded):
    path, analyst, fids = seeded
    db.set_finding_review(path, fids[0], reviewed=False, false_positive=True)
    q = get_user_queue(path, analyst)
    assert all(r["id"] != fids[0] for r in q)


def test_queue_only_returns_own_findings(seeded):
    path, analyst, fids = seeded
    # A different user has nothing assigned -> empty queue.
    assert get_user_queue(path, 999) == []


def test_queue_carries_scan_context(seeded):
    path, analyst, fids = seeded
    row = get_user_queue(path, analyst)[0]
    assert row["scan_number"] == 1
    assert row["scan_date"]
    assert row["assigned_by_name"] is None  # admin has no display_name


# ---------------------------------------------------------------------------
# Resolved-today + workload
# ---------------------------------------------------------------------------

def test_count_resolved_today(seeded):
    path, analyst, fids = seeded
    assert count_resolved_today(path, analyst) == 0
    db.set_finding_workflow(path, fids[0], "resolved")
    assert count_resolved_today(path, analyst) == 1


def _workflow_row(path, fid):
    import sqlite3
    with sqlite3.connect(path) as c:
        return c.execute(
            "SELECT workflow_status, workflow_updated_at FROM findings WHERE id=?",
            (fid,),
        ).fetchone()


def test_workflow_real_state_stamps_updated_at(seeded):
    path, _, fids = seeded
    db.set_finding_workflow(path, fids[0], "acknowledged")
    status, updated = _workflow_row(path, fids[0])
    assert status == "acknowledged"
    assert updated is not None      # real states record the change time


def test_workflow_clear_to_new_nulls_updated_at(seeded):
    # Reverting to 'new' is a clear: workflow_updated_at must be NULLed so
    # the finding reads as untouched again (no "Updated …" line).
    path, _, fids = seeded
    db.set_finding_workflow(path, fids[0], "investigating")
    assert _workflow_row(path, fids[0])[1] is not None
    db.set_finding_workflow(path, fids[0], "new")
    status, updated = _workflow_row(path, fids[0])
    assert status == "new"
    assert updated is None


def test_team_workload_shape(seeded):
    path, analyst, fids = seeded
    wl = get_team_workload(path)
    assert len(wl) == 1                       # only the analyst (admin excluded)
    a = wl[0]
    assert a["display_name"] == "Kwame"
    assert a["open_count"] == 3
    assert a["by_severity"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0}
    assert a["oldest_hours"] is not None


def test_team_workload_busiest_first():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db.init_db(path)
    import sqlite3
    with sqlite3.connect(path) as c:
        for name in ("a", "b"):
            c.execute("INSERT INTO users (email,password_hash,created_at,role,active,display_name) "
                      "VALUES (?,?,?,?,?,?)",
                      (f"{name}@x.com", "h", "2026-01-01", "analyst", 1, name))
        ua = c.execute("SELECT id FROM users WHERE email='a@x.com'").fetchone()[0]
        ub = c.execute("SELECT id FROM users WHERE email='b@x.com'").fetchone()[0]
        c.execute("INSERT INTO scans (scanned_at,files_scanned,score,score_label,filename) "
                  "VALUES ('2026-06-07 10:00:00',1,40,'High','x.evtx')")
        sid = c.execute("SELECT MAX(id) FROM scans").fetchone()[0]
        # a gets 1 finding, b gets 3.
        owners = [ua] + [ub] * 3
        for owner in owners:
            c.execute("INSERT INTO findings (scan_id,severity,rule,timestamp,workflow_status,assigned_to) "
                      "VALUES (?,?,?,?,?,?)",
                      (sid, "HIGH", "Brute Force Attempt", "2026-06-07T09:00:00Z", "new", owner))
        c.commit()
    wl = get_team_workload(path)
    assert wl[0]["display_name"] == "b"       # busiest first
    assert wl[0]["open_count"] == 3
    try:
        os.unlink(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# API integration
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    from fastapi.testclient import TestClient
    from pulse.api import create_app
    dbp = tmp_path / "test.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(dbp), config_path=str(cfg), disable_auth=True)
    return TestClient(app), str(dbp)


def test_queue_endpoint_shape(client):
    c, _ = client
    r = c.get("/api/queue")
    assert r.status_code == 200
    body = r.json()
    assert "queue" in body and "kpis" in body
    for k in ("in_queue", "overdue", "due_today", "resolved_today"):
        assert k in body["kpis"]


def test_team_workload_endpoint(client):
    c, _ = client
    r = c.get("/api/team-workload")
    assert r.status_code == 200
    assert "analysts" in r.json()


def test_priority_endpoint_sets_value(client):
    c, dbp = client
    import sqlite3
    with sqlite3.connect(dbp) as conn:
        conn.execute("INSERT INTO scans (scanned_at,files_scanned,score,score_label,filename) "
                     "VALUES ('2026-06-07 10:00:00',1,40,'High','x.evtx')")
        sid = conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]
        conn.execute("INSERT INTO findings (scan_id,severity,rule,timestamp) "
                     "VALUES (?,?,?,?)", (sid, "HIGH", "Brute Force Attempt", "2026-06-07T09:00:00Z"))
        fid = conn.execute("SELECT MAX(id) FROM findings").fetchone()[0]
        conn.commit()
    r = c.put(f"/api/findings/{fid}/priority", json={"priority": "P1", "due_date": "2026-06-08"})
    assert r.status_code == 200
    with sqlite3.connect(dbp) as conn:
        row = conn.execute("SELECT priority, due_date FROM findings WHERE id=?", (fid,)).fetchone()
    assert row == ("P1", "2026-06-08")


def _seed_finding(dbp, sev="HIGH"):
    import sqlite3
    with sqlite3.connect(dbp) as conn:
        conn.execute("INSERT INTO users (email,password_hash,created_at,role,active,display_name) "
                     "VALUES ('an@x.com','h','2026-01-01','analyst',1,'Ana')")
        uid = conn.execute("SELECT id FROM users WHERE email='an@x.com'").fetchone()[0]
        conn.execute("INSERT INTO scans (scanned_at,files_scanned,score,score_label,filename) "
                     "VALUES ('2026-06-07 10:00:00',1,40,'High','x.evtx')")
        sid = conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]
        conn.execute("INSERT INTO findings (scan_id,severity,rule,timestamp) VALUES (?,?,?,?)",
                     (sid, sev, "Brute Force Attempt", "2026-06-07T09:00:00Z"))
        fid = conn.execute("SELECT MAX(id) FROM findings").fetchone()[0]
        conn.commit()
    return fid, uid


def test_batch_assign_sets_priority_and_due(client):
    c, dbp = client
    fid, uid = _seed_finding(dbp)
    r = c.put("/api/findings/batch", json={
        "finding_ids": [fid], "op": "assign", "assignee_user_id": uid,
        "priority": "P1", "due_date": "2026-06-08",
    })
    assert r.status_code == 200
    import sqlite3
    with sqlite3.connect(dbp) as conn:
        row = conn.execute("SELECT assigned_to, priority, due_date FROM findings WHERE id=?",
                           (fid,)).fetchone()
    assert row == (uid, "P1", "2026-06-08")


def test_batch_assign_records_assigned_by(client):
    # auth-disabled mode -> assigned_by is NULL (no real caller); still assigns.
    c, dbp = client
    fid, uid = _seed_finding(dbp)
    r = c.put("/api/findings/batch", json={
        "finding_ids": [fid], "op": "assign", "assignee_user_id": uid,
    })
    assert r.status_code == 200
    assert r.json()["updated"] == 1


def test_batch_assign_rejects_bad_priority(client):
    c, dbp = client
    fid, uid = _seed_finding(dbp)
    r = c.put("/api/findings/batch", json={
        "finding_ids": [fid], "op": "assign", "assignee_user_id": uid,
        "priority": "URGENT",
    })
    assert r.status_code == 400


def test_priority_endpoint_rejects_bad_value(client):
    c, dbp = client
    import sqlite3
    with sqlite3.connect(dbp) as conn:
        conn.execute("INSERT INTO scans (scanned_at,files_scanned,score,score_label,filename) "
                     "VALUES ('2026-06-07 10:00:00',1,40,'High','x.evtx')")
        sid = conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]
        conn.execute("INSERT INTO findings (scan_id,severity,rule) VALUES (?,?,?)",
                     (sid, "HIGH", "Brute Force Attempt"))
        fid = conn.execute("SELECT MAX(id) FROM findings").fetchone()[0]
        conn.commit()
    r = c.put(f"/api/findings/{fid}/priority", json={"priority": "NOPE"})
    assert r.status_code == 400
