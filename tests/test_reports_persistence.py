# test_reports_persistence.py
# ---------------------------
# Sprint 8 — persisted reports. Reports are now stored as rows in the
# reports table (BLOB-backed) instead of files in reports/. Filenames
# remain the public identifier so existing /api/reports/{filename} URLs
# keep working.

import os
import tempfile
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from pulse import database
from pulse.api import create_app


# ---------------------------------------------------------------------------
# DB-layer helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database.init_db(path)
    try:
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_save_and_get_report_roundtrip(db_path):
    rid = database.save_report(
        db_path,
        scan_id=42,
        fmt="pdf",
        filename="pulse_scan_42_20260601_120000.pdf",
        file_data=b"%PDF-1.4 fake bytes",
        generated_by=None,
        organization_id=1,
    )
    assert isinstance(rid, int) and rid > 0

    meta = database.get_report_meta(db_path,
                                     "pulse_scan_42_20260601_120000.pdf")
    assert meta["scan_id"] == 42
    assert meta["format"] == "pdf"
    assert meta["file_size"] == len(b"%PDF-1.4 fake bytes")

    blob, m2 = database.get_report_bytes(
        db_path, "pulse_scan_42_20260601_120000.pdf",
    )
    assert blob == b"%PDF-1.4 fake bytes"
    assert m2["scan_id"] == 42


def test_save_with_duplicate_filename_replaces_bytes(db_path):
    """A retry on the same filename overwrites the prior payload rather
    than failing — keeps the user-facing flow simple."""
    database.save_report(db_path, scan_id=1, fmt="json",
                          filename="dup.json", file_data=b"{}")
    rid2 = database.save_report(db_path, scan_id=1, fmt="json",
                                 filename="dup.json", file_data=b'{"v":2}')
    assert rid2 is not None
    blob, _ = database.get_report_bytes(db_path, "dup.json")
    assert blob == b'{"v":2}'
    # Still exactly one row.
    rows = database.list_reports_db(db_path)
    assert len([r for r in rows if r["filename"] == "dup.json"]) == 1


def test_list_reports_newest_first(db_path):
    a = database.save_report(db_path, scan_id=1, fmt="pdf",
                              filename="a.pdf", file_data=b"a")
    b = database.save_report(db_path, scan_id=2, fmt="pdf",
                              filename="b.pdf", file_data=b"bbb")
    rows = database.list_reports_db(db_path)
    assert [r["id"] for r in rows] == [b, a]
    # No blob in the list payload (would dominate response size).
    assert all("file_data" not in r for r in rows)


def test_list_reports_is_org_scoped(db_path):
    database.save_report(db_path, scan_id=1, fmt="pdf",
                          filename="x.pdf", file_data=b"x",
                          organization_id=1)
    database.save_report(db_path, scan_id=2, fmt="pdf",
                          filename="y.pdf", file_data=b"y",
                          organization_id=2)
    org1 = database.list_reports_db(db_path, organization_id=1)
    org2 = database.list_reports_db(db_path, organization_id=2)
    assert {r["filename"] for r in org1} == {"x.pdf"}
    assert {r["filename"] for r in org2} == {"y.pdf"}


def test_get_report_meta_rejects_cross_tenant(db_path):
    database.save_report(db_path, scan_id=1, fmt="pdf",
                          filename="secret.pdf", file_data=b"x",
                          organization_id=1)
    assert database.get_report_meta(
        db_path, "secret.pdf", organization_id=2) is None
    assert database.get_report_meta(
        db_path, "secret.pdf", organization_id=1) is not None


def test_delete_report_by_filename(db_path):
    database.save_report(db_path, scan_id=1, fmt="pdf",
                          filename="delme.pdf", file_data=b"x")
    assert database.delete_report_by_filename(db_path, "delme.pdf") is True
    assert database.delete_report_by_filename(db_path, "delme.pdf") is False


def test_delete_reports_by_filenames_partial(db_path):
    database.save_report(db_path, scan_id=1, fmt="pdf",
                          filename="real.pdf", file_data=b"r")
    deleted, missing = database.delete_reports_by_filenames(
        db_path, ["real.pdf", "ghost.pdf"],
    )
    assert deleted == 1
    assert missing == ["ghost.pdf"]


def test_save_report_rejects_bad_inputs(db_path):
    with pytest.raises(ValueError, match="filename"):
        database.save_report(db_path, scan_id=1, fmt="pdf",
                              filename="", file_data=b"x")
    with pytest.raises(ValueError, match="bytes"):
        database.save_report(db_path, scan_id=1, fmt="pdf",
                              filename="x.pdf", file_data="not bytes")
    with pytest.raises(ValueError, match="fmt"):
        database.save_report(db_path, scan_id=1, fmt="",
                              filename="x.pdf", file_data=b"x")


def test_purge_old_reports_drops_aged_rows(db_path):
    # Manually backdate one row.
    database.save_report(db_path, scan_id=1, fmt="pdf",
                          filename="old.pdf", file_data=b"x")
    database.save_report(db_path, scan_id=1, fmt="pdf",
                          filename="new.pdf", file_data=b"y")
    import sqlite3
    backdated = (datetime.now() - timedelta(days=120)).strftime(
        "%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE reports SET generated_at = ? WHERE filename = 'old.pdf'",
            (backdated,),
        )
        conn.commit()
    n = database.purge_old_reports(db_path, days=90)
    assert n == 1
    survivors = {r["filename"] for r in database.list_reports_db(db_path)}
    assert survivors == {"new.pdf"}


def test_reports_storage_total(db_path):
    database.save_report(db_path, scan_id=1, fmt="pdf",
                          filename="a.pdf", file_data=b"a" * 100)
    database.save_report(db_path, scan_id=2, fmt="pdf",
                          filename="b.pdf", file_data=b"b" * 250)
    assert database.reports_storage_total(db_path) == 350


# ---------------------------------------------------------------------------
# API-level integration
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    db = tmp_path / "test.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db), config_path=str(cfg), disable_auth=True)
    return TestClient(app), str(db)


def _seed_scan(client_pair):
    """Stand up a scan + finding so /api/export/{id} has something
    to render. Mirrors the minimal seed in test_api.py."""
    _, db = client_pair
    import io
    # Easiest path: use the public /api/scan to take an empty fake file
    # through the parser (parser returns []), generating an empty scan.
    c, _ = client_pair
    fake = io.BytesIO(b"ElfFile\x00" + b"\x00" * 4088)
    r = c.post("/api/scan",
               files={"file": ("fake.evtx", fake, "application/octet-stream")})
    assert r.status_code in (200, 400)
    # If the upload took, a scan exists. Find its id.
    h = c.get("/api/history").json()
    if h.get("scans"):
        return h["scans"][0]["id"]
    # Fallback: insert a row directly.
    import sqlite3
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO scans (scanned_at, files_scanned, total_events,"
            "                    total_findings, score, score_label, filename)"
            " VALUES (?, 1, 0, 0, 100, 'Clean', 'test.evtx')",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
        )
        return conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]


def test_export_persists_report_and_downloads(client):
    c, db = client
    scan_id = _seed_scan(client)
    r = c.get(f"/api/export/{scan_id}?format=json")
    assert r.status_code == 200
    assert r.content  # bytes returned

    # The persisted row should be visible on /api/reports.
    listed = c.get("/api/reports").json()
    assert listed["reports"]
    row = listed["reports"][0]
    assert row["scan_id"] == scan_id
    assert row["format"] == "json"
    assert row["file_size"] > 0
    assert "_" in row["filename"]  # timestamp embedded


def test_list_reports_returns_kpis(client):
    c, _ = client
    scan_id = _seed_scan(client)
    c.get(f"/api/export/{scan_id}?format=pdf")
    body = c.get("/api/reports").json()
    assert "kpis" in body
    k = body["kpis"]
    assert k["total"] >= 1
    assert k["pdf"] >= 1
    assert k["this_week"] >= 1
    assert k["storage_bytes"] > 0
    assert body["retention_days"] == 90


def test_download_serves_db_bytes(client):
    c, _ = client
    scan_id = _seed_scan(client)
    c.get(f"/api/export/{scan_id}?format=html")
    listing = c.get("/api/reports").json()
    name = listing["reports"][0]["filename"]
    r = c.get(f"/api/reports/{name}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert r.content  # served from DB blob


def test_delete_single_report(client):
    c, _ = client
    scan_id = _seed_scan(client)
    c.get(f"/api/export/{scan_id}?format=json")
    name = c.get("/api/reports").json()["reports"][0]["filename"]
    r = c.delete(f"/api/reports/{name}")
    assert r.status_code == 200
    assert c.get(f"/api/reports/{name}").status_code == 404


def test_batch_delete_reports(client):
    c, _ = client
    scan_id = _seed_scan(client)
    c.get(f"/api/export/{scan_id}?format=pdf")
    c.get(f"/api/export/{scan_id}?format=json")
    names = [r["filename"] for r in c.get("/api/reports").json()["reports"]]
    r = c.request("DELETE", "/api/reports/batch",
                   json={"filenames": names + ["nope.pdf"]})
    assert r.status_code == 200
    body = r.json()
    assert body["deleted"] == 2
    assert body["failed"][0]["filename"] == "nope.pdf"


def test_download_unknown_returns_404(client):
    c, _ = client
    assert c.get("/api/reports/does_not_exist.pdf").status_code == 404
