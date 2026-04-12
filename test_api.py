# test_api.py
# -----------
# Tests for the Pulse REST API in pulse/api.py.
#
# HOW THESE TESTS WORK:
# FastAPI ships a TestClient that lets us call endpoints without starting
# a real HTTP server. We build a fresh app with a temporary SQLite database
# for each test so nothing persists between runs.
#
# We don't have real .evtx files lying around, so for /api/scan we build
# one on the fly using python-evtx? No — python-evtx only reads, not writes.
# Instead we test the scan endpoint with a file that's deliberately not
# a valid .evtx (the parser returns [] for unreadable files) and check
# the API still returns a well-formed response. Edge cases around
# bad uploads (wrong extension, empty body) are tested directly.
#
# RUN:
#   python -m pytest test_api.py -v


import io
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    """Fresh app + isolated database for each test."""
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    # Write a minimal config so the whitelist loader has something to read.
    config_path.write_text("whitelist:\n  accounts: []\n")

    app = create_app(db_path=str(db_path), config_path=str(config_path))
    return TestClient(app)


# ---------------------------------------------------------------------------
# /api/health
# ---------------------------------------------------------------------------

def test_health_returns_ok(client):
    """The health endpoint should always report status=ok."""
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"


def test_health_includes_version(client):
    """Health should report the Pulse version so clients know what they're talking to."""
    response = client.get("/api/health")
    body = response.json()
    assert "version" in body
    # Version should be a non-empty string like "1.1.0"
    assert isinstance(body["version"], str)
    assert len(body["version"]) > 0


# ---------------------------------------------------------------------------
# /api/scan
# ---------------------------------------------------------------------------

def test_scan_rejects_wrong_extension(client):
    """Uploading a .txt file should be refused with 400."""
    response = client.post(
        "/api/scan",
        files={"file": ("notes.txt", b"this is not an evtx file", "text/plain")},
    )
    assert response.status_code == 400
    assert "evtx" in response.json()["detail"].lower()


def test_scan_rejects_missing_file(client):
    """No file at all should fail with a 422 (FastAPI's default for missing body)."""
    response = client.post("/api/scan")
    assert response.status_code == 422


def test_scan_accepts_evtx_extension(client):
    """A file ending in .evtx should be accepted even if its contents are garbage.
    The parser returns an empty event list for unreadable files, so the API
    should return a well-formed scan with zero findings."""
    response = client.post(
        "/api/scan",
        files={"file": ("fake.evtx", b"not really an evtx file", "application/octet-stream")},
    )
    assert response.status_code == 200
    body = response.json()
    assert "scan_id" in body
    assert "findings" in body
    assert "score" in body
    assert body["filename"] == "fake.evtx"


def test_scan_result_has_expected_shape(client):
    """Every scan response should include the standard fields so clients can rely on them."""
    response = client.post(
        "/api/scan",
        files={"file": ("x.evtx", b"", "application/octet-stream")},
    )
    body = response.json()
    for field in ("scan_id", "filename", "total_events", "total_findings",
                  "score", "score_label", "severity_counts", "findings"):
        assert field in body, f"missing field: {field}"

    # severity_counts should always have all four buckets
    assert set(body["severity_counts"].keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ---------------------------------------------------------------------------
# /api/history
# ---------------------------------------------------------------------------

def test_history_empty_when_no_scans(client):
    """A fresh database has no scans — history should return an empty list."""
    response = client.get("/api/history")
    assert response.status_code == 200
    assert response.json() == {"scans": []}


def test_history_returns_scans_after_scanning(client):
    """After one scan, /api/history should return one entry."""
    client.post("/api/scan", files={"file": ("a.evtx", b"", "application/octet-stream")})
    response = client.get("/api/history")
    scans = response.json()["scans"]
    assert len(scans) == 1
    assert scans[0]["files_scanned"] == 1


def test_history_newest_first(client):
    """Multiple scans should be returned newest-first (highest id first)."""
    client.post("/api/scan", files={"file": ("a.evtx", b"", "application/octet-stream")})
    client.post("/api/scan", files={"file": ("b.evtx", b"", "application/octet-stream")})
    client.post("/api/scan", files={"file": ("c.evtx", b"", "application/octet-stream")})

    scans = client.get("/api/history").json()["scans"]
    assert len(scans) == 3
    ids = [s["id"] for s in scans]
    assert ids == sorted(ids, reverse=True)


def test_history_respects_limit(client):
    """The ?limit= query parameter should cap the returned list."""
    for _ in range(5):
        client.post("/api/scan", files={"file": ("x.evtx", b"", "application/octet-stream")})

    scans = client.get("/api/history?limit=2").json()["scans"]
    assert len(scans) == 2


def test_history_rejects_bad_limit(client):
    """Limit outside [1, 200] should be rejected with 400."""
    assert client.get("/api/history?limit=0").status_code == 400
    assert client.get("/api/history?limit=9999").status_code == 400


# ---------------------------------------------------------------------------
# /api/report/{scan_id}
# ---------------------------------------------------------------------------

def test_report_not_found(client):
    """Requesting a non-existent scan ID should 404."""
    response = client.get("/api/report/9999")
    assert response.status_code == 404


def test_report_returns_findings_for_existing_scan(client):
    """A valid scan ID should return that scan's findings list (possibly empty)."""
    scan_response = client.post(
        "/api/scan",
        files={"file": ("x.evtx", b"", "application/octet-stream")},
    )
    scan_id = scan_response.json()["scan_id"]

    response = client.get(f"/api/report/{scan_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == scan_id
    assert "findings" in body
    assert isinstance(body["findings"], list)


# ---------------------------------------------------------------------------
# Temp file cleanup
# ---------------------------------------------------------------------------

def test_scan_cleans_up_temp_file(client):
    """The temp file created during /api/scan should not linger on disk afterwards."""
    tmp_dir_before = set(os.listdir(tempfile.gettempdir()))
    client.post("/api/scan", files={"file": ("x.evtx", b"", "application/octet-stream")})
    tmp_dir_after = set(os.listdir(tempfile.gettempdir()))

    # No new .evtx temp files left behind.
    new_files = tmp_dir_after - tmp_dir_before
    leftover_evtx = [f for f in new_files if f.endswith(".evtx")]
    assert leftover_evtx == []


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def test_dashboard_returns_html(client):
    """The root route should serve the web dashboard as HTML."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "PULSE" in response.text
