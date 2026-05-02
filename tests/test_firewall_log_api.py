# test_firewall_log_api.py
# ------------------------
# Sprint 6 polish — Firewall Rules tab. Exercises both endpoints:
#   GET  /api/firewall/log?path=...   — admin-only, parses on-disk log
#   POST /api/firewall/log            — admin-only, parses uploaded log
# Plus the response shape consumers depend on (summary + suspicious +
# entries with the W3C-derived field names mapped to camel/snake-cased
# JSON keys).

import io
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app


HEADER = (
    "#Version: 1.5\n"
    "#Software: Microsoft Windows Firewall\n"
    "#Time Format: Local\n"
    "#Fields: date time action protocol src-ip dst-ip src-port dst-port size "
    "tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid\n"
    "\n"
)

# Mix of one ALLOW row and several DROPs — enough volume from one
# public source to trigger the repeated-drops rule in run_firewall_detections.
SAMPLE_LINES = [
    "2026-04-30 10:00:00 ALLOW UDP 192.168.1.10 8.8.8.8 53000 53 0 - 0 0 0 0 0 0 - - 0",
] + [
    f"2026-04-30 10:01:{i:02d} DROP TCP 1.2.3.4 192.168.1.10 4444 {1000 + i} 0 - 0 0 0 0 0 0 - - 0"
    for i in range(15)
]


def _write_log():
    fd, path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(HEADER)
        for ln in SAMPLE_LINES:
            fh.write(ln + "\n")
    return path


@pytest.fixture
def fw_client(tmp_path):
    db = tmp_path / "test.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db), config_path=str(cfg))
    c = TestClient(app)
    c.post("/api/auth/signup", json={
        "email": "admin@example.com",
        "password": "correct-horse-battery",
    })
    return c


def test_get_returns_payload_shape(fw_client):
    log = _write_log()
    try:
        body = fw_client.get(f"/api/firewall/log?path={log}").json()
        assert body["available"] is True
        # Summary derived from the parsed rows.
        assert body["summary"]["total"]   == 16
        assert body["summary"]["allowed"] == 1
        assert body["summary"]["dropped"] == 15
        assert body["summary"]["unique_sources"] == 2
        # Entries are returned newest-first and capped at the server-side
        # limit. With only 16 rows we get all of them.
        assert len(body["entries"]) == 16
        first = body["entries"][0]
        for key in ("ts", "action", "protocol", "src_ip", "dst_ip",
                    "src_port", "dst_port", "size"):
            assert key in first
        # Suspicious activity should include the repeated-drops finding
        # because 15 DROPs > 10 threshold from one public source.
        rules = {f["rule"] for f in body["suspicious"]}
        assert "Firewall Repeated Drops" in rules
    finally:
        os.remove(log)


def test_get_returns_unavailable_for_missing_path(fw_client):
    body = fw_client.get("/api/firewall/log?path=/no/such/log.txt").json()
    assert body["available"] is False
    assert body["entries"] == []
    assert body["summary"]["total"] == 0


def test_get_requires_admin(fw_client, tmp_path):
    log = _write_log()
    try:
        # Add a viewer; switch to that account.
        fw_client.post("/api/users", json={
            "email": "viewer@example.com",
            "password": "another-long-password",
            "role": "viewer",
        })
        fw_client.post("/api/auth/logout")
        fw_client.post("/api/auth/login", json={
            "email": "viewer@example.com",
            "password": "another-long-password",
        })
        r = fw_client.get(f"/api/firewall/log?path={log}")
        assert r.status_code == 403
    finally:
        os.remove(log)


def test_post_upload_parses_and_returns_payload(fw_client):
    body_bytes = HEADER.encode("utf-8") + ("\n".join(SAMPLE_LINES) + "\n").encode("utf-8")
    files = {"file": ("pfirewall.log", io.BytesIO(body_bytes), "text/plain")}
    body = fw_client.post("/api/firewall/log", files=files).json()
    assert body["available"] is True
    assert body["source"] == "upload"
    assert body["summary"]["total"] == 16
    assert body["summary"]["dropped"] == 15
    # Filename round-trips as the "path" field on upload.
    assert body["path"] == "pfirewall.log"


def test_post_upload_rejects_huge_file(fw_client):
    # Backend caps at 50MB; send 51MB to ensure the cap fires.
    big = b"x" * (51 * 1024 * 1024)
    files = {"file": ("huge.log", io.BytesIO(big), "text/plain")}
    r = fw_client.post("/api/firewall/log", files=files)
    assert r.status_code == 413


# ---------------------------------------------------------------------------
# Bundled `tests/sample-pfirewall.log` end-to-end. Same fixture the parser
# tests use, but driven through the API so we catch any regressions in the
# response shape mapping (e.g. dst-port -> dst_port, _ts -> ts) plus the
# admin auth gate working alongside real detection output.
# ---------------------------------------------------------------------------

SAMPLE_LOG = os.path.join(os.path.dirname(__file__), "sample-pfirewall.log")


def test_get_with_sample_fixture_returns_real_findings(fw_client):
    """All three firewall rules co-fire on the sample log, summary
    counts match the fixture's hand-counted shape, and the entries
    array carries the parsed rows newest-first."""
    body = fw_client.get(f"/api/firewall/log?path={SAMPLE_LOG}").json()
    assert body["available"] is True
    assert body["summary"] == {
        "total": 97, "allowed": 35, "dropped": 62, "unique_sources": 16,
    }
    rules = {f["rule"] for f in body["suspicious"]}
    assert "Firewall Blocked Sensitive Port" in rules
    assert "Firewall Port Scan"               in rules
    assert "Firewall Repeated Drops"          in rules
    # Newest-first ordering — the last row in the file should be first
    # in the response.
    first = body["entries"][0]
    assert first["action"] == "DROP"
    assert first["src_ip"] == "45.33.32.156"


def test_post_upload_with_sample_fixture(fw_client):
    """Upload path mirrors the GET path's parsing exactly."""
    with open(SAMPLE_LOG, "rb") as fh:
        files = {"file": ("sample-pfirewall.log", fh, "text/plain")}
        body = fw_client.post("/api/firewall/log", files=files).json()
    assert body["available"] is True
    assert body["source"] == "upload"
    assert body["summary"]["total"] == 97
    rules = {f["rule"] for f in body["suspicious"]}
    assert "Firewall Port Scan" in rules
