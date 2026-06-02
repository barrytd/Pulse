# test_incident_report.py
# ------------------------
# Phase 4 of the report-template catalog: Incident Investigation Report.

import json

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app
from pulse.reports.incident import (
    build_incident, _finding_sha256, _manifest_sha256,
    _executive_line, _extract_ip, _extract_user,
)
from pulse.reports.incident_renderers import render


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def findings():
    return [
        {
            "id": 101, "ref_id": "BFA-0101",
            "rule": "Brute Force Attempt", "severity": "HIGH",
            "hostname": "DC01",
            "timestamp": "2026-06-02T10:00:00Z",
            "raw_xml": '<Event><System>'
                        '<TimeCreated SystemTime="2026-06-02T10:00:00Z"/>'
                        '</System><EventData>'
                        '<Data Name="IpAddress">185.220.101.34</Data>'
                        '<Data Name="TargetUserName">admin</Data>'
                        '</EventData></Event>',
        },
        {
            "id": 102, "ref_id": "KER-0102",
            "rule": "Kerberoasting", "severity": "CRITICAL",
            "hostname": "DC01",
            "timestamp": "2026-06-02T10:15:00Z",
            "raw_xml": "<Event>...</Event>",
        },
        {
            "id": 103, "ref_id": "RDP-0103",
            "rule": "RDP Logon Detected", "severity": "MEDIUM",
            "hostname": "WS-FIN",
            "timestamp": "2026-06-02T11:00:00Z",
            "raw_xml": "<Event>...</Event>",
        },
    ]


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def test_extract_ip_from_raw_xml():
    f = {"raw_xml": '<Data Name="IpAddress">10.1.2.3</Data>'}
    assert _extract_ip(f) == "10.1.2.3"


def test_extract_user_from_raw_xml():
    f = {"raw_xml": '<Data Name="TargetUserName">jbloggs</Data>'}
    assert _extract_user(f) == "jbloggs"


def test_extract_ip_filters_loopback():
    f = {"raw_xml": '<Data Name="IpAddress">127.0.0.1</Data>'}
    assert _extract_ip(f) is None


def test_extract_user_filters_anonymous():
    f = {"raw_xml": '<Data Name="TargetUserName">ANONYMOUS LOGON</Data>'}
    assert _extract_user(f) is None


# ---------------------------------------------------------------------------
# Builder shape
# ---------------------------------------------------------------------------

def test_build_incident_header(findings):
    data = build_incident(findings, host="DC01",
                           investigator_email="r@x.com",
                           investigator_name="Robert",
                           org_name="Acme")
    h = data["header"]
    assert h["title"] == "Incident Investigation Report"
    assert h["host"] == "DC01"
    assert h["scope"] == "All unresolved findings on DC01"
    assert h["investigator"] == "Robert"
    assert h["investigator_email"] == "r@x.com"
    assert data["header"]["finding_count"] == 3


def test_build_incident_executive_line_handles_critical(findings):
    data = build_incident(findings, host="DC01")
    line = data["executive_line"]
    assert "critical" in line.lower()
    assert "active until contained" in line.lower()


def test_build_incident_executive_line_no_findings():
    data = build_incident([], host="DC01")
    assert "No findings in scope" in data["executive_line"]


def test_build_incident_affected_assets(findings):
    data = build_incident(findings, host="DC01")
    a = data["affected_assets"]
    assert "DC01" in a["hosts"] and "WS-FIN" in a["hosts"]
    assert "admin" in a["accounts"]
    assert "185.220.101.34" in a["ips"]


def test_build_incident_timeline_is_chronological(findings):
    data = build_incident(findings, host="DC01")
    ts = [t["timestamp"] for t in data["timeline"]]
    assert ts == sorted(ts)


def test_build_incident_per_finding_decoration(findings):
    data = build_incident(findings, host="DC01")
    f0 = data["findings"][0]
    assert f0["rule"] == "Brute Force Attempt"
    assert f0["source_ip"] == "185.220.101.34"
    assert f0["account"] == "admin"
    assert f0["sha256"]
    assert len(f0["sha256"]) == 64  # SHA-256 hex


def test_build_incident_intel_lookup_called(findings):
    seen = []
    def lookup(ip):
        seen.append(ip)
        return {"score": 95, "country": "DE", "isp": "Tor"}
    data = build_incident(findings, host="DC01", intel_lookup=lookup)
    assert "185.220.101.34" in seen
    intel_finding = next(f for f in data["findings"]
                          if f["source_ip"] == "185.220.101.34")
    assert intel_finding["intel"] == {
        "score": 95, "country": "DE", "isp": "Tor",
    }


def test_build_incident_intel_failure_is_swallowed(findings):
    def boom(ip):
        raise RuntimeError("network down")
    data = build_incident(findings, host="DC01", intel_lookup=boom)
    # Build still completes; affected finding has no intel decoration.
    intel_finding = next(f for f in data["findings"]
                          if f["source_ip"] == "185.220.101.34")
    assert intel_finding["intel"] is None


def test_build_incident_note_lookup_decoration(findings):
    def notes(fid):
        if fid == 101:
            return [{"author_email": "p@x.com",
                     "created_at": "2026-06-02 12:00:00",
                     "body": "Investigating now."}]
        return []
    data = build_incident(findings, host="DC01", note_lookup=notes)
    f0 = next(f for f in data["findings"] if f["id"] == 101)
    assert len(f0["notes"]) == 1
    assert f0["notes"][0]["body"] == "Investigating now."


def test_build_incident_pulls_blocks_for_affected_ips(findings):
    def blocks():
        return [
            {"ip_address": "185.220.101.34", "status": "active",
             "pushed_at": "2026-06-02 11:00:00", "comment": "Tor exit"},
            {"ip_address": "10.0.0.99", "status": "active",
             "pushed_at": "2026-06-02 11:00:00", "comment": "unrelated"},
        ]
    data = build_incident(findings, host="DC01", block_lookup=blocks)
    assert len(data["blocks_pushed"]) == 1
    assert data["blocks_pushed"][0]["ip"] == "185.220.101.34"


def test_build_incident_finding_ids_scope_label(findings):
    data = build_incident(findings, finding_ids=[101, 102, 103])
    assert "3 hand-selected" in data["header"]["scope"]


# ---------------------------------------------------------------------------
# Chain of custody
# ---------------------------------------------------------------------------

def test_finding_sha256_is_deterministic(findings):
    h1 = _finding_sha256(findings[0])
    h2 = _finding_sha256(findings[0])
    assert h1 == h2
    assert len(h1) == 64


def test_finding_sha256_changes_when_raw_xml_changes(findings):
    h1 = _finding_sha256(findings[0])
    mutated = dict(findings[0])
    mutated["raw_xml"] = mutated["raw_xml"].replace("admin", "compromised_user")
    h2 = _finding_sha256(mutated)
    assert h1 != h2


def test_manifest_sha256_changes_when_membership_changes(findings):
    data1 = build_incident(findings[:2], host="DC01")
    data2 = build_incident(findings, host="DC01")
    sha1 = data1["chain_of_custody"]["report_sha256"]
    sha2 = data2["chain_of_custody"]["report_sha256"]
    assert sha1 != sha2


def test_chain_of_custody_manifest_lists_all_findings(findings):
    data = build_incident(findings, host="DC01")
    manifest = data["chain_of_custody"]["manifest"]
    assert len(manifest) == len(findings)
    for row in manifest:
        assert len(row["sha256"]) == 64


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def test_render_json_round_trips(findings):
    data = build_incident(findings, host="DC01")
    parsed = json.loads(render(data, "json"))
    assert parsed["chain_of_custody"]["report_sha256"] == \
        data["chain_of_custody"]["report_sha256"]


def test_render_csv_has_sha256_column(findings):
    data = build_incident(findings, host="DC01")
    out = render(data, "csv").decode("utf-8-sig")
    assert "sha256" in out.splitlines()[0]
    # Per-finding hashes appear in the rows.
    assert data["findings"][0]["sha256"] in out


def test_render_html_includes_required_sections(findings):
    data = build_incident(findings, host="DC01")
    out = render(data, "html").decode("utf-8")
    for label in ("Affected Assets", "Detailed Timeline",
                  "Per-Finding Deep Dive", "Chain of Custody"):
        assert label in out
    assert "SHA-256" in out
    assert data["chain_of_custody"]["report_sha256"] in out


def test_render_pdf_returns_pdf_magic(findings):
    data = build_incident(findings, host="DC01")
    out = render(data, "pdf")
    assert out[:5] == b"%PDF-"


def test_render_unknown_format_raises(findings):
    data = build_incident(findings, host="DC01")
    with pytest.raises(ValueError, match="unknown format"):
        render(data, "xml")


# ---------------------------------------------------------------------------
# API integration
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    db = tmp_path / "test.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db), config_path=str(cfg),
                      disable_auth=True)
    return TestClient(app), str(db)


def _seed(db_path):
    from datetime import datetime
    import sqlite3
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO scans (scanned_at, files_scanned, score, score_label, "
            "                    filename, hostname) "
            "VALUES (?, 1, 35, 'Critical', 'x.evtx', 'DC01')",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
        )
        sid = conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]
        rows = [
            (sid, 'HIGH', 'Brute Force Attempt', 'DC01',
             'attempt', '2026-06-02T10:00:00Z',
             '<Event><EventData>'
             '<Data Name="IpAddress">185.220.101.34</Data>'
             '</EventData></Event>'),
            (sid, 'CRITICAL', 'Kerberoasting', 'DC01',
             'krb', '2026-06-02T10:15:00Z', '<Event/>'),
        ]
        conn.executemany(
            "INSERT INTO findings "
            "(scan_id, severity, rule, hostname, details, timestamp, raw_xml) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)", rows,
        )
        conn.commit()
        return sid


@pytest.mark.parametrize("fmt", ["pdf", "html", "json", "csv"])
def test_generate_incident_by_host(client, fmt):
    c, db = client
    _seed(db)
    r = c.post("/api/reports/generate", json={
        "template": "incident_investigation",
        "format":   fmt,
        "scope":    {"host": "DC01"},
    })
    assert r.status_code == 200, r.text
    assert r.content
    cd = r.headers.get("content-disposition", "")
    assert "pulse_incident_" in cd
    assert f".{fmt}" in cd


def test_generate_incident_by_finding_ids(client):
    c, db = client
    _seed(db)
    import sqlite3
    with sqlite3.connect(db) as conn:
        ids = [row[0] for row in
                conn.execute("SELECT id FROM findings ORDER BY id").fetchall()]
    r = c.post("/api/reports/generate", json={
        "template": "incident_investigation",
        "format":   "json",
        "scope":    {"finding_ids": ids},
    })
    assert r.status_code == 200
    payload = json.loads(r.content)
    assert payload["header"]["finding_count"] == len(ids)


def test_generate_incident_rejects_missing_scope(client):
    c, _ = client
    r = c.post("/api/reports/generate", json={
        "template": "incident_investigation",
        "format":   "pdf",
        "scope":    {},
    })
    assert r.status_code == 400
    assert "host" in r.json()["detail"].lower()


def test_generate_incident_persists_with_template_type(client):
    c, db = client
    _seed(db)
    c.post("/api/reports/generate", json={
        "template": "incident_investigation",
        "format":   "json",
        "scope":    {"host": "DC01"},
    })
    rows = c.get("/api/reports").json()["reports"]
    assert any(r.get("template_type") == "incident_investigation"
                for r in rows)
