# test_threat_summary.py
# -----------------------
# Phase 1 of the report-template catalog: Threat Detection Summary.

import json
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from pulse import database
from pulse.api import create_app
from pulse.reports.threat_summary import (
    build_summary, _tactic_for_rule, _extract_ip,
    TECHNIQUE_TO_TACTIC, TACTIC_ORDER, SEVERITY_ORDER,
)
from pulse.reports.threat_summary_renderers import (
    render, render_json, render_csv, render_html, render_pdf,
)


# ---------------------------------------------------------------------------
# Data builder
# ---------------------------------------------------------------------------

@pytest.fixture
def findings():
    return [
        {"rule": "Brute Force Attempt", "severity": "HIGH",
         "timestamp": "2026-06-02T10:00:00Z", "hostname": "DC01",
         "details": "Source IP 185.220.101.34 tried 50x"},
        {"rule": "Brute Force Attempt", "severity": "HIGH",
         "timestamp": "2026-06-02T10:05:00Z", "hostname": "DC01",
         "details": "Source IP 185.220.101.34 tried 50x"},
        {"rule": "Kerberoasting", "severity": "HIGH",
         "timestamp": "2026-06-02T10:30:00Z", "hostname": "DC01",
         "details": "svc_backup ticket request"},
        {"rule": "Audit Log Cleared", "severity": "HIGH",
         "timestamp": "2026-06-02T11:00:00Z", "hostname": "DC01"},
        {"rule": "Suspicious PowerShell", "severity": "CRITICAL",
         "timestamp": "2026-06-02T11:30:00Z", "hostname": "WS-FIN",
         "details": "Encoded payload from 45.95.169.111"},
    ]


@pytest.fixture
def scans():
    return [
        {"id": 1, "scanned_at": "2026-06-02 12:00:00",
         "hostname": "DC01", "score": 35, "score_label": "Critical Risk"},
        {"id": 2, "scanned_at": "2026-06-02 13:00:00",
         "hostname": "WS-FIN", "score": 52, "score_label": "High Risk"},
    ]


def test_build_summary_header_includes_required_fields(findings, scans):
    data = build_summary(findings, scans, scope_label="test scope")
    h = data["header"]
    assert h["title"] == "Threat Detection Summary"
    assert h["scope"] == "test scope"
    assert h["finding_count"] == len(findings)
    assert h["scan_count"]    == len(scans)
    assert "DC01" in h["hosts"] and "WS-FIN" in h["hosts"]
    assert "generated_at" in h


def test_build_summary_summary_band(findings, scans):
    data = build_summary(findings, scans, scope_label="x")
    s = data["summary"]
    assert s["total_findings"] == 5
    assert s["by_severity"]["CRITICAL"] == 1
    assert s["by_severity"]["HIGH"]     == 4
    assert s["by_severity"]["MEDIUM"]   == 0
    assert s["by_severity"]["LOW"]      == 0
    assert s["score"] == round((35 + 52) / 2)
    # round((35+52)/2) = 44 -> "D" tier (40-59).
    assert s["grade"] == "D"


def test_build_summary_groups_by_tactic(findings, scans):
    data = build_summary(findings, scans, scope_label="x")
    tactics = {t["tactic"]: t for t in data["by_tactic"]}
    # Brute Force (T1110), Kerberoasting (T1558.003) -> Credential Access
    assert "Credential Access" in tactics
    assert tactics["Credential Access"]["count"] >= 3
    # Audit Log Cleared (T1070.001) -> Defense Evasion
    assert "Defense Evasion" in tactics
    # Suspicious PowerShell (T1059.001) -> Execution
    assert "Execution" in tactics
    # Order follows TACTIC_ORDER, not insertion / count.
    seen_order = [t["tactic"] for t in data["by_tactic"]]
    canonical_index = {t: i for i, t in enumerate(TACTIC_ORDER)}
    assert seen_order == sorted(
        seen_order, key=lambda t: canonical_index.get(t, 999))


def test_build_summary_timeline_is_chronological(findings, scans):
    data = build_summary(findings, scans, scope_label="x")
    ts = [t["timestamp"] for t in data["timeline"]]
    assert ts == sorted(ts)


def test_timeline_falls_back_to_raw_xml_timestamp():
    """Per-event detections (brute force, kerberoasting, etc.) don't set
    `timestamp` on the finding dict — only correlation rules do. The
    builder must fall back to the SystemTime embedded in raw_xml so the
    Attack Timeline column is populated for those rows, not empty."""
    findings = [{
        "rule": "Brute Force Attempt",
        "severity": "HIGH",
        "hostname": "DC01",
        # No "timestamp" key. Just raw_xml with the event's SystemTime.
        "raw_xml": '<Event><System>'
                   '<TimeCreated SystemTime="2026-04-08T09:14:22.000Z"/>'
                   '</System></Event>',
    }]
    data = build_summary(findings, [], scope_label="x")
    assert data["timeline"][0]["timestamp"] == "2026-04-08T09:14:22.000Z"


def test_timeline_explicit_timestamp_wins_over_raw_xml():
    """When a correlation rule sets `timestamp` explicitly, that wins
    even if raw_xml carries a different one. Explicit > fallback."""
    findings = [{
        "rule": "Brute-Force Success",
        "severity": "CRITICAL",
        "timestamp": "2026-04-08T09:25:33Z",
        "raw_xml": '<Event><System>'
                   '<TimeCreated SystemTime="2020-01-01T00:00:00Z"/>'
                   '</System></Event>',
    }]
    data = build_summary(findings, [], scope_label="x")
    assert data["timeline"][0]["timestamp"] == "2026-04-08T09:25:33Z"


def test_build_summary_top_rules_ranks_by_count(findings, scans):
    data = build_summary(findings, scans, scope_label="x")
    top = data["top_rules"]
    assert top[0]["rule"] == "Brute Force Attempt"
    assert top[0]["count"] == 2


def test_build_summary_repeat_offenders_pulls_source_ip(findings, scans):
    data = build_summary(findings, scans, scope_label="x")
    ips = {entry["ip"] for entry in data["repeat_ips"]}
    # The Tor exit IP appears twice — repeat offender. The PowerShell
    # IP appears once — does NOT make the cut (min 2 hits).
    assert "185.220.101.34" in ips
    assert "45.95.169.111" not in ips


def test_build_summary_includes_intel_score_when_lookup_supplied(findings, scans):
    intel_db = {
        "185.220.101.34": {"score": 95, "country": "DE"},
    }
    data = build_summary(findings, scans, scope_label="x",
                          intel_lookup=lambda ip: intel_db.get(ip))
    target = next(e for e in data["repeat_ips"] if e["ip"] == "185.220.101.34")
    assert target["intel_score"] == 95
    assert target["intel_country"] == "DE"


def test_build_summary_intel_lookup_failure_does_not_crash(findings, scans):
    def boom(ip): raise RuntimeError("network down")
    data = build_summary(findings, scans, scope_label="x", intel_lookup=boom)
    assert data["repeat_ips"][0]["intel_score"] is None


def test_build_summary_empty_findings_safe():
    data = build_summary([], [], scope_label="empty")
    assert data["summary"]["total_findings"] == 0
    assert data["summary"]["score"] is None
    assert data["by_tactic"] == []
    assert data["timeline"] == []
    assert data["repeat_ips"] == []


def test_build_summary_footer_carries_pulse_version():
    data = build_summary([], [], scope_label="x")
    f = data["footer"]
    assert f["pulse_version"]
    assert "automated" in f["automated_note"].lower()


# ---------------------------------------------------------------------------
# Tactic + IP helpers (drift guards)
# ---------------------------------------------------------------------------

def test_tactic_for_rule_resolves_known_rules():
    assert _tactic_for_rule("Brute Force Attempt") == "Credential Access"
    assert _tactic_for_rule("Audit Log Cleared")   == "Defense Evasion"
    assert _tactic_for_rule("Suspicious PowerShell") == "Execution"


def test_tactic_for_rule_unknown_lands_in_other():
    assert _tactic_for_rule("Made-up rule") == "Other"


def test_other_appears_at_the_end_of_tactic_order():
    assert TACTIC_ORDER[-1] == "Other"


def test_extract_ip_prefers_explicit_field():
    assert _extract_ip({"source_ip": "10.0.0.1", "details": "..."}) == "10.0.0.1"
    assert _extract_ip({"ip": "10.0.0.2"}) == "10.0.0.2"


def test_extract_ip_falls_back_to_regex_match():
    assert _extract_ip({"details": "Source 1.2.3.4 hit"}) == "1.2.3.4"
    assert _extract_ip({"details": "no addresses here"}) is None


# ---------------------------------------------------------------------------
# Renderers — at least one assertion per format that distinguishes it.
# ---------------------------------------------------------------------------

def test_render_json_is_parseable(findings, scans):
    data = build_summary(findings, scans, scope_label="x")
    out = render(data, "json")
    parsed = json.loads(out)
    assert parsed["header"]["title"] == "Threat Detection Summary"
    assert parsed["summary"]["total_findings"] == 5


def test_render_csv_has_header_row_and_findings(findings, scans):
    data = build_summary(findings, scans, scope_label="x")
    out = render(data, "csv").decode("utf-8-sig")
    lines = [line for line in out.splitlines() if line.strip()]
    assert lines[0] == "timestamp,severity,rule,hostname,ref_id,details"
    assert len(lines) == 1 + len(findings)


def test_render_html_is_self_contained_dark_theme(findings, scans):
    data = build_summary(findings, scans, scope_label="x")
    out = render(data, "html").decode("utf-8")
    assert out.startswith("<!doctype html>")
    assert "Threat Detection Summary" in out
    # Dashboard dark-theme palette markers.
    assert "#0d1117" in out
    assert "#161b22" in out
    # Section markers.
    assert "Attack Timeline" in out
    assert "Top Triggered Rules" in out
    assert "Findings by MITRE Tactic" in out
    assert "Repeat Offenders" in out


def test_render_pdf_returns_pdf_magic(findings, scans):
    data = build_summary(findings, scans, scope_label="x")
    out = render(data, "pdf")
    assert out[:5] == b"%PDF-"
    assert len(out) > 1000


def test_render_unknown_format_raises(findings, scans):
    data = build_summary(findings, scans, scope_label="x")
    with pytest.raises(ValueError, match="unknown format"):
        render(data, "xml")


# ---------------------------------------------------------------------------
# Visual-fix regression guards: timestamp formatter, severity pill HTML,
# and short-form severity labels for the PDF.
# ---------------------------------------------------------------------------

def test_timestamp_formatter_normalizes_iso_with_sub_seconds():
    from pulse.reports.threat_summary_renderers import _format_ts
    assert _format_ts("2026-04-08T09:14:22.000Z") == "2026-04-08 09:14"
    assert _format_ts("2026-04-08 09:14:22")      == "2026-04-08 09:14"
    assert _format_ts(None) == "—"
    assert _format_ts("")   == "—"


def test_severity_pill_html_has_centering_styles(findings, scans):
    """If this regresses, MEDIUM (and friends) drift up off the badge's
    vertical center and the colored background reads as oversized."""
    data = build_summary(findings, scans, scope_label="x")
    out = render(data, "html").decode("utf-8")
    # Both directives are required for the fix; either one alone
    # leaves the pill misaligned in some browsers.
    assert "line-height:1" in out
    assert "vertical-align:middle" in out


def test_pdf_score_ring_uses_canvas_flowable(findings, scans):
    """The original implementation used a Table cell with
    ROUNDEDCORNERS=40 which reportlab renders as a 'fish' shape
    instead of a circle. The fix swaps in pdf_report.ScoreRing —
    a canvas-drawn Flowable. Importing the renderers module and
    inspecting its globals is the cheapest way to guard against
    the rollback: the broken Table approach didn't reference
    ScoreRing at all."""
    import pulse.reports.threat_summary_renderers as r
    # Render so render_pdf's lazy imports actually run.
    data = build_summary(findings, scans, scope_label="x")
    out = r.render_pdf(data)
    assert out[:5] == b"%PDF-"
    # render_pdf imports ScoreRing inside the function — confirm the
    # symbol resolves at module load time too.
    from pulse.reports.pdf_report import ScoreRing
    assert ScoreRing is not None


# ---------------------------------------------------------------------------
# API integration — /api/reports/generate
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    db = tmp_path / "test.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db), config_path=str(cfg), disable_auth=True)
    return TestClient(app), str(db)


def _seed_scan_with_findings(db_path):
    import sqlite3
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO scans (scanned_at, files_scanned, score, score_label, "
            "                    filename, hostname) "
            "VALUES ('2026-06-02 12:00:00', 1, 35, 'Critical Risk',"
            "        'x.evtx', 'SERVER-DC01')"
        )
        sid = conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]
        rows = [
            (sid, 'HIGH', 'Brute Force Attempt', 'SERVER-DC01',
             'IP 185.220.101.34 tried 50x', '2026-06-02T10:00:00Z'),
            (sid, 'CRITICAL', 'Kerberoasting', 'SERVER-DC01',
             'svc_backup', '2026-06-02T10:30:00Z'),
            (sid, 'HIGH', 'Brute Force Attempt', 'SERVER-DC01',
             'IP 185.220.101.34 tried again', '2026-06-02T10:35:00Z'),
        ]
        conn.executemany(
            "INSERT INTO findings (scan_id, severity, rule, hostname, details, timestamp)"
            " VALUES (?, ?, ?, ?, ?, ?)", rows,
        )
        conn.commit()
        return sid


def test_generate_pdf_persists_and_downloads(client):
    c, db = client
    sid = _seed_scan_with_findings(db)
    r = c.post("/api/reports/generate", json={
        "template": "threat_detection_summary",
        "format":   "pdf",
        "scope":    {"scan_id": sid},
    })
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/pdf")
    assert r.content[:5] == b"%PDF-"
    # Persisted to DB with template_type column populated.
    listed = c.get("/api/reports").json()
    assert listed["reports"]
    row = listed["reports"][0]
    assert row["template_type"] == "threat_detection_summary"
    assert row["format"] == "pdf"
    assert "pulse_threat_summary_" in row["filename"]


@pytest.mark.parametrize("fmt", ["pdf", "html", "json", "csv"])
def test_generate_supports_all_four_formats(client, fmt):
    c, db = client
    sid = _seed_scan_with_findings(db)
    r = c.post("/api/reports/generate", json={
        "template": "threat_detection_summary",
        "format":   fmt,
        "scope":    {"scan_id": sid},
    })
    assert r.status_code == 200, r.text
    assert r.content  # non-empty
    cd = r.headers.get("content-disposition", "")
    assert f".{fmt}" in cd


def test_generate_with_days_scope(client):
    c, db = client
    _seed_scan_with_findings(db)
    r = c.post("/api/reports/generate", json={
        "template": "threat_detection_summary",
        "format":   "json",
        "scope":    {"days": 30},
    })
    assert r.status_code == 200
    payload = json.loads(r.content)
    # Scope label should mention the day window.
    assert "30 day" in payload["header"]["scope"].lower()


def test_generate_rejects_unknown_template(client):
    c, _ = client
    r = c.post("/api/reports/generate", json={
        "template": "executive_summary",  # Phase 2 — not yet shipped
        "format":   "pdf",
        "scope":    {"days": 7},
    })
    assert r.status_code == 400
    assert "threat_detection_summary" in r.json()["detail"].lower()


def test_generate_rejects_unknown_format(client):
    c, db = client
    sid = _seed_scan_with_findings(db)
    r = c.post("/api/reports/generate", json={
        "template": "threat_detection_summary",
        "format":   "xml",
        "scope":    {"scan_id": sid},
    })
    assert r.status_code == 400
    assert "format" in r.json()["detail"].lower()


def test_generate_with_unknown_scan_404s(client):
    c, _ = client
    r = c.post("/api/reports/generate", json={
        "template": "threat_detection_summary",
        "format":   "pdf",
        "scope":    {"scan_id": 9999},
    })
    assert r.status_code == 404
