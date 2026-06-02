# test_phase5_reports.py
# -----------------------
# Phase 5 of the report-template catalog: Fleet Health, Board-Ready
# Posture, MITRE ATT&CK Coverage, Compliance Gap Analysis.

import json

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app
from pulse.reports.fleet_health import build_fleet_health
from pulse.reports.board_ready import build_board_ready
from pulse.reports.mitre_coverage import build_mitre_coverage
from pulse.reports.compliance_gap import build_compliance_gap
from pulse.reports.phase5_renderers import (
    render_fleet_health, render_board_ready,
    render_mitre_coverage, render_compliance_gap,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fleet_rows():
    return [
        {"hostname": "DC01", "latest_score": 35, "latest_grade": "F",
         "worst_severity": "CRITICAL", "scan_count": 5,
         "total_findings": 12, "last_scan_at": "2026-06-02 12:00:00"},
        {"hostname": "WS-FIN", "latest_score": 82, "latest_grade": "B",
         "worst_severity": "LOW", "scan_count": 3,
         "total_findings": 1, "last_scan_at": "2026-06-02 11:00:00"},
        {"hostname": "OLD-PC", "latest_score": 60, "latest_grade": "C",
         "worst_severity": "MEDIUM", "scan_count": 1,
         "total_findings": 2, "last_scan_at": "2026-05-15 09:00:00"},
    ]


@pytest.fixture
def findings():
    return [
        {"rule": "Brute Force Attempt", "severity": "HIGH",
         "hostname": "DC01"},
        {"rule": "Brute Force Attempt", "severity": "HIGH",
         "hostname": "DC01"},
        {"rule": "Kerberoasting", "severity": "CRITICAL",
         "hostname": "DC01"},
    ]


@pytest.fixture
def scans():
    return [
        {"id": 1, "hostname": "DC01", "score": 35,
         "scanned_at": "2026-06-02 12:00:00"},
        {"id": 2, "hostname": "WS-FIN", "score": 82,
         "scanned_at": "2026-06-02 11:00:00"},
    ]


# ---------------------------------------------------------------------------
# Fleet Health
# ---------------------------------------------------------------------------

def test_fleet_health_tiers_and_ranking(fleet_rows):
    data = build_fleet_health(fleet_rows, org_name="Acme", stale_days=7)
    s = data["summary"]
    assert s["total_hosts"] == 3
    assert s["healthy"] == 1
    assert s["critical"] == 1
    # OLD-PC: score 60 → "Moderate"
    assert s["moderate"] == 1
    # Stale list: OLD-PC's last scan was > 7 days ago.
    assert s["stale_count"] == 1
    assert any(r["hostname"] == "OLD-PC" for r in data["stale_hosts"])


def test_fleet_health_at_risk_includes_critical_and_d(fleet_rows):
    data = build_fleet_health(fleet_rows)
    at_risk_hosts = [r["hostname"] for r in data["at_risk_hosts"]]
    assert "DC01" in at_risk_hosts
    assert "WS-FIN" not in at_risk_hosts


def test_fleet_health_disable_stale_section(fleet_rows):
    data = build_fleet_health(fleet_rows, stale_days=None)
    assert data["summary"]["stale_count"] == 0
    assert data["stale_hosts"] == []


@pytest.mark.parametrize("fmt", ["json", "csv", "html", "pdf"])
def test_render_fleet_health_all_formats(fleet_rows, fmt):
    data = build_fleet_health(fleet_rows)
    out = render_fleet_health(data, fmt)
    assert out
    if fmt == "json":
        assert json.loads(out)["header"]["title"] == "Fleet Health Report"
    elif fmt == "pdf":
        assert out[:5] == b"%PDF-"
    elif fmt == "html":
        assert b"All Monitored Hosts" in out


# ---------------------------------------------------------------------------
# Board-Ready Posture
# ---------------------------------------------------------------------------

def test_board_ready_posture_includes_fleet_and_compliance(
        findings, scans, fleet_rows):
    data = build_board_ready(findings, scans, fleet_rows=fleet_rows,
                               period_days=30, org_name="Acme")
    assert data["fleet_summary"]["total_hosts"] == 3
    assert "nist_csf" in data["compliance"]
    assert "iso_27001" in data["compliance"]
    assert data["compliance"]["nist_csf"]["coverage_percent"] >= 0


def test_board_ready_trend_points_are_chronological(findings, scans,
                                                       fleet_rows):
    data = build_board_ready(findings, scans, fleet_rows=fleet_rows,
                               period_days=30)
    tps = [tp["timestamp"] for tp in data["trend_points"]]
    assert tps == sorted(tps)


def test_board_ready_recommendations_reflect_at_risk(fleet_rows, findings,
                                                       scans):
    data = build_board_ready(findings, scans, fleet_rows=fleet_rows,
                               period_days=30)
    joined = " ".join(data["recommendations"]).lower()
    assert ("at-risk" in joined or "stale" in joined or
            "coverage" in joined)


@pytest.mark.parametrize("fmt", ["json", "csv", "html", "pdf"])
def test_render_board_ready_all_formats(findings, scans, fleet_rows, fmt):
    data = build_board_ready(findings, scans, fleet_rows=fleet_rows,
                               period_days=30)
    out = render_board_ready(data, fmt)
    assert out
    if fmt == "pdf":
        assert out[:5] == b"%PDF-"


# ---------------------------------------------------------------------------
# MITRE Coverage
# ---------------------------------------------------------------------------

def test_mitre_coverage_matrix_in_canonical_tactic_order(findings):
    data = build_mitre_coverage(findings, period_days=30)
    tactics = [row["tactic"] for row in data["matrix"]]
    from pulse.reports.threat_summary import TACTIC_ORDER
    assert tactics == TACTIC_ORDER


def test_mitre_coverage_active_techniques_only_include_those_with_findings(
        findings):
    data = build_mitre_coverage(findings, period_days=30)
    s = data["summary"]
    assert s["active_technique_count"] >= 1
    assert s["technique_count"] >= s["active_technique_count"]


def test_mitre_coverage_top_techniques_carry_finding_counts(findings):
    data = build_mitre_coverage(findings, period_days=30)
    top = data["top_techniques"]
    assert all(t["findings_count"] > 0 for t in top)
    assert top == sorted(top, key=lambda x: -x["findings_count"])


@pytest.mark.parametrize("fmt", ["json", "csv", "html", "pdf"])
def test_render_mitre_coverage_all_formats(findings, fmt):
    data = build_mitre_coverage(findings, period_days=30)
    out = render_mitre_coverage(data, fmt)
    assert out
    if fmt == "pdf":
        assert out[:5] == b"%PDF-"


# ---------------------------------------------------------------------------
# Compliance Gap Analysis
# ---------------------------------------------------------------------------

def test_compliance_gap_silent_rules_appear_when_zero_hits():
    rule_stats = {}  # no rules have any hits at all
    data = build_compliance_gap(rule_stats, period_days=30)
    # Every enabled rule with no hits should land in silent_rules.
    assert data["summary"]["silent_count"] >= 1


def test_compliance_gap_noisy_rules_threshold():
    rule_stats = {
        "Brute Force Attempt": {
            "hits_total": 100, "tp_count": 30, "fp_count": 70,
        },  # 70% FP rate -> noisy
        "Kerberoasting": {
            "hits_total": 5, "tp_count": 1, "fp_count": 4,
        },  # only 5 hits -> not noisy yet
    }
    data = build_compliance_gap(rule_stats, period_days=30)
    noisy_names = {r["rule"] for r in data["noisy_rules"]}
    assert "Brute Force Attempt" in noisy_names
    assert "Kerberoasting" not in noisy_names


def test_compliance_gap_uncovered_techniques_excluded_when_mapped():
    """The Brute Force rule maps to T1110. Once it's enabled, T1110
    must NOT appear in the uncovered_techniques list."""
    data = build_compliance_gap({}, period_days=30)
    uncovered_ids = {u["technique"] for u in data["uncovered_techniques"]}
    assert "T1110" not in uncovered_ids


@pytest.mark.parametrize("fmt", ["json", "csv", "html", "pdf"])
def test_render_compliance_gap_all_formats(fmt):
    data = build_compliance_gap({}, period_days=30)
    out = render_compliance_gap(data, fmt)
    assert out
    if fmt == "pdf":
        assert out[:5] == b"%PDF-"


# ---------------------------------------------------------------------------
# API integration — all four Phase 5 templates
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
        conn.executemany(
            "INSERT INTO findings "
            "(scan_id, severity, rule, hostname, details, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (sid, 'HIGH', 'Brute Force Attempt', 'DC01',
                 'attempt', '2026-06-02T10:00:00Z'),
                (sid, 'CRITICAL', 'Kerberoasting', 'DC01',
                 'krb', '2026-06-02T10:15:00Z'),
            ],
        )
        conn.commit()


@pytest.mark.parametrize("template,prefix", [
    ("fleet_health",            "pulse_fleet_health"),
    ("board_ready_posture",     "pulse_board_ready"),
    ("mitre_attack_coverage",   "pulse_mitre_coverage"),
    ("compliance_gap_analysis", "pulse_compliance_gap"),
])
def test_generate_phase5_template_via_api(client, template, prefix):
    c, db = client
    _seed(db)
    r = c.post("/api/reports/generate", json={
        "template": template,
        "format":   "json",
        "scope":    {"days": 30},
    })
    assert r.status_code == 200, r.text
    assert r.content
    listed = c.get("/api/reports").json()["reports"]
    assert any(row.get("template_type") == template for row in listed)
    assert any(prefix in row["filename"] for row in listed)


@pytest.mark.parametrize("template", [
    "fleet_health", "board_ready_posture",
    "mitre_attack_coverage", "compliance_gap_analysis",
])
def test_generate_phase5_template_pdf(client, template):
    c, db = client
    _seed(db)
    r = c.post("/api/reports/generate", json={
        "template": template,
        "format":   "pdf",
        "scope":    {"days": 30},
    })
    assert r.status_code == 200
    assert r.content[:5] == b"%PDF-"


def test_full_catalog_listed_in_unknown_template_error(client):
    c, _ = client
    r = c.post("/api/reports/generate", json={
        "template": "nope_does_not_exist",
        "format":   "pdf",
        "scope":    {"days": 7},
    })
    assert r.status_code == 400
    detail = r.json()["detail"].lower()
    # All 9 templates in the catalog should be listed.
    for slug in ("threat_detection_summary", "executive_summary",
                  "nist_csf_coverage", "iso_27001_annex_a",
                  "incident_investigation", "fleet_health",
                  "board_ready_posture", "mitre_attack_coverage",
                  "compliance_gap_analysis"):
        assert slug in detail, f"missing {slug} in dispatcher error"
