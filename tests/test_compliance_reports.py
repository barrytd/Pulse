# test_compliance_reports.py
# ---------------------------
# Phase 3 of the report-template catalog: NIST CSF + ISO 27001.

import json

import pytest
from fastapi.testclient import TestClient

from pulse import database
from pulse.api import create_app
from pulse.reports.compliance import (
    build_nist_csf, build_iso_27001,
    NIST_EXPECTED_SUBCATEGORIES, ISO_EXPECTED_CONTROLS,
)
from pulse.reports.compliance_renderers import render


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def findings():
    return [
        {"rule": "Brute Force Attempt", "severity": "HIGH"},
        {"rule": "Brute Force Attempt", "severity": "HIGH"},
        {"rule": "Kerberoasting", "severity": "HIGH"},
        {"rule": "Audit Log Cleared", "severity": "HIGH"},
        {"rule": "Privilege Escalation", "severity": "HIGH"},
    ]


@pytest.fixture
def scans():
    return [
        {"id": 1, "hostname": "DC01", "score": 40,
         "scanned_at": "2026-06-02 12:00:00"},
    ]


# ---------------------------------------------------------------------------
# NIST builder
# ---------------------------------------------------------------------------

def test_build_nist_csf_header(findings, scans):
    data = build_nist_csf(findings, scans, period_days=30,
                           org_name="Acme")
    assert data["framework"] == "NIST CSF"
    h = data["header"]
    assert h["title"] == "NIST CSF Coverage Report"
    assert h["period_days"] == 30
    assert h["host_count"] == 1
    assert data["organization"] == "Acme"


def test_build_nist_csf_functions_in_canonical_order(findings, scans):
    data = build_nist_csf(findings, scans, period_days=30)
    order = [fn["label"] for fn in data["functions"]]
    assert order == ["Identify", "Protect", "Detect", "Respond", "Recover"]


def test_build_nist_csf_layers_findings_onto_subcategories(findings, scans):
    data = build_nist_csf(findings, scans, period_days=30)
    # Audit Log Cleared maps to PR.PT-1 (NIST CSF Protect function).
    protect = next(fn for fn in data["functions"] if fn["label"] == "Protect")
    audit_cleared = [r for r in protect["subcategory_rows"]
                      if "Audit Log Cleared" in r["rules"]]
    assert audit_cleared
    assert audit_cleared[0]["findings_count"] >= 1
    # Kerberoasting maps to DE.CM-7 (Detect).
    detect = next(fn for fn in data["functions"] if fn["label"] == "Detect")
    krb = [r for r in detect["subcategory_rows"]
           if "Kerberoasting" in r["rules"]]
    assert krb and krb[0]["findings_count"] >= 1


def test_build_nist_csf_coverage_gaps(findings, scans):
    data = build_nist_csf(findings, scans, period_days=30)
    # Identify function has no mapped Pulse rules today, so every
    # expected subcategory in ID lands in the gaps list.
    gaps = data["coverage_gaps"]
    id_gaps = [g for g in gaps if g["function"] == "Identify"]
    assert id_gaps
    for g in id_gaps:
        assert g["subcategory"] in NIST_EXPECTED_SUBCATEGORIES["ID"]


def test_build_nist_csf_overall_coverage_is_capped(findings, scans):
    data = build_nist_csf(findings, scans, period_days=30)
    assert 0 <= data["summary"]["overall_coverage_percent"] <= 100


def test_build_nist_csf_empty_findings(scans):
    data = build_nist_csf([], scans, period_days=7)
    assert data["summary"]["findings_in_period"] == 0
    assert isinstance(data["functions"], list)


# ---------------------------------------------------------------------------
# ISO builder
# ---------------------------------------------------------------------------

def test_build_iso_27001_header(findings, scans):
    data = build_iso_27001(findings, scans, period_days=30,
                            org_name="Acme")
    assert data["framework"] == "ISO 27001"
    assert data["header"]["title"] == "ISO 27001 Annex A Report"
    assert data["organization"] == "Acme"


def test_build_iso_27001_clauses_in_canonical_order(findings, scans):
    data = build_iso_27001(findings, scans, period_days=30)
    order = [cl["clause"] for cl in data["clauses"]]
    assert order == ["A.9", "A.12", "A.13", "A.16"]


def test_build_iso_27001_layers_findings_onto_controls(findings, scans):
    data = build_iso_27001(findings, scans, period_days=30)
    # Brute Force Attempt maps to A.9.4.2 (clause A.9).
    access = next(cl for cl in data["clauses"] if cl["clause"] == "A.9")
    bf = [r for r in access["control_rows"]
          if "Brute Force Attempt" in r["rules"]]
    # Multiple rules in the fixture map to A.9.4.2 (BFA, Kerberoasting,
    # etc.) so the control's aggregate count is at least the BFA count
    # but may be higher.
    assert bf
    assert bf[0]["rule_findings"]["Brute Force Attempt"] == 2
    assert bf[0]["findings_count"] >= 2


def test_build_iso_27001_gap_section_lists_uncovered_controls(findings, scans):
    data = build_iso_27001(findings, scans, period_days=30)
    gaps_by_clause = {}
    for gap in data["coverage_gaps"]:
        gaps_by_clause.setdefault(gap["clause"], []).append(gap["control"])
    # A.16.1.5 exists in the expected set but Pulse has no rule for it,
    # so it must appear in the gaps list under the incident-management clause.
    incident_clause_key = "A.16 Information security incident management"
    if "A.16.1.5" in ISO_EXPECTED_CONTROLS.get("A.16", []):
        assert incident_clause_key in gaps_by_clause


# ---------------------------------------------------------------------------
# Renderer outputs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("framework", ["nist", "iso"])
def test_render_all_four_formats_per_framework(findings, scans, framework):
    data = (build_nist_csf if framework == "nist" else build_iso_27001)(
        findings, scans, period_days=30,
    )
    for fmt in ("json", "csv", "html", "pdf"):
        out = render(data, fmt)
        assert out, f"{framework} {fmt} render returned empty bytes"
    # Sanity check on each format's distinguishing marker.
    assert json.loads(render(data, "json"))["framework"] in ("NIST CSF", "ISO 27001")
    csv_lines = render(data, "csv").decode("utf-8-sig").splitlines()
    assert csv_lines[0].split(",")[0] in ("function", "clause")
    html_str = render(data, "html").decode("utf-8")
    assert "<!doctype html>" in html_str
    assert "Coverage Summary" in html_str
    assert "Coverage Gaps" in html_str
    assert render(data, "pdf")[:5] == b"%PDF-"


def test_render_unknown_format_raises(findings, scans):
    data = build_nist_csf(findings, scans, period_days=30)
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
            "VALUES (?, 1, 40, 'High Risk', 'x.evtx', 'DC01')",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
        )
        sid = conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]
        conn.executemany(
            "INSERT INTO findings (scan_id, severity, rule, hostname, details, timestamp)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            [
                (sid, 'HIGH', 'Brute Force Attempt', 'DC01', 'x',
                 '2026-06-02T10:00:00Z'),
                (sid, 'HIGH', 'Kerberoasting', 'DC01', 'y',
                 '2026-06-02T10:15:00Z'),
            ],
        )
        conn.commit()


@pytest.mark.parametrize("template,prefix", [
    ("nist_csf_coverage", "pulse_nist_csf"),
    ("iso_27001_annex_a", "pulse_iso_27001"),
])
def test_generate_compliance_report_via_api(client, template, prefix):
    c, db = client
    _seed(db)
    r = c.post("/api/reports/generate", json={
        "template": template,
        "format":   "json",
        "scope":    {"days": 30},
    })
    assert r.status_code == 200, r.text
    payload = json.loads(r.content)
    assert payload["framework"] in ("NIST CSF", "ISO 27001")
    listed = c.get("/api/reports").json()["reports"]
    assert any(row.get("template_type") == template for row in listed)
    assert any(prefix in row["filename"] for row in listed)


@pytest.mark.parametrize("template", ["nist_csf_coverage", "iso_27001_annex_a"])
def test_generate_compliance_report_pdf(client, template):
    c, db = client
    _seed(db)
    r = c.post("/api/reports/generate", json={
        "template": template,
        "format":   "pdf",
        "scope":    {"days": 30},
    })
    assert r.status_code == 200
    assert r.content[:5] == b"%PDF-"
