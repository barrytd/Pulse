# test_executive_summary.py
# --------------------------
# Phase 2 of the report-template catalog: Executive Summary.

import json
import os
import tempfile
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from pulse import database
from pulse.api import create_app
from pulse.reports.executive_summary import (
    build_executive, _grade_for_score, _is_resolved,
    _what_this_means, _pick_top_risks, _build_recommendations,
    GRADE_INTERPRETATION,
)
from pulse.reports.executive_summary_renderers import (
    render, render_json, render_csv, render_html, render_pdf,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def findings():
    return [
        {"rule": "Brute Force Attempt", "severity": "HIGH",
         "timestamp": "2026-06-02T10:00:00Z", "hostname": "DC01"},
        {"rule": "Brute-Force Success", "severity": "CRITICAL",
         "timestamp": "2026-06-02T10:15:00Z", "hostname": "DC01"},
        {"rule": "Kerberoasting", "severity": "HIGH",
         "timestamp": "2026-06-02T10:30:00Z", "hostname": "DC01"},
        {"rule": "RDP Logon Detected", "severity": "MEDIUM",
         "timestamp": "2026-06-02T11:00:00Z", "hostname": "WS-FIN"},
        # One resolved finding to test the open/resolved split.
        {"rule": "Suspicious PowerShell", "severity": "CRITICAL",
         "timestamp": "2026-06-02T11:30:00Z", "hostname": "WS-FIN",
         "workflow_status": "resolved"},
    ]


@pytest.fixture
def scans():
    return [
        {"id": 1, "scanned_at": "2026-06-02 12:00:00",
         "hostname": "DC01", "score": 35, "score_label": "Critical Risk"},
        {"id": 2, "scanned_at": "2026-06-02 12:30:00",
         "hostname": "WS-FIN", "score": 52, "score_label": "High Risk"},
    ]


@pytest.fixture
def prev_findings():
    return [
        {"rule": "RDP Logon Detected", "severity": "MEDIUM",
         "timestamp": "2026-05-02T10:00:00Z", "hostname": "DC01"},
    ]


@pytest.fixture
def prev_scans():
    return [
        {"id": 0, "scanned_at": "2026-05-02 12:00:00",
         "hostname": "DC01", "score": 70, "score_label": "Moderate Risk"},
    ]


# ---------------------------------------------------------------------------
# Grade + interpretation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score,grade", [
    (100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"),
    (60, "C"), (59, "D"), (40, "D"), (39, "F"), (0, "F"),
    (None, "?"),
])
def test_grade_thresholds(score, grade):
    assert _grade_for_score(score) == grade


def test_grade_interpretation_covers_every_letter():
    for g in ("A", "B", "C", "D", "F", "?"):
        assert g in GRADE_INTERPRETATION
        assert GRADE_INTERPRETATION[g]


# ---------------------------------------------------------------------------
# Resolved-finding classification
# ---------------------------------------------------------------------------

def test_is_resolved_recognizes_workflow_status():
    assert _is_resolved({"workflow_status": "resolved"}) is True
    assert _is_resolved({"workflow_status": "investigating"}) is False


def test_is_resolved_recognizes_false_positive_flag():
    assert _is_resolved({"false_positive": True}) is True
    assert _is_resolved({"false_positive": False}) is False


def test_is_resolved_recognizes_legacy_reviewed_flag():
    """Pre-workflow-column rows still have a `reviewed` bool. We treat
    that as resolved so old findings don't pollute the open-count tile."""
    assert _is_resolved({"reviewed": True}) is True


# ---------------------------------------------------------------------------
# Builder shape
# ---------------------------------------------------------------------------

def test_build_executive_header_includes_required_fields(findings, scans):
    data = build_executive(findings, scans, period_days=30,
                            org_name="Acme Corp")
    h = data["header"]
    assert h["title"] == "Executive Security Summary"
    assert h["organization"] == "Acme Corp"
    assert h["period_days"] == 30
    assert h["host_count"] == 2
    # Period strings are YYYY-MM-DD shape, deterministic for the test
    # to verify the formatter without freezing time globally.
    assert len(h["period_start"]) == 10
    assert len(h["period_end"]) == 10


def test_build_executive_posture_grade_matches_avg_score(findings, scans):
    data = build_executive(findings, scans, period_days=30)
    # (35 + 52) / 2 = 43.5 -> 44 -> "D"
    assert data["posture"]["score"] == 44
    assert data["posture"]["grade"] == "D"
    assert "high-impact" in data["posture"]["interpretation"].lower()


def test_build_executive_trend_against_previous_period(findings, scans,
                                                         prev_findings, prev_scans):
    data = build_executive(findings, scans, period_days=30,
                            prev_findings=prev_findings,
                            prev_scans=prev_scans)
    # prev avg = 70, current = 44 -> delta = -26 -> declined
    assert data["posture"]["trend"]["direction"] == "declined"
    assert data["posture"]["trend"]["delta"] == 44 - 70


def test_build_executive_trend_first_period_when_no_prev(findings, scans):
    data = build_executive(findings, scans, period_days=30)
    assert data["posture"]["trend"]["direction"] == "first_period"
    assert data["posture"]["trend"]["delta"] is None


def test_build_executive_what_this_means_is_non_empty(findings, scans):
    data = build_executive(findings, scans, period_days=30)
    text = data["what_this_means"]
    assert text
    # Mentions the period in human language.
    assert "30 day" in text
    # Mentions critical activity because there's a CRITICAL finding.
    assert "critical" in text.lower()


def test_build_executive_what_this_means_clean_period():
    data = build_executive([], [], period_days=7)
    text = data["what_this_means"]
    assert "clean" in text.lower()
    assert "7 day" in text


# ---------------------------------------------------------------------------
# Top Risks ranking
# ---------------------------------------------------------------------------

def test_top_risks_are_ranked_severity_first(findings):
    risks = _pick_top_risks(findings, limit=3)
    assert len(risks) == 3
    # CRITICAL first.
    assert risks[0]["severity"] == "CRITICAL"
    # HIGH next.
    assert risks[1]["severity"] == "HIGH"
    # No CRITICAL/HIGH below MEDIUM in the top 3.
    assert risks[2]["severity"] in ("HIGH", "MEDIUM")


def test_top_risks_deduplicate_by_rule(findings):
    # Stuff 50 identical brute-force findings; only 1 should appear.
    bulk = [
        {"rule": "Brute Force Attempt", "severity": "HIGH",
         "timestamp": f"2026-06-02T1{i%10}:00:00Z", "hostname": "DC01"}
        for i in range(50)
    ]
    risks = _pick_top_risks(bulk, limit=3)
    rules = [r["rule"] for r in risks]
    assert rules.count("Brute Force Attempt") == 1


def test_top_risks_carry_plain_language_from_knowledge_base(findings):
    risks = _pick_top_risks(findings, limit=3)
    # Knowledge-base wired entries have these fields populated.
    for r in risks:
        assert r["what_happened"]
        assert r["why_it_matters"]
        assert r["recommended_action"]
        # No jargon — these are sentences, not "Event 4625 fired".
        assert "Event " not in r["what_happened"]


def test_top_risks_falls_back_when_all_resolved():
    """If every finding is marked resolved, the section still gets
    populated from the raw set instead of going empty."""
    resolved_only = [
        {"rule": "Brute Force Attempt", "severity": "HIGH",
         "workflow_status": "resolved"},
    ]
    risks = _pick_top_risks(resolved_only, limit=3)
    assert len(risks) == 1


# ---------------------------------------------------------------------------
# Activity overview + What Changed
# ---------------------------------------------------------------------------

def test_activity_overview_counts(findings, scans):
    data = build_executive(findings, scans, period_days=30)
    a = data["activity"]
    assert a["total_issues"] == 5
    assert a["resolved"] == 1
    assert a["open"]     == 4
    assert a["machines_monitored"] == 2
    # DC01 has unresolved CRITICAL+HIGH so it's "at risk".
    # WS-FIN's CRITICAL is resolved, so only the host with unresolved
    # CRITICAL/HIGH counts -> 1.
    assert a["machines_at_risk"] == 1
    assert a["by_severity"]["CRITICAL"] == 2
    assert a["by_severity"]["HIGH"]     == 2
    assert a["by_severity"]["MEDIUM"]   == 1
    assert a["by_severity"]["LOW"]      == 0


def test_what_changed_with_prev_period(findings, scans,
                                          prev_findings, prev_scans):
    data = build_executive(findings, scans, period_days=30,
                            prev_findings=prev_findings,
                            prev_scans=prev_scans)
    c = data["what_changed"]
    assert c["had_previous_period"] is True
    assert c["new_issues"] == 5
    assert c["previous_issues"] == 1
    assert c["issues_delta"] == 4
    assert c["score_delta"] == 44 - 70
    # WS-FIN is in current but not previous -> 1 new machine.
    assert c["new_machines"] == ["WS-FIN"]
    assert c["new_machines_count"] == 1


def test_what_changed_without_prev_period(findings, scans):
    data = build_executive(findings, scans, period_days=30)
    c = data["what_changed"]
    assert c["had_previous_period"] is False


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

def test_recommendations_populated_from_knowledge_base(findings):
    recs = _build_recommendations(findings, limit=5)
    assert 1 <= len(recs) <= 5
    # All end in a period so they read as commands.
    for line in recs:
        assert line.endswith(".")


def test_recommendations_dedup_across_findings():
    """Two findings with the same rule shouldn't fill the list with
    identical commands."""
    fs = [
        {"rule": "Brute Force Attempt", "severity": "HIGH"},
        {"rule": "Brute Force Attempt", "severity": "HIGH"},
    ]
    recs = _build_recommendations(fs, limit=10)
    assert len(recs) == len(set(recs))


def test_recommendations_fall_back_for_empty_input():
    recs = _build_recommendations([], limit=5)
    assert 1 <= len(recs) <= 5


# ---------------------------------------------------------------------------
# Renderer outputs — each format checked for at least one distinguishing
# property so a regression that drops a section gets caught.
# ---------------------------------------------------------------------------

def test_render_json_is_parseable(findings, scans):
    data = build_executive(findings, scans, period_days=30)
    parsed = json.loads(render(data, "json"))
    assert parsed["header"]["title"] == "Executive Security Summary"
    assert parsed["activity"]["total_issues"] == 5


def test_render_csv_has_section_columns(findings, scans):
    data = build_executive(findings, scans, period_days=30)
    out = render(data, "csv").decode("utf-8-sig")
    lines = [l for l in out.splitlines() if l.strip()]
    assert lines[0].split(",")[0] == "section"
    # All section labels are present.
    text = "\n".join(lines)
    for sec in ("header", "posture", "narrative", "activity",
                 "top_risks", "recommendations"):
        assert sec in text


def test_render_html_is_light_theme_self_contained(findings, scans):
    data = build_executive(findings, scans, period_days=30)
    out = render(data, "html").decode("utf-8")
    assert out.startswith("<!doctype html>")
    # Light theme: white background, dark text.
    assert "#ffffff" in out
    assert "#111827" in out
    # Section labels exactly per spec.
    for label in ("Security Posture at a Glance", "What This Means",
                  "Top Risks", "Activity Overview", "What Changed",
                  "Recommendations"):
        assert label in out
    # Footer mentions Pulse version + automated note.
    assert "Pulse v" in out
    assert "automated assessment" in out


def test_render_pdf_returns_pdf_magic(findings, scans):
    data = build_executive(findings, scans, period_days=30)
    out = render(data, "pdf")
    assert out[:5] == b"%PDF-"
    assert len(out) > 2000


def test_render_unknown_format_raises(findings, scans):
    data = build_executive(findings, scans, period_days=30)
    with pytest.raises(ValueError, match="unknown format"):
        render(data, "xml")


# ---------------------------------------------------------------------------
# API integration — /api/reports/generate template=executive_summary
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
            "VALUES (?, 1, 35, 'Critical Risk', 'x.evtx', 'SERVER-DC01')",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
        )
        sid = conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]
        rows = [
            (sid, 'HIGH', 'Brute Force Attempt', 'SERVER-DC01',
             'IP 1.2.3.4 tried 50x', '2026-06-02T10:00:00Z'),
            (sid, 'CRITICAL', 'Brute-Force Success', 'SERVER-DC01',
             'compromise', '2026-06-02T10:15:00Z'),
        ]
        conn.executemany(
            "INSERT INTO findings (scan_id, severity, rule, hostname, details, timestamp)"
            " VALUES (?, ?, ?, ?, ?, ?)", rows,
        )
        conn.commit()
        return sid


@pytest.mark.parametrize("fmt", ["pdf", "html", "json", "csv"])
def test_generate_executive_supports_all_four_formats(client, fmt):
    c, db = client
    _seed_scan_with_findings(db)
    r = c.post("/api/reports/generate", json={
        "template": "executive_summary",
        "format":   fmt,
        "scope":    {"days": 30},
    })
    assert r.status_code == 200, r.text
    assert r.content
    cd = r.headers.get("content-disposition", "")
    assert "pulse_executive_summary_" in cd
    assert f".{fmt}" in cd


def test_generate_executive_persists_with_template_type(client):
    c, db = client
    _seed_scan_with_findings(db)
    c.post("/api/reports/generate", json={
        "template": "executive_summary",
        "format":   "json",
        "scope":    {"days": 30},
    })
    body = c.get("/api/reports").json()
    rows = [r for r in body["reports"]
            if r.get("template_type") == "executive_summary"]
    assert rows, "executive_summary row should be persisted"
    assert rows[0]["format"] == "json"


def test_generate_executive_rejects_unknown_format(client):
    c, _ = client
    r = c.post("/api/reports/generate", json={
        "template": "executive_summary",
        "format":   "xml",
        "scope":    {"days": 30},
    })
    assert r.status_code == 400
    assert "format" in r.json()["detail"].lower()


def test_dispatch_lists_both_templates_in_error_message(client):
    c, _ = client
    r = c.post("/api/reports/generate", json={
        "template": "compliance_nist_v1",  # not yet shipped
        "format":   "pdf",
        "scope":    {"days": 7},
    })
    assert r.status_code == 400
    detail = r.json()["detail"].lower()
    assert "executive_summary" in detail
    assert "threat_detection_summary" in detail


def test_threat_detection_template_still_works(client):
    """Phase 2 changed the dispatch shape — make sure Phase 1's
    template still round-trips as a regression guard."""
    c, db = client
    sid = _seed_scan_with_findings(db)
    r = c.post("/api/reports/generate", json={
        "template": "threat_detection_summary",
        "format":   "json",
        "scope":    {"scan_id": sid},
    })
    assert r.status_code == 200
    parsed = json.loads(r.content)
    assert parsed["header"]["title"] == "Threat Detection Summary"
