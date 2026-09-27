# tests/test_scoring.py
# ---------------------
# Unit tests for calculate_score_from_findings in pulse/reports/reporter.py:
# the multiplicative keep-factor model, recency + status weighting, and
# the return shape downstream code relies on.
# See docs/2026-09-26-scoring-model-review.md.

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app
from pulse.database import init_db
from pulse.reports.reporter import _score_grade, calculate_score_from_findings

NOW = datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)


def _score(findings, now=NOW):
    return calculate_score_from_findings(findings, now=now)


def _criticals(n, **extra):
    """n criticals from n distinct rules (dedup is per rule)."""
    return [dict({"rule": f"Critical Rule {i}", "severity": "CRITICAL"}, **extra)
            for i in range(n)]


def _ago(**delta):
    return (NOW - timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


# ---------------------------------------------------------------------------
# Keep-factor model
# ---------------------------------------------------------------------------

def test_no_findings_is_perfect():
    r = _score([])
    assert r["score"] == 100
    assert r["grade"] == "A"
    assert r["total_deducted"] == 0
    assert r["deductions"] == []


@pytest.mark.parametrize("severity,expected,grade", [
    ("CRITICAL", 72, "C"),
    ("HIGH",     85, "B"),
    ("MEDIUM",   93, "A"),
    ("LOW",      97, "A"),
])
def test_single_finding_uses_keep_factor(severity, expected, grade):
    r = _score([{"rule": "Some Rule", "severity": severity}])
    assert r["score"] == expected
    assert r["grade"] == grade


@pytest.mark.parametrize("n,expected,grade", [
    (1, 72, "C"), (2, 52, "C"), (3, 37, "D"), (4, 27, "D"), (8, 7, "F"), (40, 0, "F"),
])
def test_matches_design_doc_table(n, expected, grade):
    r = _score(_criticals(n))
    assert r["score"] == expected
    assert r["grade"] == grade


def test_8_and_40_criticals_score_differently():
    """The saturation bug: under flat subtraction both were 0/F."""
    eight = _score(_criticals(8))["score"]
    forty = _score(_criticals(40))["score"]
    assert eight != forty
    assert eight > forty


def test_4_and_8_criticals_score_differently():
    # Flat subtraction already bottomed out at 4.
    assert _score(_criticals(4))["score"] > _score(_criticals(8))["score"] > 0


def test_every_extra_finding_moves_the_score():
    scores = [_score(_criticals(n))["score"] for n in range(0, 9)]
    assert scores == sorted(scores, reverse=True)
    assert len(set(scores)) == len(scores)


def test_mixed_severities_multiply():
    r = _score([{"rule": "A", "severity": "CRITICAL"},
                {"rule": "B", "severity": "HIGH"},
                {"rule": "C", "severity": "LOW"}])
    assert r["score"] == round(100 * 0.72 * 0.85 * 0.97)


def test_score_never_negative():
    r = _score(_criticals(200))
    assert r["score"] == 0
    assert r["total_deducted"] == 100


def test_repeated_rule_counts_once():
    fifty = [{"rule": "Brute Force Attempt", "severity": "HIGH"}] * 50
    assert _score(fifty)["score"] == 85
    assert len(_score(fifty)["deductions"]) == 1


def test_repeated_rule_keeps_worst_severity():
    r = _score([{"rule": "X", "severity": "LOW"},
                {"rule": "X", "severity": "CRITICAL"}])
    assert r["score"] == 72
    assert r["deductions"][0]["severity"] == "CRITICAL"


def test_unknown_severity_treated_as_low():
    assert _score([{"rule": "X", "severity": "WEIRD"}])["score"] == 97


@pytest.mark.parametrize("score,grade", [
    (100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"),
    (50, "C"), (49, "D"), (25, "D"), (24, "F"), (0, "F"),
])
def test_grade_bands_unchanged(score, grade):
    assert _score_grade(score) == grade


# ---------------------------------------------------------------------------
# Recency weighting — measured from when Pulse recorded the finding
# ---------------------------------------------------------------------------

def _recorded(**delta):
    """A `scanned_at` value the way Pulse stores it: naive local time."""
    return (NOW - timedelta(**delta)).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def test_uploaded_old_log_counts_at_full_weight():
    """An incident responder uploads a three-month-old log today: its
    critical is new to Pulse, so it scores a C (72), not a discounted B."""
    r = _score(_criticals(1, timestamp=_ago(days=90)))
    assert r["score"] == 72
    assert r["grade"] == "C"
    # Same thing when the scan that recorded it ran moments ago.
    r = _score(_criticals(1, timestamp=_ago(days=90), scanned_at=_recorded(minutes=5)))
    assert r["score"] == 72
    assert r["grade"] == "C"


def test_event_timestamp_is_ignored_for_recency():
    fresh_event = _score(_criticals(1, timestamp=_ago(hours=1), scanned_at=_recorded(days=30)))
    old_event = _score(_criticals(1, timestamp=_ago(days=400), scanned_at=_recorded(days=30)))
    assert fresh_event["score"] == old_event["score"] == 86


def test_finding_open_for_weeks_still_fades():
    fresh = _score(_criticals(1, scanned_at=_recorded(hours=1)))["score"]
    stale = _score(_criticals(1, scanned_at=_recorded(weeks=3)))["score"]
    assert fresh == 72
    assert stale > fresh


def test_full_weight_for_first_week():
    assert _score(_criticals(1, scanned_at=_recorded(days=6)))["score"] == 72


def test_fades_to_half_weight_by_three_weeks_and_stops():
    # Half weight: keep = 1 - 0.28 * 0.5 = 0.86.
    assert _score(_criticals(1, scanned_at=_recorded(days=21)))["score"] == 86
    assert _score(_criticals(1, scanned_at=_recorded(days=365)))["score"] == 86


def test_fade_is_gradual():
    s7 = _score(_criticals(1, scanned_at=_recorded(days=7)))["score"]
    s14 = _score(_criticals(1, scanned_at=_recorded(days=14)))["score"]
    s21 = _score(_criticals(1, scanned_at=_recorded(days=21)))["score"]
    assert s7 < s14 < s21


def test_recorded_at_wins_over_scanned_at():
    f = _criticals(1, recorded_at=_recorded(hours=1), scanned_at=_recorded(days=60))
    assert _score(f)["score"] == 72


@pytest.mark.parametrize("ts", [None, "", "not a date"])
def test_missing_or_bad_record_time_counts_as_new(ts):
    assert _score(_criticals(1, scanned_at=ts))["score"] == 72


def test_future_record_time_gets_full_weight():
    assert _score(_criticals(1, scanned_at=_recorded(days=-2)))["score"] == 72


@pytest.mark.parametrize("ts", [
    "2026-08-01T10:00:00Z",
    "2026-08-01T10:00:00.1234567Z",   # 7-digit fraction
    "2026-08-01T10:00:00+00:00",
    "2026-08-01 10:00:00",            # naive = local, how scanned_at is stored
])
def test_record_time_formats_parse(ts):
    assert _score(_criticals(1, scanned_at=ts))["score"] == 86


def test_naive_now_accepted():
    naive = NOW.replace(tzinfo=None)
    assert _score(_criticals(1, scanned_at=_recorded(days=30)), now=naive)["score"] == 86


# ---------------------------------------------------------------------------
# Status weighting
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status", ["new", "acknowledged", "investigating", None])
def test_open_statuses_weigh_full(status):
    assert _score(_criticals(1, workflow_status=status))["score"] == 72


def test_resolved_weighs_twenty_percent():
    # keep = 1 - 0.28 * 0.2 = 0.944
    assert _score(_criticals(1, workflow_status="resolved"))["score"] == 94


def test_legacy_reviewed_flag_counts_as_resolved():
    assert _score(_criticals(1, reviewed=1))["score"] == 94


def test_false_positive_does_not_count():
    r = _score(_criticals(3, false_positive=1))
    assert r["score"] == 100
    assert r["deductions"] == []


def test_resolving_raises_the_score():
    open_ = _score(_criticals(8))["score"]
    resolved = _score(_criticals(8, workflow_status="resolved"))["score"]
    assert resolved > open_


def test_open_occurrence_outweighs_resolved_one_of_same_rule():
    r = _score([{"rule": "X", "severity": "CRITICAL", "workflow_status": "resolved"},
                {"rule": "X", "severity": "CRITICAL", "workflow_status": "new"}])
    assert r["score"] == 72


def test_recency_and_status_combine():
    # Old + resolved: weight 0.5 * 0.2 = 0.1 -> keep 0.972.
    r = _score(_criticals(1, scanned_at=_recorded(days=60), workflow_status="resolved"))
    assert r["score"] == 97
    assert r["deductions"][0]["weight"] == 0.1


# ---------------------------------------------------------------------------
# Return shape (dashboard, trend chart, scans table depend on it)
# ---------------------------------------------------------------------------

def test_return_shape_is_unchanged():
    r = _score([{"rule": "Brute Force Attempt", "severity": "HIGH"},
                {"rule": "Kerberoasting", "severity": "CRITICAL"}])
    assert {"score", "label", "colour", "grade", "total_deducted",
            "deductions", "categories"} <= set(r)
    assert isinstance(r["score"], int)
    assert r["total_deducted"] == 100 - r["score"]
    for d in r["deductions"]:
        assert {"rule", "severity", "points", "category"} <= set(d)
        assert not any(k.startswith("_") for k in d)
    # Heaviest first.
    assert [d["rule"] for d in r["deductions"]] == ["Kerberoasting", "Brute Force Attempt"]
    assert r["deductions"][0]["points"] == 28
    cats = r["categories"]
    assert cats["Credential Access"]["rules_triggered"] == ["Kerberoasting"]
    assert cats["Credential Access"]["deducted"] == 28
    assert cats["Credential Access"]["status"] == "high"
    assert cats["Authentication"]["status"] == "medium"
    assert cats["Persistence"] == {"deducted": 0, "rules_triggered": [], "status": "clear"}


def test_label_tracks_score():
    assert _score([])["label"] == "SECURE"
    assert _score(_criticals(8))["label"] == "CRITICAL RISK"


def test_defaults_to_current_time():
    fresh = datetime.now(timezone.utc).isoformat()
    old = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    assert calculate_score_from_findings(_criticals(1, scanned_at=fresh))["score"] == 72
    assert calculate_score_from_findings(_criticals(1, scanned_at=old))["score"] == 86


# ---------------------------------------------------------------------------
# /api/score/daily — past days scored as of that day
# ---------------------------------------------------------------------------

def test_daily_score_for_past_day_does_not_drift(tmp_path):
    """A day 30 days back must score its critical at full weight (as it
    stood that day), not decayed by today's clock."""
    db = str(tmp_path / "t.db")
    init_db(db)
    day = datetime.now(timezone.utc) - timedelta(days=30)
    stamp = day.strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(db) as conn:
        sid = conn.execute(
            """INSERT INTO scans (scanned_at, hostname, files_scanned,
                                  total_events, total_findings, score,
                                  score_label, filename)
               VALUES (?, 'HOST', 1, 10, 1, 72, 'MODERATE RISK', 'x.evtx')""",
            (stamp,),
        ).lastrowid
        conn.execute(
            """INSERT INTO findings (scan_id, timestamp, event_id, severity, rule)
               VALUES (?, ?, '4769', 'CRITICAL', 'Golden Ticket')""",
            (sid, stamp),
        )
    config = tmp_path / "pulse.yaml"
    config.write_text("whitelist:\n  accounts: []\n")
    client = TestClient(create_app(db_path=db, config_path=str(config),
                                   disable_auth=True))
    resp = client.get("/api/score/daily?days=60")
    assert resp.status_code == 200
    row = next(r for r in resp.json()["daily_scores"]
               if r["date"] == stamp[:10])
    assert row["score"] == 72


# ---------------------------------------------------------------------------
# One scorer everywhere: reports and the CLI match the dashboard
# ---------------------------------------------------------------------------

def _mixed_findings():
    # Old event timestamps on purpose: neither path may discount them.
    return [
        {"rule": "Golden Ticket", "severity": "CRITICAL", "timestamp": _ago(days=90),
         "details": "x", "description": "x"},
        {"rule": "Brute Force Attempt", "severity": "HIGH", "timestamp": _ago(days=90),
         "details": "x", "description": "x"},
        {"rule": "Brute Force Attempt", "severity": "HIGH", "timestamp": _ago(days=89),
         "details": "x", "description": "x"},
        {"rule": "RDP Logon Detected", "severity": "LOW", "timestamp": _ago(days=1),
         "details": "x", "description": "x"},
    ] + [{"rule": f"Critical Rule {i}", "severity": "CRITICAL", "details": "x",
          "description": "x"} for i in range(6)]


def _counts(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def test_report_score_matches_dashboard_score():
    from pulse.reports.reporter import _report_score
    findings = _mixed_findings()
    dash = calculate_score_from_findings(findings)
    assert _report_score(findings) == (dash["score"], dash["label"], dash["colour"])
    # 7 criticals + 1 high + 1 low: the old flat model floored this at 0.
    assert 0 < dash["score"] < 10


def test_json_report_score_matches_dashboard_score():
    import json
    from pulse.reports.reporter import _build_json_report
    findings = _mixed_findings()
    data = json.loads(_build_json_report(findings, _counts(findings)))
    dash = calculate_score_from_findings(findings)
    assert data["summary"]["security_score"] == dash["score"]
    assert data["summary"]["risk_level"] == dash["label"]


def test_html_report_score_matches_dashboard_score():
    import re
    from pulse.reports.reporter import _build_html_report
    findings = _mixed_findings()
    html = _build_html_report(findings, _counts(findings))
    dash = calculate_score_from_findings(findings)
    m = re.search(r'class="score-number"[^>]*>\s*(\d+)', html)
    assert m, "score number not found in HTML report"
    assert int(m.group(1)) == dash["score"]
    assert dash["label"] in html


def test_exported_report_matches_stored_and_daily_score(tmp_path):
    """End to end: a scan's stored score, its exported JSON report, and
    the dashboard's daily score all agree for the same findings."""
    import json
    from pulse.database import save_scan
    db = str(tmp_path / "t.db")
    init_db(db)
    findings = _mixed_findings()
    dash = calculate_score_from_findings(findings)
    scan_id = save_scan(db, findings, scan_stats={"total_events": 10, "files_scanned": 1},
                        score=dash["score"], score_label=dash["label"])
    config = tmp_path / "pulse.yaml"
    config.write_text("whitelist:\n  accounts: []\n")
    client = TestClient(create_app(db_path=db, config_path=str(config),
                                   disable_auth=True))

    exported = client.get(f"/api/export/{scan_id}?format=json")
    assert exported.status_code == 200
    assert json.loads(exported.content)["summary"]["security_score"] == dash["score"]

    daily = client.get("/api/score/daily?days=1").json()["daily_scores"][0]
    assert daily["score"] == dash["score"]
    assert daily["grade"] == dash["grade"]
