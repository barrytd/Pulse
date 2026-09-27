# tests/test_grade_bands.py
# -------------------------
# The dashboard and the backend must agree on which letter a score gets.
# They used to disagree (frontend A90/B80/C70/D60 vs backend A90/B75/C50/
# D25), so the same score could show two different grades. The backend's
# GRADE_BANDS in pulse/reports/reporter.py is the source of truth; these
# tests read dashboard.js (no JS runtime in the suite) and fail if its
# GRADE_BANDS or _gradeFor drift away from it.

import re
from pathlib import Path

import pytest

from pulse.reports.reporter import GRADE_BANDS, _score_grade

DASHBOARD_JS = (Path(__file__).resolve().parent.parent
                / "pulse" / "static" / "js" / "dashboard.js")


def _js_source():
    return DASHBOARD_JS.read_text(encoding="utf-8")


def _js_grade_bands():
    """Parse `export const GRADE_BANDS = [[90, 'A'], ...];` from dashboard.js."""
    m = re.search(r"export const GRADE_BANDS\s*=\s*\[(.*?)\];", _js_source(), re.S)
    assert m, "dashboard.js no longer defines `export const GRADE_BANDS`"
    pairs = re.findall(r"\[\s*(\d+)\s*,\s*'([A-F])'\s*\]", m.group(1))
    assert pairs, "could not parse GRADE_BANDS entries in dashboard.js"
    return tuple((int(floor), grade) for floor, grade in pairs)


def _js_grade_for_body():
    m = re.search(r"export function _gradeFor\(score\)\s*\{(.*?)\n\}", _js_source(), re.S)
    assert m, "dashboard.js no longer defines _gradeFor(score)"
    return m.group(1)


def _grade_via_bands(score, bands):
    """The lookup _gradeFor performs, applied to a band table."""
    for floor, grade in bands:
        if score >= floor:
            return grade
    return "F"


def test_frontend_bands_equal_backend_bands():
    assert _js_grade_bands() == tuple(GRADE_BANDS)


def test_grade_for_reads_the_band_table():
    """_gradeFor must look grades up in GRADE_BANDS, not hardcode its
    own thresholds (that's how the two drifted in the first place)."""
    body = _js_grade_for_body()
    assert "GRADE_BANDS" in body
    assert not re.search(r">=\s*\d", body), (
        "_gradeFor compares against a numeric literal; use GRADE_BANDS")


@pytest.mark.parametrize("score", range(0, 101))
def test_every_score_gets_the_same_letter(score):
    assert _grade_via_bands(score, _js_grade_bands()) == _score_grade(score)


def test_bands_are_descending_and_cover_a_to_d():
    floors = [f for f, _ in GRADE_BANDS]
    assert floors == sorted(floors, reverse=True)
    assert [g for _, g in GRADE_BANDS] == ["A", "B", "C", "D"]


def test_score_history_threshold_line_uses_the_b_band():
    """The dashed 'B grade' line on the score chart comes from the band
    table too, so it moves if the bands ever change."""
    src = _js_source()
    assert "GRADE_BANDS[1][0]" in src
    assert GRADE_BANDS[1] == (75, "B")


# ---------------------------------------------------------------------------
# Report modules grade through the same bands
# ---------------------------------------------------------------------------
# The PDF, executive-summary, board-ready, threat-summary and fleet-health
# reports each used to carry their own 90/75/60/40 scale, so a 30 was a D on
# the dashboard and an F in a board report. They now call
# reporter.grade_for_score. The structural test below fails if any report
# module grows its own score -> letter thresholds again.

import ast

REPORTS_DIR = DASHBOARD_JS.parent.parent.parent / "reports"
_LETTERS = {"A", "B", "C", "D", "E", "F"}


def _report_modules():
    return sorted(p for p in REPORTS_DIR.glob("*.py") if p.name != "reporter.py")


def _local_grade_scales(path):
    """Functions that compare against a number and return a letter grade:
    the shape of a hand-rolled grade scale."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        returns_letter = any(
            isinstance(n, ast.Return) and isinstance(n.value, ast.Constant)
            and n.value.value in _LETTERS
            for n in ast.walk(fn))
        compares_number = any(
            isinstance(n, ast.Compare) and any(
                isinstance(c, ast.Constant) and isinstance(c.value, (int, float))
                and not isinstance(c.value, bool)
                for c in [n.left, *n.comparators])
            for n in ast.walk(fn))
        if returns_letter and compares_number:
            found.append(fn.name)
    return found


@pytest.mark.parametrize("path", _report_modules(), ids=lambda p: p.name)
def test_no_report_module_defines_its_own_grade_bands(path):
    scales = _local_grade_scales(path)
    assert not scales, (
        f"{path.name} maps scores to letters itself in {scales}; "
        "use pulse.reports.reporter.grade_for_score (GRADE_BANDS) instead")


def test_scale_detector_catches_a_hand_rolled_scale(tmp_path):
    """Guard the guard: the old 90/75/60/40 shape must be flagged."""
    p = tmp_path / "old_report.py"
    p.write_text(
        "def _grade(score):\n"
        "    if score >= 90: return 'A'\n"
        "    if score >= 75: return 'B'\n"
        "    if score >= 60: return 'C'\n"
        "    if score >= 40: return 'D'\n"
        "    return 'F'\n")
    assert _local_grade_scales(p) == ["_grade"]


def _report_graders():
    from pulse.reports import executive_summary, fleet_health, pdf_report, threat_summary
    return {
        "executive_summary (and board_ready)": executive_summary._grade_for_score,
        "threat_summary": threat_summary._grade_for_score,
        "fleet_health": fleet_health._grade,
        "pdf_report": pdf_report._grade_for_score,
    }


@pytest.mark.parametrize("score", range(0, 101))
def test_every_report_grades_like_the_dashboard(score):
    for name, grade in _report_graders().items():
        assert grade(score) == _score_grade(score), name


def test_board_ready_uses_the_shared_grader():
    from pulse.reports import board_ready, executive_summary
    assert board_ready._grade_for_score is executive_summary._grade_for_score


def test_fleet_tiers_follow_the_grade():
    from pulse.reports.fleet_health import _tier
    expected = {"A": "Healthy", "B": "Healthy", "C": "Moderate",
                "D": "At Risk", "F": "Critical"}
    for score in range(0, 101):
        assert _tier(score) == expected[_score_grade(score)]
    assert _tier(None) == "Unknown"


def test_missing_scores_keep_their_placeholders():
    from pulse.reports import executive_summary, fleet_health, pdf_report
    assert executive_summary._grade_for_score(None) == "?"
    assert fleet_health._grade(None) == "?"
    assert pdf_report._grade_for_score(None) is None
    assert pdf_report._grade_for_score("n/a") is None
