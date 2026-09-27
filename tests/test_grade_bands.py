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
