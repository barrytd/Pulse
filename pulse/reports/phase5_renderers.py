"""Format renderers for the Phase 5 templates: Fleet Health,
Board-Ready Posture, MITRE ATT&CK Coverage, Compliance Gap Analysis.

Each template gets its own ``render_<slug>(payload, fmt)`` entry point.
We keep them in one module instead of one each because they share an
overwhelming amount of plumbing; the per-template differences are
section composition, not core styling.

HTML and PDF both compose the shared ``report_theme`` design system so
every Pulse report (PDF + in-browser) looks identical. JSON and CSV keep
their existing byte-for-byte contracts.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List, Optional

import pulse.reports.report_theme as T


def _esc(s: Any) -> str:
    return T.esc(s)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# Map a host risk tier to a theme severity key (drives section accents +
# the tier pill color so the print theme stays internally consistent).
_TIER_SEV = {
    "Critical": "CRITICAL",
    "At Risk":  "HIGH",
    "Moderate": "MEDIUM",
    "Healthy":  "LOW",
    "Unknown":  "NONE",
}
# Letter grade -> theme severity key (board posture banner + grade accent).
_GRADE_SEV = {
    "A": "LOW", "B": "LOW", "C": "MEDIUM", "D": "HIGH", "F": "CRITICAL",
    "?": "NONE",
}


def _tier_sev(tier: Optional[str]) -> str:
    return _TIER_SEV.get(tier or "Unknown", "NONE")


def _grade_sev(grade: Optional[str]) -> str:
    return _GRADE_SEV.get((grade or "?").upper(), "NONE")


def _html_tier_pill(tier: Optional[str]) -> str:
    """Tier label rendered as a theme severity pill, but keeping the
    human tier word (Healthy / At Risk / …) rather than the sev key."""
    k = _tier_sev(tier)
    return ('<span class="rpt-pill" style="color:' + T.SEV_FG[k] + ';background:'
            + T.SEV_BG[k] + ';">' + _esc(tier or "Unknown") + '</span>')


def _pdf_tier_pill(tier: Optional[str], st):
    rl = T._rl()
    C = rl["colors"].HexColor
    k = _tier_sev(tier)
    label = str(tier or "Unknown")
    p = rl["Paragraph"]('<font color="%s"><b>%s</b></font>' % (T.SEV_FG[k], _esc(label)),
                        rl["ParagraphStyle"]("tierpill", fontName="Helvetica-Bold",
                                             fontSize=7.5, leading=10,
                                             alignment=rl["TA_CENTER"]))
    w = 12 + 5.0 * len(label)
    t = rl["Table"]([[p]], colWidths=[w])
    t.setStyle(rl["TableStyle"]([
        ("BACKGROUND", (0, 0), (-1, -1), C(T.SEV_BG[k])),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("ROUNDEDCORNERS", [5, 5, 5, 5]),
    ]))
    t.hAlign = "LEFT"
    return t


def _html_metric_strip(tiles: List) -> str:
    """A row of metric tiles styled as theme callouts. ``tiles`` is a list
    of (value, label, sev_or_None)."""
    cells = ""
    for num, label, sev in tiles:
        color = T.SEV_FG[T.sev_key(sev)] if sev else T.C_TITLE
        cells += (
            '<td style="text-align:center;padding:4px;">'
            '<div style="border:1px solid ' + T.C_BORDER + ';background:' + T.C_TINT +
            ';border-radius:5px;padding:12px 8px;">'
            '<div style="font-size:22px;font-weight:800;line-height:1.1;color:' + color + ';">'
            + _esc(num) + '</div>'
            '<div style="font-size:8.5px;text-transform:uppercase;letter-spacing:0.5px;'
            'color:' + T.C_MUTED + ';font-weight:600;margin-top:4px;">' + _esc(label) + '</div>'
            '</div></td>'
        )
    return ('<table style="width:100%;border-collapse:separate;border-spacing:0;'
            'table-layout:fixed;margin:2px 0 8px;"><tr>' + cells + '</tr></table>')


def _pdf_metric_strip(tiles: List, st):
    """A row of metric tiles as a single bordered table (mirrors the HTML
    strip). ``tiles`` is a list of (value, label, sev_or_None)."""
    rl = T._rl()
    C = rl["colors"].HexColor
    cols = len(tiles) or 1
    cell_w = T.CONTENT_W / cols
    row = []
    for num, label, sev in tiles:
        num_color = T.SEV_FG[T.sev_key(sev)] if sev else T.C_TITLE
        num_p = rl["Paragraph"](
            '<font color="%s"><b>%s</b></font>' % (num_color, _esc(num)),
            rl["ParagraphStyle"]("ms_n", fontName="Helvetica-Bold", fontSize=18,
                                 leading=20, alignment=rl["TA_CENTER"]))
        lbl_p = rl["Paragraph"](
            '<font color="%s"><b>%s</b></font>' % (T.C_MUTED, _esc(str(label).upper())),
            rl["ParagraphStyle"]("ms_l", fontName="Helvetica-Bold", fontSize=7,
                                 leading=10, alignment=rl["TA_CENTER"]))
        row.append([num_p, rl["Spacer"](1, 4), lbl_p])
    t = rl["Table"]([row], colWidths=[cell_w] * cols)
    t.setStyle(rl["TableStyle"]([
        ("BACKGROUND", (0, 0), (-1, -1), C(T.C_TINT)),
        ("BOX", (0, 0), (-1, -1), 0.6, C(T.C_BORDER)),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, C(T.C_BORDER)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 12), ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    return t


def _html_none_block(msg: str) -> str:
    return '<div class="rpt-none">' + _esc(msg) + '</div>'


def _pdf_none(msg: str, st):
    return T._rl()["Paragraph"](
        '<i><font color="%s">%s</font></i>' % (T.C_MUTED, _esc(msg)), st["muted"])


# ===========================================================================
# Fleet Health
# ===========================================================================

FLEET_REPORT_TYPE = "Fleet Health Report"


def _fleet_overall_sev(summary: Dict[str, Any]) -> str:
    """Pick a banner severity from the worst-populated tier."""
    if summary.get("critical"):
        return "CRITICAL"
    if summary.get("at_risk"):
        return "HIGH"
    if summary.get("moderate"):
        return "MEDIUM"
    if summary.get("healthy"):
        return "LOW"
    return "NONE"


def _fleet_classification(summary: Dict[str, Any]) -> str:
    return {
        "CRITICAL": "Critical hosts present",
        "HIGH":     "At-risk hosts present",
        "MEDIUM":   "Moderate fleet posture",
        "LOW":      "Fleet healthy",
    }.get(_fleet_overall_sev(summary), "No hosts monitored")


def _fleet_rows_html(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return _html_none_block("No hosts to list.")
    body = []
    for r in rows:
        score = r.get("latest_score")
        score_str = "—" if score is None else str(int(score))
        body.append([
            _esc(r.get("hostname")) if r.get("hostname") else T.html_none(),
            ('<span class="rpt-mono">' + _esc(score_str) + '</span> '
             '<span class="rpt-none" style="font-style:normal;">('
             + _esc(r.get("latest_grade") or "?") + ')</span>'),
            T.html_pill(r.get("worst_severity") or "NONE"),
            '<span class="rpt-mono">' + _esc(r.get("scan_count")) + '</span>',
            '<span class="rpt-mono">' + _esc(r.get("total_findings")) + '</span>',
            ('<span class="rpt-mono">' + _esc(r.get("last_scan_at")) + '</span>'
             if r.get("last_scan_at") else T.html_none()),
            _html_tier_pill(r.get("tier")),
        ])
    return T.html_table(
        ["Host", "Score", "Worst Sev", "Scans", "Findings", "Last Scan", "Tier"],
        body, num_cols=[1, 3, 4])


def _fleet_rows_pdf(rows: List[Dict[str, Any]], st):
    if not rows:
        return _pdf_none("No hosts to list.", st)
    rl = T._rl()
    data = []
    for r in rows:
        score = r.get("latest_score")
        score_str = "—" if score is None else str(int(score))
        data.append([
            r.get("hostname") or "",
            "%s (%s)" % (score_str, r.get("latest_grade") or "?"),
            T.pdf_pill_para(r.get("worst_severity") or "NONE", st),
            str(r.get("scan_count") or 0),
            str(r.get("total_findings") or 0),
            (r.get("last_scan_at") or "")[:19] or "—",
            _pdf_tier_pill(r.get("tier"), st),
        ])
    return T.pdf_table(
        ["Host", "Score", "Worst Sev", "Scans", "Findings", "Last Scan", "Tier"],
        data, [96, 58, 56, 40, 50, 90, 122], st, mono_cols=[1, 3, 4, 5])


def render_fleet_health_html(payload: Dict[str, Any]) -> bytes:
    h = payload.get("header", {})
    s = payload.get("summary", {})
    footer = payload.get("footer") or {}
    overall = _fleet_overall_sev(s)

    body = T.html_eyebrow_title(FLEET_REPORT_TYPE.upper(), h.get("title") or FLEET_REPORT_TYPE)
    body += T.html_metadata_grid([
        ("Organization", _esc(payload.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Generated", _esc(h.get("generated_at"))),
    ])
    body += T.html_classification_banner(overall, _fleet_classification(s))

    # Fleet summary
    strip = _html_metric_strip([
        (s.get("total_hosts", 0), "Total hosts", None),
        (s.get("healthy", 0),     "Healthy",     "LOW"),
        (s.get("at_risk", 0),     "At risk",     "HIGH"),
        (s.get("critical", 0),    "Critical",    "CRITICAL"),
        (s.get("stale_count", 0), "Stale",       None),
    ])
    body += T.html_section("Fleet Summary", strip, overall)

    # All hosts
    body += T.html_section("All Monitored Hosts", _fleet_rows_html(payload.get("hosts", [])))

    at_risk = payload.get("at_risk_hosts", [])
    if at_risk:
        body += T.html_section("At-Risk Hosts", _fleet_rows_html(at_risk), "HIGH")

    stale = payload.get("stale_hosts", [])
    if stale:
        note = ('<div class="rpt-card-meta">No scan in the last '
                + _esc(h.get("stale_days", 7)) + ' days.</div>')
        body += T.html_section("Stale Hosts", note + _fleet_rows_html(stale))

    foot = T.html_callout(
        '<b>Pulse v' + _esc(footer.get("pulse_version")) + '.</b> '
        + _esc(footer.get("automated_note")))
    body += T.html_section("Notes", foot)

    return T.html_document(FLEET_REPORT_TYPE,
                           "Pulse — " + (h.get("title") or FLEET_REPORT_TYPE),
                           body).encode("utf-8")


def render_fleet_health_pdf(payload: Dict[str, Any]) -> bytes:
    from io import BytesIO
    rl = T._rl()
    Paragraph = rl["Paragraph"]
    st = T.pdf_styles()

    h = payload.get("header", {})
    s = payload.get("summary", {})
    footer = payload.get("footer") or {}
    overall = _fleet_overall_sev(s)

    story: list = []
    story.append(Paragraph(FLEET_REPORT_TYPE.upper(), st["eyebrow"]))
    story.append(Paragraph(_esc(h.get("title") or FLEET_REPORT_TYPE), st["title"]))
    story.append(T.pdf_spacer(10))
    story.append(T.pdf_metadata_grid([
        ("Organization", _esc(payload.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Generated", _esc(h.get("generated_at"))),
    ], st))
    story.append(T.pdf_spacer(12))
    story.append(T.pdf_banner(overall, _fleet_classification(s), st))
    story.append(T.pdf_spacer(8))

    story.append(T.pdf_section("Fleet Summary", st, overall))
    story.append(T.pdf_spacer(4))
    story.append(_pdf_metric_strip([
        (s.get("total_hosts", 0), "Total hosts", None),
        (s.get("healthy", 0),     "Healthy",     "LOW"),
        (s.get("at_risk", 0),     "At risk",     "HIGH"),
        (s.get("critical", 0),    "Critical",    "CRITICAL"),
        (s.get("stale_count", 0), "Stale",       None),
    ], st))
    story.append(T.pdf_spacer(8))

    story.append(T.pdf_section("All Monitored Hosts", st))
    story.append(T.pdf_spacer(4))
    story.append(_fleet_rows_pdf(payload.get("hosts", []), st))
    story.append(T.pdf_spacer(8))

    at_risk = payload.get("at_risk_hosts", [])
    if at_risk:
        story.append(T.pdf_section("At-Risk Hosts", st, "HIGH"))
        story.append(T.pdf_spacer(4))
        story.append(_fleet_rows_pdf(at_risk, st))
        story.append(T.pdf_spacer(8))

    stale = payload.get("stale_hosts", [])
    if stale:
        story.append(T.pdf_section("Stale Hosts", st))
        story.append(T.pdf_spacer(4))
        story.append(Paragraph(
            '<font color="%s">No scan in the last %s days.</font>'
            % (T.C_MUTED, _esc(h.get("stale_days", 7))), st["muted"]))
        story.append(T.pdf_spacer(3))
        story.append(_fleet_rows_pdf(stale, st))
        story.append(T.pdf_spacer(8))

    story.append(T.pdf_section("Notes", st))
    story.append(T.pdf_spacer(4))
    story.append(T.pdf_callout([Paragraph(
        '<b>Pulse v' + _esc(footer.get("pulse_version")) + '.</b> '
        + _esc(footer.get("automated_note")), st["body"])], st))

    buf = BytesIO()
    doc, canvasmaker = T.new_doc(buf, "Pulse Fleet Health Report", FLEET_REPORT_TYPE)
    doc.build(story, canvasmaker=canvasmaker)
    return buf.getvalue()


def render_fleet_health_json(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def render_fleet_health_csv(payload: Dict[str, Any]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["hostname", "latest_score", "latest_grade",
                 "worst_severity", "scan_count", "total_findings",
                 "last_scan_at", "tier", "stale"])
    for r in payload.get("hosts", []):
        w.writerow([
            r.get("hostname"), r.get("latest_score"),
            r.get("latest_grade"), r.get("worst_severity"),
            r.get("scan_count"), r.get("total_findings"),
            r.get("last_scan_at"), r.get("tier"),
            "yes" if r.get("stale") else "no",
        ])
    return buf.getvalue().encode("utf-8-sig")


# ===========================================================================
# Board-Ready Posture
# ===========================================================================

BOARD_REPORT_TYPE = "Board-Ready Posture Report"


def _trend_line(trend: Dict[str, Any]) -> str:
    delta = trend.get("delta")
    if trend.get("direction") == "first_period":
        return "First period observed"
    verb = ("Improved" if (delta or 0) > 0
            else "Declined" if (delta or 0) < 0 else "Stable")
    return "%s by %d points vs. prior period" % (verb, abs(int(delta or 0)))


def _trend_chart_svg(points: List[Dict[str, Any]],
                     *, width: int = 720, height: int = 140) -> str:
    """Inline SVG line chart for the trend points. No external deps;
    survives print and offline viewing."""
    if not points:
        return _html_none_block("No trend data available.")
    if len(points) == 1:
        return _html_none_block(
            "One data point in this period: score %s on %s."
            % (points[0]["score"], points[0]["timestamp"]))
    n = len(points)
    margin_x = 30
    margin_y = 20
    inner_w = width - margin_x * 2
    inner_h = height - margin_y * 2
    step = inner_w / (n - 1)
    scores = [p["score"] for p in points]
    min_s = max(0, min(scores) - 10)
    max_s = min(100, max(scores) + 10)
    span = max(1, max_s - min_s)

    def y_for(s):
        return margin_y + (1 - (s - min_s) / span) * inner_h

    coords = [(margin_x + i * step, y_for(p["score"])) for i, p in enumerate(points)]
    poly = " ".join("%.1f,%.1f" % (x, y) for x, y in coords)
    dots = "".join('<circle cx="%.1f" cy="%.1f" r="3" fill="%s"/>' % (x, y, T.C_ACCENT)
                   for x, y in coords)
    grid = ""
    for sline in (25, 50, 75, 100):
        if not min_s <= sline <= max_s:
            continue
        y = y_for(sline)
        grid += (
            '<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="%s" stroke-width="1"/>'
            % (margin_x, y, margin_x + inner_w, y, T.C_BORDER)
            + '<text x="%d" y="%.1f" font-size="9" fill="%s" text-anchor="end">%d</text>'
            % (margin_x - 4, y + 3, T.C_FAINT, sline))
    return (
        '<svg viewBox="0 0 %d %d" preserveAspectRatio="xMidYMid meet" '
        'style="width:100%%; height:%dpx;">' % (width, height, height)
        + grid
        + '<polyline points="%s" fill="none" stroke="%s" stroke-width="2"/>'
        % (poly, T.C_ACCENT)
        + dots
        + '<text x="%d" y="%d" font-size="10" fill="%s">%s</text>'
        % (margin_x, height - 4, T.C_MUTED, _esc(points[0]["timestamp"]))
        + '<text x="%d" y="%d" font-size="10" text-anchor="end" fill="%s">%s</text>'
        % (margin_x + inner_w, height - 4, T.C_MUTED, _esc(points[-1]["timestamp"]))
        + '</svg>')


def render_board_ready_html(payload: Dict[str, Any]) -> bytes:
    h = payload["header"]
    p = payload["posture"]
    a = payload["activity"]
    c = payload["compliance"]
    f = payload["fleet_summary"]
    footer = payload.get("footer") or {}
    grade = p.get("grade") or "?"
    gsev = _grade_sev(grade)
    score = p.get("score")
    score_str = "—" if score is None else str(int(score))

    body = T.html_eyebrow_title(BOARD_REPORT_TYPE.upper(), h.get("title") or BOARD_REPORT_TYPE)
    body += T.html_metadata_grid([
        ("Organization", _esc(payload.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Generated", _esc(h.get("generated_at"))),
    ])
    body += T.html_classification_banner(
        gsev, "Posture grade " + _esc(grade) + " — " + _esc(p.get("interpretation")))

    # Security posture — grade dial + verdict callout
    dial = (
        '<div style="display:flex; align-items:center; gap:16px;">'
        '<div style="width:64px; height:64px; border-radius:50%; flex:none; background:'
        + T.SEV_FG[T.sev_key(gsev)] + '; color:#fff; display:flex; align-items:center;'
        ' justify-content:center; font-size:30px; font-weight:800;">' + _esc(grade) + '</div>'
        '<div><div class="rpt-callout-verdict">' + _esc(grade) + ' — '
        + _esc(p.get("interpretation")) + '</div>'
        '<div class="rpt-card-meta">Overall score: <b>' + _esc(score_str)
        + '</b> out of 100 &nbsp;·&nbsp; ' + _esc(_trend_line(p.get("trend") or {})) + '</div>'
        '</div></div>')
    body += T.html_section("Security Posture", T.html_callout(dial, gsev), gsev)

    # Score trend
    body += T.html_section("Score Trend", _trend_chart_svg(payload.get("trend_points", [])))

    # Fleet overview
    body += T.html_section("Fleet Overview", _html_metric_strip([
        (f.get("total_hosts", 0), "Total hosts", None),
        (f.get("healthy", 0),     "Healthy",     "LOW"),
        (f.get("at_risk", 0),     "At risk",     "HIGH"),
        (f.get("critical", 0),    "Critical",    "CRITICAL"),
        (f.get("stale_count", 0), "Stale",       None),
    ]))

    # Compliance coverage
    body += T.html_section("Compliance Coverage", _html_metric_strip([
        (str(c["nist_csf"]["coverage_percent"]) + "%", "NIST CSF", None),
        (c["nist_csf"]["rules_enabled"],               "NIST rules enabled", None),
        (str(c["iso_27001"]["coverage_percent"]) + "%", "ISO 27001", None),
        (c["iso_27001"]["rules_enabled"],              "ISO rules enabled", None),
    ]))

    # Activity this period
    body += T.html_section("Activity This Period", _html_metric_strip([
        (a.get("total_issues", 0), "Total issues", None),
        (a.get("open", 0),         "Open",         None),
        (a.get("resolved", 0),     "Resolved",     None),
        (a["by_severity"]["CRITICAL"], "Critical", "CRITICAL"),
    ]))

    # Strategic recommendations
    recs = payload.get("recommendations", [])
    if recs:
        items = "".join('<li style="margin-bottom:5px;">' + _esc(line) + '</li>' for line in recs)
        rec_html = '<ol style="font-size:10.5px; line-height:1.6; padding-left:20px; margin:4px 0;">' + items + '</ol>'
    else:
        rec_html = _html_none_block("No recommendations generated.")
    body += T.html_section("Strategic Recommendations", rec_html)

    foot = T.html_callout(
        '<b>Pulse v' + _esc(footer.get("pulse_version")) + '.</b> '
        + _esc(footer.get("automated_note")))
    body += T.html_section("Notes", foot)

    return T.html_document(BOARD_REPORT_TYPE,
                           "Pulse — " + (h.get("title") or BOARD_REPORT_TYPE),
                           body).encode("utf-8")


def render_board_ready_pdf(payload: Dict[str, Any]) -> bytes:
    from io import BytesIO
    rl = T._rl()
    Paragraph = rl["Paragraph"]
    Flowable = rl["Flowable"]
    C = rl["colors"].HexColor
    inch = rl["inch"]
    st = T.pdf_styles()

    h = payload["header"]
    p = payload["posture"]
    a = payload["activity"]
    c = payload["compliance"]
    f = payload["fleet_summary"]
    footer = payload.get("footer") or {}
    grade = p.get("grade") or "?"
    gsev = _grade_sev(grade)
    grade_color = C(T.SEV_FG[T.sev_key(gsev)])
    score = p.get("score")
    score_str = "—" if score is None else str(int(score))

    story: list = []
    story.append(Paragraph(BOARD_REPORT_TYPE.upper(), st["eyebrow"]))
    story.append(Paragraph(_esc(h.get("title") or BOARD_REPORT_TYPE), st["title"]))
    story.append(T.pdf_spacer(10))
    story.append(T.pdf_metadata_grid([
        ("Organization", _esc(payload.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Generated", _esc(h.get("generated_at"))),
    ], st))
    story.append(T.pdf_spacer(12))
    story.append(T.pdf_banner(
        gsev, "Posture grade %s — %s" % (_esc(grade), _esc(p.get("interpretation"))), st))
    story.append(T.pdf_spacer(8))

    # Security posture — grade circle + verdict inside a callout
    class _Circle(Flowable):
        def wrap(self, *a):
            return (0.7 * inch, 0.7 * inch)

        def draw(self):
            cv = self.canv
            r = 0.35 * inch
            cv.saveState()
            cv.setFillColor(grade_color)
            cv.circle(r, r, r, stroke=0, fill=1)
            cv.setFillColorRGB(1, 1, 1)
            cv.setFont("Helvetica-Bold", 22)
            cv.drawCentredString(r, r - 8, grade)
            cv.restoreState()

    verdict_col = [
        Paragraph("%s &mdash; %s" % (_esc(grade), _esc(p.get("interpretation"))), st["verdict"]),
        Paragraph("Overall score: <b>%s</b> out of 100" % _esc(score_str), st["body"]),
        Paragraph(_esc(_trend_line(p.get("trend") or {})), st["muted"]),
    ]
    dial = rl["Table"]([[_Circle(), verdict_col]],
                       colWidths=[0.8 * inch, T.CONTENT_W - 0.8 * inch - 24])
    dial.setStyle(rl["TableStyle"]([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 10),
    ]))
    story.append(T.pdf_section("Security Posture", st, gsev))
    story.append(T.pdf_spacer(4))
    story.append(T.pdf_callout([dial], st, gsev))
    story.append(T.pdf_spacer(8))

    # Score trend (text summary — SVG charts are HTML-only)
    story.append(T.pdf_section("Score Trend", st))
    story.append(T.pdf_spacer(4))
    tps = payload.get("trend_points", [])
    if tps:
        trow = [[tp.get("timestamp") or "—", str(tp.get("score"))] for tp in tps]
        story.append(T.pdf_table(["Date", "Score"], trow,
                                 [T.CONTENT_W - 90, 90], st, mono_cols=[0, 1]))
    else:
        story.append(_pdf_none("No trend data available.", st))
    story.append(T.pdf_spacer(8))

    # Fleet overview
    story.append(T.pdf_section("Fleet Overview", st))
    story.append(T.pdf_spacer(4))
    story.append(_pdf_metric_strip([
        (f.get("total_hosts", 0), "Total hosts", None),
        (f.get("healthy", 0),     "Healthy",     "LOW"),
        (f.get("at_risk", 0),     "At risk",     "HIGH"),
        (f.get("critical", 0),    "Critical",    "CRITICAL"),
        (f.get("stale_count", 0), "Stale",       None),
    ], st))
    story.append(T.pdf_spacer(8))

    # Compliance coverage
    story.append(T.pdf_section("Compliance Coverage", st))
    story.append(T.pdf_spacer(4))
    story.append(_pdf_metric_strip([
        ("%s%%" % c["nist_csf"]["coverage_percent"], "NIST CSF", None),
        (c["nist_csf"]["rules_enabled"],             "NIST rules", None),
        ("%s%%" % c["iso_27001"]["coverage_percent"], "ISO 27001", None),
        (c["iso_27001"]["rules_enabled"],            "ISO rules", None),
    ], st))
    story.append(T.pdf_spacer(8))

    # Activity this period
    story.append(T.pdf_section("Activity This Period", st))
    story.append(T.pdf_spacer(4))
    story.append(_pdf_metric_strip([
        (a.get("total_issues", 0), "Total issues", None),
        (a.get("open", 0),         "Open",         None),
        (a.get("resolved", 0),     "Resolved",     None),
        (a["by_severity"]["CRITICAL"], "Critical", "CRITICAL"),
    ], st))
    story.append(T.pdf_spacer(8))

    # Strategic recommendations
    story.append(T.pdf_section("Strategic Recommendations", st))
    story.append(T.pdf_spacer(4))
    recs = payload.get("recommendations", [])
    if recs:
        for i, line in enumerate(recs, start=1):
            story.append(Paragraph("<b>%d.</b> &nbsp;%s" % (i, _esc(line)), st["body"]))
            story.append(T.pdf_spacer(3))
    else:
        story.append(_pdf_none("No recommendations generated.", st))
    story.append(T.pdf_spacer(6))

    # Notes
    story.append(T.pdf_section("Notes", st))
    story.append(T.pdf_spacer(4))
    story.append(T.pdf_callout([Paragraph(
        '<b>Pulse v' + _esc(footer.get("pulse_version")) + '.</b> '
        + _esc(footer.get("automated_note")), st["body"])], st))

    buf = BytesIO()
    doc, canvasmaker = T.new_doc(buf, "Pulse Board-Ready Posture Report", BOARD_REPORT_TYPE)
    doc.build(story, canvasmaker=canvasmaker)
    return buf.getvalue()


def render_board_ready_json(payload):
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def render_board_ready_csv(payload):
    buf = io.StringIO()
    w = csv.writer(buf)
    p = payload["posture"]
    a = payload["activity"]
    c = payload["compliance"]
    f = payload["fleet_summary"]
    w.writerow(["section", "field", "value"])
    w.writerow(["posture", "score", p.get("score") if p.get("score") is not None else ""])
    w.writerow(["posture", "grade", p.get("grade")])
    w.writerow(["posture", "interpretation", p.get("interpretation")])
    w.writerow(["posture", "trend_direction", (p.get("trend") or {}).get("direction")])
    w.writerow(["posture", "trend_delta", (p.get("trend") or {}).get("delta") or ""])
    for k, v in (a.get("by_severity") or {}).items():
        w.writerow(["activity_severity", k, v])
    for fr in ("nist_csf", "iso_27001"):
        w.writerow([fr, "coverage_percent", c[fr]["coverage_percent"]])
        w.writerow([fr, "rules_enabled",    c[fr]["rules_enabled"]])
    for k in ("total_hosts", "healthy", "at_risk", "critical", "stale_count"):
        w.writerow(["fleet", k, f.get(k, 0)])
    w.writerow([])
    w.writerow(["trend_point", "timestamp", "score"])
    for tp in payload.get("trend_points", []):
        w.writerow(["trend_point", tp.get("timestamp"), tp.get("score")])
    w.writerow([])
    w.writerow(["recommendation", "rank", "action"])
    for i, line in enumerate(payload.get("recommendations", []), start=1):
        w.writerow(["recommendation", i, line])
    return buf.getvalue().encode("utf-8-sig")


# ===========================================================================
# MITRE ATT&CK Coverage
# ===========================================================================

MITRE_REPORT_TYPE = "MITRE ATT&CK Coverage Report"


def render_mitre_coverage_html(payload: Dict[str, Any]) -> bytes:
    h = payload["header"]
    s = payload["summary"]
    matrix = payload.get("matrix", [])
    footer = payload.get("footer") or {}

    body = T.html_eyebrow_title(MITRE_REPORT_TYPE.upper(), h.get("title") or MITRE_REPORT_TYPE)
    body += T.html_metadata_grid([
        ("Organization", _esc(payload.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Generated", _esc(h.get("generated_at"))),
    ])

    body += T.html_section("Coverage Summary", _html_metric_strip([
        (s.get("technique_count", 0),        "Techniques mapped", None),
        (s.get("active_technique_count", 0), "Active techniques", None),
        (s.get("covered_tactic_count", 0),   "Tactics with coverage", None),
        (s.get("total_findings", 0),         "Findings", None),
    ]))

    # Coverage matrix — one table per tactic that carries techniques
    matrix_html = ""
    for row in matrix:
        if row["technique_count"] == 0:
            continue
        trows = [[
            '<span class="rpt-mono">' + _esc(t["technique"]) + '</span>',
            (", ".join(_esc(r) for r in t["rules"]) if t["rules"] else T.html_none()),
            '<span class="rpt-mono">' + _esc(t["findings_count"]) + '</span>',
        ] for t in row["techniques"]]
        meta = ('<div class="rpt-card-meta"><b>' + _esc(row["tactic"]) + '</b> &nbsp;·&nbsp; '
                + _esc(row["technique_count"]) + ' technique(s), '
                + _esc(row["findings_count"]) + ' finding(s)</div>')
        matrix_html += meta + T.html_table(["Technique", "Mapped Rules", "Findings"],
                                           trows, num_cols=[2])
    body += T.html_section("Coverage Matrix",
                           matrix_html or _html_none_block("No techniques mapped."))

    # Top triggered techniques
    top = payload.get("top_techniques", [])
    if top:
        trows = [[
            '<span class="rpt-mono">' + _esc(t["technique"]) + '</span>',
            _esc(t["tactic"]),
            '<span class="rpt-mono">' + _esc(t["findings_count"]) + '</span>',
        ] for t in top]
        body += T.html_section("Top Triggered Techniques",
                               T.html_table(["Technique", "Tactic", "Findings"],
                                            trows, num_cols=[2]))

    if payload.get("uncovered_tactics"):
        rows = [[_esc(t)] for t in payload["uncovered_tactics"]]
        body += T.html_section("Tactics Without Coverage",
                               T.html_table(["Tactic"], rows))

    if payload.get("silent_tactics"):
        note = ('<div class="rpt-card-meta">These tactics have at least one mapped '
                'rule but no findings in the reporting period.</div>')
        rows = [[_esc(t)] for t in payload["silent_tactics"]]
        body += T.html_section("Tactics With Detection But No Activity",
                               note + T.html_table(["Tactic"], rows))

    foot = T.html_callout(
        '<b>Pulse v' + _esc(footer.get("pulse_version")) + '.</b> '
        + _esc(footer.get("automated_note")))
    body += T.html_section("Notes", foot)

    return T.html_document(MITRE_REPORT_TYPE,
                           "Pulse — " + (h.get("title") or MITRE_REPORT_TYPE),
                           body).encode("utf-8")


def render_mitre_coverage_pdf(payload: Dict[str, Any]) -> bytes:
    from io import BytesIO
    rl = T._rl()
    Paragraph = rl["Paragraph"]
    st = T.pdf_styles()

    h = payload["header"]
    s = payload["summary"]
    footer = payload.get("footer") or {}

    story: list = []
    story.append(Paragraph(MITRE_REPORT_TYPE.upper(), st["eyebrow"]))
    story.append(Paragraph(_esc(h.get("title") or MITRE_REPORT_TYPE), st["title"]))
    story.append(T.pdf_spacer(10))
    story.append(T.pdf_metadata_grid([
        ("Organization", _esc(payload.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Generated", _esc(h.get("generated_at"))),
    ], st))
    story.append(T.pdf_spacer(12))

    story.append(T.pdf_section("Coverage Summary", st))
    story.append(T.pdf_spacer(4))
    story.append(_pdf_metric_strip([
        (s.get("technique_count", 0),        "Techniques mapped", None),
        (s.get("active_technique_count", 0), "Active techniques", None),
        (s.get("covered_tactic_count", 0),   "Tactics covered", None),
        (s.get("total_findings", 0),         "Findings", None),
    ], st))
    story.append(T.pdf_spacer(8))

    story.append(T.pdf_section("Coverage Matrix", st))
    story.append(T.pdf_spacer(4))
    matrix = payload.get("matrix", [])
    any_tactic = False
    for row in matrix:
        if row["technique_count"] == 0:
            continue
        any_tactic = True
        story.append(Paragraph(
            '<b>%s</b> &nbsp;&middot;&nbsp; %s technique(s), %s finding(s)'
            % (_esc(row["tactic"]), _esc(row["technique_count"]),
               _esc(row["findings_count"])), st["muted"]))
        story.append(T.pdf_spacer(2))
        trows = [[
            t["technique"],
            ", ".join(_esc(r) for r in t["rules"]) if t["rules"] else "—",
            str(t["findings_count"]),
        ] for t in row["techniques"]]
        story.append(T.pdf_table(["Technique", "Rules", "Findings"], trows,
                                 [80, T.CONTENT_W - 130, 50], st, mono_cols=[0]))
        story.append(T.pdf_spacer(7))
    if not any_tactic:
        story.append(_pdf_none("No techniques mapped.", st))
    story.append(T.pdf_spacer(2))

    top = payload.get("top_techniques", [])
    if top:
        story.append(T.pdf_section("Top Triggered Techniques", st))
        story.append(T.pdf_spacer(4))
        trows = [[t["technique"], t["tactic"], str(t["findings_count"])] for t in top]
        story.append(T.pdf_table(["Technique", "Tactic", "Findings"], trows,
                                 [90, T.CONTENT_W - 150, 60], st, mono_cols=[0]))
        story.append(T.pdf_spacer(8))

    if payload.get("uncovered_tactics"):
        story.append(T.pdf_section("Tactics Without Coverage", st))
        story.append(T.pdf_spacer(4))
        story.append(T.pdf_table(["Tactic"], [[t] for t in payload["uncovered_tactics"]],
                                 [T.CONTENT_W], st))
        story.append(T.pdf_spacer(8))

    if payload.get("silent_tactics"):
        story.append(T.pdf_section("Tactics With Detection But No Activity", st))
        story.append(T.pdf_spacer(4))
        story.append(Paragraph(
            '<font color="%s">These tactics have at least one mapped rule but no '
            'findings in the reporting period.</font>' % T.C_MUTED, st["muted"]))
        story.append(T.pdf_spacer(3))
        story.append(T.pdf_table(["Tactic"], [[t] for t in payload["silent_tactics"]],
                                 [T.CONTENT_W], st))
        story.append(T.pdf_spacer(8))

    story.append(T.pdf_section("Notes", st))
    story.append(T.pdf_spacer(4))
    story.append(T.pdf_callout([Paragraph(
        '<b>Pulse v' + _esc(footer.get("pulse_version")) + '.</b> '
        + _esc(footer.get("automated_note")), st["body"])], st))

    buf = BytesIO()
    doc, canvasmaker = T.new_doc(buf, "Pulse MITRE ATT&CK Coverage Report", MITRE_REPORT_TYPE)
    doc.build(story, canvasmaker=canvasmaker)
    return buf.getvalue()


def render_mitre_coverage_json(payload):
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def render_mitre_coverage_csv(payload):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["tactic", "technique", "rule", "findings_count"])
    for row in payload.get("matrix", []):
        for t in row["techniques"]:
            for rule in t["rules"]:
                w.writerow([row["tactic"], t["technique"], rule,
                             t["findings_count"]])
    return buf.getvalue().encode("utf-8-sig")


# ===========================================================================
# Compliance Gap Analysis
# ===========================================================================

COMPLIANCE_REPORT_TYPE = "Compliance Gap Analysis"


def render_compliance_gap_html(payload: Dict[str, Any]) -> bytes:
    h = payload["header"]
    s = payload["summary"]
    defs = payload["definitions"]
    footer = payload.get("footer") or {}

    body = T.html_eyebrow_title(COMPLIANCE_REPORT_TYPE.upper(),
                                h.get("title") or COMPLIANCE_REPORT_TYPE)
    body += T.html_metadata_grid([
        ("Organization", _esc(payload.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Generated", _esc(h.get("generated_at"))),
    ])

    body += T.html_section("Summary", _html_metric_strip([
        (s.get("total_improvements", 0), "Total improvement items", None),
        (s.get("uncovered_count", 0),    "Uncovered techniques", None),
        (s.get("silent_count", 0),       "Silent rules", None),
        (s.get("noisy_count", 0),        "Noisy rules", None),
    ]))

    # Uncovered techniques
    uncov = payload.get("uncovered_techniques", [])
    if uncov:
        rows = [[
            '<span class="rpt-mono">' + _esc(u["technique"]) + '</span>',
            _esc(u["tactic"]),
            _esc(u["action"]),
        ] for u in uncov]
        inner = T.html_table(["Technique", "Tactic", "Action"], rows)
    else:
        inner = _html_none_block("All known techniques have at least one enabled rule.")
    body += T.html_section("Uncovered MITRE Techniques", inner)

    # Silent rules
    silent = payload.get("silent_rules", [])
    note = '<div class="rpt-card-meta">' + _esc(defs["silent_rules"]) + '</div>'
    if silent:
        rows = [[
            _esc(r["rule"]),
            T.html_pill(r.get("severity")),
            ('<span class="rpt-mono">' + _esc(r.get("mitre")) + '</span>'
             if r.get("mitre") else T.html_none()),
            _esc(r["action"]),
        ] for r in silent]
        inner = T.html_table(["Rule", "Severity", "MITRE", "Action"], rows)
    else:
        inner = _html_none_block("No silent rules.")
    body += T.html_section("Silent Rules", note + inner)

    # Noisy rules
    noisy = payload.get("noisy_rules", [])
    note = '<div class="rpt-card-meta">' + _esc(defs["noisy_rules"]) + '</div>'
    if noisy:
        rows = [[
            _esc(r["rule"]),
            T.html_pill(r.get("severity")),
            '<span class="rpt-mono">' + _esc(r["fp_rate"]) + '%</span>',
            '<span class="rpt-mono">' + _esc(r["hits_total"]) + '</span>',
            _esc(r["action"]),
        ] for r in noisy]
        inner = T.html_table(["Rule", "Severity", "FP Rate", "Total Hits", "Action"],
                             rows, num_cols=[2, 3])
    else:
        inner = _html_none_block("No noisy rules.")
    body += T.html_section("Noisy Rules", note + inner)

    foot = T.html_callout(
        '<b>Pulse v' + _esc(footer.get("pulse_version")) + '.</b> '
        + _esc(footer.get("automated_note")))
    body += T.html_section("Notes", foot)

    return T.html_document(COMPLIANCE_REPORT_TYPE,
                           "Pulse — " + (h.get("title") or COMPLIANCE_REPORT_TYPE),
                           body).encode("utf-8")


def render_compliance_gap_pdf(payload: Dict[str, Any]) -> bytes:
    from io import BytesIO
    rl = T._rl()
    Paragraph = rl["Paragraph"]
    st = T.pdf_styles()

    h = payload["header"]
    s = payload["summary"]
    defs = payload["definitions"]
    footer = payload.get("footer") or {}

    story: list = []
    story.append(Paragraph(COMPLIANCE_REPORT_TYPE.upper(), st["eyebrow"]))
    story.append(Paragraph(_esc(h.get("title") or COMPLIANCE_REPORT_TYPE), st["title"]))
    story.append(T.pdf_spacer(10))
    story.append(T.pdf_metadata_grid([
        ("Organization", _esc(payload.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Generated", _esc(h.get("generated_at"))),
    ], st))
    story.append(T.pdf_spacer(12))

    story.append(T.pdf_section("Summary", st))
    story.append(T.pdf_spacer(4))
    story.append(_pdf_metric_strip([
        (s.get("total_improvements", 0), "Total items", None),
        (s.get("uncovered_count", 0),    "Uncovered",   None),
        (s.get("silent_count", 0),       "Silent",      None),
        (s.get("noisy_count", 0),        "Noisy",       None),
    ], st))
    story.append(T.pdf_spacer(8))

    # Uncovered techniques
    story.append(T.pdf_section("Uncovered MITRE Techniques", st))
    story.append(T.pdf_spacer(4))
    uncov = payload.get("uncovered_techniques", [])
    if uncov:
        rows = [[u["technique"], u["tactic"], u["action"]] for u in uncov]
        story.append(T.pdf_table(["Technique", "Tactic", "Action"], rows,
                                 [70, 90, T.CONTENT_W - 160], st, mono_cols=[0]))
    else:
        story.append(_pdf_none("All known techniques have at least one enabled rule.", st))
    story.append(T.pdf_spacer(8))

    # Silent rules
    story.append(T.pdf_section("Silent Rules", st))
    story.append(T.pdf_spacer(4))
    story.append(Paragraph('<font color="%s">%s</font>' % (T.C_MUTED, _esc(defs["silent_rules"])),
                           st["muted"]))
    story.append(T.pdf_spacer(3))
    silent = payload.get("silent_rules", [])
    if silent:
        rows = [[
            r["rule"],
            T.pdf_pill_para(r.get("severity"), st),
            r.get("mitre") or "—",
            r["action"],
        ] for r in silent]
        story.append(T.pdf_table(["Rule", "Severity", "MITRE", "Action"], rows,
                                 [110, 56, 60, T.CONTENT_W - 226], st, mono_cols=[2]))
    else:
        story.append(_pdf_none("No silent rules.", st))
    story.append(T.pdf_spacer(8))

    # Noisy rules
    story.append(T.pdf_section("Noisy Rules", st))
    story.append(T.pdf_spacer(4))
    story.append(Paragraph('<font color="%s">%s</font>' % (T.C_MUTED, _esc(defs["noisy_rules"])),
                           st["muted"]))
    story.append(T.pdf_spacer(3))
    noisy = payload.get("noisy_rules", [])
    if noisy:
        rows = [[
            r["rule"],
            T.pdf_pill_para(r.get("severity"), st),
            "%s%%" % r["fp_rate"],
            str(r["hits_total"]),
            r["action"],
        ] for r in noisy]
        story.append(T.pdf_table(["Rule", "Severity", "FP Rate", "Hits", "Action"], rows,
                                 [96, 56, 46, 40, T.CONTENT_W - 238], st, mono_cols=[2, 3]))
    else:
        story.append(_pdf_none("No noisy rules.", st))
    story.append(T.pdf_spacer(8))

    story.append(T.pdf_section("Notes", st))
    story.append(T.pdf_spacer(4))
    story.append(T.pdf_callout([Paragraph(
        '<b>Pulse v' + _esc(footer.get("pulse_version")) + '.</b> '
        + _esc(footer.get("automated_note")), st["body"])], st))

    buf = BytesIO()
    doc, canvasmaker = T.new_doc(buf, "Pulse Compliance Gap Analysis", COMPLIANCE_REPORT_TYPE)
    doc.build(story, canvasmaker=canvasmaker)
    return buf.getvalue()


def render_compliance_gap_json(payload):
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def render_compliance_gap_csv(payload):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["kind", "id", "details", "action"])
    for u in payload.get("uncovered_techniques", []):
        w.writerow(["uncovered_technique", u["technique"],
                     f"tactic={u['tactic']}", u["action"]])
    for r in payload.get("silent_rules", []):
        w.writerow(["silent_rule", r["rule"],
                     f"severity={r.get('severity')}; mitre={r.get('mitre') or ''}",
                     r["action"]])
    for r in payload.get("noisy_rules", []):
        w.writerow(["noisy_rule", r["rule"],
                     f"fp_rate={r['fp_rate']}%; hits={r['hits_total']}",
                     r["action"]])
    return buf.getvalue().encode("utf-8-sig")


# ---------------------------------------------------------------------------
# Per-template dispatchers
# ---------------------------------------------------------------------------

_FLEET_HEALTH = {
    "json": render_fleet_health_json,
    "csv":  render_fleet_health_csv,
    "html": render_fleet_health_html,
    "pdf":  render_fleet_health_pdf,
}
_BOARD_READY = {
    "json": render_board_ready_json,
    "csv":  render_board_ready_csv,
    "html": render_board_ready_html,
    "pdf":  render_board_ready_pdf,
}
_MITRE_COVERAGE = {
    "json": render_mitre_coverage_json,
    "csv":  render_mitre_coverage_csv,
    "html": render_mitre_coverage_html,
    "pdf":  render_mitre_coverage_pdf,
}
_COMPLIANCE_GAP = {
    "json": render_compliance_gap_json,
    "csv":  render_compliance_gap_csv,
    "html": render_compliance_gap_html,
    "pdf":  render_compliance_gap_pdf,
}


def _render(disp, payload, fmt):
    fmt = (fmt or "").lower()
    if fmt not in disp:
        raise ValueError(
            f"unknown format {fmt!r}; expected one of {sorted(disp)}"
        )
    return disp[fmt](payload)


def render_fleet_health(payload, fmt):    return _render(_FLEET_HEALTH, payload, fmt)
def render_board_ready(payload, fmt):     return _render(_BOARD_READY, payload, fmt)
def render_mitre_coverage(payload, fmt):  return _render(_MITRE_COVERAGE, payload, fmt)
def render_compliance_gap(payload, fmt):  return _render(_COMPLIANCE_GAP, payload, fmt)
