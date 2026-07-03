"""Format renderers for the Executive Summary payload.

PDF + HTML are the load-bearing formats here: this report gets shared
and printed and forwarded to people who don't open the dashboard. JSON
and CSV are included for completeness (SIEM ingestion and spreadsheet
crunching, respectively) but they're not where the polish lives.

Editorial notes that drive the layout choices:
    - Light theme everywhere. Dark themes don't print well; the people
      who get this report sometimes print it.
    - Generous whitespace and a single load-bearing visual element per
      section. The reader scans for the grade, the narrative paragraph,
      and the recommendations list. Tables only when truly needed.
    - The grade letter is the cover element. Large, centered, color-
      coded. Everything else follows.
"""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Any, Dict

import pulse.reports.report_theme as T

REPORT_TYPE = "Executive Security Summary"

# Map the posture grade to a severity key the shared theme understands, so
# the classification banner / section accents pick up a sensible color. A/B
# read as healthy (low/none), C as moderate, D/F as high/critical.
_GRADE_SEV = {
    "A": "NONE", "B": "LOW", "C": "MEDIUM", "D": "HIGH", "F": "CRITICAL",
    "?": "NONE",
}
_GRADE_BANNER = {
    "A": "Strong security posture",
    "B": "Healthy posture",
    "C": "Several issues need attention",
    "D": "Multiple high-impact risks",
    "F": "Critical risks — immediate action required",
    "?": "No completed scans in period",
}


def _esc(s: Any) -> str:
    return html.escape(str(s) if s is not None else "")


# ---------------------------------------------------------------------------
# JSON — straight serialization, the SIEM-ingest format.
# ---------------------------------------------------------------------------

def render_json(summary: Dict[str, Any]) -> bytes:
    return json.dumps(summary, indent=2, sort_keys=False,
                       default=str).encode("utf-8")


# ---------------------------------------------------------------------------
# CSV — flat key/value pairs + Top Risks rows. The Executive Summary
# isn't a tabular dataset, but a flat KV dump is what a spreadsheet
# user expects ("paste this section into the quarterly compliance
# tracker"). The Top Risks land as their own block at the bottom.
# ---------------------------------------------------------------------------

def render_csv(summary: Dict[str, Any]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    h = summary.get("header", {})
    p = summary.get("posture", {})
    a = summary.get("activity", {})
    c = summary.get("what_changed", {})

    w.writerow(["section", "field", "value"])
    w.writerow(["header", "title", h.get("title", "")])
    w.writerow(["header", "organization", h.get("organization", "")])
    w.writerow(["header", "scope", h.get("scope", "")])
    w.writerow(["header", "generated_at", h.get("generated_at", "")])

    w.writerow(["posture", "grade", p.get("grade", "")])
    w.writerow(["posture", "score", p.get("score") if p.get("score") is not None else ""])
    w.writerow(["posture", "interpretation", p.get("interpretation", "")])
    w.writerow(["posture", "trend_direction", (p.get("trend") or {}).get("direction", "")])
    w.writerow(["posture", "trend_delta",     (p.get("trend") or {}).get("delta") or ""])

    w.writerow(["narrative", "what_this_means", summary.get("what_this_means", "")])

    for key in ("total_issues", "open", "resolved",
                 "machines_monitored", "machines_at_risk"):
        w.writerow(["activity", key, a.get(key, 0)])
    for sev, n in (a.get("by_severity") or {}).items():
        w.writerow(["activity_severity", sev, n])

    for key in ("issues_delta", "score_delta", "new_machines_count"):
        w.writerow(["what_changed", key, c.get(key) if c.get(key) is not None else ""])

    w.writerow([])
    w.writerow(["top_risks", "rank", "rule", "severity", "host",
                "what_happened", "why_it_matters", "recommended_action"])
    for i, r in enumerate(summary.get("top_risks", []), start=1):
        w.writerow([
            "top_risks", i, r.get("rule"), r.get("severity"),
            r.get("host") or "",
            (r.get("what_happened") or "").replace("\n", " ").strip(),
            (r.get("why_it_matters") or "").replace("\n", " ").strip(),
            (r.get("recommended_action") or "").replace("\n", " ").strip(),
        ])

    w.writerow([])
    w.writerow(["recommendations", "rank", "action"])
    for i, line in enumerate(summary.get("recommendations", []), start=1):
        w.writerow(["recommendations", i, line])

    return buf.getvalue().encode("utf-8-sig")


# ---------------------------------------------------------------------------
# HTML — board-ready, light theme, print-friendly. Self-contained so the
# user can email or print it without breaking layout. Mirrors the look
# of the dashboard but on white so it survives the print pipeline.
# ---------------------------------------------------------------------------

def _trend_phrase(t: Dict[str, Any]) -> str:
    d = (t or {}).get("direction")
    delta = (t or {}).get("delta")
    if d == "improved" and delta:
        return f"Improved by {abs(int(delta))} points vs. last period"
    if d == "declined" and delta:
        return f"Declined by {abs(int(delta))} points vs. last period"
    if d == "stable" and delta is not None:
        return f"Stable vs. last period ({'+' if delta >= 0 else ''}{int(delta)} points)"
    return "First period observed (no prior data to compare)"


def render_html(summary: Dict[str, Any]) -> bytes:
    h = summary["header"]
    p = summary["posture"]
    a = summary["activity"]
    c = summary["what_changed"]
    risks = summary.get("top_risks", []) or []
    recs = summary.get("recommendations", []) or []
    footer = summary.get("footer", {}) or {}

    grade = p.get("grade") or "?"
    grade_sev = _GRADE_SEV.get(grade, "NONE")
    score = p.get("score")
    score_str = T.html_none() if score is None else str(int(score))

    trend_line = _trend_phrase(p.get("trend") or {})

    # 1. Title block + metadata grid + classification banner ------------
    body = T.html_eyebrow_title(REPORT_TYPE.upper(), h.get("title") or REPORT_TYPE)
    body += T.html_metadata_grid([
        ("Organization", _esc(h.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Period", _esc(h.get("period_start")) + " – " + _esc(h.get("period_end"))
         if h.get("period_start") else ""),
        ("Generated", _esc(h.get("generated_at"))),
    ])
    body += T.html_classification_banner(grade_sev, _GRADE_BANNER.get(grade, ""))

    # 2. Security Posture at a Glance — grade verdict callout -----------
    posture_inner = (
        '<div class="rpt-callout-verdict">' + _esc(grade) + ' — '
        + _esc(p.get("interpretation")) + '</div>'
        '<div style="margin-top:6px;">Overall score: <b>' + score_str
        + '</b> out of 100</div>'
        '<div class="rpt-chips" style="margin-top:6px;">'
        + T.html_pill(grade_sev) + '<span style="margin-left:8px;color:'
        + T.C_MUTED + ';">' + _esc(trend_line) + '</span></div>'
    )
    body += T.html_section("Security Posture at a Glance",
                           T.html_callout(posture_inner, grade_sev), grade_sev)

    # 3. What This Means — narrative callout ----------------------------
    body += T.html_section(
        "What This Means",
        T.html_callout('<div class="rpt-callout-verdict">'
                       + _esc(summary.get("what_this_means")) + '</div>'))

    # 4. Top Risks ------------------------------------------------------
    if risks:
        risk_html = ""
        for i, r in enumerate(risks, start=1):
            sev = (r.get("severity") or "LOW").upper()
            head = ('<div class="rpt-card-head">'
                    '<span class="rpt-card-num">#' + str(i) + '</span>'
                    + T.html_pill(sev))
            if r.get("host"):
                head += '<span class="rpt-badge rpt-mono">' + _esc(r.get("host")) + '</span>'
            head += '</div>'
            inner = (head
                     + '<div class="rpt-card-rule">' + _esc(r.get("what_happened")) + '</div>'
                     + '<div class="rpt-card-meta"><b>Why it matters</b></div>'
                     + '<div class="rpt-card-desc">' + _esc(r.get("why_it_matters")) + '</div>'
                     + '<div class="rpt-card-meta"><b>Recommended action</b></div>'
                     + '<div class="rpt-card-desc">' + _esc(r.get("recommended_action")) + '</div>')
            risk_html += ('<div class="rpt-card" style="border-left-color:'
                          + T.SEV_FG[T.sev_key(sev)] + ';">' + inner + '</div>')
    else:
        risk_html = '<div class="rpt-none">No unresolved risks in this period.</div>'
    body += T.html_section("Top Risks", risk_html)

    # 5. Activity Overview — tables -------------------------------------
    sev = a.get("by_severity", {}) or {}
    overview = T.html_table(
        ["Total Issues", "Open", "Resolved", "Monitored", "At Risk"],
        [[str(a.get("total_issues", 0)), str(a.get("open", 0)),
          str(a.get("resolved", 0)), str(a.get("machines_monitored", 0)),
          str(a.get("machines_at_risk", 0))]],
        num_cols=[0, 1, 2, 3, 4])
    sev_rows = [[T.html_pill(s), str(sev.get(s, 0))]
                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
    sev_table = T.html_table(["Severity", "Count"], sev_rows, num_cols=[1])
    body += T.html_section("Activity Overview", overview + sev_table)

    # 6. What Changed ---------------------------------------------------
    if c.get("had_previous_period"):
        changed = T.html_table(
            ["This Period", "Last Period", "Net Change", "Score Change", "New Machines"],
            [[str(c.get("new_issues", 0)), str(c.get("previous_issues", 0)),
              _esc(_fmt_delta(c.get("issues_delta"))),
              _esc(_fmt_delta(c.get("score_delta"))),
              str(c.get("new_machines_count", 0))]],
            num_cols=[0, 1, 2, 3, 4])
    else:
        changed = ('<div class="rpt-none">No prior period available for '
                   'comparison yet. The next report (after another reporting '
                   'interval) will show period-over-period changes.</div>')
    body += T.html_section("What Changed", changed)

    # 7. Recommendations ------------------------------------------------
    if recs:
        recs_html = ('<ol style="margin:2px 0 6px;padding-left:20px;font-size:10px;'
                     'line-height:1.6;">'
                     + "".join('<li>' + _esc(line) + '</li>' for line in recs)
                     + '</ol>')
    else:
        recs_html = '<div class="rpt-none">No recommendations generated for this period.</div>'
    body += T.html_section("Recommendations", recs_html)

    # 8. Footer note ----------------------------------------------------
    body += T.html_callout(
        'Pulse v' + _esc(footer.get("pulse_version")) + '. '
        + _esc(footer.get("automated_note")))

    return T.html_document(
        REPORT_TYPE, "Pulse — " + (h.get("title") or REPORT_TYPE), body).encode("utf-8")


def _fmt_delta(d):
    if d is None:
        return "—"
    try:
        d = int(d)
    except (TypeError, ValueError):
        return str(d)
    if d > 0:
        return f"+{d}"
    return str(d)


# ---------------------------------------------------------------------------
# PDF — polished, board-ready, light theme. Big grade letter on the cover,
# big section headings, generous whitespace.
# ---------------------------------------------------------------------------

def render_pdf(summary: Dict[str, Any]) -> bytes:
    from io import BytesIO
    rl = T._rl()
    Paragraph = rl["Paragraph"]
    st = T.pdf_styles()

    h = summary["header"]
    p = summary["posture"]
    a = summary["activity"]
    c = summary["what_changed"]
    risks = summary.get("top_risks") or []
    recs = summary.get("recommendations") or []
    footer = summary.get("footer") or {}

    grade = p.get("grade") or "?"
    grade_sev = _GRADE_SEV.get(grade, "NONE")
    score = p.get("score")
    score_str = "—" if score is None else str(int(score))
    trend_line = _trend_phrase(p.get("trend") or {})

    story: list = []

    # 1. Title block + metadata grid + classification banner ------------
    story.append(Paragraph(REPORT_TYPE.upper(), st["eyebrow"]))
    story.append(Paragraph(_esc(h.get("title") or REPORT_TYPE), st["title"]))
    story.append(T.pdf_spacer(10))
    story.append(T.pdf_metadata_grid([
        ("Organization", _esc(h.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Period", (_esc(h.get("period_start")) + " – " + _esc(h.get("period_end")))
         if h.get("period_start") else ""),
        ("Generated", _esc(h.get("generated_at"))),
    ], st))
    story.append(T.pdf_spacer(12))
    story.append(T.pdf_banner(grade_sev, _GRADE_BANNER.get(grade, ""), st))
    story.append(T.pdf_spacer(8))

    # 2. Security Posture at a Glance — grade verdict callout -----------
    story.append(T.pdf_section("Security Posture at a Glance", st, grade_sev))
    story.append(T.pdf_spacer(4))
    posture_flow = [
        Paragraph("%s &mdash; %s" % (_esc(grade), _esc(p.get("interpretation"))),
                  st["verdict"]),
        T.pdf_spacer(4),
        Paragraph("Overall score: <b>%s</b> out of 100" % _esc(score_str), st["body"]),
        T.pdf_spacer(6),
        T.pdf_pill_para(grade_sev, st),
        T.pdf_spacer(3),
        Paragraph('<font color="%s">%s</font>' % (T.C_MUTED, _esc(trend_line)), st["muted"]),
    ]
    story.append(T.pdf_callout(posture_flow, st, grade_sev))
    story.append(T.pdf_spacer(6))

    # 3. What This Means — narrative callout ----------------------------
    story.append(T.pdf_section("What This Means", st))
    story.append(T.pdf_spacer(4))
    story.append(T.pdf_callout(
        [Paragraph(_esc(summary.get("what_this_means")), st["verdict"])], st))
    story.append(T.pdf_spacer(6))

    # 4. Top Risks -----------------------------------------------------
    story.append(T.pdf_section("Top Risks", st))
    story.append(T.pdf_spacer(6))
    if risks:
        for i, r in enumerate(risks, start=1):
            sev = (r.get("severity") or "LOW").upper()
            head = Paragraph(
                '<font color="%s"><b>#%d</b></font>&nbsp;&nbsp;'
                '<font color="%s"><b>%s</b></font>'
                % (T.C_MUTED, i, T.C_TITLE, _esc(r.get("what_happened"))),
                st["cardrule"])
            sub_bits = [T.pdf_pill_para(sev, st)]
            inner_rows = [[head], [sub_bits[0]]]
            if r.get("host"):
                inner_rows.append([Paragraph(
                    'Affected host: <b>%s</b>' % _esc(r.get("host")), st["muted"])])
            inner_rows.append([T.pdf_spacer(3)])
            inner_rows.append([Paragraph(
                '<font color="%s"><b>WHY IT MATTERS</b></font>' % T.C_MUTED, st["th"])])
            inner_rows.append([Paragraph(_esc(r.get("why_it_matters")), st["body"])])
            inner_rows.append([Paragraph(
                '<font color="%s"><b>RECOMMENDED ACTION</b></font>' % T.C_MUTED, st["th"])])
            inner_rows.append([Paragraph(_esc(r.get("recommended_action")), st["body"])])

            inner = rl["Table"](inner_rows, colWidths=[T.CONTENT_W - 16])
            inner.setStyle(rl["TableStyle"]([
                ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
            ]))
            card = rl["Table"]([[inner]], colWidths=[T.CONTENT_W])
            card.setStyle(rl["TableStyle"]([
                ("BOX", (0, 0), (-1, -1), 0.6, rl["colors"].HexColor(T.C_BORDER)),
                ("LINEBEFORE", (0, 0), (0, -1), 4, rl["colors"].HexColor(T.SEV_FG[T.sev_key(sev)])),
                ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ]))
            story.append(rl["KeepTogether"]([card]))
            story.append(T.pdf_spacer(6))
    else:
        story.append(Paragraph(
            '<i><font color="%s">No unresolved risks in this period.</font></i>' % T.C_MUTED,
            st["muted"]))
    story.append(T.pdf_spacer(4))

    # 5. Activity Overview — tables ------------------------------------
    story.append(T.pdf_section("Activity Overview", st))
    story.append(T.pdf_spacer(4))
    story.append(T.pdf_table(
        ["Total Issues", "Open", "Resolved", "Monitored", "At Risk"],
        [[str(a.get("total_issues", 0)), str(a.get("open", 0)),
          str(a.get("resolved", 0)), str(a.get("machines_monitored", 0)),
          str(a.get("machines_at_risk", 0))]],
        [102, 102, 102, 104, 102], st))
    story.append(T.pdf_spacer(6))
    sev_map = a.get("by_severity") or {}
    story.append(T.pdf_table(
        ["Severity", "Count"],
        [[T.pdf_pill_para(s, st), str(sev_map.get(s, 0))]
         for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")],
        [256, 256], st))
    story.append(T.pdf_spacer(6))

    # 6. What Changed --------------------------------------------------
    story.append(T.pdf_section("What Changed", st))
    story.append(T.pdf_spacer(4))
    if c.get("had_previous_period"):
        story.append(T.pdf_table(
            ["This Period", "Last Period", "Net Change", "Score Change", "New Machines"],
            [[str(c.get("new_issues", 0)), str(c.get("previous_issues", 0)),
              _fmt_delta(c.get("issues_delta")), _fmt_delta(c.get("score_delta")),
              str(c.get("new_machines_count", 0))]],
            [102, 102, 102, 104, 102], st))
    else:
        story.append(Paragraph(
            '<i><font color="%s">No prior period available for comparison yet. '
            'The next report will show period-over-period changes.</font></i>' % T.C_MUTED,
            st["muted"]))
    story.append(T.pdf_spacer(6))

    # 7. Recommendations -----------------------------------------------
    story.append(T.pdf_section("Recommendations", st))
    story.append(T.pdf_spacer(4))
    if recs:
        for i, line in enumerate(recs, start=1):
            story.append(Paragraph("<b>%d.</b>&nbsp;&nbsp;%s" % (i, _esc(line)), st["body"]))
            story.append(T.pdf_spacer(3))
    else:
        story.append(Paragraph(
            '<i><font color="%s">No recommendations generated for this period.</font></i>'
            % T.C_MUTED, st["muted"]))
    story.append(T.pdf_spacer(8))

    # 8. Footer note ----------------------------------------------------
    story.append(T.pdf_callout([Paragraph(
        "Pulse v%s. %s" % (_esc(footer.get("pulse_version")),
                           _esc(footer.get("automated_note"))), st["body"])], st))

    buf = BytesIO()
    doc, canvasmaker = T.new_doc(buf, "Pulse Executive Security Summary", REPORT_TYPE)
    doc.build(story, canvasmaker=canvasmaker)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Format dispatcher
# ---------------------------------------------------------------------------

_RENDERERS = {
    "json": render_json,
    "csv":  render_csv,
    "html": render_html,
    "pdf":  render_pdf,
}


def render(summary: Dict[str, Any], fmt: str) -> bytes:
    fmt = (fmt or "").lower()
    if fmt not in _RENDERERS:
        raise ValueError(
            f"unknown format {fmt!r}; expected one of {sorted(_RENDERERS)}"
        )
    return _RENDERERS[fmt](summary)
