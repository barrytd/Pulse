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


def _esc(s: Any) -> str:
    return html.escape(str(s) if s is not None else "")


# Severity + grade palette — light theme. Same hex values as the
# dashboard's `--severity-*` CSS custom properties so the colors stay
# consistent across surfaces.
SEV_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f59e0b",
    "MEDIUM":   "#3b82f6",
    "LOW":      "#10b981",
}
GRADE_COLOR = {
    "A": "#639922", "B": "#378ADD", "C": "#BA7517",
    "D": "#E24B4A", "F": "#A32D2D", "?": "#6b7280",
}


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
    grade_color = GRADE_COLOR.get(grade, "#6b7280")
    score = p.get("score")
    score_str = "—" if score is None else str(int(score))

    trend_line = _trend_phrase(p.get("trend") or {})

    # --- Top Risks block -----------------------------------------------
    risk_blocks = ""
    for i, r in enumerate(risks, start=1):
        sev = (r.get("severity") or "LOW").upper()
        sev_color = SEV_COLOR.get(sev, "#6b7280")
        host_line = (
            f'<div class="risk-host">Affected host: <strong>{_esc(r.get("host"))}</strong></div>'
            if r.get("host") else ""
        )
        risk_blocks += f"""
        <div class="risk-card">
          <div class="risk-head">
            <span class="risk-rank">#{i}</span>
            <span class="risk-sev" style="background:{sev_color}1f;color:{sev_color};border:1px solid {sev_color}55;">
              {_esc(sev)}
            </span>
          </div>
          <div class="risk-what">{_esc(r.get("what_happened"))}</div>
          {host_line}
          <div class="risk-section-label">Why it matters</div>
          <div class="risk-body">{_esc(r.get("why_it_matters"))}</div>
          <div class="risk-section-label">Recommended action</div>
          <div class="risk-body">{_esc(r.get("recommended_action"))}</div>
        </div>"""
    if not risk_blocks:
        risk_blocks = (
            '<div class="muted">No unresolved risks in this period.</div>'
        )

    # --- Activity tiles ------------------------------------------------
    def tile(num, label, accent=None):
        color = f"color:{accent};" if accent else ""
        return (f'<div class="stat-tile"><div class="stat-num" style="{color}">{num}</div>'
                f'<div class="stat-label">{label}</div></div>')

    sev = a.get("by_severity", {}) or {}
    activity_tiles = "".join([
        tile(a.get("total_issues", 0),       "Total issues found"),
        tile(a.get("open", 0),               "Still open"),
        tile(a.get("resolved", 0),           "Resolved"),
        tile(a.get("machines_monitored", 0), "Machines monitored"),
        tile(a.get("machines_at_risk", 0),   "Machines at risk",
             SEV_COLOR["HIGH"] if a.get("machines_at_risk", 0) else None),
    ])
    severity_strip = "".join([
        tile(sev.get(s, 0), s.title(), SEV_COLOR[s])
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    ])

    # --- What Changed --------------------------------------------------
    if c.get("had_previous_period"):
        changed_html = f"""
          <div class="changed-grid">
            {tile(c.get('new_issues', 0), 'Issues this period')}
            {tile(c.get('previous_issues', 0), 'Issues last period')}
            {tile(_fmt_delta(c.get('issues_delta')), 'Net change in issues',
                  '#ef4444' if (c.get('issues_delta') or 0) > 0 else '#10b981')}
            {tile(_fmt_delta(c.get('score_delta')), 'Score change',
                  '#10b981' if (c.get('score_delta') or 0) > 0 else
                  '#ef4444' if (c.get('score_delta') or 0) < 0 else None)}
            {tile(c.get('new_machines_count', 0), 'New machines added')}
          </div>"""
    else:
        changed_html = (
            '<div class="muted">No prior period available for comparison '
            'yet. The next report (after another reporting interval) will '
            'show period-over-period changes.</div>'
        )

    rec_items = "".join(
        f'<li>{_esc(line)}</li>' for line in recs
    ) or '<li class="muted">No recommendations generated for this period.</li>'

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Executive Security Summary</title>
<style>
  @page {{ size: Letter; margin: 0.6in; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #ffffff; color: #111827;
    margin: 0; padding: 36px 0;
    -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }}
  .container {{ max-width: 880px; margin: 0 auto; padding: 0 36px; }}
  h1 {{ font-size: 26px; margin: 0 0 4px 0; }}
  h2 {{
    font-size: 13px; margin: 0 0 14px 0;
    text-transform: uppercase; letter-spacing: 0.7px;
    color: #6b7280; font-weight: 700;
    border-bottom: 1px solid #e5e7eb; padding-bottom: 8px;
  }}
  .muted {{ color: #6b7280; }}
  .small {{ font-size: 12px; }}
  .section {{ margin-bottom: 36px; }}
  .org-line {{ color: #6b7280; font-size: 14px; margin-bottom: 18px; }}
  .scope-line {{ font-size: 13px; color: #374151; }}

  /* Grade hero — the single load-bearing visual on the cover. */
  .grade-hero {{
    display: flex;
    align-items: center;
    gap: 26px;
    background: #f9fafb;
    border: 1px solid #e5e7eb;
    border-radius: 10px;
    padding: 24px 28px;
    margin-bottom: 18px;
  }}
  .grade-circle {{
    width: 110px; height: 110px;
    border-radius: 50%;
    background: {grade_color};
    color: #fff;
    display: flex; align-items: center; justify-content: center;
    font-size: 56px; font-weight: 700; line-height: 1;
    flex: 0 0 auto;
  }}
  .grade-body {{ flex: 1; }}
  .grade-line {{
    font-size: 18px; font-weight: 600;
    color: #111827; margin-bottom: 6px;
  }}
  .grade-score {{
    font-size: 14px; color: #374151; margin-bottom: 10px;
  }}
  .grade-trend {{
    font-size: 13px;
    color: #6b7280;
    padding: 4px 10px;
    background: #fff; border: 1px solid #e5e7eb;
    border-radius: 999px;
    display: inline-block;
  }}

  .narrative {{
    font-size: 15px; line-height: 1.65;
    color: #111827;
    background: #fffbeb; border-left: 4px solid #f59e0b;
    padding: 14px 18px; border-radius: 6px;
  }}

  .risk-card {{
    background: #f9fafb; border: 1px solid #e5e7eb;
    border-radius: 8px; padding: 16px 18px;
    margin-bottom: 12px;
  }}
  .risk-head {{
    display: flex; align-items: center; gap: 10px; margin-bottom: 8px;
  }}
  .risk-rank {{
    background: #1f2937; color: #fff;
    width: 26px; height: 26px;
    border-radius: 50%;
    display: inline-flex; align-items: center; justify-content: center;
    font-size: 12px; font-weight: 700;
  }}
  .risk-sev {{
    padding: 3px 10px; border-radius: 999px;
    font-size: 11px; font-weight: 700; letter-spacing: 0.4px;
    line-height: 1;
  }}
  .risk-what {{ font-size: 15px; line-height: 1.5; font-weight: 500; margin-bottom: 8px; }}
  .risk-host {{ font-size: 12px; color: #6b7280; margin-bottom: 10px; }}
  .risk-section-label {{
    font-size: 10px; text-transform: uppercase; letter-spacing: 0.6px;
    color: #6b7280; margin-top: 10px;
  }}
  .risk-body {{ font-size: 13px; line-height: 1.55; color: #374151; }}

  .stat-grid, .changed-grid {{
    display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px;
  }}
  .severity-strip {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px;
    margin-top: 12px;
  }}
  .stat-tile {{
    background: #f9fafb; border: 1px solid #e5e7eb;
    border-radius: 8px; padding: 14px 12px;
    text-align: center;
  }}
  .stat-num {{ font-size: 26px; font-weight: 700; line-height: 1.1; }}
  .stat-label {{
    font-size: 11px; color: #6b7280;
    text-transform: uppercase; letter-spacing: 0.4px; margin-top: 4px;
  }}

  ol.recs {{
    padding-left: 22px; font-size: 14px; line-height: 1.65;
  }}
  ol.recs li {{ margin-bottom: 8px; }}

  footer {{
    margin-top: 36px;
    padding-top: 14px;
    border-top: 1px solid #e5e7eb;
    font-size: 11px; color: #6b7280;
    text-align: center;
    line-height: 1.6;
  }}
  @media print {{
    body {{ padding: 0; }}
    .section {{ break-inside: avoid; }}
    .grade-hero, .risk-card {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="container">

  <div class="section">
    <h1>{_esc(h.get("title"))}</h1>
    <div class="org-line">Prepared for <strong>{_esc(h.get("organization"))}</strong></div>
    <div class="scope-line">{_esc(h.get("scope"))}</div>
    <div class="scope-line muted">Generated {_esc(h.get("generated_at"))}</div>
  </div>

  <div class="section">
    <h2>Security Posture at a Glance</h2>
    <div class="grade-hero">
      <div class="grade-circle">{_esc(grade)}</div>
      <div class="grade-body">
        <div class="grade-line">{_esc(grade)} — {_esc(p.get("interpretation"))}</div>
        <div class="grade-score">Overall score: <strong>{_esc(score_str)}</strong> out of 100</div>
        <div class="grade-trend">{_esc(trend_line)}</div>
      </div>
    </div>
  </div>

  <div class="section">
    <h2>What This Means</h2>
    <div class="narrative">{_esc(summary.get("what_this_means"))}</div>
  </div>

  <div class="section">
    <h2>Top Risks</h2>
    {risk_blocks}
  </div>

  <div class="section">
    <h2>Activity Overview</h2>
    <div class="stat-grid">{activity_tiles}</div>
    <div class="severity-strip">{severity_strip}</div>
  </div>

  <div class="section">
    <h2>What Changed</h2>
    {changed_html}
  </div>

  <div class="section">
    <h2>Recommendations</h2>
    <ol class="recs">{rec_items}</ol>
  </div>

  <footer>
    Pulse v{_esc(footer.get("pulse_version"))}<br/>
    {_esc(footer.get("automated_note"))}
  </footer>

</div>
</body>
</html>"""
    return html_doc.encode("utf-8")


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
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Flowable, HRFlowable, KeepTogether, Paragraph,
        SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    from pulse.reports.pdf_report import (
        COLOR_BORDER, COLOR_MUTED, COLOR_TEXT, COLOR_TITLE,
        GRADE_COLORS, DEFAULT_GRADE_COLOR,
        CONTENT_WIDTH, LEFT_MARGIN, RIGHT_MARGIN,
        _draw_footer,
    )

    h = summary["header"]
    p = summary["posture"]
    a = summary["activity"]
    c = summary["what_changed"]
    risks = summary.get("top_risks") or []
    recs = summary.get("recommendations") or []
    footer = summary.get("footer") or {}

    grade = p.get("grade") or "?"
    grade_color = GRADE_COLORS.get(grade, DEFAULT_GRADE_COLOR)
    score = p.get("score")
    score_str = "—" if score is None else str(int(score))

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=LEFT_MARGIN, rightMargin=RIGHT_MARGIN,
        topMargin=0.75 * inch, bottomMargin=0.85 * inch,
        title="Pulse Executive Security Summary",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "EX_Title", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=24, leading=28, textColor=COLOR_TITLE, alignment=TA_LEFT,
        spaceAfter=2,
    )
    org_style = ParagraphStyle(
        "EX_Org", parent=styles["Normal"], fontName="Helvetica",
        fontSize=11, leading=14, textColor=COLOR_MUTED, alignment=TA_LEFT,
        spaceAfter=4,
    )
    scope_style = ParagraphStyle(
        "EX_Scope", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=13, textColor=COLOR_TEXT, alignment=TA_LEFT,
    )
    section_style = ParagraphStyle(
        "EX_Section", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=11, leading=14, textColor=COLOR_MUTED, alignment=TA_LEFT,
        spaceAfter=8, spaceBefore=16,
    )
    body_style = ParagraphStyle(
        "EX_Body", parent=styles["Normal"], fontName="Helvetica",
        fontSize=11, leading=16, textColor=COLOR_TEXT, alignment=TA_LEFT,
    )
    grade_line_style = ParagraphStyle(
        "EX_GradeLine", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=14, leading=18, textColor=COLOR_TITLE, alignment=TA_LEFT,
        spaceAfter=4,
    )
    grade_score_style = ParagraphStyle(
        "EX_GradeScore", parent=styles["Normal"], fontName="Helvetica",
        fontSize=11, leading=14, textColor=COLOR_TEXT, alignment=TA_LEFT,
        spaceAfter=6,
    )
    trend_style = ParagraphStyle(
        "EX_Trend", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=13, textColor=COLOR_MUTED, alignment=TA_LEFT,
    )
    narrative_style = ParagraphStyle(
        "EX_Narrative", parent=styles["Normal"], fontName="Helvetica",
        fontSize=12, leading=18, textColor=COLOR_TEXT, alignment=TA_LEFT,
        leftIndent=10, rightIndent=10,
    )
    risk_what_style = ParagraphStyle(
        "EX_RiskWhat", parent=body_style, fontName="Helvetica-Bold",
        fontSize=12, leading=16, textColor=COLOR_TITLE, spaceAfter=4,
    )
    risk_label_style = ParagraphStyle(
        "EX_RiskLabel", parent=body_style, fontName="Helvetica-Bold",
        fontSize=9, leading=11, textColor=COLOR_MUTED,
        spaceBefore=6, spaceAfter=2,
    )
    risk_body_style = ParagraphStyle(
        "EX_RiskBody", parent=body_style, fontName="Helvetica",
        fontSize=10.5, leading=15, textColor=COLOR_TEXT,
    )
    rec_style = ParagraphStyle(
        "EX_Rec", parent=body_style, fontName="Helvetica",
        fontSize=11, leading=16, textColor=COLOR_TEXT,
        leftIndent=4, spaceAfter=4,
    )

    story = []

    # -- Header ---------------------------------------------------------
    story.append(Paragraph(h.get("title") or "Executive Security Summary",
                            title_style))
    story.append(Paragraph(
        f"Prepared for <b>{html.escape(str(h.get('organization')))}</b>",
        org_style))
    story.append(Paragraph(html.escape(str(h.get("scope"))), scope_style))
    story.append(Paragraph(
        f"Generated {html.escape(str(h.get('generated_at')))}", scope_style))
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.6, color=COLOR_BORDER))

    # -- Posture at a Glance -------------------------------------------
    story.append(Paragraph("SECURITY POSTURE AT A GLANCE", section_style))

    # Big grade chip on the left, body on the right.
    grade_chip = _BigGradeChip(grade, grade_color, size=86)

    trend_line = _trend_phrase(p.get("trend") or {})
    grade_body = [
        Paragraph(
            f"{html.escape(grade)} &mdash; "
            f"{html.escape(str(p.get('interpretation') or ''))}",
            grade_line_style,
        ),
        Paragraph(
            f"Overall score: <b>{html.escape(score_str)}</b> out of 100",
            grade_score_style,
        ),
        Paragraph(html.escape(trend_line), trend_style),
    ]
    posture_table = Table(
        [[grade_chip, grade_body]],
        colWidths=[1.3 * inch, CONTENT_WIDTH - 1.3 * inch],
    )
    posture_table.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
        ("BOX",          (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("LEFTPADDING",  (0, 0), (-1, -1), 16),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
        ("TOPPADDING",   (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
    ]))
    story.append(posture_table)

    # -- What This Means -----------------------------------------------
    story.append(Paragraph("WHAT THIS MEANS", section_style))
    narrative_box = Table(
        [[Paragraph(html.escape(summary.get("what_this_means", "")),
                     narrative_style)]],
        colWidths=[CONTENT_WIDTH],
    )
    narrative_box.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
        ("LINEBEFORE",   (0, 0), (0, -1), 3, colors.HexColor("#f59e0b")),
        ("LEFTPADDING",  (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING",   (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(narrative_box)

    # -- Top Risks -----------------------------------------------------
    story.append(Paragraph("TOP RISKS", section_style))
    if risks:
        from pulse.reports.pdf_report import PILL_BG, PILL_FG
        for i, r in enumerate(risks, start=1):
            sev = (r.get("severity") or "LOW").upper()
            pill_bg = PILL_BG.get(sev, colors.HexColor("#f3f4f6"))
            pill_fg = PILL_FG.get(sev, COLOR_MUTED)
            rank_chip = _RankChip(i)
            sev_chip_style = ParagraphStyle(
                f"sev_{sev}_{i}", parent=body_style, alignment=TA_CENTER,
                fontName="Helvetica-Bold", fontSize=8.5,
                textColor=pill_fg, leading=11,
            )
            head_row = Table(
                [[rank_chip, Paragraph(sev, sev_chip_style)]],
                colWidths=[0.35 * inch, 0.6 * inch],
            )
            head_row.setStyle(TableStyle([
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("BACKGROUND",    (1, 0), (1, 0), pill_bg),
                ("ROUNDEDCORNERS", [0, 0, 0, 0]),  # corners stay rectangular
                ("LEFTPADDING",   (1, 0), (1, 0), 6),
                ("RIGHTPADDING",  (1, 0), (1, 0), 6),
                ("TOPPADDING",    (1, 0), (1, 0), 4),
                ("BOTTOMPADDING", (1, 0), (1, 0), 4),
            ]))

            blocks = [
                head_row,
                Spacer(1, 4),
                Paragraph(html.escape(r.get("what_happened") or ""),
                           risk_what_style),
            ]
            if r.get("host"):
                blocks.append(Paragraph(
                    f'Affected host: <b>{html.escape(r["host"])}</b>',
                    ParagraphStyle("ex_risk_host", parent=body_style,
                                    fontSize=10, textColor=COLOR_MUTED),
                ))
            blocks.extend([
                Paragraph("WHY IT MATTERS", risk_label_style),
                Paragraph(html.escape(r.get("why_it_matters") or ""),
                           risk_body_style),
                Paragraph("RECOMMENDED ACTION", risk_label_style),
                Paragraph(html.escape(r.get("recommended_action") or ""),
                           risk_body_style),
            ])
            card = Table([[blocks]], colWidths=[CONTENT_WIDTH])
            card.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
                ("BOX",          (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("LEFTPADDING",  (0, 0), (-1, -1), 16),
                ("RIGHTPADDING", (0, 0), (-1, -1), 16),
                ("TOPPADDING",   (0, 0), (-1, -1), 14),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
            ]))
            story.append(KeepTogether(card))
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("No unresolved risks in this period.",
                                ParagraphStyle("ex_no_risks",
                                                 parent=body_style,
                                                 textColor=COLOR_MUTED)))

    # -- Activity Overview ---------------------------------------------
    story.append(Paragraph("ACTIVITY OVERVIEW", section_style))
    sev_map = a.get("by_severity") or {}
    tiles = [
        (a.get("total_issues", 0), "Total issues",     None),
        (a.get("open", 0),         "Still open",       None),
        (a.get("resolved", 0),     "Resolved",         None),
        (a.get("machines_monitored", 0), "Machines monitored", None),
        (a.get("machines_at_risk", 0),
         "Machines at risk",
         colors.HexColor(SEV_COLOR["HIGH"])
         if a.get("machines_at_risk", 0) else None),
    ]
    story.append(_stat_grid(tiles, cols=5,
                             body_style=body_style))
    story.append(Spacer(1, 10))
    sev_tiles = [
        (sev_map.get(s, 0), s.title(),
         colors.HexColor(SEV_COLOR[s]))
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    ]
    story.append(_stat_grid(sev_tiles, cols=4, body_style=body_style))

    # -- What Changed --------------------------------------------------
    story.append(Paragraph("WHAT CHANGED", section_style))
    if c.get("had_previous_period"):
        changed_tiles = [
            (c.get("new_issues", 0),      "Issues this period",  None),
            (c.get("previous_issues", 0), "Issues last period",  None),
            (_fmt_delta(c.get("issues_delta")),
             "Net change in issues",
             colors.HexColor("#ef4444") if (c.get("issues_delta") or 0) > 0
             else colors.HexColor("#10b981")),
            (_fmt_delta(c.get("score_delta")),
             "Score change",
             colors.HexColor("#10b981") if (c.get("score_delta") or 0) > 0 else
             colors.HexColor("#ef4444") if (c.get("score_delta") or 0) < 0 else None),
            (c.get("new_machines_count", 0), "New machines", None),
        ]
        story.append(_stat_grid(changed_tiles, cols=5,
                                  body_style=body_style))
    else:
        story.append(Paragraph(
            "No prior period available for comparison yet. The next "
            "report will show period-over-period changes.",
            ParagraphStyle("ex_no_prev", parent=body_style,
                            textColor=COLOR_MUTED),
        ))

    # -- Recommendations -----------------------------------------------
    story.append(Paragraph("RECOMMENDATIONS", section_style))
    if recs:
        for i, line in enumerate(recs, start=1):
            story.append(Paragraph(
                f"<b>{i}.</b> &nbsp;{html.escape(line)}", rec_style,
            ))
    else:
        story.append(Paragraph(
            "No recommendations generated for this period.",
            ParagraphStyle("ex_no_recs", parent=body_style,
                            textColor=COLOR_MUTED),
        ))

    # -- Footer note (above page footer) -------------------------------
    story.append(Spacer(1, 18))
    story.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER))
    footer_style = ParagraphStyle(
        "EX_FooterNote", parent=body_style, fontSize=9,
        leading=12, textColor=COLOR_MUTED, alignment=TA_CENTER,
    )
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"Pulse v{html.escape(str(footer.get('pulse_version')))}",
        footer_style,
    ))
    story.append(Paragraph(
        html.escape(str(footer.get("automated_note"))),
        footer_style,
    ))

    doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Helper flowables / builders for the PDF
# ---------------------------------------------------------------------------

class _BigGradeChip:
    """Large grade-colored circle with the letter centered. The cover
    visual on the Executive Summary. We don't inherit from Flowable
    directly; the renderer wraps the chip in a 1-cell Table so layout
    constraints come from the table the chip sits inside."""

    def __init__(self, letter, color, size=80):
        from reportlab.platypus import Flowable
        outer = self
        outer.letter = (letter or "?").upper()[:1]
        outer.color = color
        outer.size = size

        class _Impl(Flowable):
            def __init__(self):
                super().__init__()

            def wrap(self, availWidth, availHeight):
                return (outer.size, outer.size)

            def draw(self):
                c = self.canv
                r = outer.size / 2.0
                c.saveState()
                c.setFillColor(outer.color)
                c.circle(r, r, r, stroke=0, fill=1)
                c.setFillColorRGB(1, 1, 1)
                # Center the letter both axes — ReportLab's
                # drawCentredString draws baseline at y, so subtract
                # ~cap-height/2 to drop the optical center to cy.
                font_size = int(outer.size * 0.5)
                c.setFont("Helvetica-Bold", font_size)
                c.drawCentredString(r, r - font_size * 0.32, outer.letter)
                c.restoreState()

        self._impl = _Impl()

    def wrap(self, availWidth, availHeight):
        return self._impl.wrap(availWidth, availHeight)

    def drawOn(self, canv, x, y, _sW=0):
        self._impl.canv = canv
        return self._impl.drawOn(canv, x, y, _sW)


class _RankChip:
    """Small numbered rank circle for the Top Risks header row."""

    def __init__(self, number, size=22):
        from reportlab.platypus import Flowable
        outer = self
        outer.number = str(int(number))
        outer.size = size

        class _Impl(Flowable):
            def wrap(self, availWidth, availHeight):
                return (outer.size, outer.size)

            def draw(self):
                from reportlab.lib import colors as _c
                c = self.canv
                r = outer.size / 2.0
                c.saveState()
                c.setFillColor(_c.HexColor("#1f2937"))
                c.circle(r, r, r, stroke=0, fill=1)
                c.setFillColorRGB(1, 1, 1)
                c.setFont("Helvetica-Bold", 10)
                c.drawCentredString(r, r - 3.2, outer.number)
                c.restoreState()

        self._impl = _Impl()

    def wrap(self, availWidth, availHeight):
        return self._impl.wrap(availWidth, availHeight)

    def drawOn(self, canv, x, y, _sW=0):
        self._impl.canv = canv
        return self._impl.drawOn(canv, x, y, _sW)


def _stat_grid(tiles, *, cols, body_style):
    """Render a row of stat tiles into a single-row Table where each
    cell stacks number + label vertically. ``tiles`` is a list of
    ``(num, label, color_override)`` tuples; ``color_override`` may be
    ``None`` (use COLOR_TITLE)."""
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

    from pulse.reports.pdf_report import (
        COLOR_BORDER, COLOR_MUTED, COLOR_TITLE, CONTENT_WIDTH,
    )

    cell_w = CONTENT_WIDTH / cols
    cells = []
    for num, label, color_override in tiles:
        num_color = color_override or COLOR_TITLE
        num_style = ParagraphStyle(
            f"tile_num_{label}", parent=body_style,
            fontName="Helvetica-Bold", fontSize=22, leading=24,
            textColor=num_color, alignment=TA_CENTER,
        )
        lbl_style = ParagraphStyle(
            f"tile_lbl_{label}", parent=body_style,
            fontName="Helvetica", fontSize=9, leading=12,
            textColor=COLOR_MUTED, alignment=TA_CENTER,
        )
        cells.append([
            Paragraph(str(num), num_style),
            Spacer(1, 4),
            Paragraph(label.upper(), lbl_style),
        ])

    tbl = Table([cells], colWidths=[cell_w] * cols)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
        ("BOX",           (0, 0), (-1, -1), 0.4, COLOR_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.4, COLOR_BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
    ]))
    return tbl


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
