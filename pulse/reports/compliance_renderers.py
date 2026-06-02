"""Format renderers for the NIST CSF + ISO 27001 compliance reports.

Both frameworks share the same shape — header, summary, per-group
rows with mapped rules and finding counts, coverage gaps, footer —
so one renderer module covers both. The framework name + the inner
key ("functions" vs "clauses") are the only thing that varies, and
the renderer keys off the dict's ``framework`` field.

Editorial notes:
    - Audit documents read formal. Light theme everywhere.
    - Tables are the load-bearing element. Auditors scan tables. Don't
      decorate them; just make them readable.
    - Coverage bars on each group give a fast visual read of where the
      detection program is strong vs thin.
"""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Any, Dict, List


def _esc(s: Any) -> str:
    return html.escape(str(s) if s is not None else "")


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def render_json(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, indent=2, sort_keys=False,
                       default=str).encode("utf-8")


# ---------------------------------------------------------------------------
# CSV — one row per (group, control, rule) so a spreadsheet user can
# pivot freely. Header columns name the framework's specific labels
# (Function vs Clause, Subcategory vs Control) so the file makes sense
# without needing a separate legend.
# ---------------------------------------------------------------------------

def render_csv(payload: Dict[str, Any]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    framework = payload.get("framework") or "Compliance"
    is_nist = framework == "NIST CSF"

    group_label   = "function" if is_nist else "clause"
    item_label    = "subcategory" if is_nist else "control_id"
    groups        = payload.get("functions" if is_nist else "clauses", [])
    item_rows_key = "subcategory_rows" if is_nist else "control_rows"

    w.writerow([group_label, item_label, "rule",
                 "rule_count_in_group", "findings_count"])
    for g in groups:
        gname = g.get("label") if is_nist else g.get("label")
        for row in g.get(item_rows_key, []):
            for r in row["rules"]:
                w.writerow([
                    gname, row[item_label], r,
                    row["rule_count"],
                    row["rule_findings"].get(r, 0),
                ])

    w.writerow([])
    w.writerow(["coverage_gap_" + (item_label if is_nist else item_label)])
    for gap in payload.get("coverage_gaps", []):
        w.writerow([gap.get("subcategory") or gap.get("control") or ""])

    return buf.getvalue().encode("utf-8-sig")


# ---------------------------------------------------------------------------
# HTML — light theme, audit-document look.
# ---------------------------------------------------------------------------

def _coverage_bar(pct: int) -> str:
    """Inline SVG-free progress bar that survives print and PDF
    save-as. Uses background color for the filled portion."""
    pct = max(0, min(100, int(pct or 0)))
    return (
        '<div class="coverage-bar-track">'
        f'  <div class="coverage-bar-fill" style="width:{pct}%;"></div>'
        '</div>'
        f'<div class="coverage-bar-label">{pct}% covered</div>'
    )


def render_html(payload: Dict[str, Any]) -> bytes:
    framework = payload.get("framework") or "Compliance"
    h = payload.get("header", {})
    summary = payload.get("summary", {})
    is_nist = framework == "NIST CSF"
    groups = payload.get("functions" if is_nist else "clauses", [])
    group_kind = "Function" if is_nist else "Clause"
    item_kind  = "Subcategory" if is_nist else "Control"
    item_key   = "subcategory" if is_nist else "control_id"
    item_rows_key = "subcategory_rows" if is_nist else "control_rows"
    gap_label = ("Subcategory" if is_nist else "Control") + " (no mapped rules)"
    gap_field = "subcategory" if is_nist else "control"

    summary_tiles = "".join([
        _tile(summary.get("overall_coverage_percent", 0),
              "Overall coverage", suffix="%"),
        _tile(summary.get("rules_enabled", 0),
              f"Enabled rules of {summary.get('rules_total', 0)}"),
        _tile(summary.get("findings_in_period", 0),
              "Findings in period"),
        _tile(len(payload.get("coverage_gaps", [])),
              ("Subcategory gaps" if is_nist else "Control gaps")),
    ])

    group_sections = ""
    for g in groups:
        rows = g.get(item_rows_key, [])
        if not rows:
            inner_table = (
                '<div class="muted">No mapped rules for this '
                f'{group_kind.lower()}.</div>'
            )
        else:
            tbody = ""
            for row in rows:
                rules_html = "".join(
                    f'<tr><td class="mono">{_esc(rule)}</td>'
                    f'<td class="num">{row["rule_findings"].get(rule, 0)}</td></tr>'
                    for rule in row["rules"]
                )
                tbody += (
                    '<tr class="control-row">'
                    f'<td class="mono control-id"><strong>{_esc(row[item_key])}</strong></td>'
                    f'<td>'
                    f'<table class="rule-table"><tbody>{rules_html}</tbody></table>'
                    f'</td>'
                    f'<td class="num findings-count">{row["findings_count"]}</td>'
                    '</tr>'
                )
            inner_table = (
                f'<table class="data-table"><thead><tr>'
                f'<th>{item_kind}</th><th>Mapped detection rules</th>'
                f'<th>Findings</th></tr></thead><tbody>{tbody}</tbody></table>'
            )

        missing_block = ""
        missing = g.get("missing_subcategories" if is_nist
                        else "missing_controls", [])
        if missing:
            missing_block = (
                f'<div class="missing-controls"><strong>'
                f'{group_kind} gaps:</strong> '
                + ", ".join(f'<span class="mono">{_esc(m)}</span>'
                             for m in missing)
                + '</div>'
            )

        group_label = g.get("label") if is_nist else g.get("label")
        group_sections += f"""
        <section class="group-section">
          <div class="group-head">
            <h3>{_esc(group_label)}</h3>
            <div class="group-stats">
              <span class="group-stat"><strong>{g.get("rules_enabled", 0)}</strong> enabled rules</span>
              <span class="group-stat"><strong>{g.get("findings_count", 0)}</strong> findings</span>
            </div>
          </div>
          <div class="coverage-bar">{_coverage_bar(g.get("coverage_percent", 0))}</div>
          {inner_table}
          {missing_block}
        </section>"""

    gaps = payload.get("coverage_gaps", [])
    if gaps:
        gap_rows = "".join(
            f'<tr><td class="mono">{_esc(gap.get(gap_field))}</td>'
            f'<td>{_esc(gap.get("function" if is_nist else "clause"))}</td></tr>'
            for gap in gaps
        )
        gaps_section = (
            f'<table class="data-table"><thead><tr>'
            f'<th>{gap_label}</th><th>{group_kind}</th></tr></thead>'
            f'<tbody>{gap_rows}</tbody></table>'
        )
    else:
        gaps_section = (
            '<div class="muted">No coverage gaps detected. Every expected '
            f'{item_kind.lower()} has at least one mapped detection rule.</div>'
        )

    title = h.get("title") or framework + " Report"
    footer = payload.get("footer", {}) or {}

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_esc(title)}</title>
<style>
  @page {{ size: Letter; margin: 0.6in; }}
  body {{
    font-family: "Times New Roman", Georgia, serif;
    background: #fff; color: #1f2328;
    margin: 0; padding: 36px 0;
    -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }}
  .container {{ max-width: 920px; margin: 0 auto; padding: 0 36px; }}
  h1 {{
    font-family: -apple-system, BlinkMacSystemFont, Helvetica, sans-serif;
    font-size: 22px; margin: 0 0 4px 0; color: #111827;
  }}
  h2 {{
    font-family: -apple-system, BlinkMacSystemFont, Helvetica, sans-serif;
    font-size: 13px; margin: 32px 0 12px 0;
    text-transform: uppercase; letter-spacing: 0.7px;
    color: #6b7280; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px;
  }}
  h3 {{
    font-family: -apple-system, BlinkMacSystemFont, Helvetica, sans-serif;
    font-size: 15px; margin: 0 0 8px 0; color: #111827;
  }}
  .muted {{ color: #6b7280; font-size: 12px; }}
  .mono {{ font-family: SFMono-Regular, Consolas, monospace; font-size: 12px; }}
  .num  {{ font-variant-numeric: tabular-nums; text-align: right; }}

  .scope-line {{ font-size: 13px; margin-bottom: 6px; }}
  .scope-line strong {{ color: #111827; }}

  .summary-tiles {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
    margin-bottom: 16px;
  }}
  .summary-tile {{
    background: #f9fafb; border: 1px solid #e5e7eb;
    border-radius: 6px; padding: 14px 12px; text-align: center;
  }}
  .summary-num   {{ font-size: 26px; font-weight: 700; color: #111827; line-height: 1.1; }}
  .summary-label {{
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px;
    color: #6b7280; margin-top: 4px;
  }}

  .group-section {{
    margin-bottom: 28px;
    background: #fff;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    padding: 18px 20px;
  }}
  .group-head {{
    display: flex; justify-content: space-between; align-items: baseline;
    gap: 12px; margin-bottom: 6px;
  }}
  .group-stats {{ font-size: 12px; color: #6b7280; }}
  .group-stat  {{ margin-left: 14px; }}
  .group-stat strong {{ color: #111827; }}

  .coverage-bar {{ display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }}
  .coverage-bar-track {{
    flex: 1;
    height: 6px; background: #f3f4f6; border-radius: 3px;
    overflow: hidden;
  }}
  .coverage-bar-fill {{
    height: 100%; background: #3b82f6;
  }}
  .coverage-bar-label {{ font-size: 11px; color: #6b7280; min-width: 84px; text-align: right; }}

  table.data-table {{
    width: 100%; border-collapse: collapse; font-size: 12px;
    margin-top: 4px;
  }}
  table.data-table th {{
    text-align: left; font-weight: 600; color: #374151;
    border-bottom: 2px solid #d1d5db; padding: 8px 10px;
    background: #f9fafb;
  }}
  table.data-table td {{
    padding: 8px 10px; border-bottom: 1px solid #e5e7eb;
    vertical-align: top;
  }}
  .control-row td.control-id {{ width: 14%; }}
  .control-row td:nth-child(3) {{ width: 12%; }}

  table.rule-table {{ width: 100%; }}
  table.rule-table td {{ padding: 2px 0 2px 0; border: none; }}
  table.rule-table td.num {{ text-align: right; color: #6b7280; }}

  .missing-controls {{
    margin-top: 10px; font-size: 12px; color: #6b7280;
    border-top: 1px dashed #e5e7eb; padding-top: 8px;
  }}

  footer {{
    margin-top: 36px;
    padding-top: 14px;
    border-top: 1px solid #e5e7eb;
    font-size: 11px; color: #6b7280;
    text-align: center; line-height: 1.6;
    font-family: -apple-system, BlinkMacSystemFont, Helvetica, sans-serif;
  }}
  @media print {{
    body {{ padding: 0; }}
    .group-section {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="container">

  <section>
    <h1>{_esc(title)}</h1>
    <div class="scope-line"><strong>Organization:</strong> {_esc(payload.get("organization"))}</div>
    <div class="scope-line"><strong>Scope:</strong> {_esc(h.get("scope"))}</div>
    <div class="scope-line muted">Generated {_esc(h.get("generated_at"))}</div>
  </section>

  <section>
    <h2>Coverage Summary</h2>
    <div class="summary-tiles">{summary_tiles}</div>
  </section>

  <section>
    <h2>{group_kind}-by-{group_kind} Coverage</h2>
    {group_sections}
  </section>

  <section>
    <h2>Coverage Gaps</h2>
    {gaps_section}
  </section>

  <footer>
    Pulse v{_esc(footer.get("pulse_version"))}<br/>
    {_esc(footer.get("automated_note"))}
  </footer>

</div>
</body>
</html>"""
    return doc.encode("utf-8")


def _tile(num: Any, label: str, suffix: str = "") -> str:
    return (
        '<div class="summary-tile">'
        f'<div class="summary-num">{num}{suffix}</div>'
        f'<div class="summary-label">{label}</div>'
        '</div>'
    )


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def render_pdf(payload: Dict[str, Any]) -> bytes:
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
        CONTENT_WIDTH, LEFT_MARGIN, RIGHT_MARGIN,
        _draw_footer,
    )

    framework = payload.get("framework") or "Compliance"
    is_nist = framework == "NIST CSF"
    h = payload.get("header", {})
    summary = payload.get("summary", {})
    groups = payload.get("functions" if is_nist else "clauses", [])
    group_kind = "Function" if is_nist else "Clause"
    item_kind  = "Subcategory" if is_nist else "Control"
    item_key   = "subcategory" if is_nist else "control_id"
    item_rows_key = "subcategory_rows" if is_nist else "control_rows"
    footer = payload.get("footer", {}) or {}

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=LEFT_MARGIN, rightMargin=RIGHT_MARGIN,
        topMargin=0.75 * inch, bottomMargin=0.85 * inch,
        title=f"Pulse {framework} Coverage Report",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CP_Title", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=20, leading=24, textColor=COLOR_TITLE, alignment=TA_LEFT,
        spaceAfter=2,
    )
    scope_style = ParagraphStyle(
        "CP_Scope", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=13, textColor=COLOR_TEXT, alignment=TA_LEFT,
    )
    muted_style = ParagraphStyle(
        "CP_Muted", parent=styles["Normal"], fontName="Helvetica",
        fontSize=9, leading=12, textColor=COLOR_MUTED, alignment=TA_LEFT,
    )
    section_style = ParagraphStyle(
        "CP_Section", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=11, leading=14, textColor=COLOR_MUTED, alignment=TA_LEFT,
        spaceAfter=8, spaceBefore=18, letterSpacing=0.5,
    )
    body_style = ParagraphStyle(
        "CP_Body", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=14, textColor=COLOR_TEXT, alignment=TA_LEFT,
    )
    group_head_style = ParagraphStyle(
        "CP_GroupHead", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=13, leading=16, textColor=COLOR_TITLE, alignment=TA_LEFT,
        spaceAfter=4,
    )
    rule_style = ParagraphStyle(
        "CP_Rule", parent=body_style, fontName="Helvetica", fontSize=9.5,
        leading=12, textColor=COLOR_TEXT,
    )
    mono_style = ParagraphStyle(
        "CP_Mono", parent=body_style, fontName="Courier", fontSize=10,
        leading=12, textColor=COLOR_TEXT,
    )

    story = []

    # -- Header ---------------------------------------------------------
    story.append(Paragraph(h.get("title") or f"{framework} Coverage Report",
                            title_style))
    story.append(Paragraph(
        f"<b>Organization:</b> {html.escape(str(payload.get('organization')))}",
        scope_style,
    ))
    story.append(Paragraph(
        f"<b>Scope:</b> {html.escape(str(h.get('scope')))}",
        scope_style,
    ))
    story.append(Paragraph(
        f"Generated {html.escape(str(h.get('generated_at')))}",
        muted_style,
    ))
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.6, color=COLOR_BORDER))

    # -- Summary tiles --------------------------------------------------
    story.append(Paragraph("COVERAGE SUMMARY", section_style))
    tile_data = [
        (f"{summary.get('overall_coverage_percent', 0)}%", "Overall coverage"),
        (str(summary.get("rules_enabled", 0)),
         f"Enabled rules / {summary.get('rules_total', 0)}"),
        (str(summary.get("findings_in_period", 0)), "Findings in period"),
        (str(len(payload.get("coverage_gaps", []))),
         ("Subcategory gaps" if is_nist else "Control gaps")),
    ]
    cell_w = CONTENT_WIDTH / 4
    tile_cells = []
    for num, label in tile_data:
        num_style = ParagraphStyle(
            f"tile_num_{label}", parent=body_style,
            fontName="Helvetica-Bold", fontSize=20, leading=22,
            textColor=COLOR_TITLE, alignment=TA_CENTER,
        )
        lbl_style = ParagraphStyle(
            f"tile_lbl_{label}", parent=body_style,
            fontName="Helvetica", fontSize=8.5, leading=11,
            textColor=COLOR_MUTED, alignment=TA_CENTER,
        )
        tile_cells.append([
            Paragraph(num, num_style),
            Spacer(1, 4),
            Paragraph(label.upper(), lbl_style),
        ])
    tile_table = Table([tile_cells], colWidths=[cell_w] * 4)
    tile_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
        ("BOX",           (0, 0), (-1, -1), 0.4, COLOR_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.4, COLOR_BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
    ]))
    story.append(tile_table)

    # -- Per-group sections --------------------------------------------
    story.append(Paragraph(
        f"{group_kind.upper()}-BY-{group_kind.upper()} COVERAGE",
        section_style,
    ))

    for g in groups:
        group_blocks = []
        group_blocks.append(Paragraph(
            html.escape(g.get("label") or ""), group_head_style,
        ))
        # Stats line: enabled rules + findings + coverage %
        stats_text = (
            f"<font color='{COLOR_MUTED.hexval()}' size='9'>"
            f"<b>{g.get('rules_enabled', 0)}</b> enabled rules &nbsp;&middot;&nbsp; "
            f"<b>{g.get('findings_count', 0)}</b> findings &nbsp;&middot;&nbsp; "
            f"coverage <b>{g.get('coverage_percent', 0)}%</b>"
            f"</font>"
        )
        group_blocks.append(Paragraph(stats_text, body_style))
        group_blocks.append(Spacer(1, 6))

        rows = g.get(item_rows_key, [])
        if rows:
            tbl_rows = [[item_kind, "Mapped detection rules", "Findings"]]
            for row in rows:
                rules_para = Paragraph(
                    "<br/>".join(
                        f"{html.escape(rule)} "
                        f"<font color='{COLOR_MUTED.hexval()}'>"
                        f"({row['rule_findings'].get(rule, 0)})</font>"
                        for rule in row["rules"]
                    ),
                    rule_style,
                )
                tbl_rows.append([
                    Paragraph(f"<b>{html.escape(row[item_key])}</b>",
                               mono_style),
                    rules_para,
                    str(row["findings_count"]),
                ])
            ctrl_w  = 1.0 * inch
            count_w = 0.6 * inch
            rules_w = CONTENT_WIDTH - ctrl_w - count_w
            tbl = Table(tbl_rows, colWidths=[ctrl_w, rules_w, count_w],
                         repeatRows=1)
            tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 9),
                ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_MUTED),
                ("LINEBELOW",     (0, 0), (-1, -1), 0.4, COLOR_BORDER),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("ALIGN",         (2, 0), (2, -1), "RIGHT"),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ]))
            group_blocks.append(tbl)
        else:
            group_blocks.append(Paragraph(
                f"No mapped rules for this {group_kind.lower()}.",
                muted_style,
            ))

        missing = g.get("missing_subcategories" if is_nist
                         else "missing_controls", [])
        if missing:
            missing_text = (
                f"<font color='{COLOR_MUTED.hexval()}' size='9'>"
                f"<b>{group_kind} gaps:</b> "
                + ", ".join(html.escape(m) for m in missing)
                + "</font>"
            )
            group_blocks.append(Spacer(1, 4))
            group_blocks.append(Paragraph(missing_text, body_style))

        story.append(KeepTogether(group_blocks))
        story.append(Spacer(1, 12))

    # -- Coverage gaps -------------------------------------------------
    story.append(Paragraph("COVERAGE GAPS", section_style))
    gaps = payload.get("coverage_gaps", [])
    if gaps:
        gap_rows = [[item_kind, group_kind]]
        for gap in gaps:
            gap_rows.append([
                Paragraph(
                    "<b>" + html.escape(gap.get(
                        "subcategory" if is_nist else "control") or "") + "</b>",
                    mono_style,
                ),
                Paragraph(html.escape(
                    gap.get("function" if is_nist else "clause") or ""),
                    body_style,
                ),
            ])
        gap_table = Table(gap_rows,
                            colWidths=[1.5 * inch, CONTENT_WIDTH - 1.5 * inch],
                            repeatRows=1)
        gap_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_MUTED),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.4, COLOR_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(gap_table)
    else:
        story.append(Paragraph(
            f"No coverage gaps detected. Every expected {item_kind.lower()} "
            f"has at least one mapped detection rule.",
            muted_style,
        ))

    # -- Footer note ---------------------------------------------------
    story.append(Spacer(1, 18))
    story.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER))
    footer_style = ParagraphStyle(
        "CP_FooterNote", parent=body_style, fontSize=9, leading=12,
        textColor=COLOR_MUTED, alignment=TA_CENTER,
    )
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"Pulse v{html.escape(str(footer.get('pulse_version')))}",
        footer_style,
    ))
    story.append(Paragraph(
        html.escape(str(footer.get("automated_note") or "")),
        footer_style,
    ))

    doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
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


def render(payload: Dict[str, Any], fmt: str) -> bytes:
    fmt = (fmt or "").lower()
    if fmt not in _RENDERERS:
        raise ValueError(
            f"unknown format {fmt!r}; expected one of {sorted(_RENDERERS)}"
        )
    return _RENDERERS[fmt](payload)
