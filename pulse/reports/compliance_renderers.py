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
import io
import json
from typing import Any, Dict, List

import pulse.reports.report_theme as T


def _esc(s: Any) -> str:
    return T.esc(s)


def _framework_view(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve the framework-specific labels/keys once so the HTML and PDF
    renderers stay symmetrical (NIST functions/subcategories vs ISO
    clauses/controls)."""
    framework = payload.get("framework") or "Compliance"
    is_nist = framework == "NIST CSF"
    return {
        "framework":     framework,
        "is_nist":       is_nist,
        "groups":        payload.get("functions" if is_nist else "clauses", []),
        "group_kind":    "Function" if is_nist else "Clause",
        "item_kind":     "Subcategory" if is_nist else "Control",
        "item_key":      "subcategory" if is_nist else "control_id",
        "item_rows_key": "subcategory_rows" if is_nist else "control_rows",
        "missing_key":   "missing_subcategories" if is_nist else "missing_controls",
        "gap_item":      "subcategory" if is_nist else "control",
        "gap_group":     "function" if is_nist else "clause",
    }


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
# HTML — shared light-theme design system (audit-document look).
# ---------------------------------------------------------------------------

def _coverage_bar(pct: int) -> str:
    """Inline progress bar styled with the shared palette so it survives
    print and PDF save-as. Background color fills the covered portion."""
    pct = max(0, min(100, int(pct or 0)))
    return (
        '<div style="display:flex;align-items:center;gap:10px;margin:4px 0 12px;">'
        '<div style="flex:1;height:6px;background:' + T.C_TINT
        + ';border-radius:3px;overflow:hidden;">'
        f'<div style="height:100%;width:{pct}%;background:{T.C_ACCENT};"></div>'
        '</div>'
        '<div style="font-size:9px;color:' + T.C_MUTED
        + ';min-width:74px;text-align:right;">' + str(pct) + '% covered</div>'
        '</div>'
    )


def _summary_tiles_html(tiles: List) -> str:
    cells = "".join(
        '<div style="background:' + T.C_TINT + ';border:1px solid ' + T.C_BORDER
        + ';border-radius:6px;padding:12px;text-align:center;">'
        '<div style="font-size:22px;font-weight:800;color:' + T.C_TITLE
        + ';line-height:1.1;">' + _esc(num) + _esc(suffix) + '</div>'
        '<div style="font-size:8.5px;text-transform:uppercase;letter-spacing:0.4px;'
        'color:' + T.C_MUTED + ';margin-top:4px;">' + _esc(label) + '</div></div>'
        for num, label, suffix in tiles
    )
    return ('<div style="display:grid;grid-template-columns:repeat(4,1fr);'
            'gap:10px;margin:4px 0 8px;">' + cells + '</div>')


def render_html(payload: Dict[str, Any]) -> bytes:
    v = _framework_view(payload)
    framework = v["framework"]
    h = payload.get("header", {})
    summary = payload.get("summary", {})
    groups = v["groups"]
    group_kind = v["group_kind"]
    item_kind = v["item_kind"]
    item_key = v["item_key"]
    item_rows_key = v["item_rows_key"]
    gap_label = item_kind + " (no mapped rules)"

    REPORT_TYPE = framework + " Coverage Report"
    title = h.get("title") or framework + " Report"

    # 1. Title block + metadata grid (scope / generated; period implied)
    body = T.html_eyebrow_title(REPORT_TYPE.upper(), title)
    body += T.html_metadata_grid([
        ("Framework", _esc(framework)),
        ("Organization", _esc(payload.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Generated", _esc(h.get("generated_at"))),
    ])

    # 2. Coverage Summary — tiles + automated-assessment callout
    tiles = [
        (summary.get("overall_coverage_percent", 0), "Overall coverage", "%"),
        (summary.get("rules_enabled", 0),
         "Enabled rules of " + str(summary.get("rules_total", 0)), ""),
        (summary.get("findings_in_period", 0), "Findings in period", ""),
        (len(payload.get("coverage_gaps", [])),
         "Subcategory gaps" if v["is_nist"] else "Control gaps", ""),
    ]
    footer = payload.get("footer", {}) or {}
    summary_inner = (_summary_tiles_html(tiles)
                     + '<div style="margin-top:9px;">' + _esc(footer.get("automated_note") or "")
                     + '</div>')
    body += T.html_section("Coverage Summary", T.html_callout(summary_inner))

    # 3. Group-by-group coverage — one section per function/clause
    for g in groups:
        inner = '<div style="font-size:9px;color:' + T.C_MUTED + ';margin:2px 0 2px;">'
        inner += ('<b style="color:' + T.C_TEXT + ';">' + str(g.get("rules_enabled", 0))
                  + '</b> enabled rules &nbsp;&middot;&nbsp; '
                  '<b style="color:' + T.C_TEXT + ';">' + str(g.get("findings_count", 0))
                  + '</b> findings</div>')
        inner += _coverage_bar(g.get("coverage_percent", 0))

        rows = g.get(item_rows_key, [])
        if rows:
            trows = []
            for row in rows:
                rules_html = "<br>".join(
                    _esc(rule) + ' <span style="color:' + T.C_MUTED + ';">('
                    + str(row["rule_findings"].get(rule, 0)) + ')</span>'
                    for rule in row["rules"]
                )
                trows.append([
                    '<span class="rpt-mono"><b>' + _esc(row[item_key]) + '</b></span>',
                    rules_html,
                    str(row["findings_count"]),
                ])
            inner += T.html_table(
                [item_kind, "Mapped detection rules", "Findings"],
                trows, num_cols=[2])
        else:
            inner += ('<div class="rpt-none">No mapped rules for this '
                      + group_kind.lower() + '.</div>')

        missing = g.get(v["missing_key"], [])
        if missing:
            inner += ('<div style="margin-top:9px;font-size:9px;color:' + T.C_MUTED
                      + ';border-top:1px dashed ' + T.C_BORDER + ';padding-top:7px;">'
                      '<b>' + group_kind + ' gaps:</b> '
                      + ", ".join('<span class="rpt-mono">' + _esc(m) + '</span>'
                                  for m in missing) + '</div>')

        body += T.html_section(_esc(g.get("label")), inner)

    # 4. Coverage Gaps
    gaps = payload.get("coverage_gaps", [])
    if gaps:
        gap_rows = [[
            '<span class="rpt-mono">' + _esc(gap.get(v["gap_item"])) + '</span>',
            _esc(gap.get(v["gap_group"])),
        ] for gap in gaps]
        gaps_section = T.html_table([gap_label, group_kind], gap_rows)
    else:
        gaps_section = ('<div class="rpt-none">No coverage gaps detected. Every expected '
                        + item_kind.lower() + ' has at least one mapped detection rule.</div>')
    body += T.html_section("Coverage Gaps", gaps_section)

    return T.html_document(REPORT_TYPE, "Pulse — " + title, body).encode("utf-8")


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def _pdf_summary_tiles(tiles: List, st) -> Any:
    """Four equal summary tiles in a bordered, tinted row (shared palette)."""
    rl = T._rl()
    C = rl["colors"].HexColor
    Paragraph = rl["Paragraph"]
    PS = rl["ParagraphStyle"]
    num_style = PS("cp_tile_num", fontName="Helvetica-Bold", fontSize=20,
                   leading=22, textColor=C(T.C_TITLE), alignment=rl["TA_CENTER"])
    lbl_style = PS("cp_tile_lbl", fontName="Helvetica", fontSize=8.5,
                   leading=11, textColor=C(T.C_MUTED), alignment=rl["TA_CENTER"])
    cell_w = T.CONTENT_W / 4
    cells = []
    for num, label, suffix in tiles:
        cells.append([
            Paragraph(_esc(num) + _esc(suffix), num_style),
            rl["Spacer"](1, 4),
            Paragraph(_esc(label).upper(), lbl_style),
        ])
    t = rl["Table"]([cells], colWidths=[cell_w] * 4)
    t.setStyle(rl["TableStyle"]([
        ("BACKGROUND",    (0, 0), (-1, -1), C(T.C_TINT)),
        ("BOX",           (0, 0), (-1, -1), 0.6, C(T.C_BORDER)),
        ("INNERGRID",     (0, 0), (-1, -1), 0.6, C(T.C_BORDER)),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
    ]))
    return t


def _pdf_coverage_bar(pct: int, st) -> Any:
    """Inline coverage bar (filled track + right-aligned label) as a flowable."""
    rl = T._rl()
    C = rl["colors"].HexColor
    pct = max(0, min(100, int(pct or 0)))
    track_w = T.CONTENT_W - 90
    fill_w = max(0, round(track_w * pct / 100.0))
    fill = rl["Table"]([[""]], colWidths=[fill_w], rowHeights=[6])
    fill.setStyle(rl["TableStyle"]([
        ("BACKGROUND", (0, 0), (-1, -1), C(T.C_ACCENT)),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    fill.hAlign = "LEFT"
    track = rl["Table"]([[fill]], colWidths=[track_w], rowHeights=[6])
    track.setStyle(rl["TableStyle"]([
        ("BACKGROUND", (0, 0), (-1, -1), C(T.C_TINT)),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    lbl = rl["Paragraph"](
        '<font color="%s">%d%% covered</font>' % (T.C_MUTED, pct),
        rl["ParagraphStyle"]("cp_bar_lbl", fontName="Helvetica", fontSize=8,
                             leading=10, alignment=rl["TA_RIGHT"], textColor=C(T.C_MUTED)))
    row = rl["Table"]([[track, lbl]], colWidths=[track_w, 86])
    row.setStyle(rl["TableStyle"]([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (0, 0), 6),
        ("RIGHTPADDING", (1, 0), (1, 0), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return row


def render_pdf(payload: Dict[str, Any]) -> bytes:
    from io import BytesIO
    rl = T._rl()
    C = rl["colors"].HexColor
    Paragraph = rl["Paragraph"]
    KeepTogether = rl["KeepTogether"]
    st = T.pdf_styles()

    v = _framework_view(payload)
    framework = v["framework"]
    h = payload.get("header", {})
    summary = payload.get("summary", {})
    groups = v["groups"]
    group_kind = v["group_kind"]
    item_kind = v["item_kind"]
    item_key = v["item_key"]
    item_rows_key = v["item_rows_key"]
    footer = payload.get("footer", {}) or {}

    REPORT_TYPE = framework + " Coverage Report"
    title = h.get("title") or REPORT_TYPE

    story: list = []

    # 1. Title block + metadata grid
    story.append(Paragraph(REPORT_TYPE.upper(), st["eyebrow"]))
    story.append(Paragraph(_esc(title), st["title"]))
    story.append(T.pdf_spacer(10))
    story.append(T.pdf_metadata_grid([
        ("Framework", _esc(framework)),
        ("Organization", _esc(payload.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Generated", _esc(h.get("generated_at"))),
    ], st))
    story.append(T.pdf_spacer(12))

    # 2. Coverage Summary — tiles + automated-assessment callout
    story.append(T.pdf_section("Coverage Summary", st))
    story.append(T.pdf_spacer(4))
    story.append(_pdf_summary_tiles([
        ("%d%%" % summary.get("overall_coverage_percent", 0), "Overall coverage", ""),
        (str(summary.get("rules_enabled", 0)),
         "Enabled rules / " + str(summary.get("rules_total", 0)), ""),
        (str(summary.get("findings_in_period", 0)), "Findings in period", ""),
        (str(len(payload.get("coverage_gaps", []))),
         "Subcategory gaps" if v["is_nist"] else "Control gaps", ""),
    ], st))
    story.append(T.pdf_spacer(8))
    story.append(T.pdf_callout(
        [Paragraph(_esc(footer.get("automated_note") or ""), st["body"])], st))
    story.append(T.pdf_spacer(6))

    # 3. Group-by-group coverage — one section per function/clause
    for g in groups:
        blocks = [T.pdf_section(g.get("label") or "", st), T.pdf_spacer(3)]
        stats = ('<font color="%s"><b>%s</b> enabled rules &nbsp;&middot;&nbsp; '
                 '<b>%s</b> findings</font>' % (
                     T.C_MUTED, g.get("rules_enabled", 0), g.get("findings_count", 0)))
        blocks.append(Paragraph(stats, st["muted"]))
        blocks.append(T.pdf_spacer(3))
        blocks.append(_pdf_coverage_bar(g.get("coverage_percent", 0), st))
        blocks.append(T.pdf_spacer(5))

        rows = g.get(item_rows_key, [])
        if rows:
            ctrl_w = 1.0 * rl["inch"]
            count_w = 0.6 * rl["inch"]
            rules_w = T.CONTENT_W - ctrl_w - count_w
            trows = []
            for row in rows:
                rules_para = Paragraph(
                    "<br/>".join(
                        "%s <font color='%s'>(%d)</font>" % (
                            _esc(rule), T.C_MUTED, row["rule_findings"].get(rule, 0))
                        for rule in row["rules"]
                    ), st["td"])
                ctrl_para = Paragraph(
                    '<font face="Courier"><b>%s</b></font>' % _esc(row[item_key]), st["td"])
                trows.append([ctrl_para, rules_para, str(row["findings_count"])])
            blocks.append(T.pdf_table(
                [item_kind, "Mapped detection rules", "Findings"],
                trows, [ctrl_w, rules_w, count_w], st))
        else:
            blocks.append(Paragraph(
                '<i><font color="%s">No mapped rules for this %s.</font></i>'
                % (T.C_MUTED, group_kind.lower()), st["muted"]))

        missing = g.get(v["missing_key"], [])
        if missing:
            blocks.append(T.pdf_spacer(4))
            blocks.append(Paragraph(
                '<font color="%s"><b>%s gaps:</b> %s</font>' % (
                    T.C_MUTED, group_kind, ", ".join(_esc(m) for m in missing)),
                st["muted"]))

        story.append(KeepTogether(blocks))
        story.append(T.pdf_spacer(10))

    # 4. Coverage Gaps
    story.append(T.pdf_section("Coverage Gaps", st))
    story.append(T.pdf_spacer(4))
    gaps = payload.get("coverage_gaps", [])
    if gaps:
        gap_rows = [[
            Paragraph('<font face="Courier"><b>%s</b></font>'
                      % _esc(gap.get(v["gap_item"]) or ""), st["td"]),
            Paragraph(_esc(gap.get(v["gap_group"]) or ""), st["td"]),
        ] for gap in gaps]
        story.append(T.pdf_table(
            [item_kind + " (no mapped rules)", group_kind], gap_rows,
            [1.5 * rl["inch"], T.CONTENT_W - 1.5 * rl["inch"]], st))
    else:
        story.append(Paragraph(
            '<i><font color="%s">No coverage gaps detected. Every expected %s '
            'has at least one mapped detection rule.</font></i>'
            % (T.C_MUTED, item_kind.lower()), st["muted"]))

    buf = BytesIO()
    doc, canvasmaker = T.new_doc(buf, "Pulse " + REPORT_TYPE, REPORT_TYPE)
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


def render(payload: Dict[str, Any], fmt: str) -> bytes:
    fmt = (fmt or "").lower()
    if fmt not in _RENDERERS:
        raise ValueError(
            f"unknown format {fmt!r}; expected one of {sorted(_RENDERERS)}"
        )
    return _RENDERERS[fmt](payload)
