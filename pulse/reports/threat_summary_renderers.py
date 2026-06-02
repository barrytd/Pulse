"""Format renderers for the Threat Detection Summary payload.

All four take the dict returned by ``threat_summary.build_summary`` and
return ``bytes`` ready for download / persistence.

Splitting renderers from the data builder means the PDF and HTML can't
disagree on the numbers — they consume the same dict. It also makes the
unit tests trivial: feed a known dict, assert on the output.
"""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Any, Dict


# ---------------------------------------------------------------------------
# JSON — straight serialization, the canonical SIEM-ingest format.
# ---------------------------------------------------------------------------

def render_json(summary: Dict[str, Any]) -> bytes:
    return json.dumps(summary, indent=2, sort_keys=False,
                       default=str).encode("utf-8")


# ---------------------------------------------------------------------------
# CSV — flat finding list, one row per timeline entry. The summary band /
# top-rules / repeat-offender data is dropped because the canonical use
# case here is "open in Excel and sort by severity".
# ---------------------------------------------------------------------------

def render_csv(summary: Dict[str, Any]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "severity", "rule", "hostname",
                "ref_id", "details"])
    for row in summary.get("timeline", []):
        w.writerow([
            row.get("timestamp") or "",
            row.get("severity") or "",
            row.get("rule") or "",
            row.get("hostname") or "",
            row.get("ref_id") or "",
            (row.get("details") or "").replace("\n", " ").strip(),
        ])
    return buf.getvalue().encode("utf-8-sig")  # BOM so Excel opens UTF-8 cleanly


# ---------------------------------------------------------------------------
# HTML — standalone dark-themed page that mirrors the dashboard's look.
# Self-contained: every style is inlined so the file can be shared,
# emailed, or opened offline without breaking. No external resources.
# ---------------------------------------------------------------------------

_SEVERITY_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f59e0b",
    "MEDIUM":   "#3b82f6",
    "LOW":      "#10b981",
}

_GRADE_COLOR = {
    "A": "#639922", "B": "#378ADD", "C": "#BA7517",
    "D": "#E24B4A", "F": "#A32D2D",
}


def _esc(s: Any) -> str:
    return html.escape(str(s) if s is not None else "")


# Normalize whatever timestamp shape the finding carried (ISO 8601 from
# the parser, "YYYY-MM-DD HH:MM:SS" from the DB, or a sub-second Z-suffix
# string from a correlation rule) into a single "YYYY-MM-DD HH:MM" form.
# Returns "—" for falsy input so the column never reads as suspiciously
# empty: anyone scanning the report sees the placeholder and knows the
# row's event time wasn't recoverable, instead of wondering whether the
# renderer is broken.
def _format_ts(value: Any) -> str:
    if not value:
        return "—"
    s = str(value).strip()
    if not s:
        return "—"
    # Drop sub-second / trailing Z so "2026-04-08T09:14:22.123Z" reads
    # as "2026-04-08 09:14".
    s = s.replace("T", " ")
    if "." in s:
        s = s.split(".", 1)[0]
    if s.endswith("Z"):
        s = s[:-1]
    return s.strip()[:16]


_SEV_SHORT = {"CRITICAL": "CRIT", "HIGH": "HIGH",
               "MEDIUM": "MED",  "LOW": "LOW"}


def _short_sev(sev: str) -> str:
    """Severity column is narrow (0.55"), so we render compact labels.
    Keeps the colored pill from clipping or pushing other columns
    out of alignment when MEDIUM finds its way in."""
    return _SEV_SHORT.get((sev or "").upper(), sev or "")


def _severity_pill(sev: str) -> str:
    color = _SEVERITY_COLOR.get(sev, "#6b7280")
    # Tweak: equal top + bottom padding plus an explicit line-height
    # matching the badge's vertical extent. Without the line-height,
    # the default 1.55 inherited from `body` pushes "MEDIUM" up off the
    # vertical center because the font ascender + descender room is
    # uneven inside the 2px padding box.
    return (f'<span class="pill" style="background:{color}1f;'
            f'color:{color};border:1px solid {color}4d;'
            f'padding:3px 9px;line-height:1;vertical-align:middle;">'
            f'{_esc(sev)}</span>')


def render_html(summary: Dict[str, Any]) -> bytes:
    h = summary["header"]
    s = summary["summary"]
    by_tactic = summary.get("by_tactic", [])
    timeline = summary.get("timeline", [])
    top_rules = summary.get("top_rules", [])
    repeat_ips = summary.get("repeat_ips", [])
    repeat_hosts = summary.get("repeat_hosts", [])
    footer = summary.get("footer", {})

    grade = s.get("grade") or "?"
    grade_color = _GRADE_COLOR.get(grade, "#6b7280")

    # Severity bar — stacked proportions for the four buckets. Falls
    # back to a flat gray bar when there are no findings so the layout
    # doesn't collapse.
    sev_total = max(1, s.get("total_findings", 0))
    sev_bar_parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = s["by_severity"].get(sev, 0)
        if n <= 0:
            continue
        pct = (n / sev_total) * 100
        sev_bar_parts.append(
            f'<div style="flex:{n};background:{_SEVERITY_COLOR[sev]};" '
            f'title="{sev} - {n} ({pct:.0f}%)"></div>'
        )
    sev_bar_html = (
        '<div style="display:flex;height:10px;border-radius:5px;overflow:hidden;'
        'background:#1f2937;">' + "".join(sev_bar_parts) + '</div>'
        if sev_bar_parts else
        '<div style="height:10px;border-radius:5px;background:#1f2937;"></div>'
    )

    tactic_html = ""
    for t in by_tactic:
        techs = ", ".join(
            f'<span class="mono">{_esc(x["id"])}</span> ({x["count"]})'
            for x in t.get("techniques", [])
        ) or '<span class="muted">no technique tag</span>'
        tactic_html += (
            f'<div class="row"><div class="row-head">'
            f'<span class="tactic-name">{_esc(t["tactic"])}</span>'
            f'<span class="muted">{t["count"]} finding'
            f'{"s" if t["count"] != 1 else ""}</span></div>'
            f'<div class="muted small">{techs}</div></div>'
        )

    timeline_rows = ""
    for row in timeline[:200]:  # cap so very large reports stay openable
        timeline_rows += (
            f'<tr><td class="mono small">{_esc(_format_ts(row.get("timestamp")))}</td>'
            f'<td>{_severity_pill(row.get("severity"))}</td>'
            f'<td>{_esc(row.get("rule"))}</td>'
            f'<td>{_esc(row.get("hostname"))}</td></tr>'
        )
    if len(timeline) > 200:
        timeline_rows += (
            f'<tr><td colspan="4" class="muted small" style="text-align:center;">'
            f'... and {len(timeline) - 200} more findings '
            f'(see JSON export for the full list)</td></tr>'
        )

    top_rules_html = ""
    for r in top_rules:
        top_rules_html += (
            f'<tr><td>{_esc(r["rule"])}</td>'
            f'<td>{_severity_pill(r.get("severity") or "LOW")}</td>'
            f'<td class="mono small">{_esc(r.get("mitre") or "-")}</td>'
            f'<td class="num">{r["count"]}</td></tr>'
        )
    if not top_rules_html:
        top_rules_html = (
            '<tr><td colspan="4" class="muted small" style="text-align:center;">'
            'No rules fired in scope.</td></tr>'
        )

    ip_rows = ""
    for entry in repeat_ips:
        score = entry.get("intel_score")
        if score is None:
            intel_cell = '<span class="muted">—</span>'
        else:
            color = "#ef4444" if score >= 75 else "#f59e0b" if score >= 25 else "#10b981"
            intel_cell = (f'<span class="pill" style="background:{color}1f;'
                          f'color:{color};border:1px solid {color}4d;">'
                          f'{score}/100</span>')
        ip_rows += (
            f'<tr><td class="mono">{_esc(entry["ip"])}</td>'
            f'<td>{_esc(entry.get("intel_country") or "-")}</td>'
            f'<td class="num">{entry["count"]}</td>'
            f'<td>{intel_cell}</td>'
            f'<td class="muted small">{_esc(", ".join(entry.get("rules", [])))}</td></tr>'
        )
    if not ip_rows and not repeat_hosts:
        repeat_section_html = (
            '<div class="muted small">No repeat offenders detected.</div>'
        )
    else:
        host_rows = ""
        for h_entry in repeat_hosts:
            host_rows += (
                f'<tr><td>{_esc(h_entry["hostname"])}</td>'
                f'<td class="num">{h_entry["count"]}</td></tr>'
            )
        repeat_section_html = ""
        if ip_rows:
            repeat_section_html += (
                '<div class="subsection-label">Source IPs</div>'
                '<table class="data-table"><thead><tr>'
                '<th>IP</th><th>Country</th><th>Hits</th>'
                '<th>Intel score</th><th>Rules</th>'
                '</tr></thead><tbody>' + ip_rows + '</tbody></table>'
            )
        if host_rows:
            repeat_section_html += (
                '<div class="subsection-label" style="margin-top:14px;">Affected hosts</div>'
                '<table class="data-table"><thead><tr>'
                '<th>Hostname</th><th>Findings</th></tr></thead>'
                '<tbody>' + host_rows + '</tbody></table>'
            )

    title = _esc(h.get("title") or "Threat Detection Summary")
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title} — Pulse</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #0d1117; color: #c9d1d9;
    margin: 0; padding: 32px 0;
  }}
  .container {{ max-width: 960px; margin: 0 auto; padding: 0 32px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px 0; color: #f0f6fc; }}
  .muted {{ color: #8b949e; }}
  .small {{ font-size: 12px; }}
  .mono {{ font-family: SFMono-Regular, Consolas, monospace; }}
  .num  {{ font-variant-numeric: tabular-nums; text-align: right; }}
  .card {{
    background: #161b22; border: 1px solid #30363d;
    border-radius: 6px; padding: 18px; margin-bottom: 16px;
  }}
  .section-label {{
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px;
    color: #8b949e; margin-bottom: 12px; font-weight: 700;
  }}
  .subsection-label {{
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
    color: #8b949e; margin-bottom: 6px;
  }}
  .pill {{
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 10px; font-weight: 700; letter-spacing: 0.4px;
  }}
  table.data-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  table.data-table th {{
    text-align: left; font-weight: 600; color: #8b949e;
    border-bottom: 1px solid #30363d; padding: 6px 8px;
  }}
  table.data-table td {{ padding: 6px 8px; border-bottom: 1px solid #21262d; }}
  table.data-table tr:last-child td {{ border-bottom: none; }}
  .header-band {{ display:flex; align-items:center; gap:20px; }}
  .grade-circle {{
    width:64px; height:64px; border-radius:50%;
    display:flex; align-items:center; justify-content:center;
    color:#fff; font-size:24px; font-weight:700;
    background: {grade_color};
    flex: 0 0 auto;
  }}
  .summary-grid {{ display:grid; grid-template-columns: repeat(4,1fr); gap:10px; margin-top:14px; }}
  .summary-tile {{
    background:#0d1117; border:1px solid #30363d; border-radius:6px;
    padding:10px; text-align:center;
  }}
  .summary-num {{ font-size:20px; font-weight:700; }}
  .summary-label {{ font-size:10px; letter-spacing:0.4px; text-transform:uppercase; color:#8b949e; }}
  .row {{ padding:10px 0; border-bottom:1px solid #21262d; }}
  .row:last-child {{ border-bottom: none; }}
  .row-head {{ display:flex; justify-content:space-between; gap:12px; align-items:center; margin-bottom:2px; }}
  .tactic-name {{ font-weight:600; }}
  footer {{ text-align:center; font-size:11px; color:#8b949e; margin-top:24px; }}
</style>
</head>
<body>
<div class="container">

  <div class="card">
    <h1>{title}</h1>
    <div class="muted small">Generated {_esc(h.get("generated_at"))}</div>
    <div class="muted small"><strong>Scope:</strong> {_esc(h.get("scope"))}</div>
    <div class="muted small"><strong>Hosts covered:</strong> {_esc(", ".join(h.get("hosts") or []) or "—")}</div>
  </div>

  <div class="card">
    <div class="section-label">Summary</div>
    <div class="header-band">
      <div class="grade-circle">{_esc(grade)}</div>
      <div style="flex:1;">
        <div style="font-size:14px;">
          <strong>{s.get("total_findings", 0)}</strong> finding{"" if s.get("total_findings") == 1 else "s"} ·
          score <strong>{s.get("score") if s.get("score") is not None else "—"}</strong>
          {f"<span class='muted small'>({_esc(s.get('score_label'))})</span>" if s.get("score_label") else ""}
        </div>
        <div style="margin-top:10px;">{sev_bar_html}</div>
        <div class="muted small" style="margin-top:6px;">
          {s["by_severity"]["CRITICAL"]} critical · {s["by_severity"]["HIGH"]} high ·
          {s["by_severity"]["MEDIUM"]} medium · {s["by_severity"]["LOW"]} low
        </div>
      </div>
    </div>
    <div class="summary-grid">
      <div class="summary-tile"><div class="summary-num" style="color:{_SEVERITY_COLOR['CRITICAL']};">{s["by_severity"]["CRITICAL"]}</div><div class="summary-label">Critical</div></div>
      <div class="summary-tile"><div class="summary-num" style="color:{_SEVERITY_COLOR['HIGH']};">{s["by_severity"]["HIGH"]}</div><div class="summary-label">High</div></div>
      <div class="summary-tile"><div class="summary-num" style="color:{_SEVERITY_COLOR['MEDIUM']};">{s["by_severity"]["MEDIUM"]}</div><div class="summary-label">Medium</div></div>
      <div class="summary-tile"><div class="summary-num" style="color:{_SEVERITY_COLOR['LOW']};">{s["by_severity"]["LOW"]}</div><div class="summary-label">Low</div></div>
    </div>
  </div>

  <div class="card">
    <div class="section-label">Findings by MITRE Tactic</div>
    {tactic_html or '<div class="muted small">No tactic-tagged findings in scope.</div>'}
  </div>

  <div class="card">
    <div class="section-label">Attack Timeline</div>
    <table class="data-table">
      <thead><tr><th>Timestamp</th><th>Severity</th><th>Rule</th><th>Host</th></tr></thead>
      <tbody>{timeline_rows or '<tr><td colspan="4" class="muted small" style="text-align:center;">No findings to chart.</td></tr>'}</tbody>
    </table>
  </div>

  <div class="card">
    <div class="section-label">Top Triggered Rules</div>
    <table class="data-table">
      <thead><tr><th>Rule</th><th>Severity</th><th>MITRE</th><th>Hits</th></tr></thead>
      <tbody>{top_rules_html}</tbody>
    </table>
  </div>

  <div class="card">
    <div class="section-label">Repeat Offenders</div>
    {repeat_section_html}
  </div>

  <footer>
    Pulse v{_esc(footer.get("pulse_version"))} ·
    {_esc(footer.get("automated_note"))}
  </footer>
</div>
</body>
</html>"""
    return body.encode("utf-8")


# ---------------------------------------------------------------------------
# PDF — reuses the existing pdf_report infrastructure (score ring colors,
# pill styles, footer hook). The threat-summary layout is its own
# top-level build_pdf so we don't try to retrofit per-finding cards onto
# a tactic-grouped report.
# ---------------------------------------------------------------------------

def render_pdf(summary: Dict[str, Any]) -> bytes:
    # Lazy import — reportlab is heavy and not needed for JSON/CSV/HTML.
    from io import BytesIO
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        HRFlowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer,
        Table, TableStyle,
    )

    from pulse.reports.pdf_report import (
        COLOR_BORDER, COLOR_MUTED, COLOR_TEXT, COLOR_TITLE,
        GRADE_COLORS, DEFAULT_GRADE_COLOR, PILL_BG, PILL_FG,
        GRAY_PILL_BG, GRAY_PILL_FG,
        CONTENT_WIDTH, LEFT_MARGIN, RIGHT_MARGIN,
        ScoreRing,
        _draw_footer, _pill,
    )

    h = summary["header"]
    s = summary["summary"]

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=LEFT_MARGIN, rightMargin=RIGHT_MARGIN,
        topMargin=0.7 * inch, bottomMargin=0.8 * inch,
        title="Pulse Threat Detection Summary",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TS_Title", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=18, leading=22, textColor=COLOR_TITLE, alignment=TA_LEFT,
        spaceAfter=2,
    )
    meta_style = ParagraphStyle(
        "TS_Meta", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=13, textColor=COLOR_MUTED, alignment=TA_LEFT,
    )
    section_label = ParagraphStyle(
        "TS_Section", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=10, leading=12, textColor=COLOR_MUTED, alignment=TA_LEFT,
        spaceAfter=4, spaceBefore=8,
    )
    body_style = ParagraphStyle(
        "TS_Body", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=14, textColor=COLOR_TEXT, alignment=TA_LEFT,
    )

    story = []

    # -- Header ----------------------------------------------------------
    story.append(Paragraph(h.get("title") or "Threat Detection Summary",
                            title_style))
    story.append(Paragraph(f"Generated {h.get('generated_at')}", meta_style))
    story.append(Paragraph(f"<b>Scope:</b> {h.get('scope') or '—'}", meta_style))
    if h.get("hosts"):
        story.append(Paragraph(
            f"<b>Hosts covered:</b> {', '.join(h['hosts'])}", meta_style))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=0.5,
                              color=COLOR_BORDER, spaceAfter=10))

    # -- Summary band ---------------------------------------------------
    # Reuse the dashboard's ScoreRing Flowable instead of rolling our own
    # Table cell — Table cells with ROUNDEDCORNERS render as an oddly-
    # shaped "fish" in reportlab when the radius exceeds the cell's half-
    # side. ScoreRing draws a real circle via canvas primitives and
    # exactly matches the dashboard look.
    score_text  = s.get("score")
    score_label = s.get("score_label") or ""
    sev = s["by_severity"]

    ring = ScoreRing(score_text, score_label, size=72, border=6)

    summary_text = (
        f"<b>{s.get('total_findings', 0)}</b> findings · "
        f"score <b>{score_text if score_text is not None else '—'}</b>"
        f"{(' (' + score_label + ')') if score_label else ''}"
        f"<br/><font color='{PILL_FG['CRITICAL'].hexval()}'>"
        f"{sev['CRITICAL']} critical</font> · "
        f"<font color='{PILL_FG['HIGH'].hexval()}'>{sev['HIGH']} high</font> · "
        f"<font color='{PILL_FG['MEDIUM'].hexval()}'>{sev['MEDIUM']} medium</font> · "
        f"<font color='{PILL_FG['LOW'].hexval()}'>{sev['LOW']} low</font>"
    )
    band = Table(
        [[ring, Paragraph(summary_text, body_style)]],
        colWidths=[0.95 * inch, CONTENT_WIDTH - 0.95 * inch],
    )
    band.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (1, 0), (1, 0), 12),
    ]))
    story.append(band)
    story.append(Spacer(1, 14))

    # -- Findings by MITRE Tactic --------------------------------------
    story.append(Paragraph("FINDINGS BY MITRE TACTIC", section_label))
    by_tactic = summary.get("by_tactic", [])
    if by_tactic:
        rows = []
        for t in by_tactic:
            techs = ", ".join(
                f"{x['id']} ({x['count']})" for x in t.get("techniques", [])
            ) or "—"
            rows.append([
                Paragraph(f"<b>{t['tactic']}</b>", body_style),
                Paragraph(str(t["count"]), body_style),
                Paragraph(techs, body_style),
            ])
        tbl = Table(rows, colWidths=[1.7 * inch, 0.5 * inch,
                                       CONTENT_WIDTH - 2.2 * inch])
        tbl.setStyle(TableStyle([
            ("VALIGN",    (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, COLOR_BORDER),
        ]))
        story.append(tbl)
    else:
        story.append(Paragraph("No tactic-tagged findings in scope.",
                                meta_style))
    story.append(Spacer(1, 12))

    # -- Attack timeline -----------------------------------------------
    story.append(Paragraph("ATTACK TIMELINE", section_label))
    timeline = summary.get("timeline", [])
    if timeline:
        # Cap at 60 rows for the PDF — anything more is unreadable and
        # the SIEM-ingest user wants the JSON anyway.
        # Pre-build the severity-pill renderer once so each row gets a
        # snug, vertically-centered badge instead of bare text with
        # only the cell's background color filled in. Equal top/bottom
        # padding in the cell style plus VALIGN=MIDDLE keeps it
        # centered for every severity, not just the longest one.
        rows = [["Timestamp", "Sev", "Rule", "Host"]]
        for r in timeline[:60]:
            sev = (r.get("severity") or "LOW").upper()
            pill_style = ParagraphStyle(
                f"TS_TL_Pill_{sev}", parent=body_style,
                alignment=1,  # TA_CENTER
                fontName="Helvetica-Bold", fontSize=8,
                textColor=PILL_FG.get(sev, COLOR_MUTED),
                leading=10,
            )
            rows.append([
                _format_ts(r.get("timestamp")),
                Paragraph(_short_sev(sev), pill_style),
                r.get("rule") or "",
                r.get("hostname") or "",
            ])
        tbl = Table(rows, colWidths=[1.45 * inch, 0.55 * inch,
                                       CONTENT_WIDTH - 3.5 * inch,
                                       1.5 * inch],
                     repeatRows=1)
        tstyle = [
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_MUTED),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.25, COLOR_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            # Equal top + bottom padding so the colored pill background
            # sits with even breathing room around the text glyphs.
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            # Severity column gets a hair more vertical padding so the
            # pill background reads as a proper badge, not a bare fill.
            ("TOPPADDING",    (1, 1), (1, -1), 5),
            ("BOTTOMPADDING", (1, 1), (1, -1), 5),
        ]
        # Severity column colorization
        for i, r in enumerate(timeline[:60], start=1):
            sev = (r.get("severity") or "LOW").upper()
            if sev in PILL_BG:
                tstyle.append(("BACKGROUND", (1, i), (1, i), PILL_BG[sev]))
        tbl.setStyle(TableStyle(tstyle))
        story.append(tbl)
        if len(timeline) > 60:
            story.append(Spacer(1, 4))
            story.append(Paragraph(
                f"... and {len(timeline) - 60} more findings (see JSON export).",
                meta_style))
    else:
        story.append(Paragraph("No findings to chart.", meta_style))
    story.append(Spacer(1, 12))

    # -- Top triggered rules -------------------------------------------
    story.append(Paragraph("TOP TRIGGERED RULES", section_label))
    top_rules = summary.get("top_rules", [])
    if top_rules:
        rows = [["Rule", "Sev", "MITRE", "Hits"]]
        for r in top_rules:
            sev = (r.get("severity") or "LOW").upper()
            pill_style = ParagraphStyle(
                f"TS_TR_Pill_{sev}", parent=body_style,
                alignment=1,
                fontName="Helvetica-Bold", fontSize=8,
                textColor=PILL_FG.get(sev, COLOR_MUTED),
                leading=10,
            )
            rows.append([
                r.get("rule") or "",
                Paragraph(_short_sev(sev), pill_style),
                r.get("mitre") or "—",
                str(r["count"]),
            ])
        tbl = Table(rows, colWidths=[CONTENT_WIDTH - 3.0 * inch,
                                       0.55 * inch, 1.2 * inch, 0.55 * inch],
                     repeatRows=1)
        tstyle = [
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_MUTED),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.25, COLOR_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (3, 0), (3, -1), "RIGHT"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING",    (1, 1), (1, -1), 5),
            ("BOTTOMPADDING", (1, 1), (1, -1), 5),
        ]
        for i, r in enumerate(top_rules, start=1):
            sev = (r.get("severity") or "LOW").upper()
            if sev in PILL_BG:
                tstyle.append(("BACKGROUND", (1, i), (1, i), PILL_BG[sev]))
        tbl.setStyle(TableStyle(tstyle))
        story.append(tbl)
    else:
        story.append(Paragraph("No rules fired in scope.", meta_style))
    story.append(Spacer(1, 12))

    # -- Repeat offenders ----------------------------------------------
    story.append(Paragraph("REPEAT OFFENDERS", section_label))
    repeat_ips = summary.get("repeat_ips", [])
    repeat_hosts = summary.get("repeat_hosts", [])
    if not repeat_ips and not repeat_hosts:
        story.append(Paragraph("No repeat offenders detected.", meta_style))
    if repeat_ips:
        story.append(Paragraph("Source IPs", meta_style))
        rows = [["IP", "Country", "Hits", "Intel", "Rules"]]
        for entry in repeat_ips:
            intel = (f"{entry['intel_score']}/100"
                     if entry.get("intel_score") is not None else "—")
            rows.append([
                entry["ip"], entry.get("intel_country") or "—",
                str(entry["count"]), intel,
                ", ".join(entry.get("rules", []))[:80],
            ])
        tbl = Table(rows, colWidths=[1.4 * inch, 0.7 * inch, 0.55 * inch,
                                       0.75 * inch,
                                       CONTENT_WIDTH - 3.4 * inch],
                     repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_MUTED),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.25, COLOR_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 8))
    if repeat_hosts:
        story.append(Paragraph("Affected hosts", meta_style))
        rows = [["Hostname", "Findings"]]
        for hentry in repeat_hosts:
            rows.append([hentry["hostname"], str(hentry["count"])])
        tbl = Table(rows, colWidths=[CONTENT_WIDTH - 0.9 * inch, 0.9 * inch],
                     repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_MUTED),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
            ("ALIGN",         (1, 0), (1, -1), "RIGHT"),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.25, COLOR_BORDER),
        ]))
        story.append(tbl)

    doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Format dispatcher — single entry point so the API endpoint doesn't
# need to know which renderer handles which format.
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
