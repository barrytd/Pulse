"""Format renderers for the Phase 5 templates: Fleet Health,
Board-Ready Posture, MITRE ATT&CK Coverage, Compliance Gap Analysis.

Each template gets its own ``render_<slug>(payload, fmt)`` entry point.
We keep them in one module instead of one each because they share an
overwhelming amount of plumbing (light-theme HTML scaffold, PDF tile
helper, JSON + CSV boilerplate); the per-template differences are
section composition, not core styling.
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
# Shared HTML scaffold + helpers
# ---------------------------------------------------------------------------

_TIER_COLOR = {
    "Healthy":  "#10b981",
    "Moderate": "#3b82f6",
    "At Risk":  "#f59e0b",
    "Critical": "#ef4444",
    "Unknown":  "#6b7280",
}
_SEV_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f59e0b",
    "MEDIUM":   "#3b82f6",
    "LOW":      "#10b981",
}
_GRADE_COLOR = {
    "A": "#639922", "B": "#378ADD", "C": "#BA7517",
    "D": "#E24B4A", "F": "#A32D2D", "?": "#6b7280",
}


def _html_scaffold(title: str, header_html: str, body_html: str,
                    footer_html: str) -> bytes:
    """Wrap section markup in a self-contained light-theme HTML page
    with the print rules every Phase 5 report needs."""
    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_esc(title)}</title>
<style>
  @page {{ size: Letter; margin: 0.6in; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #ffffff; color: #1f2328; margin: 0; padding: 36px 0;
    -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }}
  .container {{ max-width: 920px; margin: 0 auto; padding: 0 36px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px 0; color: #111827; }}
  h2 {{
    font-size: 13px; margin: 28px 0 12px 0;
    text-transform: uppercase; letter-spacing: 0.7px;
    color: #6b7280; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px;
  }}
  .muted {{ color: #6b7280; }}
  .small {{ font-size: 12px; }}
  .mono  {{ font-family: SFMono-Regular, Consolas, monospace; font-size: 12px; }}
  .num   {{ font-variant-numeric: tabular-nums; text-align: right; }}
  .center {{ text-align: center; }}

  .stat-strip {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px;
    margin-bottom: 18px;
  }}
  .stat-strip.cols-5 {{ grid-template-columns: repeat(5, 1fr); }}
  .stat-tile {{
    background: #f9fafb; border: 1px solid #e5e7eb;
    border-radius: 6px; padding: 14px 12px; text-align: center;
  }}
  .stat-num   {{ font-size: 24px; font-weight: 700; line-height: 1.1; }}
  .stat-label {{
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px;
    color: #6b7280; margin-top: 4px;
  }}

  table.data-table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 14px; }}
  table.data-table th {{
    text-align: left; font-weight: 600; color: #374151;
    border-bottom: 2px solid #d1d5db; padding: 6px 10px; background: #f9fafb;
  }}
  table.data-table td {{ padding: 6px 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}

  .tier-pill, .sev-pill, .grade-pill {{
    display: inline-block; padding: 2px 9px;
    border-radius: 999px; font-size: 10px;
    font-weight: 700; letter-spacing: 0.4px;
    line-height: 1.4;
  }}

  footer {{
    margin-top: 32px; padding-top: 14px;
    border-top: 1px solid #e5e7eb;
    font-size: 11px; color: #6b7280; text-align: center; line-height: 1.6;
  }}
  @media print {{
    body {{ padding: 0; }}
    section, .stat-strip {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="container">
{header_html}
{body_html}
<footer>{footer_html}</footer>
</div>
</body>
</html>"""
    return doc.encode("utf-8")


def _stat_tile(num: Any, label: str, color: str = None) -> str:
    style = f' style="color:{color};"' if color else ""
    return (
        f'<div class="stat-tile">'
        f'<div class="stat-num"{style}>{num}</div>'
        f'<div class="stat-label">{_esc(label)}</div>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Fleet Health renderers
# ---------------------------------------------------------------------------

def _fleet_table_html(rows: List[Dict[str, Any]],
                       columns: List[str] = None) -> str:
    if not rows:
        return '<div class="muted">No hosts to list.</div>'
    body_rows = ""
    for r in rows:
        tier = r.get("tier") or "Unknown"
        tier_color = _TIER_COLOR.get(tier, "#6b7280")
        score = r.get("latest_score")
        score_str = "—" if score is None else str(int(score))
        body_rows += (
            "<tr>"
            f"<td>{_esc(r.get('hostname'))}</td>"
            f"<td class='num'>{_esc(score_str)} <span class='muted'>({_esc(r.get('latest_grade') or '?')})</span></td>"
            f"<td>{_esc(r.get('worst_severity') or 'NONE')}</td>"
            f"<td class='num'>{_esc(r.get('scan_count'))}</td>"
            f"<td class='num'>{_esc(r.get('total_findings'))}</td>"
            f"<td class='small'>{_esc(r.get('last_scan_at') or '—')}</td>"
            f"<td><span class='tier-pill' style='background:{tier_color}1f;color:{tier_color};border:1px solid {tier_color}55;'>{_esc(tier)}</span></td>"
            "</tr>"
        )
    return (
        '<table class="data-table"><thead><tr>'
        '<th>Host</th><th>Score</th><th>Worst Sev</th>'
        '<th>Scans</th><th>Findings</th><th>Last Scan</th><th>Tier</th>'
        '</tr></thead>'
        f'<tbody>{body_rows}</tbody></table>'
    )


def render_fleet_health_html(payload: Dict[str, Any]) -> bytes:
    h = payload.get("header", {})
    s = payload.get("summary", {})
    header = f"""
    <section>
      <h1>{_esc(h.get('title'))}</h1>
      <div class="small"><strong>Organization:</strong> {_esc(payload.get('organization'))}</div>
      <div class="small"><strong>Scope:</strong> {_esc(h.get('scope'))}</div>
      <div class="small muted">Generated {_esc(h.get('generated_at'))}</div>
    </section>"""
    tiles = "".join([
        _stat_tile(s.get("total_hosts", 0), "Total hosts"),
        _stat_tile(s.get("healthy", 0),     "Healthy",      _TIER_COLOR["Healthy"]),
        _stat_tile(s.get("at_risk", 0),     "At risk",      _TIER_COLOR["At Risk"]),
        _stat_tile(s.get("critical", 0),    "Critical",     _TIER_COLOR["Critical"]),
        _stat_tile(s.get("stale_count", 0), "Stale",        _TIER_COLOR["Unknown"]),
    ])
    body = (
        '<section><h2>Fleet Summary</h2>'
        f'<div class="stat-strip cols-5">{tiles}</div></section>'
        '<section><h2>All Monitored Hosts</h2>'
        f'{_fleet_table_html(payload.get("hosts", []))}</section>'
    )
    at_risk = payload.get("at_risk_hosts", [])
    if at_risk:
        body += ('<section><h2>At-Risk Hosts</h2>'
                 f'{_fleet_table_html(at_risk)}</section>')
    stale = payload.get("stale_hosts", [])
    if stale:
        body += ('<section><h2>Stale Hosts</h2>'
                 '<div class="muted small">'
                 f"No scan in the last {h.get('stale_days', 7)} days.</div>"
                 f'{_fleet_table_html(stale)}</section>')
    footer = (
        f"Pulse v{_esc((payload.get('footer') or {}).get('pulse_version'))}<br/>"
        f"{_esc((payload.get('footer') or {}).get('automated_note'))}"
    )
    return _html_scaffold(h.get("title") or "Fleet Health Report",
                            header, body, footer)


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


def render_fleet_health_pdf(payload: Dict[str, Any]) -> bytes:
    return _table_pdf(
        title=payload["header"].get("title") or "Fleet Health Report",
        organization=payload.get("organization"),
        scope=payload["header"].get("scope"),
        generated_at=payload["header"].get("generated_at"),
        sections=_fleet_health_pdf_sections(payload),
        footer=payload.get("footer"),
    )


def _fleet_health_pdf_sections(payload):
    s = payload.get("summary", {})
    sections = [
        ("FLEET SUMMARY", _stat_grid_pdf([
            (s.get("total_hosts", 0),  "Total hosts",  None),
            (s.get("healthy", 0),      "Healthy",      _TIER_COLOR["Healthy"]),
            (s.get("at_risk", 0),      "At risk",      _TIER_COLOR["At Risk"]),
            (s.get("critical", 0),     "Critical",     _TIER_COLOR["Critical"]),
            (s.get("stale_count", 0),  "Stale",        _TIER_COLOR["Unknown"]),
        ], cols=5)),
        ("ALL HOSTS — RANKED BY RISK",
         _fleet_pdf_table(payload.get("hosts", []))),
    ]
    if payload.get("at_risk_hosts"):
        sections.append(
            ("AT-RISK HOSTS", _fleet_pdf_table(payload["at_risk_hosts"]))
        )
    if payload.get("stale_hosts"):
        sections.append(
            ("STALE HOSTS", _fleet_pdf_table(payload["stale_hosts"]))
        )
    return sections


def _fleet_pdf_table(rows):
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import Paragraph, Table, TableStyle
    from pulse.reports.pdf_report import (
        COLOR_BORDER, COLOR_MUTED, COLOR_TITLE, CONTENT_WIDTH,
    )
    if not rows:
        return Paragraph(
            "No hosts to list.",
            ParagraphStyle("empty", fontName="Helvetica",
                            fontSize=10, textColor=COLOR_MUTED),
        )
    data = [["Host", "Score", "Worst Sev", "Scans", "Findings",
             "Last Scan", "Tier"]]
    for r in rows:
        score = r.get("latest_score")
        data.append([
            r.get("hostname") or "",
            "—" if score is None else str(int(score)),
            r.get("worst_severity") or "NONE",
            str(r.get("scan_count") or 0),
            str(r.get("total_findings") or 0),
            (r.get("last_scan_at") or "")[:19],
            r.get("tier") or "Unknown",
        ])
    col_w = [
        1.6 * inch, 0.55 * inch, 0.85 * inch,
        0.55 * inch, 0.7 * inch, 1.25 * inch,
        CONTENT_WIDTH - 5.5 * inch,
    ]
    tbl = Table(data, colWidths=col_w, repeatRows=1)
    style = [
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_MUTED),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.25, COLOR_BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (1, 0), (1, -1), "RIGHT"),
        ("ALIGN",         (3, 0), (4, -1), "RIGHT"),
    ]
    for i, r in enumerate(rows, start=1):
        tier = r.get("tier") or "Unknown"
        if tier in _TIER_COLOR:
            style.append(("TEXTCOLOR", (6, i), (6, i),
                          colors.HexColor(_TIER_COLOR[tier])))
    tbl.setStyle(TableStyle(style))
    return tbl


# ---------------------------------------------------------------------------
# Board-Ready Posture renderers
# ---------------------------------------------------------------------------

def _trend_chart_svg(points: List[Dict[str, Any]],
                      *, width: int = 720, height: int = 140) -> str:
    """Inline SVG line chart for the trend points. No external deps;
    survives print and offline viewing."""
    if not points:
        return '<div class="muted">No trend data available.</div>'
    if len(points) == 1:
        return (
            f'<div class="muted">One data point in this period: '
            f'score {points[0]["score"]} on {points[0]["timestamp"]}.</div>'
        )
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

    coords = [
        (margin_x + i * step, y_for(p["score"]))
        for i, p in enumerate(points)
    ]
    poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    dots = "".join(
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="#3b82f6"/>'
        for x, y in coords
    )
    # Y gridlines at 25 / 50 / 75 / 100
    grid = ""
    for s in (25, 50, 75, 100):
        if not min_s <= s <= max_s:
            continue
        y = y_for(s)
        grid += (
            f'<line x1="{margin_x}" y1="{y:.1f}" '
            f'x2="{margin_x + inner_w}" y2="{y:.1f}" '
            f'stroke="#f3f4f6" stroke-width="1"/>'
            f'<text x="{margin_x - 4}" y="{y + 3:.1f}" font-size="9" '
            f'fill="#9ca3af" text-anchor="end">{s}</text>'
        )
    return (
        f'<svg viewBox="0 0 {width} {height}" '
        f'preserveAspectRatio="xMidYMid meet" '
        f'style="width:100%; height:{height}px;">'
        f'{grid}'
        f'<polyline points="{poly}" fill="none" stroke="#3b82f6" '
        f'stroke-width="2"/>'
        f'{dots}'
        f'<text x="{margin_x}" y="{height - 4}" font-size="10" fill="#6b7280">'
        f'{_esc(points[0]["timestamp"])}</text>'
        f'<text x="{margin_x + inner_w}" y="{height - 4}" font-size="10" '
        f'text-anchor="end" fill="#6b7280">{_esc(points[-1]["timestamp"])}</text>'
        f'</svg>'
    )


def render_board_ready_html(payload: Dict[str, Any]) -> bytes:
    h = payload["header"]
    p = payload["posture"]
    a = payload["activity"]
    c = payload["compliance"]
    f = payload["fleet_summary"]
    grade = p.get("grade") or "?"
    grade_color = _GRADE_COLOR.get(grade, "#6b7280")
    score = p.get("score")
    score_str = "—" if score is None else str(int(score))

    trend = p.get("trend") or {}
    delta = trend.get("delta")
    trend_line = (
        "First period observed" if trend.get("direction") == "first_period"
        else f"{'Improved' if (delta or 0) > 0 else 'Declined' if (delta or 0) < 0 else 'Stable'} "
             f"by {abs(int(delta or 0))} points vs. prior period"
    )

    recs = "".join(
        f"<li>{_esc(line)}</li>" for line in payload.get("recommendations", [])
    ) or '<li class="muted">No recommendations generated.</li>'

    header = f"""
    <section>
      <h1>{_esc(h.get('title'))}</h1>
      <div class="small"><strong>Organization:</strong> {_esc(payload.get('organization'))}</div>
      <div class="small"><strong>Scope:</strong> {_esc(h.get('scope'))}</div>
      <div class="small muted">Generated {_esc(h.get('generated_at'))}</div>
    </section>"""

    body = f"""
    <section>
      <h2>Security Posture</h2>
      <div style="display:flex; align-items:center; gap:22px;
                  background:#f9fafb; border:1px solid #e5e7eb;
                  border-radius:8px; padding:18px;">
        <div style="width:88px; height:88px; border-radius:50%; background:{grade_color};
                    color:#fff; display:flex; align-items:center; justify-content:center;
                    font-size:42px; font-weight:700;">{_esc(grade)}</div>
        <div>
          <div style="font-size:16px; font-weight:600;">{_esc(grade)} — {_esc(p.get('interpretation'))}</div>
          <div class="small">Overall score: <strong>{_esc(score_str)}</strong> out of 100</div>
          <div class="small muted">{_esc(trend_line)}</div>
        </div>
      </div>
    </section>

    <section>
      <h2>Score Trend</h2>
      {_trend_chart_svg(payload.get('trend_points', []))}
    </section>

    <section>
      <h2>Fleet Overview</h2>
      <div class="stat-strip cols-5">
        {_stat_tile(f.get('total_hosts', 0), 'Total hosts')}
        {_stat_tile(f.get('healthy', 0), 'Healthy', _TIER_COLOR['Healthy'])}
        {_stat_tile(f.get('at_risk', 0), 'At risk', _TIER_COLOR['At Risk'])}
        {_stat_tile(f.get('critical', 0), 'Critical', _TIER_COLOR['Critical'])}
        {_stat_tile(f.get('stale_count', 0), 'Stale')}
      </div>
    </section>

    <section>
      <h2>Compliance Coverage</h2>
      <div class="stat-strip">
        {_stat_tile(str(c['nist_csf']['coverage_percent']) + '%', 'NIST CSF')}
        {_stat_tile(c['nist_csf']['rules_enabled'], 'NIST rules enabled')}
        {_stat_tile(str(c['iso_27001']['coverage_percent']) + '%', 'ISO 27001')}
        {_stat_tile(c['iso_27001']['rules_enabled'], 'ISO rules enabled')}
      </div>
    </section>

    <section>
      <h2>Activity This Period</h2>
      <div class="stat-strip">
        {_stat_tile(a.get('total_issues', 0), 'Total issues')}
        {_stat_tile(a.get('open', 0), 'Open')}
        {_stat_tile(a.get('resolved', 0), 'Resolved')}
        {_stat_tile(a['by_severity']['CRITICAL'], 'Critical', _SEV_COLOR['CRITICAL'])}
      </div>
    </section>

    <section>
      <h2>Strategic Recommendations</h2>
      <ol style="font-size:14px; line-height:1.65; padding-left:22px;">{recs}</ol>
    </section>"""

    footer = (
        f"Pulse v{_esc((payload.get('footer') or {}).get('pulse_version'))}<br/>"
        f"{_esc((payload.get('footer') or {}).get('automated_note'))}"
    )
    return _html_scaffold(h.get("title") or "Board-Ready Posture Report",
                            header, body, footer)


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


def render_board_ready_pdf(payload):
    return _table_pdf(
        title=payload["header"].get("title") or "Board-Ready Posture Report",
        organization=payload.get("organization"),
        scope=payload["header"].get("scope"),
        generated_at=payload["header"].get("generated_at"),
        sections=_board_ready_pdf_sections(payload),
        footer=payload.get("footer"),
    )


def _board_ready_pdf_sections(payload):
    p = payload["posture"]
    a = payload["activity"]
    c = payload["compliance"]
    f = payload["fleet_summary"]
    sections = []
    sections.append(("SECURITY POSTURE", _grade_band_pdf(p)))
    sections.append(("FLEET OVERVIEW", _stat_grid_pdf([
        (f.get("total_hosts", 0),  "Total hosts", None),
        (f.get("healthy", 0),      "Healthy",     _TIER_COLOR["Healthy"]),
        (f.get("at_risk", 0),      "At risk",     _TIER_COLOR["At Risk"]),
        (f.get("critical", 0),     "Critical",    _TIER_COLOR["Critical"]),
        (f.get("stale_count", 0),  "Stale",       _TIER_COLOR["Unknown"]),
    ], cols=5)))
    sections.append(("COMPLIANCE COVERAGE", _stat_grid_pdf([
        (f"{c['nist_csf']['coverage_percent']}%",   "NIST CSF",        None),
        (c['nist_csf']['rules_enabled'],            "NIST rules",       None),
        (f"{c['iso_27001']['coverage_percent']}%",  "ISO 27001",        None),
        (c['iso_27001']['rules_enabled'],           "ISO rules",        None),
    ], cols=4)))
    sections.append(("ACTIVITY THIS PERIOD", _stat_grid_pdf([
        (a.get('total_issues', 0), "Total issues", None),
        (a.get('open', 0),         "Open",         None),
        (a.get('resolved', 0),     "Resolved",     None),
        (a['by_severity']['CRITICAL'], "Critical", _SEV_COLOR['CRITICAL']),
    ], cols=4)))
    sections.append(("STRATEGIC RECOMMENDATIONS",
                     _numbered_list_pdf(payload.get("recommendations", []))))
    return sections


def _grade_band_pdf(p):
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT
    from reportlab.platypus import Paragraph, Table, TableStyle, Flowable
    from pulse.reports.pdf_report import COLOR_BORDER, CONTENT_WIDTH, COLOR_TITLE, COLOR_TEXT, COLOR_MUTED

    grade = p.get("grade") or "?"
    grade_color = colors.HexColor(_GRADE_COLOR.get(grade, "#6b7280"))
    score = p.get("score")
    score_str = "—" if score is None else str(int(score))

    class _Circle(Flowable):
        def wrap(self, *a): return (0.95 * inch, 0.95 * inch)
        def draw(self):
            c = self.canv
            r = 0.475 * inch
            c.saveState()
            c.setFillColor(grade_color)
            c.circle(r, r, r, stroke=0, fill=1)
            c.setFillColorRGB(1, 1, 1)
            c.setFont("Helvetica-Bold", 30)
            c.drawCentredString(r, r - 10, grade)
            c.restoreState()

    line_style = ParagraphStyle(
        "br_line", fontName="Helvetica-Bold", fontSize=14, leading=18,
        textColor=COLOR_TITLE, alignment=TA_LEFT, spaceAfter=4,
    )
    score_style = ParagraphStyle(
        "br_score", fontName="Helvetica", fontSize=11, leading=14,
        textColor=COLOR_TEXT, alignment=TA_LEFT, spaceAfter=4,
    )
    trend_style = ParagraphStyle(
        "br_trend", fontName="Helvetica", fontSize=10, leading=13,
        textColor=COLOR_MUTED, alignment=TA_LEFT,
    )
    trend = p.get("trend") or {}
    delta = trend.get("delta")
    if trend.get("direction") == "first_period":
        trend_line = "First period observed"
    else:
        verb = ("Improved" if (delta or 0) > 0
                else "Declined" if (delta or 0) < 0 else "Stable")
        trend_line = f"{verb} by {abs(int(delta or 0))} points vs. prior period"

    body = [
        Paragraph(f"{grade} &mdash; {html.escape(str(p.get('interpretation') or ''))}",
                   line_style),
        Paragraph(f"Overall score: <b>{html.escape(score_str)}</b> out of 100",
                   score_style),
        Paragraph(html.escape(trend_line), trend_style),
    ]
    table = Table([[_Circle(), body]],
                   colWidths=[1.1 * inch, CONTENT_WIDTH - 1.1 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
        ("BOX",          (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 16),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
        ("TOPPADDING",   (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
    ]))
    return table


def _numbered_list_pdf(items):
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import Paragraph
    from pulse.reports.pdf_report import COLOR_TEXT, COLOR_MUTED
    if not items:
        return Paragraph("No recommendations generated.",
                          ParagraphStyle("none", fontName="Helvetica",
                                          fontSize=10, textColor=COLOR_MUTED))
    style = ParagraphStyle(
        "rec", fontName="Helvetica", fontSize=11, leading=16,
        textColor=COLOR_TEXT, spaceAfter=4,
    )
    flow = []
    for i, line in enumerate(items, start=1):
        flow.append(Paragraph(f"<b>{i}.</b> &nbsp;{html.escape(line)}", style))
    return flow


# ---------------------------------------------------------------------------
# MITRE ATT&CK Coverage renderers
# ---------------------------------------------------------------------------

def render_mitre_coverage_html(payload: Dict[str, Any]) -> bytes:
    h = payload["header"]
    s = payload["summary"]
    matrix = payload.get("matrix", [])
    header = f"""
    <section>
      <h1>{_esc(h.get('title'))}</h1>
      <div class="small"><strong>Organization:</strong> {_esc(payload.get('organization'))}</div>
      <div class="small"><strong>Scope:</strong> {_esc(h.get('scope'))}</div>
      <div class="small muted">Generated {_esc(h.get('generated_at'))}</div>
    </section>"""
    tiles = "".join([
        _stat_tile(s.get("technique_count", 0),        "Techniques mapped"),
        _stat_tile(s.get("active_technique_count", 0), "Active techniques"),
        _stat_tile(s.get("covered_tactic_count", 0),   "Tactics with coverage"),
        _stat_tile(s.get("total_findings", 0),         "Findings"),
    ])
    body = f'<section><h2>Coverage Summary</h2><div class="stat-strip">{tiles}</div></section>'

    # Matrix section: one block per tactic
    matrix_html = ""
    for row in matrix:
        if row["technique_count"] == 0:
            continue
        tech_rows = "".join(
            f'<tr><td class="mono">{_esc(t["technique"])}</td>'
            f'<td>{", ".join(_esc(r) for r in t["rules"])}</td>'
            f'<td class="num">{t["findings_count"]}</td></tr>'
            for t in row["techniques"]
        )
        matrix_html += (
            f'<div style="margin-bottom:18px;"><h3 style="font-size:14px; margin-bottom:6px;">'
            f'{_esc(row["tactic"])} '
            f'<span class="muted small">— {row["technique_count"]} technique(s), {row["findings_count"]} finding(s)</span></h3>'
            f'<table class="data-table"><thead><tr>'
            f'<th>Technique</th><th>Mapped rules</th><th>Findings</th>'
            f'</tr></thead><tbody>{tech_rows}</tbody></table></div>'
        )
    body += f'<section><h2>Coverage Matrix</h2>{matrix_html or "<div class=\'muted\'>No techniques mapped.</div>"}</section>'

    # Top techniques
    top = payload.get("top_techniques", [])
    if top:
        top_rows = "".join(
            f'<tr><td class="mono">{_esc(t["technique"])}</td>'
            f'<td>{_esc(t["tactic"])}</td>'
            f'<td class="num">{t["findings_count"]}</td></tr>'
            for t in top
        )
        body += (
            '<section><h2>Top Triggered Techniques</h2>'
            '<table class="data-table"><thead><tr>'
            '<th>Technique</th><th>Tactic</th><th>Findings</th>'
            '</tr></thead>'
            f'<tbody>{top_rows}</tbody></table></section>'
        )

    if payload.get("uncovered_tactics"):
        body += (
            '<section><h2>Tactics Without Coverage</h2><ul>'
            + "".join(f"<li>{_esc(t)}</li>" for t in payload["uncovered_tactics"])
            + '</ul></section>'
        )
    if payload.get("silent_tactics"):
        body += (
            '<section><h2>Tactics With Detection But No Activity</h2>'
            '<div class="muted small">These tactics have at least one mapped rule but no findings in the reporting period.</div>'
            '<ul>'
            + "".join(f"<li>{_esc(t)}</li>" for t in payload["silent_tactics"])
            + '</ul></section>'
        )

    footer = (
        f"Pulse v{_esc((payload.get('footer') or {}).get('pulse_version'))}<br/>"
        f"{_esc((payload.get('footer') or {}).get('automated_note'))}"
    )
    return _html_scaffold(h.get("title"), header, body, footer)


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


def render_mitre_coverage_pdf(payload):
    return _table_pdf(
        title=payload["header"].get("title") or "MITRE ATT&CK Coverage Report",
        organization=payload.get("organization"),
        scope=payload["header"].get("scope"),
        generated_at=payload["header"].get("generated_at"),
        sections=_mitre_pdf_sections(payload),
        footer=payload.get("footer"),
    )


def _mitre_pdf_sections(payload):
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from pulse.reports.pdf_report import (
        COLOR_BORDER, COLOR_MUTED, COLOR_TITLE, CONTENT_WIDTH, COLOR_TEXT,
    )
    s = payload["summary"]
    sections = []
    sections.append(("COVERAGE SUMMARY", _stat_grid_pdf([
        (s.get("technique_count", 0), "Techniques mapped", None),
        (s.get("active_technique_count", 0), "Active techniques", None),
        (s.get("covered_tactic_count", 0), "Tactics covered", None),
        (s.get("total_findings", 0), "Findings", None),
    ], cols=4)))

    # Per-tactic matrix
    matrix_flow = []
    h_style = ParagraphStyle(
        "mt_head", fontName="Helvetica-Bold", fontSize=12, leading=14,
        textColor=COLOR_TITLE, spaceBefore=10, spaceAfter=4,
    )
    m_style = ParagraphStyle(
        "mt_meta", fontName="Helvetica", fontSize=9, leading=12,
        textColor=COLOR_MUTED, spaceAfter=4,
    )
    rule_style = ParagraphStyle(
        "mt_rule", fontName="Helvetica", fontSize=9, leading=11,
        textColor=COLOR_TEXT,
    )
    for row in payload.get("matrix", []):
        if row["technique_count"] == 0:
            continue
        matrix_flow.append(Paragraph(html.escape(row["tactic"]), h_style))
        matrix_flow.append(Paragraph(
            f"{row['technique_count']} technique(s) &middot; "
            f"{row['findings_count']} finding(s)",
            m_style,
        ))
        data = [["Technique", "Rules", "Findings"]]
        for t in row["techniques"]:
            data.append([
                t["technique"],
                Paragraph(", ".join(html.escape(r) for r in t["rules"]),
                           rule_style),
                str(t["findings_count"]),
            ])
        tbl = Table(data, colWidths=[1.1 * inch,
                                       CONTENT_WIDTH - 1.8 * inch,
                                       0.7 * inch], repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_MUTED),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.25, COLOR_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("ALIGN",         (2, 0), (2, -1), "RIGHT"),
        ]))
        matrix_flow.append(tbl)
        matrix_flow.append(Spacer(1, 8))

    sections.append(("COVERAGE MATRIX", matrix_flow or
                     [Paragraph("No techniques mapped.",
                                 ParagraphStyle("none", fontName="Helvetica",
                                                  fontSize=10,
                                                  textColor=COLOR_MUTED))]))
    return sections


# ---------------------------------------------------------------------------
# Compliance Gap renderers
# ---------------------------------------------------------------------------

def render_compliance_gap_html(payload: Dict[str, Any]) -> bytes:
    h = payload["header"]
    s = payload["summary"]
    defs = payload["definitions"]
    header = f"""
    <section>
      <h1>{_esc(h.get('title'))}</h1>
      <div class="small"><strong>Organization:</strong> {_esc(payload.get('organization'))}</div>
      <div class="small"><strong>Scope:</strong> {_esc(h.get('scope'))}</div>
      <div class="small muted">Generated {_esc(h.get('generated_at'))}</div>
    </section>"""

    tiles = "".join([
        _stat_tile(s.get("total_improvements", 0), "Total improvement items"),
        _stat_tile(s.get("uncovered_count", 0),    "Uncovered techniques"),
        _stat_tile(s.get("silent_count", 0),       "Silent rules"),
        _stat_tile(s.get("noisy_count", 0),        "Noisy rules"),
    ])
    body = f'<section><h2>Summary</h2><div class="stat-strip">{tiles}</div></section>'

    # Uncovered techniques
    rows = "".join(
        f'<tr><td class="mono">{_esc(u["technique"])}</td>'
        f'<td>{_esc(u["tactic"])}</td>'
        f'<td>{_esc(u["action"])}</td></tr>'
        for u in payload.get("uncovered_techniques", [])
    )
    body += (
        '<section><h2>Uncovered MITRE Techniques</h2>'
        + (f'<table class="data-table"><thead><tr>'
           f'<th>Technique</th><th>Tactic</th><th>Action</th>'
           f'</tr></thead><tbody>{rows}</tbody></table>'
           if rows else '<div class="muted">All known techniques have at least one enabled rule.</div>')
        + '</section>'
    )

    # Silent rules
    rows = "".join(
        f'<tr><td>{_esc(r["rule"])}</td>'
        f'<td>{_esc(r.get("severity"))}</td>'
        f'<td class="mono">{_esc(r.get("mitre") or "—")}</td>'
        f'<td>{_esc(r["action"])}</td></tr>'
        for r in payload.get("silent_rules", [])
    )
    body += (
        '<section><h2>Silent Rules</h2>'
        f'<div class="muted small">{_esc(defs["silent_rules"])}</div>'
        + (f'<table class="data-table"><thead><tr>'
           f'<th>Rule</th><th>Severity</th><th>MITRE</th><th>Action</th>'
           f'</tr></thead><tbody>{rows}</tbody></table>'
           if rows else '<div class="muted">No silent rules.</div>')
        + '</section>'
    )

    # Noisy rules
    rows = "".join(
        f'<tr><td>{_esc(r["rule"])}</td>'
        f'<td>{_esc(r.get("severity"))}</td>'
        f'<td class="num">{r["fp_rate"]}%</td>'
        f'<td class="num">{r["hits_total"]}</td>'
        f'<td>{_esc(r["action"])}</td></tr>'
        for r in payload.get("noisy_rules", [])
    )
    body += (
        '<section><h2>Noisy Rules</h2>'
        f'<div class="muted small">{_esc(defs["noisy_rules"])}</div>'
        + (f'<table class="data-table"><thead><tr>'
           f'<th>Rule</th><th>Severity</th><th>FP rate</th>'
           f'<th>Total hits</th><th>Action</th>'
           f'</tr></thead><tbody>{rows}</tbody></table>'
           if rows else '<div class="muted">No noisy rules.</div>')
        + '</section>'
    )

    footer = (
        f"Pulse v{_esc((payload.get('footer') or {}).get('pulse_version'))}<br/>"
        f"{_esc((payload.get('footer') or {}).get('automated_note'))}"
    )
    return _html_scaffold(h.get("title"), header, body, footer)


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


def render_compliance_gap_pdf(payload):
    return _table_pdf(
        title=payload["header"].get("title") or "Compliance Gap Analysis",
        organization=payload.get("organization"),
        scope=payload["header"].get("scope"),
        generated_at=payload["header"].get("generated_at"),
        sections=_compliance_gap_pdf_sections(payload),
        footer=payload.get("footer"),
    )


def _compliance_gap_pdf_sections(payload):
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import Paragraph, Table, TableStyle
    from pulse.reports.pdf_report import (
        COLOR_BORDER, COLOR_MUTED, COLOR_TITLE, CONTENT_WIDTH, COLOR_TEXT,
    )
    s = payload["summary"]
    sections = [("SUMMARY", _stat_grid_pdf([
        (s.get("total_improvements", 0), "Total items", None),
        (s.get("uncovered_count", 0),    "Uncovered",   None),
        (s.get("silent_count", 0),       "Silent",      None),
        (s.get("noisy_count", 0),        "Noisy",       None),
    ], cols=4))]

    body_style = ParagraphStyle(
        "cg_body", fontName="Helvetica", fontSize=9, leading=12,
        textColor=COLOR_TEXT,
    )

    def section(title, rows, header_cells):
        if not rows:
            return Paragraph("None.", ParagraphStyle("none",
                                                       fontName="Helvetica",
                                                       fontSize=10,
                                                       textColor=COLOR_MUTED))
        data = [header_cells] + rows
        tbl = Table(data, colWidths=[CONTENT_WIDTH / len(header_cells)] *
                                      len(header_cells), repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_MUTED),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.25, COLOR_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        return tbl

    sections.append(("UNCOVERED TECHNIQUES",
                     section("u", [
                         [u["technique"], u["tactic"],
                          Paragraph(html.escape(u["action"]), body_style)]
                         for u in payload.get("uncovered_techniques", [])
                     ], ["Technique", "Tactic", "Action"])))
    sections.append(("SILENT RULES",
                     section("s", [
                         [r["rule"], r.get("severity") or "",
                          Paragraph(html.escape(r["action"]), body_style)]
                         for r in payload.get("silent_rules", [])
                     ], ["Rule", "Severity", "Action"])))
    sections.append(("NOISY RULES",
                     section("n", [
                         [r["rule"], r.get("severity") or "",
                          f"{r['fp_rate']}%", str(r["hits_total"]),
                          Paragraph(html.escape(r["action"]), body_style)]
                         for r in payload.get("noisy_rules", [])
                     ], ["Rule", "Severity", "FP rate", "Hits", "Action"])))
    return sections


# ---------------------------------------------------------------------------
# Generic PDF document builder
# ---------------------------------------------------------------------------

def _stat_grid_pdf(tiles, *, cols):
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from pulse.reports.pdf_report import (
        COLOR_BORDER, COLOR_MUTED, COLOR_TITLE, CONTENT_WIDTH,
    )
    cell_w = CONTENT_WIDTH / cols
    cells = []
    for num, label, color_override in tiles:
        num_color = (colors.HexColor(color_override) if color_override
                     else COLOR_TITLE)
        num_style = ParagraphStyle(
            f"tile_{label}_n", fontName="Helvetica-Bold",
            fontSize=20, leading=22, textColor=num_color,
            alignment=TA_CENTER,
        )
        lbl_style = ParagraphStyle(
            f"tile_{label}_l", fontName="Helvetica",
            fontSize=8.5, leading=11, textColor=COLOR_MUTED,
            alignment=TA_CENTER,
        )
        cells.append([
            Paragraph(str(num), num_style),
            Spacer(1, 4),
            Paragraph(html.escape(label.upper()), lbl_style),
        ])
    tbl = Table([cells], colWidths=[cell_w] * cols)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
        ("BOX",           (0, 0), (-1, -1), 0.4, COLOR_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.4, COLOR_BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
    ]))
    return tbl


def _table_pdf(*, title, organization, scope, generated_at,
                sections, footer):
    from io import BytesIO
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        HRFlowable, Paragraph, SimpleDocTemplate, Spacer,
    )
    from pulse.reports.pdf_report import (
        COLOR_BORDER, COLOR_MUTED, COLOR_TEXT, COLOR_TITLE,
        LEFT_MARGIN, RIGHT_MARGIN, _draw_footer,
    )

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=LEFT_MARGIN, rightMargin=RIGHT_MARGIN,
        topMargin=0.75 * inch, bottomMargin=0.85 * inch,
        title="Pulse " + title,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "pdf_title", fontName="Helvetica-Bold",
        fontSize=20, leading=24, textColor=COLOR_TITLE, alignment=TA_LEFT,
        spaceAfter=2,
    )
    scope_style = ParagraphStyle(
        "pdf_scope", fontName="Helvetica",
        fontSize=10, leading=13, textColor=COLOR_TEXT, alignment=TA_LEFT,
    )
    muted_style = ParagraphStyle(
        "pdf_muted", fontName="Helvetica",
        fontSize=9, leading=12, textColor=COLOR_MUTED, alignment=TA_LEFT,
    )
    section_style = ParagraphStyle(
        "pdf_sec", fontName="Helvetica-Bold",
        fontSize=11, leading=14, textColor=COLOR_MUTED, alignment=TA_LEFT,
        spaceAfter=8, spaceBefore=16,
    )

    story = [
        Paragraph(title, title_style),
        Paragraph(f"<b>Organization:</b> {html.escape(str(organization))}",
                   scope_style),
        Paragraph(f"<b>Scope:</b> {html.escape(str(scope))}", scope_style),
        Paragraph(f"Generated {html.escape(str(generated_at))}", muted_style),
        Spacer(1, 10),
        HRFlowable(width="100%", thickness=0.6, color=COLOR_BORDER),
    ]
    for label, content in sections:
        story.append(Paragraph(label, section_style))
        if isinstance(content, list):
            story.extend(content)
        else:
            story.append(content)

    story.append(Spacer(1, 18))
    story.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER))
    footer_style = ParagraphStyle(
        "pdf_foot", fontName="Helvetica", fontSize=9, leading=12,
        textColor=COLOR_MUTED, alignment=TA_CENTER,
    )
    footer = footer or {}
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"Pulse v{html.escape(str(footer.get('pulse_version') or ''))}",
        footer_style,
    ))
    story.append(Paragraph(
        html.escape(str(footer.get("automated_note") or "")),
        footer_style,
    ))

    doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
    return buf.getvalue()


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
