"""Format renderers for the Incident Investigation Report.

PDF is the primary handoff format. JSON is for case-management ingest.
HTML is the in-browser view. CSV is a flat finding list, mostly there
to round out the contract.

Editorial notes:
    - The Chain-of-Custody section is load-bearing. Render the
      SHA-256 manifest as a mono table; the receiver will copy hashes
      out of it.
    - Raw event XML is the technical evidence. We show it in a
      monospace block, ASCII-only (decoded or escaped), capped at a
      sensible length per-finding so a 200-event report stays
      printable.
    - Light theme everywhere — IR reports get printed.
"""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Any, Dict


def _esc(s: Any) -> str:
    return html.escape(str(s) if s is not None else "")


_SEV_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f59e0b",
    "MEDIUM":   "#3b82f6",
    "LOW":      "#10b981",
}


def render_json(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, indent=2, sort_keys=False,
                       default=str).encode("utf-8")


# ---------------------------------------------------------------------------
# CSV — flat finding list
# ---------------------------------------------------------------------------

def render_csv(payload: Dict[str, Any]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "ref_id", "timestamp", "severity", "rule",
                 "hostname", "account", "source_ip", "intel_score",
                 "workflow_status", "sha256"])
    for f in payload.get("findings", []):
        intel = f.get("intel") or {}
        w.writerow([
            f.get("id"),
            f.get("ref_id") or "",
            f.get("timestamp") or "",
            f.get("severity"),
            f.get("rule"),
            f.get("hostname") or "",
            f.get("account") or "",
            f.get("source_ip") or "",
            intel.get("score") if isinstance(intel, dict) else "",
            f.get("workflow_status"),
            f.get("sha256"),
        ])

    w.writerow([])
    w.writerow(["chain_of_custody", "report_sha256",
                 payload.get("chain_of_custody", {}).get("report_sha256", "")])
    return buf.getvalue().encode("utf-8-sig")


# ---------------------------------------------------------------------------
# HTML — light theme, print-friendly
# ---------------------------------------------------------------------------

def _truncate_xml_for_html(xml: str, *, limit: int = 4000) -> str:
    if not xml:
        return ""
    if len(xml) <= limit:
        return xml
    return xml[:limit] + "\n... (truncated; see JSON export for full XML)"


def render_html(payload: Dict[str, Any]) -> bytes:
    h = payload.get("header", {})
    assets = payload.get("affected_assets", {})
    timeline = payload.get("timeline", [])
    findings = payload.get("findings", [])
    blocks = payload.get("blocks_pushed", [])
    coc = payload.get("chain_of_custody", {})
    footer = payload.get("footer", {})

    # Affected-assets pills
    def pills(items, kind):
        if not items:
            return f'<span class="muted">No {kind} identified.</span>'
        return "".join(
            f'<span class="asset-pill">{_esc(i)}</span>' for i in items
        )

    # Timeline table rows
    timeline_rows = ""
    for t in timeline:
        sev = (t.get("severity") or "LOW").upper()
        col = _SEV_COLOR.get(sev, "#6b7280")
        timeline_rows += (
            f'<tr>'
            f'<td class="mono">{_esc(t.get("timestamp"))}</td>'
            f'<td><span class="sev-pill" style="background:{col}1f;color:{col};border:1px solid {col}55;">{sev}</span></td>'
            f'<td>{_esc(t.get("rule"))}</td>'
            f'<td>{_esc(t.get("hostname"))}</td>'
            f'<td>{_esc(t.get("account"))}</td>'
            f'<td class="mono">{_esc(t.get("source_ip"))}</td>'
            f'</tr>'
        )
    if not timeline_rows:
        timeline_rows = (
            '<tr><td colspan="6" class="muted center">No events in scope.</td></tr>'
        )

    # Per-finding deep dives
    deep_dive_blocks = ""
    for i, f in enumerate(findings, start=1):
        sev = (f.get("severity") or "LOW").upper()
        sev_color = _SEV_COLOR.get(sev, "#6b7280")
        notes_html = ""
        if f.get("notes"):
            notes_html = '<div class="dive-section-label">Analyst notes</div>'
            for n in f["notes"]:
                notes_html += (
                    f'<div class="note">'
                    f'<div class="note-meta">{_esc(n.get("author") or "—")} '
                    f'<span class="muted">· {_esc(n.get("created_at") or "")}</span></div>'
                    f'<div class="note-body">{_esc(n.get("body"))}</div>'
                    f'</div>'
                )

        intel = f.get("intel") or {}
        intel_html = ""
        if isinstance(intel, dict) and intel:
            intel_html = (
                f'<div class="dive-section-label">Threat intel</div>'
                f'<div class="dive-kv">'
                f'<div><span class="muted">IP:</span> <span class="mono">{_esc(f.get("source_ip"))}</span></div>'
                f'<div><span class="muted">Score:</span> {_esc(intel.get("score") or "—")}/100</div>'
                f'<div><span class="muted">Country:</span> {_esc(intel.get("country") or "—")}</div>'
                f'<div><span class="muted">ISP:</span> {_esc(intel.get("isp") or "—")}</div>'
                f'</div>'
            )

        raw_xml = _truncate_xml_for_html(f.get("raw_xml") or "")
        raw_block = (
            f'<div class="dive-section-label">Raw event</div>'
            f'<pre class="raw-xml">{_esc(raw_xml)}</pre>'
        ) if raw_xml else ""

        deep_dive_blocks += f"""
        <div class="dive-card">
          <div class="dive-head">
            <span class="dive-rank">#{i}</span>
            <span class="sev-pill" style="background:{sev_color}1f;color:{sev_color};border:1px solid {sev_color}55;">{sev}</span>
            <span class="dive-rule">{_esc(f.get("rule"))}</span>
            <span class="mono muted">{_esc(f.get("ref_id") or f.get("id"))}</span>
          </div>
          <div class="dive-kv">
            <div><span class="muted">When:</span> <span class="mono">{_esc(f.get("timestamp"))}</span></div>
            <div><span class="muted">Host:</span> {_esc(f.get("hostname"))}</div>
            <div><span class="muted">Account:</span> {_esc(f.get("account") or "—")}</div>
            <div><span class="muted">Source IP:</span> <span class="mono">{_esc(f.get("source_ip") or "—")}</span></div>
            <div><span class="muted">MITRE:</span> <span class="mono">{_esc(f.get("mitre") or "—")}</span></div>
            <div><span class="muted">Status:</span> {_esc(f.get("workflow_status"))}</div>
          </div>
          {f'<div class="dive-section-label">Description</div><div class="dive-body">{_esc(f.get("details") or f.get("description") or "")}</div>' if (f.get("details") or f.get("description")) else ""}
          {intel_html}
          {notes_html}
          {raw_block}
          <div class="dive-section-label">Integrity</div>
          <div class="mono muted small">SHA-256: {_esc(f.get("sha256"))}</div>
        </div>"""

    # Blocks pushed
    blocks_html = ""
    if blocks:
        block_rows = "".join(
            f'<tr>'
            f'<td class="mono">{_esc(b.get("ip"))}</td>'
            f'<td>{_esc(b.get("status"))}</td>'
            f'<td>{_esc(b.get("pushed_at") or b.get("added_at"))}</td>'
            f'<td>{_esc(b.get("comment") or "—")}</td>'
            f'</tr>'
            for b in blocks
        )
        blocks_html = (
            f'<table class="data-table"><thead><tr>'
            f'<th>IP</th><th>Status</th><th>Pushed at</th><th>Comment</th>'
            f'</tr></thead><tbody>{block_rows}</tbody></table>'
        )
    else:
        blocks_html = '<div class="muted">No firewall blocks recorded for incident IPs.</div>'

    # Chain of custody
    coc_rows = "".join(
        f'<tr>'
        f'<td>{_esc(row.get("id"))}</td>'
        f'<td class="mono">{_esc(row.get("ref_id") or "—")}</td>'
        f'<td>{_esc(row.get("rule"))}</td>'
        f'<td class="mono small">{_esc(row.get("timestamp") or "")}</td>'
        f'<td class="mono small">{_esc(row.get("sha256"))}</td>'
        f'</tr>'
        for row in coc.get("manifest", [])
    )

    title = h.get("title") or "Incident Investigation Report"
    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_esc(title)}</title>
<style>
  @page {{ size: Letter; margin: 0.55in; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #fff; color: #1f2328; margin: 0; padding: 36px 0;
    -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }}
  .container {{ max-width: 940px; margin: 0 auto; padding: 0 36px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px 0; color: #111827; }}
  h2 {{
    font-size: 13px; margin: 32px 0 12px 0;
    text-transform: uppercase; letter-spacing: 0.7px;
    color: #6b7280; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px;
  }}
  .muted {{ color: #6b7280; }}
  .mono  {{ font-family: SFMono-Regular, Consolas, monospace; font-size: 12px; }}
  .small {{ font-size: 11px; }}
  .center {{ text-align: center; }}

  .header-meta {{ font-size: 12px; line-height: 1.6; }}
  .exec-line {{
    font-size: 14px; font-weight: 500; line-height: 1.6;
    background: #fef2f2; border-left: 4px solid #ef4444;
    padding: 12px 16px; border-radius: 6px; margin-top: 12px;
  }}

  .asset-pill {{
    display: inline-block; background: #f9fafb; border: 1px solid #e5e7eb;
    border-radius: 999px; padding: 3px 10px; margin: 2px 4px 2px 0;
    font-size: 12px; line-height: 1.4;
  }}

  .sev-pill {{
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 10px; font-weight: 700; letter-spacing: 0.4px; line-height: 1;
    vertical-align: middle;
  }}

  table.data-table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  table.data-table th {{
    text-align: left; font-weight: 600; color: #374151;
    border-bottom: 2px solid #d1d5db; padding: 6px 8px; background: #f9fafb;
  }}
  table.data-table td {{ padding: 6px 8px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}

  .dive-card {{
    background: #fff; border: 1px solid #e5e7eb;
    border-radius: 6px; padding: 18px; margin-bottom: 14px;
  }}
  .dive-head {{
    display: flex; align-items: center; gap: 10px;
    flex-wrap: wrap; margin-bottom: 10px;
  }}
  .dive-rank {{
    background: #1f2937; color: #fff; width: 24px; height: 24px;
    border-radius: 50%; display: inline-flex;
    align-items: center; justify-content: center;
    font-size: 11px; font-weight: 700;
  }}
  .dive-rule {{ font-weight: 600; font-size: 14px; }}
  .dive-kv {{
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 4px 16px;
    font-size: 12px; line-height: 1.6;
  }}
  .dive-section-label {{
    font-size: 10px; text-transform: uppercase; letter-spacing: 0.6px;
    color: #6b7280; margin-top: 12px; margin-bottom: 4px;
  }}
  .dive-body {{ font-size: 13px; line-height: 1.55; }}
  .raw-xml {{
    background: #0d1117; color: #c9d1d9;
    padding: 10px 12px; border-radius: 6px;
    font-family: SFMono-Regular, Consolas, monospace; font-size: 11px;
    white-space: pre-wrap; word-wrap: break-word; overflow-x: auto;
    max-height: 240px;
  }}
  .note {{
    background: #f9fafb; border-left: 3px solid #3b82f6;
    padding: 8px 12px; border-radius: 4px; margin-bottom: 6px;
  }}
  .note-meta {{ font-size: 11px; font-weight: 600; }}
  .note-body {{ font-size: 12px; line-height: 1.5; margin-top: 2px; }}

  .coc-banner {{
    background: #f9fafb; border: 1px solid #e5e7eb;
    border-radius: 6px; padding: 14px 16px; margin-bottom: 12px;
    font-size: 12px; line-height: 1.6;
  }}
  .coc-hash {{
    font-family: SFMono-Regular, Consolas, monospace; font-size: 11px;
    word-break: break-all; background: #f3f4f6; padding: 6px 10px;
    border-radius: 4px;
  }}

  footer {{
    margin-top: 40px; padding-top: 14px;
    border-top: 1px solid #e5e7eb;
    font-size: 11px; color: #6b7280; text-align: center; line-height: 1.6;
  }}
  @media print {{
    body {{ padding: 0; }}
    .dive-card {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="container">

  <section>
    <h1>{_esc(title)}</h1>
    <div class="header-meta">
      <div><strong>Organization:</strong> {_esc(h.get("organization"))}</div>
      <div><strong>Scope:</strong> {_esc(h.get("scope"))}</div>
      <div><strong>Investigator:</strong> {_esc(h.get("investigator"))}</div>
      <div class="muted">Generated {_esc(h.get("generated_at"))}</div>
    </div>
    <div class="exec-line">{_esc(payload.get("executive_line"))}</div>
  </section>

  <section>
    <h2>Affected Assets</h2>
    <div><strong>Hosts:</strong> {pills(assets.get("hosts", []), "hosts")}</div>
    <div style="margin-top:8px;"><strong>Accounts:</strong> {pills(assets.get("accounts", []), "accounts")}</div>
    <div style="margin-top:8px;"><strong>Source IPs:</strong> {pills(assets.get("ips", []), "source IPs")}</div>
  </section>

  <section>
    <h2>Detailed Timeline</h2>
    <table class="data-table">
      <thead><tr>
        <th>Timestamp</th><th>Severity</th><th>Rule</th>
        <th>Host</th><th>Account</th><th>Source IP</th>
      </tr></thead>
      <tbody>{timeline_rows}</tbody>
    </table>
  </section>

  <section>
    <h2>Per-Finding Deep Dive</h2>
    {deep_dive_blocks or '<div class="muted">No findings in scope.</div>'}
  </section>

  <section>
    <h2>Remediation Actions Taken</h2>
    {blocks_html}
  </section>

  <section>
    <h2>Chain of Custody</h2>
    <div class="coc-banner">
      <div><strong>Generated:</strong> {_esc(coc.get("generated_at"))}</div>
      <div><strong>Investigator:</strong> {_esc(coc.get("investigator"))}</div>
      <div style="margin-top:6px;"><strong>Algorithm:</strong> {_esc(coc.get("algorithm"))}</div>
      <div style="margin-top:6px;"><strong>Report digest (SHA-256):</strong></div>
      <div class="coc-hash">{_esc(coc.get("report_sha256"))}</div>
    </div>
    <table class="data-table">
      <thead><tr>
        <th>ID</th><th>Ref</th><th>Rule</th>
        <th>Timestamp</th><th>SHA-256</th>
      </tr></thead>
      <tbody>{coc_rows}</tbody>
    </table>
  </section>

  <footer>
    Pulse v{_esc(footer.get("pulse_version"))}<br/>
    {_esc(footer.get("automated_note"))}
  </footer>

</div>
</body>
</html>"""
    return doc.encode("utf-8")


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
        HRFlowable, KeepTogether, Paragraph, Preformatted,
        SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    from pulse.reports.pdf_report import (
        COLOR_BORDER, COLOR_MUTED, COLOR_TEXT, COLOR_TITLE,
        CONTENT_WIDTH, LEFT_MARGIN, RIGHT_MARGIN,
        PILL_BG, PILL_FG, _draw_footer,
    )

    h = payload.get("header", {})
    assets = payload.get("affected_assets", {})
    timeline = payload.get("timeline", [])
    findings = payload.get("findings", [])
    blocks = payload.get("blocks_pushed", [])
    coc = payload.get("chain_of_custody", {})
    footer = payload.get("footer", {})

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=LEFT_MARGIN, rightMargin=RIGHT_MARGIN,
        topMargin=0.7 * inch, bottomMargin=0.85 * inch,
        title="Pulse Incident Investigation Report",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "INC_Title", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=20, leading=24, textColor=COLOR_TITLE, alignment=TA_LEFT,
        spaceAfter=2,
    )
    meta_style = ParagraphStyle(
        "INC_Meta", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=14, textColor=COLOR_TEXT, alignment=TA_LEFT,
    )
    muted_style = ParagraphStyle(
        "INC_Muted", parent=styles["Normal"], fontName="Helvetica",
        fontSize=9, leading=12, textColor=COLOR_MUTED, alignment=TA_LEFT,
    )
    section_style = ParagraphStyle(
        "INC_Section", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=11, leading=14, textColor=COLOR_MUTED, alignment=TA_LEFT,
        spaceAfter=8, spaceBefore=16,
    )
    body_style = ParagraphStyle(
        "INC_Body", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=14, textColor=COLOR_TEXT, alignment=TA_LEFT,
    )
    mono_style = ParagraphStyle(
        "INC_Mono", parent=body_style, fontName="Courier", fontSize=9,
        leading=12, textColor=COLOR_TEXT,
    )
    exec_style = ParagraphStyle(
        "INC_Exec", parent=body_style, fontSize=12, leading=16,
        textColor=COLOR_TEXT, leftIndent=10,
    )
    rule_head_style = ParagraphStyle(
        "INC_RuleHead", parent=body_style, fontName="Helvetica-Bold",
        fontSize=12, leading=15, textColor=COLOR_TITLE, spaceAfter=4,
    )
    raw_style = ParagraphStyle(
        "INC_Raw", parent=body_style, fontName="Courier", fontSize=7.5,
        leading=10, textColor=COLOR_TEXT,
    )

    story = []

    # -- Header ---------------------------------------------------------
    story.append(Paragraph(h.get("title") or "Incident Investigation Report",
                            title_style))
    story.append(Spacer(1, 4))
    for label, value in (
        ("Organization", h.get("organization")),
        ("Scope",        h.get("scope")),
        ("Investigator", h.get("investigator")),
    ):
        story.append(Paragraph(
            f"<b>{label}:</b> {html.escape(str(value))}", meta_style,
        ))
    story.append(Paragraph(
        f"Generated {html.escape(str(h.get('generated_at')))}",
        muted_style,
    ))
    story.append(Spacer(1, 10))
    # Executive line box
    exec_box = Table(
        [[Paragraph(html.escape(payload.get("executive_line", "")), exec_style)]],
        colWidths=[CONTENT_WIDTH],
    )
    exec_box.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
        ("LINEBEFORE",   (0, 0), (0, -1), 3, colors.HexColor("#ef4444")),
        ("LEFTPADDING",  (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING",   (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(exec_box)

    # -- Affected Assets -----------------------------------------------
    story.append(Paragraph("AFFECTED ASSETS", section_style))
    for label, items in (
        ("Hosts",      assets.get("hosts")),
        ("Accounts",   assets.get("accounts")),
        ("Source IPs", assets.get("ips")),
    ):
        value = ", ".join(items or []) or "—"
        story.append(Paragraph(
            f"<b>{label}:</b> {html.escape(value)}", body_style,
        ))

    # -- Detailed Timeline ---------------------------------------------
    story.append(Paragraph("DETAILED TIMELINE", section_style))
    if timeline:
        rows = [["Timestamp", "Sev", "Rule", "Host", "Account", "Source IP"]]
        for t in timeline[:120]:
            rows.append([
                (t.get("timestamp") or "")[:19],
                (t.get("severity") or ""),
                t.get("rule") or "",
                t.get("hostname") or "",
                t.get("account") or "",
                t.get("source_ip") or "",
            ])
        tbl = Table(rows, colWidths=[
            1.3 * inch, 0.6 * inch,
            CONTENT_WIDTH - 4.6 * inch,
            1.2 * inch, 1.0 * inch, 1.2 * inch,
        ], repeatRows=1)
        tstyle = [
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_MUTED),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.25, COLOR_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ]
        for i, t in enumerate(timeline[:120], start=1):
            sev = (t.get("severity") or "LOW").upper()
            if sev in PILL_BG:
                tstyle.append(("BACKGROUND", (1, i), (1, i), PILL_BG[sev]))
                tstyle.append(("TEXTCOLOR",  (1, i), (1, i), PILL_FG[sev]))
        tbl.setStyle(TableStyle(tstyle))
        story.append(tbl)
        if len(timeline) > 120:
            story.append(Paragraph(
                f"... and {len(timeline) - 120} more events (see JSON export).",
                muted_style,
            ))
    else:
        story.append(Paragraph("No events in scope.", muted_style))

    # -- Per-Finding Deep Dive -----------------------------------------
    story.append(Paragraph("PER-FINDING DEEP DIVE", section_style))
    for i, f in enumerate(findings, start=1):
        sev = (f.get("severity") or "LOW").upper()
        blocks_inner = []
        head_text = (
            f"<b>#{i}. {html.escape(f.get('rule') or 'Unknown')}</b> "
            f"&nbsp;&middot;&nbsp; "
            f"<font color='{(PILL_FG.get(sev) or COLOR_MUTED).hexval()}'>"
            f"{sev}</font>"
            f"&nbsp;&middot;&nbsp; "
            f"<font color='{COLOR_MUTED.hexval()}'>"
            f"{html.escape(str(f.get('ref_id') or f.get('id') or ''))}"
            f"</font>"
        )
        blocks_inner.append(Paragraph(head_text, rule_head_style))

        kv_lines = []
        for label, val in (
            ("When",       f.get("timestamp")),
            ("Host",       f.get("hostname")),
            ("Account",    f.get("account") or "—"),
            ("Source IP",  f.get("source_ip") or "—"),
            ("MITRE",      f.get("mitre") or "—"),
            ("Status",     f.get("workflow_status")),
        ):
            kv_lines.append(
                f"<b>{label}:</b> {html.escape(str(val) if val is not None else '—')}"
            )
        blocks_inner.append(Paragraph(" &nbsp; · &nbsp; ".join(kv_lines), body_style))

        desc = f.get("details") or f.get("description")
        if desc:
            blocks_inner.append(Spacer(1, 4))
            blocks_inner.append(Paragraph(
                f"<b>Description:</b> {html.escape(desc)}", body_style,
            ))

        intel = f.get("intel") or {}
        if isinstance(intel, dict) and intel:
            blocks_inner.append(Spacer(1, 4))
            blocks_inner.append(Paragraph(
                f"<b>Threat intel:</b> "
                f"score {html.escape(str(intel.get('score') or '—'))}/100, "
                f"country {html.escape(str(intel.get('country') or '—'))}, "
                f"isp {html.escape(str(intel.get('isp') or '—'))}",
                body_style,
            ))

        for note in (f.get("notes") or []):
            blocks_inner.append(Spacer(1, 4))
            note_text = (
                f"<b>Note · {html.escape(str(note.get('author') or '—'))}</b> "
                f"<font color='{COLOR_MUTED.hexval()}'>"
                f"({html.escape(str(note.get('created_at') or ''))})</font><br/>"
                f"{html.escape(str(note.get('body') or ''))}"
            )
            blocks_inner.append(Paragraph(note_text, body_style))

        if f.get("raw_xml"):
            blocks_inner.append(Spacer(1, 6))
            blocks_inner.append(Paragraph("<b>Raw event:</b>", body_style))
            xml = f["raw_xml"]
            if len(xml) > 1800:
                xml = xml[:1800] + "\n... (truncated; see JSON export)"
            blocks_inner.append(Preformatted(xml, raw_style))

        blocks_inner.append(Spacer(1, 4))
        blocks_inner.append(Paragraph(
            f"<font color='{COLOR_MUTED.hexval()}' size='8'>"
            f"<b>SHA-256:</b> "
            f"{html.escape(str(f.get('sha256') or ''))}</font>",
            body_style,
        ))

        card = Table([[blocks_inner]], colWidths=[CONTENT_WIDTH])
        card.setStyle(TableStyle([
            ("BOX",          (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("LEFTPADDING",  (0, 0), (-1, -1), 14),
            ("RIGHTPADDING", (0, 0), (-1, -1), 14),
            ("TOPPADDING",   (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ]))
        story.append(KeepTogether(card))
        story.append(Spacer(1, 8))

    if not findings:
        story.append(Paragraph("No findings in scope.", muted_style))

    # -- Remediation actions taken -------------------------------------
    story.append(Paragraph("REMEDIATION ACTIONS TAKEN", section_style))
    if blocks:
        rows = [["IP", "Status", "Pushed at", "Comment"]]
        for b in blocks:
            rows.append([
                b.get("ip") or "—",
                b.get("status") or "—",
                b.get("pushed_at") or b.get("added_at") or "—",
                b.get("comment") or "—",
            ])
        tbl = Table(rows, colWidths=[
            1.4 * inch, 1.0 * inch, 1.5 * inch,
            CONTENT_WIDTH - 3.9 * inch,
        ], repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_MUTED),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.25, COLOR_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(tbl)
    else:
        story.append(Paragraph(
            "No firewall blocks recorded for incident IPs.", muted_style,
        ))

    # -- Chain of Custody ----------------------------------------------
    story.append(Paragraph("CHAIN OF CUSTODY", section_style))
    coc_banner = Table(
        [[Paragraph(
            f"<b>Generated:</b> {html.escape(str(coc.get('generated_at')))}<br/>"
            f"<b>Investigator:</b> {html.escape(str(coc.get('investigator')))}<br/>"
            f"<b>Algorithm:</b> {html.escape(str(coc.get('algorithm')))}<br/>"
            f"<b>Report digest (SHA-256):</b>",
            body_style,
        )],
        [Paragraph(html.escape(str(coc.get("report_sha256") or "")), mono_style)]],
        colWidths=[CONTENT_WIDTH],
    )
    coc_banner.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
        ("BOX",          (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("LEFTPADDING",  (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING",   (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(coc_banner)
    story.append(Spacer(1, 8))

    if coc.get("manifest"):
        rows = [["ID", "Ref", "Rule", "Timestamp", "SHA-256"]]
        for row in coc["manifest"]:
            rows.append([
                str(row.get("id") or ""),
                row.get("ref_id") or "—",
                row.get("rule") or "",
                (row.get("timestamp") or "")[:19],
                row.get("sha256") or "",
            ])
        tbl = Table(rows, colWidths=[
            0.5 * inch, 0.9 * inch, 1.7 * inch, 1.1 * inch,
            CONTENT_WIDTH - 4.2 * inch,
        ], repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("FONTNAME",      (4, 1), (4, -1), "Courier"),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_MUTED),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.25, COLOR_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(tbl)

    # -- Footer note ---------------------------------------------------
    story.append(Spacer(1, 18))
    story.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER))
    footer_style = ParagraphStyle(
        "INC_FootNote", parent=body_style, fontSize=9, leading=12,
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
