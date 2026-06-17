"""Format renderers for the Incident Investigation Report.

PDF is the primary handoff format (professional, print-friendly, built on
the shared `report_theme` design system so every template looks the same).
JSON is for case-management ingest, CSV is a flat finding list, HTML is the
in-browser view — both also use the shared light theme.

The Chain-of-Custody section is load-bearing: the SHA-256 manifest is what a
receiver verifies, so the report digest is rendered in full and per-finding
hashes are truncated for layout only (the full values live in the JSON).
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List

import pulse.reports.report_theme as T

REPORT_TYPE = "Incident Investigation Report"
_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _esc(s: Any) -> str:
    return T.esc(s)


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------

def _sev_counts(findings: List[dict]) -> Dict[str, int]:
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        k = T.sev_key(f.get("severity"))
        if k in counts:
            counts[k] += 1
    return counts


def _top_severity(findings: List[dict]) -> str:
    present = {T.sev_key(f.get("severity")) for f in findings}
    for s in _SEV_ORDER:
        if s in present:
            return s
    return "NONE"


def _classification_label(sev: str) -> str:
    return {
        "CRITICAL": "Critical incident",
        "HIGH":     "High-severity incident",
        "MEDIUM":   "Moderate findings",
        "LOW":      "Low-severity findings",
    }.get(T.sev_key(sev), "No active findings")


def _short_sha(sha: Any, keep: int = 24) -> str:
    s = str(sha or "")
    return (s[:keep] + "…") if len(s) > keep + 1 else (s or "—")


# ---------------------------------------------------------------------------
# JSON / CSV (unchanged contract)
# ---------------------------------------------------------------------------

def render_json(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, indent=2, sort_keys=False, default=str).encode("utf-8")


def render_csv(payload: Dict[str, Any]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "ref_id", "timestamp", "severity", "rule",
                "hostname", "account", "source_ip", "intel_score",
                "workflow_status", "sha256"])
    for f in payload.get("findings", []):
        intel = f.get("intel") or {}
        w.writerow([
            f.get("id"), f.get("ref_id") or "", f.get("timestamp") or "",
            f.get("severity"), f.get("rule"), f.get("hostname") or "",
            f.get("account") or "", f.get("source_ip") or "",
            intel.get("score") if isinstance(intel, dict) else "",
            f.get("workflow_status"), f.get("sha256"),
        ])
    w.writerow([])
    w.writerow(["chain_of_custody", "report_sha256",
                payload.get("chain_of_custody", {}).get("report_sha256", "")])
    return buf.getvalue().encode("utf-8-sig")


# ---------------------------------------------------------------------------
# HTML — light theme, print-friendly (shared components)
# ---------------------------------------------------------------------------

def _count_chip_html(sev: str, n: int) -> str:
    k = T.sev_key(sev)
    return ('<span class="rpt-pill" style="color:' + T.SEV_FG[k] + ';background:' + T.SEV_BG[k] + ';">'
            + str(n) + ' ' + k + '</span>')


def _finding_card_html(num: int, f: dict) -> str:
    k = T.sev_key(f.get("severity"))
    head = ('<div class="rpt-card-head">'
            '<span class="rpt-card-num">#' + str(num) + '</span>'
            '<span class="rpt-card-rule">' + _esc(f.get("rule") or "Unknown") + '</span>'
            + T.html_pill(k))
    if f.get("ref_id"):
        head += '<span class="rpt-badge rpt-mono">' + _esc(f["ref_id"]) + '</span>'
    if f.get("mitre"):
        head += '<span class="rpt-badge" style="color:' + T.C_ACCENT + ';border-color:' + T.C_ACCENT + ';">' + _esc(f["mitre"]) + '</span>'
    head += T.html_status_badge(f.get("workflow_status")) + '</div>'

    def mv(label, val):
        return '<b>' + label + '</b> ' + (_esc(val) if val else '<span class="rpt-none">None</span>')
    meta = ('<div class="rpt-card-meta">' +
            ' &nbsp;·&nbsp; '.join([mv("When", f.get("timestamp")), mv("Host", f.get("hostname")),
                                    mv("Account", f.get("account")), mv("Source IP", f.get("source_ip"))]) +
            '</div>')
    desc = ('<div class="rpt-card-desc">' +
            (_esc(f.get("description")) if f.get("description")
             else '<span class="rpt-none">No description recorded.</span>') + '</div>')
    sha = '<div class="rpt-card-sha rpt-mono">Evidence SHA-256: ' + _esc(f.get("sha256") or "—") + '</div>'
    return ('<div class="rpt-card" style="border-left-color:' + T.SEV_FG[k] + ';">' +
            head + meta + desc + sha + '</div>')


def _coc_html(coc: dict, footer: dict) -> str:
    grid = T.html_metadata_grid([
        ("Generated", _esc(coc.get("generated_at"))),
        ("Investigator", _esc(coc.get("investigator"))),
        ("Algorithm", _esc(coc.get("algorithm"))),
    ])
    digest = ('<div class="rpt-coc-digest"><span class="lbl">Report digest (SHA-256)</span>'
              '<span class="rpt-mono">' + _esc(coc.get("report_sha256") or "—") + '</span></div>')
    manifest = coc.get("manifest", [])
    if manifest:
        rows = [[
            _esc(m.get("id")),
            '<span class="rpt-mono">' + (_esc(m.get("ref_id")) if m.get("ref_id") else "—") + '</span>',
            _esc(m.get("rule")),
            '<span class="rpt-mono">' + _esc(m.get("timestamp") or "—") + '</span>',
            '<span class="rpt-mono" title="' + _esc(m.get("sha256")) + '">' + _esc(_short_sha(m.get("sha256"))) + '</span>',
        ] for m in manifest]
        mtable = T.html_table(["ID", "Ref", "Rule", "Timestamp", "SHA-256"], rows, num_cols=[0])
    else:
        mtable = '<div class="rpt-none">No evidence items in manifest.</div>'
    warn = T.html_callout('<b>Verification.</b> ' + _esc(footer.get("automated_note") or ""), "high")
    return '<div class="rpt-coc">' + grid + digest + mtable + '</div>' + warn


def render_html(payload: Dict[str, Any]) -> bytes:
    h = payload.get("header", {})
    assets = payload.get("affected_assets", {})
    timeline = payload.get("timeline", [])
    findings = payload.get("findings", [])
    blocks = payload.get("blocks_pushed", [])
    coc = payload.get("chain_of_custody", {})
    footer = payload.get("footer", {})
    counts = _sev_counts(findings)
    top = _top_severity(findings)

    # 1. Title block
    body = T.html_eyebrow_title(REPORT_TYPE.upper(), h.get("title") or REPORT_TYPE)
    body += T.html_metadata_grid([
        ("Organization", _esc(h.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Investigator", _esc(h.get("investigator"))),
        ("Generated", _esc(h.get("generated_at"))),
    ])
    body += T.html_classification_banner(top, _classification_label(top))

    # 2. Executive summary
    chips = "".join(_count_chip_html(s, counts[s]) for s in _SEV_ORDER if counts.get(s)) \
        or '<span class="rpt-none">No findings in scope</span>'
    exec_inner = ('<div class="rpt-callout-verdict">' + _esc(payload.get("executive_line") or "") + '</div>'
                  '<div class="rpt-chips">' + chips + '</div>')
    body += T.html_section("Executive Summary", T.html_callout(exec_inner, top), top)

    # 3. Affected assets
    def asset_row(label, vals):
        v = ", ".join(_esc(x) for x in vals) if vals else T.html_none()
        return '<div class="rpt-asset"><div class="k">' + label + '</div><div class="v">' + v + '</div></div>'
    assets_html = (asset_row("Hosts", assets.get("hosts")) +
                   asset_row("Accounts", assets.get("accounts")) +
                   asset_row("Source IPs", assets.get("ips")))
    body += T.html_section("Affected Assets", assets_html)

    # 4. Detailed timeline
    if timeline:
        rows = [[
            '<span class="rpt-mono">' + _esc(t.get("timestamp") or "—") + '</span>',
            T.html_pill(t.get("severity")),
            _esc(t.get("rule")),
            _esc(t.get("hostname")) if t.get("hostname") else T.html_none(),
            _esc(t.get("account")) if t.get("account") else T.html_none(),
            ('<span class="rpt-mono">' + _esc(t.get("source_ip")) + '</span>') if t.get("source_ip") else T.html_none(),
        ] for t in timeline]
        tl = T.html_table(["Timestamp", "Severity", "Rule", "Host", "Account", "Source IP"], rows)
    else:
        tl = '<div class="rpt-none">No timeline events in scope.</div>'
    body += T.html_section("Detailed Timeline", tl)

    # 5. Per-finding deep dive
    cards = "".join(_finding_card_html(i + 1, f) for i, f in enumerate(findings)) \
        or '<div class="rpt-none">No findings in scope.</div>'
    body += T.html_section("Per-Finding Deep Dive", cards)

    # 6. Remediation actions taken
    if blocks:
        rrows = [[
            '<span class="rpt-mono">' + _esc(b.get("ip")) + '</span>',
            _esc(b.get("status") or "—"),
            '<span class="rpt-mono">' + _esc(b.get("pushed_at") or b.get("added_at") or "—") + '</span>',
            _esc(b.get("comment")) if b.get("comment") else T.html_none(),
        ] for b in blocks]
        rem = T.html_table(["Blocked IP", "Status", "When", "Note"], rrows)
    else:
        rem = '<div class="rpt-none">No remediation actions recorded for this incident.</div>'
    body += T.html_section("Remediation Actions Taken", rem)

    # 7. Chain of custody
    body += T.html_section("Chain of Custody", _coc_html(coc, footer))

    return T.html_document(REPORT_TYPE, "Pulse — " + (h.get("title") or REPORT_TYPE), body).encode("utf-8")


# ---------------------------------------------------------------------------
# PDF — professional, print-friendly (shared components)
# ---------------------------------------------------------------------------

def _pdf_chip_row(counts: Dict[str, int], st):
    rl = T._rl()
    C = rl["colors"].HexColor
    cells, widths = [], []
    for s in _SEV_ORDER:
        n = counts.get(s, 0)
        if not n:
            continue
        k = T.sev_key(s)
        txt = "%d %s" % (n, k)
        p = rl["Paragraph"]('<font color="%s"><b>%s</b></font>' % (T.SEV_FG[k], txt),
                            rl["ParagraphStyle"]("chip", fontName="Helvetica-Bold", fontSize=8,
                                                 leading=11, alignment=rl["TA_CENTER"]))
        w = 14 + 5.0 * len(txt)
        chip = rl["Table"]([[p]], colWidths=[w])
        chip.setStyle(rl["TableStyle"]([
            ("BACKGROUND", (0, 0), (-1, -1), C(T.SEV_BG[k])),
            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("ROUNDEDCORNERS", [5, 5, 5, 5]),
        ]))
        cells.append(chip)
        widths.append(w + 8)
    if not cells:
        return rl["Paragraph"]('<font color="%s"><i>No findings in scope</i></font>' % T.C_MUTED, st["muted"])
    row = rl["Table"]([cells], colWidths=widths)
    row.setStyle(rl["TableStyle"]([
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    row.hAlign = "LEFT"
    return row


def _pdf_digest_box(coc: dict, st):
    rl = T._rl()
    C = rl["colors"].HexColor
    lbl = rl["Paragraph"]('<font color="%s"><b>REPORT DIGEST (SHA-256)</b></font>' % T.C_MUTED, st["th"])
    val = rl["Paragraph"](_esc(coc.get("report_sha256") or "—"), st["mono"])
    box = rl["Table"]([[lbl], [rl["Spacer"](1, 3)], [val]], colWidths=[T.CONTENT_W])
    box.setStyle(rl["TableStyle"]([
        ("BACKGROUND", (0, 0), (-1, -1), C(T.C_TINT)),
        ("BOX", (0, 0), (-1, -1), 0.6, C(T.C_BORDER)),
        ("LEFTPADDING", (0, 0), (-1, -1), 11), ("RIGHTPADDING", (0, 0), (-1, -1), 11),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return box


def render_pdf(payload: Dict[str, Any]) -> bytes:
    from io import BytesIO
    rl = T._rl()
    Paragraph = rl["Paragraph"]
    st = T.pdf_styles()

    h = payload.get("header", {})
    assets = payload.get("affected_assets", {})
    timeline = payload.get("timeline", [])
    findings = payload.get("findings", [])
    blocks = payload.get("blocks_pushed", [])
    coc = payload.get("chain_of_custody", {})
    footer = payload.get("footer", {})
    counts = _sev_counts(findings)
    top = _top_severity(findings)

    story: list = []

    # 1. Title block
    story.append(Paragraph(REPORT_TYPE.upper(), st["eyebrow"]))
    story.append(Paragraph(_esc(h.get("title") or REPORT_TYPE), st["title"]))
    story.append(T.pdf_spacer(10))
    story.append(T.pdf_metadata_grid([
        ("Organization", _esc(h.get("organization"))),
        ("Scope", _esc(h.get("scope"))),
        ("Investigator", _esc(h.get("investigator"))),
        ("Generated", _esc(h.get("generated_at"))),
    ], st))
    story.append(T.pdf_spacer(12))
    story.append(T.pdf_banner(top, _classification_label(top), st))
    story.append(T.pdf_spacer(8))

    # 2. Executive summary
    story.append(T.pdf_section("Executive Summary", st, top))
    story.append(T.pdf_spacer(4))
    exec_flow = [Paragraph(_esc(payload.get("executive_line") or ""), st["verdict"]),
                 T.pdf_spacer(7), _pdf_chip_row(counts, st)]
    story.append(T.pdf_callout(exec_flow, st, top))
    story.append(T.pdf_spacer(6))

    # 3. Affected assets
    story.append(T.pdf_section("Affected Assets", st))
    story.append(T.pdf_spacer(4))
    story.append(T.pdf_metadata_grid([
        ("Hosts", ", ".join(_esc(x) for x in assets.get("hosts", [])) if assets.get("hosts") else ""),
        ("Accounts", ", ".join(_esc(x) for x in assets.get("accounts", [])) if assets.get("accounts") else ""),
        ("Source IPs", ", ".join(_esc(x) for x in assets.get("ips", [])) if assets.get("ips") else ""),
    ], st))
    story.append(T.pdf_spacer(6))

    # 4. Detailed timeline
    story.append(T.pdf_section("Detailed Timeline", st))
    story.append(T.pdf_spacer(4))
    if timeline:
        rows = [[
            t.get("timestamp") or "—",
            T.pdf_pill_para(t.get("severity"), st),
            t.get("rule") or "",
            t.get("hostname") or "",
            t.get("account") or "",
            t.get("source_ip") or "",
        ] for t in timeline]
        story.append(T.pdf_table(
            ["Timestamp", "Severity", "Rule", "Host", "Account", "Source IP"],
            rows, [95, 52, 118, 70, 73, 104], st, mono_cols=[0, 5]))
    else:
        story.append(Paragraph('<i><font color="%s">No timeline events in scope.</font></i>' % T.C_MUTED, st["muted"]))
    story.append(T.pdf_spacer(8))

    # 5. Per-finding deep dive
    story.append(T.pdf_section("Per-Finding Deep Dive", st))
    story.append(T.pdf_spacer(6))
    if findings:
        for i, f in enumerate(findings):
            story.append(T.pdf_finding_card(i + 1, f, st))
    else:
        story.append(Paragraph('<i><font color="%s">No findings in scope.</font></i>' % T.C_MUTED, st["muted"]))
    story.append(T.pdf_spacer(4))

    # 6. Remediation actions taken
    story.append(T.pdf_section("Remediation Actions Taken", st))
    story.append(T.pdf_spacer(4))
    if blocks:
        rrows = [[
            b.get("ip") or "",
            b.get("status") or "—",
            b.get("pushed_at") or b.get("added_at") or "—",
            b.get("comment") or "",
        ] for b in blocks]
        story.append(T.pdf_table(["Blocked IP", "Status", "When", "Note"],
                                 rrows, [110, 78, 110, 214], st, mono_cols=[0, 2]))
    else:
        story.append(Paragraph('<i><font color="%s">No remediation actions recorded for this incident.</font></i>' % T.C_MUTED, st["muted"]))
    story.append(T.pdf_spacer(8))

    # 7. Chain of custody
    story.append(T.pdf_section("Chain of Custody", st))
    story.append(T.pdf_spacer(4))
    story.append(T.pdf_metadata_grid([
        ("Generated", _esc(coc.get("generated_at"))),
        ("Investigator", _esc(coc.get("investigator"))),
        ("Algorithm", _esc(coc.get("algorithm"))),
    ], st))
    story.append(T.pdf_spacer(6))
    story.append(_pdf_digest_box(coc, st))
    story.append(T.pdf_spacer(8))
    manifest = coc.get("manifest", [])
    if manifest:
        mrows = [[
            m.get("id"),
            m.get("ref_id") or "—",
            m.get("rule") or "",
            m.get("timestamp") or "—",
            _short_sha(m.get("sha256")),
        ] for m in manifest]
        story.append(T.pdf_table(["ID", "Ref", "Rule", "Timestamp", "SHA-256"],
                                 mrows, [34, 66, 132, 96, 184], st, mono_cols=[1, 3, 4]))
        story.append(T.pdf_spacer(8))
    warn = [Paragraph('<b>Verification.</b> ' + _esc(footer.get("automated_note") or ""), st["body"])]
    story.append(T.pdf_callout(warn, st, "high"))

    buf = BytesIO()
    doc, canvasmaker = T.new_doc(buf, "Pulse Incident Investigation Report", REPORT_TYPE)
    doc.build(story, canvasmaker=canvasmaker)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Dispatch
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
        raise ValueError(f"unknown format {fmt!r}; expected one of {sorted(_RENDERERS)}")
    return _RENDERERS[fmt](payload)
