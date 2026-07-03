"""Format renderers for the Threat Detection Summary payload.

All four take the dict returned by ``threat_summary.build_summary`` and
return ``bytes`` ready for download / persistence.

Splitting renderers from the data builder means the PDF and HTML can't
disagree on the numbers — they consume the same dict. It also makes the
unit tests trivial: feed a known dict, assert on the output.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict

import pulse.reports.report_theme as T

REPORT_TYPE = "Threat Detection Summary"
_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


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
# HTML — light, print-friendly page built on the shared report design
# system (pulse.reports.report_theme). Self-contained: the theme inlines
# its stylesheet so the file can be shared, emailed, or opened offline.
# ---------------------------------------------------------------------------


def _esc(s: Any) -> str:
    return T.esc(s)


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


def _top_severity(summary: Dict[str, Any]) -> str:
    """Highest severity present in scope — drives the classification
    banner + section accent. Falls back to NONE when nothing fired."""
    by_sev = summary.get("summary", {}).get("by_severity", {})
    for s in _SEV_ORDER:
        if by_sev.get(s):
            return s
    return "NONE"


def _classification_label(sev: str) -> str:
    return {
        "CRITICAL": "Critical threat activity",
        "HIGH":     "High-severity threat activity",
        "MEDIUM":   "Moderate threat activity",
        "LOW":      "Low-severity threat activity",
    }.get(T.sev_key(sev), "No active threats detected")


def _intel_pill_html(score: Any) -> str:
    """Intel-score chip. Maps the 0-100 abuse score onto the shared
    severity hues (high score = critical hue) so it reads consistently
    with the rest of the report's color language."""
    if score is None:
        return T.html_none()
    k = "CRITICAL" if score >= 75 else "HIGH" if score >= 25 else "LOW"
    return ('<span class="rpt-pill" style="color:' + T.SEV_FG[k] + ';background:'
            + T.SEV_BG[k] + ';">' + _esc(score) + '/100</span>')


def render_html(summary: Dict[str, Any]) -> bytes:
    h = summary["header"]
    s = summary["summary"]
    by_tactic = summary.get("by_tactic", [])
    timeline = summary.get("timeline", [])
    top_rules = summary.get("top_rules", [])
    repeat_ips = summary.get("repeat_ips", [])
    repeat_hosts = summary.get("repeat_hosts", [])
    footer = summary.get("footer", {})

    top = _top_severity(summary)

    # 1. Title block + metadata + classification banner
    body = T.html_eyebrow_title(REPORT_TYPE.upper(), h.get("title") or REPORT_TYPE)
    body += T.html_metadata_grid([
        ("Scope", _esc(h.get("scope"))),
        ("Hosts covered", ", ".join(_esc(x) for x in (h.get("hosts") or []))),
        ("Generated", _esc(h.get("generated_at"))),
    ])
    body += T.html_classification_banner(top, _classification_label(top))

    # 2. Summary — verdict line + severity chips, in an accent callout
    score = s.get("score")
    grade = s.get("grade") or "?"
    verdict = ('<div class="rpt-callout-verdict">'
               '<b>' + _esc(s.get("total_findings", 0)) + '</b> finding'
               + ("" if s.get("total_findings") == 1 else "s")
               + ' &nbsp;·&nbsp; Grade <b>' + _esc(grade) + '</b>'
               + ' &nbsp;·&nbsp; Score <b>'
               + (_esc(score) if score is not None else T.html_none()) + '</b>'
               + ((' <span class="rpt-none">(' + _esc(s.get("score_label")) + ')</span>')
                  if s.get("score_label") else "")
               + '</div>')
    by_sev = s["by_severity"]
    chips = "".join(
        ('<span class="rpt-pill" style="color:' + T.SEV_FG[sev] + ';background:'
         + T.SEV_BG[sev] + ';">' + str(by_sev.get(sev, 0)) + ' ' + sev + '</span>')
        for sev in _SEV_ORDER if by_sev.get(sev)
    ) or '<span class="rpt-none">No findings in scope</span>'
    summary_inner = verdict + '<div class="rpt-chips">' + chips + '</div>'
    body += T.html_section("Summary", T.html_callout(summary_inner, top), top)

    # 3. Findings by MITRE Tactic
    if by_tactic:
        rows = [[
            _esc(t["tactic"]),
            _esc(t["count"]),
            (", ".join('<span class="rpt-mono">' + _esc(x["id"]) + '</span> (' + _esc(x["count"]) + ')'
                       for x in t.get("techniques", []))
             or T.html_none()),
        ] for t in by_tactic]
        tactic_html = T.html_table(["Tactic", "Findings", "Techniques"], rows, num_cols=[1])
    else:
        tactic_html = T.html_none()
    body += T.html_section("Findings by MITRE Tactic", tactic_html)

    # 4. Attack Timeline (cap at 200 rows so very large reports stay openable)
    if timeline:
        rows = [[
            '<span class="rpt-mono">' + _esc(_format_ts(row.get("timestamp"))) + '</span>',
            T.html_pill(row.get("severity")),
            _esc(row.get("rule")),
            _esc(row.get("hostname")) if row.get("hostname") else T.html_none(),
        ] for row in timeline[:200]]
        tl_html = T.html_table(["Timestamp", "Severity", "Rule", "Host"], rows)
        if len(timeline) > 200:
            tl_html += ('<div class="rpt-none">... and ' + str(len(timeline) - 200)
                        + ' more findings (see JSON export for the full list).</div>')
    else:
        tl_html = T.html_none()
    body += T.html_section("Attack Timeline", tl_html)

    # 5. Top Triggered Rules
    if top_rules:
        rows = [[
            _esc(r["rule"]),
            T.html_pill(r.get("severity") or "LOW"),
            ('<span class="rpt-mono">' + _esc(r.get("mitre")) + '</span>') if r.get("mitre") else T.html_none(),
            _esc(r["count"]),
        ] for r in top_rules]
        rules_html = T.html_table(["Rule", "Severity", "MITRE", "Hits"], rows, num_cols=[3])
    else:
        rules_html = T.html_none()
    body += T.html_section("Top Triggered Rules", rules_html)

    # 6. Repeat Offenders — source IPs + affected hosts subtables
    repeat_html = ""
    if repeat_ips:
        rows = [[
            '<span class="rpt-mono">' + _esc(entry["ip"]) + '</span>',
            _esc(entry.get("intel_country")) if entry.get("intel_country") else T.html_none(),
            _esc(entry["count"]),
            _intel_pill_html(entry.get("intel_score")),
            _esc(", ".join(entry.get("rules", []))) if entry.get("rules") else T.html_none(),
        ] for entry in repeat_ips]
        repeat_html += T.html_table(
            ["IP", "Country", "Hits", "Intel score", "Rules"], rows, num_cols=[2])
    if repeat_hosts:
        rows = [[
            _esc(hentry["hostname"]),
            _esc(hentry["count"]),
        ] for hentry in repeat_hosts]
        repeat_html += T.html_table(["Hostname", "Findings"], rows, num_cols=[1])
    if not repeat_html:
        repeat_html = T.html_none()
    body += T.html_section("Repeat Offenders", repeat_html)

    return T.html_document(
        REPORT_TYPE, "Pulse — " + (h.get("title") or REPORT_TYPE), body
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# PDF — professional, print-friendly, built on the shared report_theme
# design system so this template matches every other Pulse report.
# ---------------------------------------------------------------------------

def _pdf_chip_row(by_sev: Dict[str, int], st):
    """Severity-count chips (e.g. "2 HIGH"), each a rounded mini-table,
    laid out in a single row. Mirrors the Incident report's chip row."""
    rl = T._rl()
    C = rl["colors"].HexColor
    cells, widths = [], []
    for sev in _SEV_ORDER:
        n = by_sev.get(sev, 0)
        if not n:
            continue
        k = T.sev_key(sev)
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


def _intel_cell(score: Any) -> str:
    return "%s/100" % score if score is not None else ""


def render_pdf(summary: Dict[str, Any]) -> bytes:
    from io import BytesIO
    rl = T._rl()
    Paragraph = rl["Paragraph"]
    st = T.pdf_styles()

    h = summary["header"]
    s = summary["summary"]
    by_tactic = summary.get("by_tactic", [])
    timeline = summary.get("timeline", [])
    top_rules = summary.get("top_rules", [])
    repeat_ips = summary.get("repeat_ips", [])
    repeat_hosts = summary.get("repeat_hosts", [])
    footer = summary.get("footer", {})

    top = _top_severity(summary)
    by_sev = s["by_severity"]
    CW = T.CONTENT_W

    story: list = []

    # 1. Title block + metadata + classification banner
    story.append(Paragraph(REPORT_TYPE.upper(), st["eyebrow"]))
    story.append(Paragraph(_esc(h.get("title") or REPORT_TYPE), st["title"]))
    story.append(T.pdf_spacer(10))
    story.append(T.pdf_metadata_grid([
        ("Scope", _esc(h.get("scope"))),
        ("Hosts covered", ", ".join(_esc(x) for x in (h.get("hosts") or []))),
        ("Generated", _esc(h.get("generated_at"))),
    ], st))
    story.append(T.pdf_spacer(12))
    story.append(T.pdf_banner(top, _classification_label(top), st))
    story.append(T.pdf_spacer(8))

    # 2. Summary — verdict line + severity chips in an accent callout
    story.append(T.pdf_section("Summary", st, top))
    story.append(T.pdf_spacer(4))
    score = s.get("score")
    grade = s.get("grade") or "?"
    verdict = ("<b>%s</b> finding%s &nbsp;·&nbsp; Grade <b>%s</b> &nbsp;·&nbsp; Score <b>%s</b>%s" % (
        _esc(s.get("total_findings", 0)),
        "" if s.get("total_findings") == 1 else "s",
        _esc(grade),
        _esc(score) if score is not None else "—",
        (' <font color="%s">(%s)</font>' % (T.C_MUTED, _esc(s.get("score_label")))) if s.get("score_label") else "",
    ))
    summary_flow = [Paragraph(verdict, st["verdict"]), T.pdf_spacer(7),
                    _pdf_chip_row(by_sev, st)]
    story.append(T.pdf_callout(summary_flow, st, top))
    story.append(T.pdf_spacer(6))

    # 3. Findings by MITRE Tactic
    story.append(T.pdf_section("Findings by MITRE Tactic", st))
    story.append(T.pdf_spacer(4))
    if by_tactic:
        rows = [[
            t["tactic"],
            str(t["count"]),
            ", ".join("%s (%s)" % (x["id"], x["count"]) for x in t.get("techniques", [])) or "—",
        ] for t in by_tactic]
        story.append(T.pdf_table(
            ["Tactic", "Findings", "Techniques"], rows,
            [130, 60, CW - 190], st))
    else:
        story.append(Paragraph('<i><font color="%s">No tactic-tagged findings in scope.</font></i>' % T.C_MUTED, st["muted"]))
    story.append(T.pdf_spacer(8))

    # 4. Attack Timeline (cap at 60 rows; the rest live in the JSON export)
    story.append(T.pdf_section("Attack Timeline", st))
    story.append(T.pdf_spacer(4))
    if timeline:
        rows = [[
            _format_ts(r.get("timestamp")),
            T.pdf_pill_para(r.get("severity"), st),
            r.get("rule") or "",
            r.get("hostname") or "",
        ] for r in timeline[:60]]
        story.append(T.pdf_table(
            ["Timestamp", "Severity", "Rule", "Host"], rows,
            [100, 58, CW - 308, 150], st, mono_cols=[0]))
        if len(timeline) > 60:
            story.append(T.pdf_spacer(4))
            story.append(Paragraph(
                '<i><font color="%s">... and %d more findings (see JSON export).</font></i>'
                % (T.C_MUTED, len(timeline) - 60), st["muted"]))
    else:
        story.append(Paragraph('<i><font color="%s">No findings to chart.</font></i>' % T.C_MUTED, st["muted"]))
    story.append(T.pdf_spacer(8))

    # 5. Top Triggered Rules
    story.append(T.pdf_section("Top Triggered Rules", st))
    story.append(T.pdf_spacer(4))
    if top_rules:
        rows = [[
            r.get("rule") or "",
            T.pdf_pill_para(r.get("severity") or "LOW", st),
            r.get("mitre") or "—",
            str(r["count"]),
        ] for r in top_rules]
        story.append(T.pdf_table(
            ["Rule", "Severity", "MITRE", "Hits"], rows,
            [CW - 230, 58, 122, 50], st, mono_cols=[2]))
    else:
        story.append(Paragraph('<i><font color="%s">No rules fired in scope.</font></i>' % T.C_MUTED, st["muted"]))
    story.append(T.pdf_spacer(8))

    # 6. Repeat Offenders — source IPs + affected hosts
    story.append(T.pdf_section("Repeat Offenders", st))
    story.append(T.pdf_spacer(4))
    if not repeat_ips and not repeat_hosts:
        story.append(Paragraph('<i><font color="%s">No repeat offenders detected.</font></i>' % T.C_MUTED, st["muted"]))
    if repeat_ips:
        rows = [[
            entry["ip"],
            entry.get("intel_country") or "—",
            str(entry["count"]),
            _intel_cell(entry.get("intel_score")) or "—",
            ", ".join(entry.get("rules", []))[:80],
        ] for entry in repeat_ips]
        story.append(T.pdf_table(
            ["IP", "Country", "Hits", "Intel", "Rules"], rows,
            [100, 52, 42, 60, CW - 254], st, mono_cols=[0]))
        story.append(T.pdf_spacer(8))
    if repeat_hosts:
        rows = [[hentry["hostname"], str(hentry["count"])] for hentry in repeat_hosts]
        story.append(T.pdf_table(
            ["Hostname", "Findings"], rows,
            [CW - 90, 90], st))

    buf = BytesIO()
    doc, canvasmaker = T.new_doc(buf, "Pulse Threat Detection Summary", REPORT_TYPE)
    doc.build(story, canvasmaker=canvasmaker)
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
