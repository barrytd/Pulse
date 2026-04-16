# pulse/pdf_report.py
# -------------------
# Turns a scan's findings into a formatted PDF using reportlab. Called by
# the /api/report/{id}?format=pdf endpoint so the dashboard can offer a
# one-click PDF download alongside the existing HTML and JSON exports.
#
# ReportLab's high-level Platypus layer handles flow elements (paragraphs,
# tables) on a Letter-size page with auto-pagination.

from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from pulse.remediation import get_mitigations, get_remediation

SEVERITY_COLOURS = {
    "CRITICAL": colors.HexColor("#8e44ad"),
    "HIGH":     colors.HexColor("#e74c3c"),
    "MEDIUM":   colors.HexColor("#e67e22"),
    "LOW":      colors.HexColor("#3498db"),
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def build_pdf(findings, scan_meta=None):
    """
    Build a PDF report from a list of findings and return its bytes.

    Parameters:
        findings (list):   Finding dicts, already sorted / decorated.
        scan_meta (dict):  Optional scan row: id, scanned_at, hostname, score,
                          score_label, total_events, files_scanned.

    Returns:
        bytes: The rendered PDF contents, suitable for a FastAPI Response.
    """
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        title="Pulse Threat Report",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "PulseTitle", parent=styles["Title"], fontSize=20,
        spaceAfter=6, textColor=colors.HexColor("#1a1a2e"),
    )
    subtitle_style = ParagraphStyle(
        "PulseSubtitle", parent=styles["Normal"], fontSize=9,
        textColor=colors.HexColor("#7f8c8d"), spaceAfter=14,
    )
    section_style = ParagraphStyle(
        "PulseSection", parent=styles["Heading3"], fontSize=11,
        textColor=colors.HexColor("#1a1a2e"), spaceBefore=10, spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "PulseBody", parent=styles["Normal"], fontSize=9.5,
        leading=13, alignment=TA_LEFT,
    )
    small_style = ParagraphStyle(
        "PulseSmall", parent=styles["Normal"], fontSize=8,
        textColor=colors.HexColor("#7f8c8d"),
    )

    story = []

    # --- Title + scan metadata ---
    story.append(Paragraph("Pulse Threat Report", title_style))
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    meta_parts = [f"Generated {generated}"]
    if scan_meta:
        if scan_meta.get("id"):
            meta_parts.append(f"Scan #{scan_meta['id']}")
        if scan_meta.get("scanned_at"):
            meta_parts.append(f"Scanned {scan_meta['scanned_at']}")
        if scan_meta.get("hostname"):
            meta_parts.append(f"Host: {scan_meta['hostname']}")
    story.append(Paragraph(" &middot; ".join(meta_parts), subtitle_style))

    # --- Summary counts table ---
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    total = len(findings)

    summary_cells = [
        ["Total", "Critical", "High", "Medium", "Low"],
        [
            str(total),
            str(severity_counts["CRITICAL"]),
            str(severity_counts["HIGH"]),
            str(severity_counts["MEDIUM"]),
            str(severity_counts["LOW"]),
        ],
    ]
    summary_tbl = Table(summary_cells, colWidths=[1.3 * inch] * 5)
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
        ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, 0), 9),
        ("TEXTCOLOR",      (1, 1), (1, 1), SEVERITY_COLOURS["CRITICAL"]),
        ("TEXTCOLOR",      (2, 1), (2, 1), SEVERITY_COLOURS["HIGH"]),
        ("TEXTCOLOR",      (3, 1), (3, 1), SEVERITY_COLOURS["MEDIUM"]),
        ("TEXTCOLOR",      (4, 1), (4, 1), SEVERITY_COLOURS["LOW"]),
        ("FONTSIZE",       (0, 1), (-1, 1), 15),
        ("FONTNAME",       (0, 1), (-1, 1), "Helvetica-Bold"),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",     (0, 0), (-1, -1), 8),
        ("BACKGROUND",     (0, 1), (-1, 1), colors.HexColor("#f4f6f8")),
    ]))
    story.append(summary_tbl)
    story.append(Spacer(1, 16))

    if not findings:
        story.append(Paragraph("No findings detected.", body_style))
        doc.build(story)
        return buf.getvalue()

    # --- Findings listing, sorted by severity ---
    story.append(Paragraph("Findings", section_style))

    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.get("severity", "LOW"))
        if f.get("severity") in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )

    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "LOW")
        colour = SEVERITY_COLOURS.get(sev, colors.grey)
        header_row = [[
            Paragraph(
                f'<font color="white"><b>&nbsp;{sev}&nbsp;</b></font>',
                small_style,
            ),
            Paragraph(
                f'<b>{_esc(f.get("rule", "Unknown"))}</b>',
                body_style,
            ),
            Paragraph(
                f'Event {_esc(str(f.get("event_id", "-")))}',
                small_style,
            ),
        ]]
        header_tbl = Table(header_row, colWidths=[0.9 * inch, 4.5 * inch, 1.0 * inch])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), colour),
            ("BACKGROUND",    (1, 0), (-1, 0), colors.HexColor("#f4f6f8")),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(header_tbl)

        meta_bits = []
        if f.get("timestamp"):
            meta_bits.append(f'<b>When:</b> {_esc(f["timestamp"])}')
        if f.get("mitre"):
            meta_bits.append(f'<b>MITRE:</b> {_esc(f["mitre"])}')
        if meta_bits:
            story.append(Paragraph(" &nbsp; ".join(meta_bits), small_style))

        if f.get("description"):
            story.append(Paragraph(_esc(f["description"]), body_style))
        if f.get("details"):
            story.append(Paragraph(
                f'<font face="Courier" size="8" color="#555">{_esc(f["details"])}</font>',
                body_style,
            ))

        rule_name = f.get("rule", "")
        steps = f.get("remediation") or get_remediation(rule_name)
        if steps:
            story.append(Paragraph("Remediation", section_style))
            for step in steps:
                story.append(Paragraph(f"&bull; {_esc(step)}", body_style))

        mitigations = f.get("mitigations") or get_mitigations(rule_name)
        if mitigations:
            chips = ", ".join(f'{m["id"]} ({_esc(m["name"])})' for m in mitigations)
            story.append(Paragraph(
                f'<font color="#7f8c8d"><b>Mitigations:</b> {chips}</font>',
                small_style,
            ))

        story.append(Spacer(1, 12))

        # Keep the PDF a reasonable size — one page break every 6 findings
        # so large scans don't become one giant visually-dense block.
        if i % 6 == 0 and i != len(sorted_findings):
            story.append(PageBreak())

    doc.build(story)
    return buf.getvalue()


def _esc(value):
    """Escape ReportLab Paragraph markup (it uses a tiny HTML-ish grammar)."""
    if value is None:
        return ""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
