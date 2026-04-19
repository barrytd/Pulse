# pulse/pdf_report.py
# -------------------
# Turns a scan's findings into a formatted PDF using reportlab. Called by
# the /api/report/{id}?format=pdf endpoint so the dashboard can offer a
# one-click PDF download alongside the existing HTML and JSON exports.
#
# Visual style (Option B — score-ring header):
#   - White bg throughout, no dark sections, Helvetica
#   - Header: grade-colored score ring + title/meta/scope+duration/pills,
#     thin HR below the row
#   - Findings: card per finding with severity badge, rule name bold,
#     Event ID in mono, MITRE pill, timestamp, full description,
#     user/source IP meta line, → remediation bullets, mitigation pills
#   - Footer centered on every page

import re
from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Flowable, HRFlowable, KeepTogether, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

from pulse.remediation import get_mitigations, get_remediation


# -------- colors (aligned with .claude/skills/pulse-design.md) --------
# Pill set — small badges in the header + severity badge on each finding.
PILL_FG = {
    "CRITICAL": colors.HexColor("#ef4444"),
    "HIGH":     colors.HexColor("#f59e0b"),
    "MEDIUM":   colors.HexColor("#3b82f6"),
    "LOW":      colors.HexColor("#10b981"),
}
# Flattened ~0.12 alpha tint of the pill color over white.
PILL_BG = {
    "CRITICAL": colors.HexColor("#fde2e2"),
    "HIGH":     colors.HexColor("#fef1d4"),
    "MEDIUM":   colors.HexColor("#e0ecfd"),
    "LOW":      colors.HexColor("#d6f4e5"),
}
GRAY_PILL_BG = colors.HexColor("#f3f4f6")
GRAY_PILL_FG = colors.HexColor("#374151")

# Score ring — exact colors from the user's spec.
#   A 90-100 → #639922 green
#   B 75-89  → #378ADD blue
#   C 60-74  → #BA7517 amber
#   D 40-59  → #E24B4A red
#   F 0-39   → #A32D2D dark red
GRADE_COLORS = {
    "A": colors.HexColor("#639922"),
    "B": colors.HexColor("#378ADD"),
    "C": colors.HexColor("#BA7517"),
    "D": colors.HexColor("#E24B4A"),
    "F": colors.HexColor("#A32D2D"),
}
DEFAULT_GRADE_COLOR = colors.HexColor("#6b7280")

# Risk label shown under the letter in the header grade badge.
GRADE_RISK_LABEL = {
    "A": "Secure",
    "B": "Low Risk",
    "C": "Moderate Risk",
    "D": "High Risk",
    "F": "Critical Risk",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Neutral palette.
COLOR_TITLE  = colors.HexColor("#111827")
COLOR_TEXT   = colors.HexColor("#1f2328")
COLOR_MUTED  = colors.HexColor("#6b7280")
COLOR_BORDER = colors.HexColor("#e5e7eb")

PAGE_WIDTH, PAGE_HEIGHT = LETTER
LEFT_MARGIN  = 0.7 * inch
RIGHT_MARGIN = 0.7 * inch
CONTENT_WIDTH = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN


# ---------------------------------------------------------------------------
# grade resolution — score → letter grade → color
# ---------------------------------------------------------------------------

def _grade_for_score(score):
    """Map a numeric score to a letter grade per the spec."""
    if score is None:
        return None
    try:
        s = int(score)
    except (TypeError, ValueError):
        return None
    if s >= 90:
        return "A"
    if s >= 75:
        return "B"
    if s >= 60:
        return "C"
    if s >= 40:
        return "D"
    return "F"


def _ring_color(score, score_label):
    """
    Always compute color from the score — not from score_label — so the
    ring reflects the actual number shown inside it. `score_label` is a
    free-form tag like "HIGH RISK" from the legacy scorer that doesn't
    map 1:1 to letter grades.
    """
    grade = _grade_for_score(score)
    if grade:
        return GRADE_COLORS[grade], grade
    # Fallback: try a first-letter match on score_label.
    if score_label:
        letter = str(score_label).strip()[:1].upper()
        if letter in GRADE_COLORS:
            return GRADE_COLORS[letter], letter
    return DEFAULT_GRADE_COLOR, None


# ---------------------------------------------------------------------------
# score ring flowable
# ---------------------------------------------------------------------------

class GradeCircle(Flowable):
    """
    Small circular grade badge, UpGuard style — colored ring, grade
    letter centered in the same color on a transparent background.
    Sits inline to the right of the score ring; the risk label renders
    separately underneath.
    """
    def __init__(self, grade, size=28, border=2):
        super().__init__()
        self.grade = (grade or "").upper()[:1]
        self.size = size
        self.border = border
        self.color = GRADE_COLORS.get(self.grade, DEFAULT_GRADE_COLOR)

    def wrap(self, availWidth, availHeight):
        return (self.size, self.size)

    def draw(self):
        c = self.canv
        r = self.size / 2.0
        c.saveState()
        c.setStrokeColor(self.color)
        c.setLineWidth(self.border)
        c.circle(r, r, r - self.border / 2.0, stroke=1, fill=0)
        if self.grade:
            c.setFillColor(self.color)
            c.setFont("Helvetica-Bold", 13)
            c.drawCentredString(r, r - 4, self.grade)
        c.restoreState()


class ScoreRing(Flowable):
    """
    Circular score badge: grade-colored ring + two stacked labels inside
    — the numeric score on top (large) and the letter grade below (small)
    — both in the same grade color. 60pt square occupying its own cell
    in the header row.
    """
    def __init__(self, score, score_label, size=60, border=4):
        super().__init__()
        self.score = score
        self.size = size
        self.border = border
        self.color, self.grade = _ring_color(score, score_label)

    def wrap(self, availWidth, availHeight):
        return (self.size, self.size)

    def draw(self):
        c = self.canv
        r = self.size / 2.0
        c.saveState()
        c.setStrokeColor(self.color)
        c.setLineWidth(self.border)
        c.circle(r, r, r - self.border / 2.0, stroke=1, fill=0)

        number = "—" if self.score is None else str(int(self.score))
        c.setFillColor(self.color)
        c.setFont("Helvetica-Bold", 20)
        # Optical vertical center — the digit caps sit a hair above the
        # geometric center, so offset by -6.
        c.drawCentredString(r, r - 6, number)
        c.restoreState()


# ---------------------------------------------------------------------------
# pill helpers
# ---------------------------------------------------------------------------

def _measure_pill_width(text, font_size, pad_x):
    return max(0.45 * inch, len(str(text)) * font_size * 0.62 + pad_x * 2)


def _pill(text, fg, bg, *, width=None, pad_x=8, font_size=8.5,
          font_name="Helvetica-Bold", height=0.22 * inch, link=None):
    style = ParagraphStyle(
        f"Pill{id(text)}", fontName=font_name, fontSize=font_size,
        leading=font_size + 2, textColor=fg, alignment=TA_CENTER,
    )
    markup = str(text)
    if link:
        markup = f'<link href="{link}">{markup}</link>'
    para = Paragraph(markup, style)
    col_w = width if width is not None else _measure_pill_width(text, font_size, pad_x)
    tbl = Table([[para]], colWidths=[col_w], rowHeights=[height])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), bg),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("LEFTPADDING",   (0, 0), (-1, -1), pad_x),
        ("RIGHTPADDING",  (0, 0), (-1, -1), pad_x),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return tbl, col_w


# ---------------------------------------------------------------------------
# duration / scope helpers
# ---------------------------------------------------------------------------

def _format_duration(seconds):
    """1m 23s / 45s / 1h 02m style."""
    if seconds is None:
        return None
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return None
    if s < 0:
        return None
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {(s % 3600) // 60:02d}m"


def _scope_and_duration_line(scan_meta):
    """Format the optional 'Scope: ... · Duration: ...' line."""
    if not scan_meta:
        return None
    scope = scan_meta.get("scope")
    duration = _format_duration(scan_meta.get("duration_sec"))
    parts = []
    if scope:
        parts.append(f"Scope: {_esc(scope)}")
    if duration:
        parts.append(f"Duration: {duration}")
    return "  &middot;  ".join(parts) if parts else None


# ---------------------------------------------------------------------------
# finding field extractors — user + source IP are embedded in either the
# finding's description text or the raw_xml blob. Prefer explicit fields on
# the dict; fall back to regex scraping.
# ---------------------------------------------------------------------------

_IP_IN_TEXT = re.compile(
    r"\bIP\s+(?:address\s+)?([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+)",
    re.IGNORECASE,
)
_USER_IN_TEXT = re.compile(
    r"\b(?:account|user|logon)\s+'([^']+)'", re.IGNORECASE,
)
_XML_IP_TAG = re.compile(
    r'<Data Name="IpAddress">([^<]+)</Data>', re.IGNORECASE,
)
_XML_USER_TAG = re.compile(
    r'<Data Name="(?:Target|Subject)UserName">([^<]+)</Data>', re.IGNORECASE,
)


def _extract_source_meta(f):
    """Return (user, source_ip) or (None, None) if not discoverable."""
    user = f.get("user") or f.get("target_user") or f.get("subject_user")
    ip = f.get("source_ip") or f.get("ip")

    raw = f.get("raw_xml") or ""
    if not ip and raw:
        m = _XML_IP_TAG.search(raw)
        if m:
            ip = m.group(1).strip()
    if not user and raw:
        m = _XML_USER_TAG.search(raw)
        if m:
            user = m.group(1).strip()

    desc = f.get("description") or ""
    if not ip and desc:
        m = _IP_IN_TEXT.search(desc)
        if m:
            ip = m.group(1).strip()
    if not user and desc:
        m = _USER_IN_TEXT.search(desc)
        if m:
            user = m.group(1).strip()

    # Scrub obvious non-IPs ("-", "N/A", "Unknown", "::1").
    if ip and ip in ("-", "N/A", "None", "", "::1", "127.0.0.1", "Unknown"):
        ip = None
    if user and user in ("-", "ANONYMOUS", "SYSTEM", "") == False:
        # keep real values, drop junk
        if user in ("-", "", "N/A"):
            user = None
    return user or None, ip or None


# ---------------------------------------------------------------------------
# header row: score ring + title block
# ---------------------------------------------------------------------------

def _build_header(findings, scan_meta, *, title_style, meta_style):
    score = scan_meta.get("score") if scan_meta else None
    score_label = scan_meta.get("score_label") if scan_meta else None
    ring = ScoreRing(score, score_label)

    right = []
    right.append(Paragraph("Pulse Threat Report", title_style))
    right.append(Paragraph(_meta_line(scan_meta), meta_style))
    extra = _scope_and_duration_line(scan_meta)
    if extra:
        right.append(Paragraph(extra, meta_style))
    score_line = _score_summary_line(score, score_label)
    if score_line:
        right.append(Paragraph(score_line, meta_style))
    right.append(Spacer(1, 6))
    right.append(_build_pill_row(findings))

    ring_w = 60
    right_w = CONTENT_WIDTH - ring_w - 14
    tbl = Table(
        [[ring, right]],
        colWidths=[ring_w, right_w],
    )
    tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (1, 0), (1, 0), 14),
    ]))
    return tbl


def _score_summary_line(score, score_label):
    """
    'Score: 76 (C) · Moderate Risk' — number + grade letter are colored
    in the grade's ring color, the rest stays muted.
    """
    if score is None:
        return None
    color, grade = _ring_color(score, score_label)
    try:
        num = str(int(score))
    except (TypeError, ValueError):
        num = str(score)
    colored_bit = f"{num} ({grade})" if grade else num
    colored = (
        f'<font color="{color.hexval()}">{colored_bit}</font>'
    )
    risk = GRADE_RISK_LABEL.get(grade)
    tail = f"  &middot;  {risk}" if risk else ""
    return f"Score: {colored}{tail}"


def _meta_line(scan_meta):
    generated = datetime.now().strftime("%B %d, %Y")
    parts = [f"Generated {generated}"]
    if scan_meta:
        # Prefer the human-facing position number ("Scan #1" = oldest) over
        # the raw DB id, which skips values whenever scans are deleted.
        display_num = scan_meta.get("number") or scan_meta.get("id")
        if display_num:
            parts.append(f"Scan #{display_num}")
        if scan_meta.get("hostname"):
            parts.append(f"Host: {_esc(scan_meta['hostname'])}")
    return " &middot; ".join(parts)


def _build_pill_row(findings):
    """
    Small, simple pills only: gray total + one per non-zero severity.
    No grade badge here — the grade lives next to the score ring.
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
    total = len(findings)

    cells = []
    col_widths = []

    total_label = f"{total} findings" if total != 1 else "1 finding"
    pill, w = _pill(total_label, GRAY_PILL_FG, GRAY_PILL_BG)
    cells.append(pill)
    col_widths.append(w)

    for sev in SEVERITY_ORDER:
        n = counts[sev]
        if n <= 0:
            continue
        cells.append("")
        col_widths.append(0.08 * inch)
        label = f"{n} {sev.title()}"
        pill, w = _pill(label, PILL_FG[sev], PILL_BG[sev])
        cells.append(pill)
        col_widths.append(w)

    # Flex spacer absorbs remaining width so pills hug the left edge.
    cells.append("")
    col_widths.append(0.1)

    tbl = Table([cells], colWidths=col_widths, rowHeights=[0.22 * inch])
    tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return tbl


# ---------------------------------------------------------------------------
# finding card
# ---------------------------------------------------------------------------

def _build_finding_card(f, *, name_style, desc_style, meta_style,
                        section_label_style, step_style, pill_row_width):
    """
    A single finding rendered as a two-column table: severity badge
    (centered) + content stack. Content order is read-like: rule name +
    MITRE pill + event id header → description → small mono meta line
    (timestamp · user · source ip) → "REMEDIATION" label + HR →
    numbered steps → mitigation pills.
    """
    sev = f.get("severity", "LOW")
    short = _short_severity(sev)
    badge, _badge_w = _pill(
        short, PILL_FG[sev], PILL_BG[sev],
        width=0.6 * inch, font_size=8.5,
    )

    content = []

    # Header row: just the rule name on the left. Event id and MITRE
    # technique move down into the mono meta line so the heading reads
    # as a clean one-liner.
    rule_name = _esc(f.get("rule", "Unknown"))
    content.append(Paragraph(rule_name, name_style))

    # Full description — plain English, directly under the name. No
    # truncation. Falls back to `details` / `message` on finding dicts
    # that don't carry an explicit description field.
    description = (
        f.get("description")
        or f.get("details")
        or f.get("message")
    )
    if description:
        content.append(Spacer(1, 8))
        content.append(Paragraph(_esc(description), desc_style))

    # Small mono meta line — timestamp · Event XXXX · MITRE · User · IP.
    # Only render pieces we actually have.
    user, src_ip = _extract_source_meta(f)
    mitre_raw = f.get("mitre") or ""
    mitre_ids = [m.strip() for m in str(mitre_raw).split(",") if m.strip()]
    first_mitre = mitre_ids[0] if mitre_ids else None
    event_id = f.get("event_id")

    meta_bits = []
    if f.get("timestamp"):
        meta_bits.append(_esc(f["timestamp"]))
    if event_id not in (None, ""):
        meta_bits.append(f"Event {_esc(str(event_id))}")
    if first_mitre:
        mitre_url = f"https://attack.mitre.org/techniques/{first_mitre.replace('.', '/')}/"
        meta_bits.append(f'<link href="{mitre_url}">{_esc(first_mitre)}</link>')
    if user:
        meta_bits.append(f"User: {_esc(user)}")
    if src_ip:
        meta_bits.append(f"Source IP: {_esc(src_ip)}")
    if meta_bits:
        content.append(Spacer(1, 6))
        content.append(Paragraph(
            "  &middot;  ".join(meta_bits),
            meta_style,
        ))

    # REMEDIATION section — uppercase muted label + thin HR + numbered steps.
    rule = f.get("rule", "")
    steps = f.get("remediation") or get_remediation(rule)
    if steps:
        content.append(Spacer(1, 12))
        content.append(Paragraph("REMEDIATION", section_label_style))
        content.append(HRFlowable(
            width="100%", thickness=0.5, color=COLOR_BORDER,
            spaceBefore=2, spaceAfter=8,
        ))
        for idx, step in enumerate(steps, 1):
            content.append(Paragraph(
                (f'<font color="{COLOR_MUTED.hexval()}">{idx}.</font>'
                 f'&nbsp;&nbsp;{_esc(step)}'),
                step_style,
            ))

    # Mitigation pills + extra MITRE tags (beyond the first, which is
    # already shown next to the rule name up top).
    mitigations = f.get("mitigations") or get_mitigations(rule)
    mitigation_ids = [m.get("id") for m in (mitigations or []) if m.get("id")]
    extra_mitre = [mid for mid in mitre_ids[1:] if mid]  # skip first, already rendered
    pill_ids = extra_mitre + [mid for mid in mitigation_ids if mid not in mitre_ids]
    if pill_ids:
        content.append(Spacer(1, 10))
        content.append(_build_tag_pill_row(pill_ids, pill_row_width))

    # Wrap into an outer 2-col row (badge | content). The outer list
    # wraps the card so a subtle bottom border separates findings.
    badge_w = 0.7 * inch
    outer = Table(
        [[badge, content]],
        colWidths=[badge_w, CONTENT_WIDTH - badge_w],
    )
    outer.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("ALIGN",         (0, 0), (0, -1), "CENTER"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
        ("LEFTPADDING",   (1, 0), (1, 0), 14),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.75, COLOR_BORDER),
    ]))
    return outer


def _short_severity(sev):
    return {"CRITICAL": "CRIT", "MEDIUM": "MED"}.get(sev, sev)


def _build_tag_pill_row(tags, width):
    cells = []
    col_widths = []
    gap_w = 0.06 * inch
    for i, tag in enumerate(tags):
        pill, w = _pill(
            tag, COLOR_TEXT, GRAY_PILL_BG,
            font_name="Courier-Bold", font_size=7.5, pad_x=6,
        )
        cells.append(pill)
        col_widths.append(w)
        if i < len(tags) - 1:
            cells.append("")
            col_widths.append(gap_w)
    used = sum(col_widths)
    cells.append("")
    col_widths.append(max(0.1, width - used))
    tbl = Table([cells], colWidths=col_widths, rowHeights=[0.22 * inch])
    tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return tbl


# ---------------------------------------------------------------------------
# footer
# ---------------------------------------------------------------------------

def _draw_footer(canv, doc):
    canv.saveState()
    canv.setFont("Helvetica", 8)
    canv.setFillColor(COLOR_MUTED)
    canv.drawCentredString(
        PAGE_WIDTH / 2.0, 0.45 * inch,
        "Generated by Pulse Threat Detection  \u00b7  github.com/barrytd/Pulse",
    )
    canv.restoreState()


# ---------------------------------------------------------------------------
# public entry
# ---------------------------------------------------------------------------

def build_pdf(findings, scan_meta=None):
    """
    Build a PDF report from a list of findings and return its bytes.

    Parameters:
        findings (list):   Finding dicts, already sorted / decorated.
        scan_meta (dict):  Optional scan row: id, scanned_at, hostname, score,
                          score_label, total_events, files_scanned, scope,
                          duration_sec.

    Returns:
        bytes: The rendered PDF contents.
    """
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=LEFT_MARGIN, rightMargin=RIGHT_MARGIN,
        topMargin=0.7 * inch, bottomMargin=0.8 * inch,
        title="Pulse Threat Report",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "PulseTitle", parent=styles["Normal"], fontName="Helvetica",
        fontSize=18, leading=22, textColor=COLOR_TITLE, alignment=TA_LEFT,
        spaceAfter=4,
    )
    meta_style = ParagraphStyle(
        "PulseMeta", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=14, textColor=COLOR_MUTED, alignment=TA_LEFT,
    )
    name_style = ParagraphStyle(
        "PulseName", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=13, leading=17, textColor=COLOR_TEXT, alignment=TA_LEFT,
    )
    desc_style = ParagraphStyle(
        "PulseDesc", parent=styles["Normal"], fontName="Helvetica",
        fontSize=11, leading=16, textColor=COLOR_TEXT, alignment=TA_LEFT,
    )
    # 11px mono for the under-description meta line (timestamp · user · IP).
    row_meta_style = ParagraphStyle(
        "PulseRowMeta", parent=styles["Normal"], fontName="Courier",
        fontSize=11, leading=14, textColor=COLOR_MUTED, alignment=TA_LEFT,
    )
    section_label_style = ParagraphStyle(
        "PulseSectionLabel", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=9, leading=11, textColor=COLOR_MUTED, alignment=TA_LEFT,
    )
    step_style = ParagraphStyle(
        "PulseStep", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10.5, leading=15, textColor=COLOR_TEXT, alignment=TA_LEFT,
        leftIndent=4, spaceAfter=2,
    )
    story = []

    # ---- Header row -----------------------------------------------------
    story.append(_build_header(
        findings, scan_meta,
        title_style=title_style, meta_style=meta_style,
    ))
    story.append(Spacer(1, 12))
    story.append(HRFlowable(
        width="100%", thickness=0.5, color=COLOR_BORDER,
        spaceBefore=0, spaceAfter=8,
    ))

    if not findings:
        story.append(Spacer(1, 20))
        story.append(Paragraph(
            "No findings detected for this scan.",
            meta_style,
        ))
        doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
        return buf.getvalue()

    # ---- Findings list, severity-sorted --------------------------------
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.get("severity", "LOW"))
        if f.get("severity") in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )

    badge_w = 0.7 * inch
    content_w = CONTENT_WIDTH - badge_w - 14
    for f in sorted_findings:
        card = _build_finding_card(
            f,
            name_style=name_style,
            desc_style=desc_style,
            meta_style=row_meta_style,
            section_label_style=section_label_style,
            step_style=step_style,
            pill_row_width=content_w,
        )
        # KeepTogether keeps each card's badge + content on the same
        # page; ReportLab will still split if the card is taller than
        # a page on its own.
        story.append(KeepTogether(card))

    doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
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
