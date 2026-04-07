# pulse/reporter.py
# -------------------
# This module takes the findings from detections.py and turns them
# into a clean, human-readable report — either plain text or HTML.
#
# WHY TWO FORMATS?
# - Text (.txt) is quick to read in a terminal, great for servers with no GUI.
# - HTML (.html) opens in a browser with colour-coded severities. Better for
#   sharing with managers or clients who want a professional-looking output.
#
# Both formats contain the same findings — just presented differently.


import os
from datetime import datetime


# --- SEVERITY COLOURS FOR HTML ---
# Maps each severity level to a CSS colour.
# CSS colours can be names ("red"), hex codes ("#FF0000"), or rgb() values.
# These are chosen to be readable but clearly distinct.
SEVERITY_COLOURS = {
    "CRITICAL": "#8e44ad",  # Purple — most urgent, stands out from red
    "HIGH":     "#e74c3c",  # Red
    "MEDIUM":   "#e67e22",  # Orange
    "LOW":      "#3498db",  # Blue
}

# The order we want findings displayed — most severe at the top.
# sorted() uses the index position as the sort key: CRITICAL=0, HIGH=1, etc.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def generate_report(findings, output_path=None, fmt="txt"):
    """
    Creates a report from detection findings in either text or HTML format.

    Parameters:
        findings (list):   List of finding dicts from detections.py.
                           Each has "rule", "severity", and "details" keys.
        output_path (str): Where to save the report. Auto-generated if None.
        fmt (str):         "txt" or "html". Default is "txt".

    Returns:
        str: The file path where the report was saved.
    """

    # --- DECIDE WHERE TO SAVE ---
    # If no path was given, auto-generate one with a timestamp.
    # We pick the extension based on the format so the file opens correctly.
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        extension = "html" if fmt == "html" else "txt"
        output_path = os.path.join("reports", f"pulse_report_{timestamp}.{extension}")

    # --- SORT FINDINGS — most severe first ---
    # sorted() returns a new sorted list without changing the original.
    # The key= tells it what to sort by.
    # .index() gives us the position in SEVERITY_ORDER — CRITICAL=0, LOW=3.
    # Lower index = more severe = sorts to the top.
    findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.get("severity", "LOW"))
        if f.get("severity") in SEVERITY_ORDER else len(SEVERITY_ORDER)
    )

    # --- COUNT FINDINGS BY SEVERITY ---
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        severity = finding.get("severity", "LOW")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # --- ROUTE TO THE RIGHT BUILDER ---
    # We call a different function depending on the format.
    # This keeps each builder clean and focused on one job.
    if fmt == "html":
        report_text = _build_html_report(findings, severity_counts)
    else:
        report_text = _build_txt_report(findings, severity_counts)

    # --- WRITE TO FILE ---
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return output_path


def _build_txt_report(findings, severity_counts):
    """
    Builds the plain text version of the report.
    (Functions starting with _ are "private" — meant to be used only inside
    this module, not called from other files. It's a Python convention.)

    Parameters:
        findings (list):        List of finding dictionaries.
        severity_counts (dict): Pre-counted HIGH/MEDIUM/LOW totals.

    Returns:
        str: The full report as a single string.
    """

    lines = []

    lines.append("=" * 60)
    lines.append("  PULSE — Threat Detection Report")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Total findings: {len(findings)}")
    lines.append("")
    lines.append("  Severity Breakdown:")
    lines.append(f"    CRITICAL: {severity_counts['CRITICAL']}")
    lines.append(f"    HIGH:     {severity_counts['HIGH']}")
    lines.append(f"    MEDIUM:   {severity_counts['MEDIUM']}")
    lines.append(f"    LOW:      {severity_counts['LOW']}")
    lines.append("")
    lines.append("-" * 60)

    for i, finding in enumerate(findings, start=1):
        lines.append("")
        lines.append(f"  [{finding['severity']}] Finding #{i}: {finding['rule']}")
        lines.append(f"  {'-' * 40}")
        lines.append(f"  {finding['details']}")
        lines.append("")

    lines.append("-" * 60)
    lines.append("  End of report.")
    lines.append("=" * 60)
    lines.append("")

    return "\n".join(lines)


def _build_html_report(findings, severity_counts):
    """
    Builds the HTML version of the report.

    HTML is a markup language — you wrap content in tags like <h1>, <p>, <table>.
    The browser reads those tags and renders them as styled content.

    We build the HTML as one big string using an f-string (a string that can
    contain Python expressions inside curly braces).

    We also include CSS (Cascading Style Sheets) inside a <style> block.
    CSS controls colours, fonts, spacing, and layout — it's what makes
    the page look good instead of just raw unstyled text.

    Parameters:
        findings (list):        List of finding dictionaries.
        severity_counts (dict): Pre-counted HIGH/MEDIUM/LOW totals.

    Returns:
        str: A complete HTML document as a string.
    """

    # --- BUILD THE FINDINGS HTML ---
    # We build each finding card as a chunk of HTML, then join them together.
    # This is the same "build a list, join at the end" pattern from the txt report.
    finding_cards = []

    for i, finding in enumerate(findings, start=1):
        severity = finding["severity"]

        # Look up the colour for this severity level.
        # .get() with a fallback means unknown severities get grey.
        colour = SEVERITY_COLOURS.get(severity, "#95a5a6")

        # Each finding is a <div> (a box) styled with a left border in the
        # severity colour. This is a common pattern in security dashboards.
        card = f"""
        <div class="finding">
            <div class="finding-header" style="border-left: 5px solid {colour};">
                <span class="severity-badge" style="background-color: {colour};">
                    {severity}
                </span>
                <span class="finding-title">Finding #{i}: {finding['rule']}</span>
            </div>
            <div class="finding-body">
                <p>{finding['details']}</p>
            </div>
        </div>"""

        finding_cards.append(card)

    # Join all the cards into one big string.
    all_cards = "\n".join(finding_cards)

    # --- BUILD THE SUMMARY BOXES ---
    # Three coloured boxes at the top — one per severity level.
    summary_boxes = f"""
        <div class="summary">
            <div class="summary-box" style="background-color: {SEVERITY_COLOURS['CRITICAL']};">
                <div class="summary-count">{severity_counts['CRITICAL']}</div>
                <div class="summary-label">CRITICAL</div>
            </div>
            <div class="summary-box" style="background-color: {SEVERITY_COLOURS['HIGH']};">
                <div class="summary-count">{severity_counts['HIGH']}</div>
                <div class="summary-label">HIGH</div>
            </div>
            <div class="summary-box" style="background-color: {SEVERITY_COLOURS['MEDIUM']};">
                <div class="summary-count">{severity_counts['MEDIUM']}</div>
                <div class="summary-label">MEDIUM</div>
            </div>
            <div class="summary-box" style="background-color: {SEVERITY_COLOURS['LOW']};">
                <div class="summary-count">{severity_counts['LOW']}</div>
                <div class="summary-label">LOW</div>
            </div>
        </div>"""

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(findings)

    # --- ASSEMBLE THE FULL HTML DOCUMENT ---
    # This is a complete, self-contained HTML file.
    # <!DOCTYPE html> tells the browser this is modern HTML5.
    # <meta charset="UTF-8"> ensures special characters display correctly.
    # Everything inside <style>...</style> is CSS.
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pulse — Threat Detection Report</title>
    <style>
        /* CSS reset — removes browser default margins/padding */
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background-color: #1a1a2e;   /* Dark navy background */
            color: #e0e0e0;
            padding: 30px;
        }}

        /* The main container — centres content and limits width */
        .container {{
            max-width: 900px;
            margin: 0 auto;
        }}

        /* Top header bar */
        header {{
            background-color: #16213e;
            border-bottom: 3px solid #e74c3c;
            padding: 20px 30px;
            border-radius: 8px 8px 0 0;
            margin-bottom: 5px;
        }}

        header h1 {{
            font-size: 1.8rem;
            color: #ffffff;
            letter-spacing: 2px;
        }}

        header p {{
            color: #95a5a6;
            margin-top: 5px;
            font-size: 0.9rem;
        }}

        /* The three HIGH / MEDIUM / LOW summary boxes */
        .summary {{
            display: flex;           /* Lay boxes out side by side */
            gap: 15px;
            margin: 20px 0;
        }}

        .summary-box {{
            flex: 1;                 /* Each box takes equal space */
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
        }}

        .summary-count {{
            font-size: 2.5rem;
            font-weight: bold;
        }}

        .summary-label {{
            font-size: 0.85rem;
            letter-spacing: 1px;
            margin-top: 5px;
        }}

        /* Section heading above the findings list */
        .section-title {{
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: #95a5a6;
            margin: 25px 0 10px;
        }}

        /* Individual finding card */
        .finding {{
            background-color: #16213e;
            border-radius: 8px;
            margin-bottom: 12px;
            overflow: hidden;       /* Keeps the border-radius clean */
        }}

        .finding-header {{
            padding: 12px 15px;
            display: flex;
            align-items: center;
            gap: 12px;
            background-color: #0f3460;
        }}

        /* The coloured severity pill (HIGH / MEDIUM / LOW) */
        .severity-badge {{
            padding: 3px 10px;
            border-radius: 4px;
            color: white;
            font-size: 0.75rem;
            font-weight: bold;
            letter-spacing: 1px;
            white-space: nowrap;    /* Prevents the badge from wrapping */
        }}

        .finding-title {{
            font-weight: 600;
            color: #ffffff;
        }}

        .finding-body {{
            padding: 12px 15px;
            color: #b0b0b0;
            font-size: 0.92rem;
            line-height: 1.6;
        }}

        footer {{
            text-align: center;
            color: #555;
            margin-top: 30px;
            font-size: 0.8rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>PULSE</h1>
            <p>Threat Detection Report &nbsp;|&nbsp; Generated: {generated_at} &nbsp;|&nbsp; {total} findings</p>
        </header>

        {summary_boxes}

        <p class="section-title">Findings</p>

        {all_cards}

        <footer>Generated by Pulse &mdash; Windows Event Log Analyzer</footer>
    </div>
</body>
</html>"""

    return html
