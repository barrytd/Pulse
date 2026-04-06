# pulse/reporter.py
# -------------------
# This module takes the findings from detections.py and turns them
# into a clean, human-readable report.
#
# WHY A SEPARATE MODULE?
# We keep reporting separate from detection because they're different jobs.
# Detection answers "what happened?" and reporting answers "how do we
# present it?" Keeping them separate means we can later add new report
# formats (JSON, HTML, PDF) without touching the detection logic.


import os                          # For building file paths
from datetime import datetime      # For timestamps in the report filename


def generate_report(findings, output_path=None):
    """
    Creates a human-readable text report from detection findings.

    Parameters:
        findings (list):   List of finding dictionaries from detections.py.
                           Each has "rule", "severity", and "details" keys.
        output_path (str): Where to save the report file. If None, we'll
                           auto-generate a filename with the current timestamp
                           in the reports/ folder.

    Returns:
        str: The file path where the report was saved.
    """

    # --- STEP 1: DECIDE WHERE TO SAVE THE REPORT ---
    # If the caller didn't give us a specific path, we generate one.
    # datetime.now().strftime() formats the current date/time into a string.
    # The format codes: %Y=year, %m=month, %d=day, %H=hour, %M=minute, %S=second.
    # Example result: "reports/pulse_report_20240115_083045.txt"
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join("reports", f"pulse_report_{timestamp}.txt")

    # --- STEP 2: COUNT FINDINGS BY SEVERITY ---
    # We loop through all findings and tally up how many are HIGH, MEDIUM, LOW.
    # This gives the reader a quick "at a glance" summary at the top of the report.
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for finding in findings:
        # Pull out the severity level from this finding.
        severity = finding.get("severity", "LOW")
        # Increment the count for that severity level.
        # We use .get() with a default of 0 in case an unexpected severity
        # shows up that isn't in our dictionary.
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # --- STEP 3: BUILD THE REPORT AS A LIST OF LINES ---
    # Instead of writing one giant string, we build a list of lines and
    # join them at the end. This is cleaner and easier to read in code.
    lines = []

    # --- HEADER ---
    lines.append("=" * 60)
    lines.append("  PULSE — Threat Detection Report")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Total findings: {len(findings)}")
    lines.append("")

    # --- SEVERITY SUMMARY ---
    # This block gives the reader a quick picture before they dive into details.
    # Example output:
    #   HIGH:   3
    #   MEDIUM: 1
    #   LOW:    0
    lines.append("  Severity Breakdown:")
    lines.append(f"    HIGH:   {severity_counts['HIGH']}")
    lines.append(f"    MEDIUM: {severity_counts['MEDIUM']}")
    lines.append(f"    LOW:    {severity_counts['LOW']}")
    lines.append("")
    lines.append("-" * 60)

    # --- STEP 4: LIST EACH FINDING ---
    # enumerate() gives us both the index (starting at 1) and the finding.
    # This is a cleaner alternative to manually tracking a counter variable.
    for i, finding in enumerate(findings, start=1):
        lines.append("")
        lines.append(f"  [{finding['severity']}] Finding #{i}: {finding['rule']}")
        lines.append(f"  {'-' * 40}")

        # textwrap would be nice here, but let's keep it simple.
        # We just indent the details text.
        lines.append(f"  {finding['details']}")
        lines.append("")

    # --- FOOTER ---
    lines.append("-" * 60)
    lines.append("  End of report.")
    lines.append("=" * 60)
    lines.append("")

    # --- STEP 5: JOIN ALL LINES INTO ONE STRING ---
    # "\n".join() takes our list of lines and connects them with newline
    # characters. This turns ["line1", "line2"] into "line1\nline2".
    report_text = "\n".join(lines)

    # --- STEP 6: WRITE THE REPORT TO A FILE ---
    # open() with "w" mode creates the file (or overwrites it if it exists).
    # The "with" statement ensures the file gets properly closed when we're
    # done, even if an error happens. This is called a "context manager."
    # encoding="utf-8" ensures special characters (accents, symbols) are
    # handled correctly instead of potentially crashing on non-ASCII text.
    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.write(report_text)

    # --- STEP 7: RETURN THE PATH ---
    # main.py uses this to tell the user where the report was saved.
    return output_path
