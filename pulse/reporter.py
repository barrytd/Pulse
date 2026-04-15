# pulse/reporter.py
# -------------------
# Generates text and HTML reports from detection findings.
#
# HTML report features:
#   - Two tabs: Detections (filterable table) and Remediation (action cards)
#   - Dark mode toggle (persisted in localStorage)
#   - Severity-sorted findings (CRITICAL at the top)
#   - Executive summary generated from which rules fired


import csv
import io
import json
import os
import re
from datetime import datetime


# Maps each rule to its MITRE ATT&CK technique ID.
# ATT&CK is an industry-standard framework that catalogs attacker tactics
# and techniques. Each technique has an ID like T1110 (Brute Force).
# This lets analysts quickly look up the technique on attack.mitre.org
# and understand the attacker's goal.
MITRE_ATTACK_IDS = {
    "New Account (Baseline)":    "T1136.001",
    "New Service (Baseline)":    "T1543.003",
    "New Task (Baseline)":       "T1053.005",
    "Pass-the-Hash Attempt":     "T1550.002",
    "Brute Force Attempt":       "T1110",
    "Account Lockout":           "T1110",
    "User Account Created":      "T1136.001",
    "Privilege Escalation":      "T1078.002",
    "Audit Log Cleared":         "T1070.001",
    "RDP Logon Detected":        "T1021.001",
    "Service Installed":         "T1543.003",
    "Antivirus Disabled":        "T1562.001",
    "Firewall Disabled":         "T1562.004",
    "Firewall Rule Changed":     "T1562.004",
    "Scheduled Task Created":    "T1053.005",
    "Suspicious PowerShell":     "T1059.001",
    "Account Takeover Chain":    "T1078",
    "Malware Persistence Chain": "T1543.003",
    "Kerberoasting":              "T1558.003",
    "Golden Ticket":              "T1558.001",
    "Credential Dumping":         "T1003.001",
    "Logon from Disabled Account": "T1078",
    "After-Hours Logon":          "T1078",
    "Suspicious Registry Modification": "T1547.001",
    "Lateral Movement via Network Share": "T1021.002",
    "DCSync Attempt":             "T1003.006",
    "Suspicious Child Process":   "T1059",
}


SEVERITY_COLOURS = {
    "CRITICAL": "#8e44ad",
    "HIGH":     "#e74c3c",
    "MEDIUM":   "#e67e22",
    "LOW":      "#3498db",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Maps each rule name to the Windows Event ID(s) it covers.
RULE_EVENT_IDS = {
    "Brute Force Attempt":       "4625",
    "User Account Created":      "4720",
    "Privilege Escalation":      "4732",
    "Audit Log Cleared":         "1102",
    "RDP Logon Detected":        "4624",
    "Service Installed":         "7045",
    "Antivirus Disabled":        "5001",
    "Firewall Disabled":         "4950",
    "Firewall Rule Changed":     "4946 / 4947",
    "Pass-the-Hash Attempt":     "4624",
    "New Account (Baseline)":    "4720",
    "New Service (Baseline)":    "7045",
    "New Task (Baseline)":       "4698",
    "Account Lockout":           "4740",
    "Scheduled Task Created":    "4698",
    "Suspicious PowerShell":     "4104",
    "Account Takeover Chain":    "Multiple",
    "Malware Persistence Chain": "Multiple",
    "Kerberoasting":                    "4769",
    "Golden Ticket":                    "4768",
    "Credential Dumping":               "4656 / 4663",
    "Logon from Disabled Account":      "4625",
    "After-Hours Logon":                "4624",
    "Suspicious Registry Modification": "4657",
    "Lateral Movement via Network Share": "5140 / 5145",
    "DCSync Attempt":                     "4662",
    "Suspicious Child Process":           "4688",
}

# Hardcoded remediation steps per rule.
# Each entry is a short, actionable list an analyst can follow immediately.
REMEDIATION = {
    "Account Takeover Chain": [
        "Disable the newly created backdoor account immediately.",
        "Reset credentials for the compromised account.",
        "Audit all logins in the past 24 hours for lateral movement.",
        "Enforce MFA on all privileged accounts.",
    ],
    "Malware Persistence Chain": [
        "Stop and delete the suspicious service via Services (services.msc).",
        "Re-enable Windows Defender real-time protection.",
        "Run a full offline malware scan (boot into Windows Defender Offline).",
        "Check startup entries (msconfig) and scheduled tasks for persistence.",
    ],
    "Audit Log Cleared": [
        "Restore logs from backup or SIEM forwarding if available.",
        "Identify who cleared the log and when using any remaining records.",
        "Enable log forwarding to a remote SIEM so future logs cannot be wiped locally.",
    ],
    "Antivirus Disabled": [
        "Re-enable Windows Defender real-time protection immediately.",
        "Lock the AV settings via Group Policy to prevent users disabling it.",
        "Check for malware that may have executed during the unprotected window.",
    ],
    "Firewall Disabled": [
        "Re-enable the Windows Firewall profile via Group Policy.",
        "Review all network connections made while the firewall was off.",
        "Set an alert to notify on future firewall profile changes.",
    ],
    "Privilege Escalation": [
        "Remove the account from the Administrators group if the change was unauthorized.",
        "Audit all members of sensitive security groups (Administrators, Remote Desktop Users).",
        "Review who granted the privilege and whether their account is compromised.",
    ],
    "Brute Force Attempt": [
        "Lock the targeted account and force a password reset.",
        "Block the source IP address at the perimeter firewall.",
        "Enable an account lockout policy (e.g. lock after 5 failures).",
    ],
    "Firewall Rule Changed": [
        "Review the new or modified rule and remove it if unauthorized.",
        "Note: port 4444 is commonly used by reverse shells (Metasploit default).",
        "Audit all firewall rule changes over the past 48 hours.",
    ],
    "Service Installed": [
        "Verify the service name and binary path in services.msc.",
        "Stop and delete the service if unrecognized.",
        "Submit the binary to VirusTotal or scan with Defender Offline.",
    ],
    "User Account Created": [
        "Confirm with IT whether the account creation was authorized.",
        "Disable the account immediately if it was not requested.",
        "Audit what resources or systems the account accessed after creation.",
    ],
    "New Account (Baseline)": [
        "Confirm with IT whether this account was intentionally created after the baseline was taken.",
        "Disable the account immediately if it was not authorized.",
        "Check what resources or systems the new account has accessed.",
    ],
    "New Service (Baseline)": [
        "Verify the service name and binary path in services.msc.",
        "Stop and delete the service if it was not intentionally installed after the baseline.",
        "Submit the binary to VirusTotal or scan with Defender Offline.",
    ],
    "New Task (Baseline)": [
        "Review the task in Task Scheduler (taskschd.msc) and check its action and trigger.",
        "Delete the task if it was not intentionally created after the baseline.",
        "Check what binary or script the task runs.",
    ],
    "Pass-the-Hash Attempt": [
        "Reset the password of the targeted account immediately.",
        "Check if Mimikatz or credential dumping tools were run on any machine in the environment.",
        "Enable Protected Users security group for privileged accounts - prevents NTLM authentication.",
        "Consider enforcing Kerberos-only authentication for sensitive accounts.",
        "Audit all NTLM logon events (Event 4624 type 3) for the affected account across all machines.",
    ],
    "Suspicious PowerShell": [
        "Review the full script block in Event Viewer (Event 4104) for malicious intent.",
        "Check if the script downloaded or executed anything from the internet.",
        "If Base64 was used, decode it to reveal the hidden command.",
        "Investigate the user account that ran the script and check for compromise.",
    ],
    "Scheduled Task Created": [
        "Review the task in Task Scheduler (taskschd.msc) and check its action/trigger.",
        "Delete the task if it is unrecognized or runs a suspicious binary.",
        "Check who created the task and whether their account is compromised.",
        "Search for the binary or script the task runs on VirusTotal.",
    ],
    "Account Lockout": [
        "Check if the account is under active brute force attack (correlate with Event 4625).",
        "If legitimate, reset the password and unlock the account.",
        "Review the account lockout policy threshold and adjust if too aggressive.",
        "If repeated across multiple accounts, investigate the source IP for brute force activity.",
    ],
    "RDP Logon Detected": [
        "Verify the source IP is expected and belongs to a known user.",
        "If unexpected, block the IP at the firewall and audit the session activity.",
        "Consider restricting RDP access to a VPN or jump host only.",
    ],
    "DCSync Attempt": [
        "Treat this as an active domain compromise — a DCSync recovers every password hash in the domain.",
        "Isolate the workstation the request came from and capture memory for forensics.",
        "Reset the krbtgt account password twice (24h apart) to invalidate any Golden Tickets.",
        "Rotate passwords for every privileged account (Domain Admins, service accounts, break-glass).",
        "Audit which accounts have Replicating Directory Changes rights and remove any that shouldn't.",
    ],
    "Suspicious Child Process": [
        "Review the full command line in Event 4688 — decode any Base64 PowerShell to see the real payload.",
        "Capture a memory image and hash of the child process before killing it.",
        "Check the user's mailbox/browser history for the initial lure (macro document, phishing link, fake captcha).",
        "Block the parent application from spawning child shells via Attack Surface Reduction rules.",
        "Search the fleet for other hosts running the same command line — attacker often spray the lure widely.",
    ],
}


def generate_report(findings, output_path=None, fmt="txt", scan_stats=None):
    """
    Creates a report from detection findings in text, HTML, JSON, or CSV format.

    Parameters:
        findings (list):   List of finding dicts (rule, severity, details).
        output_path (str): Save path. Auto-generated if None.
        fmt (str):         "txt", "html", "json", or "csv". Default: "txt".
        scan_stats (dict): Optional scan statistics from the parser:
                           total_events, files_scanned, earliest, latest, top_event_ids.

    Returns:
        str: Path where the report was saved.
    """

    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        extensions = {"html": "html", "json": "json", "csv": "csv"}
        extension = extensions.get(fmt, "txt")
        output_path = os.path.join("reports", f"pulse_report_{timestamp}.{extension}")

    # Sort findings — most severe first.
    findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.get("severity", "LOW"))
        if f.get("severity") in SEVERITY_ORDER else len(SEVERITY_ORDER)
    )

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        severity = finding.get("severity", "LOW")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    if fmt == "html":
        report_text = _build_html_report(findings, severity_counts, scan_stats)
    elif fmt == "json":
        report_text = _build_json_report(findings, severity_counts, scan_stats)
    elif fmt == "csv":
        report_text = _build_csv_report(findings)
    else:
        report_text = _build_txt_report(findings, severity_counts, scan_stats)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return output_path


def _build_txt_report(findings, severity_counts, scan_stats=None):
    """Builds the plain text report."""

    lines = []
    lines.append("=" * 60)
    lines.append("  PULSE - Threat Detection Report")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Total findings: {len(findings)}")
    lines.append("")

    # Scan summary - shows what was parsed before the findings.
    if scan_stats:
        lines.append("  Scan Summary:")
        lines.append(f"    Files scanned:  {scan_stats['files_scanned']}")
        lines.append(f"    Total events:   {scan_stats['total_events']}")
        lines.append(f"    Time range:     {scan_stats['earliest']}")
        lines.append(f"                    to {scan_stats['latest']}")
        lines.append("")
        lines.append("    Top Event IDs:")
        for event_id, count in scan_stats["top_event_ids"]:
            lines.append(f"      Event {event_id}: {count}")
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


def _build_csv_report(findings):
    """
    Builds a CSV (comma-separated values) report.

    CSV is a simple table format that opens directly in Excel, Google Sheets,
    or any spreadsheet application. Each row is one finding with columns for
    timestamp, event ID, severity, rule name, and description.

    We use Python's csv module to handle quoting and escaping - it
    automatically wraps fields in quotes if they contain commas or newlines.
    """

    output = io.StringIO()
    # lineterminator='\n' prevents double line breaks on Windows.
    # Without it, csv.writer uses '\r\n' and then the file write adds another.
    writer = csv.writer(output, lineterminator="\n")

    # Header row.
    writer.writerow(["Timestamp", "Event ID", "Severity", "Rule Name", "MITRE ATT&CK", "Description"])

    for finding in findings:
        ts_match = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", finding["details"])
        timestamp = ts_match.group().replace("T", " ") if ts_match else ""
        event_id = RULE_EVENT_IDS.get(finding["rule"], "")
        mitre_id = MITRE_ATTACK_IDS.get(finding["rule"], "")

        writer.writerow([
            timestamp,
            event_id,
            finding["severity"],
            finding["rule"],
            mitre_id,
            finding["details"],
        ])

    return output.getvalue()


def _build_json_report(findings, severity_counts, scan_stats=None):
    """
    Builds a machine-readable JSON report.

    JSON is a standard data format that other tools can easily read.
    Tools like Splunk, ELK, or Python scripts can ingest this file
    and process the findings programmatically - no manual parsing needed.

    The output structure:
    {
        "metadata": { ... },      # When the report was generated, scan info
        "summary":  { ... },      # Severity counts and security score
        "findings": [ ... ]       # Array of individual finding objects
    }
    """

    score, score_label, _ = _calculate_score(severity_counts)

    # --- METADATA: information about the scan itself ---
    metadata = {
        "generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "tool": "Pulse",
        "version": "1.0.0",
    }

    # If we have scan stats from the parser, include them in metadata.
    if scan_stats:
        metadata["files_scanned"] = scan_stats["files_scanned"]
        metadata["total_events"] = scan_stats["total_events"]
        metadata["time_range"] = {
            "earliest": scan_stats["earliest"],
            "latest": scan_stats["latest"],
        }
        # Convert list of tuples to a dict for cleaner JSON.
        # [(4625, 100), (4624, 50)] -> {"4625": 100, "4624": 50}
        metadata["top_event_ids"] = {
            str(eid): count for eid, count in scan_stats["top_event_ids"]
        }

    # --- SUMMARY: high-level severity breakdown ---
    summary = {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "security_score": score,
        "risk_level": score_label,
    }

    # --- FINDINGS: one object per detection ---
    findings_list = []
    for finding in findings:
        # Extract the timestamp from the details string, same regex as the HTML builder.
        ts_match = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", finding["details"])
        timestamp = ts_match.group() if ts_match else None

        findings_list.append({
            "rule_name": finding["rule"],
            "severity": finding["severity"],
            "event_id": RULE_EVENT_IDS.get(finding["rule"], None),
            "timestamp": timestamp,
            "description": finding["details"],
            "mitre_attack_id": MITRE_ATTACK_IDS.get(finding["rule"], None),
        })

    report = {
        "metadata": metadata,
        "summary": summary,
        "findings": findings_list,
    }

    # indent=2 makes the JSON human-readable with nice spacing.
    # ensure_ascii=False keeps special characters intact.
    return json.dumps(report, indent=2, ensure_ascii=False)


RULE_CATEGORIES = {
    "Brute Force Attempt":       "Authentication",
    "Account Lockout":           "Authentication",
    "Pass-the-Hash Attempt":     "Credential Access",
    "RDP Logon Detected":        "Lateral Movement",
    "User Account Created":      "Persistence",
    "Privilege Escalation":      "Privilege Escalation",
    "Service Installed":         "Persistence",
    "Scheduled Task Created":    "Persistence",
    "Suspicious PowerShell":     "Execution",
    "Antivirus Disabled":        "Defense Evasion",
    "Firewall Disabled":         "Defense Evasion",
    "Firewall Rule Changed":     "Defense Evasion",
    "Audit Log Cleared":         "Defense Evasion",
    "Account Takeover Chain":    "Credential Access",
    "Malware Persistence Chain": "Persistence",
    "Kerberoasting":                    "Credential Access",
    "Golden Ticket":                    "Credential Access",
    "Credential Dumping":               "Credential Access",
    "Logon from Disabled Account":      "Authentication",
    "After-Hours Logon":                "Authentication",
    "Suspicious Registry Modification": "Persistence",
    "Lateral Movement via Network Share": "Lateral Movement",
}

SEVERITY_DEDUCTIONS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}


def _calculate_score(severity_counts):
    """
    Calculates a security score out of 100 based on severity counts.

    This is the legacy per-count version used by the CLI and HTML reports.
    The API uses calculate_score_from_findings() for smarter deduplication.

    Returns:
        tuple: (score int, label str, hex_colour str)
    """
    deductions = (
        severity_counts.get("CRITICAL", 0) * 25 +
        severity_counts.get("HIGH",     0) * 15 +
        severity_counts.get("MEDIUM",   0) *  8 +
        severity_counts.get("LOW",      0) *  3
    )
    score = max(0, 100 - deductions)
    return score, *_score_tier(score)


def calculate_score_from_findings(findings):
    """
    Calculates a deduplicated security score from a list of findings.

    Only unique rules are penalized — 50 brute force events count as one
    "Brute Force Attempt" deduction, not 50. This prevents noisy but
    low-risk events from tanking the score.

    Returns:
        dict with: score, label, colour, grade, deductions (list),
                   categories (dict of category -> {score, rules})
    """
    unique_rules = {}
    for f in findings:
        rule = f.get("rule", "Unknown")
        sev = f.get("severity", "LOW")
        if rule not in unique_rules or SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index(unique_rules[rule]):
            unique_rules[rule] = sev

    deduction_list = []
    for rule, sev in unique_rules.items():
        pts = SEVERITY_DEDUCTIONS.get(sev, 3)
        deduction_list.append({"rule": rule, "severity": sev, "points": pts,
                               "category": RULE_CATEGORIES.get(rule, "Other")})

    total_deducted = sum(d["points"] for d in deduction_list)
    score = max(0, 100 - total_deducted)
    label, colour = _score_tier(score)
    grade = _score_grade(score)

    categories = {}
    all_cats = ["Authentication", "Credential Access", "Lateral Movement",
                "Persistence", "Privilege Escalation", "Execution", "Defense Evasion"]
    for cat in all_cats:
        cat_rules = [d for d in deduction_list if d["category"] == cat]
        cat_deducted = sum(d["points"] for d in cat_rules)
        categories[cat] = {
            "deducted": cat_deducted,
            "rules_triggered": [d["rule"] for d in cat_rules],
            "status": "clear" if cat_deducted == 0 else
                      "low" if cat_deducted <= 5 else
                      "medium" if cat_deducted <= 15 else "high",
        }

    return {
        "score": score, "label": label, "colour": colour, "grade": grade,
        "total_deducted": total_deducted,
        "deductions": sorted(deduction_list, key=lambda d: d["points"], reverse=True),
        "categories": categories,
    }


def _score_tier(score):
    if score >= 90:
        return "SECURE",        "#27ae60"
    elif score >= 75:
        return "LOW RISK",      "#3498db"
    elif score >= 50:
        return "MODERATE RISK", "#e67e22"
    elif score >= 25:
        return "HIGH RISK",     "#e74c3c"
    else:
        return "CRITICAL RISK", "#8e44ad"


def _score_grade(score):
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 50: return "C"
    if score >= 25: return "D"
    return "F"


def _build_executive_summary(findings, severity_counts):
    """
    Generates a short executive summary paragraph based on what was found.
    The tone adjusts depending on the highest severity present.

    Returns:
        str: One or two sentences of plain text.
    """

    total = len(findings)
    rules_triggered = set(f["rule"] for f in findings)

    if severity_counts["CRITICAL"] > 0:
        return (
            f"This scan detected <strong>{total} finding(s)</strong>, including "
            f"<strong>{severity_counts['CRITICAL']} CRITICAL</strong> attack chain(s). "
            f"This indicates a likely active or recent compromise. "
            f"Immediate investigation and containment is recommended before remediation."
        )
    elif severity_counts["HIGH"] > 0:
        return (
            f"This scan detected <strong>{total} finding(s)</strong> including "
            f"<strong>{severity_counts['HIGH']} HIGH</strong> severity threat(s). "
            f"No confirmed attack chains were detected, but the findings suggest "
            f"active threat activity that should be investigated promptly."
        )
    elif severity_counts["MEDIUM"] > 0:
        return (
            f"This scan detected <strong>{total} finding(s)</strong> at MEDIUM severity or below. "
            f"No high-severity threats were confirmed. Review the findings below "
            f"and verify whether each event was authorized."
        )
    else:
        return (
            f"This scan detected <strong>{total} finding(s)</strong>, all at LOW severity. "
            f"No immediately dangerous activity was identified. "
            f"Review the findings below as part of routine monitoring."
        )


def _build_html_report(findings, severity_counts, scan_stats=None):
    """Builds the full two-tab HTML report (Detections + Remediation)."""

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(findings)
    score, score_label, score_colour = _calculate_score(severity_counts)

    # --- DETECTIONS TAB: table rows ---
    rows = []
    for finding in findings:
        severity  = finding["severity"]
        colour    = SEVERITY_COLOURS.get(severity, "#95a5a6")
        event_id  = RULE_EVENT_IDS.get(finding["rule"], "-")
        ts_match  = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", finding["details"])
        timestamp = ts_match.group().replace("T", " ") if ts_match else "-"

        mitre_id = MITRE_ATTACK_IDS.get(finding["rule"], "-")
        # Link to the MITRE ATT&CK page for this technique.
        if mitre_id != "-":
            mitre_html = f'<a href="https://attack.mitre.org/techniques/{mitre_id.replace(".", "/")}/" target="_blank" class="mitre-link">{mitre_id}</a>'
        else:
            mitre_html = "-"

        row = f"""
                    <tr data-severity="{severity}">
                        <td class="ts">{timestamp}</td>
                        <td class="event-id">{event_id}</td>
                        <td><span class="badge badge-{severity.lower()}">{severity}</span></td>
                        <td class="rule-name">{finding['rule']}</td>
                        <td class="mitre">{mitre_html}</td>
                        <td class="desc">{finding['details']}</td>
                    </tr>"""
        rows.append(row)
    all_rows = "\n".join(rows)

    # --- SCAN STATS PANEL ---
    # Only shown when scan_stats is provided (i.e. when running from main.py
    # against real .evtx files, not when generating test reports manually).
    scan_stats_html = ""
    if scan_stats:
        # Build the top event IDs as small inline items.
        top_ids_html = ""
        for event_id, count in scan_stats["top_event_ids"]:
            top_ids_html += f'<span class="stat-event">Event {event_id}: <strong>{count}</strong></span>'

        # Format the timestamps to be more readable (strip the trailing Z and microseconds).
        earliest = scan_stats["earliest"].replace("Z", "").split(".")[0].replace("T", " ")
        latest = scan_stats["latest"].replace("Z", "").split(".")[0].replace("T", " ")

        scan_stats_html = f"""
        <div class="scan-stats">
            <h2 class="scan-stats-title">Scan Summary</h2>
            <div class="scan-stats-grid">
                <div class="stat-box">
                    <div class="stat-value">{scan_stats['files_scanned']}</div>
                    <div class="stat-label">Files Scanned</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{scan_stats['total_events']:,}</div>
                    <div class="stat-label">Total Events</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{total}</div>
                    <div class="stat-label">Findings</div>
                </div>
                <div class="stat-box stat-box-wide">
                    <div class="stat-label">Time Range</div>
                    <div class="stat-time">{earliest}  to  {latest}</div>
                </div>
            </div>
            <div class="stat-events-row">
                <span class="stat-events-label">Top Event IDs:</span>
                {top_ids_html}
            </div>
        </div>"""

    # --- REMEDIATION TAB: executive summary + cards ---
    exec_summary = _build_executive_summary(findings, severity_counts)

    # Only show remediation cards for rules that actually fired, sorted by severity.
    triggered_rules = []
    seen = set()
    for finding in findings:  # already sorted by severity
        rule = finding["rule"]
        if rule not in seen and rule in REMEDIATION:
            seen.add(rule)
            triggered_rules.append(finding)

    remediation_cards_html = ""
    for finding in triggered_rules:
        severity = finding["severity"]
        colour   = SEVERITY_COLOURS.get(severity, "#95a5a6")
        steps    = REMEDIATION.get(finding["rule"], [])
        steps_html = "\n".join(f"<li>{s}</li>" for s in steps)

        remediation_cards_html += f"""
            <div class="rem-card">
                <div class="rem-card-header">
                    <span class="badge" style="background:{colour};">{severity}</span>
                    <span class="rem-rule-name">{finding['rule']}</span>
                </div>
                <ul class="rem-steps">
                    {steps_html}
                </ul>
            </div>"""

    # --- FULL HTML ---
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pulse - Threat Detection Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* ── CSS variables — light mode defaults ── */
        :root {{
            --bg:           #f4f6f8;
            --surface:      #ffffff;
            --nav-bg:       #1a1a2e;
            --nav-text:     #ffffff;
            --text:         #1a1a2e;
            --text-muted:   #7f8c8d;
            --border:       #dde1e7;
            --row-hover:    #f3f6fa;
            --thead-bg:     #f4f6f8;
            --tab-active:   #1a1a2e;
            --tab-text:     #ffffff;
            --tab-inactive: #e8eaed;
            --tab-inactive-text: #4a4a5a;
            --rem-bg:       #f9fafb;
            --rem-border:   #e8eaed;
        }}

        /* ── Dark mode overrides ── */
        body.dark {{
            --bg:           #0f0f1a;
            --surface:      #1a1a2e;
            --nav-bg:       #0a0a14;
            --nav-text:     #e0e0e0;
            --text:         #e0e0e0;
            --text-muted:   #7f8c8d;
            --border:       #2c3e50;
            --row-hover:    #1e2a3a;
            --thead-bg:     #16213e;
            --tab-active:   #e74c3c;
            --tab-text:     #ffffff;
            --tab-inactive: #16213e;
            --tab-inactive-text: #95a5a6;
            --rem-bg:       #16213e;
            --rem-border:   #2c3e50;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            font-size: 14px;
            transition: background 0.2s, color 0.2s;
        }}

        /* ── Navbar ── */
        .navbar {{
            background: var(--nav-bg);
            padding: 0 30px;
            display: flex;
            align-items: center;
            height: 56px;
            gap: 12px;
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        .navbar-logo {{
            color: var(--nav-text);
            font-size: 1.1rem;
            font-weight: 700;
            letter-spacing: 3px;
        }}
        .navbar-sub {{
            color: #7f8c8d;
            font-size: 0.8rem;
            padding-left: 12px;
            border-left: 1px solid #2c3e50;
        }}
        .navbar-right {{
            margin-left: auto;
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        .navbar-meta {{
            color: #7f8c8d;
            font-size: 0.8rem;
        }}

        /* ── Dark mode toggle button ── */
        .dark-toggle {{
            background: none;
            border: 1px solid #2c3e50;
            border-radius: 20px;
            padding: 4px 12px;
            color: #7f8c8d;
            font-size: 0.75rem;
            cursor: pointer;
            transition: border-color 0.2s, color 0.2s;
        }}
        .dark-toggle:hover {{
            border-color: #7f8c8d;
            color: var(--nav-text);
        }}

        /* ── Page wrapper ── */
        .page {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 28px 24px;
        }}

        h1 {{
            font-size: 1.6rem;
            font-weight: 600;
            margin-bottom: 20px;
            color: var(--text);
        }}

        /* ── Tabs ── */
        .tabs {{
            display: flex;
            gap: 4px;
            margin-bottom: 16px;
        }}
        .tab-btn {{
            padding: 9px 22px;
            border-radius: 6px 6px 0 0;
            border: none;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            background: var(--tab-inactive);
            color: var(--tab-inactive-text);
            transition: background 0.15s, color 0.15s;
        }}
        .tab-btn.active {{
            background: var(--tab-active);
            color: var(--tab-text);
        }}

        /* ── Tab panels ── */
        .tab-panel {{ display: none; }}
        .tab-panel.active {{ display: block; }}

        /* ── Filter bar ── */
        .filter-bar {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 14px 20px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.05);
        }}
        .filter-bar label {{
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-right: 4px;
        }}
        .filter-btn {{
            padding: 5px 14px;
            border-radius: 20px;
            border: 2px solid transparent;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            cursor: pointer;
            color: #fff;
            transition: opacity 0.15s, transform 0.1s;
        }}
        .filter-btn:hover {{ opacity: 0.85; transform: translateY(-1px); }}
        .filter-btn-all {{
            background: var(--tab-active);
            color: var(--tab-text);
            padding: 5px 14px;
            border-radius: 20px;
            border: none;
            font-size: 0.75rem;
            font-weight: 700;
            cursor: pointer;
        }}
        .filter-count {{
            margin-left: auto;
            font-size: 0.8rem;
            color: var(--text-muted);
        }}

        /* ── Table ── */
        .table-wrap {{
            background: var(--surface);
            border-radius: 6px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.07);
            overflow: hidden;
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        thead {{
            border-bottom: 1px solid var(--border);
        }}
        th {{
            padding: 12px 18px;
            text-align: left;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--text-muted);
            white-space: nowrap;
        }}
        td {{
            padding: 15px 18px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: var(--row-hover); transition: background 0.1s; }}
        tr.hidden {{ display: none; }}

        .ts        {{ white-space: nowrap; color: var(--text-muted); font-size: 0.82rem; width: 145px; }}
        .event-id  {{ white-space: nowrap; font-family: monospace; width: 100px; }}
        .rule-name {{ font-weight: 600; width: 200px; }}
        .mitre     {{ white-space: nowrap; width: 110px; }}
        .mitre-link {{
            display: inline-block;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', monospace;
            font-size: 0.72rem;
            background: var(--thead-bg);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 2px 6px;
            color: var(--text);
            text-decoration: none;
            white-space: nowrap;
        }}
        .mitre-link:hover {{
            border-color: var(--text-muted);
            text-decoration: none;
        }}
        .desc      {{ color: var(--text-muted); line-height: 1.6; font-size: 0.85rem; }}

        /* ── Severity badge — muted pill style ── */
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 600;
            letter-spacing: 0.3px;
            white-space: nowrap;
        }}
        /* Muted variants for the detections table */
        .badge-critical {{ background: #fdecea; color: #a93226; }}
        .badge-high     {{ background: #fef3e2; color: #c0530e; }}
        .badge-medium   {{ background: #fefce8; color: #7d6608; }}
        .badge-low      {{ background: #edfaf1; color: #1e8449; }}
        /* Dark mode adjustments for muted badges */
        body.dark .badge-critical {{ background: #3d1515; color: #e57373; }}
        body.dark .badge-high     {{ background: #3d2810; color: #ffab76; }}
        body.dark .badge-medium   {{ background: #2e2a0e; color: #f9d976; }}
        body.dark .badge-low      {{ background: #0e2d1a; color: #6fcf97; }}

        /* ── Remediation tab ── */
        .exec-summary {{
            background: var(--surface);
            border-left: 4px solid {SEVERITY_COLOURS['CRITICAL']};
            border-radius: 0 6px 6px 0;
            padding: 18px 22px;
            margin-bottom: 24px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.07);
            line-height: 1.7;
            color: var(--text);
            font-size: 0.92rem;
        }}
        .exec-summary h2 {{
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }}
        .rem-card {{
            background: var(--surface);
            border: 1px solid var(--rem-border);
            border-radius: 6px;
            margin-bottom: 14px;
            overflow: hidden;
            box-shadow: 0 1px 4px rgba(0,0,0,0.06);
        }}
        .rem-card-header {{
            background: var(--rem-bg);
            padding: 12px 18px;
            display: flex;
            align-items: center;
            gap: 12px;
            border-bottom: 1px solid var(--rem-border);
        }}
        .rem-rule-name {{
            font-weight: 600;
            font-size: 0.95rem;
        }}
        .rem-steps {{
            list-style: none;
            padding: 14px 18px;
        }}
        .rem-steps li {{
            padding: 7px 0 7px 20px;
            position: relative;
            border-bottom: 1px solid var(--rem-border);
            color: var(--text);
            font-size: 0.88rem;
            line-height: 1.5;
        }}
        .rem-steps li:last-child {{ border-bottom: none; }}
        .rem-steps li::before {{
            content: "";
            position: absolute;
            left: 0;
            top: 14px;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--text-muted);
        }}

        /* ── Scan stats panel ── */
        .scan-stats {{
            background: var(--surface);
            border-radius: 10px;
            padding: 22px 28px;
            margin-bottom: 20px;
            box-shadow: 0 1px 6px rgba(0,0,0,0.08);
        }}
        .scan-stats-title {{
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: var(--text-muted);
            margin-bottom: 14px;
        }}
        .scan-stats-grid {{
            display: flex;
            gap: 16px;
            margin-bottom: 14px;
        }}
        .stat-box {{
            background: var(--bg);
            border-radius: 8px;
            padding: 14px 20px;
            text-align: center;
            flex: 1;
        }}
        .stat-box-wide {{
            flex: 2;
            text-align: left;
        }}
        .stat-value {{
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text);
            line-height: 1;
        }}
        .stat-label {{
            font-size: 0.72rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-top: 4px;
        }}
        .stat-time {{
            font-size: 0.88rem;
            font-family: monospace;
            color: var(--text);
            margin-top: 6px;
        }}
        .stat-events-row {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
        }}
        .stat-events-label {{
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
        }}
        .stat-event {{
            font-size: 0.8rem;
            color: var(--text-muted);
            background: var(--bg);
            padding: 3px 10px;
            border-radius: 12px;
        }}
        .stat-event strong {{
            color: var(--text);
        }}

        /* ── Score hero ── */
        .score-hero {{
            background: var(--surface);
            border-radius: 10px;
            padding: 28px 36px;
            margin-bottom: 24px;
            box-shadow: 0 1px 6px rgba(0,0,0,0.08);
            display: flex;
            align-items: center;
            gap: 32px;
        }}
        .score-ring {{
            width: 110px;
            height: 110px;
            border-radius: 50%;
            border: 8px solid;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }}
        .score-number {{
            font-size: 2.2rem;
            font-weight: 700;
            line-height: 1;
        }}
        .score-denom {{
            font-size: 0.72rem;
            color: var(--text-muted);
            margin-top: 2px;
        }}
        .score-info {{
            flex: 1;
        }}
        .score-label {{
            font-size: 1.4rem;
            font-weight: 700;
            letter-spacing: 1px;
            line-height: 1.2;
        }}
        .score-sub {{
            font-size: 0.82rem;
            color: var(--text-muted);
            margin-top: 4px;
        }}
        .score-breakdown {{
            display: flex;
            gap: 20px;
            margin-top: 14px;
        }}
        .score-breakdown-item {{
            font-size: 0.8rem;
            color: var(--text-muted);
        }}
        .score-breakdown-item strong {{
            font-weight: 700;
        }}

        footer {{
            text-align: center;
            color: var(--text-muted);
            margin-top: 28px;
            font-size: 0.78rem;
        }}
    </style>
</head>
<body>

    <nav class="navbar">
        <span class="navbar-logo">PULSE</span>
        <span class="navbar-sub">Threat Detection Report</span>
        <div class="navbar-right">
            <span class="navbar-meta">Generated: {generated_at} | {total} findings</span>
            <button class="dark-toggle" onclick="toggleDark()" id="dark-btn">Dark Mode</button>
        </div>
    </nav>

    <div class="page">
        <h1>Detection Findings</h1>

        <!-- Scan summary stats -->
        {scan_stats_html}

        <!-- Security score hero -->
        <div class="score-hero">
            <div class="score-ring" style="border-color:{score_colour}; color:{score_colour};">
                <div class="score-number">{score}</div>
                <div class="score-denom">/ 100</div>
            </div>
            <div class="score-info">
                <div class="score-label" style="color:{score_colour};">{score_label}</div>
                <div class="score-sub">Pulse Security Score - based on {total} finding(s) detected</div>
                <div class="score-breakdown">
                    <span class="score-breakdown-item"><strong style="color:{SEVERITY_COLOURS['CRITICAL']};">{severity_counts['CRITICAL']}</strong> Critical (-25 pts each)</span>
                    <span class="score-breakdown-item"><strong style="color:{SEVERITY_COLOURS['HIGH']};">{severity_counts['HIGH']}</strong> High (-10 pts each)</span>
                    <span class="score-breakdown-item"><strong style="color:{SEVERITY_COLOURS['MEDIUM']};">{severity_counts['MEDIUM']}</strong> Medium (-5 pts each)</span>
                    <span class="score-breakdown-item"><strong style="color:{SEVERITY_COLOURS['LOW']};">{severity_counts['LOW']}</strong> Low (-2 pts each)</span>
                </div>
            </div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('detections', this)">Detections</button>
            <button class="tab-btn" onclick="switchTab('remediation', this)">Remediation</button>
        </div>

        <!-- DETECTIONS TAB -->
        <div class="tab-panel active" id="tab-detections">
            <div class="filter-bar">
                <label>Severity</label>
                <button class="filter-btn-all" onclick="filterRows('ALL')">All</button>
                <button class="filter-btn" style="background:{SEVERITY_COLOURS['CRITICAL']};" onclick="filterRows('CRITICAL')">CRITICAL</button>
                <button class="filter-btn" style="background:{SEVERITY_COLOURS['HIGH']};"     onclick="filterRows('HIGH')">HIGH</button>
                <button class="filter-btn" style="background:{SEVERITY_COLOURS['MEDIUM']};"   onclick="filterRows('MEDIUM')">MEDIUM</button>
                <button class="filter-btn" style="background:{SEVERITY_COLOURS['LOW']};"      onclick="filterRows('LOW')">LOW</button>
                <span class="filter-count" id="row-count">{total} results</span>
            </div>

            <div class="table-wrap">
                <table id="findings-table">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Event ID</th>
                            <th>Severity</th>
                            <th>Rule Name</th>
                            <th>MITRE ATT&CK</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {all_rows}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- REMEDIATION TAB -->
        <div class="tab-panel" id="tab-remediation">
            <div class="exec-summary">
                <h2>Executive Summary</h2>
                <p>{exec_summary}</p>
            </div>
            {remediation_cards_html}
        </div>

        <footer>Generated by Pulse - Windows Event Log Analyzer</footer>
    </div>

    <script>
        // ── Dark mode ──
        // localStorage persists the user's preference across page reloads.
        function toggleDark() {{
            const isDark = document.body.classList.toggle('dark');
            localStorage.setItem('pulse-dark', isDark ? '1' : '0');
            document.getElementById('dark-btn').textContent = isDark ? 'Light Mode' : 'Dark Mode';
        }}
        // Apply saved preference on load.
        if (localStorage.getItem('pulse-dark') === '1') {{
            document.body.classList.add('dark');
            document.getElementById('dark-btn').textContent = 'Light Mode';
        }}

        // ── Tab switching ──
        function switchTab(name, btn) {{
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('tab-' + name).classList.add('active');
            btn.classList.add('active');
        }}

        // ── Severity filter (Detections tab) ──
        function filterRows(level) {{
            const rows = document.querySelectorAll('#findings-table tbody tr');
            let visible = 0;
            rows.forEach(function(row) {{
                if (level === 'ALL' || row.dataset.severity === level) {{
                    row.classList.remove('hidden');
                    visible++;
                }} else {{
                    row.classList.add('hidden');
                }}
            }});
            document.getElementById('row-count').textContent = visible + ' results';
        }}
    </script>

</body>
</html>"""

    return html
