# pulse/reporter.py
# -------------------
# Generates text and HTML reports from detection findings.
#
# HTML report features:
#   - Two tabs: Detections (filterable table) and Remediation (action cards)
#   - Dark mode toggle (persisted in localStorage)
#   - Severity-sorted findings (CRITICAL at the top)
#   - Executive summary generated from which rules fired


import os
import re
from datetime import datetime


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
    "Account Takeover Chain":    "Multiple",
    "Malware Persistence Chain": "Multiple",
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
    "RDP Logon Detected": [
        "Verify the source IP is expected and belongs to a known user.",
        "If unexpected, block the IP at the firewall and audit the session activity.",
        "Consider restricting RDP access to a VPN or jump host only.",
    ],
}


def generate_report(findings, output_path=None, fmt="txt"):
    """
    Creates a report from detection findings in text or HTML format.

    Parameters:
        findings (list):   List of finding dicts (rule, severity, details).
        output_path (str): Save path. Auto-generated if None.
        fmt (str):         "txt" or "html". Default: "txt".

    Returns:
        str: Path where the report was saved.
    """

    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        extension = "html" if fmt == "html" else "txt"
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
        report_text = _build_html_report(findings, severity_counts)
    else:
        report_text = _build_txt_report(findings, severity_counts)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return output_path


def _build_txt_report(findings, severity_counts):
    """Builds the plain text report."""

    lines = []
    lines.append("=" * 60)
    lines.append("  PULSE - Threat Detection Report")
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


def _build_html_report(findings, severity_counts):
    """Builds the full two-tab HTML report (Detections + Remediation)."""

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(findings)

    # --- DETECTIONS TAB: table rows ---
    rows = []
    for finding in findings:
        severity  = finding["severity"]
        colour    = SEVERITY_COLOURS.get(severity, "#95a5a6")
        event_id  = RULE_EVENT_IDS.get(finding["rule"], "-")
        ts_match  = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", finding["details"])
        timestamp = ts_match.group().replace("T", " ") if ts_match else "-"

        row = f"""
                    <tr data-severity="{severity}">
                        <td class="ts">{timestamp}</td>
                        <td class="event-id">{event_id}</td>
                        <td><span class="badge" style="background:{colour};">{severity}</span></td>
                        <td class="rule-name">{finding['rule']}</td>
                        <td class="desc">{finding['details']}</td>
                    </tr>"""
        rows.append(row)
    all_rows = "\n".join(rows)

    # --- SUMMARY CARDS (shared between tabs) ---
    cards_html = ""
    for level in SEVERITY_ORDER:
        colour = SEVERITY_COLOURS[level]
        count  = severity_counts.get(level, 0)
        cards_html += f"""
            <div class="card" style="border-top: 4px solid {colour};">
                <div class="card-count" style="color:{colour};">{count}</div>
                <div class="card-label">{level}</div>
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
            --row-hover:    #fafbfc;
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
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
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

        /* ── Summary cards ── */
        .cards {{
            display: flex;
            gap: 16px;
            margin-bottom: 28px;
        }}
        .card {{
            background: var(--surface);
            border-radius: 6px;
            padding: 18px 24px;
            flex: 1;
            box-shadow: 0 1px 4px rgba(0,0,0,0.08);
            text-align: center;
        }}
        .card-count {{
            font-size: 2rem;
            font-weight: 700;
            line-height: 1;
        }}
        .card-label {{
            font-size: 0.72rem;
            font-weight: 600;
            letter-spacing: 1.5px;
            color: var(--text-muted);
            margin-top: 6px;
            text-transform: uppercase;
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
            background: var(--thead-bg);
            border-bottom: 2px solid var(--border);
        }}
        th {{
            padding: 11px 16px;
            text-align: left;
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            white-space: nowrap;
        }}
        td {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: var(--row-hover); }}
        tr.hidden {{ display: none; }}

        .ts        {{ white-space: nowrap; color: var(--text-muted); font-size: 0.82rem; width: 155px; }}
        .event-id  {{ white-space: nowrap; font-family: monospace; width: 100px; }}
        .rule-name {{ font-weight: 600; width: 200px; }}
        .desc      {{ color: var(--text-muted); line-height: 1.55; font-size: 0.85rem; }}

        /* ── Severity badge ── */
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            color: #fff;
            font-size: 0.7rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }}

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

        <!-- Summary cards -->
        <div class="cards">
            {cards_html}
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
