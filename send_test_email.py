# send_test_email.py
# ------------------
# Generates a fake report with sample findings and emails it.
# Use this to verify your email config without needing real .evtx files.
#
# Usage:
#   1. Fill in your Gmail App Password in pulse.yaml
#   2. Run: python send_test_email.py

import sys
from pulse.emailer import send_report, validate_email_config
from pulse.reporter import generate_report
from main import load_config

# --- FAKE FINDINGS ---
# These look exactly like what real detections produce.
FAKE_FINDINGS = [
    {
        "timestamp": "2026-04-08T09:14:22",
        "event_id": 4625,
        "severity": "HIGH",
        "rule": "Brute Force Login Attempt",
        "description": "10 failed logins for account: admin from IP: 192.168.1.50",
        "details": "Failure reason: Unknown user name or bad password",
        "mitre": "T1110",
    },
    {
        "timestamp": "2026-04-08T09:15:01",
        "event_id": 4624,
        "severity": "CRITICAL",
        "rule": "Pass-the-Hash Attack Detected",
        "description": "NTLM lateral movement from workstation DESKTOP-ABC to this host",
        "details": "LogonType: 3 | AuthPackage: NTLM | WorkstationName: DESKTOP-ABC",
        "mitre": "T1550.002",
    },
    {
        "timestamp": "2026-04-08T09:22:47",
        "event_id": 4698,
        "severity": "MEDIUM",
        "rule": "Scheduled Task Created",
        "description": "New scheduled task created: \\MalwareTask by user: svchost",
        "details": "TaskName: \\MalwareTask | User: svchost",
        "mitre": "T1053.005",
    },
    {
        "timestamp": "2026-04-08T09:31:15",
        "event_id": 4104,
        "severity": "HIGH",
        "rule": "Suspicious PowerShell Detected",
        "description": "PowerShell script block contained suspicious content: EncodedCommand",
        "details": "ScriptBlock: powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdA...",
        "mitre": "T1059.001",
    },
    {
        "timestamp": "2026-04-08T10:05:00",
        "event_id": 4740,
        "severity": "MEDIUM",
        "rule": "Account Lockout Detected",
        "description": "Account locked out: jsmith",
        "details": "TargetUserName: jsmith | CallerComputerName: WORKSTATION-01",
        "mitre": "T1110",
    },
]

def main():
    # Load email config from pulse.yaml
    config = load_config("pulse.yaml")
    email_config = config.get("email", {})

    # Check config before doing anything
    error = validate_email_config(email_config)
    if error:
        print(f"[!] {error}")
        print("    Open pulse.yaml and fill in your App Password.")
        sys.exit(1)

    print("[*] Generating HTML report...")
    report_path = generate_report(FAKE_FINDINGS,
                                  output_path="reports/test_email_report.html",
                                  fmt="html")
    print(f"    Saved: {report_path}")

    severity_counts = {}
    for f in FAKE_FINDINGS:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"[*] Sending to {email_config['recipient']}...")
    success = send_report(email_config, severity_counts, len(FAKE_FINDINGS),
                          findings=FAKE_FINDINGS, report_path=report_path)

    if success:
        print("[+] Email sent! Check your inbox.")
    else:
        print("[-] Send failed. Check the error above.")

if __name__ == "__main__":
    main()
