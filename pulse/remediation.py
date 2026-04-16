# pulse/remediation.py
# ---------------------
# Canonical per-rule remediation steps. One source of truth used by:
#   - pulse/reporter.py       (HTML Remediation tab)
#   - pulse/api.py            (decorates findings returned to the dashboard)
#   - pulse/static/js/*       (drawer reads finding.remediation directly)
#
# Each entry is an ordered list of short, actionable steps an analyst can
# follow immediately — short enough to read at a glance, specific enough
# to act on without googling.

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
        "Search the fleet for other hosts running the same command line — attackers often spray the lure widely.",
    ],
    "Kerberoasting": [
        "Rotate the password of every service account with an SPN to a long, random value (25+ characters).",
        "Investigate the requesting user account — Kerberoasting usually means the attacker already has a foothold.",
        "Disable RC4 Kerberos encryption domain-wide; require AES-only via Group Policy.",
        "Audit which service accounts have SPNs and remove SPNs that are no longer needed.",
        "Enable Event 4769 monitoring with RC4 encryption type filters for ongoing detection.",
    ],
    "Golden Ticket": [
        "Reset the krbtgt account password twice, 24 hours apart — this is the only way to invalidate stolen tickets.",
        "Assume full domain compromise until proven otherwise; engage incident response.",
        "Hunt for the initial credential theft event (Mimikatz, LSASS dumping) on any domain controller.",
        "Review all privileged group memberships and reset every Domain Admin / Enterprise Admin password.",
        "Forward all DC event logs to an off-host SIEM going forward so new forged tickets are detectable.",
    ],
    "Credential Dumping": [
        "Isolate the host immediately — every credential that touched it must be considered compromised.",
        "Rotate passwords for every account that has logged in to this host in the past 30 days.",
        "Enable Credential Guard on Windows 10/11 to prevent LSASS memory reads.",
        "Restrict debug privilege (SeDebugPrivilege) to a minimal set of accounts via Group Policy.",
        "Hunt for the same tooling (Mimikatz, ProcDump, comsvcs.dll MiniDump) on other hosts in the fleet.",
    ],
    "Logon from Disabled Account": [
        "Confirm the account is genuinely disabled in Active Directory — if the logon succeeded, treat as major incident.",
        "Force reset the account's password and expire any active Kerberos tickets / sessions for it.",
        "Audit authentication logs for the last 30 days to see where else the account has been used.",
        "Review how the attacker bypassed the disabled flag — likely stolen hashes or a domain controller compromise.",
    ],
    "After-Hours Logon": [
        "Contact the account owner directly to confirm whether the logon was legitimate (overtime / travel / on-call).",
        "If unexpected, disable the account, rotate its password, and block the source IP at the perimeter.",
        "Check for other activity from the same source IP around the logon timestamp.",
        "Consider enforcing time-of-day logon restrictions for sensitive accounts via Group Policy.",
    ],
    "Suspicious Registry Modification": [
        "Identify the process that wrote the registry value (Event 4657 ProcessName) and contain the host if unknown.",
        "Revert the modified key to its expected value or delete the unauthorized entry.",
        "Check common persistence locations (Run / RunOnce / Image File Execution Options) for additional modifications.",
        "Audit what executable the registry value points at and submit it to VirusTotal.",
    ],
    "Lateral Movement via Network Share": [
        "Confirm whether the accessing account legitimately needs share access to the target host.",
        "If suspicious, rotate credentials for the accessing account and disable its session.",
        "Review Event 5140 (Network Share accessed) logs for the account across the fleet.",
        "Restrict administrative shares (C$, ADMIN$) via Group Policy where possible, or require a jump host.",
    ],
}


DEFAULT_REMEDIATION = [
    "Investigate the event in its surrounding context.",
    "Correlate with other logs from the same host and timeframe.",
    "Check whether the activity was performed by an authorized user or process.",
]


# MITRE ATT&CK mitigations, keyed by ID. Names taken from
# https://attack.mitre.org/mitigations/ — kept short for UI rendering.
_MITIGATION_NAMES = {
    "M1015": "Active Directory Configuration",
    "M1018": "User Account Management",
    "M1024": "Restrict Registry Permissions",
    "M1026": "Privileged Account Management",
    "M1027": "Password Policies",
    "M1028": "Operating System Configuration",
    "M1029": "Remote Data Storage",
    "M1030": "Network Segmentation",
    "M1031": "Network Intrusion Prevention",
    "M1032": "Multi-factor Authentication",
    "M1035": "Limit Access to Resource Over Network",
    "M1036": "Account Use Policies",
    "M1037": "Filter Network Traffic",
    "M1038": "Execution Prevention",
    "M1040": "Behavior Prevention on Endpoint",
    "M1041": "Encrypt Sensitive Information",
    "M1042": "Disable or Remove Feature or Program",
    "M1043": "Credential Access Protection",
    "M1047": "Audit",
    "M1049": "Antivirus/Antimalware",
}

# Per-rule MITRE mitigation IDs. Two to three per rule, ordered by
# relevance. IDs must exist in _MITIGATION_NAMES.
MITIGATIONS = {
    "Brute Force Attempt":       ["M1027", "M1032", "M1036"],
    "User Account Created":      ["M1026", "M1018", "M1047"],
    "Privilege Escalation":      ["M1026", "M1018", "M1047"],
    "Audit Log Cleared":         ["M1029", "M1047"],
    "RDP Logon Detected":        ["M1035", "M1030", "M1032"],
    "Pass-the-Hash Attempt":     ["M1043", "M1026", "M1027"],
    "Service Installed":         ["M1047", "M1038", "M1042"],
    "Antivirus Disabled":        ["M1049", "M1024", "M1047"],
    "Firewall Disabled":         ["M1031", "M1028", "M1047"],
    "Firewall Rule Changed":     ["M1047", "M1028", "M1037"],
    "Account Lockout":           ["M1027", "M1032"],
    "Scheduled Task Created":    ["M1047", "M1038"],
    "Suspicious PowerShell":     ["M1038", "M1040", "M1042"],
    "Account Takeover Chain":    ["M1026", "M1018", "M1032"],
    "Malware Persistence Chain": ["M1049", "M1040", "M1038"],
    "Kerberoasting":             ["M1027", "M1026", "M1041"],
    "Golden Ticket":             ["M1026", "M1027", "M1043"],
    "Credential Dumping":        ["M1043", "M1028", "M1040"],
    "Logon from Disabled Account": ["M1018", "M1032", "M1026"],
    "After-Hours Logon":         ["M1036", "M1032"],
    "Suspicious Registry Modification": ["M1024", "M1047"],
    "Lateral Movement via Network Share": ["M1035", "M1037", "M1030"],
    "DCSync Attempt":            ["M1026", "M1027", "M1015"],
    "Suspicious Child Process":  ["M1040", "M1038", "M1049"],
    "New Account (Baseline)":    ["M1018", "M1026"],
    "New Service (Baseline)":    ["M1047", "M1038"],
    "New Task (Baseline)":       ["M1047", "M1038"],
}


def get_remediation(rule_name):
    """
    Return the ordered list of remediation steps for a given rule name.
    Falls back to DEFAULT_REMEDIATION for unknown rules so every finding
    the dashboard renders has something actionable.
    """
    return REMEDIATION.get(rule_name, DEFAULT_REMEDIATION)


def get_mitigations(rule_name):
    """
    Return a list of {"id": "M1026", "name": "Privileged Account Management"}
    dicts for a given rule. Empty list for unknown rules.
    """
    return [
        {"id": mid, "name": _MITIGATION_NAMES[mid]}
        for mid in MITIGATIONS.get(rule_name, [])
        if mid in _MITIGATION_NAMES
    ]


def attach_remediation(findings):
    """
    Decorate every finding dict in-place with `remediation` (list of step
    strings) and `mitigations` (list of {id, name} dicts) so the dashboard
    and any JSON-consuming tool can read both directly from the finding.
    Returns the same list so call sites can chain it.
    """
    for f in findings or []:
        rule = f.get("rule", "")
        f["remediation"] = get_remediation(rule)
        f["mitigations"] = get_mitigations(rule)
    return findings
