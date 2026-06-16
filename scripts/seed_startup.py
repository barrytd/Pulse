"""
seed_startup.py
---------------
Wipe the detection data and seed a realistic small-startup security
environment so you can test Pulse like a live deployment: a ~9-person
team, ~15 hosts (laptops + servers), and a spread of findings with
assignments and triage state already in progress.

What it does (in order):
  1. WIPES all scans, findings, notes, reports, notifications, audit log,
     IP blocks, and intel cache. Your own admin login and settings are kept.
  2. Ensures the team exists (admin / managers / analysts), all in your org,
     password "ChangeMe!8".
  3. Seeds ~15 hosts with realistic findings (a critical domain controller,
     a compromised laptop, mostly-healthy employee machines, etc.).
  4. Assigns a chunk of findings to analysts and sets workflow / review
     state so My Queue, Team, and the Dashboard all look lived-in.

Run from the repo root:
    python scripts/seed_startup.py
    python scripts/seed_startup.py --db pulse.db
    python scripts/seed_startup.py --password "ChangeMe!8"

Safe to re-run — it wipes and reseeds each time. Stop the Pulse server
first if you hit a "database is locked" error (SQLite single-writer).
"""
from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pulse.auth import hash_password  # noqa: E402
from pulse import database  # noqa: E402
from pulse.database import (  # noqa: E402
    init_db, _connect, save_scan, get_scan_findings,
    set_finding_assignee, set_finding_workflow, set_finding_review,
    create_user, get_user_by_email, mark_onboarding_dismissed,
)

# The admin whose login + org we keep and attach everything to.
ADMIN_EMAIL = "perezrobert0235249@gmail.com"
DEFAULT_PASSWORD = "ChangeMe!8"
random.seed(42)  # stable output across runs


# ---------------------------------------------------------------------------
# Team — a ~9-person startup security team. The real admin (kept) is the
# owner; everyone else is created in the same org with the password above.
# ---------------------------------------------------------------------------
TEAM = [
    ("maya.chen@pulse.example",      "Maya Chen",      "admin"),
    ("priya.iyer@pulse.example",     "Priya Iyer",     "manager"),
    ("jordan.kim@pulse.example",     "Jordan Kim",     "manager"),
    ("aiden.okafor@pulse.example",   "Aiden Okafor",   "analyst"),
    ("sofia.ramirez@pulse.example",  "Sofia Ramirez",  "analyst"),
    ("liam.odonnell@pulse.example",  "Liam O'Donnell", "analyst"),
    ("emma.schmidt@pulse.example",   "Emma Schmidt",   "analyst"),
    ("noah.williams@pulse.example",  "Noah Williams",  "analyst"),
]


def F(rule, sev, eid, mitre, desc, details):
    """Build one finding dict in the shape save_scan persists."""
    return {
        "rule": rule, "severity": sev, "event_id": eid, "mitre": mitre,
        "description": desc, "details": details,
    }


# ---------------------------------------------------------------------------
# Host profiles — (hostname, score, score_label, [findings]). A small-startup
# fleet: a couple of at-risk servers, one clearly compromised laptop, and a
# lot of mostly-healthy employee machines.
# ---------------------------------------------------------------------------
HOSTS = [
    ("DC01", 31, "HIGH RISK", [
        F("Kerberoasting", "HIGH", "4769", "T1558.003",
          "Service ticket requested with weak RC4 encryption",
          "Account 'svc_sql' requested a Kerberos service ticket (RC4-HMAC) for SPN MSSQLSvc/db01 from 10.0.0.54 — classic Kerberoasting pattern."),
        F("Golden Ticket", "CRITICAL", "4768", "T1558.001",
          "TGT requested for a non-existent account",
          "A TGT was issued for account 'administrator' with a 10-year lifetime from host LT-NOAH (10.0.0.88) — consistent with a forged Golden Ticket."),
        F("Audit Log Cleared", "HIGH", "1102", "T1070.001",
          "Security audit log cleared",
          "The Security event log was cleared by 'CORP\\\\svc_sql' at 02:14 — attackers often clear logs to hide activity."),
        F("Privilege Escalation", "HIGH", "4672", "T1548",
          "Special privileges assigned to new logon",
          "Account 'svc_sql' was granted SeDebugPrivilege and SeTcbPrivilege on a new logon session."),
    ]),
    ("DB01", 48, "POOR", [
        F("Pass-the-Hash Attempt", "HIGH", "4624", "T1550.002",
          "Network logon with NTLM from an unusual host",
          "NTLM network logon (type 3) for 'CORP\\\\dbadmin' originated from LT-NOAH (10.0.0.88), a workstation that never normally touches DB01."),
        F("Lateral Movement via Network Share", "HIGH", "5140", "T1021.002",
          "Admin share accessed from a workstation",
          "The C$ admin share on DB01 was accessed by 'CORP\\\\dbadmin' from 10.0.0.88 outside business hours."),
        F("After-Hours Logon", "MEDIUM", "4624", "T1078",
          "Interactive logon at 03:41",
          "Interactive logon for 'CORP\\\\dbadmin' at 03:41 — no scheduled maintenance window on record."),
    ]),
    ("WEB01", 57, "POOR", [
        F("Suspicious Process Creation", "HIGH", "1", "T1059",
          "w3wp.exe spawned cmd.exe then powershell.exe",
          "IIS worker w3wp.exe spawned cmd.exe -> powershell.exe -enc <base64> on WEB01 — possible web-shell command execution."),
        F("Service Installed", "MEDIUM", "7045", "T1543.003",
          "New service 'WinHelpSvc' installed",
          "Service 'WinHelpSvc' installed pointing to C:\\\\Windows\\\\Temp\\\\whsvc.exe (unsigned)."),
        F("Suspicious Network Connection", "MEDIUM", "3", "T1071",
          "Outbound connection to a rare external IP",
          "powershell.exe on WEB01 opened an outbound TCP/443 connection to 185.220.101.47 (no DNS, low-reputation range)."),
    ]),
    ("VPN01", 43, "HIGH RISK", [
        F("Brute Force Attempt", "HIGH", "4625", "T1110",
          "38 failed VPN logons for 'jkim' in 2 minutes",
          "38 failed authentications for user 'jkim' from 91.219.236.12 in 118 seconds, then a gap."),
        F("Brute-Force Success", "CRITICAL", "4624", "T1110",
          "Failed burst followed by a successful logon",
          "After the failed burst, a successful logon for 'jkim' from 91.219.236.12 (Romania) — credential likely guessed."),
        F("Impossible Travel", "HIGH", "4624", "T1078",
          "Logons from two countries 20 minutes apart",
          "'jkim' authenticated from Chicago (08:02) and Bucharest (08:23) — physically impossible travel window."),
    ]),
    ("MAIL01", 64, "FAIR", [
        F("Suspicious PowerShell", "HIGH", "4104", "T1059.001",
          "Encoded PowerShell with download cradle",
          "PowerShell on MAIL01 ran an encoded command containing IEX (New-Object Net.WebClient).DownloadString('http://...')."),
        F("Failed Login Attempt", "LOW", "4625", "T1110",
          "Occasional failed OWA logon",
          "A handful of failed Outlook Web Access logons for 'sramirez' — likely a stale phone client."),
    ]),
    ("FILE01", 69, "FAIR", [
        F("Lateral Movement via Network Share", "MEDIUM", "5145", "T1021.002",
          "Bulk access to the finance share",
          "187 files under \\\\\\\\FILE01\\\\Finance were enumerated by 'CORP\\\\dbadmin' in under a minute."),
        F("After-Hours Logon", "LOW", "4624", "T1078",
          "Backup service logon at 01:00",
          "Scheduled backup service account logged on at 01:00 — matches the nightly backup window."),
    ]),
    ("BUILD01", 72, "FAIR", [
        F("Scheduled Task Created", "MEDIUM", "4698", "T1053.005",
          "New scheduled task 'Updater'",
          "Scheduled task 'Updater' created to run C:\\\\Users\\\\Public\\\\upd.ps1 at logon, created by 'CORP\\\\ci-runner'."),
        F("Suspicious Process Creation", "MEDIUM", "1", "T1059",
          "Build agent spawned an unusual child",
          "agent.exe spawned cmd.exe /c whoami & net group 'domain admins' — recon-style commands from CI."),
    ]),
    ("LT-NOAH", 27, "HIGH RISK", [
        F("Account Takeover Chain", "CRITICAL", "", "T1078",
          "Failures, then success, then a new admin account",
          "Failed logons -> successful logon for 'nwilliams' -> creation of local admin 'svc_helper' within 6 minutes on LT-NOAH."),
        F("Credential Dumping", "CRITICAL", "4656", "T1003.001",
          "Handle to LSASS memory requested",
          "A process requested a read handle to lsass.exe memory (access mask 0x1010) on LT-NOAH — credential-dumping behavior."),
        F("Suspicious PowerShell", "HIGH", "4104", "T1059.001",
          "Obfuscated PowerShell one-liner",
          "Base64 + string-concatenation obfuscated PowerShell executed from C:\\\\Users\\\\nwilliams\\\\AppData\\\\Local\\\\Temp."),
        F("User Account Created", "MEDIUM", "4720", "T1136.001",
          "Local admin account 'svc_helper' created",
          "Local account 'svc_helper' created and added to Administrators on LT-NOAH."),
    ]),
    ("LT-LIAM", 62, "FAIR", [
        F("Antivirus Disabled", "HIGH", "5001", "T1562.001",
          "Defender real-time protection turned off",
          "Microsoft Defender real-time protection was disabled on LT-LIAM by 'CORP\\\\lodonnell'."),
        F("Suspicious Process Creation", "MEDIUM", "1", "T1059",
          "Office app spawned a shell",
          "WINWORD.EXE spawned cmd.exe on LT-LIAM — common macro-malware behavior."),
    ]),
    ("LT-AIDEN", 75, "FAIR", [
        F("Scheduled Task Created", "MEDIUM", "4698", "T1053.005",
          "New scheduled task created",
          "Scheduled task 'OneDriveSync' created on LT-AIDEN running from %APPDATA% — name looks legit, path is unusual."),
        F("Suspicious PowerShell", "LOW", "4104", "T1059.001",
          "PowerShell script block logged",
          "A short PowerShell script ran on LT-AIDEN; content looks like a dev utility, low risk."),
    ]),
    ("LT-PRIYA", 83, "GOOD", [
        F("User Account Created", "MEDIUM", "4720", "T1136.001",
          "Temp contractor account created",
          "Account 'contractor_temp' created on LT-PRIYA by 'CORP\\\\piyer' — confirm it is expected."),
        F("After-Hours Logon", "LOW", "4624", "T1078",
          "Late-evening logon",
          "Interactive logon for 'piyer' at 21:30 — manager working late, likely benign."),
    ]),
    ("LT-JORDAN", 87, "GOOD", [
        F("RDP Logon Detected", "LOW", "4624", "T1021.001",
          "RDP from a trusted internal host",
          "Remote Desktop logon for 'jkim' from 10.0.0.20 (IT jump box)."),
        F("Failed Login Attempt", "LOW", "4625", "T1110",
          "A couple of fat-finger failures",
          "2 failed logons for 'jkim' followed by success — typo, not an attack."),
    ]),
    ("LT-EMMA", 89, "GOOD", [
        F("Password Changed", "LOW", "4723", "T1078",
          "User changed their own password",
          "'eschmidt' changed her password during the scheduled rotation window."),
        F("RDP Logon Detected", "LOW", "4624", "T1021.001",
          "RDP from the IT jump box",
          "Remote Desktop logon for 'eschmidt' from 10.0.0.20."),
    ]),
    ("LT-MAYA", 91, "GOOD", [
        F("RDP Logon Detected", "LOW", "4624", "T1021.001",
          "RDP from a trusted internal host",
          "Remote Desktop logon for 'mchen' from 10.0.0.20 (IT jump box)."),
    ]),
    ("LT-SOFIA", 94, "GOOD", [
        F("Failed Login Attempt", "LOW", "4625", "T1110",
          "Single failed logon",
          "One failed logon for 'sramirez' then success — benign."),
    ]),
]


def _wipe(db_path):
    print("[wipe] clearing scans, findings, and related demo data…")
    with _connect(db_path) as conn:
        for tbl in ("findings", "scans", "finding_notes", "reports",
                    "notifications", "audit_log", "ip_block_list",
                    "intel_cache", "monitor_sessions"):
            try:
                conn.execute(f"DELETE FROM {tbl}")
            except Exception as e:  # table may not exist on older schemas
                print(f"   (skip {tbl}: {e})")


def _ensure_team(db_path, password):
    print("[team] ensuring the startup team exists (org 1)…")
    pw_hash = hash_password(password)
    ids = {}
    for email, name, role in TEAM:
        existing = get_user_by_email(db_path, email)
        if existing:
            uid = existing["id"] if isinstance(existing, dict) else existing[0]
            with _connect(db_path) as conn:
                conn.execute(
                    "UPDATE users SET display_name=?, role=?, active=1, "
                    "organization_id=1, password_hash=? WHERE id=?",
                    (name, role, pw_hash, int(uid)))
        else:
            uid = create_user(db_path, email, pw_hash, role=role, organization_id=1)
            with _connect(db_path) as conn:
                conn.execute("UPDATE users SET display_name=? WHERE id=?",
                             (name, int(uid)))
        ids[email] = int(uid)
    return ids


def _stamp_scan(db_path, scan_id, when):
    with _connect(db_path) as conn:
        try:
            conn.execute("UPDATE scans SET created_at=? WHERE id=?",
                         (when.strftime("%Y-%m-%d %H:%M:%S"), int(scan_id)))
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(description="Seed a small-startup demo environment.")
    ap.add_argument("--db", default="pulse.db")
    ap.add_argument("--password", default=DEFAULT_PASSWORD)
    args = ap.parse_args()

    db_path = args.db
    init_db(db_path)

    admin = get_user_by_email(db_path, ADMIN_EMAIL)
    if not admin:
        print(f"ERROR: admin {ADMIN_EMAIL} not found — log in once to create it first.")
        sys.exit(1)
    admin_id = admin["id"] if isinstance(admin, dict) else admin[0]

    _wipe(db_path)
    team = _ensure_team(db_path, args.password)
    managers = [team["priya.iyer@pulse.example"], team["jordan.kim@pulse.example"]]
    analysts = [team[e] for e, _, r in TEAM if r == "analyst"]

    now = datetime.now()
    all_finding_ids = []
    print(f"[hosts] seeding {len(HOSTS)} hosts…")
    for hostname, score, label, findings in HOSTS:
        # Stamp each finding with a recent timestamp and the hostname.
        when = now - timedelta(days=random.randint(0, 13), hours=random.randint(0, 23))
        for f in findings:
            f["hostname"] = hostname
            f["timestamp"] = when.strftime("%Y-%m-%d %H:%M:%S")
        scan_id = save_scan(
            db_path, findings, score=score, score_label=label,
            filename=f"{hostname.lower()}-{when.strftime('%b%d').lower()}.evtx",
            user_id=admin_id)
        _stamp_scan(db_path, scan_id, when)
        rows = get_scan_findings(db_path, scan_id) or []
        for r in rows:
            fid = r["id"] if isinstance(r, dict) else r[0]
            all_finding_ids.append(fid)

    print(f"[triage] populating assignments + workflow on {len(all_finding_ids)} findings…")
    random.shuffle(all_finding_ids)
    assigned = workflowed = reviewed = fp = 0
    for i, fid in enumerate(all_finding_ids):
        # ~55% get assigned to an analyst (round-robin), by a manager. The
        # rest stay unassigned so the "untriaged / needs attention" tiles
        # still show real numbers.
        if random.random() < 0.55 and analysts:
            set_finding_assignee(db_path, fid, analysts[i % len(analysts)],
                                 assigned_by=managers[i % len(managers)])
            assigned += 1
        # Workflow state: a realistic in-progress spread (most still 'new').
        roll = random.random()
        if roll < 0.18:
            set_finding_workflow(db_path, fid, "acknowledged"); workflowed += 1
        elif roll < 0.32:
            set_finding_workflow(db_path, fid, "investigating"); workflowed += 1
        elif roll < 0.42:
            set_finding_workflow(db_path, fid, "resolved"); workflowed += 1
        # A few reviewed / false-positive so those badges show up.
        rev = random.random()
        if rev < 0.10:
            set_finding_review(db_path, fid, True, False); reviewed += 1
        elif rev < 0.16:
            set_finding_review(db_path, fid, True, True); fp += 1

    # Clean dashboard for the admin (hide the getting-started card).
    try:
        mark_onboarding_dismissed(db_path, admin_id)
    except Exception:
        pass

    print("\n" + "=" * 60)
    print("  Startup demo environment seeded.")
    print("=" * 60)
    print(f"  Hosts:        {len(HOSTS)}")
    print(f"  Findings:     {len(all_finding_ids)}")
    print(f"  Assigned:     {assigned}   Workflow set: {workflowed}")
    print(f"  Reviewed:     {reviewed}   False positive: {fp}")
    print(f"\n  Team logins (password: {args.password}):")
    print(f"    {'(you) ' + ADMIN_EMAIL:42}  admin / owner")
    for email, name, role in TEAM:
        print(f"    {email:42}  {role}")
    print("\n  Log in at http://localhost:8000 — refresh if the server is running.")
    print("=" * 60)


if __name__ == "__main__":
    main()
