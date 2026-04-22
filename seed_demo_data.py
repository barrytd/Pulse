"""
seed_demo_data.py
-----------------
Populate ``pulse.db`` with realistic demo data so screenshots for a blog
post / LinkedIn show a lived-in dashboard instead of empty panels.

Writes to the same ``pulse.db`` the API/CLI use. Safe to re-run: if any
of the four demo hostnames already have scans, the script skips the
entire run with a message so real data is never overwritten.

Run it::

    python seed_demo_data.py                 # uses ./pulse.db
    python seed_demo_data.py --db path/to/pulse.db
    python seed_demo_data.py --force         # seed even if data exists

The four host profiles it creates:

================================== ====== =============================
Hostname                           Score  Story
================================== ====== =============================
SERVER-DC01                         35    Critical — Kerberoasting,
                                          DCSync, Golden Ticket
DESKTOP-FINANCE01                   52    High risk — Pass-the-Hash,
                                          brute force, RDP
DESKTOP-HR02                        71    Moderate — scheduled tasks,
                                          new services, after-hours
LAPTOP-DEV03                        94    Clean — occasional RDP login
================================== ====== =============================

Each host gets 6–9 scans scattered across the last 30 days with mild
score drift around its target so the Trends and History pages have a
realistic line-chart shape.
"""

from __future__ import annotations

import argparse
import os
import random
import sqlite3
import sys
from datetime import datetime, timedelta


# Deterministic by default so screenshots look the same on two runs.
# Pass --seed 0 (or any int) on the CLI to change it.
_DEFAULT_SEED = 42


# ---------------------------------------------------------------------------
# Host profiles
# ---------------------------------------------------------------------------
#
# Each profile describes the story for one machine. ``target_score`` is the
# score the NEWEST scan lands on; older scans drift +/- a few points around
# it so the history chart isn't flat. ``finding_pool`` is the menu of
# rule + severity + MITRE + description tuples the scan builder draws from;
# a scan picks 0 – len(pool) entries depending on severity.

HOST_PROFILES = [
    {
        "hostname": "SERVER-DC01",
        "target_score": 35,
        "score_label": "CRITICAL RISK",
        "story": "Domain controller under credential-attack pressure",
        "scan_count": 9,
        "finding_pool": [
            ("Kerberoasting",       "HIGH",     "T1558.003", 4769,
             "TGS request with weak RC4 encryption (etype 0x17) for service account svc_sql01.",
             "User: attacker@CORP.LOCAL | Service: MSSQLSvc/dc01.corp.local"),
            ("Golden Ticket",       "CRITICAL", "T1558.001", 4768,
             "TGT issued with anomalous 10-year lifetime — possible golden ticket forgery.",
             "User: administrator | Domain: CORP | Lifetime: 3650 days"),
            ("DCSync Attempt",      "CRITICAL", "T1003.006", 4662,
             "Directory replication GUID requested by non-DC account svc_backup.",
             "User: svc_backup@CORP.LOCAL | GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"),
            ("Credential Dumping", "CRITICAL", "T1003.001", 4656,
             "LSASS handle opened by non-system process — possible Mimikatz.",
             "Process: \\Device\\HarddiskVolume2\\tools\\mk.exe | Access: 0x1010"),
            ("Pass-the-Hash Attempt","HIGH",    "T1550.002", 4624,
             "NTLM network logon from admin workstation without Kerberos exchange.",
             "User: administrator | SourceIP: 10.0.0.45 | LogonType: 3"),
            ("Brute Force Attempt","HIGH",     "T1110",     4625,
             "12 failed logons in 4 minutes against account administrator.",
             "User: administrator | SourceIP: 203.0.113.54 | Count: 12"),
            ("Suspicious PowerShell","HIGH",   "T1059.001", 4104,
             "Base64-encoded PowerShell block with Invoke-Expression download cradle.",
             "Block length: 1842 | IEX detected: yes"),
            ("Audit Log Cleared",  "HIGH",     "T1070.001", 1102,
             "Security log cleared by administrator — attacker covering tracks.",
             "User: administrator | Client: 10.0.0.45"),
        ],
    },
    {
        "hostname": "DESKTOP-FINANCE01",
        "target_score": 52,
        "score_label": "HIGH RISK",
        "story": "Finance workstation targeted by external brute force",
        "scan_count": 8,
        "finding_pool": [
            ("Brute Force Attempt","HIGH",     "T1110",     4625,
             "8 failed RDP logons in 3 minutes from external IP.",
             "User: cfo.admin | SourceIP: 185.220.101.47 | Count: 8"),
            ("Account Lockout",    "HIGH",     "T1110",     4740,
             "Account cfo.admin locked out after repeated failed attempts.",
             "User: cfo.admin | Caller: DESKTOP-FINANCE01"),
            ("Pass-the-Hash Attempt","HIGH",   "T1550.002", 4624,
             "NTLM network logon without Kerberos — possible stolen hash.",
             "User: svc_quickbooks | SourceIP: 10.0.12.77 | LogonType: 3"),
            ("RDP Logon Detected", "MEDIUM",   "T1021.001", 4624,
             "Remote Desktop logon from unexpected internal subnet.",
             "User: contractor01 | SourceIP: 10.0.99.14 | LogonType: 10"),
            ("Privilege Escalation","HIGH",    "T1548",     4732,
             "User contractor01 added to local Administrators group.",
             "Added by: cfo.admin | Group: Administrators"),
            ("Suspicious Registry Modification","HIGH","T1547.001", 4657,
             "Run key modified to launch script at user logon.",
             "Key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"),
            ("User Account Created","MEDIUM",  "T1136.001", 4720,
             "New local account created on finance workstation.",
             "Account: helpdesk_temp | By: cfo.admin"),
        ],
    },
    {
        "hostname": "DESKTOP-HR02",
        "target_score": 71,
        "score_label": "MODERATE RISK",
        "story": "HR workstation with persistence-style indicators",
        "scan_count": 7,
        "finding_pool": [
            ("Scheduled Task Created","MEDIUM","T1053.005", 4698,
             "New scheduled task registered to run a PowerShell script at logon.",
             "Task: \\Microsoft\\Windows\\UpdateCheck | Principal: SYSTEM"),
            ("Service Installed",  "MEDIUM",   "T1543.003", 7045,
             "New service installed pointing at a user-writable path.",
             "Service: WinSysHelper | ImagePath: C:\\Users\\Public\\helper.exe"),
            ("User Account Created","MEDIUM",  "T1136.001", 4720,
             "New local account created outside the normal onboarding flow.",
             "Account: temp_hr | By: hr.admin"),
            ("Firewall Rule Changed","MEDIUM", "T1562.004", 4946,
             "Inbound firewall rule added allowing TCP 445 from any remote IP.",
             "Rule: SMB-Share-Open | Profile: Private"),
            ("After-Hours Logon",  "MEDIUM",   "T1078",     4624,
             "Interactive logon at 02:47 local — outside declared business hours.",
             "User: hr.admin | LogonType: 2"),
            ("RDP Logon Detected", "MEDIUM",   "T1021.001", 4624,
             "Inbound RDP session established from internal helpdesk subnet.",
             "User: helpdesk01 | SourceIP: 10.0.5.22"),
        ],
    },
    {
        "hostname": "LAPTOP-DEV03",
        "target_score": 94,
        "score_label": "SECURE",
        "story": "Developer laptop, mostly clean baseline",
        "scan_count": 6,
        "finding_pool": [
            ("RDP Logon Detected", "MEDIUM",   "T1021.001", 4624,
             "Expected RDP session from the dev's desktop workstation.",
             "User: r.perez | SourceIP: 10.0.10.18"),
            ("User Account Created","MEDIUM",  "T1136.001", 4720,
             "Local test account created during scripted setup.",
             "Account: testrunner | By: r.perez"),
        ],
    },
]


# Severity → weight for the find-count decision. Critical hosts pull more
# findings per scan; clean hosts pull almost none.
_FINDINGS_PER_SCAN_BY_LABEL = {
    "CRITICAL RISK":  (5, 8),   # (min, max) per scan
    "HIGH RISK":      (3, 6),
    "MODERATE RISK":  (1, 4),
    "SECURE":         (0, 1),
}


# ---------------------------------------------------------------------------
# IP block list + audit log seed data
# ---------------------------------------------------------------------------
#
# Public IPs only so the default block-list validator doesn't reject them.
# Two are 'active' (already pushed), one is 'pending' — realistic screenshot
# state for the Firewall page.

_DEMO_BLOCKS = [
    {"ip": "185.220.101.47", "comment": "Brute force against DESKTOP-FINANCE01 (cfo.admin)",
     "status": "active"},
    {"ip": "203.0.113.54",   "comment": "Repeated RDP brute force at SERVER-DC01",
     "status": "active"},
    {"ip": "198.51.100.88",  "comment": "Port scan observed in pfirewall.log",
     "status": "pending"},
]


# ---------------------------------------------------------------------------
# Worker helpers
# ---------------------------------------------------------------------------

def _hostnames_already_seeded(conn, hosts):
    row = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE hostname IN ({})".format(
            ",".join("?" * len(hosts))
        ),
        hosts,
    ).fetchone()
    return int(row[0] or 0) > 0


def _jittered_timestamps(count, now):
    """Return ``count`` datetime objects spread across the past 30 days.

    The newest is within the last 24h (so the Dashboard's "latest" card is
    populated), then earlier scans are spaced 3–5 days apart with some
    jitter so no two hosts have perfectly aligned scan times.
    """
    out = []
    # Newest scan: sometime in the last 8 hours.
    newest = now - timedelta(hours=random.randint(1, 8))
    out.append(newest)
    cursor = newest
    for _ in range(count - 1):
        cursor = cursor - timedelta(
            days=random.randint(3, 5),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        out.append(cursor)
    # Oldest first so the DB auto-increment id order matches chronological
    # order — makes "Scan #1" the earliest, "Scan #N" the latest.
    return list(reversed(out))


def _pick_findings(profile, scan_ts, is_latest):
    """Sample findings from the profile's pool. The *latest* scan gets the
    full story (so screenshots of the most-recent finding cards are rich);
    older scans get a smaller sample so the trend line isn't a flat bar."""
    lo, hi = _FINDINGS_PER_SCAN_BY_LABEL[profile["score_label"]]
    if is_latest:
        # Latest scan: show the whole pool capped at hi, so the screenshot
        # of the current findings is complete.
        sample_n = min(len(profile["finding_pool"]), hi)
    else:
        sample_n = random.randint(lo, max(lo, hi))
    sample_n = min(sample_n, len(profile["finding_pool"]))
    picks = random.sample(profile["finding_pool"], sample_n) if sample_n else []

    findings = []
    for (rule, severity, mitre, event_id, desc, details) in picks:
        # Spread finding event timestamps across the hour leading up to
        # the scan, not all stamped identically — looks more realistic in
        # the Finding detail drawer.
        event_ts = scan_ts - timedelta(minutes=random.randint(2, 55))
        findings.append({
            "timestamp":   event_ts.strftime("%Y-%m-%d %H:%M:%S"),
            "event_id":    event_id,
            "severity":    severity,
            "rule":        rule,
            "mitre":       mitre,
            "description": desc,
            "details":     details,
            "raw_xml":     None,
            "hostname":    profile["hostname"],
        })
    return findings


def _drift_score(target, is_latest):
    """Wiggle older scan scores +/- 6 pts around the target so the Trends
    line chart bounces instead of being flat. The latest scan always sits
    exactly on the target so the Dashboard score ring reads cleanly."""
    if is_latest:
        return target
    return max(5, min(99, target + random.randint(-6, 6)))


def _label_for_score(score):
    if score >= 90: return "SECURE"
    if score >= 70: return "MODERATE RISK"
    if score >= 50: return "HIGH RISK"
    return "CRITICAL RISK"


def _seed_scans(conn, profile, now):
    timestamps = _jittered_timestamps(profile["scan_count"], now)
    scan_ids = []
    for idx, ts in enumerate(timestamps):
        is_latest = (idx == len(timestamps) - 1)
        findings = _pick_findings(profile, ts, is_latest)
        score = _drift_score(profile["target_score"], is_latest)
        label = _label_for_score(score)

        total_events  = random.randint(1200, 4800)
        files_scanned = 3
        duration_sec  = random.randint(12, 48)

        cursor = conn.execute(
            """INSERT INTO scans
               (scanned_at, hostname, files_scanned, total_events,
                total_findings, score, score_label, filename, scope,
                session_id, duration_sec, user_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL)""",
            (
                ts.strftime("%Y-%m-%d %H:%M:%S"),
                profile["hostname"],
                files_scanned,
                total_events,
                len(findings),
                score,
                label,
                None,
                "Last 7 days",
                duration_sec,
            ),
        )
        scan_id = cursor.lastrowid
        scan_ids.append(scan_id)

        if findings:
            conn.executemany(
                """INSERT INTO findings
                   (scan_id, timestamp, event_id, severity, rule,
                    mitre, description, details, raw_xml, hostname)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (scan_id, f["timestamp"], str(f["event_id"]), f["severity"],
                     f["rule"], f["mitre"], f["description"], f["details"],
                     f["raw_xml"], f["hostname"])
                    for f in findings
                ],
            )
    return scan_ids


def _seed_block_list(conn, now):
    for i, b in enumerate(_DEMO_BLOCKS):
        existing = conn.execute(
            "SELECT 1 FROM ip_block_list WHERE ip_address = ?",
            (b["ip"],),
        ).fetchone()
        if existing:
            continue
        added_at = (now - timedelta(days=random.randint(1, 12))).strftime("%Y-%m-%d %H:%M:%S")
        pushed_at = added_at if b["status"] == "active" else None
        rule_name = f"Pulse-managed: {b['ip']}" if b["status"] == "active" else None
        conn.execute(
            """INSERT INTO ip_block_list
               (ip_address, comment, status, added_at, pushed_at, rule_name, finding_id)
               VALUES (?, ?, ?, ?, ?, ?, NULL)""",
            (b["ip"], b["comment"], b["status"], added_at, pushed_at, rule_name),
        )


def _seed_audit_log(conn, now):
    # Mixed pool of actions so the Audit page has variety without being
    # dominated by any single category. Times drift backward from `now`.
    entries = [
        ("scan",      None,              None,
         "dashboard", "admin@pulse.demo", "hostname=SERVER-DC01 findings=8"),
        ("scan",      None,              None,
         "dashboard", "admin@pulse.demo", "hostname=DESKTOP-FINANCE01 findings=6"),
        ("stage",     "185.220.101.47",  "Brute force against DESKTOP-FINANCE01",
         "dashboard", "admin@pulse.demo", "finding_id=1742"),
        ("push",      "185.220.101.47",  None,
         "dashboard", "admin@pulse.demo", "rule=Pulse-managed: 185.220.101.47"),
        ("stage",     "203.0.113.54",    "Repeated RDP brute force at SERVER-DC01",
         "dashboard", "admin@pulse.demo", "finding_id=1788"),
        ("push",      "203.0.113.54",    None,
         "dashboard", "admin@pulse.demo", "rule=Pulse-managed: 203.0.113.54"),
        ("stage",     "198.51.100.88",   "Port scan observed in pfirewall.log",
         "dashboard", "admin@pulse.demo", "source=firewall_log"),
        ("review",    None,              "Marked as investigated",
         "dashboard", "admin@pulse.demo", "finding_id=1742 status=reviewed"),
        ("unblock",   "10.0.0.250",      "False positive — internal scanner",
         "dashboard", "admin@pulse.demo", "rule=Pulse-managed: 10.0.0.250"),
        ("scan",      None,              None,
         "cli",       None,               "hostname=DESKTOP-HR02 findings=4"),
    ]
    # Spread across the last 14 days, oldest first.
    base = now - timedelta(days=14)
    step = timedelta(days=14) / max(1, len(entries))
    for i, (action, ip, comment, source, user, detail) in enumerate(entries):
        ts = (base + step * i + timedelta(minutes=random.randint(0, 600))).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            """INSERT INTO audit_log
               (ts, action, ip_address, comment, source, user, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (ts, action, ip, comment, source, user, detail),
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--db",
        default=os.path.join(os.getcwd(), "pulse.db"),
        help="Path to pulse.db (default: ./pulse.db)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=_DEFAULT_SEED,
        help=f"Random seed for reproducible timestamps (default: {_DEFAULT_SEED})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Seed even if any of the demo hostnames already have scans.",
    )
    args = parser.parse_args(argv)

    if not os.path.exists(args.db):
        # Import lazily — keeps seed_demo_data.py usable as a standalone
        # script even if the rest of the package has an import-time error.
        from pulse.database import init_db
        init_db(args.db)

    random.seed(args.seed)
    now = datetime.now()

    hostnames = [p["hostname"] for p in HOST_PROFILES]

    conn = sqlite3.connect(args.db)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        if not args.force and _hostnames_already_seeded(conn, hostnames):
            print("Demo hostnames already have scans in this DB — skipping.")
            print("Pass --force to seed anyway.")
            return 0

        total_scans = 0
        total_findings = 0
        for profile in HOST_PROFILES:
            scan_ids = _seed_scans(conn, profile, now)
            total_scans += len(scan_ids)
            n_findings = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE scan_id IN ({})".format(
                    ",".join("?" * len(scan_ids))
                ),
                scan_ids,
            ).fetchone()[0]
            total_findings += int(n_findings or 0)
            print(
                f"  {profile['hostname']:<20} {len(scan_ids)} scans, "
                f"{n_findings} findings, target score {profile['target_score']}"
            )

        _seed_block_list(conn, now)
        _seed_audit_log(conn, now)
        conn.commit()
    finally:
        conn.close()

    print()
    print(f"Seeded {total_scans} scans and {total_findings} findings across "
          f"{len(HOST_PROFILES)} hosts into {args.db}.")
    print("Block list: 3 entries (2 active, 1 pending). Audit log: 10 entries.")
    print("Open the dashboard and enjoy the screenshots.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
