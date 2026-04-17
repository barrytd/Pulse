"""Seed pulse.db with fake multi-host data so the Fleet page shows something.

Safe to re-run: removes any prior demo rows (matched by the fake hostnames
below) before re-inserting. Real scans are untouched.

Run:  python seed_fleet_demo.py
Undo: python seed_fleet_demo.py --undo
"""

import sqlite3
import sys
from datetime import datetime, timedelta

from pulse import database

DB_PATH = "pulse.db"

DEMO_HOSTS = [
    "WORKSTATION-01",
    "DEV-LAPTOP-07",
    "HR-PC-14",
    "FINANCE-SRV-02",
    "CEO-SURFACE",
]


def _wipe_demo():
    with sqlite3.connect(DB_PATH) as conn:
        placeholders = ",".join("?" for _ in DEMO_HOSTS)
        conn.execute(f"DELETE FROM scans WHERE hostname IN ({placeholders})", DEMO_HOSTS)
        conn.commit()


def _stamp(scan_id, when):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE scans SET scanned_at = ? WHERE id = ?",
            (when.strftime("%Y-%m-%d %H:%M:%S"), scan_id),
        )
        conn.commit()


def _seed():
    database.init_db(DB_PATH)
    now = datetime.now()

    # --- WORKSTATION-01 — clean office machine, one scan, nothing scary.
    sid = database.save_scan(DB_PATH, [
        {"rule": "RDP Logon Detected", "severity": "LOW", "hostname": "WORKSTATION-01",
         "event_id": "4624", "description": "Remote logon from trusted IP"},
    ], filename="workstation-01-apr17.evtx", score=92, score_label="GOOD")
    _stamp(sid, now - timedelta(hours=3))

    # --- DEV-LAPTOP-07 — the "on fire" machine. Multiple scans, critical finding.
    sid = database.save_scan(DB_PATH, [
        {"rule": "Failed Login Attempt", "severity": "LOW", "hostname": "DEV-LAPTOP-07",
         "event_id": "4625"},
        {"rule": "Failed Login Attempt", "severity": "LOW", "hostname": "DEV-LAPTOP-07",
         "event_id": "4625"},
    ], filename="dev-laptop-apr10.evtx", score=78, score_label="FAIR")
    _stamp(sid, now - timedelta(days=7, hours=2))

    sid = database.save_scan(DB_PATH, [
        {"rule": "Brute Force Attempt", "severity": "HIGH", "hostname": "DEV-LAPTOP-07",
         "event_id": "4625", "description": "12 failed logons for user 'admin' in 58s"},
        {"rule": "Audit Log Cleared", "severity": "CRITICAL", "hostname": "DEV-LAPTOP-07",
         "event_id": "1102", "description": "Security audit log cleared by 'admin'"},
        {"rule": "User Account Created", "severity": "MEDIUM", "hostname": "DEV-LAPTOP-07",
         "event_id": "4720", "description": "New account 'svc_helper' created"},
        {"rule": "Privilege Escalation", "severity": "HIGH", "hostname": "DEV-LAPTOP-07",
         "event_id": "4672"},
    ], filename="dev-laptop-apr15.evtx", score=34, score_label="HIGH RISK")
    _stamp(sid, now - timedelta(days=2, hours=4))

    sid = database.save_scan(DB_PATH, [
        {"rule": "Account Takeover Chain", "severity": "CRITICAL", "hostname": "DEV-LAPTOP-07",
         "description": "Failures → success → account creation in 7 min for user 'admin'"},
        {"rule": "Failed Login Attempt", "severity": "LOW", "hostname": "DEV-LAPTOP-07",
         "event_id": "4625"},
    ], filename="dev-laptop-apr17.evtx", score=28, score_label="HIGH RISK")
    _stamp(sid, now - timedelta(hours=1))

    # --- HR-PC-14 — moderate findings, one scan recently.
    sid = database.save_scan(DB_PATH, [
        {"rule": "RDP Logon Detected", "severity": "LOW", "hostname": "HR-PC-14",
         "event_id": "4624"},
        {"rule": "User Account Created", "severity": "MEDIUM", "hostname": "HR-PC-14",
         "event_id": "4720", "description": "Temp contractor account 'jsmith_temp'"},
        {"rule": "Group Membership Changed", "severity": "MEDIUM", "hostname": "HR-PC-14",
         "event_id": "4732"},
    ], filename="hr-pc-14.evtx", score=74, score_label="FAIR")
    _stamp(sid, now - timedelta(days=1, hours=8))

    # --- FINANCE-SRV-02 — server, ongoing noisy scans, HIGH severity spotted.
    sid = database.save_scan(DB_PATH, [
        {"rule": "Failed Login Attempt", "severity": "LOW", "hostname": "FINANCE-SRV-02",
         "event_id": "4625"},
    ], filename="finance-srv-02-apr01.evtx", score=88, score_label="GOOD")
    _stamp(sid, now - timedelta(days=16))

    sid = database.save_scan(DB_PATH, [
        {"rule": "Service Installed", "severity": "MEDIUM", "hostname": "FINANCE-SRV-02",
         "event_id": "7045", "description": "New service 'WinUpdateSvc' installed"},
        {"rule": "Defender Disabled", "severity": "HIGH", "hostname": "FINANCE-SRV-02",
         "event_id": "5001"},
    ], filename="finance-srv-02-apr14.evtx", score=58, score_label="POOR")
    _stamp(sid, now - timedelta(days=3, hours=6))

    # --- CEO-SURFACE — recent scan, a couple findings.
    sid = database.save_scan(DB_PATH, [
        {"rule": "RDP Logon Detected", "severity": "LOW", "hostname": "CEO-SURFACE",
         "event_id": "4624"},
        {"rule": "Failed Login Attempt", "severity": "LOW", "hostname": "CEO-SURFACE",
         "event_id": "4625"},
        {"rule": "Password Changed", "severity": "LOW", "hostname": "CEO-SURFACE",
         "event_id": "4723"},
    ], filename="ceo-surface.evtx", score=85, score_label="GOOD")
    _stamp(sid, now - timedelta(hours=9))


def main():
    if "--undo" in sys.argv:
        _wipe_demo()
        print(f"Removed demo rows for hosts: {', '.join(DEMO_HOSTS)}")
        return

    _wipe_demo()   # idempotent
    _seed()
    print(f"Seeded {len(DEMO_HOSTS)} demo hosts into {DB_PATH}.")
    print("Open the Pulse Fleet page to see them.")
    print("Undo with: python seed_fleet_demo.py --undo")


if __name__ == "__main__":
    main()
