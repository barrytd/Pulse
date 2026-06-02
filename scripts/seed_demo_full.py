"""
seed_demo_full.py
-----------------
One-shot QA-seed: populate every feature surface in Pulse so you can
walk through every tab and find bugs.

What it does:
1. Runs seed_test_users (admin + viewers across realistic names)
2. Runs seed_demo_data (4 hosts, ~30 scans, ~120 findings)
3. Runs seed_fleet_demo (5 more hosts for the Fleet page)
4. Populates the long tail that the other seeds don't touch:
   - Assigns a chunk of findings to viewers (Kwame especially)
   - Sets workflow states (acknowledged / investigating / resolved)
   - Marks some findings reviewed and some false-positive
   - Writes analyst notes onto a few findings
   - Imports 2 SIGMA rules
   - Stages + activates IP blocks
   - Writes audit-log entries (block / unblock / scan delete)
   - Drops threat-intel cache rows (high-score IPs)
   - Posts notifications to every user
   - Adds feedback submissions
   - Mints an API token for the admin
   - Marks the admin's onboarding dismissed so the welcome card is gone

Run:
    python scripts/seed_demo_full.py                # default ./pulse.db
    python scripts/seed_demo_full.py --db pulse.db
    python scripts/seed_demo_full.py --reset        # wipe + reseed

Safe to re-run; --reset deletes the demo rows first.
"""

from __future__ import annotations

import argparse
import json
import random
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pulse import database
from pulse.auth import hash_password
from pulse.core.sigma import parse_sigma
from pulse.firewall import blocker


# Seed for deterministic runs.
_DEFAULT_SEED = 73


# ----------------------------------------------------------------------
# Sample SIGMA rules — small enough to be readable, valid YAML.
# ----------------------------------------------------------------------

_SIGMA_RULES = [
    {
        "name": "SIGMA: Encoded PowerShell",
        "yaml": """
title: Suspicious Encoded PowerShell
description: Detects encoded PowerShell commands often used by malware
tags:
  - attack.execution
  - attack.t1059.001
detection:
  selection:
    EventID: 4688
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
  condition: selection
level: high
""",
    },
    {
        "name": "SIGMA: Mimikatz Command Line",
        "yaml": """
title: Mimikatz Command Line
description: Looks for mimikatz invocations on the command line
tags:
  - attack.credential_access
  - attack.t1003
detection:
  selection:
    CommandLine|contains:
      - mimikatz
      - sekurlsa::
      - lsadump::
  condition: selection
level: critical
""",
    },
]


_INTEL_CACHE = [
    # (ip, score, country, isp, total_reports)
    ("185.220.101.34", 98, "DE", "Tor Exit Node",       8421),
    ("45.95.169.111",  92, "RU", "BlueHosting",         5012),
    ("103.224.182.219", 87, "VN", "VNPT Corp",          3104),
    ("80.94.95.115",   72, "TR", "Turk Telekom",        1182),
    ("198.51.100.42",  18, "US", "Example ISP",         12),    # low — false-positive territory
    ("203.0.113.7",     5, "AU", "Sample Telco",        0),     # clean
]


_BLOCK_IPS = [
    ("185.220.101.34", "Tor exit — repeated brute force",       "active"),
    ("45.95.169.111",  "Pass-the-hash source from SERVER-DC01", "active"),
    ("103.224.182.219", "Kerberoasting attempts",                "pending"),
]


_NOTIFICATIONS = [
    ("scan_complete",   "Scan #42 finished: 12 findings on DESKTOP-FINANCE01"),
    ("finding_assigned", "You were assigned 'Kerberoasting' on SERVER-DC01"),
    ("monitor_alert",   "Live monitor detected encoded PowerShell on DEV-LAPTOP-07"),
    ("scheduled_scan",  "Weekly scan completed across 4 hosts"),
    ("firewall_block",  "Pulse blocked 185.220.101.34 at the firewall"),
]


_FEEDBACK = [
    ("idea",    "Could the findings page support keyboard shortcuts for severity filters?"),
    ("bug",     "Hostname column wraps awkwardly on narrow viewports — first noticed on the Reports page."),
    ("general", "Loving the new Security Advisor — the plain-language explanations are exactly what I needed."),
]


_NOTE_BODIES = [
    "Confirmed with the host owner — this was a test, marking false positive.",
    "Reset the password and rotated the service account. Watching for repeat hits.",
    "Pulled the raw event log for forensics. Filing ticket INC-2042 in our tracker.",
    "Source IP is a known Tor exit node. Blocked at the firewall.",
    "Coordinating with HR — this user left the company last Friday.",
]


# ----------------------------------------------------------------------
# Reset helpers — only the demo rows get wiped, real data is untouched.
# ----------------------------------------------------------------------

_DEMO_USER_EMAIL_PATTERN = "%@pulse.example"

def _reset(db_path: str) -> None:
    """Wipe demo-only rows so a re-seed lands clean. Real users / scans
    that don't match the demo patterns are preserved."""
    with sqlite3.connect(db_path) as conn:
        # Notifications, audit log, intel cache, blocks, feedback —
        # demo-only by their content.
        conn.execute("DELETE FROM notifications")
        conn.execute("DELETE FROM audit_log")
        conn.execute("DELETE FROM intel_cache")
        conn.execute("DELETE FROM ip_block_list")
        conn.execute("DELETE FROM feedback")
        conn.execute("DELETE FROM finding_notes")
        conn.execute("DELETE FROM sigma_rules")
        # Demo users only.
        conn.execute(f"DELETE FROM users WHERE email LIKE ?",
                     (_DEMO_USER_EMAIL_PATTERN,))
        conn.commit()


# ----------------------------------------------------------------------
# Section seeders. Each function is idempotent enough that calling
# seed_demo_full twice in a row produces a stable end state.
# ----------------------------------------------------------------------

def _run_user_seed(db_path: str, args) -> None:
    """Run seed_test_users in-process so we share argparse cleanly."""
    print("[users] seeding test users…")
    from scripts import seed_test_users as st
    # Drive the script's main entry directly with the equivalent CLI args.
    orig_argv = sys.argv
    sys.argv = ["seed_test_users.py", "--db", db_path]
    if args.reset:
        sys.argv.append("--reset")
    try:
        st.main() if hasattr(st, "main") else st  # noqa
    finally:
        sys.argv = orig_argv


def _run_demo_data_seed(db_path: str, args) -> None:
    print("[scans] seeding demo scans + findings…")
    from scripts import seed_demo_data as sd
    orig_argv = sys.argv
    sys.argv = ["seed_demo_data.py", "--db", db_path]
    if args.reset:
        sys.argv.append("--force")
    try:
        if hasattr(sd, "main"):
            sd.main()
    finally:
        sys.argv = orig_argv


def _run_fleet_seed(db_path: str) -> None:
    """seed_fleet_demo writes against a fixed DB_PATH, so we monkey-patch
    it for the duration of the call to honor --db."""
    print("[fleet] seeding multi-host fleet…")
    from scripts import seed_fleet_demo as sf
    original = sf.DB_PATH
    sf.DB_PATH = db_path
    try:
        if hasattr(sf, "main"):
            sf.main()
        else:
            # The original module exposes _wipe_demo / _seed.
            sf._wipe_demo()
            sf._seed()
    finally:
        sf.DB_PATH = original


def _seed_sigma_rules(db_path: str, admin_user_id: int, org_id: int | None) -> None:
    print("[sigma] importing 2 community-style SIGMA rules…")
    for entry in _SIGMA_RULES:
        try:
            parsed = parse_sigma(entry["yaml"])
            database.save_sigma_rule(
                db_path,
                organization_id=org_id,
                parsed_rule=parsed,
                yaml_source=entry["yaml"],
                created_by=admin_user_id,
            )
        except Exception as exc:
            print(f"[sigma]   skipped {entry['name']}: {exc}")


def _seed_intel_cache(db_path: str) -> None:
    print("[intel] caching threat-intel rows…")
    now = datetime.now()
    with sqlite3.connect(db_path) as conn:
        for ip, score, country, isp, reports in _INTEL_CACHE:
            payload = {
                "ip":            ip,
                "abuseConfidenceScore": score,
                "countryCode":   country,
                "isp":           isp,
                "totalReports":  reports,
            }
            conn.execute(
                "INSERT OR REPLACE INTO intel_cache "
                "(ip_address, source, score, country, isp, total_reports, "
                " last_reported, payload, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ip, "abuseipdb", score, country, isp, reports,
                 (now - timedelta(days=2)).isoformat(),
                 json.dumps(payload),
                 now.isoformat()),
            )
        conn.commit()


def _seed_blocks_and_audit(db_path: str, admin_email: str) -> None:
    print("[firewall] staging IP blocks + audit-log entries…")
    now = datetime.now()
    with sqlite3.connect(db_path) as conn:
        for ip, comment, status in _BLOCK_IPS:
            conn.execute(
                "INSERT OR IGNORE INTO ip_block_list "
                "(ip_address, comment, status, added_at, pushed_at, rule_name) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (ip, comment, status,
                 (now - timedelta(hours=6)).strftime("%Y-%m-%d %H:%M:%S"),
                 (now - timedelta(hours=5)).strftime("%Y-%m-%d %H:%M:%S")
                   if status == "active" else None,
                 f"Pulse-managed: {ip}"),
            )
        conn.commit()
    # Audit log — use the production helper so the shape matches reality.
    for ip, comment, status in _BLOCK_IPS:
        blocker.log_audit(
            db_path, action="block", ip=ip, comment=comment,
            source="dashboard", user=admin_email,
            detail=f"status={status}",
        )
    blocker.log_audit(
        db_path, action="unblock", ip="198.51.100.99",
        comment="False positive — corporate VPN egress",
        source="dashboard", user=admin_email,
    )
    blocker.log_audit(
        db_path, action="delete_scan", source="dashboard", user=admin_email,
        detail="page=history requested=2 deleted=2 ids=1,2",
    )


def _seed_notifications(db_path: str) -> None:
    print("[notifications] posting per-user notifications…")
    users = database.list_users(db_path)
    for u in users:
        for kind, msg in _NOTIFICATIONS:
            try:
                database.insert_notification(db_path, u["id"], kind, msg)
            except Exception:
                pass


def _seed_feedback(db_path: str) -> None:
    print("[feedback] writing demo feedback submissions…")
    users = database.list_users(db_path)
    for u, (kind, msg) in zip(users, _FEEDBACK):
        try:
            database.insert_feedback(db_path, u["id"], kind, msg,
                                      page_hint="/findings")
        except Exception:
            pass


def _seed_workflow_and_assignments(db_path: str) -> None:
    print("[findings] assigning + workflow-state + notes…")
    # Get viewers we want to assign to.
    users = database.list_users(db_path)
    viewers = [u for u in users if u.get("role") == "viewer" and u.get("active")]
    if not viewers:
        return

    rng = random.Random(_DEFAULT_SEED)
    # Pull every finding id with its severity.
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, severity FROM findings ORDER BY id"
        ).fetchall()
    if not rows:
        return

    # Use up to 40 findings for the workflow / assignment / notes spread.
    sample_ids = [r[0] for r in rows][:40]
    workflow_states = ["acknowledged", "investigating", "resolved"]

    note_users = [u for u in users if u.get("role") in ("admin", "viewer")]

    for idx, fid in enumerate(sample_ids):
        # Round-robin assignee
        viewer = viewers[idx % len(viewers)]
        try:
            database.set_finding_assignee(db_path, fid, viewer["id"])
        except Exception:
            pass

        # Spread workflow state
        try:
            database.set_finding_workflow(
                db_path, fid, workflow_states[idx % len(workflow_states)],
            )
        except Exception:
            pass

        # Every 4th finding marked reviewed (TP). Every 7th marked FP.
        try:
            if idx % 7 == 0:
                database.set_finding_review(db_path, fid,
                                             reviewed=False, false_positive=True,
                                             note="False positive — verified by IT.")
            elif idx % 4 == 0:
                database.set_finding_review(db_path, fid,
                                             reviewed=True, false_positive=False,
                                             note="Real event, response coordinated.")
        except Exception:
            pass

        # Every 3rd finding gets 1-2 analyst notes.
        if idx % 3 == 0 and note_users:
            for _ in range(rng.randint(1, 2)):
                author = rng.choice(note_users)
                body = rng.choice(_NOTE_BODIES)
                try:
                    database.insert_finding_note(db_path, fid, author["id"], body)
                except Exception:
                    pass


def _seed_api_token(db_path: str, admin_user_id: int) -> None:
    print("[tokens] minting an API token for the admin…")
    raw = secrets.token_urlsafe(32)
    import hashlib
    sha = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    try:
        database.create_api_token(
            db_path, admin_user_id, "demo CI token", sha, raw[-4:],
        )
    except Exception:
        pass


def _mark_onboarding_dismissed(db_path: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE users SET onboarding_dismissed_at = ? "
            "WHERE onboarding_dismissed_at IS NULL",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
        )
        conn.commit()


def _ensure_admin(db_path: str) -> tuple[int, str, int | None]:
    """Make sure the local install has an admin user. Returns
    (user_id, email, organization_id). Pulse usually has one already
    from the first sign-up; we just look it up."""
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, email, organization_id FROM users "
            "WHERE role = 'admin' AND active = 1 ORDER BY id LIMIT 1"
        ).fetchone()
    if row:
        return int(row[0]), row[1], (int(row[2]) if row[2] is not None else None)
    # No admin? Create one so the seed still works on a brand-new DB.
    pw_hash = hash_password("ChangeMe!8")
    new_id = database.create_user(
        db_path, "admin@pulse.example", pw_hash, role="admin",
    )
    return new_id, "admin@pulse.example", None


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--db", default="pulse.db",
                   help="SQLite path (default ./pulse.db)")
    p.add_argument("--reset", action="store_true",
                   help="Wipe demo rows before reseeding")
    args = p.parse_args()

    db_path = args.db
    database.init_db(db_path)

    if args.reset:
        print("[reset] wiping demo rows…")
        _reset(db_path)

    # User seed first so subsequent steps can find the admin + viewers.
    _run_user_seed(db_path, args)
    _run_demo_data_seed(db_path, args)
    _run_fleet_seed(db_path)

    admin_id, admin_email, admin_org = _ensure_admin(db_path)

    _seed_sigma_rules(db_path, admin_user_id=admin_id, org_id=admin_org)
    _seed_intel_cache(db_path)
    _seed_blocks_and_audit(db_path, admin_email)
    _seed_notifications(db_path)
    _seed_feedback(db_path)
    _seed_workflow_and_assignments(db_path)
    _seed_api_token(db_path, admin_id)
    _mark_onboarding_dismissed(db_path)

    print("\n[done] Demo data seeded. Refresh the dashboard.")
    print(f"      DB: {db_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
