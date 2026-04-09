# pulse/monitor.py
# -----------------
# Live monitoring mode — polls log files on a regular interval and alerts
# on new suspicious events as they are written to the logs.
#
# HOW IT WORKS:
#   1. On first run, Pulse reads all existing events and records their IDs.
#      Nothing is alerted — this is the "baseline" of existing activity.
#   2. Every N seconds, Pulse re-reads the log files.
#   3. Any event with a record number not seen before is treated as NEW.
#   4. The detection rules run against new events only.
#   5. If findings are found, they are printed to the terminal immediately.
#   6. Ctrl+C stops the monitor cleanly.
#
# WHY POLL INSTEAD OF SUBSCRIBE?
#   Windows has a proper event subscription API (win32evtlog), but it requires
#   the pywin32 package and only works when reading live system logs.
#   Polling works on any .evtx file, including copies and exports, making it
#   useful for both live and forensic analysis.
#
# DEDUPLICATION:
#   Each event in an .evtx file has a unique sequential record number.
#   We track a set of (filename, record_num) pairs we've already processed.
#   On each poll we only process records not in that set.

import os
import time
from datetime import datetime

from pulse.parser import parse_evtx
from pulse.detections import run_all_detections


# ---------------------------------------------------------------------------
# ANSI colour codes for terminal output
# ---------------------------------------------------------------------------

_C = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH":     "\033[93m",   # bright yellow
    "MEDIUM":   "\033[33m",   # dark yellow
    "LOW":      "\033[92m",   # bright green
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
    "RESET":    "\033[0m",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_monitor(log_folder, interval, severity_filter="LOW",
                  whitelist=None, db_path=None):
    """
    Enters live monitoring mode.  Polls log files every `interval` seconds
    and alerts on new suspicious events.

    On first entry all existing events are indexed silently — only events
    that arrive AFTER the monitor starts will trigger alerts.

    Parameters:
        log_folder (str):      Folder containing .evtx files to watch.
        interval (int):        Seconds between polls. Default 30.
        severity_filter (str): Minimum severity to display. Default LOW.
        whitelist (dict):      Whitelist config from pulse.yaml.
        db_path (str):         If set, findings are saved to the database.

    Raises:
        KeyboardInterrupt: Caught internally — prints a clean exit message.
    """
    _print_header(log_folder, interval)

    # seen_keys tracks (filename, record_num) for every event we've processed.
    seen_keys = set()

    # --- INITIAL BASELINE SCAN ---
    # Read all existing events silently to build the seen set.
    # We don't run detections here — we only want to alert on NEW events.
    print(f"  {_C['DIM']}[*] Indexing existing events...{_C['RESET']}", end="", flush=True)
    initial_events = _collect_all_events(log_folder, seen_keys)
    print(f"\r  {_C['DIM']}[*] Baseline: {len(seen_keys)} events indexed across "
          f"{len(_get_log_files(log_folder))} file(s). Watching for new activity...{_C['RESET']}")
    print()

    # --- POLL LOOP ---
    SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    poll_count = 0

    try:
        while True:
            time.sleep(interval)
            poll_count += 1
            now = datetime.now().strftime("%H:%M:%S")

            # Get only events that arrived since the last poll
            new_events = _collect_new_events(log_folder, seen_keys)

            if not new_events:
                print(f"  {_C['DIM']}[{now}] No new events ({poll_count} poll(s)){_C['RESET']}")
                continue

            # Run detections on new events only
            findings = run_all_detections(new_events)

            # Apply severity filter
            findings = [
                f for f in findings
                if SEVERITY_ORDER.index(f["severity"]) >= SEVERITY_ORDER.index(severity_filter)
            ]

            # Apply whitelist
            if whitelist:
                findings = _apply_whitelist(findings, whitelist)

            if not findings:
                print(f"  {_C['DIM']}[{now}] {len(new_events)} new event(s) — no findings{_C['RESET']}")
                continue

            # Print each finding immediately
            print(f"  [{now}] {_C['BOLD']}{len(new_events)} new event(s) — "
                  f"{len(findings)} finding(s):{_C['RESET']}")
            for finding in findings:
                print_finding(finding)

            # Save to DB if configured
            if db_path:
                try:
                    from pulse.database import save_scan
                    save_scan(db_path, findings)
                except Exception:
                    pass

            print()

    except KeyboardInterrupt:
        print()
        print(f"  {_C['DIM']}[*] Monitor stopped. Total polls: {poll_count}{_C['RESET']}")
        print()


def poll_new_events(log_folder, seen_keys):
    """
    Reads all .evtx files in log_folder and returns only events whose
    (filename, record_num) key is not already in seen_keys.

    Updates seen_keys in place with newly discovered keys.

    Parameters:
        log_folder (str):  Folder to scan for .evtx files.
        seen_keys (set):   Set of (filename, record_num) already processed.

    Returns:
        list: New event dicts not previously seen.
    """
    return _collect_new_events(log_folder, seen_keys)


def print_finding(finding):
    """
    Prints a single finding to the terminal with colour coding.

    Example output:
        ⚠  [CRITICAL] Pass-the-Hash Attack Detected
           2026-04-09 14:23:01 | Event 4624 | T1550.002
           NTLM lateral movement from workstation DESKTOP-ABC
    """
    severity = finding.get("severity", "LOW")
    colour   = _C.get(severity, _C["RESET"])
    rule     = finding.get("rule", "Unknown")
    desc     = finding.get("description", "")
    ts       = finding.get("timestamp", "")
    ev_id    = finding.get("event_id", "-")
    mitre    = finding.get("mitre", "-")

    # Format timestamp for readability
    if ts and "T" in ts:
        ts = ts.replace("T", " ").split(".")[0]

    meta = " | ".join(filter(None, [
        ts if ts and ts != "-" else None,
        f"Event {ev_id}" if ev_id and ev_id != "-" else None,
        str(mitre) if mitre and mitre != "-" else None,
    ]))

    print(f"  {colour}{_C['BOLD']}⚠  [{severity}]{_C['RESET']} {_C['BOLD']}{rule}{_C['RESET']}")
    if meta:
        print(f"     {_C['DIM']}{meta}{_C['RESET']}")
    if desc:
        print(f"     {desc}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_log_files(log_folder):
    """Returns a list of .evtx filenames in log_folder."""
    try:
        return [f for f in os.listdir(log_folder) if f.endswith(".evtx")]
    except FileNotFoundError:
        return []


def _collect_all_events(log_folder, seen_keys):
    """
    Reads all events from all log files and adds their keys to seen_keys.
    Returns the events (used for baseline count only).
    """
    events = []
    for filename in _get_log_files(log_folder):
        path = os.path.join(log_folder, filename)
        try:
            for event in parse_evtx(path):
                key = (filename, event.get("record_num"))
                seen_keys.add(key)
                events.append(event)
        except Exception:
            continue
    return events


def _collect_new_events(log_folder, seen_keys):
    """
    Reads all log files and returns only events not yet in seen_keys.
    Adds new keys to seen_keys in place.
    """
    new_events = []
    for filename in _get_log_files(log_folder):
        path = os.path.join(log_folder, filename)
        try:
            for event in parse_evtx(path):
                key = (filename, event.get("record_num"))
                if key not in seen_keys:
                    seen_keys.add(key)
                    new_events.append(event)
        except Exception:
            continue
    return new_events


def _apply_whitelist(findings, whitelist):
    """Filters out findings that match the whitelist (same logic as main.py)."""
    skip_rules    = [r.lower() for r in whitelist.get("rules",    []) or []]
    skip_accounts = [a.lower() for a in whitelist.get("accounts", []) or []]
    skip_services = [s.lower() for s in whitelist.get("services", []) or []]
    skip_ips      = whitelist.get("ips", []) or []

    out = []
    for f in findings:
        if f["rule"].lower() in skip_rules:
            continue
        details_lower = f["details"].lower()
        if any(a in details_lower for a in skip_accounts):
            continue
        if any(s in details_lower for s in skip_services):
            continue
        if any(ip in f["details"] for ip in skip_ips):
            continue
        out.append(f)
    return out


def _print_header(log_folder, interval):
    """Prints the live monitor header banner."""
    print()
    print(f"  {'─' * 48}")
    print(f"  {_C['BOLD']}PULSE LIVE MONITOR{_C['RESET']}")
    print(f"  Watching: {log_folder}")
    print(f"  Interval: every {interval}s   |   Ctrl+C to stop")
    print(f"  {'─' * 48}")
    print()
