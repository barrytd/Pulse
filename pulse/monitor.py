# pulse/monitor.py
# -----------------
# Live monitoring mode — polls log files on a regular interval and alerts
# on new suspicious events as they are written to the logs.
#
# TWO MODES:
#
#   FILE MODE (default):
#     Reads .evtx files from a folder. Works on exported/copied log files.
#     Good for forensic analysis of log files you've collected.
#     Limitation: can't see events Windows writes to the live file after
#     the file is opened (python-evtx reads a snapshot, not a live stream).
#
#   LIVE MODE (--watch without --logs, or --watch --live):
#     Uses Windows' built-in `wevtutil` command to query the live event log
#     directly. This sees events as Windows writes them in real time.
#     Watches Security and System channels by default.
#     No extra dependencies — wevtutil is built into every Windows machine.
#
# DEDUPLICATION:
#   Each event has a unique sequential record number. We track the highest
#   record number seen per channel/file. On each poll we only ask for events
#   with a higher record number, so we never process the same event twice.

import os
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime

from Evtx import Evtx as EvtxLib
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

# Channels queried in live mode
_LIVE_CHANNELS = ["Security", "System"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_monitor(log_folder, interval, severity_filter="LOW",
                  whitelist=None, db_path=None, live=False):
    """
    Enters live monitoring mode.  Polls for new suspicious events every
    `interval` seconds and prints ANSI-coloured alerts to the terminal.

    Parameters:
        log_folder (str):      Folder containing .evtx files (file mode).
        interval (int):        Seconds between polls.
        severity_filter (str): Minimum severity to display. Default LOW.
        whitelist (dict):      Whitelist config from pulse.yaml.
        db_path (str):         If set, findings are saved to the database.
        live (bool):           If True, use wevtutil to query live channels
                               instead of reading .evtx files from disk.
    """
    if live:
        _start_live_monitor(interval, severity_filter, whitelist, db_path)
    else:
        _start_file_monitor(log_folder, interval, severity_filter, whitelist, db_path)


def poll_new_events(log_folder, seen_keys):
    """
    Reads all .evtx files in log_folder and returns only events whose
    (filename, record_num) key is not already in seen_keys.
    Updates seen_keys in place with newly discovered keys.
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
# Live mode (wevtutil)
# ---------------------------------------------------------------------------

def _start_live_monitor(interval, severity_filter, whitelist, db_path):
    """Polls Windows live event channels using wevtutil."""
    print()
    print(f"  {'─' * 48}")
    print(f"  {_C['BOLD']}PULSE LIVE MONITOR{_C['RESET']}")
    print(f"  Watching: {', '.join(_LIVE_CHANNELS)} (live)")
    print(f"  Interval: every {interval}s   |   Ctrl+C to stop")
    print(f"  {'─' * 48}")
    print()

    # Baseline: record the current highest record ID per channel
    print(f"  {_C['DIM']}[*] Indexing existing events...{_C['RESET']}", end="", flush=True)
    last_ids = {}
    total = 0
    for channel in _LIVE_CHANNELS:
        last_id = _get_last_record_id(channel)
        last_ids[channel] = last_id
        total += last_id  # rough count proxy
    print(f"\r  {_C['DIM']}[*] Baseline set for {len(_LIVE_CHANNELS)} channel(s). "
          f"Watching for new activity...{_C['RESET']}")
    print()

    SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    poll_count = 0

    try:
        while True:
            time.sleep(interval)
            poll_count += 1
            now = datetime.now().strftime("%H:%M:%S")

            new_events = []
            for channel in _LIVE_CHANNELS:
                events, new_last_id = _query_new_events(channel, last_ids[channel])
                last_ids[channel] = new_last_id
                new_events.extend(events)

            if not new_events:
                print(f"  {_C['DIM']}[{now}] No new events ({poll_count} poll(s)){_C['RESET']}")
                continue

            findings = run_all_detections(new_events)
            findings = [
                f for f in findings
                if SEVERITY_ORDER.index(f["severity"]) >= SEVERITY_ORDER.index(severity_filter)
            ]
            if whitelist:
                findings = _apply_whitelist(findings, whitelist)

            if not findings:
                print(f"  {_C['DIM']}[{now}] {len(new_events)} new event(s) — no findings{_C['RESET']}")
                continue

            print(f"  [{now}] {_C['BOLD']}{len(new_events)} new event(s) — "
                  f"{len(findings)} finding(s):{_C['RESET']}")
            for finding in findings:
                print_finding(finding)

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


def _get_last_record_id(channel):
    """Returns the highest EventRecordID currently in a channel."""
    try:
        result = subprocess.run(
            ["wevtutil", "qe", channel, "/rd:true", "/c:1", "/f:xml", "/e:Events"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0 or not result.stdout.strip():
            return 0
        root = ET.fromstring(result.stdout)
        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        for event_el in root.findall(f"{ns}Event"):
            sys_el = event_el.find(f"{ns}System")
            if sys_el is not None:
                rec_el = sys_el.find(f"{ns}EventRecordID")
                if rec_el is not None:
                    return int(rec_el.text)
    except Exception:
        pass
    return 0


def _query_new_events(channel, last_id):
    """
    Queries a live channel for events with EventRecordID > last_id.
    Returns (list of event dicts, new highest record ID).
    """
    query = f"*[System[EventRecordID > {last_id}]]"
    try:
        result = subprocess.run(
            ["wevtutil", "qe", channel, f"/q:{query}", "/f:xml", "/e:Events"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0 or not result.stdout.strip():
            return [], last_id

        root = ET.fromstring(result.stdout)
        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        events = []
        max_id = last_id

        for event_el in root.findall(f"{ns}Event"):
            try:
                xml_string = ET.tostring(event_el, encoding="unicode")
                sys_el = event_el.find(f"{ns}System")
                if sys_el is None:
                    continue

                event_id_el = sys_el.find(f"{ns}EventID")
                if event_id_el is None:
                    continue
                event_id = int(event_id_el.text)

                time_el = sys_el.find(f"{ns}TimeCreated")
                timestamp = time_el.get("SystemTime", "Unknown") if time_el is not None else "Unknown"

                rec_el = sys_el.find(f"{ns}EventRecordID")
                record_num = int(rec_el.text) if rec_el is not None else None
                if record_num and record_num > max_id:
                    max_id = record_num

                events.append({
                    "event_id":   event_id,
                    "timestamp":  timestamp,
                    "data":       xml_string,
                    "record_num": record_num,
                })
            except Exception:
                continue

        return events, max_id

    except Exception:
        return [], last_id


# ---------------------------------------------------------------------------
# File mode (python-evtx)
# ---------------------------------------------------------------------------

def _start_file_monitor(log_folder, interval, severity_filter, whitelist, db_path):
    """Polls .evtx files in log_folder using python-evtx."""
    _print_header(log_folder, interval)

    seen_keys = set()

    print(f"  {_C['DIM']}[*] Indexing existing events...{_C['RESET']}", end="", flush=True)
    _collect_all_events(log_folder, seen_keys)
    print(f"\r  {_C['DIM']}[*] Baseline: {len(seen_keys)} events indexed across "
          f"{len(_get_log_files(log_folder))} file(s). Watching for new activity...{_C['RESET']}")
    print()

    SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    poll_count = 0

    try:
        while True:
            time.sleep(interval)
            poll_count += 1
            now = datetime.now().strftime("%H:%M:%S")

            new_events = _collect_new_events(log_folder, seen_keys)

            if not new_events:
                print(f"  {_C['DIM']}[{now}] No new events ({poll_count} poll(s)){_C['RESET']}")
                continue

            findings = run_all_detections(new_events)
            findings = [
                f for f in findings
                if SEVERITY_ORDER.index(f["severity"]) >= SEVERITY_ORDER.index(severity_filter)
            ]
            if whitelist:
                findings = _apply_whitelist(findings, whitelist)

            if not findings:
                print(f"  {_C['DIM']}[{now}] {len(new_events)} new event(s) — no findings{_C['RESET']}")
                continue

            print(f"  [{now}] {_C['BOLD']}{len(new_events)} new event(s) — "
                  f"{len(findings)} finding(s):{_C['RESET']}")
            for finding in findings:
                print_finding(finding)

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


# ---------------------------------------------------------------------------
# Internal helpers (file mode)
# ---------------------------------------------------------------------------

def _get_log_files(log_folder):
    """Returns a list of .evtx filenames in log_folder."""
    try:
        return [f for f in os.listdir(log_folder) if f.endswith(".evtx")]
    except FileNotFoundError:
        return []


def _collect_all_events(log_folder, seen_keys):
    """
    Baseline pass — records the record_num of every existing event WITHOUT
    parsing XML. Fast because we skip XML parsing entirely.
    """
    count = 0
    for filename in _get_log_files(log_folder):
        path = os.path.join(log_folder, filename)
        try:
            with EvtxLib.Evtx(path) as evtx_file:
                for record in evtx_file.records():
                    try:
                        record_num = record.record_num()
                    except Exception:
                        record_num = None
                    seen_keys.add((filename, record_num))
                    count += 1
        except Exception:
            continue
    return count


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
    from pulse.known_good import KNOWN_GOOD_SERVICES
    skip_rules    = [r.lower() for r in whitelist.get("rules",    []) or []]
    skip_accounts = [a.lower() for a in whitelist.get("accounts", []) or []]
    skip_services = (
        KNOWN_GOOD_SERVICES
        + [s.lower() for s in whitelist.get("services", []) or []]
    )
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
