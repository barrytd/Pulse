# pulse/parser.py
# ----------------
# This module handles reading Windows .evtx event log files.
#
# WHAT ARE .EVTX FILES?
# Windows records everything that happens on a computer in "event logs."
# These logs are stored as .evtx files (usually in C:\Windows\System32\winevt\Logs\).
# Each event has an ID number that tells you what happened:
#   - Event 4625 = Someone failed to log in
#   - Event 4720 = A new user account was created
#   - Event 4732 = Someone was added to a security group (possible privilege escalation)
#   - Event 1102 = The audit log was cleared (someone covering their tracks)
#
# FAST PATH vs FULL PATH:
#   parse_evtx() tries a fast path first using wevtutil (a Windows built-in
#   tool) with an event ID filter — and optionally a date filter via --days.
#   This fetches ONLY the ~13 event IDs that Pulse has detection rules for,
#   skipping the other 95%+ of events entirely.
#
#   For example, Security.evtx might have 67,000 events but only ~500 match
#   the event IDs Pulse cares about. With --days 30 it might be just ~50.
#
#   If wevtutil fails the full python-evtx path is used as a fallback.


import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from Evtx import Evtx


# ---------------------------------------------------------------------------
# Event IDs that Pulse has detection rules for.
# The fast path only fetches these — everything else is irrelevant.
# ---------------------------------------------------------------------------

RELEVANT_EVENT_IDS = [
    1102,   # Audit log cleared
    4104,   # Suspicious PowerShell (script block logging)
    4624,   # Successful logon (RDP, Pass-the-Hash)
    4625,   # Failed logon (brute force)
    4698,   # Scheduled task created
    4720,   # User account created
    4732,   # User added to security group
    4740,   # Account lockout
    4946,   # Firewall rule added
    4947,   # Firewall rule modified
    4950,   # Firewall setting changed
    5001,   # Antivirus / Defender disabled
    7045,   # New service installed
]

# XML namespace used by all Windows event log files
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_evtx(file_path, since=None):
    """
    Reads a .evtx file and returns a list of event dictionaries.

    Tries a fast path using wevtutil (filters to only relevant event IDs,
    and optionally only events newer than `since`). Falls back to reading
    every record with python-evtx if wevtutil fails.

    Parameters:
        file_path (str):          Path to the .evtx file to read.
        since (datetime | None):  If set, only return events after this UTC
                                  datetime. Pass None to scan all events.

    Never raises on bad input — returns [] for empty, missing, or corrupt
    files so callers (CLI, REST API) don't have to guard every call site.

    Returns:
        list: A list of dicts with keys:
              - "event_id"   (int)  e.g. 4625
              - "timestamp"  (str)  e.g. "2024-01-15T08:30:00.000Z"
              - "data"       (str)  raw XML string for the event
              - "record_num" (int)  sequential Windows record number
    """
    # Empty or unreadable files can't be parsed — return [] rather than
    # letting mmap or the XML parser blow up on zero-byte input.
    try:
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            return []
    except OSError:
        return []

    try:
        return _parse_evtx_fast(file_path, since)
    except Exception:
        try:
            return _parse_evtx_full(file_path, since)
        except Exception:
            return []


# ---------------------------------------------------------------------------
# Fast path — wevtutil with event ID + optional date filter
# ---------------------------------------------------------------------------

def _parse_evtx_fast(file_path, since=None):
    """
    Uses wevtutil to fetch ONLY events with relevant IDs from the file,
    and optionally only events newer than `since`.

    WHY THIS IS FAST:
      wevtutil applies the filter in native Windows code before sending data,
      so we only receive the events that actually matter.

    HOW IT WORKS:
      wevtutil qe "file.evtx" /lf:true /q:"*[System[(EventID=4625 or ...)
        and TimeCreated[@SystemTime >= '2026-03-01T00:00:00.000Z']]]"

        /lf:true  = read from a log FILE (not a live channel)
        /q:...    = XPath filter — only return matching events
        /f:xml    = output as XML
        /e:Events = wrap output in a root <Events> tag
    """
    abs_path = os.path.abspath(file_path)

    # Build the XPath query — event ID filter + optional date filter
    id_filter = " or ".join(f"EventID={eid}" for eid in RELEVANT_EVENT_IDS)

    if since is not None:
        # Format as ISO 8601 UTC — wevtutil expects this exact format
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        query = (
            f"*[System[({id_filter}) and "
            f"TimeCreated[@SystemTime >= '{since_str}']]]"
        )
    else:
        query = f"*[System[({id_filter})]]"

    result = subprocess.run(
        [
            "wevtutil", "qe", abs_path,
            "/lf:true",
            f"/q:{query}",
            "/f:xml",
            "/e:Events",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        raise RuntimeError(f"wevtutil error: {result.stderr.strip()}")

    output = result.stdout.strip()
    if not output:
        return []

    root = ET.fromstring(output)
    events = []

    for event_el in root.findall(f"{_NS}Event"):
        try:
            xml_string = ET.tostring(event_el, encoding="unicode")

            sys_el = event_el.find(f"{_NS}System")
            if sys_el is None:
                continue

            event_id_el = sys_el.find(f"{_NS}EventID")
            if event_id_el is None:
                continue
            event_id = int(event_id_el.text)

            time_el = sys_el.find(f"{_NS}TimeCreated")
            timestamp = (
                time_el.get("SystemTime", "Unknown")
                if time_el is not None else "Unknown"
            )

            rec_el = sys_el.find(f"{_NS}EventRecordID")
            record_num = int(rec_el.text) if rec_el is not None else None

            events.append({
                "event_id":   event_id,
                "timestamp":  timestamp,
                "data":       xml_string,
                "record_num": record_num,
            })
        except Exception:
            continue

    return events


# ---------------------------------------------------------------------------
# Full path — python-evtx (reads every record, used as fallback)
# ---------------------------------------------------------------------------

def _parse_evtx_full(file_path, since=None):
    """
    Reads every record in a .evtx file using python-evtx.

    This is the fallback when wevtutil is unavailable or fails. Slower but
    works on any system. Filters to relevant event IDs and applies the date
    filter in Python after reading.

    Parameters:
        file_path (str):          Path to the .evtx file.
        since (datetime | None):  Only return events after this UTC datetime.

    Returns:
        list: Parsed event dicts.
    """
    events = []

    with Evtx.Evtx(file_path) as evtx_file:
        for record in evtx_file.records():

            try:
                record_num = record.record_num()
            except Exception:
                record_num = None

            try:
                xml_string = record.xml()
            except Exception:
                continue

            try:
                xml_tree = ET.fromstring(xml_string)
            except ET.ParseError:
                continue

            event_id_element = xml_tree.find(f"{_NS}System/{_NS}EventID")
            if event_id_element is None:
                continue

            event_id = int(event_id_element.text)

            # Skip events Pulse has no rules for
            if event_id not in RELEVANT_EVENT_IDS:
                continue

            time_created = xml_tree.find(f"{_NS}System/{_NS}TimeCreated")
            timestamp = (
                time_created.get("SystemTime", "Unknown")
                if time_created is not None else "Unknown"
            )

            # Apply date filter if requested
            if since is not None and timestamp != "Unknown":
                try:
                    ts = datetime.fromisoformat(
                        timestamp.rstrip("Z").replace("+00:00", "")
                    ).replace(tzinfo=timezone.utc)
                    if ts < since:
                        continue
                except Exception:
                    pass

            events.append({
                "event_id":   event_id,
                "timestamp":  timestamp,
                "data":       xml_string,
                "record_num": record_num,
            })

    return events
