# test_hostname.py
# ----------------
# Tests for hostname auto-detection — Sprint 4 Thread A, step 1.
#
# Covers:
#   - _extract_computer_from_xml helper (parse Computer out of raw event XML)
#   - run_all_detections stamps hostname on per-event findings via post-pass
#   - Aggregate detections (brute force, account takeover, malware persistence
#     chain) carry hostname from their contributing events
#   - database._dominant_hostname picks the majority hostname (or None)
#   - database.save_scan persists hostname per-finding AND derives the
#     scan-level hostname from the findings rather than using socket.gethostname()

import os
import tempfile

from pulse import database
from pulse.detections import (
    run_all_detections,
    _extract_computer_from_xml,
)


# ---------------------------------------------------------------------------
# Event builders with a Computer field
# ---------------------------------------------------------------------------
#
# The helpers in test_detections.py omit the Computer element (they predate
# multi-host work). These tests need it present, so we build our own minimal
# events here rather than monkey-patching the existing helpers.

def _event_xml(event_id, ts, computer, extra_data=""):
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        f"    <EventID>{event_id}</EventID>"
        f'    <TimeCreated SystemTime="{ts}" />'
        f"    <Computer>{computer}</Computer>"
        "  </System>"
        "  <EventData>"
        f"{extra_data}"
        "  </EventData>"
        "</Event>"
    )


def make_log_cleared_event_with_host(computer, ts="2024-01-15T11:00:00.000Z"):
    xml = _event_xml(1102, ts, computer, '<Data Name="SubjectUserName">alice</Data>')
    return {"event_id": 1102, "timestamp": ts, "data": xml, "computer": computer}


def make_failed_login_event_with_host(username, computer,
                                      ts="2024-01-15T08:00:00.000000Z"):
    extra = (
        f'<Data Name="TargetUserName">{username}</Data>'
        '<Data Name="LogonType">3</Data>'
    )
    xml = _event_xml(4625, ts, computer, extra)
    return {"event_id": 4625, "timestamp": ts, "data": xml, "computer": computer}


def make_successful_logon_event_with_host(username, computer,
                                          ts="2024-01-15T09:00:00.000Z"):
    extra = (
        f'<Data Name="TargetUserName">{username}</Data>'
        '<Data Name="LogonType">3</Data>'
    )
    xml = _event_xml(4624, ts, computer, extra)
    return {"event_id": 4624, "timestamp": ts, "data": xml, "computer": computer}


def make_user_created_event_with_host(new_user, computer,
                                      ts="2024-01-15T10:00:00.000Z"):
    extra = (
        f'<Data Name="TargetUserName">{new_user}</Data>'
        '<Data Name="SubjectUserName">admin</Data>'
    )
    xml = _event_xml(4720, ts, computer, extra)
    return {"event_id": 4720, "timestamp": ts, "data": xml, "computer": computer}


def make_av_disabled_event_with_host(computer, ts="2024-01-15T13:00:00.000Z"):
    xml = _event_xml(5001, ts, computer)
    return {"event_id": 5001, "timestamp": ts, "data": xml, "computer": computer}


def make_service_installed_event_with_host(service, computer,
                                           ts="2024-01-15T14:00:00.000Z"):
    extra = (
        f'<Data Name="ServiceName">{service}</Data>'
        '<Data Name="AccountName">SYSTEM</Data>'
    )
    xml = _event_xml(7045, ts, computer, extra)
    return {"event_id": 7045, "timestamp": ts, "data": xml, "computer": computer}


def rapid_failures(username, computer, count, start_sec=0):
    out = []
    for i in range(count):
        sec = (start_sec + i) % 60
        minute = (start_sec + i) // 60
        ts = f"2024-01-15T08:{minute:02d}:{sec:02d}.000000Z"
        out.append(make_failed_login_event_with_host(username, computer, ts))
    return out


# ---------------------------------------------------------------------------
# _extract_computer_from_xml
# ---------------------------------------------------------------------------

def test_extract_computer_from_xml_returns_value():
    xml = _event_xml(4624, "2024-01-15T08:00:00.000Z", "DESKTOP-A")
    assert _extract_computer_from_xml(xml) == "DESKTOP-A"


def test_extract_computer_from_xml_returns_none_on_missing():
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>1</EventID></System>"
        "</Event>"
    )
    assert _extract_computer_from_xml(xml) is None


def test_extract_computer_from_xml_returns_none_on_empty_or_bad():
    assert _extract_computer_from_xml("") is None
    assert _extract_computer_from_xml(None) is None
    assert _extract_computer_from_xml("<not-xml") is None


# ---------------------------------------------------------------------------
# Post-pass in run_all_detections stamps per-event findings
# ---------------------------------------------------------------------------

def test_run_all_detections_stamps_hostname_on_per_event_finding():
    # Log Clearing attaches raw_xml on its findings; the post-pass should
    # extract Computer and set hostname on every finding.
    events = [make_log_cleared_event_with_host("DESKTOP-B")]
    findings = run_all_detections(events)
    assert findings, "expected at least one finding for log clearing"
    for f in findings:
        assert f.get("hostname") == "DESKTOP-B"


# ---------------------------------------------------------------------------
# Aggregate detections carry hostname explicitly
# ---------------------------------------------------------------------------

def test_brute_force_finding_carries_hostname():
    events = rapid_failures("bob", "DESKTOP-C", count=6)
    findings = run_all_detections(events)
    brute = [f for f in findings if f.get("rule") == "Brute Force Attempt"]
    assert brute, "brute force should have fired"
    assert brute[0]["hostname"] == "DESKTOP-C"


def test_account_takeover_chain_finding_carries_hostname():
    events = []
    events += rapid_failures("carol", "DESKTOP-D", count=3)
    events.append(make_successful_logon_event_with_host(
        "carol", "DESKTOP-D", ts="2024-01-15T08:30:00.000Z"))
    events.append(make_user_created_event_with_host(
        "backdoor", "DESKTOP-D", ts="2024-01-15T08:35:00.000Z"))
    findings = run_all_detections(events)
    chain = [f for f in findings if f.get("rule") == "Account Takeover Chain"]
    assert chain, "chain should have fired"
    assert chain[0]["hostname"] == "DESKTOP-D"


def test_malware_persistence_chain_finding_carries_hostname():
    events = [
        make_av_disabled_event_with_host("DESKTOP-E",
                                         ts="2024-01-15T13:00:00.000Z"),
        make_service_installed_event_with_host("evil.exe", "DESKTOP-E",
                                               ts="2024-01-15T13:30:00.000Z"),
    ]
    findings = run_all_detections(events)
    chain = [f for f in findings if f.get("rule") == "Malware Persistence Chain"]
    assert chain, "malware chain should have fired"
    assert chain[0]["hostname"] == "DESKTOP-E"


# ---------------------------------------------------------------------------
# database._dominant_hostname
# ---------------------------------------------------------------------------

def test_dominant_hostname_picks_majority():
    findings = [
        {"hostname": "HOST-A"},
        {"hostname": "HOST-A"},
        {"hostname": "HOST-B"},
    ]
    assert database._dominant_hostname(findings) == "HOST-A"


def test_dominant_hostname_none_when_all_missing():
    findings = [{"hostname": None}, {"hostname": ""}, {}]
    assert database._dominant_hostname(findings) is None


def test_dominant_hostname_none_for_empty_list():
    assert database._dominant_hostname([]) is None


# ---------------------------------------------------------------------------
# save_scan persists per-finding hostname and derives scan-level hostname
# ---------------------------------------------------------------------------

def test_save_scan_persists_finding_hostname_and_derives_scan_hostname():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        database.init_db(path)
        findings = [
            {"rule": "Audit Log Cleared", "severity": "CRITICAL",
             "hostname": "HOST-A", "event_id": "1102"},
            {"rule": "User Account Created", "severity": "MEDIUM",
             "hostname": "HOST-A", "event_id": "4720"},
            {"rule": "RDP Logon Detected", "severity": "HIGH",
             "hostname": "HOST-B", "event_id": "4624"},
        ]
        scan_id = database.save_scan(path, findings, filename="test.evtx")

        # Scan-level hostname == majority finding hostname.
        history = database.get_history(path)
        assert history[0]["hostname"] == "HOST-A"

        # Per-finding hostname is stored and returned.
        rows = database.get_scan_findings(path, scan_id)
        hosts = sorted([r["hostname"] for r in rows])
        assert hosts == ["HOST-A", "HOST-A", "HOST-B"]
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def test_save_scan_falls_back_to_local_hostname_when_no_finding_hostname():
    # Findings without hostnames (old path / unknown source) should still
    # produce a scan row — falling back to the local machine hostname rather
    # than inserting NULL, which preserves historical behaviour.
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        database.init_db(path)
        findings = [{"rule": "RDP Logon Detected", "severity": "HIGH"}]
        database.save_scan(path, findings, filename="test.evtx")
        history = database.get_history(path)
        assert history[0]["hostname"]  # non-empty — whatever socket returns
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# database.get_fleet_summary — per-host rollup for the Fleet overview page
# ---------------------------------------------------------------------------

def _fresh_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database.init_db(path)
    return path


def test_fleet_summary_empty_when_no_scans():
    path = _fresh_db()
    try:
        assert database.get_fleet_summary(path) == []
    finally:
        try: os.remove(path)
        except OSError: pass


def test_fleet_summary_rolls_up_per_host():
    path = _fresh_db()
    try:
        database.save_scan(path, [
            {"rule": "RDP Logon Detected", "severity": "HIGH",  "hostname": "HOST-A"},
            {"rule": "User Account Created","severity": "MEDIUM","hostname": "HOST-A"},
        ], filename="a1.evtx", score=70, score_label="FAIR")
        database.save_scan(path, [
            {"rule": "Audit Log Cleared", "severity": "CRITICAL", "hostname": "HOST-A"},
        ], filename="a2.evtx", score=40, score_label="HIGH RISK")
        database.save_scan(path, [
            {"rule": "RDP Logon Detected", "severity": "HIGH", "hostname": "HOST-B"},
        ], filename="b1.evtx", score=60, score_label="FAIR")

        summary = database.get_fleet_summary(path)
        by_host = {row["hostname"]: row for row in summary}

        assert set(by_host) == {"HOST-A", "HOST-B"}
        assert by_host["HOST-A"]["scan_count"] == 2
        assert by_host["HOST-A"]["total_findings"] == 3
        assert by_host["HOST-A"]["worst_severity"] == "CRITICAL"
        assert by_host["HOST-B"]["scan_count"] == 1
        assert by_host["HOST-B"]["worst_severity"] == "HIGH"
        # Latest score + grade come from the most recent scan for that host.
        assert by_host["HOST-A"]["latest_score"] == 40
        assert by_host["HOST-A"]["latest_grade"] == "HIGH RISK"
    finally:
        try: os.remove(path)
        except OSError: pass


def test_fleet_summary_excludes_scans_without_hostname():
    # Older scans may have been saved before hostname tracking; save_scan
    # falls back to the local machine, so we simulate a null-hostname row
    # with a direct DB write.
    import sqlite3
    path = _fresh_db()
    try:
        database.save_scan(path, [
            {"rule": "RDP Logon Detected", "severity": "HIGH", "hostname": "HOST-A"},
        ], filename="a.evtx")
        with sqlite3.connect(path) as conn:
            conn.execute(
                "INSERT INTO scans (filename, scanned_at, total_findings, hostname) "
                "VALUES (?, datetime('now'), 0, NULL)",
                ("legacy.evtx",),
            )
            conn.commit()

        summary = database.get_fleet_summary(path)
        assert [row["hostname"] for row in summary] == ["HOST-A"]
    finally:
        try: os.remove(path)
        except OSError: pass


def test_fleet_summary_sorted_newest_first():
    # scanned_at has second resolution, so tests that rely on ordering
    # need to stamp explicit timestamps rather than relying on wall clock.
    import sqlite3
    path = _fresh_db()
    try:
        database.save_scan(path,
            [{"rule": "RDP Logon Detected", "severity": "HIGH", "hostname": "HOST-OLD"}],
            filename="old.evtx")
        database.save_scan(path,
            [{"rule": "RDP Logon Detected", "severity": "HIGH", "hostname": "HOST-NEW"}],
            filename="new.evtx")
        with sqlite3.connect(path) as conn:
            conn.execute("UPDATE scans SET scanned_at = '2024-01-01 10:00:00' WHERE hostname = 'HOST-OLD'")
            conn.execute("UPDATE scans SET scanned_at = '2024-06-01 10:00:00' WHERE hostname = 'HOST-NEW'")
            conn.commit()
        summary = database.get_fleet_summary(path)
        assert [row["hostname"] for row in summary] == ["HOST-NEW", "HOST-OLD"]
    finally:
        try: os.remove(path)
        except OSError: pass
