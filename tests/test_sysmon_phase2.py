# test_sysmon_phase2.py
# ---------------------
# Sysmon support Phase 2: Event 10 (LSASS access), Event 3 (network
# connection / C2), Event 22 (DNS tunneling).

import os

import pytest

from pulse.core.detections import (
    detect_sysmon_lsass_access,
    detect_sysmon_network_connection,
    detect_sysmon_dns_query,
    run_all_detections,
    _is_public_ipv4,
)
from pulse.core.parser import parse_evtx
from pulse.core.rules_config import RULE_META
from pulse.core.knowledge_base import get_knowledge


NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _sysmon_event(event_id, data_fields, *, provider=True, computer="WS-01"):
    """Build a Sysmon event dict shaped like the parser's output."""
    provider_xml = (
        '<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f}"/>'
        if provider else ""
    )
    rows = "".join(
        f'<Data Name="{k}">{v}</Data>' for k, v in data_fields.items()
    )
    data = (
        f'<Event xmlns="{NS}"><System>{provider_xml}'
        f'<EventID>{event_id}</EventID>'
        f'<TimeCreated SystemTime="2026-06-03T10:00:00.000Z"/>'
        f'<Computer>{computer}</Computer></System>'
        f'<EventData>{rows}</EventData></Event>'
    )
    return {
        "event_id": event_id,
        "timestamp": "2026-06-03T10:00:00.000Z",
        "data": data,
        "record_num": 1,
        "computer": computer,
    }


# ===========================================================================
# Event 10 — LSASS Memory Access
# ===========================================================================

def _lsass_evt(source_image, granted="0x1410", target=r"C:\Windows\System32\lsass.exe",
               provider=True):
    return _sysmon_event(10, {
        "SourceImage":   source_image,
        "TargetImage":   target,
        "GrantedAccess": granted,
    }, provider=provider)


def test_lsass_access_from_unexpected_process_fires():
    evt = _lsass_evt(r"C:\Users\jdoe\AppData\Local\Temp\svc.exe")
    findings = detect_sysmon_lsass_access([evt])
    assert len(findings) == 1
    assert findings[0]["rule"] == "LSASS Memory Access"
    assert findings[0]["severity"] == "CRITICAL"
    assert "svc.exe" in findings[0]["details"]


@pytest.mark.parametrize("legit", [
    r"C:\Windows\System32\wininit.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Program Files\Windows Defender\MsMpEng.exe",
    r"C:\Windows\System32\taskmgr.exe",
])
def test_lsass_access_from_legit_process_does_not_fire(legit):
    assert detect_sysmon_lsass_access([_lsass_evt(legit)]) == []


def test_lsass_access_non_target_ignored():
    """Process access to something OTHER than lsass.exe is ignored."""
    evt = _lsass_evt(r"C:\temp\x.exe", target=r"C:\Windows\System32\notepad.exe")
    assert detect_sysmon_lsass_access([evt]) == []


def test_lsass_access_benign_mask_does_not_fire():
    """A handle without any memory-read right (0x1000 = QUERY_LIMITED)
    is normal and should not fire."""
    evt = _lsass_evt(r"C:\temp\x.exe", granted="0x1000")
    assert detect_sysmon_lsass_access([evt]) == []


def test_lsass_access_vm_read_bit_variant_fires():
    """A mask not in the explicit set but with the VM_READ (0x10) bit set
    still fires — covers tool variants."""
    evt = _lsass_evt(r"C:\temp\x.exe", granted="0x0030")
    assert len(detect_sysmon_lsass_access([evt])) == 1


def test_lsass_access_requires_sysmon_provider():
    evt = _lsass_evt(r"C:\temp\x.exe", provider=False)
    assert detect_sysmon_lsass_access([evt]) == []


# ===========================================================================
# Event 3 — Suspicious Network Connection
# ===========================================================================

def _net_evt(image, dest_ip="185.220.101.34", dest_port="443",
             initiated="true", dest_host="", provider=True):
    return _sysmon_event(3, {
        "Image":               image,
        "Initiated":           initiated,
        "DestinationIp":       dest_ip,
        "DestinationPort":     dest_port,
        "DestinationHostname": dest_host,
    }, provider=provider)


def test_lolbin_outbound_to_public_ip_fires():
    evt = _net_evt(r"C:\Windows\System32\rundll32.exe", dest_ip="93.184.216.34")
    findings = detect_sysmon_network_connection([evt])
    assert len(findings) == 1
    assert findings[0]["rule"] == "Suspicious Network Connection"
    assert findings[0]["severity"] == "HIGH"


def test_c2_port_fires_regardless_of_process():
    evt = _net_evt(r"C:\Windows\System32\svchost.exe", dest_port="4444")
    findings = detect_sysmon_network_connection([evt])
    assert len(findings) == 1
    assert "4444" in findings[0]["details"]


@pytest.mark.parametrize("port", ["1337", "31337", "4444", "6667"])
def test_known_c2_ports(port):
    evt = _net_evt(r"C:\app\legit.exe", dest_port=port)
    assert len(detect_sysmon_network_connection([evt])) == 1


def test_lolbin_to_private_ip_does_not_fire():
    """An internal connection (RFC1918) from a LOLBin isn't flagged on the
    process+public-IP rule — internal traffic is a different surface."""
    evt = _net_evt(r"C:\Windows\System32\powershell.exe",
                   dest_ip="10.0.0.5", dest_port="443")
    assert detect_sysmon_network_connection([evt]) == []


def test_normal_process_to_public_ip_does_not_fire():
    """chrome.exe reaching the internet on 443 is normal."""
    evt = _net_evt(r"C:\Program Files\Google\Chrome\chrome.exe",
                   dest_ip="93.184.216.34", dest_port="443")
    assert detect_sysmon_network_connection([evt]) == []


def test_network_requires_sysmon_provider():
    evt = _net_evt(r"C:\Windows\System32\rundll32.exe",
                   dest_ip="93.184.216.34", provider=False)
    assert detect_sysmon_network_connection([evt]) == []


def test_is_public_ipv4_helper():
    assert _is_public_ipv4("8.8.8.8") is True
    assert _is_public_ipv4("10.0.0.1") is False
    assert _is_public_ipv4("192.168.1.1") is False
    assert _is_public_ipv4("127.0.0.1") is False
    assert _is_public_ipv4("not an ip") is False
    assert _is_public_ipv4("") is False


# ===========================================================================
# Event 22 — Suspicious DNS Query
# ===========================================================================

def _dns_evt(query_name, image=r"C:\Windows\System32\svchost.exe", provider=True):
    return _sysmon_event(22, {
        "QueryName":   query_name,
        "Image":       image,
        "QueryStatus": "0",
    }, provider=provider)


def test_long_dns_label_tunneling_fires():
    long_label = "a" * 60
    evt = _dns_evt(f"{long_label}.exfil.evil.net")
    findings = detect_sysmon_dns_query([evt])
    assert len(findings) == 1
    assert findings[0]["rule"] == "Suspicious DNS Query"
    assert findings[0]["severity"] == "HIGH"


def test_lolbin_dns_query_fires_medium():
    evt = _dns_evt("update.example.com",
                   image=r"C:\Windows\System32\mshta.exe")
    findings = detect_sysmon_dns_query([evt])
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_normal_dns_query_does_not_fire():
    evt = _dns_evt("www.microsoft.com")
    assert detect_sysmon_dns_query([evt]) == []


def test_empty_query_name_ignored():
    evt = _dns_evt("")
    assert detect_sysmon_dns_query([evt]) == []


def test_dns_requires_sysmon_provider():
    evt = _dns_evt("a" * 60 + ".evil.net", provider=False)
    assert detect_sysmon_dns_query([evt]) == []


# ===========================================================================
# RULE_META + knowledge-base registration
# ===========================================================================

@pytest.mark.parametrize("rule,event_id,severity,mitre", [
    ("LSASS Memory Access",           10, "CRITICAL", "T1003.001"),
    ("Suspicious Network Connection",  3, "HIGH",     "T1071"),
    ("Suspicious DNS Query",          22, "HIGH",     "T1071.004"),
])
def test_rules_registered(rule, event_id, severity, mitre):
    assert rule in RULE_META
    assert RULE_META[rule]["event_id"] == event_id
    assert RULE_META[rule]["severity"] == severity
    assert RULE_META[rule]["mitre"] == mitre


@pytest.mark.parametrize("rule", [
    "LSASS Memory Access",
    "Suspicious Network Connection",
    "Suspicious DNS Query",
])
def test_knowledge_entries_exist(rule):
    k = get_knowledge(rule)
    assert k["plain_language"]
    assert k["why_it_matters"]
    assert k["immediate_actions"]
    assert k["difficulty"] in ("low", "medium", "high")


# ===========================================================================
# run_all_detections wiring + provider safety
# ===========================================================================

def test_run_all_wires_phase2_and_stamps_hostname():
    evt = _lsass_evt(r"C:\temp\x.exe")
    findings = run_all_detections([evt])
    sus = [f for f in findings if f["rule"] == "LSASS Memory Access"]
    assert len(sus) == 1
    # Hostname stamped from the event's Computer field via the post-pass.
    assert sus[0]["hostname"] == "WS-01"


def test_run_all_safe_on_security_log_only():
    sec = {
        "event_id": 4625,
        "timestamp": "2026-06-03T10:00:00.000Z",
        "data": (
            f'<Event xmlns="{NS}"><System><EventID>4625</EventID>'
            f'<Computer>WS-01</Computer></System><EventData>'
            f'<Data Name="TargetUserName">bob</Data></EventData></Event>'
        ),
        "record_num": 1,
    }
    findings = run_all_detections([sec])
    phase2 = {"LSASS Memory Access", "Suspicious Network Connection",
              "Suspicious DNS Query"}
    assert not any(f["rule"] in phase2 for f in findings)


# ===========================================================================
# Sample file — full chain
# ===========================================================================

def test_sample_chain_fires_all_phase2_rules():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sample = os.path.join(repo_root, "samples", "sysmon-execution-chain.evtx")
    if not os.path.exists(sample):
        pytest.skip("sample not generated")
    events = parse_evtx(sample)
    findings = run_all_detections(events)
    rules = {f["rule"] for f in findings}
    assert "LSASS Memory Access" in rules
    assert "Suspicious Network Connection" in rules
    assert "Suspicious DNS Query" in rules
    assert "Suspicious Process Creation" in rules
