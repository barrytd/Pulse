# test_correlation_rules.py
# -------------------------
# Sprint 8 — time-based correlation rules. Each test exercises one of
# the four new detection functions:
#
#   detect_brute_force_success       — 5+ 4625 then 4624 from same IP within 10 min
#   detect_impossible_travel         — same user, two hosts/IPs, within 60 s
#   detect_privilege_escalation_chain — 4720 then 4728/4732 within 5 min, same actor
#   detect_lateral_spray             — 1 source IP -> 3+ hosts, LogonType 3, within 5 min
#
# Pattern: build synthetic events in-memory (the existing test approach;
# no real .evtx files needed), feed them to the detection function,
# assert on the resulting findings list. Boundary cases (just-below
# threshold, just-outside window, missing fields) get their own test
# each to lock the contract.

from datetime import datetime, timedelta, timezone

import pytest

from pulse.core.detections import (
    detect_brute_force_success,
    detect_impossible_travel,
    detect_privilege_escalation_chain,
    detect_lateral_spray,
)


# ---------------------------------------------------------------------------
# Event builders
# ---------------------------------------------------------------------------
# Each helper returns an event dict shaped like parse_evtx output:
#   {"event_id", "timestamp", "data", "record_num", "computer"}
# The XML payload only contains the EventData fields the detection
# functions actually read — enough to drive the test, not a full
# Microsoft-shaped <Event> envelope.

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_BASE = datetime(2026, 5, 28, 9, 0, 0, tzinfo=timezone.utc)


def _iso(when):
    """ISO-8601 ms-precision string matching what the parser emits."""
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _wrap(event_id, when, computer, fields):
    """Build a complete event dict — XML envelope + flat data fields."""
    data_rows = "".join(
        f'<Data Name="{k}">{v}</Data>'
        for k, v in fields.items() if v is not None
    )
    xml = (
        f'<Event xmlns="{_NS}">'
        f'<System>'
        f'<EventID>{event_id}</EventID>'
        f'<TimeCreated SystemTime="{_iso(when)}" />'
        f'<Computer>{computer}</Computer>'
        f'</System>'
        f'<EventData>{data_rows}</EventData>'
        f'</Event>'
    )
    return {
        "event_id":   event_id,
        "timestamp":  _iso(when),
        "data":       xml,
        "record_num": 0,
        "computer":   computer,
    }


def failed_logon(when, *, user="bob", ip="203.0.113.10", host="DC-01",
                 logon_type="3"):
    return _wrap(4625, when, host, {
        "TargetUserName": user,
        "IpAddress":      ip,
        "LogonType":      logon_type,
        "FailureReason":  "%%2313",
    })


def successful_logon(when, *, user="bob", ip="10.0.0.50", host="DC-01",
                     logon_type="3", auth_pkg="NTLM"):
    return _wrap(4624, when, host, {
        "TargetUserName":            user,
        "IpAddress":                 ip,
        "LogonType":                 logon_type,
        "AuthenticationPackageName": auth_pkg,
    })


def user_created(when, *, actor="domadmin", new_user="newbie", host="DC-01"):
    return _wrap(4720, when, host, {
        "TargetUserName":  new_user,
        "SubjectUserName": actor,
    })


def added_to_group(when, *, actor="domadmin", member_cn="newbie",
                   group="Domain Admins", host="DC-01", local=False):
    # 4732 = local group, 4728 = global group. Pulse cares about both.
    event_id = 4732 if local else 4728
    return _wrap(event_id, when, host, {
        "TargetUserName":  group,
        "MemberName":      f"CN={member_cn},CN=Users,DC=acme,DC=local",
        "MemberSid":       "S-1-5-21-x-1024",
        "SubjectUserName": actor,
    })


# ---------------------------------------------------------------------------
# Brute-Force Success
# ---------------------------------------------------------------------------

def test_brute_force_success_fires_when_attacker_breaks_in():
    """5 failed logons from the same external IP, then a successful
    logon from the same IP within the 10-minute window → CRITICAL."""
    events = []
    # 8 failures over 90 seconds — well over the 5-in-10-min threshold.
    for i in range(8):
        events.append(failed_logon(_BASE + timedelta(seconds=i * 10),
                                   user="admin", ip="203.0.113.66"))
    # Successful logon from the same IP, 30s after the last failure.
    events.append(successful_logon(_BASE + timedelta(seconds=110),
                                   user="admin", ip="203.0.113.66"))

    findings = detect_brute_force_success(events)
    assert len(findings) == 1
    f = findings[0]
    assert f["rule"] == "Brute-Force Success"
    assert f["severity"] == "CRITICAL"
    assert "203.0.113.66" in f["details"]
    assert "admin" in f["details"]


def test_brute_force_success_quiet_when_no_success():
    """8 failures but no matching successful logon → no finding from
    THIS rule. The per-event Brute Force rule still fires elsewhere."""
    events = [failed_logon(_BASE + timedelta(seconds=i * 5),
                           user="admin", ip="203.0.113.66")
              for i in range(8)]
    findings = detect_brute_force_success(events)
    assert findings == []


def test_brute_force_success_quiet_when_below_threshold():
    """4 failures (one short of 5) followed by success → no finding.
    Could be a legit user mistyping a few times."""
    events = []
    for i in range(4):
        events.append(failed_logon(_BASE + timedelta(seconds=i * 10),
                                   user="admin", ip="203.0.113.66"))
    events.append(successful_logon(_BASE + timedelta(seconds=60),
                                   user="admin", ip="203.0.113.66"))
    findings = detect_brute_force_success(events)
    assert findings == []


def test_brute_force_success_quiet_when_success_from_different_ip():
    """8 failures from attacker IP, then success from a totally
    different IP — that success is unrelated and shouldn't promote."""
    events = [failed_logon(_BASE + timedelta(seconds=i * 5),
                           user="admin", ip="203.0.113.66")
              for i in range(8)]
    events.append(successful_logon(_BASE + timedelta(seconds=120),
                                   user="admin", ip="10.0.0.42"))
    findings = detect_brute_force_success(events)
    assert findings == []


def test_brute_force_success_quiet_when_window_too_wide():
    """5 failures spread over 15 minutes (window is 10 min) → no
    cluster, no finding even with a successful logon."""
    events = [failed_logon(_BASE + timedelta(minutes=i * 4),
                           user="admin", ip="203.0.113.66")
              for i in range(5)]
    events.append(successful_logon(_BASE + timedelta(minutes=21),
                                   user="admin", ip="203.0.113.66"))
    findings = detect_brute_force_success(events)
    assert findings == []


def test_brute_force_success_only_one_finding_per_burst():
    """Twelve failures + two successes from the same IP — one finding,
    not one per failure-pair or one per success."""
    events = [failed_logon(_BASE + timedelta(seconds=i * 5),
                           user="admin", ip="203.0.113.66")
              for i in range(12)]
    events.append(successful_logon(_BASE + timedelta(seconds=70),
                                   user="admin", ip="203.0.113.66"))
    events.append(successful_logon(_BASE + timedelta(seconds=120),
                                   user="admin", ip="203.0.113.66"))
    findings = detect_brute_force_success(events)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Impossible Travel
# ---------------------------------------------------------------------------

def test_impossible_travel_fires_on_two_hosts_in_under_a_minute():
    events = [
        successful_logon(_BASE,                          user="alice", host="WS-1"),
        successful_logon(_BASE + timedelta(seconds=20), user="alice", host="WS-2"),
    ]
    findings = detect_impossible_travel(events)
    assert len(findings) == 1
    f = findings[0]
    assert f["rule"] == "Impossible Travel"
    assert f["severity"] == "HIGH"
    assert "alice" in f["details"]


def test_impossible_travel_quiet_when_same_host_and_ip():
    """Same user, same host, same source IP — clearly not travel."""
    events = [
        successful_logon(_BASE,                          user="alice", host="WS-1", ip="10.0.0.5"),
        successful_logon(_BASE + timedelta(seconds=30), user="alice", host="WS-1", ip="10.0.0.5"),
    ]
    assert detect_impossible_travel(events) == []


def test_impossible_travel_quiet_when_window_exceeded():
    """90 seconds apart > the 60-second window → no finding."""
    events = [
        successful_logon(_BASE,                          user="alice", host="WS-1"),
        successful_logon(_BASE + timedelta(seconds=90), user="alice", host="WS-2"),
    ]
    assert detect_impossible_travel(events) == []


def test_impossible_travel_ignores_machine_accounts():
    """`DC-01$`, `WS-1$` etc. legitimately auth from many places."""
    events = [
        successful_logon(_BASE,                          user="DC-01$", host="WS-1"),
        successful_logon(_BASE + timedelta(seconds=10), user="DC-01$", host="WS-2"),
    ]
    assert detect_impossible_travel(events) == []


def test_impossible_travel_one_finding_per_user():
    """Three rapid logons across three different hosts — one finding,
    not three. The investigation timeline shows the rest."""
    events = [
        successful_logon(_BASE,                          user="alice", host="WS-1"),
        successful_logon(_BASE + timedelta(seconds=10), user="alice", host="WS-2"),
        successful_logon(_BASE + timedelta(seconds=20), user="alice", host="WS-3"),
    ]
    findings = detect_impossible_travel(events)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Privilege Escalation Chain
# ---------------------------------------------------------------------------

def test_priv_esc_chain_fires_on_create_then_add_to_group():
    events = [
        user_created(_BASE,                          actor="admin1", new_user="backdoor"),
        added_to_group(_BASE + timedelta(minutes=2), actor="admin1", member_cn="backdoor"),
    ]
    findings = detect_privilege_escalation_chain(events)
    assert len(findings) == 1
    f = findings[0]
    assert f["rule"] == "Privilege Escalation Chain"
    assert f["severity"] == "CRITICAL"
    assert "backdoor" in f["details"]
    assert "admin1" in f["details"]


def test_priv_esc_chain_works_with_local_group_event_4732():
    """Pulse must accept 4728 (global group) AND 4732 (local group)
    as the second leg of the chain."""
    events = [
        user_created(_BASE,                          actor="admin1", new_user="backdoor"),
        added_to_group(_BASE + timedelta(minutes=1), actor="admin1", member_cn="backdoor",
                       local=True),
    ]
    findings = detect_privilege_escalation_chain(events)
    assert len(findings) == 1


def test_priv_esc_chain_quiet_when_actor_differs():
    """If a different admin promoted the new user, that's normal
    delegation — not the "single attacker setting up persistence"
    pattern we're trying to catch."""
    events = [
        user_created(_BASE,                          actor="helpdesk", new_user="newhire"),
        added_to_group(_BASE + timedelta(minutes=1), actor="security_lead", member_cn="newhire"),
    ]
    assert detect_privilege_escalation_chain(events) == []


def test_priv_esc_chain_quiet_when_window_exceeded():
    """7 minutes apart > the 5-minute window."""
    events = [
        user_created(_BASE,                          actor="admin1", new_user="backdoor"),
        added_to_group(_BASE + timedelta(minutes=7), actor="admin1", member_cn="backdoor"),
    ]
    assert detect_privilege_escalation_chain(events) == []


def test_priv_esc_chain_quiet_when_target_user_differs():
    """If user A is created but user B is added to admins, no chain."""
    events = [
        user_created(_BASE,                          actor="admin1", new_user="alice"),
        added_to_group(_BASE + timedelta(minutes=1), actor="admin1", member_cn="bob"),
    ]
    assert detect_privilege_escalation_chain(events) == []


# ---------------------------------------------------------------------------
# Lateral Spray
# ---------------------------------------------------------------------------

def test_lateral_spray_fires_on_3_hosts_in_window():
    events = [
        successful_logon(_BASE,                          user="admin", host="SRV-A", ip="10.0.0.66"),
        successful_logon(_BASE + timedelta(seconds=60),  user="admin", host="SRV-B", ip="10.0.0.66"),
        successful_logon(_BASE + timedelta(seconds=120), user="admin", host="SRV-C", ip="10.0.0.66"),
    ]
    findings = detect_lateral_spray(events)
    assert len(findings) == 1
    f = findings[0]
    assert f["rule"] == "Lateral Spray"
    assert f["severity"] == "CRITICAL"
    assert "10.0.0.66" in f["details"]
    # All three host names referenced in the details.
    for host in ("SRV-A", "SRV-B", "SRV-C"):
        assert host in f["details"]


def test_lateral_spray_quiet_on_2_hosts():
    """Two hosts is below the 3-host threshold."""
    events = [
        successful_logon(_BASE,                         user="admin", host="SRV-A", ip="10.0.0.66"),
        successful_logon(_BASE + timedelta(seconds=10), user="admin", host="SRV-B", ip="10.0.0.66"),
    ]
    assert detect_lateral_spray(events) == []


def test_lateral_spray_quiet_when_window_exceeded():
    """3 hosts but spread across 12 minutes — no spray."""
    events = [
        successful_logon(_BASE,                          user="admin", host="SRV-A", ip="10.0.0.66"),
        successful_logon(_BASE + timedelta(minutes=6),   user="admin", host="SRV-B", ip="10.0.0.66"),
        successful_logon(_BASE + timedelta(minutes=12),  user="admin", host="SRV-C", ip="10.0.0.66"),
    ]
    assert detect_lateral_spray(events) == []


def test_lateral_spray_ignores_non_network_logons():
    """LogonType=2 (interactive console) is not lateral movement."""
    events = [
        successful_logon(_BASE,                          user="admin", host="SRV-A",
                         ip="10.0.0.66", logon_type="2"),
        successful_logon(_BASE + timedelta(seconds=30),  user="admin", host="SRV-B",
                         ip="10.0.0.66", logon_type="2"),
        successful_logon(_BASE + timedelta(seconds=60),  user="admin", host="SRV-C",
                         ip="10.0.0.66", logon_type="2"),
    ]
    assert detect_lateral_spray(events) == []


def test_lateral_spray_dedupes_same_host_visits():
    """The same source IP hitting the SAME host repeatedly is not a
    spray — it's a single relationship. Need 3 *distinct* hosts."""
    events = [
        successful_logon(_BASE,                          user="admin", host="SRV-A", ip="10.0.0.66"),
        successful_logon(_BASE + timedelta(seconds=30),  user="admin", host="SRV-A", ip="10.0.0.66"),
        successful_logon(_BASE + timedelta(seconds=60),  user="admin", host="SRV-A", ip="10.0.0.66"),
    ]
    assert detect_lateral_spray(events) == []


def test_lateral_spray_keyed_by_source_not_user():
    """Attacker using multiple credentials from one box → still a spray.
    A real intrusion may rotate accounts to stay under per-user alerts."""
    events = [
        successful_logon(_BASE,                          user="alice", host="SRV-A", ip="10.0.0.66"),
        successful_logon(_BASE + timedelta(seconds=30),  user="bob",   host="SRV-B", ip="10.0.0.66"),
        successful_logon(_BASE + timedelta(seconds=60),  user="carol", host="SRV-C", ip="10.0.0.66"),
    ]
    findings = detect_lateral_spray(events)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Integration — run_all_detections smoke
# ---------------------------------------------------------------------------

def test_run_all_detections_includes_new_rules():
    """A scenario that triggers all four new rules at once. Confirms
    they're wired into run_all_detections, not just defined."""
    from pulse.core.detections import run_all_detections
    events = []
    # 1) Brute-force success: 6 failures + 1 success from attacker IP.
    for i in range(6):
        events.append(failed_logon(_BASE + timedelta(seconds=i * 5),
                                   user="admin", ip="203.0.113.99"))
    events.append(successful_logon(_BASE + timedelta(seconds=40),
                                   user="admin", ip="203.0.113.99"))
    # 2) Impossible travel: alice from WS-1, then WS-2 ten seconds later.
    events.append(successful_logon(_BASE + timedelta(minutes=10),
                                   user="alice", host="WS-1"))
    events.append(successful_logon(_BASE + timedelta(minutes=10, seconds=10),
                                   user="alice", host="WS-2"))
    # 3) Priv-esc chain: same admin creates + immediately promotes.
    events.append(user_created(_BASE + timedelta(minutes=20),
                               actor="domadmin", new_user="persist"))
    events.append(added_to_group(_BASE + timedelta(minutes=21),
                                 actor="domadmin", member_cn="persist"))
    # 4) Lateral spray: one IP -> three boxes.
    events.append(successful_logon(_BASE + timedelta(minutes=30),
                                   user="svc", host="BOX-A", ip="10.99.99.1"))
    events.append(successful_logon(_BASE + timedelta(minutes=30, seconds=30),
                                   user="svc", host="BOX-B", ip="10.99.99.1"))
    events.append(successful_logon(_BASE + timedelta(minutes=31),
                                   user="svc", host="BOX-C", ip="10.99.99.1"))

    findings = run_all_detections(events)
    rules = {f["rule"] for f in findings}
    for expected in ("Brute-Force Success", "Impossible Travel",
                     "Privilege Escalation Chain", "Lateral Spray"):
        assert expected in rules, f"{expected!r} missing from {sorted(rules)}"


def test_correlation_rules_appear_in_rule_meta():
    """Each new detection must have a RULE_META entry so the Rules
    page renders + the compliance mapping is wired."""
    from pulse.core.rules_config import RULE_META
    for rule in ("Brute-Force Success", "Impossible Travel",
                 "Privilege Escalation Chain", "Lateral Spray"):
        assert rule in RULE_META, f"{rule!r} missing from RULE_META"
        meta = RULE_META[rule]
        assert meta.get("severity") in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert meta.get("mitre"), f"{rule}: no MITRE technique"
        assert meta.get("nist_csf"), f"{rule}: no NIST CSF subcategory"
        assert meta.get("iso_27001"), f"{rule}: no ISO 27001 control"


def test_correlation_rules_have_remediation():
    """Each new rule needs analyst-facing remediation steps + MITRE
    mitigation IDs so the finding drawer's Remediation tab isn't empty."""
    from pulse.remediation import REMEDIATION, MITIGATIONS
    for rule in ("Brute-Force Success", "Impossible Travel",
                 "Privilege Escalation Chain", "Lateral Spray"):
        steps = REMEDIATION.get(rule)
        assert steps and len(steps) >= 3, (
            f"{rule}: need at least 3 remediation steps; got {steps!r}"
        )
        mitigations = MITIGATIONS.get(rule)
        assert mitigations and len(mitigations) >= 2, (
            f"{rule}: need at least 2 MITRE mitigation IDs; got {mitigations!r}"
        )
