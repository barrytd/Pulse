# test_firewall_config.py
# -----------------------
# Tests for pulse/firewall_config.py. Every test operates on a string of
# sample netsh output so the suite is safe to run on any OS — no live
# Windows host required.

from pulse import firewall_config as fc


# ---------------------------------------------------------------------------
# Sample netsh output
# ---------------------------------------------------------------------------

PROFILES_OUTPUT = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
"""


RULES_OUTPUT = """
Rule Name:                            Wide Open Inbound
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             Any
LocalPort:                            Any
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            RDP Open World
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            3389
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            SMB Lan Only
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Private
Grouping:
LocalIP:                              Any
RemoteIP:                             192.168.1.0/24
Protocol:                             TCP
LocalPort:                            445
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Disabled Any-Any
----------------------------------------------------------------------
Enabled:                              No
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             Any
LocalPort:                            Any
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Outbound Any-Any
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             Any
LocalPort:                            Any
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Pulse-managed: block 203.0.113.9
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             203.0.113.9
Protocol:                             Any
LocalPort:                            Any
RemotePort:                           Any
Edge traversal:                       No
Action:                               Block
"""


# ---------------------------------------------------------------------------
# parse_profiles
# ---------------------------------------------------------------------------

def test_parse_profiles_extracts_state_per_profile():
    profiles = fc.parse_profiles(PROFILES_OUTPUT)
    by_name = {p["profile"]: p["enabled"] for p in profiles}
    assert by_name == {"Domain": True, "Private": False, "Public": True}


def test_parse_profiles_empty_input():
    assert fc.parse_profiles("") == []


# ---------------------------------------------------------------------------
# parse_rules
# ---------------------------------------------------------------------------

def test_parse_rules_captures_all_stanzas():
    rules = fc.parse_rules(RULES_OUTPUT)
    names = [r["name"] for r in rules]
    assert names == [
        "Wide Open Inbound",
        "RDP Open World",
        "SMB Lan Only",
        "Disabled Any-Any",
        "Outbound Any-Any",
        "Pulse-managed: block 203.0.113.9",
    ]


def test_parse_rules_fields_are_normalized():
    rules = fc.parse_rules(RULES_OUTPUT)
    rdp = next(r for r in rules if r["name"] == "RDP Open World")
    assert rdp["enabled"] is True
    assert rdp["direction"] == "In"
    assert rdp["action"] == "Allow"
    assert rdp["protocol"] == "TCP"
    assert rdp["local_port"] == "3389"
    assert rdp["remote_ip"] == "Any"

    disabled = next(r for r in rules if r["name"] == "Disabled Any-Any")
    assert disabled["enabled"] is False


def test_parse_rules_empty_input():
    assert fc.parse_rules("") == []


# ---------------------------------------------------------------------------
# detect_disabled_profiles
# ---------------------------------------------------------------------------

def test_detect_disabled_profiles_flags_only_off_profiles():
    profiles = fc.parse_profiles(PROFILES_OUTPUT)
    findings = fc.detect_disabled_profiles(profiles)
    assert len(findings) == 1
    f = findings[0]
    assert f["rule"] == "Firewall Profile Disabled"
    assert f["severity"] == "HIGH"
    assert "Private" in f["details"]


def test_detect_disabled_profiles_all_enabled_returns_empty():
    findings = fc.detect_disabled_profiles([
        {"profile": "Domain",  "enabled": True},
        {"profile": "Private", "enabled": True},
        {"profile": "Public",  "enabled": True},
    ])
    assert findings == []


# ---------------------------------------------------------------------------
# detect_any_any_rules
# ---------------------------------------------------------------------------

def test_detect_any_any_rules_flags_wide_open_inbound_allow():
    rules = fc.parse_rules(RULES_OUTPUT)
    findings = fc.detect_any_any_rules(rules)
    names = [f["details"] for f in findings]
    # Only "Wide Open Inbound" should match:
    # - RDP Open World has specific LocalPort 3389 → skipped
    # - SMB Lan Only has a RemoteIP → skipped
    # - Disabled Any-Any is disabled → skipped
    # - Outbound Any-Any is outbound → skipped
    # - Pulse-managed is our own rule → skipped
    assert len(findings) == 1
    assert findings[0]["rule"] == "Firewall Any-Any Allow Rule"
    assert findings[0]["severity"] == "MEDIUM"
    assert "Wide Open Inbound" in findings[0]["details"]
    # sanity: make sure none of the skipped rules leaked through
    blob = " ".join(names)
    assert "RDP Open World" not in blob
    assert "Outbound Any-Any" not in blob
    assert "Pulse-managed" not in blob


def test_detect_any_any_rules_skips_disabled_rule():
    rules = [{
        "name": "Off Rule",
        "enabled": False,
        "direction": "In",
        "action": "Allow",
        "protocol": "Any",
        "local_port": "Any",
        "remote_ip": "Any",
    }]
    assert fc.detect_any_any_rules(rules) == []


# ---------------------------------------------------------------------------
# detect_overly_broad_scope
# ---------------------------------------------------------------------------

def test_detect_overly_broad_scope_flags_rdp_open_to_world():
    rules = fc.parse_rules(RULES_OUTPUT)
    findings = fc.detect_overly_broad_scope(rules)
    # Only "RDP Open World" qualifies: inbound allow, specific sensitive
    # port (3389), RemoteIP=Any. SMB Lan Only has a RemoteIP so it's safe;
    # Wide Open Inbound has Any protocol+port so it's covered by any-any.
    assert len(findings) == 1
    f = findings[0]
    assert f["rule"] == "Firewall Overly Broad Scope"
    assert f["severity"] == "MEDIUM"
    assert "3389" in f["details"]
    assert "RDP" in f["details"]


def test_detect_overly_broad_scope_respects_remote_ip_constraint():
    rules = [{
        "name": "RDP from bastion only",
        "enabled": True,
        "direction": "In",
        "action": "Allow",
        "protocol": "TCP",
        "local_port": "3389",
        "remote_ip": "10.0.0.5",
    }]
    assert fc.detect_overly_broad_scope(rules) == []


def test_detect_overly_broad_scope_ignores_non_sensitive_port():
    rules = [{
        "name": "Custom app",
        "enabled": True,
        "direction": "In",
        "action": "Allow",
        "protocol": "TCP",
        "local_port": "9000",
        "remote_ip": "Any",
    }]
    assert fc.detect_overly_broad_scope(rules) == []


# ---------------------------------------------------------------------------
# run_firewall_config_detections — end-to-end over sample text
# ---------------------------------------------------------------------------

def test_run_firewall_config_detections_combines_all_checks():
    findings = fc.run_firewall_config_detections(PROFILES_OUTPUT, RULES_OUTPUT)
    rules_fired = sorted({f["rule"] for f in findings})
    assert rules_fired == [
        "Firewall Any-Any Allow Rule",
        "Firewall Overly Broad Scope",
        "Firewall Profile Disabled",
    ]
    # Every finding must have the standard keys the rest of Pulse expects.
    for f in findings:
        assert set(f.keys()) >= {"rule", "severity", "event_id", "timestamp", "details"}


def test_run_firewall_config_detections_handles_none_inputs():
    assert fc.run_firewall_config_detections(None, None) == []
