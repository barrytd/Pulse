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
    run_all_detections,
    BRUTE_FORCE_THRESHOLD,
)


# ---------------------------------------------------------------------------
# HELPER FUNCTION — builds fake events so we don't repeat ourselves
# ---------------------------------------------------------------------------
# In real .evtx data, each event has an "event_id", a "timestamp", and
# "data" (the raw XML string). Our detections read the XML to extract
# details like usernames. So our fake XML needs to have the right structure.

def make_failed_login_event(username, timestamp="2024-01-15T08:00:00.000Z"):
    """
    Builds a fake Event 4625 (failed login) dictionary.

    Parameters:
        username (str):  The account name that "failed" to log in.
        timestamp (str): When it happened (defaults to a fixed time).

    Returns:
        dict: An event dictionary in the same format parse_evtx() returns.
    """
    # This XML is a simplified version of what a real 4625 event looks like.
    # We only include the parts our detection code actually reads.
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
# BRUTE FORCE TESTS
# ===========================================================================

def test_brute_force_triggers_above_threshold():
    """
    If an account has 5+ failed logins, we SHOULD get a finding.
    This is the core scenario — the whole point of the rule.
    """
    # Create exactly BRUTE_FORCE_THRESHOLD failed logins for "admin".
    # The list comprehension builds 5 identical events (one per attempt).
    events = [make_failed_login_event("admin") for _ in range(BRUTE_FORCE_THRESHOLD)]

    findings = detect_brute_force(events)

    # We expect exactly 1 finding (one account crossed the threshold).
    assert len(findings) == 1
    # The finding should be tagged as our brute force rule.
    assert findings[0]["rule"] == "Brute Force Attempt"
    # Brute force should always be HIGH severity.
    assert findings[0]["severity"] == "HIGH"
    # The details should mention the account name.
    assert "admin" in findings[0]["details"]


def test_brute_force_does_not_trigger_below_threshold():
    """
    If an account has fewer than 5 failed logins, we should NOT flag it.
    We don't want false positives — a couple typos shouldn't raise an alarm.
    """
    # Create just 2 failed logins — well below the threshold of 5.
    events = [make_failed_login_event("admin") for _ in range(2)]

    findings = detect_brute_force(events)

    # No findings expected — 2 failures is normal.
    assert len(findings) == 0


def test_brute_force_counts_per_account():
    """
    Failed logins for DIFFERENT accounts should be counted separately.
    3 failures for "admin" + 3 for "guest" should NOT trigger (neither hit 5).
    """
    events = (
        [make_failed_login_event("admin") for _ in range(3)]
        + [make_failed_login_event("guest") for _ in range(3)]
    )

    findings = detect_brute_force(events)

    # Neither account hit 5, so no findings.
    assert len(findings) == 0


def test_brute_force_multiple_accounts_over_threshold():
    """
    If TWO accounts each have 5+ failures, we should get TWO findings.
    """
    events = (
        [make_failed_login_event("admin") for _ in range(6)]
        + [make_failed_login_event("guest") for _ in range(7)]
    )

    findings = detect_brute_force(events)

    assert len(findings) == 2


def test_brute_force_ignores_other_event_ids():
    """
    Events that aren't 4625 should be completely ignored by this rule.
    """
    # A user creation event (4720) should not be counted as a failed login.
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
# RUN_ALL_DETECTIONS TEST
# ===========================================================================

def test_run_all_detections_combines_results():
    """
    run_all_detections() should pass events through ALL rules and combine
    the results. This is an integration test — it checks that the wiring
    between the individual functions and the runner actually works.
    """
    events = (
        # 6 failed logins for "admin" — should trigger brute force
        [make_failed_login_event("admin") for _ in range(6)]
        # 1 new user — should trigger user creation
        + [make_user_created_event("backdoor", "admin")]
        # 1 priv esc — should trigger privilege escalation
        + [make_privilege_escalation_event("backdoor", "Administrators", "admin")]
        # 1 log clear — should trigger log clearing
        + [make_log_cleared_event("admin")]
        # 1 RDP logon — should trigger RDP detection
        + [make_rdp_logon_event("attacker", logon_type="10")]
        # 1 service installed — should trigger service detection
        + [make_service_installed_event("EvilSvc", "LocalSystem")]
        # 1 AV disabled — should trigger AV detection
        + [make_av_disabled_event()]
        # 1 firewall disabled — should trigger firewall disabled detection
        + [make_firewall_disabled_event("Public")]
        # 1 firewall rule added — should trigger firewall rule change detection
        + [make_firewall_rule_event(4946, "Allow Port 4444")]
    )

    findings = run_all_detections(events)

    # We expect 9 findings total — one from each detection rule.
    assert len(findings) == 9

    # Check that all nine rule names appear in the findings.
    # set() removes duplicates, so we get a unique set of rule names.
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
    }
