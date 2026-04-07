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
    )

    findings = run_all_detections(events)

    # We expect 11 findings: 9 individual rules + 2 chain detections.
    # (The chain detections fire because the events we built tell the right story.)
    assert len(findings) == 11

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
        "Account Takeover Chain",
        "Malware Persistence Chain",
    }
