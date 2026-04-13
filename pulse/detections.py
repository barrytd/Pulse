# pulse/detections.py
# --------------------
# This module contains the detection rules — the "brains" of Pulse.
#
# HOW DETECTION WORKS:
# We take the list of parsed events from parser.py and look for patterns
# that indicate something suspicious. Think of it like a security guard
# reviewing camera footage — we're not watching live, but we're looking
# for red flags after the fact.
#
# WHAT WE'RE LOOKING FOR (to start):
#
# 1. BRUTE FORCE ATTEMPTS (Event ID 4625)
#    If someone fails to log in many times in a row, they might be
#    guessing passwords. We flag this when we see 5+ failed logins
#    from the same account within a short time window.
#
# 2. NEW USER CREATION (Event ID 4720)
#    Attackers who gain access often create a new user account as a
#    "backdoor" so they can come back later. Any new account creation
#    is worth investigating.
#
# 3. PRIVILEGE ESCALATION (Event ID 4732)
#    This fires when a user is added to a security group (like
#    Administrators). An attacker might add their backdoor account
#    to the admin group to gain full control.
#
# 4. LOG CLEARING (Event ID 1102)
#    If someone clears the security log, they're probably trying to
#    hide what they did. This is almost always suspicious.
#
# 5. FIREWALL RULE CHANGED (Event ID 4946 / 4947)
#    4946 = a new rule was added to the Windows Firewall exception list.
#    4947 = an existing firewall rule was modified.
#    Attackers often punch holes in the firewall to allow their tools
#    to communicate out (C2 traffic) or to let themselves back in.
#
# 6. FIREWALL DISABLED (Event ID 4950)
#    Fires when a Windows Firewall profile (Domain, Private, or Public)
#    is changed. Turning off the firewall is a huge red flag — it
#    removes the first line of defense on the machine.
#
# 7. ANTIVIRUS / DEFENDER DISABLED (Event ID 5001)
#    Windows Defender logs this when real-time protection is turned off.
#    Attackers disable AV early in an attack so their malware isn't caught.
#
# 8. SUSPICIOUS SERVICE INSTALLED (Event ID 7045)
#    Logged when a new service is installed on the system. Malware
#    frequently installs itself as a service so it survives reboots
#    (this is called "persistence").
#
# 9. RDP LOGON DETECTED (Event ID 4624, Logon Type 10)
#    Event 4624 is a successful logon, but Logon Type 10 specifically
#    means it came through Remote Desktop (RDP). Attackers love RDP
#    because it gives them a full GUI session on the target machine.


import platform
import xml.etree.ElementTree as ET          # Built-in XML parser
from datetime import datetime, timedelta   # For comparing event timestamps


# Cache for SID -> friendly name lookups. SIDs repeat constantly across
# events (same admin doing many actions), so caching turns N lookups into 1.
_SID_CACHE = {}


def _resolve_sid(sid_string):
    """Translate a Windows SID like "S-1-5-21-...-1003" into "DOMAIN\\user".

    Falls back to returning the SID unchanged on:
      - non-Windows platforms (Linux/macOS dev machines)
      - unresolvable SIDs (orphaned accounts, remote domains)
      - any ctypes / API failure

    Implementation uses advapi32 directly via ctypes so we don't need to
    add pywin32 as a dependency.
    """
    if not sid_string:
        return sid_string
    if sid_string in _SID_CACHE:
        return _SID_CACHE[sid_string]
    if platform.system() != "Windows":
        return sid_string

    try:
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        # Step 1: "S-1-5-..." string -> binary SID struct.
        sid_ptr = ctypes.c_void_p()
        if not advapi32.ConvertStringSidToSidW(
            ctypes.c_wchar_p(sid_string),
            ctypes.byref(sid_ptr),
        ):
            return sid_string

        try:
            # Step 2: binary SID -> (name, domain). Buffers start at 256
            # chars; if the lookup needs more, Windows writes the required
            # size into name_size/domain_size and returns 0 — we'd retry,
            # but 256 covers every real-world account name.
            name_size   = wintypes.DWORD(256)
            domain_size = wintypes.DWORD(256)
            name_buf    = ctypes.create_unicode_buffer(name_size.value)
            domain_buf  = ctypes.create_unicode_buffer(domain_size.value)
            sid_type    = wintypes.DWORD()

            if not advapi32.LookupAccountSidW(
                None,                       # local machine
                sid_ptr,
                name_buf,
                ctypes.byref(name_size),
                domain_buf,
                ctypes.byref(domain_size),
                ctypes.byref(sid_type),
            ):
                return sid_string

            name   = name_buf.value
            domain = domain_buf.value
            resolved = f"{domain}\\{name}" if domain else name or sid_string
        finally:
            kernel32.LocalFree(sid_ptr)

        _SID_CACHE[sid_string] = resolved
        return resolved
    except Exception:
        return sid_string


# These are the Windows Event IDs we care about.
# We store them as constants (variables that never change) at the top
# of the file so they're easy to find and update.
EVENT_FAILED_LOGIN = 4625
EVENT_USER_CREATED = 4720
EVENT_PRIVILEGE_ESCALATION = 4732
EVENT_LOG_CLEARED = 1102
EVENT_FIREWALL_RULE_ADDED = 4946
EVENT_FIREWALL_RULE_MODIFIED = 4947
EVENT_FIREWALL_PROFILE_CHANGED = 4950
EVENT_AV_DISABLED = 5001
EVENT_SERVICE_INSTALLED = 7045
EVENT_SUCCESSFUL_LOGON = 4624
EVENT_KERBEROS_TGS = 4769
EVENT_KERBEROS_TGT = 4768
EVENT_OBJECT_ACCESS = 4663
EVENT_HANDLE_REQUEST = 4656
EVENT_NETWORK_SHARE = 5140
EVENT_SHARE_FILE_ACCESS = 5145
EVENT_REGISTRY_MODIFIED = 4657

# How many failed logins within the time window triggers a brute force alert.
BRUTE_FORCE_THRESHOLD = 5

# How many minutes to look back when counting failures.
# 5 failures spread over a week = probably typos.
# 5 failures within 10 minutes = probably an attack.
BRUTE_FORCE_WINDOW_MINUTES = 10

# Logon Type 10 = Remote Desktop (RDP). Other types:
# 2 = Interactive (local keyboard), 3 = Network, 7 = Unlock.
# We only flag type 10 because it means someone is connecting remotely.
RDP_LOGON_TYPE = "10"

# The XML namespace used in Windows event logs.
# Every tag in the XML is prefixed with this namespace, so we need it
# whenever we search through the XML tree. Same one from parser.py.
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _parse_event_time(event):
    """Parse an event's timestamp string into a datetime object, or None."""
    timestamp_str = event["timestamp"].rstrip("Z")
    try:
        return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        try:
            return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None


def _get_xml_field(xml_tree, field_name):
    """Extract a named field from EventData in a parsed XML tree."""
    for el in xml_tree.findall(f"{NS}EventData/{NS}Data"):
        if el.get("Name") == field_name:
            return el.text
    return None


def detect_brute_force(events):
    """
    Looks for accounts with too many failed login attempts within a time window.

    WHY A TIME WINDOW?
    The old version counted ALL failures across the entire log. That meant
    5 failures spread over 3 weeks looked the same as 5 failures in 30 seconds.
    Real brute force attacks happen fast. This version only flags failures that
    cluster together within BRUTE_FORCE_WINDOW_MINUTES minutes.

    HOW IT WORKS:
    For each account, we collect a list of timestamps for every failure.
    Then we sort those timestamps and use a "sliding window" — we check
    every consecutive group of BRUTE_FORCE_THRESHOLD failures and ask:
    "did all of these happen within our time window?"

    Parameters:
        events (list): List of event dictionaries from the parser.

    Returns:
        list: A list of findings (same format as before).
    """

    findings = []

    # --- COLLECT FAILURE TIMESTAMPS PER ACCOUNT ---
    # Instead of a simple count, we now store a LIST of datetime objects.
    # Example: {"admin": [datetime(2024,1,15,8,0,1), datetime(2024,1,15,8,0,3), ...]}
    #
    # datetime objects are Python's way of representing a specific point in time.
    # Unlike a string like "2024-01-15T08:00:01", a datetime object lets you
    # do math — you can subtract two datetimes to get the gap between them.
    failure_times = {}

    for event in events:

        if event["event_id"] != EVENT_FAILED_LOGIN:
            continue

        xml_tree = ET.fromstring(event["data"])

        target_user = None
        for data_element in xml_tree.findall(f"{NS}EventData/{NS}Data"):
            if data_element.get("Name") == "TargetUserName":
                target_user = data_element.text
                break

        if not target_user:
            continue

        # --- PARSE THE TIMESTAMP STRING INTO A DATETIME OBJECT ---
        # event["timestamp"] is a string like "2024-01-15T08:00:01.000000Z".
        # strptime() (string parse time) converts it into a datetime object
        # we can do arithmetic on.
        #
        # The format codes:
        #   %Y = 4-digit year    %m = month    %d = day
        #   %H = hour (24h)      %M = minute   %S = second
        #   %f = microseconds    Z at the end = UTC timezone marker (we strip it)
        timestamp_str = event["timestamp"].rstrip("Z")  # Remove the trailing Z

        try:
            # Try the format with microseconds first (most common).
            event_time = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            try:
                # Fall back to without microseconds.
                event_time = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                # If we still can't parse it, skip this event rather than crash.
                continue

        # Add this timestamp to the list for this account.
        # setdefault() creates an empty list the first time we see an account,
        # then appends to it every subsequent time.
        failure_times.setdefault(target_user, []).append(event_time)

    # --- SLIDING WINDOW CHECK PER ACCOUNT ---
    # Now we check each account's list of failure timestamps.
    already_flagged = set()  # Tracks accounts we've already flagged

    for account, times in failure_times.items():

        # If there aren't even THRESHOLD failures total, skip immediately.
        if len(times) < BRUTE_FORCE_THRESHOLD:
            continue

        # Sort the timestamps oldest-to-newest so we can slide through them.
        times.sort()

        # The window is a timedelta object — a duration of time.
        # timedelta(minutes=10) represents "10 minutes".
        window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)

        # --- THE SLIDING WINDOW ---
        # We look at every possible group of THRESHOLD consecutive failures.
        # For each group, we check if all of them fit within the time window.
        #
        # Example: times = [T1, T2, T3, T4, T5, T6]
        # Iteration 1: look at T1..T5 — is T5 - T1 <= 10 minutes? If yes, flag.
        # Iteration 2: look at T2..T6 — is T6 - T2 <= 10 minutes? If yes, flag.
        for i in range(len(times) - BRUTE_FORCE_THRESHOLD + 1):

            # The first and last timestamp in this group.
            window_start = times[i]
            window_end   = times[i + BRUTE_FORCE_THRESHOLD - 1]

            if window_end - window_start <= window:
                # All THRESHOLD failures happened within the window!
                if account not in already_flagged:
                    already_flagged.add(account)
                    findings.append({
                        "rule": "Brute Force Attempt",
                        "severity": "HIGH",
                        "details": (
                            f"Account '{account}' had {BRUTE_FORCE_THRESHOLD}+ failed "
                            f"login attempts within {BRUTE_FORCE_WINDOW_MINUTES} minutes "
                            f"(between {window_start.strftime('%Y-%m-%dT%H:%M:%S')} and "
                            f"{window_end.strftime('%H:%M:%S')}). "
                            f"This strongly indicates a password guessing attack."
                        ),
                    })
                break  # No need to keep checking this account once flagged.

    return findings


def detect_user_creation(events):
    """
    Flags any new user account creation events.

    Parameters:
        events (list): List of event dictionaries from the parser.

    Returns:
        list: A list of findings (same format as detect_brute_force).
    """

    findings = []

    for event in events:

        # Only care about Event ID 4720 — new user account created.
        if event["event_id"] != EVENT_USER_CREATED:
            continue

        # --- EXTRACT WHO CREATED THE ACCOUNT AND WHAT ACCOUNT WAS CREATED ---
        xml_tree = ET.fromstring(event["data"])

        # We want two pieces of info from <EventData>:
        #   - "TargetUserName": The NEW account that was created
        #   - "SubjectUserName": The account that CREATED it (the actor)
        new_account = None
        created_by = None

        for data_element in xml_tree.findall(f"{NS}EventData/{NS}Data"):
            name = data_element.get("Name")
            if name == "TargetUserName":
                new_account = data_element.text
            elif name == "SubjectUserName":
                created_by = data_element.text

        findings.append({
            "rule": "User Account Created",
            "severity": "MEDIUM",
            "details": (
                f"New account '{new_account or 'Unknown'}' was created "
                f"by '{created_by or 'Unknown'}' at {event['timestamp']}. "
                f"Verify this was authorized - attackers create backdoor accounts."
            ),
        })

    return findings


def detect_privilege_escalation(events):
    """
    Flags when users are added to sensitive security groups.

    Parameters:
        events (list): List of event dictionaries from the parser.

    Returns:
        list: A list of findings (same format as detect_brute_force).
    """

    findings = []

    for event in events:

        # Only care about Event ID 4732 — user added to a security group.
        if event["event_id"] != EVENT_PRIVILEGE_ESCALATION:
            continue

        # --- EXTRACT WHO WAS ADDED, BY WHOM, AND TO WHAT GROUP ---
        xml_tree = ET.fromstring(event["data"])

        member_added = None
        member_sid   = None
        added_by = None
        group_name = None

        for data_element in xml_tree.findall(f"{NS}EventData/{NS}Data"):
            name = data_element.get("Name")
            if name == "MemberName":
                # MemberName is the account that was ADDED to the group.
                member_added = data_element.text
            elif name == "MemberSid":
                # Windows frequently writes MemberName as "-" and only
                # fills in the SID. Keep it as a fallback so we don't
                # show a bare dash in the finding.
                member_sid = data_element.text
            elif name == "SubjectUserName":
                # SubjectUserName is the account that DID the adding.
                added_by = data_element.text
            elif name == "TargetUserName":
                # TargetUserName here is actually the GROUP name
                # (confusing, but that's how Microsoft named it).
                group_name = data_element.text

        # Prefer the resolved name; fall back to translating the SID via
        # LookupAccountSid; then the raw SID; only say "Unknown" if we
        # truly have nothing.
        if member_added and member_added.strip() and member_added.strip() != "-":
            who = member_added
        elif member_sid:
            who = _resolve_sid(member_sid)
        else:
            who = "Unknown"

        findings.append({
            "rule": "Privilege Escalation",
            "severity": "HIGH",
            "details": (
                f"'{who}' was added to security group "
                f"'{group_name or 'Unknown'}' by '{added_by or 'Unknown'}' "
                f"at {event['timestamp']}. "
                f"Check if this was a legitimate admin action."
            ),
        })

    return findings


def detect_log_clearing(events):
    """
    Flags when the security audit log has been cleared.

    Parameters:
        events (list): List of event dictionaries from the parser.

    Returns:
        list: A list of findings (same format as detect_brute_force).
    """

    findings = []

    for event in events:

        # Only care about Event ID 1102 — audit log was cleared.
        if event["event_id"] != EVENT_LOG_CLEARED:
            continue

        # --- EXTRACT WHO CLEARED THE LOG ---
        # For 1102 events, the structure is slightly different.
        # The actor info is inside <UserData> instead of <EventData>.
        # But we can still check <EventData> as a fallback.
        xml_tree = ET.fromstring(event["data"])

        cleared_by = None

        # First try: look in <UserData> (where 1102 events typically store it).
        for data_element in xml_tree.findall(f".//{NS}SubjectUserName"):
            cleared_by = data_element.text
            break

        # Second try: check <EventData> format just in case.
        if not cleared_by:
            for data_element in xml_tree.findall(f"{NS}EventData/{NS}Data"):
                if data_element.get("Name") == "SubjectUserName":
                    cleared_by = data_element.text
                    break

        findings.append({
            "rule": "Audit Log Cleared",
            "severity": "HIGH",
            "details": (
                f"The security audit log was cleared by "
                f"'{cleared_by or 'Unknown'}' at {event['timestamp']}. "
                f"This is a strong indicator of an attacker covering their tracks."
            ),
        })

    return findings


def detect_rdp_logon(events):
    """
    Flags successful Remote Desktop (RDP) logons (Event 4624, LogonType 10).

    WHY THIS MATTERS:
    Event 4624 fires for ALL successful logons, but Logon Type 10 means
    the user connected via Remote Desktop Protocol (RDP). RDP gives an
    attacker a full graphical desktop session — they can see the screen,
    open programs, browse files. It's one of the most powerful access
    methods an attacker can use.

    This rule is different from the others because we can't just check
    the event_id — we also have to dig into the XML and check LogonType.
    A 4624 with LogonType 3 (network share access) is normal; LogonType 10
    is the one we flag.

    Parameters:
        events (list): List of event dictionaries from the parser.

    Returns:
        list: A list of findings (same format as detect_brute_force).
    """

    findings = []

    for event in events:

        # First gate: only look at successful logons (4624).
        if event["event_id"] != EVENT_SUCCESSFUL_LOGON:
            continue

        # --- SECOND GATE: CHECK THE LOGON TYPE ---
        # We need to parse the XML and look at LogonType.
        # Only LogonType "10" is RDP — everything else we skip.
        xml_tree = ET.fromstring(event["data"])

        logon_type = None
        target_user = None
        source_ip = None

        for data_element in xml_tree.findall(f"{NS}EventData/{NS}Data"):
            name = data_element.get("Name")
            if name == "LogonType":
                logon_type = data_element.text
            elif name == "TargetUserName":
                target_user = data_element.text
            elif name == "IpAddress":
                # The IP address of the machine that connected via RDP.
                # This is critical for investigation — it tells you WHERE
                # the attacker came from.
                source_ip = data_element.text

        # Skip if this isn't an RDP logon (type 10).
        # We compare as strings because XML text is always a string.
        if logon_type != RDP_LOGON_TYPE:
            continue

        findings.append({
            "rule": "RDP Logon Detected",
            "severity": "MEDIUM",
            "details": (
                f"Remote Desktop logon by '{target_user or 'Unknown'}' "
                f"from IP {source_ip or 'Unknown'} "
                f"at {event['timestamp']}. "
                f"RDP access should be monitored closely - attackers use it "
                f"for full interactive control of the machine."
            ),
        })

    return findings


def detect_pass_the_hash(events):
    """
    Detects potential Pass-the-Hash (PtH) attacks (Event ID 4624).

    WHAT IS PASS-THE-HASH?
    Normally to log in, you type a password. Windows hashes it and compares
    it to the stored hash. In a PtH attack, an attacker steals the hash
    itself (often using Mimikatz from memory) and sends THAT directly to
    Windows bypassing the need for the real password. Windows sees a
    valid hash and lets them in.

    HOW WE DETECT IT:
    A PtH login has three specific characteristics in Event 4624:
      1. LogonType = 3 (Network logon — attacker connecting over the network)
      2. AuthenticationPackageName = NTLM (the hash-based auth protocol)
      3. LogonProcessName = NtLmSsp (the NTLM Security Support Provider)

    Legitimate NTLM network logons happen (printers, file shares), so we
    add an extra filter: skip machine accounts (those ending in $), and
    skip logons from localhost (127.0.0.1 or ::1), which are typically
    internal system processes.

    XML FIELDS WE CHECK:
      <Data Name="LogonType">3</Data>
      <Data Name="AuthenticationPackageName">NTLM</Data>
      <Data Name="LogonProcessName">NtLmSsp</Data>
      <Data Name="TargetUserName">jsmith</Data>
      <Data Name="IpAddress">192.168.1.50</Data>
    """

    findings = []

    for event in events:
        if event["event_id"] != EVENT_SUCCESSFUL_LOGON:
            continue

        xml_tree = ET.fromstring(event["data"])

        logon_type = None
        auth_package = None
        logon_process = None
        target_user = None
        source_ip = None

        for data_element in xml_tree.findall(f"{NS}EventData/{NS}Data"):
            name = data_element.get("Name")
            if name == "LogonType":
                logon_type = data_element.text
            elif name == "AuthenticationPackageName":
                auth_package = data_element.text
            elif name == "LogonProcessName":
                logon_process = data_element.text
            elif name == "TargetUserName":
                target_user = data_element.text
            elif name == "IpAddress":
                source_ip = data_element.text

        # Gate 1: must be a network logon (type 3).
        if logon_type != "3":
            continue

        # Gate 2: must use NTLM authentication.
        if not auth_package or auth_package.upper() != "NTLM":
            continue

        # Gate 3: must go through NtLmSsp (the NTLM SSP provider).
        # Kerberos uses a different process name, so this filters out Kerberos.
        if not logon_process or "NtLmSsp" not in logon_process:
            continue

        # Gate 4: skip machine accounts (names ending in $).
        # These are normal Windows background operations, not human logins.
        if target_user and target_user.endswith("$"):
            continue

        # Gate 5: skip localhost connections — these are internal processes,
        # not an attacker coming in from the network.
        if source_ip in ("127.0.0.1", "::1", "-", None):
            continue

        findings.append({
            "rule": "Pass-the-Hash Attempt",
            "severity": "HIGH",
            "details": (
                f"Possible Pass-the-Hash login by '{target_user or 'Unknown'}' "
                f"from IP {source_ip} at {event['timestamp']}. "
                f"Network logon (type 3) using NTLM authentication - "
                f"an attacker may be using a stolen password hash to "
                f"authenticate without knowing the real password."
            ),
        })

    return findings


def detect_service_installed(events):
    """
    Flags when a new service is installed on the system (Event 7045).

    WHY THIS MATTERS:
    Services are programs that run in the background, often starting
    automatically when Windows boots. Malware frequently installs itself
    as a service to achieve "persistence" — surviving reboots so the
    attacker doesn't lose access. Legitimate software installs services
    too, but any unexpected service warrants investigation.

    Parameters:
        events (list): List of event dictionaries from the parser.

    Returns:
        list: A list of findings (same format as detect_brute_force).
    """

    findings = []

    for event in events:

        if event["event_id"] != EVENT_SERVICE_INSTALLED:
            continue

        # --- EXTRACT SERVICE NAME AND ACCOUNT ---
        # "ServiceName" is the name of the new service.
        # "AccountName" is the account the service will run as.
        # Services running as "LocalSystem" have FULL access to the machine,
        # which is extra suspicious if the service is unknown.
        xml_tree = ET.fromstring(event["data"])

        service_name = None
        account_name = None

        for data_element in xml_tree.findall(f"{NS}EventData/{NS}Data"):
            name = data_element.get("Name")
            if name == "ServiceName":
                service_name = data_element.text
            elif name == "AccountName":
                account_name = data_element.text

        findings.append({
            "rule": "Service Installed",
            "severity": "MEDIUM",
            "details": (
                f"New service '{service_name or 'Unknown'}' was installed "
                f"running as '{account_name or 'Unknown'}' "
                f"at {event['timestamp']}. "
                f"Malware often installs as a service for persistence. "
                f"Verify this is a legitimate application."
            ),
        })

    return findings


def detect_av_disabled(events):
    """
    Flags when antivirus real-time protection is turned off (Event 5001).

    WHY THIS MATTERS:
    Windows Defender (Microsoft's built-in antivirus) logs Event 5001
    when real-time protection is disabled. This is one of the FIRST things
    attackers do after gaining access — they kill the AV so their malware
    can run without being detected or quarantined.

    This event has no <EventData> fields — the fact that it happened at
    all IS the finding. So this is the simplest detection rule we have.

    Parameters:
        events (list): List of event dictionaries from the parser.

    Returns:
        list: A list of findings (same format as detect_brute_force).
    """

    findings = []

    for event in events:

        if event["event_id"] != EVENT_AV_DISABLED:
            continue

        # No XML digging needed — Event 5001 has no useful extra fields.
        # The event itself is the red flag.
        findings.append({
            "rule": "Antivirus Disabled",
            "severity": "HIGH",
            "details": (
                f"Windows Defender real-time protection was disabled "
                f"at {event['timestamp']}. "
                f"This is a critical finding - attackers disable AV to "
                f"run malware undetected. Investigate immediately."
            ),
        })

    return findings


def detect_firewall_disabled(events):
    """
    Flags when a Windows Firewall profile is changed (Event 4950).

    WHY THIS MATTERS:
    Windows has three firewall profiles: Domain, Private, and Public.
    Each controls traffic filtering for a different network type.
    Disabling any of them removes a critical layer of defense. Attackers
    do this so their tools can communicate freely without being blocked.

    Parameters:
        events (list): List of event dictionaries from the parser.

    Returns:
        list: A list of findings (same format as detect_brute_force).
    """

    findings = []

    for event in events:

        if event["event_id"] != EVENT_FIREWALL_PROFILE_CHANGED:
            continue

        # --- EXTRACT WHICH PROFILE WAS CHANGED ---
        # Real Windows 4950 events write the profile name into
        # "ProfileChanged" (e.g. "Public Profile"), plus SettingType and
        # SettingValue describing exactly what was flipped. Some test
        # fixtures and older docs use "ProfileName" — fall back to that
        # so we stay compatible.
        xml_tree = ET.fromstring(event["data"])

        profile       = None
        setting_type  = None
        setting_value = None
        for data_element in xml_tree.findall(f"{NS}EventData/{NS}Data"):
            name = data_element.get("Name")
            if name in ("ProfileChanged", "ProfileName") and not profile:
                profile = data_element.text
            elif name == "SettingType":
                setting_type = data_element.text
            elif name == "NewProfileSetting" or name == "SettingValue":
                setting_value = data_element.text

        # Build a richer details line when SettingType/Value are present.
        if setting_type and setting_value:
            change = (
                f"setting '{setting_type}' changed to '{setting_value}' on "
                f"'{profile or 'Unknown profile'}'"
            )
        else:
            change = f"profile '{profile or 'Unknown'}' was changed"

        findings.append({
            "rule": "Firewall Disabled",
            "severity": "HIGH",
            "details": (
                f"Windows Firewall {change} "
                f"at {event['timestamp']}. "
                f"If the firewall was disabled, the machine is now exposed. "
                f"Attackers disable firewalls to allow unrestricted network access."
            ),
        })

    return findings


def detect_firewall_rule_change(events):
    """
    Flags when Windows Firewall rules are added (4946) or modified (4947).

    WHY THIS MATTERS:
    Attackers need network access for their tools to work. They often add
    firewall exceptions to allow command-and-control (C2) traffic out, or
    modify existing rules to open ports for backdoor access.

    Parameters:
        events (list): List of event dictionaries from the parser.

    Returns:
        list: A list of findings (same format as detect_brute_force).
    """

    findings = []

    for event in events:

        # We care about BOTH 4946 (rule added) and 4947 (rule modified).
        # Instead of two separate if-statements, we check if the event_id
        # is "in" a set of IDs we care about. Sets use curly braces {}.
        if event["event_id"] not in {EVENT_FIREWALL_RULE_ADDED, EVENT_FIREWALL_RULE_MODIFIED}:
            continue

        # --- FIGURE OUT IF THIS WAS AN ADD OR A MODIFY ---
        # We label the finding differently so the analyst knows what happened.
        if event["event_id"] == EVENT_FIREWALL_RULE_ADDED:
            action = "added"
        else:
            action = "modified"

        # --- EXTRACT THE RULE NAME FROM THE XML ---
        xml_tree = ET.fromstring(event["data"])

        rule_name = None
        for data_element in xml_tree.findall(f"{NS}EventData/{NS}Data"):
            if data_element.get("Name") == "RuleName":
                rule_name = data_element.text
                break

        findings.append({
            "rule": "Firewall Rule Changed",
            "severity": "MEDIUM",
            "details": (
                f"Firewall rule '{rule_name or 'Unknown'}' was {action} "
                f"at {event['timestamp']}. "
                f"Verify this was an authorized change - attackers modify "
                f"firewall rules to allow C2 traffic or open backdoor ports."
            ),
        })

    return findings


def detect_account_lockout(events):
    """
    Detects when a user account gets locked out (Event ID 4740).

    WHY THIS MATTERS:
    Windows can be configured to lock an account after too many failed
    login attempts (e.g. 5 failures in 10 minutes). When this happens,
    Event 4740 is logged. A few lockouts might just be a user forgetting
    their password, but many lockouts in a short time - especially across
    multiple accounts - is a strong indicator of an active brute force attack.

    Unlike Event 4625 (failed login), a lockout means the system already
    decided the failures were suspicious enough to take action.

    XML DATA WE EXTRACT:
      <Data Name="TargetUserName">jsmith</Data>    - the locked out account
    """

    findings = []

    for event in events:
        if event["event_id"] != 4740:
            continue

        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        xml_tree = ET.fromstring(event["data"])
        event_data = xml_tree.find(f"{ns}EventData")

        target_user = None
        if event_data is not None:
            for data_elem in event_data:
                if data_elem.get("Name") == "TargetUserName":
                    target_user = data_elem.text

        findings.append({
            "rule": "Account Lockout",
            "severity": "HIGH",
            "details": (
                f"Account '{target_user or 'Unknown'}' was locked out "
                f"at {event['timestamp']}. "
                f"This may indicate an active brute force attack or "
                f"a misconfigured service using stale credentials."
            ),
        })

    return findings


def detect_scheduled_task_created(events):
    """
    Detects when a new scheduled task is created (Event ID 4698).

    WHY THIS MATTERS:
    Scheduled tasks are one of the most common persistence mechanisms
    attackers use. They create a task that runs their malware on a schedule
    (e.g. every time the computer boots, or every hour). This way, even
    if the malware process is killed, the scheduled task brings it back.

    Legitimate scheduled tasks exist too (Windows Update, antivirus scans),
    but a NEW task being created - especially by an unexpected user - is
    worth investigating.

    XML DATA WE EXTRACT:
      <Data Name="TaskName">\\MalwareTask</Data>   - name of the task
      <Data Name="SubjectUserName">admin</Data>   - who created it
    """

    findings = []

    for event in events:
        if event["event_id"] != 4698:
            continue

        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        xml_tree = ET.fromstring(event["data"])
        event_data = xml_tree.find(f"{ns}EventData")

        task_name = None
        created_by = None
        if event_data is not None:
            for data_elem in event_data:
                if data_elem.get("Name") == "TaskName":
                    task_name = data_elem.text
                elif data_elem.get("Name") == "SubjectUserName":
                    created_by = data_elem.text

        findings.append({
            "rule": "Scheduled Task Created",
            "severity": "MEDIUM",
            "details": (
                f"Scheduled task '{task_name or 'Unknown'}' was created "
                f"by '{created_by or 'Unknown'}' at {event['timestamp']}. "
                f"Verify this is legitimate - attackers use scheduled tasks "
                f"for persistence (surviving reboots)."
            ),
        })

    return findings


def detect_suspicious_powershell(events):
    """
    Detects suspicious PowerShell script execution (Event ID 4104).

    WHY THIS MATTERS:
    PowerShell is one of the most powerful tools on a Windows system -
    and one of the most abused by attackers. Event 4104 logs the actual
    script text that was run (called "Script Block Logging"). We check
    for known suspicious patterns:

      - Base64 encoded commands (-EncodedCommand, FromBase64String)
      - Download cradles (Invoke-WebRequest, DownloadString, Net.WebClient)
      - Execution bypass (-ExecutionPolicy Bypass)
      - Credential theft (Mimikatz, Get-Credential, SecureString)
      - Obfuscation indicators (lots of backticks, string concatenation)

    If ANY of these patterns appear in the script text, we flag it.

    XML DATA WE EXTRACT:
      <Data Name="ScriptBlockText">the actual PowerShell code</Data>
    """

    # These are patterns commonly seen in malicious PowerShell.
    # Each tuple is (pattern_to_search, description_for_the_finding).
    SUSPICIOUS_PATTERNS = [
        ("encodedcommand", "encoded command execution"),
        ("frombase64string", "Base64 decoding"),
        ("invoke-webrequest", "web download"),
        ("downloadstring", "web download"),
        ("net.webclient", "web download"),
        ("invoke-expression", "dynamic code execution (IEX)"),
        ("-executionpolicy bypass", "execution policy bypass"),
        ("mimikatz", "credential theft tool"),
        ("get-credential", "credential harvesting"),
        ("invoke-mimikatz", "credential theft tool"),
        ("set-masterbootrecord", "destructive MBR modification"),
        ("invoke-shellcode", "shellcode injection"),
    ]

    findings = []

    for event in events:
        if event["event_id"] != 4104:
            continue

        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        xml_tree = ET.fromstring(event["data"])
        event_data = xml_tree.find(f"{ns}EventData")

        script_text = None
        if event_data is not None:
            for data_elem in event_data:
                if data_elem.get("Name") == "ScriptBlockText":
                    script_text = data_elem.text

        if not script_text:
            continue

        # Check for suspicious patterns in the script text.
        script_lower = script_text.lower()
        matched = []
        for pattern, description in SUSPICIOUS_PATTERNS:
            if pattern in script_lower:
                matched.append(description)

        if matched:
            # Show the first 120 characters of the script for context.
            preview = script_text[:120].replace("\n", " ")
            if len(script_text) > 120:
                preview += "..."

            findings.append({
                "rule": "Suspicious PowerShell",
                "severity": "HIGH",
                "details": (
                    f"Suspicious PowerShell script detected at {event['timestamp']}. "
                    f"Matched patterns: {', '.join(matched)}. "
                    f"Script preview: {preview}"
                ),
            })

    return findings


def detect_account_takeover_chain(events):
    """
    Detects a classic account takeover sequence:
      brute force → successful login → new user created

    WHY THIS MATTERS:
    Individual events can each be somewhat ambiguous. But when you see
    all three happen in sequence for the same account, it tells a story:
      1. Attacker guesses the password (brute force failures)
      2. Attacker gets in (successful login)
      3. Attacker creates a backdoor account so they can come back later

    This is called "correlation" — connecting multiple events to reveal
    a pattern that's more significant than any single event alone.
    It's how real SIEM platforms (Splunk, Microsoft Sentinel) work.

    HOW IT WORKS:
    We scan the events for each account and check if they experienced:
      - 2+ failed logins (4625)  — evidence of password guessing
      - At least 1 success (4624) after those failures
      - A new user account created (4720) in the same session

    We track timing to make sure these events happen in a plausible order,
    not just that they all exist somewhere in the log.

    Parameters:
        events (list): List of event dictionaries from the parser.

    Returns:
        list: A list of findings. Severity is CRITICAL — this is the
              highest-confidence finding Pulse can produce.
    """

    findings = []

    # --- PASS 1: COLLECT DATA PER ACCOUNT ---
    # We build a picture of what happened for each account:
    # when they failed, when they succeeded, and whether a new account appeared.

    failure_times   = {}  # account -> list of failure datetimes
    success_times   = {}  # account -> list of success datetimes
    new_users_found = []  # list of (new_username, created_at) tuples

    for event in events:

        # --- PARSE TIMESTAMP (same logic as brute force) ---
        timestamp_str = event["timestamp"].rstrip("Z")
        try:
            event_time = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            try:
                event_time = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                continue

        xml_tree = ET.fromstring(event["data"])

        # --- COLLECT FAILED LOGINS ---
        if event["event_id"] == EVENT_FAILED_LOGIN:
            user = None
            for el in xml_tree.findall(f"{NS}EventData/{NS}Data"):
                if el.get("Name") == "TargetUserName":
                    user = el.text
                    break
            if user:
                failure_times.setdefault(user, []).append(event_time)

        # --- COLLECT SUCCESSFUL LOGINS (non-RDP, type 3 = network) ---
        # We're looking for the attacker getting IN, not just RDP sessions.
        elif event["event_id"] == EVENT_SUCCESSFUL_LOGON:
            user = None
            for el in xml_tree.findall(f"{NS}EventData/{NS}Data"):
                if el.get("Name") == "TargetUserName":
                    user = el.text
                    break
            if user:
                success_times.setdefault(user, []).append(event_time)

        # --- COLLECT NEW ACCOUNT CREATION EVENTS ---
        elif event["event_id"] == EVENT_USER_CREATED:
            new_user = None
            for el in xml_tree.findall(f"{NS}EventData/{NS}Data"):
                if el.get("Name") == "TargetUserName":
                    new_user = el.text
                    break
            if new_user:
                new_users_found.append((new_user, event_time))

    # --- PASS 2: LOOK FOR THE CHAIN ---
    # For each account that had failures, check if:
    #   1. There were 2+ failures
    #   2. A success happened AFTER those failures
    #   3. A new user was created AFTER the success

    for account, failures in failure_times.items():

        if len(failures) < 2:
            continue  # Not enough failures to be suspicious on their own

        # Sort and find the last failure time.
        failures.sort()
        last_failure = failures[-1]

        # Check if there's a successful login AFTER the failures.
        successes_after = [
            t for t in success_times.get(account, [])
            if t > last_failure
        ]

        if not successes_after:
            continue  # No success after the brute force — chain broken

        first_success = min(successes_after)

        # Check if a new user account was created AFTER the successful login.
        # new_users_found is a list of (username, time) tuples.
        new_users_after = [
            (username, t) for username, t in new_users_found
            if t > first_success
        ]

        if not new_users_after:
            continue  # No new account created — chain incomplete

        # We have all three steps! This is a confirmed attack chain.
        new_usernames = ", ".join(u for u, _ in new_users_after)

        findings.append({
            "rule": "Account Takeover Chain",
            "severity": "CRITICAL",
            "details": (
                f"ATTACK CHAIN DETECTED for account '{account}': "
                f"({len(failures)}) failed logins ending at "
                f"{last_failure.strftime('%Y-%m-%dT%H:%M:%S')}, "
                f"followed by a successful login at "
                f"{first_success.strftime('%Y-%m-%dT%H:%M:%S')}, "
                f"followed by creation of new account(s): '{new_usernames}'. "
                f"This strongly indicates a successful account takeover with "
                f"backdoor account creation. Investigate immediately."
            ),
        })

    return findings


def detect_malware_persistence_chain(events):
    """
    Detects a classic malware persistence sequence:
      AV disabled → new service installed

    WHY THIS MATTERS:
    These two events individually are already suspicious. But when AV is
    disabled and THEN a new service appears, it's a textbook malware
    installation pattern:
      1. Attacker turns off antivirus so it can't block the malware
      2. Attacker installs the malware as a service so it survives reboots

    The time ordering matters — a service installed BEFORE the AV was
    disabled is less suspicious (probably just a legitimate app).

    Parameters:
        events (list): List of event dictionaries from the parser.

    Returns:
        list: A list of findings with severity CRITICAL.
    """

    findings = []

    av_disabled_times  = []  # list of datetimes when AV was turned off
    services_installed = []  # list of (service_name, datetime) tuples

    for event in events:

        timestamp_str = event["timestamp"].rstrip("Z")
        try:
            event_time = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            try:
                event_time = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                continue

        if event["event_id"] == EVENT_AV_DISABLED:
            av_disabled_times.append(event_time)

        elif event["event_id"] == EVENT_SERVICE_INSTALLED:
            xml_tree = ET.fromstring(event["data"])
            service_name = None
            for el in xml_tree.findall(f"{NS}EventData/{NS}Data"):
                if el.get("Name") == "ServiceName":
                    service_name = el.text
                    break
            if service_name:
                services_installed.append((service_name, event_time))

    # If we never saw AV disabled or no services were installed, no chain.
    if not av_disabled_times or not services_installed:
        return findings

    # Find the earliest time AV was disabled.
    first_av_disabled = min(av_disabled_times)

    # Find any services installed AFTER AV was turned off.
    suspicious_services = [
        (name, t) for name, t in services_installed
        if t > first_av_disabled
    ]

    if suspicious_services:
        service_names = ", ".join(n for n, _ in suspicious_services)
        findings.append({
            "rule": "Malware Persistence Chain",
            "severity": "CRITICAL",
            "details": (
                f"ATTACK CHAIN DETECTED: Antivirus was disabled at "
                f"{first_av_disabled.strftime('%Y-%m-%dT%H:%M:%S')}, "
                f"followed by installation of service(s): '{service_names}'. "
                f"This matches the pattern of malware disabling defences "
                f"before installing itself for persistence. Investigate immediately."
            ),
        })

    return findings


def detect_kerberoasting(events):
    """
    Detects Kerberoasting — TGS ticket requests using RC4 encryption.

    Kerberoasting is an attack where an attacker requests Kerberos TGS
    tickets for service accounts using weak RC4 encryption (0x17),
    then cracks the tickets offline to recover service account passwords.
    We flag when multiple RC4 TGS requests come from the same account.

    Event ID: 4769 (Kerberos Service Ticket Operations)
    MITRE ATT&CK: T1558.003
    """
    findings = []
    rc4_requests = {}

    for event in events:
        if event["event_id"] != EVENT_KERBEROS_TGS:
            continue

        xml_tree = ET.fromstring(event["data"])
        ticket_encryption = _get_xml_field(xml_tree, "TicketEncryptionType")
        target_user = _get_xml_field(xml_tree, "TargetUserName")
        service_name = _get_xml_field(xml_tree, "ServiceName")
        if ticket_encryption and ticket_encryption.strip() == "0x17":
            key = target_user or service_name or "unknown"
            rc4_requests.setdefault(key, []).append(event["timestamp"])

    for account, timestamps in rc4_requests.items():
        if len(timestamps) >= 3:
            findings.append({
                "rule": "Kerberoasting",
                "severity": "HIGH",
                "details": (
                    f"Potential Kerberoasting detected: {len(timestamps)} TGS ticket "
                    f"requests using RC4 encryption (0x17) for service '{account}'. "
                    f"First seen: {timestamps[0]}. Attackers request RC4-encrypted "
                    f"tickets to crack service account passwords offline."
                ),
            })

    return findings


def detect_golden_ticket(events):
    """
    Detects potential Golden Ticket attacks via suspicious TGT requests.

    A Golden Ticket is a forged Kerberos TGT that gives an attacker
    domain admin access. Signs include TGT requests with abnormal
    encryption types, unusual account names, or requests from IPs
    that aren't domain controllers.

    Event ID: 4768 (Kerberos Authentication Service)
    MITRE ATT&CK: T1558.001
    """
    findings = []

    for event in events:
        if event["event_id"] != EVENT_KERBEROS_TGT:
            continue

        xml_tree = ET.fromstring(event["data"])
        target_user = _get_xml_field(xml_tree, "TargetUserName") or ""
        status = _get_xml_field(xml_tree, "Status") or ""
        ticket_encryption = _get_xml_field(xml_tree, "TicketEncryptionType") or ""

        if target_user.lower() in ("krbtgt", "administrator") and status == "0x0":
            findings.append({
                "rule": "Golden Ticket",
                "severity": "CRITICAL",
                "details": (
                    f"Suspicious TGT request for privileged account '{target_user}' "
                    f"at {event['timestamp']}. Encryption type: {ticket_encryption}. "
                    f"This may indicate a Golden Ticket attack — a forged Kerberos "
                    f"ticket granting unrestricted domain access."
                ),
            })

    return findings


def detect_credential_dumping(events):
    """
    Detects access to the LSASS process — a sign of credential dumping.

    Tools like Mimikatz read LSASS memory to extract plaintext passwords,
    NTLM hashes, and Kerberos tickets. Windows logs this as object access
    events targeting lsass.exe.

    Event IDs: 4656 (handle request), 4663 (object access)
    MITRE ATT&CK: T1003.001
    """
    findings = []
    flagged = False

    for event in events:
        if event["event_id"] not in (EVENT_HANDLE_REQUEST, EVENT_OBJECT_ACCESS):
            continue

        xml_tree = ET.fromstring(event["data"])
        object_name = _get_xml_field(xml_tree, "ObjectName") or ""
        process_name = _get_xml_field(xml_tree, "ProcessName") or ""

        if "lsass" in object_name.lower() or "lsass" in process_name.lower():
            if not flagged:
                subject_user = _get_xml_field(xml_tree, "SubjectUserName") or "unknown"
                findings.append({
                    "rule": "Credential Dumping",
                    "severity": "CRITICAL",
                    "details": (
                        f"LSASS process access detected at {event['timestamp']} "
                        f"by user '{subject_user}'. Process: {process_name or 'N/A'}. "
                        f"This is a strong indicator of credential dumping (Mimikatz, "
                        f"procdump, or similar tools extracting passwords from memory)."
                    ),
                })
                flagged = True

    return findings


def detect_disabled_account_logon(events):
    """
    Detects logon attempts using disabled accounts.

    If someone is trying to authenticate with an account that has been
    disabled, it suggests they have old credentials and are testing them.
    This is common in insider threats and post-compromise scenarios.

    Event ID: 4625 (failed logon), Sub Status 0xC0000072
    MITRE ATT&CK: T1078
    """
    findings = []
    flagged_accounts = set()

    for event in events:
        if event["event_id"] != EVENT_FAILED_LOGIN:
            continue

        xml_tree = ET.fromstring(event["data"])
        sub_status = _get_xml_field(xml_tree, "SubStatus") or ""
        target_user = _get_xml_field(xml_tree, "TargetUserName") or "unknown"

        if sub_status.strip().lower() == "0xc0000072" and target_user not in flagged_accounts:
            flagged_accounts.add(target_user)
            source_ip = _get_xml_field(xml_tree, "IpAddress") or "N/A"
            findings.append({
                "rule": "Logon from Disabled Account",
                "severity": "MEDIUM",
                "details": (
                    f"Logon attempt using disabled account '{target_user}' "
                    f"at {event['timestamp']} from IP {source_ip}. "
                    f"Someone is trying credentials for an account that has been "
                    f"deliberately disabled."
                ),
            })

    return findings


def detect_after_hours_logon(events):
    """
    Detects successful logons outside business hours (before 6 AM or after 10 PM).

    Unusual logon times can indicate compromised credentials being used
    by attackers in different time zones, or insider threats operating
    outside normal oversight windows.

    Event ID: 4624 (successful logon)
    MITRE ATT&CK: T1078
    """
    findings = []
    flagged_accounts = set()

    for event in events:
        if event["event_id"] != EVENT_SUCCESSFUL_LOGON:
            continue

        event_time = _parse_event_time(event)
        if not event_time:
            continue

        if event_time.hour < 6 or event_time.hour >= 22:
            xml_tree = ET.fromstring(event["data"])
            target_user = _get_xml_field(xml_tree, "TargetUserName") or "unknown"
            logon_type = _get_xml_field(xml_tree, "LogonType") or ""

            if target_user.endswith("$") or target_user.upper() in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "DWM-1", "UMFD-0", "UMFD-1"):
                continue

            if target_user not in flagged_accounts:
                flagged_accounts.add(target_user)
                findings.append({
                    "rule": "After-Hours Logon",
                    "severity": "MEDIUM",
                    "details": (
                        f"Logon outside business hours: user '{target_user}' "
                        f"logged in at {event_time.strftime('%Y-%m-%dT%H:%M:%S')} "
                        f"(logon type {logon_type}). Logons between 10 PM and 6 AM "
                        f"may indicate unauthorized access."
                    ),
                })

    return findings


def detect_registry_persistence(events):
    """
    Detects suspicious modifications to autorun registry keys.

    Malware commonly adds entries to Run/RunOnce registry keys so it
    starts automatically on every boot. Changes to these keys outside
    of software installations should be investigated.

    Event ID: 4657 (registry value modified)
    MITRE ATT&CK: T1547.001
    """
    findings = []

    AUTORUN_KEYS = [
        "\\currentversion\\run",
        "\\currentversion\\runonce",
        "\\currentversion\\runservices",
        "\\currentversion\\policies\\explorer\\run",
        "\\currentversion\\windows\\load",
        "\\currentversion\\winlogon\\shell",
        "\\currentversion\\winlogon\\userinit",
    ]

    for event in events:
        if event["event_id"] != EVENT_REGISTRY_MODIFIED:
            continue

        xml_tree = ET.fromstring(event["data"])
        object_name = (_get_xml_field(xml_tree, "ObjectName") or "").lower()
        subject_user = _get_xml_field(xml_tree, "SubjectUserName") or "unknown"
        object_value = _get_xml_field(xml_tree, "ObjectValueName") or ""
        new_value = _get_xml_field(xml_tree, "NewValue") or ""

        for key_pattern in AUTORUN_KEYS:
            if key_pattern in object_name:
                findings.append({
                    "rule": "Suspicious Registry Modification",
                    "severity": "HIGH",
                    "details": (
                        f"Autorun registry key modified by '{subject_user}' "
                        f"at {event['timestamp']}. Key: ...{object_name[-80:]}. "
                        f"Value: {object_value}. New data: {new_value[:100]}. "
                        f"This is a common malware persistence technique."
                    ),
                })
                break

    return findings


def detect_lateral_movement_shares(events):
    """
    Detects access to administrative network shares (C$, ADMIN$, IPC$).

    Attackers use admin shares to move laterally between machines on a
    network — copying tools, executing commands, or exfiltrating data.
    Legitimate admin share access is rare in most environments.

    Event IDs: 5140 (network share accessed), 5145 (share object access)
    MITRE ATT&CK: T1021.002
    """
    findings = []
    flagged = set()

    ADMIN_SHARES = ["c$", "admin$", "ipc$"]

    for event in events:
        if event["event_id"] not in (EVENT_NETWORK_SHARE, EVENT_SHARE_FILE_ACCESS):
            continue

        xml_tree = ET.fromstring(event["data"])
        share_name = (_get_xml_field(xml_tree, "ShareName") or "").strip().lower()
        subject_user = _get_xml_field(xml_tree, "SubjectUserName") or "unknown"
        source_ip = _get_xml_field(xml_tree, "IpAddress") or "N/A"

        share_base = share_name.split("\\")[-1] if "\\" in share_name else share_name
        if share_base in ADMIN_SHARES:
            key = subject_user + "|" + share_base
            if key not in flagged:
                flagged.add(key)
                findings.append({
                    "rule": "Lateral Movement via Network Share",
                    "severity": "HIGH",
                    "details": (
                        f"Administrative share '{share_name}' accessed by "
                        f"'{subject_user}' from {source_ip} at {event['timestamp']}. "
                        f"Admin share access is commonly used for lateral movement "
                        f"— copying tools between machines or remote execution."
                    ),
                })

    return findings


def run_all_detections(events):
    """
    Runs every detection rule against the parsed events.

    This is the main function other parts of the code will call.
    It runs all individual detection functions and combines their
    results into one big list.

    Parameters:
        events (list): List of event dictionaries from the parser.

    Returns:
        list: Combined list of all findings from all detection rules.
    """
    # We collect all findings into one list.
    # The "or []" at the end of each line is a safety net:
    # if a detection function returns None (because it's not built yet),
    # we treat it as an empty list instead of crashing.
    findings = []
    findings += detect_brute_force(events) or []
    findings += detect_user_creation(events) or []
    findings += detect_privilege_escalation(events) or []
    findings += detect_log_clearing(events) or []
    findings += detect_rdp_logon(events) or []
    findings += detect_pass_the_hash(events) or []
    findings += detect_service_installed(events) or []
    findings += detect_av_disabled(events) or []
    findings += detect_firewall_disabled(events) or []
    findings += detect_firewall_rule_change(events) or []
    findings += detect_account_lockout(events) or []
    findings += detect_scheduled_task_created(events) or []
    findings += detect_suspicious_powershell(events) or []
    findings += detect_account_takeover_chain(events) or []
    findings += detect_malware_persistence_chain(events) or []
    findings += detect_kerberoasting(events) or []
    findings += detect_golden_ticket(events) or []
    findings += detect_credential_dumping(events) or []
    findings += detect_disabled_account_logon(events) or []
    findings += detect_after_hours_logon(events) or []
    findings += detect_registry_persistence(events) or []
    findings += detect_lateral_movement_shares(events) or []
    return findings
