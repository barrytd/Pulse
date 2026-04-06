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


import xml.etree.ElementTree as ET  # Built-in XML parser — same one we used in parser.py


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

# How many failed logins before we call it a brute force attempt?
BRUTE_FORCE_THRESHOLD = 5

# Logon Type 10 = Remote Desktop (RDP). Other types:
# 2 = Interactive (local keyboard), 3 = Network, 7 = Unlock.
# We only flag type 10 because it means someone is connecting remotely.
RDP_LOGON_TYPE = "10"

# The XML namespace used in Windows event logs.
# Every tag in the XML is prefixed with this namespace, so we need it
# whenever we search through the XML tree. Same one from parser.py.
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def detect_brute_force(events):
    """
    Looks for accounts with too many failed login attempts.

    Parameters:
        events (list): List of event dictionaries from the parser.

    Returns:
        list: A list of findings. Each finding is a dictionary with:
              - "rule": Name of the detection rule that triggered
              - "severity": How serious this is ("LOW", "MEDIUM", "HIGH")
              - "details": Human-readable description of what was found
    """

    # This will hold our findings — suspicious things we detect.
    findings = []

    # --- COUNT FAILED LOGINS PER ACCOUNT ---
    # We need to figure out HOW MANY times each account failed to log in.
    # A dictionary is perfect for this: the key is the account name,
    # and the value is how many times we saw a failed login for that account.
    # Example: {"admin": 12, "jsmith": 2}
    failed_counts = {}

    for event in events:

        # Skip any event that isn't a failed login (4625).
        # This is like a bouncer at a door — only 4625 events get through.
        if event["event_id"] != EVENT_FAILED_LOGIN:
            continue

        # --- DIG INTO THE XML TO FIND THE ACCOUNT NAME ---
        # The account that failed to log in is buried in the XML inside
        # <EventData>. Specifically, it's in a <Data> tag where the
        # Name attribute is "TargetUserName".
        #
        # The XML looks something like this:
        #   <EventData>
        #     <Data Name="TargetUserName">admin</Data>
        #     <Data Name="LogonType">3</Data>
        #     ...
        #   </EventData>
        xml_tree = ET.fromstring(event["data"])

        # .findall() returns a LIST of all matching tags (there are many <Data> tags).
        # We loop through them to find the one with Name="TargetUserName".
        target_user = None
        for data_element in xml_tree.findall(f"{NS}EventData/{NS}Data"):
            # .get("Name") reads the "Name" attribute on this <Data> tag.
            if data_element.get("Name") == "TargetUserName":
                # .text is the actual value between the tags (the username).
                target_user = data_element.text
                break  # Found it — no need to keep looking.

        # If we couldn't find a username (rare but possible), skip this event.
        if not target_user:
            continue

        # --- INCREMENT THE COUNT ---
        # .get(key, default) returns the current count, or 0 if this is
        # the first time we're seeing this account. Then we add 1.
        failed_counts[target_user] = failed_counts.get(target_user, 0) + 1

    # --- CHECK WHICH ACCOUNTS EXCEEDED THE THRESHOLD ---
    # .items() gives us each key-value pair: (account_name, count).
    for account, count in failed_counts.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            findings.append({
                "rule": "Brute Force Attempt",
                "severity": "HIGH",
                "details": (
                    f"Account '{account}' had {count} failed login attempts. "
                    f"Threshold is {BRUTE_FORCE_THRESHOLD}. "
                    f"This may indicate a password guessing attack."
                ),
            })

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
                f"Verify this was authorized — attackers create backdoor accounts."
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
        added_by = None
        group_name = None

        for data_element in xml_tree.findall(f"{NS}EventData/{NS}Data"):
            name = data_element.get("Name")
            if name == "MemberName":
                # MemberName is the account that was ADDED to the group.
                member_added = data_element.text
            elif name == "SubjectUserName":
                # SubjectUserName is the account that DID the adding.
                added_by = data_element.text
            elif name == "TargetUserName":
                # TargetUserName here is actually the GROUP name
                # (confusing, but that's how Microsoft named it).
                group_name = data_element.text

        findings.append({
            "rule": "Privilege Escalation",
            "severity": "HIGH",
            "details": (
                f"'{member_added or 'Unknown'}' was added to security group "
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
                f"RDP access should be monitored closely — attackers use it "
                f"for full interactive control of the machine."
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
                f"This is a critical finding — attackers disable AV to "
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
        # The "ProfileName" field tells us which firewall profile was
        # affected: "Domain", "Private", or "Public".
        xml_tree = ET.fromstring(event["data"])

        profile = None
        for data_element in xml_tree.findall(f"{NS}EventData/{NS}Data"):
            if data_element.get("Name") == "ProfileName":
                profile = data_element.text
                break

        findings.append({
            "rule": "Firewall Disabled",
            "severity": "HIGH",
            "details": (
                f"Windows Firewall profile '{profile or 'Unknown'}' was changed "
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
                f"Verify this was an authorized change — attackers modify "
                f"firewall rules to allow C2 traffic or open backdoor ports."
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
    findings += detect_service_installed(events) or []
    findings += detect_av_disabled(events) or []
    findings += detect_firewall_disabled(events) or []
    findings += detect_firewall_rule_change(events) or []
    return findings
