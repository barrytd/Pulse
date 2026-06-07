# Pulse sample data

Five synthetic `.evtx` files demonstrating different attack scenarios, plus a sample `pfirewall.log`. Upload any of them via the dashboard's drop zone (or `python main.py --logs samples/`) to see Pulse in action without needing access to a real Windows domain.

## How to use

```bash
# CLI — scan one file, save HTML report
python main.py --logs samples/ --format html

# Or via the dashboard:
python main.py --api
# then drag samples/brute-force-server.evtx onto the upload zone at http://localhost:8000
```

## Format

These are **Pulse-synthetic .evtx** files — they begin with the standard `ElfFile\x00` magic header (so the upload validator accepts them) followed by a `PULSE-SYNTH-v1\n` sentinel and a UTF-8 JSON event list. The parser detects the sentinel and routes to the JSON reader; real binary `.evtx` files are unaffected.

To regenerate / customize, edit and rerun `scripts/generate_sample_evtx.py`. The script is the source of truth; the files in this directory are its output.

## What each file demonstrates

| File | Scenario | Events | Triggers | Expected score |
|---|---|---:|---|:---:|
| **brute-force-server.evtx** | Domain controller under brute-force attack. ~150 normal interactive logons across the morning, then 15 failed logons from `203.0.113.54` against `Administrator` in 2 minutes, followed by a successful logon from the same IP and a new user creation. Plus 3 stray failures from `198.51.100.88` and an account lockout on a different account. | 171 | 🔴 CRITICAL · Account Takeover Chain<br/>🟠 HIGH · Brute Force Attempt<br/>🟠 HIGH · Pass-the-Hash Attempt<br/>🟠 HIGH · Account Lockout<br/>🟡 MEDIUM · User Account Created | **F** |
| **credential-theft-workstation.evtx** | Compromised finance workstation. Outlook spawns `cmd.exe` → encoded PowerShell → `mimikatz.exe` + `procdump64.exe` accessing LSASS. Explicit-credential logon (4648), NTLM network logon (4624 type 3), and `tlowe` added to `Domain Admins`. | 7 | 🔴 CRITICAL · Credential Dumping<br/>🟠 HIGH · Suspicious Child Process<br/>🟠 HIGH · Pass-the-Hash Attempt<br/>🟠 HIGH · Privilege Escalation | **F** |
| **persistence-malware.evtx** | Malware persistence on a web server. Defender real-time protection disabled, then a new auto-start service installed running encoded PowerShell, a scheduled task pointing at the same binary, a Run-key registry write, and a firewall rule opening port 4444 inbound. | 5 | 🔴 CRITICAL · Malware Persistence Chain<br/>🟠 HIGH · Antivirus Disabled<br/>🟠 HIGH · Suspicious Registry Modification<br/>🟡 MEDIUM · Service Installed<br/>🟡 MEDIUM · Scheduled Task Created<br/>🟡 MEDIUM · Firewall Rule Changed | **F** |
| **lateral-movement-dc.evtx** | Active Directory attack on a domain controller. Kerberoasting (3× TGS requests for SPNs with RC4 encryption), a Golden Ticket signal (4768 for `krbtgt` with multi-year lifetime), DCSync (4662 with the `DS-Replication-Get-Changes` GUIDs from a non-DC account), admin-share access (`C$` + `ADMIN$` + PsExec), and an audit-log clear. | 8 | 🔴 CRITICAL · DCSync Attempt<br/>🔴 CRITICAL · Golden Ticket<br/>🟠 HIGH · Kerberoasting<br/>🟠 HIGH · Lateral Movement via Network Share<br/>🟠 HIGH · Audit Log Cleared | **F** |
| **sysmon-execution-chain.evtx** | Sysmon process-execution chain on a finance workstation. Every event is a Sysmon Event 1 (process create) from the `Microsoft-Windows-Sysmon` provider — showcasing the full-command-line visibility Sysmon adds over the Security log. A phishing `.docm` spawns `cmd.exe` → encoded PowerShell stager → `certutil` LOLBin download → `comsvcs.dll MiniDump` against LSASS. | 4 | 🟠 HIGH · Suspicious Process Creation (×4) | **F** |
| **sample-pfirewall.log** | Windows Firewall log with a mix of normal traffic, port-scan probes from public IPs against 3389/22/445, and a `DROP` cluster. Drop on the Firewall Log tab (Firewall page) to see the parser surface suspicious activity. | n/a | 🟠 HIGH · Firewall Repeated Drops<br/>🟡 MEDIUM · Suspicious Outbound | n/a |

## A note on the data

Every IP, hostname, and user name in these samples is synthetic. External IPs use the IETF documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`) so they can never collide with a real host. Account names are obvious placeholders (`tlowe`, `kparker`, `Administrator`) — none correspond to real people. Service principals and computer names use `acme.local`, the most common documentation domain.

The scenarios are based on real ATT&CK technique chains but compressed in time + simplified for clarity. A real incident would have far more noise around each signal.

## Antivirus note

These `.evtx` files deliberately **do not** contain the literal credential-dumping module command strings (e.g. the Mimikatz `sekurlsa::` / `lsadump::` commands). Endpoint antivirus scans file *content* for those strings and would otherwise quarantine the samples as `HackTool:Win32/Mimikatz` the moment you clone the repo — even though they're harmless synthetic logs. The scenarios still demonstrate credential theft through techniques the detections catch (suspicious binary names, LSASS handle access, the `comsvcs.dll MiniDump` LOLBin) without carrying the AV-trigger strings. The `samples/sigma/` rule files are the exception: a SIGMA rule that *detects* Mimikatz must contain those strings to match, the same way an antivirus signature database does.
