"""Plain-language security knowledge base.

Pulse's differentiator is that it ships to people who don't have a SOC.
A small-business IT admin, a freelancer, a student, a 3-person startup
without a security team — they need a tool that explains *what they're
looking at* and *what to do right now*, not just an alert.

This module maps every detection rule to a knowledge entry written for
that audience. The finding drawer renders it as a "Security Guide"
card between the description and the (more technical) Remediation
card. The Security Advisor sidebar page reads from the same source.

Each entry has:

    plain_language          one sentence, no jargon, what happened
    why_it_matters          one short paragraph on the real-world impact
    immediate_actions       ordered list of concrete steps for right now
    prevention              how to stop this from happening again
    learn_more              list of {label, url} — MITRE + vendor docs
    difficulty              "low" | "medium" | "high" — how easy to pull off
    common_false_positives  bulleted scenarios where the rule fires legit

Editorial rules:
    - No assumed background. Skip "NTLM", "SID", "RC4". Say "older
      authentication method", "user identifier", "weak encryption".
    - Action verbs first: "Change the password.", not "Password change
      is recommended."
    - Difficulty rates *exploit difficulty*, not detection difficulty.
      `low` = anyone running a public tool can do this;
      `medium` = needs some knowledge or pre-existing access;
      `high`  = takes real skill / multiple steps / specialized tools.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# Generic learn-more block for MITRE technique pages. Built once at the
# bottom of each entry so we don't repeat the URL pattern 30 times.
def _mitre(tid: str, label: Optional[str] = None) -> Dict[str, str]:
    return {
        "label": label or f"MITRE ATT&CK {tid}",
        "url":   f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
    }


KNOWLEDGE: Dict[str, Dict[str, Any]] = {

    # -------------------------------------------------------------
    # Authentication / credential rules
    # -------------------------------------------------------------
    "Brute Force Attempt": {
        "plain_language": (
            "Someone is repeatedly trying to log in with the wrong password — "
            "almost certainly guessing or running a password-cracking tool."
        ),
        "why_it_matters": (
            "If the attacker guesses the right password, they get the same "
            "access the real owner of that account has. If the account has "
            "admin rights or access to sensitive data, this can become a "
            "full takeover quickly."
        ),
        "immediate_actions": [
            "Check whether the account being targeted is a real, active user.",
            "If the source IP is external and unexpected, block it at the firewall.",
            "Force a password reset on the targeted account.",
            "Turn on multi-factor authentication for that account.",
        ],
        "prevention": (
            "Enforce account lockouts after 5 failed attempts. Require MFA "
            "on every account that has remote access (RDP, VPN, email). Use "
            "long passphrases (12+ characters) so guessing becomes impractical."
        ),
        "learn_more": [
            _mitre("T1110", "Brute Force"),
            {"label": "Microsoft: Account lockout policy",
             "url": "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/account-lockout-policy"},
        ],
        "difficulty": "low",
        "common_false_positives": [
            "A user genuinely forgetting their password and trying several variants.",
            "An app or service running with a stale, cached password after a recent reset.",
            "Backup software or a scheduled task using an expired credential.",
        ],
    },

    "User Account Created": {
        "plain_language": (
            "A new user account was just added to this computer or domain."
        ),
        "why_it_matters": (
            "Attackers who break in often create their own user account as "
            "a backdoor so they can come back later, even after the original "
            "entry point is patched. Every new account is worth a sanity check."
        ),
        "immediate_actions": [
            "Confirm with whoever administers this system that the new account is expected.",
            "If it was not authorized, disable it immediately.",
            "Check what groups the new account was added to — admin rights are a red flag.",
            "Review what the account has done since it was created.",
        ],
        "prevention": (
            "Restrict account creation to a small group of trusted admins. "
            "Send an email or chat notification whenever a new account is created."
        ),
        "learn_more": [
            _mitre("T1136.001", "Create Account: Local Account"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Normal onboarding of a new employee.",
            "Automated user provisioning from an HR system.",
        ],
    },

    "Privilege Escalation": {
        "plain_language": (
            "A user was just added to a powerful security group (like Administrators)."
        ),
        "why_it_matters": (
            "Whoever owns that account now has admin powers — they can install "
            "software, read any file, and turn off your security tools. If "
            "the change wasn't approved, treat this as an active breach."
        ),
        "immediate_actions": [
            "Confirm the change was authorized by the IT owner of the account.",
            "If not, remove the user from the group right now.",
            "Find out who made the change — that account may also be compromised.",
            "Reset both passwords (the elevated user and whoever made the change).",
        ],
        "prevention": (
            "Use the principle of least privilege: regular users do not need "
            "admin rights. Require change approval for any group membership "
            "change to Administrators / Domain Admins."
        ),
        "learn_more": [
            _mitre("T1548", "Abuse Elevation Control Mechanism"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Planned promotion of a user to admin during onboarding.",
            "Routine IT administration during a maintenance window.",
        ],
    },

    "Audit Log Cleared": {
        "plain_language": (
            "Someone wiped the Windows security event log."
        ),
        "why_it_matters": (
            "Attackers clear logs to hide their tracks. Legitimate users "
            "almost never do this. If you didn't clear the log yourself, "
            "assume something happened that someone is trying to cover up."
        ),
        "immediate_actions": [
            "Identify the account that cleared the log.",
            "Pull any backup or forwarded copies of the log from before it was cleared.",
            "Treat the host as compromised until proven otherwise.",
            "Reset the password of the account that performed the clear.",
        ],
        "prevention": (
            "Forward security logs in real time to a central server "
            "(Windows Event Forwarding, syslog, or a SIEM) so a local "
            "wipe doesn't destroy your only copy."
        ),
        "learn_more": [
            _mitre("T1070.001", "Indicator Removal: Clear Windows Event Logs"),
        ],
        "difficulty": "low",
        "common_false_positives": [
            "An admin clearing the log during planned maintenance or before reimaging.",
        ],
    },

    "RDP Logon Detected": {
        "plain_language": (
            "Someone logged into this computer remotely using Remote Desktop."
        ),
        "why_it_matters": (
            "RDP is one of the most common ways attackers get in once they "
            "have a working password. Every RDP login is worth confirming, "
            "especially from an IP you don't recognize."
        ),
        "immediate_actions": [
            "Verify the login was from a real user, not an attacker who has the password.",
            "Check the source IP — if it's external or unfamiliar, treat it as suspicious.",
            "If the login was unauthorized, disconnect the session and change the password.",
        ],
        "prevention": (
            "Don't expose RDP directly to the internet — put it behind a VPN. "
            "Require MFA. Lock RDP down to specific source IPs at the firewall."
        ),
        "learn_more": [
            _mitre("T1021.001", "Remote Services: Remote Desktop Protocol"),
        ],
        "difficulty": "low",
        "common_false_positives": [
            "Normal remote work by an admin or developer.",
            "IT support remoting in to fix something.",
        ],
    },

    "Pass-the-Hash Attempt": {
        "plain_language": (
            "Someone logged in using a stolen password fingerprint instead of "
            "the actual password — a known attacker technique."
        ),
        "why_it_matters": (
            "This means an attacker probably already stole the password "
            "fingerprint from another machine. They're now moving sideways "
            "through your network. This is mid-attack, not early-stage."
        ),
        "immediate_actions": [
            "Identify the account being impersonated and reset its password right away.",
            "Find the computer where the fingerprint was originally stolen — "
            "it's compromised.",
            "Disconnect the affected machines from the network until you investigate.",
            "Look for other logins from the same account in the last 7 days.",
        ],
        "prevention": (
            "Don't let admins log into regular workstations with their admin "
            "accounts. Use Windows Credential Guard. Disable older NTLM "
            "authentication where you can."
        ),
        "learn_more": [
            _mitre("T1550.002", "Use Alternate Authentication Material: Pass the Hash"),
        ],
        "difficulty": "high",
        "common_false_positives": [
            "Very rare — most legitimate logins do not trigger this pattern.",
        ],
    },

    "Account Lockout": {
        "plain_language": (
            "A user account got locked because of too many wrong passwords."
        ),
        "why_it_matters": (
            "Lockouts are usually either a forgetful user or an active "
            "password-guessing attack. Repeated lockouts on the same account, "
            "especially privileged ones, are a strong attack signal."
        ),
        "immediate_actions": [
            "Ask the user if they were trying to log in.",
            "If not, check the source of the failed attempts — likely an attacker.",
            "Block the source IP at the firewall if external.",
            "Reset the password and turn on MFA for the account.",
        ],
        "prevention": (
            "Set a sensible lockout threshold (5-10 attempts). Notify the "
            "user and an admin every time it happens."
        ),
        "learn_more": [
            _mitre("T1110", "Brute Force"),
        ],
        "difficulty": "low",
        "common_false_positives": [
            "User forgot password after a recent reset.",
            "Old saved credentials in a phone or app trying to sync.",
        ],
    },

    "Logon from Disabled Account": {
        "plain_language": (
            "Someone tried to log in using an account that was disabled — "
            "probably a former employee's old account."
        ),
        "why_it_matters": (
            "Attackers often try old, disabled, or forgotten accounts because "
            "those passwords don't get rotated. A real user wouldn't get this "
            "error — they'd know their account is gone."
        ),
        "immediate_actions": [
            "Confirm the account should still be disabled (no surprise re-hire).",
            "Identify the source machine and IP — if external, block it.",
            "Check whether the disabled account's password was leaked anywhere.",
        ],
        "prevention": (
            "Delete (don't just disable) terminated employee accounts after "
            "a short grace period. Rotate any shared service-account "
            "passwords when someone with knowledge of them leaves."
        ),
        "learn_more": [
            _mitre("T1078", "Valid Accounts"),
        ],
        "difficulty": "low",
        "common_false_positives": [
            "Re-hire whose account was disabled but not yet re-enabled.",
        ],
    },

    "After-Hours Logon": {
        "plain_language": (
            "Someone logged in outside of typical business hours."
        ),
        "why_it_matters": (
            "Attackers often work when nobody is watching — nights and "
            "weekends. By itself this isn't proof of an attack, but "
            "combined with other red flags it strongly suggests one."
        ),
        "immediate_actions": [
            "Confirm with the user whether they actually logged in then.",
            "Look at what the account did during that session — files opened, "
            "software run, network connections made.",
        ],
        "prevention": (
            "Set login-hour restrictions on accounts that should only work "
            "business hours. Alert admins on unusual login times."
        ),
        "learn_more": [
            _mitre("T1078", "Valid Accounts"),
        ],
        "difficulty": "low",
        "common_false_positives": [
            "Someone genuinely working late or on the weekend.",
            "A scheduled task running under a user account.",
            "A user in a different time zone.",
        ],
    },

    # -------------------------------------------------------------
    # Persistence
    # -------------------------------------------------------------
    "Service Installed": {
        "plain_language": (
            "A new Windows service was installed on this computer."
        ),
        "why_it_matters": (
            "Attackers install services as a way to keep their access — "
            "services start automatically on every reboot. If you didn't "
            "install software recently, treat any new service as suspicious."
        ),
        "immediate_actions": [
            "Find the service in services.msc and look at what file it runs.",
            "Confirm the file is from a vendor you trust.",
            "If you don't recognize it, stop and disable the service, then quarantine the file.",
        ],
        "prevention": (
            "Limit who can install software to admins only. Use Application "
            "Allowlisting (Microsoft Defender Application Control) on critical hosts."
        ),
        "learn_more": [
            _mitre("T1543.003", "Create or Modify System Process: Windows Service"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Installing legitimate software (antivirus, backup agent, etc).",
            "Windows updates that add new services.",
        ],
    },

    "Scheduled Task Created": {
        "plain_language": (
            "Someone created a scheduled task — a job that runs automatically "
            "at a set time or on a trigger."
        ),
        "why_it_matters": (
            "Like services, scheduled tasks are a common way attackers keep "
            "access. A task that runs every hour as SYSTEM is a great hiding "
            "spot for malware."
        ),
        "immediate_actions": [
            "Open Task Scheduler and find the task.",
            "Look at what command it runs and who it runs as.",
            "If it runs anything from a temp folder or AppData, treat it as suspicious.",
            "Delete the task and check for related changes (services, registry).",
        ],
        "prevention": (
            "Restrict task creation to admins where possible. Review the "
            "scheduled-task inventory regularly so new entries stand out."
        ),
        "learn_more": [
            _mitre("T1053.005", "Scheduled Task/Job: Scheduled Task"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Legitimate apps creating update-check tasks (Chrome, Adobe, etc).",
            "IT scripts that schedule recurring maintenance jobs.",
        ],
    },

    "Suspicious Registry Modification": {
        "plain_language": (
            "Something just changed a Windows registry key that controls what "
            "runs automatically when the computer starts."
        ),
        "why_it_matters": (
            "These registry keys are the #1 spot malware hides. By writing "
            "itself here, the attacker makes sure their code runs every time "
            "you boot up — even after you 'clean' the system."
        ),
        "immediate_actions": [
            "Identify the value that was added and what file it points to.",
            "Scan that file with antivirus.",
            "Remove the registry entry if it's malicious.",
            "Look for other persistence mechanisms (services, scheduled tasks).",
        ],
        "prevention": (
            "Use a tool like Autoruns or Microsoft Defender for Endpoint to "
            "regularly audit what runs at startup."
        ),
        "learn_more": [
            _mitre("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Installing software that legitimately adds itself to startup.",
        ],
    },

    # -------------------------------------------------------------
    # Defense evasion / endpoint manipulation
    # -------------------------------------------------------------
    "Antivirus Disabled": {
        "plain_language": (
            "Windows Defender (or another antivirus) was just turned off."
        ),
        "why_it_matters": (
            "This is one of the first things an attacker does once they get "
            "in — they shut off the thing watching them. If you didn't "
            "disable AV yourself, assume something is being run that AV "
            "would have flagged."
        ),
        "immediate_actions": [
            "Turn antivirus back on immediately.",
            "Run a full scan.",
            "Find what disabled it (process, scheduled task, GPO).",
            "Treat the host as compromised until the scan comes back clean.",
        ],
        "prevention": (
            "Use Microsoft Defender's tamper protection so it can't be turned "
            "off by local admins. Push security settings via Group Policy so "
            "they get re-applied automatically."
        ),
        "learn_more": [
            _mitre("T1562.001", "Impair Defenses: Disable or Modify Tools"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Troubleshooting a software compatibility issue (an admin "
            "temporarily turning AV off).",
        ],
    },

    "Firewall Disabled": {
        "plain_language": (
            "The Windows Firewall was just turned off on this computer."
        ),
        "why_it_matters": (
            "With the firewall off, anything on the network can reach this "
            "machine. Attackers turn it off so their tools can communicate "
            "back to them without being blocked."
        ),
        "immediate_actions": [
            "Turn the firewall back on right away.",
            "Find out what process or account disabled it.",
            "Check what new network connections happened while it was off.",
        ],
        "prevention": (
            "Enforce firewall on via Group Policy so a local change gets "
            "reverted on the next refresh."
        ),
        "learn_more": [
            _mitre("T1562.004", "Impair Defenses: Disable or Modify System Firewall"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "An admin disabling it temporarily for troubleshooting.",
        ],
    },

    "Firewall Rule Changed": {
        "plain_language": (
            "A firewall rule was added or changed."
        ),
        "why_it_matters": (
            "Attackers punch holes in the firewall to let their tools talk to "
            "the outside world, or to let themselves back in later. A rule "
            "change you don't recognize is a red flag."
        ),
        "immediate_actions": [
            "Look at what the rule allows — which ports, which direction.",
            "Confirm with whoever administers the host that the change was intended.",
            "If it wasn't, delete the rule and investigate further.",
        ],
        "prevention": (
            "Lock down who can modify firewall rules. Review the active rule "
            "set monthly."
        ),
        "learn_more": [
            _mitre("T1562.004", "Impair Defenses: Disable or Modify System Firewall"),
        ],
        "difficulty": "low",
        "common_false_positives": [
            "Installing software that legitimately needs a firewall exception.",
            "An IT admin opening a port for a new service.",
        ],
    },

    "Firewall Profile Disabled": {
        "plain_language": (
            "A Windows Firewall profile (Domain, Private, or Public) is "
            "currently turned off."
        ),
        "why_it_matters": (
            "Same impact as turning the firewall off entirely on that "
            "network type — the machine is exposed."
        ),
        "immediate_actions": [
            "Re-enable the profile from Windows Defender Firewall settings.",
            "Investigate why it was off — was it manual or via Group Policy?",
        ],
        "prevention": (
            "Force all three profiles on via Group Policy."
        ),
        "learn_more": [
            _mitre("T1562.004"),
        ],
        "difficulty": "low",
        "common_false_positives": [
            "Intentional disable for testing or troubleshooting.",
        ],
    },

    "Firewall Any-Any Allow Rule": {
        "plain_language": (
            "A firewall rule exists that allows all traffic from any source — "
            "essentially leaving the door wide open."
        ),
        "why_it_matters": (
            "Any-any allow rules defeat the point of a firewall. They're "
            "often added during troubleshooting and then forgotten."
        ),
        "immediate_actions": [
            "Find the rule and check if it's still needed.",
            "Replace it with a narrow rule (specific port, specific source).",
            "Delete it if there's no good reason to keep it.",
        ],
        "prevention": (
            "Code-review firewall changes the same way you would code changes."
        ),
        "learn_more": [
            _mitre("T1562.004"),
        ],
        "difficulty": "low",
        "common_false_positives": [
            "Rules intentionally configured on isolated lab networks.",
        ],
    },

    "Firewall Overly Broad Scope": {
        "plain_language": (
            "A firewall rule is allowing more traffic than it probably should."
        ),
        "why_it_matters": (
            "Broad rules increase what an attacker can reach if they get into "
            "the network. Tighter rules reduce the blast radius of any breach."
        ),
        "immediate_actions": [
            "Review the rule's scope.",
            "Narrow the allowed source / destination / port to the minimum.",
        ],
        "prevention": (
            "When creating rules, default to the narrowest scope that still "
            "works."
        ),
        "learn_more": [
            _mitre("T1562.004"),
        ],
        "difficulty": "low",
        "common_false_positives": [
            "Broad rules legitimately needed for internal infrastructure "
            "(e.g. domain controllers).",
        ],
    },

    # -------------------------------------------------------------
    # Execution / PowerShell
    # -------------------------------------------------------------
    "Suspicious PowerShell": {
        "plain_language": (
            "PowerShell ran a command that looks like an attacker's hiding "
            "technique — encoded text, downloaded scripts, or unusual flags."
        ),
        "why_it_matters": (
            "Encoded PowerShell is one of the most common ways attackers run "
            "their tools on Windows. Legitimate admin scripts rarely need to "
            "hide what they're doing."
        ),
        "immediate_actions": [
            "Decode the command to see what it actually ran.",
            "Look at what files it touched and what network connections it made.",
            "If it ran malware, isolate the host from the network.",
        ],
        "prevention": (
            "Turn on PowerShell script-block logging and constrained language "
            "mode. Restrict who can run PowerShell on production hosts."
        ),
        "learn_more": [
            _mitre("T1059.001", "Command and Scripting Interpreter: PowerShell"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Sysadmin scripts that legitimately use encoded commands for "
            "deployment automation.",
        ],
    },

    "Suspicious Process Creation": {
        "plain_language": (
            "A program started with a command line that matches a known "
            "attacker technique — like a built-in Windows tool being used "
            "to download a file, or an Office app launching a command "
            "prompt."
        ),
        "why_it_matters": (
            "Attackers prefer to 'live off the land' — abusing tools that "
            "ship with Windows (certutil, rundll32, mshta) so antivirus "
            "doesn't flag a new file. The command line is the giveaway. "
            "This detection needs Sysmon, which records the full command "
            "line that the standard Windows log usually leaves out."
        ),
        "immediate_actions": [
            "Read the full command line to see what the process was doing.",
            "Check what the process's parent was — an Office app or browser "
            "spawning a shell is a strong malware signal.",
            "Look at what files or network connections followed it.",
            "If it pulled down or ran a payload, isolate the host.",
        ],
        "prevention": (
            "Deploy Sysmon with a tuned config (the SwiftOnSecurity baseline "
            "is a good start) on every host. Block or restrict the common "
            "living-off-the-land binaries where your environment doesn't "
            "need them, and enable attack-surface-reduction rules."
        ),
        "learn_more": [
            _mitre("T1059", "Command and Scripting Interpreter"),
            _mitre("T1218", "System Binary Proxy Execution (LOLBins)"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Software-deployment tools and installers that legitimately use "
            "certutil, msbuild, or encoded PowerShell.",
            "Admin automation that spawns shells from scripting hosts.",
        ],
    },

    "LSASS Memory Access": {
        "plain_language": (
            "A program tried to read the memory of LSASS — the Windows "
            "process that holds everyone's passwords, password hashes, and "
            "login tickets — and it wasn't one of the few programs that's "
            "supposed to."
        ),
        "why_it_matters": (
            "This is one of the most reliable signs of an active attack. "
            "Reading LSASS memory is how attackers harvest credentials to "
            "move from one machine to the rest of your network. If this "
            "fired, assume the passwords and hashes on this host are "
            "already in the attacker's hands."
        ),
        "immediate_actions": [
            "Isolate the host from the network immediately.",
            "Identify the program that accessed LSASS and where it came from.",
            "Force-reset passwords for every account that logged into this "
            "host recently — especially admins.",
            "Rotate the computer account and any cached service-account "
            "credentials.",
        ],
        "prevention": (
            "Turn on LSASS protection (RunAsPPL / Credential Guard). Keep "
            "Sysmon deployed so you see these handle requests. Limit which "
            "accounts have admin rights, since reading LSASS requires them."
        ),
        "learn_more": [
            _mitre("T1003.001", "OS Credential Dumping: LSASS Memory"),
        ],
        "difficulty": "low",
        "common_false_positives": [
            "Some endpoint-protection and backup agents read LSASS; if you "
            "recognize the source program, add it to your allow-list.",
        ],
    },

    # -------------------------------------------------------------
    # Command and control
    # -------------------------------------------------------------
    "Suspicious Network Connection": {
        "plain_language": (
            "A program that normally has no reason to talk to the internet "
            "made an outbound connection — or a connection went to a port "
            "commonly used by hacking tools."
        ),
        "why_it_matters": (
            "After breaking in, attackers need a way to control the machine "
            "remotely and pull down more tools. When a utility like "
            "PowerShell or rundll32 reaches out to the internet, it's often "
            "phoning home to the attacker's server."
        ),
        "immediate_actions": [
            "Look up the destination address — check its reputation.",
            "Identify the program that opened the connection and what "
            "started it.",
            "Block the destination at the firewall and isolate the host if "
            "the connection looks like command-and-control.",
        ],
        "prevention": (
            "Restrict outbound traffic so only approved programs reach the "
            "internet. Block the common command-and-control ports at the "
            "perimeter. Keep an eye on tools that shouldn't make network "
            "connections."
        ),
        "learn_more": [
            _mitre("T1071", "Application Layer Protocol"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Admin scripts that legitimately download updates or call an "
            "internal API over PowerShell.",
        ],
    },

    "Suspicious DNS Query": {
        "plain_language": (
            "A program looked up a domain name that's abnormally long or "
            "random-looking, which is how attackers sneak data out of a "
            "network or hide their command channel inside ordinary-looking "
            "DNS traffic."
        ),
        "why_it_matters": (
            "DNS is allowed out of almost every network, so attackers abuse "
            "it to tunnel stolen data or talk to their servers without "
            "tripping firewalls. Very long or gibberish domain names are a "
            "classic tunneling signature."
        ),
        "immediate_actions": [
            "Identify the program making the queries and the parent domain.",
            "Check whether large amounts of DNS traffic are going to one "
            "domain — a sign of tunneling.",
            "Block the domain and isolate the host if it looks like active "
            "exfiltration.",
        ],
        "prevention": (
            "Route DNS through a filtering resolver that blocks known-bad "
            "and newly-registered domains. Alert on abnormally long query "
            "names. Restrict which hosts can query external DNS directly."
        ),
        "learn_more": [
            _mitre("T1071.004", "Application Layer Protocol: DNS"),
            _mitre("T1572", "Protocol Tunneling"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Some content-delivery networks and security products use long, "
            "auto-generated subdomains that can look like tunneling.",
        ],
    },

    # -------------------------------------------------------------
    # Credential access
    # -------------------------------------------------------------
    "Kerberoasting": {
        "plain_language": (
            "Someone is trying to crack a service account password by "
            "tricking the domain into handing them an encrypted ticket."
        ),
        "why_it_matters": (
            "Service accounts often have powerful permissions and rarely "
            "have their passwords rotated. If the attacker cracks the "
            "password offline, they get whatever that service can do — "
            "which is often a lot."
        ),
        "immediate_actions": [
            "Identify which service accounts were targeted.",
            "Check if those accounts have weak or old passwords.",
            "Rotate the passwords to long, random ones (25+ characters).",
            "Switch the accounts to use AES encryption instead of older "
            "encryption types if you can.",
        ],
        "prevention": (
            "Use Group Managed Service Accounts (gMSAs) where possible — "
            "Windows rotates their passwords automatically. Avoid putting "
            "regular user accounts in service-account roles."
        ),
        "learn_more": [
            _mitre("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting"),
        ],
        "difficulty": "high",
        "common_false_positives": [
            "Rare — most legitimate apps don't request tickets in this pattern.",
        ],
    },

    "Golden Ticket": {
        "plain_language": (
            "Someone is using a forged authentication ticket to impersonate "
            "any user — including domain admins — without needing a password."
        ),
        "why_it_matters": (
            "This is one of the worst things you can see in a Windows "
            "environment. The attacker has already compromised the domain "
            "controller and stolen its master key. They can be anyone, do "
            "anything, and the only way to recover is to reset the key twice."
        ),
        "immediate_actions": [
            "Treat the domain as fully compromised.",
            "Reset the krbtgt account password twice (Microsoft has a script for this).",
            "Plan for a full domain rebuild — this attack is hard to truly clean.",
            "Engage incident response support if you can.",
        ],
        "prevention": (
            "Protect domain controllers like crown jewels. Restrict who can "
            "log into them. Monitor for unusual ticket requests."
        ),
        "learn_more": [
            _mitre("T1558.001", "Steal or Forge Kerberos Tickets: Golden Ticket"),
        ],
        "difficulty": "high",
        "common_false_positives": [
            "Almost none — this rule rarely fires on benign activity.",
        ],
    },

    "Credential Dumping": {
        "plain_language": (
            "Something is trying to read the area of memory where Windows "
            "stores password fingerprints — the classic credential-stealing move."
        ),
        "why_it_matters": (
            "If the dump succeeds, the attacker walks away with the password "
            "fingerprints of everyone who has logged into this machine — "
            "including any admin who fixed something recently."
        ),
        "immediate_actions": [
            "Identify the process doing the reading.",
            "If it's not a legit security tool, treat the host as compromised.",
            "Reset the passwords of everyone who has logged into this machine recently.",
        ],
        "prevention": (
            "Turn on Windows Credential Guard. Don't let admins log into "
            "regular workstations with their domain admin accounts."
        ),
        "learn_more": [
            _mitre("T1003.001", "OS Credential Dumping: LSASS Memory"),
        ],
        "difficulty": "high",
        "common_false_positives": [
            "Legitimate EDR / antivirus tools may trigger this — verify the "
            "process is a known security tool before assuming the worst.",
        ],
    },

    # -------------------------------------------------------------
    # Lateral movement
    # -------------------------------------------------------------
    "Lateral Movement via Network Share": {
        "plain_language": (
            "Someone connected from one computer on your network to another "
            "via a file share. Attackers do this to spread."
        ),
        "why_it_matters": (
            "Once an attacker has one foothold, they look for ways to jump to "
            "other machines. Network shares are a common path. Spotting this "
            "early limits how far they get."
        ),
        "immediate_actions": [
            "Confirm the source and destination machines belong to the same user.",
            "Check what files were accessed during the connection.",
            "If unauthorized, isolate the source host — it's the foothold.",
        ],
        "prevention": (
            "Limit who can connect to administrative shares (C$, ADMIN$). "
            "Segment your network so workstations can't share-connect to each other."
        ),
        "learn_more": [
            _mitre("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Normal file sharing between users.",
            "Backup software accessing remote shares.",
        ],
    },

    # -------------------------------------------------------------
    # Multi-event chains
    # -------------------------------------------------------------
    "Account Takeover Chain": {
        "plain_language": (
            "A sequence of events looks like an attacker took over an "
            "account: failed logins, then a success, then suspicious activity."
        ),
        "why_it_matters": (
            "Chain rules fire only when multiple things line up — they're "
            "high-confidence signals. If you see this, an attack is in progress."
        ),
        "immediate_actions": [
            "Reset the affected account's password immediately.",
            "End any active sessions for that account.",
            "Audit everything the account has done in the last 24 hours.",
            "Turn on MFA if it wasn't already.",
        ],
        "prevention": (
            "Enforce MFA on every account that can log in from outside. "
            "Lockout policies. Phishing-resistant authentication."
        ),
        "learn_more": [
            _mitre("T1078", "Valid Accounts"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Very rare — chains require multiple signals.",
        ],
    },

    "Malware Persistence Chain": {
        "plain_language": (
            "A sequence of events looks like malware installing itself to "
            "survive reboots — files dropped, then auto-start configured."
        ),
        "why_it_matters": (
            "This is mid-attack. The attacker is establishing long-term "
            "presence. Move fast — every hour they stay in, they spread further."
        ),
        "immediate_actions": [
            "Isolate the host from the network.",
            "Identify the persistence mechanism (service, scheduled task, registry).",
            "Remove it and any dropper files.",
            "Reset credentials used on the machine in the last 7 days.",
            "Consider a full reimage if you can't confidently identify all changes.",
        ],
        "prevention": (
            "Application allowlisting. Restrict admin rights on workstations. "
            "Keep endpoint detection turned on."
        ),
        "learn_more": [
            _mitre("T1543.003"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Very rare.",
        ],
    },

    "Brute-Force Success": {
        "plain_language": (
            "Many failed logins were followed by a successful one from the "
            "same source — an attacker probably just guessed a password."
        ),
        "why_it_matters": (
            "This is the moment an attack stops being an attempt and starts "
            "being a breach. Whatever access that account had, the attacker "
            "now has."
        ),
        "immediate_actions": [
            "Reset that account's password immediately.",
            "End every active session for the account.",
            "Block the source IP at the firewall.",
            "Audit what the account did after the successful login.",
            "Turn on MFA for the account.",
        ],
        "prevention": (
            "MFA on every remote-access account. Strong passwords. Lockout "
            "policies that kick in long before an attacker can guess right."
        ),
        "learn_more": [
            _mitre("T1110.001", "Brute Force: Password Guessing"),
            _mitre("T1078", "Valid Accounts"),
        ],
        "difficulty": "low",
        "common_false_positives": [
            "Very rare. A user who fat-fingered their password 5+ times "
            "before getting it right is possible but uncommon.",
        ],
    },

    "Impossible Travel": {
        "plain_language": (
            "The same user logged in from two different locations too far "
            "apart to physically travel between — meaning one of them isn't them."
        ),
        "why_it_matters": (
            "If a user authenticates from New York and then from Singapore "
            "60 seconds later, someone else has their credentials. The "
            "second login is the attacker."
        ),
        "immediate_actions": [
            "Reset the account's password.",
            "End all active sessions.",
            "Ask the user which of the two logins was actually them.",
            "Block the suspicious source IP.",
        ],
        "prevention": (
            "Turn on MFA, especially location-aware MFA. Use conditional "
            "access policies that block logins from unexpected countries."
        ),
        "learn_more": [
            _mitre("T1078"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "User on a VPN that changes their apparent location.",
            "Two devices syncing at the same time from different networks.",
        ],
    },

    "Privilege Escalation Chain": {
        "plain_language": (
            "An attacker created a new user and added it to an admin group "
            "within minutes — classic backdoor-account creation."
        ),
        "why_it_matters": (
            "This is the move attackers make to keep admin access even if "
            "their initial account gets caught. The new account looks "
            "normal at first glance."
        ),
        "immediate_actions": [
            "Disable the newly created account immediately.",
            "Identify who created it — that account is also compromised.",
            "Reset both passwords.",
            "Audit recent group membership changes for any other surprises.",
        ],
        "prevention": (
            "Require change approval for any admin-group addition. Alert on "
            "all account creations."
        ),
        "learn_more": [
            _mitre("T1098", "Account Manipulation"),
            _mitre("T1136.001"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Genuine onboarding flow where IT creates an account and "
            "immediately grants admin rights.",
        ],
    },

    "Lateral Spray": {
        "plain_language": (
            "One source machine just connected to many different computers "
            "in a short time — typical of an attacker mapping or spreading "
            "through the network."
        ),
        "why_it_matters": (
            "Normal users don't connect to dozens of machines in a few "
            "minutes. This pattern almost always means automated tooling — "
            "either yours (which you'd know about) or an attacker's."
        ),
        "immediate_actions": [
            "Identify the source machine — it's almost certainly compromised.",
            "Isolate it from the network.",
            "Reset credentials used on it recently.",
            "Investigate every host it touched.",
        ],
        "prevention": (
            "Network segmentation. Block workstation-to-workstation SMB at "
            "the firewall. Limit which accounts can connect across many hosts."
        ),
        "learn_more": [
            _mitre("T1021", "Remote Services"),
            _mitre("T1078"),
        ],
        "difficulty": "medium",
        "common_false_positives": [
            "Vulnerability scanners.",
            "Patching tools (WSUS, SCCM) doing their rounds.",
            "IT staff running an inventory sweep.",
        ],
    },
}


# A generic fallback so the UI never has to guard for missing entries.
_FALLBACK: Dict[str, Any] = {
    "plain_language": (
        "Something the detection engine flagged as worth a look. The technical "
        "description and event details below explain what fired the rule."
    ),
    "why_it_matters": (
        "Even when the meaning isn't obvious, every finding is worth a quick "
        "sanity check — most attacks are caught early because someone took "
        "the time to investigate a single odd alert."
    ),
    "immediate_actions": [
        "Read the description and event details for context.",
        "Compare against normal activity on this host.",
        "If anything looks off, isolate the host and dig deeper.",
    ],
    "prevention": (
        "Keep endpoint protection on, patch regularly, and limit who has "
        "admin rights."
    ),
    "learn_more": [
        {"label": "MITRE ATT&CK Tactics",
         "url": "https://attack.mitre.org/tactics/enterprise/"},
    ],
    "difficulty": "medium",
    "common_false_positives": [
        "Without rule-specific context, it's hard to say.",
    ],
}


def get_knowledge(rule_name: str) -> Dict[str, Any]:
    """Return the knowledge entry for a rule name, or the generic fallback."""
    return KNOWLEDGE.get(rule_name, _FALLBACK)


def attach_knowledge(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Decorate every finding in-place with `knowledge` so the dashboard
    can render the Security Guide card without a second API call.
    Returns the same list for call-site chaining."""
    for f in findings or []:
        rule = f.get("rule") or ""
        f["knowledge"] = get_knowledge(rule)
    return findings


def get_rule_names() -> List[str]:
    """Return the set of rule names that have explicit knowledge entries
    (useful for the test that guards against drift between RULE_META and
    KNOWLEDGE)."""
    return list(KNOWLEDGE.keys())
