# Changelog

All notable changes to Pulse are documented here.
Format: newest entries at the top, grouped by date.

---

## 2026-04-06 (continued)

### Added — 5 new detection rules
- **Firewall Rule Changed** (Event 4946/4947) — flags when firewall rules are added or modified, extracts the rule name
- **Firewall Disabled** (Event 4950) — flags when a Windows Firewall profile is changed/disabled
- **Antivirus/Defender Disabled** (Event 5001) — flags when real-time protection is turned off
- **Suspicious Service Installed** (Event 7045) — flags when a new service is installed, extracts service name and account
- **RDP Logon Detected** (Event 4624, LogonType 10) — flags Remote Desktop logins, extracts username and source IP

### Updated
- `run_all_detections()` now includes all 9 detection rules
- **Unit tests** expanded from 13 to 27 tests covering all rules
- Added `.claude/` to `.gitignore`
- Added `CHANGELOG.md`

---

## 2026-04-06 — Initial Release

### Added
- **Parser module** (`pulse/parser.py`) — reads `.evtx` files using `python-evtx`, extracts event ID, timestamp, and raw XML from each record
- **Detection rules** (`pulse/detections.py`) — four threat detection rules:
  - Brute Force Detection (Event 4625) — flags accounts with 5+ failed logins
  - User Account Creation (Event 4720) — flags new account creation with actor details
  - Privilege Escalation (Event 4732) — flags users added to security groups
  - Audit Log Clearing (Event 1102) — flags when security logs are wiped
- **Reporter module** (`pulse/reporter.py`) — generates a formatted `.txt` report with severity breakdown and finding details, auto-saves to `reports/` folder
- **Unit tests** (`test_detections.py`) — 13 tests covering all detection rules including edge cases
- **Entry point** (`main.py`) — wires parse, detect, and report steps together
- `pulse/__init__.py` — package marker with version
- `requirements.txt` — dependency list (`python-evtx`)
- `.gitignore` — ignores cache, logs, reports, and secrets

### Fixed
- Moved module files into `pulse/` subdirectory so `main.py` imports work correctly
