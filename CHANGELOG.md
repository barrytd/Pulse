# Changelog

All notable changes to Pulse are documented here.
Format: newest entries at the top, grouped by date.

---

## 2026-04-07 (continued)

### Fixed
- **Timestamp column showing "-"** for brute force and attack chain findings in HTML report - changed `strftime('%H:%M:%S')` to `strftime('%Y-%m-%dT%H:%M:%S')` in `detect_brute_force`, `detect_account_takeover_chain`, and `detect_malware_persistence_chain` so the reporter regex can extract a full date
- **Em dashes removed** from finding detail text in 4 detection rules (User Account Created, RDP Logon, AV Disabled, Firewall Rule Changed)

### Added
- **Security Score panel** at the top of the HTML report - a score out of 100 that drops based on severity of findings (CRITICAL -25, HIGH -10, MEDIUM -5, LOW -2), displayed as a circular ring with a color-coded risk label (SECURE / LOW RISK / MEDIUM RISK / HIGH RISK / CRITICAL RISK)
- **Inter font** loaded from Google Fonts for cleaner, more professional typography matching industry security dashboards

---

## 2026-04-07 (continued)

### Added
- **Remediation tab** in the HTML report - hardcoded action steps for all 11 detection rules, sorted CRITICAL first
- **Executive summary** auto-generated based on severity of findings (tone adjusts: CRITICAL compromise detected vs routine monitoring)
- **Dark mode toggle** in the HTML report navbar - preference persisted in localStorage across reloads
- **Two-tab layout** - Detections tab (existing filterable table) and Remediation tab
- Em dashes removed from all report output (replaced with plain hyphens for compatibility)

---

## 2026-04-07

### Added
- **CLI arguments** (`main.py`) — Pulse is now a proper command-line tool:
  - `--logs FOLDER` — specify where to find `.evtx` files (default: `logs/`)
  - `--output FILE` — specify the output report path
  - `--format txt|html` — choose report format (default: `txt`)
  - `--help` — auto-generated usage page
- **HTML report** (`pulse/reporter.py`) — dark-themed browser report with colour-coded severity badges (HIGH=red, MEDIUM=orange, LOW=blue) and a summary panel
- **Time-windowed brute force** (`pulse/detections.py`) — brute force rule now only fires if 5+ failures happen within a 10-minute window, eliminating false positives from typos spread over days
- **Attack chain correlation** (`pulse/detections.py`) — two new CRITICAL-severity rules that connect multiple events into attack patterns:
  - **Account Takeover Chain** — brute force → successful login → new user created
  - **Malware Persistence Chain** — AV disabled → new service installed (in that order)
- **Tests expanded from 28 to 34** — new tests cover time-window boundary conditions and chain ordering (service before/after AV, success before/after failures)

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
