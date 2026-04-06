# Changelog

All notable changes to Pulse are documented here.
Format: newest entries at the top, grouped by date.

---

## 2026-04-06

### Added
- **Parser module** (`pulse/parser.py`) — reads `.evtx` files using `python-evtx`, extracts event ID, timestamp, and raw XML from each record
- **Detection rules** (`pulse/detections.py`) — four threat detection rules:
  - Brute Force Detection (Event 4625) — flags accounts with 5+ failed logins
  - User Account Creation (Event 4720) — flags new account creation with actor details
  - Privilege Escalation (Event 4732) — flags users added to security groups
  - Audit Log Clearing (Event 1102) — flags when security logs are wiped
- **Reporter module** (`pulse/reporter.py`) — generates a formatted `.txt` report with severity breakdown and finding details, auto-saves to `reports/` folder
- **Unit tests** (`test_detections.py`) — 13 tests covering all detection rules including edge cases (below threshold, per-account counting, ignoring irrelevant events)
- Installed `python-evtx` and `pytest` dependencies

### Fixed
- Moved module files (`parser.py`, `detections.py`, `reporter.py`, `__init__.py`) into `pulse/` subdirectory so `main.py` imports work correctly

### Project foundation (pre-existing)
- `main.py` — entry point that wires parse, detect, and report steps together
- `pulse/__init__.py` — package marker with version
- `requirements.txt` — dependency list
- `.gitignore` — ignores cache, logs, reports, and secrets
