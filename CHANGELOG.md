# Changelog

All notable changes to Pulse are documented here.
Format: newest entries at the top, grouped by date.

---

## 2026-04-14

### Added
- **Single-user dashboard authentication** (`pulse/auth.py`, `pulse/web/login.html`) — clean dark-themed login page that doubles as a first-user signup form when no account exists yet. Password hashing uses stdlib `hashlib.scrypt`; session cookies are HMAC-SHA256 signed with a secret auto-generated into `pulse.yaml` on first boot. No external auth deps
- **Auth middleware** on `/api/*` — every endpoint is 401 without a valid session cookie, except `/api/health` and `/api/auth/*`. `GET /` 302-redirects to `/login` when signed out
- **Account routes** — `POST /api/auth/signup` (closed after first user, 409 thereafter), `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/status`, `PUT /api/auth/email`, `PUT /api/auth/password`. Email/password changes require current password re-entry
- **Settings rewrite** — new "My Account" card on the Settings page lets you change your login email and password from the browser and sign out. The old SMTP fields are now hidden behind a provider dropdown (Gmail / Outlook / Yahoo / Custom) that auto-fills host and port — no more jargon for non-sysadmin users
- **Live monitor email alerts** (`pulse/monitor_service.py`) — live monitoring can now email findings, gated by a new `monitor_enabled` toggle and `monitor_interval_minutes` setting (5 min to 4 hours). Slow SMTP won't block the poll loop (`asyncio.to_thread`). Alert config is editable from the Settings page
- **`dispatch_alerts` helper** (`pulse/emailer.py`) — shared alert-dispatch logic used by the CLI scan path, the API scan path, and now the live monitor, so throttling and cooldown behave consistently everywhere
- **Dashboard empty state** — when no scans fall inside the filtered time window, the Dashboard now shows a banner with "Upload .evtx" / "Open Monitor" CTAs plus muted zero-state panels instead of hiding everything behind a single "No data" card

### Changed
- **`create_app(...)`** accepts a `disable_auth=False` test flag so the existing API test fixture stays simple
- **`users` table** added to SQLite on startup (`pulse/database.py`) with UNIQUE email constraint and scrypt-format password hashes

### Tests
- 25 new tests in `test_auth.py` (unit: scrypt round-trip, cookie sign/verify/tamper/expiry; API: needs_signup flag, signup closed after first user, login/logout, protected 401/200, root redirects, email/password updates)
- 5 new tests in `test_monitor_service.py` for the monitor email-interval throttle
- 5 new tests in `test_alerts.py` for `dispatch_alerts` (covers throttling + CLI/API parity)
- 3 new tests in `test_api.py` for the monitor config fields
- Test count: 189 → 227, all passing

---

## 2026-04-12

### Added
- **Web dashboard** (`pulse/web/index.html`) — single-page dark-themed UI served at `GET /`:
  - Sidebar navigation: Dashboard, Scans, Findings, History, Whitelist, Settings
  - Drag-and-drop `.evtx` upload modal with file picker fallback
  - Security score ring visualization with color-coded risk levels
  - Score history table (5 most recent on dashboard, full list on History page)
  - Scan drill-down: click any scan to view its findings
  - Light/dark theme toggle with `localStorage` persistence
  - Dashboard test added to `test_api.py`
- **REST API** (`pulse/api.py`) — FastAPI server with four endpoints:
  - `POST /api/scan` — upload a `.evtx` file, get findings as JSON back. File is parsed in-memory and deleted immediately (ephemeral storage)
  - `GET /api/history` — list recent scans from the local SQLite database (`?limit=N`, capped at 200)
  - `GET /api/report/{id}` — return findings for a specific past scan; 404 if the scan doesn't exist
  - `GET /api/health` — aliveness check, returns Pulse version
- **`--api` flag** on `main.py` — starts the API with uvicorn. `--host` and `--port` override defaults
- **Interactive OpenAPI docs** — Swagger UI auto-generated at `http://127.0.0.1:8000/docs`
- **`pulse/whitelist.py`** — extracted `filter_whitelist` from `main.py` so both the CLI and the API share the same filtering logic
- **`CONTRIBUTING.md`** and **`SECURITY.md`** — dev setup, test commands, and responsible disclosure policy
- **GitHub tag `v1.1.0`** — stable release covering everything since v1.0.0 (live monitoring, history, interactive, baseline, Pass-the-Hash, parallel parsing, ECG animation, `--days`, and now the REST API)

### Fixed
- **Parser no longer crashes on empty/corrupt files** — `parse_evtx()` now returns `[]` for empty, missing, or unreadable `.evtx` files instead of raising `ValueError: cannot mmap an empty file`. Protects both the CLI and the API from bad input

### Tests
- 14 new tests in `test_api.py` covering every endpoint, bad inputs, history pagination, 404s, and temp-file cleanup
- Test count: 146 → 160, all passing

### Dependencies
- `fastapi>=0.100.0`, `uvicorn[standard]>=0.23.0`, `python-multipart>=0.0.6` (runtime)
- `httpx>=0.25.0` (testing only — required by FastAPI's TestClient)

---

## 2026-04-11 (continued)

### Added
- **`--days N` flag** — limits scan to the last N days of events (e.g. `--days 30`, `--days 180`). Works by passing a time filter directly to wevtutil so old events are skipped before any data is returned
- **Fast path parser** — `parse_evtx()` now uses wevtutil with an event ID filter (`RELEVANT_EVENT_IDS`) to fetch only the ~13 event IDs Pulse has rules for, skipping 95%+ of events. Falls back to python-evtx if wevtutil fails
- **Date + time in interactive mode** — TIME column now shows full `YYYY-MM-DD HH:MM:SS` instead of just `HH:MM:SS`

### Performance
- Scanning 382 files that previously hung now completes in seconds with `--days 30`
- Event ID pre-filtering reduces parsed events from ~67,000 to ~500-2,000 for a typical Security.evtx

---

## 2026-04-11

### Added
- **Interactive terminal mode** (`--interactive`) — browse findings after a scan, mark as investigated, add to whitelist directly from the terminal. No manual YAML editing needed
- **Known-good service whitelist** (`pulse/known_good.py`) — 100+ built-in entries covering anti-cheat, gaming platforms, hardware peripherals, Google, Microsoft, security software, VPNs, and common apps. Automatically merged with user's `pulse.yaml` whitelist on every scan
- **ECG heartbeat animation** — scrolling green ECG line with live file counter during parsing (`pulse/animations.py`)
- **Parallel file parsing** — `.evtx` files parsed across all CPU cores using `multiprocessing.Pool` with callbacks for real-time progress updates and a 30-second stall timeout for locked live files

### Fixed
- **Heartbeat message overlap** — shorter progress messages now padded to fixed width so they fully overwrite longer ones
- **Interactive mode TIME column blank** — timestamps extracted from embedded `details` string when no explicit `timestamp` field is present on a finding
- **Parser hanging on live log files** — added per-file stall timeout; files locked by Windows (e.g. live Security.evtx) are skipped automatically after 30 seconds of no progress

### Tests
- Test count: 146, all passing

---

## 2026-04-09

### Added
- **Live monitoring mode** (`--watch`) — polls Windows event channels (Security, System) in real time using `wevtutil`. Alerts on new suspicious events within seconds. Use `--interval` to set poll frequency (default 30s)
- **SQLite scan history** (`--history`) — every scan is saved to `pulse.db`. View past scans with security score trends and trend arrows (↑/↓) using `--history`
- **Parallel file parsing** — `.evtx` files are now parsed across all available CPU cores using `multiprocessing.Pool`, significantly faster when scanning many files
- **Built-in known-good service whitelist** (`pulse/known_good.py`) — ~100 entries covering anti-cheat engines, gaming platforms, hardware peripherals (Corsair, Razer, Logitech, NZXT), Google, Microsoft, security software, VPNs, and common apps. Suppressed automatically on every scan with no configuration needed
- **`record_num` field** added to every parsed event for deduplication in live monitoring

### Fixed
- **Live file reading** — `parse_evtx` now skips corrupt/partial records instead of crashing, allowing Pulse to read live Windows log files that are actively being written to
- **`Evtx` context manager** — fixed `TypeError` that occurred when reading live `.evtx` files by wrapping file access in a `with` statement as required by the library

### Tests
- 10 new tests for monitor module (poll_new_events, print_finding, _apply_whitelist)
- 11 new tests for database module (init, save, history, findings, sorting)
- Test count: 75 → 146, all passing

---

## 2026-04-08

### Added
- **4 new detection rules** - Account Lockout (Event 4740), Scheduled Task Created (Event 4698), Suspicious PowerShell (Event 4104 with pattern matching for encoded commands, download cradles, Mimikatz, etc.), Pass-the-Hash Attempt (Event 4624, NTLM network logon — detects stolen hash use, T1550.002)
- **Baseline comparison** (`--save-baseline`) — snapshots current accounts, services, and scheduled tasks on a known-good machine. Future scans auto-load the baseline and flag anything new (`New Account (Baseline)`, `New Service (Baseline)`, `New Task (Baseline)` findings)
- **MITRE ATT&CK tagging** - every detection rule maps to its ATT&CK technique ID (e.g. T1110, T1059.001). HTML report shows clickable links to attack.mitre.org
- **Security Score panel** - a score out of 100 at the top of every HTML report, displayed as a circular ring with a colour-coded risk label
- **Scan summary statistics** - HTML and text reports now show files scanned, total events, time range, and top event IDs
- **JSON report format** - `--format json` outputs structured data with metadata, severity summary, security score, and findings array with MITRE IDs
- **CSV report format** - `--format csv` exports findings as a spreadsheet for Excel or Google Sheets
- **Config file support** - `pulse.yaml` stores default settings so you don't need CLI flags every time
- **Whitelist/allowlist** - suppress known-good accounts, services, IPs, and rule names from findings via `pulse.yaml`
- **Inter font** loaded from Google Fonts for cleaner report typography
- **PyYAML** added as a dependency for config file parsing

### Fixed
- **Timestamp column showing "-"** for brute force and attack chain findings in HTML report
- **Em dashes removed** from all finding detail text and README

### Tests
- 41 new tests added (detections, JSON, CSV, config, whitelist)
- Test count: 34 -> 75, all passing
- Detection count: 11 -> 15 (13 individual + 2 chains)

---

## 2026-04-07

### Added
- **CLI arguments** (`main.py`) — Pulse is now a proper command-line tool:
  - `--logs FOLDER` — specify where to find `.evtx` files (default: `logs/`)
  - `--output FILE` — specify the output report path
  - `--format txt|html` — choose report format (default: `txt`)
  - `--severity LEVEL` — only show findings at or above this severity (default: `LOW`)
  - `--help` — auto-generated usage page
- **HTML report** (`pulse/reporter.py`) — dark-themed browser report with colour-coded severity badges and a summary panel
- **Time-windowed brute force** (`pulse/detections.py`) — brute force rule now only fires if 5+ failures happen within a 10-minute window, eliminating false positives from typos spread over days
- **Attack chain correlation** (`pulse/detections.py`) — two new CRITICAL-severity rules that connect multiple events into attack patterns:
  - **Account Takeover Chain** — brute force → successful login → new user created
  - **Malware Persistence Chain** — AV disabled → new service installed (in that order)
- **Two-tab layout** — Detections tab (filterable table) and Remediation tab
- **Remediation tab** — hardcoded action steps for all 11 detection rules, sorted CRITICAL first
- **Executive summary** — auto-generated based on severity of findings (tone adjusts: CRITICAL compromise detected vs routine monitoring)
- **Dark mode toggle** in the HTML report navbar — preference persisted in localStorage across reloads
- **Security Score panel** at the top of the HTML report — a score out of 100 that drops based on severity of findings (CRITICAL -25, HIGH -10, MEDIUM -5, LOW -2), displayed as a circular ring with a colour-coded risk label (SECURE / LOW RISK / MEDIUM RISK / HIGH RISK / CRITICAL RISK)
- **Inter font** loaded from Google Fonts for cleaner, more professional typography
- **Tests expanded from 28 to 34** — new tests cover time-window boundary conditions and chain ordering

### Fixed
- **Timestamp column showing "-"** for brute force and attack chain findings in HTML report — changed `strftime('%H:%M:%S')` to `strftime('%Y-%m-%dT%H:%M:%S')` so the reporter regex can extract a full date
- **Em dashes removed** from all finding detail text (replaced with plain hyphens for compatibility)

---

## 2026-04-06

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
