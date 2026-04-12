# Pulse

**A lightweight Windows event log analyzer for threat detection and SOC triage.**

Pulse is a blue team tool that reads Windows event logs (.evtx files), identifies suspicious patterns, and outputs a clean report - in plain text or a colour-coded HTML page you can open in any browser.

---

## Why Pulse?

Windows event logs hold a goldmine of forensic data, but digging through them manually is tedious and error-prone. Pulse automates the boring parts - parsing the logs, flagging suspicious patterns, correlating events into attack chains, and organising the findings into a clean report. Built as a hands-on learning project to explore threat detection, digital forensics, and Python development.

---

## Features

### Detection Rules (15 total)

| Rule | Event ID | Severity | MITRE ATT&CK | What it catches |
|---|---|---|---|---|
| Brute Force Attempt | 4625 | HIGH | T1110 | 5+ failed logins within a 10-minute window |
| Account Lockout | 4740 | HIGH | T1110 | Account locked out - active brute force indicator |
| User Account Created | 4720 | MEDIUM | T1136.001 | New accounts - potential backdoors |
| Privilege Escalation | 4732 | HIGH | T1078.002 | Users added to security groups |
| Audit Log Cleared | 1102 | HIGH | T1070.001 | Someone wiping their tracks |
| RDP Logon Detected | 4624 (type 10) | MEDIUM | T1021.001 | Remote Desktop logins with source IP |
| Pass-the-Hash Attempt | 4624 (type 3, NTLM) | HIGH | T1550.002 | NTLM network logons that may indicate stolen hash use |
| Service Installed | 7045 | MEDIUM | T1543.003 | New services - common malware persistence method |
| Scheduled Task Created | 4698 | MEDIUM | T1053.005 | New scheduled tasks - persistence mechanism |
| Suspicious PowerShell | 4104 | HIGH | T1059.001 | Encoded commands, download cradles, Mimikatz |
| Antivirus Disabled | 5001 | HIGH | T1562.001 | Defender real-time protection turned off |
| Firewall Disabled | 4950 | HIGH | T1562.004 | Firewall profile changed or disabled |
| Firewall Rule Changed | 4946 / 4947 | MEDIUM | T1562.004 | Firewall rules added or modified |
| **Account Takeover Chain** | Multiple | **CRITICAL** | T1078 | Brute force -> successful login -> new user created |
| **Malware Persistence Chain** | Multiple | **CRITICAL** | T1543.003 | AV disabled -> new service installed |

### Reporting
- **Text report** - clean, readable `.txt` output for terminals and quick triage
- **HTML report** - professional SOC dashboard with security score, scan stats, severity filters, remediation tab, and dark mode
- **JSON report** - structured machine-readable output for piping into Splunk, ELK, or Python scripts
- **CSV export** - spreadsheet format that opens in Excel or Google Sheets
- **Security Score** - a score out of 100 at the top of HTML reports, colour-coded from SECURE to CRITICAL RISK
- **MITRE ATT&CK tagging** - each finding links to its ATT&CK technique on attack.mitre.org
- **Email delivery** - send the finished HTML report via SMTP after a scan with `--email`

### Live Monitoring
- **`--watch` mode** - queries live Windows event channels (Security, System) in real time using `wevtutil`
- Alerts on new suspicious events within seconds, with ANSI-coloured terminal output
- `--interval` flag controls poll frequency (default 30s)
- Findings saved to the database automatically during monitoring

### Scan History
- **SQLite database** - every scan saved to `pulse.db` automatically
- **`--history` flag** - view past scans with security scores and trend arrows (↑/↓)

### Interactive Mode
- **`--interactive` flag** - after a scan, browse findings one by one in the terminal
- Mark findings as investigated or false positive
- Add entries directly to the whitelist from the terminal — no manual YAML editing needed

### REST API
- **`--api` flag** - starts a local FastAPI server so other tools can send `.evtx` files over HTTP and get findings back as JSON
- **Endpoints**: `POST /api/scan` (file upload), `GET /api/history`, `GET /api/report/{id}`, `GET /api/health`
- **Interactive docs** auto-generated at `http://127.0.0.1:8000/docs` (Swagger UI)
- Uploaded files are parsed in-memory and deleted immediately — nothing is kept on disk
- Same whitelist, baseline, and scoring logic as the CLI

### Noise Reduction
- **Built-in known-good whitelist** - 100+ entries covering anti-cheat, gaming platforms, hardware peripherals, Google, Microsoft, security software, VPNs, and common apps — suppressed by default with no configuration
- **Custom whitelist** - add your own entries in `pulse.yaml` (accounts, services, IPs, rules)

### Baseline Comparison
- **`--save-baseline`** - snapshots the current state of user accounts, services, and scheduled tasks on a known-good machine
- Future scans automatically compare against the baseline and flag anything new that wasn't there before (`New Account`, `New Service`, `New Task` findings)
- Baseline stored in `pulse_baseline.json` in the project root

### Performance
- **Parallel parsing** - `.evtx` files parsed across all CPU cores using `multiprocessing`
- **ECG heartbeat animation** - scrolling terminal animation with live file counter during parsing
- **160 unit tests** - every detection rule, report format, config, whitelist, database, and monitor tested

---

## Project Structure

```
Pulse/
├── pulse/
│   ├── __init__.py         # Makes "pulse" a Python package
│   ├── parser.py           # Reads and parses .evtx log files
│   ├── detections.py       # 15 detection rules + attack chain correlation
│   ├── reporter.py         # Generates text, HTML, JSON, and CSV reports
│   ├── emailer.py          # SMTP email delivery of HTML reports
│   ├── monitor.py          # Live monitoring via wevtutil
│   ├── database.py         # SQLite scan history
│   ├── interactive.py      # Interactive terminal mode
│   ├── animations.py       # ECG heartbeat terminal animation
│   ├── api.py              # REST API (FastAPI) — /api/scan, /api/history, /api/report, /api/health
│   ├── whitelist.py        # Whitelist filtering shared by CLI and API
│   └── known_good.py       # Built-in known-good service whitelist
├── logs/                   # Drop .evtx files here for analysis
├── reports/                # Generated reports saved here
├── pulse.db                # SQLite scan history database
├── test_detections.py      # 146 unit tests for detection engine
├── test_api.py             # 14 unit tests for the REST API
├── main.py                 # Entry point - run this to analyse logs
├── pulse.yaml              # Config file for default settings
├── requirements.txt        # Python dependencies
├── CHANGELOG.md            # Daily change log
└── README.md               # You are here
```

---

## Getting Started

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

```bash
# Clone the repo
git clone https://github.com/barrytd/Pulse.git
cd Pulse

# Install dependencies
pip install -r requirements.txt
```

### Usage

```bash
# Basic scan — reads logs/ folder, saves a .txt report to reports/
python main.py

# Scan a custom folder (e.g. live Windows logs)
python main.py --logs "C:/Windows/System32/winevt/Logs"

# Generate an HTML report
python main.py --format html

# Only show HIGH and above findings
python main.py --severity HIGH

# Browse findings interactively after the scan
python main.py --interactive

# View past scan history with score trends
python main.py --history

# Watch live — alerts on new suspicious events in real time
python main.py --watch

# Watch with a faster poll interval
python main.py --watch --interval 5

# Only scan the last 30 days of events (much faster on large log folders)
python main.py --days 30

# Scan the last 6 months
python main.py --days 180

# Save a baseline snapshot of known accounts, services, and tasks
python main.py --save-baseline

# Send the HTML report by email after the scan
python main.py --format html --email

# Start the REST API server (docs at http://127.0.0.1:8000/docs)
python main.py --api

# Start the API on a custom port
python main.py --api --port 9000

# See all options
python main.py --help
```

### Getting .evtx files

On any Windows machine, export logs from Event Viewer:

```
Event Viewer > Windows Logs > Security > Save All Events As...
```

Or copy directly from `C:\Windows\System32\winevt\Logs\`.

---

## Example Output (HTML)

The HTML report opens in any browser with colour-coded findings:

- **CRITICAL** - attack chains (account takeover, malware persistence)
- **HIGH** - brute force, AV disabled, firewall changes, log clearing
- **MEDIUM** - RDP logins, new services, new user accounts

---

## Running Tests

```bash
python -m pytest test_detections.py -v
```

All 146 tests run without needing real `.evtx` files - the test suite uses fake event data that mirrors real Windows log structure.

---

## Roadmap

### Done
- [x] Project structure and foundation
- [x] `.evtx` file parsing (parallel, with per-file timeout)
- [x] Detection rules - 15 rules covering login attacks, persistence, defence evasion, credential abuse
- [x] Human-readable text report output
- [x] HTML report with security score, scan stats, severity filters, remediation tab, dark mode
- [x] JSON report output - machine-readable findings for Splunk, ELK, Python scripts
- [x] CSV export - spreadsheet format for Excel and Google Sheets
- [x] CLI flags (`--logs`, `--output`, `--format`, `--severity`)
- [x] Config file support (`pulse.yaml`) - store default settings
- [x] Whitelist/allowlist - suppress known-good accounts, services, IPs, and rules
- [x] Built-in known-good service whitelist (100+ entries, zero config needed)
- [x] Baseline comparison - snapshot known-good state with `--save-baseline`, flag anything new on future scans
- [x] Attack chain correlation (connects multiple events into attack patterns)
- [x] MITRE ATT&CK tagging - each finding links to its technique on attack.mitre.org
- [x] Scan summary statistics - files scanned, total events, time range, top event IDs
- [x] Email delivery - send finished HTML report via SMTP with `--email`
- [x] SQLite scan history - every scan saved to `pulse.db`; use `--history` for trends
- [x] Live monitoring mode - `--watch` queries live Windows channels in real time
- [x] Interactive terminal mode - `--interactive` to browse, investigate, and whitelist findings
- [x] Parallel file parsing across all CPU cores
- [x] ECG heartbeat animation during parsing
- [x] REST API (FastAPI) - `--api` exposes Pulse as a local web service with `/api/scan`, `/api/history`, `/api/report/{id}`, `/api/health`, and auto-generated Swagger docs at `/docs`
- [x] 160 unit tests, all passing

- [x] Web dashboard - single-page dark-themed UI served at `/`, with sidebar navigation, drag-and-drop upload, score ring, scan history, and light/dark theme toggle
- [x] Functional Settings & Whitelist pages - edit whitelist from the browser, view active config and all detection rules
- [x] Report export from dashboard - download HTML or JSON report for any scan result
- [x] Multi-file upload - drag multiple `.evtx` files at once for batch scanning
- [x] Deduplicated daily scoring - unique-rule-based scoring with letter grades (A-F), MITRE category breakdown, and daily aggregation

### Sprint 2 — Apr 14–27, 2026
- [ ] **Email alerts** - send summary email when a scan finds CRITICAL/HIGH severity items
- [ ] **New detection rules** - expand from 15 to 20+ (Kerberoasting, golden ticket, suspicious PowerShell, etc.)

### Sprint 3 — Apr 28 – May 11, 2026
- [ ] **Remediation suggestions** - each finding includes a "how to fix" recommendation with step-by-step guidance
- [ ] **Scheduled scans** - watch a folder for new `.evtx` files and auto-scan them on arrival
- [ ] **Recurring reports** - auto-generate daily or weekly HTML summary reports
- [ ] **PDF export** - download formatted PDF reports from the dashboard

### Sprint 4 — May 12–25, 2026
- [ ] **Multi-machine support** - track scores per hostname, compare security posture across endpoints
- [ ] **Firewall log analysis** - parse Windows Firewall logs, detect suspicious outbound connections, flag risky rules and misconfigurations
- [ ] **Audit log** - track who scanned what and when within the dashboard

### Sprint 5 — Jun 2–15, 2026
- [ ] **User authentication** - login page, sessions, role-based access control (admin vs viewer)
- [ ] **Compliance mapping** - tag findings against NIST CSF and ISO 27001 controls
- [ ] **Trend analytics** - score-over-time charts, improvement tracking, historical comparisons

### Sprint 6 — Jun 16–29, 2026
- [ ] **Incident workflows** - mark findings as acknowledged, investigating, or resolved
- [ ] **Custom branding** - upload company logo, set organization name on reports and dashboard
- [ ] **Dashboard widgets** - customizable layout with drag-and-drop panels
- [ ] **Threat intel integration** - correlate findings with external threat intelligence feeds

---

## License

MIT License - see LICENSE for details.
