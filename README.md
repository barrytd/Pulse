# Pulse

**A lightweight Windows event log analyzer for threat detection and SOC triage.**

Pulse is a blue team tool that reads Windows event logs (.evtx files), identifies suspicious patterns, and outputs a clean report - in plain text or a colour-coded HTML page you can open in any browser.

---

## Why Pulse?

Windows event logs hold a goldmine of forensic data, but digging through them manually is tedious and error-prone. Pulse automates the boring parts - parsing the logs, flagging suspicious patterns, correlating events into attack chains, and organising the findings into a clean report. Built as a hands-on learning project to explore threat detection, digital forensics, and Python development.

---

## Features

### Detection Rules (24 total)

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
| Kerberoasting | 4769 (RC4) | HIGH | T1558.003 | TGS requests with weak RC4 encryption |
| Golden Ticket | 4769 / 4624 | HIGH | T1558.001 | Anomalous TGT lifetime or domain mismatch |
| Credential Dumping | 4656 | HIGH | T1003.001 | LSASS handle access from non-system processes |
| Logon from Disabled Account | 4625 / 4624 | HIGH | T1078 | Logon attempt against an account marked disabled |
| After-Hours Logon | 4624 | MEDIUM | T1078 | Interactive logon outside business hours |
| Suspicious Registry Modification | 4657 | MEDIUM | T1547.001 | Run/RunOnce/Image File Execution Options writes |
| Lateral Movement via Network Share | 5140 / 5145 | MEDIUM | T1021.002 | Admin share access (`ADMIN$`, `C$`) from new hosts |
| **DCSync Attempt** | 4662 | **CRITICAL** | T1003.006 | Directory replication GUIDs requested by non-DC accounts |
| **Suspicious Child Process** | 4688 | HIGH | T1059 | Office / browser parents spawning cmd / powershell / wscript |
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
- **Slack / Discord webhook** - post threat findings to a channel via incoming webhook (auto-detects flavor from URL); fires alongside email and shares a per-rule cooldown

### Live Monitoring
- **CLI `--watch` mode** - queries live Windows event channels (Security, System) in real time via `wevtutil`, ANSI-coloured terminal alerts, configurable `--interval`
- **Dashboard live monitor** - pulsing LIVE indicator, Start/Stop and Test Alert buttons, slide-in alert feed with audio ding, poll-history diagnostics, and a 15-minute sliding detection window with finding dedup so cross-poll patterns (like Brute Force) still trigger
- Findings saved to the database automatically during monitoring
- Auto-resumes monitoring across page reloads and server restarts via `localStorage`

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
- **271 unit tests** - every detection rule, report format, config, whitelist, database, API endpoint, alert pathway, and webhook delivery tested

---

## Project Structure

```
Pulse/
├── pulse/
│   ├── parser.py           # Reads and parses .evtx log files
│   ├── detections.py       # 24 detection rules + attack chain correlation
│   ├── reporter.py         # Generates text, HTML, JSON, and CSV reports
│   ├── emailer.py          # SMTP email delivery + CRITICAL/HIGH alert emails
│   ├── webhook.py          # Slack / Discord webhook delivery
│   ├── monitor.py          # CLI live monitoring via wevtutil
│   ├── monitor_service.py  # Async in-process live monitor (SSE-backed, for the dashboard)
│   ├── database.py         # SQLite scan history
│   ├── interactive.py      # Interactive terminal mode
│   ├── animations.py       # ECG heartbeat terminal animation
│   ├── api.py              # FastAPI REST API + SSE stream for live monitor
│   ├── auth.py             # Single-user auth: scrypt hashing + signed session cookies
│   ├── whitelist.py        # Whitelist filtering shared by CLI and API
│   ├── known_good.py       # Built-in known-good service whitelist
│   ├── static/js/          # Native ES modules: api, dashboard, scans, findings, monitor, settings, etc.
│   └── web/
│       ├── index.html      # Single-page dashboard
│       └── login.html      # Sign-in / first-user signup page
├── logs/                   # Drop .evtx files here for analysis
├── reports/                # Generated reports saved here
├── pulse.db                # SQLite scan history database
├── test_detections.py      # Detection engine tests
├── test_api.py             # REST API tests
├── test_alerts.py          # Email alert tests
├── test_auth.py            # Auth + session cookie tests
├── test_webhook.py         # Slack / Discord webhook tests
├── main.py                 # Entry point - run this to analyse logs
├── pulse.yaml              # Config file for default settings
├── requirements.txt        # Python dependencies
├── CHANGELOG.md            # Daily change log
├── ROADMAP.md              # Current status + sprint plan
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

All 271 tests run without needing real `.evtx` files — the test suite uses fake event data that mirrors real Windows log structure.

---

## Roadmap & Changelog

- Current status and planned sprints: [ROADMAP.md](ROADMAP.md)
- Commit-level change history: [CHANGELOG.md](CHANGELOG.md)

---

## License

MIT License - see LICENSE for details.
