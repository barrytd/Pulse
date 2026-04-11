# Pulse

**A lightweight Windows event log analyzer for threat detection and SOC triage.**

Pulse is a blue team tool that reads Windows event logs (.evtx files), identifies suspicious patterns, and outputs a clean report - in plain text or a colour-coded HTML page you can open in any browser.

---

## Why Pulse?

Windows event logs hold a goldmine of forensic data, but digging through them manually is tedious and error-prone. Pulse automates the boring parts - parsing the logs, flagging suspicious patterns, correlating events into attack chains, and organising the findings into a clean report. Built as a hands-on learning project to explore threat detection, digital forensics, and Python development.

---

## Features

### Detection Rules (14 total)

| Rule | Event ID | Severity | MITRE ATT&CK | What it catches |
|---|---|---|---|---|
| Brute Force Attempt | 4625 | HIGH | T1110 | 5+ failed logins within a 10-minute window |
| Account Lockout | 4740 | HIGH | T1110 | Account locked out - active brute force indicator |
| User Account Created | 4720 | MEDIUM | T1136.001 | New accounts - potential backdoors |
| Privilege Escalation | 4732 | HIGH | T1078.002 | Users added to security groups |
| Audit Log Cleared | 1102 | HIGH | T1070.001 | Someone wiping their tracks |
| RDP Logon Detected | 4624 (type 10) | MEDIUM | T1021.001 | Remote Desktop logins with source IP |
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

### Noise Reduction
- **Built-in known-good whitelist** - 100+ entries covering anti-cheat, gaming platforms, hardware peripherals, Google, Microsoft, security software, VPNs, and common apps — suppressed by default with no configuration
- **Custom whitelist** - add your own entries in `pulse.yaml` (accounts, services, IPs, rules)

### Performance
- **Parallel parsing** - `.evtx` files parsed across all CPU cores using `multiprocessing`
- **ECG heartbeat animation** - scrolling terminal animation with live file counter during parsing
- **146 unit tests** - every detection rule, report format, config, whitelist, database, and monitor tested

---

## Project Structure

```
Pulse/
├── pulse/
│   ├── __init__.py         # Makes "pulse" a Python package
│   ├── parser.py           # Reads and parses .evtx log files
│   ├── detections.py       # 14 detection rules + attack chain correlation
│   ├── reporter.py         # Generates text, HTML, JSON, and CSV reports
│   ├── emailer.py          # SMTP email delivery of HTML reports
│   ├── monitor.py          # Live monitoring via wevtutil
│   ├── database.py         # SQLite scan history
│   ├── interactive.py      # Interactive terminal mode
│   ├── animations.py       # ECG heartbeat terminal animation
│   └── known_good.py       # Built-in known-good service whitelist
├── logs/                   # Drop .evtx files here for analysis
├── reports/                # Generated reports saved here
├── pulse.db                # SQLite scan history database
├── test_detections.py      # 146 unit tests
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

# Send the HTML report by email after the scan
python main.py --format html --email

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
- [x] Detection rules - 14 rules covering login attacks, persistence, defence evasion, credential abuse
- [x] Human-readable text report output
- [x] HTML report with security score, scan stats, severity filters, remediation tab, dark mode
- [x] JSON report output - machine-readable findings for Splunk, ELK, Python scripts
- [x] CSV export - spreadsheet format for Excel and Google Sheets
- [x] CLI flags (`--logs`, `--output`, `--format`, `--severity`)
- [x] Config file support (`pulse.yaml`) - store default settings
- [x] Whitelist/allowlist - suppress known-good accounts, services, IPs, and rules
- [x] Built-in known-good service whitelist (100+ entries, zero config needed)
- [x] Attack chain correlation (connects multiple events into attack patterns)
- [x] MITRE ATT&CK tagging - each finding links to its technique on attack.mitre.org
- [x] Scan summary statistics - files scanned, total events, time range, top event IDs
- [x] Email delivery - send finished HTML report via SMTP with `--email`
- [x] SQLite scan history - every scan saved to `pulse.db`; use `--history` for trends
- [x] Live monitoring mode - `--watch` queries live Windows channels in real time
- [x] Interactive terminal mode - `--interactive` to browse, investigate, and whitelist findings
- [x] Parallel file parsing across all CPU cores
- [x] ECG heartbeat animation during parsing
- [x] 146 unit tests, all passing

### Next up
- [ ] **REST API** - expose Pulse as a local web service so other tools can submit `.evtx` files and get findings back as JSON
- [ ] **Web dashboard** - a browser-based UI to upload logs, view findings, track history across multiple machines, and manage whitelists

---

## License

MIT License - see LICENSE for details.
