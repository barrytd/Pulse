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

### Other
- **CLI flags** - customise log folder, output path, format, and severity filter
- **Config file** - `pulse.yaml` for storing default settings
- **Whitelist** - suppress known-good accounts, services, IPs, and rules
- **ASCII banner** on startup
- **75 unit tests** - every detection rule, report format, config, and whitelist tested

---

## Project Structure

```
Pulse/
├── pulse/
│   ├── __init__.py         # Makes "pulse" a Python package
│   ├── parser.py           # Reads and parses .evtx log files
│   ├── detections.py       # 14 detection rules + attack chain correlation
│   └── reporter.py         # Generates text, HTML, JSON, and CSV reports
├── logs/                   # Drop .evtx files here for analysis
├── reports/                # Generated reports saved here
├── test_detections.py      # 75 unit tests for all detection rules
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
# Basic - scans the logs/ folder and saves a .txt report to reports/
python main.py

# Specify a custom log folder
python main.py --logs C:\Windows\System32\winevt\Logs

# Generate an HTML report instead of plain text
python main.py --format html

# Save the report to a specific file
python main.py --output my_report.html --format html

# Only show HIGH and above findings
python main.py --severity HIGH

# See all options
python main.py --help

# Watch log files live — alerts on new suspicious events as they arrive
python main.py --watch

# Watch with a custom poll interval (seconds)
python main.py --watch --interval 10
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
- [x] `.evtx` file parsing
- [x] Detection rules - 14 rules covering login attacks, persistence, defence evasion, credential abuse
- [x] Human-readable text report output
- [x] HTML report with security score, scan stats, severity filters, remediation tab, dark mode
- [x] JSON report output - machine-readable findings for Splunk, ELK, Python scripts
- [x] CSV export - spreadsheet format for Excel and Google Sheets
- [x] CLI flags (`--logs`, `--output`, `--format`, `--severity`)
- [x] Config file support (`pulse.yaml`) - store default settings
- [x] Whitelist/allowlist - suppress known-good accounts, services, IPs, and rules
- [x] Attack chain correlation (connects multiple events into attack patterns)
- [x] MITRE ATT&CK tagging - each finding links to its technique on attack.mitre.org
- [x] Scan summary statistics - files scanned, total events, time range, top event IDs
- [x] Unit tests (75 tests, all passing)

### Next up
- [ ] **Pass-the-hash detection** (Event 4624, NTLM logon type) - credential abuse pattern
- [ ] **Baseline comparison** - compare a log against a "known good" snapshot to surface anomalies
- [ ] **Email delivery** - send the finished HTML report via email automatically when a scan completes

### Longer-term
- [x] **SQLite database** - every scan is saved to `pulse.db`; use `--history` to view past scans with score trends
- [x] **Live monitoring mode** - use `--watch` to poll log files every 30 seconds and alert in real time as suspicious events appear
- [ ] **Interactive terminal mode** - after a scan, let the user drill into individual findings, view raw event XML, and mark findings as investigated or false positive
- [ ] **REST API** - expose Pulse as a local web service so other tools can submit `.evtx` files and get findings back as JSON, enabling integration into larger pipelines
- [ ] **Web dashboard** - a browser-based UI to upload logs, view findings, track history across multiple machines, and manage whitelists

---

## License

MIT License - see LICENSE for details.
