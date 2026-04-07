# Pulse

**A lightweight Windows event log analyzer for threat detection and SOC triage.**

Pulse is a blue team tool that reads Windows event logs (.evtx files), identifies suspicious patterns, and outputs a clean report - in plain text or a colour-coded HTML page you can open in any browser.

---

## Why Pulse?

Windows event logs hold a goldmine of forensic data, but digging through them manually is tedious and error-prone. Pulse automates the boring parts - parsing the logs, flagging suspicious patterns, correlating events into attack chains, and organising the findings into a clean report. Built as a hands-on learning project to explore threat detection, digital forensics, and Python development.

---

## Features

### Detection Rules (11 total)

| Rule | Event ID | Severity | What it catches |
|---|---|---|---|
| Brute Force Attempt | 4625 | HIGH | 5+ failed logins within a 10-minute window |
| User Account Created | 4720 | MEDIUM | New accounts - potential backdoors |
| Privilege Escalation | 4732 | HIGH | Users added to security groups |
| Audit Log Cleared | 1102 | HIGH | Someone wiping their tracks |
| RDP Logon Detected | 4624 (type 10) | MEDIUM | Remote Desktop logins with source IP |
| Service Installed | 7045 | MEDIUM | New services - common malware persistence method |
| Antivirus Disabled | 5001 | HIGH | Defender real-time protection turned off |
| Firewall Disabled | 4950 | HIGH | Firewall profile changed or disabled |
| Firewall Rule Changed | 4946 / 4947 | MEDIUM | Firewall rules added or modified |
| **Account Takeover Chain** | Multiple | **CRITICAL** | Brute force -> successful login -> new user created |
| **Malware Persistence Chain** | Multiple | **CRITICAL** | AV disabled -> new service installed |

### Reporting
- **Text report** - clean, readable `.txt` output for terminals and quick triage
- **HTML report** - dark-themed, colour-coded report you can open in any browser and share with others
- **Security Score** - a score out of 100 at the top of every HTML report, colour-coded from SECURE to CRITICAL RISK

### Other
- **CLI flags** - customise log folder, output path, format, and severity filter without editing code
- **ASCII banner** on startup
- **34 unit tests** - every detection rule is tested including edge cases and chain ordering

---

## Project Structure

```
Pulse/
├── pulse/
│   ├── __init__.py         # Makes "pulse" a Python package
│   ├── parser.py           # Reads and parses .evtx log files
│   ├── detections.py       # 11 detection rules + attack chain correlation
│   └── reporter.py         # Generates text and HTML reports
├── logs/                   # Drop .evtx files here for analysis
├── reports/                # Generated reports saved here
├── test_detections.py      # 34 unit tests for all detection rules
├── main.py                 # Entry point - run this to analyse logs
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

All 34 tests run without needing real `.evtx` files - the test suite uses fake event data that mirrors real Windows log structure.

---

## Roadmap

### Done
- [x] Project structure and foundation
- [x] `.evtx` file parsing
- [x] Detection rules - 11 rules covering login attacks, persistence, defence evasion
- [x] Human-readable text report output
- [x] HTML report with colour-coded severity and security score panel
- [x] CLI flags (`--logs`, `--output`, `--format`, `--severity`)
- [x] Attack chain correlation (connects multiple events into attack patterns)
- [x] Unit tests (34 tests, all passing)

### Near-term
- [ ] **JSON report output** - machine-readable findings for piping into other tools (Splunk, ELK, Python scripts)
- [ ] **Scan summary statistics** - show total events parsed, time range covered, and top event types before the findings list so analysts get context at a glance
- [ ] **Config file support** - load defaults from a `pulse.yaml` file (log folder, thresholds, format) so you don't have to type flags every time
- [ ] **Whitelist/allowlist** - suppress known-good accounts and service names from findings to reduce false positives in noisy environments

### Medium-term
- [ ] **More detection rules** - expand coverage with:
  - PowerShell script block logging (Event 4104) - catch encoded/obfuscated PS commands
  - Scheduled task creation (Event 4698) - another common persistence method
  - Pass-the-hash detection (Event 4624, NTLM logon type) - credential abuse pattern
  - Account lockout (Event 4740) - high volume indicates active brute force
- [ ] **MITRE ATT&CK tagging** - label each finding with the relevant ATT&CK technique ID (e.g. T1110 for brute force, T1136 for account creation) so findings map directly to the industry-standard threat framework
- [ ] **Baseline comparison** - compare a log against a "known good" snapshot of the same machine to surface anomalies that wouldn't stand out alone (new account that didn't exist yesterday, service that appeared overnight)
- [ ] **CSV export** - export findings as a spreadsheet for analysts who prefer working in Excel or sharing with non-technical stakeholders
- [ ] **Email delivery** - send the finished HTML report via email automatically when a scan completes

### Longer-term
- [ ] **SQLite database** - store all parsed events and findings locally so Pulse can compare scans over time, track trends, and ask questions like "has this account ever logged in via RDP before?"
- [ ] **Live monitoring mode** - instead of one-shot analysis, watch a log file for new events and alert in real time as suspicious activity happens
- [ ] **Interactive terminal mode** - after a scan, let the user drill into individual findings, view raw event XML, and mark findings as investigated or false positive
- [ ] **REST API** - expose Pulse as a local web service so other tools can submit `.evtx` files and get findings back as JSON, enabling integration into larger pipelines
- [ ] **Web dashboard** - a browser-based UI to upload logs, view findings, track history across multiple machines, and manage whitelists

---

## License

MIT License - see LICENSE for details.
