# Pulse

**A lightweight Windows event log analyzer for threat detection and SOC triage.**

Pulse is a blue team tool that reads Windows event logs (.evtx files), identifies suspicious patterns, and outputs a clean report — in plain text or a colour-coded HTML page you can open in any browser.

---

## Why Pulse?

Windows event logs hold a goldmine of forensic data, but digging through them manually is tedious and error-prone. Pulse automates the boring parts — parsing the logs, flagging suspicious patterns, correlating events into attack chains, and organising the findings into a clean report. Built as a hands-on learning project to explore threat detection, digital forensics, and Python development.

---

## Features

### Detection Rules (11 total)

| Rule | Event ID | Severity | What it catches |
|---|---|---|---|
| Brute Force Attempt | 4625 | HIGH | 5+ failed logins within a 10-minute window |
| User Account Created | 4720 | MEDIUM | New accounts — potential backdoors |
| Privilege Escalation | 4732 | HIGH | Users added to security groups |
| Audit Log Cleared | 1102 | HIGH | Someone wiping their tracks |
| RDP Logon Detected | 4624 (type 10) | MEDIUM | Remote Desktop logins with source IP |
| Service Installed | 7045 | MEDIUM | New services — common malware persistence method |
| Antivirus Disabled | 5001 | HIGH | Defender real-time protection turned off |
| Firewall Disabled | 4950 | HIGH | Firewall profile changed or disabled |
| Firewall Rule Changed | 4946 / 4947 | MEDIUM | Firewall rules added or modified |
| **Account Takeover Chain** | Multiple | **CRITICAL** | Brute force → successful login → new user created |
| **Malware Persistence Chain** | Multiple | **CRITICAL** | AV disabled → new service installed |

### Reporting
- **Text report** — clean, readable `.txt` output for terminals and quick triage
- **HTML report** — dark-themed, colour-coded report (HIGH=red, MEDIUM=orange) you can open in any browser and share with others

### Other
- **CLI flags** — customise log folder, output path, and report format without editing code
- **ASCII banner** on startup
- **34 unit tests** — every detection rule is tested including edge cases and chain ordering

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
├── main.py                 # Entry point — run this to analyse logs
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
# Basic — scans the logs/ folder and saves a .txt report to reports/
python main.py

# Specify a custom log folder
python main.py --logs C:\Windows\System32\winevt\Logs

# Generate an HTML report instead of plain text
python main.py --format html

# Save the report to a specific file
python main.py --output my_report.html --format html

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

- **CRITICAL** — attack chains (account takeover, malware persistence)
- **HIGH** — brute force, AV disabled, firewall changes, log clearing
- **MEDIUM** — RDP logins, new services, new user accounts

---

## Running Tests

```bash
python -m pytest test_detections.py -v
```

All 34 tests run without needing real `.evtx` files — the test suite uses fake event data that mirrors real Windows log structure.

---

## Roadmap

- [x] Project structure and foundation
- [x] `.evtx` file parsing
- [x] Detection rules — 11 rules covering login attacks, persistence, defence evasion
- [x] Human-readable text report output
- [x] HTML report with colour-coded severity
- [x] CLI flags (`--logs`, `--output`, `--format`)
- [x] Attack chain correlation (connects multiple events into attack patterns)
- [x] Unit tests (34 tests, all passing)
- [ ] JSON report output for use with other tools (Splunk, ELK, etc.)
- [ ] Whitelist/allowlist — suppress known-good accounts and services
- [ ] SaaS web dashboard (future)

---

## License

MIT License — see LICENSE for details.
