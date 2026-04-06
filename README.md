# Pulse

**A lightweight Windows event log analyzer for threat detection and SOC triage.**

Pulse is a blue team tool that reads Windows event logs (.evtx files), identifies suspicious patterns (failed logins, new user creation, privilege escalation attempts), and outputs a clean, human-readable report.

---

## Why Pulse?

Small businesses can't afford enterprise SIEM tools like Splunk or Sentinel. Pulse gives them a simple, affordable way to spot threats hiding in their Windows event logs.

---

## Features

- **Parse** Windows `.evtx` event log files
- **Detect** suspicious patterns:
  - Brute force login attempts (Event ID 4625)
  - New user account creation (Event ID 4720)
  - Privilege escalation / group changes (Event ID 4732)
  - Audit log clearing (Event ID 1102)
- **Report** findings in a clean, readable format

---

## Project Structure

```
Pulse/
├── pulse/                  # Main application code
│   ├── __init__.py         # Makes "pulse" a Python package
│   ├── parser.py           # Reads and parses .evtx log files
│   ├── detections.py       # Detection rules for suspicious activity
│   └── reporter.py         # Generates the output report
├── logs/                   # Drop .evtx files here for analysis
├── reports/                # Generated reports go here
├── tests/                  # Unit tests
│   └── test_detections.py  # Tests for detection logic
├── main.py                 # Entry point — run this to analyze logs
├── requirements.txt        # Python dependencies
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
git clone https://github.com/YOUR_USERNAME/Pulse.git
cd Pulse

# Install dependencies
pip install -r requirements.txt
```

### Usage

```bash
# Place your .evtx files in the logs/ folder, then run:
python main.py
```

A report will be generated in the `reports/` folder.

---

## Roadmap

- [x] Project structure and foundation
- [ ] .evtx file parsing
- [ ] Detection rules (failed logins, user creation, privilege escalation)
- [ ] Human-readable report output
- [ ] CLI flags (custom log path, output format)
- [ ] JSON report output for automation
- [ ] SaaS web dashboard (future)

---

## License

MIT License — see LICENSE for details.
