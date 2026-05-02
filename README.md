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
- **PDF report** - grade-coloured score ring, scope + duration, per-finding cards with full description, mono meta line, numbered remediation steps, and MITRE / mitigation pills
- **Security Score** - a score out of 100 at the top of every report, graded A–F (A #639922 Secure · B #378ADD Low Risk · C #BA7517 Moderate Risk · D #E24B4A High Risk · F #A32D2D Critical Risk)
- **MITRE ATT&CK tagging** - each finding links to its ATT&CK technique on attack.mitre.org
- **Email delivery** - send the finished HTML report via SMTP after a scan with `--email`
- **Slack / Discord webhook** - post threat findings to a channel via incoming webhook (auto-detects flavor from URL); fires alongside email and shares a per-rule cooldown

### Firewall & Response
- **Windows Firewall log parser** - reads `pfirewall.log`, surfaces port-scan aggregates and sensitive-port probes (3389 / 22 / 445 / 3306 / 5985) from public IPs; intra-LAN chatter is skipped
- **IP block list** - Pulse-owned list of blocked source IPs pushed into Windows Firewall via `netsh advfirewall`. Every rule is prefixed `Pulse-managed:` so user-authored firewall rules are never touched; RFC1918, loopback, link-local, and your own IPs are rejected at stage time
- **One-click block from finding** - any finding with a discoverable source IP shows a Block button in the detail drawer; the staged entry carries a comment linking back to the finding
- **Firewall page** - dashboard tab with Blocked IPs (stage / push / unblock) and a Firewall Log view of parsed detections
- **Block-list CLI** - `--block-ip <ip> [--comment TEXT] [--confirm]`, `--block-list`, `--block-push`, `--unblock-ip <ip> [--force]`, `--firewall-log [PATH]`

### Live Monitoring
- **CLI `--watch` mode** - queries live Windows event channels (Security, System) in real time via `wevtutil`, ANSI-coloured terminal alerts, configurable `--interval`
- **Dashboard live monitor** - pulsing LIVE indicator, Start/Stop and Test Alert buttons, slide-in alert feed with audio ding, poll-history diagnostics, and a 15-minute sliding detection window with finding dedup so cross-poll patterns (like Brute Force) still trigger
- Findings saved to the database automatically during monitoring
- Auto-resumes monitoring across page reloads and server restarts via `localStorage`

### Scan History
- **Pluggable database** - SQLite by default (`pulse.db`, zero setup); flip to PostgreSQL for shared deployments by setting `DATABASE_URL=postgresql://…`. `scripts/migrate_to_postgres.py` copies an existing SQLite history into Postgres in one shot
- **`--history` flag** - view past scans with security scores and trend arrows (↑/↓)
- **Position-based scan numbers** - "Scan #N" is the row's position in current history (oldest = #1); delete everything and the next scan shows as #1 again. Internal DB id stays stable for lookups

### Interactive Mode
- **`--interactive` flag** - after a scan, browse findings one by one in the terminal
- Mark findings as investigated or false positive
- Add entries directly to the whitelist from the terminal — no manual YAML editing needed

### REST API
- **`--api` flag** - starts a local FastAPI server so other tools can send `.evtx` files over HTTP and get findings back as JSON
- **Endpoints**: `POST /api/scan` (file upload), `GET /api/history`, `GET /api/report/{id}`, `GET /api/health`
- **Interactive docs** auto-generated at `http://127.0.0.1:8000/docs` (Swagger UI)
- **API token auth** - mint long-lived bearer tokens from Settings > API Tokens, then call any endpoint with `Authorization: Bearer pulse_…`. Tokens inherit the owner's role and can be revoked from the same page
- Uploaded files are parsed in-memory and deleted immediately — nothing is kept on disk
- Same whitelist, baseline, and scoring logic as the CLI

### Accounts, Compliance, & Analytics
- **Multi-user accounts** - admin vs viewer roles; admins manage users from Settings > Users, viewers see only the scans they personally ran
- **Profile picture upload** - avatars stored as BLOBs on the users row so they survive Render's ephemeral filesystem; top-right corner syncs immediately
- **Audit log** - every block / unblock / push / scan / review / user-management action is recorded; filter by user or action type and export as CSV
- **Compliance page** - per-CSF-function and per-Annex-A-clause coverage cards plus a per-rule lookup. Every detection rule is tagged with a NIST CSF subcategory (e.g. `DE.CM-1`) and an ISO 27001 control (e.g. `A.9.4.2`)
- **Trend analytics** - 7 / 30 / 90-day rolling window with window-over-window delta, daily finding line chart, severity breakdown, top rules, and top hosts
- **Score-over-time chart** on the Dashboard — daily security scores plotted, grade-tinted

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
- **499 unit tests** - every detection rule, report format, config, whitelist, database, API endpoint, alert pathway, webhook delivery, firewall-log parser, IP block-list lifecycle, per-user data isolation, and API token lifecycle tested

---

## Project Structure

```
Pulse/
├── pulse/                  # Application package — see pulse/README.md for
│   │                         a per-module index and one-liner for each file
│   ├── README.md           # Module map (core, reports, alerts, monitor, firewall, …)
│   ├── core/               # Parsing, detection, scoring
│   │   ├── parser.py           # Reads and parses .evtx log files
│   │   ├── detections.py       # Detection engine + attack chain correlation
│   │   ├── rules_config.py     # Declarative list of every built-in detection rule
│   │   └── known_good.py       # Built-in 100+ service-account allowlist
│   ├── reports/            # HTML, PDF, scan-diff rendering
│   │   ├── reporter.py         # HTML, JSON, CSV, and text reports
│   │   ├── pdf_report.py       # ReportLab PDF report with grade-coloured score ring
│   │   └── comparison.py       # Scan diff → {new, resolved, shared}
│   ├── alerts/             # Outbound notifications + schedule plumbing
│   │   ├── emailer.py          # SMTP delivery — threshold alerts + full reports
│   │   ├── webhook.py          # Slack / Discord webhook delivery
│   │   └── scheduler.py        # Folder-watch scheduler for .evtx drops
│   ├── monitor/            # Live, scheduled, and on-box scans
│   │   ├── monitor.py          # Live-monitor loop (CLI + dashboard SSE)
│   │   ├── monitor_service.py  # Session bookkeeping for monitor runs
│   │   ├── system_scan.py      # "Scan My System" — reads C:\Windows\…\winevt\Logs
│   │   └── scheduled_scan.py   # Background thread that fires scheduled scans
│   ├── firewall/           # Windows Firewall audit + IP block list
│   │   ├── firewall_parser.py  # pfirewall.log parser + public-IP detections
│   │   ├── firewall_config.py  # netsh advfirewall audit (profiles, any-any rules)
│   │   └── blocker.py          # Pulse-managed IP block list + netsh push/unblock
│   ├── api.py              # FastAPI app, /api/* endpoints, SPA shell routing
│   ├── auth.py             # scrypt password hashing, session cookies, RBAC
│   ├── database.py         # SQLite schema + every query helper
│   ├── whitelist.py        # User-configurable whitelist layer
│   ├── remediation.py      # Per-rule remediation steps + MITRE mitigation IDs
│   ├── interactive.py      # Interactive terminal browser
│   ├── animations.py       # ECG heartbeat animation during parsing
│   ├── static/js/          # Native ES modules: api, dashboard, scans, findings, …
│   └── web/
│       ├── index.html      # Single-page dashboard
│       └── login.html      # Sign-in / first-user signup page
├── tests/                  # Pytest suite (one test_<module>.py per pulse module)
│   ├── test_detections.py        # Detection engine tests
│   ├── test_api.py               # REST API tests
│   ├── test_alerts.py            # Email alert tests
│   ├── test_auth.py              # Auth, RBAC, multi-user management
│   ├── test_data_isolation.py    # Per-user scan ownership + API scoping
│   ├── test_webhook.py           # Slack / Discord webhook tests
│   ├── test_firewall_parser.py   # Firewall log parser + detection tests
│   ├── test_firewall_config.py   # netsh advfirewall audit tests
│   ├── test_blocker.py           # IP block-list lifecycle + safety rails
│   ├── test_monitor_service.py   # Live monitor session bookkeeping
│   ├── test_system_scan.py       # System-scan plumbing
│   └── test_hostname.py          # Hostname attribution
├── logs/                   # Drop .evtx files here for analysis
├── reports/                # Generated reports saved here
├── pulse.db                # SQLite scan history database
├── main.py                 # CLI entry point — run this to analyse logs
├── seed_fleet_demo.py      # Demo seeding script (multi-host fleet)
├── send_test_email.py      # SMTP sanity check
├── pulse.yaml              # Config file for default settings
├── requirements.txt        # Python dependencies
├── BACKLOG.md              # Unscheduled but validated ideas
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

## Multi-tenant (Sprint 7)

When you self-host Pulse on the public internet, every signup creates a
fresh **organization** and rows are scoped to it — two different
customers running on the same instance never see each other's scans,
agents, findings, or notifications. Admins can invite teammates via
**Settings → Users**; teammates join the admin's org and share scan,
fleet, and agent visibility (the right collaboration boundary for a SOC
team).

- Self-signup (`POST /api/auth/signup`) auto-creates a new org with a
  slug derived from the user's email. Set **`PULSE_HOSTED_SIGNUP=1`** on
  the deployment to keep the endpoint open past the first user (default
  is closed-after-bootstrap so a self-hosted install doesn't accidentally
  let strangers create accounts).
- Admin-created users (`POST /api/users`) inherit the admin's
  `organization_id` so they immediately see existing scans and agents.
- Legacy single-user installs upgrade in place: `init_db` runs
  `_backfill_organizations`, which mints a personal org per user and
  stamps every owned scan / agent / notification with that
  `organization_id`. Re-running is idempotent — only NULL columns are
  touched.
- Every read / write helper (`get_history`, `get_scan_findings`,
  `delete_scans`, `list_agents`, `set_agent_paused`, …) accepts an
  `organization_id` parameter; the API uses `_read_scope_kwargs` to
  splat the right scope into each call.

## Pulse Agent (Sprint 7)

The hosted Pulse dashboard runs on Linux and can't read a Windows host's
event log over the network. The **Pulse Agent** is a lightweight client
you install on each Windows host you want to monitor — it scans the
local event log and ships findings to your hosted dashboard over HTTPS.

The wire layer (enrollment exchange, heartbeat, findings ingest) ships
with the server in v1.6.0+. The agent runtime ships with the same
package (`pulse.agent`) — a packaged `pulse-agent.exe` lands later this
sprint, but the runtime can be exercised today via Python.

### Two-step setup

**1.** In the dashboard, go to **Settings → Agents → Enroll a Pulse Agent**.
Pick a name, click **Enroll Agent**, and copy the `pe_…` token from the
banner (shown once).

**2.** On the Windows host, run the enroll command. This trades the
single-use enrollment token for a long-lived bearer and writes it to
`%PROGRAMDATA%\Pulse\agent.yaml` (or `~/.pulse/agent.yaml` on non-
Windows).

```powershell
python -m pulse.agent enroll https://your-pulse-domain.example.com pe_AAAA...
```

Then start the agent loop:

```powershell
python -m pulse.agent run
```

The agent heartbeats every 60 seconds and runs a full local scan every
30 minutes by default; tune via `scan_interval_sec` / `heartbeat_interval_sec`
in the config file. Stop with Ctrl+C — a packaged Windows Service
installer is the next ship in Sprint 7.

### Auto-update channel

On startup the agent calls `GET /api/agent/latest` and logs an
`update available` warning when the server reports a newer build,
including the download URL. The check is best-effort — a failing probe
never blocks the heartbeat or scan loop. Override the default GitHub
Releases / CHANGELOG URLs on the server side via env vars:

- `PULSE_AGENT_DOWNLOAD_URL` — where to point the operator for the
  latest build (default: `https://github.com/anthropics/pulse/releases/latest`)
- `PULSE_AGENT_NOTES_URL` — release notes URL (default: the CHANGELOG)

When the agent supplies its bearer token the server resolves the calling
agent and computes `outdated`/`current` server-side (compared against
the version the agent reported on enrollment), so the agent doesn't have
to do its own semver math.

### CLI reference

```text
python -m pulse.agent enroll <server_url> <enrollment_token>   # one-time
python -m pulse.agent run                                       # daemon
python -m pulse.agent status                                    # config dump
```

Add `--config <path>` (before the subcommand) to override the default
config location, or `-v` / `-vv` for log verbosity. `--insecure` is
available on `enroll` for dev work against a self-signed Pulse server
(never use in production):

```powershell
python -m pulse.agent --config C:\custom\agent.yaml status
python -m pulse.agent -vv run
python -m pulse.agent enroll http://localhost:8000 pe_dev_token --insecure
```

### Building `pulse-agent.exe`

The packaged binary is what ends customers on a Windows host actually
run. Build it on a Windows developer box:

```powershell
pip install -r requirements-agent.txt
python scripts/build_agent.py --clean
```

Outputs a one-folder bundle under `dist/pulse-agent/` (37 MB total,
6.5 MB launcher exe). Add `--onefile` to collapse to a single .exe at
the cost of a slower cold start. Build artifacts are gitignored — the
final binary ships via GitHub Releases, not source control.

The exe takes the same CLI as `python -m pulse.agent`, so smoke-testing
is identical:

```powershell
.\dist\pulse-agent\pulse-agent.exe --help
.\dist\pulse-agent\pulse-agent.exe enroll https://your-pulse pe_AAAA...
.\dist\pulse-agent\pulse-agent.exe run
```

### Running as a Windows Service

For unattended hosts, register the agent with Windows so it survives
reboots and runs as SYSTEM (which can read every event-log channel
without UAC). Two paths — `sc.exe` is built into Windows; **NSSM** is
the friendlier wrapper.

**Path 1 — `sc.exe` (no extra tooling).** Copy the unpacked bundle
under `C:\Program Files\Pulse\`, then:

```powershell
sc.exe create PulseAgent binPath= "\"C:\Program Files\Pulse\pulse-agent\pulse-agent.exe\" run" start= auto DisplayName= "Pulse Agent"
sc.exe description PulseAgent "Pulse threat-detection agent — ships local event-log findings to the configured Pulse server."
sc.exe start PulseAgent
```

The space after `binPath=` / `start=` / `DisplayName=` is required —
that's a `sc.exe` quirk, not a typo.

**Path 2 — [NSSM](https://nssm.cc/) (recommended).** NSSM handles
service-mode quirks (no STDOUT, signal differences) better than raw
`sc.exe`:

```powershell
nssm install PulseAgent "C:\Program Files\Pulse\pulse-agent\pulse-agent.exe" run
nssm set PulseAgent DisplayName "Pulse Agent"
nssm set PulseAgent Description "Pulse threat-detection agent."
nssm set PulseAgent Start SERVICE_AUTO_START
nssm start PulseAgent
```

Either way, lock the agent.yaml token file down so only SYSTEM +
Administrators can read it:

```powershell
icacls "C:\ProgramData\Pulse\agent.yaml" /inheritance:r /grant:r "SYSTEM:(R,W)" "Administrators:(F)"
```

A bundled installer that does this in one click is the next-up Sprint 7
item — see [ROADMAP.md](ROADMAP.md).

---

## Example Output (HTML)

The HTML report opens in any browser with colour-coded findings:

- **CRITICAL** - attack chains (account takeover, malware persistence)
- **HIGH** - brute force, AV disabled, firewall changes, log clearing
- **MEDIUM** - RDP logins, new services, new user accounts

---

## Running Tests

```bash
# Run the whole suite
python -m pytest -q

# Run a single module
python -m pytest tests/test_detections.py -v
```

All 271 tests run without needing real `.evtx` files — the test suite uses fake event data that mirrors real Windows log structure.

---

## Roadmap & Changelog

- Current status and planned sprints: [ROADMAP.md](ROADMAP.md)
- Validated but unscheduled ideas: [BACKLOG.md](BACKLOG.md)
- Commit-level change history: [CHANGELOG.md](CHANGELOG.md)

---

## License

MIT License - see LICENSE for details.
