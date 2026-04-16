# Pulse Roadmap

Current status and planned work by sprint. See [CHANGELOG.md](CHANGELOG.md) for a commit-level history.

---

## Shipped

- Project structure and foundation
- `.evtx` file parsing (parallel, per-file timeout)
- 22 detection rules covering login attacks, persistence, defence evasion, credential abuse
- Attack chain correlation (multi-event patterns)
- MITRE ATT&CK tagging — each finding links to its technique
- Scan summary statistics (files scanned, total events, time range, top event IDs)
- Human-readable text report output
- HTML report with security score, scan stats, severity filters, remediation tab, dark mode
- JSON report output — machine-readable findings for Splunk, ELK, Python scripts
- CSV export — spreadsheet format for Excel and Google Sheets
- CLI flags (`--logs`, `--output`, `--format`, `--severity`, `--days`, `--email`, `--api`, etc.)
- Config file support (`pulse.yaml`) — default settings, email config, alert config
- Whitelist / allowlist — suppress known-good accounts, services, IPs, and rules
- Built-in known-good service whitelist (100+ entries, zero config)
- Baseline comparison — snapshot known-good state, flag anything new on future scans
- Email delivery — send finished HTML report via SMTP with `--email`
- SQLite scan history — every scan saved to `pulse.db`; `--history` for trends
- Deduplicated daily scoring with letter grades (A–F), MITRE category breakdown
- Live monitoring (CLI) — `--watch` queries live Windows channels in real time
- Interactive terminal mode — `--interactive` browse, investigate, and whitelist findings
- Parallel file parsing across all CPU cores
- ECG heartbeat animation during parsing
- REST API (FastAPI) — `/api/scan`, `/api/history`, `/api/report/{id}`, `/api/health`, Swagger docs at `/docs`
- Web dashboard — single-page dark-themed UI with sidebar nav, drag-and-drop upload, score ring, scan history, light/dark theme toggle
- Functional Settings & Whitelist pages — edit whitelist from the browser, view active config and all detection rules
- Report export from dashboard — download HTML or JSON report for any scan
- Multi-file upload — drag multiple `.evtx` files at once for batch scanning
- **Live monitor in dashboard** — SSE-powered live panel with pulsing indicator, slide-in alerts, audio ding, test-alert button, sliding 15-minute detection window, finding dedup, per-poll event-ID diagnostics, localStorage auto-resume
- **Dashboard authentication** — single-user login/signup page, scrypt-hashed passwords, signed session cookies, `/api/*` auth middleware, "My Account" card for changing email/password
- **Email alerts with throttling** — `dispatch_alerts` helper unifies CLI + API scan alert paths; per-rule cooldown prevents repeat-finding spam
- **Live monitor email alerts** — monitor polls can now email findings, gated by a user-configurable interval (5 min – 4 hours)
- **Settings UX polish** — SMTP jargon hidden behind a provider dropdown (Gmail / Outlook / Yahoo / Custom) with auto-filled host and port
- **Dashboard zero-state polish** — friendly banner + empty panels when the filtered window has no scans, instead of hiding everything
- **Slack / Discord webhook delivery** — alongside email alerts, with shared cooldown, payload caps, and a Settings card with test button
- **Frontend modularized** — `pulse/web/index.html` split into native ES modules under `pulse/static/js/` (api, dashboard, scans, findings, monitor, settings, etc.) with a central action registry replacing inline `on*` handlers
- 271 unit tests, all passing

---

## Sprint 2 — Apr 14–27, 2026 (Alerting & detection depth)

- [x] Email alerts — send summary email when a scan finds CRITICAL/HIGH items
- [x] Alert throttling — dedupe repeated findings so one noisy host doesn't spam inbox
- [x] Live-monitor email alerts — interval-gated emails straight from the monitor loop
- [x] Slack / Discord webhook — optional webhook URL in `pulse.yaml` to post CRITICAL findings
- [x] Kerberoasting detection — Event ID 4769 with weak encryption type (RC4)
- [x] Golden ticket detection — anomalous TGT lifetime / mismatched domain in 4769/4624
- [x] DCSync detection — 4662 with directory-replication GUIDs from non-DC accounts
- [x] Suspicious child process chain — Office / browser spawning cmd.exe, powershell.exe, wscript.exe
- [x] Finding detail drawer — click a finding in the dashboard to see raw event XML + context
- [x] Dashboard search — search bar that filters findings by user, IP, rule, or event ID

---

## Sprint 3 — Apr 28 – May 11, 2026 (Remediation & automation)

- [ ] Remediation suggestions — each rule includes a "how to fix" recommendation with step-by-step guidance
- [ ] Remediation tab rewrite — group fixes by rule and show MITRE mitigation IDs (M1026, etc.)
- [ ] Scheduled scans — watch a folder for new `.evtx` files and auto-scan on arrival
- [ ] Recurring reports — auto-generate daily or weekly HTML summary reports
- [ ] PDF export — download formatted PDF reports from the dashboard
- [ ] Report comparison — diff two scans side by side, highlight new / resolved findings
- [x] "Mark reviewed" status — per-finding state saved to DB, persists across scans
- [x] CLI `--quiet` / `--json-only` — machine-friendly output for cron pipelines

---

## Sprint 4 — May 12–25, 2026 (Multi-host & firewall)

- [ ] Multi-machine support — track scores per hostname, compare security posture across endpoints
- [ ] Hostname auto-detection — parse `Computer` field from each `.evtx` event, tag findings
- [ ] Per-host dashboard view — pick a machine, see only its history and trend
- [ ] Fleet overview page — sortable table of all machines with score, last scan, top severity
- [ ] Firewall log parser — parse `pfirewall.log`, extract blocked / allowed connections
- [ ] Suspicious outbound detection — flag connections to non-RFC1918 IPs on unusual ports
- [ ] Firewall rule misconfiguration rules — any-any rules, disabled profiles, overly broad scope
- [ ] **IP block list** — manage a Pulse-owned list of blocked source IPs that gets pushed into Windows Firewall (`netsh advfirewall`) as inbound deny rules. Each entry has an optional comment field (e.g. "brute force on 2026-04-15", "Tor exit node") so an analyst remembers why it was added. Add/remove from the dashboard, see "Pulse-managed" tag on each rule so user-created rules are never touched
- [ ] One-click "block source IP" action — on any finding with a source IP (Brute Force, RDP Logon, etc.) the dashboard shows a Block button that adds the IP to the block list with a pre-filled comment linking back to the finding
- [ ] Audit log — track who scanned what and when within the dashboard
- [ ] Export fleet CSV — one-row-per-host summary for spreadsheets

---

## Sprint 5 — Jun 2–15, 2026 (Auth, compliance, analytics)

- [x] User authentication — login page backed by SQLite users table with scrypt hashes (shipped early, single-user)
- [x] Session management — signed cookies, logout, 30-day expiry (shipped early)
- [ ] Role-based access — admin (full) vs viewer (read-only) roles enforced in API
- [ ] API token auth — generate / revoke tokens for CI pipelines hitting `/api/scan`
- [ ] NIST CSF mapping — tag each rule against Identify / Protect / Detect / Respond / Recover
- [ ] ISO 27001 mapping — link rules to Annex A controls (A.9 access, A.12 ops, etc.)
- [ ] Compliance report view — dashboard page showing coverage per framework
- [ ] Score-over-time chart — line chart of daily scores, 30 / 90 day windows
- [ ] Trend analytics page — rule frequency heatmap, top offenders, week-over-week delta

---

## Sprint 6 — Jun 16–29, 2026 (Workflows, branding, threat intel)

- [ ] Incident workflow states — mark findings as acknowledged, investigating, or resolved
- [ ] Analyst notes — free-text notes field per finding, stored in DB, shown in report
- [ ] Assignment — assign a finding to a user, filter dashboard by "assigned to me"
- [ ] Custom branding — upload company logo, set organization name on reports and dashboard
- [ ] Configurable severity colours — override the default CRITICAL/HIGH/MEDIUM palette
- [ ] Dashboard widgets — customizable layout with drag-and-drop panels
- [ ] Threat intel integration — correlate source IPs with AbuseIPDB / OTX feeds
- [ ] IOC lookup panel — paste an IP or hash, query intel feeds, cache results locally
- [ ] Weekly threat brief — auto-emailed digest of top findings across the fleet
