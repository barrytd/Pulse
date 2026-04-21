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
- **Firewall feature set** — `pfirewall.log` parser, Pulse-managed IP block list with `netsh` push / unblock, one-click block-from-finding, Firewall page with Blocked IPs + Firewall Log tabs, CLI `--block-ip / --block-list / --block-push / --unblock-ip / --firewall-log`
- **PDF report overhaul** — grade-coloured score ring + title / scope / duration / colored score line, per-finding cards with full description, mono meta line, numbered remediation, MITRE / mitigation pills
- **Position-based scan numbering** — displayed "Scan #" tracks position in current history, so deleting all scans resets back to #1 (internal DB id preserved for lookups)
- **Real SPA URL routing** — every page has its own path (`/dashboard`, `/monitor`, `/scans/{id}`, etc.); browser Back / Forward / Refresh / deep-linking all work
- **Bulk-select + batch-delete on every list page** — Scans, Reports, Whitelist, Firewall Block List, Monitor Sessions, History all share the same checkbox + sticky action bar pattern with matching `DELETE /api/<resource>/batch` endpoints
- 447 unit tests, all passing

---

## Sprint 2 — Apr 14–15, 2026 (Alerting & detection depth) — shipped v1.2.0

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

## Sprint 3 — Apr 15–16, 2026 (Remediation & automation) — shipped v1.3.0

- [x] Remediation suggestions — each rule includes a "how to fix" recommendation with step-by-step guidance
- [x] Remediation tab rewrite — group fixes by rule and show MITRE mitigation IDs (M1026, etc.)
- [x] Scheduled scans — watch a folder for new `.evtx` files and auto-scan on arrival
- [x] Recurring reports — auto-generate daily or weekly HTML summary reports
- [x] PDF export — download formatted PDF reports from the dashboard
- [x] Report comparison — diff two scans side by side, highlight new / resolved findings
- [x] "Mark reviewed" status — per-finding state saved to DB, persists across scans
- [x] CLI `--quiet` / `--json-only` — machine-friendly output for cron pipelines

---

## Sprint 4 — Apr 17–24, 2026 (Multi-host & firewall) — shipped v1.4.0

- [x] Multi-machine support — track scores per hostname, compare security posture across endpoints
- [x] Hostname auto-detection — parse `Computer` field from each `.evtx` event, tag findings
- [x] Per-host dashboard view — pick a machine, see only its history and trend
- [x] Fleet overview page — sortable table of all machines with score, last scan, top severity
- [x] Firewall log parser — parse `pfirewall.log`, extract blocked / allowed connections
- [x] Suspicious outbound detection — flag DROPs from public IPs to high-value ports (3389, 22, 445, 3306, 5985), plus port-scan aggregation across many dst-ports
- [x] Firewall rule misconfiguration rules — any-any rules, disabled profiles, overly broad scope
- [x] **IP block list** — Pulse-owned list of blocked source IPs pushed into Windows Firewall via `netsh advfirewall` as inbound deny rules. Every rule is prefixed `Pulse-managed:` so user-authored rules are never touched; optional comment per entry; add / push / unblock from the Firewall page and CLI
- [x] One-click "block source IP" action — any finding with a source IP shows a Block button in the detail drawer that stages the IP with a comment linking back to the finding
- [x] Audit log — track who scanned what and when within the dashboard
- [x] Export fleet CSV — one-row-per-host summary for spreadsheets

---

## Sprint 5 — Apr 25 – May 1, 2026 (Auth, compliance, analytics)

- [x] User authentication — login page backed by SQLite users table with scrypt hashes (shipped early, single-user)
- [x] Session management — signed cookies, logout, 30-day expiry (shipped early)
- [x] Role-based access — admin (full) vs viewer (read-only) roles enforced in API
- [x] Score-over-time chart — line chart of daily scores on the Dashboard
- [x] Multi-user account management — admin can create, edit, and deactivate user accounts from the dashboard (Settings > Users)
- [x] Data isolation — viewers see only their own scans / findings / reports; admins see all (scan_scope_for)
- [x] Admin activity history — Audit page shows every block/unblock/scan/review action, filterable by user and action type, CSV export
- [x] Hosted deployment — Pulse runs on Render with env-var config fallback, production CORS lock, disabled `/docs`, startup health log
- [x] Profile picture upload — stored as a BLOB on the users row so it survives Render restarts; auto-syncs to top-right avatar
- [x] NIST CSF mapping — every rule tagged against Identify / Protect / Detect / Respond / Recover subcategories
- [x] ISO 27001 mapping — every rule linked to an Annex A control (A.9 access, A.12 ops, etc.)
- [x] Compliance report view — Compliance page shows per-CSF-function + per-clause coverage and a per-rule lookup table
- [x] Trend analytics page — Trends page with window-over-window delta, daily finding line chart, severity breakdown, top rules + top hosts bars
- [x] API token auth — generate / revoke tokens for CI pipelines hitting `/api/scan` (Settings > API Tokens; Bearer header, per-user, sha256-at-rest, raw shown once, `last_used_at` bumps on every call)
- [ ] PostgreSQL migration — replace SQLite with PostgreSQL, include a migration script that moves existing pulse.db data automatically, keep SQLite as fallback for local single-user installs

---

## Sprint 6 — May 2–8, 2026 (Workflows, branding, threat intel)

- [ ] Windows Service installer — one-time setup that installs Pulse as a Windows Service running with SYSTEM privileges, so scheduled scans and system log access always work without manual elevation
- [ ] Incident workflow states — mark findings as acknowledged, investigating, or resolved
- [ ] Analyst notes — free-text notes field per finding, stored in DB, shown in report
- [ ] Assignment — assign a finding to a user, filter dashboard by "assigned to me"
- [ ] Custom branding — upload company logo, set organization name on reports and dashboard
- [ ] Configurable severity colours — override the default CRITICAL/HIGH/MEDIUM palette
- [ ] Dashboard widgets — customizable layout with drag-and-drop panels
- [ ] Threat intel integration — correlate source IPs with AbuseIPDB / OTX feeds
- [ ] IOC lookup panel — paste an IP or hash, query intel feeds, cache results locally
- [ ] Weekly threat brief — auto-emailed digest of top findings across the fleet
- [ ] Public landing page — a clean page explaining what Pulse does with a download link for the CLI and an email signup for updates
- [ ] Email waitlist — store signups in the database, exportable as CSV
- [ ] In-app feedback button — lets users submit feedback without leaving the app, stored in DB
