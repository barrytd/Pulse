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
- [x] PostgreSQL migration — new `pulse/db_backend.py` adapter lets Pulse run against SQLite (default) or PostgreSQL (`DATABASE_URL=postgresql://…`); `scripts/migrate_to_postgres.py` copies an existing `pulse.db` into a target Postgres database and bumps per-table id sequences; SQLite stays the fallback for local single-user installs
- [x] **UX blueprint pass** — full dashboard UX rebuild against `.claude/skills/pulse-ux-blueprint.md`: design-token rollout (semantic colors, spacing, type scale), Ctrl+K command palette with fuzzy scoring + recents, universal right-side drawer primitive, Monitor three-band rebuild, Rules page with per-rule hit counts + 24h sparkline + MITRE coverage matrix, Fleet KPI strip + host-detail drawer, Firewall pending-changes banner + tiered bulk-confirm, Whitelist KPI strip + tiered bulk-confirm, Dashboard standup row (reduction funnel + top offenders), Compliance hero coverage gauge + stacked bar, Trends mean-±2σ anomaly bands

---

## Sprint 6 — May 2–8, 2026 (Workflows, branding, threat intel)

- [ ] Windows Service installer — one-time setup that installs Pulse as a Windows Service running with SYSTEM privileges, so scheduled scans and system log access always work without manual elevation
- [x] Incident workflow states — mark findings as acknowledged, investigating, or resolved
- [x] Analyst notes — free-text notes field per finding, stored in DB, shown in finding drawer and PDF reports, timestamped and attributed to the author
- [x] Assignment — assign a finding to a user, filter dashboard by "assigned to me", show assignment in finding drawer and fleet detail
- [x] Custom branding — upload company logo, set organization name on reports and dashboard
- [ ] Configurable severity colours — override the default CRITICAL/HIGH/MEDIUM palette
- [ ] Dashboard widgets — customizable layout with drag-and-drop panels
- [ ] Threat intel integration — correlate source IPs with AbuseIPDB / OTX feeds
- [ ] IOC lookup panel — paste an IP or hash, query intel feeds, cache results locally
- [ ] Weekly threat brief — auto-emailed digest of top findings across the fleet
- [ ] Public landing page — a clean page explaining what Pulse does with a download link for the CLI and an email signup for updates
- [ ] Email waitlist — store signups in the database, exportable as CSV
- [x] In-app feedback button — lets users submit feedback without leaving the app, stored in DB

---

## Sprint 7 — TBD (Agent / server split — the Splunk distribution model)

The hosted dashboard on Render can't scan a Windows machine itself — the OS can't read `.evtx` files or tail the Windows Event Log. "Scan my system" from the hosted UI currently fails with an authorization error because the server has no access to the user's local logs. The plan is to split Pulse the way Splunk does: a hosted multi-tenant dashboard + a downloadable Windows agent that ships detections to it over HTTPS.

### Hosted dashboard (stays on Render)
- [ ] Multi-tenant data model — every scan / finding / fleet row scoped to an `organization_id` so agents from different customers never cross-contaminate
- [ ] Agent enrollment flow — Settings > Agents page generates a per-host enrollment token (long-lived, rotatable, scoped to one org); install script on Windows consumes it once and exchanges for a regular API token
- [ ] Agent status panel — each registered host shows last-heartbeat, agent version, auto-scan schedule, "pause agent" button; stale agents (>24h no check-in) turn red on the Fleet page
- [ ] `POST /api/agent/heartbeat` + `POST /api/agent/findings` — new endpoints the agent hits instead of uploading raw `.evtx`. Findings arrive pre-computed so the server never has to run detections on Linux
- [ ] Hide / disable "Scan my system" in hosted mode — replace with a **Download Pulse Agent** button that links to the installer; CLI-upload path stays usable for analysts who prefer to scan manually
- [ ] Public landing / signup page — Splunk-style `pulse.io`-ish marketing page with Sign Up → org created → agent download link in one flow

### Downloadable Windows agent
- [ ] Packaged `pulse-agent.exe` via PyInstaller — reuses `pulse/detections.py` and `pulse/core/rules_config.py`; bundles a minimal config + YAML enrollment token
- [ ] Windows Service installer — registers Pulse Agent as a SYSTEM-privileged service (moved up from Sprint 6) so scheduled scans + Event Log access work without manual UAC each time
- [ ] Local-scan → HTTPS upload pipeline — agent runs detections every N minutes, POSTs findings to the hosted API using the enrollment-minted bearer token; retries + offline queue if the dashboard is unreachable
- [ ] Tamper resistance — service locked to Administrators for start/stop, token file ACL'd to SYSTEM + Administrators
- [ ] Auto-update channel — agent checks `GET /api/agent/latest` on startup, downloads + verifies a signed installer when a newer version is available
- [ ] Local dashboard mode (optional) — same installer can run Pulse as a single-user local dashboard (current behavior) instead of as an agent, controlled by one install-time checkbox

### Deferred product questions (flag before starting this sprint)
- Pricing model: free-for-N-agents vs. per-seat vs. self-host-only? Changes whether enrollment needs a billing gate
- Agent-to-server protocol: plain REST (shipped fast) vs. gRPC (more efficient at fleet scale). Start with REST
- Code signing: agent `.exe` needs a real Authenticode cert for SmartScreen to stop warning on download

---

## Backlog — unscheduled, prioritized by impact

Features validated by SOC/SIEM research but not yet committed to a sprint. Ordered roughly by impact-to-effort ratio.

### Detection depth

- [ ] SIGMA rule import — parse SIGMA YAML files and convert them into Pulse detection rules, enabling community rule packs (thousands of rules on SigmaHQ/sigma GitHub) without hand-writing each one
- [ ] Time-based correlation rules — sequence and threshold detections that reason over windows of time rather than single events:
  - Brute force success: N failed logins (4625) followed by a successful login (4624) from the same source IP within a configurable window
  - Impossible travel: same user authenticating from two different hosts within seconds
  - Privilege escalation chain: new user created (4720) then immediately added to an admin group (4728/4732)
  - Lateral spray: same source IP hitting 3+ distinct hosts within 5 minutes
- [ ] Sysmon log support — parse Sysmon channel events (Event 1 process create, Event 3 network connection, Event 7 image load, Event 11 file create, Event 22 DNS query) to enable command-line-pattern detections (Mimikatz, encoded PowerShell, LOLBins) and network-based detections (C2 beaconing frequency, DNS tunneling) that are impossible with standard Security/Application/System logs alone

### Operational health

- [ ] Alert fatigue metrics — surface detection-pipeline health data: alerts suppressed by throttling this week, reviewed vs ignored ratio, dead rules (never triggered), noisy rules (high fire rate + high false-positive rate); display as a card on Dashboard or a section on Trends
- [ ] API rate limiting — per-token request limits (e.g. 60 req/min default, configurable) to prevent misbehaving agents or scripts from hammering the API; return 429 with Retry-After header
- [ ] Data retention policy — configurable retention window (90/180/365 days) with automatic archival or purge of aged findings, scans, and audit log entries; required for GDPR/HIPAA compliance and database performance at scale

### Incident response

- [ ] Evidence preservation — "Export incident package" button on any finding or group of findings that generates a ZIP containing: relevant raw .evtx snippet, PDF report scoped to those findings, audit log entries related to the incident, analyst notes, remediation actions taken, and a JSON manifest with hashes for chain-of-custody integrity

### Platform hardening

- [ ] Webhook signature verification — sign outgoing Slack/Discord webhook payloads with HMAC so receivers can verify authenticity
- [ ] Encrypted config secrets — encrypt SMTP passwords, API keys, and webhook URLs at rest in pulse.yaml using a machine-derived key rather than storing plaintext
- [ ] Session hardening — add CSRF tokens to state-changing API endpoints, enforce SameSite=Strict on session cookies, add idle timeout (configurable, default 30 min)
