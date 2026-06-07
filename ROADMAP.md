# Pulse Roadmap

Flat status board organized by category, sorted by priority within each section. See [CHANGELOG.md](CHANGELOG.md) for commit-level history.

**Priority key:** 🔴 Urgent · 🟠 High · 🟡 Medium · 🟢 Low

---

## 🟦 In Progress

> Currently being built. Cap at 1–2 to keep focus.

*Nothing in flight right now.*

---

## 🟪 Up Next

> The next things to pull into **In Progress**. Top-of-list ships next.

| Priority | Item | Notes |
|---|---|---|
| 🟠 High | **Sysmon log support — Phase 2** | Phase 1 shipped (2026-06-03): parser plumbing + Event 1 process-create command-line analysis ("Suspicious Process Creation" rule). Remaining: Event 3 (network connections for C2 beaconing), Event 10 (process access for LSASS credential dumping), Event 22 (DNS queries for tunneling). Parser already fetches all four IDs; Phase 2 adds the three remaining detections. |
| 🟡 Medium | **Rule performance dashboard** | Performance tab on Rules page: per-rule total hits, 24h sparkline, TP vs FP ratio, average scan time, health indicator (green/amber/red). |

---

## 🟧 Blocked

> Work that needs an external resource (hardware, cert, decision) before it can land.

| Priority | Item | Blocked on |
|---|---|---|
| 🟠 High | **Bundled Windows Service installer** | Windows test box for `sc.exe` / NSSM validation. README documents the manual install paths today. |
| 🟡 Medium | **Local dashboard mode toggle** | Bundled installer above. Single-checkbox at install time picks "agent only" vs. "local single-user dashboard". |
| 🟠 High | **Code-signed `pulse-agent.exe`** | Authenticode cert acquisition. Stops SmartScreen from flagging the download. |
| 🟠 High | **Agent auto-download + signature verification** | Code-signing cert (above). The probe channel (`/api/agent/latest`) is shipped; the verification half waits on the cert. |

---

## 📋 Development Backlog

> Validated work, prioritized. Pull from the top of each tier into Up Next when capacity opens.

### 🔴 Urgent / 🟠 High — Security & operational maturity

| Item | Notes |
|---|---|
| **Encrypted config secrets** | Fernet encryption for SMTP password / webhook URLs / API keys in `pulse.yaml` using machine-derived key. Auto-encrypt plaintext secrets on first run after upgrade. Env vars bypass config file entirely. |
| **Session hardening** | CSRF tokens on state-changing endpoints, `SameSite=Strict` cookies (currently `Lax`), configurable idle timeout (default 30 min), active-sessions list in Settings → Profile with *Revoke* option. |
| **Webhook signature verification** | HMAC-SHA256 signature + `X-Pulse-Signature` header on outgoing Slack/Discord payloads with documented verification process. |
| **Data retention policy** | Settings → Advanced → Retention with configurable windows per data type (findings 365d, scans 365d, audit log 730d, notifications 90d). Daily background purge job. Audit log entries about purges exempt from purging. Dry-run mode. |
| **API rate limiting (per-token)** | Per-token (60/min default) and per-IP (120/min unauthenticated) limits on top of the existing endpoint-level caps. HTTP 429 + `Retry-After`. `X-RateLimit-Remaining` / `X-RateLimit-Reset` headers. Per-token override in Settings → API Tokens. |

### 🟡 Medium — Distribution & DX

| Item | Notes |
|---|---|
| **AI Security Advisor (live)** | Premium tier — integrate the Anthropic API for contextual "explain this finding" / "what should I do" on individual findings. Sends event data + rule context to Claude with a SOC-analyst system prompt; result shown in the finding drawer next to the existing static Security Guide. Cache responses per finding ID. Requires the user to configure an Anthropic API key in Settings → Integrations. Justifies a paid tier in the future pricing model alongside the multi-tenant hosted deploy. |
| **Evidence export** | *Export incident package* button on findings. Generates ZIP with: scoped PDF report, raw event XML, related audit entries, analyst notes, JSON manifest with SHA-256 hashes for chain-of-custody. Available from detail drawer + bulk action bar. |
| **Docker distribution** | `Dockerfile` + `docker-compose.yml` bundling Pulse + PostgreSQL. `PULSE_ADMIN_EMAIL` + `PULSE_ADMIN_PASSWORD` env vars for first-run setup. Persistent volumes for DB + uploads. |
| **One-liner install script** | `curl \| bash` script for Linux: install deps, create systemd service, start on port 8443, print admin URL. |
| **CONTRIBUTING.md** | Dev environment setup, running tests, adding a detection rule (step-by-step with example), adding a dashboard page, code style, PR review process. |
| **Sample data bundle** | `samples/` directory with 3–4 synthetic `.evtx` files containing known threats (brute force, credential dumping, lateral movement, persistence), sample `pfirewall.log`, README explaining what each demonstrates. |

### 🟢 Low — Polish & nice-to-haves

| Item | Notes |
|---|---|
| **Remote log collection via WinRM** | Enter hostname/IP, Pulse pulls Security/Application/System event logs over WinRM, runs detections against them. Complements the agent model (agent pushes, WinRM pulls). Needs credential management + connectivity check. |
| **Alert fatigue metrics** | Card on Dashboard / section on Trends: alerts suppressed by throttling this week, reviewed vs ignored ratio, dead rules (zero fires), noisy rules (high fire + high FP rate). |
| **Custom branding (v2)** | Admin uploads company logo + org name, both render as a *subtitle* under the Pulse mark — never as a replacement (v1 reverted 2026-04-24 because it killed brand recognition). Empty `branding` table still in DB; reuse the schema. |
| **Customizable dashboard layout (v2)** | Drag-reorder + hide/restore for KPI strip / standup row / charts / MITRE / last-scan findings. v1 shipped 2026-04-28, reverted 2026-04-29 — revisit only when there's a specific user signal. |
| **Sidebar filter configs (other pages)** | Per-page sidebar-filter framework already exists (`pulse/static/js/sidebar-filters.js`). Findings page is wired; wire each of Dashboard / Monitor / Fleet / Audit Log / Firewall with the right dimensions for that surface. |
| **Findings sidebar — Rule filter** | Top-N (10–15 rules) + "Show all" affordance — current list overflows the sidebar on noisy installs. |
| **Public landing page polish** | Live-demo link with read-only viewer + pre-loaded sample data, GitHub stars badge, test-count badge, social-proof section. |

---

## 🪲 Bugs

> Tracked defects. Drop in here with a one-line repro + the file where it bites; promote into **Up Next** with priority based on severity + frequency.

*No tracked bugs right now.*

---

## ❓ Decisions Needed

> Product questions that gate downstream work. Answer before pulling the dependent item into Up Next.

- **Pricing model** — free-for-N-agents vs. per-seat vs. self-host-only. Gates whether enrollment needs a billing layer.
- **Agent-to-server protocol** — REST (shipped, fast) vs. gRPC (more efficient at fleet scale). Default: stay on REST until fleet size justifies the migration.
- **Code-signing certificate** — needed before SmartScreen-friendly public distribution of `pulse-agent.exe`. Cheapest path: Sectigo / DigiCert OV (~$200/year). EV needed for instant SmartScreen reputation.

---

## ✅ Shipped

<details>
<summary><strong>v1.8.0 — Security Advisor, Report Catalog, Role Hierarchy (June 2026) — click to expand</strong></summary>

- **Security Advisor + per-rule knowledge base** — plain-language Security Guide card in every finding drawer for all 30 detection rules. Security Advisor sidebar page with posture sentence, top concerns, attack-concept explainers, hardening checklist. Risk-level shields on the findings table. 68 new tests.
- **Report template catalog (9 templates)** — Threat Detection Summary, Executive Summary, NIST CSF Coverage, ISO 27001 Annex A, Incident Investigation (with chain-of-custody SHA-256 manifest), Fleet Health, Board-Ready Posture, MITRE ATT&CK Coverage, Compliance Gap Analysis. All four formats (PDF/HTML/JSON/CSV). DB-backed persistence with 90-day retention. Flat-grid catalog UI with category chip filter. Polished 560px generate modal (scope cards + 2×2 format grid). 1057 tests passing.
- **Three-role hierarchy** — admin > manager > analyst. Legacy viewer rows migrated to analyst at boot. Role badges (A/Mg/An). Manager-level endpoint gating (whitelist, firewall, reports, audit exports).
- **SIGMA rule import** — paste community SIGMA YAML; evaluated alongside built-in rules. SIGMA Import tab on Rules page. 63 new tests.
- **Time-based correlation engine** — Brute-Force Success, Impossible Travel, Privilege Escalation Chain, Lateral Spray. 25 new tests.
- **Project root reorganization** — scripts/, docs/, installer/ subdirectories.
- **Bug fixes** — sign-in cache bug, viewer assignment visibility, Findings page filter state in URL.

</details>

<details>
<summary><strong>Post-v1.7.0 interim work (May 2026) — click to expand</strong></summary>

- **Email verification on signup** (2026-05-13)
- **Agent tamper resistance** — `pulse-agent harden` + ACL audit at startup. (2026-05-13)
- **Full security audit + hardening pass** — 8 issues fixed, 12 new security tests. (2026-05-14)
- **Dependency pinning + automated CVE scan** — `requirements-lock.txt`, `pip-audit` test. (2026-05-14)
- **Documentation refresh** + README rewrite, Dockerfile, CONTRIBUTING.md. (2026-05-14 / 2026-05-27)

</details>

<details>
<summary><strong>v1.7.0 — Agent / server split + multi-tenant (May 2026) — click to expand</strong></summary>

The hosted dashboard on Render couldn't scan a Windows machine itself. Sprint 7 split Pulse into a hosted multi-tenant dashboard + downloadable Windows agent.

**Hosted dashboard:**
- Multi-tenant data model — `organizations` table + `organization_id` denormalized onto users, scans, agents, notifications. `_read_scope_kwargs` API helper. Self-signup creates a fresh org; admin-side user creation joins the admin's org. Idempotent backfill at every `init_db`. Cross-org reads/writes return 404 / no-op.
- Agent enrollment flow — Settings → Agents mints single-use 1h-TTL `pe_…` enrollment tokens; agent exchanges via `POST /api/agent/exchange` for long-lived `pa_…` bearer. Both sha256-at-rest, raw values shown once.
- Agent status panel — Settings → Agents lists every host with status pill (online / stale / offline / paused / pending), last-heartbeat, hostname + platform + version. Pause + Delete actions per row.
- `POST /api/agent/heartbeat` + `POST /api/agent/findings` — heartbeat bumps `last_heartbeat_at` + surfaces paused flag; findings ingest writes a scan attributed to the enrolling user with `scans.agent_id` stamped. Paused agents ack but drop findings.
- Hide / disable "Scan my system" in hosted mode — topbar swaps to **Download Agent** on non-Windows hosts.
- Public multi-tenant signup — `PULSE_HOSTED_SIGNUP=1` opens `POST /api/auth/signup` past the first user.
- Marketing landing page — CrowdStrike-style site at `/` with hero, stats band, three use-case sections, 12-feature grid, three-step download flow, three-tier pricing, FAQ, multi-column footer.
- Windows download wire — `/api/agent/download` streams the locally-built bundle as a zip; landing page's Download CTA points at it with GitHub fallback via `/api/agent/download/check`.

**Downloadable Windows agent:**
- Packaged `pulse-agent.exe` via PyInstaller — `installer/pulse-agent.spec` + `scripts/build_agent.py`. One-folder bundle (37 MB / 6.5 MB launcher) or `--onefile`. Shipped as v1.7.0 GitHub release asset.
- Local-scan → HTTPS upload pipeline — `AgentRuntime` runs detections every 30 min, heartbeats every 60s, ships via `POST /api/agent/findings`. `AgentTransport` distinguishes transient (retry) from permanent (re-enroll) errors.
- Auto-update channel — `GET /api/agent/latest` returns `{version, download_url, release_notes_url}`. Bearer-auth branch computes `outdated`/`current` server-side.

</details>

<details>
<summary><strong>Sprint 6 — v1.6.0 (April–May 2026) — click to expand</strong></summary>

Workflows, branding, threat intel.

**ACs:**
- Incident workflow states — mark findings as acknowledged, investigating, or resolved.
- Analyst notes — free-text notes field per finding, shown in drawer + PDF, timestamped + author-attributed.
- Assignment — assign findings to users, filter dashboard by "assigned to me".
- Configurable severity colours — override the default CRITICAL/HIGH/MEDIUM palette.
- In-app feedback button — submit feedback without leaving the app.

**Deferred / reverted:**
- ~~Custom branding~~ — first pass shipped 2026-04-23, reverted 2026-04-24 (lost brand recognition). Tracked in Backlog as "Custom branding (v2)".
- ~~Dashboard widgets~~ — first pass shipped 2026-04-28, reverted 2026-04-29 (button surfaced before use case clear). Tracked in Backlog as "Customizable dashboard layout (v2)".
- ~~Windows Service installer~~ — moved to Sprint 7's downloadable-agent block; now in Blocked above.

**Bonus polish landed under v1.6.0:**
Relative timestamps everywhere; Scans → History merge; Reports page rewrite; Whitelist empty-state onboarding; Compliance Coverage Gaps; Getting Started checklist; Notification bell; Role visibility; Threat Intel inside the drawer; Firewall Rules tab live; Pulse Agents transport layer (server-side); Monitor first-start race fix; Topbar Scan-My-System hosted-mode swap.

</details>

<details>
<summary><strong>Sprints 2–5 — v1.2.0 through v1.5.0 (April 2026) — click to expand</strong></summary>

### Sprint 2 — v1.2.0 — Alerting & detection depth
- Email alerts (CRITICAL/HIGH summary) + throttling + live-monitor email alerts + Slack/Discord webhooks.
- Kerberoasting (4769 RC4), Golden Ticket, DCSync, Suspicious Child Process detections.
- Finding detail drawer + dashboard search.

### Sprint 3 — v1.3.0 — Remediation & automation
- Remediation suggestions per rule + MITRE mitigation IDs.
- Scheduled scans (folder watch) + recurring HTML summary reports.
- PDF export from dashboard; scan comparison (diff two scans).
- "Mark reviewed" persisted state; CLI `--quiet` / `--json-only`.

### Sprint 4 — v1.4.0 — Multi-host & firewall
- Hostname auto-detection from `Computer` field; per-host dashboard + Fleet overview.
- `pfirewall.log` parser + sensitive-port detection (3389 / 22 / 445 / 3306 / 5985).
- Firewall rule misconfiguration rules (any-any, disabled profiles).
- IP block list (Pulse-managed `netsh` rules, prefix-tagged so user rules untouched).
- One-click "block source IP" from finding drawer; audit log; fleet CSV export.

### Sprint 5 — v1.5.0 — Auth, compliance, analytics
- Auth: scrypt password hashing, signed session cookies, 30-day expiry, RBAC (admin/viewer).
- Multi-user account management (Settings → Users); per-user data isolation; admin activity history.
- Hosted deployment to Render (env-var config fallback, prod CORS lock, disabled `/docs`).
- Profile picture upload (BLOB on user row).
- NIST CSF + ISO 27001 mapping per rule; Compliance page; Trend analytics page.
- API token auth (Bearer header, per-user, sha256-at-rest); PostgreSQL migration support (`db_backend.py` adapter).
- **UX blueprint pass** — design tokens, Ctrl+K command palette, universal drawer primitive, Monitor / Rules / Fleet / Firewall / Whitelist / Dashboard / Compliance / Trends rebuilds.

</details>

<details>
<summary><strong>Foundation — pre-v1.2.0 — click to expand</strong></summary>

- `.evtx` file parsing (parallel, per-file timeout)
- 22 detection rules covering login attacks, persistence, defence evasion, credential abuse
- Attack chain correlation (multi-event patterns)
- MITRE ATT&CK tagging
- Scan summary statistics
- Text / HTML / JSON / CSV report formats
- CLI flags (`--logs`, `--output`, `--format`, `--severity`, `--days`, `--email`, `--api`, etc.)
- Config file support (`pulse.yaml`)
- Whitelist / allowlist + built-in 100+ known-good service whitelist
- Baseline comparison (`--save-baseline`)
- Email delivery via SMTP
- SQLite scan history + `--history` flag with trends
- Deduplicated daily scoring with A–F grades
- Live monitoring (CLI `--watch`)
- Interactive terminal mode (`--interactive`)
- Parallel file parsing across CPU cores
- ECG heartbeat animation during parsing
- REST API (FastAPI) — `/api/scan`, `/api/history`, `/api/report/{id}`, `/api/health`, Swagger at `/docs`
- Web dashboard — single-page dark-themed UI, drag-and-drop upload, score ring, theme toggle
- Functional Settings & Whitelist pages
- Report export from dashboard
- Multi-file upload
- Live monitor in dashboard (SSE)
- Dashboard authentication (single-user)
- Frontend modularized (native ES modules under `pulse/static/js/`)
- Firewall feature set (CLI + dashboard)
- PDF report overhaul (grade-coloured score ring)
- Position-based scan numbering
- Real SPA URL routing
- Bulk-select + batch-delete on every list page

</details>
