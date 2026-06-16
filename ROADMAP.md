# Pulse Roadmap

Flat status board organized by category, sorted by priority within each section. See [CHANGELOG.md](CHANGELOG.md) for commit-level history.

**Priority key:** 🔴 Urgent · 🟠 High · 🟡 Medium · 🟢 Low

---

## 🟦 In Progress

> Currently being built. Cap at 1–2 to keep focus.

*Nothing in flight right now.* (Security PIN shipped 2026-06-08 — see CHANGELOG.)

---

## 🟪 Up Next

> The next things to pull into **In Progress**. Top-of-list ships next.

*Nothing queued right now — pull from the Development Backlog below (the **Add-host onboarding** under Distribution is the highest-leverage adoption item).*

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
| **Multi-tenant hardening (before hosted signup)** | **Data-isolation core ✅ shipped 2026-06-16** — hosted org admins are now pinned to their own organization (`_read_scope_kwargs` + `_has_global_scope`), `/api/users` list/role/active/delete are org-scoped (404 on a cross-org id so existence doesn't leak), the "last admin" guard counts per-org, and a private **platform super-admin** allowlist (`PULSE_SUPERADMIN_EMAILS`, env-only — not grantable via signup/API) keeps global scope. Single-tenant self-host is unchanged (admin still sees CLI/NULL-org scans). 11-test multi-org suite ([`tests/test_multitenant_admin_scope.py`](tests/test_multitenant_admin_scope.py)) proves admin-of-A can't read/touch org-B and the super-admin still can. **Still to do before public signup:** CSRF custom-header check on mutating routes; trusted-proxy allowlist for the rate-limiter's `X-Forwarded-For` (today XFF is trusted blindly); and an audit of the remaining admin-list surfaces (feedback, notifications) for org scoping. |
| **Invite-by-code onboarding for teammates** | Replace the current "admin types a teammate's email + password" flow with an invite link/code: admin picks a role (Manager/Analyst) → one-time, expiring invite link → the specialist opens it, sets *their own* password, and joins the org with that role. The cleaner UX for the "sign up → invite specialists" model. Pairs with multi-tenant hardening above. |
| **Encrypted config secrets** | Fernet encryption for SMTP password / webhook URLs / API keys in `pulse.yaml` using machine-derived key. Auto-encrypt plaintext secrets on first run after upgrade. Env vars bypass config file entirely. |
| **Session hardening** | CSRF tokens on state-changing endpoints, `SameSite=Strict` cookies (currently `Lax`), configurable idle timeout (default 30 min), active-sessions list in Settings → Profile with *Revoke* option. |
| **Webhook signature verification** | HMAC-SHA256 signature + `X-Pulse-Signature` header on outgoing Slack/Discord payloads with documented verification process. |
| **Data retention policy** | Settings → Advanced → Retention with configurable windows per data type (findings 365d, scans 365d, audit log 730d, notifications 90d). Daily background purge job. Audit log entries about purges exempt from purging. Dry-run mode. |
| **API rate limiting (per-token)** | Per-token (60/min default) and per-IP (120/min unauthenticated) limits on top of the existing endpoint-level caps. HTTP 429 + `Retry-After`. `X-RateLimit-Remaining` / `X-RateLimit-Reset` headers. Per-token override in Settings → API Tokens. |

### 🟡 Medium — Distribution & DX

| Item | Notes |
|---|---|
| **Security Buddy ("Pip") — live AI assistant** | ✅ **MVP shipped 2026-06-16** (floating chat circle, backend-proxied Haiku 4.5, 10 free Q/day metering, dynamic follow-up suggestions, prompt-injection-safe — see Shipped). Full design in [research report §2](.claude/research/2026-06-07-triage-drawer-ux-and-security-buddy.md). **Still to do (post-MVP):** streaming responses; cache the canned per-finding explanation by `finding_id` to serve repeats free; paid tier (higher daily cap) + `bonus_questions` admin top-up UI; token-usage logging for cost monitoring; optional IP/username redaction before send. Positioning: *explanation, not autonomy* — helps you understand and decide, never acts on its own. The headline differentiator for the "no-SOC" buyer priced out of Security Copilot ($2,920/mo per SCU) et al. |
| **Pip knowledge base — curated, grounded reference** | Give Pip vetted, battle-tested cybersecurity knowledge so it answers from documented fact, not just the model's training. **Idea (Robert, 2026-06-16):** maintain a structured reference (Markdown files, e.g. `pulse/buddy_knowledge/`) covering Windows event IDs, attack techniques mapped to the detection rules, common false-positive patterns, and "first response" playbooks — written/curated over time from real experience. **Approach:** start simple — inject a concise, relevant slice into the system prompt per question (cheap, no infra). Grow into retrieval (embed the docs, fetch the top-k relevant chunks per question) only if the corpus gets large enough that injecting it all costs too many tokens. Keep each entry short (token cost is per question), version it, and prefer linking the user to the matching Security Advisor / knowledge-base entry already in Pulse so the in-app docs and Pip stay consistent. Pairs with the local `knowledge_base.py` that already powers the Security Advisor — Pip could read from the same source of truth. |
| **Evidence export** | *Export incident package* button on findings. Generates ZIP with: scoped PDF report, raw event XML, related audit entries, analyst notes, JSON manifest with SHA-256 hashes for chain-of-custody. Available from detail drawer + bulk action bar. |
| **Docker distribution** | `Dockerfile` + `docker-compose.yml` bundling Pulse + PostgreSQL. `PULSE_ADMIN_EMAIL` + `PULSE_ADMIN_PASSWORD` env vars for first-run setup. Persistent volumes for DB + uploads. |
| **One-liner install script** | `curl \| bash` script for Linux: install deps, create systemd service, start on port 8443, print admin URL. |
| **"Add a host" onboarding (agent enrollment)** | Turn the Settings → Agents panel into a real onboarding flow: a **download button** for the agent + a **copy-paste command with the live enrollment token already filled in**, and a **one-line PowerShell installer** (`iwr https://<server>/install.ps1 \| iex`, token baked in) that downloads the agent, **registers it as a Windows Service / scheduled task** (survives reboot + logoff), and enrolls it — so a customer connects a machine in ~2 min instead of hand-running CLI steps. Server-side `GET /install.ps1`. **This is the highest-leverage adoption gap** — the detection engine + agent transport + enrollment are already done; this is the missing onboarding UX. (Depends on the bundled `pulse-agent.exe` from Blocked for the polished version; a Python-runtime script works today.) |
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

- **Pricing model** — open-core: the detection engine stays free/open-source (self-host = $0, the funnel); monetize the **hosted convenience + premium features** (Security Buddy, report catalog, multi-host fleet, longer retention). Audience is price-sensitive (freelancers / 3-person startups / nonprofits / students), so keep it cheap + simple. **Cost reality:** AI is *not* the cost driver — each Buddy question ≈ $0.006, so a paid user @ 10/day costs ~$0.50–1.80/mo in API; hosting + maintainer time are the real costs. **Working hypothesis:** one **Pro tier ~$7–12/mo** (or ~$70–120/yr) with a hard-capped free hosted tier (1 host, 10 Buddy Q/day, 30-day retention) as marketing. Don't bill AI per-question to users — bundle it under a daily cap (the cap is abuse control, not cost recovery). Validate demand before locking numbers. Gates whether enrollment needs a billing layer (Stripe). Full cost model: [research report §2.1](.claude/research/2026-06-07-triage-drawer-ux-and-security-buddy.md).
- **Scale + concurrency ceiling** — *"Can Pulse handle heavy load / many people working at once?"* **Honest read:** for its actual job — host-based Windows event-log detection for a **small team** — yes. FastAPI is async (handles many concurrent users), the data is org-scoped, and the roles/queue model is built for several analysts triaging at once. Agents scan every ~30 min and ship only *findings* (not raw logs), so even dozens–low-hundreds of hosts is light traffic. **The real ceiling is the database:** SQLite (the default) has a single-writer lock that bottlenecks under heavy concurrent writes. **Recommendation:** make **Postgres the default for any hosted / multi-user deployment** (already supported via `db_backend` — this is config, not a rewrite); load-test "N analysts + M agents" and document the supported envelope; only add a job-queue for agent ingestion when host counts actually grow into the thousands. Don't over-engineer ahead of demand.
- **Web / application *traffic* monitoring — a different lane?** — *"Could someone use Pulse to manage the traffic of a website/app?"* **Honest read: not today, and it's a different product category.** Pulse analyzes **host event logs** (periodic, batch) for *threats* — it is not a real-time, high-throughput **traffic** monitor (that's WAF / reverse-proxy / APM / streaming-SIEM territory: thousands of events/sec, a streaming ingest pipeline, a time-series store). Bolting that onto the current architecture would be a major build, not a feature. **Recommendation:** **stay in lane** — be the best "Windows threat detection for people without a SOC," not a worse Datadog/Cloudflare. If web/app-log *security* detection is wanted later, the right shape is a **generic log-shipper + detections for non-Windows sources** (web access logs, syslog, app logs) feeding the *same* findings model — a deliberate post-PMF expansion, gated on real demand. Validate that customers ask for it before building.
- **Agent-to-server protocol** — REST (shipped, fast) vs. gRPC (more efficient at fleet scale). Default: stay on REST until fleet size justifies the migration.
- **Code-signing certificate** — needed before SmartScreen-friendly public distribution of `pulse-agent.exe`. Cheapest path: Sectigo / DigiCert OV (~$200/year). EV needed for instant SmartScreen reputation.

---

## ✅ Shipped

<details>
<summary><strong>Post-v1.8.0 work (June 2026) — click to expand</strong></summary>

- **Security Buddy ("Pip") — live AI assistant (MVP)** — a floating robot chat circle in the bottom-right corner of the dashboard. Click it to ask Pip anything: what a finding means, whether something looks dangerous, or general security questions. Answers come from **Claude Haiku 4.5**, proxied **server-side** through `POST /api/buddy/ask` so the Anthropic API key never touches the browser (read from the `ANTHROPIC_API_KEY` env var). Metered per user per UTC day via a new `user_ai_usage` table — **10 free questions/day** (admins can top up an account via `bonus_questions`), `429` + friendly "you're out for today" message when exhausted, counter shown in the panel. Security posture: read-only/no-tools, event-log/finding text passed to the model is fenced in an `<untrusted_data>` block with a system-prompt instruction to treat it as data (prompt-injection defense), output is HTML-escaped before render, and the panel discloses that chats are sent to Anthropic. Opening a finding drawer slides Pip left to sit beside it and hands Pip that finding's details so the user can ask about what they're reading — shown transparently as a "Looking at &lt;rule&gt;" pill so it's never a mystery what Pip can see (and cleared when the drawer closes; otherwise Pip only knows what the user types). Replies never use em dashes (stripped server-side), persist in the browser across refreshes (with a "New chat" reset), and stay in scope — for anything Pip can't help with it points to the in-app Feedback option and the GitHub issues page. Degrades gracefully when no key is configured ("Pip isn't set up yet"). (2026-06-16)
- **Multi-tenant admin isolation (data-isolation core)** — closed the cross-tenant gap that would have let one hosted org's admin read and manage another org's data. Hosted org admins are now scoped to their own organization for reads and for every `/api/users` operation (list/role/active/delete, 404 on a cross-org id so existence doesn't leak); the "last admin" guard counts per-org; and a private env-only super-admin allowlist (`PULSE_SUPERADMIN_EMAILS`) keeps global scope. Single-tenant self-host is unchanged. 11 new isolation tests. *Remaining before public signup: CSRF header check + trusted-proxy `X-Forwarded-For` allowlist.* (2026-06-16)
- **Team Workload moved to its own "Team" page** — the per-analyst manager oversight view (open count, severity mix, oldest-unresolved age, avg fix time) was pulled off the Dashboard into a dedicated **Team** sidebar item, gated to managers/admins. Also blocked browser autofill of the saved login email into the Findings / Dashboard / Audit / Firewall search boxes (readonly-until-focus, since Chrome ignores `autocomplete="off"`). (2026-06-16)
- **Rule performance dashboard** — new **Performance** tab on the Rules page. Per-rule health view (`GET /api/rules/performance`) that classifies every rule green/amber/red: **noisy** (≥30 hits AND ≥30% false-positive rate — needs tuning), **watch** (silent/never-fired, or 15-30% FP), **healthy** (firing cleanly), **disabled**. Header tiles for healthy / need-a-look / noisy / silent counts + average scan time + scans analyzed. Rows sorted problems-first with a health dot, 24h sparkline, TP/FP breakdown, and last-fired. 9 new tests. (2026-06-07)
- **Finding drawer redesign** — restructured for the non-expert: leads with the plain-language summary + difficulty, a single "What to do now" action list, a compact "Framework references" line (MITRE pills only), raw event data deduplicated into a collapsed "Technical details" section, and a "Tracking" separator over the workflow/notes controls. (2026-06-07)
- **First-run hero** — new accounts with zero scans open to a focused "Run your first scan" call to action instead of an empty dashboard. (2026-06-07)
- **CLI + UI polish** — `--logs` accepts a single `.evtx` file; "New findings" KPI relabeled "Untriaged"; equal-height data-reduction funnel boxes. (2026-06-07)
- **Sysmon log support** — full coverage of the four high-value Sysmon event types. Parser fetches the Sysmon channel (Event IDs 1, 3, 10, 22), all detections provider-gated. Four new rules: **Suspicious Process Creation** (Event 1 — command-line analysis for encoded PowerShell, LOLBins, credential tooling, Office-spawns-shell), **LSASS Memory Access** (Event 10 — credential dumping via memory-read handle to lsass.exe, allow-list + access-mask gated, CRITICAL), **Suspicious Network Connection** (Event 3 — LOLBin outbound + C2 ports), **Suspicious DNS Query** (Event 22 — tunneling via long subdomain labels). Knowledge-base entries + compliance mappings for all four. New `sysmon-execution-chain.evtx` sample. 65 new tests. Also defanged the literal Mimikatz module strings out of every `.evtx` sample so cloning the repo no longer trips endpoint AV's `HackTool:Win32/Mimikatz` content signature on synthetic test data. (2026-06-03)

</details>

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
