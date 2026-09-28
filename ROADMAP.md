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

- **Add-host onboarding (agent enrollment)** | The highest-leverage adoption gap now that the public-signup security gates have all shipped (CSRF + XFF + org-scoping, plus the mandatory email OTP; see Shipped). Turn Settings → Agents into a real flow: download button + copy-paste command with the enrollment token pre-filled + a one-line PowerShell installer that registers the agent as a Windows service and enrolls it. See the **Add a host** row in the Development Backlog.

- **SOAR playbooks & integrations** | Turn Pulse from detect-and-report into detect-and-act: a connector layer (VirusTotal, GreyNoise, OTX alongside AbuseIPDB), a playbook engine (trigger → conditions → actions), and enrichment/response run inside the finding drawer so analysts never leave Pulse. Full design in [docs/2026-09-26-soar-playbooks-and-integrations.md](docs/2026-09-26-soar-playbooks-and-integrations.md). **Phases 1, 2 and 3 are shipped** (connector layer, playbook engine + Automations page, Investigate panel + five enrichment connectors, click-together builder, ClickUp/Jira tickets + outbound webhook; see Shipped). **Next:** Phase 4, the Toolkit hub, in the Automation & integrations backlog tier. Shodan and MISP / OpenCTI were not built in Phase 3 and remain open there.

- **Look-and-feel pass, part 2: other pages on the shared kit** | Part 1 (bundled Inter, the dashboard tightened, the shared `.ui-*` surface kit in `components.css`) shipped 2026-09-27; see Shipped. Next: move Findings, Fleet, Automations, Settings and the rest onto the kit's cards, spacing and type. The Settings narrow-screen bug (see Bugs) fits here.

*Public-signup security gate is complete — see the Development Backlog row.*

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
| ✅ **Public-signup gate — COMPLETE (all shipped)** | The multi-tenant *data-isolation* core plus all three hardening items are done, so open public signup is unblocked from a security standpoint. **1. ✅ CSRF protection — shipped 2026-06-26.** Mutating `/api/*` routes require a custom `X-Pulse-Request` header (a cross-site page can't set one); agent transport + Bearer requests are exempt. See CHANGELOG + [`tests/test_csrf.py`](tests/test_csrf.py). **2. ✅ Trusted-proxy `X-Forwarded-For` handling — shipped 2026-06-24.** `PULSE_TRUSTED_PROXY_HOPS` (default 0). **Deploy note: set `PULSE_TRUSTED_PROXY_HOPS=1` on Render.** See [`tests/test_rate_limit.py`](tests/test_rate_limit.py). **3. ✅ Org-scope admin-list surfaces — shipped 2026-06-26.** `GET /api/feedback` is now org-scoped like `/api/users`; notifications were already per-user (no cross-org surface). *(Also shipped alongside: the mandatory email OTP gate, 2026-06-25.)* |
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

### 🟠 High / 🟡 Medium — Automation & integrations (SOAR)

> Turn Pulse into a SIEM **+ SOAR** platform: react to findings automatically, and add outside services as drop-in connectors. Full design + API facts + phased plan: [docs/2026-09-26-soar-playbooks-and-integrations.md](docs/2026-09-26-soar-playbooks-and-integrations.md). Build in the three phases below, top-down.

| Item | Notes |
|---|---|
| ✅ **Phase 1 — Connector layer + VirusTotal — shipped 2026-09-26** | New `pulse/connectors/` with a base-class + self-registering pattern (mirrors how rules register). Port AbuseIPDB (`intel.py`) onto it as the first connector, then add **VirusTotal** (header `x-apikey`; endpoints `/ip_addresses/{ip}`, `/files/{hash}`, `/domains/{domain}`, `/urls/{id}`; free tier 4/min, 500/day; **public key is non-commercial → make it bring-your-own-key**). Show both verdicts **inside the finding drawer** next to the block button. No engine yet. Small, ships a wanted feature, proves the plugin model. **Start here.** |
| ✅ **Phase 2 — Playbook engine (no builder UI) — shipped 2026-09-26** | New `pulse/soar/engine.py` + 3 tables (`connectors_config`, `playbooks`, `playbook_runs`, all org-scoped). Playbook = stored JSON recipe: `trigger` (`finding_created`) → `conditions` → ordered `steps` (connector + action + placeholders like `{{ finding.source_ip }}`). Engine matches conditions, runs steps, logs every step to a run record. **Response actions default to approval-required (wire to the security PIN); enrichment auto-runs.** Create playbooks via API / JSON-paste (like SIGMA import). New **Automations** page listing playbooks + runs; show triggered runs in the finding drawer. Ship 2–3 built-in example playbooks. |
| **Phase 3 — Investigate panel, visual builder + connector catalog** | **Part 1 ✅ shipped 2026-09-27:** the Investigate panel, plus GreyNoise, AlienVault OTX, GeoIP, Whois (RDAP + port 43) and DNS connectors, and the Slack/Discord + firewall response connectors (shipped with Phase 2). GeoIP ships DB-IP Country Lite (bundled 2026-09-27, CC BY 4.0) and takes a user-supplied City database as an override; City Lite is too large to bundle and MaxMind's EULA forbids redistribution. **Part 2 ✅ shipped 2026-09-27:** the click-together playbook builder on the Automations page. **Part 3 ✅ shipped 2026-09-27:** ClickUp/Jira ticketing and a generic outbound webhook (both approval-gated). **Phase 3 is complete.** **Not built, still open:** Shodan, optional MISP / OpenCTI, and `if` blocks in the builder (JSON-only for now). Original scope: **Investigate panel** in the finding drawer: one click runs every enrichment connector that fits the finding's indicators (IP → AbuseIPDB + VirusTotal + GreyNoise + Shodan + GeoIP; domain → Whois + DNS; hash → VirusTotal), so the browser-bookmark tools become buttons inside Pulse. Click-together playbook builder (pick trigger, add condition rows, drag action steps) so a non-coder builds one without touching JSON. Fold in the bookmark-bar catalog: **GreyNoise, AlienVault OTX, Shodan, Whois/DNS, MaxMind GeoIP** (bundled GeoLite2 DB, offline), plus **ClickUp/Jira ticketing** and a **generic outbound webhook**. **MISP / OpenCTI** as optional, off-by-default, bring-your-own-instance intel-feed connectors (enrich from your feed; optionally push a finding's IOCs out to share). Generalize Slack/Discord (`webhook.py`) and firewall block (`blocker.py`) into response connectors. See the connector catalog in the design doc. |
| **Phase 4 — Unified Toolkit hub (post-Phase 3)** | A new left-sidebar page ("Toolkit" / "Workbench") that is one front door to everything: run any connector lookup on a pasted IP / domain / hash with no finding open (standalone Investigate), quick access to the MITRE / NIST / ISO frameworks and the Security Advisor knowledge base already in Pulse, the threat-intel connectors (incl. optional MISP / OpenCTI), and a small analyze-and-decode utility (base64 / hex, CyberChef-style). Mostly assembles pieces built in Phases 1–3; the only new work is the page + sidebar item (same pattern as Findings / Fleet) plus the decode tool. Idea (Robert, 2026-09-26): fold the scattered tools and browser bookmarks into one place so nobody leaves the app. Ship a first version after Phase 3. |
| ✅ **Safety rails (build into Phase 2, not after) — shipped with Phase 2** | Response steps PIN-gated by default; every run org-scoped + audit-logged; a connector failure (bad key / timeout / rate limit) logs and continues, never crashes the run; cache lookups keyed on (indicator, provider) like `intel_cache` already does, and respect each provider's per-minute cap so a finding burst doesn't blow the daily quota. |

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

- **Two detection rules aren't registered** — `DCSync Attempt` (CRITICAL, 4662) and `Suspicious Child Process` (HIGH, 4688) fire from [`pulse/core/detections.py`](pulse/core/detections.py) but have no entry in `RULE_META` ([`pulse/core/rules_config.py`](pulse/core/rules_config.py)), so they can't be switched off on the Rules page, have no NIST/ISO mapping, and fall back to the generic plain-language guide. Fix: add both to `RULE_META` and `KNOWLEDGE`.
- **Settings scrolls sideways on narrow screens** — at 420px wide, every card on a Settings tab is squeezed to about 128px and the page scrolls horizontally. Repro: open Settings → Notifications in a 420px-wide window. This was already there before 2026-09-27 and wasn't caused by the playbook-responses card. Likely cause: `.settings-layout` in [`pulse/static/css/components.css`](pulse/static/css/components.css) keeps its `200px 1fr` grid with no narrow-screen breakpoint, so the tab nav takes a fixed column. The header buttons also run past the edge. Fix: stack the tab nav above the content under a max-width breakpoint.

(Two 2026-06-16 defects — the Settings theme-toggle tab reset and the Fleet incident-report button — were fixed 2026-06-24; see Shipped + CHANGELOG.)

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
<summary><strong>September 2026 — SOAR, scoring, dashboard — click to expand</strong></summary>

- **Look-and-feel pass, part 1: Inter + shared surface kit** — Inter bundled locally (`static/vendor/inter/`, no font CDN) and first in `--font-body`, so every page uses it; tighter heading letter-spacing; the dashboard tightened to about one screen (smaller empty score ring, shorter gaps, rows and chart, "Last updated" in the filter bar); the dashboard's card, spacing and type rules pulled into a shared `.ui-*` kit in `components.css` for other pages to adopt. Other pages not restyled yet. [`tests/test_ui_foundation.py`](tests/test_ui_foundation.py). (2026-09-27)
- **Tickets + outbound webhook (SOAR phase 3, part 3)** — two drop-in response connectors: open a ClickUp or Jira ticket (bring your own token and list / project), and POST a JSON payload, optionally HMAC-signed, to a URL the admin sets. Both always need approval and send only the step's inputs. Admin-set URLs go through a guarded request (https, no loopback or cloud-metadata addresses, private only when allowed, no redirects). Completes Phase 3. [`tests/test_response_connectors.py`](tests/test_response_connectors.py). (2026-09-27)
- **Click-together playbook builder (SOAR phase 3, part 2)** — build a playbook on the Automations page without JSON: conditions from a fixed safe set, ordered steps with a picker for values like the source IP or an earlier step's result, Check / Save with clear errors, and Edit for existing playbooks. Saves the same JSON the engine runs; response steps are always approval-gated, enforced on save. [`tests/test_playbook_builder.py`](tests/test_playbook_builder.py). (2026-09-27)
- **Bundled GeoIP database** — DB-IP "IP to Country Lite" ships in [`pulse/data/`](pulse/data/README.md) (8 MB, CC BY 4.0), so GeoIP works offline with no setup; results carry the required "IP Geolocation by DB-IP" attribution; a user-supplied City database still takes priority. Settles the bundling decision: City Lite (127 MB) is over GitHub's file limit and MaxMind's GeoLite2 can't be redistributed. (2026-09-27)
- **Investigate panel + five enrichment connectors (SOAR phase 3, part 1)** — one click in the finding drawer runs every connector that fits the finding's IPs, domains and file hashes, in parallel, with one result per provider. New drop-in connectors: GreyNoise and AlienVault OTX (bring-your-own keys), GeoIP (local `.mmdb`, offline), Whois (RDAP then port 43) and DNS. Private IPs and internal names are never sent. [`tests/test_investigate.py`](tests/test_investigate.py). (2026-09-27)
- **Playbook engine + Automations page (SOAR phase 2)** — stored JSON playbooks react to new findings: lookups run on their own, every response step (firewall block, Slack/Discord post) waits for a manager/admin approval with the security PIN. No full-auto mode. Org-scoped, audit-logged, three built-in examples. [`tests/test_soar.py`](tests/test_soar.py). (2026-09-26)
- **Connector layer + VirusTotal (SOAR phase 1)** — `pulse/connectors/` with self-registering connectors; AbuseIPDB moved onto it; VirusTotal added (bring-your-own key, 4/min + 500/day quota); both verdicts in the finding drawer next to Block. [`tests/test_connectors.py`](tests/test_connectors.py). (2026-09-26)
- **Share-of-remaining security score** — each unique finding removes a share of the remaining health (Critical 0.72 … Low 0.97), so 8 and 40 criticals score differently; open findings count fully, resolved 20%, false positives not at all; recency fades from when Pulse recorded the finding. One scorer for the dashboard, CLI and every report, and every report grades with the dashboard's A–F bands. [`tests/test_scoring.py`](tests/test_scoring.py), [`tests/test_grade_bands.py`](tests/test_grade_bands.py). (2026-09-26)
- **Dashboard redesign** — one hero (score + "needs attention"), a 4-stat strip, score history + findings by severity; soft cards instead of bordered boxes; a "Run your first scan" empty state. (2026-09-26)

</details>

<details>
<summary><strong>Post-v1.8.0 work (June 2026) — click to expand</strong></summary>

- **Authenticator-app 2FA (TOTP, RFC 6238)** — opt-in per user (Settings → Profile: QR + manual key, confirm-code-before-activation, 8 single-use recovery codes shown once as sha256 hashes) or mandatory per org. Login gets a second step after the password (`mfa_required` → `POST /api/auth/2fa/verify`, 6-digit or recovery code, ±1 step drift, replay-protected, rate-limited like login, generic errors). Admins can force-disable 2FA for a locked-out member of their own org only (PIN-gated, audit-logged). Org "require 2FA" policy blocks non-compliant members from everything but the setup screen. Uses `pyotp` + `qrcode` (server-side QR, no CDN). [`tests/test_2fa.py`](tests/test_2fa.py). (2026-06-28)
- **Fresh-visitor fixes (OTP screen, air-gap vendoring, onboarding)** — a first-run dogfooding pass fixed: (1) the **email-OTP verification screen** — signup `otp_required` and unverified-login now route to a real code-entry screen (6-digit input, email shown, resend with a 60s countdown, wrong/expired/attempts-remaining error states); verify-otp logs the user straight in; and `login.html` now sends the `X-Pulse-Request` CSRF header (it was missing → would have 403'd browser logins). No-SMTP self-host still auto-verifies so it's never bricked. (2) **Air-gap vendoring** — Chart.js (4.4.0) + Lucide (1.23.0) pinned into `static/vendor/`, Google Fonts replaced with a system stack; the dashboard renders fully offline, no CDN leaks (see [`static/vendor/README.md`](pulse/static/vendor/README.md)). (3) **Onboarding/docs polish** — README account-creation step, pinned-install quick start, 8000-vs-8443 port note, API-client CSRF note, httpx comment + banner-grammar fixes. (2026-06-27)
- **CSRF protection + feedback org-scoping** — mutating `/api/*` routes now require a custom `X-Pulse-Request` header (a cross-site page can auto-send the session cookie but can't set a custom header), enforced in the auth middleware; a `window.fetch` wrapper ([`csrf.js`](pulse/static/js/csrf.js)) attaches it app-wide. Agent transport (`/api/agent/*`) and Bearer-token requests are exempt; the admin `/api/agents` UI is gated. `GET /api/feedback` is now org-scoped like `/api/users` (notifications were already per-user). Completes the public-signup security gate. [`tests/test_csrf.py`](tests/test_csrf.py). (2026-06-26)
- **Mandatory 6-digit email OTP gate** — replaced the soft verification link with a hard one-time-code gate. When SMTP is configured, a self-signup or admin-invited account is emailed a random 6-digit code (generated with `secrets`, stored only as a sha256 hash, 10-minute expiry) and **cannot log in or hold a session until it enters the code**. Single-use codes; 5 wrong attempts invalidate the code; verify is rate-limited like login (per-IP burst + 423 lockout); resends are throttled per email (60s cooldown, 3/hour). Every failure is one opaque message so nothing leaks (wrong vs. expired vs. unknown-email are indistinguishable; resend never reveals account state). Local no-SMTP installs auto-verify as before. New `POST /api/auth/verify-otp` + email-addressed resend; `email_otp_*` columns; full `tests/test_auth.py` coverage. (2026-06-25)
- **Two UI bugs fixed** — (1) **Settings theme toggle no longer resets the tab.** Changing light/dark on the Appearance tab re-renders via a bare `navigate('settings')`, which used to force the Profile tab; `navigate` now keeps the current tab unless one is explicitly passed. (2) **Fleet "Generate Incident Report for this host" is no longer silent.** `generateIncidentReportForHost` now returns the async `openGenerateReportModal` promise, so fleet.js's `.catch` actually surfaces failures instead of them becoming swallowed unhandled rejections. Both pinned by source-guard regression tests in [`tests/test_frontend_regressions.py`](tests/test_frontend_regressions.py) (no JS test runner in this repo). (2026-06-24)
- **All report templates unified on the shared `report_theme` design system** — the remaining 8 templates (**Executive Summary, Threat Detection Summary, NIST CSF, ISO 27001, Fleet Health, Board-Ready Posture, MITRE Coverage, Compliance Gap**) now compose the same shared print/PDF components as the Incident report: brand header + "Page X of Y" footer on every page, section headers, severity pills, classification banners, zebra tables, callouts, metadata grids, and the graceful "None recorded" empty state. Each `render_pdf` + `render_html` was rewritten onto `report_theme`; **JSON/CSV outputs are byte-for-byte unchanged** and each report keeps its own content + section order. Old per-template dark-theme CSS / hand-rolled reportlab code removed. Every report now looks identical and prints consistently. (2026-06-24)
- **Rate-limiter `X-Forwarded-For` spoofing fix** — the limiter no longer trusts the client-supplied `X-Forwarded-For` header blindly (which let anyone rotate a fake IP to mint fresh per-IP buckets, or set a victim's IP to burn their budget). New `PULSE_TRUSTED_PROXY_HOPS` env (default **0** = ignore XFF, use the socket peer) controls how many proxy hops to trust; the client IP is read from the unforgeable right end of the forwarded chain. **Proxied deploys (Render) must set `PULSE_TRUSTED_PROXY_HOPS=1`.** New `tests/test_rate_limit.py` (9 tests) pins the behavior incl. a rotating-XFF evasion test. (2026-06-24)
- **Security Buddy ("Pip") — live AI assistant (MVP)** — a floating robot chat circle in the bottom-right corner of the dashboard. Click it to ask Pip anything: what a finding means, whether something looks dangerous, or general security questions. Answers come from **Claude Haiku 4.5**, proxied **server-side** through `POST /api/buddy/ask` so the Anthropic API key never touches the browser (read from the `ANTHROPIC_API_KEY` env var). Metered per user per UTC day via a new `user_ai_usage` table — **10 free questions/day** (admins can top up an account via `bonus_questions`), `429` + friendly "you're out for today" message when exhausted, counter shown in the panel. Security posture: read-only/no-tools, event-log/finding text passed to the model is fenced in an `<untrusted_data>` block with a system-prompt instruction to treat it as data (prompt-injection defense), output is HTML-escaped before render, and the panel discloses that chats are sent to Anthropic. Opening a finding drawer slides Pip left to sit beside it and hands Pip that finding's details so the user can ask about what they're reading — shown transparently as a "Looking at &lt;rule&gt;" pill so it's never a mystery what Pip can see (and cleared when the drawer closes; otherwise Pip only knows what the user types). Replies never use em dashes (stripped server-side), persist in the browser across refreshes (with a "New chat" reset), and stay in scope — for anything Pip can't help with it points to the in-app Feedback option and the GitHub issues page. Degrades gracefully when no key is configured ("Pip isn't set up yet"). (2026-06-16)
- **Fleet page redesign** — constrained the host table to ~1500px with fixed column widths and proper alignment (text left, numbers right), added an **Actions** column header with report + view-findings icons that reveal on row hover, a **top filter bar** (hostname search + Risk + Status dropdowns + Export CSV moved into it), **risk-worst-first default sort** with clickable sortable headers, 44px rows + hover/zebra + a status-dot legend (online/stale/offline), and unified the KPI tiles with the Risk filter on one 4-band model (Critical/High/Fair/Secure). The **host drawer** now answers "what's wrong with this machine": posture + a **severity-breakdown bar** + a **findings list** (top 8, click to open the host's findings) + real footer actions (Generate report / View all findings / Close). New backend `GET /api/fleet/host/{hostname}` feeds the drawer. (2026-06-16)
- **Settings rail grouped + Billing tab** — the flat 12-item settings rail is now grouped into ACCOUNT / PREFERENCES / CONFIGURATION / TEAM / WORKSPACE with uppercase group labels (sidebar style), role-gated so all-admin groups vanish for non-admins. New admin-only **Billing** tab (`/settings/billing`) — placeholder "Coming soon" card, optionally surfacing read-only Pip AI-usage (used/limit today). Pages + routes unchanged. (2026-06-16)
- **Multi-tenant admin isolation (data-isolation core)** — closed the cross-tenant gap that would have let one hosted org's admin read and manage another org's data. Hosted org admins are now scoped to their own organization for reads and for every `/api/users` operation (list/role/active/delete, 404 on a cross-org id so existence doesn't leak); the "last admin" guard counts per-org; and a private env-only super-admin allowlist (`PULSE_SUPERADMIN_EMAILS`) keeps global scope. Single-tenant self-host is unchanged. 11 new isolation tests. *Remaining before public signup: CSRF header check (the trusted-proxy `X-Forwarded-For` gate shipped 2026-06-24).* (2026-06-16)
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
