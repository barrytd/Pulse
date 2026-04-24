# Changelog

All notable changes to Pulse are documented here.
Format: newest entries at the top, grouped by date.

---

## 2026-04-23 — Sprint 6 (in progress)

### Added
- **In-app feedback** (`feedback` table, `POST /api/feedback`, `GET /api/feedback` admin-only) — "Give Feedback" in the user-avatar dropdown now opens an in-app modal, and a persistent floating "Feedback" pill sits in the bottom-right corner of every page. Users pick a type (Bug / Idea / General), type a message up to 4000 chars, and submit; the current SPA route is captured as `page_hint` for context. Rows land in `pulse.db` with `user_id` + timestamp
- **Settings → Feedback admin tab** — admin-only review UI with a 5-tile KPI strip (Total / Bugs / Ideas / General / Top Page) and a table of submissions (relative time + UTC on hover, kind chip, submitter email, page path, 140-char preview). Click a row to expand the full message
- **User display names** (`users.display_name` column, admin-only `PUT /api/users/{id}/display_name`) — analysts' names replace email prefixes everywhere identity is surfaced. Admins edit names inline from Settings → Users (new "Name" column, saves on blur / Enter, 100-char cap). The top-right greeting now uses the first word of `display_name` ("Hey, Robert!") falling back to the email prefix when unset. User-menu avatar initial tracks the same source. Users cannot edit their own name — admins own the identity surface.
- **Assignment UI uses display names** — every finding response now carries `assignee_display_name` via the same LEFT JOIN that provides `assignee_email`. Findings-list "Assigned To" cell, drawer picker, notes-thread author lines, and the Settings → Notes admin tab all render the display name primary with the email as hover-title or muted secondary text for disambiguation.
- **Drawer assign picker redesign** — swapped the plain `<select>` for a custom `.assign-picker` listbox so each option renders display name on top and email in muted mono underneath. Hidden native `<select>` keeps screen readers + the existing `setFindingAssignee` change-flow honest.
- **"Assigned to me" toggle moved** — no longer a separate chip next to the Status dropdown. Now lives in the severity pill row (ALL / CRITICAL / HIGH / MEDIUM / LOW | Assigned to me) so every list-level filter reads as one horizontal group. Divider rule makes the grouping visible without a second row.
- **Sidebar quick-assign tray** — new users-icon button at the bottom of the sidebar opens a `.pulse-dropdown` with "Assign to me", "Assign to…", "Unassign". Enabled only when a finding drawer is open (otherwise disabled with a "Open a finding first" tooltip). "Assign to…" re-opens the drawer's existing picker so the sidebar stays as a shortcut surface, not a duplicate user list.
- **Finding assignment** (`findings.assigned_to` + `assigned_at` columns, `PUT /api/finding/{id}/assign`) — closes the triage arc: workflow state → notes → who's working it. Every finding response now carries `assigned_to`, `assigned_at`, and `assignee_email` (joined from users) so the UI can render context without a second fetch. Drawer shows an assignee dropdown (All active users for admins; self-only for viewers who can't list users) with a one-click "Assign to me" button. Findings list "Assigned To" column now shows the real assignee's short local-part as an accent chip (hover reveals full email). New toolbar "Assigned to me" filter chip narrows the list to the caller's active work. Endpoint is login-gated + scan-ownership checked + validates the assignee is an active user. Fires `pulse:assignee-changed` events so list rows update live from the drawer without a refetch.
- **Settings → Notes admin tab** (`GET /api/notes`, admin-only) — cross-finding notes feed so admins can skim every analyst note posted across the app without clicking into each finding individually. 4-tile KPI strip (Total / Last 7 days / Authors / Top Rule) + table (relative time, severity pill, author email, rule + ref_id link, 140-char body preview). Click a row to expand the full body; click the rule link to jump to the parent scan
- **Analyst notes** (`finding_notes` table, `GET/POST/DELETE /api/finding/{id}/notes`) — append-only timestamped, author-attributed note thread per finding. Drawer shows notes oldest-first with author email + relative timestamp, a compose textarea (4000-char cap, live counter), and a subtle `×` delete on each note (viewers can delete their own; admins can delete any). Findings list rows gain a small speech-bubble `notes-chip` with a count next to the workflow chip — hidden when the count is 0 so untouched rows stay clean. Fires `pulse:notes-changed` events so the badge stays in sync across the page without a refetch. POST is rate-limited (60/hr per IP) and gated by the same scan-ownership check as the workflow endpoint. PDF report integration still pending — notes are DB-side only until report generation picks them up
 — every finding now carries an incident-response state independent of the existing review/false-positive flags: `new → acknowledged → investigating → resolved`. The finding detail drawer shows a 4-pill picker with the current state highlighted and a "Updated …" timestamp; clicking a pill fires the endpoint optimistically and broadcasts a `pulse:workflow-changed` event so visible list rows repaint the inline chip without a full refetch. Findings-page rule cells gain a color-coded chip (muted grey for New, accent blue for Acknowledged, amber for Investigating, green for Resolved) that's hidden while the state is still `new` so untouched rows stay visually quiet. Endpoint requires login and checks scan ownership — viewers can only change state on findings they own

### Security
- **RBAC gaps closed on admin-config endpoints** — every config-mutating or outbound-side-effect endpoint now declares `Depends(require_admin)`, preventing viewers from modifying global SMTP/webhook/scheduler/whitelist/rule state:
  - `PUT /api/config/email`, `PUT /api/config/alerts`, `PUT /api/config/webhook`, `PUT /api/config/whitelist`
  - `POST /api/alerts/test`, `POST /api/webhook/test` (also closes the SSRF chain: previously, any authenticated viewer could repoint `webhook.url` to an internal address and trigger a server-side POST)
  - `POST /api/scheduler/config`, `PUT /api/rules/{name}/enabled`, `DELETE /api/whitelist/batch`
  - `DELETE /api/reports/batch`, `DELETE /api/reports/{filename}` (admin-only; reports are shared filesystem state)
  - `GET /api/reports`, `GET /api/reports/{filename}` (require_login — viewers can download their own scans' reports)
- **Finding review auth + ownership check** — `PUT /api/finding/{finding_id}/review` now requires login and verifies the finding's scan belongs to the caller (admins unaffected; viewers get a 404 on cross-scope findings to avoid leaking existence)
- **Session cookie `Secure` flag in production** — login / signup cookies now set `secure=True` when `PULSE_ENV=production` so they can't travel over plaintext on accidental `http://` hops. Dev-mode cookies stay non-secure so `http://127.0.0.1` works
- **Feedback endpoint hardening** — `POST /api/feedback` now rejects non-JSON / non-object bodies with 400 and coerces `kind` / `message` / `page_hint` to strings defensively so weird client payloads can't 500 the server
- **Rate limiting** (`pulse/rate_limit.py`) — new per-IP sliding-window limiter applied to the brute-forceable / spammable endpoints: `POST /api/auth/login` (10/5min), `POST /api/auth/signup` (10/5min), `POST /api/feedback` (10/hr), `POST /api/tokens` (20/hr). Over-the-limit returns `429` with a `Retry-After` header. In-process only (single-worker Render free tier); for horizontal scale the backing dict can be swapped for Redis
- **Input validation hardening** — every body-taking endpoint in the auth / user / token / block-ip surface now rejects non-dict JSON bodies, coerces string fields defensively, and caps lengths (email 320, password 1024, comment 500, IP 64) so oversized strings can't reach the DB
- **Avatar magic-byte verification** — `POST /api/me/avatar` now checks the first bytes against PNG (`89 50 4E 47`) and JPEG (`FF D8 FF`) magic numbers; a client-set `Content-Type: image/png` on a non-PNG file is rejected with 400. Stored mime is derived from the bytes, not the header
- **Explicit auth on remaining routes** — every `/api/*` route (except the documented exempts: `/api/health`, `/api/auth/*`) now declares `Depends(require_login)` or `Depends(require_admin)`. Previously some routes relied only on the middleware; this closes the "future refactor strips middleware for one path" class of regression. Monitor bulk-delete endpoints tightened to `require_admin`
- **Production CORS misconfig warning** — when `PULSE_ENV=production` but `PULSE_ALLOWED_ORIGIN` is empty, the startup banner now prints a warning instead of silently dropping CORS middleware

---

## 2026-04-21 — v1.5.0 (Sprint 5: Auth, compliance, analytics)

### UX blueprint pass (late-sprint polish against `.claude/skills/pulse-ux-blueprint.md`)
- **Design-token rollout** — semantic color / spacing / type scale variables (`--bg-0..--bg-4`, `--text-high/body/dim`, `--severity-*`, `--space-1..--space-12`, `--font-body/mono`) threaded through every page, so one theme edit repaints the whole app
- **Monitor three-band rebuild** — replaced stacked cards with a top status strip + middle alert stream + bottom controls; SSE indicator, audio ding, test-alert button, and sliding 15-minute window preserved
- **Ctrl+K command palette** (`pulse/static/js/cmdk.js`) — fuzzy-scored action search with recents, keyboard-only navigation, highlights match positions; registered across every page
- **Universal right-side drawer primitive** (`pulse/static/js/drawer.js`) — `openDrawer({title, subtitle, badges, sections, actions, onClose})` pattern; adopted by the Fleet host-detail view, with existing finding-detail drawer left intact for backward compatibility
- **Rules page upgrade** — per-rule hit counts (total / 24h) + 24-hour sparkline + false-positive rate pill + last-fired relative time, plus a **MITRE Coverage** tab rendering a tactic × technique intensity matrix. Backed by a new `get_rule_stats(db_path, user_id)` aggregator and an enriched `/api/rules/details` endpoint (now auth-gated with per-user scope)
- **Fleet KPI strip + drawer** — six clickable tiles (Online / At Risk / Critical / Newly Enrolled / Total / Offline) pre-filter the host list; clicking a host row opens the universal drawer with an Overview panel + "View on Dashboard" action that preserves the old dashboard-filter navigation
- **Firewall pending-changes banner** — Palo-Alto-Panorama-style amber banner when staged rules exist ("N pending changes · Review · Discard"), flashing focus on first pending row. Three-tile KPI strip (Active / Pending / Blocked this week) and a shared tiered bulk-confirm helper (≤10 simple confirm, 11–50 consequence confirm, >50 typed `DELETE N ENTRIES`) replaces the old single-line window.confirm
- **Whitelist KPI strip** — six tiles (Custom / Accounts / Services / IPs / Rules / Built-in) with the same tiered bulk-confirm pattern
- **Dashboard standup row** — reduction funnel (Events → Findings → Crit+High → Critical with K/M-formatted counts + tone-colored stages) and a Top Offenders card (top 5 hosts by finding count, proportional bars, relative-time last-seen) sit between the stat cards and the score/history middle row
- **Compliance hero gauge** — SVG circular gauge of enabled/total rules at the top of the page, plus a stacked bar for Enabled / Disabled (with Waived / N/A placeholders noted as not yet modelled)
- **Trends anomaly bands** — daily volume chart overlays a translucent yellow mean-±2σ band and a dashed mean line, so spikes stand out against the baseline; tooltips are filtered to the findings line so the band guides stay decorative
- **Security fix** — `/api/compliance` now requires login (was inadvertently unauthenticated before the release audit)

### Added
- **Role-based access control** (`users.role` column, `require_admin` dependency) — admin vs viewer roles enforced in the API. Viewers can read scans / findings / reports but can't change settings, block IPs, or manage users. `_scan_scope_for(app, user_id)` gives admins the full picture while viewers are scoped to the scans they personally ran
- **Multi-user account management** (`/api/users`, Settings > Users tab) — admins can create, disable, and delete additional accounts. Guardrails reject demoting / deactivating / deleting the last active admin so nobody gets locked out. Every write is audited via `blocker.log_audit`
- **Data isolation** (`scans.user_id` column + per-query scope filter) — viewers see only scans they kicked off; admins see everything. Covers `/api/history`, `/api/findings`, `/api/scan/{id}`, trend analytics, and fleet summaries. Legacy `user_id = NULL` rows (CLI / pre-RBAC) are visible to admins
- **Admin activity history** (`/api/audit`, Audit page) — every block / unblock / push / scan / review / user-management action writes a row. Filter by user, action type, or date; one-click CSV export
- **Hosted deployment** — production-ready on Render free tier. `PULSE_ENV=production` switch enables env-var config fallback (`PULSE_SECRET`, SMTP creds), locks `/docs` and CORS, anchors `pulse.db` to `os.getcwd()` so threads can't drift, and emits a startup health banner summarizing which channels (email / Slack / Discord) are wired
- **Profile picture upload** (`users.avatar_blob BLOB`, `POST/GET /api/me/avatar`, Settings > Profile) — avatars stored as BLOBs on the users row so they survive Render's ephemeral filesystem. 2 MB cap, PNG / JPEG only. Top-right corner avatar syncs immediately via `refreshUserMenuAvatar(cacheBuster)`
- **NIST CSF + ISO 27001 rule mappings** (`pulse/core/rules_config.py`) — every detection rule tagged against a NIST CSF subcategory (e.g. `DE.CM-1`) and an ISO 27001 Annex A control (e.g. `A.9.4.2`). Shared `SEVERITY_RANK` + `rule_sort_key()` ordering (CRITICAL → HIGH → MEDIUM → LOW, then alphabetical) used by both the Rules page and the Compliance page
- **Compliance page** (`pulse/static/js/compliance.js`, `GET /api/compliance`) — per-CSF-function and per-Annex-A-clause coverage cards plus a flat per-rule lookup table. `build_compliance_summary(disabled)` aggregates enabled / disabled counts by control, so disabling a rule immediately shows up as a coverage gap
- **Trend analytics page** (`pulse/static/js/trends.js`, `GET /api/analytics/trends?days=N`) — rolling-window view with 7 / 30 / 90-day selector, window-over-window delta (red ↑ = findings climbing, green ↓ = falling), daily finding volume line chart, severity breakdown bars, top rules (bar chart, colored by severity), top hosts
- **Score-over-time chart** on the Dashboard — line chart of daily security scores, grade-tinted
- **API token auth** (`pulse/auth.py` — `generate_api_token`, `hash_api_token`; `api_tokens` table; Settings > API Tokens) — long-lived bearer tokens for CI pipelines. Format is `pulse_` + 32 hex chars; sha256 + last4 stored, raw shown once. Auth middleware accepts either a session cookie or `Authorization: Bearer <token>`. Tokens inherit their owner's role; deactivated users' tokens are rejected; `last_used_at` bumps on every call so the UI can show "last used 5 min ago"
- **PostgreSQL backend** (`pulse/db_backend.py`, `scripts/migrate_to_postgres.py`) — Pulse now runs against either SQLite (default, zero setup) or PostgreSQL. Set `DATABASE_URL=postgresql://…` and Pulse auto-detects and switches drivers on next start. The adapter translates `?` → `%s` placeholders, appends `RETURNING id` to INSERTs so `cursor.lastrowid` keeps working, rewrites `INTEGER PRIMARY KEY AUTOINCREMENT` → `BIGSERIAL` and `BLOB` → `BYTEA` in DDL, and swallows `ADD COLUMN IF NOT EXISTS` idempotently on both backends. One non-portable SQL query (`was_recently_alerted`) now computes its cutoff in Python instead of SQLite's `datetime('now', 'localtime', …)` modifier. The startup banner redacts Postgres passwords before logging the DSN. `scripts/migrate_to_postgres.py` copies every table out of a local `pulse.db` into a target Postgres, using `ON CONFLICT (id) DO NOTHING` for idempotency and bumping each table's `*_id_seq` to `MAX(id)` so the live app doesn't collide on the next insert

### Changed
- `/api/me` now returns `has_avatar: bool` alongside `role` and `active` so the frontend can decide whether to render the avatar `<img>` or the fallback initial
- `/api/rules/details` returns rules sorted by severity-then-alpha (was alphabetical); the Rules page and Compliance page share the ordering via `rule_sort_key`
- `pulse/api.py` imports now pull `generate_api_token` from `pulse.auth` and `create_api_token / list_api_tokens / revoke_api_token / find_api_token_user / touch_api_token` from `pulse.database`

### Tests
- 447 → 499 passing. New cases in `test_auth.py` cover the full token lifecycle (mint / list / bearer auth against `/api/history` / revoke / cross-user isolation / deactivated-user rejection / malformed token). New `test_db_backend.py` covers SQL-translation (`?` → `%s`, RETURNING-id injection), DDL rewrites (AUTOINCREMENT / BLOB), resolve_target precedence, SQLite-connect PRAGMA, the missing-driver error path, and the `_PgConnection` context-manager commit / rollback behaviour against a fake psycopg connection. Existing auth / data-isolation / API / alerts / webhook suites unchanged and green

---

## 2026-04-20 — v1.4.0

### Added
- **Windows Firewall configuration audit** (`pulse/firewall_config.py`) — three new rules powered by live `netsh advfirewall` output: **Firewall Profile Disabled** (HIGH; any of Domain / Private / Public in State OFF), **Firewall Any-Any Allow Rule** (MEDIUM; enabled inbound allow with any protocol, any local port, any remote IP — skips Pulse-managed rules), **Firewall Overly Broad Scope** (MEDIUM; inbound allow on a sensitive port 22 / 23 / 135 / 139 / 445 / 1433 / 3306 / 3389 / 5432 / 5900 / 5985 / 5986 with RemoteIP = Any). Pure-data parsers (`parse_profiles`, `parse_rules`) keep the module OS-agnostic for testing; `scan_firewall_config()` returns `[]` silently on non-Windows. Runs automatically on every `/api/scan` and via the new `--firewall-config` CLI flag
- **Audit Log page** (`pulse/static/js/audit.js`, `GET /api/audit`) — sidebar entry renders the `audit_log` table newest-first with action badges, user/source column, IP, and detail. Every `/api/scan`, scan-delete (Scans and History pages), block / unblock / push now writes an audit row via `blocker.log_audit`, so a reviewer has one place to see the who-did-what-and-when story for sensitive actions
- **Fleet CSV export** (`GET /api/fleet/export.csv`, Export CSV button on the Fleet page) — one-row-per-host summary with `hostname,scan_count,last_scan_at,total_findings,latest_score,latest_grade,worst_severity`; browser-native download with a timestamped filename so analysts can hand the list straight to a spreadsheet or ticket
- **Windows Firewall log parser** (`pulse/firewall_parser.py`) — reads `pfirewall.log` (default `%windir%\System32\LogFiles\Firewall\pfirewall.log`), skips private / loopback / link-local sources, and surfaces two detection classes: **port scan** (one public IP, many DROPs across many dst-ports in a short window) and **sensitive-port probe** (single DROP on 3389 / 22 / 445 / 3306 / 5985 from a public IP)
- **IP block list** (`pulse/blocker.py`, `ip_block_list` table, `/api/block-list`, `/api/block-ip`, `/api/block-ip/{ip}/push`, `/api/unblock-ip/{ip}`) — manage a Pulse-owned list of blocked source IPs. Each row has status `pending` / `active`, optional comment (e.g. "brute force on 2026-04-15"), and a rule name prefixed `Pulse-managed:` so user-authored firewall rules are never touched. Safety rails reject RFC1918, loopback, link-local, multicast, and the local machine's own IPs
- **One-click "Block source IP" action** — every finding with a discoverable source IP (Brute Force, RDP, Pass-the-Hash, etc.) now shows a Block button in the detail drawer. Stages the IP with a pre-filled comment linking back to the finding; a second click (or `--confirm`) pushes it to Windows Firewall via `netsh advfirewall`
- **Firewall page** (`pulse/static/js/firewall.js`) — sidebar entry with two tabs: **Blocked IPs** (Pulse-managed rows with push / unblock controls and an Add-block modal) and **Firewall Log** (parsed detections from `pfirewall.log`). Non-Windows hosts can stage / list / audit; push surfaces a clear "skipped on Linux" message
- **Block-list CLI** (`main.py`) — `--block-ip <ip> [--comment TEXT] [--confirm]`, `--block-list`, `--block-push`, `--unblock-ip <ip> [--force]`, `--firewall-log [PATH]` for cron / scripted workflows
- **Scan duration tracking** (`scans.duration_sec` column) — every scan records wall-clock time from parse start to save. Surfaced in the PDF header ("Duration: 1m 23s") and available to the UI
- **PDF report redesign** (`pulse/pdf_report.py`) — cleaner two-column layout with grade-coloured 60pt score ring on the left; title + generated date + Scan # + Host + Scope + Duration on the right; a new `Score: 76 (C) · Moderate Risk` summary line (colored bits in the grade's ring color) above small severity pills. Each finding card shows rule name → full description → mono meta line (timestamp · Event ID · MITRE link · User · Source IP) → "REMEDIATION" label + HR + numbered steps → MITRE / mitigation pills. Grade palette: A #639922, B #378ADD, C #BA7517, D #E24B4A, F #A32D2D. Risk labels: A Secure, B Low Risk, C Moderate Risk, D High Risk, F Critical Risk
- **Position-based scan numbering** — the displayed "Scan #N" is now the row's position in current history (oldest = #1), computed via a correlated subquery in `get_history` and a new `get_scan_number()` helper. Delete every scan and the next one shows as **Scan #1** again. Internal auto-increment DB id stays unchanged; only the number shown in the PDF header, dashboard findings table, Findings detail drawer, Scan detail page title, History compare dropdown / diff headers, and download filenames (`pulse_scan_{N}.pdf`) uses the new position
- **Real SPA URL routing** (`pulse/static/js/navigation.js`, `pulse/api.py`) — every sidebar nav now calls `history.pushState({page}, '', '/pageName')`; browser Back / Forward / Refresh behave like a normal site. Page boot parses `location.pathname` so refreshing on `/fleet` lands on Fleet instead of Dashboard, and `/scans/{id}` deep-links straight into a scan detail view. FastAPI serves the SPA shell for every top-level path (`/dashboard`, `/monitor`, `/scans`, `/scans/{id}`, `/reports`, `/history`, `/fleet`, `/firewall`, `/whitelist`, `/rules`, `/settings`) — auth-gated, so an unauthenticated deep-link still redirects to `/login`
- **Bulk-select + batch-delete** on Reports, Whitelist, Firewall Block List, Monitor Sessions, and History — copies the Scans page pattern exactly: per-row checkbox + select-all header + sticky action bar with a single confirm prompt. Five new backend endpoints (`DELETE /api/reports/batch`, `/api/whitelist/batch`, `/api/block-ip/batch`, `/api/monitor/sessions/batch`, `/api/history/batch`) plus matching `apiDelete*` helpers in `pulse/static/js/api.js`. Built-in whitelist entries show no checkbox (can't be removed); active monitor sessions are skipped for the same reason

### Changed
- Dashboard download links no longer hardcode `a.download` — the browser honours the server's `Content-Disposition`, so the filename reflects the display number instead of the raw DB id
- Finding metadata attached on the dashboard + findings page now carries `_scan_number` alongside `_scan_id` so the display can use the position while navigation still hits the stable DB id

### Tests
- 407 passing (core suite), covering `test_detections.py`, `test_api.py`, `test_blocker.py`, `test_firewall_parser.py`, and the new `test_firewall_config.py` (14 cases: profile / rule parsers, each detection, pure-data entry point). New `/api/fleet/export.csv` and `/api/audit` cases in `test_api.py`

---

## 2026-04-16 — v1.3.0

### Added
- **Scan My System** (`pulse/system_scan.py`, `POST /api/scan/system`) — reads directly from `C:\Windows\System32\winevt\Logs\` with a lookback window; no upload step. Modal picker offers 24h / 3d / 7d / 30d / custom ranges and a "send alert when complete" toggle
- **Scheduled scans** (`pulse/scheduled_scan.py`) — cron-style recurring system scans configured from the Settings page; next-run timestamp surfaced in the dashboard
- **Admin-privilege banner** — on Windows when Pulse isn't elevated, a non-blocking banner nudges the user to restart as admin for full Security-log coverage. Dismissal persists per browser via localStorage
- **Channels multi-select** — Monitor page's channel picker is now a dropdown of checkboxes for Security / System / Application / Windows PowerShell / PowerShell Operational / TaskScheduler Operational, plus a free-text "Custom…" field. Selection persists across sessions
- **Clickable live-feed findings** — every row in the live monitor feed opens the shared slide-in detail drawer (rule, severity, MITRE link, remediation, review workflow) — the same drawer the Findings page uses
- **Dashboard live-panel gear popover** — compact settings popover next to Start Monitoring with the poll-interval slider and the same channel multi-select, so dashboard users never need to leave the page to reconfigure
- **Scans + Findings merge** — Findings is now the "All Findings" tab on the Scans page with a shared tab bar; the sidebar link is gone, old `#findings` hashes redirect so bookmarks still land correctly
- **Scope column on Scans** — replaces the empty Duration column. System scans show their lookback ("Last 7 days", "Last 24 hours", ...); manual uploads show "Manual upload". Persisted on the `scans.scope` column; older rows fall back to filename
- **Monitor Sessions** (`monitor_sessions` table, `pulse/monitor_service.py`, `/api/monitor/sessions*`) — DVR-style record of every Start→Stop span with poll + events + findings counters. Monitor page renders collapsible session cards below Poll History; expand to see a session's findings, click one to open the shared drawer. Per-card delete and Clear-all controls; scans carry `session_id` so cascading cleanup removes linked findings

### Changed
- Dashboard sidebar no longer lists Findings as a top-level page
- `scans` table gains `scope` and `session_id` columns (migrated with `ALTER TABLE IF NOT EXISTS`-style try/except so existing DBs upgrade cleanly)

### Tests
- Test count: 271 → 286, all passing

---

## 2026-04-16

### Added
- **Remediation module** (`pulse/remediation.py`) — single source of truth for per-rule "how to fix" steps plus MITRE ATT&CK mitigation IDs (M1026, M1027, etc.). `attach_remediation(findings)` decorates each finding with `remediation` steps + `mitigations` chips so every downstream consumer (HTML/PDF/dashboard drawer) gets the same content
- **Remediation tab rewrite** (`pulse/reporter.py`) — grouped by rule with finding-count badges and clickable MITRE mitigation chips linking to `attack.mitre.org/mitigations/<ID>`
- **Finding review workflow** (`pulse/database.py`, `pulse/api.py`, `pulse/static/js/findings.js`) — mark any finding as `reviewed` or `false_positive` from the dashboard drawer; state is keyed by a stable `finding_uid` hash and persists across future scans. Two new endpoints (`PUT /api/findings/{uid}/review`, `DELETE /api/findings/{uid}/review`) + a filter dropdown on the Findings page
- **Scheduled scans** (`--schedule FOLDER`) — folder-watch mode that auto-scans every new `.evtx` file dropped into the directory. Dedupes by mtime so re-saved files don't trigger repeat runs
- **Recurring summary reports** (`--summary {daily,weekly,monthly}`) — aggregates scans across a 1/7/30-day window into a single HTML digest (total scans, avg score, severity breakdown, top rules with progress bars, affected hosts, worst scan callout). Pair with `--email` for a cron-able digest
- **PDF export** (`pulse/pdf_report.py`) — ReportLab-based formatted report with cover page, severity summary table, per-finding cards including remediation steps + MITRE mitigations. `GET /api/report/{id}?format=pdf` + a new "Export PDF" button on the scan detail view
- **Scan comparison** (`pulse/comparison.py`, `pulse/api.py`, `pulse/static/js/history.js`) — `GET /api/compare?a=&b=` returns `{new, resolved, shared}` keyed by (rule, description). History page gains two scan dropdowns + Compare button that renders a three-column diff (New / Shared / Resolved)
- **`--quiet` / `--json-only` CLI flags** — machine-friendly output for cron pipelines. `--quiet` suppresses progress/animation output; `--json-only` writes JSON to stdout and silences everything else so `pulse ... | jq` just works
- **`--config PATH` CLI flag** — load settings from a custom YAML file instead of the default `pulse.yaml`. Pre-parsed before the main argparse pass so config-driven defaults still apply

### Changed
- **`.gitignore`** — tightened `logs/*.evtx` to `*.evtx` so stray event logs anywhere in the tree are never committed; added `pulse.db`
- **American spelling** in user-visible dashboard text (modularized, color, flavor) — matches the project's US-English copy direction without mass-rewriting existing British spellings elsewhere

### Dependencies
- `reportlab>=4.0.0` — PDF generation (pure Python, no native deps)

### Tests
- Test count: 271 → 324, all passing (new coverage for remediation grouping, MITRE chips in HTML, summary report aggregation, PDF byte output, diff bucket logic, review workflow endpoints, `--quiet`/`--json-only`/`--schedule`/`--summary`/`--config` CLI paths)

---

## 2026-04-15

### Added
- **DCSync detection** (`pulse/detections.py`) — `detect_dcsync()` flags Event 4662 records carrying any of the three directory-replication extended-rights GUIDs (`DS-Replication-Get-Changes`, `-All`, `-In-Filtered-Set`). Computer accounts (those ending in `$`) are skipped so legitimate domain-controller replication traffic does not generate noise; per-actor dedupe keeps a single CRITICAL finding per attacker. MITRE T1003.006
- **Suspicious child process detection** (`pulse/detections.py`) — `detect_suspicious_child_process()` reads Event 4688 and flags Office/browser parents (Word, Excel, Outlook, Chrome, Edge, etc.) spawning shell-like children (`cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`, etc.). Includes truncated command line for triage. MITRE T1059
- **Slack / Discord webhook delivery** (`pulse/webhook.py`) — new module with auto-detect from URL, explicit flavor override, severity-coloured Slack attachments (10-cap + overflow notice) and Discord embeds (integer colours, 9-cap), and POSTs via stdlib `urllib.request` (no extra dependency). Errors are swallowed and reported as `False` so a broken webhook never crashes a scan
- **`dispatch_alerts` webhook integration** (`pulse/emailer.py`) — accepts a `webhook_config`, fires both channels in parallel, and records cooldown if *either* channel succeeded so a broken SMTP can no longer cause webhook-successful notifications to repeat every scan
- **API webhook surface** (`pulse/api.py`) — `GET /api/config` returns `webhook.url_set` (boolean) but never the URL itself; `PUT /api/config/webhook` validates flavor + scheme and keeps the saved URL when the request body is blank; `POST /api/webhook/test` posts a sample finding even when the webhook is disabled in config
- **Settings card for webhooks** (`pulse/static/js/settings.js`) — new "Slack / Discord Notifications" card between Live Monitor Emails and Scan Defaults with enable toggle, service dropdown (Auto / Slack / Discord), password-style URL field, save + send-test buttons
- **Parser fast-path event IDs** (`pulse/parser.py`) — added 4662 and 4688 to `RELEVANT_EVENT_IDS` so the wevtutil pre-filter surfaces the events the new rules need

### Tests
- 14 new tests in `test_detections.py` (6 DCSync: replication GUID, all three GUID variants, ignores unrelated GUIDs, skips computer accounts, dedupes per actor, ignores non-4662; 8 child process: Word→PowerShell, Chrome→cmd, Outlook→wscript, ignores explorer→cmd and Word→splwow64, includes truncated command line, ignores non-4688)
- 20 new tests in `test_webhook.py` covering flavor detection, config validation, payload shape (Slack attachments + colour stripe, 10-cap + overflow, Discord embeds + integer colours, description truncation), `send_webhook` with mocked `urlopen` (slack/discord URL routing, explicit flavor override, network error → False, HTTPError → False), and `dispatch_alerts` integration (fires when enabled, skips when disabled, records cooldown when webhook alone succeeds)
- 8 new tests in `test_api.py` for the new webhook config + test endpoints (URL never echoed, blank URL keeps existing, bad flavor/scheme rejected, test endpoint requires URL and returns 502 on POST failure)
- Test count: 229 → 271, all passing

---

## 2026-04-14

### Added
- **Single-user dashboard authentication** (`pulse/auth.py`, `pulse/web/login.html`) — clean dark-themed login page that doubles as a first-user signup form when no account exists yet. Password hashing uses stdlib `hashlib.scrypt`; session cookies are HMAC-SHA256 signed with a secret auto-generated into `pulse.yaml` on first boot. No external auth deps
- **Auth middleware** on `/api/*` — every endpoint is 401 without a valid session cookie, except `/api/health` and `/api/auth/*`. `GET /` 302-redirects to `/login` when signed out
- **Account routes** — `POST /api/auth/signup` (closed after first user, 409 thereafter), `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/status`, `PUT /api/auth/email`, `PUT /api/auth/password`. Email/password changes require current password re-entry
- **Settings rewrite** — new "My Account" card on the Settings page lets you change your login email and password from the browser and sign out. The old SMTP fields are now hidden behind a provider dropdown (Gmail / Outlook / Yahoo / Custom) that auto-fills host and port — no more jargon for non-sysadmin users
- **Live monitor email alerts** (`pulse/monitor_service.py`) — live monitoring can now email findings, gated by a new `monitor_enabled` toggle and `monitor_interval_minutes` setting (5 min to 4 hours). Slow SMTP won't block the poll loop (`asyncio.to_thread`). Alert config is editable from the Settings page
- **`dispatch_alerts` helper** (`pulse/emailer.py`) — shared alert-dispatch logic used by the CLI scan path, the API scan path, and now the live monitor, so throttling and cooldown behave consistently everywhere
- **Dashboard empty state** — when no scans fall inside the filtered time window, the Dashboard now shows a banner with "Upload .evtx" / "Open Monitor" CTAs plus muted zero-state panels instead of hiding everything behind a single "No data" card

### Changed
- **`create_app(...)`** accepts a `disable_auth=False` test flag so the existing API test fixture stays simple
- **`users` table** added to SQLite on startup (`pulse/database.py`) with UNIQUE email constraint and scrypt-format password hashes

### Tests
- 25 new tests in `test_auth.py` (unit: scrypt round-trip, cookie sign/verify/tamper/expiry; API: needs_signup flag, signup closed after first user, login/logout, protected 401/200, root redirects, email/password updates)
- 5 new tests in `test_monitor_service.py` for the monitor email-interval throttle
- 5 new tests in `test_alerts.py` for `dispatch_alerts` (covers throttling + CLI/API parity)
- 3 new tests in `test_api.py` for the monitor config fields
- Test count: 189 → 227, all passing

---

## 2026-04-12

### Added
- **Web dashboard** (`pulse/web/index.html`) — single-page dark-themed UI served at `GET /`:
  - Sidebar navigation: Dashboard, Scans, Findings, History, Whitelist, Settings
  - Drag-and-drop `.evtx` upload modal with file picker fallback
  - Security score ring visualization with color-coded risk levels
  - Score history table (5 most recent on dashboard, full list on History page)
  - Scan drill-down: click any scan to view its findings
  - Light/dark theme toggle with `localStorage` persistence
  - Dashboard test added to `test_api.py`
- **REST API** (`pulse/api.py`) — FastAPI server with four endpoints:
  - `POST /api/scan` — upload a `.evtx` file, get findings as JSON back. File is parsed in-memory and deleted immediately (ephemeral storage)
  - `GET /api/history` — list recent scans from the local SQLite database (`?limit=N`, capped at 200)
  - `GET /api/report/{id}` — return findings for a specific past scan; 404 if the scan doesn't exist
  - `GET /api/health` — aliveness check, returns Pulse version
- **`--api` flag** on `main.py` — starts the API with uvicorn. `--host` and `--port` override defaults
- **Interactive OpenAPI docs** — Swagger UI auto-generated at `http://127.0.0.1:8000/docs`
- **`pulse/whitelist.py`** — extracted `filter_whitelist` from `main.py` so both the CLI and the API share the same filtering logic
- **`CONTRIBUTING.md`** and **`SECURITY.md`** — dev setup, test commands, and responsible disclosure policy
- **GitHub tag `v1.1.0`** — stable release covering everything since v1.0.0 (live monitoring, history, interactive, baseline, Pass-the-Hash, parallel parsing, ECG animation, `--days`, and now the REST API)

### Fixed
- **Parser no longer crashes on empty/corrupt files** — `parse_evtx()` now returns `[]` for empty, missing, or unreadable `.evtx` files instead of raising `ValueError: cannot mmap an empty file`. Protects both the CLI and the API from bad input

### Tests
- 14 new tests in `test_api.py` covering every endpoint, bad inputs, history pagination, 404s, and temp-file cleanup
- Test count: 146 → 160, all passing

### Dependencies
- `fastapi>=0.100.0`, `uvicorn[standard]>=0.23.0`, `python-multipart>=0.0.6` (runtime)
- `httpx>=0.25.0` (testing only — required by FastAPI's TestClient)

---

## 2026-04-11 (continued)

### Added
- **`--days N` flag** — limits scan to the last N days of events (e.g. `--days 30`, `--days 180`). Works by passing a time filter directly to wevtutil so old events are skipped before any data is returned
- **Fast path parser** — `parse_evtx()` now uses wevtutil with an event ID filter (`RELEVANT_EVENT_IDS`) to fetch only the ~13 event IDs Pulse has rules for, skipping 95%+ of events. Falls back to python-evtx if wevtutil fails
- **Date + time in interactive mode** — TIME column now shows full `YYYY-MM-DD HH:MM:SS` instead of just `HH:MM:SS`

### Performance
- Scanning 382 files that previously hung now completes in seconds with `--days 30`
- Event ID pre-filtering reduces parsed events from ~67,000 to ~500-2,000 for a typical Security.evtx

---

## 2026-04-11

### Added
- **Interactive terminal mode** (`--interactive`) — browse findings after a scan, mark as investigated, add to whitelist directly from the terminal. No manual YAML editing needed
- **Known-good service whitelist** (`pulse/known_good.py`) — 100+ built-in entries covering anti-cheat, gaming platforms, hardware peripherals, Google, Microsoft, security software, VPNs, and common apps. Automatically merged with user's `pulse.yaml` whitelist on every scan
- **ECG heartbeat animation** — scrolling green ECG line with live file counter during parsing (`pulse/animations.py`)
- **Parallel file parsing** — `.evtx` files parsed across all CPU cores using `multiprocessing.Pool` with callbacks for real-time progress updates and a 30-second stall timeout for locked live files

### Fixed
- **Heartbeat message overlap** — shorter progress messages now padded to fixed width so they fully overwrite longer ones
- **Interactive mode TIME column blank** — timestamps extracted from embedded `details` string when no explicit `timestamp` field is present on a finding
- **Parser hanging on live log files** — added per-file stall timeout; files locked by Windows (e.g. live Security.evtx) are skipped automatically after 30 seconds of no progress

### Tests
- Test count: 146, all passing

---

## 2026-04-09

### Added
- **Live monitoring mode** (`--watch`) — polls Windows event channels (Security, System) in real time using `wevtutil`. Alerts on new suspicious events within seconds. Use `--interval` to set poll frequency (default 30s)
- **SQLite scan history** (`--history`) — every scan is saved to `pulse.db`. View past scans with security score trends and trend arrows (↑/↓) using `--history`
- **Parallel file parsing** — `.evtx` files are now parsed across all available CPU cores using `multiprocessing.Pool`, significantly faster when scanning many files
- **Built-in known-good service whitelist** (`pulse/known_good.py`) — ~100 entries covering anti-cheat engines, gaming platforms, hardware peripherals (Corsair, Razer, Logitech, NZXT), Google, Microsoft, security software, VPNs, and common apps. Suppressed automatically on every scan with no configuration needed
- **`record_num` field** added to every parsed event for deduplication in live monitoring

### Fixed
- **Live file reading** — `parse_evtx` now skips corrupt/partial records instead of crashing, allowing Pulse to read live Windows log files that are actively being written to
- **`Evtx` context manager** — fixed `TypeError` that occurred when reading live `.evtx` files by wrapping file access in a `with` statement as required by the library

### Tests
- 10 new tests for monitor module (poll_new_events, print_finding, _apply_whitelist)
- 11 new tests for database module (init, save, history, findings, sorting)
- Test count: 75 → 146, all passing

---

## 2026-04-08

### Added
- **4 new detection rules** - Account Lockout (Event 4740), Scheduled Task Created (Event 4698), Suspicious PowerShell (Event 4104 with pattern matching for encoded commands, download cradles, Mimikatz, etc.), Pass-the-Hash Attempt (Event 4624, NTLM network logon — detects stolen hash use, T1550.002)
- **Baseline comparison** (`--save-baseline`) — snapshots current accounts, services, and scheduled tasks on a known-good machine. Future scans auto-load the baseline and flag anything new (`New Account (Baseline)`, `New Service (Baseline)`, `New Task (Baseline)` findings)
- **MITRE ATT&CK tagging** - every detection rule maps to its ATT&CK technique ID (e.g. T1110, T1059.001). HTML report shows clickable links to attack.mitre.org
- **Security Score panel** - a score out of 100 at the top of every HTML report, displayed as a circular ring with a colour-coded risk label
- **Scan summary statistics** - HTML and text reports now show files scanned, total events, time range, and top event IDs
- **JSON report format** - `--format json` outputs structured data with metadata, severity summary, security score, and findings array with MITRE IDs
- **CSV report format** - `--format csv` exports findings as a spreadsheet for Excel or Google Sheets
- **Config file support** - `pulse.yaml` stores default settings so you don't need CLI flags every time
- **Whitelist/allowlist** - suppress known-good accounts, services, IPs, and rule names from findings via `pulse.yaml`
- **Inter font** loaded from Google Fonts for cleaner report typography
- **PyYAML** added as a dependency for config file parsing

### Fixed
- **Timestamp column showing "-"** for brute force and attack chain findings in HTML report
- **Em dashes removed** from all finding detail text and README

### Tests
- 41 new tests added (detections, JSON, CSV, config, whitelist)
- Test count: 34 -> 75, all passing
- Detection count: 11 -> 15 (13 individual + 2 chains)

---

## 2026-04-07

### Added
- **CLI arguments** (`main.py`) — Pulse is now a proper command-line tool:
  - `--logs FOLDER` — specify where to find `.evtx` files (default: `logs/`)
  - `--output FILE` — specify the output report path
  - `--format txt|html` — choose report format (default: `txt`)
  - `--severity LEVEL` — only show findings at or above this severity (default: `LOW`)
  - `--help` — auto-generated usage page
- **HTML report** (`pulse/reporter.py`) — dark-themed browser report with colour-coded severity badges and a summary panel
- **Time-windowed brute force** (`pulse/detections.py`) — brute force rule now only fires if 5+ failures happen within a 10-minute window, eliminating false positives from typos spread over days
- **Attack chain correlation** (`pulse/detections.py`) — two new CRITICAL-severity rules that connect multiple events into attack patterns:
  - **Account Takeover Chain** — brute force → successful login → new user created
  - **Malware Persistence Chain** — AV disabled → new service installed (in that order)
- **Two-tab layout** — Detections tab (filterable table) and Remediation tab
- **Remediation tab** — hardcoded action steps for all 11 detection rules, sorted CRITICAL first
- **Executive summary** — auto-generated based on severity of findings (tone adjusts: CRITICAL compromise detected vs routine monitoring)
- **Dark mode toggle** in the HTML report navbar — preference persisted in localStorage across reloads
- **Security Score panel** at the top of the HTML report — a score out of 100 that drops based on severity of findings (CRITICAL -25, HIGH -10, MEDIUM -5, LOW -2), displayed as a circular ring with a colour-coded risk label (SECURE / LOW RISK / MEDIUM RISK / HIGH RISK / CRITICAL RISK)
- **Inter font** loaded from Google Fonts for cleaner, more professional typography
- **Tests expanded from 28 to 34** — new tests cover time-window boundary conditions and chain ordering

### Fixed
- **Timestamp column showing "-"** for brute force and attack chain findings in HTML report — changed `strftime('%H:%M:%S')` to `strftime('%Y-%m-%dT%H:%M:%S')` so the reporter regex can extract a full date
- **Em dashes removed** from all finding detail text (replaced with plain hyphens for compatibility)

---

## 2026-04-06

### Added — 5 new detection rules
- **Firewall Rule Changed** (Event 4946/4947) — flags when firewall rules are added or modified, extracts the rule name
- **Firewall Disabled** (Event 4950) — flags when a Windows Firewall profile is changed/disabled
- **Antivirus/Defender Disabled** (Event 5001) — flags when real-time protection is turned off
- **Suspicious Service Installed** (Event 7045) — flags when a new service is installed, extracts service name and account
- **RDP Logon Detected** (Event 4624, LogonType 10) — flags Remote Desktop logins, extracts username and source IP

### Updated
- `run_all_detections()` now includes all 9 detection rules
- **Unit tests** expanded from 13 to 27 tests covering all rules
- Added `.claude/` to `.gitignore`
- Added `CHANGELOG.md`

---

## 2026-04-06 — Initial Release

### Added
- **Parser module** (`pulse/parser.py`) — reads `.evtx` files using `python-evtx`, extracts event ID, timestamp, and raw XML from each record
- **Detection rules** (`pulse/detections.py`) — four threat detection rules:
  - Brute Force Detection (Event 4625) — flags accounts with 5+ failed logins
  - User Account Creation (Event 4720) — flags new account creation with actor details
  - Privilege Escalation (Event 4732) — flags users added to security groups
  - Audit Log Clearing (Event 1102) — flags when security logs are wiped
- **Reporter module** (`pulse/reporter.py`) — generates a formatted `.txt` report with severity breakdown and finding details, auto-saves to `reports/` folder
- **Unit tests** (`test_detections.py`) — 13 tests covering all detection rules including edge cases
- **Entry point** (`main.py`) — wires parse, detect, and report steps together
- `pulse/__init__.py` — package marker with version
- `requirements.txt` — dependency list (`python-evtx`)
- `.gitignore` — ignores cache, logs, reports, and secrets

### Fixed
- Moved module files into `pulse/` subdirectory so `main.py` imports work correctly
