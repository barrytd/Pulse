# Changelog

All notable changes to Pulse are documented here.
Format: newest entries at the top, grouped by date.

---

## 2026-06-16 — Multi-tenant admin isolation (data-isolation core)

Hardening before any stranger gets a hosted login: stop one organization's admin from seeing or managing another organization's data.

- **Hosted admins are pinned to their own org.** `_read_scope_kwargs` no longer grants every `admin` global scope. A new `_has_global_scope()` grants cross-tenant scope only to auth-disabled installs, the env-only super-admin, and **single-tenant self-host** admins (who must keep global scope so they still see CLI-uploaded scans with `organization_id = NULL`). On a hosted deploy (`PULSE_HOSTED_SIGNUP=1`), each org admin is scoped to their own `organization_id`.
- **`/api/users` is org-scoped.** List returns only the caller's org; role/active/delete/display-name return **404** on a target in another org (404, not 403, so a cross-org id's existence doesn't leak). The "last admin" guard now counts admins **per organization**, so org A can't demote its only admin even though other orgs have admins.
- **Platform super-admin via `PULSE_SUPERADMIN_EMAILS`.** A comma-separated, env-only allowlist of emails that keep global scope. It can't be granted through signup or any API, so no tenant can escalate into it.
- **DB helpers** `list_users` and `count_admins` gained an `organization_id` filter.
- **11-test multi-org suite** (`tests/test_multitenant_admin_scope.py`) proves admin-of-A can't read/list/modify/delete in org-B, the per-org last-admin guard fires, and the super-admin still sees and manages everyone. Single-tenant behavior is unchanged (existing `test_data_isolation.py` still green). 1196 tests passing.
- *Still to do before public signup: CSRF custom-header check on mutating routes, and a trusted-proxy allowlist for the rate-limiter's `X-Forwarded-For`.*

## 2026-06-16 — Demo environment seed + triage polish

- **`scripts/seed_startup.py`** — one command to wipe the detection data and seed a realistic small-startup environment for live-style testing: a ~9-person team (admin / managers / analysts, all in your org, password `ChangeMe!8`), ~15 hosts (laptops + servers with believable stories — a critical domain controller, a compromised laptop, a brute-forced VPN, mostly-healthy employee machines), ~35 findings across all severities, plus assignments and workflow/review state already in progress so My Queue, Team, and the Dashboard look lived-in. Keeps your own admin login. Re-runnable.
- **Removed redundant confirmation toasts.** Marking a finding reviewed / false-positive or changing its workflow state no longer pops a "Marked reviewed and false positive" banner in the corner — the checkbox, badge, and highlighted pill already show the new state. Error toasts are kept.
- **Pip: follow-up chips in the user's voice.** Suggestions are now phrased as the question *you* tap to ask Pip ("Can you help with a specific alert?"), never as Pip asking you ("Do you have an alert open?").
- **Pip: real finding details in context.** When a finding drawer is open, Pip now receives the actual event details (event ID, host, the raw detail line with task/account/command/IP) so it can analyze *that* finding directly instead of asking you to retype what's on screen.
- **Pip: slides back on navigation.** Navigating away with a finding drawer open now tucks Pip back to the corner and clears the "Looking at &lt;finding&gt;" context, instead of leaving it stranded mid-screen.

## 2026-06-16 — Security Buddy "Pip" (MVP)

The headline AI feature: a floating robot chat circle in the bottom-right corner that anyone can click to ask security questions in plain language.

- **Floating chat widget.** A round mascot button (bottom-right) opens a chat panel. Ask Pip what a finding means, whether something looks dangerous, or any general security question. A "questions left today" counter and a typing indicator. New self-contained `buddy.js` + `buddy.css` (themed light/dark off the shared variables); mounts independently of `app.js`.
- **Dynamic follow-up suggestions.** After each reply, Pip offers 2–3 tappable follow-up questions tailored to what it just said — they refresh every turn instead of a fixed chip bar (starter prompts show on the greeting). The model returns them after a `[[FOLLOWUPS]]` marker that's parsed off server-side, so it never appears in the answer text.
- **Backend-proxied, key never in the browser.** New `pulse/buddy.py` calls the Anthropic **Claude Haiku 4.5** Messages API over `httpx` (already a dependency — no new package). The API key is read **server-side** from the `ANTHROPIC_API_KEY` env var. Two routes: `GET /api/buddy/status` (available? questions left?) and `POST /api/buddy/ask`.
- **Per-day metering.** New `user_ai_usage` table (`usage_date`, `questions_used`, `bonus_questions`) caps each user at **10 free questions per UTC day** — API billing is pay-as-you-go (separate from any personal Claude subscription), so this is the cost valve. Exhausting it returns `429` with a friendly "you're out for today, resets at midnight UTC" message. A blocked/failed answer never burns a question.
- **Prompt-injection safe.** Event-log and finding text is untrusted, so any finding context is fenced in an `<untrusted_data>` block and the system prompt tells the model to treat everything inside as data to analyze, never instructions to follow. Pip is read-only (no tools), output is HTML-escaped before render, and the panel discloses that chats are sent to Anthropic.
- **Finding-aware, transparently.** Opening a finding drawer slides Pip left to sit beside it (instead of overlapping) and hands Pip that finding's details (rule, severity, MITRE, plain-language meaning) so you can ask "is this dangerous?" about what you're reading. A "Looking at &lt;rule&gt;" pill in the panel makes it clear when Pip can see the finding; closing the drawer slides Pip back and clears the context.
- **No em dashes.** Pip is told not to use em/en dashes, and any that slip through are stripped server-side (spaced dashes become commas, ranges become hyphens) so replies read human. The hardcoded greeting was de-dashed too.
- **Thorough answers.** Tuned to give concrete, actionable guidance (not "tell me more"), with a longer answer cap so replies aren't cut off.
- **Stays in its lane + refers out.** Pip answers only what's asked (no pivoting to findings it wasn't given), and for anything out of scope — non-security questions, credentials, account/billing, bugs, feature requests — it briefly bows out and points to the **Feedback** option in the sidebar and the **GitHub issues** page (`github.com/barrytd/Pulse/issues`). URLs in replies are clickable.
- **Remembers your chat.** The conversation persists in the browser across refreshes (forgotten after a day), so a reload no longer wipes what Pip said or makes you re-ask and burn a question. A **New chat** button in the header starts fresh.
- **Stale-context fix.** Finding context is now bound to the live drawer state, so a previously-viewed finding can never bleed into a later, unrelated question.
- **Graceful when unconfigured.** With no `ANTHROPIC_API_KEY`, the widget still renders and explains that an administrator needs to add a key — no errors, no broken UI.

---

## 2026-06-16 — Team page + dashboard polish

- **Team Workload moved to its own "Team" page.** The per-analyst oversight view (open count, severity mix, oldest-unresolved age, avg fix time) felt out of place stacked into the Dashboard, so it's now a dedicated **Team** item in the sidebar (General group), gated to managers and admins (analysts don't see it; the backend still 403s `/api/team-workload`). The Dashboard no longer fetches or renders it, so it loads a touch lighter.
- **Browser-autofill blocked on filter/search boxes.** The saved login email was being autofilled into the search fields on Findings, Dashboard, Audit Log, and Firewall, and getting committed as a filter (the Findings list would show "0 of N"). Two causes, both fixed: (1) since Chrome ignores `autocomplete="off"` for saved emails, those inputs (and Pip's input) now render `readonly` and only become editable on real focus — the browser can't autofill a readonly field; (2) the Findings/Audit pages auto-focused the search box on load, which stripped that protection and let the email in — focus is now restored **only** when the user was actively typing (captured just before each re-render), never on a fresh page load.

---

## 2026-06-08 — Finding drawer triage polish

Extends the drawer redesign with the rest of the research recommendations:

- **Summary / Full toggle** at the top. **Summary** (the default for a fresh visitor, remembered per browser) leads with just the header band + "What happened" + "What to do now" + the threat-intel verdict — everything else (intel detail, technical, framework refs, firewall, assign, notes) is hidden until **Full**.
- **Difficulty badge moved into the header band** next to the severity pill, so the "how hard is this to pull off?" signal reads at a glance (removed the duplicate pill from the security-guide card).
- **One-line threat-intel verdict badge** in the header (e.g. "Malicious · 92") that fills in when AbuseIPDB returns a score — visible even in Summary mode where the full intel section is hidden.
- **Workflow + review controls pinned to a sticky footer**, always reachable without scrolling past the whole drawer. The body scrolls between the header and the footer.

---

## 2026-06-08 — Findings KPI strip overhaul

The old Open / Untriaged / Active / Resolved tiles overlapped (an item could be all three), so they read as "broken." Replaced with four **non-overlapping** tiles that always tell a story:

- **Needs attention** — untriaged critical / high (red).
- **In progress** — acknowledged or investigating (blue).
- **Critical + High open** — unresolved, high severity (amber).
- **Resolved** — closed in the last 7 days (green).

Each tile is a **clickable filter** into the list (sets status + severity), acting like a radio — click the active tile again to clear. The number is tinted by tone so the strip reads at a glance, and a genuinely-zero tile shows a **friendly line instead of a bare 0** ("All clear", "None open"), green when zero is the good outcome. Counts always reflect the full dataset; the tile filters only the table below.

---

## 2026-06-08 — Team role hierarchy Phase 6: sidebar role-gating + default landing

The final piece of the admin > manager > analyst hierarchy.

- **Per-role default landing.** An **analyst** opening the app lands on **My Queue**; managers and admins land on the **Dashboard**.
- **Role-gated sidebar.** Analysts no longer see nav they can't use — **Firewall, Whitelist, Rules, Audit Log** are hidden (those are manager/admin response + config + audit surfaces); a **manager** sees everything except **Audit Log**; an **admin** sees all. Empty nav groups collapse so no label is left orphaned. Settings stays visible to everyone (it carries each user's own profile / password / PIN); its admin-only tabs were already filtered.
- **Navigation guard.** Following a link to a page above your role (command palette, a stale bookmark) redirects to your default landing instead of a dead page. The role is resolved once at boot (with a 1.5s fail-open timeout) so the sidebar + landing are correct on first paint. Backend role checks are unchanged — this is the UX layer on top of them.
- **Topbar role pill** — a small badge next to the avatar always shows the signed-in role (Admin / Manager / Analyst); Admin gets the accent so it stands out.
- New `roles.js` (role ranks, page-access map, default landing, sidebar gating, topbar badge).

---

## 2026-06-08 — Settings UI redesign (TryHackMe-style) + tab polish

- **Wide, label-above form layout.** Replaced the old label-on-left two-column rows. The settings content is now a wide card (max-width 1200px, left-anchored next to the tab rail) with a reusable two-column field grid (`.settings-grid` / `.settings-field`, with `.full` to span). Each field's label sits above its input; inputs fill their column; buttons get their own row (`.settings-actions`); collapses to one column below 768px. Data-table pages (Findings, Audit, History, Scans, Fleet, Firewall, Reports) are untouched.
- **MY ACCOUNT / SECURITY PIN** cards converted to the new grid (email full-width; password pairs side by side; actions on their own row).
- **Profile tab tightened** — merged the "Profile Picture" and "Profile" cards into one. Avatar + Upload button lead the card; Display name + Role sit side by side in the grid.
- **No more tab-switch flash.** Clicking a settings tab used to blank the page, refetch every endpoint, and rebuild the whole rail. Now a tab switch swaps only the content panel from a cache (`_panelCache`), keeps the rail + header mounted, and fades in over 120ms. Full render only on first load / cross-page nav / after a mutation.
- **PIN show/hide eye** toggle on the PIN inputs, and the "Install Pulse Agent" numbered steps got proper alignment.

---

## 2026-06-08 — Security PIN (step-up auth for destructive actions)

Protects against a stolen session / account takeover: even with a valid login, an attacker can't do real damage without a second secret they don't have.

- **A separate PIN** (4–12 digits, scrypt-hashed), distinct from the password and session. **Setting or changing it requires the account password**, so a session-only thief can't set their own PIN.
- **Gated actions** return `403 pin_required` until confirmed: block/unblock a firewall IP, deactivate/delete a user, change a role. A correct PIN at `POST /api/me/pin/verify` grants a **5-minute elevation bound to that browser via a signed cookie** — the attacker's session never elevates because they can't enter the PIN. **Opt-in per user** (set a PIN → it's enforced; no PIN → actions proceed as before).
- **Hard lockout** after 5 wrong PINs (15 min) — low-entropy PINs can't be brute-forced; even the correct PIN is refused while locked.
- `pin_hash` is never read into the user object (not in the column allowlist), so it can't leak via any API.
- Frontend: a **Security PIN card** in Settings → Account (set/change/remove, password-confirmed) and a **PIN prompt modal** that pops on a gated action and retries it after elevation (`pinGuard` wrapper).
- 11 new tests (`test_security_pin.py`). 1174 tests pass.

---

## 2026-06-07 — Security audit fixes (access control + headers)

A hygiene + vulnerability pass (no committed secrets, no SQL/command injection, no XXE/path-traversal, XSS escaping verified sound, scrypt hashing + login lockout confirmed). Fixed the access-control gaps it surfaced:

- **IDOR on `PUT /api/findings/{id}/priority` (fixed).** The priority endpoint (added with the team-queue work) skipped the ownership check every other finding endpoint does, so a manager could set priority/due-date on any finding in any org by id. Now calls `_check_finding_scope` → 404 cross-scope.
- **Cross-org assignee leak (fixed).** `/api/finding/{id}/assign` and the batch assign validated that the assignee was *active* but not that they were in the caller's org — a manager could hand a finding to a user in another tenant, who'd then see it in their queue. Added `_check_assignee_in_scope` → 400 on an out-of-org assignee.
- **Security headers (added).** Every response now sends `X-Frame-Options: DENY` (clickjacking), `X-Content-Type-Options: nosniff`, and `Referrer-Policy: strict-origin-when-cross-origin`; `Strict-Transport-Security` in production. (A Content-Security-Policy is intentionally deferred — the SPA uses CDN scripts + inline styles and needs a dedicated CSP pass.)
- 2 cross-tenant IDOR regression tests added (`test_data_isolation.py`). 1163 tests pass.

*Flagged for a decision (not changed here):* tenant **admins currently have global scope** across all orgs and the `/api/users` management endpoints aren't org-scoped — fine for single-tenant, but a cross-tenant boundary break if hosted multi-tenant signup is enabled. Plus CSRF relies on `SameSite=Lax` only, and the rate limiter trusts `X-Forwarded-For`. These need a deliberate hardening pass before any multi-tenant launch.

---

## 2026-06-07 — Settings Profile/Account split + tab routing

- **Split the Profile tab in two.** **Profile** now holds identity only — profile picture / Upload Avatar, display name (with the admin "Edit on the Users tab" link), and role + description. A new **Account** tab (directly below Profile) holds the sign-in management section — account email, new/current password, Save account changes, and Sign out.
- **Account-dropdown links now route distinctly** instead of all landing on the same page: **View Profile → Settings ▸ Profile**, **Manage Account → Settings ▸ Account**. The sidebar **Settings** item still opens on the default first tab (Profile). Each deep-links straight to the correct tab.
- **Settings tabs are now real routes** — `/settings/profile`, `/settings/account`, `/settings/notifications`, etc. The active tab is reflected in the URL (in-page tab clicks `replaceState`; deep-links `pushState`), so refresh + back/forward behave correctly. Added the server-side `/settings/{tab}` SPA route (and a missing `/queue` route) so a direct load of a deep link serves the app shell. Threat-intel + onboarding links now deep-link to the exact tab; the old `localStorage` tab hand-off was removed.

---

## 2026-06-07 — Finding drawer + theme-toggle polish

- **Workflow selector** — dropped the "New" button. The selector now offers only **Acknowledged / Investigating / Resolved**; an untouched finding shows no highlighted pill (the implicit "new" state is never labeled or logged). Clicking a pill sets + saves + audits it; clicking the **active** pill again is a single-step undo that reverts to the value held right before that selection (a prior pill re-highlights; no prior → back to no pill). Reverting to the untouched state clears `workflow_status` + `workflow_updated_at` **without** writing an audit entry. The "Updated …" line tracks the most recent real change.
- **Review checkboxes now hydrate on reopen (bug fix)** — marking a finding *Reviewed* or *False positive*, closing the drawer, and reopening it left the checkboxes blank. They now carry a **persistent highlighted state** read from the finding's saved `reviewed` / `false_positive` flags on every open (replacing the old 3-second confirmation flash). The "Last reviewed" line is unchanged. Save path untouched — only the load/display path.
- **Framework references pills** — fixed the jammed `M1027Password Policies` rendering: each pill now reads `M1027 Password Policies` (ID, space, name) and the pills lay out in a wrapping flex row (8px gap) with consistent tag-pill padding (4×10px), radius, and a subtle border.
- **Dark-mode toggle icon** — the Appearance row now shows a **moon when dark mode is active and a sun when light**, swapping the instant the toggle is flipped (label stays "Dark Mode").

---

## 2026-06-07 — Team role hierarchy Phase 5: Team Workload card

The manager's "who's working on what" view — the *organize the team* half of the hierarchy.

- **Team Workload card** on the Dashboard (`/api/team-workload`): one row per active analyst with their **open (unresolved assigned) count**, a **severity mini-bar** (crit/high/med/low proportions of their queue), **oldest-unresolved age** (turns red past 72h), and **average time-to-resolve** (30-day). Busiest analyst first.
- **Click an analyst → their findings** — deep-links to the Findings page filtered by assignee (`/findings?assignee=<id>`), so a manager can drill from "Ana has 9 open" straight into Ana's list.
- **Auto role-gated**: the card fetches best-effort and hides itself when the caller isn't a manager/admin (403) or there are no analysts (solo account) — no explicit role check needed in the UI.

*Remaining (Phase 6, next):* sidebar role-gating so analysts land on My Queue by default and don't see admin-only nav.

---

## 2026-06-07 — Team role hierarchy Phase 4: assignment dialog

The piece that actually gets prioritized work into an analyst's queue. A manager now hands findings over with a priority + due date + context note in one step, instead of the quick dropdown that only set an owner.

- **Assignment dialog** (`assign-dialog.js` + modal): pick an analyst, set priority (defaults to **Auto**, which resolves from severity — Critical→P1 … Low→P4), set an optional due date, and add an optional note that lands in the finding's notes thread. Opens from **two places**: the finding drawer ("Assign + priority…") and the Findings **bulk bar** ("Assign + priority…") for many findings at once.
- **One round-trip**: extended `PUT /api/findings/batch` (`op=assign`) + `batch_set_finding_assignee` to set assignee + `assigned_by` + priority + due date in a single scoped update. The optional note is posted per finding afterward (best-effort).
- The drawer's Assigned-to section now **shows the current priority + due date** (with overdue/today color cues) when set.
- 3 new tests (batch assign sets priority/due, records the assigner, rejects a bad priority). 1159 tests pass.

---

## 2026-06-07 — Team role hierarchy Phase 3: priority schema + My Queue

Continues the admin > manager > analyst hierarchy so a small team can divide the work — a super-admin owns the org, a manager assigns + prioritizes, and analysts work their queue day to day.

- **Findings schema**: new `priority` (P1–P4), `due_date`, and `assigned_by` columns. `set_finding_assignee` now records who made the assignment; new `set_finding_priority(finding_id, priority, due_date)` helper. `FINDING_PRIORITIES` + `SEVERITY_DEFAULT_PRIORITY` constants (Critical→P1 … Low→P4) for the assignment-dialog default.
- **`get_user_queue(user_id)`** — an analyst's unresolved assigned findings, sorted **priority → severity → oldest-first** (P1 beats an unset CRITICAL). Each row carries the parent scan's number/date/host + who assigned it, so the page renders without a second query. `count_resolved_today(user_id)` powers the "resolved today" KPI.
- **`get_team_workload(org)`** — per-analyst board for managers: open count, avg time-to-resolve (30 days), oldest-unresolved age, severity mix, busiest-first.
- **`GET /api/queue`** — the analyst's queue + KPI tiles (in queue / overdue / due today / resolved today). **`GET /api/team-workload`** (manager-or-above). **`PUT /api/findings/{id}/priority`** (manager-or-above) sets priority + due date with an audit-log entry.
- **My Queue page** (sidebar, under General): KPI strip + a priority-sorted table (priority badge, severity, rule + scan/assigned-by, host, due-date with overdue/today color cues, status). Rows deep-link to the source scan. Empty state when the queue is clear.
- 17 new tests in `test_team_queue.py`. 1156 tests pass.

*Still to come (next):* Team Workload dashboard section, the assignment dialog (pick analyst + priority + due date) from the drawer + bulk bar, and sidebar role-gating so analysts land on My Queue.

---

## 2026-06-07 — Rule performance dashboard

New **Performance** tab on the Rules page — an operational health view distinct from the configuration-oriented Rules table.

- **`GET /api/rules/performance`** classifies every detection rule into a health band, server-side so the UI (and any future report) agree: **noisy/red** (≥30 hits AND ≥30% false-positive rate — drowning analysts, needs tuning), **watch/amber** (silent — enabled but never fired, or 15-30% FP), **healthy/green** (firing with an acceptable FP rate), **disabled/grey**. Each rule carries a one-line `health_reason`.
- Returns aggregate summary: counts per band, a `silent` subset, average scan duration (`duration_sec`), and scans analyzed.
- **Performance tab UI**: six header tiles (Healthy / Need a look / Noisy / Silent / Avg scan time / Scans analyzed), then a per-rule table sorted problems-first — health dot, rule + reason, severity, 24h hits sparkline, FP rate with TP/FP breakdown, last fired. Reuses the existing sparkline + severity-tone helpers.
- 9 new tests in `test_rules_performance.py`. 1139 tests pass.

---

## 2026-06-07 — Finding drawer redesign + first-run hero + UI polish

### Finding drawer redesign (less redundancy, clearer hierarchy)
The drawer explained the same event up to three times and had two overlapping "what to do" lists. Restructured around the non-expert reader who reads top to bottom.

- **Leads with the plain-language summary.** The Security Guide's "what happened" sentence + difficulty pill now sits at the very top of the drawer, directly under the severity badge and MITRE tag — the first thing the user reads.
- **One action list, not two.** The Security Guide's "What to do now" list is now the single source of next steps, promoted directly under the summary. The Remediation section's duplicate numbered list is gone.
- **Remediation → compact "Framework references."** Just the MITRE mitigation pills (e.g. M1026 / M1018 / M1032) for users who want the formal mapping — no repeated steps.
- **Raw event text deduplicated into a collapsible "Technical details" section**, collapsed by default. Holds the metadata (timestamp, event ID), the technical description/details, and the raw event XML. The old top raw-text box and the separate Description/Event Details sections are removed; experts are one click away.
- **Clear "Tracking" separator** splits the understanding area (summary, actions, technical) from the bookkeeping area (workflow state, assignment, notes, review) at the bottom.
- Findings with no knowledge-base entry (SIGMA imports, edge rules) fall back to leading with their own description so the drawer never opens empty.

### First-run hero
A brand-new account with no scans used to open to an empty dashboard that read as broken. New accounts now see a focused **"Run your first scan"** hero with a 1-2-3 mini guide and two clear CTAs (Scan my system / Upload a .evtx log). It disappears permanently once any scan exists. The Getting Started checklist and inline empty banner are suppressed while the hero shows, so there's a single, clear next step.

### UI polish
- Findings KPI relabeled: **"New findings" → "Untriaged"** with tightened sublabels ("all unresolved" vs "not yet reviewed") so the Open/Untriaged distinction is obvious.
- Dashboard data-reduction funnel boxes are now equal height (the "Crit + High" label no longer wraps and pushes its box taller).

### CLI
- `--logs` now accepts a single `.evtx` file, not just a directory. Passing a file previously raised `NotADirectoryError`; it now scans that one file, while a directory still scans every `.evtx` inside.

---

## 2026-06-03 — Sysmon support (Phase 2: network + credential access)

Completes Sysmon support. Phase 1 added process-create command-line analysis; Phase 2 adds the three remaining high-value Sysmon event types — and the parser already fetched all four IDs, so this is pure detection logic.

- **New rule — "LSASS Memory Access"** (Sysmon Event 10, CRITICAL, T1003.001): the highest-fidelity credential-dumping signal Pulse has. Flags a memory-read handle to `lsass.exe` from any process outside a small allow-list of legitimate accessors (wininit, services, Defender, Task Manager, …), gated on credential-dump access masks (0x1410, 0x1010, …) or any mask carrying the `PROCESS_VM_READ` bit. Unlike the Security-log 4656 path, Sysmon shows the exact access mask and source process, so false positives are rare.
- **New rule — "Suspicious Network Connection"** (Sysmon Event 3, HIGH, T1071): flags (a) living-off-the-land binaries (powershell, rundll32, mshta, certutil, …) making outbound connections to public IPs, and (b) connections to ports tied to offensive tooling (4444 Metasploit, 6667 IRC botnet C2, 1337/31337, …) regardless of process.
- **New rule — "Suspicious DNS Query"** (Sysmon Event 22, HIGH/MEDIUM, T1071.004): flags DNS tunneling (abnormally long subdomain labels encoding exfiltrated data) and LOLBins issuing their own DNS queries. Tunneling is HIGH; a lone suspicious-process query is MEDIUM.
- Knowledge-base entries (plain-language guide, immediate actions, prevention) for all three. RULE_META + compliance mappings. New techniques (T1059, T1071, T1071.004, T1572) added to the MITRE coverage report's tactic map (Execution / Command and Control).
- The `sysmon-execution-chain.evtx` sample extended into a complete chain: process-create stages → LSASS memory access → C2 beacon on 4444 → DNS-tunnel exfiltration. Now fires all four Sysmon rules.
- 34 new tests in `test_sysmon_phase2.py` covering each detection's positive + benign cases, the LSASS allow-list, public-IP gating, C2 ports, DNS tunneling thresholds, provider gating, and the full sample chain.

Pulse now ships **33 detection rules** (4 of them Sysmon-based). 1130 tests passing.

---

## 2026-06-03 — Sysmon support (Phase 1: process-create analysis)

First slice of Sysmon (System Monitor) support. Sysmon writes to its own channel with far richer telemetry than the Security log — full command lines, file hashes, parent-process context. Phase 1 wires the parser to read Sysmon events and adds the highest-value detection: command-line analysis of process-create events.

- **Parser** ([`pulse/core/parser.py`](pulse/core/parser.py)): new `SYSMON_EVENT_IDS` (1, 3, 10, 22) merged into the fast-path fetch filter so a Sysmon `.evtx` or live channel surfaces alongside Security-log events. Detections gate on the provider name, so a Security-log-only scan is a safe no-op.
- **New rule — "Suspicious Process Creation"** ([`detect_sysmon_process_create`](pulse/core/detections.py), Sysmon Event 1, HIGH, T1059): analyzes the full command line that Sysmon records but the Security log's 4688 usually omits. Flags encoded/obfuscated PowerShell, living-off-the-land binaries (certutil download, regsvr32 remote scriptlet, rundll32/mshta/bitsadmin/wmic abuse), credential-dumping tools, and Office/scripting apps spawning a shell. Provider-gated so it never confuses a same-numbered event from another channel.
- **Knowledge base + RULE_META**: full Security Advisor guide entry (plain language, why it matters, immediate actions, prevention, difficulty) and compliance mappings (DE.CM-7 / A.12.4.1).
- **Sample**: new `samples/sysmon-execution-chain.evtx` — a phishing-doc → encoded-PowerShell → certutil-download → LSASS-dump chain, all as Sysmon Event 1.
- **Tests**: 31 new in `test_sysmon_detections.py` covering provider gating, every command-line indicator family, parent-child relationships, benign cases, and end-to-end sample firing.
- **AV-signature hygiene**: defanged the literal Mimikatz module command strings (`sekurlsa::` / `lsadump::`) out of every `.evtx` sample and the detection source so cloning the repo no longer trips endpoint AV's `HackTool:Win32/Mimikatz` content signature on harmless synthetic test data. Detection regexes are assembled from fragments — they still match the real strings at runtime; only the bytes on disk are split. The `samples/sigma/` rule files keep the strings by necessity (a rule that detects Mimikatz must contain its signature, like an AV database).

1090 tests passing.

---

## v1.8.0 — Security Advisor, Report Catalog, Role Hierarchy (2026-06-02)

The release that puts plain language and reporting front and center. Pulse's audience is small teams without a SOC — v1.8 is built around that premise: every detection now explains itself, every report is one click away, and the role model finally matches how real teams work.

### Security Advisor + per-rule knowledge base
Every finding now ships with a plain-language **Security Guide** card in the drawer. Covers all 30 built-in detection rules. Each entry has: what happened (no jargon), why it matters, numbered immediate actions, exploit difficulty rating (Low/Medium/High), common false positives, and learn-more links. A new **Security Advisor** sidebar page (`/advisor`) translates the current posture into one sentence, ranks the top concerns by severity × difficulty × count, explains common attack types in plain language, and shows a hardening checklist where some items are auto-verified from open findings. Risk-level shields (green/orange/red) on the findings table give a quick at-a-glance difficulty signal. 68 new tests.

### Report template catalog (9 templates, 4 formats each)
All generated reports are now saved to the database (90-day retention) and listed on the redesigned Reports page. Every template produces PDF, HTML, JSON, and CSV.

- **Threat Detection Summary** — tactic-grouped findings, attack timeline, repeat-offender IPs with intel scores, chain-of-custody SHA-256 manifest. (Phase 1)
- **Executive Summary** — plain-language posture overview for leadership: letter grade, trend vs. previous period, top 3 risks written in non-technical language, activity tiles, recommendations. (Phase 2)
- **NIST CSF Coverage Report** — theoretical coverage + observed detection activity per CSF function, gap section listing uncovered subcategories. (Phase 3)
- **ISO 27001 Annex A Report** — same treatment for ISO 27001 Annex A controls. (Phase 3)
- **Incident Investigation Report** — per-finding deep-dive with raw event XML, threat-intel decoration, analyst notes, firewall blocks, and a SHA-256 chain-of-custody manifest for IR handoff. Entry points from the Findings bulk action bar and Fleet host rows. (Phase 4)
- **Fleet Health Report** — every monitored host ranked by risk tier, stale-host spotlight. (Phase 5)
- **Board-Ready Posture Report** — quarterly executive view with inline SVG score trend chart, fleet overview, compliance percentages, strategic recommendations. (Phase 5)
- **MITRE ATT&CK Coverage Report** — techniques laid out in canonical tactic order with finding counts, top-fired techniques, uncovered-tactic gaps. (Phase 5)
- **Compliance Gap Analysis** — uncovered MITRE techniques, silent rules, noisy rules — each framed as an actionable improvement item. (Phase 5)

**Reports page redesign:** flat 9-template grid with category chip filter (All / Threat Detection / Executive / Compliance / Incident / Fleet), KPI tiles (Total / PDF / This Week / Storage Used), and a polished generate modal (560px, side-by-side scope cards, 2×2 format grid, right-aligned footer).

### Three-role hierarchy (admin > manager > analyst)
The old binary admin/viewer split is gone. Three roles with distinct permissions:
- **Admin** — system settings, users, agents, API tokens.
- **Manager** — sees every org finding, assigns work to analysts, manages whitelist + firewall + reports + audit log exports.
- **Analyst** — works the queue of assigned findings; browses every org finding read-only.

Role badges updated (A / Mg / An). Settings > Users role dropdown has all three options. Legacy `viewer` rows migrated to `analyst` at boot. Backwards-compatible: `viewer` is accepted everywhere and silently rewritten. Phases 3–8 (My Queue page, Team Workload section, priority + due-date columns) deferred to v1.9.

### SIGMA rule import
Paste community SIGMA YAML into the dashboard and Pulse evaluates it alongside every built-in rule. Parser covers the pragmatic subset (selection blocks, `|contains` / `|startswith` / `|endswith` / `|re`, `and` / `or` / `not`). Unsupported aggregations fail loud at import time. `sigma_rules` table is org-scoped. New **SIGMA Import** tab on the Rules page with preview, import, toggle, delete. 63 new tests.

### Project root reorganization
`scripts/`, `docs/`, `installer/` subdirectories created. Standalone utilities and ancillary docs moved out of the root.

**Tests:** 1057 passing (up from ~870 at v1.7.0).

---

## 2026-06-02 — Report template catalog Phases 3, 4, and 5 (full catalog shipped)

The catalog is complete. Seven new templates land across three phases, totaling nine templates with the two from earlier. All share the same dispatch pattern proven in Phase 1.

### Phase 3 — NIST CSF + ISO 27001 (compliance reports)

Theoretical control coverage + observed detection activity in one document. Auditors want both.

- Shared `pulse/reports/compliance.py` module exports `build_nist_csf()` and `build_iso_27001()`. Layers period finding counts onto the theoretical view from `rules_config.build_compliance_summary`. `NIST_EXPECTED_SUBCATEGORIES` + `ISO_EXPECTED_CONTROLS` define what should be there; the gap sections are the diff.
- Renderers in `pulse/reports/compliance_renderers.py` dispatch on the dict's `framework` field. HTML uses serif body type + print-ready CSS for the audit-document look. PDF uses `KeepTogether` per group so sections don't split across pages. Coverage bars per group.
- API: `nist_csf_coverage` and `iso_27001_annex_a` slugs registered. Disabled-rules list from pulse.yaml flows through.
- UI: new "Compliance" category section (blue accent) with both cards. Both default to "Recent activity" scope.
- **17 tests** in `test_compliance_reports.py`.

### Phase 4 — Incident Investigation Report

The IR-handoff document. Different scope shape (host or finding_ids) instead of date-range.

- `pulse/reports/incident.py` builds per-finding rich detail: source IP + account extracted from raw XML, threat-intel decoration (best-effort, cache-only), analyst notes from the database, remediation actions taken (IP blocks). Chain-of-custody: SHA-256 over (id, ref_id, rule, timestamp, raw_xml) per finding plus a report-level digest over the concatenated finding hashes. Hex digests printed in the manifest so a reviewer can recompute and verify.
- Renderers in `pulse/reports/incident_renderers.py`. PDF uses `KeepTogether` on every finding card. Raw event XML rendered in 7.5pt Courier with a per-card truncation cap so a 100-finding report stays printable. HTML embeds the dark-themed event block + manifest table.
- API: dedicated `_generate_incident_report` helper routes the host / finding_ids scope.
- UI: new "Incident" category section (orange accent). Modal hides date-range radios for this template; shows either a host picker or a preselected-findings confirmation line.
- **Entry points**: Findings page bulk action bar now has a "Generate Incident Report" button that pre-scopes to the selected finding IDs. Fleet page table rows have a per-host siren icon that opens the modal pre-scoped to that host.
- **31 tests** in `test_incident_report.py`.

### Phase 5 — Fleet Health, Board-Ready, MITRE Coverage, Compliance Gap

Four templates, one commit because they share infrastructure (single light-theme HTML scaffold, shared PDF stat-tile + table helpers).

- **Fleet Health** (`pulse/reports/fleet_health.py`): every monitored host ranked by risk. Risk tiers match the dashboard's score thresholds. Stale section spotlights hosts with no recent scan. Green accent on the card.
- **Board-Ready Posture** (`pulse/reports/board_ready.py`): quarterly-style executive view. Inline SVG line chart for the score trend (no external chart library so it survives print). Reuses the Executive Summary's narrative + NIST + ISO + Fleet builders. Purple accent.
- **MITRE ATT&CK Coverage** (`pulse/reports/mitre_coverage.py`): techniques laid out in the canonical ATT&CK tactic order. Top-fired techniques list. Silent + uncovered tactic spotlights. Red accent.
- **Compliance Gap Analysis** (`pulse/reports/compliance_gap.py`): uncovered techniques, silent rules (enabled but never fired), noisy rules (≥30 hits AND ≥30% FP rate). Each gap framed as an actionable improvement item. Blue accent.
- All four share `pulse/reports/phase5_renderers.py` — one HTML scaffold + one generic table-PDF document builder + per-template content composers. Four `render_<slug>(payload, fmt)` entry points.
- API: four slugs registered in the dispatcher (`fleet_health`, `board_ready_posture`, `mitre_attack_coverage`, `compliance_gap_analysis`). Phase 5 templates pull from `get_fleet_summary`, `get_rule_stats`, and the existing rule-config helpers — no new database queries needed.
- New `_resolve_org_name()` helper extracted in `pulse/api.py` since five different templates now look up the same org name.
- UI: new "Fleet" category section (green accent). MITRE Coverage tucked under the existing Threat Detection category. Board-Ready under Executive. Gap Analysis under Compliance.
- **37 tests** in `test_phase5_reports.py`.

### Catalog totals

Nine templates spanning five categories (Threat Detection, Executive, Compliance, Incident, Fleet). All four output formats (PDF / HTML / JSON / CSV). All saved to the reports table with `template_type` populated. 85 new tests across Phases 3–5; **1057 tests pass overall**.

---

## 2026-06-02 — Report template catalog Phase 2: Executive Summary

The board-ready report. Phase 2 of the 5-phase catalog plan. Same dispatch pattern proven in Phase 1; the API endpoint now selects builder + renderer based on `template_type` so future templates (Compliance, Incident Investigation, Fleet Health) drop in without further refactoring.

What this report is for: the one-pager an admin forwards to their boss. Every section is written for someone who does *not* read security logs for a living. No event IDs, no MITRE technique codes, no rule slugs in the body text.

- **Builder** in [`pulse/reports/executive_summary.py`](pulse/reports/executive_summary.py). `build_executive(findings, scans, *, period_days, prev_findings, prev_scans, scope_label, org_name)` returns a structured payload with: header (title, org name, period range, generation time), posture at a glance (letter grade A–F + one-sentence interpretation + score out of 100 + trend vs. previous period), a 2-3 sentence plain-language narrative generated from the actual counts and top host, top 3 unresolved risks (with what-happened / why-it-matters / recommended-action pulled from the Security Advisor knowledge base), activity overview tiles (total / open / resolved / machines monitored / machines at risk), "What Changed" comparison vs. previous period, 3-5 forward-looking recommendations, and a footer pointing technical readers to the Threat Detection Summary.
- **Renderers** in [`pulse/reports/executive_summary_renderers.py`](pulse/reports/executive_summary_renderers.py). All four formats consume the same dict so the PDF and HTML can't disagree on the numbers.
  - **PDF**: light theme, polished. 24pt title, big colored grade circle on the cover, generous whitespace, board-ready. New helper flowables: `_BigGradeChip` (canvas-drawn colored circle with centered letter) and `_RankChip` (numbered rank circle for the Top Risks header). `KeepTogether` on each risk card so a card never splits across pages.
  - **HTML**: light theme, print-friendly with `@page` + `@media print` rules. Self-contained styles so the file emails / prints cleanly. Big colored grade circle on the cover band, the narrative paragraph rendered as a yellow-tinted callout, severity-colored stat tiles.
  - **JSON**: pretty-printed payload for SIEM-side parsing.
  - **CSV**: section + field + value KV layout plus separate Top Risks and Recommendations blocks at the bottom (the use case is "paste sections into a quarterly compliance tracker", not "open as a table").
- **API**: `POST /api/reports/generate` now dispatches on `template` — `threat_detection_summary` and `executive_summary` are both recognized; unknown values return 400 with the full supported list. Executive Summary requests with a `{days: N}` scope also fetch the previous N-day window so the trend indicator + "What Changed" can populate; per-scan scope still works but doesn't yield a comparison period. Filename prefix is `pulse_executive_summary_` so history rows are easy to scan.
- **Reports page UI**: new "Executive" category section under "Threat Detection", with a purple (`#8b5cf6`) left-border accent. Card description: "One-page security overview in plain language for leadership and stakeholders. No technical jargon." The Generate modal now uses per-template metadata (`_TEMPLATES`) to set the title and subtitle, default scope, and which scope radios show. Executive Summary defaults to "Recent activity" and hides the per-scan radio because period comparison is its whole point. Time-window dropdown gains a "Custom range…" option with a 1–365 day input.
- **Knowledge-base integration**: the Top Risks section pulls `plain_language`, `why_it_matters`, and the first `immediate_actions` step from `pulse/core/knowledge_base.py` so the risk cards read in the same voice as the Security Advisor drawer. Findings without a knowledge entry fall back to their own `description` / `details` so the section never goes empty.
- **What This Means**: rule-based narrative generator. Same inputs always produce the same paragraph — a reader who memorizes one report's wording can spot the next period's deltas instantly.
- **Tests**: 44 new in [`tests/test_executive_summary.py`](tests/test_executive_summary.py) covering grade thresholds, resolved-finding classification (including the legacy `reviewed` flag), header + posture + trend + activity + What Changed shape, top-risks ranking and dedup, recommendation dedup + fallback, all four renderers, and end-to-end API generation including a regression guard that Phase 1's `threat_detection_summary` template still round-trips through the new dispatch. Plus one updated assertion in `test_threat_summary.py` for the new dispatcher error message. **972 tests pass overall (up from 928).**

---

## 2026-06-02 — Report template catalog Phase 1: Threat Detection Summary

The first entry in the new report-template catalog. This is the report a user generates right after their first scan — tactic-grouped findings, attack timeline, top rules, repeat offenders. Phase 1 of a 5-phase plan; future templates (Executive Summary, Compliance NIST/ISO, Incident Investigation, Fleet Health) plug into the same dispatch pattern proven here.

- **Schema**: `reports.template_type` column added via `ALTER`. Legacy rows (pre-template) keep a NULL value; the UI displays them as generic "scan export".
- **Data builder** in [`pulse/reports/threat_summary.py`](pulse/reports/threat_summary.py). One pure-Python function takes findings + scan metadata and returns a structured dict with: header (title, scope, hosts, generation time), summary band (totals, severity breakdown, score + grade), findings grouped by MITRE tactic in canonical kill-chain order, chronological attack timeline, top-N triggered rules, repeat-offender source IPs and hosts (with threat-intel scores when the intel cache has them), and a footer with the Pulse version + automated-assessment note.
- **MITRE technique → tactic map** mirrors the JS map in [`pulse/static/js/rules.js`](pulse/static/js/rules.js) so the dashboard's MITRE coverage matrix and the report group findings the same way. An "Other" sink bucket keeps unmapped rules visible.
- **Four format renderers** in [`pulse/reports/threat_summary_renderers.py`](pulse/reports/threat_summary_renderers.py) all consume the same dict so PDF and HTML can't disagree on the numbers:
  - **JSON** — straight serialization, the canonical SIEM-ingest format.
  - **CSV** — flat finding list with UTF-8 BOM so Excel opens it cleanly.
  - **HTML** — standalone dark-themed page that mirrors the dashboard's look. Self-contained: every style inlined so the file shares / emails / opens offline cleanly.
  - **PDF** — reuses the existing `pulse/reports/pdf_report.py` infrastructure (grade-colored score ring, severity pills, footer). New section builders for tactic, timeline, top rules, repeat-offender tables.
- **`POST /api/reports/generate`** endpoint takes `{template, format, scope}` where scope is either `{scan_id}` or `{days}`. Persists the bytes to the `reports` table with the new `template_type` column, then returns the file as a download. Intel-cache lookup is best-effort (cache-only, no network) so the report never blocks on AbuseIPDB.
- **Reports page UI**: new template catalog section above the history table. Card for "Threat Detection Summary" under a "Threat Detection" category heading, with the spec'd description and a Generate button. The existing Generate Report modal now supports a "Data scope" toggle (single scan vs recent N days) plus the four format radios. Generated file downloads via blob so the persisted filename matches what shows up in the history table. Toast: "Report saved and downloaded. View it anytime on the Reports page."
- 29 tests in [`tests/test_threat_summary.py`](tests/test_threat_summary.py) cover the builder shape, tactic mapping, IP extraction, intel-failure tolerance, all four renderer formats, end-to-end API generation, scope handling, and template/format validation. Full suite: 923 tests pass.

---

## 2026-06-02 — Role hierarchy (Phase 1+2) + Reports persistence

### Three-role hierarchy: admin > manager > analyst (Phase 1+2 of 8)

Pulse's role model used to be admin/viewer, where "viewer" served double-duty as both "can see things" and "can be assigned findings." The new hierarchy splits those responsibilities cleanly.

- **Admin** — system settings, user management, agents, API tokens, integrations, branding. Same as before.
- **Manager** — sees every finding in the org, assigns work to analysts, manages whitelist + firewall + reports + audit log. No system settings.
- **Analyst** — works the findings assigned to them; browses every finding in the org read-only. (This is the renamed-from-viewer role.)

What landed:
- Database: new `VALID_ROLES = ('admin', 'manager', 'analyst')` constant, `normalize_role()` helper that rewrites legacy `viewer` to `analyst`, `role_is_at_least()` for rank-aware comparisons. `create_user` and `update_user_role` accept all three. `init_db` runs a one-shot `UPDATE users SET role = 'analyst' WHERE role = 'viewer'` so an upgraded deploy comes up with every row already migrated.
- Auth: new `require_manager` FastAPI dependency (admin OR manager). `require_admin` and `require_login` unchanged.
- API: `/api/users` POST + `/api/users/{id}/role` PUT accept all three roles. Last-admin-demotion guard tightened so demoting an admin to either manager or analyst still blocks when it would lock everyone out. The following endpoints promoted from admin-only to manager-or-above: `DELETE /api/reports/{filename}`, `DELETE /api/reports/batch`, `GET /api/audit/export.csv|json|ndjson`, `DELETE /api/whitelist/batch`, `PUT /api/config/whitelist`, `GET /api/firewall/log`, `POST /api/firewall/log`.
- Frontend: role badge shows `A` (admin), `Mg` (manager), `An` (analyst). Settings > Profile role description rewritten for all three roles. Settings > Users 3-dot menu offers Make admin / Make manager / Make analyst (hiding the user's current role). New-user form has all three options. Legacy `viewer` values still render as `Analyst` everywhere during the rollout window.
- Seeds: `seed_test_users.py` mixes admins, managers, and analysts so QA exercises every role. `seed_demo_full.py` uses analysts as the assignee pool.
- 29 tests in `test_role_hierarchy.py` cover normalize / role_is_at_least / create-with-each-role / viewer-alias / init-time migration. 12 existing test files that referenced `viewer` updated to `analyst`. 154 role-touching tests pass.

Phases 3–8 (priority + due-date columns, My Queue page, Team Workload section, sidebar role-gating, full permission tests) are deferred to a follow-up sprint.

### Reports persistence

Generated reports used to land in the `reports/` directory and disappear whenever a hosted deploy restarted with an ephemeral filesystem. Now they're stored in the database so a team that generated a PDF on Monday can grab it on Friday without anyone needing shell access to the server.

- New `reports` table — `(id, scan_id, format, filename UNIQUE, file_data BLOB, file_size, generated_by, generated_at, organization_id)`. Filenames now embed a timestamp (`pulse_scan_42_20260602_120000.pdf`) so multiple historical exports of the same scan coexist instead of overwriting each other. The db_backend layer rewrites `BLOB` to `bytea` on Postgres.
- DB helpers in `pulse/database.py`: `save_report`, `list_reports_db`, `get_report_meta`, `get_report_bytes`, `delete_report_by_filename`, `delete_reports_by_filenames`, `purge_old_reports`, `reports_storage_total`. Org-scoped reads/deletes block cross-tenant access.
- `/api/export/{scan_id}` now persists every generation to the DB before returning the bytes for download. A DB save failure is logged to the audit trail but never blocks the download.
- `/api/reports` returns a richer payload — per-row metadata (scan number, scan date, hostname, generator display name, file size) plus KPI tiles (`total`, `pdf`, `this_week`, `storage_bytes`) and the org's `retention_days`.
- `/api/reports/{filename}` GET serves bytes straight from the DB blob with the right MIME type. DELETE removes the DB row.
- `/api/reports/batch` DELETE uses the new bulk helper. Both single and batch deletes are scoped to the caller's org.
- 90-day retention purge runs on every `init_db` boot. Idempotent — the operation is a bounded DELETE, not a full table scan.
- Reports page UI overhaul: KPI strip at the top (Total / PDF / This week / Storage used), filter chip bar (Format / Scan / Generated by / Time range), updated table columns (Generated · Scan link · Format badge · Size · Generated by · Actions), search box still narrows by filename/host/generator, retention footer note. Empty state copy updated to mention the 90-day retention.
- Generate flow toast updated: "Report saved and downloaded. View it anytime on the Reports page." If the user is on the Reports page when they generate, the list refreshes automatically so the new row appears.
- 16 new tests in `test_reports_persistence.py` cover save/get/list/delete/purge round-trips, duplicate-filename overwrite semantics, org-scope isolation, and the API list/download/delete endpoints. 894 tests pass overall.

---

## 2026-06-01 — Security Advisor + project reorg

### Security Advisor (Sprint 8 — Pulse positioning ticket)

Pulse's audience is the small team without a SOC analyst: freelance IT admins, 3-person startups, nonprofits, students. Enterprise tools (CrowdStrike, Splunk) explain nothing because they assume their customers already know. Pulse now explains everything.

- New [`pulse/core/knowledge_base.py`](pulse/core/knowledge_base.py) with plain-language entries for all 30 detection rules. Each entry: one-sentence explanation, why it matters, numbered immediate-actions list, prevention, learn-more links (MITRE + vendor docs), exploit-difficulty rating (low / medium / high), and common false positives. Editorial rule: no jargon — instead of "NTLM authentication downgrade detected via Event 4624 LogonType 3" we write "Someone logged into this computer from the network using an older, less secure authentication method."
- `attach_remediation()` now also attaches the knowledge dict to every finding so the dashboard never needs a second round trip.
- New **Security Guide** card in the finding drawer (and inline expand row) — blue-tinted left border to distinguish from the orange-tinted Remediation card. Plain-language explanation, difficulty pill, expandable Why this matters / Prevention / False positives, numbered immediate actions, learn-more links.
- New **Security Advisor** sidebar page (`/advisor`) with: posture summary in one sentence ("Your network has 3 critical issues that need immediate attention. The most active host is SERVER-DC01."), top concerns ranked by severity × exploit difficulty × count, attack-concept explainers (Brute Force, Pass-the-Hash, Credential Dumping, etc.), and a hardening checklist where auto items are derived from open findings ("✓ Audit logging is on", "! Antivirus is enabled and tamper-protected") and manual items are reminders the user verifies themselves.
- Risk-level shields on the findings table — a small green / orange / red square next to each rule name shows how easy that attack is to pull off. Hover tooltip: "Low/Medium/High exploitation difficulty".
- Backlog entry added for **AI Security Advisor (live)** — live Anthropic API integration for contextual analysis of specific findings. Premium-tier feature; static knowledge base ships free.
- 68 new tests: `tests/test_knowledge_base.py` (65) — every RULE_META entry has a knowledge entry (drift guard), entry shape validation, fallback behavior; `tests/test_advisor_api.py` (4) — `/api/advisor/overview` payload shape.

### Project root reorganization

Moved standalone utility scripts and ancillary docs out of the repo root into purpose-named directories. Only convention-expected files (README, LICENSE, requirements*, Dockerfile, etc.) stay at root.

- `seed_demo_data.py`, `seed_fleet_demo.py`, `send_test_email.py` → `scripts/`
- `BUSINESS.md` → `docs/`
- `pulse-agent.spec` → `installer/`
- Each moved script gained a `sys.path` tweak so `python scripts/foo.py` keeps working from the repo root. PyInstaller spec now resolves the project root via `SPECPATH` so the build works regardless of cwd.

---

## 2026-05-28 — SIGMA rule import

### SIGMA rule import (Sprint 8 — "Up Next" High-priority ticket)

Admins can now paste community SIGMA YAML rules straight into Pulse and have them fire on every scan alongside the built-in detections. SigmaHQ ships thousands of community rules; this unlocks them.

- Parser + runtime matcher in [`pulse/core/sigma.py`](pulse/core/sigma.py). Supports the pragmatic subset most community rules use: selection blocks with equality / `|contains` / `|startswith` / `|endswith` / `|re` modifiers; `and` / `or` / `not` / parens conditions; severity mapped from `level:` (`critical` / `high` / `medium` / `low` / `informational`); MITRE technique pulled from `attack.tXXXX[.XXX]` tags. Aggregations, `1 of them`, and the `|all` modifier raise `SigmaUnsupported` at parse time so unimplementable rules fail loud, not silent.
- New `sigma_rules` DB table stores original YAML + compiled JSON spec with `organization_id` scoping for multi-tenant isolation. Helpers in [`pulse/database.py`](pulse/database.py): `save_sigma_rule`, `list_sigma_rules`, `get_sigma_rule`, `set_sigma_rule_enabled`, `delete_sigma_rule` — all org-scoped so one tenant can't touch another tenant's rules.
- `run_all_detections(events, sigma_rules=...)` now optionally accepts a list of enabled SIGMA rules and runs them alongside the built-ins. The `/api/scan` endpoint loads the caller's org's enabled rules and passes them through. A broken stored row is skipped instead of crashing the scan.
- REST API under [`/api/rules/sigma`](pulse/api.py): `GET` list / detail (any signed-in user in the org), `POST` upload + `POST` preview / `PUT` enable / `DELETE` (admin-only, rate-limited at 200 uploads / 30 previews per window). Body accepts either `{yaml: "..."}` JSON or a raw `text/yaml` payload. 64 KB size cap.
- New **SIGMA Import** tab on the Rules page ([`pulse/static/js/rules.js`](pulse/static/js/rules.js)) with: imported-rules table (name, severity, MITRE, enable/disable toggle, delete), and an importer card for admins (paste YAML → Preview shows what Pulse extracted → Import saves). Viewers see the list read-only.
- 3 sample SIGMA rules in [`samples/sigma/`](samples/sigma/): encoded PowerShell (`T1059.001`), mimikatz CLI (`T1003.001`), rundll32 from temp (`T1218.011`). Each one targets a real Windows attack the built-ins don't already cover.
- 63 new tests across [`tests/test_sigma_parser.py`](tests/test_sigma_parser.py) (30), [`tests/test_sigma_db.py`](tests/test_sigma_db.py) (10), [`tests/test_sigma_runtime.py`](tests/test_sigma_runtime.py) (6), [`tests/test_sigma_api.py`](tests/test_sigma_api.py) (17).

---

## 2026-05-28 — Time-based correlation engine + three bug fixes

### Time-based correlation engine (Sprint 8 — "Up Next" Urgent ticket)

Four new sequence-aware detections that catch attacks single-event rules miss. The detection engine until now fired per-event; these four read the full event stream and emit findings only when a multi-event pattern matches within a sliding time window.

| Rule | Severity | Pattern | MITRE |
|---|---|---|---|
| **Brute-Force Success** | 🔴 CRITICAL | 5+ Event 4625 (failed) from one source IP within 10 min → 1+ Event 4624 (success) from same IP | T1110.001 → T1078 |
| **Impossible Travel** | 🟠 HIGH | Same user authenticates from two different hosts/IPs within 60 s | T1078 |
| **Privilege Escalation Chain** | 🔴 CRITICAL | Event 4720 (user created) → Event 4728/4732 (added to group) within 5 min, same actor | T1136.001 + T1098 |
| **Lateral Spray** | 🔴 CRITICAL | One source IP → 3+ distinct hosts via LogonType=3 (network logon) within 5 min | T1021 + T1078 |

All four are scoped + de-duped per (IP / user / actor) so a single attack burst emits one finding, not one per matched event. Boundary cases (just-below threshold, just-outside window, machine accounts, same-host repeats, missing fields) all degrade silently to "no finding."

- Functions: `detect_brute_force_success`, `detect_impossible_travel`, `detect_privilege_escalation_chain`, `detect_lateral_spray` in [`pulse/core/detections.py`](pulse/core/detections.py). Wired into `run_all_detections`.
- `RULE_META` entries in [`pulse/core/rules_config.py`](pulse/core/rules_config.py) with severity / MITRE / NIST CSF / ISO 27001.
- Per-rule remediation steps + MITRE mitigation IDs in [`pulse/remediation.py`](pulse/remediation.py) so the finding drawer's Remediation tab is populated.
- 25 new tests in [`tests/test_correlation_rules.py`](tests/test_correlation_rules.py): each rule has a fires-on-match test, a quiet-on-near-miss test, a window-boundary test, and a "one-finding-per-burst" dedupe test. Plus an integration test that drives a full scenario through `run_all_detections` and asserts all four rules light up.
- Smoke check against shipped samples: the existing `samples/brute-force-server.evtx` (171 events, 5 detections previously) now also fires **Brute-Force Success** because the synthetic attacker IP eventually succeeds. Confirms the new rule works against realistic synthetic data, not just hand-built unit tests.

### Three bug fixes from live UI testing

While the user was exercising the dashboard end-to-end, three real bugs surfaced. All three are fixed with regression tests.

- **Cache-induced sign-in loop** (commit `c240c77`). `FileResponse` for `/`, `/login`, `/welcome` didn't set cache headers; browser served the cached landing page after sign-in, so the user landed back on the marketing page until a hard refresh. Fix: `Cache-Control: no-store, no-cache, must-revalidate` + `Pragma: no-cache` + `Expires: 0` on all three routes. Regression test: `test_auth_state_pages_set_no_store_cache_header`.
- **Assignment-visibility blocking** (commit `c240c77`). A viewer assigned 25 findings saw "No findings" on their Findings page because `get_history` / `get_scan_findings` filtered strictly by org scope and the scans were out-of-org. Fix: both helpers gained an `assignee_user_id` parameter that OR-widens the scope clause via `EXISTS (SELECT 1 FROM findings WHERE scan_id=s.id AND assigned_to=?)`. New `_findings_scope_kwargs(app, user_id)` helper plumbs it through `/api/history`, `/api/report/{id}`, `/api/findings/export.csv`, `/api/score/daily`, `/api/compare`, `/api/export/{id}`. Non-findings endpoints (`delete_scans`, `list_agents`, `get_fleet_summary`) keep the plain `_read_scope_kwargs` — assignees should NOT gain delete-power or fleet-management on out-of-scope hosts. 4 regression tests in [`tests/test_assignment_visibility.py`](tests/test_assignment_visibility.py): viewer sees assigned scan in history, viewer can fetch report, **viewer does NOT see un-assigned out-of-scope scans** (prevents privilege escalation), admin behavior unchanged.
- **Filter state resets on F5** (commit `a79411f`). Findings-page filter state lived in JS module memory only; refresh wiped it. Fix: round-trip the filter Sets / query / sort through `URLSearchParams`. Hook points: `applyFindingsView()` calls `_syncFiltersToUrl()` on every filter change (via `history.replaceState`); `renderFindingsPage()` calls `_loadFiltersFromUrl()` on initial load (only when no `_pendingFindingsFilter` deep-link is already set). Encoding: `?severity=CRITICAL,HIGH&-rule=Audit%20Log%20Cleared&q=PowerShell&sort=severity:desc`. Empty axes aren't serialized to keep URLs clean. Side benefit: filtered views are now shareable / bookmarkable.

### Known issue (deferred to separate ticket)

The 62 orphan `"Robert's organization"` rows in the live DB stem from `_backfill_organizations` creating org rows but the `UPDATE users SET organization_id = ?` step not persisting — every server restart adds two more orphans. Tracked in the ROADMAP backlog. The assignment-visibility fix routes around the consequences for now (a viewer assigned a finding sees it regardless of org), but it should be fixed before hosted multi-tenant goes live.

Tests: **730 passing** (+25 new correlation tests + previously committed 5 from the bug fixes).

## 2026-05-27 — Release polish: sample data, README rewrite, CONTRIBUTING, Docker

Four landings to make Pulse evaluatable + contributable for the GitHub browse experience.

### Sample data bundle

- New `samples/` directory with four synthetic `.evtx` files demonstrating real attack patterns end-to-end: `brute-force-server.evtx` (171 events, 5 detections incl. Account Takeover Chain), `credential-theft-workstation.evtx` (7 events, 4 detections incl. Credential Dumping), `persistence-malware.evtx` (5 events, 6 detections incl. Malware Persistence Chain), `lateral-movement-dc.evtx` (8 events, 5 detections incl. DCSync + Golden Ticket). Plus the existing `sample-pfirewall.log`.
- New [`samples/README.md`](samples/README.md) — per-file scenario description, expected detections + severities, expected grade.
- New [`scripts/generate_sample_evtx.py`](scripts/generate_sample_evtx.py) — regenerates all four samples. Self-contained (doesn't import `pulse`), deterministic time math so reruns produce byte-identical output.

### Pulse-synthetic .evtx format

To ship sample files without requiring a Windows host + admin + `wevtutil` (real `.evtx` is a binary Microsoft format and `python-evtx` is read-only), [`pulse/core/parser.py`](pulse/core/parser.py) gains a synth-file path:

- The standard 8-byte `ElfFile\x00` magic header (so the upload validator's magic-byte check still accepts the file) followed by a `PULSE-SYNTH-v1\n` sentinel followed by a UTF-8 JSON event list.
- The parser detects the sentinel before falling through to wevtutil / python-evtx and routes to `_parse_pulse_synth()`. Real binary `.evtx` files are unaffected — they never contain the sentinel after the magic.
- Security guarantee held: the upload validator's first-8-bytes-must-be-`ElfFile\x00` check remains intact, so renamed-junk uploads are still rejected. The new code path is *additive*, not a relaxation.
- 12 new tests in [`tests/test_parser_synth.py`](tests/test_parser_synth.py) covering happy path (round-trip, multiple events, `since` filter, defaults for missing fields) and negative cases (missing marker falls through to binary parser, bad JSON returns `[]`, non-list payload returns `[]`, non-dict entries skipped) + parametrized end-to-end tests that load each shipped sample and assert its canonical rule fires.

### README rewrite

- [`README.md`](README.md) restructured for GitHub browse: shield badges (Python, license, test count, release tag, stars) → one-line "What Pulse does" → 4-line Quick Start with sample-data references → Quick Start with Docker → features as a compact two-column table → all 25 detection rules in a sorted-by-severity table with event IDs + MITRE technique → architecture summary → screenshots placeholder → docs links → production-deploys note → contributing + license.

### CONTRIBUTING.md

- New [`CONTRIBUTING.md`](CONTRIBUTING.md) — full dev environment setup, running tests (incl. `-m "not network"` offline mode), step-by-step tutorial for adding a detection rule (function → `RULE_META` entry → NIST CSF + ISO 27001 mapping → tests → run suite), adding a dashboard page (4 touch points), code style (Python + JS + HTML escaping + parameterized SQL), PR process, and security-issue disclosure via GitHub's private vulnerability reporting.

### Docker distribution

- New [`Dockerfile`](Dockerfile) — `python:3.11-slim` base, non-root user, installs from `requirements-lock.txt` for reproducible builds, copies only the runtime surface (no tests / samples / dist).
- New [`docker-compose.yml`](docker-compose.yml) — two-service compose: Pulse + Postgres 16 alpine. Documented env vars for `PULSE_SECRET`, `DATABASE_URL`, `PULSE_ADMIN_EMAIL`/`PULSE_ADMIN_PASSWORD` (first-run seed), and optional alert channels.
- New [`docker/entrypoint.sh`](docker/entrypoint.sh) — POSIX sh that waits for Postgres readiness (60s timeout, 1s backoff via `psycopg.connect`) then seeds the first admin user from `PULSE_ADMIN_EMAIL`/`PULSE_ADMIN_PASSWORD` env vars (idempotent — skipped on re-runs when a user already exists).
- New [`.dockerignore`](.dockerignore) — keeps `.git`, `venv/`, `tests/`, `samples/`, `dist/`, `*.db`, `pulse.yaml`, `.env`, and OS junk out of the build context.

Tests: **700 passing** (+12 from the new synth parser test file).

## 2026-05-14 — Dependency pinning + automated CVE scan

Follow-up to today's security audit. Closes the "advisory — pin dependencies" gap by adding a lock file for production deploys and wiring `pip-audit` into the test suite so future CVEs surface on every test run instead of waiting for a manual check.

- **New [requirements-lock.txt](requirements-lock.txt)** — exact `==` pins for all 43 runtime + test + build dependencies. Production deploys (Render, customer self-host, CI) should use this instead of `requirements.txt` (`>=` ranges). [README.md](README.md) explains the workflow + refresh procedure (`pip install -r requirements.txt && pytest -q && pip-audit --strict && pip freeze > requirements-lock.txt`).
- **CVE fixes uncovered by the first audit run** — three packages had known vulnerabilities:
  - `pip` 25.3 → 26.1.1 (CVE-2026-1703, -3219, -6357)
  - `pytest` 9.0.2 → 9.0.3 (CVE-2025-71176)
  - `python-multipart` 0.0.26 → 0.0.28 (CVE-2026-42561 — runtime dep, affects all installs). `requirements.txt` floor bumped from `>=0.0.6` to `>=0.0.28`.
- **New [requirements-dev.txt](requirements-dev.txt)** — dev-only tooling kept out of the production install footprint. Currently `pytest>=8.0,<10.0` + `pip-audit>=2.7,<3.0`. Install via `pip install -r requirements.txt -r requirements-dev.txt`.
- **New test `test_no_known_cves_in_dependencies`** in [tests/test_security_hardening.py](tests/test_security_hardening.py) — spawns `python -m pip_audit --strict --progress-spinner off` and fails the suite if any installed package has a known CVE registered with osv.dev or the PyPI advisory feed. `--strict` upgrades warnings to errors so a skipped-package isn't a soft pass.
- **`network` pytest marker** registered in [tests/conftest.py](tests/conftest.py) via `pytest_configure` — the pip-audit test is decorated `@pytest.mark.network` so air-gapped environments can skip with `pytest -m "not network"`. Verified: full suite still passes with the test selected (online) and deselected (offline).

Tests: **689 passing** (+1 since the security audit ship).

## 2026-05-14 — Security audit + hardening pass

Full codebase security audit across SQL injection, input validation, path traversal, auth/authz, XSS, sensitive data exposure, rate limiting, CORS, dependency posture, error handling, and file-upload safety. Surfaced and fixed every issue found; the clean categories are documented below as evidence the audit ran.

### Fixed

- **H1 · Path traversal** in `GET /api/firewall/log?path=…` — admin-only endpoint allowed reading any host file (`/etc/passwd`, `SAM`, etc.). Hardened in [pulse/api.py](pulse/api.py): `..` sequences rejected, null bytes rejected, only `.log` extensions accepted; in production mode (`PULSE_ENV=production`) the `path` parameter is rejected entirely — only the upload endpoint is supported on hosted deploys.
- **H2 · XSS** in [pulse/static/js/upload.js](pulse/static/js/upload.js) lines 24/146 — file names and error messages were interpolated into `innerHTML` without escaping. Self-XSS only (attacker would need to pick a malicious file from their own filesystem), but fixed via the existing `escapeHtml` helper for hygiene.
- **M1 · Login lockout** in [pulse/api.py](pulse/api.py) `/api/auth/login` — added two-layer protection. Layer 1: per-IP burst cap of 50/5min via the existing rate-limit `hit()`. Layer 2: 10 *failed* logins per IP per 15 min returns **HTTP 423 Locked** with a clear `Retry-After`. Successful logins never consume failure budget. Added new `rate_limit.check()` (test without ticking) + `rate_limit.record()` (tick without checking) helpers in [pulse/rate_limit.py](pulse/rate_limit.py) to enable the failure-only-counts pattern.
- **M2 · Rate limit on `POST /api/scan`** — .evtx parsing is CPU-bound (multiprocessing, per-file timeout) and single-worker on Render free tier. Added 20-uploads/hour per IP cap.
- **M3 · Error-message leak** in [pulse/firewall/blocker.py](pulse/firewall/blocker.py) `stage_ip` + `unblock_ip` — `f"Database error: {e}"` returned the raw exception text to the API caller (e.g. `(sqlite3.OperationalError) no such table: ip_block_list`), leaking schema + driver details. Now logs full details server-side and returns a generic "check the server log" message.
- **M4 · Info leak** in `GET /api/health` — `is_admin` field was always returned, fingerprinting the server's privilege level on hosted deploys. Now redacted when `PULSE_ENV=production`; still exposed on the local single-user dashboard (which needs it for the "run as administrator" banner).
- **L1 · Silent audit-log swallow** at [pulse/api.py](pulse/api.py) `_audit_user_action` — security-relevant `blocker.log_audit()` failures were swallowed without trace. Now `print()`s to stderr so the journal / Render log picks them up; user-facing operation still succeeds because the audit row's failure shouldn't 500 the requester.
- **L2 · Rate limit on `GET /verify`** — added 60-attempts/15min per IP to bound DB-lookup cost on token-spray misuse. The 256-bit token space makes actual brute force infeasible; this is a cost-bound, not a security-bound.

### Verified clean (no fix needed)

- **SQL injection**: every f-string SQL interpolation in [pulse/database.py](pulse/database.py) and [pulse/api.py](pulse/api.py) uses trusted constants (`_USER_COLS`, `_AGENT_COLS`, computed `?,?,?` placeholder strings, two-element hardcoded scope-column whitelist). All user-supplied values use parameterized `?` placeholders. Zero `LIKE` patterns. Zero string concatenation with user input building SQL fragments.
- **Subprocess injection**: every `subprocess.run()` call uses list-form args (no `shell=True`). User-supplied values (IPs, file paths) are validated before reaching `netsh` / `icacls`.
- **CORS**: production requires explicit `PULSE_ALLOWED_ORIGIN`, no wildcard fallback, warns on missing. Dev limited to localhost / 127.0.0.1.
- **Cookie flags**: all three issuances (`signup`, `login`, `verify`) set `HttpOnly`, `SameSite=Lax`, `Secure` in production. `Strict` rejected because it would break the verification-email click-through.
- **File uploads**: avatar (MIME whitelist + magic bytes + 2MB + DB blob), `.evtx` scan (streaming + 500MB cap + magic + `tempfile`), firewall log upload (streaming + 50MB cap + `tempfile`).
- **Auth/authz**: every `/api/*` route has the correct dependency (`require_login` / `require_admin`); admin-only routes (`/api/users`, `/api/audit/export.*`, `/api/alerts/test`, `/api/webhook/test`, `/api/intel/test`, `/api/config/*`, `/api/scheduler/config`, `/api/rules/*/enabled`, `/api/monitor/sessions` DELETE-all) are gated. Multi-tenant org-scoping via `_read_scope_kwargs` wired through every read/write helper. Agent-transport routes have separate auth via `Authorization: Bearer pa_…`.
- **Sensitive data**: passwords never logged or returned; `_public_user()` strips `password_hash`; API tokens and agent tokens stored sha256-at-rest with `last4` for UI identification only.
- **Bare `except:`**: zero in the codebase. All `except Exception:` handlers either fail-closed (auth path) or are documented "best-effort, never break the request" patterns; the audit-relevant silent swallow at `_audit_user_action` is the only one that got a `print()` added.
- **XSS in dashboard**: 15 of 20 JS modules import `escapeHtml` and use it consistently. The 5 that don't either have their own `_escape` helper (`drawer.js`, `command-palette.js`), only render hardcoded URLs (`user-menu.js`), or only render static strings (`system-scan.js`). Findings, notes, audit, notifications, whitelist, settings all properly escape user-supplied content.

### Advisory (not fixed in this pass)

- **Dependency pins**: `requirements.txt` uses `>=` (lower-bound) for every package, so a fresh install months from now could pick up an unexpected major version. Recommend `pip freeze > requirements.txt` (after verifying current versions in CI are good) or running `pip-audit` as a periodic check. Not changed here to avoid breaking the build by pinning to whatever's locally installed.

### Tests

12 new tests in [tests/test_security_hardening.py](tests/test_security_hardening.py):

- `test_firewall_log_rejects_non_log_extension`
- `test_firewall_log_rejects_parent_traversal`
- `test_firewall_log_rejects_null_byte`
- `test_firewall_log_blocks_custom_path_in_production`
- `test_firewall_log_default_path_still_works`
- `test_login_lockout_after_ten_failures`
- `test_login_success_does_not_consume_failure_budget`
- `test_scan_endpoint_rate_limited`
- `test_blocker_db_error_does_not_leak_schema`
- `test_health_redacts_is_admin_in_production`
- `test_health_exposes_is_admin_in_dev`
- `test_verify_endpoint_rate_limited`

Plus one existing test updated for the new `.log` extension constraint.

Tests at this commit: **688 passing** (+12).

## 2026-05-13 — Sprint 7 — Agent tamper-resistance

The agent's `agent.yaml` file holds a long-lived `pa_…` bearer in plain text — treat it like an SSH key. This ship makes the agent self-audit its own ACL on startup and surfaces a `pulse-agent harden` subcommand that locks the file down to SYSTEM + Administrators only. Small, focused, doesn't break anything that worked yesterday.

- New [pulse/agent/permissions.py](pulse/agent/permissions.py): `audit_token_file_permissions(path)` runs `icacls` and returns a `PermissionsVerdict` (`ok` / `loose` / `not_found` / `not_windows` / `error`). Detects `Everyone`, `BUILTIN\Users`, `NT AUTHORITY\Authenticated Users` (and their SID forms `S-1-1-0`, `S-1-5-32-545`, `S-1-5-11` for localized Windows installs).
- `harden_token_file(path)` strips ACL inheritance and grants `SYSTEM:(R,W)` + `Administrators:(F)` only. Inheritance-strip comes before the grants so the parent dir's ACEs can't re-clobber them.
- `AgentRuntime.run_forever()` now invokes `_audit_token_permissions()` once at startup (after the update check). Loose ACL → WARNING in the journal with the exact `pulse-agent harden` command to run. Non-Windows hosts skip silently.
- `AgentRuntime` constructor accepts a new `config_path=` kwarg so the audit checks the file we actually loaded from when `--config <path>` was used, not the platform default. `__main__.cmd_run` plumbs it through.
- New `pulse-agent harden` subcommand ([pulse/agent/__main__.py](pulse/agent/__main__.py)): calls `harden_token_file` against `--config` (or the default path) and prints the verdict. Exits 1 when the file is missing or icacls failed, 0 on success.
- 14 new tests in [tests/test_agent_permissions.py](tests/test_agent_permissions.py): non-Windows no-op, missing-file branch, detects Everyone / BUILTIN\Users / Authenticated Users, accepts locked-down ACL, handles icacls binary missing, harden invokes icacls with correct flag ordering, harden surfaces rc != 0, log level routing (loose → WARNING, ok → INFO), runtime startup fires the audit once.

Plus a ROADMAP cleanup: `[x] Packaged pulse-agent.exe via PyInstaller` (shipped with v1.7.0) and `[x] Local-scan → HTTPS upload pipeline` (shipped as `AgentRuntime` heartbeat + scan loop) — both were technically done but still showing as `[ ]` because nobody updated the ROADMAP when they landed.

Tests: **676 passing** (+14 since the email verification ship).

## 2026-05-13 — Sprint 8 prep — Email verification on signup

Unblocks turning on `PULSE_HOSTED_SIGNUP=1` for real customers: every new tenant now gets a verification email with a one-time `pv_…` token, and the user lands unverified until they click the link. Single-user installs without SMTP auto-verify on signup so the existing CLI / localhost flow keeps working unchanged.

- New `users` columns: `email_verification_token_sha256` (NULL once consumed), `email_verification_expires_at` (24h TTL), `email_verified_at` (NULL while pending, timestamp once verified). Idempotent backfill stamps `email_verified_at = created_at` on every pre-Sprint-8 row so legacy accounts don't suddenly start failing the verified check.
- New DB helpers in [pulse/database.py](pulse/database.py): `mint_email_verification_token(user_id, ttl_hours=24)` returns the raw `pv_…` token (sha256-at-rest); `consume_email_verification_token(raw)` validates expiry + clears columns + stamps verified; `is_email_verified(user_id)` for callers; `mark_user_email_verified(user_id)` for the auto-verify branch.
- New generic `send_transactional_email(email_config, recipient, subject, html_body, text_body)` in [pulse/alerts/emailer.py](pulse/alerts/emailer.py) — same SMTP boilerplate as `send_alert` but decoupled from the alerts pipeline so verification mail goes out even when alerts are off.
- `/api/auth/signup` ([pulse/api.py](pulse/api.py)) — two branches: SMTP configured → mint token + mail link + leave user unverified, returns `{verification_sent: true}`; SMTP not configured → auto-verify immediately, returns `{verification_sent: false}`. Failure in the mail layer falls back to auto-verify so signup never 500s on a misconfigured SMTP.
- New `GET /verify?token=…` route — consumes the token, redirects to `/?verified=1` on success or `/login?verified=0` on invalid/expired/replayed, issues a fresh session cookie so the user lands logged in on the dashboard immediately. No session required to hit `/verify` (the token IS the credential).
- New `POST /api/auth/resend-verification` — logged-in unverified users can request a fresh link. Rate-limited (3/15min per IP). Returns `{sent, smtp_configured, already_verified}` so the UI can pick the right "check your inbox" vs "your email is already verified" vs "SMTP isn't configured" message.
- `/api/me` and `/api/auth/status` now surface `email_verified: bool` so the dashboard can render a "verify your email" banner without an extra round-trip.
- 11 new tests in [tests/test_auth.py](tests/test_auth.py): auto-verify when SMTP off, mint+send+receive when SMTP on, /verify success + redirect, /verify rejects bad token, /verify rejects replay, resend when SMTP configured, resend reports smtp_off, resend short-circuits when already verified, DB-level mint/consume round-trip, DB-level expiry.

Tests at this commit: **662 passing** (+10).

## 2026-05-12 — Release v1.7.0 (Sprint 7 close)

Sprint 7 — *Agent / server split, multi-tenant, marketing site* — ships. The headline since v1.6.0:

- **Pulse Agent** is a real thing: `pulse/agent/` package (config, transport, scanner, runtime, CLI), 6.5 MB packaged `pulse-agent.exe` via PyInstaller, two-token enrollment, 60s heartbeat, auto-update probe on startup
- **Multi-tenant data model**: every owned row carries `organization_id`. Two customers on the same instance never see each other's data, but org-mates share scan / agent / finding visibility. Idempotent backfill heals legacy single-user installs in place
- **Public multi-tenant signup**: `PULSE_HOSTED_SIGNUP=1` opens `/api/auth/signup` past the first user; each signup mints a fresh org
- **Marketing landing page at `/`**: ~1100-line CrowdStrike-style site with hero + stats band + three use-case sections + 12-feature grid + three-step install + three-tier pricing + FAQ + multi-column footer
- **Windows download wire**: `GET /api/agent/download` streams the locally-built bundle as a zip; `GET /api/agent/download/check` lets the landing page soft-disable the CTA when the server has no bundle on disk (falls back to a GitHub link)
- **Auto-update channel**: `GET /api/agent/latest` returns `{version, download_url, release_notes_url}`; bearer-auth branch adds `outdated` / `current` so the agent doesn't have to compute its own semver
- **Hosted-mode topbar swap**: "Scan My System" → "Download Agent" on non-Windows hosts; command palette filters `act.system_scan` away accordingly
- **README** rewritten: 462 → 162 lines, stale counts refreshed (25 rules, 652 tests)

Tests at release: **652 passing** (+153 since v1.6.0).

Deferred to Sprint 8: bundled Windows Service installer, local dashboard mode toggle, signed auto-download. Email verification + password reset + onboarding wizard are the immediate next-up before flipping `PULSE_HOSTED_SIGNUP=1` for real users.

## 2026-05-07 — Sprint 7 — Marketing landing page + Windows download

`/` is now a proper product site instead of a redirect to the login form. Unauthenticated visitors get a CrowdStrike / UpGuard-style marketing page with a hero, stats band, three use-case sections (SOC, IT, security researcher), 12-card feature grid, three-step "how it works", three-tier pricing teaser, FAQ, and a multi-column footer. Logged-in users still get the dashboard at the same path; the old `/welcome` mount stays for back-compat.

The "Download for Windows" CTA streams the locally-built `dist/pulse-agent/` as a zip via a new `/api/agent/download` endpoint — no GitHub Releases dance required to ship the binary today. PyInstaller produces a 6.5 MB launcher exe + 37 MB one-folder bundle on Windows; the endpoint zips the bundle on demand and serves it as `pulse-agent-{version}-windows-x64.zip`.

- New `/api/agent/download` endpoint ([pulse/api.py](pulse/api.py)) — public (under the auth-exempt `/api/agent/` prefix). 503 with build instructions when `dist/pulse-agent/` doesn't exist; otherwise zips the bundle in-memory (~20 MB compressed) and streams it with `Content-Disposition: attachment` headers
- `/` route in [pulse/api.py](pulse/api.py) rewritten — serves `landing.html` for unauthenticated visitors, dashboard for logged-in users, and dashboard unconditionally when auth is disabled (single-user CLI mode)
- [pulse/web/landing.html](pulse/web/landing.html) rewritten end-to-end (~1100 lines, was ~350): sticky nav with backdrop-blur, hero with mock dashboard frame and gradient headline, "Built on" trust strip (MITRE / NIST CSF / ISO 27001 / AbuseIPDB / SIGMA), stats band (100+ techniques / 60s heartbeat / <30s alert / $0 ingest), three alternating use-case sections each with a custom mockup (SOC card list, fleet host grid, monitor stream), 12-card feature grid with inline SVG icons, three-step download flow with copy-paste commands, three-tier pricing (Self-host free / Hosted coming soon / Enterprise), 7-question FAQ with `<details>` disclosure, big closing CTA + waitlist, multi-column footer
- 4 new tests ([tests/test_agents.py](tests/test_agents.py), [tests/test_auth.py](tests/test_auth.py)): 503 when bundle missing, 200 + ZIP magic + correct archive structure when present, public-no-auth access, `/` routing for both unauthenticated (landing) and authenticated (dashboard) visitors

## 2026-05-02 — Sprint 7 — Auto-update channel for Pulse Agent

The agent now phones home for version drift detection. On startup it calls `GET /api/agent/latest` and surfaces an "update available" warning in its journal when the server reports a newer build, with the GitHub Releases URL one keystroke away. Best-effort: a failing update check never blocks the heartbeat / scan loop.

- New endpoint `GET /api/agent/latest` (in [pulse/api.py](pulse/api.py)) returns `{version, download_url, release_notes_url}`. Public (lives under the `/api/agent/` prefix that's already auth-exempt). Optional bearer auth: when supplied, the server resolves the calling agent, computes `outdated`/`current` from the version the agent reported on enrollment, and stamps `last_status='checked-update'` so the Agents tab can show "last checked update" telemetry before the next heartbeat fires
- `PULSE_AGENT_DOWNLOAD_URL` + `PULSE_AGENT_NOTES_URL` env vars override the default GitHub Releases / CHANGELOG URLs — useful for staging deploys that want a private build channel
- New `AgentTransport.get_latest_version()` ([pulse/agent/transport.py](pulse/agent/transport.py)) and a small `_get` / `_handle_response` refactor so GET and POST share the same error-mapping path
- New `AgentRuntime._check_for_updates()` ([pulse/agent/runtime.py](pulse/agent/runtime.py)) called once at the top of `run_forever()`. Trusts the server's `outdated` flag when present (compares against the agent's *reported* version, not the local module string — they're the same value when the agent imports `pulse.__version__`)
- 4 new tests in [tests/test_agent_runtime.py](tests/test_agent_runtime.py) cover unauth public probe, bearer-auth `outdated` comparison, `last_status` telemetry stamp, and the warning-log path when the runtime detects drift

## 2026-05-02 — Sprint 7 — Public multi-tenant signup

`PULSE_HOSTED_SIGNUP=1` opens `POST /api/auth/signup` past the first user — every new email mints a brand-new organization, so customers sharing a hosted Pulse instance each land in their own isolated tenant. Default off, so a self-hosted install keeps the safe single-tenant behavior (no rando off the internet can sign up on your local Pulse). This unblocks the multi-tenant data model from 2026-05-02 — without it the org-isolation tests couldn't be exercised by real customers.

- `app.state.hosted_signup` flag fed from the `PULSE_HOSTED_SIGNUP` env var ([pulse/api.py](pulse/api.py))
- `auth_signup` rewritten: 409 only when the install is single-tenant *and* a user already exists. Hosted-mode signups always succeed for fresh emails. First signup (single-tenant or hosted) still gets admin via the existing `create_user` first-row promotion. Pre-checks `get_user_by_email` to return a clean 409 instead of bubbling the UNIQUE-constraint exception
- `auth_status` response gains `hosted_signup` + `signup_open` so the login page can decide whether to render the "Create account" link
- [pulse/web/login.html](pulse/web/login.html) extended with a mode-switch link (login ↔ signup) that only renders in hosted-mode-with-existing-users (bootstrap signup hides it because there's nothing to log into yet). Signup copy reads "Create a Pulse workspace" in hosted mode vs. "Create your account" on bootstrap
- 5 new tests in [tests/test_auth.py](tests/test_auth.py): hosted-signup status flags, multiple signups allowed, each user lands in a fresh org, first user still admin, duplicate email returns 409

## 2026-05-02 — Sprint 7 — Hosted-mode topbar swap

The topbar's "Scan My System" button is the wrong CTA on a Linux server that can't read a Windows host's event log. On non-Windows hosts the button now becomes **Download Agent** with a `download` icon, pointing the user at Settings → Agents — the supported way to monitor Windows fleets from a hosted dashboard. The .evtx CLI fallback stays available on the History page for analysts who want one-off triage.

- `_applyHostPlatformGating` (boot-time `/api/health` probe) now rewrites the topbar action to `goToAgentEnroll`, label to "Download Agent", icon to `download`. Lucide is re-rendered after the swap so the new icon paints
- New action `goToAgentEnroll` (in [pulse/static/js/app.js](pulse/static/js/app.js)) calls `setActiveSettingsTab('agents')` then `navigate('settings')` so the user lands directly on the Agents tab
- `_renderAgentsPanel` ([pulse/static/js/settings.js](pulse/static/js/settings.js)) gains an "Install Pulse Agent on a Windows host" install-instructions card above the enrollment form: pip install + `python -m pulse.agent enroll` + `run` snippet, with a note that the packaged `pulse-agent.exe` ships later this sprint
- Command palette (Ctrl/Cmd-K) gates `act.system_scan` behind a host-platform `condition()` check — hidden on non-Windows. New `act.download_agent` entry takes its place on hosted hosts ("Install Pulse Agent" → Settings → Agents)
- `_COMMANDS` rendering switches to `_availableCommands()` so per-entry `condition` filters apply to both no-query (recents+default) and query-ranked code paths

## 2026-05-02 — Sprint 7 — Multi-tenant data model

Hosted Pulse becomes safe to share across customers. Every owned row (scans, agents, notifications) carries an `organization_id`, and the API filters reads / writes by that column instead of by `user_id`, so two customers running on the same instance never see each other's data — but every member of the same org *does* share scan/agent/finding visibility (the right collaboration boundary for a SOC team).

- New `organizations` table (id, name, slug, created_at) with unique slugs minted from name or email local-part on collision
- `users.organization_id`, `scans.organization_id`, `agents.organization_id`, `notifications.organization_id` ALTERed in via idempotent `init_db` migration
- `_backfill_organizations` runs every startup: any row with NULL `organization_id` gets a fresh per-user org so legacy single-user installs upgrade in place without manual SQL
- Self-signup (POST `/api/auth/signup`) auto-creates a new org for the new tenant; admin-side user creation (POST `/api/users`) joins the new user to the admin's existing org
- `_read_scope_kwargs(app, user_id)` helper resolves to `{}` for admin / no-auth, `{"organization_id": N}` for org members, `{"user_id": N}` for legacy untenanted users — splat into every read/write helper
- `get_history`, `get_scan_findings`, `get_scan_number`, `get_fleet_summary`, `get_rule_stats`, `get_trend_analytics`, `delete_scans`, `list_agents`, `set_agent_paused`, `delete_agent`, `_scope_filter_finding_ids`, `batch_set_finding_*` all gained an `organization_id` parameter that supersedes `user_id`
- `_agent_owner_or_admin` (`PUT|DELETE /api/agents/{id}`) treats org membership as authorization so any teammate can pause/delete shared agents
- 9 new tests in `tests/test_data_isolation.py` cover create-org, slug uniqueness, auto-org on signup, explicit-org join, scan stamping, history org-scope, the legacy-row backfill, and three end-to-end cross-tenant assertions (history invisible, report 404, delete no-op)
- Existing per-user isolation tests rewritten to assert the new org-shared semantics (admin + viewer in the same org now see each other's scans, agents, and reports — that was always the multi-tenant intent)

## 2026-04-30 — Release v1.6.0 (Sprint 6 close)

Sprint 6 — *Workflows, branding, threat intel* — locks in. v1.5.0 already shipped Sprint 5 (auth / compliance / analytics); this ship picks up the cursor at 1.6.0 to match the sprint number.

### Sprint 6 acceptance criteria — shipped

- **Incident workflow states** — finding-level `new / acknowledged / investigating / resolved` axis with drawer pill picker
- **Analyst notes** — append-only thread per finding, drawer composer, admin cross-finding feed in Settings → Notes
- **Assignment** — assign findings to active users, "Assigned to me" filter, sidebar quick-assign tray
- **Configurable severity colours** — per-browser palette overrides
- **In-app feedback** — floating FAB + admin Settings → Feedback review tab

### Sprint 6 acceptance criteria — deferred / moved

- ~~**Custom branding**~~ — first pass shipped 2026-04-23 then reverted 2026-04-24 because replacing the Pulse lockup hurt brand recognition. Tracked in `BACKLOG.md` as "Custom branding (v2)" — same `branding` table reused, org name renders as a *subtitle* under the Pulse mark next time
- ~~**Dashboard widgets**~~ — drag-and-drop reorder + hide/restore shipped 2026-04-28, reverted 2026-04-29 because the "Customize layout" button surfaced before the use case was clear. Tracked in `BACKLOG.md` under "Polish & UX"
- ~~**Windows Service installer**~~ — moved to Sprint 7's downloadable-agent block so the SYSTEM-elevation work happens once for both `pulse-agent.exe` and the local install paths

### Bonus work bundled into v1.6.0

A polish pass + Sprint-7 transport-layer prep landed across the same window. Highlights:

- **Relative timestamps everywhere** — `formatRelativeTime` / `relTimeHtml` helper with Apr-21 cutover past 7 days, hover tooltip with the absolute datetime. Rolled out to Findings, Scans/History, Audit Log, Fleet, Firewall, Reports, Threat Intel, Settings (Users / Tokens / Agents / Notes / Feedback / Waitlist), Monitor (live feed + sessions), and the Dashboard's Last-Scan / Repeat-Offenders / Needs-Attention surfaces. Two duplicate ad-hoc relative-time formatters in `findings.js` and `settings.js` were deleted
- **Scans → History merge** — standalone Scans list page deleted (~595 lines of dead code removed from `findings.js`, ~200 lines of CSS). `/findings` is the All-Findings page, `/history` owns the scan list with the new Upload `.evtx` button + per-row hover-only Quick PDF action. `/scans/{id}` deep-link target survives for History → scan-detail navigation
- **Reports page rewrite** — page header with primary "Generate Report" button, real onboarding empty state (icon + title + subtitle + CTA), modal with scan dropdown + 4-format radio tiles. After upload completes, navigate to `/history` instead of the deleted Scans list
- **Whitelist empty-state onboarding** — replaced one-line "No whitelist entries yet" with a proper panel: title + subtitle with `SYSTEM` / backup-agent example + "Add your first entry" (focuses the Add input) + "Learn more" toggle revealing inline Account / Service / IP / Rule reference. Dynamic built-ins count surfaces below
- **Compliance Coverage Gaps** — new amber/orange KPI tile up top + Coverage Gaps card after the framework grids: uncovered MITRE techniques, silent rules (enabled + zero hits), noisy rules (≥20 hits + ≥40% FP rate)
- **Getting Started checklist** — 5-step Dashboard onboarding card (Upload `.evtx` / Review a finding / Email alerts / Invite team / Whitelist entry). Progress bar, dismiss link persists in `users.onboarding_dismissed_at`. Drawer-open auto-marks step 2; `/me/onboarding` endpoint computes all 5 flags server-side
- **Notification bell** — topbar bell with unread badge + 320×480 dropdown panel. Backend `notifications` table (capped 100 per user) with triggers on scan complete (manual + agent), finding assigned, live-monitor alert (admins fan-out), scheduled scan finished, IP block pushed
- **Role visibility** — avatar-dropdown shows role under name; Settings → Profile has read-only Role row with role-specific explanation; Settings → Users gains Last-active column backed by `users.last_active_at` (touched in auth middleware); A/V role badges render next to user names in audit log, assignment picker, notes thread
- **Threat Intel inside the drawer** — the existing AbuseIPDB section in the finding drawer was repositioned to sit between Event Details and Remediation (the natural triage path); standalone Threat Intel page kept with a discoverability callout
- **Pulse Agents — server-side transport layer** — new `agents` table with two-phase token columns (`pe_…` enrollment / `pa_…` bearer, both sha256-at-rest). `POST /api/agent/exchange | heartbeat | findings`. Settings → Agents tab with status pill (online / stale / offline / paused / pending), Pause + Delete actions. Wire is live for the Sprint 7 `pulse-agent.exe` to plug into
- **Topbar "Scan My System" hosted-mode swap** — `/api/health` already exposed `platform_windows`; the dashboard now reads it at boot and rewrites the topbar button to "Upload `.evtx`" → navigate to History → open upload modal, on non-Windows hosts. Pairs with the Render deployment
- **Firewall Rules tab live** — placeholder removed; the existing `pulse/firewall/firewall_parser.py` is now wired into the page. Path-based `GET /api/firewall/log` for Windows hosts + multipart `POST /api/firewall/log` for Linux hosts (50MB cap, in-memory parse, temp file deleted). KPI tiles (Total / Allowed / Dropped / Unique sources), Suspicious activity card (port scans, repeated drops, sensitive-port probes — new `detect_repeated_drops` rule added), Action / Protocol / Direction filter chips + IP search, hover-only Block + Lookup actions on DROP rows with public source IPs. `tests/sample-pfirewall.log` ships as a fixture so the parser regressions surface immediately
- **Customizable dashboard widgets**, the orphan-monitor-session cleanup, removal of `autoResume`, the Monitor "Live pill on, page IDLE" first-start race fix (`_refreshStatus()` on every page mount + `_forceMonitorPageRender()` after Start), and the BACKLOG.md / ROADMAP.md split all also landed in this window
- **Dashboard simplification** — removed the Severity Breakdown donut and MITRE Categories card from the Dashboard (Trends owns severity now, Rules page owns MITRE coverage). Top Triggered Rules survives as a full-width card. Net ~250 lines lighter
- **Fleet KPI tiles** — replaced agent-presence tiles (Online / Offline / Newly Enrolled) with score-grounded ones (Total Hosts / Critical Risk / High Risk / Secure) since hosts are scanned hostnames not heartbeating agents yet

### Tests

618 tests passing, up from 477 at the start of Sprint 6. New suites: `test_agents.py` (12), `test_notifications.py` (8), `test_onboarding.py` (8), `test_firewall_log_api.py` (7 — including the `sample-pfirewall.log` end-to-end). Three new parser tests in `test_firewall_parser.py` and a fixture-backed end-to-end suite that proves all three firewall detection rules co-fire on real-shaped data.

### Version

`pulse/__init__.py` bumped to `1.6.0`. v1.5.0 was Sprint 5 (already on GitHub).

---

## 2026-04-30 — Firewall Rules tab live + sample fixture

### Added
- **Firewall Rules tab — pfirewall.log parsing surface.** Replaces the "coming in Sprint 4" placeholder. Path-based + upload-based parsing routes through `GET / POST /api/firewall/log` (admin-only, 50MB upload cap, temp-file deleted post-parse). Frontend renders KPI tiles (Total / Allowed / Dropped / Unique source IPs), a Suspicious activity card listing port scans + repeated drops + sensitive-port probes, filter chips for Action / Protocol / Direction + IP search, and an entries table with timestamp + colored ALLOW/DROP chip + protocol + src/dst IP+port + inferred direction + size. DROP rows with a public source IP get hover-only Block (stages to the existing Block List flow) and Lookup (calls the existing `apiFetchIntel`) buttons. `detect_repeated_drops` is a new third firewall-detection rule that fires when a public source racks up >10 DROPs across the parsed window. `tests/sample-pfirewall.log` is a real-shaped fixture (97 rows, hits all three detection rules) and seeds 5 new tests across the parser + API levels

---

## 2026-04-28 — Pulse Agents (Sprint 7 transport layer)

### Added
- **`agents` table + `scans.agent_id`** (`pulse/database.py`) — one row per registered host with two-phase token columns: `enrollment_token_sha256` (single-use, 1h TTL) is filled by the dashboard at mint and cleared on exchange; `agent_token_sha256` + `agent_token_last4` are filled at exchange and stay until the operator deletes the agent. Heartbeat metadata (`last_heartbeat_at`, `last_status`, `version`, `paused`) is updated by every check-in. Scans uploaded by an agent carry the new `scans.agent_id` column for provenance
- **`pulse/agents.py`** — server-side enrollment + heartbeat orchestration. Token generation uses `secrets.token_urlsafe` with `pe_` / `pa_` prefixes (so logs read at a glance), sha256 hashing pattern matches `api_tokens`, single-use enrollment guarded by hash-clear-on-exchange, and `compute_status()` maps a row → status pill (`online` / `stale` / `offline` / `paused` / `pending`) using 3-min and 1-hour heartbeat windows
- **API endpoints** (`pulse/api.py`):
  - `POST /api/agents` (admin-authed) — mint enrollment token, returns the raw value exactly once
  - `GET  /api/agents` — list with status (viewers see their own agents; admins see all)
  - `PUT  /api/agents/{id}` — toggle the paused flag (owner or admin)
  - `DELETE /api/agents/{id}` — hard delete; bearer token stops working immediately
  - `POST /api/agent/exchange` — *no auth*. Trades a still-pending enrollment token for a long-lived agent token; rate-limited to 30 attempts / 5 min / IP. Single use: a successful call clears the enrollment hash so a replay returns 401
  - `POST /api/agent/heartbeat` — Bearer-authed by `agent_token`. Bumps `last_heartbeat_at`, returns `{paused}` so the agent can self-throttle
  - `POST /api/agent/findings` — Bearer-authed; persists a scan + findings attributed to the enrolling user with `scans.agent_id` stamped. Hostname/scope/duration come from the request body, defaulting to the agent's registered hostname. Paused agents still ack the heartbeat side-channel but their findings are dropped server-side. 25k-finding cap matches the upload-side ceiling
- **Auth middleware exception** for `/api/agent/` (singular) — those routes authenticate themselves against the `agents` table; the user-session middleware was returning 401 before we ever reached the handler. The plural `/api/agents/` management routes stay behind the normal user-session check
- **Settings → Agents tab** (`pulse/static/js/settings.js`) — third-from-top tab in the Settings nav. Top card: enroll a new agent by name, surfaces the raw enrollment token in a tinted "copy this now" banner with a Copy button (clipboard API + `window.prompt` fallback). Bottom card: registered-agents table with name, status pill, hostname/platform, version, last-seen relative time, and per-row Pause/Resume + Delete buttons
- **`tests/test_agents.py`** — 12 new tests cover the full server-side flow: enrollment + exchange round-trip, replay rejection, expired-token rejection, heartbeat updates, status computation across all five states, end-to-end POST chain over `TestClient`, paused-agent drop semantics, agent listing without secrets, delete-revokes-token, and viewer-cannot-manage-admin-agent ownership guard

### Why this lands first
The roadmap's Sprint 7 is "agent / server split — the Splunk distribution model". This change ships the wire layer the future Pulse Agent will speak: enrollment, heartbeat, and findings ingest. With this in place, the next ship (`pulse-agent.exe` via PyInstaller) has a real server to talk to from minute one. Multi-tenant data isolation is still pending — agents currently attach to the enrolling user, which is correct for single-org installs but will need an `organization_id` column before this can serve more than one customer

---

## 2026-04-29 — Polish pass

### Removed
- ~~**Customizable dashboard widgets**~~ — *reverted from the 2026-04-28 ship.* The drag-and-drop reorder, hide/restore, and `localStorage`-backed layout persistence all worked, but the "Customize layout" button on the Dashboard read as a placeholder during the cleanup pass — a feature surfaced before its use case was clear. Removed entirely: `dashboard-layout.js` deleted, the widget shells / customize bar / hidden-panel tray markup inlined back to direct concatenation in `renderDashboardPage()`, the `enterDashEditMode` / `exitDashEditMode` / `hideDashWidget` / `showDashWidget` / `resetDashLayout` actions deleted from the registry, and the `~200 lines of `.dash-widget*` / `.dash-customize*` / `.dash-hidden-*` CSS removed. Roadmap entry for this Sprint 6 item flipped back to deferred. The default panel order (KPI strip → standup → charts → MITRE → last-scan findings) is what every user sees again. Stale `localStorage.pulseDashWidgets` entries from the previous build are harmless — the loader is gone, so they're never read

### Fixed
- **Monitor "Live pill on, page IDLE" race** (`pulse/static/js/monitor.js`) — clicking Start Monitoring now triggers a synchronous `_forceMonitorPageRender()` after the API call resolves, instead of relying solely on the `requestAnimationFrame`-based scheduler. The rAF path was occasionally dropping the very first frame after a fresh `--api` boot, leaving the page stuck on IDLE while the topbar Live indicator flipped on. Both paths now fire on the same tick
- **Orphaned monitor sessions on server restart** (`pulse/database.py::close_orphaned_monitor_sessions`) — `init_db()` now stamps `ended_at = started_at` on every `monitor_sessions` row that lacks an end timestamp. The in-memory `MonitorManager` lives only inside the Pulse process; a Ctrl+C / crash / deploy-restart that exited before `stop()` ran would otherwise leave rows that read as "ACTIVE" forever in the dashboard. The cleanup runs on every server boot and is idempotent
- **Auto-resume after server restart** (`pulse/static/js/monitor.js::monitorClient.init`) — removed the `localStorage.pulse.monitor.autoResume` flag check that caused the dashboard to silently relaunch the monitor on a fresh server boot. Closing the API and starting it again should mean monitoring is off until the user explicitly clicks Start. The flag is no longer written by `start()`/`stop()` either; init removes any stale value left over from previous installs

### Changed
- **Relative timestamps everywhere** — `formatRelativeTime(iso)` now switches to a "Apr 21" (or "Apr 21, 2024" if cross-year) absolute-month-day format past the 7-day mark, instead of the unbounded "Xd ago" it used before. New companion `relTimeHtml(iso, extraClass?)` returns a `<span class="rel-time" title="<full-datetime>">…</span>` so every timestamp gets the absolute value as a hover tooltip without callers escaping it themselves. Rolled out to: Findings table (Time column), Scans table (Date/Time + Last scan KPI), History table (Date column + comparison labels + dropdown options), Audit Log table (relative branch routes through the shared helper, absolute toggle preserved), Fleet table (Last Scan column + host detail drawer), Firewall table (Added / Pushed columns), Monitor live event feed + idle-panel session list + sessions rail, Reports table, Threat Intel result card + recent-lookups list, Settings → Users / API Tokens / Agents / Feedback / Waitlist / Notes admin tables, Dashboard "Repeat offenders" + "Last Scan Findings" + "Needs Attention" rows, finding drawer (assigned / reviewed / workflow updated / notes thread). Two duplicate ad-hoc relative-time formatters in `findings.js` and `settings.js` were deleted so there's exactly one source of truth

---

## 2026-04-28 — Customizable dashboard widgets *(reverted 2026-04-29)*

---

## 2026-04-24 — Contextual sidebar filter panel (first pass)

### Added
- **Sidebar filter framework** (`pulse/static/js/sidebar-filters.js`) — pluggable per-page registry. A page calls `registerSidebarFilterConfig(pageId, builder)` with a builder that returns `{ clearActive, onClear, groups: [{ id, label, items, onToggle }] }`, and `navigate()` calls `updateSidebarFilters()` on every page change to re-render the panel. Each group is collapsible; collapse state persists per-(page, group) in `localStorage.pulseSidebarFilterCollapsed`. Checkbox toggles fire real-time (no Apply button); the "Clear filters" link at the top only surfaces when at least one filter is active. Panel hides entirely when the sidebar is collapsed to 48 px.
- **Findings page sidebar filters** — four multi-select groups wired: Severity (with colored dots), Status (workflow state: new / acknowledged / investigating / resolved), Assigned to (live-computed from every user that currently owns a finding + an "Unassigned" bucket), Host (one entry per unique scanned hostname). Filters compose as UNION-within-group, INTERSECTION-across-groups on top of the existing toolbar filters. New sidebar state on `findingsState`: `sidebarSev`, `sidebarStatus`, `sidebarAssignee`, `sidebarHost` (all `Set` instances, reset on every `renderFindingsPage()`).

### Deferred to follow-up
- Rule filter on Findings (rule list can get long — needs a dedicated top-N + "Show all" UI)
- Dashboard, Monitor, Fleet, Audit Log, Firewall sidebar filter configs — the framework is in place; each page can register its own builder when it's next touched

---

## 2026-04-24 — Density pass (Sprint 6 polish)

### Changed
- **Sidebar** — 220→200px, `--bg-1` surface so it sits one elevation below `.content` (`--bg-0`). Nav split into three unlabelled groups (workflow / assets / config) separated by 12px gutters. Active row is a 3px green left-accent + subtle green-tinted background (no more filled highlight). Hover is `rgba(255,255,255,0.04)`. Brand block matches the topbar hairline exactly — both 56px, `box-sizing: border-box`, `1px solid rgba(255,255,255,0.06)` — so the bottom edge runs as one continuous line across the full app width.
- **Dashboard KPI row expanded to 6 cards** — added **MTTD** (mean time to detect, avg `scanned_at − event_timestamp` across the Needs-Attention window) and **Open Findings** (unreviewed crit/high, shares the same source as the Needs Attention panel). Cards tightened to 12×14 padding + 24px hero number so all six fit on one row at 1440+; wraps to 3×2 under 1280.
- **Dashboard three-column chart row** replaces the old side-by-side layout — new SVG severity donut (left), compact score ring (center), score history line chart (right), equal-height cards. MITRE bars + Top Triggered Rules move to a full-width 2fr/1fr row below the chart band so the bars get horizontal room.
- **Global standards** — `.card` now uses `--bg-2` surface with `1px solid rgba(255,255,255,0.06)` border and 16px padding. `.data-table` rows are 36px tall with 12px horizontal cell padding. Search inputs / filter pills are pinned to 36px height so every control on a filter bar aligns on one baseline. Page heads use `20px / 600` titles with a uniform 16px bottom margin. `.content` padding normalized to `24px 24px 48px` with a `.content > * + *` rule giving every stacked section a consistent 16px rhythm

---

## 2026-04-23 — Sprint 6 (in progress)

### Added
- **In-app feedback** (`feedback` table, `POST /api/feedback`, `GET /api/feedback` admin-only) — "Give Feedback" in the user-avatar dropdown now opens an in-app modal, and a persistent floating "Feedback" pill sits in the bottom-right corner of every page. Users pick a type (Bug / Idea / General), type a message up to 4000 chars, and submit; the current SPA route is captured as `page_hint` for context. Rows land in `pulse.db` with `user_id` + timestamp
- **Settings → Feedback admin tab** — admin-only review UI with a 5-tile KPI strip (Total / Bugs / Ideas / General / Top Page) and a table of submissions (relative time + UTC on hover, kind chip, submitter email, page path, 140-char preview). Click a row to expand the full message
- ~~**Custom organization branding**~~ — *reverted 2026-04-24.* The first-pass implementation (admin uploads logo + sets org name; sidebar swaps "PULSE / Threat Detection" for "{ORG NAME} / Powered by Pulse") was shipped then rolled back because replacing the Pulse logotype cost too much brand recognition. The API routes, Settings card, sidebar-override JS, and branding CSS are all removed; the empty `branding` table stays in the schema so a v2 pass (org name as a *subtitle* under the Pulse lockup) can reuse it. Tracked in the Backlog under "Branding + white-label"
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
