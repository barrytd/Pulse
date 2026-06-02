# `pulse/` — module index

This folder is the Pulse Python package. Modules are grouped into
subpackages by concern so CLI, API, scheduler, and monitor code can
find what they need without one giant flat namespace. Each file is a
small, focused unit — no single module owns more than a few
responsibilities.

Entry points live **outside** this folder:

- [`../main.py`](../main.py) — CLI entry point. Parses `--logs`, `--api`,
  `--watch`, etc. and dispatches into the functions below.
- [`../scripts/seed_fleet_demo.py`](../scripts/seed_fleet_demo.py) — seeds a demo fleet
  (multiple hostnames) into `pulse.db` so the Fleet page has data.
- [`../scripts/send_test_email.py`](../scripts/send_test_email.py) — one-shot SMTP sanity
  check for the email config in `pulse.yaml`.

---

## [`core/`](core/) — parsing, detection, scoring

| Module | Role |
|---|---|
| [`core/parser.py`](core/parser.py) | Reads `.evtx` files (parallel, per-file timeout). Produces raw event dicts the detection layer consumes. |
| [`core/detections.py`](core/detections.py) | The detection engine. Loads rules, applies them to parsed events, emits findings. `run_all_detections()` is the top-level orchestrator. |
| [`core/rules_config.py`](core/rules_config.py) | Declarative list of every built-in detection rule (name, severity, description, MITRE technique, remediation guidance, framework mappings). |
| [`core/known_good.py`](core/known_good.py) | Built-in 100+-entry whitelist of known-good service accounts, SIDs, and IPs so zero-config scans aren't spammed by legitimate Windows internals. |

## [`reports/`](reports/) — rendering + diffing

| Module | Role |
|---|---|
| [`reports/reporter.py`](reports/reporter.py) | Renders HTML and text reports (severity filter tabs, remediation tab, dark mode, security score). |
| [`reports/pdf_report.py`](reports/pdf_report.py) | ReportLab-based PDF report. Grade-coloured score ring, per-finding cards, numbered remediation, MITRE mitigation pills. |
| [`reports/comparison.py`](reports/comparison.py) | Diffs two scans into `{new, resolved, shared}` buckets. Drives the Scan Comparison feature on the History page. |

## [`alerts/`](alerts/) — outbound notifications + schedule plumbing

| Module | Role |
|---|---|
| [`alerts/emailer.py`](alerts/emailer.py) | SMTP delivery for threshold alert emails and full-report emails. Handles text+HTML multipart and optional PDF attachment. |
| [`alerts/webhook.py`](alerts/webhook.py) | Slack (Block Kit) + Discord (embeds) webhook delivery with auto-flavor detection from URL. |
| [`alerts/scheduler.py`](alerts/scheduler.py) | Watches a folder for new `.evtx` drops and triggers scans on stable files. |

## [`monitor/`](monitor/) — live + scheduled + on-box scans

| Module | Role |
|---|---|
| [`monitor/monitor.py`](monitor/monitor.py) | Core live-monitor loop — queries Windows event channels in real time and runs detections on each poll. |
| [`monitor/monitor_service.py`](monitor/monitor_service.py) | Session bookkeeping for monitor runs (start→stop spans, per-session counters, session-scoped findings). |
| [`monitor/system_scan.py`](monitor/system_scan.py) | "Scan My System" entry point — reads directly from `C:\Windows\System32\winevt\Logs\` with a lookback window. |
| [`monitor/scheduled_scan.py`](monitor/scheduled_scan.py) | Background thread that fires system scans on the user's configured cadence and dispatches alerts. |

## [`firewall/`](firewall/) — Windows Firewall audit + IP block list

| Module | Role |
|---|---|
| [`firewall/firewall_parser.py`](firewall/firewall_parser.py) | Reads `pfirewall.log` and detects port scans + sensitive-port probes from public IPs. |
| [`firewall/firewall_config.py`](firewall/firewall_config.py) | Parses live `netsh advfirewall` output and flags disabled profiles, any-any allow rules, and overly broad scope on sensitive ports (3389 / 22 / 445 / ...). |
| [`firewall/blocker.py`](firewall/blocker.py) | Pulse-managed IP block list. Stages IPs in SQLite, pushes inbound deny rules via `netsh advfirewall`, writes the audit log. Every rule is prefixed `Pulse-managed:`. |

## [`agent/`](agent/) — downloadable Windows agent (Sprint 7)

| Module | Role |
|---|---|
| [`agent/config.py`](agent/config.py) | `AgentConfig` dataclass + `load_config` / `save_config`. Default path: `%PROGRAMDATA%\Pulse\agent.yaml` on Windows, `~/.pulse/agent.yaml` elsewhere. Drops unknown keys for forward-compat. |
| [`agent/transport.py`](agent/transport.py) | `AgentTransport` — thin `httpx.Client` wrapper for the four agent endpoints (`exchange`, `heartbeat`, `findings`, `latest`). `TransportError(permanent=…)` distinguishes "retry later" from "re-enroll required". |
| [`agent/scanner.py`](agent/scanner.py) | `scan_for_findings()` reuses `pulse.core.detections` + `pulse.core.parser` + `pulse.monitor.system_scan._resolve_log_paths`. RuntimeError on non-Windows hosts. |
| [`agent/runtime.py`](agent/runtime.py) | `AgentRuntime` — main loop. Independent heartbeat (60s) and scan (30min) cadences with sentinel-None "first tick fires" semantics. Startup auto-update probe + token-file ACL audit. |
| [`agent/permissions.py`](agent/permissions.py) | `audit_token_file_permissions(path)` runs `icacls` and detects loose ACLs (Everyone / BUILTIN\\Users / Authenticated Users + SID forms). `harden_token_file(path)` strips inheritance and grants SYSTEM + Administrators only. |
| [`agent/__main__.py`](agent/__main__.py) | CLI entry — `enroll <url> <token>`, `run`, `status`, `harden`. Invoked as `python -m pulse.agent` or via the packaged `pulse-agent.exe`. |

## Root — API, auth, and cross-cutting pieces

These stay at `pulse/` top level because they're consumed by every
subpackage or are deliberately neutral (no domain of their own).

| Module | Role |
|---|---|
| [`api.py`](api.py) | FastAPI application — every `/api/*` endpoint, SPA shell routing, static file mount, auth middleware, marketing landing route. |
| [`auth.py`](auth.py) | Password hashing (scrypt), signed session cookies (HMAC-SHA256), `require_login` and `require_admin` FastAPI dependencies, API-token Bearer auth. |
| [`database.py`](database.py) | Schema + all query helpers: users (with multi-tenant `organization_id` + email-verification columns), scans, findings, agents, audit log, IP block list, monitor sessions, fleet summary, notifications, finding notes. |
| [`db_backend.py`](db_backend.py) | Pluggable SQLite/Postgres adapter. SQLite by default; `DATABASE_URL=postgresql://…` flips to psycopg with `?`→`%s` translation and `RETURNING` for `lastrowid`. |
| [`agents.py`](agents.py) | Server-side agent token plumbing (separate from the `agent/` package which is the *client* runtime): mint enrollment, exchange enrollment for bearer, authenticate Bearer header against the `agents` table. |
| [`whitelist.py`](whitelist.py) | User-configurable whitelist layer on top of `known_good`. Suppresses findings whose `user`, `ip`, `rule`, or `detail` matches. |
| [`remediation.py`](remediation.py) | "How do I fix this?" lookups — per-rule step-by-step guidance plus MITRE ATT&CK mitigation IDs (M1026, M1027, ...). Attached to findings before they're rendered. |
| [`rate_limit.py`](rate_limit.py) | In-process sliding-window rate limiter. `hit()` ticks + checks; `check()` checks without ticking; `record()` ticks without checking. Used for the failed-login lockout pattern and per-endpoint burst caps. |
| [`intel.py`](intel.py) | AbuseIPDB threat-intel lookup with 24h on-disk cache. Returns confidence-of-abuse score, country, ISP, last-reported. Opt-in via `pulse.yaml` API key. |
| [`interactive.py`](interactive.py) | Terminal-mode browser — lets the CLI user page through findings, investigate, and add whitelist entries without leaving the terminal. |
| [`animations.py`](animations.py) | ECG heartbeat / spinner animations shown while parsing. |

## Package marker

| File | Role |
|---|---|
| [`__init__.py`](__init__.py) | Marks `pulse/` as a Python package. Exposes `__version__`. |
| [`static/`](static/) | Dashboard JavaScript modules (ES modules) + CSS. Not imported by Python — served by `api.py`. |
| [`web/`](web/) | Static HTML shells. `index.html` (dashboard SPA), `login.html` (sign-in / first-user signup), `landing.html` (marketing page for unauthenticated visitors at `/`). |

---

## Tests

Unit tests live in [`../tests/`](../tests/) and are discovered automatically
by pytest:

```bash
python -m pytest -q
```

Each `tests/test_<module>.py` exercises the public API of the matching
`pulse.<subpackage>.<module>`, with a handful of cross-cutting files
(`test_api.py`, `test_auth.py`, `test_data_isolation.py`) covering
endpoint integration.
