# `pulse/` — module index

This folder is the Pulse Python package. Every module lives here so that
CLI, API, scheduler, and monitor code can import each other through
`pulse.X`. Each file is a small, focused unit — no single module is more
than a few responsibilities.

Entry points live **outside** this folder:

- [`../main.py`](../main.py) — CLI entry point. Parses `--logs`, `--api`,
  `--watch`, etc. and dispatches into the functions below.
- [`../seed_fleet_demo.py`](../seed_fleet_demo.py) — seeds a demo fleet
  (multiple hostnames) into `pulse.db` so the Fleet page has data.
- [`../send_test_email.py`](../send_test_email.py) — one-shot SMTP sanity
  check for the email config in `pulse.yaml`.

---

## Core — parsing, detection, scoring

| Module | Role |
|---|---|
| [`parser.py`](parser.py) | Reads `.evtx` files (parallel, per-file timeout). Produces raw event dicts the detection layer consumes. |
| [`detections.py`](detections.py) | The detection engine. Loads rules, applies them to parsed events, emits findings. `run_all_detections()` is the top-level orchestrator. |
| [`rules_config.py`](rules_config.py) | Declarative list of every built-in detection rule (name, severity, description, MITRE technique, remediation guidance, framework mappings). |
| [`remediation.py`](remediation.py) | "How do I fix this?" lookups — per-rule step-by-step guidance plus MITRE ATT&CK mitigation IDs (M1026, M1027, ...). Attached to findings before they're rendered. |
| [`comparison.py`](comparison.py) | Diffs two scans into `{new, resolved, shared}` buckets. Drives the Scan Comparison feature on the History page. |
| [`known_good.py`](known_good.py) | Built-in 100+-entry whitelist of known-good service accounts, SIDs, and IPs so zero-config scans aren't spammed by legitimate Windows internals. |
| [`whitelist.py`](whitelist.py) | User-configurable whitelist layer on top of `known_good`. Suppresses findings whose `user`, `ip`, `rule`, or `detail` matches. |

## Reporting

| Module | Role |
|---|---|
| [`reporter.py`](reporter.py) | Renders HTML and text reports (severity filter tabs, remediation tab, dark mode, security score). |
| [`pdf_report.py`](pdf_report.py) | ReportLab-based PDF report. Grade-coloured score ring, per-finding cards, numbered remediation, MITRE mitigation pills. |
| [`emailer.py`](emailer.py) | SMTP delivery for threshold alert emails and full-report emails. Handles text+HTML multipart and optional PDF attachment. |
| [`webhook.py`](webhook.py) | Slack (Block Kit) + Discord (embeds) webhook delivery with auto-flavor detection from URL. |

## API + web dashboard

| Module | Role |
|---|---|
| [`api.py`](api.py) | FastAPI application — every `/api/*` endpoint, SPA shell routing, static file mount, auth middleware. |
| [`auth.py`](auth.py) | Password hashing (scrypt), signed session cookies (HMAC-SHA256), `require_login` and `require_admin` FastAPI dependencies. |
| [`database.py`](database.py) | SQLite schema + all query helpers: scans, findings, users, audit log, IP block list, monitor sessions, fleet summary. |

## Live monitoring

| Module | Role |
|---|---|
| [`monitor.py`](monitor.py) | Core live-monitor loop — queries Windows event channels in real time and runs detections on each poll. |
| [`monitor_service.py`](monitor_service.py) | Session bookkeeping for monitor runs (start→stop spans, per-session counters, session-scoped findings). |
| [`system_scan.py`](system_scan.py) | "Scan My System" entry point — reads directly from `C:\Windows\System32\winevt\Logs\` with a lookback window. |
| [`scheduler.py`](scheduler.py) | Cron parser + next-run math used by the scheduled-scan runner. |
| [`scheduled_scan.py`](scheduled_scan.py) | Background thread that fires system scans on the user's configured cadence and dispatches alerts. |

## Firewall

| Module | Role |
|---|---|
| [`firewall_parser.py`](firewall_parser.py) | Reads `pfirewall.log` and detects port scans + sensitive-port probes from public IPs. |
| [`firewall_config.py`](firewall_config.py) | Parses live `netsh advfirewall` output and flags disabled profiles, any-any allow rules, and overly broad scope on sensitive ports (3389 / 22 / 445 / ...). |
| [`blocker.py`](blocker.py) | Pulse-managed IP block list. Stages IPs in SQLite, pushes inbound deny rules via `netsh advfirewall`, writes the audit log. Every rule is prefixed `Pulse-managed:`. |

## UX polish

| Module | Role |
|---|---|
| [`interactive.py`](interactive.py) | Terminal-mode browser — lets the CLI user page through findings, investigate, and add whitelist entries without leaving the terminal. |
| [`animations.py`](animations.py) | ECG heartbeat / spinner animations shown while parsing. |

## Package marker

| File | Role |
|---|---|
| [`__init__.py`](__init__.py) | Marks `pulse/` as a Python package. Exposes `__version__`. |
| [`static/`](static/) | Dashboard JavaScript modules (ES modules) + CSS. Not imported by Python — served by `api.py`. |
| [`web/`](web/) | Dashboard HTML shells (`index.html`, `login.html`). |

---

## Tests

Unit tests live in [`../tests/`](../tests/) and are discovered automatically
by pytest:

```bash
python -m pytest -q
```

Each `tests/test_<module>.py` exercises the public API of the `pulse.<module>`
it's named after, with a handful of cross-cutting files (`test_api.py`,
`test_auth.py`) covering endpoint integration.
