# Pulse

> Open-source Windows event log analyzer and threat detection tool for SOC triage.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-689%20passing-brightgreen)
![Release](https://img.shields.io/github/v/release/barrytd/Pulse?label=release)
![Stars](https://img.shields.io/github/stars/barrytd/Pulse?style=social)

<!-- Drop a hero screenshot here: docs/screenshots/dashboard.png (max 800px wide). -->

---

## What Pulse does

Pulse parses Windows `.evtx` event logs, runs 25 detection rules mapped to MITRE ATT&CK, scores your security posture A through F, and gives you a web dashboard for triage. It supports fleet monitoring across multiple hosts, IP blocking through Windows Firewall, email + Slack + Discord alerts, PDF reports, a REST API, and a downloadable Windows agent for continuous monitoring.

---

## Quick start

```bash
git clone https://github.com/barrytd/Pulse.git
cd Pulse
pip install -r requirements.txt
python main.py --api
```

Open `http://localhost:8000` and upload any file from `samples/` to see Pulse light up:

- `samples/brute-force-server.evtx` — domain controller brute-force + account takeover (5 detections, grade F)
- `samples/credential-theft-workstation.evtx` — Mimikatz + LSASS dump + lateral movement (4 detections, grade F)
- `samples/persistence-malware.evtx` — service install + scheduled task + Run-key write (6 detections, grade F)
- `samples/lateral-movement-dc.evtx` — Kerberoasting + Golden Ticket + DCSync (5 detections, grade F)

See [`samples/README.md`](samples/README.md) for what each scenario simulates and which rules it triggers.

### Quick start with Docker

```bash
git clone https://github.com/barrytd/Pulse.git
cd Pulse
docker compose up -d
```

Open `http://localhost:8443`. Postgres + Pulse start as separate containers; the first launch creates the admin user from `PULSE_ADMIN_EMAIL` / `PULSE_ADMIN_PASSWORD` (set those in `docker-compose.yml` first).

---

## Features

| Area | Capability |
|---|---|
| **Detection** | 25 rules mapped to MITRE ATT&CK · NIST CSF + ISO 27001 control IDs · multi-event attack chains · custom whitelist + 100+ built-in known-good entries · baseline diff for new accounts / services / tasks |
| **Dashboard** | Single-page app with live monitor (SSE) · finding drawer with notes thread · workflow states (new → ack → investigating → resolved) · assignment · Ctrl+K command palette · dark mode |
| **Alerting** | SMTP email · Slack + Discord webhooks · per-rule cooldown · threshold-tripped · live monitor email alerts with interval gating |
| **Fleet** | Per-host security score · last-scan timestamp · severity mix · drill-into-host view · CSV export |
| **Firewall** | `pfirewall.log` parser · port-scan + sensitive-port probe detection · Pulse-managed IP block list via `netsh advfirewall` · one-click block from finding drawer |
| **Compliance** | NIST CSF coverage by Function (Identify/Protect/Detect/Respond/Recover) · ISO 27001 Annex A mapping per rule · coverage-gap report (uncovered techniques, silent rules, noisy rules) |
| **API** | FastAPI surface with Swagger at `/docs` · Bearer-token auth (Settings → API Tokens) · REST endpoints for scan upload, history, reports, agent transport |
| **Agent** | Packaged `pulse-agent.exe` (37 MB) · two-token enrollment (single-use enrollment → long-lived bearer) · 60s heartbeat + 30min scan cadence · auto-update probe · ACL self-audit |
| **Multi-tenant** | Every owned row scoped to `organization_id` · self-signup mints fresh org · email verification · admin invites join the admin's org |
| **Reports** | Text / HTML / JSON / CSV / PDF · grade-coloured score ring · per-finding remediation steps · MITRE mitigation IDs |

---

## Detection rules

All 25 rules, sorted by severity. Sub-detections (DCSync, Suspicious Child Process) emit under their parent rule. Full source: [`pulse/core/rules_config.py`](pulse/core/rules_config.py).

| Rule | Event ID(s) | Severity | MITRE |
|---|---|---|---|
| Account Takeover Chain | (correlated) | 🔴 CRITICAL | T1078 |
| Credential Dumping | 4656 · 4663 | 🔴 CRITICAL | T1003.001 |
| Golden Ticket | 4768 | 🔴 CRITICAL | T1558.001 |
| Malware Persistence Chain | (correlated) | 🔴 CRITICAL | T1543.003 |
| Account Lockout | 4740 | 🟠 HIGH | T1110 |
| Antivirus Disabled | 5001 | 🟠 HIGH | T1562.001 |
| Audit Log Cleared | 1102 | 🟠 HIGH | T1070.001 |
| Brute Force Attempt | 4625 | 🟠 HIGH | T1110 |
| Firewall Disabled | 4950 | 🟠 HIGH | T1562.004 |
| Firewall Profile Disabled | (config) | 🟠 HIGH | T1562.004 |
| Kerberoasting | 4769 | 🟠 HIGH | T1558.003 |
| Lateral Movement via Network Share | 5140 · 5145 | 🟠 HIGH | T1021.002 |
| Pass-the-Hash Attempt | 4624 | 🟠 HIGH | T1550.002 |
| Privilege Escalation | 4732 | 🟠 HIGH | T1548 |
| Suspicious PowerShell | 4104 | 🟠 HIGH | T1059.001 |
| Suspicious Registry Modification | 4657 | 🟠 HIGH | T1547.001 |
| After-Hours Logon | 4624 | 🟡 MEDIUM | T1078 |
| Firewall Any-Any Allow Rule | (config) | 🟡 MEDIUM | T1562.004 |
| Firewall Overly Broad Scope | (config) | 🟡 MEDIUM | T1562.004 |
| Firewall Rule Changed | 4946 · 4947 | 🟡 MEDIUM | T1562.004 |
| Logon from Disabled Account | 4625 | 🟡 MEDIUM | T1078 |
| RDP Logon Detected | 4624 | 🟡 MEDIUM | T1021.001 |
| Scheduled Task Created | 4698 | 🟡 MEDIUM | T1053.005 |
| Service Installed | 7045 | 🟡 MEDIUM | T1543.003 |
| User Account Created | 4720 | 🟡 MEDIUM | T1136.001 |

---

## Architecture

**Server** — Python 3.8+ · [FastAPI](https://fastapi.tiangolo.com/) · SQLite by default, PostgreSQL with `DATABASE_URL=postgresql://…` via a pluggable adapter ([`pulse/db_backend.py`](pulse/db_backend.py)). No build step on the frontend: vanilla ES modules under [`pulse/static/js/`](pulse/static/js/), CSS variables for theming, Server-Sent Events for the live monitor feed.

**Agent** — Same Python package, packaged via PyInstaller into a 37 MB Windows binary (`pulse-agent.exe`). Runs the same detection engine locally and POSTs findings to the server over HTTPS. Two-token auth: a single-use `pe_…` enrollment token mints a long-lived `pa_…` bearer; both stored sha256-at-rest. See [`pulse/agent/`](pulse/agent/) and [`scripts/build_agent.py`](scripts/build_agent.py).

**Storage** — All scan history, findings, audit log, agents, notifications, organizations, users, API tokens, IP block list, and finding notes live in one schema ([`pulse/database.py`](pulse/database.py)). Multi-tenant rows carry an `organization_id`; the API helper `_read_scope_kwargs` enforces tenant isolation on every read/write.

**Tests** — 689 passing across the suite (688 offline; one runs `pip-audit --strict` and is marked `@pytest.mark.network`).

---

## Screenshots

<!-- Add screenshots to docs/screenshots/ and reference them here:
     - dashboard.png        — score ring + KPI strip + last-scan findings
     - findings.png         — filter bar + table + status pills
     - monitor.png          — live SSE feed + Start/Stop banner
     - fleet.png            — per-host card grid + score badges
     - rules.png            — per-rule hit counts + MITRE coverage matrix
     - audit.png            — audit log table + filter chips
-->

*Screenshots coming with the next release.* Until then, point Pulse at the `samples/` directory and see the same surfaces with real detection data.

---

## Documentation

- [`ROADMAP.md`](ROADMAP.md) — status board (in progress / up next / blocked / backlog / shipped)
- [`CHANGELOG.md`](CHANGELOG.md) — commit-level history
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — dev setup, running tests, adding a detection rule, PR process
- [`pulse/README.md`](pulse/README.md) — per-module index of the application package
- API docs — `http://localhost:8000/docs` (Swagger UI) when running with `--api`

---

## Production deploys

```bash
pip install -r requirements-lock.txt          # exact pins, not >= ranges
python -m pip_audit --strict                  # CVE scan against the pinned set
```

`requirements.txt` (loose ranges) is for dev; `requirements-lock.txt` (exact pins) is for production / hosted deploys so a compromised or buggy upstream package can't silently break Pulse or introduce a vulnerable transitive dep. A test in [`tests/test_security_hardening.py`](tests/test_security_hardening.py) runs `pip-audit --strict` against the live environment on every test sweep (marked `@pytest.mark.network`, skip with `-m "not network"`).

---

## Contributing

Pull requests welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for dev environment setup, the step-by-step tutorial for adding a new detection rule, and the PR process. Good first issues are labeled on GitHub.

For security issues, please use GitHub's private vulnerability reporting — don't open a public issue.

---

## License

MIT — see [`LICENSE`](LICENSE).
