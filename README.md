# Pulse

**Real-time Windows threat detection — self-hosted, MITRE-mapped, free.**

Pulse parses Windows event logs (`.evtx`), runs 25 detection rules, and surfaces findings in a SOC-style dashboard. Drop a lightweight agent on every host, watch detections fire live in the browser, triage from one page. No SIEM bill, no per-event pricing.

---

## Features

**Detections** — 25 rules covering brute force, credential dumping (DCSync, Kerberoasting, LSASS access), persistence (services, scheduled tasks, registry Run keys), lateral movement (admin shares, RDP, pass-the-hash), defense evasion (audit log clearing, AV/firewall disable), and three multi-event attack chains. Each finding tags its MITRE ATT&CK technique, NIST CSF subcategory, and ISO 27001 control. See [pulse/core/rules_config.py](pulse/core/rules_config.py) for the full table.

**Dashboard** — single-page app at `/` (logged-in): live monitor with SSE feed, scan history with score trend, per-host fleet view, findings drawer with append-only notes thread, workflow states (new → ack → investigating → resolved), assignment, MITRE/NIST/ISO coverage report, trends (7/30/90-day), audit log.

**Pulse Agent** — Windows binary that scans the local event log and ships findings over HTTPS. Two-token auth, 60s heartbeat, 30-minute scan cadence (configurable). Pause / delete / revoke from the dashboard. See **Pulse Agent** below.

**Reports** — Text, HTML, JSON, CSV, PDF. Each scan gets a 0–100 security score graded A–F.

**Alerts** — SMTP email + Slack/Discord webhooks, threshold-tripped with cooldown.

**Firewall response** — Reads `pfirewall.log`, surfaces port-scan probes from public IPs, blocks IPs via `netsh advfirewall` from the finding drawer.

**Noise reduction** — Built-in 100+ known-good account allowlist + user whitelist + baseline snapshot for new-account / new-service / new-task diffing.

**Multi-tenant** — Every owned row scoped to an `organization_id`. Self-signup mints a fresh org; admin-side user creation joins the admin's org. See **Multi-tenant** below.

**API** — FastAPI surface with Swagger UI at `/docs`. Bearer tokens minted from Settings → API Tokens.

---

## Quick start

```bash
git clone https://github.com/barrytd/Pulse.git
cd Pulse
pip install -r requirements.txt

# Scan the default logs/ folder
python main.py

# Start the dashboard + REST API
python main.py --api

# Live monitor with terminal alerts
python main.py --watch

# See every flag
python main.py --help
```

`.evtx` files: drop them in `logs/`, or point at `C:\Windows\System32\winevt\Logs\` with `--logs <path>`. Reports land in `reports/`.

---

## Marketing site & download

`/` serves a marketing landing page for unauthenticated visitors; logged-in users get the dashboard at the same path. The landing's **Download for Windows** CTA streams the built `dist/pulse-agent/` bundle as a zip via `GET /api/agent/download`. When the server has no bundle on disk (the Render-style deploy), the CTAs auto-fall back to the GitHub repo via `/api/agent/download/check` — no dead buttons.

---

## Pulse Agent

The hosted dashboard runs on Linux and can't read a remote Windows host's event log. Install Pulse Agent on each Windows host you want monitored.

### Two-step setup

1. In the dashboard: **Settings → Agents → Enroll a Pulse Agent**. Copy the `pe_…` token from the banner (shown once).
2. On the Windows host:

```powershell
# Python entry point (works today on any machine with Python 3.8+):
python -m pulse.agent enroll https://your-pulse pe_AAAA...
python -m pulse.agent run

# …or the packaged exe (no Python needed on the host):
.\dist\pulse-agent\pulse-agent.exe enroll https://your-pulse pe_AAAA...
.\dist\pulse-agent\pulse-agent.exe run
```

### Building the binary

```powershell
pip install -r requirements-agent.txt
python scripts/build_agent.py --clean
```

Outputs a one-folder bundle under `dist/pulse-agent/` (37 MB total, 6.5 MB launcher). `--onefile` collapses to a single .exe.

### Running as a Windows Service

[NSSM](https://nssm.cc/) is the easy path:

```powershell
nssm install PulseAgent "C:\Program Files\Pulse\pulse-agent\pulse-agent.exe" run
nssm set PulseAgent Start SERVICE_AUTO_START
nssm start PulseAgent

# Lock the bearer-token file down to SYSTEM + Administrators.
icacls "C:\ProgramData\Pulse\agent.yaml" /inheritance:r /grant:r "SYSTEM:(R,W)" "Administrators:(F)"
```

`sc.exe` works too — see [ROADMAP.md](ROADMAP.md) for the bundled-installer follow-up.

### Auto-update channel

The agent calls `GET /api/agent/latest` at startup and logs an `update available` warning when the server reports a newer build. Overrides:

- `PULSE_AGENT_DOWNLOAD_URL` — defaults to the GitHub Releases page
- `PULSE_AGENT_NOTES_URL` — defaults to the CHANGELOG

---

## Multi-tenant

Every scan / agent / notification carries an `organization_id`. Two customers on the same hosted Pulse instance never see each other's data, but every member of the same org shares scan / agent / finding visibility (the right SOC team boundary).

- Self-signup (`POST /api/auth/signup`) auto-creates a new org. Set `PULSE_HOSTED_SIGNUP=1` on the deployment to keep signup open past the first user (default closes after bootstrap so a self-hosted install doesn't accidentally let strangers create accounts).
- Admins invite teammates via **Settings → Users**; teammates join the admin's org.
- Legacy single-user installs upgrade in place via an idempotent backfill in `init_db`.

---

## Project structure

```
pulse/        Application package — see pulse/README.md for the per-module index
tests/        Pytest suite (one test_<module>.py per module)
scripts/      Build + utility scripts (build_agent.py, migrate_to_postgres.py)
main.py       CLI entry point
pulse.yaml    Config (whitelist, alerts, secrets template)
```

Persistent files:
- `pulse.db` — SQLite scan history (use `DATABASE_URL=postgresql://…` to point at Postgres)
- `pulse_baseline.json` — saved with `--save-baseline`, diffed on future scans
- `logs/`, `reports/`, `dist/` — drop zone, report output, build artifacts

---

## Tests

```bash
python -m pytest -q                    # all 652 tests
python -m pytest tests/test_detections.py -v   # single module
```

The suite covers every detection rule, the API surface, multi-tenant isolation, agent runtime cadence, firewall log parsing, IP block-list lifecycle, and the auto-update channel. No real `.evtx` files needed — synthetic event data mirrors the live structure.

---

## Links

- Current sprint plan: [ROADMAP.md](ROADMAP.md)
- Unscheduled ideas: [BACKLOG.md](BACKLOG.md)
- Change history: [CHANGELOG.md](CHANGELOG.md)
- API docs: `http://localhost:8000/docs` (Swagger UI) when running with `--api`

---

## License

MIT — see [LICENSE](LICENSE).
