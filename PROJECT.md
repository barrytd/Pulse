# Pulse: Project Overview

Last updated: June 8, 2026
Maintainer: Robert Perez
Repository: github.com/barrytd/Pulse
License: MIT (open source)

> This is a living document. Update it as the product changes. Keep it plain and short so anyone can read it.

## What Pulse is

Pulse is a threat detection tool for Windows. It reads Windows event logs, finds signs of an attack, and explains each finding in plain language so you know what happened and what to do about it. It runs as a web dashboard your team signs into, with a small agent on each Windows machine you want to watch.

The short version: Pulse is the security tool for people who do not have a Security Operations Center.

## Who it is for

- Small IT teams and service providers who run Windows but have no dedicated security team.
- Startups and small businesses that cannot afford a large enterprise tool.
- Junior analysts and students learning blue team work.
- Penetration testers and incident responders who need fast triage of a log file.

## The problem it solves

Windows event logs hold the evidence of most attacks, but reading them by hand is slow and needs skills most small teams do not have. The tools that do this well are expensive, complex, and built for large security teams. Pulse gives small teams good Windows log analysis without the price or the steep learning curve. Every finding comes with a plain explanation and clear next steps.

## How it works

1. A person signs up. They become the admin of their own workspace (their organization).
2. They connect their Windows machines by installing a small agent on each one. The agent reads the local event logs, runs the detections on the machine itself, and sends back only the findings. Raw logs never leave their network.
3. Findings appear on the dashboard. The admin or a manager assigns them to analysts.
4. Analysts work their queue. They review each finding, mark it real or a false positive, add notes, and move it through to resolved.

You can also drop a `.evtx` log file straight into the dashboard for a one-off scan, or scan the machine Pulse is running on, with no agent needed.

## What it does today

### Detection
- 33 detection rules mapped to MITRE ATT&CK.
- Sysmon support (process creation, LSASS access, network connections, DNS queries).
- Multi-event correlation that links separate events into one attack chain.
- Import of community SIGMA rules.
- A built-in list of over 100 known-good services to cut false positives.

### Dashboard and triage
- A single-page web app with a security score, charts, and a view that shows raw events narrowing down to critical findings.
- A finding panel that leads with a plain summary, the actions to take, and the framework references, with the raw event data tucked into a section you can expand.
- My Queue: each analyst's assigned, unresolved findings, sorted by priority.
- Team Workload: a per-analyst view for managers (open count, oldest item, average time to fix).
- Workflow states, review flags, and a notes thread on every finding.
- Live monitoring, a command palette, and dark and light themes.

### Reports
- Nine report templates (threat summary, executive summary, NIST CSF, ISO 27001, incident, fleet health, board-ready, MITRE coverage, compliance gap).
- Four formats each (PDF, HTML, JSON, CSV), saved with history.

### Fleet and hosts
- Per-host security score, risk tier, and a spotlight on hosts that have gone quiet.
- A downloadable Windows agent with token enrollment, a check-in every 60 seconds, and a scan every 30 minutes.

### Response and hardening
- Block an attacking IP from a finding, managed through the Windows firewall.
- A custom whitelist to suppress known-good activity.
- Threat intel lookups against AbuseIPDB.
- Alerts by email, Slack, and Discord.

### Team and access
- Three roles: admin, manager, analyst.
- Each workspace sees only its own data.
- An audit log of every action.
- A compliance view that maps coverage to NIST CSF and ISO 27001.

## The team model

- Admin: owns the workspace. Manages users, settings, and billing. Can do everything.
- Manager: assigns findings, sets priority and due dates, oversees the team, manages the whitelist and firewall.
- Analyst: works the findings assigned to them, reviews and resolves them, adds notes.

## How you connect it to your network

- Agent (the main path): install the agent on each Windows host. It enrolls with a one-time token, then scans on a schedule and ships findings. Best for ongoing monitoring.
- Upload: drag a `.evtx` file into the dashboard. No install. Good for a one-off review.
- Scan this machine: scan the host that Pulse is running on directly.

## Architecture

- Backend: Python with FastAPI.
- Frontend: a single-page app in plain JavaScript, no framework.
- Database: SQLite for single-machine use, PostgreSQL for hosted and multi-user use.
- Sign-in: session cookies, scrypt password hashing, and API tokens for automation.
- Agent: a separate Python program that ships as a Windows executable.
- Hosting: runs on one server (for example Render) or self-hosted on your own machine.

## Security

- Passwords and PINs are hashed with scrypt.
- Login has rate limiting and lockout.
- Each workspace's data is kept separate from every other workspace.
- Response headers protect against clickjacking and content sniffing.
- A security PIN (in progress) asks for a second confirmation before destructive actions like blocking an IP or removing a user, so a stolen login cannot do real damage.
- The detection engine runs on the customer's own machine, so raw logs stay on their network.

## Pricing direction

Pulse is open source and free to self-host, and that will not change. The plan is open-core: the detection engine stays free, and a future paid tier covers the hosted convenience and premium features (more hosts, longer history, the report catalog, and a planned AI assistant). Nothing is gated today. Prices will be set once real users show what they will pay for.

## What is next

- Security PIN for sensitive actions (in progress).
- A simple "add a host" flow with a one-line installer.
- Tenant hardening before public sign-up (scope every admin to their own workspace, add a private platform-owner role).
- Invite teammates by code.
- An AI assistant ("Pip") that explains findings in chat.

See `ROADMAP.md` for the full current list. See `CHANGELOG.md` for the day-to-day history.

## Status

- Open source on GitHub: github.com/barrytd/Pulse
- License: MIT
- Over 1,160 automated tests, all passing.
- Active development.
