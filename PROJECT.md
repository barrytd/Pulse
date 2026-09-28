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
- 35 detection rules mapped to MITRE ATT&CK.
- Sysmon support (process creation, LSASS access, network connections, DNS queries).
- Multi-event correlation that links separate events into one attack chain.
- Import of community SIGMA rules.
- A built-in list of over 100 known-good services to cut false positives.

### Dashboard and triage
- A single-page web app. The dashboard leads with the security grade and one plain-language line about what's wrong, next to the unreviewed critical and high findings, then four key numbers as tiles, and the score history beside findings by severity. A brand-new account sees a "Run your first scan" prompt instead of empty zeros. The grade ring is the biggest thing on the page. It fits on about one screen, stays a comfortable width on wide monitors, uses the Inter font (bundled, so it works offline), and is built from shared card, spacing and type styles that every page now uses. Sidebar, topbar and page share one continuous surface in light and dark, and every page works on a phone-width screen without scrolling sideways.
- The security score (0 to 100, graded A to F) uses diminishing returns: each unique finding removes a share of the health that is left, so the score gets close to 0 without hitting it, and a host with 40 critical findings scores lower than one with 8. Open findings count fully, resolved ones count a little, and false positives don't count. A finding fades after it has been open for a week, measured from when Pulse recorded it, so an old log uploaded today is scored at full strength. The dashboard, the command line, and every report use the same scorer, so one host gets one score everywhere.
- A finding panel that leads with a plain summary, the actions to take, and the framework references, with the raw event data tucked into a section you can expand.
- My Queue: each analyst's assigned, unresolved findings, sorted by priority.
- Team: its own page for managers and admins, with a per-analyst view (open count, oldest item, average time to fix).
- Workflow states, review flags, and a notes thread on every finding.
- Pip, a Security Buddy: a floating chat circle you can click to ask what a finding means, whether something looks dangerous, or any security question, answered in plain language. It suggests follow-up questions, remembers your chat when you refresh, and can see the finding you have open so you can ask about it directly.
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
- Threat intel lookups against AbuseIPDB and VirusTotal. Both verdicts show in the finding panel right above the block button, so an analyst can check an IP's reputation without opening another site. VirusTotal uses the customer's own API key; Pulse never ships one.
- An Investigate button in the finding panel: one click looks up every IP address, domain and file hash in the finding across all the threat-intel sources at once (AbuseIPDB, VirusTotal, GreyNoise, AlienVault OTX, GeoIP location, Whois registration age, and DNS) and shows every verdict together. GreyNoise and OTX use the customer's own free keys. GeoIP works out of the box from a bundled country-level database (DB-IP, free to redistribute), offline; customers can add a city-level database for more detail.
- Alerts by email, Slack, and Discord.
- Automations (playbooks): saved recipes that react to new findings on their own. A playbook can look the attacker up on AbuseIPDB and VirusTotal the moment a finding fires, then propose a response such as blocking the IP or alerting the team. Lookups run by themselves; every response waits for a manager or admin to approve it on the Automations page or in the finding. Admins build their own with a click-together builder (pick the conditions, add the steps, choose values like the attacker's IP from a list; no code), start from one of three ready-made examples, or paste JSON.

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
- Integrations: a connector layer in `pulse/connectors/`. Each outside service (AbuseIPDB, VirusTotal) is one file with the same small interface, and it registers itself, so adding a new one needs no changes to the core. Playbooks (`pulse/soar/`) run on top of it: a background worker matches each new finding against the organization's playbooks and records every step of every run.
- Hosting: runs on one server (for example Render) or self-hosted on your own machine.

## Security

- Passwords and PINs are hashed with scrypt.
- Login has rate limiting and lockout.
- Each workspace's data is kept separate from every other workspace.
- Response headers protect against clickjacking and content sniffing.
- A security PIN asks for a second confirmation before destructive actions like blocking an IP or removing a user, so a stolen login cannot do real damage. It is a separate secret from the password, opt-in per user, and locks out after repeated wrong tries.
- The detection engine runs on the customer's own machine, so raw logs stay on their network.
- Threat intel lookups never send private IP addresses or internal domain names to outside services. API keys stay on the server, every lookup is cached, and each provider's free-tier limit is respected so a noisy host cannot burn the quota. A failed lookup shows "no intel" instead of breaking the page.
- Playbooks can never block an IP, send a message, open a ticket or call a webhook on their own. Every response step waits for a person with manager or admin rights to approve it, with their security PIN when they have one set, and it runs exactly the values they were shown. There is no fully automatic mode. Playbook expressions are a small, limited language, never code, so a stored playbook cannot run commands on the server.
- The Pip AI assistant is off unless an administrator adds an Anthropic API key, the key stays on the server (never in the browser), and the chat panel discloses that questions are sent to Anthropic to be answered. Pip is read-only and cannot take any action in Pulse.

## Pricing direction

Pulse is open source and free to self-host, and that will not change. The plan is open-core: the detection engine stays free, and a future paid tier covers the hosted convenience and premium features (more hosts, longer history, the report catalog, and a higher daily limit for the Pip AI assistant). Nothing is gated today. Prices will be set once real users show what they will pay for.

## What is next

- Automations: phases 1 to 3 are built (the connector layer, the playbook engine, the click-together builder, the Investigate panel, seven enrichment connectors, and four response connectors: firewall block, Slack/Discord, ClickUp/Jira tickets and an outbound webhook). Next is phase 4, a Toolkit page that runs any lookup without a finding open. Shodan and MISP / OpenCTI were left out of phase 3 and stay on the roadmap. Design: `docs/2026-09-26-soar-playbooks-and-integrations.md`.
- A simple "add a host" flow with a one-line installer.
- Tenant hardening before public sign-up: the core is done (each workspace's admin is now scoped to their own workspace, with a private platform-owner role set by an environment variable). Still to add before opening sign-up to strangers: cross-site request protection and trusting the right network address behind a proxy.
- Invite teammates by code.
- More for Pip, the AI assistant: streaming replies, a paid tier with a higher daily question limit, and a curated cybersecurity knowledge file so Pip answers from vetted, documented fact instead of only its training.

See `ROADMAP.md` for the full current list. See `CHANGELOG.md` for the day-to-day history.

## Status

- Open source on GitHub: github.com/barrytd/Pulse
- License: MIT
- Over 1,800 automated tests, all passing.
- Active development.
