# Pulse v2.0.0

Pulse began as a command-line script that scanned a Windows event log and printed a report. **v2.0.0 is the release where it became a product** — a multi-user web platform with an AI assistant built in, for the small teams, solo IT folks, and junior analysts who get a security alert and have no SOC to ask "is this bad?"

New here? **Pulse** parses Windows `.evtx` event logs, runs 33 detection rules mapped to MITRE ATT&CK, scores your security posture A–F, and gives you a web dashboard to triage findings and generate professional reports. It's open source (MIT) and runs locally or hosted.

## Headline features

**🤖 Pip — a built-in AI security buddy.** A floating assistant that explains any finding in plain English: what happened, whether it's actually dangerous, and what to do right now. Answers come from Claude, proxied server-side so your API key never touches the browser. Pip slides in beside whatever finding you're viewing, is read-only (it explains, it never acts on its own), and is metered per user per day to keep costs predictable.

**🏢 Multi-tenant isolation.** Pulse can now host multiple organizations with hard data isolation — each org's admin sees and manages only their own org's scans, findings, and users. A private, environment-only super-admin allowlist keeps platform-owner access out of reach of any tenant. Single-user self-host is unchanged: the lone admin still sees everything.

**🖥️ Redesigned Fleet page.** A full-width, risk-sorted view of every monitored host with online / stale / offline status and a single filter bar (hostname, risk, status, CSV export). Click any host for a drilldown drawer showing its posture, a severity breakdown, and its findings — with one-click report generation.

**📄 Unified, print-ready report system.** All 9 report templates — Incident Investigation, Executive Summary, Threat Detection, NIST CSF, ISO 27001, Fleet Health, Board-Ready Posture, MITRE Coverage, and Compliance Gap — now render through one shared design system: a branded header and "Page X of Y" footer on every page, consistent severity pills, zebra tables, callouts, and a graceful "None recorded" for empty fields, in both PDF and HTML.

## Security hardening

- **The API key stays server-side.** The Anthropic key that powers Pip is read from the environment only, used solely in the outbound request, and never returned to the browser or written to a log. Verified by audit.
- **Rate-limiter `X-Forwarded-For` spoofing fixed.** The limiter no longer trusts the client-supplied `X-Forwarded-For` header blindly — which previously let anyone rotate a fake IP to dodge per-IP caps, or set a victim's IP to burn their budget. A new `PULSE_TRUSTED_PROXY_HOPS` setting controls how much of the forwarded chain to trust (see Upgrade notes).
- **Credentials never cross the wire.** Config endpoints mask every secret to a boolean (`password_set` / `url_set` / `api_key_set`); `.env`, `pulse.yaml`, and databases are gitignored and never serialized.

## Upgrade notes

- **Behind a reverse proxy or load balancer (Render, nginx, Cloudflare)?** Set **`PULSE_TRUSTED_PROXY_HOPS=1`** in your environment so the rate limiter reads the real client IP. Without it, every client collapses to the proxy's IP and shares a single rate-limit bucket (over-aggressive limiting). Local and directly-exposed installs need no change — the default is `0`, which ignores the header and uses the direct connection.
- **Pip is optional and stays off until configured.** Set `ANTHROPIC_API_KEY` in the server's environment to enable it; without a key the widget still renders and explains that an admin needs to add one. API usage is pay-as-you-go and separate from any personal Claude subscription.
- **No migration steps required.** Existing scans, findings, and users carry over as-is.

## Get started

```bash
git clone https://github.com/barrytd/Pulse.git
cd Pulse
pip install -r requirements.txt
python main.py --api
```

Open http://localhost:8000 and upload any file from `samples/` to see Pulse light up. Full commit-level history is in [CHANGELOG.md](https://github.com/barrytd/Pulse/blob/main/CHANGELOG.md).
