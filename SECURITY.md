# Security Policy

Pulse is a security tool, so security issues in Pulse itself are taken seriously. Thank you for helping keep it safe.

---

## Supported versions

Only the latest release on `main` receives security fixes. Older tagged versions are frozen.

| Version | Supported |
|---|---|
| `main` (latest) | Yes |
| Older tags | No |

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Instead, email details to the maintainer by opening a [GitHub security advisory](https://github.com/barrytd/Pulse/security/advisories/new). This creates a private channel where we can discuss the issue before any public disclosure.

Please include:

- A clear description of the vulnerability
- Steps to reproduce (a minimal proof of concept is ideal)
- The version or commit hash you tested against
- The impact you think it has

---

## What to expect

- **Within 72 hours** — acknowledgement that your report was received
- **Within 7 days** — initial assessment of severity and scope
- **Within 30 days** — a fix, a mitigation, or a clear timeline for one

If a fix ships, you will be credited in the release notes unless you ask to remain anonymous.

---

## Scope

Security issues I am interested in:

- Code execution via malicious `.evtx` file parsing
- Path traversal or file write issues when handling log folders or output paths
- Command injection via wevtutil argument handling
- Credential exposure in reports, logs, or the database
- SMTP credential handling issues in the email module
- Any way to trick Pulse into reporting incorrect or missing findings
- Cross-tenant data access in hosted multi-tenant mode (`PULSE_HOSTED_SIGNUP=1`) — one organization's admin reading or managing another organization's scans, findings, users, playbooks, or playbook runs. Org admins are scoped to their own organization; only the env-only `PULSE_SUPERADMIN_EMAILS` allowlist gets cross-tenant scope.
- Any way to make a playbook run a response action (block an IP, post a message) **without** a person approving it, run it twice from one approval, or run different values from the ones the approver was shown.
- Escaping the playbook expression language (conditions / `{{ placeholders }}`) to run code on the server.
- Getting a connector to send a private IP, an internal hostname, or data to a host other than its configured provider (SSRF).
- API keys (AbuseIPDB, VirusTotal, GreyNoise, OTX) or webhook URLs leaking to the browser, logs, or reports.

Out of scope:

- Issues in upstream dependencies (report those upstream)
- Social engineering attacks
- Denial of service requiring local filesystem access (Pulse is a local tool)

---

## Playbook approval model

Playbooks ([`pulse/soar/`](pulse/soar/)) react to new findings automatically, but they can't act on their own:

- **Lookups run by themselves; responses never do.** Every response step (a firewall block, a Slack/Discord post) pauses the run until a person approves it. A playbook that sets `requires_approval: false` on a response step is rejected when it's imported. There is no fully automatic mode.
- **Who can approve:** managers and admins only, and only for their own organization's runs. Approving requires the user's **security PIN** step-up when they have one set (the same gate as the dashboard's Block button). Denying stops the rest of the run.
- **What runs is what was shown.** The step runs exactly the inputs the approver saw. Each approval is single-use (a conditional database update), so two people approving at once can't run it twice. Runs snapshot their playbook, so editing a playbook can't change a step that's already waiting.
- **No code execution.** Conditions and `{{ placeholders }}` are parsed with Python's `ast` and walked against a whitelist (and / or / not, comparisons, dotted names, literals). Calls, subscripts, arithmetic and dunder access are rejected at import. Nothing is ever passed to `eval`.
- **Response connectors reuse existing safeguards.** A playbook block goes through the same blocker as the Block button (loopback, link-local, multicast, self-block and private addresses refused) and pushes only its own IP. A playbook post can only reach the Slack/Discord webhooks configured in Settings; a recipe can't supply a URL.
- **Audit trail.** Playbook changes, runs, approvals, denials and executed actions are written to the audit log, tagged with the organization.

---

## Third-party data flow

Pulse runs locally. Data leaves your environment only through features an administrator turns on.

### Threat-intel lookups (connectors)

Each outside lookup is **bring-your-own-key** and sends nothing until its key is set in Settings or the environment (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `GREYNOISE_API_KEY`, `OTX_API_KEY`). Pulse never ships a key.

| Connector | Sent to | What's sent |
|---|---|---|
| AbuseIPDB | api.abuseipdb.com | a public IP address |
| VirusTotal | www.virustotal.com | a public IP, a public domain, or a file hash |
| GreyNoise | api.greynoise.io | a public IP address |
| AlienVault OTX | otx.alienvault.com | a public IP, a public domain, or a file hash |
| Whois | IANA, then the domain's registry / registrar (RDAP or port 43) | a public domain name |
| DNS | the Pulse host's own resolver | a public domain name |
| GeoIP | **nothing:** reads a local `.mmdb` file (the bundled DB-IP country database, or one you supply) | — |

Safeguards:

- **Private, loopback, link-local, reserved and documentation IP ranges are never sent**, and neither are internal names (`.local`, `.corp`, `.lan`, `.internal`, …). The Investigate panel lists anything it held back as "Not sent anywhere".
- **Indicators are chosen on the server** from the stored finding, not supplied by the browser.
- **Keys stay server-side.** `GET /api/config` only reports whether each key is set; the value never reaches the browser.
- **Quotas are respected.** Every answer is cached, and each provider is held to its free-tier limits, so a burst of findings can't exhaust a key. Failures show "no intel" instead of retrying.
- Investigations are written to the audit log with the indicators that were sent.
- VirusTotal's free public API is for non-commercial use; that choice stays with the key's owner.

### The Pip AI assistant

The optional Security Buddy ("Pip") is off until an administrator sets an `ANTHROPIC_API_KEY`. When a user asks Pip a question, the following is sent to **Anthropic's Claude API** to generate the answer:

- The user's typed question and the recent chat history in that panel.
- If a finding is open, a short summary of it (rule name, severity, MITRE technique, hostname, and the plain-language description) — this can include event-log-derived text.

Safeguards in place:

- The API key is read **server-side only** (`ANTHROPIC_API_KEY` env var) and is never exposed to the browser. The browser talks only to Pulse's own `POST /api/buddy/ask`.
- Pip is **read-only**: no tools, no function calling. It cannot scan, block, or change anything in Pulse.
- Any finding/event text is treated as **untrusted data** — it is fenced in an `<untrusted_data>` block with a system-prompt instruction to never follow instructions embedded in log data (prompt-injection defense).
- Model output is **HTML-escaped** before rendering.
- The chat panel **discloses** that questions are sent to Anthropic.

### Alerts

Email (SMTP) and Slack/Discord webhook alerts send finding summaries to the destinations an administrator configures.

If you do not want any data leaving your environment, leave `ANTHROPIC_API_KEY` and the threat-intel keys unset, don't configure alerts, and don't click Investigate (its Whois/DNS lookups need no key). Pulse then runs entirely locally; GeoIP reads a local file.

---

## Safe harbor

Good-faith security research on Pulse is welcome. If you stay within the scope above and give me reasonable time to fix issues before public disclosure, I will not pursue any legal action.
