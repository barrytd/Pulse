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
- Cross-tenant data access in hosted multi-tenant mode (`PULSE_HOSTED_SIGNUP=1`) — one organization's admin reading or managing another organization's scans, findings, or users. Org admins are scoped to their own organization; only the env-only `PULSE_SUPERADMIN_EMAILS` allowlist gets cross-tenant scope.

Out of scope:

- Issues in upstream dependencies (report those upstream)
- Social engineering attacks
- Denial of service requiring local filesystem access (Pulse is a local tool)

---

## Third-party data flow — the Pip AI assistant

Pulse's optional Security Buddy ("Pip") is the only feature that sends data to a third party, and only when an administrator opts in by setting an `ANTHROPIC_API_KEY`. When a user asks Pip a question, the following is sent to **Anthropic's Claude API** to generate the answer:

- The user's typed question and the recent chat history in that panel.
- If a finding is open, a short summary of it (rule name, severity, MITRE technique, hostname, and the plain-language description) — this can include event-log-derived text.

Safeguards in place:

- The API key is read **server-side only** (`ANTHROPIC_API_KEY` env var) and is never exposed to the browser. The browser talks only to Pulse's own `POST /api/buddy/ask`.
- Pip is **read-only**: no tools, no function calling. It cannot scan, block, or change anything in Pulse.
- Any finding/event text is treated as **untrusted data** — it is fenced in an `<untrusted_data>` block with a system-prompt instruction to never follow instructions embedded in log data (prompt-injection defense).
- Model output is **HTML-escaped** before rendering.
- The chat panel **discloses** that questions are sent to Anthropic.

If you do not want any data leaving your environment, leave `ANTHROPIC_API_KEY` unset — Pip stays off and Pulse runs entirely locally.

---

## Safe harbor

Good-faith security research on Pulse is welcome. If you stay within the scope above and give me reasonable time to fix issues before public disclosure, I will not pursue any legal action.
