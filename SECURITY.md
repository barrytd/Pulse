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

Out of scope:

- Issues in upstream dependencies (report those upstream)
- Social engineering attacks
- Denial of service requiring local filesystem access (Pulse is a local tool)

---

## Safe harbor

Good-faith security research on Pulse is welcome. If you stay within the scope above and give me reasonable time to fix issues before public disclosure, I will not pursue any legal action.
