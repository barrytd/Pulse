"""File-permission audit + hardening for the agent's bearer token file.

The agent's ``agent.yaml`` holds the long-lived `pa_…` bearer in plain
text. Treat it like an SSH private key: the filesystem ACL is the *only*
thing standing between a non-admin local user and the agent's
credentials. This module ships two pieces:

  1. :func:`audit_token_file_permissions` — read-only check that returns
     a structured verdict. The agent runtime calls it at startup so a
     misconfigured ACL surfaces in the journal instead of biting a
     customer in production. On non-Windows hosts this is a no-op
     (POSIX `chmod 600` semantics are different and the agent ships
     on Windows anyway).

  2. :func:`harden_token_file` — invoked by ``pulse-agent harden`` (and
     by the bundled Service installer when it lands). Strips ACL
     inheritance and grants Read+Write to SYSTEM + Full to
     Administrators only. Idempotent — re-running on an already-locked
     file is a no-op.

Both functions are tolerant of "the file doesn't exist yet" (just
returns a `not_found` verdict) so the agent can call them before
``enroll`` has written anything.
"""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from dataclasses import dataclass
from typing import Optional


log = logging.getLogger("pulse.agent.permissions")


@dataclass
class PermissionsVerdict:
    """Outcome of an ACL audit. ``status`` is the machine-readable code;
    ``message`` is the human-facing line the CLI / journal prints."""

    status: str           # ok | loose | not_windows | not_found | error
    message: str
    path: str

    @property
    def is_loose(self) -> bool:
        return self.status == "loose"


def audit_token_file_permissions(path: str) -> PermissionsVerdict:
    """Inspect ``path``'s ACL and return a verdict.

    Windows: runs ``icacls <path>`` and looks for the "Everyone" /
    "Users" / "Authenticated Users" principals — any of those means the
    bearer token is readable by non-admins.

    Non-Windows: returns ``status='not_windows'`` so the runtime knows
    to skip without flagging anything (POSIX semantics are different and
    Linux agents are dev-only).

    Missing file: returns ``status='not_found'`` so a freshly-installed
    agent (pre-enrollment) doesn't trigger a false warning.
    """
    if platform.system() != "Windows":
        return PermissionsVerdict(
            status="not_windows",
            message="permission audit skipped on non-Windows host",
            path=path,
        )
    if not path or not os.path.isfile(path):
        return PermissionsVerdict(
            status="not_found",
            message=f"token file not found: {path}",
            path=path,
        )

    try:
        # ``icacls`` is the canonical Windows ACL reader. Output is
        # multi-line with one principal per line. We don't try to parse
        # the full SDDL — we just check for the broad principals that
        # mean "any local user can read this".
        result = subprocess.run(
            ["icacls", path],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return PermissionsVerdict(
            status="error",
            message=f"icacls failed: {exc}",
            path=path,
        )

    text = (result.stdout or "") + "\n" + (result.stderr or "")
    # Principals that indicate "anyone with a local account can read".
    # Localized Windows installs use different display names (e.g.
    # "Jeder" on German, "Tout le monde" on French) — match the SID
    # form too as a belt-and-suspenders.
    LOOSE_PRINCIPALS = (
        "Everyone",
        "BUILTIN\\Users",
        "NT AUTHORITY\\Authenticated Users",
        "S-1-1-0",       # Everyone
        "S-1-5-32-545",  # BUILTIN\Users
        "S-1-5-11",      # Authenticated Users
    )
    for principal in LOOSE_PRINCIPALS:
        if principal in text:
            return PermissionsVerdict(
                status="loose",
                message=(
                    f"token file {path} is readable by {principal!r} — "
                    f"any local user can steal the agent's bearer. Run "
                    f"`pulse-agent harden` to fix."
                ),
                path=path,
            )
    return PermissionsVerdict(
        status="ok",
        message=f"token file ACL looks locked down",
        path=path,
    )


def log_audit_result(verdict: PermissionsVerdict) -> None:
    """Emit the right log level for a verdict. Called from the runtime
    so the warning surfaces in the journal even when the operator's not
    watching the CLI."""
    if verdict.status == "loose":
        log.warning(verdict.message)
    elif verdict.status == "error":
        log.warning("permission audit error: %s", verdict.message)
    else:
        # ok / not_found / not_windows — info-level, not noisy.
        log.info(verdict.message)


def harden_token_file(path: str) -> PermissionsVerdict:
    """Strip ACL inheritance and grant SYSTEM + Administrators only.

    Equivalent to the README's manual ``icacls`` snippet but bundled so
    a customer can run ``pulse-agent harden`` (or the Service installer
    can call it once at install time) without copy-pasting Windows
    commands.

    Returns a verdict so callers can branch on the result. Non-Windows
    hosts return ``status='not_windows'``; missing file returns
    ``status='not_found'``.
    """
    if platform.system() != "Windows":
        return PermissionsVerdict(
            status="not_windows",
            message="harden is Windows-only",
            path=path,
        )
    if not path or not os.path.isfile(path):
        return PermissionsVerdict(
            status="not_found",
            message=f"token file not found: {path}",
            path=path,
        )

    # 1. Remove inherited permissions. ``/inheritance:r`` strips all
    #    inherited ACEs (parents are typically C:\ProgramData which is
    #    readable by Authenticated Users).
    # 2. Grant SYSTEM Read+Write — the service runs as SYSTEM and needs
    #    to read the token + occasionally re-save the config (e.g. on
    #    auto-update).
    # 3. Grant Administrators Full — humans + the installer.
    # Order matters: icacls processes flags left-to-right and the
    # grants must come *after* the inheritance strip or they'd be
    # re-clobbered by the inherited ACEs from the parent dir.
    try:
        result = subprocess.run(
            [
                "icacls", path,
                "/inheritance:r",
                "/grant:r", "SYSTEM:(R,W)",
                "/grant:r", "Administrators:(F)",
            ],
            capture_output=True, text=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return PermissionsVerdict(
            status="error",
            message=f"icacls failed: {exc}",
            path=path,
        )

    if result.returncode != 0:
        return PermissionsVerdict(
            status="error",
            message=(
                f"icacls returned {result.returncode}: "
                f"{(result.stderr or result.stdout).strip()[:200]}"
            ),
            path=path,
        )
    return PermissionsVerdict(
        status="ok",
        message=f"token file ACL hardened: SYSTEM + Administrators only",
        path=path,
    )
