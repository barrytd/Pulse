# pulse/blocker.py
# ----------------
# IP block list — manages a Pulse-owned list of source IPs that get pushed
# into Windows Firewall as inbound deny rules via `netsh advfirewall`.
#
# LIFECYCLE
#   stage_ip()     adds a row to ip_block_list with status='pending'
#   push_pending() finds every pending row, runs netsh to create the rule,
#                  flips status to 'active', stamps pushed_at + rule_name
#   unblock_ip()   deletes the netsh rule (if active) and removes the row
#   list_blocks()  returns every row for display
#
# SAFETY
#   - RFC1918 private IPs, loopback, link-local, multicast are rejected so
#     a typo doesn't lock an operator out of their own network.
#   - The local machine's own IPs are rejected — blocking yourself is a
#     fast way to trap a remote session.
#   - Duplicates are rejected — the UNIQUE constraint on ip_address is the
#     database-level backstop; stage_ip() checks first and returns a
#     friendly error rather than letting sqlite3.IntegrityError bubble up.
#   - Every netsh rule name begins with "Pulse-managed:" so a teardown of
#     Pulse-owned rules can never touch a user-authored firewall rule.
#   - Non-Windows hosts can still stage / list / audit, but push is a no-op
#     that returns a clear message so the CLI can say "skipped on Linux".
#
# ADMIN PRIVILEGE
#   netsh requires elevation. _is_admin() checks ctypes.windll.shell32
#   first (real Windows), then falls back to os.geteuid() == 0 so tests
#   can exercise the path on POSIX. If a push is attempted without admin,
#   the netsh call will fail with exit 1 and we surface the message.

from __future__ import annotations

import ipaddress
import os
import platform
import socket
import subprocess
from datetime import datetime
from typing import Optional

from pulse.database import _connect


# Prefix every netsh rule we create so a listing / teardown can trivially
# distinguish Pulse-managed rules from user-authored ones. Any rule name
# outside this prefix is NEVER modified by Pulse.
RULE_PREFIX = "Pulse-managed:"


# ---------------------------------------------------------------------------
# Platform / privilege helpers
# ---------------------------------------------------------------------------

def is_windows() -> bool:
    return platform.system() == "Windows"


def _is_admin() -> bool:
    """Return True if the current process has admin / root rights.

    Windows path uses ctypes to hit shell32.IsUserAnAdmin(). POSIX path
    falls back to os.geteuid() == 0 so test runners and Linux CI still
    hit a realistic branch — push_pending() uses this as a pre-check so
    a non-elevated Windows user gets a friendly error before netsh runs
    and produces opaque output.
    """
    if is_windows():
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0   # type: ignore[attr-defined]
    except AttributeError:
        return False


# ---------------------------------------------------------------------------
# IP safety checks
# ---------------------------------------------------------------------------

def _validate_ip(ip: str, allow_private: bool = False) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse + validate, raising ValueError with a human-readable message.

    Two tiers:
      - Hard refusals (loopback, link-local, multicast, unspecified) are
        always rejected — even `allow_private=True` cannot override them.
        Blocking these never protects against an attacker and only harms
        the host's own networking.
      - Soft refusal (private / RFC1918) is the insider-threat case. By
        default we reject to prevent typos and self-lockouts. Pass
        `allow_private=True` (the API/CLI "force" path) to accept it;
        callers must independently confirm with the operator first.
    """
    raw = (ip or "").strip()
    if not raw:
        raise ValueError("IP address is required")
    try:
        parsed = ipaddress.ip_address(raw)
    except ValueError:
        raise ValueError(f"'{raw}' is not a valid IP address") from None
    # Hard refusals — never overridable.
    if parsed.is_loopback:
        raise ValueError("Cannot block a loopback address (127.0.0.0/8)")
    if parsed.is_link_local:
        raise ValueError("Cannot block link-local addresses (169.254.x)")
    if parsed.is_multicast:
        raise ValueError("Cannot block multicast addresses")
    if parsed.is_unspecified:
        raise ValueError("Cannot block the unspecified address (0.0.0.0)")
    # Soft refusal — private / RFC1918. Force path (allow_private=True)
    # bypasses this for the insider-threat / compromised-laptop case.
    if parsed.is_private and not allow_private:
        raise ValueError("Cannot block private / RFC1918 addresses (10.x, 172.16-31.x, 192.168.x)")
    return parsed


def _get_local_ips() -> set[str]:
    """Best-effort list of IPs bound to this machine. Used to reject
    attempts to block yourself, which would lock an operator out of a
    remote session. Wrapped in try/except because getaddrinfo can throw
    on hosts with no DNS config.
    """
    ips: set[str] = set()
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addr = info[4][0]
            if addr:
                ips.add(addr)
    except Exception:
        pass
    return ips


# ---------------------------------------------------------------------------
# netsh wrappers — every subprocess call funnels through these so tests
# can monkeypatch subprocess.run in one place.
# ---------------------------------------------------------------------------

def _rule_name_for(ip: str) -> str:
    return f"{RULE_PREFIX} Block {ip}"


def _netsh_add_rule(ip: str, rule_name: str) -> tuple[bool, str]:
    """Invoke netsh to add an inbound deny rule. Returns (ok, message).

    Does not raise — callers want a structured pair so the CLI and API can
    surface the error without a stack trace. If netsh itself is missing
    (non-Windows or stripped image), we catch FileNotFoundError.
    """
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
        "enable=yes",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return False, "netsh was not found on this system (non-Windows?)"
    if result.returncode != 0:
        msg = (result.stderr or result.stdout or "").strip() or f"netsh exited {result.returncode}"
        if "access is denied" in msg.lower() or "elevation" in msg.lower():
            msg += " — try running Pulse as administrator."
        return False, msg
    return True, "ok"


def _netsh_delete_rule(rule_name: str) -> tuple[bool, str]:
    """Delete a previously-created rule by name. Safe to call even if
    the rule is already gone — netsh returns non-zero but we report the
    failure back to the caller so a listing-cleanup routine can decide
    whether to proceed."""
    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return False, "netsh was not found on this system (non-Windows?)"
    if result.returncode != 0:
        msg = (result.stderr or result.stdout or "").strip() or f"netsh exited {result.returncode}"
        return False, msg
    return True, "ok"


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def log_audit(
    db_path: str,
    action: str,
    ip: Optional[str] = None,
    comment: Optional[str] = None,
    source: str = "cli",
    user: Optional[str] = None,
    detail: Optional[str] = None,
) -> None:
    """Record one action in the audit_log table. Never raises — auditing
    should not break the action that triggered it."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with _connect(db_path) as conn:
            conn.execute(
                """INSERT INTO audit_log (ts, action, ip_address, comment, source, user, detail)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (ts, action, ip, comment, source, user, detail),
            )
    except Exception:
        pass


def get_audit_log(db_path: str, limit: int = 200) -> list[dict]:
    """Return audit rows newest-first. Used by the CLI and the dashboard
    Audit page.

    Joins `users.display_name` on the email stored in `audit_log.user` so
    the dashboard can render a friendly name where one is set, without a
    second lookup per row.
    """
    try:
        with _connect(db_path) as conn:
            cursor = conn.execute(
                """SELECT a.id, a.ts, a.action, a.ip_address, a.comment, a.source,
                          a.user, a.detail,
                          u.display_name AS user_display_name,
                          u.role        AS user_role
                   FROM audit_log a
                   LEFT JOIN users u ON u.email = a.user
                   ORDER BY a.id DESC
                   LIMIT ?""",
                (int(limit),),
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Public API — stage / list / push / unblock
# ---------------------------------------------------------------------------

def stage_ip(
    db_path: str,
    ip: str,
    comment: Optional[str] = None,
    finding_id: Optional[int] = None,
    source: str = "cli",
    user: Optional[str] = None,
    force: bool = False,
) -> dict:
    """Stage an IP for blocking. Does NOT touch the firewall — push_pending()
    or a --confirm flag does that.

    `force=True` relaxes the RFC1918 refusal for the insider-threat case
    (compromised internal device, malicious employee laptop). Hard
    refusals — loopback, link-local, multicast, self-block — still apply
    and cannot be bypassed. Forced stages are tagged in the audit log as
    `stage_forced` so compliance reviews can find them.

    Returns a dict: {ok: bool, message: str, row: dict | None, forced: bool}.
    """
    try:
        parsed = _validate_ip(ip, allow_private=force)
    except ValueError as e:
        return {"ok": False, "message": str(e), "row": None, "forced": False}

    canonical = str(parsed)
    if canonical in _get_local_ips():
        return {
            "ok": False,
            "message": f"'{canonical}' looks like one of this machine's own IPs — refusing to self-block.",
            "row": None,
            "forced": False,
        }

    # Record whether this stage used the force path so the API/UI can
    # label it clearly and the audit row captures the override.
    was_forced = bool(force and parsed.is_private)

    added_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_comment = (comment or "").strip() or None

    try:
        with _connect(db_path) as conn:
            existing = conn.execute(
                "SELECT id, status FROM ip_block_list WHERE ip_address = ?",
                (canonical,),
            ).fetchone()
            if existing:
                return {
                    "ok": False,
                    "message": f"{canonical} is already {existing[1]} in the block list",
                    "row": None,
                    "forced": False,
                }
            cursor = conn.execute(
                """INSERT INTO ip_block_list
                   (ip_address, comment, status, added_at, finding_id)
                   VALUES (?, ?, 'pending', ?, ?)""",
                (canonical, clean_comment, added_at, finding_id),
            )
            new_id = cursor.lastrowid
            row = conn.execute(
                """SELECT id, ip_address, comment, status, added_at,
                          pushed_at, rule_name, finding_id
                   FROM ip_block_list WHERE id = ?""",
                (new_id,),
            ).fetchone()
            cols = ("id", "ip_address", "comment", "status", "added_at",
                    "pushed_at", "rule_name", "finding_id")
            row_dict = dict(zip(cols, row))
    except Exception as e:
        return {"ok": False, "message": f"Database error: {e}", "row": None, "forced": False}

    if was_forced:
        log_audit(
            db_path,
            "stage_forced",
            canonical,
            clean_comment,
            source=source,
            user=user,
            detail="RFC1918 override — analyst confirmed",
        )
        msg = f"Staged {canonical} for blocking (forced override — internal IP)"
    else:
        log_audit(db_path, "stage", canonical, clean_comment, source=source, user=user)
        msg = f"Staged {canonical} for blocking"
    return {"ok": True, "message": msg, "row": row_dict, "forced": was_forced}


def list_blocks(db_path: str) -> list[dict]:
    """Return every row in ip_block_list, newest-first."""
    try:
        with _connect(db_path) as conn:
            cursor = conn.execute(
                """SELECT id, ip_address, comment, status, added_at,
                          pushed_at, rule_name, finding_id
                   FROM ip_block_list
                   ORDER BY id DESC"""
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception:
        return []


def push_pending(db_path: str, source: str = "cli", user: Optional[str] = None) -> dict:
    """Push every pending row to Windows Firewall.

    Returns {ok, pushed, skipped, failures, message}. The CLI prints the
    summary; the dashboard toasts it. Non-Windows platforms short-circuit
    with ok=False so the caller knows nothing was touched.
    """
    pending = [r for r in list_blocks(db_path) if r["status"] == "pending"]
    if not pending:
        return {"ok": True, "pushed": 0, "skipped": 0, "failures": [], "message": "No pending entries to push."}

    if not is_windows():
        return {
            "ok": False,
            "pushed": 0,
            "skipped": len(pending),
            "failures": [],
            "message": "Push is only supported on Windows. Rows remain pending.",
        }

    if not _is_admin():
        return {
            "ok": False,
            "pushed": 0,
            "skipped": len(pending),
            "failures": [],
            "message": "Administrator privileges are required to modify Windows Firewall. Re-run Pulse as admin.",
        }

    pushed = 0
    failures: list[dict] = []
    for row in pending:
        ip = row["ip_address"]
        rule_name = _rule_name_for(ip)
        ok, msg = _netsh_add_rule(ip, rule_name)
        if not ok:
            failures.append({"ip": ip, "error": msg})
            log_audit(db_path, "push_failed", ip, row.get("comment"), source=source, user=user, detail=msg)
            continue
        pushed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with _connect(db_path) as conn:
                conn.execute(
                    """UPDATE ip_block_list
                       SET status = 'active', pushed_at = ?, rule_name = ?
                       WHERE id = ?""",
                    (pushed_at, rule_name, int(row["id"])),
                )
        except Exception as e:
            failures.append({"ip": ip, "error": f"DB update failed: {e}"})
            continue
        pushed += 1
        log_audit(db_path, "push", ip, row.get("comment"), source=source, user=user, detail=rule_name)

    ok = len(failures) == 0
    return {
        "ok": ok,
        "pushed": pushed,
        "skipped": 0,
        "failures": failures,
        "message": (
            f"Pushed {pushed} rule(s)"
            + (f"; {len(failures)} failed" if failures else "")
        ),
    }


def unblock_ip(db_path: str, ip: str, source: str = "cli", user: Optional[str] = None) -> dict:
    """Remove an IP from the block list. If the row is 'active', also
    delete the matching netsh rule. Returns {ok, message}.

    Private IPs are accepted here — if a forced-block row exists for a
    RFC1918 address, we still want to be able to remove it. Hard refusals
    (loopback, link-local, multicast, unspecified) still apply."""
    try:
        parsed = _validate_ip(ip, allow_private=True)
    except ValueError as e:
        return {"ok": False, "message": str(e)}
    canonical = str(parsed)

    with _connect(db_path) as conn:
        row = conn.execute(
            """SELECT id, status, rule_name, comment
               FROM ip_block_list WHERE ip_address = ?""",
            (canonical,),
        ).fetchone()

    if not row:
        return {"ok": False, "message": f"{canonical} is not in the block list"}

    _id, status, rule_name, comment = row

    if status == "active":
        if not is_windows():
            return {
                "ok": False,
                "message": (
                    f"Row for {canonical} is marked active but this host isn't Windows — "
                    "refusing to remove the DB row while the firewall rule might still exist."
                ),
            }
        if not _is_admin():
            return {
                "ok": False,
                "message": "Administrator privileges are required to remove the firewall rule.",
            }
        ok, msg = _netsh_delete_rule(rule_name or _rule_name_for(canonical))
        if not ok:
            log_audit(db_path, "unblock_failed", canonical, comment, source=source, user=user, detail=msg)
            return {"ok": False, "message": f"netsh failed: {msg}"}

    try:
        with _connect(db_path) as conn:
            conn.execute("DELETE FROM ip_block_list WHERE id = ?", (int(_id),))
    except Exception as e:
        return {"ok": False, "message": f"Database error: {e}"}

    log_audit(db_path, "unblock", canonical, comment, source=source, user=user)
    return {"ok": True, "message": f"Removed {canonical} from the block list"}
