# pulse/system_scan.py
# ---------------------
# One-shot scan of the local Windows event-log folder.
#
# WHAT THIS DOES
#   Reads .evtx files straight out of C:\Windows\System32\winevt\Logs\,
#   parses each one with a time-window filter, runs every detection rule,
#   applies the configured whitelist, saves the scan to SQLite, and fires
#   threshold alerts. No file upload, no browser drag-and-drop.
#
# WHY IT IS WINDOWS-ONLY
#   The winevt folder and the wevtutil fast path do not exist on Linux
#   or macOS. Callers MUST check `is_supported_platform()` before calling
#   `scan_system()`; the function itself also guards but surfacing a clear
#   error earlier gives the UI a cleaner place to show the message.

import ctypes
import os
import platform
from datetime import datetime, timedelta, timezone

# Cached once at import. Admin status doesn't change within a process, and
# calling IsUserAnAdmin() on every /api/health tick would be wasteful.
_IS_ADMIN = None


def is_admin():
    """Return True if the current process has Windows admin privileges.

    Returns False on non-Windows hosts and when the ctypes call fails
    (very old Windows releases, sandboxed environments, etc.). Result
    is memoized — admin status cannot change without a process restart.
    """
    global _IS_ADMIN
    if _IS_ADMIN is not None:
        return _IS_ADMIN
    if platform.system() != "Windows":
        _IS_ADMIN = False
        return False
    try:
        _IS_ADMIN = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        _IS_ADMIN = False
    return _IS_ADMIN

from pulse.database import init_db, save_scan
from pulse.detections import run_all_detections
from pulse.emailer import dispatch_alerts
from pulse.parser import parse_evtx
from pulse.remediation import attach_remediation
from pulse.reporter import calculate_score_from_findings
from pulse.whitelist import filter_whitelist


# The three main channels that Pulse has rules for. We scan only these by
# default because the winevt folder contains hundreds of provider logs and
# walking all of them would take minutes without surfacing anything new —
# every relevant event ID lives in one of these three files.
DEFAULT_SYSTEM_LOGS = ("Security.evtx", "System.evtx", "Application.evtx")

SYSTEM_LOGS_DIR = r"C:\Windows\System32\winevt\Logs"


def is_supported_platform():
    """True on Windows, False everywhere else."""
    return platform.system() == "Windows"


def _scope_label(days):
    """Human-readable scope for a system scan with a lookback window.

    Maps the common dropdown choices to the labels the UI shows
    ("Last 24 hours", "Last 7 days", ...) and falls back to a generic
    "Last N days" for custom ranges.
    """
    if days is None or days <= 0:
        return "All time"
    if days == 1:
        return "Last 24 hours"
    return "Last {} days".format(int(days))


def _resolve_log_paths(log_dir=None, names=DEFAULT_SYSTEM_LOGS):
    """Return the absolute paths of the default system logs that actually
    exist on disk. Missing files are silently skipped so a machine without
    Application.evtx (rare but possible) still produces a useful scan."""
    base = log_dir or SYSTEM_LOGS_DIR
    paths = []
    for name in names:
        p = os.path.join(base, name)
        if os.path.isfile(p):
            paths.append(p)
    return paths


def scan_system(
    db_path,
    config,
    days=1,
    send_alerts=True,
    log_dir=None,
    progress=None,
):
    """Run a full system scan and persist the results.

    Parameters:
        db_path (str):   SQLite path to save the scan into.
        config (dict):   Loaded pulse.yaml — used for whitelist + alert routing.
        days (int):      Only parse events from the last N days.
        send_alerts (bool): If True, fire configured email/webhook alerts.
        log_dir (str):   Override the Windows log directory (tests pass a tmp).
        progress (callable): Optional progress callback, invoked with
                         (phase, info_dict). Phases: "start", "file", "done".

    Returns:
        dict: {scan_id, total_events, total_findings, score, score_label,
               grade, severity_counts, findings, alert, files_scanned,
               skipped_files}.

    Raises:
        RuntimeError: If not running on Windows.
        FileNotFoundError: If the winevt folder is missing entirely.
    """
    if not is_supported_platform():
        raise RuntimeError("System scan requires Windows")

    base = log_dir or SYSTEM_LOGS_DIR
    if not os.path.isdir(base):
        raise FileNotFoundError(
            f"Windows event log folder not found: {base}"
        )

    since = None
    if days and days > 0:
        # Use UTC because wevtutil expects UTC timestamps on the filter.
        since = datetime.now(timezone.utc) - timedelta(days=days)

    paths = _resolve_log_paths(log_dir=base)
    if progress:
        progress("start", {"files": [os.path.basename(p) for p in paths], "days": days})

    all_events = []
    skipped = []
    files_scanned = 0
    for path in paths:
        name = os.path.basename(path)
        if progress:
            progress("file", {"file": name, "status": "parsing"})
        try:
            events = parse_evtx(path, since=since)
        except Exception:
            # parse_evtx swallows its own errors, but protect against anything
            # the fallback path might raise (locked files, etc.). Skipping one
            # file should never break the whole scan.
            skipped.append(name)
            if progress:
                progress("file", {"file": name, "status": "skipped"})
            continue
        files_scanned += 1
        all_events.extend(events or [])
        if progress:
            progress("file", {
                "file": name,
                "status": "done",
                "events": len(events or []),
            })

    findings = run_all_detections(all_events)
    whitelist = (config.get("whitelist") or {}) if config else {}
    findings = filter_whitelist(findings, whitelist)

    score_data = calculate_score_from_findings(findings)

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    scan_stats = {
        "total_events": len(all_events),
        "files_scanned": files_scanned,
    }
    init_db(db_path)
    scan_id = save_scan(
        db_path,
        findings,
        scan_stats=scan_stats,
        score=score_data["score"],
        score_label=score_data["label"],
        filename="System Scan",
        scope=_scope_label(days),
    )

    alert_summary = {"enabled": False, "sent": False}
    if send_alerts and findings:
        try:
            alert_summary = dispatch_alerts(
                db_path,
                findings,
                (config or {}).get("email") or {},
                (config or {}).get("alerts") or {},
                (config or {}).get("webhook") or {},
            )
        except Exception:
            # Never let a broken SMTP or webhook kill the scan result.
            pass

    result = {
        "scan_id": scan_id,
        "total_events": len(all_events),
        "total_findings": len(findings),
        "score": score_data["score"],
        "score_label": score_data["label"],
        "grade": score_data["grade"],
        "severity_counts": sev_counts,
        "findings": attach_remediation(findings),
        "alert": alert_summary,
        "files_scanned": files_scanned,
        "skipped_files": skipped,
    }
    if progress:
        progress("done", {
            "scan_id": scan_id,
            "total_findings": len(findings),
            "score": score_data["score"],
        })
    return result
