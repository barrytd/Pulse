"""Local-host scan path for the Pulse Agent.

Reuses the same Windows-event-log parser and detection rules as the
server-side ``scan_system`` (Sprint 6). The difference is the output:
``scan_system`` persists to SQLite and dispatches alerts; the agent
just returns the findings + a small ``scan_meta`` dict so the runtime
can POST them to the configured Pulse server.

If the agent is ever installed on a non-Windows host (CI, Linux dev
sandbox), this module raises ``RuntimeError`` — the W3C-style winevtutil
queries simply don't work elsewhere. The transport + runtime modules
themselves are platform-agnostic so the agent test suite can exercise
them without touching the Windows-only code path.
"""

from __future__ import annotations

import os
import platform
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from pulse.core.detections import run_all_detections
from pulse.core.parser import parse_evtx
from pulse.monitor.system_scan import (
    DEFAULT_SYSTEM_LOGS,
    SYSTEM_LOGS_DIR,
    _resolve_log_paths,
    is_supported_platform,
)
from pulse.reports.reporter import calculate_score_from_findings
from pulse.whitelist import filter_whitelist


def scan_for_findings(
    *,
    days: int = 1,
    log_dir: Optional[str] = None,
    channels: Optional[List[str]] = None,
    whitelist: Optional[dict] = None,
) -> Tuple[dict, list]:
    """Parse the local Windows event logs and run every enabled
    detection. Returns ``(scan_meta, findings)`` where ``scan_meta`` is
    the dict to attach to ``POST /api/agent/findings`` and ``findings``
    is the list the same endpoint expects in its body.

    Parameters mirror ``scan_system`` minus the database / alert plumbing:

      days:      Lookback window. Defaults to 1.
      log_dir:   Override the Windows logs folder. Defaults to the
                 system path; tests pass a temp folder.
      channels:  Subset of channel names to scan. Empty = the standard
                 Security/System/Application set.
      whitelist: ``{accounts: [], services: [], ips: [], rules: []}``
                 dict — same shape as ``pulse.yaml``'s whitelist
                 section. Optional; if omitted, no suppression runs.
    """
    if not is_supported_platform():
        raise RuntimeError(
            "Pulse Agent scan requires Windows — current platform: "
            + platform.system()
        )

    base = log_dir or SYSTEM_LOGS_DIR
    if not os.path.isdir(base):
        raise FileNotFoundError(f"Windows event log folder not found: {base}")

    # wevtutil expects UTC on the lookback bound. Match scan_system.
    since = None
    if days and days > 0:
        since = datetime.now(timezone.utc) - timedelta(days=days)

    paths = _resolve_log_paths(log_dir=base,
                               names=channels or DEFAULT_SYSTEM_LOGS)

    started = datetime.now()
    all_events: list = []
    files_scanned = 0
    skipped: list = []
    for path in paths:
        try:
            events = parse_evtx(path, since=since)
        except Exception:
            # parse_evtx already swallows its own errors; this catch
            # protects against the surrounding glue (locked files,
            # permission errors). One bad channel never breaks the run.
            skipped.append(os.path.basename(path))
            continue
        files_scanned += 1
        all_events.extend(events or [])

    findings = run_all_detections(all_events)
    if whitelist:
        findings = filter_whitelist(findings, whitelist)

    score_data = calculate_score_from_findings(findings)
    finished = datetime.now()
    duration_sec = max(0, int((finished - started).total_seconds()))

    scan_meta = {
        "hostname":      platform.node(),
        "scope":         f"Pulse Agent — last {days} day{'' if days == 1 else 's'}",
        "files_scanned": files_scanned,
        "total_events":  len(all_events),
        "duration_sec":  duration_sec,
        "skipped":       skipped,
        # The server re-computes its own score from the findings, but
        # we include ours so a payload trace makes sense at a glance.
        "score":         score_data.get("score"),
    }
    return scan_meta, findings
