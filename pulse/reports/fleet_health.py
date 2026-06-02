"""Fleet Health Report — Phase 5 of the report catalog.

Security posture across every monitored host, ranked by risk. The
audience is the small-team admin asking "which boxes do I look at
this morning?". Stale hosts (no scan in N days) get their own
spotlight because forgotten endpoints are a real failure mode.

The data comes straight from ``database.get_fleet_summary`` —
this builder shapes that into report-friendly tiers and ranks.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from pulse import __version__ as _PULSE_VERSION


# ---------------------------------------------------------------------------
# Risk tier thresholds. Match the score-grade thresholds elsewhere so a
# host showing grade B on the dashboard reads as "Healthy" here, not
# "Moderate". Auditors notice when scales drift.
# ---------------------------------------------------------------------------

def _tier(score: Optional[int]) -> str:
    if score is None:
        return "Unknown"
    if score >= 90:
        return "Healthy"      # A
    if score >= 75:
        return "Healthy"      # B
    if score >= 60:
        return "Moderate"     # C
    if score >= 40:
        return "At Risk"      # D
    return "Critical"         # F


def _grade(score: Optional[int]) -> str:
    if score is None:
        return "?"
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


# ---------------------------------------------------------------------------
# Stale-host classification. Default: a host counts as stale if its
# newest scan is older than 7 days, since weekly is Pulse's recommended
# baseline cadence. Tunable by the caller — passing ``stale_days=None``
# disables the Stale Hosts section.
# ---------------------------------------------------------------------------

def _stale(host_row: Dict[str, Any], cutoff: Optional[datetime]) -> bool:
    if cutoff is None:
        return False
    last = host_row.get("last_scan_at")
    if not last:
        return True
    try:
        last_dt = datetime.strptime(str(last)[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    return last_dt < cutoff


def build_fleet_health(fleet_rows: List[Dict[str, Any]],
                       *,
                       scope_label: Optional[str] = None,
                       stale_days: int = 7,
                       org_name: Optional[str] = None) -> Dict[str, Any]:
    """Build the Fleet Health Report payload.

    Parameters
    ----------
    fleet_rows:
        Output of ``database.get_fleet_summary`` (one row per hostname).
    scope_label:
        Human string for the header. Defaults to "Across {N} hosts".
    stale_days:
        Hosts with no scan in this many days land in the Stale Hosts
        section. Pass ``None`` to skip the section.
    org_name:
        Organization name surfaced in the header. Falls back to
        ``"your organization"`` when not provided.
    """
    fleet_rows = list(fleet_rows or [])
    cutoff = (datetime.now() - timedelta(days=stale_days)
              if stale_days else None)

    # Annotate + sort by score asc (worst first), then last-scan desc.
    annotated: List[Dict[str, Any]] = []
    for h in fleet_rows:
        score = h.get("latest_score")
        annotated.append({
            "hostname":       (h.get("hostname") or "").strip(),
            "latest_score":   score,
            "latest_grade":   h.get("latest_grade") or _grade(score),
            "worst_severity": h.get("worst_severity") or "NONE",
            "scan_count":     int(h.get("scan_count") or 0),
            "total_findings": int(h.get("total_findings") or 0),
            "last_scan_at":   h.get("last_scan_at"),
            "tier":           _tier(score),
            "stale":          _stale(h, cutoff),
        })
    annotated.sort(
        key=lambda r: (
            r["latest_score"] if r["latest_score"] is not None else 999,
            r["last_scan_at"] or "",
        ),
    )

    tier_counter = Counter(r["tier"] for r in annotated)
    at_risk = [r for r in annotated
               if r["tier"] in ("At Risk", "Critical")]
    stale = [r for r in annotated if r["stale"]]

    if not scope_label:
        scope_label = (
            f"Across {len(annotated)} host{'s' if len(annotated) != 1 else ''}"
        )

    return {
        "header": {
            "title":         "Fleet Health Report",
            "scope":         scope_label,
            "host_count":    len(annotated),
            "stale_days":    stale_days,
            "generated_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "organization": org_name or "your organization",
        "summary": {
            "total_hosts":      len(annotated),
            "healthy":          tier_counter.get("Healthy",  0),
            "moderate":         tier_counter.get("Moderate", 0),
            "at_risk":          tier_counter.get("At Risk",  0),
            "critical":         tier_counter.get("Critical", 0),
            "unknown":          tier_counter.get("Unknown",  0),
            "at_risk_count":    len(at_risk),
            "stale_count":      len(stale),
        },
        "hosts":         annotated,
        "at_risk_hosts": at_risk[:25],
        "stale_hosts":   stale[:25],
        "footer": {
            "pulse_version": _PULSE_VERSION,
            "automated_note": (
                "Stale hosts are those without a scan in the last "
                f"{stale_days} day{'s' if stale_days != 1 else ''}. "
                "Run Pulse on those endpoints to bring them current."
            ),
        },
    }
