"""Board-Ready Posture Report — Phase 5 of the report catalog.

Quarterly-style report for the board. Reuses the Executive Summary
narrative + the Compliance + Fleet builders so the data layer is
mostly free.

The audience: a CEO / board reading the printed PDF in a meeting.
Minimal jargon. Big numbers. Big charts.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from pulse import __version__ as _PULSE_VERSION
from pulse.reports.compliance import build_nist_csf, build_iso_27001
from pulse.reports.executive_summary import (
    _grade_for_score, GRADE_INTERPRETATION, _is_resolved,
)
from pulse.reports.fleet_health import build_fleet_health


def _score_trend(scans: List[Dict[str, Any]],
                  *, buckets: int = 10) -> List[Dict[str, Any]]:
    """Sample the score history into evenly-spaced buckets for the
    trend chart. We avoid using a chart library so the renderers can
    produce print-safe inline SVG."""
    if not scans:
        return []
    sortable = []
    for s in scans:
        ts = s.get("scanned_at")
        score = s.get("score")
        if not ts or score is None:
            continue
        try:
            t = datetime.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        sortable.append((t, int(score)))
    sortable.sort()
    if not sortable:
        return []
    # If the data fits in fewer than `buckets` points, just return each.
    if len(sortable) <= buckets:
        return [
            {"timestamp": t.strftime("%Y-%m-%d"), "score": s}
            for t, s in sortable
        ]
    start, end = sortable[0][0], sortable[-1][0]
    span = (end - start).total_seconds() or 1
    bucket_size = span / buckets
    sampled: List[Dict[str, Any]] = []
    j = 0
    for i in range(buckets):
        bucket_end = start + timedelta(seconds=bucket_size * (i + 1))
        group_scores = []
        while j < len(sortable) and sortable[j][0] <= bucket_end:
            group_scores.append(sortable[j][1])
            j += 1
        if group_scores:
            sampled.append({
                "timestamp": bucket_end.strftime("%Y-%m-%d"),
                "score":     round(sum(group_scores) / len(group_scores)),
            })
    return sampled


def build_board_ready(findings: List[Dict[str, Any]],
                       scans: List[Dict[str, Any]],
                       *,
                       fleet_rows: Optional[List[Dict[str, Any]]] = None,
                       period_days: int = 90,
                       scope_label: Optional[str] = None,
                       prev_findings: Optional[List[Dict[str, Any]]] = None,
                       prev_scans: Optional[List[Dict[str, Any]]] = None,
                       disabled_rules: Optional[List[str]] = None,
                       org_name: Optional[str] = None,
                       ) -> Dict[str, Any]:
    """Build the Board-Ready Posture payload."""
    findings = list(findings or [])
    scans    = list(scans or [])
    fleet_rows = list(fleet_rows or [])
    prev_findings = list(prev_findings or [])
    prev_scans = list(prev_scans or [])

    # Score average + grade.
    scored = [int(s["score"]) for s in scans if s.get("score") is not None]
    score = round(sum(scored) / len(scored)) if scored else None
    grade = _grade_for_score(score)
    prev_scored = [int(s["score"]) for s in prev_scans
                   if s.get("score") is not None]
    prev_score = (round(sum(prev_scored) / len(prev_scored))
                  if prev_scored else None)

    if prev_score is None or score is None:
        trend_direction = "first_period"
        trend_delta = None
    else:
        trend_delta = score - prev_score
        if trend_delta >= 5:
            trend_direction = "improved"
        elif trend_delta <= -5:
            trend_direction = "declined"
        else:
            trend_direction = "stable"

    sev_counts = Counter()
    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        sev_counts[sev] += 1

    resolved = sum(1 for f in findings if _is_resolved(f))
    open_count = len(findings) - resolved

    # Compliance % from existing builders (cheap to call).
    nist = build_nist_csf(findings, scans, period_days=period_days,
                            disabled_rules=disabled_rules,
                            org_name=org_name)
    iso = build_iso_27001(findings, scans, period_days=period_days,
                            disabled_rules=disabled_rules,
                            org_name=org_name)

    # Fleet rollup from existing builder.
    fleet = build_fleet_health(fleet_rows, org_name=org_name)

    # Trend chart samples.
    trend_points = _score_trend(scans, buckets=10)

    # Strategic recommendations — leadership-oriented framing. Less
    # tactical than the Executive Summary; more "where to invest".
    recommendations: List[str] = []
    if fleet["summary"]["at_risk_count"] > 0:
        recommendations.append(
            f"Prioritize remediation work on the "
            f"{fleet['summary']['at_risk_count']} at-risk host"
            f"{'s' if fleet['summary']['at_risk_count'] != 1 else ''}; "
            f"these account for the bulk of the current risk score."
        )
    if fleet["summary"]["stale_count"] > 0:
        recommendations.append(
            f"Bring {fleet['summary']['stale_count']} stale endpoint"
            f"{'s' if fleet['summary']['stale_count'] != 1 else ''} "
            f"back into scanning rotation. Unscanned hosts hide both "
            f"compliance posture and incident signal."
        )
    nist_pct = nist["summary"]["overall_coverage_percent"]
    iso_pct  = iso["summary"]["overall_coverage_percent"]
    if nist_pct < 60 or iso_pct < 60:
        recommendations.append(
            f"Expand detection coverage: NIST CSF at {nist_pct}%, "
            f"ISO 27001 at {iso_pct}%. Pulse's rule catalog now spans "
            f"every framework function but several mappings remain "
            f"unfilled."
        )
    if trend_direction == "declined":
        recommendations.append(
            "Security score declined this period. Review the Top Risks "
            "section of the Threat Detection Summary and ensure the "
            "responsible team has an owner for each."
        )
    if not recommendations:
        recommendations.append(
            "Maintain the current cadence: weekly scans, monthly "
            "report review, quarterly tabletop exercises."
        )

    if not scope_label:
        scope_label = (
            f"Last {period_days} day{'s' if period_days != 1 else ''} "
            f"({fleet['summary']['total_hosts']} host"
            f"{'s' if fleet['summary']['total_hosts'] != 1 else ''})"
        )

    return {
        "header": {
            "title":         "Board-Ready Posture Report",
            "scope":         scope_label,
            "period_days":   period_days,
            "generated_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "organization":  org_name or "your organization",
        "posture": {
            "score":          score,
            "grade":          grade,
            "interpretation": GRADE_INTERPRETATION.get(grade, ""),
            "trend": {
                "direction": trend_direction,
                "delta":     trend_delta,
            },
        },
        "trend_points":  trend_points,
        "fleet_summary": fleet["summary"],
        "compliance": {
            "nist_csf": {
                "coverage_percent":   nist_pct,
                "rules_enabled":      nist["summary"]["rules_enabled"],
                "findings_in_period": nist["summary"]["findings_in_period"],
            },
            "iso_27001": {
                "coverage_percent":   iso_pct,
                "rules_enabled":      iso["summary"]["rules_enabled"],
                "findings_in_period": iso["summary"]["findings_in_period"],
            },
        },
        "activity": {
            "total_issues": len(findings),
            "open":         open_count,
            "resolved":     resolved,
            "by_severity":  {k: sev_counts.get(k, 0)
                              for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        },
        "recommendations": recommendations,
        "footer": {
            "pulse_version":  _PULSE_VERSION,
            "automated_note": (
                "This report is intended for board / executive review. "
                "For investigator-level detail, generate the Threat "
                "Detection Summary or Incident Investigation Report."
            ),
        },
    }
