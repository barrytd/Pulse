"""MITRE ATT&CK Coverage Report — Phase 5.

What techniques Pulse detected activity for in the reporting period,
laid out on the ATT&CK tactic matrix. For threat hunters and detection
engineers. Reuses ``threat_summary.TECHNIQUE_TO_TACTIC`` so the
dashboard's coverage matrix and this report group findings the same way.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from pulse import __version__ as _PULSE_VERSION
from pulse.core.rules_config import RULE_META
from pulse.reports.threat_summary import (
    TACTIC_ORDER, TECHNIQUE_TO_TACTIC,
)


def _rule_technique(rule_name: str) -> Optional[str]:
    meta = RULE_META.get(rule_name) or {}
    t = meta.get("mitre")
    if not t:
        return None
    if isinstance(t, list):
        return t[0] if t else None
    return t


def _technique_tactic(technique: str) -> str:
    return TECHNIQUE_TO_TACTIC.get(technique or "", "Other")


def build_mitre_coverage(findings: List[Dict[str, Any]],
                          *,
                          period_days: int = 30,
                          scope_label: Optional[str] = None,
                          disabled_rules: Optional[Iterable[str]] = None,
                          org_name: Optional[str] = None
                          ) -> Dict[str, Any]:
    """Build the MITRE ATT&CK Coverage payload."""
    findings = list(findings or [])
    disabled = set(disabled_rules or [])

    # ---- Finding counts per (technique, rule) -------------------
    rule_hits = Counter()
    for f in findings:
        rule = (f.get("rule") or "").strip()
        if rule:
            rule_hits[rule] += 1

    # ---- Technique coverage -------------------------------------
    # Build a map of technique -> {rules, enabled_rules, findings_count,
    # tactic}. Walk RULE_META so every rule (whether it fired or not)
    # contributes to the coverage view.
    techniques: Dict[str, Dict[str, Any]] = {}
    for rule_name, meta in RULE_META.items():
        tid = meta.get("mitre")
        if not tid:
            continue
        if isinstance(tid, list):
            tid = tid[0] if tid else None
            if not tid:
                continue
        bucket = techniques.setdefault(tid, {
            "technique":      tid,
            "tactic":         _technique_tactic(tid),
            "rules":          [],
            "enabled_count":  0,
            "findings_count": 0,
        })
        bucket["rules"].append(rule_name)
        if rule_name not in disabled:
            bucket["enabled_count"] += 1
        bucket["findings_count"] += rule_hits.get(rule_name, 0)

    # ---- Bucket techniques per tactic ----------------------------
    tactic_buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for t in techniques.values():
        tactic_buckets[t["tactic"]].append(t)
    for tactic in tactic_buckets:
        # Sort techniques inside each tactic: findings desc, then ID.
        tactic_buckets[tactic].sort(
            key=lambda x: (-x["findings_count"], x["technique"]),
        )

    matrix: List[Dict[str, Any]] = []
    for tactic in TACTIC_ORDER:
        bucket = tactic_buckets.get(tactic) or []
        matrix.append({
            "tactic":         tactic,
            "technique_count": len(bucket),
            "active_count":   sum(1 for t in bucket if t["findings_count"] > 0),
            "findings_count": sum(t["findings_count"] for t in bucket),
            "techniques":     bucket,
        })

    # ---- Top-fired techniques (across all tactics) ---------------
    top_techniques = sorted(
        (t for t in techniques.values() if t["findings_count"] > 0),
        key=lambda x: x["findings_count"], reverse=True,
    )[:10]

    # ---- Silent tactics (no activity) ----------------------------
    silent_tactics = [
        row["tactic"]
        for row in matrix
        if row["technique_count"] > 0 and row["findings_count"] == 0
    ]
    no_coverage_tactics = [
        row["tactic"]
        for row in matrix
        if row["technique_count"] == 0 and row["tactic"] != "Other"
    ]

    if not scope_label:
        scope_label = (
            f"Last {period_days} day{'s' if period_days != 1 else ''}"
        )

    return {
        "header": {
            "title":        "MITRE ATT&CK Coverage Report",
            "scope":        scope_label,
            "period_days":  period_days,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "organization": org_name or "your organization",
        "summary": {
            "technique_count":        len(techniques),
            "active_technique_count": sum(1 for t in techniques.values()
                                            if t["findings_count"] > 0),
            "tactic_count":           len(TACTIC_ORDER),
            "covered_tactic_count":   sum(1 for r in matrix
                                            if r["technique_count"] > 0),
            "total_findings":         sum(rule_hits.values()),
        },
        "matrix":            matrix,
        "top_techniques":    top_techniques,
        "silent_tactics":    silent_tactics,
        "uncovered_tactics": no_coverage_tactics,
        "footer": {
            "pulse_version": _PULSE_VERSION,
            "automated_note": (
                "Technique mappings reflect Pulse's detection-rule "
                "library at the time of generation. A technique with "
                "an enabled rule but no findings is normal — it means "
                "Pulse is watching, just nothing matched."
            ),
        },
    }
