"""Compliance Gap Analysis — Phase 5.

Prioritized roadmap of detection gaps: uncovered MITRE techniques,
silent rules, noisy rules. Each gap is framed as an actionable
improvement item so a detection engineer can pull the list straight
into their backlog.

Reuses the per-rule stats already computed for the Rules page
(``database.get_rule_stats``) plus the MITRE technique map from the
threat-summary module.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from pulse import __version__ as _PULSE_VERSION
from pulse.core.rules_config import RULE_META
from pulse.reports.threat_summary import (
    TACTIC_ORDER, TECHNIQUE_TO_TACTIC,
)


# Tunables for what counts as silent/noisy. These match the defaults
# the Rules page uses so the gap report and the live UI agree on which
# rules deserve attention.
SILENT_DEFINITION = "Enabled rules that have never fired since install."
NOISY_DEFINITION  = (
    "Enabled rules with >= 30 total fires AND a false-positive rate >= 30%."
)


def _is_silent(stat: Dict[str, Any]) -> bool:
    return (stat.get("hits_total") or 0) == 0


def _fp_rate(stat: Dict[str, Any]) -> float:
    tp = stat.get("tp_count") or 0
    fp = stat.get("fp_count") or 0
    total = tp + fp
    if total == 0:
        return 0.0
    return fp / total


def _is_noisy(stat: Dict[str, Any]) -> bool:
    total = stat.get("hits_total") or 0
    if total < 30:
        return False
    return _fp_rate(stat) >= 0.30


def build_compliance_gap(rule_stats: Dict[str, Dict[str, Any]],
                          *,
                          disabled_rules: Optional[Iterable[str]] = None,
                          period_days: int = 30,
                          scope_label: Optional[str] = None,
                          org_name: Optional[str] = None,
                          ) -> Dict[str, Any]:
    """Build the Compliance Gap Analysis payload.

    ``rule_stats`` is the dict returned by ``database.get_rule_stats``.
    Keys are rule names; values carry hits_total, hits_24h, last_fired,
    tp_count, fp_count, spark_24h.
    """
    rule_stats = rule_stats or {}
    disabled = set(disabled_rules or [])

    # ---- Uncovered MITRE techniques -----------------------------
    # An "uncovered" technique is one that exists in our technique→
    # tactic map but has no enabled Pulse rule mapping to it. This is
    # the canonical detection-coverage gap.
    covered_techniques = set()
    for rule_name, meta in RULE_META.items():
        if rule_name in disabled:
            continue
        tid = meta.get("mitre")
        if isinstance(tid, list):
            tid = tid[0] if tid else None
        if tid:
            covered_techniques.add(tid)

    uncovered = []
    for tid, tactic in TECHNIQUE_TO_TACTIC.items():
        if tid in covered_techniques:
            continue
        uncovered.append({
            "technique": tid,
            "tactic":    tactic,
            "action": (
                f"Add a Pulse rule (built-in or SIGMA import) covering "
                f"{tid} so the {tactic} tactic is monitored."
            ),
        })
    uncovered.sort(key=lambda x: (TACTIC_ORDER.index(x["tactic"])
                                    if x["tactic"] in TACTIC_ORDER else 99,
                                    x["technique"]))

    # ---- Silent rules -------------------------------------------
    silent: List[Dict[str, Any]] = []
    for rule_name in RULE_META:
        if rule_name in disabled:
            continue
        stat = rule_stats.get(rule_name) or {}
        if _is_silent(stat):
            meta = RULE_META.get(rule_name) or {}
            silent.append({
                "rule":      rule_name,
                "severity":  meta.get("severity"),
                "mitre":     meta.get("mitre"),
                "last_fired": stat.get("last_fired"),
                "action": (
                    f"Confirm '{rule_name}' has working test coverage. "
                    f"If it should be firing, investigate why the "
                    f"upstream events aren't reaching it."
                ),
            })

    # ---- Noisy rules --------------------------------------------
    noisy: List[Dict[str, Any]] = []
    for rule_name, stat in rule_stats.items():
        if rule_name in disabled:
            continue
        if not _is_noisy(stat):
            continue
        meta = RULE_META.get(rule_name) or {}
        rate = _fp_rate(stat)
        noisy.append({
            "rule":       rule_name,
            "severity":   meta.get("severity"),
            "mitre":      meta.get("mitre"),
            "hits_total": stat.get("hits_total") or 0,
            "fp_count":   stat.get("fp_count") or 0,
            "tp_count":   stat.get("tp_count") or 0,
            "fp_rate":    round(rate * 100),
            "action": (
                f"Tune '{rule_name}': "
                f"{round(rate*100)}% of decisions were marked false "
                f"positive over {stat.get('hits_total')} hits. Add a "
                f"whitelist entry, narrow the rule condition, or "
                f"lower its severity."
            ),
        })
    noisy.sort(key=lambda x: (-x["fp_rate"], -x["hits_total"]))

    if not scope_label:
        scope_label = (
            f"Last {period_days} day{'s' if period_days != 1 else ''}"
        )

    return {
        "header": {
            "title":        "Compliance Gap Analysis",
            "scope":        scope_label,
            "period_days":  period_days,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "organization": org_name or "your organization",
        "definitions": {
            "silent_rules": SILENT_DEFINITION,
            "noisy_rules":  NOISY_DEFINITION,
        },
        "summary": {
            "uncovered_count":     len(uncovered),
            "silent_count":        len(silent),
            "noisy_count":         len(noisy),
            "total_improvements":  len(uncovered) + len(silent) + len(noisy),
        },
        "uncovered_techniques": uncovered,
        "silent_rules":         silent,
        "noisy_rules":          noisy,
        "footer": {
            "pulse_version": _PULSE_VERSION,
            "automated_note": (
                "Address noisy rules first (high analyst fatigue cost). "
                "Then uncovered techniques (real detection gaps). "
                "Silent rules last — many are correct-but-quiet."
            ),
        },
    }
