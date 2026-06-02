"""Shared compliance-data builder for the NIST CSF + ISO 27001 report
templates (Phase 3 of the report-template catalog).

The Compliance page in the dashboard already aggregates rule mappings
into a per-framework coverage view (``build_compliance_summary`` in
``pulse/core/rules_config.py``). This module layers actual-finding
counts from the reporting period on top of that view so the audit
reports show *theoretical coverage* AND *observed detection activity*
side by side — which is what an auditor actually wants to see.

The split mirrors Phase 1 + 2:

    ``build_nist_csf(findings, scans, *, period_days, scope_label, ...)``
    ``build_iso_27001(findings, scans, *, period_days, scope_label, ...)``
        Return JSON-serializable dicts. Each format renderer consumes
        the same dict so PDF and HTML can't disagree on the numbers.

The two builders share most of their plumbing (rule-by-framework
walk, finding aggregation per control, coverage-gap detection) so
they sit in the same module instead of one each.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional

from pulse import __version__ as _PULSE_VERSION
from pulse.core.rules_config import (
    ISO_27001_CLAUSES, NIST_CSF_FUNCTIONS, RULE_META,
    build_compliance_summary,
)


# ---------------------------------------------------------------------------
# NIST CSF — every subcategory we expect to see covered, even when no rule
# maps to it yet. This is the canonical "what should be there" list; the
# coverage-gap section is the diff between this and the actually-mapped
# subcategories. Keep the list pragmatic: just the subcategories that
# Windows-event-log detection can plausibly cover, not the full CSF tree.
# ---------------------------------------------------------------------------

NIST_EXPECTED_SUBCATEGORIES: Dict[str, List[str]] = {
    "ID": [  # Identify
        "ID.AM-1", "ID.AM-2", "ID.RA-1",
    ],
    "PR": [  # Protect
        "PR.AC-1", "PR.AC-4", "PR.AC-6",
        "PR.DS-1", "PR.IP-1", "PR.IP-12",
        "PR.PT-1", "PR.PT-3", "PR.PT-4",
    ],
    "DE": [  # Detect
        "DE.AE-2", "DE.AE-3", "DE.AE-5",
        "DE.CM-1", "DE.CM-3", "DE.CM-4", "DE.CM-7",
        "DE.DP-2", "DE.DP-4",
    ],
    "RS": [  # Respond
        "RS.AN-1", "RS.MI-1", "RS.MI-2",
    ],
    "RC": [  # Recover
        "RC.RP-1",
    ],
}


# ---------------------------------------------------------------------------
# ISO 27001 — same idea: pragmatic expected control set per clause we
# care about. ISO clauses we don't have rules for stay out of the
# expected list so the gap section doesn't get noisy.
# ---------------------------------------------------------------------------

ISO_EXPECTED_CONTROLS: Dict[str, List[str]] = {
    "A.9": [   # Access control
        "A.9.2.1", "A.9.2.3", "A.9.2.4", "A.9.2.5", "A.9.2.6",
        "A.9.4.2", "A.9.4.4",
    ],
    "A.12": [  # Operations security
        "A.12.2.1", "A.12.4.1", "A.12.4.2", "A.12.4.3",
        "A.12.5.1", "A.12.6.1",
    ],
    "A.13": [  # Communications security
        "A.13.1.1", "A.13.1.2", "A.13.1.3",
    ],
    "A.16": [  # Incident management
        "A.16.1.2", "A.16.1.4", "A.16.1.5", "A.16.1.7",
    ],
}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _is_resolved(finding: Dict[str, Any]) -> bool:
    if finding.get("workflow_status") == "resolved":
        return True
    if finding.get("false_positive"):
        return True
    if finding.get("reviewed"):
        return True
    return False


def _findings_by_rule(findings: List[Dict[str, Any]]) -> Counter:
    counts = Counter()
    for f in findings:
        rule = (f.get("rule") or "").strip()
        if rule:
            counts[rule] += 1
    return counts


def _coverage_percent(enabled: int, expected: int) -> int:
    """Coverage = enabled-rule-backed controls / expected controls.
    Capped at 100 so a category with more enabled rules than expected
    controls doesn't read as "115%" (which makes auditors uncomfortable).
    """
    if expected <= 0:
        return 0
    pct = (enabled / expected) * 100.0
    return int(min(100, round(pct)))


def _scope_label(period_days: int, scans: List[Dict[str, Any]]) -> str:
    hosts = sorted({(s.get("hostname") or "").strip()
                     for s in scans if s.get("hostname")})
    host_count = len([h for h in hosts if h])
    return (
        f"Last {period_days} day{'s' if period_days != 1 else ''} "
        f"({len(scans)} scan{'s' if len(scans) != 1 else ''}, "
        f"{host_count} host{'s' if host_count != 1 else ''})"
    )


def _header(title: str, scope_label: str, period_days: int,
            scans: List[Dict[str, Any]]) -> Dict[str, Any]:
    hosts = sorted({(s.get("hostname") or "").strip()
                     for s in scans if s.get("hostname")})
    return {
        "title":        title,
        "scope":        scope_label,
        "period_days":  period_days,
        "hosts":        [h for h in hosts if h],
        "host_count":   len([h for h in hosts if h]),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _footer() -> Dict[str, Any]:
    return {
        "pulse_version":  _PULSE_VERSION,
        "automated_note": (
            "This is an automated assessment generated by Pulse. The "
            "control mappings reflect Pulse's detection-rule library at "
            "the time of generation and are intended to support, not "
            "replace, a formal audit review."
        ),
    }


# ---------------------------------------------------------------------------
# NIST CSF builder
# ---------------------------------------------------------------------------

def build_nist_csf(findings: List[Dict[str, Any]],
                    scans: Optional[List[Dict[str, Any]]] = None,
                    *,
                    period_days: int = 30,
                    scope_label: Optional[str] = None,
                    disabled_rules: Optional[Iterable[str]] = None,
                    org_name: Optional[str] = None) -> Dict[str, Any]:
    """Build the NIST CSF Coverage report payload.

    Layers actual detection activity from the reporting period onto the
    theoretical coverage view that ``build_compliance_summary`` returns.
    """
    findings = list(findings or [])
    scans    = list(scans or [])
    summary  = build_compliance_summary(disabled_rules or [])
    rule_hits = _findings_by_rule(findings)

    functions: List[Dict[str, Any]] = []
    total_enabled = total_findings = 0
    total_expected = sum(len(v) for v in NIST_EXPECTED_SUBCATEGORIES.values())

    # NIST_CSF_FUNCTIONS preserves canonical ordering — Identify first, etc.
    for prefix, label in NIST_CSF_FUNCTIONS.items():
        bucket = summary["nist_csf"].get(label, {})
        subcats = bucket.get("subcategories", {}) or {}

        covered_keys = set(subcats.keys())
        expected_keys = set(NIST_EXPECTED_SUBCATEGORIES.get(prefix, []))
        missing = sorted(expected_keys - covered_keys)

        sub_rows = []
        function_findings = 0
        for sub_key in sorted(covered_keys):
            rules_for_sub = subcats[sub_key]
            sub_findings = sum(rule_hits.get(r, 0) for r in rules_for_sub)
            function_findings += sub_findings
            sub_rows.append({
                "subcategory":    sub_key,
                "rules":          sorted(rules_for_sub),
                "rule_count":     len(rules_for_sub),
                "findings_count": sub_findings,
                "rule_findings":  {
                    r: rule_hits.get(r, 0) for r in rules_for_sub
                },
            })

        enabled = bucket.get("enabled", 0)
        total_enabled += enabled
        total_findings += function_findings

        functions.append({
            "prefix":           prefix,
            "label":            label,
            "subcategory_rows": sub_rows,
            "rules_total":      enabled + bucket.get("disabled", 0),
            "rules_enabled":    enabled,
            "rules_disabled":   bucket.get("disabled", 0),
            "findings_count":   function_findings,
            "missing_subcategories": missing,
            "coverage_percent": _coverage_percent(
                len(covered_keys & expected_keys), len(expected_keys),
            ),
        })

    # All missing subcategories rolled up for the Coverage Gaps section.
    all_gaps: List[Dict[str, str]] = []
    for fn in functions:
        for sub in fn["missing_subcategories"]:
            all_gaps.append({
                "subcategory": sub,
                "function":    fn["label"],
            })

    overall_coverage = _coverage_percent(
        sum(len(set(NIST_EXPECTED_SUBCATEGORIES.get(fn["prefix"], []))
                  & {row["subcategory"] for row in fn["subcategory_rows"]})
             for fn in functions),
        total_expected,
    )

    if not scope_label:
        scope_label = _scope_label(period_days, scans)

    return {
        "framework":      "NIST CSF",
        "header":         _header("NIST CSF Coverage Report",
                                    scope_label, period_days, scans),
        "organization":   org_name or "your organization",
        "summary": {
            "functions_count":         len(NIST_CSF_FUNCTIONS),
            "expected_subcategories":  total_expected,
            "rules_total":             sum(fn["rules_total"]    for fn in functions),
            "rules_enabled":           total_enabled,
            "findings_in_period":      total_findings,
            "overall_coverage_percent": overall_coverage,
        },
        "functions":      functions,
        "coverage_gaps":  all_gaps,
        "footer":         _footer(),
    }


# ---------------------------------------------------------------------------
# ISO 27001 Annex A builder
# ---------------------------------------------------------------------------

def build_iso_27001(findings: List[Dict[str, Any]],
                     scans: Optional[List[Dict[str, Any]]] = None,
                     *,
                     period_days: int = 30,
                     scope_label: Optional[str] = None,
                     disabled_rules: Optional[Iterable[str]] = None,
                     org_name: Optional[str] = None) -> Dict[str, Any]:
    """Build the ISO 27001 Annex A coverage report payload."""
    findings = list(findings or [])
    scans    = list(scans or [])
    summary  = build_compliance_summary(disabled_rules or [])
    rule_hits = _findings_by_rule(findings)

    clauses: List[Dict[str, Any]] = []
    total_expected = sum(len(v) for v in ISO_EXPECTED_CONTROLS.values())
    total_findings = total_enabled = 0

    # Walk clauses in ISO_27001_CLAUSES order so the report reads in
    # numerical clause order (A.9, A.12, A.13, A.16) not insertion-by-rule.
    for clause_key, clause_title in ISO_27001_CLAUSES.items():
        label = f"{clause_key} {clause_title}"
        bucket = summary["iso_27001"].get(label, {})
        controls = bucket.get("controls", {}) or {}

        covered_ids = set(controls.keys())
        expected_ids = set(ISO_EXPECTED_CONTROLS.get(clause_key, []))
        missing = sorted(expected_ids - covered_ids)

        control_rows = []
        clause_findings = 0
        for ctrl_id in sorted(covered_ids):
            rules_for_ctrl = controls[ctrl_id]
            ctrl_findings = sum(rule_hits.get(r, 0) for r in rules_for_ctrl)
            clause_findings += ctrl_findings
            control_rows.append({
                "control_id":     ctrl_id,
                "rules":          sorted(rules_for_ctrl),
                "rule_count":     len(rules_for_ctrl),
                "findings_count": ctrl_findings,
                "rule_findings":  {
                    r: rule_hits.get(r, 0) for r in rules_for_ctrl
                },
            })

        enabled = bucket.get("enabled", 0)
        total_enabled += enabled
        total_findings += clause_findings

        clauses.append({
            "clause":         clause_key,
            "title":          clause_title,
            "label":          label,
            "control_rows":   control_rows,
            "rules_total":    enabled + bucket.get("disabled", 0),
            "rules_enabled":  enabled,
            "rules_disabled": bucket.get("disabled", 0),
            "findings_count": clause_findings,
            "missing_controls": missing,
            "coverage_percent": _coverage_percent(
                len(covered_ids & expected_ids), len(expected_ids),
            ),
        })

    all_gaps: List[Dict[str, str]] = []
    for cl in clauses:
        for missing_ctrl in cl["missing_controls"]:
            all_gaps.append({
                "control": missing_ctrl,
                "clause":  cl["label"],
            })

    overall_coverage = _coverage_percent(
        sum(len(set(ISO_EXPECTED_CONTROLS.get(cl["clause"], []))
                  & {row["control_id"] for row in cl["control_rows"]})
             for cl in clauses),
        total_expected,
    )

    if not scope_label:
        scope_label = _scope_label(period_days, scans)

    return {
        "framework":      "ISO 27001",
        "header":         _header("ISO 27001 Annex A Report",
                                    scope_label, period_days, scans),
        "organization":   org_name or "your organization",
        "summary": {
            "clauses_count":           len(ISO_27001_CLAUSES),
            "expected_controls":       total_expected,
            "rules_total":             sum(cl["rules_total"]    for cl in clauses),
            "rules_enabled":           total_enabled,
            "findings_in_period":      total_findings,
            "overall_coverage_percent": overall_coverage,
        },
        "clauses":        clauses,
        "coverage_gaps":  all_gaps,
        "footer":         _footer(),
    }
