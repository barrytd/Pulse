"""Threat Detection Summary — Phase 1 of the report-template catalog.

The "Threat Detection Summary" is the canonical post-scan report: it
turns a list of findings (plus scan context) into a structured
assessment grouped by MITRE tactic, with an attack timeline, top rules,
and repeat-offender source IPs / hosts. It's the report a user
generates right after their first scan, so it justifies Pulse existing.

The module split is deliberate:

    ``build_summary(findings, scans, *, scope_label)``
        Returns a JSON-serializable dict with every piece of data the
        report needs. All four format renderers consume this single
        dict — there's one source of truth for what shows up, so the
        PDF and HTML can't disagree on the numbers.

    ``render_json``, ``render_csv``, ``render_html``, ``render_pdf``
        Format-specific renderers. Each one takes the dict and returns
        ``bytes`` ready for download / persistence.

This is the pattern future templates (Executive Summary, Compliance,
Incident Investigation) follow.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from pulse import __version__ as _PULSE_VERSION
from pulse.core.rules_config import RULE_META


# ---------------------------------------------------------------------------
# MITRE technique -> tactic map. Mirrors the JS map in pulse/static/js/rules.js
# so the dashboard's "MITRE Coverage" matrix and the Threat Summary report
# group findings the same way. If a technique isn't here we fall back to
# "Other" — the tactic bucket exists so a finding never disappears just
# because we missed adding it to the map.
# ---------------------------------------------------------------------------

TECHNIQUE_TO_TACTIC: Dict[str, str] = {
    "T1110":     "Credential Access",
    "T1110.001": "Credential Access",
    "T1110.003": "Credential Access",
    "T1078":     "Persistence",
    "T1078.002": "Privilege Escalation",
    "T1136.001": "Persistence",
    "T1070.001": "Defense Evasion",
    "T1021":     "Lateral Movement",
    "T1021.001": "Lateral Movement",
    "T1021.002": "Lateral Movement",
    "T1550.002": "Lateral Movement",
    "T1543.003": "Persistence",
    "T1053.005": "Execution",
    "T1059.001": "Execution",
    "T1562.001": "Defense Evasion",
    "T1562.004": "Defense Evasion",
    "T1558.001": "Credential Access",
    "T1558.003": "Credential Access",
    "T1003.001": "Credential Access",
    "T1547.001": "Persistence",
    "T1548":     "Privilege Escalation",
    "T1098":     "Persistence",
    "T1218.011": "Defense Evasion",
}

# Canonical tactic ordering — same order the MITRE ATT&CK matrix uses
# left-to-right. Used to sort the "Findings by MITRE Tactic" section so
# the report reads kill-chain-first.
TACTIC_ORDER: List[str] = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact", "Other",
]


# Severity ordering for the summary band + sorting passes.
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Score thresholds (matches calculate_score_from_findings in pulse.scoring).
def _grade_for_score(score: int) -> str:
    if score is None:
        return "?"
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _tactic_for_rule(rule_name: str) -> str:
    """Resolve a rule name -> MITRE tactic. Falls through RULE_META.mitre
    -> TECHNIQUE_TO_TACTIC. "Other" is the sink bucket for unmapped rules."""
    meta = RULE_META.get(rule_name) or {}
    tid = meta.get("mitre")
    if not tid:
        return "Other"
    if isinstance(tid, list):
        tid = tid[0] if tid else None
    return TECHNIQUE_TO_TACTIC.get(tid or "", "Other")


# ---------------------------------------------------------------------------
# IP extraction (for the Repeat Offenders section)
# ---------------------------------------------------------------------------

# Matches IPv4 inside a finding's `details` blob. We deliberately do not
# parse IPv6 here — the data we get from event logs is overwhelmingly v4
# and the false-positive cost of regex-matching v6 inside arbitrary text
# is too high for this report's purpose.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _extract_ip(finding: Dict[str, Any]) -> Optional[str]:
    """Best-effort source-IP extraction. Findings already carry parsed
    metadata in different shapes across rules — explicit ``source_ip``
    when the detection set it, otherwise the first v4 match in the
    free-text details field."""
    explicit = finding.get("source_ip") or finding.get("ip")
    if explicit:
        return str(explicit)
    text = finding.get("details") or finding.get("description") or ""
    if not text:
        return None
    m = _IPV4_RE.search(text)
    return m.group(0) if m else None


# ---------------------------------------------------------------------------
# Public builder
# ---------------------------------------------------------------------------

def build_summary(findings: List[Dict[str, Any]],
                  scans: Optional[List[Dict[str, Any]]] = None,
                  *,
                  scope_label: Optional[str] = None,
                  intel_lookup=None) -> Dict[str, Any]:
    """Turn raw findings + scan metadata into a structured report payload.

    Parameters
    ----------
    findings: list of finding dicts. May span one scan or many.
    scans: list of scan rows (id, scanned_at, hostname, score,
           score_label, total_events, files_scanned). Used for the
           header's host list + the summary band's score. ``None`` is
           accepted so the builder works against a hand-built list of
           findings with no scan context (tests, ad-hoc CLI calls).
    scope_label: human string for the "Data scope" header line — e.g.
           ``"Scan #42 (DESKTOP-FINANCE01, 2026-06-02)"`` or
           ``"Last 30 days (4 hosts)"``. Set by the caller because only
           they know how the report was triggered.
    intel_lookup: optional callable ``(ip) -> dict or None`` returning a
           cached threat-intel row. Used for the Repeat Offenders
           section. Pass ``None`` to suppress the intel column.

    Returns
    -------
    A JSON-serializable dict. See the inline schema comment at the
    bottom of this module for the exact shape.
    """
    findings = list(findings or [])
    scans    = list(scans or [])

    sev_counts = Counter()
    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        if sev not in SEVERITY_ORDER:
            sev = "LOW"
        sev_counts[sev] += 1

    hosts = sorted({
        (s.get("hostname") or "").strip()
        for s in scans if s.get("hostname")
    } | {
        (f.get("hostname") or "").strip()
        for f in findings if f.get("hostname")
    })
    hosts = [h for h in hosts if h]

    # Pick the most recent scan as the "primary" scan when building a
    # per-scan report. When the caller passed many scans (date range),
    # we average the scores so the summary band has one number.
    score = None
    score_label = None
    if scans:
        scored = [s for s in scans if s.get("score") is not None]
        if scored:
            score = round(sum(int(s["score"]) for s in scored) / len(scored))
            score_label = scored[0].get("score_label")
    grade = _grade_for_score(score) if score is not None else None

    # ---- Findings by MITRE tactic ----------------------------------
    by_tactic: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        rule = f.get("rule") or "Unknown"
        tactic = _tactic_for_rule(rule)
        bucket = by_tactic.setdefault(tactic, {
            "tactic":      tactic,
            "count":       0,
            "techniques":  {},
        })
        bucket["count"] += 1
        meta = RULE_META.get(rule) or {}
        tid = meta.get("mitre")
        if isinstance(tid, list):
            tid = tid[0] if tid else None
        if tid:
            tbucket = bucket["techniques"].setdefault(tid, {
                "id":    tid,
                "rules": set(),
                "count": 0,
            })
            tbucket["rules"].add(rule)
            tbucket["count"] += 1
    # Order tactics by canonical kill-chain position, flatten technique
    # sets to sorted lists for JSON safety.
    tactic_rows: List[Dict[str, Any]] = []
    for tactic in TACTIC_ORDER:
        if tactic not in by_tactic:
            continue
        b = by_tactic[tactic]
        techs = [
            {
                "id":    t["id"],
                "count": t["count"],
                "rules": sorted(t["rules"]),
            }
            for t in sorted(b["techniques"].values(),
                             key=lambda x: x["count"], reverse=True)
        ]
        tactic_rows.append({
            "tactic":     tactic,
            "count":      b["count"],
            "techniques": techs,
        })

    # ---- Attack timeline (chronological) ----------------------------
    def _ts_key(f):
        ts = f.get("timestamp") or ""
        return str(ts)
    timeline = sorted(
        ({
            "timestamp": f.get("timestamp"),
            "severity":  (f.get("severity") or "LOW").upper(),
            "rule":      f.get("rule"),
            "hostname":  f.get("hostname"),
            "details":   (f.get("details") or "")[:240],
            "ref_id":    f.get("ref_id"),
            "id":        f.get("id"),
        } for f in findings),
        key=lambda r: r["timestamp"] or "",
    )

    # ---- Top triggered rules ---------------------------------------
    rule_counter = Counter()
    for f in findings:
        if f.get("rule"):
            rule_counter[f["rule"]] += 1
    top_rules = [
        {
            "rule":     name,
            "count":    n,
            "severity": (RULE_META.get(name) or {}).get("severity"),
            "mitre":    (RULE_META.get(name) or {}).get("mitre"),
        }
        for name, n in rule_counter.most_common(10)
    ]

    # ---- Repeat offenders ------------------------------------------
    ip_hits: Dict[str, Dict[str, Any]] = {}
    host_hits = Counter()
    for f in findings:
        ip = _extract_ip(f)
        if ip:
            entry = ip_hits.setdefault(ip, {
                "ip":              ip,
                "count":           0,
                "rules":           set(),
                "first_seen":      None,
                "last_seen":       None,
                "intel_score":     None,
                "intel_country":   None,
            })
            entry["count"] += 1
            if f.get("rule"):
                entry["rules"].add(f["rule"])
            ts = f.get("timestamp")
            if ts:
                if not entry["first_seen"] or ts < entry["first_seen"]:
                    entry["first_seen"] = ts
                if not entry["last_seen"] or ts > entry["last_seen"]:
                    entry["last_seen"] = ts
        host = (f.get("hostname") or "").strip()
        if host:
            host_hits[host] += 1

    # Decorate IPs with cached intel scores when the caller supplied a
    # lookup. The lookup is sync + best-effort — a network error or a
    # missing cache row leaves the score as None.
    if intel_lookup:
        for ip, entry in ip_hits.items():
            try:
                intel = intel_lookup(ip)
            except Exception:
                intel = None
            if intel:
                entry["intel_score"]   = intel.get("score")
                entry["intel_country"] = intel.get("country")

    repeat_ips = [
        {**v, "rules": sorted(v["rules"])}
        for v in sorted(
            ip_hits.values(),
            key=lambda e: e["count"], reverse=True,
        )
        if v["count"] >= 2
    ][:15]
    repeat_hosts = [
        {"hostname": h, "count": n}
        for h, n in host_hits.most_common(15)
        if n >= 2
    ]

    payload: Dict[str, Any] = {
        "header": {
            "title":           "Threat Detection Summary",
            "generated_at":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scope":           scope_label or _default_scope_label(scans),
            "hosts":           hosts,
            "scan_count":      len(scans),
            "finding_count":   len(findings),
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": {
                "CRITICAL": sev_counts.get("CRITICAL", 0),
                "HIGH":     sev_counts.get("HIGH", 0),
                "MEDIUM":   sev_counts.get("MEDIUM", 0),
                "LOW":      sev_counts.get("LOW", 0),
            },
            "score":       score,
            "score_label": score_label,
            "grade":       grade,
        },
        "by_tactic":     tactic_rows,
        "timeline":      timeline,
        "top_rules":     top_rules,
        "repeat_ips":    repeat_ips,
        "repeat_hosts":  repeat_hosts,
        "footer": {
            "pulse_version": _PULSE_VERSION,
            "automated_note": (
                "This is an automated assessment generated by Pulse. "
                "Findings reflect detections at scan time and should be "
                "validated by a human reviewer before action."
            ),
        },
    }
    return payload


def _default_scope_label(scans):
    if not scans:
        return "No scans in scope"
    if len(scans) == 1:
        s = scans[0]
        return (
            f"Scan #{s.get('number') or s.get('id')}"
            f" ({s.get('hostname') or 'unknown host'}, "
            f"{(s.get('scanned_at') or '').split(' ')[0]})"
        )
    return f"{len(scans)} scans"
