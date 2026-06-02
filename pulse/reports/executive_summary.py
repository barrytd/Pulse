"""Executive Summary — Phase 2 of the report-template catalog.

The Executive Summary is the one-pager an admin forwards to their boss.
It justifies why Pulse is sitting in their environment. Every section is
written for someone who does *not* read security logs for a living:
no event IDs, no MITRE technique codes, no rule slugs in the body text.

The split mirrors Phase 1 (Threat Detection Summary):

    ``build_executive(...)``
        Returns a JSON-serializable dict. All four format renderers
        consume this single dict so the PDF and HTML can never disagree
        on the numbers.

    ``render_json``, ``render_csv``, ``render_html``, ``render_pdf``
        Live in ``executive_summary_renderers``. Each takes the dict
        and returns ``bytes`` ready for download / persistence.

The data builder also computes a previous-period comparison when the
caller hands in ``prev_findings``/``prev_scans`` — used by the
"What Changed" + "Trend" sections. Both are optional; if omitted the
report still renders, the trend just reads as "first period observed".
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional

from pulse import __version__ as _PULSE_VERSION
from pulse.core.knowledge_base import get_knowledge as _kb
from pulse.core.rules_config import RULE_META
from pulse.reports.threat_summary import _finding_timestamp


# ---------------------------------------------------------------------------
# Grade interpretation. The line under the letter on the cover. Written
# for a non-technical reader: each is one short, calm sentence.
# ---------------------------------------------------------------------------

GRADE_INTERPRETATION: Dict[str, str] = {
    "A": "Strong security posture. Keep doing what you're doing.",
    "B": "Healthy posture with a few minor items worth tightening.",
    "C": "Several issues need attention to keep your environment safe.",
    "D": "Multiple high-impact risks. Plan to address the top items this week.",
    "F": "Critical risks. Immediate action required.",
    "?": "No completed scans in the reporting period yet.",
}


def _grade_for_score(score: Optional[int]) -> str:
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


_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_SEV_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _is_resolved(finding: Dict[str, Any]) -> bool:
    """Open vs resolved for stat-tile purposes. A finding is "resolved"
    if a reviewer marked it resolved or flagged it false-positive. The
    legacy ``reviewed`` flag predates the workflow column so we treat it
    as resolved too — a real install rarely has both set."""
    if finding.get("workflow_status") == "resolved":
        return True
    if finding.get("false_positive"):
        return True
    if finding.get("reviewed"):
        return True
    return False


def _machine_set(rows: Iterable[Dict[str, Any]]) -> set:
    return {
        (r.get("hostname") or "").strip()
        for r in rows
        if (r.get("hostname") or "").strip()
    }


def _avg_score(scans: Iterable[Dict[str, Any]]) -> Optional[int]:
    vals = [int(s["score"]) for s in scans
            if s.get("score") is not None]
    if not vals:
        return None
    return round(sum(vals) / len(vals))


def _what_this_means(sev: Dict[str, int], top_host: Optional[str],
                     top_risk_line: Optional[str], period_days: int) -> str:
    """Generate a 2-3 sentence plain-language narrative from the
    aggregate numbers. Phrasing is rule-based, not freeform: the
    exact same inputs produce the exact same output so the same scan
    re-run reads identically and a reader who memorizes one paragraph
    can spot the next period's deltas at a glance."""
    period_phrase = (
        f"over the past {period_days} day{'s' if period_days != 1 else ''}"
    )
    total = sum(sev.get(k, 0) for k in _SEV_ORDER)
    if total == 0:
        return (
            f"Your environment looks clean {period_phrase}. "
            f"Pulse detected no notable security issues during this "
            f"reporting period. Keep monitoring to maintain the trend."
        )
    parts: List[str] = []
    if sev.get("CRITICAL"):
        parts.append(
            f"Your environment shows signs of active attack attempts. "
            f"{period_phrase.capitalize()}, Pulse detected "
            f"{sev['CRITICAL']} critical issue"
            f"{'s' if sev['CRITICAL'] != 1 else ''}"
        )
        if top_risk_line:
            parts[-1] += f" including {top_risk_line}"
        parts[-1] += "."
        if top_host:
            parts.append(
                f"The most urgent activity centers on {top_host} "
                f"and should be addressed today."
            )
    elif sev.get("HIGH"):
        parts.append(
            f"Your environment has notable security issues to triage. "
            f"{period_phrase.capitalize()}, Pulse detected "
            f"{sev['HIGH']} high-severity issue"
            f"{'s' if sev['HIGH'] != 1 else ''}."
        )
        if top_host:
            parts.append(
                f"Activity concentrates on {top_host}; "
                f"address the top items this week."
            )
    else:
        parts.append(
            f"Your environment shows low-priority signals only. "
            f"{period_phrase.capitalize()}, Pulse detected "
            f"{total} issue{'s' if total != 1 else ''}, all "
            f"medium or lower severity. Review at your normal cadence."
        )
    return " ".join(parts)


def _humanize_risk(finding: Dict[str, Any]) -> Dict[str, str]:
    """Turn a finding into the three plain-language fields the Top
    Risks section wants. Pulls from the Security Advisor knowledge
    base when the rule has an entry; otherwise falls back to the
    finding's own description / details so the section is never empty.

    Returns ``{what_happened, why_it_matters, recommended_action}``.
    """
    rule = finding.get("rule") or "Unknown detection"
    k = _kb(rule) or {}
    what = (k.get("plain_language")
            or finding.get("description")
            or finding.get("details")
            or f"The {rule} detection fired on this host.")
    why = (k.get("why_it_matters")
           or "An unattended issue here may give an attacker more access "
              "or cover than they should have.")
    actions = k.get("immediate_actions") or []
    if actions:
        action = actions[0]
    elif finding.get("recommended_action"):
        action = finding["recommended_action"]
    else:
        action = ("Investigate the affected host and contain the "
                  "source of the activity before further escalation.")
    return {
        "what_happened":      str(what).strip(),
        "why_it_matters":     str(why).strip(),
        "recommended_action": str(action).strip(),
    }


def _pick_top_risks(findings: List[Dict[str, Any]],
                     limit: int = 3) -> List[Dict[str, Any]]:
    """Rank unresolved findings by severity weight, then by exploit-
    difficulty weight from the knowledge base (easy attacks score
    higher because anyone can do them), then by recency."""
    candidates = [f for f in findings if not _is_resolved(f)]
    if not candidates:
        # Fall back to the raw set so we never ship an empty Top Risks
        # block in a period with all-resolved noise.
        candidates = list(findings)

    _DIFF_BUMP = {"low": 1.4, "medium": 1.0, "high": 0.7}

    def score(f):
        sev = (f.get("severity") or "LOW").upper()
        sev_w = _SEV_WEIGHT.get(sev, 1)
        k = _kb(f.get("rule") or "") or {}
        diff_w = _DIFF_BUMP.get((k.get("difficulty") or "medium").lower(), 1.0)
        ts = _finding_timestamp(f) or ""
        return (sev_w * diff_w, ts)

    candidates.sort(key=score, reverse=True)

    risks = []
    seen_rules = set()
    for f in candidates:
        rule = f.get("rule") or "Unknown"
        # Deduplicate by rule so a host firing the same rule 200 times
        # doesn't fill all 3 Top Risks slots with the same line.
        if rule in seen_rules:
            continue
        seen_rules.add(rule)
        human = _humanize_risk(f)
        risks.append({
            "rule":               rule,
            "severity":           (f.get("severity") or "LOW").upper(),
            "host":               (f.get("hostname") or "").strip() or None,
            "what_happened":      human["what_happened"],
            "why_it_matters":     human["why_it_matters"],
            "recommended_action": human["recommended_action"],
        })
        if len(risks) >= limit:
            break
    return risks


def _build_recommendations(findings: List[Dict[str, Any]],
                            *, limit: int = 5) -> List[str]:
    """Forward-looking action items pulled from the knowledge base's
    ``prevention`` strings + the immediate-actions from the top
    findings. De-duplicated and capped at ``limit`` items so the
    section reads as a tight punchlist, not a wall of text."""
    out: List[str] = []
    seen = set()

    # Build a stable, severity-ordered finding queue first.
    queue = sorted(
        findings,
        key=lambda f: _SEV_WEIGHT.get((f.get("severity") or "LOW").upper(), 1),
        reverse=True,
    )

    # 1) Immediate actions from top findings — concrete things to do.
    for f in queue:
        k = _kb(f.get("rule") or "") or {}
        for step in (k.get("immediate_actions") or []):
            step = (step or "").strip().rstrip(".")
            if not step:
                continue
            key = step.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(step + ".")
            if len(out) >= limit:
                return out

    # 2) Prevention strings — broader posture recommendations.
    for f in queue:
        k = _kb(f.get("rule") or "") or {}
        prev = (k.get("prevention") or "").strip()
        if not prev:
            continue
        # Use the first sentence so the line stays scannable.
        first_sentence = prev.split(".")[0].strip()
        if not first_sentence:
            continue
        key = first_sentence.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(first_sentence + ".")
        if len(out) >= limit:
            return out

    # 3) Generic fallbacks so even an empty-data period still emits a
    # forward-looking list.
    fallbacks = [
        "Enable multi-factor authentication on every remote-access account.",
        "Keep antivirus and Windows updates on automatic.",
        "Review who has administrator access on each server quarterly.",
        "Forward security logs to a central store so a local wipe can't hide activity.",
        "Run a Pulse scan weekly so the trend has data to compare against.",
    ]
    for line in fallbacks:
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(line)
        if len(out) >= limit:
            break
    return out[:limit]


# ---------------------------------------------------------------------------
# Public builder
# ---------------------------------------------------------------------------

def build_executive(findings: List[Dict[str, Any]],
                    scans: Optional[List[Dict[str, Any]]] = None,
                    *,
                    period_days: int = 30,
                    scope_label: Optional[str] = None,
                    prev_findings: Optional[List[Dict[str, Any]]] = None,
                    prev_scans: Optional[List[Dict[str, Any]]] = None,
                    org_name: Optional[str] = None) -> Dict[str, Any]:
    """Build the Executive Summary payload.

    Parameters
    ----------
    findings, scans:
        The current reporting period.
    period_days:
        Length of the current period in days; used in the narrative
        paragraph and the date-range header.
    scope_label:
        Human-readable scope. If omitted, derived from ``period_days``
        and the host set.
    prev_findings, prev_scans:
        Previous-period comparison data. When supplied, the trend
        indicator and "What Changed" section get populated. Omit
        for first-period reports.
    org_name:
        Organization / install name surfaced in the header. Falls back
        to "your organization" when not provided.
    """
    findings = list(findings or [])
    scans    = list(scans or [])
    prev_findings = list(prev_findings or [])
    prev_scans    = list(prev_scans or [])

    # ---- Posture --------------------------------------------------
    cur_score  = _avg_score(scans)
    prev_score = _avg_score(prev_scans)
    grade = _grade_for_score(cur_score)

    if prev_score is None or cur_score is None:
        trend_direction = "first_period"
        trend_delta     = None
    else:
        delta = cur_score - prev_score
        trend_delta = delta
        if delta >= 5:
            trend_direction = "improved"
        elif delta <= -5:
            trend_direction = "declined"
        else:
            trend_direction = "stable"

    posture = {
        "score":          cur_score,
        "grade":          grade,
        "interpretation": GRADE_INTERPRETATION.get(grade, ""),
        "trend": {
            "direction": trend_direction,
            "delta":     trend_delta,
        },
    }

    # ---- Severity counts -----------------------------------------
    sev_counts = Counter()
    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        if sev not in _SEV_ORDER:
            sev = "LOW"
        sev_counts[sev] += 1

    # ---- Top risks ------------------------------------------------
    top_risks = _pick_top_risks(findings, limit=3)

    # ---- What This Means narrative -------------------------------
    host_counter = Counter()
    for f in findings:
        h = (f.get("hostname") or "").strip()
        if h:
            host_counter[h] += 1
    top_host = host_counter.most_common(1)[0][0] if host_counter else None
    top_risk_line = None
    if top_risks:
        # First risk's plain-language statement, lower-cased + trimmed
        # so it slots cleanly into the middle of a sentence.
        wh = top_risks[0]["what_happened"].rstrip(".")
        first_word = wh.split()[0] if wh else ""
        # Lowercase only when the first word is a generic article/verb,
        # not when it starts with a proper noun like "Someone".
        if first_word.lower() not in ("someone", "an", "the", "your"):
            top_risk_line = wh
        else:
            top_risk_line = wh[0].lower() + wh[1:]
    narrative = _what_this_means(
        dict(sev_counts), top_host, top_risk_line, period_days,
    )

    # ---- Activity overview ---------------------------------------
    resolved_count = sum(1 for f in findings if _is_resolved(f))
    open_count = len(findings) - resolved_count
    monitored_machines = _machine_set(scans)
    at_risk_machines = {
        (f.get("hostname") or "").strip()
        for f in findings
        if (f.get("hostname") or "").strip()
        and not _is_resolved(f)
        and (f.get("severity") or "").upper() in ("CRITICAL", "HIGH")
    }
    activity = {
        "total_issues":       len(findings),
        "resolved":           resolved_count,
        "open":               open_count,
        "machines_monitored": len(monitored_machines),
        "machines_at_risk":   len(at_risk_machines),
        "by_severity": {sev: sev_counts.get(sev, 0) for sev in _SEV_ORDER},
    }

    # ---- What Changed --------------------------------------------
    prev_machine_set = _machine_set(prev_scans)
    new_machines = sorted(monitored_machines - prev_machine_set)
    what_changed = {
        "new_issues":          len(findings),
        "previous_issues":     len(prev_findings),
        "issues_delta":        len(findings) - len(prev_findings),
        "resolved_in_period":  resolved_count,
        "score_delta":         trend_delta,
        "score_direction":     trend_direction,
        "new_machines":        new_machines,
        "new_machines_count":  len(new_machines),
        "had_previous_period": bool(prev_findings or prev_scans),
    }

    # ---- Recommendations ----------------------------------------
    recommendations = _build_recommendations(findings, limit=5)

    # ---- Header --------------------------------------------------
    period_end = datetime.now()
    period_start = period_end - timedelta(days=period_days)
    if not scope_label:
        host_count = len(monitored_machines)
        scope_label = (
            f"{period_start.strftime('%Y-%m-%d')} – "
            f"{period_end.strftime('%Y-%m-%d')} "
            f"({host_count} host{'s' if host_count != 1 else ''})"
        )

    header = {
        "title":         "Executive Security Summary",
        "organization":  org_name or "your organization",
        "scope":         scope_label,
        "period_days":   period_days,
        "period_start":  period_start.strftime("%Y-%m-%d"),
        "period_end":    period_end.strftime("%Y-%m-%d"),
        "generated_at":  period_end.strftime("%Y-%m-%d %H:%M:%S"),
        "host_count":    len(monitored_machines),
    }

    footer = {
        "pulse_version":  _PULSE_VERSION,
        "automated_note": (
            "This is an automated assessment generated by Pulse. "
            "For full technical detail, generate the Threat Detection "
            "Summary report covering the same period."
        ),
    }

    return {
        "header":           header,
        "posture":          posture,
        "what_this_means":  narrative,
        "top_risks":        top_risks,
        "activity":         activity,
        "what_changed":     what_changed,
        "recommendations":  recommendations,
        "footer":           footer,
    }
