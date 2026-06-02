"""Incident Investigation Report — Phase 4 of the report catalog.

Different shape from Phases 1-3: instead of a rolling reporting period,
this report scopes to a single host or a hand-picked set of findings.
It's the IR handoff document — every finding ships with its raw event
XML, threat-intel data, analyst notes, and a SHA-256 manifest so the
report can serve as evidence.

Public surface:
    ``build_incident(findings, *, host=None, finding_ids=None,
                      investigator_email=None, investigator_name=None,
                      org_name=None, intel_lookup=None,
                      note_lookup=None, block_lookup=None)``
        Returns a JSON-serializable dict. The ``*_lookup`` callables
        let the API layer inject helpers (database.list_finding_notes,
        intel.lookup_ip, blocker.list_blocks) without this module
        importing the rest of pulse — keeps testing trivial.

The chain-of-custody manifest is a list of per-finding rows: db id +
SHA-256 hex of the finding's raw_xml + ref_id + a per-finding timestamp.
A report-level SHA-256 over the concatenated finding hashes acts as a
single tamper indicator the receiver can quote in their case notes.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional

from pulse import __version__ as _PULSE_VERSION
from pulse.core.rules_config import RULE_META
from pulse.reports.threat_summary import _finding_timestamp


# ---------------------------------------------------------------------------
# Account + IP extraction — same patterns the dashboard uses.
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_XML_USER = re.compile(
    r'<Data\s+Name="(?:TargetUserName|SubjectUserName)">([^<]+)</Data>',
    re.IGNORECASE,
)
_XML_IP = re.compile(
    r'<Data\s+Name="(?:IpAddress|SourceAddress|SourceIp|ClientAddress)">([^<]+)</Data>',
    re.IGNORECASE,
)


def _extract_user(finding: Dict[str, Any]) -> Optional[str]:
    explicit = (finding.get("user") or finding.get("target_user")
                 or finding.get("subject_user"))
    if explicit:
        return str(explicit)
    raw = finding.get("raw_xml") or ""
    if raw:
        m = _XML_USER.search(raw)
        if m:
            val = m.group(1).strip()
            if val and val not in ("-", "ANONYMOUS LOGON", "N/A"):
                return val
    return None


def _extract_ip(finding: Dict[str, Any]) -> Optional[str]:
    explicit = finding.get("source_ip") or finding.get("ip")
    if explicit:
        return str(explicit)
    raw = finding.get("raw_xml") or ""
    if raw:
        m = _XML_IP.search(raw)
        if m:
            val = m.group(1).strip()
            if val and val not in ("-", "N/A", "::1", "127.0.0.1", "Unknown"):
                return val
    text = finding.get("details") or finding.get("description") or ""
    if text:
        m = _IPV4_RE.search(text)
        if m:
            return m.group(0)
    return None


# ---------------------------------------------------------------------------
# Chain-of-custody hashing
# ---------------------------------------------------------------------------

def _finding_sha256(finding: Dict[str, Any]) -> str:
    """Deterministic per-finding hash. Hashes the raw event XML when
    present (the source of truth for per-event detections) plus the
    finding's stable identifiers so a renamed rule / re-saved row still
    produces a consistent digest the receiver can reconcile against the
    DB later."""
    h = hashlib.sha256()
    parts = [
        str(finding.get("id") or ""),
        str(finding.get("ref_id") or ""),
        str(finding.get("rule") or ""),
        str(_finding_timestamp(finding) or ""),
        str(finding.get("raw_xml") or ""),
    ]
    for p in parts:
        h.update(p.encode("utf-8", errors="replace"))
        h.update(b"\x1f")  # unit separator between parts
    return h.hexdigest()


def _manifest_sha256(rows: List[Dict[str, Any]]) -> str:
    """Report-level digest over the per-finding hashes. A reviewer can
    quote this single hex in case notes; if the report is altered the
    digest no longer matches the recomputation."""
    h = hashlib.sha256()
    for row in rows:
        h.update(row["sha256"].encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Executive-line generator
# ---------------------------------------------------------------------------

def _executive_line(findings: List[Dict[str, Any]],
                     host: Optional[str], finding_set_size: Optional[int]) -> str:
    sev_counts = Counter()
    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        sev_counts[sev] += 1
    n_critical = sev_counts.get("CRITICAL", 0)
    n_high     = sev_counts.get("HIGH", 0)
    n_total    = len(findings)

    if n_total == 0:
        return "No findings in scope for this investigation."

    scope_phrase = (f"on {host}" if host
                    else (f"across {finding_set_size or n_total} selected findings"))

    if n_critical:
        return (
            f"Incident involves {n_critical} critical and {n_high} high-"
            f"severity finding{'s' if (n_critical + n_high) != 1 else ''} "
            f"{scope_phrase}. Treat as active until contained."
        )
    if n_high:
        return (
            f"Incident involves {n_high} high-severity finding"
            f"{'s' if n_high != 1 else ''} {scope_phrase}. Investigate before "
            f"the source escalates."
        )
    return (
        f"Investigation covers {n_total} finding"
        f"{'s' if n_total != 1 else ''} {scope_phrase}. No critical or "
        f"high-severity events in scope."
    )


# ---------------------------------------------------------------------------
# Public builder
# ---------------------------------------------------------------------------

def build_incident(findings: List[Dict[str, Any]],
                    *,
                    host: Optional[str] = None,
                    finding_ids: Optional[Iterable[int]] = None,
                    investigator_email: Optional[str] = None,
                    investigator_name: Optional[str] = None,
                    org_name: Optional[str] = None,
                    intel_lookup: Optional[Callable[[str],
                                                       Optional[Dict[str, Any]]]] = None,
                    note_lookup: Optional[Callable[[int],
                                                       List[Dict[str, Any]]]] = None,
                    block_lookup: Optional[Callable[[],
                                                       List[Dict[str, Any]]]] = None,
                    ) -> Dict[str, Any]:
    findings = list(findings or [])
    finding_id_set = set(finding_ids) if finding_ids else None

    # ---- Sort chronologically for the timeline ---------------------
    def _ts(f):
        return _finding_timestamp(f) or ""
    timeline = sorted(findings, key=_ts)

    # ---- Affected assets ------------------------------------------
    hosts = set()
    accounts = set()
    ips = set()
    for f in findings:
        h = (f.get("hostname") or "").strip()
        if h:
            hosts.add(h)
        u = _extract_user(f)
        if u:
            accounts.add(u)
        ip = _extract_ip(f)
        if ip:
            ips.add(ip)

    # ---- Decorate per-finding details ------------------------------
    per_finding = []
    chain_rows = []
    for f in timeline:
        ip = _extract_ip(f)
        user = _extract_user(f)
        notes = []
        if note_lookup:
            try:
                notes = note_lookup(int(f.get("id") or 0)) or []
            except Exception:
                notes = []
        intel = None
        if intel_lookup and ip:
            try:
                intel = intel_lookup(ip)
            except Exception:
                intel = None
        meta = RULE_META.get(f.get("rule") or "") or {}
        mitre = meta.get("mitre")

        sha = _finding_sha256(f)
        per_finding.append({
            "id":               f.get("id"),
            "ref_id":           f.get("ref_id"),
            "rule":             f.get("rule"),
            "severity":         (f.get("severity") or "LOW").upper(),
            "mitre":            mitre if not isinstance(mitre, list) else (mitre[0] if mitre else None),
            "timestamp":        _finding_timestamp(f),
            "hostname":         (f.get("hostname") or "").strip() or None,
            "account":          user,
            "source_ip":        ip,
            "intel":            intel,
            "raw_xml":          f.get("raw_xml") or "",
            "details":          f.get("details") or "",
            "description":      f.get("description") or "",
            "notes":            [
                {
                    "author":     n.get("author_email") or n.get("author_name")
                                  or n.get("user_email") or n.get("email"),
                    "created_at": n.get("created_at"),
                    "body":       n.get("body") or "",
                }
                for n in notes
            ],
            "workflow_status":  (f.get("workflow_status") or "new").lower(),
            "false_positive":   bool(f.get("false_positive")),
            "reviewed":         bool(f.get("reviewed")),
            "sha256":           sha,
        })
        chain_rows.append({
            "id":        f.get("id"),
            "ref_id":    f.get("ref_id"),
            "rule":      f.get("rule"),
            "timestamp": _finding_timestamp(f),
            "sha256":    sha,
        })

    # ---- Remediation actions already taken (IP blocks) ------------
    blocks_for_incident = []
    if block_lookup and ips:
        try:
            all_blocks = block_lookup() or []
        except Exception:
            all_blocks = []
        ip_set_lower = {ip.lower() for ip in ips}
        for b in all_blocks:
            ip = (b.get("ip_address") or "").lower()
            if ip in ip_set_lower:
                blocks_for_incident.append({
                    "ip":         b.get("ip_address"),
                    "comment":    b.get("comment"),
                    "status":     b.get("status"),
                    "pushed_at":  b.get("pushed_at"),
                    "added_at":   b.get("added_at"),
                    "rule_name":  b.get("rule_name"),
                })

    # ---- Scope label + header --------------------------------------
    if host:
        scope_label = f"All unresolved findings on {host}"
    elif finding_id_set:
        scope_label = f"{len(finding_id_set)} hand-selected finding(s)"
    elif hosts:
        host_list = ", ".join(sorted(hosts))
        scope_label = f"Findings across {len(hosts)} host(s): {host_list}"
    else:
        scope_label = "Manual finding selection"

    investigator = (investigator_name or investigator_email
                     or "Unattributed (CLI / automation)")

    summary = _executive_line(findings, host, len(finding_id_set or []))

    report_sha = _manifest_sha256(chain_rows)

    return {
        "header": {
            "title":         "Incident Investigation Report",
            "scope":         scope_label,
            "investigator":  investigator,
            "investigator_email": investigator_email,
            "organization":  org_name or "your organization",
            "generated_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "host":          host,
            "finding_count": len(findings),
        },
        "executive_line": summary,
        "affected_assets": {
            "hosts":    sorted(hosts),
            "accounts": sorted(accounts),
            "ips":      sorted(ips),
        },
        "timeline":     [
            {
                "id":        row["id"],
                "ref_id":    row["ref_id"],
                "timestamp": row["timestamp"],
                "severity":  row["severity"],
                "rule":      row["rule"],
                "hostname":  row["hostname"],
                "account":   row["account"],
                "source_ip": row["source_ip"],
            }
            for row in per_finding
        ],
        "findings":          per_finding,
        "blocks_pushed":     blocks_for_incident,
        "chain_of_custody": {
            "generated_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "investigator":   investigator,
            "investigator_email": investigator_email,
            "report_sha256":  report_sha,
            "manifest":       chain_rows,
            "algorithm":      "SHA-256 over (id, ref_id, rule, timestamp, raw_xml)",
        },
        "footer": {
            "pulse_version": _PULSE_VERSION,
            "automated_note": (
                "This report is intended for incident-response handoff. "
                "Verify the SHA-256 manifest before treating the report "
                "as evidence: any modification invalidates the digest."
            ),
        },
    }
