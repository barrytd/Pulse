"""
pulse/rules_config.py
---------------------
Central registry of detection rule metadata + per-rule enabled/disabled
state, plus helpers for filtering findings by the disabled list.

The dashboard's Rules page reads/writes this via the REST API; the CLI
scan loop and the API scan loop both filter their findings through
``filter_by_enabled`` after the whitelist pass so a disabled rule has
no visible output anywhere in Pulse.

Disabled rules are persisted as a flat list under ``disabled_rules:``
at the top level of ``pulse.yaml``. An empty or missing list means all
rules are enabled, which is the default.
"""

from typing import Iterable, List


# Static rule metadata table. Event IDs that a rule looks at, the
# default severity emitted when the rule fires, and the canonical
# MITRE ATT&CK technique. Aggregate/chain rules have ``event_id: None``
# because they correlate across multiple events instead of firing on
# any single one. Lists (e.g. [4946, 4947]) mean the rule watches
# multiple IDs; the frontend renders them joined by comma.
RULE_META = {
    "Brute Force Attempt":              {"event_id": 4625,          "severity": "HIGH",     "mitre": "T1110",     "nist_csf": "DE.CM-1",  "iso_27001": "A.9.4.2"},
    "User Account Created":             {"event_id": 4720,          "severity": "MEDIUM",   "mitre": "T1136.001", "nist_csf": "PR.AC-1",  "iso_27001": "A.9.2.1"},
    "Privilege Escalation":             {"event_id": 4732,          "severity": "HIGH",     "mitre": "T1548",     "nist_csf": "PR.AC-4",  "iso_27001": "A.9.2.3"},
    "Audit Log Cleared":                {"event_id": 1102,          "severity": "HIGH",     "mitre": "T1070.001", "nist_csf": "PR.PT-1",  "iso_27001": "A.12.4.2"},
    "RDP Logon Detected":               {"event_id": 4624,          "severity": "MEDIUM",   "mitre": "T1021.001", "nist_csf": "DE.CM-7",  "iso_27001": "A.9.4.2"},
    "Pass-the-Hash Attempt":            {"event_id": 4624,          "severity": "HIGH",     "mitre": "T1550.002", "nist_csf": "DE.CM-4",  "iso_27001": "A.9.2.4"},
    "Service Installed":                {"event_id": 7045,          "severity": "MEDIUM",   "mitre": "T1543.003", "nist_csf": "DE.CM-7",  "iso_27001": "A.12.5.1"},
    "Antivirus Disabled":               {"event_id": 5001,          "severity": "HIGH",     "mitre": "T1562.001", "nist_csf": "PR.PT-4",  "iso_27001": "A.12.2.1"},
    "Firewall Disabled":                {"event_id": 4950,          "severity": "HIGH",     "mitre": "T1562.004", "nist_csf": "PR.PT-4",  "iso_27001": "A.13.1.1"},
    "Firewall Rule Changed":            {"event_id": [4946, 4947],  "severity": "MEDIUM",   "mitre": "T1562.004", "nist_csf": "PR.IP-1",  "iso_27001": "A.13.1.1"},
    "Account Lockout":                  {"event_id": 4740,          "severity": "HIGH",     "mitre": "T1110",     "nist_csf": "DE.CM-1",  "iso_27001": "A.9.4.2"},
    "Scheduled Task Created":           {"event_id": 4698,          "severity": "MEDIUM",   "mitre": "T1053.005", "nist_csf": "DE.CM-7",  "iso_27001": "A.12.5.1"},
    "Suspicious PowerShell":            {"event_id": 4104,          "severity": "HIGH",     "mitre": "T1059.001", "nist_csf": "DE.CM-4",  "iso_27001": "A.12.2.1"},
    "Account Takeover Chain":           {"event_id": None,          "severity": "CRITICAL", "mitre": "T1078",     "nist_csf": "DE.AE-3",  "iso_27001": "A.16.1.2"},
    "Malware Persistence Chain":        {"event_id": None,          "severity": "CRITICAL", "mitre": "T1543.003", "nist_csf": "DE.AE-3",  "iso_27001": "A.12.2.1"},
    "Kerberoasting":                    {"event_id": 4769,          "severity": "HIGH",     "mitre": "T1558.003", "nist_csf": "DE.CM-7",  "iso_27001": "A.9.4.2"},
    "Golden Ticket":                    {"event_id": 4768,          "severity": "CRITICAL", "mitre": "T1558.001", "nist_csf": "DE.CM-7",  "iso_27001": "A.9.4.2"},
    "Credential Dumping":               {"event_id": [4656, 4663],  "severity": "CRITICAL", "mitre": "T1003.001", "nist_csf": "DE.CM-4",  "iso_27001": "A.9.2.4"},
    "Logon from Disabled Account":      {"event_id": 4625,          "severity": "MEDIUM",   "mitre": "T1078",     "nist_csf": "PR.AC-1",  "iso_27001": "A.9.2.6"},
    "After-Hours Logon":                {"event_id": 4624,          "severity": "MEDIUM",   "mitre": "T1078",     "nist_csf": "DE.AE-2",  "iso_27001": "A.9.4.2"},
    "Suspicious Registry Modification": {"event_id": 4657,          "severity": "HIGH",     "mitre": "T1547.001", "nist_csf": "DE.CM-4",  "iso_27001": "A.12.5.1"},
    "Lateral Movement via Network Share": {"event_id": [5140, 5145], "severity": "HIGH",    "mitre": "T1021.002", "nist_csf": "DE.CM-1",  "iso_27001": "A.13.1.3"},
    # Live Windows Firewall configuration audit (pulse/firewall_config.py).
    # event_id=None because these rules inspect the firewall's current
    # policy state via netsh, not a Windows event.
    "Firewall Profile Disabled":          {"event_id": None,          "severity": "HIGH",    "mitre": "T1562.004", "nist_csf": "PR.PT-4",  "iso_27001": "A.13.1.1"},
    "Firewall Any-Any Allow Rule":        {"event_id": None,          "severity": "MEDIUM",  "mitre": "T1562.004", "nist_csf": "PR.IP-1",  "iso_27001": "A.13.1.1"},
    "Firewall Overly Broad Scope":        {"event_id": None,          "severity": "MEDIUM",  "mitre": "T1562.004", "nist_csf": "PR.IP-1",  "iso_27001": "A.13.1.1"},
}


# NIST Cybersecurity Framework — function labels. The subcategories above
# use the "XX.YY-N" convention (e.g. DE.CM-1), so the two-letter prefix
# maps back to one of five functions. Used by the Compliance page to
# group coverage.
NIST_CSF_FUNCTIONS = {
    "ID": "Identify",
    "PR": "Protect",
    "DE": "Detect",
    "RS": "Respond",
    "RC": "Recover",
}


# ISO 27001 Annex A — top-level clause titles. Keys are the clause prefix
# before the second dot (e.g. "A.9" → Access control). Used for the
# Compliance page coverage groupings.
ISO_27001_CLAUSES = {
    "A.9":  "Access control",
    "A.12": "Operations security",
    "A.13": "Communications security",
    "A.16": "Information security incident management",
}


def get_rule_names() -> List[str]:
    """Return a sorted list of every known detection rule name."""
    return sorted(RULE_META.keys())


def get_disabled_rules(config: dict) -> List[str]:
    """Read the disabled-rules list from a parsed pulse.yaml dict."""
    if not isinstance(config, dict):
        return []
    raw = config.get("disabled_rules") or []
    if not isinstance(raw, list):
        return []
    return [str(r) for r in raw if r]


def set_rule_enabled(config: dict, rule: str, enabled: bool) -> dict:
    """
    Mutate ``config`` in place so ``rule`` is enabled/disabled, and
    return the same dict. Adding to the disabled list means the rule
    will be skipped during filtering; removing puts it back in play.
    Unknown rule names are silently accepted — ``list_rules`` on the
    frontend uses ``RULE_META`` so UI buttons can only produce names
    that actually exist, and this keeps the backend forgiving.
    """
    if not isinstance(config, dict):
        config = {}
    current = list(get_disabled_rules(config))
    if enabled:
        current = [r for r in current if r != rule]
    elif rule not in current:
        current.append(rule)
    config["disabled_rules"] = current
    return config


def filter_by_enabled(findings: Iterable[dict], disabled: Iterable[str]) -> list:
    """
    Drop every finding whose ``rule`` appears in ``disabled``. Used in
    both the CLI scan path and the API scan path, right after the
    whitelist filter, so disabling a rule takes effect everywhere.
    """
    disabled_set = set(disabled or [])
    if not disabled_set:
        return list(findings)
    return [f for f in findings if f.get("rule") not in disabled_set]


def build_compliance_summary(disabled: Iterable[str] = ()) -> dict:
    """Aggregate rule metadata into a per-framework coverage summary.

    Returns a dict shaped as::

        {
          "nist_csf":  {"Detect": {"subcategories": {...}, "rules": [...], "enabled": N, "disabled": M}, ...},
          "iso_27001": {"A.9 Access control": {"controls": {...}, "rules": [...], "enabled": N, "disabled": M}, ...},
          "rules":     [ {"name": "...", "nist_csf": "DE.CM-1", "iso_27001": "A.9.4.2",
                          "enabled": True, "severity": "HIGH"}, ... ],
        }

    The Compliance page renders the two top-level framework dicts as
    coverage cards and the flat ``rules`` list as a lookup table so the
    analyst can see which specific rules back a given control.
    """
    disabled_set = set(disabled or [])
    nist_summary: dict = {label: {"subcategories": {}, "rules": [], "enabled": 0, "disabled": 0}
                          for label in NIST_CSF_FUNCTIONS.values()}
    iso_summary: dict = {}

    rules_view = []
    for name in sorted(RULE_META.keys()):
        meta = RULE_META[name]
        is_enabled = name not in disabled_set
        nist_tag = meta.get("nist_csf") or ""
        iso_tag  = meta.get("iso_27001") or ""

        # NIST CSF — first two letters identify the function.
        fn_prefix = (nist_tag.split(".")[0] or "").upper()
        fn_label  = NIST_CSF_FUNCTIONS.get(fn_prefix)
        if fn_label:
            bucket = nist_summary[fn_label]
            bucket["rules"].append(name)
            subs = bucket["subcategories"].setdefault(nist_tag, [])
            subs.append(name)
            if is_enabled: bucket["enabled"]  += 1
            else:          bucket["disabled"] += 1

        # ISO 27001 — "A.9.4.2" → clause prefix "A.9".
        parts = iso_tag.split(".")
        clause_key = ".".join(parts[:2]) if len(parts) >= 2 else ""
        clause_title = ISO_27001_CLAUSES.get(clause_key)
        if clause_title:
            label = f"{clause_key} {clause_title}"
            bucket = iso_summary.setdefault(label, {"controls": {}, "rules": [], "enabled": 0, "disabled": 0})
            bucket["rules"].append(name)
            ctrls = bucket["controls"].setdefault(iso_tag, [])
            ctrls.append(name)
            if is_enabled: bucket["enabled"]  += 1
            else:          bucket["disabled"] += 1

        rules_view.append({
            "name":      name,
            "severity":  meta.get("severity"),
            "mitre":     meta.get("mitre"),
            "nist_csf":  nist_tag,
            "iso_27001": iso_tag,
            "enabled":   is_enabled,
        })

    return {
        "nist_csf":  nist_summary,
        "iso_27001": iso_summary,
        "rules":     rules_view,
    }
