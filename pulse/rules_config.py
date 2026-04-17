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
    "Brute Force Attempt":              {"event_id": 4625,          "severity": "HIGH",     "mitre": "T1110"},
    "User Account Created":             {"event_id": 4720,          "severity": "MEDIUM",   "mitre": "T1136.001"},
    "Privilege Escalation":             {"event_id": 4732,          "severity": "HIGH",     "mitre": "T1548"},
    "Audit Log Cleared":                {"event_id": 1102,          "severity": "HIGH",     "mitre": "T1070.001"},
    "RDP Logon Detected":               {"event_id": 4624,          "severity": "MEDIUM",   "mitre": "T1021.001"},
    "Pass-the-Hash Attempt":            {"event_id": 4624,          "severity": "HIGH",     "mitre": "T1550.002"},
    "Service Installed":                {"event_id": 7045,          "severity": "MEDIUM",   "mitre": "T1543.003"},
    "Antivirus Disabled":               {"event_id": 5001,          "severity": "HIGH",     "mitre": "T1562.001"},
    "Firewall Disabled":                {"event_id": 4950,          "severity": "HIGH",     "mitre": "T1562.004"},
    "Firewall Rule Changed":            {"event_id": [4946, 4947],  "severity": "MEDIUM",   "mitre": "T1562.004"},
    "Account Lockout":                  {"event_id": 4740,          "severity": "HIGH",     "mitre": "T1110"},
    "Scheduled Task Created":           {"event_id": 4698,          "severity": "MEDIUM",   "mitre": "T1053.005"},
    "Suspicious PowerShell":            {"event_id": 4104,          "severity": "HIGH",     "mitre": "T1059.001"},
    "Account Takeover Chain":           {"event_id": None,          "severity": "CRITICAL", "mitre": "T1078"},
    "Malware Persistence Chain":        {"event_id": None,          "severity": "CRITICAL", "mitre": "T1543.003"},
    "Kerberoasting":                    {"event_id": 4769,          "severity": "HIGH",     "mitre": "T1558.003"},
    "Golden Ticket":                    {"event_id": 4768,          "severity": "CRITICAL", "mitre": "T1558.001"},
    "Credential Dumping":               {"event_id": [4656, 4663],  "severity": "CRITICAL", "mitre": "T1003.001"},
    "Logon from Disabled Account":      {"event_id": 4625,          "severity": "MEDIUM",   "mitre": "T1078"},
    "After-Hours Logon":                {"event_id": 4624,          "severity": "MEDIUM",   "mitre": "T1078"},
    "Suspicious Registry Modification": {"event_id": 4657,          "severity": "HIGH",     "mitre": "T1547.001"},
    "Lateral Movement via Network Share": {"event_id": [5140, 5145], "severity": "HIGH",    "mitre": "T1021.002"},
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
