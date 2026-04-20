# pulse/comparison.py
# -------------------
# Pure diff logic for two scans' findings lists.
#
# Two findings are considered "the same" when they share a rule name and a
# description — the description usually carries the identifying bits
# (account, IP, service name) that make one brute-force hit distinct from
# another. Using both prevents the trivial case where two scans both
# include "Brute Force Attempt" from collapsing every variant together.

from pulse.remediation import attach_remediation


def _key(finding):
    """Stable identity key for a finding across scans."""
    return (finding.get("rule", ""), finding.get("description", ""))


def diff_findings(findings_a, findings_b):
    """
    Diff two lists of findings.

    Returns a dict with:
        new:      findings in B but not in A (appeared in the newer scan)
        resolved: findings in A but not in B (disappeared in the newer scan)
        shared:   findings present in both (carried over)

    Each bucket is decorated with remediation / mitigations so the frontend
    can render the drawer without another lookup.

    The caller decides which scan is "before" (A) and which is "after" (B).
    """
    a_by_key = {_key(f): f for f in findings_a or []}
    b_by_key = {_key(f): f for f in findings_b or []}

    new_keys      = set(b_by_key) - set(a_by_key)
    resolved_keys = set(a_by_key) - set(b_by_key)
    shared_keys   = set(a_by_key) & set(b_by_key)

    # Keep original iteration order rather than set order so output is stable.
    new_list      = [b_by_key[k] for k in (_key(f) for f in findings_b) if k in new_keys]
    resolved_list = [a_by_key[k] for k in (_key(f) for f in findings_a) if k in resolved_keys]
    # For shared we prefer the B side (newer metadata like review flags).
    shared_list   = [b_by_key[k] for k in (_key(f) for f in findings_b) if k in shared_keys]

    return {
        "new":      attach_remediation(list(new_list)),
        "resolved": attach_remediation(list(resolved_list)),
        "shared":   attach_remediation(list(shared_list)),
    }
