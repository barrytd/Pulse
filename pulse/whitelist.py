# pulse/whitelist.py
# ------------------
# Applies the Pulse whitelist to a list of findings.
#
# WHAT IS THE WHITELIST?
# Some events that look suspicious are actually legitimate for your
# environment — e.g. a service account that genuinely logs in from
# multiple machines, an IP block that belongs to your security tool,
# or a scheduled task Windows creates on every boot. The whitelist
# tells Pulse to ignore these so your report only shows real anomalies.
#
# Two layers stack together:
#   1. BUILT-IN: pulse/known_good.py lists 100+ known-good services
#      (anti-cheat, Google, Microsoft, etc.) and is always applied.
#   2. USER:    the "whitelist" section of pulse.yaml lets each user
#               add their own accounts, services, IPs, or whole rules.
#
# This module lives in pulse/ (instead of main.py) so both the CLI and
# the REST API can use the same filtering logic. If it were in main.py,
# the API would have to import main.py, which triggers a fresh load of
# the CLI entry point — bad news for tests and uvicorn startup.

from pulse.known_good import KNOWN_GOOD_SERVICES


def filter_whitelist(findings, whitelist):
    """
    Remove findings that match whitelisted values.

    The whitelist is a dictionary with four optional lists:
        accounts:  usernames to ignore (matched in finding details)
        rules:     rule names to skip entirely
        services:  service names to ignore (matched in finding details)
        ips:       IP addresses to ignore (matched in finding details)

    A finding is dropped if:
        - Its rule name is in the "rules" list, OR
        - Any whitelisted account, service, or IP appears in details text

    Parameters:
        findings (list):   Findings from run_all_detections().
        whitelist (dict):  Whitelist section from pulse.yaml (may be empty).

    Returns:
        list: Filtered findings with whitelisted items removed.
    """
    if not whitelist:
        whitelist = {}

    skip_rules    = [r.lower() for r in whitelist.get("rules", []) or []]
    skip_accounts = [a.lower() for a in whitelist.get("accounts", []) or []]
    skip_services = (
        KNOWN_GOOD_SERVICES
        + [s.lower() for s in whitelist.get("services", []) or []]
    )
    skip_ips = whitelist.get("ips", []) or []

    filtered = []
    for finding in findings:
        if finding["rule"].lower() in skip_rules:
            continue

        details_lower = finding["details"].lower()

        if any(account in details_lower for account in skip_accounts):
            continue
        if any(service in details_lower for service in skip_services):
            continue
        if any(ip in finding["details"] for ip in skip_ips):
            continue

        filtered.append(finding)

    return filtered
