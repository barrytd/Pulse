# pulse/interactive.py
# ---------------------
# Interactive terminal mode for Pulse.
#
# After a scan produces findings, the user can browse them one by one,
# mark findings as investigated, and add items to the pulse.yaml whitelist.
#
# HOW TO USE:
#   Run any scan with the --interactive flag:
#     python main.py --interactive
#     python main.py --logs C:/Windows/System32/winevt/Logs --interactive
#
# CONTROLS:
#   Findings list:  type a number + Enter to inspect   |  q + Enter to quit
#   Detail view:    i = mark investigated               |  w = add to whitelist
#                   b = back to list                    |  q = quit

import os
import re
import textwrap

import yaml


# ---------------------------------------------------------------------------
# Colours  (same palette as monitor.py / main.py)
# ---------------------------------------------------------------------------

_C = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[92m",
    "GREEN":    "\033[92m",
    "CYAN":     "\033[96m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
    "RESET":    "\033[0m",
}

# Rules whose key entity is an account name
_ACCOUNT_RULES = {
    "Brute Force Attempt",
    "Account Lockout",
    "Pass-the-Hash Attempt",
    "Privilege Escalation",
    "User Account Created",
    "Account Takeover Chain",
}

# Rules whose key entity is a service name
_SERVICE_RULES = {
    "Service Installed",
    "Malware Persistence Chain",
    "New Service (Baseline)",
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_interactive_mode(findings, config_path):
    """
    Enter interactive mode to browse and act on scan findings.

    Parameters:
        findings (list):    List of finding dicts from run_all_detections().
        config_path (str):  Absolute path to pulse.yaml (for whitelist writes).
    """
    if not findings:
        print("  No findings to review.")
        return

    # Enable ANSI escape codes on Windows cmd.exe
    if os.name == "nt":
        os.system("")

    # Per-finding status: "new" | "reviewed" | "whitelisted"
    statuses = ["new"] * len(findings)

    try:
        while True:
            _clear()
            _print_header(findings, statuses)
            _print_findings_list(findings, statuses)
            print()
            print(f"  {_C['DIM']}Enter a number to inspect, or [q] to quit.{_C['RESET']}")
            print()

            choice = input("  > ").strip().lower()

            if choice == "q":
                break

            if not choice.isdigit():
                _flash(f"  Type a number between 1 and {len(findings)}.")
                continue

            idx = int(choice) - 1
            if not (0 <= idx < len(findings)):
                _flash(f"  Invalid number. Enter 1–{len(findings)}.")
                continue

            # --- Detail loop ---
            quit_all = _detail_loop(findings, idx, statuses, config_path)
            if quit_all:
                break

    except KeyboardInterrupt:
        pass

    print()
    print(f"  {_C['DIM']}Exiting interactive mode.{_C['RESET']}")
    print()


# ---------------------------------------------------------------------------
# Detail view
# ---------------------------------------------------------------------------

def _detail_loop(findings, idx, statuses, config_path):
    """
    Show the detail view for one finding and handle actions.
    Returns True if the user wants to quit entirely.
    """
    while True:
        _clear()
        _print_finding_detail(findings[idx], idx, statuses[idx])

        action = input("  > ").strip().lower()

        if action == "q":
            return True   # signal outer loop to quit

        if action == "b":
            return False  # back to findings list

        if action == "i":
            statuses[idx] = "reviewed"
            print()
            print(f"  {_C['GREEN']}[*] Marked as investigated.{_C['RESET']}")
            print()
            input("  Press Enter to continue...")
            continue

        if action == "w":
            _handle_whitelist(findings[idx], idx, statuses, config_path)
            input("  Press Enter to continue...")
            continue

        # Unknown key — re-render
        continue


# ---------------------------------------------------------------------------
# Whitelist action
# ---------------------------------------------------------------------------

def _handle_whitelist(finding, idx, statuses, config_path):
    """Detect what to whitelist, confirm with user, write to pulse.yaml."""
    bucket, value = _detect_whitelist_type(finding)

    print()
    print(f"  Add to whitelist?")
    print(f"    Type  : {bucket}")
    print(f"    Value : {value}")
    print()
    confirm = input("  Confirm [y/n]: ").strip().lower()

    if confirm != "y":
        print(f"  {_C['DIM']}Cancelled.{_C['RESET']}")
        return

    ok = _append_to_whitelist(config_path, bucket, value)
    if ok:
        statuses[idx] = "whitelisted"
        print()
        print(f"  {_C['GREEN']}[*] '{value}' added to whitelist[{bucket}].{_C['RESET']}")
        print(f"  {_C['DIM']}Re-run Pulse to apply.{_C['RESET']}")
    else:
        print()
        print(f"  {_C['DIM']}[!] Already in whitelist — no change made.{_C['RESET']}")


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _print_header(findings, statuses):
    """Summary bar at the top of the findings list."""
    total       = len(findings)
    reviewed    = statuses.count("reviewed")
    whitelisted = statuses.count("whitelisted")
    new         = statuses.count("new")

    print()
    print(f"  {'─' * 56}")
    print(f"  {_C['BOLD']}PULSE INTERACTIVE MODE{_C['RESET']}"
          f"  {_C['DIM']}q = quit{_C['RESET']}")
    print(f"  {'─' * 56}")
    print(
        f"  {_C['BOLD']}{total}{_C['RESET']} finding(s)  |  "
        f"{_C['GREEN']}{reviewed}{_C['RESET']} reviewed  |  "
        f"{_C['DIM']}{whitelisted} whitelisted  |  "
        f"{new} new{_C['RESET']}"
    )
    print(f"  {'─' * 56}")
    print()


def _print_findings_list(findings, statuses):
    """Numbered findings table."""
    header = f"  {'#':<4}{'SEVERITY':<12}{'RULE':<36}{'DATE & TIME':<22}  STATUS"
    print(f"  {_C['DIM']}{header.strip()}{_C['RESET']}")
    print(f"  {'─' * 80}")

    for i, (finding, status) in enumerate(zip(findings, statuses), start=1):
        severity  = finding.get("severity", "LOW")
        rule      = finding.get("rule", "Unknown")[:34]
        timestamp = finding.get("timestamp", "")
        colour    = _C.get(severity, _C["RESET"])

        time_str = _extract_time(finding)

        # Status label with colour
        if status == "reviewed":
            status_str = f"{_C['GREEN']}reviewed{_C['RESET']}"
        elif status == "whitelisted":
            status_str = f"{_C['DIM']}whitelisted{_C['RESET']}"
        else:
            status_str = "new"

        print(
            f"  {i:<4}"
            f"{colour}{severity:<12}{_C['RESET']}"
            f"{rule:<36}"
            f"{time_str:<22}  "
            f"{status_str}"
        )


def _print_finding_detail(finding, idx, status):
    """Full detail view for a single finding."""
    severity = finding.get("severity", "LOW")
    colour   = _C.get(severity, _C["RESET"])

    print()
    print(f"  {'─' * 56}")
    print(f"  {_C['BOLD']}Finding #{idx + 1}{_C['RESET']}")
    print(f"  {'─' * 56}")
    print()

    fields = [
        ("Rule",        finding.get("rule",        "N/A")),
        ("Severity",    f"{colour}{severity}{_C['RESET']}"),
        ("Event ID",    str(finding.get("event_id", "N/A"))),
        ("Time",        _extract_time(finding)),
        ("MITRE",       str(finding.get("mitre",   "N/A"))),
        ("Status",      status),
    ]

    for label, value in fields:
        print(f"  {_C['DIM']}{label:<12}{_C['RESET']}{value}")

    print()

    # Description — wrap at 68 chars
    description = finding.get("description", "") or finding.get("details", "")
    if description:
        print(f"  {_C['DIM']}Description{_C['RESET']}")
        for line in textwrap.wrap(description, width=68):
            print(f"    {line}")
        print()

    # Details (if separate from description)
    details = finding.get("details", "")
    if details and details != description:
        print(f"  {_C['DIM']}Details{_C['RESET']}")
        for line in textwrap.wrap(details, width=68):
            print(f"    {line}")
        print()

    print(f"  {'─' * 56}")
    print()
    print(
        f"  {_C['BOLD']}[i]{_C['RESET']} mark investigated  "
        f"  {_C['BOLD']}[w]{_C['RESET']} add to whitelist"
        f"  {_C['BOLD']}[b]{_C['RESET']} back"
        f"  {_C['BOLD']}[q]{_C['RESET']} quit"
    )
    print()


# ---------------------------------------------------------------------------
# Whitelist helpers
# ---------------------------------------------------------------------------

def _detect_whitelist_type(finding):
    """
    Infer which whitelist bucket this finding belongs to and extract the value.

    Returns:
        tuple: (bucket, value) where bucket is one of:
               "accounts", "services", "ips", "rules"
    """
    rule    = finding.get("rule", "")
    details = finding.get("details", "")

    # Account-centric rules — extract the account name
    if rule in _ACCOUNT_RULES:
        match = re.search(r"[Aa]ccount '([^']+)'", details)
        if match:
            return "accounts", match.group(1)

    # Service-centric rules — extract the service name
    if rule in _SERVICE_RULES:
        match = re.search(r"[Ss]ervice '([^']+)'", details)
        if match:
            return "services", match.group(1)

    # IP address in details
    match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", details)
    if match:
        return "ips", match.group(1)

    # Fallback — whitelist the whole rule name
    return "rules", rule


def _append_to_whitelist(config_path, bucket, value):
    """
    Read pulse.yaml, append value to whitelist[bucket], write it back.

    NOTE: yaml.dump does not preserve hand-written comments. Any comments
    in the whitelist section of pulse.yaml will be lost after the first
    whitelist write. Users can re-add them manually if needed.

    Returns:
        bool: True if added, False if already present or on error.
    """
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except OSError:
        print(f"  [!] Could not read {config_path}")
        return False

    # Ensure the whitelist section exists
    if not isinstance(config.get("whitelist"), dict):
        config["whitelist"] = {}

    whitelist = config["whitelist"]

    # Ensure the target bucket exists
    if not isinstance(whitelist.get(bucket), list):
        whitelist[bucket] = []

    # Check for duplicates (case-insensitive for text, exact for IPs)
    existing = whitelist[bucket]
    if bucket == "ips":
        if value in existing:
            return False
    else:
        if value.lower() in [v.lower() for v in existing]:
            return False

    existing.append(value)

    try:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
    except OSError:
        print(f"  [!] Could not write to {config_path}")
        return False

    return True


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _extract_time(finding):
    """Extract a readable date + time from a finding.
    Checks the 'timestamp' field first, then the embedded timestamp in 'details'."""
    ts = finding.get("timestamp", "")
    if ts and "T" in ts:
        date, time = ts.split("T")[0], ts.split("T")[1][:8]
        return f"{date} {time}"
    if ts and " " in ts:
        parts = ts.split(" ")
        return f"{parts[0]} {parts[1][:8]}"
    # Fall back to timestamp embedded in details string
    details = finding.get("details", "")
    m = re.search(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", details)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    return "N/A"


def _clear():
    """Clear the terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def _flash(message):
    """Print a temporary message — user will see it until next render."""
    print()
    print(f"  {_C['DIM']}{message}{_C['RESET']}")
    print()
    input("  Press Enter to continue...")
