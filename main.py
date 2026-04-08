# main.py
# --------
# This is the ENTRY POINT of Pulse — the file you run to kick everything off.
#
# HOW TO RUN:
#   python main.py                            (uses defaults: logs/ and reports/)
#   python main.py --logs /path/to/logs       (custom log folder)
#   python main.py --output myreport.html     (custom output file)
#   python main.py --format html              (html or txt, default is txt)
#   python main.py --help                     (shows all options)
#
# WHAT IT DOES:
#   1. Reads command-line arguments to configure the run
#   2. Looks in the log folder for .evtx files
#   3. Parses each file to extract events
#   4. Runs detection rules against those events
#   5. Generates a report in the chosen format


import os
import argparse                                      # Built-in: handles command-line arguments
from collections import Counter                      # Built-in: counts how often each value appears
import yaml                                          # Third-party: reads YAML config files
from pulse.parser import parse_evtx
from pulse.detections import run_all_detections
from pulse.reporter import generate_report


# Path to the config file. Lives in the project root next to main.py.
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pulse.yaml")


def load_config(config_path=None):
    """
    Loads default settings from a YAML config file.

    YAML is a human-readable data format - it looks like a simple list of
    key: value pairs. Python's yaml.safe_load() reads it into a dictionary.

    If the file doesn't exist, returns an empty dict (all defaults come from argparse).
    If the file has a syntax error, prints a warning and returns an empty dict
    so Pulse can still run with CLI defaults.

    Parameters:
        config_path (str): Path to the YAML file. Defaults to CONFIG_PATH.

    Returns:
        dict: The config values, e.g. {"logs": "logs", "format": "html", ...}
    """
    if config_path is None:
        config_path = CONFIG_PATH

    if not os.path.exists(config_path):
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        # safe_load returns None for an empty file.
        return config if isinstance(config, dict) else {}
    except yaml.YAMLError as e:
        print(f"  [!] Warning: Could not parse {config_path}: {e}")
        print("  [!] Using default settings.")
        return {}


def build_arg_parser(config=None):
    """
    Defines what command-line arguments Pulse accepts.

    argparse is Python's built-in module for building CLI tools.
    You describe your arguments here, and argparse does three things:
      1. Reads them from the command line when the user runs the script
      2. Validates them (e.g. checks required ones are present)
      3. Generates a --help page automatically

    Parameters:
        config (dict): Optional defaults from pulse.yaml. CLI flags override these.

    Returns:
        argparse.ArgumentParser: The configured parser object.
    """
    if config is None:
        config = {}

    # ArgumentParser is the object that knows about all our arguments.
    # description= is what shows up when the user runs: python main.py --help
    parser = argparse.ArgumentParser(
        description="Pulse - Windows Event Log Analyzer for threat detection.",
        epilog="Example: python main.py --logs C:\\Windows\\System32\\winevt\\Logs --format html",
    )

    # --- ARGUMENT: --logs ---
    # config.get("logs", "logs") means: use the value from pulse.yaml if it
    # has a "logs" key, otherwise fall back to "logs" as the hardcoded default.
    # This pattern repeats for every argument below.
    parser.add_argument(
        "--logs",
        default=config.get("logs", "logs"),
        metavar="FOLDER",
        help="Folder containing .evtx files to analyse. Default: logs/",
    )

    # --- ARGUMENT: --output ---
    parser.add_argument(
        "--output",
        default=config.get("output", None),
        metavar="FILE",
        help="Output file path for the report. Default: auto-generated in reports/",
    )

    # --- ARGUMENT: --format ---
    parser.add_argument(
        "--format",
        default=config.get("format", "txt"),
        choices=["txt", "html", "json"],
        metavar="FORMAT",
        help="Report format: txt, html, or json. Default: txt",
    )

    parser.add_argument(
        "--severity",
        default=config.get("severity", "LOW"),
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        metavar="LEVEL",
        help="Only show findings at or above this severity level. Default: LOW (shows everything)",
    )

    return parser


def filter_whitelist(findings, whitelist):
    """
    Removes findings that match whitelisted values.

    The whitelist is a dictionary with four optional lists:
      accounts:  usernames to ignore (matched against finding details)
      rules:     rule names to skip entirely
      services:  service names to ignore (matched against finding details)
      ips:       IP addresses to ignore (matched against finding details)

    A finding is removed if:
      - Its rule name is in the "rules" list, OR
      - Any whitelisted account, service, or IP appears in the finding's details text

    Parameters:
        findings (list):   List of finding dicts from the detection engine.
        whitelist (dict):  Whitelist config from pulse.yaml.

    Returns:
        list: Filtered findings with whitelisted items removed.
    """
    if not whitelist:
        return findings

    # Pull out each whitelist category. Use empty lists as defaults.
    skip_rules = [r.lower() for r in whitelist.get("rules", []) or []]
    skip_accounts = [a.lower() for a in whitelist.get("accounts", []) or []]
    skip_services = [s.lower() for s in whitelist.get("services", []) or []]
    skip_ips = whitelist.get("ips", []) or []

    filtered = []
    for finding in findings:
        # Check 1: is the entire rule whitelisted?
        if finding["rule"].lower() in skip_rules:
            continue

        # Check 2: does the details text contain any whitelisted value?
        # We lowercase the details for case-insensitive matching.
        details_lower = finding["details"].lower()

        # Check accounts - look for the account name inside quotes in the details.
        # e.g. "Account 'svc_backup' had 5+ failed login attempts..."
        if any(account in details_lower for account in skip_accounts):
            continue

        # Check services - same approach.
        # e.g. "New service 'WindowsUpdateSvc' was installed..."
        if any(service in details_lower for service in skip_services):
            continue

        # Check IPs - these are case-sensitive (IPs don't have case).
        if any(ip in finding["details"] for ip in skip_ips):
            continue

        filtered.append(finding)

    return filtered


BANNER = r"""
  ____  _   _ _     ____  _____
 |  _ \| | | | |   / ___|| ____|
 | |_) | | | | |   \___ \|  _|
 |  __/| |_| | |___ ___) | |___
 |_|    \___/|_____|____/|_____|

  Windows Event Log Analyzer  |  Blue Team Edition
  --------------------------------------------------
"""


def main():
    """
    The main function that orchestrates the entire Pulse workflow.
    """

    # Print the banner first so it's the first thing the user sees.
    # end="" avoids adding an extra blank line after the banner (it already has one).
    print(BANNER)

    # --- STEP 0: LOAD CONFIG + PARSE COMMAND-LINE ARGUMENTS ---
    # First we load pulse.yaml (if it exists) to get default values.
    # Then argparse reads the CLI flags. If the user typed --format html,
    # that overrides whatever pulse.yaml says. If they didn't type --format,
    # the value from pulse.yaml is used. If pulse.yaml doesn't exist either,
    # the hardcoded defaults kick in (e.g. "txt").
    config = load_config()
    if config:
        print("  [*] Loaded settings from pulse.yaml")
    parser = build_arg_parser(config)
    args = parser.parse_args()

    # Pull the values out into plain variables for readability.
    log_folder = args.logs
    output_path = args.output
    report_format = args.format
    severity_filter = args.severity

    # --- STEP 1: PREFLIGHT CHECKS ---
    if not os.path.exists(log_folder):
        print(f"[!] Log folder '{log_folder}' not found. Creating it...")
        os.makedirs(log_folder)

    # Make sure the reports/ folder exists (unless the user gave a full path).
    # If they gave --output /tmp/report.txt we don't need to create reports/.
    if output_path is None:
        report_folder = "reports"
        if not os.path.exists(report_folder):
            print(f"[!] Report folder '{report_folder}' not found. Creating it...")
            os.makedirs(report_folder)

    # --- STEP 2: FIND LOG FILES ---
    log_files = [f for f in os.listdir(log_folder) if f.endswith(".evtx")]

    if not log_files:
        print(f"  No .evtx files found in '{log_folder}'.")
        print("  Drop your Windows event log files there and run again.")
        print()
        print("  Export logs from Event Viewer:")
        print("  Windows Logs > Security > Save All Events As...")
        print()
        return

    # --- STEP 3: PARSE EACH LOG FILE ---
    all_events = []

    for log_file in log_files:
        file_path = os.path.join(log_folder, log_file)
        print(f"  [*] Parsing: {log_file}")
        events = parse_evtx(file_path)
        if events:
            all_events.extend(events)

    print(f"  [*] Total events parsed: {len(all_events)}")
    print()

    # --- STEP 3b: BUILD SCAN STATISTICS ---
    # Counter is a dict subclass that counts how many times each value appears.
    # Counter([4625, 4625, 4720, 4625]) -> {4625: 3, 4720: 1}
    # .most_common(10) gives the top 10 as a list of (event_id, count) tuples.
    event_counts = Counter(e["event_id"] for e in all_events)

    # Collect all timestamps, filter out "Unknown", and sort to find the range.
    # min() and max() give us the earliest and latest event times.
    timestamps = sorted(e["timestamp"] for e in all_events if e["timestamp"] != "Unknown")

    scan_stats = {
        "total_events": len(all_events),
        "files_scanned": len(log_files),
        "earliest": timestamps[0] if timestamps else "Unknown",
        "latest": timestamps[-1] if timestamps else "Unknown",
        "top_event_ids": event_counts.most_common(10),
    }

    # --- STEP 4: RUN DETECTIONS ---
    print("  [*] Running detection rules...")
    findings = run_all_detections(all_events)

    # --- FILTER BY SEVERITY ---
    # SEVERITY_ORDER is a list where position = rank.
    # "LOW" is at index 0 (lowest), "CRITICAL" is at index 3 (highest).
    # We keep a finding only if its severity rank is >= the user's chosen rank.
    SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    findings = [
        f for f in findings
        if SEVERITY_ORDER.index(f["severity"]) >= SEVERITY_ORDER.index(severity_filter)
    ]

    # --- FILTER BY WHITELIST ---
    # Remove findings that match known-good accounts, services, IPs, or rules
    # defined in the whitelist section of pulse.yaml.
    whitelist = config.get("whitelist", {})
    before_count = len(findings)
    findings = filter_whitelist(findings, whitelist)
    suppressed = before_count - len(findings)
    if suppressed > 0:
        print(f"  [*] Whitelist suppressed {suppressed} finding(s)")

    print(f"  [*] Findings: {len(findings)}")

    # --- STEP 5: GENERATE REPORT ---
    if findings:
        print(f"  [*] Generating {report_format.upper()} report...")

        # We pass output_path (may be None) and report_format to the reporter.
        # The reporter will handle auto-naming if output_path is None.
        report_path = generate_report(findings, output_path=output_path, fmt=report_format, scan_stats=scan_stats)
        print(f"  [*] Report saved to: {report_path}")
    else:
        print("  [*] No suspicious activity detected. You're clean!")

    print()
    print("=" * 50)
    print("  Scan complete.")
    print("=" * 50)


if __name__ == "__main__":
    main()
