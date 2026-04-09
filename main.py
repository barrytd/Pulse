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


import json
import os
import argparse                                      # Built-in: handles command-line arguments
from collections import Counter                      # Built-in: counts how often each value appears
import yaml                                          # Third-party: reads YAML config files
from pulse.parser import parse_evtx
from pulse.detections import run_all_detections
from pulse.reporter import generate_report, SEVERITY_ORDER
from pulse.emailer import send_report, validate_email_config
from pulse.database import init_db, save_scan, get_history
from pulse.reporter import _calculate_score
from pulse.monitor import start_monitor


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
        choices=["txt", "html", "json", "csv"],
        metavar="FORMAT",
        help="Report format: txt, html, json, or csv. Default: txt",
    )

    parser.add_argument(
        "--severity",
        default=config.get("severity", "LOW"),
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        metavar="LEVEL",
        help="Only show findings at or above this severity level. Default: LOW (shows everything)",
    )

    # --- ARGUMENT: --email ---
    # When passed, Pulse sends the finished report to the recipient
    # configured in the email section of pulse.yaml.
    parser.add_argument(
        "--email",
        action="store_true",
        help="Send the finished report via email (requires email settings in pulse.yaml).",
    )

    # --- ARGUMENT: --history ---
    # Shows a table of past scans stored in the local database.
    parser.add_argument(
        "--history",
        action="store_true",
        help="Show a summary of past scans from the local database.",
    )

    # --- ARGUMENT: --watch ---
    # Enters live monitoring mode: polls the log folder every --interval
    # seconds and alerts on new suspicious events as they appear.
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Enter live monitoring mode. Polls for new events continuously.",
    )

    # --- ARGUMENT: --interval ---
    parser.add_argument(
        "--interval",
        type=int,
        default=config.get("monitor", {}).get("interval", 30) if config.get("monitor") else 30,
        metavar="SECONDS",
        help="How often to check for new events in --watch mode. Default: 30s",
    )

    # --- ARGUMENT: --save-baseline ---
    # This flag captures the current state of accounts, services, and tasks
    # as a "known good" snapshot. Future scans compare against it and flag
    # anything new that wasn't there before.
    parser.add_argument(
        "--save-baseline",
        action="store_true",        # No value needed - just --save-baseline
        help="Save a baseline snapshot of accounts, services, and tasks for future comparison.",
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


BASELINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pulse_baseline.json")


def build_baseline(events):
    """
    Extracts a snapshot of "known good" entities from parsed events.

    We record which accounts, services, and scheduled tasks exist right now.
    On future scans, anything NEW that wasn't in this snapshot is flagged
    as an anomaly worth investigating.

    Parameters:
        events (list): Parsed events from the log files.

    Returns:
        dict: Baseline snapshot with accounts, services, and tasks lists.
    """
    import xml.etree.ElementTree as ET

    NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

    accounts  = set()
    services  = set()
    tasks     = set()

    for event in events:
        try:
            xml_tree = ET.fromstring(event["data"])
            event_data = xml_tree.find(f"{NS}EventData")
            if event_data is None:
                continue

            fields = {d.get("Name"): d.text for d in event_data}

            if event["event_id"] == 4720:   # User account created
                name = fields.get("TargetUserName")
                if name:
                    accounts.add(name.lower())

            elif event["event_id"] == 7045:  # Service installed
                name = fields.get("ServiceName")
                if name:
                    services.add(name.lower())

            elif event["event_id"] == 4698:  # Scheduled task created
                name = fields.get("TaskName")
                if name:
                    tasks.add(name.lower())

        except Exception:
            continue

    return {
        "created_at": __import__("datetime").datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "accounts":  sorted(accounts),
        "services":  sorted(services),
        "tasks":     sorted(tasks),
    }


def save_baseline(events, path=None):
    """Builds and saves the baseline snapshot to a JSON file."""
    if path is None:
        path = BASELINE_PATH
    baseline = build_baseline(events)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)
    return path, baseline


def load_baseline(path=None):
    """
    Loads the baseline snapshot from disk.

    Returns None if the file doesn't exist (first run, no baseline yet).
    """
    if path is None:
        path = BASELINE_PATH
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def compare_baseline(findings, baseline):
    """
    Compares findings against the baseline and tags any finding where the
    account, service, or task was NOT in the baseline as a new anomaly.

    Instead of removing findings, we add a "new_since_baseline" field so
    the reporter can highlight them. We also generate extra findings for
    any new item that appeared in the events but not in the baseline.

    Parameters:
        findings (list):  Detection findings after all rules have run.
        baseline (dict):  Loaded baseline snapshot.

    Returns:
        list: Findings with "new_since_baseline" key added where relevant,
              plus any new baseline-comparison findings prepended.
    """
    import re

    known_accounts = set(baseline.get("accounts", []))
    known_services = set(baseline.get("services", []))
    known_tasks    = set(baseline.get("tasks", []))

    extra = []

    for finding in findings:
        details_lower = finding["details"].lower()

        # Look for newly created accounts not in the baseline.
        if finding["rule"] == "User Account Created":
            # Extract the account name from the details string.
            match = re.search(r"new account '([^']+)'", details_lower)
            if match:
                account = match.group(1)
                if account not in known_accounts:
                    extra.append({
                        "rule": "New Account (Baseline)",
                        "severity": "HIGH",
                        "details": (
                            f"Account '{match.group(1)}' did not exist at baseline. "
                            f"Original finding: {finding['details']}"
                        ),
                    })

        # Look for newly installed services not in the baseline.
        elif finding["rule"] in ("Service Installed", "Malware Persistence Chain"):
            match = re.search(r"service '([^']+)'", details_lower)
            if match:
                service = match.group(1)
                if service not in known_services:
                    extra.append({
                        "rule": "New Service (Baseline)",
                        "severity": "HIGH",
                        "details": (
                            f"Service '{match.group(1)}' did not exist at baseline. "
                            f"Original finding: {finding['details']}"
                        ),
                    })

        # Look for newly created tasks not in the baseline.
        elif finding["rule"] == "Scheduled Task Created":
            match = re.search(r"task '([^']+)'", details_lower)
            if match:
                task = match.group(1)
                if task not in known_tasks:
                    extra.append({
                        "rule": "New Task (Baseline)",
                        "severity": "MEDIUM",
                        "details": (
                            f"Scheduled task '{match.group(1)}' did not exist at baseline. "
                            f"Original finding: {finding['details']}"
                        ),
                    })

    return extra + findings


def _print_history(db_path):
    """
    Prints a formatted table of past scans from the database.

    Shows scan ID, date, hostname, findings count, score, label, and a
    trend arrow (↑ better / ↓ worse) compared to the previous scan.
    """
    scans = get_history(db_path)

    if not scans:
        print("  No scan history found. Run a scan first to start building history.")
        return

    print(f"  {'ID':<5} {'Date':<20} {'Host':<20} {'Findings':<10} {'Score':<7} {'Label':<14} {'Trend'}")
    print("  " + "-" * 80)

    for i, scan in enumerate(scans):
        scan_id  = scan["id"]
        date     = scan["scanned_at"]
        host     = (scan["hostname"] or "Unknown")[:18]
        findings = scan["total_findings"]
        score    = scan["score"] if scan["score"] is not None else "-"
        label    = (scan["score_label"] or "-")[:13]

        # Trend: compare score to the next row (which is the previous scan,
        # since results are newest-first).
        trend = ""
        if i < len(scans) - 1 and scan["score"] is not None and scans[i + 1]["score"] is not None:
            diff = scan["score"] - scans[i + 1]["score"]
            if diff > 0:
                trend = f"↑ +{diff}"
            elif diff < 0:
                trend = f"↓ {diff}"
            else:
                trend = "="

        print(f"  {scan_id:<5} {date:<20} {host:<20} {findings:<10} {score:<7} {label:<14} {trend}")

    print()


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
    log_folder         = args.logs
    output_path        = args.output
    report_format      = args.format
    severity_filter    = args.severity
    save_baseline_flag = args.save_baseline
    send_email_flag    = args.email
    show_history_flag  = args.history
    watch_flag         = args.watch
    watch_interval     = args.interval

    # DB path comes from config, defaulting to pulse.db in the project root.
    db_config = config.get("database", {})
    db_path   = (db_config or {}).get("path", "pulse.db") if db_config is not None else "pulse.db"

    # Always initialise the DB (creates tables if they don't exist yet).
    if db_path:
        init_db(db_path)

    # --- HISTORY MODE ---
    # If --history was passed, print past scans and exit immediately.
    if show_history_flag:
        _print_history(db_path)
        return

    # --- WATCH MODE ---
    # If --watch was passed, enter live monitoring and never return
    # until the user presses Ctrl+C.
    #
    # LIVE MODE: if no custom --logs was given (user is using the default
    # "logs" folder), use wevtutil to query the live Windows event channels
    # directly. This sees new events in real time without file-locking issues.
    #
    # FILE MODE: if --logs points at a specific folder, poll those .evtx files
    # instead (useful for watching exported/forensic log files).
    if watch_flag:
        whitelist = config.get("whitelist", {})
        default_logs = config.get("logs", "logs")
        use_live = (log_folder == default_logs)
        start_monitor(
            log_folder=log_folder,
            interval=watch_interval,
            severity_filter=severity_filter,
            whitelist=whitelist,
            db_path=db_path if db_path else None,
            live=use_live,
        )
        return

    # --- STEP 1: PREFLIGHT CHECKS ---
    # Validate email config early so we don't scan for 10 minutes
    # and then fail at the last step because the password was wrong.
    email_config = config.get("email", {})
    if send_email_flag:
        error = validate_email_config(email_config)
        if error:
            print(f"  [!] {error}")
            print("      Fill in the email section of pulse.yaml and try again.")
            print()
            return

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

    # --- STEP 3c: SAVE OR LOAD BASELINE ---
    # If --save-baseline was passed, capture the current state and exit.
    # The user should do this on a clean, known-good machine before attackers
    # have made any changes. Then future scans compare against it.
    if save_baseline_flag:
        path, baseline = save_baseline(all_events)
        print(f"  [*] Baseline saved to: {path}")
        print(f"      Accounts : {len(baseline['accounts'])}")
        print(f"      Services : {len(baseline['services'])}")
        print(f"      Tasks    : {len(baseline['tasks'])}")
        print()
        print("  Run Pulse normally to compare future scans against this baseline.")
        print()
        return

    # Auto-load the baseline if it exists. If it does, any new accounts,
    # services, or tasks found in this scan that weren't there before
    # will generate extra findings.
    baseline = load_baseline()
    if baseline:
        print(f"  [*] Baseline loaded (captured {baseline['created_at']})")

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

    # --- APPLY BASELINE COMPARISON ---
    # If a baseline was loaded, prepend extra findings for anything new.
    if baseline:
        before = len(findings)
        findings = compare_baseline(findings, baseline)
        new_count = len(findings) - before
        if new_count > 0:
            print(f"  [*] Baseline flagged {new_count} new item(s) not seen before")

    print(f"  [*] Findings: {len(findings)}")

    # --- STEP 5: GENERATE REPORT ---
    if findings:
        print(f"  [*] Generating {report_format.upper()} report...")

        # We pass output_path (may be None) and report_format to the reporter.
        # The reporter will handle auto-naming if output_path is None.
        report_path = generate_report(findings, output_path=output_path, fmt=report_format, scan_stats=scan_stats)
        print(f"  [*] Report saved to: {report_path}")

        # --- STEP 6: SEND EMAIL ---
        # Only runs if --email was passed and config is valid (already checked).
        if send_email_flag:
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in findings:
                sev = f.get("severity", "LOW")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            print(f"  [*] Sending report to {email_config['recipient']}...")
            success = send_report(email_config, severity_counts,
                                  len(findings), findings=findings,
                                  report_path=report_path)
            if success:
                print(f"  [*] Email sent successfully.")
    else:
        print("  [*] No suspicious activity detected. You're clean!")

    # --- STEP 7: SAVE TO DATABASE ---
    # Always save the scan result so --history works over time.
    if db_path:
        severity_counts_db = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW")
            severity_counts_db[sev] = severity_counts_db.get(sev, 0) + 1

        score, score_label, _ = _calculate_score(severity_counts_db)
        scan_id = save_scan(db_path, findings, scan_stats=scan_stats,
                            score=score, score_label=score_label)
        print(f"  [*] Scan #{scan_id} saved to database ({db_path})")

    print()
    print("=" * 50)
    print("  Scan complete.")
    print("=" * 50)


if __name__ == "__main__":
    main()
