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
import argparse                                      # NEW: handles command-line arguments
from collections import Counter                      # Counts how often each event ID appears
from pulse.parser import parse_evtx
from pulse.detections import run_all_detections
from pulse.reporter import generate_report


def build_arg_parser():
    """
    Defines what command-line arguments Pulse accepts.

    argparse is Python's built-in module for building CLI tools.
    You describe your arguments here, and argparse does three things:
      1. Reads them from the command line when the user runs the script
      2. Validates them (e.g. checks required ones are present)
      3. Generates a --help page automatically

    Returns:
        argparse.ArgumentParser: The configured parser object.
    """

    # ArgumentParser is the object that knows about all our arguments.
    # description= is what shows up when the user runs: python main.py --help
    parser = argparse.ArgumentParser(
        description="Pulse — Windows Event Log Analyzer for threat detection.",
        epilog="Example: python main.py --logs C:\\Windows\\System32\\winevt\\Logs --format html",
    )

    # --- ARGUMENT: --logs ---
    # This tells Pulse where to find .evtx files.
    # default="logs" means if the user doesn't supply it, we use "logs/".
    # metavar is what shows in the --help output instead of the internal variable name.
    parser.add_argument(
        "--logs",
        default="logs",
        metavar="FOLDER",
        help="Folder containing .evtx files to analyse. Default: logs/",
    )

    # --- ARGUMENT: --output ---
    # Where to save the report. If not supplied, we auto-generate a filename.
    # default=None means "not specified" — the reporter will create a name.
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Output file path for the report. Default: auto-generated in reports/",
    )

    # --- ARGUMENT: --format ---
    # Which report format to generate.
    # choices= restricts the user to only these values — argparse will error
    # automatically if they type something else (e.g. --format pdf).
    parser.add_argument(
        "--format",
        default="txt",
        choices=["txt", "html", "json"],
        metavar="FORMAT",
        help="Report format: txt, html, or json. Default: txt",
    )

    parser.add_argument(
        "--severity",
        default="LOW",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        metavar="LEVEL",
        help="Only show findings at or above this severity level. Default: LOW (shows everything)",
    )

    return parser


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

    # --- STEP 0: PARSE COMMAND-LINE ARGUMENTS ---
    parser = build_arg_parser()
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
