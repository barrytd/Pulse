# main.py
# --------
# This is the ENTRY POINT of Pulse — the file you run to kick everything off.
#
# HOW TO RUN:
#   python main.py
#
# WHAT IT DOES (once fully built):
#   1. Looks in the "logs/" folder for .evtx files
#   2. Parses each file to extract events
#   3. Runs detection rules against those events
#   4. Generates a report and saves it to "reports/"
#
# WHY IS THIS FILE SEPARATE?
# "main.py" is a Python convention. It keeps the startup logic in one
# obvious place. The actual work happens in the modules inside pulse/.
# This file just wires them together.


import os                          # For working with file paths and directories
from pulse.parser import parse_evtx              # Step 1: Read log files
from pulse.detections import run_all_detections  # Step 2: Detect threats
from pulse.reporter import generate_report       # Step 3: Write the report


def main():
    """
    The main function that orchestrates the entire Pulse workflow.
    """

    # --- CONFIGURATION ---
    # These variables control where Pulse looks for logs and saves reports.
    # Later we'll replace these with command-line arguments so the user
    # can customize them without editing code.
    log_folder = "logs"
    report_folder = "reports"

    # --- STEP 0: PREFLIGHT CHECKS ---
    # Make sure the folders we need actually exist.
    # os.path.exists() returns True if the folder is there, False if not.
    if not os.path.exists(log_folder):
        print(f"[!] Log folder '{log_folder}' not found. Creating it...")
        os.makedirs(log_folder)

    if not os.path.exists(report_folder):
        print(f"[!] Report folder '{report_folder}' not found. Creating it...")
        os.makedirs(report_folder)

    # --- STEP 1: FIND LOG FILES ---
    # os.listdir() gives us every filename in the folder.
    # We filter for files ending in ".evtx" (Windows event logs).
    # The list comprehension below is a compact way to build a filtered list.
    log_files = [f for f in os.listdir(log_folder) if f.endswith(".evtx")]

    if not log_files:
        print("=" * 50)
        print("  PULSE — Windows Event Log Analyzer")
        print("=" * 50)
        print()
        print("  No .evtx files found in the 'logs/' folder.")
        print("  Drop your Windows event log files there and run again.")
        print()
        print("  On a Windows machine, you can export logs from:")
        print("  Event Viewer > Windows Logs > Security > Save All Events As...")
        print()
        return  # Exit early — nothing to analyze

    # --- STEP 2: PARSE EACH LOG FILE ---
    print("=" * 50)
    print("  PULSE — Windows Event Log Analyzer")
    print("=" * 50)
    print()

    all_events = []  # We'll collect events from ALL log files into one list

    for log_file in log_files:
        # os.path.join() safely combines folder + filename for any OS.
        # It uses the right slash (\ on Windows, / on Mac/Linux).
        file_path = os.path.join(log_folder, log_file)
        print(f"  [*] Parsing: {log_file}")

        events = parse_evtx(file_path)
        if events:
            all_events.extend(events)  # .extend() adds items from one list to another

    print(f"  [*] Total events parsed: {len(all_events)}")
    print()

    # --- STEP 3: RUN DETECTIONS ---
    print("  [*] Running detection rules...")
    findings = run_all_detections(all_events)
    print(f"  [*] Findings: {len(findings)}")
    print()

    # --- STEP 4: GENERATE REPORT ---
    if findings:
        print("  [*] Generating report...")
        report_path = generate_report(findings)
        print(f"  [*] Report saved to: {report_path}")
    else:
        print("  [*] No suspicious activity detected. You're clean!")

    print()
    print("=" * 50)
    print("  Scan complete.")
    print("=" * 50)


# --- WHAT IS THIS BLOCK? ---
# This is a Python convention. It means:
# "Only run main() if this file is executed directly."
# If someone imports this file from another script, main() won't run
# automatically — they'd have to call it themselves.
# This is important for testing and for when Pulse grows into a larger app.
if __name__ == "__main__":
    main()
