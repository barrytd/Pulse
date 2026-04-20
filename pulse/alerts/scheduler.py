# pulse/scheduler.py
# -------------------
# Scheduled-scan mode — watches a folder for new .evtx files and runs a full
# scan on each one as it arrives. Useful for SOC pipelines where logs from
# many endpoints are dropped into a shared folder and need to be picked up
# automatically.
#
# DESIGN:
#   - Poll the watch folder every `interval` seconds (default 60).
#   - Track (abs_path, size) tuples for files we've already processed.
#     Including size guards against partial writes: a file that's still
#     growing won't be scanned until its size stabilises between polls.
#   - For each stable new file, call on_new_file(path). The caller decides
#     what "scan" means — typically parse → detect → save → alert.
#   - Return to the top of the loop, sleep, repeat. Stops on Ctrl+C.
#
# NOT PERSISTED: the seen-files set lives only in memory, so a restarted
# scheduler re-scans files it already processed. That is fine for cron-style
# use (one-shot per file drop) and keeps the module dependency-free.

import os
import time


def _evtx_files_in(folder):
    """Return a sorted list of absolute .evtx paths currently in `folder`."""
    if not os.path.isdir(folder):
        return []
    out = []
    for name in os.listdir(folder):
        if not name.lower().endswith(".evtx"):
            continue
        path = os.path.join(folder, name)
        if os.path.isfile(path):
            out.append(os.path.abspath(path))
    out.sort()
    return out


def _file_size(path):
    """Size in bytes, or None if the file vanished mid-scan."""
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def find_new_stable_files(folder, seen):
    """
    One poll iteration: look at the folder and return which files are
    ready to scan. A file is ready if:
      1. Its absolute path is not in `seen`.
      2. Its size matches the size recorded on the previous poll — i.e.
         the writer has stopped appending. Files seen for the first time
         are recorded but NOT returned; we wait one more poll to confirm
         the file is stable before scanning.

    Parameters:
        folder (str): Directory to scan.
        seen (dict):  {abs_path: last_known_size}. Mutated in place.

    Returns:
        list[str]: Absolute paths of files that are new AND stable.
    """
    ready = []
    for path in _evtx_files_in(folder):
        prev_size = seen.get(path)
        if prev_size == -1:
            # Sentinel: already scanned. Never touch again.
            continue
        size = _file_size(path)
        if size is None:
            continue
        if prev_size is None:
            # First sighting — record size and wait for the next poll.
            seen[path] = size
            continue
        if prev_size == size:
            # Stable since last poll and not yet processed — scan now.
            ready.append(path)
            seen[path] = -1
        else:
            # Size changed — file is still being written. Update and wait.
            seen[path] = size
    return ready


def run_scheduler(folder, interval, on_new_file, log=print, sleep=time.sleep,
                  stop_after=None):
    """
    Main scheduler loop. Polls `folder` every `interval` seconds and calls
    `on_new_file(path)` for every new stable .evtx file it finds.

    Parameters:
        folder (str):          Directory to watch.
        interval (int):        Seconds between polls.
        on_new_file (callable): Invoked with one absolute file path per new file.
        log (callable):        Where to send status lines (print by default;
                               pass a no-op in --quiet mode).
        sleep (callable):      Sleep function. Overridable for tests.
        stop_after (int|None): Optional cap on number of iterations (for tests).
                               None = run forever until Ctrl+C.

    Returns:
        dict: {"iterations": n, "scanned": [list of file paths processed]}.
              Only meaningful when stop_after is set; production use loops forever.
    """
    if not os.path.isdir(folder):
        os.makedirs(folder, exist_ok=True)

    log(f"  [*] Scheduler watching {folder} (every {interval}s)")
    log("      Drop .evtx files into the folder — they will be scanned automatically.")
    log("      Press Ctrl+C to stop.")

    seen = {}
    scanned = []
    iterations = 0

    try:
        while True:
            ready = find_new_stable_files(folder, seen)
            for path in ready:
                log(f"  [*] New file detected: {os.path.basename(path)}")
                try:
                    on_new_file(path)
                    scanned.append(path)
                except Exception as exc:  # noqa: BLE001 — scheduler must keep running
                    log(f"  [!] Scan failed for {path}: {exc}")
            iterations += 1
            if stop_after is not None and iterations >= stop_after:
                break
            sleep(interval)
    except KeyboardInterrupt:
        log("\n  [*] Scheduler stopped.")

    return {"iterations": iterations, "scanned": scanned}
