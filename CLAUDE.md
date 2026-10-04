# CLAUDE.md

Guidance for Claude Code (and anyone else) making changes in this repository.

## Documentation policy

**Docs change in the same commit as the code, never later.** Whenever a change alters behavior, features, counts or security posture, update every affected doc in that commit. A change isn't done until its docs match.

| Doc | Keep accurate |
|---|---|
| `README.md` | Summary, features table, quick start, test-count badge (and the "Tests" line under Architecture), rule count (summary, features table, "Detection rules" heading and table), Python version badge, screenshots when the UI they show changes |
| `PROJECT.md` | "What Pulse is and does" whenever capabilities change; the rule and test counts under "What it does today" and "Status" |
| `CHANGELOG.md` | A new top entry for every behavior change (newest first, dated) |
| `ROADMAP.md` | Move items to Shipped when done; keep In Progress / Up Next / Bugs / backlog statuses honest |
| `SECURITY.md` | Whenever security behavior changes: approval gates, what data leaves the machine and where, key handling, scope |
| `CONTRIBUTING.md` | Whenever an extension point changes: adding a detection rule, a connector, a dashboard page, test conventions |
| `samples/README.md` | Rules each sample triggers and its expected grade, when detections or scoring change |

### Where the numbers come from

Don't copy counts from other docs; recompute them from the code.

```bash
# Tests (README badge + Architecture line, PROJECT.md Status)
python -m pytest --collect-only -q | tail -1

# Detection rules: distinct rule names the engine can emit, from the
# event-log detections plus the Windows Firewall *config* audit. Firewall
# *log* parser findings (pulse/firewall/firewall_parser.py) are a separate
# feature and not counted. Every one of these should also be in RULE_META
# (pulse/core/rules_config.py); if the two numbers differ, a rule is
# unregistered (see ROADMAP.md -> Bugs).
python -c "import re; print(len({r for f in ('pulse/core/detections.py','pulse/firewall/firewall_config.py') for r in re.findall(r'\"rule\"\s*:\s*\"([^\"]+)\"', open(f, encoding='utf-8').read())}))"
python -c "from pulse.core.rules_config import RULE_META; print(len(RULE_META))"

# Minimum Python: the highest Requires-Python among the pins in
# requirements-lock.txt (currently 3.10).
```

## Repo hygiene

- Never leave scratch, temp or tool-output files in the repo. Put them in a temp or scratchpad directory outside the working tree.
- Keep `.gitignore` covering anything a tool or workflow tends to drop in the tree (for example `Claude outputs/`).
- Line endings are set by `.gitattributes` (`* text=auto`); don't commit changes that only flip CRLF/LF.
- Tests never touch the network or the real firewall (except the `network`-marked pip-audit check). Mock at the boundary.

## Clean up what you launch

Headless browsers and preview servers started while working (screenshots, UI checks, `serve.py`-style throwaway servers) must not outlive the task. Left running, they pile up in Task Manager and eat the machine's memory.

- **Close browsers in teardown, every time.** Wrap each launch in `try`/`finally` (or a pytest fixture that `yield`s and closes after), so it closes even when a check fails or is interrupted.
- **Kill the whole process tree, not just the PID you started.** On Windows, `proc.kill()` ends only that one process. Chrome's browser, GPU and renderer children keep running. Use `taskkill /PID <pid> /T /F`, then remove the temp `--user-data-dir` profile.
- **A hard-killed run can't clean up after itself** (`finally` and `atexit` never run), so sweep at the end.
- **Before you say a task is finished,** stop every server you started and confirm no headless Chrome is left:

```powershell
# Kill headless Chrome running on a temp profile (only automation launches these)
Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" |
  Where-Object { $_.CommandLine -match '--headless' -and $_.CommandLine -like "*--user-data-dir=*$env:TEMP*" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

# Must print 0
(Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" | Where-Object { $_.CommandLine -match '--headless' }).Count
```

  Report the count in your summary. Never kill the user's normal (non-headless) Chrome.
