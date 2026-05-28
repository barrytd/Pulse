# Sample SIGMA rules

These YAML files are starter SIGMA rules you can paste into the Pulse
**Rules → SIGMA Import** tab to try out the importer. Each one targets
a real Windows attack technique that the built-in detections don't
already cover.

| File | Severity | MITRE | What it catches |
|------|----------|-------|------------------|
| `powershell-encoded.yml` | HIGH | T1059.001 | `powershell -EncodedCommand` payload hiding |
| `mimikatz-cli.yml` | CRITICAL | T1003.001 | mimikatz / sekurlsa / lsadump command lines |
| `rundll32-temp.yml` | HIGH | T1218.011 | rundll32.exe launched from `%TEMP%` |

## How to use

1. Sign in as an admin and open the **Rules** page.
2. Switch to the **SIGMA Import** tab.
3. Paste the YAML contents into the importer textarea and click
   **Preview** to see what Pulse extracted, then **Import** to save.
4. The new rule fires against every subsequent scan and live-monitor
   batch. Toggle or delete it from the imported-rules list.

## What Pulse supports

Pulse parses the pragmatic subset of SIGMA used by the majority of
community rules on SigmaHQ:

* selection blocks with equality, `|contains`, `|startswith`,
  `|endswith`, and `|re` modifiers
* condition expressions with `and`, `or`, `not`, and parentheses
* MITRE technique extraction from `attack.tXXXX[.XXX]` tags
* `level: critical|high|medium|low|informational` mapped to Pulse
  severities

Aggregations (`count() by user`), `1 of them` / `all of them`, and
the `|all` modifier are intentionally rejected — Pulse's time-based
correlation engine handles sequence rules through a different path.
