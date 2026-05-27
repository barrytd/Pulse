# Contributing to Pulse

Thanks for thinking about contributing. Pulse is an open-source Windows event log analyzer and threat detection tool for SOC triage, and we welcome contributions of every shape — new detection rules, dashboard pages, documentation fixes, bug reports.

Looking for somewhere to start? Check [GitHub issues](https://github.com/barrytd/Pulse/issues) — anything tagged `good first issue` has been scoped to be approachable for a first PR.

---

## Setting up the development environment

```bash
# 1. Clone + venv
git clone https://github.com/barrytd/Pulse.git
cd Pulse
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

# 2. Install runtime + dev dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 3. Bootstrap config (optional — Pulse will fall back to defaults)
cp pulse.yaml.example pulse.yaml

# 4. Start the dev server
python main.py --api
```

Open `http://localhost:8000`. First-time visitors hit a signup page; the first account becomes the admin. Drop a file from `samples/` onto the upload zone to see detections fire end-to-end.

---

## Running tests

```bash
# Full suite (689 tests as of v1.7.0)
python -m pytest -q

# A single module
python -m pytest tests/test_detections.py -v

# Skip network-dependent tests (CVE scan) for air-gapped / offline runs
python -m pytest -m "not network"
```

The suite covers every detection rule, the API surface, multi-tenant isolation, agent runtime cadence, firewall log parsing, IP block-list lifecycle, the auto-update channel, email verification, and the security-hardening fixes. No real `.evtx` files needed — synthetic event data mirrors the live structure.

---

## Adding a detection rule

This is the most common contribution path. Five steps end-to-end:

### 1. Write the detection function

Detections live in [`pulse/core/detections.py`](pulse/core/detections.py). Each one is a plain function that takes a list of event dicts and returns a list of finding dicts. Follow the existing pattern:

```python
def detect_my_new_rule(events):
    """One-sentence summary of what this catches.

    Detailed explanation — what the attack looks like, what events
    indicate it, what could trigger false positives.

    Event ID: 1234 (Brief Event Name)
    MITRE ATT&CK: T1234.567
    """
    findings = []

    for event in events:
        if event["event_id"] != 1234:
            continue

        # Parse the event's XML and read the EventData fields we need.
        xml_tree = ET.fromstring(event["data"])
        target_user = _get_xml_field(xml_tree, "TargetUserName")
        source_ip   = _get_xml_field(xml_tree, "IpAddress")

        # The match condition — what makes this event suspicious.
        if not target_user or not _looks_suspicious(target_user):
            continue

        findings.append({
            "rule":      "My New Rule",
            "severity":  "HIGH",
            "raw_xml":   event["data"],
            "event_id":  event["event_id"],
            "details": (
                f"Suspicious activity by {target_user} from {source_ip} at "
                f"{event['timestamp']}. Expected behavior: ... Why this matters: ..."
            ),
        })

    return findings
```

Then register it in the `DETECTION_FUNCTIONS` list at the bottom of `detections.py` so `run_all_detections()` invokes it.

### 2. Register the rule metadata

Add an entry to `RULE_META` in [`pulse/core/rules_config.py`](pulse/core/rules_config.py) so the dashboard's Rules page knows about it:

```python
"My New Rule": {
    "event_id":    1234,
    "severity":    "HIGH",
    "description": "Concise summary that shows up in the Rules tab.",
    "mitre":       "T1234.567",
    "mitre_name":  "Sub-Technique Name",
    "nist_csf":    "DE.CM-1",         # NIST CSF subcategory
    "iso_27001":   "A.12.4.1",        # ISO 27001 Annex A control
    "remediation": [
        "First step the analyst should take.",
        "Second step — typically containment.",
        "Third step — typically eradication.",
        "Fourth step — verification.",
    ],
},
```

### 3. Add NIST CSF + ISO 27001 mappings

The compliance page reads these from the `nist_csf` and `iso_27001` fields in the same `RULE_META` entry. Use the closest control:

- **NIST CSF**: `ID.*` Identify · `PR.*` Protect · `DE.*` Detect · `RS.*` Respond · `RC.*` Recover. Most detection rules land in `DE.CM-*` (continuous monitoring).
- **ISO 27001 Annex A**: `A.9` access control · `A.12.4` logging + monitoring · `A.16` incident management.

If you're not sure, open the PR and we'll discuss.

### 4. Write tests

At minimum, a test that fires the rule on a matching event and a test that doesn't fire on a non-matching one. Use the in-memory event-dict pattern — [`tests/test_detections.py`](tests/test_detections.py) has helpers (`make_failed_login_event`, `make_rapid_failures`) you can model your own off of:

```python
def test_my_new_rule_fires_on_match():
    events = [build_event_4625(target_user="suspect", source_ip="203.0.113.5")]
    findings = detect_my_new_rule(events)
    assert len(findings) == 1
    assert findings[0]["rule"] == "My New Rule"
    assert findings[0]["severity"] == "HIGH"


def test_my_new_rule_quiet_on_normal_traffic():
    events = [build_event_4625(target_user="alice", source_ip="10.0.0.1")]
    assert detect_my_new_rule(events) == []
```

### 5. Run the full suite

```bash
python -m pytest -q
```

Everything must stay green. Open the PR with a one-line summary of what the rule catches + a paste of the new tests passing.

---

## Adding a dashboard page

The dashboard is a single-page app under [`pulse/static/js/`](pulse/static/js/). No build step — vanilla ES modules. Four touch points:

1. **Create the JS module** in `pulse/static/js/<your-page>.js`. Look at `pulse/static/js/findings.js` for the canonical pattern: a `renderPage()` export that builds the page HTML, plus action handlers wired via the data-action registry in [`app.js`](pulse/static/js/app.js).
2. **Register the SPA route** — add the route name to `_SPA_PAGES` in [`pulse/api.py`](pulse/api.py) so deep links (`/yourpage`) hit the dashboard shell instead of 404ing.
3. **Add the nav item** — sidebar links live in `pulse/web/index.html`. Match the existing pattern (Lucide icon + `data-action="navigate" data-arg="yourpage"`).
4. **Follow the existing page anatomy**: page header → KPI tile strip → filter bar → primary list/table → detail drawer. The [universal drawer primitive](pulse/static/js/drawer.js) and the filter chip framework are reusable — don't roll your own.

---

## Code style

- **Python** — PEP 8. snake_case for function names, dataclasses for record types where ownership matters. Docstrings on every public function. Type hints welcome but not required.
- **JavaScript** — ES modules, no transpiler. `function` declarations for top-level handlers; arrow functions inside callbacks. No frameworks. Use the design tokens in [`pulse/static/css/`](pulse/static/css/) (CSS variables) rather than hardcoded colors / spacing.
- **HTML escaping** — **every** user-supplied string rendered into the dashboard must go through `escapeHtml()` (exported from `pulse/static/js/dashboard.js`). The security-hardening audit (2026-05-14) checked all 20 JS modules; new pages must keep that 100%.
- **SQL** — parameterized queries (`?` for SQLite, `%s` for Postgres via the `db_backend.py` adapter) for every value. The codebase has zero string-concatenated SQL with user input; new code keeps that bar.

---

## Pull request process

1. Fork the repo.
2. Create a feature branch from `main`: `git checkout -b feature/my-detection`.
3. Make changes. Keep commits focused — one logical change per commit, with a message explaining the *why*.
4. Run the full test suite locally: `python -m pytest -q`. Everything must pass.
5. Open the PR against `main` with:
   - A one-sentence summary in the title.
   - A description covering what changed, why, and how it was tested.
   - Screenshots if the change is UI-visible.
6. CI will run the test suite + `pip-audit`. PRs need a green CI to merge.

Substantive changes get a review pass — expect a round or two of comments on PRs that touch detection logic, the auth layer, or the multi-tenant scope helpers.

---

## Reporting security issues

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) instead. We'll triage within a few business days, work with you on a fix + coordinated disclosure timeline, and credit you in the CHANGELOG when the patch ships.

The 2026-05-14 [security audit](CHANGELOG.md) is the baseline — we aim to ship every release with the audit's clean categories still clean.
