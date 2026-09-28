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
# Full suite (about 1,750 tests; a few minutes)
python -m pytest -q

# A single module
python -m pytest tests/test_detections.py -v

# Skip network-dependent tests (CVE scan) for air-gapped / offline runs
python -m pytest -m "not network"
```

The suite covers every detection rule, the API surface, multi-tenant isolation, agent runtime cadence, firewall log parsing, IP block-list lifecycle, the auto-update channel, email verification, the security-hardening fixes, scoring, the connectors, and the playbook engine. No real `.evtx` files needed — synthetic event data mirrors the live structure. **No test touches the network or the real firewall**: connector tests mock HTTP / sockets at the boundary, and playbook tests replace the firewall blocker. Keep it that way (the one exception is the `network`-marked pip-audit check).

---

## Adding a detection rule

This is the most common contribution path. Six steps end-to-end:

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

Then add a call to it in `run_all_detections()` at the bottom of `detections.py` (`findings += detect_my_new_rule(events) or []`), next to the rules of the same kind. That list is explicit on purpose: a rule that isn't called there never runs.

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

### 4. Write the plain-language guide

Every rule gets an entry in `KNOWLEDGE` in [`pulse/core/knowledge_base.py`](pulse/core/knowledge_base.py): what happened in one sentence without jargon, why it matters, immediate actions, prevention, difficulty and common false positives. This is what the finding drawer, the dashboard's verdict line and Pip show. [`tests/test_knowledge_base.py`](tests/test_knowledge_base.py) fails if a rule in `RULE_META` has no entry.

### 5. Write tests

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

### 6. Run the full suite

```bash
python -m pytest -q
```

Everything must stay green. Open the PR with a one-line summary of what the rule catches + a paste of the new tests passing.

---

## Adding a connector

Connectors are how Pulse talks to outside services (or local lookups). Each is **one file** in [`pulse/connectors/`](pulse/connectors/); the package imports every module on first use, so a new file joins the Investigate panel, the playbook engine and the Automations page's connector list with no other change. [`pulse/connectors/greynoise.py`](pulse/connectors/greynoise.py) is a compact model to copy.

```python
from .base import Connector, register, is_public_ip

@register
class MyConnector(Connector):
    key = "myservice"                # unique id, used in playbooks
    name = "My Service"              # shown in the UI
    kind = "enrichment"              # "enrichment" (reads) or "response" (acts)
    config_fields = ["api_key"]      # health_check() needs these set

    def actions(self):
        return ["lookup_ip"]         # lookup_ip / lookup_domain / lookup_hash
                                     # are what the Investigate panel runs

    def config_from_pulse(self, pulse_config):
        ...                          # read your key from pulse.yaml / env

    def run(self, action, inputs, config):
        ...                          # return a dict, or None for "no intel"

    def summarize(self, action, result):
        ...                          # one plain-language line for the panel

    # Optional, for the playbook builder (sensible defaults exist for
    # lookup_ip / lookup_domain / lookup_hash):
    result_fields = {"score": "Abuse score"}   # offered as {{ <step>.score }}
    def action_inputs(self, action): ...       # [{name, label, required, multiline}]
    def action_label(self, action): ...        # "Look up an IP address"
```

The playbook builder reads `action_inputs`, `action_label` and `result_fields` from `GET /api/playbooks/builder`, so a new connector appears in the builder automatically. Recipe validation rejects a step that leaves a required input empty. Every `result_fields` key must be a key your results really contain; [`tests/test_playbook_builder.py`](tests/test_playbook_builder.py) checks that.

The rules every connector follows (reviewers check these):

- **Fail safe.** Any error, timeout, bad key or rate limit returns `None` ("no intel"), never raises. Callers go through `connectors.run_action()`, which also catches exceptions, but don't rely on it.
- **Never send private data.** Refuse non-public IPs with `is_public_ip()` and internal names with `normalize_domain()` (both in `base.py`) *before* any network call.
- **Bring-your-own key.** Read keys from `pulse.yaml` (`threat_intel.<name>_api_key`) or an environment variable; never ship one, and make no call until a key is set. Add the key to `_threat_intel_view` and the `PUT /api/config/threat_intel` field list in `api.py`, and to the Settings card, so it's settable and never echoed back.
- **Cache and respect quotas.** Cache answers in `intel_cache` (`read_cache` / `write_cache`, keyed on indicator + provider), including "not found" answers, and hold live calls to the provider's limit with a `QuotaGuard`.
- **Include a `verdict`** in results: `malicious`, `suspicious`, `clean`, `info` or `unknown`.
- **Response connectors** (`kind = "response"`) always require human approval in playbooks; the engine enforces it. Don't let a recipe supply a destination (URL, host); use what's configured in Settings. When that destination is a URL an admin typed (like the outbound webhook or a Jira site), call it through `request_guarded()` in `base.py`, which refuses loopback, cloud-metadata and (unless allowed) private addresses and never follows redirects. Send only the step's inputs, cache nothing, and return `{"ok": False, "message": ...}` on failure. [`pulse/connectors/outbound_webhook.py`](pulse/connectors/outbound_webhook.py) is the model to copy.
- **Tests** mock the network at the boundary (see [`tests/test_investigate.py`](tests/test_investigate.py), which blocks the network by default): request shape, verdicts, caching, the failure paths, and that private/internal indicators are never sent.

---

## Adding a dashboard page

The dashboard is a single-page app under [`pulse/static/js/`](pulse/static/js/). No build step — vanilla ES modules. Touch points:

1. **Create the JS module** in `pulse/static/js/<your-page>.js`. Look at `pulse/static/js/findings.js` for the canonical pattern: a `renderPage()` export that builds the page HTML, plus action handlers wired via the data-action registry in [`app.js`](pulse/static/js/app.js).
2. **Register it client-side** in [`navigation.js`](pulse/static/js/navigation.js): import the renderer, add the name to `validPages`, and add it to the `renderers` map. If the page is for managers/admins only, add it to `PAGE_MIN_ROLE` in [`roles.js`](pulse/static/js/roles.js) (the API must still enforce the role).
3. **Register the SPA route** — add the same name to `_SPA_PAGES` in [`pulse/api.py`](pulse/api.py) so deep links and refreshes (`/yourpage`) load the dashboard instead of 404ing. [`tests/test_frontend_regressions.py`](tests/test_frontend_regressions.py) fails if `validPages` and `_SPA_PAGES` drift apart.
4. **Add the nav item** — sidebar links live in `pulse/web/index.html`. Match the existing pattern (Lucide icon + `data-action="navigate" data-arg="yourpage"`).
5. **Follow the existing page anatomy**: page header → KPI tile strip → filter bar → primary list/table → detail drawer. The [universal drawer primitive](pulse/static/js/drawer.js) and the filter chip framework are reusable — don't roll your own.
6. **Build new layout from the shared surface kit** in [`components.css`](pulse/static/css/components.css) (the "Shared surface kit" block), the same classes the dashboard uses: `.ui-page` (caps content at `--content-max`, 1280px, and centers it), `.ui-stack` (sections spaced by `--gap-section`), `.ui-split` (main + side column; `.ui-split-even` for two equal columns), `.ui-card` (elevated card, light and dark), `.ui-panel` with `.ui-panel-head` / `h3` / `.ui-panel-empty`, `.ui-eyebrow` / `.ui-sublabel` / `.ui-link` for type, `.ui-stats` for a stat strip (`.ui-stats-tiles` makes each stat its own `.ui-card` tile) and `.ui-sev` for severity tags. It collapses at 1180px, 900px (even splits) and 640px on its own. Keep kit rules in `components.css` only and page-specific rules in the page's own stylesheet; [`tests/test_ui_foundation.py`](tests/test_ui_foundation.py) checks both.

---

## Code style

- **Python** — PEP 8. snake_case for function names, dataclasses for record types where ownership matters. Docstrings on every public function. Type hints welcome but not required.
- **JavaScript** — ES modules, no transpiler. `function` declarations for top-level handlers; arrow functions inside callbacks. No frameworks. Use the design tokens in [`pulse/static/css/`](pulse/static/css/) (CSS variables) rather than hardcoded colors / spacing. The font is `var(--font-body)` (bundled Inter); don't add another font or load one from a CDN. The app shell (sidebar, topbar, page ground) is one surface driven by the shell tokens in `base.css` (`--shell-bg`, `--shell-line`, `--nav-*`, `--card-edge`); `sidebar.css` and the topbar only read them, so don't give the sidebar its own fill or hardcode a color there.
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
6. There's no hosted CI yet, so include the output of `python -m pytest -q` (all passing, including the `pip-audit` check) in the PR description.

Substantive changes get a review pass — expect a round or two of comments on PRs that touch detection logic, the auth layer, or the multi-tenant scope helpers.

---

## Reporting security issues

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) instead. We'll triage within a few business days, work with you on a fix + coordinated disclosure timeline, and credit you in the CHANGELOG when the patch ships.

The 2026-05-14 [security audit](CHANGELOG.md) is the baseline — we aim to ship every release with the audit's clean categories still clean.
