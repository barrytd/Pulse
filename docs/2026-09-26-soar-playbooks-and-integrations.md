# Pulse: SOAR Playbooks & Integrations

Date: 2026-09-26
Author: Robert Perez (design), researched with Claude
Status: Design doc, not built yet. Hand this to Claude Code to build in phases.

> Plain-English design for turning Pulse from "detect and report" into "detect, then act on its own." Read the summary, then the three build phases.

---

## The one-sentence version

Pulse already detects threats. This adds the layer on top that reacts to them without a person clicking: look the attacker up in outside services, decide, and respond (block, alert, open a ticket), all from inside Pulse so nobody opens another website.

## Words, so we mean the same thing

- **SIEM** (what Pulse is now): the tool that collects logs and finds threats. Pulse parses `.evtx`, runs 33 rules, scores posture.
- **SOAR** (what we're adding): the tool that *reacts* to a threat automatically. The letters stand for Security Orchestration, Automation and Response. In plain terms: when something fires, run a saved list of steps by itself.
- **Connector** (also "integration" or "plugin"): one small piece of code that talks to one outside service. VirusTotal is a connector. "Post to Slack" is a connector. "Block an IP" is a connector.
- **Action**: one step a connector can do. The VirusTotal connector's action is "look up this IP." The Slack connector's action is "send this message."
- **Playbook**: one saved recipe. A trigger, some optional checks, and an ordered list of actions. Example below.
- **Trigger**: the thing that starts a playbook. In Pulse, a finding firing.
- **Run**: one time a playbook executed, with the result of every step saved so you can see what happened.

## Why Pulse is closer than it looks

You already have three of the four SOAR parts. Only the glue is missing.

| SOAR part | What Pulse has today | File |
|---|---|---|
| Triggers | Findings, rules, the live monitor feed | `pulse/monitor/monitor.py`, `pulse/core/detections.py` |
| Connectors (look-up) | AbuseIPDB threat intel, with a documented "add another provider" pattern | `pulse/intel.py` |
| Connectors (respond) | Block an IP, send Slack/Discord webhook, send email | `pulse/firewall/blocker.py`, `pulse/alerts/webhook.py`, `pulse/alerts/emailer.py` |
| **Playbook engine** | **Missing. This is the whole build.** | new |

The missing glue is: a common shape every connector follows (so adding VirusTotal is one file, not a core edit), and an engine that ties a trigger to a chain of connector actions.

## What "all in one place, they don't leave" turns into

Today an analyst who wants a VirusTotal verdict opens virustotal.com in another browser tab, copies the IP, reads the result, comes back, and clicks block. Two products, lots of clicking.

After this:
- The VirusTotal and AbuseIPDB verdicts show *inside the finding drawer*, next to the block button. No other tab.
- With a playbook, the lookup already ran before the analyst even opened the finding, and a Slack message with the verdict is already posted. The analyst reviews a decision instead of doing the legwork.

That is the quality-of-life jump you're describing.

---

## How other open-source SOAR tools do it

Short version so we borrow the proven shape, not reinvent it.

- **OpenSOAR** and **Shuffle** both use the same flow: an event comes in, gets normalized (fields pulled into a standard shape), gets matched against playbook conditions, and matched playbooks run their steps. Every step's result is saved to the database as an audit trail.
- Connectors follow an **adapter pattern**: one base class with a fixed set of methods (`connect`, `health_check`, `get_actions`, `run`), and every integration fills them in the same way. That is exactly what `intel.py` already hints at in its comments.
- Playbooks can be defined as code or as data (JSON/YAML). Code is more powerful but harder for a non-coder to build. Data (a stored recipe) is easier to build a click-together UI for later. **Recommendation: store playbooks as data in the DB.** It fits Pulse's no-SOC audience, keeps a UI builder on the table, and avoids running arbitrary code.
- Mature tools put a **human approval checkpoint** before high-impact actions (blocking, disabling accounts). We should copy this. It pairs perfectly with your existing security PIN.

Sources at the bottom.

---

## The design

### 1. Connector interface (the plugin system)

Every connector is one file in a new `pulse/connectors/` folder. Each one is a small class with the same shape:

```python
class Connector:
    key = "virustotal"                 # unique id
    name = "VirusTotal"                # shown in the UI
    kind = "enrichment"                # "enrichment" or "response"
    config_fields = ["api_key"]        # what it needs from settings

    def health_check(self) -> bool: ...        # is the key set and valid?
    def actions(self) -> list[str]: ...        # e.g. ["lookup_ip", "lookup_hash"]
    def run(self, action: str, inputs: dict, config: dict) -> dict: ...
```

Connectors register themselves so the engine finds them at startup, the same way rules already work. Adding a new integration = drop a file in `pulse/connectors/`, done. No core edits.

Refactor note: `intel.py` (AbuseIPDB) becomes the first connector so the existing threat-intel feature rides the new system instead of sitting beside it.

Starter set of connectors:

| Connector | Kind | Actions | Notes |
|---|---|---|---|
| AbuseIPDB | enrichment | `lookup_ip` | Port from `intel.py`. Free tier: 1,000 checks/day. |
| VirusTotal | enrichment | `lookup_ip`, `lookup_hash`, `lookup_domain`, `lookup_url` | Header `x-apikey`. Free tier: 4/min, 500/day. **See license caveat below.** |
| GreyNoise | enrichment | `lookup_ip` | Tells you if an IP is internet-wide noise vs targeted. Free "Community" tier exists. |
| AlienVault OTX | enrichment | `lookup_ip`, `lookup_hash`, `lookup_domain` | Free, community threat feed. |
| Slack | response | `post_message` | Generalize `webhook.py`. |
| Discord | response | `post_message` | Already in `webhook.py`. |
| Email | response | `send` | Already in `emailer.py`. |
| Firewall block | response | `block_ip` | Already in `firewall/blocker.py`. PIN-gated. |
| ClickUp / Jira / generic webhook | response | `create_ticket` / `post` | "Open a ticket" so findings leave Pulse into a work tracker. |

### 2. Playbook shape (stored as data)

A playbook is a row in a new `playbooks` table. The recipe is JSON:

```json
{
  "name": "Enrich and contain a critical external IP",
  "enabled": true,
  "trigger": { "on": "finding_created" },
  "conditions": [
    { "field": "severity", "op": "in", "value": ["CRITICAL", "HIGH"] },
    { "field": "source_ip", "op": "is_public", "value": true }
  ],
  "steps": [
    { "connector": "abuseipdb",  "action": "lookup_ip",  "with": { "ip": "{{ finding.source_ip }}" }, "save_as": "abuse" },
    { "connector": "virustotal", "action": "lookup_ip",  "with": { "ip": "{{ finding.source_ip }}" }, "save_as": "vt" },
    { "if": "{{ abuse.score >= 80 or vt.malicious >= 3 }}", "then": [
        { "connector": "firewall", "action": "block_ip", "with": { "ip": "{{ finding.source_ip }}" }, "requires_approval": true },
        { "connector": "slack",    "action": "post_message", "with": { "text": "Blocked {{ finding.source_ip }} — AbuseIPDB {{ abuse.score }}, VT {{ vt.malicious }} engines flagged it." } }
    ]}
  ]
}
```

Reading it in plain terms: when a critical or high finding fires and the source IP is a public internet address, look it up on AbuseIPDB and VirusTotal; if either says it's bad, block it (after a human OKs) and tell the team in Slack.

The `{{ ... }}` bits are placeholders the engine fills in from the finding and from earlier step results. `requires_approval: true` means the step waits for a person to confirm (your security PIN) before it runs.

### 3. Playbook engine (the glue)

New module, roughly `pulse/soar/engine.py`:

1. Listens for a trigger event. Start with `finding_created`, emitted where findings are already saved (agent ingest, upload scan, live monitor).
2. For each enabled playbook, checks its conditions against the finding. No match, skip.
3. On a match, creates a **run** record and walks the steps in order.
4. For each step: fill in the placeholders, call the connector's `run`, save the result to the run's log, and make it available to later steps.
5. If a step has `requires_approval`, pause the run and surface an approval prompt in the UI. On approve, continue; on deny, stop and log it.
6. Save the whole run (status, per-step results, timing) so it shows up in a new "Automations" page and in the finding drawer ("This finding triggered: Enrich and contain — 3 steps, blocked the IP").

Data model, three new tables:
- `connectors_config`: which connectors are on, their settings (encrypt the API keys, see roadmap "Encrypted config secrets").
- `playbooks`: the recipes above, org-scoped like everything else.
- `playbook_runs`: one row per run, with the step-by-step log.

Safety rules baked in from day one:
- Response actions (block, ticket) default to **approval required**. Enrichment (lookups) runs freely because it only reads.
- Every run is org-scoped and written to the audit log.
- A connector failing (bad key, timeout, rate limit) never crashes the run. It logs the failure and moves on, the same defensive style `intel.py` already uses.
- Rate-limit awareness: cache lookups (you already cache AbuseIPDB in `intel_cache`) and respect each service's per-minute cap so a burst of findings doesn't blow the quota.

---

## Build it in three phases

**Phase 1 — Connector layer + VirusTotal.** Build the connector base class and registry. Move AbuseIPDB onto it. Add VirusTotal as the second connector. Show both verdicts in the finding drawer. No engine yet. This is small, ships a feature you want anyway, and proves the plugin model. *Start here.*

**Phase 2 — Playbook engine, no UI builder.** Add the three tables, the engine, and the `finding_created` trigger. Let playbooks be created through the API / a JSON paste box (like the existing SIGMA import). Wire the approval step to the security PIN. Add an "Automations" page that lists playbooks and their runs. Ship two or three built-in example playbooks so users see the value without building one.

**Phase 3 — Click-together playbook builder + more connectors.** A visual builder (pick a trigger, add condition rows, drag action steps) so a non-coder builds a playbook without touching JSON. Add GreyNoise, OTX, ClickUp/Jira ticketing, and a generic outbound webhook so users connect their own tools.

---

## Caveats worth knowing before you build

- **VirusTotal free key is not for commercial use.** Their public API (4/min, 500/day) says it "must not be used in commercial products or services." For self-hosted free users bringing their own key, that's their call. For your future hosted/paid tier, you'd need a VirusTotal Premium agreement, or make VirusTotal a bring-your-own-key connector the user turns on themselves. Design the connector so the key is always the user's, never bundled.
- **Don't drift into traffic monitoring.** This stays in your lane (host threat detection). Playbooks react to findings, they don't turn Pulse into a live traffic firewall. Matches the "stay in lane" decision already in the roadmap.
- **Approval gates are not optional.** Auto-blocking an IP with no human check is how a false positive locks out your own admin. Enrichment auto-runs; response waits for a person unless the user explicitly opts a specific playbook into full auto.
- **Rate limits are real quotas.** Cache every lookup and key the cache on (indicator, provider), which `intel_cache` already does. A noisy install could otherwise burn a 500/day VirusTotal quota in one bad afternoon.

---

## Sources

- [What Is a SOAR Playbook? — JumpCloud](https://jumpcloud.com/it-index/what-is-a-soar-playbook)
- [OpenSOAR architecture (Python-native playbooks, connector adapters)](https://docs.opensoar.app/engineering/architecture/)
- [Introducing Shuffle — an Open Source SOAR platform](https://medium.com/shuffle-automation/introducing-shuffle-an-open-source-soar-platform-part-1-58a529de7d12)
- [VirusTotal API v3 overview](https://docs.virustotal.com/reference/overview)
- [VirusTotal public vs premium API (rate limits + commercial-use restriction)](https://docs.virustotal.com/reference/public-vs-premium-api)
- [AbuseIPDB API documentation](https://www.abuseipdb.com/api.html)
- [Creating and discovering plugins — Python Packaging Guide](https://packaging.python.org/guides/creating-and-discovering-plugins/)
- [How to Build Plugin Systems in Python](https://oneuptime.com/blog/post/2026-01-30-python-plugin-systems/view)
