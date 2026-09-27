# pulse/soar/builder.py
# ---------------------
# What the Automations page's click-together playbook builder may offer.
#
# The builder never invents recipe syntax: it assembles the same JSON the
# engine already runs, from the vocabulary below, and every save goes
# through recipe.normalize() like a pasted playbook. So:
#   * condition rows come from a fixed, safe set (CONDITION_KINDS), each
#     mapping to one {field, op, value} condition the validator accepts;
#   * steps come from the registered connectors, with the inputs each
#     action reads (Connector.action_inputs) and the result fields later
#     steps may reference (Connector.result_fields);
#   * placeholders are only `finding.*` paths and earlier steps' results.
# Response steps always require approval; the builder shows that as a
# fixed badge, and recipe.normalize() enforces it on save.

from __future__ import annotations

from .. import connectors
from ..core.rules_config import RULE_META
from . import recipe

SEVERITIES = list(recipe.SEVERITIES)[::-1]   # CRITICAL first

# Rules that fire but aren't in RULE_META yet (ROADMAP -> Bugs). Offered
# so a playbook can react to them; drop from here once registered.
_UNREGISTERED_RULES = ("DCSync Attempt", "Suspicious Child Process")


def rule_names():
    return sorted(set(RULE_META) | set(_UNREGISTERED_RULES))


# value types: "choice" (one of options), "multi" (several of options),
# "text" (free text), "fixed" (no input; the kind itself carries it).
def condition_kinds():
    rules = rule_names()
    return [
        {"key": "severity_at_least", "label": "Severity is at least",
         "field": "severity", "op": "severity_at_least",
         "value": {"type": "choice", "options": SEVERITIES, "default": "HIGH"}},
        {"key": "severity_in", "label": "Severity is one of",
         "field": "severity", "op": "in",
         "value": {"type": "multi", "options": SEVERITIES}},
        {"key": "source_ip_public", "label": "Source IP is a public internet address",
         "field": "source_ip", "op": "is_public", "value": {"type": "fixed", "value": True}},
        {"key": "source_ip_not_public", "label": "Source IP is a private or internal address",
         "field": "source_ip", "op": "is_public", "value": {"type": "fixed", "value": False}},
        {"key": "source_ip_present", "label": "The finding has a source IP",
         "field": "source_ip", "op": "exists", "value": {"type": "fixed", "value": True}},
        {"key": "rule_in", "label": "Rule is one of",
         "field": "rule", "op": "in", "value": {"type": "multi", "options": rules}},
        {"key": "rule_not_in", "label": "Rule is not one of",
         "field": "rule", "op": "not_in", "value": {"type": "multi", "options": rules}},
        {"key": "hostname_contains", "label": "Host name contains",
         "field": "hostname", "op": "contains", "value": {"type": "text"}},
    ]


FINDING_PLACEHOLDERS = [
    ("source_ip", "Source IP"),
    ("hostname", "Host name"),
    ("rule", "Rule name"),
    ("severity", "Severity"),
    ("ref_id", "Finding reference (e.g. BFS-0006)"),
    ("mitre", "MITRE technique"),
    ("timestamp", "Event time"),
]


def schema():
    """Everything the builder UI needs, derived from the same code the
    validator and engine use."""
    out_connectors = []
    for c in connectors.all_connectors():
        out_connectors.append({
            "key": c.key, "name": c.name, "kind": c.kind,
            "actions": [{"key": a, "label": c.action_label(a),
                         "inputs": c.action_inputs(a)} for a in c.actions()],
            "result_fields": [{"key": k, "label": v} for k, v in c.result_fields.items()],
            # Response actions can't skip a human; the UI shows it as fixed.
            "requires_approval": c.kind == "response",
        })
    return {
        "triggers": [{"key": "finding_created", "label": "When a new finding is created"}],
        "condition_kinds": condition_kinds(),
        "finding_placeholders": [{"path": f"finding.{k}", "label": v}
                                 for k, v in FINDING_PLACEHOLDERS],
        "connectors": out_connectors,
        "limits": {"max_steps": recipe.MAX_STEPS, "max_name": recipe.MAX_NAME},
    }
