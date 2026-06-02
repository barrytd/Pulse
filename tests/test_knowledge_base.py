# test_knowledge_base.py
# -----------------------
# Pulse Security Advisor — plain-language knowledge base for findings.

import pytest

from pulse.core.knowledge_base import (
    KNOWLEDGE, get_knowledge, attach_knowledge, _FALLBACK,
)
from pulse.core.rules_config import RULE_META
from pulse.remediation import attach_remediation


# ---------------------------------------------------------------------------
# Coverage: every detection rule must have an explicit knowledge entry
# ---------------------------------------------------------------------------

def test_every_rule_meta_entry_has_knowledge():
    """If a rule exists in RULE_META, an analyst will see findings for it.
    Findings without plain-language explanations defeat the whole point
    of the Security Advisor."""
    missing = sorted(set(RULE_META.keys()) - set(KNOWLEDGE.keys()))
    assert missing == [], (
        f"Knowledge base is missing entries for: {missing}"
    )


# ---------------------------------------------------------------------------
# Entry shape
# ---------------------------------------------------------------------------

_REQUIRED_FIELDS = {
    "plain_language", "why_it_matters", "immediate_actions",
    "prevention", "learn_more", "difficulty", "common_false_positives",
}


@pytest.mark.parametrize("rule_name", sorted(KNOWLEDGE.keys()))
def test_each_entry_has_required_fields(rule_name):
    entry = KNOWLEDGE[rule_name]
    missing = _REQUIRED_FIELDS - set(entry.keys())
    assert missing == set(), f"{rule_name} missing fields: {missing}"

    assert isinstance(entry["plain_language"], str) and entry["plain_language"]
    assert isinstance(entry["why_it_matters"], str) and entry["why_it_matters"]
    assert isinstance(entry["immediate_actions"], list) and entry["immediate_actions"]
    assert isinstance(entry["prevention"], str) and entry["prevention"]
    assert isinstance(entry["learn_more"], list)
    assert entry["difficulty"] in {"low", "medium", "high"}
    assert isinstance(entry["common_false_positives"], list)


@pytest.mark.parametrize("rule_name", sorted(KNOWLEDGE.keys()))
def test_learn_more_links_are_well_formed(rule_name):
    for link in KNOWLEDGE[rule_name]["learn_more"]:
        assert "label" in link and link["label"]
        assert "url" in link and link["url"].startswith("https://")


# ---------------------------------------------------------------------------
# get_knowledge fallback
# ---------------------------------------------------------------------------

def test_unknown_rule_returns_fallback():
    out = get_knowledge("Some Rule That Does Not Exist")
    assert out is _FALLBACK
    assert "plain_language" in out


def test_empty_rule_name_returns_fallback():
    assert get_knowledge("") is _FALLBACK


# ---------------------------------------------------------------------------
# attach_knowledge / attach_remediation pipeline integration
# ---------------------------------------------------------------------------

def test_attach_knowledge_decorates_findings():
    findings = [{"rule": "Brute Force Attempt"}, {"rule": "User Account Created"}]
    out = attach_knowledge(findings)
    assert out is findings  # in-place + returned for chaining
    assert findings[0]["knowledge"]["difficulty"] == "low"
    assert "guessing" in findings[0]["knowledge"]["plain_language"].lower()


def test_attach_remediation_also_attaches_knowledge():
    """attach_remediation is the universal enrichment step on the scan
    pipeline; the API never hands findings to clients without going
    through it. Knowledge must ride along so the drawer can render
    the Security Guide without a second round trip."""
    findings = [{"rule": "Audit Log Cleared"}]
    attach_remediation(findings)
    assert "remediation" in findings[0]
    assert "mitigations" in findings[0]
    assert "knowledge" in findings[0]
    assert findings[0]["knowledge"]["difficulty"] == "low"


def test_attach_knowledge_handles_unknown_rule_gracefully():
    findings = [{"rule": "Made Up Rule"}]
    attach_knowledge(findings)
    # Falls back to the generic entry; doesn't crash.
    assert findings[0]["knowledge"]["difficulty"] == "medium"


def test_attach_knowledge_on_empty_list():
    assert attach_knowledge([]) == []
    assert attach_knowledge(None) is None  # no-op when nothing to attach
