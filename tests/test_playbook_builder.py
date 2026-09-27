# tests/test_playbook_builder.py
# ------------------------------
# The click-together playbook builder (Automations page). The builder
# assembles the same JSON recipe the engine runs, from the vocabulary in
# pulse/soar/builder.py, and every save goes through recipe.normalize().
# These tests pin that the vocabulary is valid and consistent with the
# engine (so a builder can't offer something that breaks), that
# builder-shaped recipes round-trip through the API, and that the
# frontend wiring can't silently drop an action.
#
# No network: connector fetches are stubbed like tests/test_soar.py.

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pulse import connectors
from pulse.api import create_app
from pulse.core.rules_config import RULE_META
from pulse.soar import builder, engine, recipe

ROOT = Path(__file__).resolve().parent.parent
JS = ROOT / "pulse" / "static" / "js"
PW = "correct-horse-battery"


def _kind(key):
    return next(k for k in builder.condition_kinds() if k["key"] == key)


def _sample_value(kind):
    v = kind["value"]
    if v["type"] == "fixed":
        return v["value"]
    if v["type"] == "multi":
        return v["options"][:2]
    if v["type"] == "choice":
        return v.get("default") or v["options"][0]
    return "dc"


def _recipe(conditions=None, steps=None, **extra):
    r = {"name": "Built with the builder", "enabled": True,
         "trigger": {"on": "finding_created"}, "match": "all",
         "conditions": conditions or [],
         "steps": steps or [{"connector": "dns", "action": "lookup_domain",
                             "with": {"domain": "example.com"}, "save_as": "dns"}]}
    r.update(extra)
    return r


# ---------------------------------------------------------------------------
# Vocabulary is valid and matches the engine
# ---------------------------------------------------------------------------

class TestVocabulary:
    @pytest.mark.parametrize("kind", builder.condition_kinds(), ids=lambda k: k["key"])
    def test_every_condition_kind_is_a_valid_condition(self, kind):
        cond = {"field": kind["field"], "op": kind["op"], "value": _sample_value(kind)}
        recipe.normalize(_recipe(conditions=[cond]))

    @pytest.mark.parametrize("key,finding,expected", [
        ("source_ip_public", {"details": "from 45.33.32.156"}, True),
        ("source_ip_public", {"details": "from 10.0.0.5"}, False),
        ("source_ip_not_public", {"details": "from 10.0.0.5"}, True),
        ("source_ip_present", {"details": "no address here"}, False),
        ("severity_at_least", {"severity": "CRITICAL"}, True),
        ("severity_at_least", {"severity": "LOW"}, False),
    ])
    def test_condition_kinds_filter_findings(self, key, finding, expected):
        k = _kind(key)
        cond = {"field": k["field"], "op": k["op"], "value": _sample_value(k)}
        assert engine.condition_holds(cond, engine.finding_context(finding)) is expected

    def test_rule_options_are_rules_the_engine_really_emits(self):
        emitted = set()
        for f in ("pulse/core/detections.py", "pulse/firewall/firewall_config.py"):
            emitted |= set(re.findall(r'"rule"\s*:\s*"([^"]+)"', (ROOT / f).read_text(encoding="utf-8")))
        offered = set(_kind("rule_in")["value"]["options"])
        assert offered <= emitted, sorted(offered - emitted)
        assert set(RULE_META) <= offered

    def test_finding_placeholders_resolve(self):
        ctx = engine.finding_context({"details": "from 45.33.32.156", "rule": "X",
                                      "hostname": "H", "severity": "HIGH"})
        for p in builder.schema()["finding_placeholders"]:
            key = p["path"].split(".", 1)[1]
            assert p["path"].startswith("finding.") and key in ctx, p

    def test_every_action_declares_its_inputs(self):
        for c in connectors.all_connectors():
            for a in c.actions():
                inputs = c.action_inputs(a)
                assert inputs, (c.key, a)
                assert any(i["required"] for i in inputs), (c.key, a)
                assert c.action_label(a)

    def test_result_fields_exist_in_connector_results(self):
        """A placeholder the builder offers (e.g. {{ abuseipdb.score }}) must
        be a key the connector really returns, or it silently renders empty."""
        from pulse.connectors import (abuseipdb, dns_lookup, greynoise, otx,
                                      virustotal, whois_lookup)
        samples = {
            "abuseipdb": abuseipdb._finish({"ip": "1.2.3.4", "score": 1, "country": "US",
                                            "total_reports": 0}, False),
            "virustotal": virustotal._finish(virustotal._empty("1.2.3.4", "ip"), False),
            "greynoise": greynoise._finish(greynoise._entry("1.2.3.4", found=True), False),
            "otx": otx._finish(otx._entry("1.2.3.4", "ip", found=True), False),
            "whois": whois_lookup._finish(whois_lookup._entry("example.com", found=True), False),
            "dns": dns_lookup._finish({"indicator": "example.com", "type": "domain", "source": "dns",
                                       "found": True, "addresses": [], "internal": []}),
            "geoip": {"found": True, "country": "X", "country_code": "X", "city": None},
        }
        for c in connectors.all_connectors(kind="enrichment"):
            missing = set(c.result_fields) - set(samples[c.key])
            assert not missing, (c.key, missing)

    def test_response_connectors_are_marked_as_needing_approval(self):
        s = builder.schema()
        flags = {c["key"]: c["requires_approval"] for c in s["connectors"]}
        assert flags["firewall"] is True and flags["webhook"] is True
        assert flags["abuseipdb"] is False


# ---------------------------------------------------------------------------
# Validation the builder relies on
# ---------------------------------------------------------------------------

class TestValidation:
    def test_required_input_missing_is_rejected(self):
        with pytest.raises(recipe.RecipeError, match="'IP address to block' is required"):
            recipe.normalize(_recipe(steps=[{"connector": "firewall", "action": "block_ip",
                                             "with": {"comment": "x"}}]))
        with pytest.raises(recipe.RecipeError, match="'Message' is required"):
            recipe.normalize(_recipe(steps=[{"connector": "webhook", "action": "post_message",
                                             "with": {"text": "   "}}]))

    def test_optional_input_may_be_empty(self):
        recipe.normalize(_recipe(steps=[{"connector": "firewall", "action": "block_ip",
                                         "with": {"ip": "{{ finding.source_ip }}"}}]))

    def test_placeholder_to_a_later_step_is_rejected(self):
        steps = [{"connector": "webhook", "action": "post_message",
                  "with": {"text": "score {{ abuseipdb.score }}"}},
                 {"connector": "abuseipdb", "action": "lookup_ip",
                  "with": {"ip": "{{ finding.source_ip }}"}, "save_as": "abuseipdb"}]
        with pytest.raises(recipe.RecipeError, match="isn't available here"):
            recipe.normalize(_recipe(steps=steps))


# ---------------------------------------------------------------------------
# API: schema + builder-shaped recipes round-trip
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(tmp_path / "t.db"), config_path=str(cfg))
    c = TestClient(app)
    assert c.post("/api/auth/signup", json={"email": "admin@x.com", "password": PW}).status_code == 200
    return c


BUILT = _recipe(
    conditions=[{"field": "severity", "op": "severity_at_least", "value": "HIGH"},
                {"field": "source_ip", "op": "is_public", "value": True},
                {"field": "rule", "op": "in", "value": ["Brute Force Attempt", "Brute-Force Success"]}],
    steps=[{"connector": "abuseipdb", "action": "lookup_ip",
            "with": {"ip": "{{ finding.source_ip }}"}, "save_as": "abuseipdb"},
           {"connector": "webhook", "action": "post_message",
            "with": {"text": "{{ finding.rule }} from {{ finding.source_ip }}, abuse score {{ abuseipdb.score }}"},
            "requires_approval": True}],
    description="Made with the builder")


class TestApi:
    def test_schema_endpoint(self, client):
        r = client.get("/api/playbooks/builder")
        assert r.status_code == 200
        s = r.json()
        assert s["triggers"] == [{"key": "finding_created", "label": "When a new finding is created"}]
        assert {k["key"] for k in s["condition_kinds"]} >= {"severity_at_least", "source_ip_public", "rule_in"}
        fw = next(c for c in s["connectors"] if c["key"] == "firewall")
        assert fw["actions"][0]["inputs"][0]["name"] == "ip"

    def test_schema_needs_manager(self, client):
        client.post("/api/users", json={"email": "an@x.com", "password": PW, "role": "analyst"})
        client.post("/api/auth/logout")
        client.post("/api/auth/login", json={"email": "an@x.com", "password": PW})
        assert client.get("/api/playbooks/builder").status_code == 403

    def test_builder_recipe_saves_and_round_trips(self, client):
        r = client.post("/api/playbooks", json={"recipe": BUILT})
        assert r.status_code == 200, r.text
        pid = r.json()["id"]
        stored = client.get(f"/api/playbooks/{pid}").json()["recipe"]
        assert stored["conditions"] == BUILT["conditions"]
        assert stored["steps"][1]["requires_approval"] is True
        assert stored["description"] == "Made with the builder"
        edited = dict(BUILT, name="Renamed", match="any")
        r = client.put(f"/api/playbooks/{pid}", json={"recipe": edited})
        assert r.status_code == 200 and r.json()["name"] == "Renamed"
        assert client.get(f"/api/playbooks/{pid}").json()["recipe"]["match"] == "any"

    def test_response_step_without_approval_is_refused_on_save(self, client):
        bad = json.loads(json.dumps(BUILT))
        bad["steps"][1]["requires_approval"] = False
        r = client.post("/api/playbooks", json={"recipe": bad})
        assert r.status_code == 400
        assert any("always requires human approval" in e for e in r.json()["detail"]["errors"])
        assert client.get("/api/playbooks").json()["playbooks"] == []

    def test_validate_returns_clear_errors(self, client):
        bad = _recipe(name="", steps=[{"connector": "firewall", "action": "block_ip", "with": {}}])
        r = client.post("/api/playbooks/validate", json={"recipe": bad})
        assert r.status_code == 400
        errs = r.json()["detail"]["errors"]
        assert any("`name` is required" in e for e in errs)
        assert any("is required for Firewall block" in e for e in errs)


# ---------------------------------------------------------------------------
# Frontend wiring (no JS runner in the suite: read the source)
# ---------------------------------------------------------------------------

def _app_actions():
    src = (JS / "app.js").read_text(encoding="utf-8")
    body = src[src.index("const actions"):]
    body = body[:body.index("};")]
    return set(re.findall(r"^\s+([A-Za-z_$][\w$]*),?\s*$", body, re.M))


@pytest.mark.parametrize("module", ["playbook-builder.js", "automations.js"])
def test_every_data_action_is_registered(module):
    """A data-action name missing from app.js's registry is a button that
    silently does nothing."""
    src = (JS / module).read_text(encoding="utf-8")
    used = set(re.findall(r'data-action(?:-change|-input)?="([A-Za-z_$][\w$]*)"', src))
    used.discard("navigate")
    assert used, module
    assert used <= _app_actions(), sorted(used - _app_actions())


def test_builder_uses_the_server_vocabulary_and_no_eval():
    src = (JS / "playbook-builder.js").read_text(encoding="utf-8")
    assert "/api/playbooks/builder" in src
    assert "eval(" not in src and "new Function" not in src
    # It never hard-codes the approval rule off: response steps are
    # always sent with requires_approval true.
    assert "out.requires_approval = true" in src
