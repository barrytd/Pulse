# tests/test_soar.py
# ------------------
# Playbook engine (pulse/soar/): the safe expression language, recipe
# validation, the engine (matching, enrichment, approval pauses, failure
# handling, dedupe, org scoping), the response connectors, and the HTTP
# API (permissions, PIN step-up, org isolation, audit).
#
# Nothing here touches the network or the real firewall: threat-intel
# fetches, blocker.stage_ip / push_pending and webhook posts are all
# replaced with recorders.

import json

import pytest
from fastapi.testclient import TestClient

from pulse import database
from pulse.api import create_app
from pulse.auth import hash_password
from pulse.connectors import abuseipdb, virustotal as vt
from pulse.database import init_db, save_scan
from pulse.firewall import blocker
from pulse.soar import engine, expr, recipe, store, templates

PW = "correct-horse-battery"
PUBLIC_IP = "45.33.32.156"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """No real network, firewall or webhook in any test here."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    vt.QUOTA.reset()
    calls = {"stage": [], "push": [], "post": []}

    def fake_stage(db_path, ip, comment=None, finding_id=None, source="cli", user=None, force=False):
        calls["stage"].append({"ip": ip, "user": user, "source": source,
                               "finding_id": finding_id, "force": force})
        return {"ok": True, "message": "staged", "row": None, "forced": False}

    def fake_push(db_path, source="cli", user=None, only_ips=None):
        calls["push"].append({"only_ips": only_ips, "user": user})
        return {"ok": True, "pushed": len(only_ips or []), "skipped": 0, "failures": [],
                "message": "pushed"}

    monkeypatch.setattr(blocker, "stage_ip", fake_stage)
    monkeypatch.setattr(blocker, "push_pending", fake_push)
    import pulse.alerts.webhook as webhook
    monkeypatch.setattr(webhook, "_post_json",
                        lambda url, payload, timeout=10: calls["post"].append((url, payload)) or True)
    monkeypatch.setattr(abuseipdb, "fetch", lambda ip, key: None)
    monkeypatch.setattr(vt, "fetch", lambda action, ind, key: None)
    yield calls
    vt.QUOTA.reset()


@pytest.fixture
def db(tmp_path):
    p = str(tmp_path / "t.db")
    init_db(p)
    return p


KEYS = {"threat_intel": {"abuseipdb_api_key": "a-key", "virustotal_api_key": "v-key"},
        "delivery": {"slack": {"enabled": True, "webhook_url": "https://hooks.example/slack"}}}


def _finding(rule="Brute Force Attempt", severity="HIGH", ip=PUBLIC_IP, host="DC-01"):
    return {"rule": rule, "severity": severity, "hostname": host,
            "description": f"{rule} detected", "details": f"Source IP: {ip}" if ip else "none",
            "timestamp": "2026-09-26T10:00:00Z", "event_id": "4625", "mitre": "T1110"}


def _scan(db_path, findings, user_id=None):
    return save_scan(db_path, findings, scan_stats={"total_events": 10, "files_scanned": 1},
                     score=50, score_label="MODERATE RISK", user_id=user_id)


def _playbook(db_path, rec, org=0):
    clean, _ = recipe.normalize(rec)
    return store.create_playbook(db_path, org, clean)


def _abuse_says(monkeypatch, score):
    monkeypatch.setattr(abuseipdb, "fetch", lambda ip, key: {
        "ip": ip, "source": "abuseipdb", "score": score, "country": "RU", "isp": "x",
        "total_reports": 9, "last_reported": None, "fetched_at": store.now_str(), "_raw": {}})


def _vt_says(monkeypatch, malicious):
    def fake(action, ind, key):
        e = vt._empty(ind, "ip")
        e.update(found=True, malicious=malicious, harmless=60, engines=60 + malicious)
        return e
    monkeypatch.setattr(vt, "fetch", fake)


def _audit_actions(db_path):
    return [r["action"] for r in blocker.get_audit_log(db_path, limit=500)]


def _contain_template():
    return templates.get("contain-malicious-ip")["recipe"]


# ---------------------------------------------------------------------------
# Expressions: safe subset only
# ---------------------------------------------------------------------------

class TestExpressions:
    CTX = {"finding": {"source_ip": PUBLIC_IP, "severity": "HIGH"},
           "abuse": {"score": 85}, "vt": None}

    def test_placeholder_keeps_native_type_when_whole(self):
        assert expr.render("{{ abuse.score }}", self.CTX) == 85

    def test_placeholder_interpolates_inside_text(self):
        assert expr.render("IP {{ finding.source_ip }} scored {{ abuse.score }}", self.CTX) \
            == f"IP {PUBLIC_IP} scored 85"

    def test_two_placeholders_are_never_read_as_one(self):
        # Regression: "{{ a }} on {{ b }}" used to be parsed as a single
        # placeholder "a }} on {{ b" and blow up.
        ctx = {"finding": {"rule": "Golden Ticket", "hostname": "DC-01"}}
        assert expr.render("{{ finding.rule }} on {{ finding.hostname }}", ctx)             == "Golden Ticket on DC-01"

    def test_missing_values_render_empty_or_none(self):
        assert expr.render("{{ vt.malicious }}", self.CTX) is None
        assert expr.render("x{{ vt.malicious }}y", self.CTX) == "xy"

    @pytest.mark.parametrize("src,expected", [
        ("abuse.score >= 80", True),
        ("abuse.score >= 80 and finding.severity == 'HIGH'", True),
        ("vt.malicious >= 3", False),              # None -> comparison is False
        ("abuse.score >= 80 or vt.malicious >= 3", True),
        ("not (abuse.score < 50)", True),
        ("finding.severity in ['HIGH', 'CRITICAL']", True),
        ("vt == None", True),
        ("{{ abuse.score > 90 }}", False),
    ])
    def test_evaluate(self, src, expected):
        assert expr.evaluate(src, self.CTX) is expected

    @pytest.mark.parametrize("src", [
        "__import__('os').system('whoami')",
        "finding.__class__",
        "open('x')",
        "abuse.score + 1 > 2",
        "[x for x in finding]",
        "finding['severity'] == 'HIGH'",
        "lambda: 1",
        "(yield)",
        "abuse.score if True else 0",
    ])
    def test_code_is_rejected(self, src):
        with pytest.raises(expr.ExprError):
            expr.parse_condition(src)

    def test_placeholder_paths_must_be_dotted_names(self):
        with pytest.raises(expr.ExprError):
            expr.render("{{ finding.__dict__ }}", self.CTX)
        with pytest.raises(expr.ExprError):
            expr.placeholder_paths("{{ open('x') }}")


# ---------------------------------------------------------------------------
# Recipe validation
# ---------------------------------------------------------------------------

def _rec(**over):
    base = {"name": "t", "trigger": {"on": "finding_created"},
            "steps": [{"connector": "abuseipdb", "action": "lookup_ip",
                       "with": {"ip": "{{ finding.source_ip }}"}, "save_as": "abuse"}]}
    base.update(over)
    return base


class TestRecipe:
    @pytest.mark.parametrize("t", templates.TEMPLATES, ids=lambda t: t["key"])
    def test_builtin_templates_are_valid(self, t):
        clean, flat = recipe.normalize(t["recipe"])
        assert flat["steps"]
        # Every response step in a template waits for a person.
        assert all(s["requires_approval"] for s in flat["steps"] if s["kind"] == "response")

    def test_response_step_cannot_skip_approval(self):
        rec = _rec(steps=[{"connector": "firewall", "action": "block_ip",
                           "with": {"ip": "{{ finding.source_ip }}"},
                           "requires_approval": False}])
        with pytest.raises(recipe.RecipeError) as e:
            recipe.normalize(rec)
        assert "always requires human approval" in str(e.value)

    def test_response_step_gets_approval_even_if_omitted(self):
        rec = _rec(steps=[{"connector": "webhook", "action": "post_message",
                           "with": {"text": "hi"}}])
        clean, flat = recipe.normalize(rec)
        assert flat["steps"][0]["requires_approval"] is True
        assert clean["steps"][0]["requires_approval"] is True

    def test_accepts_json_text(self):
        clean, _ = recipe.normalize(json.dumps(_rec()))
        assert clean["name"] == "t"

    @pytest.mark.parametrize("bad,msg", [
        ("{not json", "Invalid JSON"),
        ("[]", "JSON object"),
        (_rec(trigger={"on": "scan_finished"}), "trigger"),
        (_rec(steps=[]), "non-empty"),
        (_rec(steps=[{"connector": "nope", "action": "x"}]), "unknown connector"),
        (_rec(steps=[{"connector": "abuseipdb", "action": "lookup_hash"}]), "no action"),
        (_rec(conditions=[{"field": "colour", "op": "eq", "value": 1}]), "unknown field"),
        (_rec(conditions=[{"field": "rule", "op": "matches", "value": 1}]), "unknown op"),
        (_rec(conditions=[{"field": "rule", "op": "in", "value": "x"}]), "list"),
        (_rec(conditions=[{"field": "severity", "op": "severity_at_least", "value": "HUGE"}]),
         "severity_at_least"),
        (_rec(steps=[{"connector": "abuseipdb", "action": "lookup_ip",
                      "with": {"ip": "{{ vt.ip }}"}}]), "isn't available"),
        (_rec(steps=[{"if": "{{ abuse.score > 1 }}", "then": [
            {"connector": "webhook", "action": "post_message", "with": {"text": "x"}}]}]),
         "isn't available"),
        (_rec(steps=[{"if": "{{ open('x') }}", "then": [
            {"connector": "webhook", "action": "post_message", "with": {"text": "x"}}]}]),
         "not allowed"),
        (_rec(surprise=1), "Unknown top-level"),
        (_rec(steps=[{"connector": "abuseipdb", "action": "lookup_ip", "save_as": "finding"}]),
         "save_as"),
    ])
    def test_rejects(self, bad, msg):
        with pytest.raises(recipe.RecipeError) as e:
            recipe.normalize(bad)
        assert msg.lower() in str(e.value).lower()

    def test_step_and_depth_limits(self):
        many = [{"connector": "abuseipdb", "action": "lookup_ip"}] * (recipe.MAX_STEPS + 1)
        with pytest.raises(recipe.RecipeError, match="at most"):
            recipe.normalize(_rec(steps=many))
        leaf = {"connector": "abuseipdb", "action": "lookup_ip"}
        deep = leaf
        for _ in range(recipe.MAX_DEPTH):
            deep = {"if": "{{ finding.severity == 'HIGH' }}", "then": [deep]}
        with pytest.raises(recipe.RecipeError, match="nest"):
            recipe.normalize(_rec(steps=[deep]))

    def test_nested_if_steps_carry_their_guards(self):
        _, flat = recipe.normalize(_contain_template())
        assert [s["guards"] for s in flat["steps"]] == [[], [], ["g0"], ["g0"]]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class TestMatching:
    def test_source_ip_is_extracted_like_the_drawer(self):
        ctx = engine.finding_context({"details": "from 999.1.1.1 then 10.0.0.5 and 8.8.8.8"})
        assert ctx["source_ip"] == "10.0.0.5"

    @pytest.mark.parametrize("cond,expected", [
        ({"field": "severity", "op": "severity_at_least", "value": "HIGH"}, True),
        ({"field": "severity", "op": "severity_at_least", "value": "CRITICAL"}, False),
        ({"field": "rule", "op": "eq", "value": "brute force attempt"}, True),
        ({"field": "rule", "op": "in", "value": ["Kerberoasting"]}, False),
        ({"field": "rule", "op": "not_in", "value": ["Kerberoasting"]}, True),
        ({"field": "details", "op": "contains", "value": "source ip"}, True),
        ({"field": "source_ip", "op": "is_public", "value": True}, True),
        ({"field": "event_id", "op": "gte", "value": 4600}, True),
        ({"field": "mitre", "op": "exists", "value": True}, True),
    ])
    def test_conditions(self, cond, expected):
        assert engine.condition_holds(cond, engine.finding_context(_finding())) is expected


class TestEngine:
    def test_enrichment_runs_on_its_own(self, db, monkeypatch):
        _abuse_says(monkeypatch, 12)
        _vt_says(monkeypatch, 0)
        _playbook(db, templates.get("enrich-external-ip")["recipe"])
        sid = _scan(db, [_finding()])
        run_ids = engine.handle_scan(db, sid, KEYS)
        run = store.get_run(db, 0, run_ids[0])
        assert run["status"] == store.COMPLETED
        assert [s["status"] for s in run["steps"]] == ["done", "done"]
        assert run["context"]["abuse"]["score"] == 12
        assert run["steps"][0]["inputs"] == {"ip": PUBLIC_IP}
        assert "playbook_run_started" in _audit_actions(db)
        assert "playbook_run_completed" in _audit_actions(db)

    def test_no_match_no_run(self, db):
        _playbook(db, templates.get("enrich-external-ip")["recipe"])
        low = _scan(db, [_finding(severity="LOW")])
        private = _scan(db, [_finding(ip="10.1.2.3")])
        assert engine.handle_scan(db, low, KEYS) == []
        assert engine.handle_scan(db, private, KEYS) == []

    def test_disabled_playbook_does_not_run(self, db):
        pid = _playbook(db, templates.get("enrich-external-ip")["recipe"])
        store.set_playbook_enabled(db, 0, pid, False)
        assert engine.handle_scan(db, _scan(db, [_finding()]), KEYS) == []

    def test_response_step_waits_for_approval(self, db, monkeypatch, _isolate):
        _abuse_says(monkeypatch, 95)
        _playbook(db, _contain_template())
        run_id = engine.handle_scan(db, _scan(db, [_finding()]), KEYS)[0]
        run = store.get_run(db, 0, run_id)
        assert run["status"] == store.AWAITING
        pending = run["steps"][-1]
        assert pending["connector"] == "firewall"
        assert pending["inputs"]["ip"] == PUBLIC_IP
        assert _isolate["stage"] == [] and _isolate["push"] == []   # nothing blocked yet
        assert "playbook_step_awaiting_approval" in _audit_actions(db)

    def test_approve_runs_the_step_then_pauses_on_the_next(self, db, monkeypatch, _isolate):
        _abuse_says(monkeypatch, 95)
        _playbook(db, _contain_template())
        run_id = engine.handle_scan(db, _scan(db, [_finding()]), KEYS)[0]

        run = engine.approve(db, 0, run_id, "boss@x.com", KEYS)
        assert _isolate["stage"][0]["ip"] == PUBLIC_IP
        assert _isolate["stage"][0]["user"] == "boss@x.com"
        assert _isolate["stage"][0]["force"] is False
        # Only this IP is pushed, never other staged rows.
        assert _isolate["push"] == [{"only_ips": [PUBLIC_IP], "user": "boss@x.com"}]
        # The webhook post is the next response step: it waits too.
        assert run["status"] == store.AWAITING
        assert run["steps"][-2]["status"] == "done"
        assert run["steps"][-2]["approved_by"] == "boss@x.com"
        assert _isolate["post"] == []

        run = engine.approve(db, 0, run_id, "boss@x.com", KEYS)
        assert run["status"] == store.COMPLETED
        url, payload = _isolate["post"][0]
        assert url == "https://hooks.example/slack"
        assert PUBLIC_IP in payload["text"] and "score 95" in payload["text"]
        acts = _audit_actions(db)
        assert acts.count("playbook_step_approved") == 2
        assert acts.count("playbook_action_executed") == 2

    def test_approval_is_single_use(self, db, monkeypatch, _isolate):
        _abuse_says(monkeypatch, 95)
        _playbook(db, _contain_template())
        run_id = engine.handle_scan(db, _scan(db, [_finding()]), KEYS)[0]
        run = store.get_run(db, 0, run_id)
        assert store.claim_awaiting(db, 0, run_id, run["cursor"]) is True
        assert store.claim_awaiting(db, 0, run_id, run["cursor"]) is False
        with pytest.raises(engine.ApprovalError):
            engine.approve(db, 0, run_id, "boss@x.com", KEYS)
        assert _isolate["stage"] == []

    def test_deny_stops_the_run(self, db, monkeypatch, _isolate):
        _abuse_says(monkeypatch, 95)
        _playbook(db, _contain_template())
        run_id = engine.handle_scan(db, _scan(db, [_finding()]), KEYS)[0]
        run = engine.deny(db, 0, run_id, "boss@x.com")
        assert run["status"] == store.DENIED
        assert run["steps"][-1]["status"] == "denied"
        assert _isolate["stage"] == []
        with pytest.raises(engine.ApprovalError):
            engine.approve(db, 0, run_id, "boss@x.com", KEYS)
        assert "playbook_step_denied" in _audit_actions(db)

    def test_if_false_skips_response_steps(self, db, monkeypatch, _isolate):
        _abuse_says(monkeypatch, 3)
        _vt_says(monkeypatch, 0)
        _playbook(db, _contain_template())
        run = store.get_run(db, 0, engine.handle_scan(db, _scan(db, [_finding()]), KEYS)[0])
        assert run["status"] == store.COMPLETED
        assert [s["status"] for s in run["steps"]] == ["done", "done", "skipped", "skipped"]
        assert _isolate["stage"] == []

    def test_failing_connectors_are_logged_and_the_run_continues(self, db, monkeypatch):
        def boom(ip, key):
            raise RuntimeError("AbuseIPDB exploded")
        monkeypatch.setattr(abuseipdb, "fetch", boom)
        _vt_says(monkeypatch, 5)
        _playbook(db, _contain_template())
        run = store.get_run(db, 0, engine.handle_scan(db, _scan(db, [_finding()]), KEYS)[0])
        # AbuseIPDB blew up, VirusTotal still ran, and its verdict alone
        # tripped the `if`, so the block is waiting for approval.
        assert run["steps"][0]["status"] == "no_result"
        assert run["steps"][1]["status"] == "done"
        assert run["status"] == store.AWAITING

    def test_failed_response_action_is_logged_and_the_run_continues(self, db, monkeypatch, _isolate):
        _abuse_says(monkeypatch, 95)
        monkeypatch.setattr(blocker, "stage_ip",
                            lambda *a, **k: {"ok": False, "message": "Already on the block list."})
        _playbook(db, _contain_template())
        run_id = engine.handle_scan(db, _scan(db, [_finding()]), KEYS)[0]
        run = engine.approve(db, 0, run_id, "boss@x.com", KEYS)
        assert run["steps"][-2]["status"] == "failed"
        assert "Already on the block list" in run["steps"][-2]["message"]
        assert run["status"] == store.AWAITING          # moved on to the webhook step
        assert "playbook_action_failed" in _audit_actions(db)

    def test_switched_off_connector_is_skipped(self, db, monkeypatch):
        _abuse_says(monkeypatch, 95)
        store.set_connector_enabled(db, 0, "virustotal", False)
        _playbook(db, templates.get("enrich-external-ip")["recipe"])
        run = store.get_run(db, 0, engine.handle_scan(db, _scan(db, [_finding()]), KEYS)[0])
        assert [s["status"] for s in run["steps"]] == ["done", "skipped"]
        assert "switched off" in run["steps"][1]["message"]

    def test_burst_of_same_finding_makes_one_run(self, db):
        _playbook(db, templates.get("enrich-external-ip")["recipe"])
        sid = _scan(db, [_finding()] * 5 + [_finding(ip="8.8.8.8")])
        assert len(engine.handle_scan(db, sid, KEYS)) == 2   # one per source IP
        again = _scan(db, [_finding()])
        assert engine.handle_scan(db, again, KEYS) == []      # within 24h

    def test_run_uses_the_recipe_it_started_with(self, db, monkeypatch, _isolate):
        _abuse_says(monkeypatch, 95)
        pid = _playbook(db, _contain_template())
        run_id = engine.handle_scan(db, _scan(db, [_finding()]), KEYS)[0]
        # Someone edits the playbook while the block is waiting.
        edited = _rec(name="edited", steps=[{"connector": "abuseipdb", "action": "lookup_ip"}])
        store.update_playbook(db, 0, pid, recipe.normalize(edited)[0])
        engine.approve(db, 0, run_id, "boss@x.com", KEYS)
        assert _isolate["stage"][0]["ip"] == PUBLIC_IP

    def test_one_broken_run_does_not_stop_the_others(self, db, monkeypatch):
        _playbook(db, templates.get("enrich-external-ip")["recipe"])
        _playbook(db, templates.get("enrich-external-ip")["recipe"])
        real = engine.advance
        calls = []

        def flaky(db_path, org, run_id, cfg, **kw):
            calls.append(run_id)
            if len(calls) == 1:
                raise RuntimeError("surprise")
            return real(db_path, org, run_id, cfg, **kw)

        monkeypatch.setattr(engine, "advance", flaky)
        first, second = engine.handle_scan(db, _scan(db, [_finding()]), KEYS)
        assert store.get_run(db, 0, first)["status"] == store.FAILED
        assert "surprise" in store.get_run(db, 0, first)["steps"][-1]["message"]
        assert store.get_run(db, 0, second)["status"] == store.COMPLETED
        assert "playbook_run_failed" in _audit_actions(db)

    def test_never_raises(self, db, monkeypatch):
        monkeypatch.setattr(store, "list_playbooks", lambda *a, **k: 1 / 0)
        assert engine.handle_scan(db, _scan(db, [_finding()]), KEYS) == []


class TestOrgScoping:
    def _two_orgs(self, db):
        a = database.create_organization(db, name="Acme")
        b = database.create_organization(db, name="Beta")
        ua = database.create_user(db, "a@acme.test", hash_password(PW), role="admin",
                                  organization_id=a)
        ub = database.create_user(db, "b@beta.test", hash_password(PW), role="admin",
                                  organization_id=b)
        return a, b, ua, ub

    def test_playbooks_only_run_on_their_own_orgs_findings(self, db):
        a, b, ua, ub = self._two_orgs(db)
        _playbook(db, templates.get("enrich-external-ip")["recipe"], org=a)
        assert engine.handle_scan(db, _scan(db, [_finding()], user_id=ub), KEYS) == []
        ran = engine.handle_scan(db, _scan(db, [_finding()], user_id=ua), KEYS)
        assert len(ran) == 1
        assert store.get_run(db, b, ran[0]) is None          # invisible to org B
        assert store.get_run(db, a, ran[0]) is not None

    def test_server_scan_belongs_to_the_only_org(self, db):
        org = database.create_organization(db, name="Solo")
        _playbook(db, templates.get("enrich-external-ip")["recipe"], org=org)
        assert len(engine.handle_scan(db, _scan(db, [_finding()]), KEYS)) == 1

    def test_server_scan_with_several_orgs_runs_nothing(self, db):
        a, b, *_ = self._two_orgs(db)
        _playbook(db, templates.get("enrich-external-ip")["recipe"], org=a)
        _playbook(db, templates.get("enrich-external-ip")["recipe"], org=b)
        assert engine.handle_scan(db, _scan(db, [_finding()]), KEYS) == []


# ---------------------------------------------------------------------------
# Response connectors
# ---------------------------------------------------------------------------

class TestResponseConnectors:
    def test_webhook_posts_only_to_configured_hooks(self, _isolate):
        from pulse import connectors
        c = connectors.get("webhook")
        cfg = connectors.config_for(c, KEYS)
        out = c.run("post_message", {"text": "hello", "url": "https://evil.example"}, cfg)
        assert out["ok"] is True
        assert [u for u, _ in _isolate["post"]] == ["https://hooks.example/slack"]

    def test_webhook_without_config_fails_cleanly(self):
        from pulse import connectors
        c = connectors.get("webhook")
        out = c.run("post_message", {"text": "hi"}, connectors.config_for(c, {}))
        assert out["ok"] is False and "Settings" in out["message"]
        assert c.health_check(connectors.config_for(c, {})) is False

    def test_push_pending_only_ips(self, tmp_path, monkeypatch):
        # Real push_pending (not the fixture's fake), on a fake non-Windows
        # host so nothing can touch the firewall: rows are counted, not pushed.
        import importlib
        real = importlib.reload(blocker)
        monkeypatch.setattr(real, "is_windows", lambda: False)
        db_path = str(tmp_path / "b.db")
        init_db(db_path)
        real.stage_ip(db_path, "45.33.32.156")
        real.stage_ip(db_path, "8.8.4.4")
        assert real.push_pending(db_path, only_ips=["8.8.4.4"])["skipped"] == 1
        assert real.push_pending(db_path)["skipped"] == 2


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------

@pytest.fixture
def api(tmp_path):
    """Auth on. First signup = admin. Returns (client, db_path, app)."""
    db_path = str(tmp_path / "api.db")
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=db_path, config_path=str(cfg))
    app.state.soar.sync = True
    c = TestClient(app)
    assert c.post("/api/auth/signup", json={"email": "admin@x.com", "password": PW}).status_code == 200
    return c, db_path, app


def _me(c):
    return c.get("/api/me").json()


class TestPlaybookApi:
    def test_import_validate_and_errors(self, api):
        c, *_ = api
        ok = c.post("/api/playbooks/validate", json={"json": json.dumps(_contain_template())})
        assert ok.status_code == 200 and ok.json()["approval_steps"] == 2
        bad = c.post("/api/playbooks", json={"json": '{"name": "x", "steps": []}'})
        assert bad.status_code == 400
        assert bad.json()["detail"]["errors"]
        assert c.post("/api/playbooks", json={"json": ""}).status_code == 400

    def test_create_list_toggle_delete_with_audit(self, api):
        c, db_path, _ = api
        r = c.post("/api/playbooks", json={"json": json.dumps(_contain_template())})
        assert r.status_code == 200
        pid = r.json()["id"]
        listed = c.get("/api/playbooks").json()["playbooks"]
        assert [p["id"] for p in listed] == [pid]
        assert listed[0]["steps"][2]["requires_approval"] is True
        assert c.put(f"/api/playbooks/{pid}/enabled", json={"enabled": False}).json()["enabled"] is False
        assert c.get(f"/api/playbooks/{pid}").json()["enabled"] is False
        assert c.delete(f"/api/playbooks/{pid}").status_code == 200
        assert c.get(f"/api/playbooks/{pid}").status_code == 404
        acts = _audit_actions(db_path)
        for a in ("playbook_create", "playbook_disable", "playbook_delete"):
            assert a in acts

    def test_templates_listed_and_added(self, api):
        c, *_ = api
        keys = [t["key"] for t in c.get("/api/playbooks/templates").json()["templates"]]
        assert len(keys) >= 2
        r = c.post("/api/playbooks", json={"template": keys[0]})
        assert r.status_code == 200 and r.json()["origin"] == f"template:{keys[0]}"
        assert c.post("/api/playbooks", json={"template": "nope"}).status_code == 404

    def test_approval_needs_manager_and_pin(self, api, monkeypatch, _isolate):
        c, db_path, app = api
        _abuse_says(monkeypatch, 95)
        c.put("/api/config/threat_intel", json={"abuseipdb_api_key": "a-key"})
        c.post("/api/playbooks", json={"template": "contain-malicious-ip"})
        me = _me(c)
        sid = _scan(db_path, [_finding()], user_id=me["id"])
        app.state.soar.scan_saved(sid)
        runs = c.get("/api/playbook-runs?status=awaiting_approval").json()["runs"]
        assert len(runs) == 1
        run_id = runs[0]["id"]

        # PIN set -> approval needs a fresh PIN confirmation.
        c.post("/api/me/pin", json={"pin": "135790", "current_password": PW})
        r = c.post(f"/api/playbook-runs/{run_id}/approve")
        assert r.status_code == 403 and r.json()["detail"]["code"] == "pin_required"
        assert _isolate["stage"] == []
        assert c.post("/api/me/pin/verify", json={"pin": "135790"}).status_code == 200
        r = c.post(f"/api/playbook-runs/{run_id}/approve")
        assert r.status_code == 200
        assert _isolate["stage"][0]["user"] == "admin@x.com"
        # Already handled -> 409, never a second block.
        c.post(f"/api/playbook-runs/{run_id}/deny")
        assert c.post(f"/api/playbook-runs/{run_id}/approve").status_code in (200, 409)
        assert len(_isolate["stage"]) == 1

    def test_analyst_cannot_approve_or_edit(self, api, monkeypatch):
        c, db_path, app = api
        _abuse_says(monkeypatch, 95)
        c.put("/api/config/threat_intel", json={"abuseipdb_api_key": "a-key"})
        c.post("/api/playbooks", json={"template": "contain-malicious-ip"})
        sid = _scan(db_path, [_finding()], user_id=_me(c)["id"])
        app.state.soar.scan_saved(sid)
        run_id = c.get("/api/playbook-runs").json()["runs"][0]["id"]
        c.post("/api/users", json={"email": "an@x.com", "password": PW, "role": "analyst"})
        c.post("/api/auth/logout")
        c.post("/api/auth/login", json={"email": "an@x.com", "password": PW})
        assert c.post(f"/api/playbook-runs/{run_id}/approve").status_code == 403
        assert c.post("/api/playbooks", json={"template": "enrich-external-ip"}).status_code == 403
        assert c.get("/api/playbooks").status_code == 403

    def test_finding_runs_for_the_drawer(self, api, monkeypatch):
        c, db_path, app = api
        c.post("/api/playbooks", json={"template": "enrich-external-ip"})
        sid = _scan(db_path, [_finding()], user_id=_me(c)["id"])
        app.state.soar.scan_saved(sid)
        fid = database.get_scan_findings(db_path, sid)[0]["id"]
        runs = c.get(f"/api/findings/{fid}/playbook-runs").json()["runs"]
        assert len(runs) == 1 and runs[0]["finding"]["source_ip"] == PUBLIC_IP
        assert c.get("/api/findings/999999/playbook-runs").status_code == 404

    def test_connectors_list_and_toggle(self, api):
        c, db_path, _ = api
        rows = {r["key"]: r for r in c.get("/api/connectors").json()["connectors"]}
        assert rows["firewall"]["kind"] == "response"
        assert rows["virustotal"]["configured"] is False
        assert c.put("/api/connectors/virustotal", json={"enabled": False}).status_code == 200
        assert c.get("/api/connectors").json()["connectors"][2]["enabled"] is False
        assert c.put("/api/connectors/nope", json={"enabled": False}).status_code == 404
        assert "connector_disable" in _audit_actions(db_path)

    def test_upload_triggers_playbooks(self, api):
        c, db_path, _ = api
        c.post("/api/playbooks", json={"json": json.dumps(_rec(
            name="any finding",
            steps=[{"connector": "abuseipdb", "action": "lookup_ip",
                    "with": {"ip": "{{ finding.source_ip }}"}}]))})
        with open("samples/brute-force-server.evtx", "rb") as fh:
            r = c.post("/api/scan", files={"file": ("brute-force-server.evtx", fh)})
        assert r.status_code == 200
        assert c.get("/api/playbook-runs").json()["runs"]


class TestCrossOrgApi:
    def test_other_orgs_playbooks_and_runs_are_404(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PULSE_HOSTED_SIGNUP", "1")
        db_path = str(tmp_path / "mt.db")
        cfg = tmp_path / "pulse.yaml"
        cfg.write_text("whitelist:\n  accounts: []\n")
        app = create_app(db_path=db_path, config_path=str(cfg))
        app.state.soar.sync = True

        def tenant(email):
            c = TestClient(app)
            assert c.post("/api/auth/signup", json={"email": email, "password": PW}).status_code == 200
            return c

        a, b = tenant("a@acme.test"), tenant("b@beta.test")
        pid = a.post("/api/playbooks", json={"template": "enrich-external-ip"}).json()["id"]
        sid = _scan(db_path, [_finding()], user_id=_me(a)["id"])
        app.state.soar.scan_saved(sid)
        run_id = a.get("/api/playbook-runs").json()["runs"][0]["id"]

        assert b.get("/api/playbooks").json()["playbooks"] == []
        assert b.get(f"/api/playbooks/{pid}").status_code == 404
        assert b.delete(f"/api/playbooks/{pid}").status_code == 404
        assert b.get("/api/playbook-runs").json()["runs"] == []
        assert b.get(f"/api/playbook-runs/{run_id}").status_code == 404
        assert b.post(f"/api/playbook-runs/{run_id}/deny").status_code == 404
