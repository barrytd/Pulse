# tests/test_response_connectors.py
# ---------------------------------
# SOAR phase 3, part 3: the ticketing connector (ClickUp / Jira) and the
# generic outbound webhook, plus the guarded-request helper both use.
#
# No request leaves the test: DNS (socket.getaddrinfo) and the HTTP opener
# (urllib.request.build_opener) are replaced at the boundary.

import base64
import hashlib
import hmac
import io
import json
import socket
import urllib.error
import urllib.request

import pytest
from fastapi.testclient import TestClient

from pulse import connectors
from pulse.api import create_app
from pulse.connectors import base, outbound_webhook as ow, ticketing
from pulse.database import init_db, save_scan
from pulse.firewall import blocker
from pulse.soar import builder, engine, recipe, store

PW = "correct-horse-battery"
PUBLIC = "93.184.216.34"


def _addr(*ips):
    return lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
                                        for ip in ips]


class _Resp:
    def __init__(self, status=200, body=b"{}"):
        self.status, self._body = status, body

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Opener:
    """Stands in for urllib.request.build_opener(...): records requests."""

    def __init__(self, reply=None, error=None):
        self.requests, self.handlers = [], []
        self.reply, self.error = reply or _Resp(), error

    def __call__(self, *handlers):
        self.handlers = list(handlers)
        return self

    def open(self, req, timeout=None):
        self.requests.append(req)
        if self.error:
            raise self.error
        return self.reply

    @property
    def last(self):
        return self.requests[-1]

    def body(self):
        return json.loads(self.last.data.decode("utf-8"))

    def header(self, name):
        return {k.lower(): v for k, v in self.last.header_items()}.get(name.lower())


@pytest.fixture
def net(monkeypatch):
    """Public DNS by default + a recording opener. Nothing leaves."""
    monkeypatch.setattr(socket, "getaddrinfo", _addr(PUBLIC))
    opener = _Opener()
    monkeypatch.setattr(urllib.request, "build_opener", opener)
    return opener


def _http_error(code):
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(b""))


CLICKUP = {"ticketing": {"provider": "clickup", "clickup_token": "pk_test", "clickup_list_id": "901"}}
JIRA = {"ticketing": {"provider": "jira", "jira_url": "https://acme.atlassian.net",
                      "jira_email": "sec@acme.test", "jira_token": "jt", "jira_project": "SEC"}}
HOOK = {"outbound_webhook": {"url": "https://hooks.acme.test/pulse", "secret": "s3cret"}}


def _run(key, action, inputs, pulse_config):
    c = connectors.get(key)
    return connectors.run_action(key, action, inputs, connectors.config_for(c, pulse_config))


# ---------------------------------------------------------------------------
# Guarded requests
# ---------------------------------------------------------------------------

class TestGuard:
    @pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "169.254.169.254", "fe80::1",
                                    "0.0.0.0", "224.0.0.1", "::ffff:127.0.0.1"])
    def test_loopback_link_local_metadata_always_refused(self, monkeypatch, ip):
        monkeypatch.setattr(socket, "getaddrinfo", _addr(ip))
        with pytest.raises(base.DestinationRefused):
            base.check_destination("https://looks-public.test/x", allow_private=True)

    @pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.10", "172.16.0.1", "100.64.1.1", "fd00::1"])
    def test_private_needs_explicit_permission(self, monkeypatch, ip):
        monkeypatch.setattr(socket, "getaddrinfo", _addr(ip))
        with pytest.raises(base.DestinationRefused, match="private"):
            base.check_destination("https://n8n.lan.test/hook")
        base.check_destination("https://n8n.lan.test/hook", allow_private=True)

    def test_any_bad_address_in_the_answer_refuses(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _addr(PUBLIC, "127.0.0.1"))
        with pytest.raises(base.DestinationRefused):
            base.check_destination("https://mixed.test/")

    @pytest.mark.parametrize("url,allow,msg", [
        ("http://hooks.test/x", False, "https"),
        ("ftp://hooks.test/x", True, "https"),
        ("https://user:pw@hooks.test/x", False, "credentials"),
        ("not a url", False, "https"),
    ])
    def test_url_shape(self, net, url, allow, msg):
        with pytest.raises(base.DestinationRefused, match=msg):
            base.check_destination(url, allow_private=allow)

    def test_http_allowed_with_private(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _addr("10.0.0.5"))
        base.check_destination("http://n8n.lan.test:5678/hook", allow_private=True)

    def test_redirects_are_not_followed(self, net):
        base.request_guarded("https://hooks.test/x", payload={"a": 1})
        assert base._NoRedirect in net.handlers
        assert base._NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://127.0.0.1/") is None

    def test_refused_url_is_never_opened(self, monkeypatch, net):
        monkeypatch.setattr(socket, "getaddrinfo", _addr("169.254.169.254"))
        with pytest.raises(base.DestinationRefused):
            base.request_guarded("https://metadata.test/latest", payload={})
        assert net.requests == []


# ---------------------------------------------------------------------------
# Ticketing
# ---------------------------------------------------------------------------

class TestClickUp:
    def test_creates_a_task(self, net):
        net.reply = _Resp(body=json.dumps({"id": "abc", "url": "https://app.clickup.com/t/abc"}).encode())
        out = _run("ticket", "create_ticket",
                   {"title": "Brute force on DC-01", "description": "From 45.33.32.156", "priority": "High"},
                   CLICKUP)
        assert net.last.full_url == "https://api.clickup.com/api/v2/list/901/task"
        assert net.last.get_method() == "POST"
        assert net.header("Authorization") == "pk_test"
        assert net.body() == {"name": "Brute force on DC-01", "description": "From 45.33.32.156",
                              "priority": 2}
        assert out["ok"] and out["url"] == "https://app.clickup.com/t/abc"

    def test_unknown_priority_is_left_out(self, net):
        _run("ticket", "create_ticket", {"title": "x", "priority": "whenever"}, CLICKUP)
        assert "priority" not in net.body()

    @pytest.mark.parametrize("code,msg", [(401, "credentials"), (404, "list / project"),
                                          (302, "redirect"), (500, "HTTP 500")])
    def test_failures(self, net, code, msg):
        net.error = _http_error(code)
        out = _run("ticket", "create_ticket", {"title": "x"}, CLICKUP)
        assert out["ok"] is False and msg in out["message"]

    def test_offline(self, net):
        net.error = urllib.error.URLError("down")
        assert _run("ticket", "create_ticket", {"title": "x"}, CLICKUP)["ok"] is False


class TestJira:
    def test_creates_an_issue(self, net):
        net.reply = _Resp(body=json.dumps({"id": "10001", "key": "SEC-42"}).encode())
        out = _run("ticket", "create_ticket", {"title": "Golden Ticket on DC-01", "description": "d"}, JIRA)
        assert net.last.full_url == "https://acme.atlassian.net/rest/api/2/issue"
        auth = net.header("Authorization")
        assert base64.b64decode(auth.split(" ", 1)[1]).decode() == "sec@acme.test:jt"
        assert net.body() == {"fields": {"project": {"key": "SEC"}, "summary": "Golden Ticket on DC-01",
                                         "issuetype": {"name": "Task"}, "description": "d"}}
        assert out["ok"] and out["url"] == "https://acme.atlassian.net/browse/SEC-42"

    def test_private_jira_needs_permission(self, monkeypatch, net):
        monkeypatch.setattr(socket, "getaddrinfo", _addr("10.1.2.3"))
        out = _run("ticket", "create_ticket", {"title": "x"}, JIRA)
        assert out["ok"] is False and "private" in out["message"] and net.requests == []
        allowed = {"ticketing": dict(JIRA["ticketing"], allow_private=True)}
        assert _run("ticket", "create_ticket", {"title": "x"}, allowed)["ok"] is True

    def test_credentials_check_creates_nothing(self, net):
        assert ticketing.check_credentials(JIRA)["ok"] is True
        assert net.last.get_method() == "GET"
        assert net.last.full_url.endswith("/rest/api/2/myself")
        assert ticketing.check_credentials(CLICKUP)["ok"] is True
        assert net.last.get_method() == "GET" and net.last.full_url.endswith("/list/901")


class TestTicketConfig:
    @pytest.mark.parametrize("cfg", [{}, {"ticketing": {"provider": "clickup", "clickup_token": "t"}},
                                     {"ticketing": {"provider": "jira", "jira_url": "https://x.test"}},
                                     {"ticketing": {"provider": "trello"}}])
    def test_incomplete_settings_are_not_set_up(self, net, cfg):
        c = connectors.get("ticket")
        assert c.health_check(connectors.config_for(c, cfg)) is False
        out = _run("ticket", "create_ticket", {"title": "x"}, cfg)
        assert out["ok"] is False and net.requests == []

    def test_title_required(self, net):
        assert _run("ticket", "create_ticket", {"title": "  "}, CLICKUP)["ok"] is False


# ---------------------------------------------------------------------------
# Outbound webhook
# ---------------------------------------------------------------------------

class TestOutboundWebhook:
    def test_payload_is_only_the_step_inputs(self, net):
        out = _run("outbound_webhook", "send",
                   {"message": "Blocked 45.33.32.156", "event": "pulse.block"}, HOOK)
        assert out["ok"]
        assert net.last.full_url == "https://hooks.acme.test/pulse"
        body = net.body()
        assert set(body) == {"source", "event", "message", "sent_at"}
        assert body["message"] == "Blocked 45.33.32.156" and body["event"] == "pulse.block"

    def test_signature_verifies(self, net):
        _run("outbound_webhook", "send", {"message": "hi"}, HOOK)
        ts, sig = net.header("X-Pulse-Timestamp"), net.header("X-Pulse-Signature")
        expected = hmac.new(b"s3cret", ts.encode() + b"." + net.last.data, hashlib.sha256).hexdigest()
        assert sig == "sha256=" + expected

    def test_unsigned_without_secret(self, net):
        _run("outbound_webhook", "send", {"message": "hi"},
             {"outbound_webhook": {"url": "https://hooks.acme.test/pulse"}})
        assert net.header("X-Pulse-Signature") is None

    def test_a_step_cannot_choose_the_url(self, net):
        _run("outbound_webhook", "send", {"message": "hi", "url": "https://evil.test/"}, HOOK)
        assert net.last.full_url == "https://hooks.acme.test/pulse"

    def test_refused_destination_and_failures(self, monkeypatch, net):
        monkeypatch.setattr(socket, "getaddrinfo", _addr("169.254.169.254"))
        out = _run("outbound_webhook", "send", {"message": "hi"}, HOOK)
        assert out["ok"] is False and net.requests == []
        monkeypatch.setattr(socket, "getaddrinfo", _addr(PUBLIC))
        net.error = _http_error(301)
        assert "redirect" in _run("outbound_webhook", "send", {"message": "hi"}, HOOK)["message"]

    def test_not_set_up_without_url(self, net):
        c = connectors.get("outbound_webhook")
        assert c.health_check(connectors.config_for(c, {})) is False
        assert _run("outbound_webhook", "send", {"message": "hi"}, {})["ok"] is False


# ---------------------------------------------------------------------------
# Playbooks: approval, builder, and no data the step didn't ask for
# ---------------------------------------------------------------------------

class TestInPlaybooks:
    def test_both_are_response_actions_in_the_builder(self):
        by = {c["key"]: c for c in builder.schema()["connectors"]}
        for key in ("ticket", "outbound_webhook"):
            assert by[key]["kind"] == "response" and by[key]["requires_approval"] is True
        for key, action in (("ticket", "create_ticket"), ("outbound_webhook", "send")):
            with pytest.raises(recipe.RecipeError, match="always requires human approval"):
                recipe.normalize({"name": "x", "trigger": {"on": "finding_created"},
                                  "steps": [{"connector": key, "action": action,
                                             "with": {"title": "t", "message": "m"},
                                             "requires_approval": False}]})

    def test_engine_waits_then_sends_only_what_the_step_says(self, tmp_path, net, monkeypatch):
        monkeypatch.setattr(blocker, "stage_ip", lambda *a, **k: {"ok": True})
        db = str(tmp_path / "t.db")
        init_db(db)
        clean, _ = recipe.normalize({
            "name": "Hand off", "trigger": {"on": "finding_created"},
            "steps": [{"connector": "outbound_webhook", "action": "send",
                       "with": {"message": "{{ finding.rule }} on {{ finding.hostname }}"}},
                      {"connector": "ticket", "action": "create_ticket",
                       "with": {"title": "Investigate {{ finding.rule }}"}}]})
        store.create_playbook(db, 0, clean)
        sid = save_scan(db, [{"rule": "Golden Ticket", "severity": "CRITICAL", "hostname": "DC-01",
                              "details": "user secret-admin from 45.33.32.156, password=hunter2",
                              "description": "x"}],
                        scan_stats={"total_events": 1, "files_scanned": 1})
        cfg = dict(HOOK, **CLICKUP)
        run_id = engine.handle_scan(db, sid, cfg)[0]
        assert store.get_run(db, 0, run_id)["status"] == store.AWAITING
        assert net.requests == []                           # nothing sent before approval
        engine.approve(db, 0, run_id, "boss@x.com", cfg)
        sent = net.body()
        assert sent["message"] == "Golden Ticket on DC-01"
        assert "hunter2" not in net.last.data.decode() and "45.33.32.156" not in net.last.data.decode()
        run = engine.approve(db, 0, run_id, "boss@x.com", cfg)
        assert net.body() == {"name": "Investigate Golden Ticket"}
        assert run["status"] == store.COMPLETED


# ---------------------------------------------------------------------------
# Settings API
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    c = TestClient(create_app(db_path=str(tmp_path / "t.db"), config_path=str(cfg)))
    assert c.post("/api/auth/signup", json={"email": "a@x.com", "password": PW}).status_code == 200
    return c


class TestSettingsApi:
    def test_ticketing_saved_and_secrets_never_returned(self, client):
        r = client.put("/api/config/ticketing", json={
            "provider": "jira", "jira_url": "https://acme.atlassian.net", "jira_email": "e@x.com",
            "jira_token": "JIRA-SECRET", "jira_project": "SEC"})
        assert r.status_code == 200 and r.json()["configured"] is True
        cfg = client.get("/api/config")
        assert "JIRA-SECRET" not in cfg.text
        view = cfg.json()["ticketing"]
        assert view["jira_token_set"] is True and view["jira_project"] == "SEC"
        # Blank keeps, "null" clears.
        client.put("/api/config/ticketing", json={"jira_token": ""})
        assert client.get("/api/config").json()["ticketing"]["jira_token_set"] is True
        client.put("/api/config/ticketing", json={"jira_token": "null"})
        assert client.get("/api/config").json()["ticketing"]["jira_token_set"] is False

    @pytest.mark.parametrize("body,msg", [
        ({"provider": "trello"}, "provider"),
        ({"jira_url": "http://jira.acme.test"}, "https"),
        ({"jira_url": "https://u:p@jira.acme.test"}, "credentials"),
    ])
    def test_ticketing_validation(self, client, body, msg):
        r = client.put("/api/config/ticketing", json=body)
        assert r.status_code == 400 and msg in r.json()["detail"]

    def test_webhook_url_and_secret_never_returned(self, client):
        r = client.put("/api/config/outbound_webhook", json={
            "url": "https://hooks.acme.test/T0KEN/path", "secret": "SIGN-SECRET"})
        assert r.status_code == 200
        cfg = client.get("/api/config")
        assert "T0KEN" not in cfg.text and "SIGN-SECRET" not in cfg.text
        view = cfg.json()["outbound_webhook"]
        assert view == {"url_set": True, "host": "hooks.acme.test", "secret_set": True,
                        "allow_private": False}

    def test_webhook_http_only_with_private_allowed(self, client):
        assert client.put("/api/config/outbound_webhook",
                          json={"url": "http://n8n.lan:5678/x"}).status_code == 400
        assert client.put("/api/config/outbound_webhook",
                          json={"allow_private": True, "url": "http://n8n.lan:5678/x"}).status_code == 200

    def test_test_buttons(self, client, net):
        assert client.post("/api/config/ticketing/test").status_code == 502     # not set up
        client.put("/api/config/outbound_webhook", json={"url": "https://hooks.acme.test/p"})
        r = client.post("/api/config/outbound_webhook/test")
        assert r.status_code == 200 and net.body()["event"] == "pulse.test"
        assert client.post("/api/config/nope/test").status_code == 404

    def test_admin_only(self, client):
        client.post("/api/users", json={"email": "an@x.com", "password": PW, "role": "analyst"})
        client.post("/api/auth/logout")
        client.post("/api/auth/login", json={"email": "an@x.com", "password": PW})
        assert client.put("/api/config/outbound_webhook", json={"url": "https://x.test"}).status_code == 403
        assert client.post("/api/config/outbound_webhook/test").status_code == 403
