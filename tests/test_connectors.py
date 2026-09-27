# tests/test_connectors.py
# ------------------------
# Unit tests for pulse/connectors/ (registry, AbuseIPDB + VirusTotal
# connectors, quota guard) and the /api/intel/{ip}/verdicts endpoint
# that feeds the finding drawer.
#
# Every outbound call is mocked at the urllib layer; none of these
# tests touch the network.

import io
import json
import urllib.error
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from pulse import connectors
from pulse.api import create_app
from pulse.connectors import base, virustotal as vt
from pulse.database import init_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_env_and_quota(monkeypatch):
    """Keep dev-machine keys out of the tests and give every test a
    fresh VirusTotal budget."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    vt.QUOTA.reset()
    yield
    vt.QUOTA.reset()


@pytest.fixture
def db_path(tmp_path):
    p = tmp_path / "test.db"
    init_db(str(p))
    return str(p)


def _make_client(tmp_path, intel_yaml):
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n" + intel_yaml)
    app = create_app(db_path=str(tmp_path / "test.db"),
                     config_path=str(config_path), disable_auth=True)
    return TestClient(app)


@pytest.fixture
def client(tmp_path):
    """App with both provider keys configured."""
    return _make_client(tmp_path,
        "threat_intel:\n"
        "  enabled: true\n"
        "  abuseipdb_api_key: abuse-test-key\n"
        "  virustotal_api_key: vt-test-key\n"
        "  cache_ttl_hours: 24\n")


def _fake_response(payload):
    """Minimal urlopen-style context manager that yields JSON."""
    class _Resp:
        status = 200
        def read(self):
            return json.dumps(payload).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
    return _Resp()


def _http_error(code):
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(b""))


def _vt_payload(malicious=5, suspicious=1, harmless=60, undetected=24, **attrs):
    body = {
        "last_analysis_stats": {
            "malicious": malicious, "suspicious": suspicious,
            "harmless": harmless, "undetected": undetected, "timeout": 2,
        },
        "reputation": -12,
        "last_analysis_date": 1790000000,
    }
    body.update(attrs)
    return {"data": {"attributes": body}}


ABUSE_PAYLOAD = {
    "data": {
        "ipAddress":            "45.33.32.156",
        "abuseConfidenceScore": 87,
        "countryCode":          "RU",
        "isp":                  "Bad ISP Ltd",
        "totalReports":         412,
        "lastReportedAt":       "2026-09-25T10:00:00+00:00",
    }
}


def _route(abuse=None, vt_resp=None):
    """urlopen side_effect that answers per provider based on the URL.
    Each arg is a payload dict, or an Exception to raise."""
    def _side_effect(req, timeout=None):
        url = req.full_url
        answer = abuse if "abuseipdb" in url else vt_resp
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            raise AssertionError(f"unexpected request to {url}")
        return _fake_response(answer)
    return _side_effect


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_discovers_builtin_connectors(self):
        assert connectors.get("abuseipdb") is not None
        assert connectors.get("virustotal") is not None

    def test_unknown_key_returns_none(self):
        assert connectors.get("nope") is None

    def test_filter_by_kind_is_sorted(self):
        keys = [c.key for c in connectors.all_connectors(kind="enrichment")]
        assert keys == sorted(keys)
        assert {"abuseipdb", "virustotal"} <= set(keys)
        responses = [c.key for c in connectors.all_connectors(kind="response")]
        assert responses == ["firewall", "outbound_webhook", "ticket", "webhook"]

    def test_connectors_declare_their_shape(self):
        for c in connectors.all_connectors():
            assert c.key and c.name
            assert c.kind in ("enrichment", "response")
            assert isinstance(c.actions(), list) and c.actions()

    def test_duplicate_key_rejected(self):
        with pytest.raises(ValueError):
            @connectors.register
            class _Dupe(connectors.Connector):
                key = "virustotal"

    def test_missing_key_rejected(self):
        with pytest.raises(ValueError):
            @connectors.register
            class _NoKey(connectors.Connector):
                pass

    def test_run_action_unknown_connector_or_action_returns_none(self):
        assert connectors.run_action("nope", "lookup_ip", {}, {}) is None
        assert connectors.run_action("abuseipdb", "lookup_hash", {}, {}) is None

    def test_run_action_swallows_connector_errors(self):
        c = connectors.get("virustotal")
        with patch.object(c, "run", side_effect=RuntimeError("boom")):
            assert connectors.run_action("virustotal", "lookup_ip",
                                         {"ip": "8.8.8.8"}, {}) is None

    def test_config_for_reads_keys_and_adds_db_path(self):
        cfg = {"threat_intel": {"virustotal_api_key": "  vk  ",
                                "cache_ttl_hours": 6}}
        out = connectors.config_for(connectors.get("virustotal"), cfg,
                                    db_path="x.db")
        assert out == {"api_key": "vk", "ttl_hours": 6, "db_path": "x.db"}

    def test_config_for_falls_back_to_env(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "from-env")
        out = connectors.config_for(connectors.get("virustotal"), {})
        assert out["api_key"] == "from-env"


# ---------------------------------------------------------------------------
# AbuseIPDB connector
# ---------------------------------------------------------------------------

class TestAbuseIPDBConnector:
    def _cfg(self, db_path, key="k"):
        return {"api_key": key, "ttl_hours": 24, "db_path": db_path}

    def test_lookup_returns_verdict_and_caches(self, db_path):
        with patch("urllib.request.urlopen",
                   return_value=_fake_response(ABUSE_PAYLOAD)):
            first = connectors.run_action("abuseipdb", "lookup_ip",
                                          {"ip": "45.33.32.156"},
                                          self._cfg(db_path))
        assert first["score"] == 87
        assert first["verdict"] == "malicious"
        assert first["cached"] is False

        with patch("urllib.request.urlopen") as mock_urlopen:
            second = connectors.run_action("abuseipdb", "lookup_ip",
                                           {"ip": "45.33.32.156"},
                                           self._cfg(db_path))
        mock_urlopen.assert_not_called()
        assert second["cached"] is True
        assert second["verdict"] == "malicious"

    def test_no_key_returns_none_without_network(self, db_path):
        with patch("urllib.request.urlopen") as mock_urlopen:
            out = connectors.run_action("abuseipdb", "lookup_ip",
                                        {"ip": "8.8.8.8"},
                                        self._cfg(db_path, key=None))
        assert out is None
        mock_urlopen.assert_not_called()

    def test_health_check_needs_key(self):
        c = connectors.get("abuseipdb")
        assert c.health_check({"api_key": "k"}) is True
        assert c.health_check({"api_key": None}) is False


# ---------------------------------------------------------------------------
# VirusTotal connector
# ---------------------------------------------------------------------------

class TestVirusTotalRequests:
    def _run(self, db_path, action, inputs, key="vt-key"):
        return connectors.run_action(
            "virustotal", action, inputs,
            {"api_key": key, "ttl_hours": 24, "db_path": db_path})

    @pytest.mark.parametrize("action,inputs,path", [
        ("lookup_ip", {"ip": "45.33.32.156"}, "/ip_addresses/45.33.32.156"),
        ("lookup_hash", {"hash": "44D88612FEA8A8F36DE82E1278ABB02F"},
         "/files/44d88612fea8a8f36de82e1278abb02f"),
        ("lookup_domain", {"domain": "Evil.Example.COM."},
         "/domains/evil.example.com"),
    ])
    def test_endpoint_and_api_key_header(self, db_path, action, inputs, path):
        seen = {}

        def _capture(req, timeout=None):
            seen["url"] = req.full_url
            seen["key"] = req.get_header("X-apikey")
            return _fake_response(_vt_payload())

        with patch("urllib.request.urlopen", side_effect=_capture):
            out = self._run(db_path, action, inputs)
        assert seen["url"] == "https://www.virustotal.com/api/v3" + path
        assert seen["key"] == "vt-key"
        assert out is not None and out["found"] is True

    def test_ip_result_is_normalized(self, db_path):
        payload = _vt_payload(country="NL", as_owner="Some Hosting BV")
        with patch("urllib.request.urlopen", return_value=_fake_response(payload)):
            out = self._run(db_path, "lookup_ip", {"ip": "45.33.32.156"})
        assert out["malicious"] == 5
        assert out["suspicious"] == 1
        # Timeouts don't count as engines that answered.
        assert out["engines"] == 90
        assert out["score"] == round(100 * 5 / 90)
        assert out["verdict"] == "malicious"
        assert out["country"] == "NL"
        assert out["as_owner"] == "Some Hosting BV"
        assert out["reputation"] == -12
        assert out["last_analysis"].startswith("2026-")
        assert out["cached"] is False

    def test_hash_result_carries_file_context(self, db_path):
        payload = _vt_payload(malicious=60, meaningful_name="eicar.com",
                              type_description="Text")
        with patch("urllib.request.urlopen", return_value=_fake_response(payload)):
            out = self._run(db_path, "lookup_hash",
                            {"hash": "44d88612fea8a8f36de82e1278abb02f"})
        assert out["type"] == "file"
        assert out["name"] == "eicar.com"
        assert out["file_type"] == "Text"

    @pytest.mark.parametrize("mal,sus,expected", [
        (0, 0, "clean"), (1, 0, "suspicious"), (0, 2, "suspicious"),
        (2, 5, "suspicious"), (3, 0, "malicious"),
    ])
    def test_verdict_thresholds(self, db_path, mal, sus, expected):
        payload = _vt_payload(malicious=mal, suspicious=sus)
        with patch("urllib.request.urlopen", return_value=_fake_response(payload)):
            out = self._run(db_path, "lookup_ip", {"ip": "8.8.8.8"})
        assert out["verdict"] == expected


class TestVirusTotalFailSafe:
    def _run(self, db_path, inputs=None, key="vt-key", action="lookup_ip"):
        return connectors.run_action(
            "virustotal", action, inputs or {"ip": "8.8.8.8"},
            {"api_key": key, "ttl_hours": 24, "db_path": db_path})

    def test_no_key_returns_none_without_network(self, db_path):
        with patch("urllib.request.urlopen") as mock_urlopen:
            assert self._run(db_path, key=None) is None
        mock_urlopen.assert_not_called()

    @pytest.mark.parametrize("err", [
        _http_error(401), _http_error(403), _http_error(429), _http_error(500),
        urllib.error.URLError("down"), TimeoutError("slow"),
    ])
    def test_failures_return_none_and_are_not_cached(self, db_path, err):
        with patch("urllib.request.urlopen", side_effect=err):
            assert self._run(db_path) is None
        assert base.read_cache(db_path, "8.8.8.8", "virustotal") is None

    def test_malformed_body_returns_none(self, db_path):
        with patch("urllib.request.urlopen",
                   return_value=_fake_response({"data": "nope"})):
            assert self._run(db_path) is None

    def test_404_is_cached_as_not_found(self, db_path):
        with patch("urllib.request.urlopen", side_effect=_http_error(404)):
            first = self._run(db_path)
        assert first["found"] is False
        assert first["verdict"] == "unknown"
        # A "never seen" answer cost a request, so it's cached too.
        with patch("urllib.request.urlopen") as mock_urlopen:
            second = self._run(db_path)
        mock_urlopen.assert_not_called()
        assert second["found"] is False and second["cached"] is True

    def test_failure_falls_back_to_stale_cache(self, db_path):
        with patch("urllib.request.urlopen",
                   return_value=_fake_response(_vt_payload(malicious=7))):
            self._run(db_path)
        # Age the row past the TTL, then fail the refresh.
        with base.database._connect(db_path) as conn:
            conn.execute("UPDATE intel_cache SET fetched_at = ? "
                         "WHERE source = 'virustotal'", ("2020-01-01T00:00:00",))
        with patch("urllib.request.urlopen", side_effect=_http_error(500)):
            out = self._run(db_path)
        assert out["malicious"] == 7
        assert out["cached"] is True

    @pytest.mark.parametrize("inputs,action", [
        ({"ip": "10.0.0.5"}, "lookup_ip"),
        ({"ip": "127.0.0.1"}, "lookup_ip"),
        ({"ip": "garbage"}, "lookup_ip"),
        ({"hash": "not-a-hash"}, "lookup_hash"),
        ({"hash": "abc123"}, "lookup_hash"),
        ({"domain": "dc01.corp"}, "lookup_domain"),
        ({"domain": "fileserver.local"}, "lookup_domain"),
        ({"domain": "8.8.8.8"}, "lookup_domain"),
        ({"domain": "localhost"}, "lookup_domain"),
        ({}, "lookup_domain"),
    ])
    def test_private_or_invalid_indicators_never_sent(self, db_path, inputs, action):
        with patch("urllib.request.urlopen") as mock_urlopen:
            assert self._run(db_path, inputs=inputs, action=action) is None
        mock_urlopen.assert_not_called()


class TestVirusTotalQuota:
    def test_fifth_request_in_a_minute_is_not_sent(self, db_path):
        ips = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"]
        with patch("urllib.request.urlopen",
                   return_value=_fake_response(_vt_payload())) as mock_urlopen:
            results = [connectors.run_action(
                "virustotal", "lookup_ip", {"ip": ip},
                {"api_key": "k", "ttl_hours": 24, "db_path": db_path})
                for ip in ips]
        assert mock_urlopen.call_count == 4
        assert all(r is not None for r in results[:4])
        # Over quota, nothing cached: "no intel", not a wait or a raise.
        assert results[4] is None

    def test_cache_hits_do_not_spend_quota(self, db_path):
        cfg = {"api_key": "k", "ttl_hours": 24, "db_path": db_path}
        with patch("urllib.request.urlopen",
                   return_value=_fake_response(_vt_payload())) as mock_urlopen:
            for _ in range(10):
                assert connectors.run_action("virustotal", "lookup_ip",
                                             {"ip": "8.8.8.8"}, cfg) is not None
        assert mock_urlopen.call_count == 1

    def test_guard_per_minute_window_slides(self):
        now = [1_000_000.0]
        q = base.QuotaGuard(per_minute=4, per_day=500, clock=lambda: now[0])
        assert all(q.try_acquire() for _ in range(4))
        assert q.try_acquire() is False
        now[0] += 60
        assert q.try_acquire() is True

    def test_guard_daily_cap_resets_next_utc_day(self):
        now = [86400.0 * 20000]  # midnight UTC
        q = base.QuotaGuard(per_minute=1000, per_day=3, clock=lambda: now[0])
        assert all(q.try_acquire() for _ in range(3))
        now[0] += 3600
        assert q.try_acquire() is False
        now[0] += 86400
        assert q.try_acquire() is True


# ---------------------------------------------------------------------------
# API — /api/intel/{ip}/verdicts, config, key test
# ---------------------------------------------------------------------------

class TestVerdictsApi:
    def test_both_providers_report(self, client):
        side = _route(abuse=ABUSE_PAYLOAD,
                      vt_resp=_vt_payload(malicious=9, as_owner="Bad AS"))
        with patch("urllib.request.urlopen", side_effect=side):
            resp = client.get("/api/intel/45.33.32.156/verdicts")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ip"] == "45.33.32.156"
        by_key = {v["connector"]: v for v in body["verdicts"]}
        assert by_key["abuseipdb"]["status"] == "ok"
        assert by_key["abuseipdb"]["name"] == "AbuseIPDB"
        assert by_key["abuseipdb"]["result"]["score"] == 87
        assert by_key["virustotal"]["status"] == "ok"
        assert by_key["virustotal"]["result"]["malicious"] == 9
        assert by_key["virustotal"]["result"]["verdict"] == "malicious"
        # Internal payloads and keys never reach the browser.
        assert "_raw" not in resp.text
        assert "vt-test-key" not in resp.text
        assert "abuse-test-key" not in resp.text

    def test_one_provider_failing_does_not_fail_the_other(self, client):
        side = _route(abuse=ABUSE_PAYLOAD, vt_resp=_http_error(401))
        with patch("urllib.request.urlopen", side_effect=side):
            resp = client.get("/api/intel/45.33.32.156/verdicts")
        assert resp.status_code == 200
        by_key = {v["connector"]: v for v in resp.json()["verdicts"]}
        assert by_key["abuseipdb"]["status"] == "ok"
        assert by_key["virustotal"]["status"] == "no_intel"
        assert "result" not in by_key["virustotal"]

    def test_missing_vt_key_reports_no_key(self, tmp_path):
        c = _make_client(tmp_path,
            "threat_intel:\n  enabled: true\n  abuseipdb_api_key: k\n")
        with patch("urllib.request.urlopen",
                   side_effect=_route(abuse=ABUSE_PAYLOAD)):
            resp = c.get("/api/intel/45.33.32.156/verdicts")
        by_key = {v["connector"]: v for v in resp.json()["verdicts"]}
        assert by_key["abuseipdb"]["status"] == "ok"
        assert by_key["virustotal"]["status"] == "no_key"

    def test_disabled_skips_every_lookup(self, tmp_path):
        c = _make_client(tmp_path,
            "threat_intel:\n  enabled: false\n"
            "  abuseipdb_api_key: k\n  virustotal_api_key: v\n")
        with patch("urllib.request.urlopen") as mock_urlopen:
            resp = c.get("/api/intel/45.33.32.156/verdicts")
        mock_urlopen.assert_not_called()
        assert {v["status"] for v in resp.json()["verdicts"]} == {"disabled"}

    def test_private_ip_404s(self, client):
        with patch("urllib.request.urlopen") as mock_urlopen:
            resp = client.get("/api/intel/192.168.1.10/verdicts")
        assert resp.status_code == 404
        mock_urlopen.assert_not_called()


class TestVirusTotalConfigApi:
    def test_config_exposes_flag_not_key(self, client):
        resp = client.get("/api/config")
        ti = resp.json()["threat_intel"]
        assert ti["virustotal_api_key_set"] is True
        assert ti["api_key_set"] is True
        assert "vt-test-key" not in resp.text

    def test_enabled_with_only_a_vt_key(self, tmp_path):
        c = _make_client(tmp_path,
            "threat_intel:\n  enabled: true\n  virustotal_api_key: v\n")
        ti = c.get("/api/config").json()["threat_intel"]
        assert ti["enabled"] is True
        assert ti["api_key_set"] is False
        assert ti["virustotal_api_key_set"] is True

    def test_put_saves_and_clears_vt_key(self, tmp_path):
        c = _make_client(tmp_path, "threat_intel:\n  enabled: true\n")
        resp = c.put("/api/config/threat_intel",
                     json={"virustotal_api_key": "  new-vt-key  "})
        assert resp.status_code == 200
        assert resp.json()["virustotal_api_key_set"] is True
        # Empty string leaves the saved key alone.
        c.put("/api/config/threat_intel", json={"virustotal_api_key": ""})
        assert c.get("/api/config").json()["threat_intel"]["virustotal_api_key_set"] is True
        # "null" clears it.
        c.put("/api/config/threat_intel", json={"virustotal_api_key": "null"})
        assert c.get("/api/config").json()["threat_intel"]["virustotal_api_key_set"] is False

    def test_key_test_endpoint_hits_virustotal(self, client):
        with patch("urllib.request.urlopen",
                   return_value=_fake_response(_vt_payload(malicious=0))):
            resp = client.post("/api/intel/test?connector=virustotal")
        assert resp.status_code == 200
        assert resp.json()["malicious"] == 0

    def test_key_test_bad_vt_key_502s(self, client):
        with patch("urllib.request.urlopen", side_effect=_http_error(401)):
            resp = client.post("/api/intel/test?connector=virustotal")
        assert resp.status_code == 502

    def test_key_test_respects_quota(self, client):
        for _ in range(4):
            assert vt.QUOTA.try_acquire()
        with patch("urllib.request.urlopen") as mock_urlopen:
            resp = client.post("/api/intel/test?connector=virustotal")
        assert resp.status_code == 429
        mock_urlopen.assert_not_called()

    def test_key_test_unknown_connector_400s(self, client):
        assert client.post("/api/intel/test?connector=nope").status_code == 400
