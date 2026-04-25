# tests/test_intel.py
# -------------------
# Unit tests for pulse/intel.py + the threat-intel API endpoints.
#
# AbuseIPDB is mocked at the urllib layer — none of these tests touch
# the network. The real client gets a single integration test path that
# is only meaningful when an env var is set, and is otherwise skipped.

import io
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from pulse import intel
from pulse.api import create_app
from pulse.database import init_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    """Fresh app + isolated DB + minimal pulse.yaml."""
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text(
        "whitelist:\n  accounts: []\n"
        "threat_intel:\n"
        "  enabled: true\n"
        "  abuseipdb_api_key: test-key-for-tests\n"
        "  cache_ttl_hours: 24\n"
    )
    app = create_app(db_path=str(db_path), config_path=str(config_path),
                     disable_auth=True)
    return TestClient(app)


@pytest.fixture
def db_path(tmp_path):
    """Initialized DB for direct intel.py tests (no API client needed)."""
    p = tmp_path / "test.db"
    init_db(str(p))
    return str(p)


def _fake_response(payload):
    """Build a minimal urlopen-style context manager that yields JSON."""
    class _Resp:
        status = 200
        def read(self):
            return json.dumps(payload).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
    return _Resp()


# ---------------------------------------------------------------------------
# IP classification — public vs. private guard
# ---------------------------------------------------------------------------

class TestIsPublicIp:
    def test_rejects_private_v4(self):
        assert intel._is_public_ip("10.0.0.1") is False
        assert intel._is_public_ip("192.168.1.5") is False
        assert intel._is_public_ip("172.16.0.1") is False

    def test_rejects_loopback_link_local_multicast(self):
        assert intel._is_public_ip("127.0.0.1") is False
        assert intel._is_public_ip("169.254.10.1") is False
        assert intel._is_public_ip("224.0.0.1") is False

    def test_rejects_v6_loopback_link_local(self):
        assert intel._is_public_ip("::1") is False
        assert intel._is_public_ip("fe80::1") is False

    def test_accepts_routable_v4(self):
        assert intel._is_public_ip("8.8.8.8") is True
        assert intel._is_public_ip("1.1.1.1") is True

    def test_accepts_routable_v6(self):
        # Cloudflare public DNS
        assert intel._is_public_ip("2606:4700:4700::1111") is True

    def test_rejects_garbage(self):
        assert intel._is_public_ip("") is False
        assert intel._is_public_ip(None) is False
        assert intel._is_public_ip("not-an-ip") is False
        assert intel._is_public_ip("999.999.999.999") is False


# ---------------------------------------------------------------------------
# lookup_ip — full public flow with mocked HTTP
# ---------------------------------------------------------------------------

class TestLookupIp:
    def test_private_ip_returns_none_without_hitting_api(self, db_path):
        with patch("urllib.request.urlopen") as mock_urlopen:
            result = intel.lookup_ip("10.0.0.5", db_path, api_key="anything")
        assert result is None
        mock_urlopen.assert_not_called()

    def test_no_key_no_cache_returns_none(self, db_path):
        with patch.dict("os.environ", {}, clear=False):
            # Make sure ABUSEIPDB_API_KEY isn't leaking from the dev env.
            with patch.object(intel, "_env_api_key", return_value=None):
                with patch("urllib.request.urlopen") as mock_urlopen:
                    result = intel.lookup_ip("8.8.8.8", db_path, api_key=None)
        assert result is None
        mock_urlopen.assert_not_called()

    def test_cache_miss_fetches_and_stores(self, db_path):
        api_payload = {
            "data": {
                "ipAddress":            "8.8.8.8",
                "abuseConfidenceScore": 0,
                "countryCode":          "US",
                "isp":                  "Google LLC",
                "totalReports":         0,
                "lastReportedAt":       None,
            }
        }
        with patch("urllib.request.urlopen", return_value=_fake_response(api_payload)):
            first = intel.lookup_ip("8.8.8.8", db_path, api_key="k")
        assert first is not None
        assert first["score"] == 0
        assert first["country"] == "US"
        assert first["isp"] == "Google LLC"
        assert first["cached"] is False  # fresh fetch

        # Second call should hit the cache, not the API.
        with patch("urllib.request.urlopen") as mock_urlopen:
            second = intel.lookup_ip("8.8.8.8", db_path, api_key="k")
        assert second is not None
        assert second["cached"] is True
        mock_urlopen.assert_not_called()

    def test_high_score_ip_round_trip(self, db_path):
        api_payload = {
            "data": {
                "ipAddress":            "45.33.32.156",
                "abuseConfidenceScore": 87,
                "countryCode":          "RU",
                "isp":                  "Bad ISP Ltd",
                "totalReports":         412,
                "lastReportedAt":       "2026-04-25T10:00:00+00:00",
            }
        }
        with patch("urllib.request.urlopen", return_value=_fake_response(api_payload)):
            result = intel.lookup_ip("45.33.32.156", db_path, api_key="k")
        assert result["score"] == 87
        assert result["total_reports"] == 412
        assert result["country"] == "RU"

    def test_http_error_with_stale_cache_returns_stale(self, db_path):
        # Seed a cache entry directly so we can test the failover path.
        intel._write_cache(db_path, "8.8.8.8", "abuseipdb", {
            "score":         0,
            "country":       "US",
            "isp":           "Google LLC",
            "total_reports": 0,
            "last_reported": None,
            "fetched_at":    "2020-01-01T00:00:00",  # very stale
            "_raw":          {},
        })
        # Network failure on refresh — caller should get the stale row,
        # not None.
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("boom")):
            result = intel.lookup_ip("8.8.8.8", db_path, api_key="k")
        assert result is not None
        assert result["score"] == 0
        assert result["cached"] is True

    def test_http_error_without_cache_returns_none(self, db_path):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("boom")):
            result = intel.lookup_ip("8.8.8.8", db_path, api_key="k")
        assert result is None


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

class TestConfigHelpers:
    def test_get_api_key_from_config_extracts_value(self):
        cfg = {"threat_intel": {"abuseipdb_api_key": "  abc123  "}}
        assert intel.get_api_key_from_config(cfg) == "abc123"

    def test_get_api_key_returns_none_when_missing(self):
        assert intel.get_api_key_from_config({}) is None
        assert intel.get_api_key_from_config({"threat_intel": {}}) is None
        assert intel.get_api_key_from_config({"threat_intel": {"abuseipdb_api_key": ""}}) is None
        assert intel.get_api_key_from_config({"threat_intel": {"abuseipdb_api_key": "   "}}) is None

    def test_ttl_hours_clamps_invalid(self):
        assert intel.get_ttl_hours_from_config({"threat_intel": {"cache_ttl_hours": 6}}) == 6
        assert intel.get_ttl_hours_from_config({"threat_intel": {"cache_ttl_hours": "bad"}}) == 24
        assert intel.get_ttl_hours_from_config({"threat_intel": {"cache_ttl_hours": 0}}) == 1

    def test_is_enabled_requires_key(self):
        assert intel.is_enabled_in_config({"threat_intel": {"enabled": True}}) is False
        cfg = {"threat_intel": {"enabled": True, "abuseipdb_api_key": "k"}}
        assert intel.is_enabled_in_config(cfg) is True

    def test_is_enabled_respects_explicit_disable(self):
        cfg = {"threat_intel": {"enabled": False, "abuseipdb_api_key": "k"}}
        assert intel.is_enabled_in_config(cfg) is False


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

class TestThreatIntelApi:
    def test_get_config_exposes_api_key_set_flag(self, client):
        resp = client.get("/api/config")
        assert resp.status_code == 200
        body = resp.json()
        assert body["threat_intel"]["api_key_set"] is True
        assert body["threat_intel"]["enabled"] is True
        # Critical: the raw key must NEVER appear in the response.
        assert "test-key-for-tests" not in resp.text

    def test_put_config_threat_intel_saves_settings(self, client):
        resp = client.put("/api/config/threat_intel", json={
            "enabled": False,
            "cache_ttl_hours": 12,
        })
        assert resp.status_code == 200
        # Reading back should reflect the saved state.
        body = client.get("/api/config").json()
        assert body["threat_intel"]["enabled"] is False
        assert body["threat_intel"]["cache_ttl_hours"] == 12
        # Empty key field must not clear the existing key.
        assert body["threat_intel"]["api_key_set"] is True

    def test_put_config_explicit_null_clears_key(self, client):
        resp = client.put("/api/config/threat_intel", json={
            "abuseipdb_api_key": "null",
        })
        assert resp.status_code == 200
        body = client.get("/api/config").json()
        assert body["threat_intel"]["api_key_set"] is False

    def test_put_config_rejects_bad_ttl(self, client):
        resp = client.put("/api/config/threat_intel", json={"cache_ttl_hours": 0})
        assert resp.status_code == 400
        resp = client.put("/api/config/threat_intel", json={"cache_ttl_hours": "abc"})
        assert resp.status_code == 400

    def test_get_intel_for_private_ip_404s(self, client):
        resp = client.get("/api/intel/10.0.0.1")
        assert resp.status_code == 404

    def test_get_intel_returns_normalized_dict(self, client):
        api_payload = {
            "data": {
                "ipAddress":            "45.33.32.156",
                "abuseConfidenceScore": 75,
                "countryCode":          "RU",
                "isp":                  "Bad Co",
                "totalReports":         99,
                "lastReportedAt":       "2026-04-25T10:00:00+00:00",
            }
        }
        with patch("urllib.request.urlopen", return_value=_fake_response(api_payload)):
            resp = client.get("/api/intel/45.33.32.156")
        assert resp.status_code == 200
        body = resp.json()
        assert body["score"] == 75
        assert body["country"] == "RU"
        assert body["total_reports"] == 99
        # Internal _raw must not leak through.
        assert "_raw" not in body
