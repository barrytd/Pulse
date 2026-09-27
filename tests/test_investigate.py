# tests/test_investigate.py
# -------------------------
# Phase 3 part 1: the enrichment connectors (GreyNoise, AlienVault OTX,
# GeoIP, Whois/RDAP, DNS), indicator extraction, the Investigate runner
# (one provider failing never hides the others) and its endpoint.
#
# Nothing touches the network: urllib / sockets / the mmdb reader / the
# resolver are replaced at the boundary, like tests/test_connectors.py.

import io
import json
import socket
import time
import urllib.error
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from pulse import connectors, investigate
from pulse.api import create_app
from pulse.connectors import dns_lookup, geoip, greynoise, otx, whois_lookup
from pulse.connectors import virustotal as vt
from pulse.database import init_db, save_scan

PUBLIC_IP = "45.33.32.156"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for var in ("GREYNOISE_API_KEY", "OTX_API_KEY", "ABUSEIPDB_API_KEY",
                "VIRUSTOTAL_API_KEY", "PULSE_GEOIP_DB"):
        monkeypatch.delenv(var, raising=False)
    for q in (greynoise.QUOTA, otx.QUOTA, whois_lookup.QUOTA, vt.QUOTA):
        q.reset()
    yield


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Nothing in this file may reach the internet. Whois (RDAP + port
    43) and urllib fail by default; a test that needs an answer stubs it
    explicitly (a later monkeypatch / `with patch` wins)."""
    def offline(*a, **k):
        raise OSError("network disabled in tests")
    monkeypatch.setattr(whois_lookup, "_http_json", offline)
    monkeypatch.setattr(whois_lookup, "_query", offline)
    monkeypatch.setattr(whois_lookup, "_bootstrap", {"at": 0.0, "map": None})
    monkeypatch.setattr("urllib.request.urlopen", offline)
    yield


@pytest.fixture
def db(tmp_path):
    p = str(tmp_path / "t.db")
    init_db(p)
    return p


def _resp(payload):
    class _R:
        status = 200
        def read(self):
            return json.dumps(payload).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    return _R()


def _http_error(code):
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(b""))


def _capture(payload):
    seen = {}

    def fake(req, timeout=None):
        seen["url"] = req.full_url
        seen["headers"] = {k.lower(): v for k, v in req.header_items()}
        return _resp(payload)
    return seen, fake


def _run(key, action, inputs, db_path, pulse_config=None):
    c = connectors.get(key)
    return connectors.run_action(key, action, inputs,
                                 connectors.config_for(c, pulse_config or {}, db_path=db_path))


# ---------------------------------------------------------------------------
# Registry: every new connector drops in
# ---------------------------------------------------------------------------

def test_new_connectors_register_as_enrichment():
    keys = {c.key: c for c in connectors.all_connectors(kind="enrichment")}
    for k, actions in {"greynoise": ["lookup_ip"],
                       "otx": ["lookup_ip", "lookup_domain", "lookup_hash"],
                       "geoip": ["lookup_ip"], "whois": ["lookup_domain"],
                       "dns": ["lookup_domain"]}.items():
        assert keys[k].actions() == actions


# ---------------------------------------------------------------------------
# GreyNoise
# ---------------------------------------------------------------------------

GN_CFG = {"threat_intel": {"greynoise_api_key": "gn-key"}}


class TestGreyNoise:
    def test_request_shape_and_verdicts(self, db):
        seen, fake = _capture({"ip": PUBLIC_IP, "noise": True, "riot": False,
                               "classification": "malicious", "name": "unknown",
                               "last_seen": "2026-09-20"})
        with patch("urllib.request.urlopen", side_effect=fake):
            out = _run("greynoise", "lookup_ip", {"ip": PUBLIC_IP}, db, GN_CFG)
        assert seen["url"] == "https://api.greynoise.io/v3/community/" + PUBLIC_IP
        assert seen["headers"]["key"] == "gn-key"
        assert out["verdict"] == "malicious" and out["noise"] is True
        assert "classified malicious" in connectors.get("greynoise").summarize("lookup_ip", out)

    @pytest.mark.parametrize("body,verdict", [
        ({"noise": False, "riot": True, "classification": "benign", "name": "Google"}, "clean"),
        ({"noise": True, "riot": False, "classification": "benign"}, "clean"),
        ({"noise": True, "riot": False, "classification": "unknown"}, "suspicious"),
    ])
    def test_verdicts(self, db, body, verdict):
        with patch("urllib.request.urlopen", return_value=_resp(body)):
            assert _run("greynoise", "lookup_ip", {"ip": PUBLIC_IP}, db, GN_CFG)["verdict"] == verdict

    def test_not_observed_is_cached(self, db):
        with patch("urllib.request.urlopen", side_effect=_http_error(404)):
            first = _run("greynoise", "lookup_ip", {"ip": PUBLIC_IP}, db, GN_CFG)
        assert first["found"] is False and first["verdict"] == "unknown"
        assert "Could be targeted" in connectors.get("greynoise").summarize("lookup_ip", first)
        with patch("urllib.request.urlopen") as net:
            assert _run("greynoise", "lookup_ip", {"ip": PUBLIC_IP}, db, GN_CFG)["cached"] is True
        net.assert_not_called()

    @pytest.mark.parametrize("err", [_http_error(429), _http_error(401),
                                     urllib.error.URLError("down"), TimeoutError()])
    def test_failures_are_no_intel(self, db, err):
        with patch("urllib.request.urlopen", side_effect=err):
            assert _run("greynoise", "lookup_ip", {"ip": PUBLIC_IP}, db, GN_CFG) is None

    @pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "203.0.113.9", "not-an-ip"])
    def test_private_reserved_never_sent(self, db, ip):
        with patch("urllib.request.urlopen") as net:
            assert _run("greynoise", "lookup_ip", {"ip": ip}, db, GN_CFG) is None
        net.assert_not_called()

    def test_needs_a_key(self, db):
        with patch("urllib.request.urlopen") as net:
            assert _run("greynoise", "lookup_ip", {"ip": PUBLIC_IP}, db, {}) is None
        net.assert_not_called()
        assert connectors.get("greynoise").health_check({"api_key": None}) is False

    def test_quota(self, db):
        with patch("urllib.request.urlopen", return_value=_resp({"noise": False})) as net:
            for i in range(12):
                _run("greynoise", "lookup_ip", {"ip": f"8.8.{i}.8"}, db, GN_CFG)
        assert net.call_count == greynoise.QUOTA.per_minute


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------

OTX_CFG = {"threat_intel": {"otx_api_key": "otx-key"}}


class TestOTX:
    @pytest.mark.parametrize("action,inputs,path", [
        ("lookup_ip", {"ip": PUBLIC_IP}, "IPv4/" + PUBLIC_IP),
        ("lookup_ip", {"ip": "2606:4700:4700::1111"}, "IPv6/2606%3A4700%3A4700%3A%3A1111"),
        ("lookup_domain", {"domain": "Evil.Example.COM"}, "domain/evil.example.com"),
        ("lookup_hash", {"hash": SHA256.upper()}, "file/" + SHA256),
    ])
    def test_request_shape(self, db, action, inputs, path):
        seen, fake = _capture({"pulse_info": {"count": 0, "pulses": []}})
        with patch("urllib.request.urlopen", side_effect=fake):
            out = _run("otx", action, inputs, db, OTX_CFG)
        assert seen["url"] == f"https://otx.alienvault.com/api/v1/indicators/{path}/general"
        assert seen["headers"]["x-otx-api-key"] == "otx-key"
        assert out["verdict"] == "clean"

    @pytest.mark.parametrize("count,verdict", [(0, "clean"), (1, "suspicious"), (5, "malicious")])
    def test_pulse_thresholds(self, db, count, verdict):
        body = {"pulse_info": {"count": count, "pulses": [{"name": "Emotet C2"}] * min(count, 3)},
                "reputation": 0, "country_name": "Russia"}
        with patch("urllib.request.urlopen", return_value=_resp(body)):
            out = _run("otx", "lookup_ip", {"ip": PUBLIC_IP}, db, OTX_CFG)
        assert out["verdict"] == verdict and out["pulse_count"] == count
        if count:
            assert "Emotet C2" in connectors.get("otx").summarize("lookup_ip", out)

    def test_unknown_indicator_cached(self, db):
        with patch("urllib.request.urlopen", side_effect=_http_error(404)):
            assert _run("otx", "lookup_hash", {"hash": SHA256}, db, OTX_CFG)["found"] is False
        with patch("urllib.request.urlopen") as net:
            assert _run("otx", "lookup_hash", {"hash": SHA256}, db, OTX_CFG)["cached"] is True
        net.assert_not_called()

    @pytest.mark.parametrize("action,inputs", [
        ("lookup_ip", {"ip": "192.168.1.1"}), ("lookup_domain", {"domain": "dc01.corp"}),
        ("lookup_domain", {"domain": "files.local"}), ("lookup_hash", {"hash": "nope"}),
    ])
    def test_internal_indicators_never_sent(self, db, action, inputs):
        with patch("urllib.request.urlopen") as net:
            assert _run("otx", action, inputs, db, OTX_CFG) is None
        net.assert_not_called()

    def test_failure_is_no_intel(self, db):
        with patch("urllib.request.urlopen", side_effect=_http_error(429)):
            assert _run("otx", "lookup_ip", {"ip": PUBLIC_IP}, db, OTX_CFG) is None


# ---------------------------------------------------------------------------
# GeoIP (local .mmdb file)
# ---------------------------------------------------------------------------

class _FakeReader:
    def __init__(self, records):
        self.records = records
        self.closed = False

    def get(self, ip):
        return self.records.get(ip)

    def close(self):
        self.closed = True


CITY = {"country": {"iso_code": "GB", "names": {"en": "United Kingdom"}},
        "city": {"names": {"en": "London"}},
        "subdivisions": [{"names": {"en": "England"}}],
        "continent": {"names": {"en": "Europe"}},
        "location": {"latitude": 51.5, "longitude": -0.1, "accuracy_radius": 100}}


class TestGeoIP:
    @pytest.fixture
    def mmdb(self, tmp_path, monkeypatch):
        f = tmp_path / "GeoLite2-City.mmdb"
        f.write_bytes(b"fake")
        reader = _FakeReader({PUBLIC_IP: CITY})
        monkeypatch.setattr(geoip, "reader_available", lambda: True)
        import types
        monkeypatch.setitem(__import__("sys").modules, "maxminddb",
                            types.SimpleNamespace(open_database=lambda p: reader))
        geoip._reader.update(key=None, reader=None)
        return str(f), reader

    def test_lookup_is_local_and_mapped(self, db, mmdb):
        path, _ = mmdb
        cfg = {"threat_intel": {"geoip_db_path": path}}
        with patch("urllib.request.urlopen") as net, patch("socket.create_connection") as sock:
            out = _run("geoip", "lookup_ip", {"ip": PUBLIC_IP}, db, cfg)
        net.assert_not_called()
        sock.assert_not_called()
        assert (out["country_code"], out["city"], out["region"]) == ("GB", "London", "England")
        assert out["verdict"] == "info"
        assert connectors.get("geoip").summarize("lookup_ip", out) == "London, England, United Kingdom"

    def test_unknown_ip_and_private_ip(self, db, mmdb):
        cfg = {"threat_intel": {"geoip_db_path": mmdb[0]}}
        assert _run("geoip", "lookup_ip", {"ip": "8.8.8.8"}, db, cfg)["found"] is False
        assert _run("geoip", "lookup_ip", {"ip": "10.1.1.1"}, db, cfg) is None

    def test_not_set_up_without_file_or_reader(self, tmp_path, monkeypatch):
        c = connectors.get("geoip")
        monkeypatch.setattr(geoip, "DATA_DIR", tmp_path / "nothing-here")
        assert c.health_check(connectors.config_for(c, {})) is False
        monkeypatch.setattr(geoip, "reader_available", lambda: False)
        f = tmp_path / "x.mmdb"
        f.write_bytes(b"x")
        cfg = {"threat_intel": {"geoip_db_path": str(f)}}
        assert c.health_check(connectors.config_for(c, cfg)) is False

    def test_path_precedence(self, tmp_path, monkeypatch):
        data = tmp_path / "data"
        data.mkdir()
        (data / "dbip-city-lite.mmdb").write_bytes(b"x")
        monkeypatch.setattr(geoip, "DATA_DIR", data)
        assert geoip.resolve_path({}).endswith("dbip-city-lite.mmdb")
        env = tmp_path / "env.mmdb"
        env.write_bytes(b"x")
        monkeypatch.setenv("PULSE_GEOIP_DB", str(env))
        assert geoip.resolve_path({}) == str(env)
        cfgf = tmp_path / "cfg.mmdb"
        cfgf.write_bytes(b"x")
        assert geoip.resolve_path({"threat_intel": {"geoip_db_path": str(cfgf)}}) == str(cfgf)
        # An explicit path that doesn't exist is "not found", not a fallback.
        assert geoip.resolve_path({"threat_intel": {"geoip_db_path": str(tmp_path / "gone.mmdb")}}) is None

    def test_bad_database_is_no_intel(self, db, tmp_path, monkeypatch):
        f = tmp_path / "broken.mmdb"
        f.write_bytes(b"garbage")
        monkeypatch.setattr(geoip, "reader_available", lambda: True)
        monkeypatch.setattr(geoip, "_open", lambda p: (_ for _ in ()).throw(ValueError("bad")))
        cfg = {"threat_intel": {"geoip_db_path": str(f)}}
        assert _run("geoip", "lookup_ip", {"ip": PUBLIC_IP}, db, cfg) is None


# ---------------------------------------------------------------------------
# Whois / RDAP
# ---------------------------------------------------------------------------

COM_WHOIS = """Domain Name: EXAMPLE-BAD.COM
Registrar WHOIS Server: whois.registrar.test
Registrar: Shady Registrar LLC
Creation Date: {created}
Registry Expiry Date: 2027-01-01T00:00:00Z
Name Server: NS1.EXAMPLE-BAD.COM
"""


class TestWhois:
    @pytest.mark.parametrize("dom,expected", [
        ("a.b.example.com", "example.com"), ("news.bbc.co.uk", "bbc.co.uk"),
        ("example.org", "example.org"), ("x.example.com.au", "example.com.au"),
    ])
    def test_registrable(self, dom, expected):
        assert whois_lookup.registrable(dom) == expected

    def test_new_domain_is_suspicious(self):
        created = time.strftime("%Y-%m-%dT00:00:00Z", time.gmtime(time.time() - 3 * 86400))
        rec = whois_lookup.parse("example-bad.com", COM_WHOIS.format(created=created))
        assert rec["found"] and rec["registrar"] == "Shady Registrar LLC"
        assert rec["age_days"] in (2, 3)
        assert whois_lookup.verdict_for(rec) == "suspicious"
        assert "(new domain)" in connectors.get("whois").summarize("lookup_domain",
                                                                   whois_lookup._finish(rec, False))

    def test_old_domain_is_info(self):
        rec = whois_lookup.parse("example-bad.com", COM_WHOIS.format(created="1997-09-15T04:00:00Z"))
        assert whois_lookup.verdict_for(rec) == "info"

    @pytest.mark.parametrize("text", ["No match for \"NOPE.COM\".", "Domain not found.", ""])
    def test_not_found(self, text):
        assert whois_lookup.parse("nope.com", text)["found"] is False

    @pytest.mark.parametrize("value", ["2024-05-01T12:00:00Z", "2024-05-01", "01-May-2024",
                                       "2024.05.01", "2024-05-01T12:00:00.5Z"])
    def test_date_formats(self, value):
        assert whois_lookup.parse_date(value).date().isoformat() == "2024-05-01"

    def test_rdap_is_used_first(self, db, monkeypatch):
        monkeypatch.setattr(whois_lookup, "rdap_base", lambda tld: "https://rdap.test/")
        seen = []

        def fake_json(url):
            seen.append(url)
            return {"events": [{"eventAction": "registration", "eventDate": "1994-12-13T03:49:48Z"},
                               {"eventAction": "expiration", "eventDate": "2034-12-13T03:49:48Z"}],
                    "entities": [{"roles": ["registrar"],
                                  "vcardArray": ["vcard", [["fn", {}, "text", "Nominet UK"]]]}],
                    "nameservers": [{"ldhName": "ns1.bbc.co.uk."}]}
        monkeypatch.setattr(whois_lookup, "_http_json", fake_json)
        with patch("socket.create_connection") as sock:
            out = _run("whois", "lookup_domain", {"domain": "news.bbc.co.uk"}, db)
        sock.assert_not_called()
        assert seen == ["https://rdap.test/domain/bbc.co.uk"]
        assert out["protocol"] == "rdap" and out["registrar"] == "Nominet UK"
        assert out["created"] == "1994-12-13" and out["name_servers"] == ["ns1.bbc.co.uk"]

    def test_rdap_404_is_not_registered(self, db, monkeypatch):
        monkeypatch.setattr(whois_lookup, "rdap_base", lambda tld: "https://rdap.test/")
        monkeypatch.setattr(whois_lookup, "_http_json",
                            lambda url: (_ for _ in ()).throw(_http_error(404)))
        assert _run("whois", "lookup_domain", {"domain": "nope-pulse.com"}, db)["found"] is False

    def test_falls_back_to_port_43(self, db, monkeypatch):
        monkeypatch.setattr(whois_lookup, "rdap_base", lambda tld: None)
        created = "2001-01-01T00:00:00Z"
        answers = {("whois.iana.org", "com"): "refer: whois.verisign-grs.com\n",
                   ("whois.verisign-grs.com", "example-bad.com"): COM_WHOIS.format(created=created),
                   ("whois.registrar.test", "example-bad.com"): "Registrant Country: PA\n"}
        monkeypatch.setattr(whois_lookup, "_query", lambda server, q: answers[(server, q)])
        out = _run("whois", "lookup_domain", {"domain": "example-bad.com"}, db)
        assert out["registrar"] == "Shady Registrar LLC" and out["country"] == "PA"
        assert out["created"] == "2001-01-01"

    def test_offline_is_no_intel(self, db, monkeypatch):
        monkeypatch.setattr(whois_lookup, "rdap_base", lambda tld: None)
        monkeypatch.setattr(whois_lookup, "_query",
                            lambda s, q: (_ for _ in ()).throw(OSError("no network")))
        assert _run("whois", "lookup_domain", {"domain": "example.com"}, db) is None

    def test_cached(self, db, monkeypatch):
        monkeypatch.setattr(whois_lookup, "fetch", lambda d: whois_lookup._entry(d, found=False))
        _run("whois", "lookup_domain", {"domain": "example.com"}, db)
        monkeypatch.setattr(whois_lookup, "fetch", lambda d: 1 / 0)
        assert _run("whois", "lookup_domain", {"domain": "example.com"}, db)["cached"] is True

    @pytest.mark.parametrize("dom", ["dc01.corp", "printer.local", "intranet.home", "10.0.0.1"])
    def test_internal_names_never_queried(self, db, dom, monkeypatch):
        monkeypatch.setattr(whois_lookup, "fetch", lambda d: 1 / 0)
        assert _run("whois", "lookup_domain", {"domain": dom}, db) is None


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def _addrinfo(*addrs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in addrs]


class TestDNS:
    def test_resolves(self, db):
        with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34", "93.184.216.34")):
            out = _run("dns", "lookup_domain", {"domain": "example.com"}, db)
        assert out["addresses"] == ["93.184.216.34"] and out["verdict"] == "info"

    def test_public_name_pointing_inside_is_suspicious(self, db):
        with patch("socket.getaddrinfo", return_value=_addrinfo("10.0.0.7")):
            out = _run("dns", "lookup_domain", {"domain": "update-check.xyz"}, db)
        assert out["verdict"] == "suspicious" and out["internal"] == ["10.0.0.7"]
        assert "internal address" in connectors.get("dns").summarize("lookup_domain", out)

    def test_nxdomain(self, db):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("nx")):
            out = _run("dns", "lookup_domain", {"domain": "nope-pulse.com"}, db)
        assert out["found"] is False and out["verdict"] == "unknown"

    def test_slow_resolver_times_out(self, db, monkeypatch):
        monkeypatch.setattr(dns_lookup, "TIMEOUT", 0.05)
        with patch("socket.getaddrinfo", side_effect=lambda *a, **k: time.sleep(0.5) or []):
            assert _run("dns", "lookup_domain", {"domain": "slow.com"}, db) is None

    def test_internal_names_not_resolved(self, db):
        with patch("socket.getaddrinfo") as gai:
            assert _run("dns", "lookup_domain", {"domain": "fileserver.corp"}, db) is None
        gai.assert_not_called()


# ---------------------------------------------------------------------------
# Indicator extraction
# ---------------------------------------------------------------------------

class TestExtraction:
    def test_ips_domains_hashes(self):
        f = {"description": "DNS query",
             "details": (f"Source {PUBLIC_IP} and 10.0.0.5 queried evil-c2.xyz and "
                         "DESKTOP-1.corp.local; ran lsass.exe and payload.ps1; "
                         "package Microsoft.Windows.Client.OOBE_1000; System.IO"),
             "raw_xml": f"<Data>SHA1=da39a3ee5e6b4b0d3255bfef95601890afd80709,SHA256={SHA256.upper()}</Data>"}
        out = investigate.extract_indicators(f)
        assert out["ip"] == [PUBLIC_IP]
        assert out["domain"] == ["evil-c2.xyz"]
        assert out["hash"] == [SHA256]           # strongest hash kind only
        assert {"type": "ip", "value": "10.0.0.5"}.items() <= out["skipped"][0].items()

    def test_internal_domain_is_listed_as_skipped(self):
        out = investigate.extract_indicators({"details": "beacon to backup.corp.local"})
        assert out["domain"] == []
        assert out["skipped"][0]["value"] == "backup.corp.local"

    def test_caps(self):
        ips = " ".join(f"8.8.{i}.8" for i in range(10))
        assert len(investigate.extract_indicators({"details": ips})["ip"]) == investigate.MAX_PER_TYPE

    def test_nothing_to_look_up(self):
        out = investigate.extract_indicators({"details": "User bob logged on at 09:00"})
        assert out == {"ip": [], "domain": [], "hash": [], "skipped": []}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

FINDING = {"id": 1, "details": f"from {PUBLIC_IP} to evil-c2.xyz", "raw_xml": f"SHA256={SHA256}"}


def _by(result):
    return {(g["type"], v["connector"]): v for g in result["indicators"] for v in g["verdicts"]}


class TestRunner:
    def test_every_fitting_connector_runs(self, db, monkeypatch):
        called = []
        real = connectors.run_action

        def spy(key, action, inputs, cfg):
            called.append((key, action))
            return {"verdict": "clean", "found": True}
        monkeypatch.setattr(connectors, "run_action", spy)
        cfg = {"threat_intel": {"abuseipdb_api_key": "a", "virustotal_api_key": "v",
                                "greynoise_api_key": "g", "otx_api_key": "o"}}
        monkeypatch.setattr(geoip, "resolve_path", lambda c: "x.mmdb")
        monkeypatch.setattr(geoip, "reader_available", lambda: True)
        res = investigate.investigate(FINDING, pulse_config=cfg, db_path=db)
        assert sorted(k for k, a in called if a == "lookup_ip") == \
            ["abuseipdb", "geoip", "greynoise", "otx", "virustotal"]
        assert sorted(k for k, a in called if a == "lookup_domain") == \
            ["dns", "otx", "virustotal", "whois"]
        assert sorted(k for k, a in called if a == "lookup_hash") == ["otx", "virustotal"]
        order = [v["connector"] for v in res["indicators"][0]["verdicts"]]
        assert order[:2] == ["abuseipdb", "virustotal"]
        monkeypatch.setattr(connectors, "run_action", real)

    def test_one_provider_failing_never_hides_the_others(self, db, monkeypatch):
        cfg = {"threat_intel": {"greynoise_api_key": "g", "otx_api_key": "o"}}
        monkeypatch.setattr(greynoise, "fetch", lambda ip, key: 1 / 0)       # blows up
        monkeypatch.setattr(otx, "fetch", lambda kind, ind, key: otx._entry(ind, kind, found=True,
                                                                            pulse_count=7))
        with patch("socket.getaddrinfo", return_value=_addrinfo("1.2.3.4")):
            res = investigate.investigate(FINDING, pulse_config=cfg, db_path=db)
        by = _by(res)
        assert by[("ip", "greynoise")]["status"] == "no_intel"
        assert by[("ip", "otx")]["status"] == "ok" and by[("ip", "otx")]["verdict"] == "malicious"
        assert by[("ip", "abuseipdb")]["status"] == "not_set_up"
        assert by[("domain", "dns")]["status"] == "ok"
        assert "Named in 7 OTX threat reports" in by[("ip", "otx")]["summary"]

    def test_slow_provider_times_out_alone(self, db, monkeypatch):
        monkeypatch.setattr(investigate, "DEADLINE_SECONDS", 0.3)
        cfg = {"threat_intel": {"greynoise_api_key": "g", "otx_api_key": "o"}}
        monkeypatch.setattr(greynoise, "fetch", lambda ip, key: time.sleep(2) or None)
        monkeypatch.setattr(otx, "fetch", lambda kind, ind, key: otx._entry(ind, kind, found=False))
        with patch("socket.getaddrinfo", return_value=_addrinfo("1.2.3.4")):
            started = time.time()
            res = investigate.investigate({"details": f"from {PUBLIC_IP}"},
                                          pulse_config=cfg, db_path=db)
        assert time.time() - started < 1.5
        by = _by(res)
        assert by[("ip", "greynoise")] == {"connector": "greynoise", "name": "GreyNoise",
                                           "status": "no_intel", "message": "Timed out."}
        assert by[("ip", "otx")]["status"] == "ok"

    def test_org_switch_and_global_off(self, db):
        cfg = {"threat_intel": {"otx_api_key": "o"}}
        res = investigate.investigate({"details": f"from {PUBLIC_IP}"}, pulse_config=cfg,
                                      db_path=db, disabled_keys={"otx"})
        assert _by(res)[("ip", "otx")]["status"] == "disabled"
        res = investigate.investigate({"details": f"from {PUBLIC_IP}"}, pulse_config=cfg,
                                      db_path=db, lookups_off=True)
        assert {v["status"] for g in res["indicators"] for v in g["verdicts"]} == {"disabled"}


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    db_path = str(tmp_path / "api.db")
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=db_path, config_path=str(cfg))
    c = TestClient(app)
    assert c.post("/api/auth/signup", json={"email": "a@x.com",
                                            "password": "correct-horse-battery"}).status_code == 200
    me = c.get("/api/me").json()
    sid = save_scan(db_path, [{"rule": "Suspicious DNS", "severity": "HIGH",
                               "description": "DNS query", "details": f"from {PUBLIC_IP} to evil-c2.xyz and 10.9.9.9",
                               "timestamp": "2026-09-26T10:00:00Z", "event_id": "22",
                               "hostname": "WS-1"}],
                    scan_stats={"total_events": 1, "files_scanned": 1}, user_id=me["id"])
    from pulse.database import get_scan_findings
    fid = get_scan_findings(db_path, sid)[0]["id"]
    return c, db_path, fid


class TestInvestigateApi:
    def test_investigate_endpoint(self, client, monkeypatch):
        c, db_path, fid = client
        with patch("socket.getaddrinfo", return_value=_addrinfo("5.6.7.8")), \
             patch.object(whois_lookup, "fetch", lambda d: whois_lookup._entry(d, found=False)):
            r = c.post(f"/api/findings/{fid}/investigate")
        assert r.status_code == 200
        body = r.json()
        types = [(g["type"], g["value"]) for g in body["indicators"]]
        assert types == [("ip", PUBLIC_IP), ("domain", "evil-c2.xyz")]
        assert body["skipped"][0]["value"] == "10.9.9.9"
        by = _by(body)
        assert by[("domain", "dns")]["status"] == "ok"
        assert by[("ip", "greynoise")]["status"] == "not_set_up"
        from pulse.firewall.blocker import get_audit_log
        entry = next(e for e in get_audit_log(db_path) if e["action"] == "investigate")
        assert PUBLIC_IP in entry["detail"] and "10.9.9.9" not in entry["detail"]

    def test_get_not_allowed_and_unknown_finding(self, client):
        c, _, fid = client
        assert c.get(f"/api/findings/{fid}/investigate").status_code == 405
        assert c.post("/api/findings/999999/investigate").status_code == 404

    def test_needs_login(self, client):
        c, _, fid = client
        c.post("/api/auth/logout")
        assert c.post(f"/api/findings/{fid}/investigate").status_code == 401

    def test_rate_limited(self, client, monkeypatch):
        c, _, fid = client
        monkeypatch.setattr(investigate, "investigate",
                            lambda *a, **k: {"indicators": [], "skipped": []})
        codes = [c.post(f"/api/findings/{fid}/investigate").status_code for _ in range(21)]
        assert codes[:20] == [200] * 20 and codes[20] == 429

    def test_org_connector_switch_is_honored(self, client):
        c, _, fid = client
        c.put("/api/connectors/dns", json={"enabled": False})
        with patch.object(dns_lookup, "_resolve") as resolve:
            r = c.post(f"/api/findings/{fid}/investigate")
        resolve.assert_not_called()
        assert _by(r.json())[("domain", "dns")]["status"] == "disabled"

    def test_settings_for_new_keys_and_geoip(self, client, tmp_path):
        c, *_ = client
        r = c.put("/api/config/threat_intel", json={"greynoise_api_key": "g-secret",
                                                     "otx_api_key": "o-secret"})
        assert r.json()["greynoise_api_key_set"] and r.json()["otx_api_key_set"]
        cfg = c.get("/api/config")
        assert "g-secret" not in cfg.text and "o-secret" not in cfg.text
        assert c.put("/api/config/threat_intel",
                     json={"geoip_db_path": "C:/etc/passwd"}).status_code == 400
        mm = tmp_path / "GeoLite2-City.mmdb"
        mm.write_bytes(b"x")
        r = c.put("/api/config/threat_intel", json={"geoip_db_path": str(mm)})
        assert r.status_code == 200 and r.json()["geoip"]["found"] == str(mm)
        assert c.put("/api/config/threat_intel", json={"otx_api_key": "null"}).json()["otx_api_key_set"] is False

    def test_key_test_endpoint(self, client, monkeypatch):
        c, *_ = client
        assert c.post("/api/intel/test?connector=greynoise").status_code == 400
        c.put("/api/config/threat_intel", json={"greynoise_api_key": "g"})
        monkeypatch.setattr(greynoise, "fetch", lambda ip, key: greynoise._entry(ip, found=True))
        assert c.post("/api/intel/test?connector=greynoise").json()["found"] is True
