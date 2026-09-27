# pulse/connectors/geoip.py
# -------------------------
# GeoIP enrichment connector: country / city / network for an IP, looked
# up in a local MaxMind-format (.mmdb) database file. No network call,
# ever, so it works offline and air-gapped.
#
# Works out of the box: Pulse bundles DB-IP "IP to Country Lite"
# (pulse/data/dbip-country-lite.mmdb, CC BY 4.0), so every install gets
# country-level lookups offline with no setup. DB-IP's license requires
# the attribution "IP Geolocation by DB-IP" (https://db-ip.com) wherever
# results are shown; results from any DB-IP database carry it in
# `attribution`, and the Investigate panel renders it.
#
# For city-level detail, bring your own .mmdb in the GeoIP2 layout and it
# takes priority over the bundled file:
#   * DB-IP "IP to City Lite" (127 MB, too big to bundle in the repo)
#   * MaxMind GeoLite2 City / Country (free account; its license forbids
#     redistribution, so Pulse can never ship it)
# Set threat_intel.geoip_db_path (Settings) or PULSE_GEOIP_DB, or drop the
# file in the top-level data/ folder under one of DEFAULT_NAMES.
#
# Needs the `maxminddb` reader (requirements.txt). Missing reader or file
# -> the connector reports "not set up"; a bad file -> "no intel".

from __future__ import annotations

import os
import threading
from pathlib import Path

from .base import Connector, config_str, env_value, is_public_ip, now_iso, register

ENV_PATH = "PULSE_GEOIP_DB"
DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
DEFAULT_NAMES = ("GeoLite2-City.mmdb", "GeoLite2-Country.mmdb",
                 "dbip-city-lite.mmdb", "dbip-country-lite.mmdb")
# Shipped with Pulse; used when nothing more specific is configured.
BUNDLED = Path(__file__).resolve().parent.parent / "data" / "dbip-country-lite.mmdb"
DBIP_ATTRIBUTION = {"text": "IP Geolocation by DB-IP", "url": "https://db-ip.com"}

_reader_lock = threading.Lock()
_reader = {"key": None, "reader": None, "dbip": False}


def resolve_path(pulse_config):
    """The database file to use, or None when none is configured/found."""
    explicit = config_str(pulse_config, "geoip_db_path") or env_value(ENV_PATH)
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for name in DEFAULT_NAMES:
        p = DATA_DIR / name
        if p.is_file():
            return str(p)
    return str(BUNDLED) if BUNDLED.is_file() else None


def is_bundled(path):
    try:
        return path is not None and Path(path).resolve() == BUNDLED.resolve()
    except OSError:
        return False


def reader_available():
    try:
        import maxminddb  # noqa: F401
        return True
    except ImportError:
        return False


def _open(path):
    """Cached reader, reopened when the file changes (monthly updates)."""
    import maxminddb
    key = (path, os.path.getmtime(path))
    with _reader_lock:
        if _reader["key"] != key:
            if _reader["reader"] is not None:
                try:
                    _reader["reader"].close()
                except Exception:
                    pass
            _reader["reader"] = maxminddb.open_database(path)
            _reader["key"] = key
            try:
                db_type = str(_reader["reader"].metadata().database_type or "")
            except Exception:
                db_type = ""
            _reader["dbip"] = db_type.upper().startswith("DBIP")
        return _reader["reader"]


def _name(obj):
    names = (obj or {}).get("names") or {}
    return names.get("en") or next(iter(names.values()), None)


def lookup_ip(ip, db_path_file):
    """{ip, found, country_code, country, city, region, continent,
    latitude, longitude, accuracy_km, asn, as_org} or None."""
    if not db_path_file or not is_public_ip(ip):
        return None
    try:
        rec = _open(db_path_file).get(ip.strip())
    except Exception:
        return None
    # DB-IP's CC BY 4.0 license: attribution travels with every result.
    attribution = dict(DBIP_ATTRIBUTION) if _reader["dbip"] else None
    if not rec:
        return {"ip": ip.strip(), "source": "geoip", "found": False,
                "fetched_at": now_iso(), "verdict": "unknown", "cached": False,
                "attribution": attribution}
    country = rec.get("country") or rec.get("registered_country") or {}
    subdivisions = rec.get("subdivisions") or [{}]
    location = rec.get("location") or {}
    return {
        "ip": ip.strip(), "source": "geoip", "found": True,
        "country_code": country.get("iso_code"),
        "country": _name(country),
        "region": _name(subdivisions[0]) if subdivisions else None,
        "city": _name(rec.get("city")),
        "continent": _name(rec.get("continent")),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
        "accuracy_km": location.get("accuracy_radius"),
        "asn": rec.get("autonomous_system_number"),
        "as_org": rec.get("autonomous_system_organization"),
        "fetched_at": now_iso(),
        # Location is context, not a judgement of the IP.
        "verdict": "info",
        "cached": False,
        "attribution": attribution,
    }


@register
class GeoIPConnector(Connector):
    key = "geoip"
    result_fields = {"country": "Country", "country_code": "Country code", "city": "City"}
    name = "GeoIP"
    kind = "enrichment"
    config_fields = ["db_file"]

    def actions(self):
        return ["lookup_ip"]

    def config_from_pulse(self, pulse_config):
        return {"db_file": resolve_path(pulse_config) if reader_available() else None}

    def summarize(self, action, result):
        if not result:
            return None
        if not result.get("found"):
            return "Not in the GeoIP database."
        place = ", ".join(p for p in (result.get("city"), result.get("region"),
                                      result.get("country")) if p)
        extra = result.get("as_org")
        return (place or "Unknown location") + (f" · {extra}" if extra else "")

    def run(self, action, inputs, config):
        if action != "lookup_ip":
            return None
        return lookup_ip(inputs.get("ip"), config.get("db_file"))
