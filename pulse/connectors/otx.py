# pulse/connectors/otx.py
# -----------------------
# AlienVault OTX (LevelBlue Open Threat Exchange) enrichment connector.
# https://otx.alienvault.com/assets/static/external_api.html
#
# OTX is a free community threat feed: researchers publish "pulses"
# (threat reports) listing the IPs, domains and file hashes they saw in an
# attack. The number of pulses mentioning an indicator is the signal.
#
# Bring-your-own key (free OTX account): threat_intel.otx_api_key or
# OTX_API_KEY, sent as the X-OTX-API-KEY header. Nothing is called
# without it.
#
# OTX doesn't publish a rate limit, so live calls are held to a
# conservative QUOTA; every answer is cached (404 "unknown indicator"
# too) and a 429 or any failure is "no intel". Private / reserved IPs and
# internal domain names are never sent.

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request

from .base import (
    DEFAULT_CACHE_TTL_HOURS, HTTP_TIMEOUT_SECONDS, USER_AGENT, Connector,
    QuotaGuard, coerce_int, config_str, env_value, is_public_ip, is_stale,
    normalize_domain, normalize_hash, now_iso, read_cache, register,
    ttl_hours_from_config, write_cache,
)

SOURCE = "otx"
API_BASE = "https://otx.alienvault.com/api/v1/indicators/"
ENV_KEY = "OTX_API_KEY"
QUOTA = QuotaGuard(per_minute=20, per_day=1000)

# Pulses (independent threat reports) mentioning an indicator.
MALICIOUS_PULSES = 5

_ACTIONS = {"lookup_ip": "ip", "lookup_domain": "domain", "lookup_hash": "file"}


def verdict_for(entry):
    if not entry.get("found"):
        return "unknown"
    n = entry.get("pulse_count") or 0
    if n >= MALICIOUS_PULSES:
        return "malicious"
    return "suspicious" if n > 0 else "clean"


def _section(kind, indicator):
    """OTX path section for an indicator, e.g. ('IPv4', '8.8.8.8')."""
    if kind == "ip":
        return "IPv6" if ipaddress.ip_address(indicator).version == 6 else "IPv4"
    return "domain" if kind == "domain" else "file"


def _normalize(kind, value):
    if kind == "ip":
        return value.strip() if is_public_ip(value) else None
    if kind == "file":
        return normalize_hash(value)
    return normalize_domain(value)


def lookup(action, value, db_path, api_key=None, ttl_hours=DEFAULT_CACHE_TTL_HOURS):
    """Cached, quota-aware lookup. Returns a normalized dict or None.

        {
            "indicator", "type": "ip" | "domain" | "file", "source": "otx",
            "found":       bool,
            "pulse_count": int,          # threat reports naming it
            "pulses":      [str],        # up to 3 report titles
            "reputation":  int | None,   # OTX reputation (IPs)
            "country":     str | None,
            "verdict", "fetched_at", "cached",
        }
    """
    kind = _ACTIONS.get(action)
    indicator = _normalize(kind, value) if kind else None
    if not indicator:
        return None
    cached = _read(db_path, indicator)
    if cached and not is_stale(cached["fetched_at"], ttl_hours):
        return _finish(cached, True)
    fetched = None
    if api_key and QUOTA.try_acquire():
        fetched = fetch(kind, indicator, api_key)
    if fetched is None:
        return _finish(cached, True) if cached else None
    _write(db_path, indicator, fetched)
    return _finish(fetched, False)


def fetch(kind, indicator, api_key):
    url = (API_BASE + _section(kind, indicator) + "/"
           + urllib.parse.quote(indicator, safe="") + "/general")
    req = urllib.request.Request(url, method="GET", headers={
        "X-OTX-API-KEY": api_key, "Accept": "application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            if resp.status != 200:
                return None
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return _entry(indicator, kind, found=False)
        return None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    info = data.get("pulse_info") or {}
    pulses = [p.get("name") for p in (info.get("pulses") or [])
              if isinstance(p, dict) and p.get("name")][:3]
    return _entry(indicator, kind, found=True,
                  pulse_count=coerce_int(info.get("count")) or 0, pulses=pulses,
                  reputation=coerce_int(data.get("reputation")),
                  country=data.get("country_name") or None)


def _entry(indicator, kind, *, found, pulse_count=0, pulses=None, reputation=None, country=None):
    return {"indicator": indicator, "type": kind, "source": SOURCE, "found": found,
            "pulse_count": pulse_count, "pulses": pulses or [],
            "reputation": reputation, "country": country, "fetched_at": now_iso()}


def _finish(entry, cached):
    entry["cached"] = cached
    entry["verdict"] = verdict_for(entry)
    return entry


def _write(db_path, indicator, entry):
    write_cache(db_path, indicator, SOURCE, {
        "score": None, "country": entry.get("country"), "isp": None,
        "total_reports": entry.get("pulse_count"), "last_reported": None,
        "fetched_at": entry.get("fetched_at"),
        "_raw": {k: v for k, v in entry.items() if k != "cached"},
    })


def _read(db_path, indicator):
    row = read_cache(db_path, indicator, SOURCE)
    if not row or not isinstance(row.get("_raw"), dict):
        return None
    entry = dict(row["_raw"])
    entry["fetched_at"] = row["fetched_at"]
    return entry


@register
class OTXConnector(Connector):
    key = "otx"
    result_fields = {"pulse_count": "Threat reports naming it", "verdict": "Verdict"}
    name = "AlienVault OTX"
    kind = "enrichment"
    config_fields = ["api_key"]

    def actions(self):
        return list(_ACTIONS)

    def config_from_pulse(self, pulse_config):
        return {"api_key": config_str(pulse_config, "otx_api_key") or env_value(ENV_KEY),
                "ttl_hours": ttl_hours_from_config(pulse_config)}

    def summarize(self, action, result):
        if not result:
            return None
        if not result.get("found") or not result.get("pulse_count"):
            return "Not in any OTX threat report."
        n = result["pulse_count"]
        line = f"Named in {n} OTX threat report{'s' if n != 1 else ''}"
        if result.get("pulses"):
            line += ": " + "; ".join(result["pulses"][:2])
        return line

    def run(self, action, inputs, config):
        value = {"lookup_ip": inputs.get("ip"), "lookup_domain": inputs.get("domain"),
                 "lookup_hash": inputs.get("hash")}.get(action)
        return lookup(action, value, config.get("db_path"), api_key=config.get("api_key"),
                      ttl_hours=config.get("ttl_hours", DEFAULT_CACHE_TTL_HOURS))
