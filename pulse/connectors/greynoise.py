# pulse/connectors/greynoise.py
# -----------------------------
# GreyNoise Community enrichment connector
# (https://docs.greynoise.io/reference/getcommunityip).
#
# Answers "is this IP internet-wide background noise, or is it aimed at
# me?". An IP GreyNoise sees scanning the whole internet ("noise") is
# less alarming than one it has never seen; a RIOT hit means a known
# business service (Microsoft, Google, a CDN) rather than an attacker.
#
# Bring-your-own key: nothing is called until a free Community key is set
# under Settings (threat_intel.greynoise_api_key, or GREYNOISE_API_KEY),
# so an install never talks to GreyNoise unless its owner opted in.
#
# Quota: free Community use is capped (100 lookups a day, and GreyNoise
# has also published 50 a week for free accounts). Every answer is
# cached, including 404 "not observed", and live calls are held to
# QUOTA. A 429 or any other failure is "no intel", never an error.
# Private / reserved IPs are never sent.

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from .base import (
    DEFAULT_CACHE_TTL_HOURS, HTTP_TIMEOUT_SECONDS, USER_AGENT, Connector,
    QuotaGuard, config_str, env_value, is_public_ip, is_stale, now_iso,
    read_cache, register, ttl_hours_from_config, write_cache,
)

SOURCE = "greynoise"
API_URL = "https://api.greynoise.io/v3/community/"
ENV_KEY = "GREYNOISE_API_KEY"
QUOTA = QuotaGuard(per_minute=10, per_day=50)


def verdict_for(entry):
    if not entry.get("found"):
        return "unknown"
    cls = (entry.get("classification") or "").lower()
    if cls == "malicious":
        return "malicious"
    if entry.get("riot") or cls == "benign":
        return "clean"
    return "suspicious" if entry.get("noise") else "unknown"


def lookup_ip(ip, db_path, api_key=None, ttl_hours=DEFAULT_CACHE_TTL_HOURS):
    """Cached, quota-aware lookup. Returns a normalized dict or None.

        {
            "ip", "source": "greynoise",
            "found":          bool,   # False = not observed by GreyNoise
            "noise":          bool,   # seen mass-scanning the internet
            "riot":           bool,   # known business service
            "classification": str | None,  # benign / malicious / unknown
            "name":           str | None,  # e.g. "Google"
            "last_seen":      str | None,
            "verdict", "fetched_at", "cached",
        }
    """
    if not is_public_ip(ip):
        return None
    ip = ip.strip()
    cached = _read(db_path, ip)
    if cached and not is_stale(cached["fetched_at"], ttl_hours):
        return _finish(cached, True)
    fetched = None
    if api_key and QUOTA.try_acquire():
        fetched = fetch(ip, api_key)
    if fetched is None:
        return _finish(cached, True) if cached else None
    _write(db_path, ip, fetched)
    return _finish(fetched, False)


def fetch(ip, api_key):
    req = urllib.request.Request(
        API_URL + urllib.parse.quote(ip, safe=""),
        method="GET",
        headers={"key": api_key, "Accept": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            if resp.status != 200:
                return None
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # 404 = "IP not observed scanning the internet or contained in
        # RIOT". A real answer (and a meaningful one), so it's cached.
        if e.code == 404:
            return _entry(ip, found=False)
        return None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return _entry(ip, found=True, noise=bool(data.get("noise")), riot=bool(data.get("riot")),
                  classification=data.get("classification") or None,
                  name=data.get("name") or None, last_seen=data.get("last_seen") or None)


def _entry(ip, *, found, noise=False, riot=False, classification=None, name=None,
           last_seen=None):
    return {"ip": ip, "source": SOURCE, "found": found, "noise": noise, "riot": riot,
            "classification": classification, "name": name, "last_seen": last_seen,
            "fetched_at": now_iso()}


def _finish(entry, cached):
    entry["cached"] = cached
    entry["verdict"] = verdict_for(entry)
    return entry


def _write(db_path, ip, entry):
    write_cache(db_path, ip, SOURCE, {
        "score": None, "country": None, "isp": entry.get("name"),
        "total_reports": None, "last_reported": entry.get("last_seen"),
        "fetched_at": entry.get("fetched_at"),
        "_raw": {k: v for k, v in entry.items() if k != "cached"},
    })


def _read(db_path, ip):
    row = read_cache(db_path, ip, SOURCE)
    if not row or not isinstance(row.get("_raw"), dict):
        return None
    entry = dict(row["_raw"])
    entry["fetched_at"] = row["fetched_at"]
    return entry


@register
class GreyNoiseConnector(Connector):
    key = "greynoise"
    result_fields = {"classification": "Classification", "name": "Organization", "verdict": "Verdict"}
    name = "GreyNoise"
    kind = "enrichment"
    config_fields = ["api_key"]

    def actions(self):
        return ["lookup_ip"]

    def config_from_pulse(self, pulse_config):
        return {"api_key": config_str(pulse_config, "greynoise_api_key") or env_value(ENV_KEY),
                "ttl_hours": ttl_hours_from_config(pulse_config)}

    def summarize(self, action, result):
        if not result:
            return None
        if not result.get("found"):
            return "Not seen scanning the internet, so not background noise. Could be targeted."
        if result.get("riot"):
            return f"Known business service{': ' + result['name'] if result.get('name') else ''} (RIOT)."
        cls = result.get("classification") or "unknown"
        return (f"Seen scanning the internet · classified {cls}"
                + (f" · {result['name']}" if result.get("name") else "")
                + (f" · last seen {result['last_seen']}" if result.get("last_seen") else ""))

    def run(self, action, inputs, config):
        if action != "lookup_ip":
            return None
        return lookup_ip(inputs.get("ip"), config.get("db_path"), api_key=config.get("api_key"),
                         ttl_hours=config.get("ttl_hours", DEFAULT_CACHE_TTL_HOURS))
