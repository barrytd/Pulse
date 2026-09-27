# pulse/connectors/abuseipdb.py
# -----------------------------
# AbuseIPDB enrichment connector (https://www.abuseipdb.com/api).
#
# Looks up the abuse-confidence score for a public IP, normalizes the
# response into a small dict the dashboard + reports render uniformly,
# and caches it in `intel_cache` under source "abuseipdb" so repeated
# queries (one IP firing N detections, the Firewall page reloading)
# don't burn the free tier's 1,000 checks/day.
#
# Defensive by design:
#   * Missing API key        -> None (caller renders "no intel")
#   * Private/loopback IPs   -> never sent to the external service
#   * Malformed IP           -> None
#   * HTTP failure / timeout -> stale cache if we have it, else None

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from .base import (
    DEFAULT_CACHE_TTL_HOURS, HTTP_TIMEOUT_SECONDS, USER_AGENT, Connector,
    coerce_int, config_str, env_value, is_public_ip, is_stale, now_iso,
    read_cache, register, ttl_hours_from_config, write_cache,
)

SOURCE = "abuseipdb"

# Versioned in the URL so a future v3 doesn't break us silently.
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

ENV_KEY = "ABUSEIPDB_API_KEY"


def verdict_for(score):
    """AbuseIPDB convention: 75+ is high-confidence abuse, 25-74 has
    some reports, below that is clean."""
    if score is None:
        return "unknown"
    if score >= 75:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "clean"


def lookup_ip(ip, db_path, api_key=None, ttl_hours=DEFAULT_CACHE_TTL_HOURS):
    """Return a normalized intel dict for `ip`, or None. Never raises.

    Lookup order:
      1. Reject anything that's not a public, routable IP.
      2. Check the DB cache; return if fresh.
      3. Hit AbuseIPDB with `api_key`.
      4. Persist the result to cache.

    Returned dict shape:
        {
            "ip":            str,
            "source":        "abuseipdb",
            "score":         int | None, # 0-100 confidence of abuse
            "verdict":       str,        # malicious/suspicious/clean/unknown
            "country":       str | None, # ISO 2-letter code
            "isp":           str | None,
            "total_reports": int | None,
            "last_reported": str | None, # ISO timestamp
            "fetched_at":    str,        # ISO timestamp of cache write
            "cached":        bool,       # True when served from cache
        }

    With no key and no cache entry, returns None. With no key (or a
    failed fetch) and a stale cache entry, returns the stale entry:
    day-old data beats nothing when the admin removed the key by mistake.
    """
    if not is_public_ip(ip):
        return None

    cached = read_cache(db_path, ip, SOURCE)
    if cached and not is_stale(cached["fetched_at"], ttl_hours):
        return _finish(cached, True)

    fetched = fetch(ip, api_key) if api_key else None
    if fetched is None:
        return _finish(cached, True) if cached else None

    write_cache(db_path, ip, SOURCE, fetched)
    return _finish(fetched, False)


def fetch(ip, api_key):
    """Hit AbuseIPDB /check, bypassing the cache. Return a normalized
    dict or None on any error."""
    qs = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": "90",  # AbuseIPDB's default reporting window
    })
    req = urllib.request.Request(
        f"{ABUSEIPDB_URL}?{qs}",
        method="GET",
        headers={
            "Key":        api_key,
            "Accept":     "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            if resp.status != 200:
                return None
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError,
            TimeoutError, OSError, ValueError):
        return None

    data = payload.get("data") or {}
    if not data:
        return None

    return {
        "ip":            ip,
        "source":        SOURCE,
        "score":         coerce_int(data.get("abuseConfidenceScore")),
        "country":       data.get("countryCode") or None,
        "isp":           data.get("isp") or None,
        "total_reports": coerce_int(data.get("totalReports")),
        "last_reported": data.get("lastReportedAt") or None,
        "fetched_at":    now_iso(),
        # Raw payload for callers that want fields we haven't normalized
        # (usage type, domain, hostnames, etc.).
        "_raw":          data,
    }


def _finish(entry, cached):
    entry["cached"] = cached
    entry["verdict"] = verdict_for(entry.get("score"))
    return entry


@register
class AbuseIPDBConnector(Connector):
    key = "abuseipdb"
    result_fields = {"score": "Abuse score (0-100)", "country": "Country code", "total_reports": "Reports in 90 days", "verdict": "Verdict"}
    name = "AbuseIPDB"
    kind = "enrichment"
    config_fields = ["api_key"]

    def actions(self):
        return ["lookup_ip"]

    def config_from_pulse(self, pulse_config):
        return {
            "api_key":   config_str(pulse_config, "abuseipdb_api_key")
                         or env_value(ENV_KEY),
            "ttl_hours": ttl_hours_from_config(pulse_config),
        }

    def summarize(self, action, result):
        if not result:
            return None
        score = result.get("score")
        if score is None:
            return "No abuse data."
        reports = result.get("total_reports")
        return (f"Abuse confidence {score}/100"
                + (f", {reports} report{'s' if reports != 1 else ''} in 90 days" if reports is not None else "")
                + (f" · {result['country']}" if result.get("country") else "")
                + (f" · {result['isp']}" if result.get("isp") else ""))

    def run(self, action, inputs, config):
        if action != "lookup_ip":
            return None
        return lookup_ip(
            inputs.get("ip"), config.get("db_path"),
            api_key=config.get("api_key"),
            ttl_hours=config.get("ttl_hours", DEFAULT_CACHE_TTL_HOURS),
        )
