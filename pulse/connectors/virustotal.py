# pulse/connectors/virustotal.py
# ------------------------------
# VirusTotal enrichment connector (API v3, https://docs.virustotal.com).
#
# Bring-your-own-key only. Pulse never ships a key: the public API's
# terms say it "must not be used in commercial products or services",
# so the key is always the user's, pasted under Settings (or supplied as
# the VIRUSTOTAL_API_KEY env var on their own deploy).
#
# Actions: lookup_ip, lookup_hash, lookup_domain. Each returns the
# engine counts from `last_analysis_stats` plus a few context fields.
#
# Quota: the free tier allows 4 requests/min and 500/day. Every lookup
# is cached in `intel_cache` under source "virustotal" (a 404 "never
# seen" answer too, since that's a real answer and costs a request), and
# live requests go through a QuotaGuard so a burst of findings can't
# burn the daily budget. Over quota means "no intel" (or stale cache),
# never a wait.
#
# Fail-safe: bad key, timeout, 429, malformed response -> stale cache if
# we have it, else None. Nothing here raises.

from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .base import (
    DEFAULT_CACHE_TTL_HOURS, HTTP_TIMEOUT_SECONDS, USER_AGENT, Connector,
    QuotaGuard, coerce_int, config_str, env_value, is_public_ip, is_stale,
    normalize_domain, normalize_hash, now_iso, read_cache, register,
    ttl_hours_from_config, write_cache,
)

SOURCE = "virustotal"
VT_API_BASE = "https://www.virustotal.com/api/v3"
ENV_KEY = "VIRUSTOTAL_API_KEY"

# Free public API budget.
QUOTA = QuotaGuard(per_minute=4, per_day=500)

# Engines flagging an indicator as malicious before we call it malicious.
# One or two hits is common noise from a single aggressive engine.
MALICIOUS_THRESHOLD = 3

_KINDS = {
    # action:        (type,     URL path segment)
    "lookup_ip":     ("ip",     "ip_addresses"),
    "lookup_hash":   ("file",   "files"),
    "lookup_domain": ("domain", "domains"),
}


# ---------------------------------------------------------------------------
# Input normalization
# ---------------------------------------------------------------------------

def _normalize(kind, value):
    if kind == "ip":
        return value.strip() if is_public_ip(value) else None
    if kind == "file":
        return normalize_hash(value)
    return normalize_domain(value)


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------

def verdict_for(entry):
    if not entry.get("found"):
        return "unknown"
    if (entry.get("malicious") or 0) >= MALICIOUS_THRESHOLD:
        return "malicious"
    if (entry.get("malicious") or 0) > 0 or (entry.get("suspicious") or 0) > 0:
        return "suspicious"
    return "clean"


def lookup(action, value, db_path, api_key=None,
           ttl_hours=DEFAULT_CACHE_TTL_HOURS):
    """Cached, quota-aware lookup. Returns a normalized dict or None.

    Returned dict shape:
        {
            "indicator":     str,
            "type":          "ip" | "file" | "domain",
            "source":        "virustotal",
            "found":         bool,       # False when VT has never seen it
            "malicious":     int,        # engines flagging malicious
            "suspicious":    int,
            "harmless":      int,
            "undetected":    int,
            "engines":       int,        # total engines that answered
            "score":         int | None, # malicious / engines, 0-100
            "verdict":       str,        # malicious/suspicious/clean/unknown
            "reputation":    int | None, # VT community score
            "last_analysis": str | None, # ISO timestamp
            "fetched_at":    str,
            "cached":        bool,
            # plus per-type context: country + as_owner (ip),
            # name + file_type (file), registrar (domain)
        }
    """
    if action not in _KINDS:
        return None
    kind, _ = _KINDS[action]
    indicator = _normalize(kind, value)
    if not indicator:
        return None

    cached = _read(db_path, indicator)
    if cached and not is_stale(cached["fetched_at"], ttl_hours):
        return _finish(cached, True)

    fetched = None
    if api_key and QUOTA.try_acquire():
        fetched = fetch(action, indicator, api_key)
    if fetched is None:
        return _finish(cached, True) if cached else None

    _write(db_path, indicator, fetched)
    return _finish(fetched, False)


def fetch(action, indicator, api_key):
    """One live request to VirusTotal, bypassing cache and quota.
    Returns a normalized dict (found=False on 404) or None on failure."""
    kind, segment = _KINDS[action]
    url = f"{VT_API_BASE}/{segment}/{urllib.parse.quote(indicator, safe='')}"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "x-apikey":   api_key,
            "Accept":     "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            if resp.status != 200:
                return None
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # 404 = VirusTotal has never seen this indicator. That's a real
        # answer, so it gets cached like any other. 401/403 (bad key),
        # 429 (quota) and 5xx are failures.
        if e.code == 404:
            return _empty(indicator, kind)
        return None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None

    attrs = ((payload or {}).get("data") or {}).get("attributes")
    if not isinstance(attrs, dict):
        return None
    return _parse(indicator, kind, attrs)


def _parse(indicator, kind, attrs):
    stats = attrs.get("last_analysis_stats") or {}
    entry = _empty(indicator, kind)
    entry["found"] = True
    for k in ("malicious", "suspicious", "harmless", "undetected"):
        entry[k] = coerce_int(stats.get(k)) or 0
    # Only engines that returned a verdict; timeouts / failures /
    # type-unsupported don't count toward the denominator.
    engines = (entry["malicious"] + entry["suspicious"]
               + entry["harmless"] + entry["undetected"])
    entry["engines"] = engines
    entry["score"] = round(100 * entry["malicious"] / engines) if engines else None
    entry["reputation"] = coerce_int(attrs.get("reputation"))
    entry["last_analysis"] = _epoch_to_iso(attrs.get("last_analysis_date"))
    if kind == "ip":
        entry["country"] = attrs.get("country") or None
        entry["as_owner"] = attrs.get("as_owner") or None
    elif kind == "file":
        entry["name"] = attrs.get("meaningful_name") or None
        entry["file_type"] = attrs.get("type_description") or None
    else:
        entry["registrar"] = attrs.get("registrar") or None
    return entry


def _empty(indicator, kind):
    entry = {
        "indicator":     indicator,
        "type":          kind,
        "source":        SOURCE,
        "found":         False,
        "malicious":     0,
        "suspicious":    0,
        "harmless":      0,
        "undetected":    0,
        "engines":       0,
        "score":         None,
        "reputation":    None,
        "last_analysis": None,
        "fetched_at":    now_iso(),
    }
    if kind == "ip":
        entry["ip"] = indicator
    return entry


def _epoch_to_iso(v):
    ts = coerce_int(v)
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc) \
            .replace(tzinfo=None).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _finish(entry, cached):
    entry["cached"] = cached
    entry["verdict"] = verdict_for(entry)
    return entry


# The normalized dict is stored whole in `payload`; the fixed columns
# get the closest match so shared views (recent lookups) stay readable.

def _write(db_path, indicator, entry):
    write_cache(db_path, indicator, SOURCE, {
        "score":         entry.get("score"),
        "country":       entry.get("country"),
        "isp":           entry.get("as_owner"),
        "total_reports": entry.get("malicious"),
        "last_reported": entry.get("last_analysis"),
        "fetched_at":    entry.get("fetched_at"),
        "_raw":          {k: v for k, v in entry.items() if k != "cached"},
    })


def _read(db_path, indicator):
    row = read_cache(db_path, indicator, SOURCE)
    if not row or not isinstance(row.get("_raw"), dict):
        return None
    entry = dict(row["_raw"])
    entry["fetched_at"] = row["fetched_at"]
    return entry


@register
class VirusTotalConnector(Connector):
    key = "virustotal"
    result_fields = {"malicious": "Engines flagging it", "engines": "Engines that answered", "verdict": "Verdict"}
    name = "VirusTotal"
    kind = "enrichment"
    config_fields = ["api_key"]

    def actions(self):
        return list(_KINDS)

    def config_from_pulse(self, pulse_config):
        return {
            "api_key":   config_str(pulse_config, "virustotal_api_key")
                         or env_value(ENV_KEY),
            "ttl_hours": ttl_hours_from_config(pulse_config),
        }

    def summarize(self, action, result):
        if not result:
            return None
        if not result.get("found"):
            return "VirusTotal has never seen it."
        line = f"{result.get('malicious', 0)} of {result.get('engines', 0)} engines flag it"
        if result.get("suspicious"):
            line += f" (+{result['suspicious']} suspicious)"
        extra = result.get("name") or result.get("as_owner") or result.get("registrar")
        return line + (f" · {extra}" if extra else "")

    def run(self, action, inputs, config):
        value = {
            "lookup_ip":     inputs.get("ip"),
            "lookup_hash":   inputs.get("hash"),
            "lookup_domain": inputs.get("domain"),
        }.get(action)
        return lookup(
            action, value, config.get("db_path"),
            api_key=config.get("api_key"),
            ttl_hours=config.get("ttl_hours", DEFAULT_CACHE_TTL_HOURS),
        )
