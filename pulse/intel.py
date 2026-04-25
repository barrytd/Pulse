# pulse/intel.py
# ----------------
# Threat-intelligence lookup for source IPs surfaced by Pulse.
#
# Wraps the AbuseIPDB free-tier API (https://www.abuseipdb.com/api),
# normalizing the response into a small dict the dashboard + reports
# can render uniformly. Lookups are cached in the `intel_cache` DB
# table so repeated queries (a single IP that fires N detections, the
# Firewall page reloading) don't burn quota or block the request loop.
#
# The module is deliberately defensive:
#   * Missing API key       -> returns None (caller renders "no intel")
#   * Private/loopback IPs  -> never sent to the external service
#   * Malformed IP          -> returns None
#   * HTTP failure / timeout-> returns None, no exception bubbles up
#
# Adding a second provider (OTX, VirusTotal, GreyNoise) means writing a
# new `_lookup_via_<provider>` function and routing it from `lookup_ip`
# based on a config switch. The cache table already keys on (ip, source)
# so providers don't collide.

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from . import database

# How long a cached entry is considered fresh. Mirrors the AbuseIPDB
# free-tier 24h refresh recommendation; long enough to keep quota use
# reasonable, short enough that a freshly-listed IP shows up in the UI
# the same day. Configurable via the `threat_intel.cache_ttl_hours` key
# in pulse.yaml; this is just the default.
DEFAULT_CACHE_TTL_HOURS = 24

# Outbound timeout. AbuseIPDB usually responds in <500ms, but lookups
# happen synchronously in the request loop so a hung connection would
# stall the dashboard. 5s is a reasonable upper bound.
HTTP_TIMEOUT_SECONDS = 5

# AbuseIPDB endpoint. Versioned in the URL so a future v3 doesn't break
# us silently — pin to v2 explicitly.
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_ip(ip, db_path, api_key=None, ttl_hours=DEFAULT_CACHE_TTL_HOURS,
              source="abuseipdb"):
    """Return a normalized intel dict for `ip`, or None.

    Lookup order:
      1. Reject anything that's not a public, routable IP (private,
         loopback, link-local, multicast, reserved).
      2. Check the DB cache; return if fresh.
      3. Hit AbuseIPDB with `api_key` (or fall back to env var
         `ABUSEIPDB_API_KEY`); never raise on failure.
      4. Persist the result to cache (even an empty result, so we don't
         hammer the API on a stream of unknown IPs).

    Returned dict shape:
        {
            "ip":            str,
            "source":        str,        # 'abuseipdb' for now
            "score":         int | None, # 0-100 confidence of abuse
            "country":       str | None, # ISO 2-letter code
            "isp":           str | None,
            "total_reports": int | None,
            "last_reported": str | None, # ISO timestamp
            "fetched_at":    str,        # ISO timestamp of cache write
            "cached":        bool,       # True when served from cache
        }

    Returns None when the IP is non-public, the cache is empty, and no
    valid `api_key` is configured. Never raises.
    """
    if not _is_public_ip(ip):
        return None

    cached = _read_cache(db_path, ip, source)
    if cached and not _is_stale(cached["fetched_at"], ttl_hours):
        cached["cached"] = True
        return cached

    api_key = api_key or _env_api_key()
    if not api_key:
        # No key + no fresh cache = nothing we can return. Return the
        # stale cache if we have one — better to show day-old data than
        # nothing at all when the admin removed the key by mistake.
        if cached:
            cached["cached"] = True
            return cached
        return None

    fetched = _lookup_via_abuseipdb(ip, api_key)
    if fetched is None:
        if cached:
            cached["cached"] = True
            return cached
        return None

    _write_cache(db_path, ip, source, fetched)
    fetched["cached"] = False
    return fetched


def _is_public_ip(ip):
    """True only for public, routable IPv4/IPv6 addresses.

    We never send private IPs (RFC 1918), loopback, link-local,
    multicast, or reserved ranges to a third-party service — both for
    privacy (internal hostnames could be inferred) and to save quota
    on lookups that would always come back empty.
    """
    if not ip or not isinstance(ip, str):
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
    except (ValueError, TypeError):
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    return True


# ---------------------------------------------------------------------------
# Provider — AbuseIPDB
# ---------------------------------------------------------------------------

def _lookup_via_abuseipdb(ip, api_key):
    """Hit AbuseIPDB /check. Return a normalized dict or None on any error.

    Free-tier rate limit is 1000 lookups/day. We rely on the cache to
    keep us well under that — a typical fleet has dozens, not thousands,
    of distinct external IPs.
    """
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
            "User-Agent": "Pulse/1.5",
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
        "source":        "abuseipdb",
        "score":         _coerce_int(data.get("abuseConfidenceScore")),
        "country":       data.get("countryCode") or None,
        "isp":           data.get("isp") or None,
        "total_reports": _coerce_int(data.get("totalReports")),
        "last_reported": data.get("lastReportedAt") or None,
        "fetched_at":    _now_iso(),
        # Stash the raw payload so the API endpoint can return it for
        # callers that want fields we haven't normalized (usage type,
        # domain, hostnames, etc.).
        "_raw":          data,
    }


# ---------------------------------------------------------------------------
# Cache I/O
# ---------------------------------------------------------------------------

def _read_cache(db_path, ip, source):
    """Return the cache row as a dict, or None if missing."""
    try:
        with database._connect(db_path) as conn:
            row = conn.execute(
                """SELECT ip_address, source, score, country, isp,
                          total_reports, last_reported, payload, fetched_at
                   FROM intel_cache
                   WHERE ip_address = ? AND source = ?""",
                (ip, source),
            ).fetchone()
    except Exception:
        return None
    if not row:
        return None
    raw = None
    if row[7]:
        try:
            raw = json.loads(row[7])
        except (TypeError, ValueError):
            raw = None
    return {
        "ip":            row[0],
        "source":        row[1],
        "score":         row[2],
        "country":       row[3],
        "isp":           row[4],
        "total_reports": row[5],
        "last_reported": row[6],
        "_raw":          raw,
        "fetched_at":    row[8],
    }


def _write_cache(db_path, ip, source, entry):
    """UPSERT the cache row. Silently swallows DB errors so a transient
    cache failure never breaks the user-facing lookup path."""
    payload_json = None
    if entry.get("_raw") is not None:
        try:
            payload_json = json.dumps(entry["_raw"])
        except (TypeError, ValueError):
            payload_json = None
    try:
        with database._connect(db_path) as conn:
            conn.execute(
                """INSERT INTO intel_cache
                       (ip_address, source, score, country, isp,
                        total_reports, last_reported, payload, fetched_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ip_address, source) DO UPDATE SET
                       score         = excluded.score,
                       country       = excluded.country,
                       isp           = excluded.isp,
                       total_reports = excluded.total_reports,
                       last_reported = excluded.last_reported,
                       payload       = excluded.payload,
                       fetched_at    = excluded.fetched_at""",
                (ip, source,
                 entry.get("score"),
                 entry.get("country"),
                 entry.get("isp"),
                 entry.get("total_reports"),
                 entry.get("last_reported"),
                 payload_json,
                 entry.get("fetched_at") or _now_iso()),
            )
    except Exception:
        pass


def _is_stale(fetched_at, ttl_hours):
    """True when `fetched_at` is older than ttl_hours. Tolerates a missing
    or malformed timestamp by treating it as stale."""
    if not fetched_at:
        return True
    try:
        # Stored as UTC ISO without timezone marker — parse naive then
        # treat as UTC for the comparison.
        ts = datetime.fromisoformat(fetched_at.replace("Z", ""))
    except (TypeError, ValueError):
        return True
    age = datetime.utcnow() - ts
    return age >= timedelta(hours=ttl_hours)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _coerce_int(v):
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _now_iso():
    """UTC ISO timestamp without microseconds — matches the format used
    elsewhere in Pulse (`scanned_at`, `created_at`)."""
    return datetime.utcnow().replace(microsecond=0).isoformat()


def _env_api_key():
    """Fallback to env var so deployments (Render, Docker) can wire the
    key without touching pulse.yaml. None when unset."""
    import os
    val = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    return val or None


# ---------------------------------------------------------------------------
# Config helpers — read from a Pulse config dict
# ---------------------------------------------------------------------------

def get_api_key_from_config(config):
    """Pull the AbuseIPDB key from a pulse.yaml config dict. Returns
    None when the section is missing or the key is empty / whitespace."""
    if not isinstance(config, dict):
        return None
    block = config.get("threat_intel") or {}
    raw = block.get("abuseipdb_api_key")
    if not raw or not isinstance(raw, str):
        return None
    raw = raw.strip()
    return raw or None


def get_ttl_hours_from_config(config, default=DEFAULT_CACHE_TTL_HOURS):
    """Pull the cache TTL from config. Falls back to the module default."""
    if not isinstance(config, dict):
        return default
    block = config.get("threat_intel") or {}
    raw = block.get("cache_ttl_hours", default)
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return default


def is_enabled_in_config(config):
    """True when a key is set AND the user hasn't explicitly disabled
    threat-intel lookups. Defaults to enabled when a key exists."""
    if not isinstance(config, dict):
        return False
    block = config.get("threat_intel") or {}
    if block.get("enabled") is False:
        return False
    return bool(get_api_key_from_config(config) or _env_api_key())
