# pulse/intel.py
# ----------------
# Threat-intelligence lookup for source IPs surfaced by Pulse.
#
# The provider code now lives in `pulse/connectors/` (one file per
# service, see base.py for the interface). This module keeps the
# original function names so existing callers (incident reports, the
# IOC page, the /api/intel endpoints) don't change: `lookup_ip` routes
# to the AbuseIPDB connector, and the cache helpers are the shared ones
# every enrichment connector writes through.
#
# The contract is unchanged:
#   * Missing API key       -> returns None (caller renders "no intel")
#   * Private/loopback IPs  -> never sent to the external service
#   * Malformed IP          -> returns None
#   * HTTP failure / timeout-> returns None, no exception bubbles up

from __future__ import annotations

from . import database
from .connectors import abuseipdb as _abuseipdb
from .connectors import base as _base

DEFAULT_CACHE_TTL_HOURS = _base.DEFAULT_CACHE_TTL_HOURS
HTTP_TIMEOUT_SECONDS = _base.HTTP_TIMEOUT_SECONDS
ABUSEIPDB_URL = _abuseipdb.ABUSEIPDB_URL

_is_public_ip = _base.is_public_ip
_read_cache = _base.read_cache
_write_cache = _base.write_cache
_is_stale = _base.is_stale
_coerce_int = _base.coerce_int
_now_iso = _base.now_iso


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_ip(ip, db_path, api_key=None, ttl_hours=DEFAULT_CACHE_TTL_HOURS,
              source="abuseipdb"):
    """Return a normalized AbuseIPDB intel dict for `ip`, or None.

    `api_key` falls back to the ABUSEIPDB_API_KEY env var. See
    `pulse.connectors.abuseipdb.lookup_ip` for the flow and the
    returned shape. Never raises. `source` is accepted for backward
    compatibility; AbuseIPDB is the only provider routed here.
    """
    return _abuseipdb.lookup_ip(ip, db_path,
                                api_key=api_key or _env_api_key(),
                                ttl_hours=ttl_hours)


def _lookup_via_abuseipdb(ip, api_key):
    """Live AbuseIPDB request, bypassing the cache. None on any error."""
    return _abuseipdb.fetch(ip, api_key)


def list_recent_cache(db_path, limit=50, source="abuseipdb"):
    """Return up to `limit` cache rows newest-first, narrowed to one
    provider. Powers the "Recent lookups" panel on the IOC page.
    Returns an empty list on any DB error so the page can still render.

    Each row matches the `lookup_ip` return shape minus the `_raw`
    payload (kept on the server; the recent panel doesn't need it)."""
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 50
    try:
        with database._connect(db_path) as conn:
            rows = conn.execute(
                """SELECT ip_address, source, score, country, isp,
                          total_reports, last_reported, fetched_at
                   FROM intel_cache
                   WHERE source = ?
                   ORDER BY fetched_at DESC
                   LIMIT ?""",
                (source, limit),
            ).fetchall()
    except Exception:
        return []
    out = []
    for r in rows or []:
        out.append({
            "ip":            r[0],
            "source":        r[1],
            "score":         r[2],
            "country":       r[3],
            "isp":           r[4],
            "total_reports": r[5],
            "last_reported": r[6],
            "fetched_at":    r[7],
        })
    return out


def _env_api_key():
    """AbuseIPDB key from the environment, or None."""
    return _base.env_value(_abuseipdb.ENV_KEY)


# ---------------------------------------------------------------------------
# Config helpers — read from a Pulse config dict
# ---------------------------------------------------------------------------

def get_api_key_from_config(config):
    """Pull the AbuseIPDB key from a pulse.yaml config dict. Returns
    None when the section is missing or the key is empty / whitespace."""
    return _base.config_str(config, "abuseipdb_api_key")


def get_virustotal_key_from_config(config):
    """Pull the VirusTotal key from a pulse.yaml config dict, or None."""
    return _base.config_str(config, "virustotal_api_key")


def get_ttl_hours_from_config(config, default=DEFAULT_CACHE_TTL_HOURS):
    """Pull the cache TTL from config. Falls back to the module default."""
    return _base.ttl_hours_from_config(config, default)


def is_enabled_in_config(config):
    """True when at least one provider key is set AND the user hasn't
    explicitly disabled threat-intel lookups."""
    if not isinstance(config, dict):
        return False
    block = config.get("threat_intel") or {}
    if block.get("enabled") is False:
        return False
    return bool(get_api_key_from_config(config)
                or get_virustotal_key_from_config(config)
                or _env_api_key())
