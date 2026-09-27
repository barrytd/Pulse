# pulse/connectors/base.py
# ------------------------
# The shape every connector follows, plus the registry they add
# themselves to and the helpers they share (public-IP guard, the
# `intel_cache` table, a per-provider quota guard).
#
# A connector is one small class that talks to one outside service.
# It declares what it is (`key`, `name`, `kind`), what settings it
# needs (`config_fields`), what it can do (`actions()`), and does it
# (`run()`). Decorate the class with `@register` and drop the file in
# `pulse/connectors/`; the package imports every module on first use,
# so no core edit is needed to add one.
#
# Fail-safe contract: callers go through `run_action()`, which turns
# any exception into None ("no intel"). A bad key, a timeout, or a rate
# limit must never break the dashboard request that asked for the data.

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import threading
import urllib.request
import time
from collections import deque
from datetime import datetime, timedelta

from .. import database

log = logging.getLogger(__name__)

# How long a cached entry is considered fresh. Overridden by the
# `threat_intel.cache_ttl_hours` key in pulse.yaml.
DEFAULT_CACHE_TTL_HOURS = 24

# Outbound timeout. Lookups happen synchronously in the request loop,
# so a hung connection would stall the dashboard.
HTTP_TIMEOUT_SECONDS = 5

USER_AGENT = "Pulse/2.0"


# ---------------------------------------------------------------------------
# Base class + registry
# ---------------------------------------------------------------------------

class Connector:
    """One integration with one outside service.

    Subclasses set the class attributes and implement `run()`. The
    `config` dict passed to `run()` / `health_check()` is what
    `config_from_pulse()` returns, plus a `db_path` key the caller adds
    so enrichment connectors can reach the cache.
    """

    key = ""                 # unique id, e.g. "virustotal"
    name = ""                # shown in the UI
    kind = "enrichment"      # "enrichment" (reads) or "response" (acts)
    config_fields = []       # settings this connector needs

    def actions(self):
        """Action names this connector supports, e.g. ["lookup_ip"]."""
        return []

    def config_from_pulse(self, pulse_config):
        """Pull this connector's settings out of a pulse.yaml dict."""
        return {}

    def health_check(self, config):
        """True when the connector has what it needs to run (key set)."""
        return all(config.get(f) for f in self.config_fields)

    def run(self, action, inputs, config):
        """Do `action` with `inputs`. Return a result dict, or None when
        there is nothing to report. May raise; `run_action` catches."""
        raise NotImplementedError

    # --- Playbook-builder metadata ------------------------------------
    # Result fields later playbook steps may reference as
    # {{ <save_as>.<field> }}, e.g. {"score": "Abuse score (0-100)"}.
    result_fields = {}

    def action_label(self, action):
        """Plain-language name for an action, shown in the builder."""
        return ACTION_LABELS.get(action, action.replace("_", " ").capitalize())

    def action_inputs(self, action):
        """The inputs `run(action, ...)` reads: [{name, label, required,
        multiline}]. The builder renders one field per entry, and recipe
        validation rejects a step that leaves a required one empty."""
        return [dict(i) for i in DEFAULT_INPUTS.get(action, [])]

    def summarize(self, action, result):
        """One plain-language line describing `result`, shown in the
        finding drawer's Investigate panel. None to show nothing."""
        return None


ACTION_LABELS = {
    "lookup_ip":     "Look up an IP address",
    "lookup_domain": "Look up a domain",
    "lookup_hash":   "Look up a file hash",
    "block_ip":      "Block an IP address",
    "post_message":  "Post a message",
}

DEFAULT_INPUTS = {
    "lookup_ip":     [{"name": "ip", "label": "IP address", "required": True, "multiline": False}],
    "lookup_domain": [{"name": "domain", "label": "Domain", "required": True, "multiline": False}],
    "lookup_hash":   [{"name": "hash", "label": "File hash", "required": True, "multiline": False}],
}

_REGISTRY = {}


def register(cls):
    """Class decorator: instantiate the connector and add it to the
    registry under its `key`. Duplicate keys are a programming error."""
    if not cls.key:
        raise ValueError(f"{cls.__name__} has no key")
    if cls.key in _REGISTRY:
        raise ValueError(f"Duplicate connector key: {cls.key}")
    _REGISTRY[cls.key] = cls()
    return cls


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def is_public_ip(ip):
    """True only for public, routable IPv4/IPv6 addresses.

    We never send private IPs (RFC 1918), loopback, link-local,
    multicast, or reserved ranges to a third-party service, both for
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


_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
# Internal-only suffixes. Sending these off-host would leak the
# network's naming, and outside services would have nothing on them.
INTERNAL_SUFFIXES = (
    ".local", ".localdomain", ".lan", ".home", ".internal", ".intranet",
    ".corp", ".private", ".localhost", ".arpa", ".test", ".invalid",
    ".example",
)


def normalize_hash(value):
    """Lowercased MD5/SHA-1/SHA-256 hex, or None."""
    if not value or not isinstance(value, str):
        return None
    v = value.strip().lower()
    return v if _HASH_RE.match(v) else None


def normalize_domain(value):
    """Lowercased public-looking domain name, or None. Rejects IPs,
    single labels, and internal suffixes like .local / .corp, so no
    connector ever sends the network's internal naming off-host."""
    if not value or not isinstance(value, str):
        return None
    v = value.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(v)
        return None
    except ValueError:
        pass
    if not _DOMAIN_RE.match(v):
        return None
    if any(v.endswith(s) for s in INTERNAL_SUFFIXES):
        return None
    return v


def env_value(name):
    """Read a key from the environment so deployments (Render, Docker)
    can wire it without touching pulse.yaml. None when unset."""
    val = os.environ.get(name, "").strip()
    return val or None


def config_str(pulse_config, field):
    """Pull a stripped string from the `threat_intel` block, or None."""
    if not isinstance(pulse_config, dict):
        return None
    block = pulse_config.get("threat_intel") or {}
    raw = block.get(field)
    if not raw or not isinstance(raw, str):
        return None
    return raw.strip() or None


def ttl_hours_from_config(pulse_config, default=DEFAULT_CACHE_TTL_HOURS):
    """Cache TTL from the `threat_intel` block. Falls back to `default`."""
    if not isinstance(pulse_config, dict):
        return default
    block = pulse_config.get("threat_intel") or {}
    raw = block.get("cache_ttl_hours", default)
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return default


def coerce_int(v):
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def now_iso():
    """UTC ISO timestamp without microseconds. Matches the format used
    elsewhere in Pulse (`scanned_at`, `created_at`)."""
    return datetime.utcnow().replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# intel_cache I/O
# ---------------------------------------------------------------------------
# One row per (indicator, source). The column is named `ip_address` for
# history, but it holds whatever the provider looked up (IP, file hash,
# domain); those never collide with each other. `payload` keeps the
# provider-specific fields as JSON.

def read_cache(db_path, indicator, source):
    """Return the cache row as a dict, or None if missing."""
    try:
        with database._connect(db_path) as conn:
            row = conn.execute(
                """SELECT ip_address, source, score, country, isp,
                          total_reports, last_reported, payload, fetched_at
                   FROM intel_cache
                   WHERE ip_address = ? AND source = ?""",
                (indicator, source),
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


def write_cache(db_path, indicator, source, entry):
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
                (indicator, source,
                 entry.get("score"),
                 entry.get("country"),
                 entry.get("isp"),
                 entry.get("total_reports"),
                 entry.get("last_reported"),
                 payload_json,
                 entry.get("fetched_at") or now_iso()),
            )
    except Exception:
        pass


def is_stale(fetched_at, ttl_hours):
    """True when `fetched_at` is older than ttl_hours. Tolerates a missing
    or malformed timestamp by treating it as stale."""
    if not fetched_at:
        return True
    try:
        # Stored as UTC ISO without timezone marker; parse naive then
        # treat as UTC for the comparison.
        ts = datetime.fromisoformat(fetched_at.replace("Z", ""))
    except (TypeError, ValueError):
        return True
    return datetime.utcnow() - ts >= timedelta(hours=ttl_hours)


# ---------------------------------------------------------------------------
# Quota guard
# ---------------------------------------------------------------------------

class QuotaGuard:
    """Per-minute + per-day request budget for one provider.

    `try_acquire()` spends one request and returns True, or returns
    False without spending when either budget is used up. It never
    sleeps: a lookup that would go over quota just returns "no intel"
    (or stale cache) and the next one after the window frees up works.

    In-process and in-memory, same scope as `pulse/rate_limit.py`. On a
    single-worker deploy that matches the provider's view of the key; a
    restart resets the daily count, which errs toward the provider
    returning 429, and that path is already handled as "no intel".
    """

    def __init__(self, per_minute, per_day, clock=time.time):
        self.per_minute = per_minute
        self.per_day = per_day
        self._clock = clock
        self._minute = deque()
        self._day_key = None
        self._day_count = 0
        self._lock = threading.Lock()

    def try_acquire(self):
        with self._lock:
            now = self._clock()
            while self._minute and now - self._minute[0] >= 60:
                self._minute.popleft()
            day_key = time.strftime("%Y-%m-%d", time.gmtime(now))
            if day_key != self._day_key:
                self._day_key = day_key
                self._day_count = 0
            if len(self._minute) >= self.per_minute:
                return False
            if self._day_count >= self.per_day:
                return False
            self._minute.append(now)
            self._day_count += 1
            return True

    def reset(self):
        with self._lock:
            self._minute.clear()
            self._day_key = None
            self._day_count = 0


# ---------------------------------------------------------------------------
# Outbound requests to admin-configured URLs (response connectors)
# ---------------------------------------------------------------------------
# A URL an admin types into Settings (a generic webhook, a self-hosted
# Jira) could point Pulse at its own network: http://169.254.169.254/
# (cloud metadata), http://localhost:8000/..., an internal admin panel.
# post_json_guarded() refuses those before connecting:
#   * https only (http is allowed only together with allow_private, for
#     LAN tools like a self-hosted n8n);
#   * every address the host resolves to is checked: loopback,
#     link-local (incl. metadata), multicast, reserved and unspecified
#     are always refused; private (RFC 1918 / ULA) only with
#     allow_private;
#   * redirects are never followed, so a public URL can't bounce the
#     request inside.
# Residual risk: DNS can change between the check and the connect (DNS
# rebinding). The redirect block and the address check still stop the
# common cases; admins set these URLs, never playbooks.

class DestinationRefused(ValueError):
    """The URL points somewhere Pulse won't send to."""


def check_destination(url, allow_private=False):
    """Raise DestinationRefused unless `url` is an acceptable outbound
    target. Returns the parsed URL."""
    import socket
    import urllib.parse

    parsed = urllib.parse.urlparse(str(url or "").strip())
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise DestinationRefused("The URL must start with https://.")
    if parsed.scheme == "http" and not allow_private:
        raise DestinationRefused("The URL must use https:// (plain http is only allowed "
                                 "for private destinations, when those are enabled).")
    if parsed.username or parsed.password:
        raise DestinationRefused("Put credentials in the settings fields, not in the URL.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        raise DestinationRefused("The URL has an invalid port.")
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        raise DestinationRefused(f"Can't resolve {parsed.hostname}.")
    for info in infos:
        addr = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        mapped = getattr(addr, "ipv4_mapped", None)
        addr = mapped or addr
        if (addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_unspecified or addr.is_reserved):
            raise DestinationRefused(f"{parsed.hostname} resolves to {addr}, a loopback, "
                                     "link-local or reserved address. Pulse never sends there.")
        # is_global, not is_private: also catches carrier-grade NAT
        # (100.64.0.0/10) and other non-public ranges.
        if not addr.is_global and not allow_private:
            raise DestinationRefused(f"{parsed.hostname} resolves to the private address {addr}. "
                                     "Turn on private destinations to allow it.")
    return parsed


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None     # the 3xx surfaces as an HTTPError instead


def request_guarded(url, *, method="POST", payload=None, headers=None, allow_private=False,
                    timeout=10, body=None):
    """Guarded HTTP request. Returns (status, parsed_json_or_None). Raises
    DestinationRefused for a refused URL, and urllib / OS errors for
    network failures; callers turn both into an ok=False result."""
    check_destination(url, allow_private=allow_private)
    data = body if body is not None else (
        json.dumps(payload).encode("utf-8") if payload is not None else None)
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "User-Agent": USER_AGENT, **(headers or {})})
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(req, timeout=timeout) as resp:
        raw = resp.read(256 * 1024)
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            parsed = None
        return resp.status, parsed
