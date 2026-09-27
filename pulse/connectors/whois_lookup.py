# pulse/connectors/whois_lookup.py
# --------------------------------
# Whois enrichment connector: who registered a domain, and when.
#
# Standard library only, no API key. Two protocols:
#   * RDAP (RFC 9083, JSON over HTTPS) first. IANA's bootstrap file says
#     which RDAP server handles each TLD. Since ICANN dropped the port-43
#     requirement for gTLDs (January 2025), RDAP is the reliable path and
#     some registries (.uk) only answer it.
#   * classic Whois (RFC 3912, TCP 43) as a fallback: whois.iana.org
#     names the TLD's server; thin registries (.com / .net) name a
#     registrar Whois server, which is asked too.
#
# The useful signal is age: a domain registered in the last NEW_DOMAIN_DAYS
# is a classic phishing / malware sign, so it's "suspicious"; otherwise
# the record is context ("info").
#
# Only public-looking domains are ever queried (internal suffixes like
# .local / .corp are refused, same guard as every connector). Answers are
# cached; live queries are held to QUOTA because registries throttle.
# Offline / blocked port 43 / any parse problem -> "no intel".

from __future__ import annotations

import json
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .base import (
    DEFAULT_CACHE_TTL_HOURS, HTTP_TIMEOUT_SECONDS, USER_AGENT, Connector,
    QuotaGuard, is_stale, normalize_domain, now_iso, read_cache, register,
    ttl_hours_from_config, write_cache,
)

SOURCE = "whois"
RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_TTL = 24 * 3600
IANA = "whois.iana.org"
PORT = 43
TIMEOUT = 5
MAX_BYTES = 64 * 1024
NEW_DOMAIN_DAYS = 30
QUOTA = QuotaGuard(per_minute=10, per_day=500)

_HOST_RE = re.compile(r"^[a-z0-9.-]{3,253}$")
# Second-level labels under which registrations happen at the third
# level (example.co.uk). Approximation of the public suffix list, good
# enough to pick the name a registry knows.
_SECOND_LEVEL = {"co", "com", "net", "org", "ac", "gov", "edu", "ltd", "plc",
                 "ne", "or", "go", "gob", "nic", "mil"}
_NOT_FOUND = ("no match for", "not found", "no data found", "no entries found",
              "domain not found", "status: free", "no object found")

_FIELDS = {
    "registrar":  ("registrar",),
    "created":    ("creation date", "created on", "created", "registered on",
                   "registration time", "domain registration date"),
    "expires":    ("registry expiry date", "registrar registration expiration date",
                   "expiration date", "expiry date", "paid-till", "expires on"),
    "updated":    ("updated date", "last updated", "changed", "last modified"),
    "org":        ("registrant organization", "registrant organisation", "org"),
    "country":    ("registrant country", "country"),
}


def registrable(domain):
    """sub.example.co.uk -> example.co.uk; a.b.example.com -> example.com."""
    labels = domain.split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _query(server, query):
    with socket.create_connection((server, PORT), timeout=TIMEOUT) as s:
        # normalize_domain only admits ASCII names, so ASCII is exact.
        s.sendall((query + "\r\n").encode("ascii"))
        chunks, total = [], 0
        while total < MAX_BYTES:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
            total += len(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _field(text, names):
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        if k.strip().lower() in names and v.strip():
            return v.strip()
    return None


def _all(text, names):
    out = []
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() in names and v.strip():
                out.append(v.strip().lower().rstrip("."))
    return out


def _referral(text, *keys):
    host = _field(text, keys)
    if host:
        host = host.lower().replace("whois://", "").replace("rwhois://", "").split("/")[0].strip()
        if _HOST_RE.match(host):
            return host
    return None


def parse_date(value):
    """Registry dates come in many shapes; return a UTC date or None."""
    if not value:
        return None
    v = value.strip().split(" (")[0]
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return d.astimezone(timezone.utc) if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d",
                "%Y-%m-%d %H:%M:%S", "%d-%b-%Y %H:%M:%S %Z"):
        try:
            return datetime.strptime(v, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def parse(domain, text):
    """Normalized record from raw Whois text."""
    low = text.lower()
    if not text.strip() or any(m in low for m in _NOT_FOUND):
        return _entry(domain, found=False)
    rec = {k: _field(text, names) for k, names in _FIELDS.items()}
    created = parse_date(rec["created"])
    age = (datetime.now(timezone.utc) - created).days if created else None
    ns = sorted(set(_all(text, ("name server", "nserver"))))[:4]
    return _entry(domain, found=True, registrar=rec["registrar"],
                  created=created.date().isoformat() if created else None,
                  expires=(parse_date(rec["expires"]).date().isoformat()
                           if parse_date(rec["expires"]) else None),
                  age_days=age, org=rec["org"], country=rec["country"], name_servers=ns)


_bootstrap = {"at": 0.0, "map": None}
_bootstrap_lock = threading.Lock()


def _http_json(url):
    req = urllib.request.Request(url, headers={
        "Accept": "application/rdap+json, application/json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
        return json.loads(resp.read().decode("utf-8"))


def rdap_base(tld):
    """RDAP base URL for a TLD from IANA's bootstrap file (cached a day),
    or None."""
    with _bootstrap_lock:
        if _bootstrap["map"] is None or time.time() - _bootstrap["at"] > BOOTSTRAP_TTL:
            try:
                data = _http_json(RDAP_BOOTSTRAP)
                mapping = {}
                for svc in data.get("services") or []:
                    urls = [u for u in (svc[1] if len(svc) > 1 else []) if str(u).startswith("https://")]
                    if urls:
                        for t in svc[0]:
                            mapping[str(t).lower()] = urls[0] if urls[0].endswith("/") else urls[0] + "/"
                _bootstrap.update(at=time.time(), map=mapping)
            except (urllib.error.URLError, OSError, ValueError, TypeError, IndexError):
                if _bootstrap["map"] is None:
                    return None
        return _bootstrap["map"].get(tld)


def _vcard_fn(entity):
    card = (entity.get("vcardArray") or [None, []])
    for item in card[1] if len(card) > 1 else []:
        if isinstance(item, list) and item and item[0] == "fn" and len(item) > 3:
            return str(item[3]).strip() or None
    return None


def fetch_rdap(domain):
    """RDAP lookup. A normalized record, or None when there's no RDAP
    server for the TLD or the request failed (caller falls back)."""
    base = rdap_base(domain.rsplit(".", 1)[-1])
    if not base:
        return None
    try:
        data = _http_json(base + "domain/" + urllib.parse.quote(domain, safe=""))
    except urllib.error.HTTPError as e:
        return _entry(domain, found=False) if e.code == 404 else None
    except (urllib.error.URLError, OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    events = {str(e.get("eventAction", "")).lower(): e.get("eventDate")
              for e in data.get("events") or [] if isinstance(e, dict)}
    registrar = org = None
    for ent in data.get("entities") or []:
        roles = ent.get("roles") or []
        if "registrar" in roles and not registrar:
            registrar = _vcard_fn(ent)
        if "registrant" in roles and not org:
            org = _vcard_fn(ent)
    created = parse_date(events.get("registration"))
    expires = parse_date(events.get("expiration"))
    ns = sorted({str(n.get("ldhName", "")).lower().rstrip(".")
                 for n in data.get("nameservers") or [] if n.get("ldhName")})[:4]
    return _entry(domain, found=True, registrar=registrar, org=org,
                  created=created.date().isoformat() if created else None,
                  expires=expires.date().isoformat() if expires else None,
                  age_days=(datetime.now(timezone.utc) - created).days if created else None,
                  name_servers=ns, protocol="rdap")


def fetch(domain):
    """Live lookup: RDAP, then classic Whois. None on any failure."""
    rec = fetch_rdap(domain)
    if rec is not None:
        return rec
    return fetch_port43(domain)


def fetch_port43(domain):
    """Classic Whois, following IANA -> registry -> registrar."""
    tld = domain.rsplit(".", 1)[-1]
    try:
        server = _referral(_query(IANA, tld), "refer", "whois")
        if not server:
            return None
        text = _query(server, domain)
        registrar_server = _referral(text, "registrar whois server")
        if registrar_server and registrar_server != server:
            try:
                deeper = _query(registrar_server, domain)
                if deeper.strip():
                    text = text + "\n" + deeper
            except OSError:
                pass
    except (OSError, UnicodeError):
        return None
    return parse(domain, text)


def _entry(domain, *, found, **fields):
    e = {"indicator": domain, "type": "domain", "source": SOURCE, "found": found,
         "registrar": None, "created": None, "expires": None, "age_days": None,
         "org": None, "country": None, "name_servers": [], "fetched_at": now_iso()}
    e.update(fields)
    return e


def verdict_for(entry):
    if not entry.get("found"):
        return "unknown"
    age = entry.get("age_days")
    return "suspicious" if age is not None and age < NEW_DOMAIN_DAYS else "info"


def lookup_domain(value, db_path, ttl_hours=DEFAULT_CACHE_TTL_HOURS):
    domain = normalize_domain(value)
    if not domain:
        return None
    domain = registrable(domain)
    row = read_cache(db_path, domain, SOURCE)
    cached = dict(row["_raw"], fetched_at=row["fetched_at"]) \
        if row and isinstance(row.get("_raw"), dict) else None
    if cached and not is_stale(cached["fetched_at"], ttl_hours):
        return _finish(cached, True)
    fetched = fetch(domain) if QUOTA.try_acquire() else None
    if fetched is None:
        return _finish(cached, True) if cached else None
    write_cache(db_path, domain, SOURCE, {
        "score": None, "country": fetched.get("country"), "isp": fetched.get("registrar"),
        "total_reports": None, "last_reported": fetched.get("created"),
        "fetched_at": fetched["fetched_at"], "_raw": fetched})
    return _finish(fetched, False)


def _finish(entry, cached):
    entry["cached"] = cached
    entry["verdict"] = verdict_for(entry)
    return entry


@register
class WhoisConnector(Connector):
    key = "whois"
    result_fields = {"age_days": "Domain age (days)", "registrar": "Registrar", "verdict": "Verdict"}
    name = "Whois"
    kind = "enrichment"
    config_fields = []

    def actions(self):
        return ["lookup_domain"]

    def health_check(self, config):
        return True

    def config_from_pulse(self, pulse_config):
        return {"ttl_hours": ttl_hours_from_config(pulse_config)}

    def summarize(self, action, result):
        if not result:
            return None
        if not result.get("found"):
            return "No Whois record (unregistered, or the registry hides it)."
        bits = []
        if result.get("age_days") is not None:
            age = result["age_days"]
            bits.append(f"Registered {age} day{'s' if age != 1 else ''} ago"
                        + (" (new domain)" if age < NEW_DOMAIN_DAYS else "")
                        + (f", {result['created']}" if result.get("created") else ""))
        if result.get("registrar"):
            bits.append(result["registrar"])
        if result.get("country"):
            bits.append(result["country"])
        return " · ".join(bits) or "Registered (no dates published)."

    def run(self, action, inputs, config):
        if action != "lookup_domain":
            return None
        return lookup_domain(inputs.get("domain"), config.get("db_path"),
                             ttl_hours=config.get("ttl_hours", DEFAULT_CACHE_TTL_HOURS))
