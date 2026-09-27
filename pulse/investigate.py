# pulse/investigate.py
# --------------------
# The finding drawer's Investigate panel: one click runs every enrichment
# connector that fits the indicators in a finding, and returns all the
# verdicts together.
#
#   source IP  -> every connector with lookup_ip     (AbuseIPDB, VirusTotal,
#                                                     GreyNoise, OTX, GeoIP)
#   domain     -> every connector with lookup_domain (Whois, DNS, VirusTotal, OTX)
#   file hash  -> every connector with lookup_hash   (VirusTotal, OTX)
#
# "Fits" is read from each connector's actions(), so a connector dropped
# into pulse/connectors/ joins the panel with no change here.
#
# Indicators are extracted on the server from the stored finding, so the
# server decides what may leave the machine: private / reserved IPs and
# internal domain names are listed as skipped and never sent anywhere.
#
# Lookups run in parallel under one deadline. Each provider's outcome is
# its own entry (ok / not_set_up / no_intel / disabled), so one provider
# failing or timing out never hides the others. Same pattern as
# /api/intel/{ip}/verdicts.

from __future__ import annotations

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, wait

# Module-level on purpose: with postponed annotations FastAPI resolves
# the route's `Request` annotation against this module's globals.
from fastapi import Depends, HTTPException, Request

from . import connectors
from .connectors.base import is_public_ip, normalize_domain, normalize_hash

MAX_PER_TYPE = 3
DEADLINE_SECONDS = 20

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)
_HASH_RE = re.compile(r"\b(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b", re.I)

# Tokens like lsass.exe or payload.ps1 look like domains to a regex. A
# real TLD is never one of these file extensions (".com" is kept: it's a
# far more common TLD than a DOS executable).
_FILE_EXTS = {
    "exe", "dll", "sys", "ps1", "psm1", "psd1", "bat", "cmd", "vbs", "vbe", "js",
    "jse", "wsf", "wsh", "hta", "scr", "msi", "msp", "lnk", "log", "txt", "evtx",
    "etl", "xml", "json", "yaml", "yml", "ini", "cfg", "conf", "dat", "tmp", "bin",
    "zip", "rar", "gz", "tar", "cab", "iso", "img", "db", "sqlite", "csv", "doc",
    "docx", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "rtf", "png", "jpg", "jpeg",
    "gif", "ico", "bmp", "mov", "mp4", "mp3", "wav", "py", "jar", "class", "ocx",
    "cpl", "drv", "efi", "inf", "reg", "pol", "manifest", "config",
}

# Generic TLDs accepted as domains; any two-letter country code is also
# accepted. Anything else ("Microsoft.Windows.Client.OOBE") is a package
# or namespace name, not a domain. Missing a rare TLD only means that
# domain isn't offered for lookup.
_GENERIC_TLDS = {
    "com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "name", "pro",
    "mobi", "asia", "tel", "travel", "jobs", "aero", "coop", "museum", "app", "dev",
    "xyz", "online", "site", "top", "club", "shop", "store", "live", "cloud", "tech",
    "space", "website", "fun", "icu", "vip", "work", "buzz", "link", "click", "win",
    "bid", "loan", "download", "stream", "science", "party", "review", "trade",
    "date", "racing", "cricket", "accountant", "men", "gdn", "kim", "rest", "bar",
    "cyou", "sbs", "cfd", "monster", "quest", "lol", "one", "life", "world", "today",
    "email", "network", "systems", "services", "support", "digital", "news", "blog",
    "page", "host", "cam", "best", "ink", "wiki", "zone", "global", "company",
}

TYPE_ACTION = {"ip": "lookup_ip", "domain": "lookup_domain", "hash": "lookup_hash"}
INPUT_KEY = {"ip": "ip", "domain": "domain", "hash": "hash"}
# Display order in the panel; connectors not listed follow alphabetically.
_ORDER = ["abuseipdb", "virustotal", "greynoise", "otx", "geoip", "whois", "dns"]


def extract_indicators(finding):
    """{"ip": [...], "domain": [...], "hash": [...], "skipped": [...]}

    IPs and domains come from the finding's description and details; file
    hashes also from the raw event (Sysmon puts them there). At most
    MAX_PER_TYPE of each. When several hash types are present (Sysmon
    logs MD5, SHA-1 and SHA-256 of the same file) only the strongest kind
    is kept, so one file isn't looked up three times.
    """
    text = " ".join(str(finding.get(k) or "") for k in ("description", "details"))
    raw = str(finding.get("raw_xml") or "")
    out = {"ip": [], "domain": [], "hash": [], "skipped": []}

    for m in _IPV4_RE.finditer(text):
        ip = m.group(0)
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if ip in out["ip"] or any(s["value"] == ip for s in out["skipped"]):
            continue
        if is_public_ip(ip):
            if len(out["ip"]) < MAX_PER_TYPE:
                out["ip"].append(ip)
        else:
            out["skipped"].append({"type": "ip", "value": ip,
                                   "reason": "Private or reserved address: never sent to an outside service."})

    for m in _DOMAIN_RE.finditer(text):
        original = m.group(0)
        token = original.lower()
        tld = token.rsplit(".", 1)[-1]
        if tld in _FILE_EXTS:
            continue
        # Namespaces / package names are PascalCase; domains in logs are
        # all lower or all upper case.
        if original != original.lower() and original != original.upper():
            continue
        if len(tld) != 2 and tld not in _GENERIC_TLDS and tld not in ("local", "corp", "lan",
                                                                         "internal", "home"):
            continue
        # Part of an email address or a URL path is fine; part of a longer
        # dotted number (an IP) isn't a domain.
        d = normalize_domain(token)
        if not d:
            if "." in token and not _IPV4_RE.fullmatch(token) and token not in \
                    [s["value"] for s in out["skipped"]]:
                out["skipped"].append({"type": "domain", "value": token,
                                       "reason": "Internal name: never sent to an outside service."})
            continue
        if d not in out["domain"] and len(out["domain"]) < MAX_PER_TYPE:
            out["domain"].append(d)

    hashes = []
    for m in _HASH_RE.finditer(text + " " + raw):
        h = normalize_hash(m.group(0))
        if h and h not in hashes:
            hashes.append(h)
    if hashes:
        strongest = max(len(h) for h in hashes)
        out["hash"] = [h for h in hashes if len(h) == strongest][:MAX_PER_TYPE]
    return out


def _order_key(c):
    return (_ORDER.index(c.key) if c.key in _ORDER else len(_ORDER), c.key)


def plan(indicators):
    """[(type, value, connector)] for every lookup that fits."""
    jobs = []
    for kind, action in TYPE_ACTION.items():
        fits = sorted((c for c in connectors.all_connectors(kind="enrichment")
                       if action in c.actions()), key=_order_key)
        for value in indicators.get(kind) or []:
            for c in fits:
                jobs.append((kind, value, c))
    return jobs


def investigate(finding, *, pulse_config, db_path, disabled_keys=(), lookups_off=False):
    """Run every fitting lookup for one finding. Never raises.

    disabled_keys: connectors switched off for the caller's organization.
    lookups_off:   threat-intel lookups switched off in Settings.
    """
    indicators = extract_indicators(finding)
    jobs = plan(indicators)
    results = {}
    pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="pulse-investigate")
    futures = {}
    try:
        for job in jobs:
            kind, value, c = job
            cfg = connectors.config_for(c, pulse_config, db_path=db_path)
            if lookups_off or c.key in disabled_keys:
                results[job] = {"status": "disabled"}
            elif not c.health_check(cfg):
                results[job] = {"status": "not_set_up"}
            else:
                futures[pool.submit(connectors.run_action, c.key, TYPE_ACTION[kind],
                                    {INPUT_KEY[kind]: value}, cfg)] = job
        done, _ = wait(futures, timeout=DEADLINE_SECONDS)
        for fut, job in futures.items():
            res = fut.result() if fut in done else None
            results[job] = ({"status": "ok", "result": res} if res is not None else
                            {"status": "no_intel",
                             "message": None if fut in done else "Timed out."})
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    groups = []
    for kind in TYPE_ACTION:
        for value in indicators.get(kind) or []:
            verdicts = []
            for job in jobs:
                if job[0] != kind or job[1] != value:
                    continue
                c = job[2]
                r = results.get(job, {"status": "no_intel"})
                entry = {"connector": c.key, "name": c.name, "status": r["status"]}
                if r.get("message"):
                    entry["message"] = r["message"]
                if r["status"] == "ok":
                    res = {k: v for k, v in r["result"].items() if not str(k).startswith("_")} \
                        if isinstance(r["result"], dict) else r["result"]
                    entry["result"] = res
                    entry["verdict"] = (res or {}).get("verdict") if isinstance(res, dict) else None
                    try:
                        entry["summary"] = c.summarize(TYPE_ACTION[kind], res)
                    except Exception:
                        entry["summary"] = None
                verdicts.append(entry)
            groups.append({"type": kind, "value": value, "verdicts": verdicts})
    return {"indicators": groups, "skipped": indicators["skipped"]}


# ---------------------------------------------------------------------------
# HTTP route (registered from api._register_routes)
# ---------------------------------------------------------------------------

def register_routes(app, *, check_finding_scope, read_config):
    from . import database, rate_limit
    from .auth import require_login
    from .soar import store

    @app.post("/api/findings/{finding_id}/investigate")
    def investigate_finding(finding_id: int, request: Request,
                            user_id: int = Depends(require_login)):
        """Run every enrichment connector that fits the finding's
        indicators. POST because it spends provider quota and sends
        indicators to outside services (so it's CSRF-protected and
        rate-limited)."""
        rate_limit.hit(request, "investigate", window_sec=60, max_hits=20)
        check_finding_scope(finding_id, user_id)
        with database._connect(app.state.db_path) as conn:
            row = conn.execute(
                "SELECT id, rule, severity, hostname, description, details, raw_xml "
                "FROM findings WHERE id = ?", (int(finding_id),)).fetchone()
        if row is None:
            raise HTTPException(404, detail="Finding not found.")
        finding = dict(zip(("id", "rule", "severity", "hostname", "description",
                            "details", "raw_xml"), row))
        config = read_config(app.state.config_path) or {}
        org = (database.get_user_organization_id(app.state.db_path, user_id) or 0) if user_id else 0
        disabled = {k for k, on in store.connector_states(app.state.db_path, org).items() if not on}
        lookups_off = (config.get("threat_intel") or {}).get("enabled") is False

        result = investigate(finding, pulse_config=config, db_path=app.state.db_path,
                             disabled_keys=disabled, lookups_off=lookups_off)

        from .firewall.blocker import log_audit
        user = database.get_user_by_id(app.state.db_path, user_id) if user_id else None
        sent = [f"{g['type']}:{g['value']}" for g in result["indicators"]]
        log_audit(app.state.db_path, "investigate", comment=f"finding:{finding_id}",
                  source="dashboard", user=(user or {}).get("email"),
                  detail=f"org={org} indicators={','.join(sent) or 'none'}")
        return dict(result, finding_id=finding_id)
