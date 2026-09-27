# pulse/connectors/dns_lookup.py
# ------------------------------
# DNS enrichment connector: what a domain resolves to right now.
#
# Uses the host's own resolver (socket.getaddrinfo), standard library
# only, no API key. The red flag it looks for is a public-looking domain
# that resolves to a private / loopback address: that's how DNS rebinding
# and "phone home to an internal box" tricks work, so it's "suspicious".
# A name that doesn't resolve at all is reported as such.
#
# Internal names (.local, .corp, ...) are refused like everywhere else,
# so their lookups can't leak to an upstream resolver. Not cached: DNS
# answers change and the OS resolver already caches. The lookup runs with
# a hard timeout so a slow resolver can't stall an investigation.

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

from .base import Connector, normalize_domain, now_iso, register

TIMEOUT = 5
MAX_ADDRESSES = 8
_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="pulse-dns")


def _resolve(domain):
    infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    seen = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


def lookup_domain(value):
    domain = normalize_domain(value)
    if not domain:
        return None
    try:
        addresses = _pool.submit(_resolve, domain).result(timeout=TIMEOUT)
    except socket.gaierror:
        return _finish({"indicator": domain, "type": "domain", "source": "dns",
                        "found": False, "addresses": [], "internal": [],
                        "fetched_at": now_iso()})
    except (FutureTimeout, OSError, UnicodeError):
        return None
    internal = []
    for a in addresses:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            internal.append(a)
    return _finish({"indicator": domain, "type": "domain", "source": "dns",
                    "found": bool(addresses), "addresses": addresses[:MAX_ADDRESSES],
                    "internal": internal, "fetched_at": now_iso()})


def _finish(entry):
    entry["cached"] = False
    if not entry["found"]:
        entry["verdict"] = "unknown"
    elif entry["internal"]:
        entry["verdict"] = "suspicious"
    else:
        entry["verdict"] = "info"
    return entry


@register
class DNSConnector(Connector):
    key = "dns"
    result_fields = {"found": "Resolves (true/false)", "verdict": "Verdict"}
    name = "DNS"
    kind = "enrichment"
    config_fields = []

    def actions(self):
        return ["lookup_domain"]

    def health_check(self, config):
        return True

    def summarize(self, action, result):
        if not result:
            return None
        if not result.get("found"):
            return "Does not resolve (no DNS record)."
        addrs = result.get("addresses") or []
        line = "Resolves to " + ", ".join(addrs[:3]) + (f" (+{len(addrs) - 3} more)" if len(addrs) > 3 else "")
        if result.get("internal"):
            line += " · points at an internal address"
        return line

    def run(self, action, inputs, config):
        if action != "lookup_domain":
            return None
        return lookup_domain(inputs.get("domain"))
