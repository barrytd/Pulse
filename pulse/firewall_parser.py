# pulse/firewall_parser.py
# -------------------------
# Windows Firewall log parser + detections. The log is written by the
# built-in "Log dropped packets" / "Log successful connections" options
# under Windows Firewall with Advanced Security.
#
# FORMAT (W3C-style, space-delimited, documented by Microsoft):
#
#   #Version: 1.5
#   #Software: Microsoft Windows Firewall
#   #Time Format: Local
#   #Fields: date time action protocol src-ip dst-ip src-port dst-port size
#            tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid
#
#   2026-04-18 10:23:45 DROP TCP 203.0.113.45 192.168.1.10 4444 3389 0 - 0 ...
#
# Defaults — %windir%\System32\LogFiles\Firewall\pfirewall.log
#
# DETECTIONS
#   - Port-scan: one external IP with many DROPs across many dst-ports in a
#     short window.
#   - Sensitive-port probe: a DROP on a high-value port (3389, 22, 445,
#     3306, 5985) from a public IP — even a single line is worth showing
#     because these ports should never face the internet.
#
# Everything private / loopback / link-local is ignored at the source-IP
# level so routine intra-LAN chatter doesn't spam the UI.

from __future__ import annotations

import ipaddress
import os
import platform
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Optional


# Fields written by Windows Firewall when the log is first opened. Kept as
# a constant so the parser stays robust against files missing the #Fields
# header (we fall back to this order).
DEFAULT_FIELDS = [
    "date", "time", "action", "protocol", "src-ip", "dst-ip",
    "src-port", "dst-port", "size", "tcpflags", "tcpsyn", "tcpack",
    "tcpwin", "icmptype", "icmpcode", "info", "path", "pid",
]

# High-value ports. A single blocked probe is enough to flag — these
# should never be exposed to the public internet on an end-user box.
SENSITIVE_PORTS = {
    22:   "SSH",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5985: "WinRM",
    5986: "WinRM (TLS)",
}

# Tuning knobs for the port-scan heuristic.
PORT_SCAN_MIN_PORTS    = 10
PORT_SCAN_WINDOW_MIN   = 5


def default_log_path() -> str:
    """Windows default. Missing on non-Windows, but we still return a
    path so CLI usage / tests can reason about it without branching."""
    windir = os.environ.get("WINDIR", r"C:\Windows")
    return os.path.join(windir, "System32", "LogFiles", "Firewall", "pfirewall.log")


def _is_public_ipv4(raw: str) -> bool:
    """True if `raw` is a routable IPv4 worth attention. Excludes private,
    loopback, link-local, multicast and malformed strings."""
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_private or ip.is_link_local:
        return False
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False
    return True


def parse_log(path: str) -> Iterator[dict]:
    """Yield one dict per log line. Header lines (#Version, #Software, ...)
    are consumed; the #Fields line is honored so a custom log layout still
    parses correctly.

    Malformed rows are skipped silently — the firewall rotates the log on
    startup and the last line can be truncated.
    """
    if not os.path.exists(path):
        return

    fields = list(DEFAULT_FIELDS)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                if line.lower().startswith("#fields:"):
                    fields = line.split(":", 1)[1].strip().split()
                continue
            parts = line.split()
            if len(parts) < 8:
                continue
            # The W3C layout is positional — pad/truncate to the field list.
            padded = parts[:len(fields)] + ["-"] * max(0, len(fields) - len(parts))
            row = dict(zip(fields, padded))
            ts = _parse_timestamp(row.get("date"), row.get("time"))
            if ts is None:
                continue
            row["_ts"] = ts
            yield row


def _parse_timestamp(date: Optional[str], time: Optional[str]) -> Optional[datetime]:
    if not date or not time or date == "-" or time == "-":
        return None
    try:
        return datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Detections — emit findings in the same shape as pulse/detections.py so the
# save_scan path and the dashboard render them identically.
# ---------------------------------------------------------------------------

def detect_sensitive_port_probes(entries: Iterable[dict]) -> list[dict]:
    """DROP on a sensitive dst-port from a public IP → one finding per
    (src-ip, dst-port) pair. Grouped so a single IP spraying 3389 for an
    hour produces one finding with a hit count, not a hundred."""
    groups: dict[tuple, dict] = {}
    for row in entries:
        if (row.get("action") or "").upper() != "DROP":
            continue
        src = row.get("src-ip") or ""
        if not _is_public_ipv4(src):
            continue
        try:
            port = int(row.get("dst-port") or 0)
        except ValueError:
            continue
        if port not in SENSITIVE_PORTS:
            continue
        key = (src, port)
        g = groups.get(key)
        if g is None:
            g = {
                "src": src,
                "port": port,
                "service": SENSITIVE_PORTS[port],
                "hits": 0,
                "first": row["_ts"],
                "last": row["_ts"],
                "protocol": (row.get("protocol") or "?").upper(),
            }
            groups[key] = g
        g["hits"] += 1
        if row["_ts"] < g["first"]:
            g["first"] = row["_ts"]
        if row["_ts"] > g["last"]:
            g["last"] = row["_ts"]

    findings: list[dict] = []
    for g in groups.values():
        severity = "HIGH" if g["hits"] >= 5 else "MEDIUM"
        findings.append({
            "rule": "Firewall Blocked Sensitive Port",
            "severity": severity,
            "event_id": "FW-SENS",
            "timestamp": g["first"].strftime("%Y-%m-%d %H:%M:%S"),
            "details": (
                f"{g['hits']} blocked {g['protocol']} connection(s) from {g['src']} "
                f"to port {g['port']} ({g['service']}) between "
                f"{g['first'].strftime('%Y-%m-%d %H:%M:%S')} and "
                f"{g['last'].strftime('%H:%M:%S')}. Public exposure of "
                f"{g['service']} is high-risk."
            ),
        })
    return findings


def detect_port_scans(entries: Iterable[dict]) -> list[dict]:
    """A single public IP hitting many distinct destination ports inside a
    short rolling window → port scan. Uses a sliding timestamp window
    keyed by source IP so long-running trickle scans still fire when they
    cross the threshold."""
    per_src: dict[str, list[tuple[datetime, int]]] = defaultdict(list)
    for row in entries:
        if (row.get("action") or "").upper() != "DROP":
            continue
        src = row.get("src-ip") or ""
        if not _is_public_ipv4(src):
            continue
        try:
            port = int(row.get("dst-port") or 0)
        except ValueError:
            continue
        per_src[src].append((row["_ts"], port))

    window = timedelta(minutes=PORT_SCAN_WINDOW_MIN)
    findings: list[dict] = []
    for src, hits in per_src.items():
        hits.sort(key=lambda x: x[0])
        flagged = False
        for i in range(len(hits)):
            j = i
            ports = set()
            while j < len(hits) and hits[j][0] - hits[i][0] <= window:
                ports.add(hits[j][1])
                j += 1
            if len(ports) >= PORT_SCAN_MIN_PORTS:
                first = hits[i][0]
                last = hits[j - 1][0]
                findings.append({
                    "rule": "Firewall Port Scan",
                    "severity": "HIGH",
                    "event_id": "FW-SCAN",
                    "timestamp": first.strftime("%Y-%m-%d %H:%M:%S"),
                    "details": (
                        f"{src} probed {len(ports)} distinct ports in "
                        f"{PORT_SCAN_WINDOW_MIN} minutes (between "
                        f"{first.strftime('%Y-%m-%d %H:%M:%S')} and "
                        f"{last.strftime('%H:%M:%S')}). Classic port-scan pattern."
                    ),
                })
                flagged = True
                break
        if flagged:
            continue

    return findings


def run_firewall_detections(entries: Iterable[dict]) -> list[dict]:
    """Run every firewall-log rule. Consumes the iterator once by
    materializing it — parse_log streams a generator, but the rules need
    multiple passes over the same entries."""
    rows = list(entries)
    findings: list[dict] = []
    findings += detect_sensitive_port_probes(rows)
    findings += detect_port_scans(rows)
    return findings


def scan_firewall_log(path: Optional[str] = None) -> list[dict]:
    """Top-level entry point: open the log and return findings. Missing
    logs return [] silently — many Windows hosts don't enable firewall
    logging by default and we shouldn't fail a scan over it."""
    if path is None:
        path = default_log_path()
    if not os.path.exists(path):
        return []
    return run_firewall_detections(parse_log(path))


def is_available() -> bool:
    """Quick check for CLI integration — lets the caller decide whether
    to surface a status message like "firewall log enabled: yes/no"."""
    if platform.system() != "Windows":
        return False
    return os.path.exists(default_log_path())
