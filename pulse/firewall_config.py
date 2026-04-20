# pulse/firewall_config.py
# --------------------------
# Windows Firewall *configuration* auditor. Unlike firewall_parser.py —
# which reads pfirewall.log to find blocked packets after the fact — this
# module inspects the *live* firewall policy for misconfigurations an
# attacker could abuse:
#
#   - a disabled profile (Domain / Private / Public)
#   - an "any-any" allow rule (any protocol, any local port, any remote
#     address, inbound, currently enabled)
#   - an inbound allow rule with an overly broad scope (RemoteIP = Any)
#
# DATA SOURCE
#   `netsh advfirewall show allprofiles`           — profile state
#   `netsh advfirewall firewall show rule name=all` — rule definitions
#
# These are read-only commands and do not require administrator rights.
# On non-Windows hosts (or when netsh is missing) every entry point
# returns [] silently so scan pipelines can call this unconditionally.
#
# PARSERS TAKE STRINGS
#   The parsing functions operate on raw netsh output text so they are
#   trivially unit-testable without a live Windows host. `scan_firewall_config`
#   wires them to real subprocess calls; tests can bypass that layer.

from __future__ import annotations

import platform
import shutil
import subprocess
from datetime import datetime
from typing import Iterable, Optional


# How long we give netsh to reply. 10 s is generous — both commands
# return in well under a second on a healthy host.
_NETSH_TIMEOUT_SEC = 10

# Rules with names starting with these prefixes are Pulse's own managed
# blocks (see pulse/blocker.py). We skip them when looking for any-any
# or overly-broad misconfigurations so Pulse never flags itself.
_PULSE_RULE_PREFIXES = ("Pulse-managed:",)


def is_available() -> bool:
    """True if the live firewall config can be queried on this host.
    Non-Windows or a missing `netsh` executable → False; callers then
    skip the check entirely instead of surfacing a confusing error."""
    if platform.system() != "Windows":
        return False
    return shutil.which("netsh") is not None


# ---------------------------------------------------------------------------
# netsh wrappers
# ---------------------------------------------------------------------------

def _run_netsh(args: list[str]) -> Optional[str]:
    """Run `netsh <args>` and return its stdout. Returns None on any
    failure (non-Windows host, missing binary, non-zero exit, timeout)
    so the caller can short-circuit to an empty finding list."""
    if not is_available():
        return None
    try:
        result = subprocess.run(
            ["netsh"] + args,
            capture_output=True,
            text=True,
            timeout=_NETSH_TIMEOUT_SEC,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout or ""


def fetch_profiles_output() -> Optional[str]:
    """Live output of `netsh advfirewall show allprofiles`."""
    return _run_netsh(["advfirewall", "show", "allprofiles"])


def fetch_rules_output() -> Optional[str]:
    """Live output of `netsh advfirewall firewall show rule name=all verbose`.
    `verbose` adds the RemoteIP / LocalIP / Grouping lines we need to
    spot overly-broad scope."""
    return _run_netsh([
        "advfirewall", "firewall", "show", "rule",
        "name=all", "verbose",
    ])


# ---------------------------------------------------------------------------
# Parsers — operate on plain text, no subprocess.
# ---------------------------------------------------------------------------

def parse_profiles(text: str) -> list[dict]:
    """
    Parse `netsh advfirewall show allprofiles` into a list of dicts:
        [{"profile": "Domain", "enabled": False}, ...]

    netsh prints one stanza per profile, each opening with a header like
    "Domain Profile Settings:" followed by "State ON" / "State OFF" on
    its own line. We tolerate localized spacing and stray blank lines.
    """
    profiles: list[dict] = []
    current: Optional[str] = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        lower = line.lower()
        # Header. Matches "Domain Profile Settings:" / "Private Profile ..."
        # / "Public Profile ...". We key off the leading word so future
        # Windows builds that tweak the wording still match.
        if lower.endswith("profile settings:"):
            head = line.split()[0]
            current = head
            continue
        # State line — tolerate "State                   ON" / "State: ON".
        if current and lower.startswith("state"):
            token = line.split()[-1].strip().rstrip(":").upper()
            if token in {"ON", "OFF"}:
                profiles.append({
                    "profile": current,
                    "enabled": token == "ON",
                })
                current = None
    return profiles


def parse_rules(text: str) -> list[dict]:
    """
    Parse `netsh advfirewall firewall show rule name=all verbose` into
    a list of rule dicts. Each stanza starts with "Rule Name:" followed
    by a line of dashes and then key/value lines; a blank line (or the
    next "Rule Name:") marks the end of a stanza.

    Fields captured (all strings, normalized to Title Case values where
    netsh prints them that way):
        name, enabled, direction, profiles, action, protocol,
        local_port, remote_port, local_ip, remote_ip, grouping
    """
    rules: list[dict] = []
    current: Optional[dict] = None

    def _flush():
        nonlocal current
        if current and current.get("name"):
            rules.append(current)
        current = None

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        # The dashes that appear directly under "Rule Name:" are
        # decoration, not a stanza separator — skip them without
        # touching `current`.
        if set(stripped) == {"-"}:
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key_norm = key.strip().lower()
        value = value.strip()
        if key_norm == "rule name":
            _flush()
            current = {"name": value}
            continue
        if current is None:
            continue
        if key_norm == "enabled":
            current["enabled"] = value.lower() == "yes"
        elif key_norm == "direction":
            current["direction"] = value  # "In" / "Out"
        elif key_norm == "profiles":
            current["profiles"] = value   # "Domain,Private,Public" etc.
        elif key_norm == "action":
            current["action"] = value     # "Allow" / "Block"
        elif key_norm == "protocol":
            current["protocol"] = value   # "Any" / "TCP" / ...
        elif key_norm == "localport":
            current["local_port"] = value
        elif key_norm == "remoteport":
            current["remote_port"] = value
        elif key_norm == "localip":
            current["local_ip"] = value
        elif key_norm == "remoteip":
            current["remote_ip"] = value
        elif key_norm == "grouping":
            current["grouping"] = value
    _flush()
    return rules


# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def detect_disabled_profiles(profiles: Iterable[dict]) -> list[dict]:
    """One finding per profile whose State is OFF. Severity is HIGH —
    leaving any profile disabled on a connected host removes packet
    filtering entirely for that network category."""
    findings: list[dict] = []
    ts = _now_iso()
    for p in profiles:
        if p.get("enabled"):
            continue
        name = p.get("profile") or "Unknown"
        findings.append({
            "rule":      "Firewall Profile Disabled",
            "severity":  "HIGH",
            "event_id":  "FW-CFG",
            "timestamp": ts,
            "details": (
                f"Windows Firewall '{name}' profile is OFF. Inbound "
                f"traffic matching this profile is not filtered — "
                f"re-enable via Windows Security → Firewall & network "
                f"protection, or `netsh advfirewall set {name.lower()}profile state on`."
            ),
        })
    return findings


def _is_any(value: Optional[str]) -> bool:
    """netsh emits 'Any' for wide-open rule fields. Treat empty or a
    literal 'Any' as wide-open — both mean 'no constraint'."""
    if value is None:
        return True
    v = value.strip().lower()
    return v == "" or v == "any"


def _is_pulse_rule(name: str) -> bool:
    return any(name.startswith(p) for p in _PULSE_RULE_PREFIXES)


def detect_any_any_rules(rules: Iterable[dict]) -> list[dict]:
    """
    Flag every ENABLED inbound ALLOW rule that matches on Any protocol,
    Any local port, AND Any remote IP. A rule that wide-open is
    effectively no filter at all on the inbound side.

    Outbound rules are not flagged here — most applications legitimately
    need broad outbound access. Pulse-managed rules are skipped.
    """
    findings: list[dict] = []
    ts = _now_iso()
    for r in rules:
        if not r.get("enabled", False):
            continue
        name = r.get("name") or ""
        if _is_pulse_rule(name):
            continue
        direction = (r.get("direction") or "").lower()
        if direction != "in":
            continue
        action = (r.get("action") or "").lower()
        if action != "allow":
            continue
        if not (
            _is_any(r.get("protocol"))
            and _is_any(r.get("local_port"))
            and _is_any(r.get("remote_ip"))
        ):
            continue
        findings.append({
            "rule":      "Firewall Any-Any Allow Rule",
            "severity":  "MEDIUM",
            "event_id":  "FW-CFG",
            "timestamp": ts,
            "details": (
                f"Inbound allow rule '{name}' matches any protocol, any "
                f"port, and any remote address. This rule removes all "
                f"inbound filtering for traffic that matches it. Narrow "
                f"the protocol/port/source or disable the rule if it is "
                f"no longer needed."
            ),
        })
    return findings


def detect_overly_broad_scope(rules: Iterable[dict]) -> list[dict]:
    """
    Inbound ALLOW rules that target a *specific* port but accept from
    *any* remote IP are a common accident: a user opens RDP / SMB /
    WinRM for themselves and leaves the source unrestricted. We flag
    these only when the port is on the sensitive list so we don't spam
    legitimate service rules (mDNS, etc.).

    Rules already flagged by `detect_any_any_rules` are skipped here so
    the same rule isn't double-reported.
    """
    # Ports whose inbound exposure is worth flagging when RemoteIP=Any.
    sensitive_ports = {
        "22":   "SSH",
        "23":   "Telnet",
        "135":  "RPC",
        "139":  "NetBIOS",
        "445":  "SMB",
        "1433": "MSSQL",
        "3306": "MySQL",
        "3389": "RDP",
        "5432": "PostgreSQL",
        "5900": "VNC",
        "5985": "WinRM",
        "5986": "WinRM (TLS)",
    }

    findings: list[dict] = []
    ts = _now_iso()
    for r in rules:
        if not r.get("enabled", False):
            continue
        name = r.get("name") or ""
        if _is_pulse_rule(name):
            continue
        if (r.get("direction") or "").lower() != "in":
            continue
        if (r.get("action") or "").lower() != "allow":
            continue
        # Skip wide-open rules — detect_any_any_rules handles those.
        if _is_any(r.get("protocol")) and _is_any(r.get("local_port")):
            continue
        if not _is_any(r.get("remote_ip")):
            continue
        local_port = (r.get("local_port") or "").strip()
        # Split on common separators netsh might use for a port list.
        port_tokens = [p.strip() for p in local_port.replace(";", ",").split(",") if p.strip()]
        matched = [p for p in port_tokens if p in sensitive_ports]
        if not matched:
            continue
        service_list = ", ".join(f"{p} ({sensitive_ports[p]})" for p in matched)
        findings.append({
            "rule":      "Firewall Overly Broad Scope",
            "severity":  "MEDIUM",
            "event_id":  "FW-CFG",
            "timestamp": ts,
            "details": (
                f"Inbound allow rule '{name}' opens sensitive port(s) "
                f"{service_list} to any remote IP. Restrict the rule's "
                f"RemoteIP to a specific subnet or management host, or "
                f"require a VPN / jump host for this service."
            ),
        })
    return findings


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def run_firewall_config_detections(
    profiles_text: Optional[str],
    rules_text: Optional[str],
) -> list[dict]:
    """Pure-data entry point. Takes already-fetched netsh output (either
    string is allowed to be None) and returns the combined findings."""
    profiles = parse_profiles(profiles_text or "")
    rules = parse_rules(rules_text or "")
    findings: list[dict] = []
    findings += detect_disabled_profiles(profiles)
    findings += detect_any_any_rules(rules)
    findings += detect_overly_broad_scope(rules)
    return findings


def scan_firewall_config() -> list[dict]:
    """Top-level entry point. Queries netsh live and returns findings.
    Returns [] on non-Windows hosts or when netsh cannot be run — the
    caller does not have to guard for OS."""
    if not is_available():
        return []
    profiles_text = fetch_profiles_output()
    rules_text = fetch_rules_output()
    if profiles_text is None and rules_text is None:
        return []
    return run_firewall_config_detections(profiles_text, rules_text)
