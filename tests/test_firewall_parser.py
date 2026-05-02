# test_firewall_parser.py
# ------------------------
# Tests for pulse/firewall_parser.py. Uses tempfile to write a throwaway
# pfirewall.log so the tests don't depend on the host firewall being
# configured, and are safe to run on any OS.

import os
import tempfile

import pytest

from pulse.firewall import firewall_parser as fw


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

HEADER = (
    "#Version: 1.5\n"
    "#Software: Microsoft Windows Firewall\n"
    "#Time Format: Local\n"
    "#Fields: date time action protocol src-ip dst-ip src-port dst-port size "
    "tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid\n"
    "\n"
)


def _write_log(lines):
    fd, path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(HEADER)
        for ln in lines:
            fh.write(ln.rstrip() + "\n")
    return path


def _drop(path):
    try:
        os.remove(path)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# parse_log
# ---------------------------------------------------------------------------

def test_parse_log_skips_headers_and_parses_fields():
    path = _write_log([
        "2026-04-18 10:23:45 DROP TCP 203.0.113.45 192.168.1.10 4444 3389 0 - 0 0 0 - - - RECEIVE -",
    ])
    try:
        rows = list(fw.parse_log(path))
        assert len(rows) == 1
        r = rows[0]
        assert r["action"] == "DROP"
        assert r["src-ip"] == "203.0.113.45"
        assert r["dst-port"] == "3389"
        assert r["_ts"].year == 2026
    finally:
        _drop(path)


def test_parse_log_skips_malformed_rows():
    path = _write_log([
        "2026-04-18 10:23:45 DROP TCP 203.0.113.45 192.168.1.10 4444 3389 0",  # ok
        "garbage",                                                             # malformed
        "2026-04-18 99:99:99 DROP TCP 8.8.8.8 1.2.3.4 1 2 0",                  # bad ts
        "2026-04-18 10:23:46 DROP TCP 8.8.8.8 192.168.1.10 443 445 0",         # ok
    ])
    try:
        rows = list(fw.parse_log(path))
        assert len(rows) == 2
    finally:
        _drop(path)


def test_parse_log_missing_file_returns_empty():
    rows = list(fw.parse_log("/nonexistent/pfirewall.log"))
    assert rows == []


# ---------------------------------------------------------------------------
# _is_public_ipv4
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip,expected", [
    ("8.8.8.8",      True),
    ("203.0.113.5",  False),   # TEST-NET-3 → reserved
    ("127.0.0.1",    False),
    ("10.0.0.5",     False),
    ("192.168.1.1",  False),
    ("169.254.1.1",  False),
    ("0.0.0.0",      False),
    ("not-an-ip",    False),
    ("-",            False),
])
def test_is_public_ipv4(ip, expected):
    assert fw._is_public_ipv4(ip) is expected


# ---------------------------------------------------------------------------
# detect_sensitive_port_probes
# ---------------------------------------------------------------------------

def test_sensitive_port_probe_single_hit_is_medium():
    path = _write_log([
        "2026-04-18 10:23:45 DROP TCP 8.8.8.8 192.168.1.10 4444 3389 0 - 0 0 0 - - - RECEIVE -",
    ])
    try:
        findings = fw.run_firewall_detections(fw.parse_log(path))
        probes = [f for f in findings if f["rule"] == "Firewall Blocked Sensitive Port"]
        assert len(probes) == 1
        assert probes[0]["severity"] == "MEDIUM"
        assert "8.8.8.8" in probes[0]["details"]
        assert "RDP" in probes[0]["details"]
    finally:
        _drop(path)


def test_sensitive_port_probe_many_hits_upgrades_to_high():
    lines = []
    for i in range(6):
        lines.append(
            f"2026-04-18 10:23:{40+i:02d} DROP TCP 8.8.8.8 192.168.1.10 4444 3389 0 - 0 0 0 - - - RECEIVE -"
        )
    path = _write_log(lines)
    try:
        findings = fw.run_firewall_detections(fw.parse_log(path))
        probes = [f for f in findings if f["rule"] == "Firewall Blocked Sensitive Port"]
        assert len(probes) == 1
        assert probes[0]["severity"] == "HIGH"
        assert "6" in probes[0]["details"]   # hit count surfaces in the text
    finally:
        _drop(path)


def test_sensitive_port_probe_ignores_private_source():
    path = _write_log([
        "2026-04-18 10:23:45 DROP TCP 192.168.1.5 192.168.1.10 4444 3389 0 - 0 0 0 - - - RECEIVE -",
    ])
    try:
        findings = fw.run_firewall_detections(fw.parse_log(path))
        assert findings == []
    finally:
        _drop(path)


def test_sensitive_port_probe_ignores_allow_lines():
    path = _write_log([
        "2026-04-18 10:23:45 ALLOW TCP 8.8.8.8 192.168.1.10 4444 3389 0 - 0 0 0 - - - RECEIVE -",
    ])
    try:
        findings = fw.run_firewall_detections(fw.parse_log(path))
        assert findings == []
    finally:
        _drop(path)


def test_sensitive_port_probe_ignores_non_sensitive_ports():
    # Port 9999 is not in SENSITIVE_PORTS, and a single hit isn't enough
    # to cross the port-scan threshold, so we expect zero findings.
    path = _write_log([
        "2026-04-18 10:23:45 DROP TCP 8.8.8.8 192.168.1.10 4444 9999 0 - 0 0 0 - - - RECEIVE -",
    ])
    try:
        findings = fw.run_firewall_detections(fw.parse_log(path))
        assert findings == []
    finally:
        _drop(path)


# ---------------------------------------------------------------------------
# detect_port_scans
# ---------------------------------------------------------------------------

def test_port_scan_fires_at_threshold():
    lines = []
    for i in range(fw.PORT_SCAN_MIN_PORTS):
        port = 10000 + i
        lines.append(
            f"2026-04-18 10:23:{i:02d} DROP TCP 8.8.8.8 192.168.1.10 4444 {port} 0 - 0 0 0 - - - RECEIVE -"
        )
    path = _write_log(lines)
    try:
        findings = fw.run_firewall_detections(fw.parse_log(path))
        scans = [f for f in findings if f["rule"] == "Firewall Port Scan"]
        assert len(scans) == 1
        assert scans[0]["severity"] == "HIGH"
        assert "8.8.8.8" in scans[0]["details"]
    finally:
        _drop(path)


def test_port_scan_does_not_fire_below_threshold():
    lines = []
    for i in range(fw.PORT_SCAN_MIN_PORTS - 1):
        port = 10000 + i
        lines.append(
            f"2026-04-18 10:23:{i:02d} DROP TCP 8.8.8.8 192.168.1.10 4444 {port} 0 - 0 0 0 - - - RECEIVE -"
        )
    path = _write_log(lines)
    try:
        findings = fw.run_firewall_detections(fw.parse_log(path))
        scans = [f for f in findings if f["rule"] == "Firewall Port Scan"]
        assert scans == []
    finally:
        _drop(path)


def test_port_scan_ignores_private_source():
    lines = []
    for i in range(fw.PORT_SCAN_MIN_PORTS):
        port = 10000 + i
        lines.append(
            f"2026-04-18 10:23:{i:02d} DROP TCP 10.0.0.5 192.168.1.10 4444 {port} 0 - 0 0 0 - - - RECEIVE -"
        )
    path = _write_log(lines)
    try:
        findings = fw.run_firewall_detections(fw.parse_log(path))
        assert findings == []
    finally:
        _drop(path)


# ---------------------------------------------------------------------------
# scan_firewall_log — top-level entry
# ---------------------------------------------------------------------------

def test_scan_firewall_log_returns_empty_when_missing():
    assert fw.scan_firewall_log("/nonexistent/pfirewall.log") == []


def test_scan_firewall_log_findings_have_required_fields():
    path = _write_log([
        "2026-04-18 10:23:45 DROP TCP 8.8.8.8 192.168.1.10 4444 3389 0 - 0 0 0 - - - RECEIVE -",
    ])
    try:
        findings = fw.scan_firewall_log(path)
        assert len(findings) >= 1
        f = findings[0]
        # Same shape as other detections — rule/severity/event_id/timestamp/details.
        for key in ("rule", "severity", "event_id", "timestamp", "details"):
            assert key in f, f"missing {key} in finding"
        assert f["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    finally:
        _drop(path)


# ---------------------------------------------------------------------------
# detect_repeated_drops — sustained probing from a single source
# ---------------------------------------------------------------------------

def test_detect_repeated_drops_fires_above_threshold():
    """11+ drops from the same public IP -> one finding with HIT count."""
    src = "1.2.3.4"
    lines = [
        # 12 drops on 12 different ports (deliberately under PORT_SCAN
        # threshold so port-scan doesn't ALSO fire) — we want only the
        # repeated-drops rule for this assertion.
        f"2026-04-30 10:00:{i:02d} DROP TCP {src} 192.168.1.10 4444 {1000 + i} 0 - 0 0 0 0 0 0 - - 0"
        for i in range(12)
    ]
    path = _write_log(lines)
    try:
        findings = fw.detect_repeated_drops(fw.parse_log(path))
        assert len(findings) == 1
        f = findings[0]
        assert f["rule"] == "Firewall Repeated Drops"
        assert f["src"] == src
        assert f["hits"] == 12
    finally:
        _drop(path)


def test_detect_repeated_drops_skips_below_threshold():
    """10 drops <= threshold -> nothing fires (the threshold is `>`, not `>=`)."""
    src = "1.2.3.5"
    lines = [
        f"2026-04-30 10:00:{i:02d} DROP TCP {src} 192.168.1.10 4444 {1000 + i} 0 - 0 0 0 0 0 0 - - 0"
        for i in range(10)
    ]
    path = _write_log(lines)
    try:
        assert fw.detect_repeated_drops(fw.parse_log(path)) == []
    finally:
        _drop(path)


def test_detect_repeated_drops_ignores_private_sources():
    """LAN sources never count toward the noise heuristic — every box
    on a busy network would otherwise show up."""
    lines = [
        f"2026-04-30 10:00:{i:02d} DROP TCP 10.0.0.5 192.168.1.10 4444 {1000 + i} 0 - 0 0 0 0 0 0 - - 0"
        for i in range(20)
    ]
    path = _write_log(lines)
    try:
        assert fw.detect_repeated_drops(fw.parse_log(path)) == []
    finally:
        _drop(path)


# ---------------------------------------------------------------------------
# Bundled `tests/sample-pfirewall.log` fixture — a real-shaped log with a
# mix of LAN ALLOW chatter, sensitive-port probes from multiple public
# sources, a 12-port scan from one IP, and 15 repeated drops from that
# same IP. Locks in expected counts so a future parser regression that
# silently drops rows or misclassifies actions surfaces immediately.
# ---------------------------------------------------------------------------

SAMPLE_LOG_PATH = os.path.join(os.path.dirname(__file__), "sample-pfirewall.log")


def test_sample_log_parses_to_expected_row_count():
    """97 rows, 35 ALLOW + 62 DROP — anything else means the parser
    silently dropped lines (e.g. a header-fields regression)."""
    rows = list(fw.parse_log(SAMPLE_LOG_PATH))
    assert len(rows) == 97
    actions = {}
    for r in rows:
        a = (r.get("action") or "").upper()
        actions[a] = actions.get(a, 0) + 1
    assert actions == {"ALLOW": 35, "DROP": 62}


def test_sample_log_fires_every_detection_rule():
    """The fixture is hand-tuned so all three rules co-fire. If a future
    detection refactor breaks one, we catch it here."""
    rows = list(fw.parse_log(SAMPLE_LOG_PATH))
    findings = fw.run_firewall_detections(rows)
    rules = {f["rule"] for f in findings}
    assert "Firewall Blocked Sensitive Port" in rules
    assert "Firewall Port Scan"               in rules
    assert "Firewall Repeated Drops"          in rules


def test_sample_log_port_scan_identifies_correct_source():
    """One IP (185.220.101.47) deliberately probes 12 distinct ports in
    a 5-minute window — that's the canonical scan signature."""
    rows = list(fw.parse_log(SAMPLE_LOG_PATH))
    scans = fw.detect_port_scans(rows)
    sources = [
        # parse the first IP token out of the details — the rule emits
        # "<ip> probed <n> distinct ports..."
        f["details"].split()[0] for f in scans
    ]
    assert "185.220.101.47" in sources
