# tests/test_sample_uploads.py
# ----------------------------
# Every file in samples/ must upload, scan, and produce what
# samples/README.md promises.
#
# Two bugs this guards against:
#   1. The browser's .evtx magic check (upload.js) had a wrong byte
#      (0x4C, "L", where "ElfFile" has a lowercase "l", 0x6C), so the
#      upload dialog rejected every real .evtx with "header mismatch"
#      before the server ever saw it.
#   2. The built-in known-good service list was matched against every
#      finding's text, so "Windows Defender real-time protection was
#      disabled" (Antivirus Disabled) matched "windows defender" and was
#      silently dropped.

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pulse import api
from pulse.core.parser import parse_evtx
from pulse.whitelist import filter_whitelist

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = sorted((ROOT / "samples").glob("*.evtx"))
PW = "correct-horse-battery"


def _client_magic():
    js = (ROOT / "pulse" / "static" / "js" / "upload.js").read_text(encoding="utf-8")
    m = re.search(r"const _EVTX_MAGIC = \[([^\]]+)\]", js)
    assert m, "upload.js no longer defines _EVTX_MAGIC"
    return bytes(int(x.strip(), 16) for x in m.group(1).split(","))


def _readme_rows():
    """Parse the samples/README.md table: file -> (events, rules, grade, score)."""
    text = (ROOT / "samples" / "README.md").read_text(encoding="utf-8")
    rows = {}
    for line in text.splitlines():
        m = re.match(r"\|\s*\*\*([\w.-]+\.evtx)\*\*\s*\|.*?\|\s*(\d+)\s*\|(.*)\|\s*\*\*([A-F]) \((\d+)\)\*\*\s*\|\s*$", line)
        if not m:
            continue
        rules = {re.sub(r"\s*\(×\d+\)\s*$", "", part.split("·", 1)[1]).strip()
                 for part in m.group(3).split("<br/>")}
        rows[m.group(1)] = (int(m.group(2)), rules, m.group(4), int(m.group(5)))
    return rows


def test_there_are_samples_and_readme_rows_for_each():
    assert SAMPLES, "samples/*.evtx missing"
    assert {p.name for p in SAMPLES} == set(_readme_rows())


def test_browser_and_server_check_the_same_magic():
    assert _client_magic() == api._EVTX_MAGIC == b"ElfFile\x00"


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda p: p.name)
def test_sample_passes_both_header_checks_and_parses(sample):
    head = sample.read_bytes()[:8]
    assert head == _client_magic(), "the upload dialog would reject this file"
    assert head.startswith(api._EVTX_MAGIC), "the server would reject this file"
    assert parse_evtx(str(sample)), "parsed to zero events"


@pytest.fixture
def client(tmp_path, monkeypatch):
    # The API scan also audits the live Windows Firewall; keep tests off it.
    monkeypatch.setattr(api.firewall_config, "scan_firewall_config", lambda: [])
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    c = TestClient(api.create_app(db_path=str(tmp_path / "t.db"), config_path=str(cfg)))
    assert c.post("/api/auth/signup", json={"email": "a@x.com", "password": PW}).status_code == 200
    return c


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda p: p.name)
def test_sample_uploads_scans_and_matches_the_readme(client, sample):
    events, rules, grade, score = _readme_rows()[sample.name]
    assert len(parse_evtx(str(sample))) == events
    with sample.open("rb") as fh:
        r = client.post("/api/scan", files={"file": (sample.name, fh, "application/octet-stream")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert {f["rule"] for f in body["findings"]} == rules
    assert (body["grade"], body["score"]) == (grade, score)


# ---------------------------------------------------------------------------
# Built-in known-good services only quiet "Service Installed"
# ---------------------------------------------------------------------------

def _f(rule, details):
    return {"rule": rule, "details": details, "severity": "HIGH"}


def test_av_tamper_alert_is_not_whitelisted_by_builtin_names():
    av = _f("Antivirus Disabled", "Windows Defender real-time protection was disabled at 09:02.")
    assert filter_whitelist([av], {}) == [av]


def test_builtin_names_still_quiet_service_installs():
    svc = _f("Service Installed", "New service 'Windows Defender Antivirus Service' was installed.")
    assert filter_whitelist([svc], {}) == []


def test_user_listed_services_still_apply_to_any_rule():
    av = _f("Antivirus Disabled", "Windows Defender real-time protection was disabled.")
    assert filter_whitelist([av], {"services": ["Windows Defender"]}) == []
