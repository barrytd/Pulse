# test_parser_synth.py
# --------------------
# Coverage for the Pulse-synthetic .evtx ingest path added 2026-05-27.
#
# The synth-format header is `ElfFile\x00` + `PULSE-SYNTH-v1\n` followed
# by a UTF-8 JSON event list. The standard 8-byte magic comes first so
# the upload validator (which only checks bytes 0–8) still accepts the
# file; the sentinel after the magic is what routes the parser to the
# JSON reader instead of falling through to wevtutil / python-evtx.

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from pulse.core.parser import parse_evtx

_MAGIC = b"ElfFile\x00"
_MARKER = b"PULSE-SYNTH-v1\n"


def _write(tmp_path, body):
    """Write `body` to a temp .evtx file and return the path."""
    path = tmp_path / "synth.evtx"
    path.write_bytes(body)
    return str(path)


def _synth_file(tmp_path, events):
    return _write(tmp_path, _MAGIC + _MARKER + json.dumps(events).encode("utf-8"))


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_synth_round_trip(tmp_path):
    """Single event with every field set survives the round-trip."""
    payload = [{
        "event_id":   4625,
        "timestamp":  "2026-05-27T09:00:00.000Z",
        "data":       "<Event><EventID>4625</EventID></Event>",
        "record_num": 1,
        "computer":   "DC-01",
    }]
    out = parse_evtx(_synth_file(tmp_path, payload))
    assert len(out) == 1
    assert out[0]["event_id"] == 4625
    assert out[0]["timestamp"] == "2026-05-27T09:00:00.000Z"
    assert out[0]["computer"] == "DC-01"
    assert out[0]["record_num"] == 1
    assert "<EventID>4625</EventID>" in out[0]["data"]


def test_synth_multiple_events_preserve_order(tmp_path):
    payload = [
        {"event_id": 4625, "timestamp": "2026-05-27T09:00:00Z",
         "data": "<a/>", "record_num": 1, "computer": "H"},
        {"event_id": 4624, "timestamp": "2026-05-27T09:01:00Z",
         "data": "<b/>", "record_num": 2, "computer": "H"},
        {"event_id": 4720, "timestamp": "2026-05-27T09:02:00Z",
         "data": "<c/>", "record_num": 3, "computer": "H"},
    ]
    out = parse_evtx(_synth_file(tmp_path, payload))
    assert [e["event_id"] for e in out] == [4625, 4624, 4720]
    assert [e["record_num"] for e in out] == [1, 2, 3]


def test_synth_since_filter(tmp_path):
    """`since` parameter must drop older events from the synth path the
    same way it drops them from the binary parsers."""
    payload = [
        {"event_id": 4625, "timestamp": "2026-05-26T09:00:00Z",
         "data": "<old/>", "record_num": 1, "computer": "H"},
        {"event_id": 4625, "timestamp": "2026-05-27T09:00:00Z",
         "data": "<new/>", "record_num": 2, "computer": "H"},
    ]
    since = datetime(2026, 5, 27, tzinfo=timezone.utc)
    out = parse_evtx(_synth_file(tmp_path, payload), since=since)
    assert len(out) == 1
    assert "<new/>" in out[0]["data"]


def test_synth_missing_optional_fields_default_safely(tmp_path):
    """Pulse's binary parsers emit "" / 0 for missing fields rather than
    raising; the synth path matches that contract."""
    payload = [{"event_id": 1102}]  # No timestamp, data, record_num, or computer
    out = parse_evtx(_synth_file(tmp_path, payload))
    assert len(out) == 1
    assert out[0]["event_id"] == 1102
    assert out[0]["timestamp"] == ""
    assert out[0]["data"] == ""
    assert out[0]["record_num"] == 0
    assert out[0]["computer"] == ""


# ---------------------------------------------------------------------------
# Negative cases — the synth path must fail closed
# ---------------------------------------------------------------------------

def test_synth_marker_required(tmp_path):
    """`ElfFile\\x00` alone (without the synth marker) must NOT take the
    synth code path — it falls through to the binary parser, which sees
    garbage and returns []. This is the security guarantee that prevents
    a renamed-junk upload from being silently treated as JSON."""
    body = _MAGIC + b"\x00" * 4088 + b'[{"event_id": 4625}]'
    out = parse_evtx(_write(tmp_path, body))
    assert out == []


def test_synth_bad_json_returns_empty(tmp_path):
    """A file with the right magic + marker but malformed JSON returns
    [] rather than raising — matches the binary-parser tolerance."""
    body = _MAGIC + _MARKER + b"{this is not valid json"
    assert parse_evtx(_write(tmp_path, body)) == []


def test_synth_non_list_payload_returns_empty(tmp_path):
    """The payload must be a JSON list; a dict / scalar / null returns []."""
    body = _MAGIC + _MARKER + b'{"event_id": 4625}'
    assert parse_evtx(_write(tmp_path, body)) == []


def test_synth_non_dict_entries_are_skipped(tmp_path):
    """Mixed payload: dicts are kept, non-dict entries are dropped
    (defense against hand-edited samples with stray nulls)."""
    body = _MAGIC + _MARKER + json.dumps([
        {"event_id": 4625},
        "not a dict",
        None,
        {"event_id": 4624},
    ]).encode("utf-8")
    out = parse_evtx(_write(tmp_path, body))
    assert [e["event_id"] for e in out] == [4625, 4624]


# ---------------------------------------------------------------------------
# End-to-end against the real shipped sample files
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename,expected_rule", [
    ("brute-force-server.evtx",          "Brute Force Attempt"),
    ("credential-theft-workstation.evtx", "Credential Dumping"),
    ("persistence-malware.evtx",          "Service Installed"),
    ("lateral-movement-dc.evtx",          "DCSync Attempt"),
])
def test_shipped_samples_parse_and_trigger_canonical_rule(filename, expected_rule):
    """Every sample file in samples/ must parse cleanly AND fire the
    rule it advertises in samples/README.md. Catches regressions where
    a refactor breaks the synth path or a sample drifts out of sync
    with the detection logic."""
    from pulse.core.detections import run_all_detections
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(repo_root, "samples", filename)
    if not os.path.isfile(path):
        pytest.skip(f"sample {filename} not present (run scripts/generate_sample_evtx.py)")

    events = parse_evtx(path)
    assert len(events) > 0, f"{filename} parsed to zero events"

    findings = run_all_detections(events)
    rules = {f.get("rule") for f in findings}
    assert expected_rule in rules, (
        f"{filename} did not trigger {expected_rule!r}. Got: {sorted(rules)}"
    )
