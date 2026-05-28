# test_sigma_runtime.py
# ----------------------
# Sprint 8 — SIGMA rule import, Phase 3. Covers ``run_sigma_rules`` and
# its wiring into ``run_all_detections``.

import os
import tempfile

import pytest

from pulse import database
from pulse.core.detections import run_all_detections
from pulse.core.sigma import parse_sigma, run_sigma_rules


_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _event(event_id, **fields):
    data = "".join(
        f'<Data Name="{k}">{v}</Data>' for k, v in fields.items() if v is not None
    )
    xml = (
        f'<Event xmlns="{_NS}">'
        f'<System><EventID>{event_id}</EventID></System>'
        f'<EventData>{data}</EventData>'
        f'</Event>'
    )
    return {
        "event_id":   event_id,
        "timestamp":  "2026-05-28T09:00:00.000Z",
        "data":       xml,
        "record_num": 1,
        "computer":   "TEST-PC",
    }


_YAML = """
title: Suspicious PowerShell Encoded Command
description: Detects encoded PowerShell commands often used by malware
tags:
  - attack.execution
  - attack.t1059.001
detection:
  selection:
    EventID: 4688
    CommandLine|contains: '-EncodedCommand'
  condition: selection
level: high
"""


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database.init_db(path)
    try:
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _stored_row(db_path, rid):
    return database.get_sigma_rule(db_path, rid)


# ---------------------------------------------------------------------------
# run_sigma_rules direct
# ---------------------------------------------------------------------------

def test_run_sigma_rules_emits_pulse_shaped_findings(db_path):
    rid = database.save_sigma_rule(
        db_path, organization_id=1,
        parsed_rule=parse_sigma(_YAML), yaml_source=_YAML,
    )
    rows = database.list_sigma_rules(db_path, organization_id=1,
                                      enabled_only=True)
    events = [
        _event(4688, CommandLine="powershell -EncodedCommand SGVsbG8="),
        _event(4624, CommandLine="powershell -EncodedCommand SGVsbG8="),  # wrong id
        _event(4688, CommandLine="notepad.exe"),                          # wrong cmd
    ]
    findings = run_sigma_rules(events, rows)
    assert len(findings) == 1
    f = findings[0]
    assert f["rule"] == "Suspicious PowerShell Encoded Command"
    assert f["severity"] == "HIGH"
    assert f["mitre"] == "T1059.001"
    assert f["event_id"] == 4688
    assert "raw_xml" in f and "<Event" in f["raw_xml"]


def test_run_sigma_rules_skips_corrupt_compiled_json(db_path):
    """A broken stored row must not crash the whole batch."""
    rows = [
        {"name": "broken", "severity": "HIGH", "mitre": None,
         "description": "", "compiled_json": "not valid json {"},
    ]
    # Should return empty, not raise.
    assert run_sigma_rules([_event(4688)], rows) == []


def test_run_sigma_rules_no_events_or_no_rules_returns_empty(db_path):
    rid = database.save_sigma_rule(
        db_path, organization_id=1,
        parsed_rule=parse_sigma(_YAML), yaml_source=_YAML,
    )
    rows = database.list_sigma_rules(db_path, organization_id=1,
                                      enabled_only=True)
    assert run_sigma_rules([], rows) == []
    assert run_sigma_rules([_event(4688)], []) == []


# ---------------------------------------------------------------------------
# run_all_detections wiring
# ---------------------------------------------------------------------------

def test_run_all_detections_includes_sigma_when_passed(db_path):
    database.save_sigma_rule(
        db_path, organization_id=1,
        parsed_rule=parse_sigma(_YAML), yaml_source=_YAML,
    )
    rows = database.list_sigma_rules(db_path, organization_id=1,
                                      enabled_only=True)
    events = [_event(4688, CommandLine="powershell -EncodedCommand x")]
    f_without = run_all_detections(events)
    f_with = run_all_detections(events, sigma_rules=rows)
    extra = [f for f in f_with if f.get("rule") not in {x.get("rule") for x in f_without}]
    assert any(f["rule"] == "Suspicious PowerShell Encoded Command"
               for f in extra)


def test_run_all_detections_skips_sigma_when_none(db_path):
    events = [_event(4688, CommandLine="powershell -EncodedCommand x")]
    findings = run_all_detections(events)
    assert all(f.get("rule") != "Suspicious PowerShell Encoded Command"
               for f in findings)


def test_disabled_sigma_rules_do_not_fire(db_path):
    rid = database.save_sigma_rule(
        db_path, organization_id=1,
        parsed_rule=parse_sigma(_YAML), yaml_source=_YAML,
    )
    database.set_sigma_rule_enabled(db_path, rid, False)
    rows = database.list_sigma_rules(db_path, organization_id=1,
                                      enabled_only=True)
    assert rows == []
    events = [_event(4688, CommandLine="powershell -EncodedCommand x")]
    findings = run_all_detections(events, sigma_rules=rows)
    assert all(f.get("rule") != "Suspicious PowerShell Encoded Command"
               for f in findings)
