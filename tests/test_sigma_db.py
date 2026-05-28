# test_sigma_db.py
# -----------------
# Sprint 8 — SIGMA rule import, Phase 2. Covers the sigma_rules table
# helpers in pulse/database.py: save / list / get / set_enabled / delete,
# plus multi-tenant scoping.

import os
import tempfile

import pytest

from pulse import database
from pulse.core.sigma import parse_sigma


_YAML_A = """
title: Suspicious PowerShell Encoded Command
description: Detects encoded PowerShell commands often used by malware
tags:
  - attack.execution
  - attack.t1059.001
detection:
  selection:
    EventID: 4688
    CommandLine|contains:
      - '-EncodedCommand'
  condition: selection
level: high
"""

_YAML_B = """
title: Mimikatz Command Line
description: Looks for mimikatz invocations on the command line
tags:
  - attack.credential_access
  - attack.t1003
detection:
  selection:
    CommandLine|contains: mimikatz
  condition: selection
level: critical
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


# ---------------------------------------------------------------------------
# save / list / get
# ---------------------------------------------------------------------------

def test_save_round_trips_parsed_rule(db_path):
    rule = parse_sigma(_YAML_A)
    rid = database.save_sigma_rule(
        db_path,
        organization_id=1,
        parsed_rule=rule,
        yaml_source=_YAML_A,
        created_by=42,
    )
    assert isinstance(rid, int) and rid > 0

    fetched = database.get_sigma_rule(db_path, rid)
    assert fetched["name"] == "Suspicious PowerShell Encoded Command"
    assert fetched["severity"] == "HIGH"
    assert fetched["mitre"] == "T1059.001"
    assert fetched["enabled"] is True
    assert fetched["origin"] == "sigma-import"
    assert fetched["organization_id"] == 1
    assert fetched["created_by"] == 42
    assert "EncodedCommand" in fetched["yaml_source"]
    # compiled_json must be valid JSON the matcher can consume
    import json
    compiled = json.loads(fetched["compiled_json"])
    assert "selections" in compiled
    assert compiled["condition"]["op"] == "ref"


def test_list_returns_newest_first(db_path):
    r1 = parse_sigma(_YAML_A)
    r2 = parse_sigma(_YAML_B)
    id1 = database.save_sigma_rule(db_path, organization_id=1,
                                    parsed_rule=r1, yaml_source=_YAML_A)
    id2 = database.save_sigma_rule(db_path, organization_id=1,
                                    parsed_rule=r2, yaml_source=_YAML_B)
    rows = database.list_sigma_rules(db_path, organization_id=1)
    assert [r["id"] for r in rows] == [id2, id1]


def test_get_unknown_returns_none(db_path):
    assert database.get_sigma_rule(db_path, 9999) is None


# ---------------------------------------------------------------------------
# enable / disable
# ---------------------------------------------------------------------------

def test_set_enabled_toggles_flag(db_path):
    rid = database.save_sigma_rule(
        db_path, organization_id=1,
        parsed_rule=parse_sigma(_YAML_A), yaml_source=_YAML_A,
    )
    assert database.set_sigma_rule_enabled(db_path, rid, False) is True
    assert database.get_sigma_rule(db_path, rid)["enabled"] is False
    assert database.set_sigma_rule_enabled(db_path, rid, True) is True
    assert database.get_sigma_rule(db_path, rid)["enabled"] is True


def test_enabled_only_filter(db_path):
    a = database.save_sigma_rule(db_path, organization_id=1,
                                  parsed_rule=parse_sigma(_YAML_A),
                                  yaml_source=_YAML_A)
    b = database.save_sigma_rule(db_path, organization_id=1,
                                  parsed_rule=parse_sigma(_YAML_B),
                                  yaml_source=_YAML_B)
    database.set_sigma_rule_enabled(db_path, a, False)
    rows = database.list_sigma_rules(db_path, organization_id=1,
                                      enabled_only=True)
    assert [r["id"] for r in rows] == [b]


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

def test_delete_removes_row(db_path):
    rid = database.save_sigma_rule(
        db_path, organization_id=1,
        parsed_rule=parse_sigma(_YAML_A), yaml_source=_YAML_A,
    )
    assert database.delete_sigma_rule(db_path, rid) is True
    assert database.get_sigma_rule(db_path, rid) is None
    # Deleting an already-gone row is a no-op, not a crash.
    assert database.delete_sigma_rule(db_path, rid) is False


# ---------------------------------------------------------------------------
# Multi-tenant isolation
# ---------------------------------------------------------------------------

def test_list_scoped_to_organization(db_path):
    a = database.save_sigma_rule(db_path, organization_id=1,
                                  parsed_rule=parse_sigma(_YAML_A),
                                  yaml_source=_YAML_A)
    b = database.save_sigma_rule(db_path, organization_id=2,
                                  parsed_rule=parse_sigma(_YAML_B),
                                  yaml_source=_YAML_B)
    org1 = database.list_sigma_rules(db_path, organization_id=1)
    org2 = database.list_sigma_rules(db_path, organization_id=2)
    assert [r["id"] for r in org1] == [a]
    assert [r["id"] for r in org2] == [b]
    # Admin scope (no org filter) sees both.
    assert {r["id"] for r in database.list_sigma_rules(db_path)} == {a, b}


def test_get_scoped_rejects_cross_tenant(db_path):
    rid = database.save_sigma_rule(db_path, organization_id=1,
                                    parsed_rule=parse_sigma(_YAML_A),
                                    yaml_source=_YAML_A)
    assert database.get_sigma_rule(db_path, rid, organization_id=1) is not None
    assert database.get_sigma_rule(db_path, rid, organization_id=2) is None


def test_set_enabled_scoped_rejects_cross_tenant(db_path):
    rid = database.save_sigma_rule(db_path, organization_id=1,
                                    parsed_rule=parse_sigma(_YAML_A),
                                    yaml_source=_YAML_A)
    # Tenant 2 cannot toggle tenant 1's rule.
    assert database.set_sigma_rule_enabled(
        db_path, rid, False, organization_id=2
    ) is False
    assert database.get_sigma_rule(db_path, rid)["enabled"] is True
    # Tenant 1 can.
    assert database.set_sigma_rule_enabled(
        db_path, rid, False, organization_id=1
    ) is True
    assert database.get_sigma_rule(db_path, rid)["enabled"] is False


def test_delete_scoped_rejects_cross_tenant(db_path):
    rid = database.save_sigma_rule(db_path, organization_id=1,
                                    parsed_rule=parse_sigma(_YAML_A),
                                    yaml_source=_YAML_A)
    assert database.delete_sigma_rule(db_path, rid, organization_id=2) is False
    assert database.get_sigma_rule(db_path, rid) is not None
    assert database.delete_sigma_rule(db_path, rid, organization_id=1) is True
    assert database.get_sigma_rule(db_path, rid) is None
