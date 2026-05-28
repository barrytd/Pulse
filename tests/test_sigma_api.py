# test_sigma_api.py
# ------------------
# Sprint 8 — SIGMA rule import, Phase 4. Covers the REST API endpoints
# under /api/rules/sigma. Tests run against a fresh TestClient + isolated
# SQLite database for each test (same pattern as test_api.py).

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app


_YAML_OK = """
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

_YAML_BAD = "this is not: valid: yaml: nesting:"

_YAML_UNSUPPORTED = """
title: aggregated
detection:
  selection: { EventID: 4625 }
  condition: selection | count() by user > 5
level: high
"""


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(config_path),
                     disable_auth=True)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Listing — empty state
# ---------------------------------------------------------------------------

def test_list_starts_empty(client):
    r = client.get("/api/rules/sigma")
    assert r.status_code == 200
    assert r.json() == {"rules": []}


# ---------------------------------------------------------------------------
# Upload (POST /api/rules/sigma)
# ---------------------------------------------------------------------------

def test_upload_yaml_as_json_body(client):
    r = client.post("/api/rules/sigma", json={"yaml": _YAML_OK})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "Suspicious PowerShell Encoded Command"
    assert body["severity"] == "HIGH"
    assert body["mitre"] == "T1059.001"
    assert body["enabled"] is True
    assert "yaml_source" in body
    assert "compiled_json" in body


def test_upload_yaml_as_raw_text(client):
    r = client.post(
        "/api/rules/sigma",
        content=_YAML_OK,
        headers={"content-type": "text/yaml"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["severity"] == "HIGH"


def test_upload_empty_body_rejected(client):
    r = client.post("/api/rules/sigma", json={"yaml": ""})
    assert r.status_code == 400
    assert "empty" in r.json()["detail"].lower()


def test_upload_bad_yaml_returns_400(client):
    r = client.post("/api/rules/sigma", json={"yaml": _YAML_BAD})
    assert r.status_code == 400
    assert "sigma parse error" in r.json()["detail"].lower()


def test_upload_unsupported_returns_422(client):
    r = client.post("/api/rules/sigma", json={"yaml": _YAML_UNSUPPORTED})
    assert r.status_code == 422
    assert "unsupported" in r.json()["detail"].lower()


def test_upload_too_large_rejected(client):
    big = "title: x\ndescription: " + ("A" * 70_000) + "\n"
    r = client.post(
        "/api/rules/sigma",
        content=big,
        headers={"content-type": "text/yaml"},
    )
    assert r.status_code == 413


# ---------------------------------------------------------------------------
# Preview
# ---------------------------------------------------------------------------

def test_preview_returns_metadata_without_saving(client):
    r = client.post("/api/rules/sigma/preview", json={"yaml": _YAML_OK})
    assert r.status_code == 200
    body = r.json()
    assert body["title"] == "Suspicious PowerShell Encoded Command"
    assert body["severity"] == "HIGH"
    assert body["mitre"] == "T1059.001"
    # No row should have been persisted.
    assert client.get("/api/rules/sigma").json()["rules"] == []


def test_preview_surfaces_parse_errors(client):
    r = client.post("/api/rules/sigma/preview", json={"yaml": _YAML_BAD})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Get / list after upload
# ---------------------------------------------------------------------------

def test_list_after_upload(client):
    new_id = client.post("/api/rules/sigma",
                          json={"yaml": _YAML_OK}).json()["id"]
    rows = client.get("/api/rules/sigma").json()["rules"]
    assert len(rows) == 1
    assert rows[0]["id"] == new_id
    # Heavy fields stripped from list payload.
    assert "yaml_source" not in rows[0]
    assert "compiled_json" not in rows[0]


def test_get_single_includes_yaml_and_compiled(client):
    new_id = client.post("/api/rules/sigma",
                          json={"yaml": _YAML_OK}).json()["id"]
    r = client.get(f"/api/rules/sigma/{new_id}")
    assert r.status_code == 200
    body = r.json()
    assert "yaml_source" in body
    assert "compiled_json" in body
    assert "EncodedCommand" in body["yaml_source"]


def test_get_unknown_returns_404(client):
    assert client.get("/api/rules/sigma/9999").status_code == 404


# ---------------------------------------------------------------------------
# Enable / disable
# ---------------------------------------------------------------------------

def test_toggle_enabled(client):
    new_id = client.post("/api/rules/sigma",
                          json={"yaml": _YAML_OK}).json()["id"]
    r = client.put(f"/api/rules/sigma/{new_id}/enabled", json={"enabled": False})
    assert r.status_code == 200
    assert client.get(f"/api/rules/sigma/{new_id}").json()["enabled"] is False
    r = client.put(f"/api/rules/sigma/{new_id}/enabled", json={"enabled": True})
    assert client.get(f"/api/rules/sigma/{new_id}").json()["enabled"] is True


def test_toggle_missing_field_rejected(client):
    new_id = client.post("/api/rules/sigma",
                          json={"yaml": _YAML_OK}).json()["id"]
    r = client.put(f"/api/rules/sigma/{new_id}/enabled", json={})
    assert r.status_code == 400


def test_toggle_unknown_returns_404(client):
    r = client.put("/api/rules/sigma/9999/enabled", json={"enabled": False})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

def test_delete_removes_rule(client):
    new_id = client.post("/api/rules/sigma",
                          json={"yaml": _YAML_OK}).json()["id"]
    r = client.delete(f"/api/rules/sigma/{new_id}")
    assert r.status_code == 200
    assert client.get(f"/api/rules/sigma/{new_id}").status_code == 404


def test_delete_unknown_returns_404(client):
    assert client.delete("/api/rules/sigma/9999").status_code == 404
