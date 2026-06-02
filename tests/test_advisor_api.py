# test_advisor_api.py
# --------------------
# Security Advisor page payload.

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(config_path),
                     disable_auth=True)
    return TestClient(app)


def test_advisor_overview_shape_on_empty_db(client):
    r = client.get("/api/advisor/overview")
    assert r.status_code == 200, r.text
    body = r.json()
    # Core shape
    assert "posture" in body and isinstance(body["posture"], str)
    assert "totals" in body and isinstance(body["totals"], dict)
    assert "top_concerns" in body and isinstance(body["top_concerns"], list)
    assert "concepts" in body and isinstance(body["concepts"], list)
    assert "checklist" in body and isinstance(body["checklist"], list)
    # Totals shape
    for key in ("critical", "high", "medium", "low", "open_total"):
        assert key in body["totals"]
        assert isinstance(body["totals"][key], int)
    # Empty DB: clean posture, no top concerns, but concepts + checklist
    # are static and always present.
    assert body["totals"]["open_total"] == 0
    assert body["top_concerns"] == []
    assert "clean" in body["posture"].lower()
    assert len(body["concepts"]) >= 5
    assert len(body["checklist"]) >= 5


def test_concept_entries_have_plain_language(client):
    body = client.get("/api/advisor/overview").json()
    for c in body["concepts"]:
        assert c["name"]
        assert c["plain_language"]
        assert c["difficulty"] in {"low", "medium", "high"}


def test_checklist_items_have_required_keys(client):
    body = client.get("/api/advisor/overview").json()
    for item in body["checklist"]:
        assert "label" in item and item["label"]
        assert "auto" in item
        assert "open" in item
