# tests/test_waitlist.py
# ----------------------
# Coverage for the public landing page email waitlist: DB helpers and
# the four HTTP endpoints (POST /api/waitlist, GET, CSV export, DELETE).

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app
from pulse import database


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(config_path), disable_auth=True)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------

class TestWaitlistDb:

    def test_add_signup_returns_row_id(self, tmp_path):
        db = str(tmp_path / "test.db")
        database.init_db(db)
        new_id = database.add_waitlist_signup(db, "alice@example.com")
        assert new_id is not None
        assert new_id > 0

    def test_add_signup_idempotent_on_email(self, tmp_path):
        db = str(tmp_path / "test.db")
        database.init_db(db)
        a = database.add_waitlist_signup(db, "bob@example.com")
        b = database.add_waitlist_signup(db, "bob@example.com")
        assert a == b
        assert database.count_waitlist_signups(db) == 1

    def test_add_signup_normalizes_email_case(self, tmp_path):
        db = str(tmp_path / "test.db")
        database.init_db(db)
        database.add_waitlist_signup(db, "  Carol@EXAMPLE.com  ")
        rows = database.list_waitlist_signups(db)
        assert rows[0]["email"] == "carol@example.com"

    def test_add_signup_rejects_empty_email(self, tmp_path):
        db = str(tmp_path / "test.db")
        database.init_db(db)
        assert database.add_waitlist_signup(db, "") is None
        assert database.add_waitlist_signup(db, "   ") is None
        assert database.count_waitlist_signups(db) == 0

    def test_list_returns_newest_first(self, tmp_path):
        db = str(tmp_path / "test.db")
        database.init_db(db)
        database.add_waitlist_signup(db, "first@example.com")
        database.add_waitlist_signup(db, "second@example.com")
        rows = database.list_waitlist_signups(db)
        assert rows[0]["email"] == "second@example.com"
        assert rows[1]["email"] == "first@example.com"

    def test_delete_signup_removes_row(self, tmp_path):
        db = str(tmp_path / "test.db")
        database.init_db(db)
        new_id = database.add_waitlist_signup(db, "del@example.com")
        assert database.delete_waitlist_signup(db, new_id) is True
        assert database.count_waitlist_signups(db) == 0
        # Second delete returns False (already gone).
        assert database.delete_waitlist_signup(db, new_id) is False


# ---------------------------------------------------------------------------
# POST /api/waitlist  — public sign-up
# ---------------------------------------------------------------------------

class TestWaitlistPost:

    def test_valid_email_returns_ok(self, client):
        resp = client.post("/api/waitlist", json={"email": "you@example.com"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert isinstance(body["id"], int)

    def test_missing_email_returns_400(self, client):
        resp = client.post("/api/waitlist", json={})
        assert resp.status_code == 400

    def test_invalid_email_returns_400(self, client):
        for bad in ("not-an-email", "@nope.com", "no@dot", "x" * 300 + "@x.com"):
            resp = client.post("/api/waitlist", json={"email": bad})
            assert resp.status_code == 400, f"expected 400 for {bad!r}"

    def test_invalid_json_returns_400(self, client):
        resp = client.post("/api/waitlist", content=b"not json",
                           headers={"Content-Type": "application/json"})
        assert resp.status_code == 400

    def test_resubmitting_same_email_is_idempotent(self, client):
        a = client.post("/api/waitlist", json={"email": "dup@example.com"})
        b = client.post("/api/waitlist", json={"email": "dup@example.com"})
        assert a.status_code == 200 and b.status_code == 200
        assert a.json()["id"] == b.json()["id"]

    def test_source_is_persisted(self, client):
        client.post("/api/waitlist", json={"email": "tracked@example.com",
                                           "source": "landing"})
        rows = client.get("/api/waitlist").json()["rows"]
        assert rows[0]["source"] == "landing"


# ---------------------------------------------------------------------------
# GET /api/waitlist  — admin list view (auth disabled in test fixture)
# ---------------------------------------------------------------------------

class TestWaitlistList:

    def test_empty_returns_zero_count(self, client):
        body = client.get("/api/waitlist").json()
        assert body["count"] == 0
        assert body["rows"] == []

    def test_returns_seeded_rows(self, client):
        client.post("/api/waitlist", json={"email": "a@x.com"})
        client.post("/api/waitlist", json={"email": "b@x.com"})
        body = client.get("/api/waitlist").json()
        assert body["count"] == 2
        assert {r["email"] for r in body["rows"]} == {"a@x.com", "b@x.com"}

    def test_limit_validated(self, client):
        assert client.get("/api/waitlist?limit=0").status_code == 400
        assert client.get("/api/waitlist?limit=10000").status_code == 400


# ---------------------------------------------------------------------------
# CSV export + DELETE
# ---------------------------------------------------------------------------

class TestWaitlistExportAndDelete:

    def test_csv_has_header_and_one_row_per_signup(self, client):
        client.post("/api/waitlist", json={"email": "csv1@x.com"})
        client.post("/api/waitlist", json={"email": "csv2@x.com",
                                           "source": "twitter"})

        resp = client.get("/api/waitlist/export.csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        assert 'attachment; filename="pulse-waitlist-' in resp.headers["content-disposition"]

        lines = resp.text.strip().splitlines()
        assert lines[0].split(",") == ["id", "email", "source", "created_at"]
        # header + 2 rows
        assert len(lines) == 3
        assert "csv1@x.com" in resp.text
        assert "csv2@x.com" in resp.text
        assert "twitter" in resp.text

    def test_delete_removes_row(self, client):
        new_id = client.post("/api/waitlist", json={"email": "del@x.com"}).json()["id"]
        resp = client.delete(f"/api/waitlist/{new_id}")
        assert resp.status_code == 200
        assert client.get("/api/waitlist").json()["count"] == 0

    def test_delete_nonexistent_returns_404(self, client):
        resp = client.delete("/api/waitlist/99999")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Landing page route
# ---------------------------------------------------------------------------

class TestLandingPage:

    def test_welcome_serves_landing_html(self, client):
        resp = client.get("/welcome")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/html")
        # Sanity check — the form must be present so the public sign-up
        # flow has a UI to land on.
        assert "waitlist-form" in resp.text
        assert "/api/waitlist" in resp.text
