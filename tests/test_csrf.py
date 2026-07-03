# tests/test_csrf.py
# ------------------
# CSRF protection: mutating requests (POST/PUT/PATCH/DELETE) must carry the
# custom X-Pulse-Request header. A cross-site page can auto-send the victim's
# session cookie but cannot set a custom header, so this defeats CSRF. Agent
# transport routes (/api/agent/*) and Bearer-token requests are exempt (a
# non-browser daemon / a header the browser never auto-attaches).
#
# NOTE: conftest's autouse _send_csrf_header fixture makes every TestClient
# send the header by default. Tests that prove REJECTION pop it first.

import pytest
from fastapi.testclient import TestClient

from pulse import database
from pulse.api import create_app


@pytest.fixture
def auth_client(tmp_path):
    db_path = tmp_path / "test.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")   # no SMTP -> signup auto-verifies
    app = create_app(db_path=str(db_path), config_path=str(cfg))
    client = TestClient(app)
    client.post("/api/auth/signup", json={
        "email": "admin@example.com", "password": "correct-horse-battery"})
    return client


# ---------------------------------------------------------------------------
# The header gate
# ---------------------------------------------------------------------------

def test_mutating_request_without_csrf_header_rejected(auth_client):
    """A cookie-authed POST with no X-Pulse-Request header is 403'd before it
    ever reaches the handler."""
    auth_client.headers.pop("x-pulse-request", None)
    r = auth_client.post("/api/feedback", json={"kind": "general", "message": "hello there"})
    assert r.status_code == 403


def test_mutating_request_with_csrf_header_allowed(auth_client):
    """The same POST with the header (sent by default) is not CSRF-blocked."""
    r = auth_client.post("/api/feedback", json={"kind": "general", "message": "hello there"})
    assert r.status_code != 403


def test_get_requests_are_not_gated(auth_client):
    """GET is not state-changing, so it never needs the header."""
    auth_client.headers.pop("x-pulse-request", None)
    r = auth_client.get("/api/notifications")
    assert r.status_code != 403


def test_put_and_delete_also_gated(auth_client):
    """The gate covers PUT/DELETE too, not just POST."""
    auth_client.headers.pop("x-pulse-request", None)
    # A made-up id is fine — CSRF is checked before the handler runs.
    assert auth_client.put("/api/users/999/role", json={"role": "analyst"}).status_code == 403
    assert auth_client.delete("/api/users/999").status_code == 403


# ---------------------------------------------------------------------------
# Exemptions: Bearer tokens + agent transport
# ---------------------------------------------------------------------------

def test_bearer_token_request_exempt_from_csrf(auth_client):
    """A Bearer-token (CI / agent) request needs no CSRF header — the browser
    never auto-attaches Authorization, so it can't be forged cross-site."""
    raw = auth_client.post("/api/tokens", json={"name": "ci"}).json()["token"]
    # Fresh client: no session cookie, and no CSRF header.
    fresh = TestClient(auth_client.app)
    fresh.headers.pop("x-pulse-request", None)
    r = fresh.post("/api/scan",
                   headers={"Authorization": "Bearer " + raw},
                   files={"file": ("t.evtx", b"not a real evtx", "application/octet-stream")})
    # CSRF must NOT block it (would be 403). It reaches the handler and fails
    # the magic-byte check (400) — proof the Bearer request got through.
    assert r.status_code != 403


def test_agent_transport_path_exempt_from_csrf(auth_client):
    """Routes under /api/agent/* are exempt (a non-browser daemon posts them
    with its own token). Without valid agent auth the request 401s — but it
    is never 403'd by CSRF."""
    fresh = TestClient(auth_client.app)
    fresh.headers.pop("x-pulse-request", None)
    r = fresh.post("/api/agent/heartbeat", json={})
    assert r.status_code != 403


def test_admin_agent_ui_route_is_gated(auth_client):
    """The admin agent-management UI (/api/agents, note the plural) is a
    cookie route and IS gated — only the transport /api/agent/* is exempt."""
    auth_client.headers.pop("x-pulse-request", None)
    r = auth_client.post("/api/agents", json={"hostname": "x"})
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Org-scoping: GET /api/feedback (mirrors /api/users)
# ---------------------------------------------------------------------------

def test_feedback_list_is_org_scoped():
    """A hosted org admin sees only their own org's feedback; global scope
    (None) sees all."""
    import tempfile, os
    db_path = os.path.join(tempfile.mkdtemp(), "fb.db")
    database.init_db(db_path)
    org_a = database.create_organization(db_path, name="A", slug="a")
    org_b = database.create_organization(db_path, name="B", slug="b")
    ua = database.create_user(db_path, "a@a.test", "h", organization_id=org_a)
    ub = database.create_user(db_path, "b@b.test", "h", organization_id=org_b)
    database.insert_feedback(db_path, ua, "general", "from org A")
    database.insert_feedback(db_path, ub, "general", "from org B")

    only_a = database.list_feedback(db_path, organization_id=org_a)
    assert len(only_a) == 1 and only_a[0]["message"] == "from org A"
    only_b = database.list_feedback(db_path, organization_id=org_b)
    assert len(only_b) == 1 and only_b[0]["message"] == "from org B"
    # Global scope (no filter) sees both.
    assert len(database.list_feedback(db_path, organization_id=None)) == 2
