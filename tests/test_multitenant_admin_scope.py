"""
Multi-tenant admin isolation (hosted-signup mode).

Proves the multi-tenant hardening: with PULSE_HOSTED_SIGNUP on, every signup
is its own organization and an org admin is confined to their own tenant —
they cannot read another org's data, cannot list/modify/delete users in
another org, and the "last admin" guard protects each org independently.
A platform super-admin (PULSE_SUPERADMIN_EMAILS) still sees and manages
everyone.

Single-tenant self-host behavior (admin sees everything) is covered by the
existing tests in test_data_isolation.py, which run without hosted signup.
"""
import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app
from pulse import database

SUPER_EMAIL = "super@pulse.test"
PW = "correct-horse-battery"


@pytest.fixture
def hosted(tmp_path, monkeypatch):
    monkeypatch.setenv("PULSE_HOSTED_SIGNUP", "1")
    monkeypatch.setenv("PULSE_SUPERADMIN_EMAILS", SUPER_EMAIL)
    db_path = tmp_path / "mt.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(cfg))

    def signup(email):
        c = TestClient(app)
        r = c.post("/api/auth/signup", json={"email": email, "password": PW})
        assert r.status_code in (200, 201), r.text
        return c, c.get("/api/me").json()

    # Three separate tenants. The super-admin's email is in the env allowlist.
    csuper, me_super = signup(SUPER_EMAIL)      # org 1 + global super-admin
    ca, me_a = signup("admin-a@acme.test")      # org 2
    cb, me_b = signup("admin-b@init.test")      # org 3

    def add_analyst(client, email):
        client.post("/api/users", json={"email": email, "password": PW, "role": "analyst"})
        users = client.get("/api/users").json()["users"]
        return next(u["id"] for u in users if u["email"] == email)

    analyst_a = add_analyst(ca, "an-a@acme.test")
    analyst_b = add_analyst(cb, "an-b@init.test")

    # One scan per tenant, stamped with the org via the admin's user_id.
    database.save_scan(str(db_path),
                       [{"rule": "RDP Logon Detected", "severity": "HIGH", "hostname": "ACME-PC"}],
                       filename="acme.evtx", user_id=me_a["id"])
    database.save_scan(str(db_path),
                       [{"rule": "Audit Log Cleared", "severity": "CRITICAL", "hostname": "INIT-PC"}],
                       filename="init.evtx", user_id=me_b["id"])

    return {
        "ca": ca, "cb": cb, "csuper": csuper,
        "me_a": me_a, "me_b": me_b, "me_super": me_super,
        "analyst_a": analyst_a, "analyst_b": analyst_b,
    }


# --- read scope -----------------------------------------------------------

def test_admin_history_is_org_scoped(hosted):
    """Admin A sees only their org's scan, not org B's."""
    files_a = {s.get("filename") for s in hosted["ca"].get("/api/history").json()["scans"]}
    assert "acme.evtx" in files_a
    assert "init.evtx" not in files_a


def test_super_admin_sees_every_org_scan(hosted):
    files = {s.get("filename") for s in hosted["csuper"].get("/api/history").json()["scans"]}
    assert {"acme.evtx", "init.evtx"} <= files


# --- user listing ---------------------------------------------------------

def test_user_list_is_org_scoped(hosted):
    emails_a = {u["email"] for u in hosted["ca"].get("/api/users").json()["users"]}
    assert "admin-a@acme.test" in emails_a
    assert "an-a@acme.test" in emails_a
    # No sign of the other tenant.
    assert "admin-b@init.test" not in emails_a
    assert "an-b@init.test" not in emails_a


def test_super_admin_lists_all_users(hosted):
    emails = {u["email"] for u in hosted["csuper"].get("/api/users").json()["users"]}
    assert {"admin-a@acme.test", "admin-b@init.test",
            "an-a@acme.test", "an-b@init.test", SUPER_EMAIL} <= emails


# --- cross-org user management is blocked (404, doesn't leak existence) ----

def test_admin_cannot_change_role_in_other_org(hosted):
    r = hosted["ca"].put(f"/api/users/{hosted['analyst_b']}/role", json={"role": "manager"})
    assert r.status_code == 404
    # Org B's analyst is untouched.
    assert hosted["cb"].get("/api/users").json()["users"]


def test_admin_cannot_deactivate_user_in_other_org(hosted):
    r = hosted["ca"].put(f"/api/users/{hosted['analyst_b']}/active", json={"active": False})
    assert r.status_code == 404


def test_admin_cannot_delete_user_in_other_org(hosted):
    r = hosted["ca"].delete(f"/api/users/{hosted['analyst_b']}")
    assert r.status_code == 404
    # Still there.
    emails_b = {u["email"] for u in hosted["cb"].get("/api/users").json()["users"]}
    assert "an-b@init.test" in emails_b


def test_admin_cannot_touch_other_orgs_admin(hosted):
    r = hosted["ca"].delete(f"/api/users/{hosted['me_b']['id']}")
    assert r.status_code == 404


# --- per-org "last admin" guard ------------------------------------------

def test_last_admin_guard_is_per_org(hosted):
    """Org A has exactly one admin (admin A). Demoting them must 409 even
    though other orgs (and the super-admin) also have admins — without
    per-org counting the global count would be >1 and wrongly allow it."""
    r = hosted["ca"].put(f"/api/users/{hosted['me_a']['id']}/role", json={"role": "analyst"})
    assert r.status_code == 409


def test_admin_can_manage_own_org_user(hosted):
    """Sanity: the scoping doesn't block legitimate same-org management."""
    r = hosted["ca"].put(f"/api/users/{hosted['analyst_a']}/role", json={"role": "manager"})
    assert r.status_code == 200
    assert r.json()["role"] == "manager"


# --- super-admin can manage across orgs ----------------------------------

def test_super_admin_can_manage_any_org_user(hosted):
    r = hosted["csuper"].put(f"/api/users/{hosted['analyst_b']}/role", json={"role": "manager"})
    assert r.status_code == 200
    assert r.json()["role"] == "manager"
