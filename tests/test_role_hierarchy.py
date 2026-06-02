# test_role_hierarchy.py
# -----------------------
# Three-role hierarchy: admin > manager > analyst. Plus backwards-compat
# for the legacy 'viewer' role name.

import os
import tempfile

import pytest

from pulse import database
from pulse.database import (
    VALID_ROLES, normalize_role, role_is_at_least,
    create_user, update_user_role, get_user_by_id,
)


# ---------------------------------------------------------------------------
# normalize_role + VALID_ROLES + role_is_at_least
# ---------------------------------------------------------------------------

def test_valid_roles_are_three():
    assert set(VALID_ROLES) == {"admin", "manager", "analyst"}


@pytest.mark.parametrize("input_val,expected", [
    ("admin",    "admin"),
    ("Admin",    "admin"),
    ("  ADMIN ", "admin"),
    ("manager",  "manager"),
    ("analyst",  "analyst"),
    ("viewer",   "analyst"),  # back-compat alias
    ("VIEWER",   "analyst"),
    ("",         ""),
    (None,       ""),
])
def test_normalize_role(input_val, expected):
    assert normalize_role(input_val) == expected


@pytest.mark.parametrize("role,required,expected", [
    ("admin",   "analyst", True),
    ("admin",   "manager", True),
    ("admin",   "admin",   True),
    ("manager", "analyst", True),
    ("manager", "manager", True),
    ("manager", "admin",   False),
    ("analyst", "analyst", True),
    ("analyst", "manager", False),
    ("analyst", "admin",   False),
    ("viewer",  "analyst", True),    # legacy = analyst
    ("viewer",  "manager", False),
    ("unknown", "analyst", False),
    ("",        "analyst", False),
])
def test_role_is_at_least(role, required, expected):
    assert role_is_at_least(role, required) is expected


# ---------------------------------------------------------------------------
# create_user + update_user_role accept all three roles
# ---------------------------------------------------------------------------

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


def test_create_user_with_each_role(db_path):
    for role in ("admin", "manager", "analyst"):
        uid = create_user(db_path,
                           f"{role}@example.com",
                           "hash", role=role)
        assert get_user_by_id(db_path, uid)["role"] == role


def test_create_user_with_legacy_viewer_stores_analyst(db_path):
    """An older caller still passing role='viewer' should land an
    analyst row — the auth/UI layer never has to deal with the legacy
    value after the rewrite. Create an admin first so the second user
    doesn't trip the first-user-is-admin promotion rule."""
    create_user(db_path, "admin@example.com", "hash", role="admin")
    uid = create_user(db_path, "old@example.com", "hash", role="viewer")
    assert get_user_by_id(db_path, uid)["role"] == "analyst"


def test_create_user_rejects_unknown_role(db_path):
    with pytest.raises(ValueError, match="role"):
        create_user(db_path, "x@y.com", "hash", role="superuser")


def test_update_user_role_walks_the_hierarchy(db_path):
    uid = create_user(db_path, "u@example.com", "hash", role="analyst")
    update_user_role(db_path, uid, "manager")
    assert get_user_by_id(db_path, uid)["role"] == "manager"
    update_user_role(db_path, uid, "admin")
    assert get_user_by_id(db_path, uid)["role"] == "admin"
    update_user_role(db_path, uid, "analyst")
    assert get_user_by_id(db_path, uid)["role"] == "analyst"


def test_update_user_role_accepts_viewer_as_analyst(db_path):
    uid = create_user(db_path, "u@example.com", "hash", role="admin")
    update_user_role(db_path, uid, "viewer")
    assert get_user_by_id(db_path, uid)["role"] == "analyst"


# ---------------------------------------------------------------------------
# Init-time migration: viewer rows get rewritten to analyst on init_db
# ---------------------------------------------------------------------------

def test_init_db_migrates_viewer_rows_to_analyst(db_path):
    """An installed Pulse with legacy 'viewer' rows must come up with
    every row already migrated, so /api/users responses never carry
    the legacy value to the frontend."""
    # Force a legacy row by going around the validation layer.
    import sqlite3
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO users (email, password_hash, created_at, role, active)"
            " VALUES (?, ?, ?, 'viewer', 1)",
            ("legacy@example.com", "hash", "2026-01-01 00:00:00"),
        )
        assert conn.execute(
            "SELECT role FROM users WHERE email = 'legacy@example.com'"
        ).fetchone()[0] == "viewer"

    # Re-running init_db should rewrite the legacy row.
    database.init_db(db_path)
    import sqlite3
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT role FROM users WHERE email = 'legacy@example.com'"
        ).fetchone()
    assert row[0] == "analyst"
