"""
seed_test_users.py — populate the local `pulse.db` with a handful of
test users so the assignment dropdowns have real names to pick from.

This is a dev-only convenience, not a production tool. Each user gets:
  - A realistic SOC-analyst first + last name
  - display_name set to "First Last"
  - email set to first.last@pulse.example (kept short for the UI)
  - A scrypt-hashed password (default: "ChangeMe!8" — change before any
    deploy you plan to log into)
  - A mix of roles (admin / viewer) and active / deactivated states so
    the admin user-management + assignee picker show realistic variety

Usage (from the repo root):
    python scripts/seed_test_users.py
    python scripts/seed_test_users.py --reset      # wipe the seeded
                                                   # users and re-add
    python scripts/seed_test_users.py --db pulse.db
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make `pulse` importable when the script is run from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pulse.auth import hash_password  # noqa: E402
from pulse.database import (            # noqa: E402
    init_db,
    get_user_by_email,
    create_user,
    update_user_display_name,
    update_user_role,
    update_user_active,
    _connect,
)


# Chosen to mix common and less-common names, different role mixes, and
# a couple of display names that include a middle initial so the "split
# on space, take first word" greeting logic sees realistic shapes.
SEED_USERS: list[dict] = [
    {"email": "robert.perez@pulse.example",   "name": "Robert Perez",         "role": "admin",  "active": True},
    {"email": "maya.chen@pulse.example",      "name": "Maya Chen",            "role": "admin",  "active": True},
    {"email": "aiden.okafor@pulse.example",   "name": "Aiden Okafor",         "role": "viewer", "active": True},
    {"email": "priya.iyer@pulse.example",     "name": "Priya Iyer",           "role": "viewer", "active": True},
    {"email": "jordan.kim@pulse.example",     "name": "Jordan Kim",           "role": "viewer", "active": True},
    {"email": "liam.odonnell@pulse.example",  "name": "Liam O'Donnell",       "role": "viewer", "active": True},
    {"email": "sofia.ramirez@pulse.example",  "name": "Sofia Ramirez",        "role": "viewer", "active": True},
    {"email": "hiroshi.tanaka@pulse.example", "name": "Hiroshi Tanaka",       "role": "admin",  "active": True},
    {"email": "emma.schmidt@pulse.example",   "name": "Emma Schmidt",         "role": "viewer", "active": True},
    {"email": "noah.williams@pulse.example",  "name": "Noah Williams",        "role": "viewer", "active": True},
    {"email": "amelia.davies@pulse.example",  "name": "Amelia R. Davies",     "role": "viewer", "active": True},
    {"email": "kwame.asante@pulse.example",   "name": "Kwame Asante",         "role": "viewer", "active": True},
    # Deactivated users test the "only active users show up in the picker"
    # branch — they'll appear in Settings > Users but NOT in the dropdown.
    {"email": "zoe.morrison@pulse.example",   "name": "Zoe Morrison",         "role": "viewer", "active": False},
    {"email": "taro.yamamoto@pulse.example",  "name": "Taro Yamamoto",        "role": "viewer", "active": False},
]


DEFAULT_PASSWORD = "ChangeMe!8"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="pulse.db", help="Path to pulse.db (default: ./pulse.db)")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete any previously-seeded @pulse.example users before re-adding",
    )
    parser.add_argument(
        "--password",
        default=DEFAULT_PASSWORD,
        help=f"Password assigned to every seeded user (default: {DEFAULT_PASSWORD!r})",
    )
    args = parser.parse_args()

    db_path = args.db
    init_db(db_path)

    if args.reset:
        _reset_seeded(db_path)

    created, skipped = 0, 0
    pw_hash = hash_password(args.password)

    for spec in SEED_USERS:
        email = spec["email"].lower().strip()
        if get_user_by_email(db_path, email):
            skipped += 1
            continue
        # create_user defaults to role='admin' on the first row — since
        # the first user is always you, these seeded rows come in later
        # and we override role explicitly afterward anyway.
        new_id = create_user(db_path, email, pw_hash, role=spec["role"])
        update_user_display_name(db_path, new_id, spec["name"])
        if spec["role"] != "admin":
            # create_user auto-upgrades the very first row to admin; if
            # the seed user is supposed to be a viewer, normalize here.
            update_user_role(db_path, new_id, spec["role"])
        if not spec["active"]:
            update_user_active(db_path, new_id, False)
        created += 1

    print(f"[seed] created={created} skipped_existing={skipped}")
    print(f"[seed] password for every seeded user: {args.password!r}")
    print(f"[seed] tip: log in as robert.perez@pulse.example (admin) to try the assignment dropdown")
    return 0


def _reset_seeded(db_path: str) -> None:
    """Remove every @pulse.example user added by a previous seed run."""
    with _connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM users WHERE email LIKE ?",
            ("%@pulse.example",),
        )
        print(f"[seed] --reset removed {cur.rowcount} previously seeded user(s)")


if __name__ == "__main__":
    raise SystemExit(main())
