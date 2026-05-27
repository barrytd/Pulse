#!/bin/sh
# Pulse container entrypoint
# --------------------------
# Two jobs:
#   1. Wait for Postgres if DATABASE_URL points at one — without this,
#      the first docker-compose boot races: Pulse starts before
#      postgres has accepted connections, init_db crashes, container
#      restarts. The check loops with a 1s backoff for up to 60s.
#   2. Seed an initial admin user from PULSE_ADMIN_EMAIL +
#      PULSE_ADMIN_PASSWORD on first boot. Skips if either env var is
#      unset OR if any user already exists in the DB. Idempotent so a
#      restart never re-creates rows.
#
# Then exec into the actual CMD (uvicorn via main.py --api).
#
# POSIX sh (not bash) — alpine + slim images don't always include bash.

set -e

# ---------------------------------------------------------------------------
# 1. Postgres readiness probe
# ---------------------------------------------------------------------------
# Only relevant when DATABASE_URL is set to postgres(ql)://. SQLite path
# is a local file, no readiness needed.
case "${DATABASE_URL:-}" in
    postgres*://*|postgresql*://*)
        echo "[entrypoint] DATABASE_URL points at Postgres; waiting for ready..."
        # python -c uses psycopg's connection probe — pulse already
        # depends on psycopg so no extra package to install.
        timeout=60
        until python -c "
import os, sys, time
import psycopg
try:
    with psycopg.connect(os.environ['DATABASE_URL'], connect_timeout=3) as c:
        c.execute('SELECT 1')
    sys.exit(0)
except Exception as e:
    sys.exit(1)
" 2>/dev/null; do
            timeout=$((timeout - 1))
            if [ "$timeout" -le 0 ]; then
                echo "[entrypoint] Postgres did not become ready within 60s. Aborting." >&2
                exit 1
            fi
            sleep 1
        done
        echo "[entrypoint] Postgres is ready."
        ;;
    *)
        # Empty DATABASE_URL or sqlite: nothing to wait for.
        ;;
esac

# ---------------------------------------------------------------------------
# 2. Optional admin seed
# ---------------------------------------------------------------------------
# Lets `docker compose up -d` produce a usable instance with one set of
# env vars instead of forcing the operator to hit /signup manually.
# Skips if either env var is unset OR if any user already exists.
if [ -n "${PULSE_ADMIN_EMAIL:-}" ] && [ -n "${PULSE_ADMIN_PASSWORD:-}" ]; then
    echo "[entrypoint] Seeding admin user ${PULSE_ADMIN_EMAIL} (if not already present)..."
    python -c "
import os
from pulse import database
from pulse.auth import hash_password

db_path = os.environ.get('DATABASE_URL') or 'pulse.db'
database.init_db(db_path)

email = os.environ['PULSE_ADMIN_EMAIL'].strip().lower()
existing = database.get_user_by_email(db_path, email)
if existing:
    print(f'[entrypoint]   user {email!r} already exists; skipping seed')
else:
    # Any pre-existing rows in the users table? If so the first-user
    # rule already picked an admin and we won't auto-create another.
    if database.count_users(db_path) > 0:
        print('[entrypoint]   users already exist; will not auto-seed')
    else:
        uid = database.create_user(
            db_path, email, hash_password(os.environ['PULSE_ADMIN_PASSWORD']),
            role='admin',
        )
        # Stamp verification immediately — operators shouldn't have to
        # click an email link for the seed account, and a single-user
        # install with no SMTP would never receive one anyway.
        database.mark_user_email_verified(db_path, uid)
        print(f'[entrypoint]   created admin user {email!r} (id={uid})')
"
fi

# ---------------------------------------------------------------------------
# 3. Hand off to the actual server command
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting: $@"
exec "$@"
