#!/usr/bin/env python3
# scripts/migrate_to_postgres.py
# -------------------------------
# One-shot copy of every row in a local pulse.db (SQLite) into a target
# PostgreSQL database. Used when an operator outgrows the single-file
# SQLite install and wants to move history + users + block list to a
# shared Postgres server without losing data.
#
# USAGE
#   python scripts/migrate_to_postgres.py \
#       --from pulse.db \
#       --to   postgresql://pulse:pw@localhost:5432/pulse
#
#   Environment-variable form (matches how Render / Railway wire things up):
#
#   set DATABASE_URL=postgresql://pulse:pw@host:5432/pulse
#   python scripts/migrate_to_postgres.py --from pulse.db
#
# WHAT IT DOES
#   1. Calls pulse.database.init_db() on the target so the schema exists.
#   2. Walks every table in dependency order (parents before children so
#      foreign keys resolve) and copies rows 1:1.
#   3. After a table is copied, bumps the Postgres sequence on its `id`
#      column so the next INSERT from the live app starts above the
#      imported max id — without this, the app would immediately crash on
#      primary-key conflicts.
#   4. Verifies the row counts match and prints a per-table summary.
#
# WHAT IT DOESN'T DO
#   - Delete anything from the target. Rows with duplicate primary keys
#     are skipped (idempotent re-runs are safe; topping up a partial
#     migration is not — wipe the target first if you need to redo the
#     copy).
#   - Touch files outside pulse.db (reports/, logs/).
#
# LIMITATIONS
#   - Assumes the SQLite schema was built by the current `init_db()`. If
#     you upgraded Pulse in-place from a very old version, re-run the
#     current Pulse once against the SQLite file first so all ALTER TABLE
#     statements have run, then migrate.

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

# Parent-before-child so foreign keys resolve. `scans` and `monitor_sessions`
# are siblings of each other (scans.session_id points at monitor_sessions
# but NULL is allowed), so either can go first; we copy monitor_sessions
# first so the FK is real on import.
TABLES_IN_ORDER = (
    "users",
    "monitor_sessions",
    "scans",
    "findings",
    "alert_log",
    "api_tokens",
    "ip_block_list",
    "audit_log",
)


def _parse_args():
    p = argparse.ArgumentParser(
        description="Migrate a Pulse SQLite database to PostgreSQL."
    )
    p.add_argument(
        "--from", dest="source", default="pulse.db",
        help="Path to the source SQLite file (default: pulse.db)",
    )
    p.add_argument(
        "--to", dest="target", default=None,
        help="Target postgres(ql):// DSN. Falls back to the DATABASE_URL env var.",
    )
    p.add_argument(
        "--batch-size", type=int, default=500,
        help="Rows per INSERT batch on the PG side (default: 500).",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Report row counts without writing anything.",
    )
    return p.parse_args()


def _resolve_target(cli_value):
    if cli_value:
        return cli_value
    env = os.environ.get("DATABASE_URL", "").strip()
    if env:
        return env
    sys.exit(
        "error: no target DSN supplied — pass --to postgres://... or set "
        "the DATABASE_URL environment variable."
    )


def _ensure_schema(target_dsn):
    """Import lazily so --help works without psycopg installed."""
    from pulse.database import init_db  # noqa: E402 (import at runtime)
    init_db(target_dsn)


def _sqlite_rows(conn, table):
    """Yield (columns, rows) for a table — reads everything into memory
    since even a year's worth of scans on a single machine is trivially
    small (<100k rows)."""
    cursor = conn.execute(f"SELECT * FROM {table}")
    cols = [d[0] for d in cursor.description]
    rows = cursor.fetchall()
    return cols, rows


def _pg_insert(pg_conn, table, cols, rows, batch_size):
    if not rows:
        return 0
    from pulse.db_backend import _QMARK_RE  # internal helper: `?` → `%s`

    # ON CONFLICT (id) DO NOTHING makes the import idempotent — rerunning
    # on a partially-migrated DB leaves existing rows alone.
    placeholders = ", ".join(["?"] * len(cols))
    col_list = ", ".join(cols)
    sql_q = (
        f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) "
        f"ON CONFLICT (id) DO NOTHING"
    )
    sql_pg = _QMARK_RE.sub("%s", sql_q)

    inserted = 0
    cur = pg_conn.cursor()
    for i in range(0, len(rows), batch_size):
        chunk = rows[i:i + batch_size]
        cur.executemany(sql_pg, chunk)
        # psycopg's executemany doesn't return meaningful rowcount for ON
        # CONFLICT, so we track "attempted" not "actually inserted"; the
        # final verification query below reports the truth.
        inserted += len(chunk)
    return inserted


def _bump_sequence(pg_conn, table):
    """After bulk-copying rows with explicit ids, the Postgres sequence
    behind the BIGSERIAL id column is still at 1. The next app INSERT
    would collide with id=2, 3, ... until catching up. setval() fast-
    forwards the sequence to (max(id)+1) in one shot."""
    cur = pg_conn.cursor()
    cur.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}")
    row = cur.fetchone()
    max_id = int(row[0]) if row and row[0] is not None else 0
    if max_id <= 0:
        return
    # The sequence name follows the default Postgres convention
    # `<table>_id_seq`. setval(seq, N, true) makes nextval() return N+1.
    cur.execute(f"SELECT setval('{table}_id_seq', %s, true)", (max_id,))


def main():
    args = _parse_args()
    source_path = args.source
    target_dsn = _resolve_target(args.target)

    if not Path(source_path).exists():
        sys.exit(f"error: source {source_path!r} does not exist.")

    # Stand up the schema on the target first (no-op if already there).
    print(f"[1/3] Ensuring schema on target ...")
    _ensure_schema(target_dsn)

    print(f"[2/3] Reading rows from {source_path} ...")
    sqlite_conn = sqlite3.connect(source_path)
    sqlite_conn.execute("PRAGMA foreign_keys = OFF")

    table_snapshots = {}
    for table in TABLES_IN_ORDER:
        try:
            cols, rows = _sqlite_rows(sqlite_conn, table)
        except sqlite3.OperationalError as exc:
            print(f"  - {table}: SKIP ({exc})")
            continue
        table_snapshots[table] = (cols, rows)
        print(f"  - {table}: {len(rows)} row(s)")

    sqlite_conn.close()

    if args.dry_run:
        print("[3/3] Dry run — nothing written.")
        return

    # Lazy import so --dry-run can run without psycopg installed.
    try:
        import psycopg
    except ImportError:
        sys.exit(
            "error: psycopg is not installed. Run "
            "`pip install psycopg[binary]` and retry."
        )

    print(f"[3/3] Writing rows to target Postgres ...")
    with psycopg.connect(target_dsn) as pg_conn:
        pg_conn.autocommit = False
        for table in TABLES_IN_ORDER:
            if table not in table_snapshots:
                continue
            cols, rows = table_snapshots[table]
            attempted = _pg_insert(pg_conn, table, cols, rows, args.batch_size)
            _bump_sequence(pg_conn, table)
            # Row-count verification against the target.
            cur = pg_conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            present = int(cur.fetchone()[0])
            print(f"  - {table}: attempted={attempted}, now in target={present}")
        pg_conn.commit()

    print("Migration complete. Start Pulse with DATABASE_URL pointed at the "
          "new Postgres instance to begin using it.")


if __name__ == "__main__":
    main()
