# pulse/db_backend.py
# --------------------
# Thin compatibility layer that lets the rest of Pulse stay written against
# the sqlite3 API while also supporting PostgreSQL.
#
# WHY?
#   SQLite is perfect for a local single-user install (file on disk, zero
#   setup). But once you run Pulse on a shared server with multiple analysts
#   the single-writer story gets painful — and PostgreSQL is the obvious
#   upgrade. We don't want to maintain two copies of every query, so this
#   module normalizes the two drivers to one surface:
#
#     * `?` placeholders work against both backends (rewritten to `%s` for PG).
#     * `cursor.lastrowid` works against both (INSERTs into tables with an
#       auto-id column get a RETURNING id appended transparently for PG).
#     * `with connect(url) as conn:` commits on exit, rolls back on exception,
#       and closes the connection — same as sqlite3's implicit behaviour.
#     * Schema DDL gets rewritten for PG:
#       `INTEGER PRIMARY KEY AUTOINCREMENT` → `BIGSERIAL PRIMARY KEY`, `BLOB`
#       → `BYTEA`, etc.
#
# WHAT WE DIDN'T ABSTRACT:
#   Query results. Both drivers return plain tuples from fetchone / fetchall,
#   so callers that already read by index keep working without a wrapper.
#
# SELECTING A BACKEND:
#   `connect(target)` treats a string starting with `postgres://` or
#   `postgresql://` as a DSN and opens a psycopg connection. Everything else
#   is treated as a filesystem path and opens SQLite.

from __future__ import annotations

import os
import re
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterable, Optional, Sequence, Tuple

try:
    import psycopg
    import psycopg.errors as _pg_errors
    _HAS_PG = True
except Exception:  # pragma: no cover - psycopg is optional
    psycopg = None
    _pg_errors = None
    _HAS_PG = False


# Raised when a Postgres URL is supplied but psycopg isn't installed. We
# surface this explicitly so operators get an actionable error rather than
# a confusing "module not found" from deep in the stack.
class PostgresDriverMissing(RuntimeError):
    """psycopg is not installed but a Postgres URL was supplied."""


def is_postgres_url(target: Optional[str]) -> bool:
    """Return True if `target` looks like a Postgres DSN."""
    if not isinstance(target, str):
        return False
    t = target.strip().lower()
    return t.startswith("postgres://") or t.startswith("postgresql://")


# ---------------------------------------------------------------------------
# Portable "OperationalError" so callers can `except OperationalError:` the
# same way whether the backing driver is sqlite3 or psycopg. We re-export
# sqlite3.OperationalError because existing code already catches it.
# ---------------------------------------------------------------------------

OperationalError = sqlite3.OperationalError


# ---------------------------------------------------------------------------
# Public connect()
# ---------------------------------------------------------------------------

def connect(target: str):
    """Open a connection compatible with the sqlite3 surface.

    Parameters
    ----------
    target : str
        Either a filesystem path (SQLite) or a `postgres(ql)://` DSN.

    Returns
    -------
    A connection-like object. For SQLite this is the native sqlite3 Connection
    (with `PRAGMA foreign_keys = ON` already set). For Postgres this is a
    thin wrapper that rewrites `?` → `%s`, exposes `lastrowid`, and behaves
    like sqlite3 in a `with` block.
    """
    if is_postgres_url(target):
        if not _HAS_PG:
            raise PostgresDriverMissing(
                "DATABASE_URL points at Postgres but the 'psycopg' package "
                "is not installed. Run `pip install psycopg[binary]` or "
                "switch back to SQLite."
            )
        return _PgConnection(psycopg.connect(target, autocommit=False))

    # Default: SQLite. Foreign-key enforcement is off by default in SQLite,
    # so we turn it on for every connection.
    conn = sqlite3.connect(target)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# ---------------------------------------------------------------------------
# DDL translation — the SQLite DDL strings defined in pulse/database.py are
# the source of truth. For Postgres we rewrite the handful of dialect-specific
# bits so the same `CREATE TABLE IF NOT EXISTS` string can initialise either
# backend.
# ---------------------------------------------------------------------------

_DDL_REPLACEMENTS = (
    # SQLite's AUTOINCREMENT column on INTEGER PRIMARY KEY → BIGSERIAL.
    (re.compile(r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT", re.IGNORECASE),
     "BIGSERIAL PRIMARY KEY"),
    # BLOB → BYTEA.
    (re.compile(r"\bBLOB\b", re.IGNORECASE), "BYTEA"),
)


def translate_ddl_for_postgres(ddl: str) -> str:
    """Apply the SQLite→Postgres DDL rewrites needed by Pulse's schema."""
    out = ddl
    for pattern, repl in _DDL_REPLACEMENTS:
        out = pattern.sub(repl, out)
    return out


# ---------------------------------------------------------------------------
# Postgres connection / cursor wrappers
# ---------------------------------------------------------------------------

_QMARK_RE = re.compile(r"\?")

# INSERT statements without an explicit RETURNING clause need one appended
# so we can report `lastrowid` on the returned cursor.
_INSERT_HEAD_RE = re.compile(r"^\s*INSERT\s+INTO\s+", re.IGNORECASE)
_RETURNING_RE = re.compile(r"\bRETURNING\b", re.IGNORECASE)


def _translate_sql(sql: str) -> Tuple[str, bool]:
    """Rewrite a SQLite-flavoured SQL string for psycopg.

    Returns (translated_sql, needs_returning_id). `needs_returning_id` is
    True when we appended a RETURNING id so the caller can read it off the
    cursor to populate lastrowid.
    """
    translated = _QMARK_RE.sub("%s", sql)
    needs_returning = False
    if _INSERT_HEAD_RE.search(translated) and not _RETURNING_RE.search(translated):
        translated = translated.rstrip().rstrip(";") + " RETURNING id"
        needs_returning = True
    return translated, needs_returning


class _PgCursor:
    """sqlite3-cursor-shaped wrapper around a psycopg cursor."""

    def __init__(self, raw_cursor):
        self._cur = raw_cursor
        self._lastrowid: Optional[int] = None

    # --- sqlite3 Cursor surface -------------------------------------------------
    @property
    def lastrowid(self) -> Optional[int]:
        return self._lastrowid

    @property
    def rowcount(self) -> int:
        # psycopg returns -1 for "unknown"; sqlite3 never does. Clamp so
        # callers that do `cursor.rowcount or 0` behave identically.
        rc = self._cur.rowcount
        return rc if rc is not None and rc >= 0 else 0

    @property
    def description(self):
        return self._cur.description

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def __iter__(self):
        return iter(self._cur)

    # Internal: assign lastrowid from a RETURNING row if one was added.
    def _consume_returning(self):
        row = self._cur.fetchone()
        if row is not None:
            self._lastrowid = int(row[0])


class _PgConnection:
    """sqlite3-Connection-shaped wrapper around a psycopg Connection.

    Context-manager semantics mirror sqlite3:
      * on clean exit, commit + close
      * on exception, rollback + close
    """

    def __init__(self, raw_conn):
        self._conn = raw_conn

    # --- context manager --------------------------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
        finally:
            self._conn.close()
        # Don't swallow the exception.
        return False

    # --- sqlite3 Connection surface --------------------------------------------
    def execute(self, sql: str, params: Optional[Sequence[Any]] = None) -> _PgCursor:
        translated, needs_returning = _translate_sql(sql)
        cur = self._conn.cursor()
        cur.execute(translated, params or ())
        wrapper = _PgCursor(cur)
        if needs_returning:
            wrapper._consume_returning()
        return wrapper

    def executemany(self, sql: str, seq: Iterable[Sequence[Any]]) -> _PgCursor:
        translated = _QMARK_RE.sub("%s", sql)
        cur = self._conn.cursor()
        cur.executemany(translated, list(seq))
        return _PgCursor(cur)

    def cursor(self) -> _PgCursor:
        return _PgCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


# ---------------------------------------------------------------------------
# Init-time helpers: run CREATE TABLE / ALTER TABLE with dialect awareness.
# ---------------------------------------------------------------------------

def init_ddl(conn, create_statements: Iterable[str], alter_statements: Iterable[str]):
    """Execute a batch of CREATE TABLE + ALTER TABLE statements portably.

    * `create_statements` — `CREATE TABLE IF NOT EXISTS` strings written in
      SQLite dialect. They're rewritten on the fly for Postgres.
    * `alter_statements`  — `ALTER TABLE ... ADD COLUMN ...` strings. SQLite
      raises OperationalError when the column already exists; we swallow
      that. Postgres supports `ADD COLUMN IF NOT EXISTS` so we rewrite the
      statement to use it (and never raise).
    """
    is_pg = isinstance(conn, _PgConnection)
    for ddl in create_statements:
        if is_pg:
            ddl = translate_ddl_for_postgres(ddl)
        conn.execute(ddl)
    for ddl in alter_statements:
        if is_pg:
            ddl_pg = ddl
            ddl_pg = re.sub(
                r"ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+",
                r"ALTER TABLE \1 ADD COLUMN IF NOT EXISTS ",
                ddl_pg,
                count=1,
                flags=re.IGNORECASE,
            )
            ddl_pg = translate_ddl_for_postgres(ddl_pg)
            try:
                conn.execute(ddl_pg)
            except Exception:  # pragma: no cover - defensive
                pass
        else:
            try:
                conn.execute(ddl)
            except sqlite3.OperationalError:
                pass


# ---------------------------------------------------------------------------
# Config resolution — one place to answer "what DB should I use?"
# ---------------------------------------------------------------------------

def resolve_target(cli_value: Optional[str] = None, default: str = "pulse.db") -> str:
    """Pick the DB target from (in order): explicit arg, DATABASE_URL env, default.

    This gives operators a single environment variable knob to flip a Render
    instance onto Postgres without touching the YAML file, while still
    letting the CLI and tests pass a path explicitly.
    """
    if cli_value:
        return cli_value
    env = os.environ.get("DATABASE_URL", "").strip()
    if env:
        return env
    return default
