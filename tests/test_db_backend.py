# tests/test_db_backend.py
# ------------------------
# Covers the SQL-translation and driver-selection logic in
# pulse.db_backend. We don't spin up a real Postgres here — the Postgres
# paths are exercised against a fake cursor/connection so the test suite
# stays self-contained on every dev machine and CI runner.

import os
import sqlite3
import tempfile

import pytest

from pulse import db_backend


# ---------------------------------------------------------------------------
# is_postgres_url
# ---------------------------------------------------------------------------

class TestIsPostgresUrl:
    def test_recognises_postgres_scheme(self):
        assert db_backend.is_postgres_url("postgres://user@host/db") is True
        assert db_backend.is_postgres_url("postgresql://u:p@h:5432/db") is True

    def test_mixed_case_prefix_still_matches(self):
        assert db_backend.is_postgres_url("PostgreSQL://host/db") is True

    def test_sqlite_path_is_not_postgres(self):
        assert db_backend.is_postgres_url("pulse.db") is False
        assert db_backend.is_postgres_url("/tmp/pulse.db") is False
        assert db_backend.is_postgres_url(None) is False

    def test_non_string_is_not_postgres(self):
        assert db_backend.is_postgres_url(42) is False


# ---------------------------------------------------------------------------
# SQL translation
# ---------------------------------------------------------------------------

class TestTranslateSql:
    def test_qmarks_become_percent_s(self):
        out, _ = db_backend._translate_sql("SELECT * FROM t WHERE id = ? AND n = ?")
        assert out == "SELECT * FROM t WHERE id = %s AND n = %s"

    def test_insert_gets_returning_id_appended(self):
        out, needs = db_backend._translate_sql(
            "INSERT INTO users (email) VALUES (?)"
        )
        assert out.endswith("RETURNING id")
        assert needs is True

    def test_insert_with_existing_returning_is_left_alone(self):
        sql = "INSERT INTO users (email) VALUES (?) RETURNING id"
        out, needs = db_backend._translate_sql(sql)
        # Already had RETURNING, so we don't re-append.
        assert out.count("RETURNING") == 1
        assert needs is False

    def test_non_insert_is_not_touched_beyond_qmarks(self):
        out, needs = db_backend._translate_sql("SELECT 1 FROM t WHERE id = ?")
        assert "RETURNING" not in out
        assert needs is False


# ---------------------------------------------------------------------------
# DDL translation
# ---------------------------------------------------------------------------

class TestTranslateDdl:
    def test_autoincrement_becomes_bigserial(self):
        ddl = "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)"
        out = db_backend.translate_ddl_for_postgres(ddl)
        assert "BIGSERIAL PRIMARY KEY" in out
        assert "AUTOINCREMENT" not in out

    def test_blob_becomes_bytea(self):
        ddl = "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, img BLOB)"
        out = db_backend.translate_ddl_for_postgres(ddl)
        assert "BYTEA" in out
        assert "BLOB" not in out

    def test_idempotent(self):
        # Running translate twice in a row mustn't mangle an already-
        # translated string — defensive against accidental double-wrap.
        ddl = "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, img BLOB)"
        once = db_backend.translate_ddl_for_postgres(ddl)
        twice = db_backend.translate_ddl_for_postgres(once)
        assert once == twice


# ---------------------------------------------------------------------------
# resolve_target
# ---------------------------------------------------------------------------

class TestResolveTarget:
    def test_explicit_wins(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgres://from-env/db")
        assert db_backend.resolve_target("explicit.db") == "explicit.db"

    def test_env_is_used_when_no_arg(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgres://from-env/db")
        assert db_backend.resolve_target() == "postgres://from-env/db"

    def test_default_when_neither_set(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        assert db_backend.resolve_target() == "pulse.db"


# ---------------------------------------------------------------------------
# SQLite connect — end-to-end. Proves the default path still works.
# ---------------------------------------------------------------------------

class TestSqliteConnect:
    def test_sqlite_connect_returns_native_connection(self):
        path = tempfile.mktemp(suffix=".db")
        try:
            conn = db_backend.connect(path)
            assert isinstance(conn, sqlite3.Connection)
            # foreign_keys PRAGMA should already be on.
            cur = conn.execute("PRAGMA foreign_keys")
            assert cur.fetchone()[0] == 1
            conn.close()
        finally:
            if os.path.exists(path):
                os.unlink(path)


# ---------------------------------------------------------------------------
# Postgres missing driver path — we want a clean error when the user
# points at Postgres without installing psycopg.
# ---------------------------------------------------------------------------

class TestPostgresMissingDriver:
    def test_missing_driver_raises_actionable_error(self, monkeypatch):
        monkeypatch.setattr(db_backend, "_HAS_PG", False)
        with pytest.raises(db_backend.PostgresDriverMissing):
            db_backend.connect("postgresql://user@host/db")


# ---------------------------------------------------------------------------
# _PgConnection wrapper behaviour — we exercise it with a hand-rolled fake
# psycopg connection so we don't need a real Postgres to run the suite.
# ---------------------------------------------------------------------------

class _FakeCursor:
    def __init__(self, conn):
        self._conn = conn
        self._rows_out = []
        self._desc = None
        self.rowcount = 0

    def execute(self, sql, params=None):
        self._conn.executed.append((sql, params))
        if "RETURNING id" in sql:
            self._rows_out = [(42,)]
            self.rowcount = 1
        else:
            self._rows_out = []
            self.rowcount = 0

    def executemany(self, sql, seq):
        self._conn.executed.append(("MANY:" + sql, list(seq)))
        self.rowcount = len(seq)

    def fetchone(self):
        return self._rows_out.pop(0) if self._rows_out else None

    def fetchall(self):
        out, self._rows_out = self._rows_out, []
        return out

    def __iter__(self):
        return iter(self._rows_out)


class _FakePgConn:
    def __init__(self):
        self.executed = []
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return _FakeCursor(self)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


class TestPgConnectionWrapper:
    def test_insert_populates_lastrowid_via_returning(self):
        fake = _FakePgConn()
        conn = db_backend._PgConnection(fake)
        cur = conn.execute("INSERT INTO users (email) VALUES (?)", ("a@b.c",))
        assert cur.lastrowid == 42
        # SQL sent to the driver must have been translated.
        sent_sql, sent_params = fake.executed[0]
        assert "%s" in sent_sql
        assert "?" not in sent_sql
        assert sent_sql.endswith("RETURNING id")
        assert sent_params == ("a@b.c",)

    def test_context_manager_commits_on_clean_exit(self):
        fake = _FakePgConn()
        with db_backend._PgConnection(fake) as conn:
            conn.execute("SELECT 1")
        assert fake.committed is True
        assert fake.rolled_back is False
        assert fake.closed is True

    def test_context_manager_rolls_back_on_error(self):
        fake = _FakePgConn()
        with pytest.raises(ValueError):
            with db_backend._PgConnection(fake):
                raise ValueError("boom")
        assert fake.committed is False
        assert fake.rolled_back is True
        assert fake.closed is True

    def test_executemany_translates_placeholders(self):
        fake = _FakePgConn()
        conn = db_backend._PgConnection(fake)
        conn.executemany(
            "INSERT INTO findings (a, b) VALUES (?, ?)",
            [(1, 2), (3, 4)],
        )
        sent_sql, _ = fake.executed[0]
        # executemany should translate placeholders but NOT add a
        # per-row RETURNING — that would break the batch insert.
        assert sent_sql.startswith("MANY:")
        assert "%s" in sent_sql
        assert "?" not in sent_sql
        assert "RETURNING" not in sent_sql


# ---------------------------------------------------------------------------
# init_ddl against SQLite proves the schema builder is still correct on the
# default backend.
# ---------------------------------------------------------------------------

class TestInitDdlSqlite:
    def test_alter_table_duplicate_column_is_swallowed(self):
        path = tempfile.mktemp(suffix=".db")
        try:
            conn = db_backend.connect(path)
            db_backend.init_ddl(
                conn,
                ("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)",),
                ("ALTER TABLE t ADD COLUMN extra TEXT",),
            )
            # Re-running the alter must not raise — db_backend should
            # swallow OperationalError from "duplicate column".
            db_backend.init_ddl(
                conn,
                ("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)",),
                ("ALTER TABLE t ADD COLUMN extra TEXT",),
            )
            conn.close()
        finally:
            if os.path.exists(path):
                os.unlink(path)
