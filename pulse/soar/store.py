# pulse/soar/store.py
# -------------------
# DB access for the playbook engine: playbooks, playbook_runs and
# connectors_config (tables defined in pulse/database.py).
#
# Every function takes an `org` and filters on it, so a caller can never
# read or change another organization's playbooks or runs by id. `org` is
# an int, with 0 meaning "no organization" (see the schema comment).

from __future__ import annotations

import json
from datetime import datetime, timedelta

from .. import database

_PB_COLS = ("id", "organization_id", "name", "enabled", "recipe_json",
            "origin", "created_at", "created_by", "updated_at")
_RUN_COLS = ("id", "organization_id", "playbook_id", "playbook_name",
             "finding_id", "scan_id", "dedupe_key", "status", "step_cursor",
             "recipe_json", "context_json", "steps_json", "created_at",
             "updated_at", "finished_at")

# Run statuses.
RUNNING = "running"
AWAITING = "awaiting_approval"
COMPLETED = "completed"
DENIED = "denied"
FAILED = "failed"
FINISHED = (COMPLETED, DENIED, FAILED)


def _org(org):
    try:
        return int(org or 0)
    except (TypeError, ValueError):
        return 0


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _loads(raw, default):
    try:
        return json.loads(raw) if raw else default
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------

def _row_to_playbook(row):
    d = dict(zip(_PB_COLS, row))
    d["enabled"] = bool(d["enabled"])
    d["recipe"] = _loads(d.pop("recipe_json"), {})
    return d


def create_playbook(db_path, org, recipe, *, created_by=None, origin="import"):
    with database._connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO playbooks (organization_id, name, enabled, recipe_json,
                                      origin, created_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (_org(org), recipe["name"], 1 if recipe.get("enabled", True) else 0,
             json.dumps(recipe), origin, now_str(), created_by),
        )
        return cur.lastrowid


def list_playbooks(db_path, org, enabled_only=False):
    sql = f"SELECT {', '.join(_PB_COLS)} FROM playbooks WHERE organization_id = ?"
    if enabled_only:
        sql += " AND enabled = 1"
    with database._connect(db_path) as conn:
        rows = conn.execute(sql + " ORDER BY id", (_org(org),)).fetchall()
    return [_row_to_playbook(r) for r in rows]


def get_playbook(db_path, org, playbook_id):
    with database._connect(db_path) as conn:
        row = conn.execute(
            f"SELECT {', '.join(_PB_COLS)} FROM playbooks WHERE id = ? AND organization_id = ?",
            (int(playbook_id), _org(org)),
        ).fetchone()
    return _row_to_playbook(row) if row else None


def update_playbook(db_path, org, playbook_id, recipe):
    with database._connect(db_path) as conn:
        cur = conn.execute(
            """UPDATE playbooks SET name = ?, enabled = ?, recipe_json = ?, updated_at = ?
               WHERE id = ? AND organization_id = ?""",
            (recipe["name"], 1 if recipe.get("enabled", True) else 0,
             json.dumps(recipe), now_str(), int(playbook_id), _org(org)),
        )
        return cur.rowcount > 0


def set_playbook_enabled(db_path, org, playbook_id, enabled):
    pb = get_playbook(db_path, org, playbook_id)
    if not pb:
        return False
    recipe = dict(pb["recipe"], enabled=bool(enabled))
    return update_playbook(db_path, org, playbook_id, recipe)


def delete_playbook(db_path, org, playbook_id):
    """Delete the playbook. Its past runs stay (they're history)."""
    with database._connect(db_path) as conn:
        cur = conn.execute("DELETE FROM playbooks WHERE id = ? AND organization_id = ?",
                           (int(playbook_id), _org(org)))
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------

def _row_to_run(row):
    d = dict(zip(_RUN_COLS, row))
    d["cursor"] = d.pop("step_cursor")
    d["recipe"] = _loads(d.pop("recipe_json"), {})
    d["context"] = _loads(d.pop("context_json"), {})
    d["steps"] = _loads(d.pop("steps_json"), [])
    return d


def create_run(db_path, org, *, playbook_id, playbook_name, finding_id, scan_id,
               dedupe_key, recipe, context):
    ts = now_str()
    with database._connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO playbook_runs (organization_id, playbook_id, playbook_name,
                   finding_id, scan_id, dedupe_key, status, step_cursor, recipe_json,
                   context_json, steps_json, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)""",
            (_org(org), int(playbook_id), playbook_name, finding_id, scan_id,
             dedupe_key, RUNNING, json.dumps(recipe), json.dumps(context, default=str),
             "[]", ts, ts),
        )
        return cur.lastrowid


def get_run(db_path, org, run_id):
    with database._connect(db_path) as conn:
        row = conn.execute(
            f"SELECT {', '.join(_RUN_COLS)} FROM playbook_runs WHERE id = ? AND organization_id = ?",
            (int(run_id), _org(org)),
        ).fetchone()
    return _row_to_run(row) if row else None


def list_runs(db_path, org, *, status=None, finding_id=None, playbook_id=None, limit=50):
    sql = f"SELECT {', '.join(_RUN_COLS)} FROM playbook_runs WHERE organization_id = ?"
    args = [_org(org)]
    if status:
        sql += " AND status = ?"
        args.append(status)
    if finding_id is not None:
        sql += " AND finding_id = ?"
        args.append(int(finding_id))
    if playbook_id is not None:
        sql += " AND playbook_id = ?"
        args.append(int(playbook_id))
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(max(1, min(int(limit), 500)))
    with database._connect(db_path) as conn:
        rows = conn.execute(sql, tuple(args)).fetchall()
    return [_row_to_run(r) for r in rows]


def save_run(db_path, run):
    finished = run.get("finished_at")
    if run["status"] in FINISHED and not finished:
        finished = now_str()
        run["finished_at"] = finished
    with database._connect(db_path) as conn:
        conn.execute(
            """UPDATE playbook_runs SET status = ?, step_cursor = ?, context_json = ?,
                   steps_json = ?, updated_at = ?, finished_at = ?
               WHERE id = ? AND organization_id = ?""",
            (run["status"], int(run["cursor"]),
             json.dumps(run["context"], default=str), json.dumps(run["steps"], default=str),
             now_str(), finished, int(run["id"]), _org(run["organization_id"])),
        )


def claim_awaiting(db_path, org, run_id, cursor):
    """Atomically move a run out of awaiting_approval. Returns True only
    for the one caller that wins, so two people approving at once can't
    execute the same step twice."""
    with database._connect(db_path) as conn:
        cur = conn.execute(
            """UPDATE playbook_runs SET status = ?, updated_at = ?
               WHERE id = ? AND organization_id = ? AND status = ? AND step_cursor = ?""",
            (RUNNING, now_str(), int(run_id), _org(org), AWAITING, int(cursor)),
        )
        return cur.rowcount == 1


def recent_run_exists(db_path, org, playbook_id, dedupe_key, hours):
    since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    with database._connect(db_path) as conn:
        row = conn.execute(
            """SELECT 1 FROM playbook_runs
               WHERE organization_id = ? AND playbook_id = ? AND dedupe_key = ?
                 AND created_at >= ?""",
            (_org(org), int(playbook_id), dedupe_key, since),
        ).fetchone()
    return row is not None


def run_counts_by_playbook(db_path, org):
    """{playbook_id: {"runs": n, "last_run_at": ts, "awaiting": n}}"""
    with database._connect(db_path) as conn:
        rows = conn.execute(
            """SELECT playbook_id, COUNT(*), MAX(created_at),
                      SUM(CASE WHEN status = ? THEN 1 ELSE 0 END)
               FROM playbook_runs WHERE organization_id = ? GROUP BY playbook_id""",
            (AWAITING, _org(org)),
        ).fetchall()
    return {r[0]: {"runs": r[1], "last_run_at": r[2], "awaiting": int(r[3] or 0)} for r in rows}


# ---------------------------------------------------------------------------
# Connector on/off per org
# ---------------------------------------------------------------------------

def connector_states(db_path, org):
    """{connector_key: enabled} for keys the org has changed. A key that
    isn't here is enabled."""
    with database._connect(db_path) as conn:
        rows = conn.execute(
            "SELECT connector_key, enabled FROM connectors_config WHERE organization_id = ?",
            (_org(org),),
        ).fetchall()
    return {k: bool(e) for k, e in rows}


def connector_enabled(db_path, org, key):
    return connector_states(db_path, org).get(key, True)


def set_connector_enabled(db_path, org, key, enabled, *, updated_by=None):
    with database._connect(db_path) as conn:
        conn.execute(
            """INSERT INTO connectors_config (organization_id, connector_key, enabled,
                                              updated_at, updated_by)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT (organization_id, connector_key) DO UPDATE SET
                   enabled = excluded.enabled,
                   updated_at = excluded.updated_at,
                   updated_by = excluded.updated_by""",
            (_org(org), key, 1 if enabled else 0, now_str(), updated_by),
        )
