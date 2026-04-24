# pulse/database.py
# ------------------
# Handles all SQLite database operations for Pulse.
#
# WHY SQLITE?
#   SQLite is a file-based database that ships with Python (no install needed).
#   It stores everything in a single file (pulse.db by default), making it
#   easy to back up, move, or delete. It's perfect for local tools like Pulse
#   where you don't need a server running in the background.
#
# WHAT GETS STORED?
#   Every time Pulse runs a scan, two things are saved:
#     1. A "scan" record — metadata about the scan (when, how many files, score)
#     2. One "finding" record per detection — the full detail of each alert
#
#   This lets you answer questions like:
#     - "Has my score improved since last week?"
#     - "When was the first time this rule fired?"
#     - "How many CRITICAL findings have I had this month?"
#
# SCHEMA:
#   scans    — one row per scan run
#   findings — one row per finding, linked to a scan via scan_id

import re
import sqlite3
import socket
from datetime import datetime, timedelta

from . import db_backend


def compute_ref_prefix(rule):
    """Return a 3-letter uppercase prefix derived from a rule name.

    Examples:
        "Pass-the-Hash Attempt"   -> "PTH"  (one initial per word)
        "Brute Force Attempt"     -> "BRF"  (2 words: first initial + 2nd
                                             char of first word + 2nd word
                                             initial)
        "Kerberoasting"           -> "KER"  (single word: first 3 chars)
    Non-letter characters (hyphens, digits, punctuation) are treated as word
    separators so "Pass-the-Hash" splits into three words.
    """
    words = [w for w in re.split(r"[^A-Za-z]+", rule or "") if w]
    if len(words) >= 3:
        prefix = words[0][0] + words[1][0] + words[2][0]
    elif len(words) == 2:
        first = words[0]
        prefix = first[0] + (first[1] if len(first) > 1 else "X") + words[1][0]
    elif len(words) == 1:
        prefix = (words[0] + "XX")[:3]
    else:
        prefix = "RUL"
    return prefix.upper()


def compute_ref_id(rule, finding_id):
    """'<3-letter prefix>-<zero-padded id>', e.g. 'PTH-0142'."""
    return "{}-{:04d}".format(compute_ref_prefix(rule), int(finding_id))


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at     TEXT    NOT NULL,
    hostname       TEXT,
    files_scanned  INTEGER DEFAULT 0,
    total_events   INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    score          INTEGER,
    score_label    TEXT,
    filename       TEXT,
    scope          TEXT,
    user_id        INTEGER
);
"""

_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    timestamp      TEXT,
    event_id       TEXT,
    severity       TEXT,
    rule           TEXT,
    mitre          TEXT,
    description    TEXT,
    details        TEXT,
    raw_xml        TEXT,
    hostname       TEXT,
    reviewed       INTEGER DEFAULT 0,
    false_positive INTEGER DEFAULT 0,
    review_note    TEXT,
    reviewed_at    TEXT,
    ref_id         TEXT
);
"""

# Records every email alert sent so we can enforce a cooldown window.
# Without this, a --watch loop that re-detects the same brute force every
# 30 seconds would send an email every 30 seconds. With this, we check
# alert_log first: if we already alerted on "Brute Force Attempt" within
# the last 60 minutes, skip sending another.
_CREATE_ALERT_LOG = """
CREATE TABLE IF NOT EXISTS alert_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    sent_at   TEXT    NOT NULL,
    rule      TEXT    NOT NULL,
    severity  TEXT,
    hostname  TEXT
);
"""

# Dashboard login. Scope today is single-user, but the schema supports more
# rows so future invite flows don't need a migration.
_CREATE_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'admin',
    active        INTEGER NOT NULL DEFAULT 1
);
"""

# Long-lived API tokens scoped to a user, used for CI pipelines hitting
# /api/scan and friends. Only the sha256 of the raw token is stored —
# the plaintext is shown to the user exactly once on creation and is
# unrecoverable afterwards. `last4` is the last 4 chars of the raw
# token, kept unhashed so the UI can let the user identify "which token
# did I paste into Jenkins" without exposing the full secret.
_CREATE_API_TOKENS = """
CREATE TABLE IF NOT EXISTS api_tokens (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name           TEXT    NOT NULL,
    token_sha256   TEXT    NOT NULL UNIQUE,
    last4          TEXT    NOT NULL,
    created_at     TEXT    NOT NULL,
    last_used_at   TEXT,
    revoked        INTEGER NOT NULL DEFAULT 0
);
"""

# IP block list — Pulse-managed inbound deny rules that get pushed into
# Windows Firewall via `netsh advfirewall`. Each row represents one IP we
# want (or have pushed) a firewall rule for. `status` tracks the lifecycle:
#   'pending' — staged in the DB but not yet in the firewall
#   'active'  — rule has been pushed to Windows Firewall
# The `rule_name` column stores the exact netsh rule name so we can find
# and delete it later. Every rule name starts with "Pulse-managed:" so we
# never touch user-created firewall rules.
_CREATE_IP_BLOCK_LIST = """
CREATE TABLE IF NOT EXISTS ip_block_list (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT    NOT NULL UNIQUE,
    comment     TEXT,
    status      TEXT    NOT NULL DEFAULT 'pending',
    added_at    TEXT    NOT NULL,
    pushed_at   TEXT,
    rule_name   TEXT,
    finding_id  INTEGER
);
"""

# Audit log — every block-list action is recorded here so a reviewer can
# reconstruct who did what. Separate from alert_log (which is email spam
# cooldown). Source is 'dashboard' or 'cli'. user is the signed-in email
# when the action came through the API; None for CLI actions.
_CREATE_AUDIT_LOG = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    ip_address  TEXT,
    comment     TEXT,
    source      TEXT    NOT NULL DEFAULT 'cli',
    user        TEXT,
    detail      TEXT
);
"""

# One row per "start monitoring → stop monitoring" span. Scans generated
# by the live monitor point back here via scans.session_id so the UI can
# group a session's findings together ("DVR for the monitor").
_CREATE_MONITOR_SESSIONS = """
CREATE TABLE IF NOT EXISTS monitor_sessions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at     TEXT    NOT NULL,
    ended_at       TEXT,
    duration_sec   INTEGER,
    poll_count     INTEGER DEFAULT 0,
    events_checked INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    channels       TEXT
);
"""

# In-app feedback submissions. Populated by the user-menu "Give Feedback"
# modal; `kind` is one of 'bug' / 'idea' / 'general'. `page_hint` records
# the SPA route the user was on when they opened the modal so bug reports
# land with context. `status` is reserved for future triage ('new',
# 'read', 'closed') — no UI yet.
_CREATE_FEEDBACK = """
CREATE TABLE IF NOT EXISTS feedback (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    submitted_at TEXT    NOT NULL,
    user_id      INTEGER,
    kind         TEXT    NOT NULL,
    message      TEXT    NOT NULL,
    page_hint    TEXT,
    status       TEXT    NOT NULL DEFAULT 'new'
);
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_db(db_path):
    """
    Creates the database file and tables if they don't already exist.

    Safe to call every time Pulse starts — it uses CREATE TABLE IF NOT EXISTS
    so it won't overwrite or reset an existing database.

    Parameters:
        db_path (str): Path to the SQLite file, or a `postgres(ql)://` DSN.
    """
    create_statements = (
        _CREATE_SCANS,
        _CREATE_FINDINGS,
        _CREATE_ALERT_LOG,
        _CREATE_USERS,
        _CREATE_API_TOKENS,
        _CREATE_IP_BLOCK_LIST,
        _CREATE_AUDIT_LOG,
        _CREATE_MONITOR_SESSIONS,
        _CREATE_FEEDBACK,
    )
    # ALTER TABLE ... ADD COLUMN for every column that was added after the
    # initial schema shipped. SQLite raises when the column already exists;
    # Postgres uses ADD COLUMN IF NOT EXISTS (db_backend.init_ddl rewrites
    # for us). The first user created before RBAC existed stays admin so
    # nobody gets locked out of an upgraded database.
    alter_statements = (
        "ALTER TABLE scans ADD COLUMN filename TEXT",
        "ALTER TABLE scans ADD COLUMN scope TEXT",
        "ALTER TABLE scans ADD COLUMN session_id INTEGER",
        "ALTER TABLE scans ADD COLUMN duration_sec INTEGER",
        "ALTER TABLE scans ADD COLUMN user_id INTEGER",
        "ALTER TABLE findings ADD COLUMN raw_xml TEXT",
        "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'",
        "ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE users ADD COLUMN avatar_blob BLOB",
        "ALTER TABLE users ADD COLUMN avatar_mime TEXT",
        "ALTER TABLE findings ADD COLUMN review_status TEXT DEFAULT 'new'",
        "ALTER TABLE findings ADD COLUMN review_note TEXT",
        "ALTER TABLE findings ADD COLUMN reviewed_at TEXT",
        "ALTER TABLE findings ADD COLUMN hostname TEXT",
        "ALTER TABLE findings ADD COLUMN reviewed INTEGER DEFAULT 0",
        "ALTER TABLE findings ADD COLUMN false_positive INTEGER DEFAULT 0",
        "ALTER TABLE findings ADD COLUMN ref_id TEXT",
    )

    with _connect(db_path) as conn:
        db_backend.init_ddl(conn, create_statements, alter_statements)

        # One-shot backfill from the legacy single-status column: rows that
        # were already marked 'reviewed' get reviewed=1; rows marked
        # 'false_positive' get false_positive=1. Idempotent — re-running
        # writes the same values. We only touch rows still at default 0/0
        # so a user who later clears `reviewed` doesn't get it re-set from
        # stale review_status on the next startup.
        try:
            conn.execute(
                "UPDATE findings SET reviewed = 1 "
                "WHERE review_status = 'reviewed' AND reviewed = 0 AND false_positive = 0"
            )
            conn.execute(
                "UPDATE findings SET false_positive = 1 "
                "WHERE review_status = 'false_positive' AND reviewed = 0 AND false_positive = 0"
            )
        except db_backend.OperationalError:
            pass

        # Backfill short reference IDs (e.g. "PTH-0142") for any finding
        # that existed before the ref_id column was added. Idempotent — only
        # rows with ref_id IS NULL are touched, so a user can rename a rule
        # after the fact without this clobbering a custom ref.
        try:
            rows = conn.execute(
                "SELECT id, rule FROM findings WHERE ref_id IS NULL"
            ).fetchall()
            for fid, rule in rows:
                conn.execute(
                    "UPDATE findings SET ref_id = ? WHERE id = ?",
                    (compute_ref_id(rule, fid), int(fid)),
                )
        except db_backend.OperationalError:
            pass


def save_scan(db_path, findings, scan_stats=None, score=None, score_label=None, filename=None, scope=None, session_id=None, duration_sec=None, user_id=None):
    """
    Saves a completed scan and all its findings to the database.

    Parameters:
        db_path (str):      Path to the .db file.
        findings (list):    List of finding dicts from run_all_detections().
        scan_stats (dict):  Optional scan metadata (files_scanned, total_events).
        score (int):        Optional security score (0-100).
        score_label (str):  Optional label e.g. "HIGH RISK".
        filename (str):     Optional name of the scanned file.
        scope (str):        Human-readable scope of what this scan covered —
                            e.g. "Last 7 days" for a system scan, or
                            "Manual upload" for a dropped .evtx.

    Returns:
        int: The scan_id of the newly inserted scan row.
    """
    scanned_at    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Prefer the hostname(s) present on the findings themselves — that's the
    # machine the events actually came from. Falls back to the local
    # machine name so uploaded-but-hostname-less scans still have a value.
    hostname      = _dominant_hostname(findings) or _get_hostname()
    files_scanned = scan_stats.get("files_scanned", 0) if scan_stats else 0
    total_events  = scan_stats.get("total_events",  0) if scan_stats else 0
    total_findings = len(findings)

    with _connect(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO scans
               (scanned_at, hostname, files_scanned, total_events,
                total_findings, score, score_label, filename, scope,
                session_id, duration_sec, user_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scanned_at, hostname, files_scanned, total_events,
             total_findings, score, score_label, filename, scope,
             session_id, duration_sec,
             int(user_id) if user_id else None)
        )
        scan_id = cursor.lastrowid

        # Insert one row per finding
        rows = []
        for f in findings:
            rows.append((
                scan_id,
                f.get("timestamp"),
                str(f.get("event_id", "")),
                f.get("severity"),
                f.get("rule"),
                f.get("mitre"),
                f.get("description"),
                f.get("details"),
                f.get("raw_xml"),
                f.get("hostname"),
            ))

        conn.executemany(
            """INSERT INTO findings
               (scan_id, timestamp, event_id, severity, rule,
                mitre, description, details, raw_xml, hostname)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows
        )

        # Stamp short reference IDs on the rows we just wrote. We select
        # back by scan_id instead of relying on batch lastrowid because
        # executemany() doesn't return a per-row id range on Postgres.
        fresh = conn.execute(
            "SELECT id, rule FROM findings WHERE scan_id = ? AND ref_id IS NULL",
            (scan_id,),
        ).fetchall()
        for fid, rule in fresh:
            conn.execute(
                "UPDATE findings SET ref_id = ? WHERE id = ?",
                (compute_ref_id(rule, fid), int(fid)),
            )

    return scan_id


def get_history(db_path, limit=20, user_id=None):
    """
    Returns a list of past scans, newest first.

    Each item is a dict with keys:
        id, scanned_at, hostname, files_scanned, total_events,
        total_findings, score, score_label

    Parameters:
        db_path (str):   Path to the .db file.
        limit (int):     Maximum number of scans to return (default 20).
        user_id (int|None): If set, only scans owned by this user are
                            returned. ``None`` returns every scan (the
                            admin / CLI view).

    Returns:
        list[dict]: Past scans, or an empty list if the DB doesn't exist yet.
    """
    try:
        with _connect(db_path) as conn:
            if user_id is None:
                where_outer, where_inner, params = "", "", ()
            else:
                where_outer = " WHERE s.user_id = ?"
                where_inner = " AND s2.user_id = ?"
                params = (int(user_id), int(user_id))
            cursor = conn.execute(
                f"""SELECT s.id, s.scanned_at, s.hostname, s.files_scanned,
                          s.total_events, s.total_findings, s.score, s.score_label,
                          s.filename, s.scope, s.duration_sec,
                          (SELECT COUNT(*) FROM scans s2
                           WHERE s2.id <= s.id{where_inner}) AS number
                   FROM scans s{where_outer}
                   ORDER BY s.id DESC
                   LIMIT ?""",
                params + (limit,)
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception:
        return []


def get_scan_number(db_path, scan_id, user_id=None):
    """
    Return the display number (position in current scan history, oldest = 1)
    for a given DB id. Returns None if the scan doesn't exist (or isn't
    visible to the supplied ``user_id``).
    """
    try:
        with _connect(db_path) as conn:
            if user_id is None:
                row = conn.execute(
                    "SELECT COUNT(*) FROM scans WHERE id <= ? "
                    "AND EXISTS (SELECT 1 FROM scans WHERE id = ?)",
                    (scan_id, scan_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT COUNT(*) FROM scans WHERE id <= ? AND user_id = ? "
                    "AND EXISTS (SELECT 1 FROM scans WHERE id = ? AND user_id = ?)",
                    (scan_id, int(user_id), scan_id, int(user_id)),
                ).fetchone()
            return int(row[0]) if row and row[0] else None
    except Exception:
        return None


def get_findings_since(db_path, days, user_id=None):
    """
    Return every finding whose parent scan ran within the last `days` days,
    annotated with the parent scan's id, timestamp, hostname, score, and
    score_label so a summary renderer can group by scan or by rule.

    Parameters:
        db_path (str): Path to the .db file.
        days (int):    Window in days (1 for last 24h, 7 for last week).

    Returns:
        list[dict]: Findings, newest-scan first; empty list if the DB is
                   missing or nothing falls within the window.
    """
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    try:
        with _connect(db_path) as conn:
            extra_where, extra_params = "", ()
            if user_id is not None:
                extra_where = " AND s.user_id = ?"
                extra_params = (int(user_id),)
            cursor = conn.execute(
                f"""SELECT f.id, f.ref_id, f.scan_id, f.timestamp, f.event_id, f.severity,
                          f.rule, f.mitre, f.description, f.details,
                          f.reviewed, f.false_positive,
                          s.scanned_at, s.hostname, s.score, s.score_label,
                          s.filename
                   FROM findings f
                   JOIN scans s ON s.id = f.scan_id
                   WHERE s.scanned_at >= ?{extra_where}
                   ORDER BY s.id DESC,
                       CASE f.severity
                           WHEN 'CRITICAL' THEN 1
                           WHEN 'HIGH'     THEN 2
                           WHEN 'MEDIUM'   THEN 3
                           WHEN 'LOW'      THEN 4
                           ELSE 5
                       END""",
                (cutoff,) + extra_params
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception:
        return []


def get_rule_stats(db_path, user_id=None):
    """
    Return per-rule aggregate statistics computed from the findings table.

    For every rule that has fired at least once, returns total hits, hits
    in the last 24h, a 24-bucket hourly histogram for the sparkline, the
    most recent timestamp, and false-positive / true-positive counts.

    Parameters:
        db_path (str):      Path to the .db file.
        user_id (int|None): If set, only counts findings from scans owned
                            by this user; None gives the admin / CLI view.

    Returns:
        dict[str, dict]: Keyed by rule name. Each value has the shape::

            {
                "hits_total":  int,
                "hits_24h":    int,
                "last_fired":  str | None,   # ISO-ish timestamp from scans
                "fp_count":    int,
                "tp_count":    int,
                "spark_24h":   list[int],    # 24 ints, oldest -> newest
            }
    """
    from collections import defaultdict
    now = datetime.now()
    cutoff_24h = (now - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    extra_where, extra_params = "", ()
    if user_id is not None:
        extra_where = " AND s.user_id = ?"
        extra_params = (int(user_id),)
    stats = {}
    try:
        with _connect(db_path) as conn:
            cursor = conn.execute(
                f"""SELECT f.rule,
                          COUNT(*)                                  AS hits_total,
                          SUM(CASE WHEN s.scanned_at >= ? THEN 1 ELSE 0 END)
                                                                    AS hits_24h,
                          SUM(CASE WHEN f.false_positive = 1 THEN 1 ELSE 0 END)
                                                                    AS fp_count,
                          SUM(CASE WHEN f.reviewed = 1 AND f.false_positive = 0 THEN 1 ELSE 0 END)
                                                                    AS tp_count,
                          MAX(s.scanned_at)                         AS last_fired
                   FROM findings f
                   JOIN scans s ON s.id = f.scan_id
                   WHERE f.rule IS NOT NULL{extra_where}
                   GROUP BY f.rule""",
                (cutoff_24h,) + extra_params
            )
            for row in cursor.fetchall():
                rule, hits_total, hits_24h, fp_count, tp_count, last_fired = row
                stats[rule] = {
                    "hits_total":  int(hits_total or 0),
                    "hits_24h":    int(hits_24h or 0),
                    "fp_count":    int(fp_count or 0),
                    "tp_count":    int(tp_count or 0),
                    "last_fired":  last_fired,
                    "spark_24h":   [0] * 24,
                }
            # Second pass — hour-bucket histogram for the sparkline. Running
            # this separately keeps the main aggregate GROUP BY simple and
            # still only touches the last-24h slice.
            cursor2 = conn.execute(
                f"""SELECT f.rule, s.scanned_at
                   FROM findings f
                   JOIN scans s ON s.id = f.scan_id
                   WHERE f.rule IS NOT NULL AND s.scanned_at >= ?{extra_where}""",
                (cutoff_24h,) + extra_params
            )
            buckets = defaultdict(lambda: [0] * 24)
            for rule, scanned_at in cursor2.fetchall():
                try:
                    ts = datetime.strptime(str(scanned_at), "%Y-%m-%d %H:%M:%S")
                except Exception:
                    continue
                hours_ago = int((now - ts).total_seconds() // 3600)
                if 0 <= hours_ago < 24:
                    # bucket 0 = oldest, bucket 23 = most recent full hour
                    buckets[rule][23 - hours_ago] += 1
            for rule, bkt in buckets.items():
                if rule in stats:
                    stats[rule]["spark_24h"] = bkt
    except Exception:
        return {}
    return stats


def get_scans_since(db_path, days, user_id=None):
    """Return every scan row whose scanned_at falls within the last `days` days.

    Pass ``user_id`` to restrict the result to one user's scans; ``None``
    returns every row (admin / CLI view).
    """
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    try:
        with _connect(db_path) as conn:
            extra_where, extra_params = "", ()
            if user_id is not None:
                extra_where = " AND user_id = ?"
                extra_params = (int(user_id),)
            cursor = conn.execute(
                f"""SELECT id, scanned_at, hostname, files_scanned,
                          total_events, total_findings, score, score_label,
                          filename
                   FROM scans
                   WHERE scanned_at >= ?{extra_where}
                   ORDER BY id DESC""",
                (cutoff,) + extra_params
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception:
        return []


def get_scan_findings(db_path, scan_id, user_id=None):
    """
    Returns all findings for a specific scan.

    Parameters:
        db_path (str):   Path to the .db file.
        scan_id (int):   The scan ID to look up.
        user_id (int|None): If set, an empty list is returned when the scan
                            belongs to another user. ``None`` bypasses the
                            ownership check (admin / CLI view).

    Returns:
        list[dict]: Findings for that scan.
    """
    with _connect(db_path) as conn:
        if user_id is not None:
            owner = conn.execute(
                "SELECT user_id FROM scans WHERE id = ?", (int(scan_id),)
            ).fetchone()
            if not owner or owner[0] != int(user_id):
                return []
        cursor = conn.execute(
            """SELECT id, ref_id, timestamp, event_id, severity, rule,
                      mitre, description, details, raw_xml, hostname,
                      reviewed, false_positive, review_note, reviewed_at
               FROM findings
               WHERE scan_id = ?
               ORDER BY
                   CASE severity
                       WHEN 'CRITICAL' THEN 1
                       WHEN 'HIGH'     THEN 2
                       WHEN 'MEDIUM'   THEN 3
                       WHEN 'LOW'      THEN 4
                       ELSE 5
                   END""",
            (scan_id,)
        )
        cols = [d[0] for d in cursor.description]
        rows = []
        for row in cursor.fetchall():
            d = dict(zip(cols, row))
            d["reviewed"] = bool(d.get("reviewed"))
            d["false_positive"] = bool(d.get("false_positive"))
            rows.append(d)
        return rows


def set_finding_review(db_path, finding_id, reviewed, false_positive, note=None):
    """
    Update the review flags (and optional note) for a single finding.

    reviewed and false_positive are INDEPENDENT booleans — a finding can
    be reviewed, a false positive, both, or neither. 'Reviewed' means
    an analyst looked at it; 'false_positive' means it's not a real
    threat. Those are different judgements, so they toggle separately.

    Parameters:
        db_path (str):         Path to the .db file.
        finding_id (int):      Row id from the findings table.
        reviewed (bool):       Whether the finding has been reviewed.
        false_positive (bool): Whether the finding is a false positive.
        note (str | None):     Free-text analyst note. Pass None to clear.

    Returns:
        dict | None: The updated finding row (same shape as get_scan_findings
                     items) or None if no such finding id exists.
    """
    r = 1 if reviewed else 0
    fp = 1 if false_positive else 0
    # reviewed_at is the timestamp of the most recent touch — set it if
    # either flag is on, clear it if the user flipped both off so the UI
    # can tell "never touched" apart from "touched then reset".
    reviewed_at = (datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                   if (r or fp) else None)
    clean_note = (note or "").strip() or None

    with _connect(db_path) as conn:
        conn.execute(
            """UPDATE findings
               SET reviewed = ?, false_positive = ?,
                   review_note = ?, reviewed_at = ?
               WHERE id = ?""",
            (r, fp, clean_note, reviewed_at, int(finding_id)),
        )
        row = conn.execute(
            """SELECT id, ref_id, scan_id, timestamp, event_id, severity, rule,
                      mitre, description, details, raw_xml, hostname,
                      reviewed, false_positive, review_note, reviewed_at
               FROM findings WHERE id = ?""",
            (int(finding_id),),
        ).fetchone()
        if not row:
            return None
        cols = ("id", "ref_id", "scan_id", "timestamp", "event_id", "severity", "rule",
                "mitre", "description", "details", "raw_xml", "hostname",
                "reviewed", "false_positive", "review_note", "reviewed_at")
        d = dict(zip(cols, row))
        d["reviewed"] = bool(d["reviewed"])
        d["false_positive"] = bool(d["false_positive"])
        return d


def get_fleet_summary(db_path, user_id=None):
    """Roll up scan + finding counts per hostname for the Fleet overview.

    Returns one row per distinct ``scans.hostname`` with:
        - hostname       (str)
        - scan_count     (int)   total scans recorded for this host
        - last_scan_at   (str)   scanned_at of the newest scan
        - total_findings (int)   sum of total_findings across every scan
        - latest_score   (int|None)  score from the newest scan
        - latest_grade   (str|None)  letter grade from the newest scan
        - worst_severity (str|None)  highest severity seen across all findings

    Scans without a hostname are excluded — they predate Sprint 4 or came
    from logs with no Computer field, which can't be attributed to a host.
    The list is sorted by last_scan_at DESC.
    """
    sev_rank = {
        "CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4,
    }
    try:
        with _connect(db_path) as conn:
            # Two queries are simpler than one window-function query and
            # SQLite's min/max-over-group gymnastics. First query: per-host
            # aggregates. Second: newest scan row per host so we can read
            # its score + grade without relying on GROUP BY argmax tricks.
            scope_where, scope_params = "", ()
            if user_id is not None:
                scope_where = " AND user_id = ?"
                scope_params = (int(user_id),)
            cursor = conn.execute(
                f"""SELECT hostname,
                          COUNT(*)                    AS scan_count,
                          MAX(scanned_at)             AS last_scan_at,
                          COALESCE(SUM(total_findings), 0) AS total_findings
                   FROM scans
                   WHERE hostname IS NOT NULL AND hostname != ''{scope_where}
                   GROUP BY hostname
                   ORDER BY last_scan_at DESC""",
                scope_params
            )
            rows = cursor.fetchall()
            if not rows:
                return []

            out = []
            for host, scans, last_at, total_findings in rows:
                latest = conn.execute(
                    f"""SELECT score, score_label
                       FROM scans
                       WHERE hostname = ?{scope_where}
                       ORDER BY id DESC
                       LIMIT 1""",
                    (host,) + scope_params,
                ).fetchone()
                latest_score = latest[0] if latest else None
                latest_grade = latest[1] if latest else None

                worst_row = conn.execute(
                    f"""SELECT MIN(CASE f.severity
                                      WHEN 'CRITICAL' THEN 1
                                      WHEN 'HIGH'     THEN 2
                                      WHEN 'MEDIUM'   THEN 3
                                      WHEN 'LOW'      THEN 4
                                      ELSE 5 END) AS rank,
                              f.severity
                       FROM findings f
                       JOIN scans s ON s.id = f.scan_id
                       WHERE s.hostname = ?{(" AND s.user_id = ?" if user_id is not None else "")}""",
                    (host,) + scope_params,
                ).fetchone()
                worst = None
                if worst_row and worst_row[0] is not None and worst_row[0] < 5:
                    # MIN() + ANY value trick: the returned severity isn't
                    # guaranteed to match the minimum rank across all rows in
                    # SQLite, so map the numeric rank back explicitly.
                    rank_to_sev = {v: k for k, v in sev_rank.items()}
                    worst = rank_to_sev.get(worst_row[0])

                out.append({
                    "hostname":       host,
                    "scan_count":     int(scans or 0),
                    "last_scan_at":   last_at,
                    "total_findings": int(total_findings or 0),
                    "latest_score":   int(latest_score) if latest_score is not None else None,
                    "latest_grade":   latest_grade,
                    "worst_severity": worst,
                })
            return out
    except Exception:
        return []


def delete_scans(db_path, scan_ids, user_id=None):
    """Delete one or more scans (and their findings via ON DELETE CASCADE).

    Pass ``user_id`` to restrict the delete to rows owned by that user —
    a viewer can only wipe their own scans. ``None`` deletes unconditionally
    (admin / CLI tool path).

    Returns the number of scan rows actually deleted.
    """
    ids = [int(i) for i in (scan_ids or []) if str(i).strip()]
    if not ids:
        return 0
    placeholders = ",".join("?" for _ in ids)
    with _connect(db_path) as conn:
        if user_id is None:
            cursor = conn.execute(
                f"DELETE FROM scans WHERE id IN ({placeholders})", ids
            )
        else:
            cursor = conn.execute(
                f"DELETE FROM scans WHERE id IN ({placeholders}) AND user_id = ?",
                ids + [int(user_id)]
            )
        return cursor.rowcount or 0


# ---------------------------------------------------------------------------
# Analytics — aggregates for the Trends dashboard page
# ---------------------------------------------------------------------------


def get_trend_analytics(db_path, days=30, user_id=None):
    """Aggregate finding counts over a rolling window for the Trends page.

    Returns a dict with:
      - window_days (int)        the requested window length
      - totals (dict)            {this_window, prev_window, delta_pct}
      - top_rules  (list[dict])  top 10 rules by count in this window
                                 (rule, count, severity)
      - top_hosts  (list[dict])  top 10 hostnames by finding count
                                 (hostname, count)
      - severity_breakdown (dict)  {CRITICAL, HIGH, MEDIUM, LOW}
      - daily_counts (list[dict])  [{date: 'YYYY-MM-DD', count: N}] for
                                   every day in the window (dense — zero-
                                   fill so the line chart doesn't gap)

    When ``user_id`` is provided, every aggregate is scoped to scans owned
    by that user (data-isolation for non-admins). ``None`` returns every
    scan (the admin view).
    """
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = 30
    if days <= 0:
        days = 30

    # Cutoff anchors — we look back two full windows so we can compare
    # "this window" against the one just before it for a WoW/MoM delta.
    now = datetime.now()
    this_start = (now - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    prev_start = (now - timedelta(days=days * 2)).strftime("%Y-%m-%d %H:%M:%S")

    empty = {
        "window_days": days,
        "totals": {"this_window": 0, "prev_window": 0, "delta_pct": None},
        "top_rules": [],
        "top_hosts": [],
        "severity_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "daily_counts": _dense_daily(now, days, {}),
    }

    try:
        with _connect(db_path) as conn:
            scope_filter = ""
            scope_params = ()
            if user_id is not None:
                scope_filter = " AND s.user_id = ?"
                scope_params = (int(user_id),)

            def _count_in(start_iso, end_iso=None):
                sql = (
                    "SELECT COUNT(*) FROM findings f "
                    "JOIN scans s ON s.id = f.scan_id "
                    "WHERE s.scanned_at >= ?"
                )
                params = [start_iso]
                if end_iso is not None:
                    sql += " AND s.scanned_at < ?"
                    params.append(end_iso)
                sql += scope_filter
                params.extend(scope_params)
                row = conn.execute(sql, params).fetchone()
                return int(row[0]) if row else 0

            this_total = _count_in(this_start)
            prev_total = _count_in(prev_start, this_start)

            # WoW / MoM delta as a percentage. A zero previous window can't
            # produce a meaningful percentage, so we report None (UI shows
            # "n/a") rather than pretend the change was "infinite".
            delta_pct = None
            if prev_total:
                delta_pct = round(((this_total - prev_total) / prev_total) * 100.0, 1)

            top_rules_rows = conn.execute(
                "SELECT f.rule, f.severity, COUNT(*) AS n FROM findings f "
                "JOIN scans s ON s.id = f.scan_id "
                "WHERE s.scanned_at >= ?" + scope_filter +
                " AND f.rule IS NOT NULL AND f.rule != '' "
                "GROUP BY f.rule ORDER BY n DESC LIMIT 10",
                (this_start,) + scope_params,
            ).fetchall()

            top_hosts_rows = conn.execute(
                "SELECT COALESCE(NULLIF(f.hostname, ''), NULLIF(s.hostname, '')) AS host, "
                "       COUNT(*) AS n FROM findings f "
                "JOIN scans s ON s.id = f.scan_id "
                "WHERE s.scanned_at >= ?" + scope_filter +
                " GROUP BY host HAVING host IS NOT NULL "
                "ORDER BY n DESC LIMIT 10",
                (this_start,) + scope_params,
            ).fetchall()

            sev_rows = conn.execute(
                "SELECT UPPER(f.severity) AS sev, COUNT(*) AS n FROM findings f "
                "JOIN scans s ON s.id = f.scan_id "
                "WHERE s.scanned_at >= ?" + scope_filter +
                " AND f.severity IS NOT NULL GROUP BY sev",
                (this_start,) + scope_params,
            ).fetchall()

            # SQLite stores scanned_at as 'YYYY-MM-DD HH:MM:SS' — substr the
            # first 10 chars for the date bucket. This stays in local time
            # because that's what save_scan writes, so the dashboard line
            # chart lines up with what the user sees on History.
            daily_rows = conn.execute(
                "SELECT substr(s.scanned_at, 1, 10) AS d, COUNT(*) AS n "
                "FROM findings f JOIN scans s ON s.id = f.scan_id "
                "WHERE s.scanned_at >= ?" + scope_filter +
                " GROUP BY d ORDER BY d ASC",
                (this_start,) + scope_params,
            ).fetchall()

    except db_backend.OperationalError:
        return empty

    sev_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for sev, n in sev_rows:
        key = (sev or "").upper()
        if key in sev_breakdown:
            sev_breakdown[key] = int(n)

    daily_map = {row[0]: int(row[1]) for row in daily_rows if row[0]}

    return {
        "window_days": days,
        "totals": {
            "this_window": this_total,
            "prev_window": prev_total,
            "delta_pct":   delta_pct,
        },
        "top_rules": [
            {"rule": r[0], "severity": (r[1] or "").upper() or None, "count": int(r[2])}
            for r in top_rules_rows
        ],
        "top_hosts": [{"hostname": r[0], "count": int(r[1])} for r in top_hosts_rows],
        "severity_breakdown": sev_breakdown,
        "daily_counts": _dense_daily(now, days, daily_map),
    }


def _dense_daily(now, days, by_date):
    """Return a list of {date, count} covering every day from `now - days`
    to `now`, zero-filling days that had no findings."""
    out = []
    start = now - timedelta(days=days - 1)
    for i in range(days):
        d = (start + timedelta(days=i)).strftime("%Y-%m-%d")
        out.append({"date": d, "count": int(by_date.get(d, 0))})
    return out


# ---------------------------------------------------------------------------
# Monitor sessions — one row per Start/Stop span on the live monitor
# ---------------------------------------------------------------------------

def create_monitor_session(db_path, started_at=None, channels=None):
    """Insert a new monitor session and return its id."""
    started_at = started_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    channels_txt = ",".join(channels) if channels else None
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO monitor_sessions
               (started_at, channels)
               VALUES (?, ?)""",
            (started_at, channels_txt),
        )
        return cursor.lastrowid


def close_monitor_session(db_path, session_id, poll_count, events_checked, findings_count):
    """Stamp the session's ended_at + duration + final counters."""
    ended_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT started_at FROM monitor_sessions WHERE id = ?",
            (int(session_id),),
        ).fetchone()
        duration_sec = None
        if row:
            try:
                started = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
                duration_sec = int((datetime.now() - started).total_seconds())
            except Exception:
                duration_sec = None
        conn.execute(
            """UPDATE monitor_sessions
               SET ended_at = ?, duration_sec = ?, poll_count = ?,
                   events_checked = ?, findings_count = ?
               WHERE id = ?""",
            (ended_at, duration_sec, int(poll_count or 0),
             int(events_checked or 0), int(findings_count or 0), int(session_id)),
        )


def list_monitor_sessions(db_path, limit=100):
    """Return monitor sessions newest-first, with findings_count rolled up
    from linked scans so an interrupted session (no close) still shows a
    sensible count."""
    try:
        with _connect(db_path) as conn:
            cursor = conn.execute(
                """SELECT ms.id, ms.started_at, ms.ended_at, ms.duration_sec,
                          ms.poll_count, ms.events_checked, ms.findings_count,
                          ms.channels,
                          COALESCE(SUM(s.total_findings), 0) AS live_findings
                   FROM monitor_sessions ms
                   LEFT JOIN scans s ON s.session_id = ms.id
                   GROUP BY ms.id
                   ORDER BY ms.id DESC
                   LIMIT ?""",
                (int(limit),),
            )
            cols = [d[0] for d in cursor.description]
            out = []
            for row in cursor.fetchall():
                d = dict(zip(cols, row))
                # Prefer the closed-out stored count; otherwise use the live
                # roll-up so "currently active" sessions still show a number.
                if not d.get("findings_count"):
                    d["findings_count"] = int(d.get("live_findings") or 0)
                d.pop("live_findings", None)
                out.append(d)
            return out
    except Exception:
        return []


def get_monitor_session_findings(db_path, session_id):
    """Return every finding whose parent scan is linked to this session."""
    try:
        with _connect(db_path) as conn:
            cursor = conn.execute(
                """SELECT f.id, f.ref_id, f.scan_id, f.timestamp, f.event_id, f.severity,
                          f.rule, f.mitre, f.description, f.details, f.raw_xml,
                          f.reviewed, f.false_positive, f.review_note, f.reviewed_at,
                          s.scanned_at
                   FROM findings f
                   JOIN scans s ON s.id = f.scan_id
                   WHERE s.session_id = ?
                   ORDER BY f.id DESC""",
                (int(session_id),),
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception:
        return []


def delete_monitor_session(db_path, session_id):
    """Delete a single session plus all scans (and findings via cascade)
    that belonged to it. Returns True if a session row was removed."""
    try:
        with _connect(db_path) as conn:
            conn.execute(
                "DELETE FROM scans WHERE session_id = ?",
                (int(session_id),),
            )
            cursor = conn.execute(
                "DELETE FROM monitor_sessions WHERE id = ?",
                (int(session_id),),
            )
            return (cursor.rowcount or 0) > 0
    except Exception:
        return False


def delete_all_monitor_sessions(db_path):
    """Wipe every session + its linked scans/findings. Returns count deleted."""
    try:
        with _connect(db_path) as conn:
            conn.execute(
                "DELETE FROM scans WHERE session_id IS NOT NULL",
            )
            cursor = conn.execute("DELETE FROM monitor_sessions")
            return cursor.rowcount or 0
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Alert log — cooldown tracking for email alerts
# ---------------------------------------------------------------------------

def record_alert(db_path, rule, severity=None, hostname=None):
    """
    Records that an alert email was just sent for a given rule.

    Called by the email-alert code AFTER a successful send_alert() call.
    The row it writes is what was_recently_alerted() checks against.

    Parameters:
        db_path (str):  Path to the .db file.
        rule (str):     Name of the detection rule that triggered, e.g.
                        "Brute Force Attempt".
        severity (str): Severity label (CRITICAL/HIGH/MEDIUM/LOW).
        hostname (str): Which host the alert was about. Defaults to local.
    """
    sent_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if hostname is None:
        hostname = _get_hostname()

    with _connect(db_path) as conn:
        conn.execute(
            """INSERT INTO alert_log (sent_at, rule, severity, hostname)
               VALUES (?, ?, ?, ?)""",
            (sent_at, rule, severity, hostname)
        )


def was_recently_alerted(db_path, rule, cooldown_minutes=60):
    """
    Checks whether an alert for `rule` was already sent within the cooldown window.

    Cooldown is a spam guard. Without it, --watch mode would re-detect the
    same brute force every poll cycle and email you every 30 seconds until
    you disabled the feature in anger. With it, each unique rule only fires
    at most once per `cooldown_minutes`.

    Parameters:
        db_path (str):           Path to the .db file.
        rule (str):              Rule name to check.
        cooldown_minutes (int):  How far back to look. 60 = "last hour".

    Returns:
        bool: True if we already alerted on this rule recently, False otherwise.
    """
    if not db_path:
        return False   # no DB -> can't track cooldown -> always allow

    # Compute the cutoff in Python so the SQL stays portable across SQLite
    # and Postgres — SQLite's `datetime('now', 'localtime', '-N minutes')`
    # modifier syntax isn't valid Postgres. record_alert writes sent_at as
    # a local-time string via datetime.now(), so we do the same here.
    cutoff = (datetime.now() - timedelta(minutes=int(cooldown_minutes))).strftime("%Y-%m-%d %H:%M:%S")
    try:
        with _connect(db_path) as conn:
            cursor = conn.execute(
                """SELECT 1 FROM alert_log
                   WHERE rule = ?
                     AND sent_at > ?
                   LIMIT 1""",
                (rule, cutoff)
            )
            return cursor.fetchone() is not None
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Users (dashboard login)
# ---------------------------------------------------------------------------

def count_users(db_path):
    """Number of rows in the users table. Used to decide whether signup is
    still open (signup is allowed only when the table is empty)."""
    with _connect(db_path) as conn:
        row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        return int(row[0]) if row else 0


_USER_COLS = "id, email, password_hash, created_at, role, active, avatar_mime"


def _row_to_user(row):
    if not row:
        return None
    return {
        "id": row[0],
        "email": row[1],
        "password_hash": row[2],
        "created_at": row[3],
        "role": row[4] or "admin",
        "active": bool(row[5]) if row[5] is not None else True,
        "avatar_mime": row[6] if len(row) > 6 else None,
    }


def set_user_avatar(db_path, user_id, blob, mime):
    """Store an avatar image as a BLOB on the user row. The mime type is
    tracked separately so GET /api/me/avatar can serve the file with the
    right Content-Type."""
    with _connect(db_path) as conn:
        conn.execute(
            "UPDATE users SET avatar_blob = ?, avatar_mime = ? WHERE id = ?",
            (blob, mime, int(user_id)),
        )


def get_user_avatar(db_path, user_id):
    """Return (blob, mime) for a user's avatar, or (None, None) if unset."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT avatar_blob, avatar_mime FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
    if not row or row[0] is None:
        return None, None
    return row[0], row[1]


def create_user(db_path, email, password_hash, role="viewer"):
    """Insert a new user and return the row id. Email is lowercased and
    stripped so lookups are consistent. `role` is 'admin' or 'viewer'; the
    first user created (empty table) is always promoted to admin so there
    is never a locked-out database."""
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("email is required")
    role = (role or "viewer").strip().lower()
    if role not in ("admin", "viewer"):
        raise ValueError("role must be 'admin' or 'viewer'")
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _connect(db_path) as conn:
        first = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        if first:
            role = "admin"
        cursor = conn.execute(
            "INSERT INTO users (email, password_hash, created_at, role, active)"
            " VALUES (?, ?, ?, ?, 1)",
            (email, password_hash, created_at, role),
        )
        return cursor.lastrowid


def get_user_by_email(db_path, email):
    email = (email or "").strip().lower()
    if not email:
        return None
    with _connect(db_path) as conn:
        row = conn.execute(
            f"SELECT {_USER_COLS} FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        return _row_to_user(row)


def get_user_by_id(db_path, user_id):
    with _connect(db_path) as conn:
        row = conn.execute(
            f"SELECT {_USER_COLS} FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
        return _row_to_user(row)


def list_users(db_path):
    """Return every user (active + deactivated), newest first. Used by the
    admin user-management page."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT {_USER_COLS} FROM users ORDER BY id DESC"
        ).fetchall()
    return [_row_to_user(r) for r in rows]


def update_user_email(db_path, user_id, new_email):
    new_email = (new_email or "").strip().lower()
    if not new_email:
        raise ValueError("email is required")
    with _connect(db_path) as conn:
        conn.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, int(user_id)))


def update_user_password(db_path, user_id, password_hash):
    with _connect(db_path) as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, int(user_id)),
        )


def update_user_role(db_path, user_id, role):
    """Set the role ('admin'|'viewer') on a user."""
    role = (role or "").strip().lower()
    if role not in ("admin", "viewer"):
        raise ValueError("role must be 'admin' or 'viewer'")
    with _connect(db_path) as conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, int(user_id)))


def update_user_active(db_path, user_id, active):
    """Activate / deactivate a user. Deactivated users can't log in."""
    with _connect(db_path) as conn:
        conn.execute(
            "UPDATE users SET active = ? WHERE id = ?",
            (1 if active else 0, int(user_id)),
        )


def delete_user(db_path, user_id):
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (int(user_id),))


def count_admins(db_path, *, active_only=True):
    """How many admin accounts exist. Used to guard against the last admin
    being demoted or deactivated — which would lock everyone out."""
    sql = "SELECT COUNT(*) FROM users WHERE role = 'admin'"
    if active_only:
        sql += " AND active = 1"
    with _connect(db_path) as conn:
        row = conn.execute(sql).fetchone()
        return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# API tokens (CI-pipeline bearer auth)
# ---------------------------------------------------------------------------

def create_api_token(db_path, user_id, name, token_sha256, last4):
    """Insert a new token row and return the new row id. The raw token is
    never stored — only its sha256 plus the last 4 chars so the UI can
    identify the entry ("ends in a1b2")."""
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _connect(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO api_tokens (user_id, name, token_sha256, last4, created_at, revoked)"
            " VALUES (?, ?, ?, ?, ?, 0)",
            (int(user_id), name, token_sha256, last4, created_at),
        )
        return cursor.lastrowid


def list_api_tokens(db_path, user_id):
    """Return non-revoked tokens for a user, newest first. Each row is a
    dict: id, name, last4, created_at, last_used_at."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, name, last4, created_at, last_used_at"
            "  FROM api_tokens"
            " WHERE user_id = ? AND revoked = 0"
            " ORDER BY id DESC",
            (int(user_id),),
        ).fetchall()
    return [
        {
            "id": r[0],
            "name": r[1],
            "last4": r[2],
            "created_at": r[3],
            "last_used_at": r[4],
        }
        for r in rows
    ]


def revoke_api_token(db_path, token_id, user_id):
    """Soft-delete: mark the token revoked if it belongs to this user.
    Returns True if a row was updated, False if the id didn't match."""
    with _connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE api_tokens SET revoked = 1"
            " WHERE id = ? AND user_id = ? AND revoked = 0",
            (int(token_id), int(user_id)),
        )
        return cursor.rowcount > 0


def find_api_token_user(db_path, token_sha256):
    """Look up the user_id that owns a given token hash, or None if no
    live token matches. Used by the API auth middleware to authenticate
    Bearer-token requests."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT user_id FROM api_tokens"
            " WHERE token_sha256 = ? AND revoked = 0",
            (token_sha256,),
        ).fetchone()
    return int(row[0]) if row else None


def touch_api_token(db_path, token_sha256):
    """Bump last_used_at to now so the UI can show 'last used 5 min ago'.
    Silently no-ops if the token doesn't exist or is revoked."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _connect(db_path) as conn:
        conn.execute(
            "UPDATE api_tokens SET last_used_at = ?"
            " WHERE token_sha256 = ? AND revoked = 0",
            (now, token_sha256),
        )


# ---------------------------------------------------------------------------
# Feedback
# ---------------------------------------------------------------------------

_FEEDBACK_KINDS = ("bug", "idea", "general")


def insert_feedback(db_path, user_id, kind, message, page_hint=None):
    """Persist one feedback submission. Returns the new row id.

    Caller is expected to validate `kind` + `message` length before calling;
    this function re-validates `kind` as a cheap safety net but does not
    re-truncate the message.
    """
    if kind not in _FEEDBACK_KINDS:
        kind = "general"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO feedback (submitted_at, user_id, kind, message, page_hint)
               VALUES (?, ?, ?, ?, ?)""",
            (ts, user_id, kind, message, page_hint),
        )
        try:
            return cursor.lastrowid
        except Exception:
            return None


def list_feedback(db_path, limit=200):
    """Return feedback submissions newest-first. Admin view only."""
    try:
        with _connect(db_path) as conn:
            cursor = conn.execute(
                """SELECT f.id, f.submitted_at, f.user_id, f.kind, f.message,
                          f.page_hint, f.status, u.email
                   FROM feedback f
                   LEFT JOIN users u ON u.id = f.user_id
                   ORDER BY f.id DESC
                   LIMIT ?""",
                (int(limit),),
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _connect(db_path):
    """Opens a connection to the configured database.

    Accepts either a SQLite file path or a `postgres(ql)://` DSN; the
    returned object behaves like a sqlite3 Connection either way (see
    pulse.db_backend).
    """
    return db_backend.connect(db_path)


def _get_hostname():
    try:
        return socket.gethostname()
    except Exception:
        return "Unknown"


def _dominant_hostname(findings):
    """Return the hostname that appears on the most findings, or None.

    Used to tag a scan with the machine its log events came from — which is
    not necessarily the machine running Pulse (uploaded .evtx files often
    come from elsewhere).
    """
    if not findings:
        return None
    counts = {}
    for f in findings:
        host = (f.get("hostname") or "").strip()
        if not host:
            continue
        counts[host] = counts.get(host, 0) + 1
    if not counts:
        return None
    return max(counts.items(), key=lambda kv: kv[1])[0]
