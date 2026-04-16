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

import sqlite3
import socket
from datetime import datetime, timedelta


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
    filename       TEXT
);
"""

_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    timestamp     TEXT,
    event_id      TEXT,
    severity      TEXT,
    rule          TEXT,
    mitre         TEXT,
    description   TEXT,
    details       TEXT,
    raw_xml       TEXT,
    review_status TEXT DEFAULT 'new',
    review_note   TEXT,
    reviewed_at   TEXT
);
"""

# Valid values for findings.review_status. Kept as a module constant so the
# API layer and dashboard can reference the same source of truth.
REVIEW_STATUSES = ("new", "reviewed", "false_positive")

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
    created_at    TEXT    NOT NULL
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
        db_path (str): Path to the .db file (e.g. "pulse.db").
    """
    with _connect(db_path) as conn:
        conn.execute(_CREATE_SCANS)
        conn.execute(_CREATE_FINDINGS)
        conn.execute(_CREATE_ALERT_LOG)
        conn.execute(_CREATE_USERS)
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN filename TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE findings ADD COLUMN raw_xml TEXT")
        except sqlite3.OperationalError:
            pass
        for col, ddl in (
            ("review_status", "ALTER TABLE findings ADD COLUMN review_status TEXT DEFAULT 'new'"),
            ("review_note",   "ALTER TABLE findings ADD COLUMN review_note TEXT"),
            ("reviewed_at",   "ALTER TABLE findings ADD COLUMN reviewed_at TEXT"),
        ):
            try:
                conn.execute(ddl)
            except sqlite3.OperationalError:
                pass


def save_scan(db_path, findings, scan_stats=None, score=None, score_label=None, filename=None):
    """
    Saves a completed scan and all its findings to the database.

    Parameters:
        db_path (str):      Path to the .db file.
        findings (list):    List of finding dicts from run_all_detections().
        scan_stats (dict):  Optional scan metadata (files_scanned, total_events).
        score (int):        Optional security score (0-100).
        score_label (str):  Optional label e.g. "HIGH RISK".
        filename (str):     Optional name of the scanned file.

    Returns:
        int: The scan_id of the newly inserted scan row.
    """
    scanned_at    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname      = _get_hostname()
    files_scanned = scan_stats.get("files_scanned", 0) if scan_stats else 0
    total_events  = scan_stats.get("total_events",  0) if scan_stats else 0
    total_findings = len(findings)

    with _connect(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO scans
               (scanned_at, hostname, files_scanned, total_events,
                total_findings, score, score_label, filename)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (scanned_at, hostname, files_scanned, total_events,
             total_findings, score, score_label, filename)
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
            ))

        conn.executemany(
            """INSERT INTO findings
               (scan_id, timestamp, event_id, severity, rule,
                mitre, description, details, raw_xml)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows
        )

    return scan_id


def get_history(db_path, limit=20):
    """
    Returns a list of past scans, newest first.

    Each item is a dict with keys:
        id, scanned_at, hostname, files_scanned, total_events,
        total_findings, score, score_label

    Parameters:
        db_path (str): Path to the .db file.
        limit (int):   Maximum number of scans to return (default 20).

    Returns:
        list[dict]: Past scans, or an empty list if the DB doesn't exist yet.
    """
    try:
        with _connect(db_path) as conn:
            cursor = conn.execute(
                """SELECT id, scanned_at, hostname, files_scanned,
                          total_events, total_findings, score, score_label,
                          filename
                   FROM scans
                   ORDER BY id DESC
                   LIMIT ?""",
                (limit,)
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception:
        return []


def get_findings_since(db_path, days):
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
            cursor = conn.execute(
                """SELECT f.id, f.scan_id, f.timestamp, f.event_id, f.severity,
                          f.rule, f.mitre, f.description, f.details,
                          f.review_status,
                          s.scanned_at, s.hostname, s.score, s.score_label,
                          s.filename
                   FROM findings f
                   JOIN scans s ON s.id = f.scan_id
                   WHERE s.scanned_at >= ?
                   ORDER BY s.id DESC,
                       CASE f.severity
                           WHEN 'CRITICAL' THEN 1
                           WHEN 'HIGH'     THEN 2
                           WHEN 'MEDIUM'   THEN 3
                           WHEN 'LOW'      THEN 4
                           ELSE 5
                       END""",
                (cutoff,)
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception:
        return []


def get_scans_since(db_path, days):
    """Return every scan row whose scanned_at falls within the last `days` days."""
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    try:
        with _connect(db_path) as conn:
            cursor = conn.execute(
                """SELECT id, scanned_at, hostname, files_scanned,
                          total_events, total_findings, score, score_label,
                          filename
                   FROM scans
                   WHERE scanned_at >= ?
                   ORDER BY id DESC""",
                (cutoff,)
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception:
        return []


def get_scan_findings(db_path, scan_id):
    """
    Returns all findings for a specific scan.

    Parameters:
        db_path (str): Path to the .db file.
        scan_id (int): The scan ID to look up.

    Returns:
        list[dict]: Findings for that scan.
    """
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """SELECT id, timestamp, event_id, severity, rule,
                      mitre, description, details, raw_xml,
                      review_status, review_note, reviewed_at
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
        return [dict(zip(cols, row)) for row in cursor.fetchall()]


def set_finding_review(db_path, finding_id, status, note=None):
    """
    Update the review status (and optional note) for a single finding.

    Parameters:
        db_path (str):      Path to the .db file.
        finding_id (int):   Row id from the findings table.
        status (str):       One of REVIEW_STATUSES.
        note (str | None):  Free-text analyst note. Pass None to clear.

    Returns:
        dict | None: The updated finding row (same shape as get_scan_findings
                     items) or None if no such finding id exists.

    Raises:
        ValueError: if status is not in REVIEW_STATUSES.
    """
    if status not in REVIEW_STATUSES:
        raise ValueError(f"status must be one of {REVIEW_STATUSES}")

    # 'new' is the default / reset state — clear the reviewed_at timestamp
    # so the UI can tell "never reviewed" apart from "was reviewed then reset".
    reviewed_at = None if status == "new" else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_note = (note or "").strip() or None

    with _connect(db_path) as conn:
        conn.execute(
            """UPDATE findings
               SET review_status = ?, review_note = ?, reviewed_at = ?
               WHERE id = ?""",
            (status, clean_note, reviewed_at, int(finding_id)),
        )
        row = conn.execute(
            """SELECT id, scan_id, timestamp, event_id, severity, rule,
                      mitre, description, details, raw_xml,
                      review_status, review_note, reviewed_at
               FROM findings WHERE id = ?""",
            (int(finding_id),),
        ).fetchone()
        if not row:
            return None
        cols = ("id", "scan_id", "timestamp", "event_id", "severity", "rule",
                "mitre", "description", "details", "raw_xml",
                "review_status", "review_note", "reviewed_at")
        return dict(zip(cols, row))


def delete_scans(db_path, scan_ids):
    """Delete one or more scans (and their findings via ON DELETE CASCADE).
    Returns the number of scan rows actually deleted."""
    ids = [int(i) for i in (scan_ids or []) if str(i).strip()]
    if not ids:
        return 0
    placeholders = ",".join("?" for _ in ids)
    with _connect(db_path) as conn:
        cursor = conn.execute(
            f"DELETE FROM scans WHERE id IN ({placeholders})", ids
        )
        return cursor.rowcount or 0


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

    try:
        with _connect(db_path) as conn:
            # SQLite's datetime() + modifier does the time math for us.
            # "now" - "60 minutes" gives the cutoff; any row sent_at after
            # that cutoff counts as "recent".
            # record_alert writes sent_at in local time via Python's
            # datetime.now(), but SQLite's bare datetime('now') returns UTC.
            # Passing 'localtime' as a modifier makes the comparison
            # timezone-consistent on any machine.
            cursor = conn.execute(
                """SELECT 1 FROM alert_log
                   WHERE rule = ?
                     AND sent_at > datetime('now', 'localtime', ?)
                   LIMIT 1""",
                (rule, f"-{int(cooldown_minutes)} minutes")
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


def create_user(db_path, email, password_hash):
    """Insert a new user and return the row id. Email is lowercased and
    stripped so lookups are consistent."""
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("email is required")
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _connect(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email, password_hash, created_at),
        )
        return cursor.lastrowid


def get_user_by_email(db_path, email):
    email = (email or "").strip().lower()
    if not email:
        return None
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, email, password_hash, created_at FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not row:
            return None
        return {"id": row[0], "email": row[1], "password_hash": row[2], "created_at": row[3]}


def get_user_by_id(db_path, user_id):
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, email, password_hash, created_at FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
        if not row:
            return None
        return {"id": row[0], "email": row[1], "password_hash": row[2], "created_at": row[3]}


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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _connect(db_path):
    """Opens a SQLite connection with foreign key enforcement enabled."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _get_hostname():
    try:
        return socket.gethostname()
    except Exception:
        return "Unknown"
