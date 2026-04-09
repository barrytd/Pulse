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
from datetime import datetime


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
    score_label    TEXT
);
"""

_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    timestamp   TEXT,
    event_id    TEXT,
    severity    TEXT,
    rule        TEXT,
    mitre       TEXT,
    description TEXT,
    details     TEXT
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


def save_scan(db_path, findings, scan_stats=None, score=None, score_label=None):
    """
    Saves a completed scan and all its findings to the database.

    Parameters:
        db_path (str):      Path to the .db file.
        findings (list):    List of finding dicts from run_all_detections().
        scan_stats (dict):  Optional scan metadata (files_scanned, total_events).
        score (int):        Optional security score (0-100).
        score_label (str):  Optional label e.g. "HIGH RISK".

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
                total_findings, score, score_label)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (scanned_at, hostname, files_scanned, total_events,
             total_findings, score, score_label)
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
            ))

        conn.executemany(
            """INSERT INTO findings
               (scan_id, timestamp, event_id, severity, rule,
                mitre, description, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
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
                          total_events, total_findings, score, score_label
                   FROM scans
                   ORDER BY id DESC
                   LIMIT ?""",
                (limit,)
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
            """SELECT timestamp, event_id, severity, rule,
                      mitre, description, details
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
