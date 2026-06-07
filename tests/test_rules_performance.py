# test_rules_performance.py
# -------------------------
# Rule Performance dashboard — /api/rules/performance health view.

from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "test.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db), config_path=str(cfg), disable_auth=True)
    return TestClient(app), str(db)


def _seed(db_path, *, noisy_hits=40, noisy_fp=20, scan_duration=12):
    """Seed one noisy rule (lots of hits + FPs), one healthy rule (fires
    clean), leaving the rest silent (never fired)."""
    import sqlite3
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO scans (scanned_at, files_scanned, score, score_label, "
            "                    filename, duration_sec) "
            "VALUES (?, 1, 40, 'High', 'x.evtx', ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_duration),
        )
        sid = conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]
        rows = []
        for i in range(noisy_hits):
            fp = 1 if i < noisy_fp else 0
            rows.append((sid, "HIGH", "Brute Force Attempt", fp, 1,
                         "2026-06-07T10:00:00Z"))
        # One healthy rule: fired, reviewed as TP, no FP.
        rows.append((sid, "CRITICAL", "Kerberoasting", 0, 1,
                     "2026-06-07T10:05:00Z"))
        conn.executemany(
            "INSERT INTO findings (scan_id, severity, rule, false_positive, "
            "                       reviewed, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
        return sid


def test_performance_endpoint_shape(client):
    c, db = client
    _seed(db)
    r = c.get("/api/rules/performance")
    assert r.status_code == 200
    body = r.json()
    assert "summary" in body and "rules" in body
    s = body["summary"]
    for key in ("total_rules", "healthy", "watch", "noisy", "disabled",
                 "silent", "avg_scan_seconds", "scans_analyzed"):
        assert key in s


def test_noisy_rule_classified_red(client):
    c, db = client
    _seed(db, noisy_hits=40, noisy_fp=20)  # 50% FP over 40 hits
    body = c.get("/api/rules/performance").json()
    bf = next(r for r in body["rules"] if r["name"] == "Brute Force Attempt")
    assert bf["health"] == "noisy"
    assert bf["fp_rate"] == 50
    assert "tuning" in bf["health_reason"].lower()


def test_healthy_rule_classified_green(client):
    c, db = client
    _seed(db)
    body = c.get("/api/rules/performance").json()
    krb = next(r for r in body["rules"] if r["name"] == "Kerberoasting")
    assert krb["health"] == "healthy"
    assert krb["fp_rate"] == 0


def test_silent_rule_classified_watch(client):
    c, db = client
    _seed(db)
    body = c.get("/api/rules/performance").json()
    # Any rule that never fired (e.g. Golden Ticket) is "watch" + silent.
    gt = next(r for r in body["rules"] if r["name"] == "Golden Ticket")
    assert gt["health"] == "watch"
    assert gt["hits_total"] == 0
    assert "never fired" in gt["health_reason"].lower()


def test_summary_counts_add_up(client):
    c, db = client
    _seed(db)
    s = c.get("/api/rules/performance").json()["summary"]
    assert (s["healthy"] + s["watch"] + s["noisy"] + s["disabled"]
            == s["total_rules"])
    # Silent is a subset of watch.
    assert s["silent"] <= s["watch"]
    assert s["noisy"] >= 1
    assert s["healthy"] >= 1


def test_rows_sorted_problems_first(client):
    c, db = client
    _seed(db)
    rows = c.get("/api/rules/performance").json()["rules"]
    band = {"noisy": 0, "watch": 1, "healthy": 2, "disabled": 3}
    ranks = [band.get(r["health"], 9) for r in rows]
    assert ranks == sorted(ranks), "rows should be health-sorted"
    # The noisy rule leads.
    assert rows[0]["health"] == "noisy"


def test_avg_scan_seconds_reported(client):
    c, db = client
    _seed(db, scan_duration=18)
    s = c.get("/api/rules/performance").json()["summary"]
    assert s["avg_scan_seconds"] == 18
    assert s["scans_analyzed"] == 1


def test_disabled_rule_classified_disabled(client):
    c, db = client
    _seed(db)
    # Disable a rule via the config endpoint.
    c.put("/api/rules/Brute Force Attempt/enabled", json={"enabled": False})
    body = c.get("/api/rules/performance").json()
    bf = next(r for r in body["rules"] if r["name"] == "Brute Force Attempt")
    assert bf["health"] == "disabled"
    assert bf["enabled"] is False


def test_empty_db_all_silent(client):
    c, _ = client
    body = c.get("/api/rules/performance").json()
    s = body["summary"]
    # No scans: every enabled rule is silent/watch, none noisy.
    assert s["noisy"] == 0
    assert s["healthy"] == 0
    assert s["watch"] == s["total_rules"]
    assert s["avg_scan_seconds"] is None
    assert s["scans_analyzed"] == 0
