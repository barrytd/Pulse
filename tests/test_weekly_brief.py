# tests/test_weekly_brief.py
# --------------------------
# Coverage for the weekly threat brief: composer (DB → dict), email
# rendering, and the two HTTP endpoints (/api/weekly-brief, POST /send).

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app
from pulse import database
from pulse.alerts.weekly_brief import (
    compose_weekly_brief,
    _build_html_body,
    _build_plain_body,
    _build_subject,
    send_weekly_brief,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(config_path), disable_auth=True)
    return TestClient(app)


def _seed_findings(db_path, findings, filename="seed.evtx"):
    database.init_db(db_path)
    return database.save_scan(db_path, findings, filename=filename)


# ---------------------------------------------------------------------------
# compose_weekly_brief()
# ---------------------------------------------------------------------------

class TestComposeWeeklyBrief:

    def test_empty_db_returns_zeroed_brief(self, tmp_path):
        db = tmp_path / "empty.db"
        # Touch the DB once so subsequent reads don't crash.
        database.init_db(str(db))
        brief = compose_weekly_brief(str(db), days=7)

        assert brief["scans_run"] == 0
        assert brief["findings_total"] == 0
        assert brief["severity_counts"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        assert brief["top_rules"] == []
        assert brief["top_hosts"] == []
        assert brief["critical_findings"] == []
        # Score trend is None when there's nothing to compare.
        assert brief["score_start"] is None
        assert brief["score_end"] is None
        assert brief["score_delta"] is None

    def test_severity_counts_are_aggregated(self, tmp_path):
        db = tmp_path / "test.db"
        _seed_findings(str(db), [
            {"rule": "RDP Logon Detected", "severity": "HIGH",     "hostname": "HOST-A"},
            {"rule": "Audit Log Cleared",  "severity": "CRITICAL", "hostname": "HOST-A"},
            {"rule": "User Account Created", "severity": "MEDIUM", "hostname": "HOST-A"},
            {"rule": "After-Hours Logon",  "severity": "LOW",      "hostname": "HOST-A"},
        ])

        brief = compose_weekly_brief(str(db), days=7)
        assert brief["findings_total"] == 4
        assert brief["severity_counts"] == {
            "CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1,
        }

    def test_top_rules_keeps_worst_severity(self, tmp_path):
        # Same rule fires at both LOW and CRITICAL — the digest must show
        # CRITICAL so the badge colour reflects the worst hit.
        db = tmp_path / "test.db"
        _seed_findings(str(db), [
            {"rule": "Privilege Escalation", "severity": "LOW",      "hostname": "H"},
            {"rule": "Privilege Escalation", "severity": "CRITICAL", "hostname": "H"},
            {"rule": "Privilege Escalation", "severity": "HIGH",     "hostname": "H"},
            {"rule": "Other Rule",           "severity": "LOW",      "hostname": "H"},
        ])

        brief = compose_weekly_brief(str(db), days=7)
        rules = {r["rule"]: r for r in brief["top_rules"]}
        assert rules["Privilege Escalation"]["count"] == 3
        assert rules["Privilege Escalation"]["severity"] == "CRITICAL"
        assert rules["Other Rule"]["severity"] == "LOW"

    def test_top_hosts_buckets_by_hostname(self, tmp_path):
        db = tmp_path / "test.db"
        _seed_findings(str(db), [
            {"rule": "X", "severity": "HIGH", "hostname": "HOST-A"},
            {"rule": "X", "severity": "HIGH", "hostname": "HOST-A"},
        ], filename="a.evtx")
        _seed_findings(str(db), [
            {"rule": "X", "severity": "HIGH", "hostname": "HOST-B"},
        ], filename="b.evtx")

        brief = compose_weekly_brief(str(db), days=7)
        hosts = {h["host"]: h for h in brief["top_hosts"]}
        assert hosts["HOST-A"]["findings"] == 2
        assert hosts["HOST-A"]["scans"] == 1
        assert hosts["HOST-B"]["findings"] == 1

    def test_window_excludes_old_scans(self, tmp_path):
        db = tmp_path / "test.db"
        scan_id = _seed_findings(str(db), [
            {"rule": "Old finding", "severity": "HIGH", "hostname": "HOST-A"},
        ])
        # Hand-edit the scan timestamp to be 30 days ago so the 7-day
        # window leaves it out entirely.
        old_ts = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        with database._connect(str(db)) as conn:
            conn.execute("UPDATE scans SET scanned_at = ? WHERE id = ?", (old_ts, scan_id))
            conn.execute("UPDATE findings SET timestamp = ? WHERE scan_id = ?", (old_ts, scan_id))
            conn.commit()

        brief = compose_weekly_brief(str(db), days=7)
        assert brief["scans_run"] == 0
        assert brief["findings_total"] == 0

    def test_days_clamped_to_safe_range(self, tmp_path):
        db = tmp_path / "test.db"
        database.init_db(str(db))
        # Negative / huge values normalize cleanly instead of throwing.
        for val in (-1, 0, 99999, "weird"):
            brief = compose_weekly_brief(str(db), days=val)
            assert 1 <= brief["period_days"] <= 365

    def test_score_trend_uses_oldest_and_newest_scored(self, tmp_path):
        # Scans are returned newest-first; trend should be oldest → newest.
        db = tmp_path / "test.db"
        database.init_db(str(db))
        database.save_scan(str(db),
            [{"rule": "X", "severity": "LOW", "hostname": "H"}],
            score=72, score_label="OK", filename="first.evtx",
        )
        database.save_scan(str(db),
            [{"rule": "X", "severity": "LOW", "hostname": "H"}],
            score=88, score_label="GOOD", filename="latest.evtx",
        )

        brief = compose_weekly_brief(str(db), days=7)
        assert brief["score_start"] == 72
        assert brief["score_end"] == 88
        assert brief["score_delta"] == 16


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

class TestRenderers:

    def _brief(self):
        return {
            "period_days": 7, "period_start": "2026-04-19", "period_end": "2026-04-26",
            "scans_run": 3, "findings_total": 5,
            "severity_counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1},
            "score_start": 70, "score_end": 80, "score_delta": 10,
            "top_rules": [{"rule": "RDP Logon", "count": 2, "severity": "HIGH"}],
            "top_hosts": [{"host": "HOST-A", "findings": 4, "scans": 2}],
            "critical_findings": [
                {"rule": "Audit Log Cleared", "hostname": "HOST-A", "timestamp": "2026-04-26 09:30"},
            ],
        }

    def test_subject_flags_critical_count(self):
        b = self._brief()
        assert "CRITICAL" in _build_subject(b)
        assert "1 CRITICAL" in _build_subject(b)

    def test_subject_falls_back_to_all_clear(self):
        b = self._brief()
        b["severity_counts"] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        b["findings_total"] = 0
        assert "all clear" in _build_subject(b)

    def test_html_includes_period_and_top_rule(self):
        html = _build_html_body(self._brief())
        assert "2026-04-19" in html
        assert "RDP Logon" in html

    def test_plain_body_lists_critical_findings(self):
        body = _build_plain_body(self._brief())
        assert "Audit Log Cleared" in body
        assert "HOST-A" in body


# ---------------------------------------------------------------------------
# send_weekly_brief()
# ---------------------------------------------------------------------------

class TestSendWeeklyBrief:

    def test_returns_false_when_recipient_missing(self):
        ok = send_weekly_brief({"smtp_host": "x", "smtp_port": 587,
                                "sender": "a@b", "password": "x"}, "", {"period_days": 7})
        assert ok is False

    def test_returns_false_when_smtp_invalid(self):
        ok = send_weekly_brief({}, "you@example.com", {"period_days": 7})
        assert ok is False

    def test_smtp_call_uses_configured_credentials(self, tmp_path):
        db = tmp_path / "test.db"
        database.init_db(str(db))
        brief = compose_weekly_brief(str(db), days=7)

        with patch("pulse.alerts.weekly_brief.smtplib.SMTP") as mock_smtp:
            mock_server = mock_smtp.return_value.__enter__.return_value
            ok = send_weekly_brief(
                {"smtp_host": "smtp.example.com", "smtp_port": 587,
                 "sender": "pulse@example.com", "password": "pw",
                 "recipient": "pulse@example.com"},
                "ops@example.com",
                brief,
            )

        assert ok is True
        mock_smtp.assert_called_once_with("smtp.example.com", 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("pulse@example.com", "pw")
        # Recipient + sender flow through to sendmail.
        args, _ = mock_server.sendmail.call_args
        assert args[0] == "pulse@example.com"
        assert args[1] == ["ops@example.com"]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

class TestWeeklyBriefApi:

    def test_get_returns_brief_dict(self, client):
        resp = client.get("/api/weekly-brief")
        assert resp.status_code == 200
        body = resp.json()
        for k in ("period_days", "scans_run", "findings_total",
                  "severity_counts", "top_rules", "top_hosts",
                  "critical_findings"):
            assert k in body

    def test_get_rejects_out_of_range_days(self, client):
        assert client.get("/api/weekly-brief?days=0").status_code == 400
        assert client.get("/api/weekly-brief?days=400").status_code == 400

    def test_get_returns_seeded_findings_in_window(self, client):
        db = client.app.state.db_path
        _seed_findings(db, [
            {"rule": "RDP Logon Detected", "severity": "HIGH", "hostname": "HOST-A"},
        ])
        body = client.get("/api/weekly-brief?days=7").json()
        assert body["findings_total"] == 1
        assert body["severity_counts"]["HIGH"] == 1

    def test_post_send_400s_without_smtp(self, client, tmp_path):
        # Default config has no SMTP password — send must fail with a clear msg.
        resp = client.post("/api/weekly-brief/send", json={"days": 7})
        assert resp.status_code == 400
        assert "smtp" in resp.json()["detail"].lower()

    def test_post_send_400s_without_recipient(self, client):
        # Configure SMTP password but no recipient → still a 400.
        config_path = client.app.state.config_path
        config_path = str(config_path) if hasattr(config_path, "__fspath__") else config_path
        import yaml
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        cfg["email"] = {"smtp_host": "x", "smtp_port": 587, "sender": "s@e",
                        "password": "pw"}
        cfg["alerts"] = {"recipient": ""}
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(cfg, f)

        resp = client.post("/api/weekly-brief/send", json={"days": 7})
        assert resp.status_code == 400
        assert "recipient" in resp.json()["detail"].lower()

    def test_post_send_emails_when_smtp_ok(self, client):
        config_path = str(client.app.state.config_path)
        import yaml
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        cfg["email"] = {"smtp_host": "smtp.x", "smtp_port": 587,
                        "sender": "pulse@x", "password": "pw",
                        "recipient": "ops@x"}
        cfg["alerts"] = {"recipient": "ops@x"}
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(cfg, f)

        with patch("pulse.alerts.weekly_brief.smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__.return_value.sendmail.return_value = {}
            resp = client.post("/api/weekly-brief/send", json={"days": 7})

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "sent"
        assert body["recipient"] == "ops@x"
