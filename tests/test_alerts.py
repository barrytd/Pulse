# test_alerts.py
# --------------
# Unit tests for the threshold-based email alert feature.
#
# WHAT THIS TESTS:
#   1. filter_alert_findings — severity threshold math
#   2. alert_log table + record_alert / was_recently_alerted — cooldown
#   3. send_alert — SMTP handshake is called correctly (mocked)
#
# We never send real email in tests. smtplib.SMTP is replaced with a
# fake that records the calls so we can assert against them.

import os
import sqlite3
import tempfile
from unittest.mock import patch, MagicMock

import pytest

from pulse.alerts.emailer import filter_alert_findings, send_alert, dispatch_alerts
from pulse.database import init_db, record_alert, was_recently_alerted


# ---------------------------------------------------------------------------
# filter_alert_findings
# ---------------------------------------------------------------------------

def _findings():
    """A mixed list of findings spanning every severity level."""
    return [
        {"rule": "Brute Force Attempt",  "severity": "HIGH"},
        {"rule": "Account Takeover",     "severity": "CRITICAL"},
        {"rule": "RDP Logon Detected",   "severity": "MEDIUM"},
        {"rule": "Noise",                "severity": "LOW"},
    ]


def test_filter_threshold_high_includes_high_and_critical():
    result = filter_alert_findings(_findings(), "HIGH")
    rules = {f["rule"] for f in result}
    assert rules == {"Brute Force Attempt", "Account Takeover"}


def test_filter_threshold_critical_includes_only_critical():
    result = filter_alert_findings(_findings(), "CRITICAL")
    rules = {f["rule"] for f in result}
    assert rules == {"Account Takeover"}


def test_filter_threshold_low_includes_everything():
    result = filter_alert_findings(_findings(), "LOW")
    assert len(result) == 4


def test_filter_threshold_medium_excludes_low():
    result = filter_alert_findings(_findings(), "MEDIUM")
    rules = {f["rule"] for f in result}
    assert "Noise" not in rules
    assert len(result) == 3


def test_filter_threshold_is_case_insensitive():
    result = filter_alert_findings(_findings(), "high")
    assert len(result) == 2


def test_filter_empty_list_returns_empty():
    assert filter_alert_findings([], "HIGH") == []


# ---------------------------------------------------------------------------
# Cooldown tracking in the database
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db():
    """
    Gives each test its own SQLite file so they don't share state.
    tempfile.NamedTemporaryFile(delete=False) returns a path we can pass
    to init_db; yield hands it to the test; the finally block cleans up.
    """
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    try:
        yield path
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def test_was_recently_alerted_false_when_never_alerted(tmp_db):
    assert was_recently_alerted(tmp_db, "Brute Force Attempt", 60) is False


def test_record_then_was_recently_alerted_true(tmp_db):
    record_alert(tmp_db, "Brute Force Attempt", severity="HIGH")
    assert was_recently_alerted(tmp_db, "Brute Force Attempt", 60) is True


def test_was_recently_alerted_is_rule_scoped(tmp_db):
    # Alerting on rule A should NOT silence an alert on rule B.
    record_alert(tmp_db, "Rule A", severity="HIGH")
    assert was_recently_alerted(tmp_db, "Rule A", 60) is True
    assert was_recently_alerted(tmp_db, "Rule B", 60) is False


def test_was_recently_alerted_respects_cooldown_window(tmp_db):
    # Manually backdate a row to 2 hours ago. A 60-minute cooldown should
    # treat it as expired; a 180-minute cooldown should still match.
    with sqlite3.connect(tmp_db) as conn:
        conn.execute(
            """INSERT INTO alert_log (sent_at, rule, severity, hostname)
               VALUES (datetime('now', 'localtime', '-120 minutes'), 'Old Rule', 'HIGH', 'host')"""
        )
    assert was_recently_alerted(tmp_db, "Old Rule", 60)  is False
    assert was_recently_alerted(tmp_db, "Old Rule", 180) is True


def test_was_recently_alerted_returns_false_when_db_missing():
    # No DB configured -> no cooldown tracking -> always allow.
    assert was_recently_alerted(None, "anything", 60) is False


# ---------------------------------------------------------------------------
# send_alert (SMTP mocked)
# ---------------------------------------------------------------------------

def _email_config():
    return {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "sender":    "alerts@example.com",
        "recipient": "ops@example.com",
        "password":  "hunter2",
    }


def test_send_alert_returns_false_when_no_findings():
    assert send_alert(_email_config(), {}, []) is False


def test_send_alert_returns_false_when_config_invalid():
    bad = {"smtp_host": "", "smtp_port": 587, "sender": "", "recipient": "", "password": ""}
    findings = [{"rule": "Brute Force", "severity": "HIGH", "details": "x"}]
    assert send_alert(bad, {}, findings) is False


def test_send_alert_calls_smtp_and_returns_true():
    findings = [
        {"rule": "Brute Force Attempt", "severity": "HIGH",     "details": "5 failed logins"},
        {"rule": "Account Takeover",    "severity": "CRITICAL", "details": "chain detected"},
    ]
    fake_server = MagicMock()
    # Support the `with smtplib.SMTP(...) as server:` context-manager pattern.
    fake_smtp_cls = MagicMock()
    fake_smtp_cls.return_value.__enter__.return_value = fake_server

    with patch("pulse.alerts.emailer.smtplib.SMTP", fake_smtp_cls):
        ok = send_alert(_email_config(), {"recipient": None}, findings)

    assert ok is True
    fake_smtp_cls.assert_called_once_with("smtp.example.com", 587)
    fake_server.starttls.assert_called_once()
    fake_server.login.assert_called_once_with("alerts@example.com", "hunter2")
    fake_server.sendmail.assert_called_once()
    # 3rd positional arg of sendmail is the rendered message — should have
    # the PULSE ALERT subject and mention both triggering rules.
    msg = fake_server.sendmail.call_args[0][2]
    assert "[PULSE ALERT]" in msg
    assert "Brute Force Attempt" in msg
    assert "Account Takeover" in msg


def test_send_alert_uses_alert_recipient_override():
    findings = [{"rule": "Brute Force", "severity": "HIGH", "details": "x"}]
    alert_cfg = {"recipient": "soc-team@example.com"}

    fake_server = MagicMock()
    fake_smtp_cls = MagicMock()
    fake_smtp_cls.return_value.__enter__.return_value = fake_server

    with patch("pulse.alerts.emailer.smtplib.SMTP", fake_smtp_cls):
        send_alert(_email_config(), alert_cfg, findings)

    # sendmail(sender, recipient, msg) — recipient should be the override.
    assert fake_server.sendmail.call_args[0][1] == "soc-team@example.com"


# ---------------------------------------------------------------------------
# dispatch_alerts — the top-level helper both CLI and API use
# ---------------------------------------------------------------------------

def _findings_above_threshold():
    return [
        {"rule": "Brute Force Attempt", "severity": "HIGH",     "details": "x"},
        {"rule": "Account Takeover",    "severity": "CRITICAL", "details": "y"},
        {"rule": "RDP Logon Detected",  "severity": "MEDIUM",   "details": "z"},
    ]


def _patch_smtp_ok():
    """Return (patch_ctx, fake_server) for a successful SMTP mock."""
    fake_server = MagicMock()
    fake_smtp_cls = MagicMock()
    fake_smtp_cls.return_value.__enter__.return_value = fake_server
    return patch("pulse.alerts.emailer.smtplib.SMTP", fake_smtp_cls), fake_server


def test_dispatch_noop_when_alerts_disabled(tmp_db):
    alert_cfg = {"enabled": False, "threshold": "HIGH"}
    result = dispatch_alerts(tmp_db, _findings_above_threshold(), _email_config(), alert_cfg)
    assert result["enabled"] is False
    assert result["sent"] is False


def test_dispatch_noop_when_no_findings(tmp_db):
    alert_cfg = {"enabled": True, "threshold": "HIGH"}
    result = dispatch_alerts(tmp_db, [], _email_config(), alert_cfg)
    assert result["enabled"] is True
    assert result["sent"] is False
    assert result["fresh"] == 0


def test_dispatch_sends_and_records_on_first_fire(tmp_db):
    alert_cfg = {"enabled": True, "threshold": "HIGH", "cooldown_minutes": 60}
    ctx, _server = _patch_smtp_ok()
    with ctx:
        result = dispatch_alerts(tmp_db, _findings_above_threshold(), _email_config(), alert_cfg)

    assert result["sent"] is True
    # Only HIGH + CRITICAL pass the HIGH threshold; MEDIUM is excluded.
    assert result["over_threshold"] == 2
    assert result["fresh"] == 2
    # Both rules recorded so the next scan is suppressed by cooldown.
    assert was_recently_alerted(tmp_db, "Brute Force Attempt", 60) is True
    assert was_recently_alerted(tmp_db, "Account Takeover",    60) is True


def test_dispatch_suppresses_when_cooldown_active(tmp_db):
    # Seed: a recent alert already exists for Brute Force. Another scan
    # should NOT re-send for that rule.
    record_alert(tmp_db, "Brute Force Attempt", severity="HIGH")

    alert_cfg = {"enabled": True, "threshold": "HIGH", "cooldown_minutes": 60}
    findings = [{"rule": "Brute Force Attempt", "severity": "HIGH", "details": "x"}]
    ctx, fake_server = _patch_smtp_ok()
    with ctx:
        result = dispatch_alerts(tmp_db, findings, _email_config(), alert_cfg)

    assert result["fresh"] == 0
    assert result["sent"] is False
    assert "Brute Force Attempt" in result["skipped_rules"]
    fake_server.sendmail.assert_not_called()


def test_dispatch_partial_cooldown_still_sends_for_fresh_rules(tmp_db):
    # One rule on cooldown, another still fresh — email should go out
    # with the fresh rule only.
    record_alert(tmp_db, "Brute Force Attempt", severity="HIGH")

    alert_cfg = {"enabled": True, "threshold": "HIGH", "cooldown_minutes": 60}
    findings = [
        {"rule": "Brute Force Attempt", "severity": "HIGH",     "details": "suppressed"},
        {"rule": "Account Takeover",    "severity": "CRITICAL", "details": "fresh"},
    ]
    ctx, fake_server = _patch_smtp_ok()
    with ctx:
        result = dispatch_alerts(tmp_db, findings, _email_config(), alert_cfg)

    assert result["sent"] is True
    assert result["fresh"] == 1
    assert result["skipped_rules"] == ["Brute Force Attempt"]
    # Sent message should mention only the fresh rule.
    msg = fake_server.sendmail.call_args[0][2]
    assert "Account Takeover" in msg
