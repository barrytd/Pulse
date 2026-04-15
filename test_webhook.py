# test_webhook.py
# ---------------
# Tests for Slack/Discord webhook delivery.
#
# WHAT THIS TESTS:
#   1. Flavor detection from URL
#   2. Config validation (enabled, url set, scheme)
#   3. Payload shape for Slack and Discord
#   4. send_webhook POST path — urllib.request.urlopen is mocked
#   5. dispatch_alerts wires webhook in alongside email

import json
from unittest.mock import patch, MagicMock

import pytest

from pulse.webhook import (
    detect_flavor,
    validate_webhook_config,
    send_webhook,
    _build_slack_payload,
    _build_discord_payload,
)


# ---------------------------------------------------------------------------
# detect_flavor
# ---------------------------------------------------------------------------

def test_detect_flavor_slack():
    assert detect_flavor("https://hooks.slack.com/services/T000/B000/abc") == "slack"


def test_detect_flavor_discord():
    assert detect_flavor("https://discord.com/api/webhooks/123/abc") == "discord"
    assert detect_flavor("https://discordapp.com/api/webhooks/123/abc") == "discord"


def test_detect_flavor_unknown():
    assert detect_flavor("https://example.com/hook") is None
    assert detect_flavor("") is None
    assert detect_flavor(None) is None


# ---------------------------------------------------------------------------
# validate_webhook_config
# ---------------------------------------------------------------------------

def test_validate_rejects_disabled():
    assert validate_webhook_config({"enabled": False, "url": "https://x"}) == "webhook disabled"


def test_validate_rejects_missing_url():
    assert "url" in validate_webhook_config({"enabled": True, "url": ""}).lower()


def test_validate_rejects_non_http_scheme():
    err = validate_webhook_config({"enabled": True, "url": "ftp://hooks.slack.com/x"})
    assert "http" in err.lower()


def test_validate_accepts_https_url():
    cfg = {"enabled": True, "url": "https://hooks.slack.com/services/T/B/abc"}
    assert validate_webhook_config(cfg) is None


# ---------------------------------------------------------------------------
# Payload shape
# ---------------------------------------------------------------------------

def _findings():
    return [
        {"rule": "Brute Force Attempt", "severity": "HIGH",     "details": "5 failed logins for alice"},
        {"rule": "Account Takeover",    "severity": "CRITICAL", "details": "login + new user"},
    ]


def test_slack_payload_contains_text_and_attachments():
    payload = _build_slack_payload(_findings(), "HOST-A")
    assert "text" in payload
    assert "HOST-A" in payload["text"]
    assert len(payload["attachments"]) == 2
    # Colour stripe should reflect severity.
    colours = [a["color"] for a in payload["attachments"]]
    assert "#e74c3c" in colours  # HIGH
    assert "#8e44ad" in colours  # CRITICAL


def test_slack_payload_caps_at_ten_attachments_plus_overflow():
    many = [{"rule": f"Rule {i}", "severity": "HIGH", "details": "x"} for i in range(15)]
    payload = _build_slack_payload(many, None)
    # 10 real + 1 overflow notice
    assert len(payload["attachments"]) == 11
    assert "+5 more" in payload["attachments"][-1]["text"]


def test_discord_payload_contains_content_and_embeds():
    payload = _build_discord_payload(_findings(), "HOST-A")
    assert "content" in payload
    assert "HOST-A" in payload["content"]
    assert len(payload["embeds"]) == 2
    # Discord uses integer colours.
    assert all(isinstance(e["color"], int) for e in payload["embeds"])


def test_discord_payload_truncates_long_details():
    big = [{"rule": "R", "severity": "HIGH", "details": "x" * 5000}]
    payload = _build_discord_payload(big, None)
    # Discord caps embed description at 4096 chars; we stay well under 1500.
    assert len(payload["embeds"][0]["description"]) <= 1500


# ---------------------------------------------------------------------------
# send_webhook — urllib mocked
# ---------------------------------------------------------------------------

def _mock_urlopen(status=200):
    """Return a patch context for urlopen that returns the given HTTP status."""
    resp = MagicMock()
    resp.status = status
    # Context manager protocol used by urlopen.
    cm = MagicMock()
    cm.__enter__.return_value = resp
    cm.__exit__.return_value = False
    return patch("pulse.webhook.urllib.request.urlopen", return_value=cm)


def test_send_webhook_returns_false_on_invalid_config():
    assert send_webhook({}, _findings()) is False
    assert send_webhook({"enabled": False, "url": "https://x"}, _findings()) is False


def test_send_webhook_posts_slack_payload_to_slack_url():
    cfg = {"enabled": True, "url": "https://hooks.slack.com/services/T/B/abc"}
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = req.data
        captured["headers"] = dict(req.headers)
        cm = MagicMock()
        cm.__enter__.return_value = MagicMock(status=200)
        cm.__exit__.return_value = False
        return cm

    with patch("pulse.webhook.urllib.request.urlopen", side_effect=fake_urlopen):
        assert send_webhook(cfg, _findings()) is True

    assert captured["url"] == cfg["url"]
    body = json.loads(captured["body"].decode())
    # Slack shape: has "attachments", not "embeds".
    assert "attachments" in body
    assert "embeds" not in body


def test_send_webhook_uses_discord_format_when_url_matches():
    cfg = {"enabled": True, "url": "https://discord.com/api/webhooks/123/abc"}
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["body"] = req.data
        cm = MagicMock()
        cm.__enter__.return_value = MagicMock(status=204)
        cm.__exit__.return_value = False
        return cm

    with patch("pulse.webhook.urllib.request.urlopen", side_effect=fake_urlopen):
        assert send_webhook(cfg, _findings()) is True

    body = json.loads(captured["body"].decode())
    assert "embeds" in body
    assert "attachments" not in body


def test_send_webhook_explicit_flavor_overrides_url_detection():
    # URL looks like Slack, but config says Discord — Discord wins.
    cfg = {"enabled": True, "flavor": "discord", "url": "https://hooks.slack.com/x/y/z"}
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["body"] = req.data
        cm = MagicMock()
        cm.__enter__.return_value = MagicMock(status=200)
        cm.__exit__.return_value = False
        return cm

    with patch("pulse.webhook.urllib.request.urlopen", side_effect=fake_urlopen):
        send_webhook(cfg, _findings())

    body = json.loads(captured["body"].decode())
    assert "embeds" in body


def test_send_webhook_returns_false_on_network_error():
    cfg = {"enabled": True, "url": "https://hooks.slack.com/x/y/z"}
    with patch("pulse.webhook.urllib.request.urlopen", side_effect=OSError("boom")):
        assert send_webhook(cfg, _findings()) is False


def test_send_webhook_returns_false_on_http_error_4xx():
    import urllib.error
    cfg = {"enabled": True, "url": "https://hooks.slack.com/x/y/z"}
    err = urllib.error.HTTPError(cfg["url"], 400, "Bad Request", {}, None)
    with patch("pulse.webhook.urllib.request.urlopen", side_effect=err):
        assert send_webhook(cfg, _findings()) is False


# ---------------------------------------------------------------------------
# dispatch_alerts — email + webhook together
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path):
    from pulse.database import init_db
    path = str(tmp_path / "pulse.db")
    init_db(path)
    return path


def _email_ok_ctx():
    fake_server = MagicMock()
    fake_smtp_cls = MagicMock()
    fake_smtp_cls.return_value.__enter__.return_value = fake_server
    return patch("pulse.emailer.smtplib.SMTP", fake_smtp_cls), fake_server


def _findings_high():
    return [{"rule": "Brute Force Attempt", "severity": "HIGH", "details": "x"}]


def _email_cfg():
    return {
        "smtp_host": "smtp.x.com",
        "smtp_port": 587,
        "sender":    "a@x.com",
        "recipient": "b@x.com",
        "password":  "p",
    }


def test_dispatch_fires_webhook_when_enabled(tmp_db):
    from pulse.emailer import dispatch_alerts

    alert_cfg   = {"enabled": True, "threshold": "HIGH", "cooldown_minutes": 60}
    webhook_cfg = {"enabled": True, "url": "https://hooks.slack.com/services/T/B/c"}

    email_ctx, _srv = _email_ok_ctx()
    with email_ctx, patch("pulse.webhook.send_webhook", return_value=True) as fake_post:
        result = dispatch_alerts(tmp_db, _findings_high(), _email_cfg(), alert_cfg, webhook_cfg)

    assert result["sent"] is True
    assert result["webhook_sent"] is True
    fake_post.assert_called_once()


def test_dispatch_skips_webhook_when_disabled(tmp_db):
    from pulse.emailer import dispatch_alerts

    alert_cfg   = {"enabled": True, "threshold": "HIGH", "cooldown_minutes": 60}
    webhook_cfg = {"enabled": False, "url": "https://hooks.slack.com/x/y/z"}

    email_ctx, _srv = _email_ok_ctx()
    with email_ctx, patch("pulse.webhook.send_webhook", return_value=True) as fake_post:
        result = dispatch_alerts(tmp_db, _findings_high(), _email_cfg(), alert_cfg, webhook_cfg)

    assert result["sent"] is True
    assert result["webhook_sent"] is False
    fake_post.assert_not_called()


def test_dispatch_records_cooldown_if_webhook_alone_succeeds(tmp_db):
    """If email fails but webhook succeeds, the rule should still enter cooldown
    so we don't keep re-notifying forever."""
    from pulse.emailer import dispatch_alerts
    from pulse.database import was_recently_alerted

    alert_cfg   = {"enabled": True, "threshold": "HIGH", "cooldown_minutes": 60}
    webhook_cfg = {"enabled": True, "url": "https://hooks.slack.com/x/y/z"}

    # send_alert patched to fail, send_webhook patched to succeed.
    with patch("pulse.emailer.send_alert", return_value=False), \
         patch("pulse.webhook.send_webhook", return_value=True):
        dispatch_alerts(tmp_db, _findings_high(), _email_cfg(), alert_cfg, webhook_cfg)

    assert was_recently_alerted(tmp_db, "Brute Force Attempt", 60) is True
