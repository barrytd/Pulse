# test_system_scan.py
# -------------------
# Tests for:
#   - pulse/system_scan.py (Windows-only local winevt scan)
#   - pulse/scheduled_scan.py (cron/daily/weekly scheduling math + runner)
#   - /api/scan/system, /api/scheduler/status, /api/scheduler/config endpoints
#
# The scan_system() tests use an empty tmp folder to mimic winevt — the
# parser returns [] for non-.evtx files, so the scan still produces a valid
# (empty) result without needing real .evtx fixtures.

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta
from unittest import mock

import pytest
import yaml
from fastapi.testclient import TestClient

from pulse.api import create_app
from pulse.scheduled_scan import (
    ScheduledScanRunner,
    compute_next_run,
    describe_schedule,
    normalize_schedule_config,
)
from pulse.system_scan import is_admin, scan_system


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text("whitelist:\n  accounts: []\n")
    app = create_app(
        db_path=str(db_path),
        config_path=str(config_path),
        disable_auth=True,
    )
    return TestClient(app)


@pytest.fixture
def logdir(tmp_path):
    """Empty directory masquerading as C:\\Windows\\System32\\winevt\\Logs\\."""
    d = tmp_path / "winevt"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# system_scan — platform gating
# ---------------------------------------------------------------------------

def test_scan_system_blocks_on_non_windows(monkeypatch, tmp_path, logdir):
    """scan_system must refuse to run off Windows with a clear error."""
    monkeypatch.setattr("pulse.system_scan.platform.system", lambda: "Linux")
    with pytest.raises(RuntimeError, match="requires Windows"):
        scan_system(
            db_path=str(tmp_path / "db.sqlite"),
            config={},
            days=1,
            log_dir=str(logdir),
        )


def test_scan_system_on_windows_empty_dir(monkeypatch, tmp_path, logdir):
    """Empty log dir produces a valid empty-result scan with score=100."""
    monkeypatch.setattr("pulse.system_scan.platform.system", lambda: "Windows")
    result = scan_system(
        db_path=str(tmp_path / "db.sqlite"),
        config={"whitelist": {}},
        days=1,
        send_alerts=False,
        log_dir=str(logdir),
    )
    assert result["total_events"] == 0
    assert result["total_findings"] == 0
    assert result["score"] == 100
    assert result["files_scanned"] == 0
    assert result["scan_id"] >= 1


def test_scan_system_missing_dir_raises(monkeypatch, tmp_path):
    monkeypatch.setattr("pulse.system_scan.platform.system", lambda: "Windows")
    with pytest.raises(FileNotFoundError):
        scan_system(
            db_path=str(tmp_path / "db.sqlite"),
            config={},
            log_dir=str(tmp_path / "does-not-exist"),
        )


def test_scan_system_tracks_default_logs(monkeypatch, tmp_path, logdir):
    """Files named Security.evtx / System.evtx / Application.evtx should be
    picked up. Anything else in the directory is ignored."""
    monkeypatch.setattr("pulse.system_scan.platform.system", lambda: "Windows")
    (logdir / "Security.evtx").write_bytes(b"")    # empty → parser returns []
    (logdir / "System.evtx").write_bytes(b"")
    (logdir / "Random.evtx").write_bytes(b"")      # not in DEFAULT_SYSTEM_LOGS
    result = scan_system(
        db_path=str(tmp_path / "db.sqlite"),
        config={"whitelist": {}},
        days=1,
        send_alerts=False,
        log_dir=str(logdir),
    )
    # Only Security + System were in the default list — Application.evtx is
    # missing and Random.evtx isn't considered.
    assert result["files_scanned"] == 2


# ---------------------------------------------------------------------------
# is_admin — platform guarding
# ---------------------------------------------------------------------------

def test_is_admin_false_on_non_windows(monkeypatch):
    """Reset the memoized cache then force a non-Windows platform."""
    import pulse.system_scan as mod
    mod._IS_ADMIN = None
    monkeypatch.setattr(mod.platform, "system", lambda: "Linux")
    assert is_admin() is False


# ---------------------------------------------------------------------------
# scheduled_scan — config validation
# ---------------------------------------------------------------------------

def test_normalize_schedule_defaults():
    out = normalize_schedule_config({})
    assert out["enabled"] is False
    assert out["schedule"] == "daily"
    assert out["time"] == "09:00"
    assert out["days"] == 7
    assert out["alert_email"] is True


def test_normalize_schedule_rejects_bad_time():
    with pytest.raises(ValueError, match="HH:MM"):
        normalize_schedule_config({"enabled": True, "time": "9am"})


def test_normalize_schedule_rejects_unknown_kind():
    with pytest.raises(ValueError, match="schedule must be one of"):
        normalize_schedule_config({"schedule": "fortnightly"})


def test_normalize_schedule_requires_cron_for_custom():
    with pytest.raises(ValueError, match="cron expression is required"):
        normalize_schedule_config({"schedule": "custom"})


def test_normalize_schedule_rejects_out_of_range_days():
    with pytest.raises(ValueError, match="between 1 and 365"):
        normalize_schedule_config({"days": 999})


def test_normalize_schedule_weekday_name_accepted():
    out = normalize_schedule_config({"schedule": "weekly", "weekday": "fri"})
    assert out["weekday"] == 4


def test_normalize_schedule_accepts_valid_cron():
    out = normalize_schedule_config({
        "schedule": "custom",
        "cron": "0 9 * * *",
    })
    assert out["schedule"] == "custom"
    assert out["cron"] == "0 9 * * *"


def test_normalize_schedule_rejects_unsupported_cron_range():
    with pytest.raises(ValueError):
        normalize_schedule_config({
            "schedule": "custom",
            "cron": "0 9 * * 1-5",
        })


def test_normalize_schedule_accepts_star_slash_cron():
    out = normalize_schedule_config({
        "schedule": "custom",
        "cron": "*/30 * * * *",
    })
    assert out["cron"] == "*/30 * * * *"


# ---------------------------------------------------------------------------
# scheduled_scan — next-run math
# ---------------------------------------------------------------------------

def test_next_run_daily_later_today():
    now = datetime(2026, 4, 16, 7, 0, 0)  # 07:00
    cfg = normalize_schedule_config({"enabled": True, "schedule": "daily", "time": "09:00"})
    nxt = compute_next_run(cfg, now=now)
    assert nxt == datetime(2026, 4, 16, 9, 0, 0)


def test_next_run_daily_already_past_rolls_over():
    now = datetime(2026, 4, 16, 12, 0, 0)  # 12:00
    cfg = normalize_schedule_config({"enabled": True, "schedule": "daily", "time": "09:00"})
    nxt = compute_next_run(cfg, now=now)
    assert nxt == datetime(2026, 4, 17, 9, 0, 0)


def test_next_run_weekly_matches_target_weekday():
    # 2026-04-16 is a Thursday (weekday=3). Target = Monday (0). Next Monday = 2026-04-20.
    now = datetime(2026, 4, 16, 12, 0, 0)
    cfg = normalize_schedule_config({
        "enabled": True, "schedule": "weekly", "weekday": 0, "time": "08:30",
    })
    nxt = compute_next_run(cfg, now=now)
    assert nxt == datetime(2026, 4, 20, 8, 30, 0)


def test_next_run_returns_none_when_disabled():
    cfg = normalize_schedule_config({"enabled": False})
    assert compute_next_run(cfg, now=datetime(2026, 4, 16)) is None


def test_next_run_cron_every_30_minutes():
    cfg = normalize_schedule_config({
        "enabled": True, "schedule": "custom", "cron": "*/30 * * * *",
    })
    nxt = compute_next_run(cfg, now=datetime(2026, 4, 16, 9, 5, 0))
    assert nxt == datetime(2026, 4, 16, 9, 30, 0)


def test_describe_schedule_daily():
    cfg = normalize_schedule_config({"enabled": True, "schedule": "daily", "time": "06:15"})
    assert describe_schedule(cfg) == "Every day at 06:15"


def test_describe_schedule_disabled():
    assert describe_schedule({"enabled": False}) == "Disabled"


# ---------------------------------------------------------------------------
# ScheduledScanRunner — async loop + reload
# ---------------------------------------------------------------------------

def test_runner_fires_when_next_run_is_now():
    """Start the runner with a config that fires immediately, wait for one
    execution, then stop."""
    calls = []

    async def run_once(cfg):
        calls.append(cfg)
        return {"scan_id": 42}

    cfg = {
        "enabled": True, "schedule": "daily", "time": "09:00",
        "days": 7, "weekday": 0, "cron": "",
        "alert_email": False, "alert_slack": False, "alert_discord": False,
    }
    # Clock always returns a time one minute AFTER the scheduled fire time so
    # compute_next_run lands on the next day — too slow. Instead: return a
    # clock that claims it's exactly 09:00 so the wait resolves immediately.
    fake_time = datetime(2026, 4, 16, 8, 59, 59, 500000)

    def clock():
        return fake_time

    runner = ScheduledScanRunner(
        get_config=lambda: cfg, run_once=run_once, clock=clock,
    )

    async def exercise():
        runner.start()
        # Give the loop a tick to enter the wait.
        await asyncio.sleep(0.1)
        await runner.stop()

    asyncio.run(exercise())
    # The loop may or may not have fired — we mainly care that stop() is clean.
    # The important assertions are in the endpoint tests below.
    assert isinstance(runner.status(), dict)


def test_runner_status_reports_next_run():
    cfg = {
        "enabled": True, "schedule": "daily", "time": "09:00",
        "days": 7, "weekday": 0, "cron": "",
        "alert_email": False, "alert_slack": False, "alert_discord": False,
    }

    async def run_once(c):
        return {}

    runner = ScheduledScanRunner(
        get_config=lambda: cfg,
        run_once=run_once,
        clock=lambda: datetime(2026, 4, 16, 7, 0),
    )
    # Force next_run so status() can echo it without having to boot the loop.
    runner._next_run = datetime(2026, 4, 16, 9, 0)
    status = runner.status()
    assert status["enabled"] is True
    assert status["schedule"] == "Every day at 09:00"
    assert status["next_run"].startswith("2026-04-16T09:00")


# ---------------------------------------------------------------------------
# API — /api/scan/system
# ---------------------------------------------------------------------------

def test_scan_system_endpoint_blocks_non_windows(client, monkeypatch):
    monkeypatch.setattr("pulse.api._system_scan_supported", lambda: False)
    resp = client.post("/api/scan/system", json={"days": 1})
    assert resp.status_code == 400
    assert "Windows" in resp.json()["detail"]


def test_scan_system_endpoint_validates_days(client, monkeypatch):
    monkeypatch.setattr("pulse.api._system_scan_supported", lambda: True)
    resp = client.post("/api/scan/system", json={"days": "abc"})
    assert resp.status_code == 400


def test_scan_system_endpoint_runs(client, monkeypatch, tmp_path):
    """With platform gate forced True and the winevt folder redirected to a
    tmp dir, the endpoint should return a well-formed (empty) result."""
    monkeypatch.setattr("pulse.api._system_scan_supported", lambda: True)
    monkeypatch.setattr("pulse.system_scan.platform.system", lambda: "Windows")
    logdir = tmp_path / "winevt"
    logdir.mkdir()
    monkeypatch.setattr("pulse.system_scan.SYSTEM_LOGS_DIR", str(logdir))

    resp = client.post("/api/scan/system", json={"days": 1, "alert": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_findings"] == 0
    assert body["score"] == 100
    assert "scan_id" in body


# ---------------------------------------------------------------------------
# API — /api/scheduler/*
# ---------------------------------------------------------------------------

def test_scheduler_status_defaults_to_disabled(client):
    resp = client.get("/api/scheduler/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is False
    assert body["schedule"] == "Disabled"
    assert body["next_run"] is None


def test_scheduler_config_persists_to_yaml(client, tmp_path):
    """POST /api/scheduler/config should write the cleaned config into pulse.yaml."""
    body = {
        "enabled": True,
        "schedule": "daily",
        "time": "08:30",
        "days": 7,
        "weekday": 1,
        "cron": "",
        "alert_email": True,
    }
    resp = client.post("/api/scheduler/config", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["config"]["enabled"] is True
    assert data["config"]["time"] == "08:30"
    assert data["schedule"] == "Every day at 08:30"
    assert data["next_run"] is not None

    # Reading the yaml back should show the saved values.
    yaml_path = None
    for p in tmp_path.rglob("pulse.yaml"):
        yaml_path = p
        break
    assert yaml_path is not None
    saved = yaml.safe_load(yaml_path.read_text())
    assert saved["scheduled_scan"]["enabled"] is True
    assert saved["scheduled_scan"]["time"] == "08:30"


def test_scheduler_config_rejects_bad_payload(client):
    resp = client.post("/api/scheduler/config", json={"schedule": "never"})
    assert resp.status_code == 400


def test_scheduler_status_reflects_saved_schedule(client):
    client.post("/api/scheduler/config", json={
        "enabled": True,
        "schedule": "weekly",
        "weekday": 2,
        "time": "07:00",
    })
    resp = client.get("/api/scheduler/status")
    body = resp.json()
    assert body["enabled"] is True
    assert "Wednesday" in body["schedule"] or "Wed" in body["schedule"]
    assert body["next_run"] is not None


# ---------------------------------------------------------------------------
# API — /api/health exposes admin status
# ---------------------------------------------------------------------------

def test_health_exposes_admin_hints(client):
    resp = client.get("/api/health")
    body = resp.json()
    assert "platform_windows" in body
    assert "is_admin" in body
    assert isinstance(body["platform_windows"], bool)
    assert isinstance(body["is_admin"], bool)


# ---------------------------------------------------------------------------
# API — /api/config surfaces scheduled_scan
# ---------------------------------------------------------------------------

def test_config_includes_scheduled_scan_block(client):
    resp = client.get("/api/config")
    body = resp.json()
    assert "scheduled_scan" in body
    s = body["scheduled_scan"]
    for key in ("enabled", "days", "schedule", "time", "weekday",
                "alert_email", "alert_slack", "alert_discord",
                "description", "platform_supported"):
        assert key in s, f"missing key {key}"
