# pulse/scheduled_scan.py
# ------------------------
# Time-based recurring scans ("every day at 09:00", "every Monday at 08:30",
# or a full cron expression) of the local Windows event logs.
#
# This is the companion to pulse/scheduler.py, which is a folder-watch loop.
# The API-driven dashboard feature needs cron-style triggers instead of file
# drops, so this module handles:
#
#   1. Validating + normalising the schedule config the UI saves to pulse.yaml.
#   2. Computing the next run datetime from that config.
#   3. Running one async loop that sleeps until the next fire time, calls the
#      system-scan primitive, re-computes, and sleeps again.
#
# Cron support: "Custom" schedules accept a 5-field cron expression. Parsing
# is intentionally tiny — the legal field forms are `*`, a single integer,
# a comma list, or `*/N` step. That covers every realistic use ("every 6
# hours", "weekdays at 09:00", etc.) without a new dependency.

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta


# Scheduling types. Picked so the pulse.yaml values read naturally.
SCHEDULE_DAILY  = "daily"
SCHEDULE_WEEKLY = "weekly"
SCHEDULE_CUSTOM = "custom"
VALID_SCHEDULES = (SCHEDULE_DAILY, SCHEDULE_WEEKLY, SCHEDULE_CUSTOM)

# Monday=0 … Sunday=6 — matches Python's datetime.weekday().
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

log = logging.getLogger("pulse.monitor.scheduled_scan")


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

def normalize_schedule_config(raw):
    """Take whatever the UI sent and return a clean dict ready for pulse.yaml.

    Raises ValueError with a human-readable message on invalid input so the
    API layer can surface it verbatim in a 400.
    """
    raw = raw or {}
    out = {
        "enabled":      bool(raw.get("enabled", False)),
        "days":         _clean_days(raw.get("days", 7)),
        "schedule":     (raw.get("schedule") or SCHEDULE_DAILY).lower(),
        "time":         (raw.get("time") or "09:00").strip(),
        "weekday":      _clean_weekday(raw.get("weekday", 1)),
        "cron":         (raw.get("cron") or "").strip(),
        "alert_email":   bool(raw.get("alert_email", True)),
        "alert_slack":   bool(raw.get("alert_slack", False)),
        "alert_discord": bool(raw.get("alert_discord", False)),
    }
    if out["schedule"] not in VALID_SCHEDULES:
        raise ValueError(
            "schedule must be one of: " + ", ".join(VALID_SCHEDULES)
        )
    if out["schedule"] in (SCHEDULE_DAILY, SCHEDULE_WEEKLY):
        _parse_hhmm(out["time"])  # raises ValueError on bad input
    if out["schedule"] == SCHEDULE_CUSTOM:
        if not out["cron"]:
            raise ValueError("cron expression is required for custom schedules")
        # Probe-parse once so bad cron shapes fail at save-time.
        _parse_cron(out["cron"])
    return out


def _clean_days(value):
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError("days must be an integer")
    if n < 1 or n > 365:
        raise ValueError("days must be between 1 and 365")
    return n


def _clean_weekday(value):
    if isinstance(value, str):
        v = value.strip().lower()
        if v in WEEKDAYS:
            return WEEKDAYS.index(v)
        try:
            value = int(v)
        except ValueError:
            raise ValueError("weekday must be 0-6 or mon-sun")
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError("weekday must be 0-6 or mon-sun")
    if n < 0 or n > 6:
        raise ValueError("weekday must be 0-6 (Monday=0)")
    return n


def _parse_hhmm(s):
    try:
        hh, mm = s.split(":")
        h = int(hh); m = int(mm)
    except (ValueError, AttributeError):
        raise ValueError("time must be HH:MM (24-hour)")
    if not (0 <= h < 24 and 0 <= m < 60):
        raise ValueError("time out of range")
    return h, m


# ---------------------------------------------------------------------------
# Next-run calculation
# ---------------------------------------------------------------------------

def compute_next_run(config, now=None):
    """Given a normalized config + the current datetime, return the next
    datetime the job should fire at. None if schedule is disabled or
    malformed. `now` is injectable for tests."""
    if not config or not config.get("enabled"):
        return None
    now = now or datetime.now()
    kind = config.get("schedule") or SCHEDULE_DAILY
    try:
        if kind == SCHEDULE_DAILY:
            return _next_daily(config.get("time") or "09:00", now)
        if kind == SCHEDULE_WEEKLY:
            return _next_weekly(
                config.get("weekday", 1),
                config.get("time") or "09:00",
                now,
            )
        if kind == SCHEDULE_CUSTOM:
            return _next_cron(config.get("cron") or "", now)
    except ValueError:
        return None
    return None


def _next_daily(time_str, now):
    h, m = _parse_hhmm(time_str)
    candidate = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate


def _next_weekly(weekday, time_str, now):
    h, m = _parse_hhmm(time_str)
    # How many days until the target weekday (0..6; 0 = "today" if current
    # hh:mm hasn't passed yet, otherwise 7).
    delta_days = (weekday - now.weekday()) % 7
    candidate = now.replace(hour=h, minute=m, second=0, microsecond=0) + timedelta(days=delta_days)
    if candidate <= now:
        candidate += timedelta(days=7)
    return candidate


# ---------------------------------------------------------------------------
# Cron-ish parsing (minute, hour, dom, month, dow)
# Only `*`, plain int, comma list, and `*/N` are supported. That covers every
# realistic scheduling need without shipping croniter.
# ---------------------------------------------------------------------------

@dataclass
class _CronField:
    values: set  # set of matching integers in the field's range


def _parse_field(token, low, high):
    token = (token or "").strip()
    if not token:
        raise ValueError("cron field empty")
    rng = range(low, high + 1)
    if token == "*":
        return _CronField(set(rng))
    if token.startswith("*/"):
        try:
            step = int(token[2:])
        except ValueError:
            raise ValueError(f"invalid cron step: {token}")
        if step <= 0:
            raise ValueError("cron step must be positive")
        return _CronField({v for v in rng if (v - low) % step == 0})
    values = set()
    for part in token.split(","):
        part = part.strip()
        try:
            n = int(part)
        except ValueError:
            raise ValueError(f"unsupported cron token: {part}")
        if n < low or n > high:
            raise ValueError(f"cron value {n} out of range {low}-{high}")
        values.add(n)
    return _CronField(values)


def _parse_cron(expr):
    parts = expr.split()
    if len(parts) != 5:
        raise ValueError("cron expression must have 5 fields: minute hour dom month dow")
    return {
        "minute":  _parse_field(parts[0], 0, 59),
        "hour":    _parse_field(parts[1], 0, 23),
        "dom":     _parse_field(parts[2], 1, 31),
        "month":   _parse_field(parts[3], 1, 12),
        "dow":     _parse_field(parts[4], 0, 6),
    }


def _next_cron(expr, now):
    fields = _parse_cron(expr)
    # Walk forward minute-by-minute until a matching slot is found. 2 years
    # is a generous cap — no legitimate expression fails to match within that.
    candidate = now.replace(second=0, microsecond=0) + timedelta(minutes=1)
    end = candidate + timedelta(days=366 * 2)
    while candidate < end:
        # Python weekday: Monday=0..Sunday=6. Cron dow: Sunday=0..Saturday=6.
        # We stick with Python's convention (Monday=0) for simplicity — the
        # field docs in the UI will say "Monday=0".
        if (
            candidate.minute in fields["minute"].values
            and candidate.hour in fields["hour"].values
            and candidate.day in fields["dom"].values
            and candidate.month in fields["month"].values
            and candidate.weekday() in fields["dow"].values
        ):
            return candidate
        candidate += timedelta(minutes=1)
    raise ValueError("cron expression never matches")


def describe_schedule(config):
    """Human-readable sentence for the UI ("Every day at 09:00")."""
    if not config or not config.get("enabled"):
        return "Disabled"
    kind = config.get("schedule") or SCHEDULE_DAILY
    if kind == SCHEDULE_DAILY:
        return f"Every day at {config.get('time', '09:00')}"
    if kind == SCHEDULE_WEEKLY:
        day = WEEKDAYS[_clean_weekday(config.get("weekday", 1))].capitalize()
        return f"Every {day} at {config.get('time', '09:00')}"
    if kind == SCHEDULE_CUSTOM:
        return f"Cron: {config.get('cron', '')}"
    return "Unknown schedule"


# ---------------------------------------------------------------------------
# Async runner — sleeps until the next scheduled time, calls the callback,
# repeats. Designed to be spawned as an asyncio task from create_app().
# ---------------------------------------------------------------------------

class ScheduledScanRunner:
    """Runs one scheduled-scan coroutine. Owns the next-run calculation and
    a `reload()` method so the Settings page can reconfigure without a
    process restart. Not thread-safe — only one instance per app."""

    def __init__(self, get_config, run_once, clock=None):
        """`get_config` is a 0-arg callable that returns the latest scheduled_scan
        dict from pulse.yaml (re-read every loop so edits take effect).
        `run_once` is a coroutine function that performs the actual scan.
        `clock` lets tests inject a fake datetime.now-like callable."""
        self._get_config = get_config
        self._run_once = run_once
        self._clock = clock or datetime.now
        self._task = None
        self._reload_event = asyncio.Event()
        self._stopping = False
        self._last_run = None
        self._last_result = None
        self._next_run = None

    def start(self):
        if self._task and not self._task.done():
            return
        self._stopping = False
        self._task = asyncio.create_task(self._loop())

    async def stop(self):
        self._stopping = True
        self._reload_event.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except asyncio.TimeoutError:
                self._task.cancel()
        self._task = None

    def reload(self):
        """Nudge the loop to re-read config and recompute the next fire time.
        Called by the API after the Settings page saves a new schedule."""
        self._reload_event.set()

    def status(self):
        cfg = self._get_config() or {}
        return {
            "enabled": bool(cfg.get("enabled")),
            "schedule": describe_schedule(cfg),
            "next_run": self._next_run.isoformat() if self._next_run else None,
            "last_run": self._last_run.isoformat() if self._last_run else None,
            "last_result": self._last_result,
        }

    async def _loop(self):
        while not self._stopping:
            cfg = self._get_config() or {}
            self._next_run = compute_next_run(cfg, self._clock())
            if not self._next_run:
                # Disabled or malformed — park until a reload wakes us.
                self._reload_event.clear()
                try:
                    await self._reload_event.wait()
                except asyncio.CancelledError:
                    return
                continue

            wait_seconds = max(0.0, (self._next_run - self._clock()).total_seconds())
            self._reload_event.clear()
            try:
                await asyncio.wait_for(self._reload_event.wait(), timeout=wait_seconds)
                # Reload fired — skip the scan and recompute.
                continue
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                return

            if self._stopping:
                return

            # Fire the scan. Never let an exception in the callback kill the
            # whole scheduler — log and keep looping.
            try:
                self._last_run = self._clock()
                result = await self._run_once(cfg)
                self._last_result = result
            except Exception as exc:  # noqa: BLE001 — scheduler must keep running
                log.exception("scheduled scan failed: %s", exc)
                self._last_result = {"error": str(exc)}
