# pulse/monitor_service.py
# -------------------------
# Async, in-process live monitor for the web dashboard.
#
# Why a separate module from pulse/monitor.py?
#   pulse/monitor.py is CLI-shaped — blocking while True loops, ANSI colours,
#   print() for output. That's great for `python main.py --watch` but useless
#   for a FastAPI server, which needs the loop to yield to the event loop so
#   SSE clients keep getting pings and other API requests still respond.
#
# This module wraps the SAME polling helpers (_query_new_events for wevtutil,
# _collect_new_events for .evtx files) in an asyncio task. When a finding is
# detected it's:
#   1. Saved to SQLite via save_scan (same table the one-shot scans use).
#   2. Broadcast to every subscribed SSE client via per-client asyncio.Queue.
#
# The event-bus pattern (fan-out queues) means adding more channels later —
# e.g. Slack webhook, browser toast, in-browser notification API — is just
# "add another subscriber".

import asyncio
import platform
from collections import deque
from datetime import datetime, timedelta

from pulse.core.detections import run_all_detections
from pulse.database import (
    close_monitor_session,
    create_monitor_session,
    save_scan,
)
from pulse.alerts.emailer import dispatch_alerts
from pulse.monitor.monitor import (
    _apply_whitelist,
    _collect_new_events,
    _get_last_record_id,
    _query_new_events,
)


_SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# How far back the live monitor accumulates events for detection. Rules like
# Brute Force need N failures within a short window — if each poll only sees
# its own batch, failures spread across poll boundaries never hit the
# threshold. Keeping ~15 minutes of recent events in memory closes that gap.
_DETECTION_WINDOW_MINUTES = 15


class MonitorManager:
    """Owns the async polling loop and fan-out to SSE subscribers.

    One instance lives on app.state.monitor for the lifetime of the FastAPI
    process. Starting / stopping it is idempotent (calling start twice just
    returns the existing task).
    """

    def __init__(self, db_path, config_path, config_getter):
        self.db_path      = db_path
        self.config_path  = config_path
        self._get_config  = config_getter   # callable -> fresh config dict

        # --- Runtime state --------------------------------------------------
        self.active         = False
        self.mode           = "live"                 # "live" (wevtutil) or "file"
        self.channels       = ["Security", "System"]
        self.log_folder     = None                   # populated in file mode
        self.poll_interval  = 30                     # seconds

        # --- Stats for the dashboard header --------------------------------
        self.started_at          = None
        self.last_check_at       = None
        self.events_checked      = 0
        self.findings_detected   = 0
        self.poll_count          = 0

        # Current monitor-session row. Set when start() fires, cleared when
        # stop() closes the session. Every save_scan() from _poll_once() is
        # tagged with this so the Monitor page can list per-session findings.
        self.session_id          = None

        # Short-term check history so the Monitor page can show even polls
        # that produced no findings ("events checked, nothing to alert on").
        self.check_history = deque(maxlen=100)

        # --- Pub/sub primitives --------------------------------------------
        self._task         = None           # the asyncio polling task
        self._stop_event   = None           # asyncio.Event set to request stop
        self._subscribers  = set()          # asyncio.Queue per connected client
        self._lock         = asyncio.Lock() # guards start/stop transitions

        # Per-channel last-record-ID (live mode) and seen-keys (file mode).
        # Reset each time start() runs so the first poll doesn't flood the
        # browser with every pre-existing event.
        self._last_ids     = {}
        self._seen_keys    = set()

        # Throttle for monitor-triggered email alerts. dispatch_alerts has
        # its own per-rule cooldown, but we also gate the whole email path
        # by a user-configurable interval so a noisy host can't trigger an
        # email every 30-second poll.
        self._last_monitor_email_at = None

        # Sliding detection window + dedup set.
        # _recent_events is a deque of (captured_at, event_dict) pairs kept
        # for _DETECTION_WINDOW_MINUTES so rules like Brute Force can see
        # patterns that span multiple polls. _seen_finding_keys remembers
        # findings we already broadcast from this window so the same brute
        # force doesn't alert on every single subsequent poll.
        self._recent_events     = deque()
        self._seen_finding_keys = set()

    # ------------------------------------------------------------------
    # Subscribe / unsubscribe — used by the SSE endpoint
    # ------------------------------------------------------------------
    def subscribe(self):
        """Register a new SSE client; returns the queue it should drain."""
        queue = asyncio.Queue(maxsize=256)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue):
        self._subscribers.discard(queue)

    async def _broadcast(self, event):
        """Fan-out one event dict to every connected subscriber.

        Slow clients whose queue is full are dropped — we'd rather lose one
        event for them than block the polling loop for everyone else.
        """
        dead = []
        for q in self._subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._subscribers.discard(q)

    # ------------------------------------------------------------------
    # Public control surface
    # ------------------------------------------------------------------
    async def start(self, poll_interval=None, mode=None, channels=None, log_folder=None):
        """Start the polling loop. Idempotent — if already running, just updates config."""
        async with self._lock:
            if poll_interval is not None:
                self.poll_interval = max(5, int(poll_interval))
            if mode in ("live", "file"):
                self.mode = mode
            if channels:
                self.channels = list(channels)
            if log_folder:
                self.log_folder = log_folder

            if self.active:
                await self._broadcast_status()
                return self.status()

            # Live mode only works on Windows (wevtutil is Windows-only).
            # On other platforms fall back to file mode over the configured
            # logs folder so the dashboard still does something useful.
            if self.mode == "live" and platform.system() != "Windows":
                self.mode = "file"

            self.active            = True
            self.started_at        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.last_check_at     = None
            self.events_checked    = 0
            self.findings_detected = 0
            self.poll_count        = 0
            self.check_history.clear()

            # New session row per start — records the full Start→Stop span.
            try:
                self.session_id = await asyncio.to_thread(
                    create_monitor_session,
                    self.db_path,
                    self.started_at,
                    self.channels,
                )
            except Exception:
                self.session_id = None
            self._last_ids         = {}
            self._seen_keys        = set()
            self._recent_events.clear()
            self._seen_finding_keys.clear()
            self._last_monitor_email_at = None
            self._stop_event       = asyncio.Event()

            # Baseline pass so the first real poll only sees *new* events.
            await asyncio.to_thread(self._baseline)

            self._task = asyncio.create_task(self._loop())
            await self._broadcast_status()
            return self.status()

    async def stop(self):
        async with self._lock:
            if not self.active:
                return self.status()
            self.active = False
            if self._stop_event:
                self._stop_event.set()
            if self._task:
                try:
                    await asyncio.wait_for(self._task, timeout=5)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    self._task.cancel()
            self._task = None

            # Close the session row with the final counters. Swallow errors
            # so a DB write hiccup never blocks stop().
            if self.session_id is not None:
                try:
                    await asyncio.to_thread(
                        close_monitor_session,
                        self.db_path,
                        self.session_id,
                        self.poll_count,
                        self.events_checked,
                        self.findings_detected,
                    )
                except Exception:
                    pass
                self.session_id = None

            await self._broadcast_status()
            return self.status()

    def status(self):
        """Plain dict — what /api/monitor/status returns and what SSE sends
        under the `status` event name."""
        return {
            "active":            self.active,
            "mode":              self.mode,
            "channels":          list(self.channels),
            "log_folder":        self.log_folder,
            "poll_interval":     self.poll_interval,
            "poll_count":        self.poll_count,
            "events_checked":    self.events_checked,
            "findings_detected": self.findings_detected,
            "started_at":        self.started_at,
            "last_check_at":     self.last_check_at,
            "subscribers":       len(self._subscribers),
            "platform_supports_live": platform.system() == "Windows",
        }

    async def inject_test_finding(self):
        """Push a synthetic CRITICAL finding through the fan-out so the UI
        can be exercised end-to-end without a real detection match.

        Does NOT touch the database or stats — this is purely for UI
        verification, not a logged scan result.
        """
        now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fake = {
            "rule":        "Pulse Test Alert",
            "severity":    "CRITICAL",
            "event_id":    0,
            "timestamp":   now_iso,
            "mitre":       "",
            "description": "Synthetic alert from /api/monitor/test-alert",
            "details":     "This is a test alert to verify the live monitor UI.",
        }
        await self._broadcast({
            "type":    "finding",
            "finding": fake,
            "at":      now_iso,
            "stats":   self._stats_snapshot(),
        })

    def recent_checks(self, limit=50):
        """Returns the recent poll history — one entry per check, including
        polls that found nothing. The Monitor page uses this to show activity
        even in quiet periods."""
        data = list(self.check_history)
        return data[-limit:][::-1]   # newest first

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _baseline(self):
        """Runs once at start() — records 'what we've already seen' so the
        first real poll only surfaces events that arrive *after* monitoring
        begins. Blocking; called via asyncio.to_thread."""
        if self.mode == "live":
            for ch in self.channels:
                try:
                    self._last_ids[ch] = _get_last_record_id(ch)
                except Exception:
                    self._last_ids[ch] = 0
        else:
            # File mode — the file-poll helper expects seen_keys to be seeded
            # with every existing (filename, record_num) pair. Do that cheaply
            # by calling _collect_new_events once and discarding the events
            # (they're the "existing" ones).
            if self.log_folder:
                try:
                    _collect_new_events(self.log_folder, self._seen_keys)
                except Exception:
                    pass

    async def _loop(self):
        """The polling loop — runs until stop() is called."""
        try:
            # Announce we're live.
            await self._broadcast({
                "type":      "status",
                "message":   "Monitoring started",
                "status":    self.status(),
            })

            while self.active:
                # Wait either for the interval OR for an explicit stop
                # request. stop() sets _stop_event, which wins the race.
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=self.poll_interval,
                    )
                    break  # stop_event fired
                except asyncio.TimeoutError:
                    pass   # interval elapsed — do a poll

                if not self.active:
                    break

                await self._poll_once()
        except asyncio.CancelledError:
            pass
        finally:
            self.active = False

    async def _poll_once(self):
        """One poll cycle — query new events, run detections, save, broadcast."""
        self.poll_count   += 1
        now_iso            = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.last_check_at = now_iso

        # Blocking work goes in a thread so the event loop stays responsive.
        try:
            new_events = await asyncio.to_thread(self._collect_new)
        except Exception as exc:
            await self._broadcast({
                "type":    "monitor_error",
                "message": f"Poll failed: {exc}",
                "at":      now_iso,
            })
            return

        self.events_checked += len(new_events)

        # --- Sliding detection window --------------------------------------
        # Append this poll's events to the rolling buffer, drop anything
        # older than _DETECTION_WINDOW_MINUTES, then run detections over
        # the combined recent set so pattern rules (Brute Force, Password
        # Spray, etc.) work across poll boundaries.
        captured_at = datetime.now()
        for ev in new_events:
            self._recent_events.append((captured_at, ev))
        cutoff = captured_at - timedelta(minutes=_DETECTION_WINDOW_MINUTES)
        while self._recent_events and self._recent_events[0][0] < cutoff:
            self._recent_events.popleft()

        # Surface per-poll event IDs so the UI can show "what did we see?"
        event_ids = sorted({
            ev.get("event_id")
            for ev in new_events
            if ev.get("event_id") is not None
        })
        check_entry = {
            "at":        now_iso,
            "events":    len(new_events),
            "findings":  0,
            "event_ids": event_ids,
        }

        findings = []
        detection_input = [ev for _, ev in self._recent_events]
        if detection_input:
            try:
                findings = await asyncio.to_thread(run_all_detections, detection_input)
            except Exception:
                findings = []

            # Apply whitelist (same logic as the CLI scanner).
            config    = self._get_config() or {}
            whitelist = config.get("whitelist") or {}
            if whitelist:
                try:
                    findings = _apply_whitelist(findings, whitelist)
                except Exception:
                    pass

        # Dedup: only fire findings we haven't already reported from this
        # rolling window. Key is (rule, event_id, timestamp, details) —
        # stable across polls so a single brute-force cluster alerts once.
        new_findings = []
        for f in findings:
            key = (
                f.get("rule"),
                f.get("event_id"),
                f.get("timestamp"),
                f.get("details"),
            )
            if key in self._seen_finding_keys:
                continue
            self._seen_finding_keys.add(key)
            new_findings.append(f)
        findings = new_findings

        # Trim the dedup set periodically so it doesn't grow unboundedly;
        # capping it at a few thousand keys keeps memory flat over days.
        if len(self._seen_finding_keys) > 5000:
            self._seen_finding_keys = set(list(self._seen_finding_keys)[-2500:])

        check_entry["findings"] = len(findings)
        self.check_history.append(check_entry)

        if findings:
            self.findings_detected += len(findings)
            # Persist so the rest of the dashboard (history, findings page,
            # score trend) sees the new data immediately.
            try:
                await asyncio.to_thread(
                    save_scan,
                    self.db_path,
                    findings,
                    {"files_scanned": 0, "total_events": len(new_events)},
                    None,
                    None,
                    f"[monitor] {self.mode} poll {self.poll_count}",
                    "Live monitor",
                    self.session_id,
                )
            except Exception:
                pass

            for f in findings:
                await self._broadcast({
                    "type":      "finding",
                    "finding":   _serialise_finding(f),
                    "at":        now_iso,
                    "stats":     self._stats_snapshot(),
                })

            # Fire an email for monitor findings when the user has enabled
            # it AND the configured interval has elapsed since the last one.
            await self._maybe_dispatch_monitor_email(findings)

        # Always send a heartbeat so "time since last check" in the UI stays
        # fresh even during quiet periods.
        await self._broadcast({
            "type":   "check",
            "check":  check_entry,
            "stats":  self._stats_snapshot(),
        })

    def _monitor_email_due(self, interval_minutes, now=None):
        """True if enough time has passed since the last monitor email.

        First call (no prior email) always returns True so the first poll
        that finds something can fire. interval_minutes<=0 is treated as
        "no throttle".
        """
        if self._last_monitor_email_at is None:
            return True
        if interval_minutes <= 0:
            return True
        now = now or datetime.now()
        return (now - self._last_monitor_email_at) >= timedelta(minutes=interval_minutes)

    async def _maybe_dispatch_monitor_email(self, findings):
        """Fire an email for the current poll's findings, gated by the
        user's monitor_enabled switch and monitor_interval_minutes throttle.

        Errors are swallowed so a broken SMTP config never stops the
        polling loop.
        """
        if not findings:
            return
        config = self._get_config() or {}
        alert_cfg = config.get("alerts") or {}
        if not alert_cfg.get("monitor_enabled"):
            return
        interval = int(alert_cfg.get("monitor_interval_minutes", 30))
        if not self._monitor_email_due(interval):
            return
        try:
            result = await asyncio.to_thread(
                dispatch_alerts,
                self.db_path,
                findings,
                config.get("email") or {},
                alert_cfg,
                config.get("webhook") or {},
            )
        except Exception:
            return
        if result.get("sent") or result.get("webhook_sent"):
            self._last_monitor_email_at = datetime.now()

    def _collect_new(self):
        """Blocking helper: returns a list of new event dicts based on mode."""
        if self.mode == "live":
            events = []
            for ch in self.channels:
                last = self._last_ids.get(ch, 0)
                new, new_last = _query_new_events(ch, last)
                self._last_ids[ch] = new_last
                for ev in new:
                    ev["_channel"] = ch
                events.extend(new)
            return events
        else:
            if not self.log_folder:
                return []
            return _collect_new_events(self.log_folder, self._seen_keys)

    def _stats_snapshot(self):
        return {
            "poll_count":        self.poll_count,
            "events_checked":    self.events_checked,
            "findings_detected": self.findings_detected,
            "last_check_at":     self.last_check_at,
        }

    async def _broadcast_status(self):
        await self._broadcast({"type": "status", "status": self.status()})


def _serialise_finding(f):
    """Trim a finding dict to the fields the browser actually renders.

    Raw parsed events can carry big XML blobs in `.data` — we don't need
    to stream those to the dashboard."""
    return {
        "rule":        f.get("rule"),
        "severity":    f.get("severity"),
        "event_id":    f.get("event_id"),
        "timestamp":   f.get("timestamp"),
        "mitre":       f.get("mitre"),
        "description": f.get("description"),
        "details":     f.get("details"),
    }
