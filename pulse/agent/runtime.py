"""Pulse Agent main loop.

The runtime sits in a forever-loop on the local host doing two things
on independent cadences:

  1. Heartbeat every ``cfg.heartbeat_interval_sec`` (default 60s) so the
     server's Agents tab shows ``online`` instead of ``stale``.
  2. Scan every ``cfg.scan_interval_sec`` (default 30 min) — runs the
     same Windows-event-log detections the standalone Pulse Server does,
     then ships the findings to ``POST /api/agent/findings``.

Failures are bucketed by transport.TransportError.permanent:

  - permanent=True   → token revoked / re-enroll required. Stop.
  - permanent=False  → server unreachable / 5xx. Sleep + retry next tick.

The loop sleeps in 1-second slices so SIGTERM / Ctrl+C / Windows-
Service-stop signals are picked up promptly. Scan-side findings that
fail to ship are retried on the next scan tick (no offline queue yet —
that's the next-up TODO from the Sprint 7 ACs).
"""

from __future__ import annotations

import logging
import platform
import signal
import time
from typing import Callable, Optional

from pulse import __version__ as PULSE_VERSION
from pulse.agent.config import AgentConfig, save_config
from pulse.agent.scanner import scan_for_findings
from pulse.agent.transport import AgentTransport, TransportError


log = logging.getLogger("pulse.agent")


class AgentRuntime:
    """Long-running agent loop. Construct with a fully-loaded
    ``AgentConfig`` (must already carry an ``agent_token``) and call
    ``run_forever()`` to enter the loop. Tests can also call ``tick()``
    directly to drive one iteration without sleeping."""

    def __init__(self, cfg: AgentConfig, *,
                 transport: Optional[AgentTransport] = None,
                 clock: Optional[Callable[[], float]] = None):
        if not cfg.server_url:
            raise ValueError("AgentConfig.server_url must be set")
        if not cfg.agent_token:
            raise ValueError("AgentConfig.agent_token must be set — run `enroll` first")
        self.cfg = cfg
        self.transport = transport or AgentTransport(
            cfg.server_url, cfg.agent_token, verify_tls=cfg.verify_tls,
        )
        self._clock = clock or time.monotonic
        self._stop = False
        # Sentinel: ``None`` means "never" so the first tick always
        # fires both the heartbeat and a scan, regardless of the
        # configured cadences. Subsequent ticks compare elapsed time
        # against the interval as usual.
        self._last_heartbeat_at: Optional[float] = None
        self._last_scan_at:      Optional[float] = None
        # Server has marked us paused. We still heartbeat (so the
        # Agents tab doesn't show stale) but we skip scan + ship.
        self._paused = False

    # --- Lifecycle -----------------------------------------------------

    def stop(self) -> None:
        """Idempotent. Asks the loop to exit before its next tick."""
        self._stop = True

    def run_forever(self) -> None:
        """Block on the heartbeat + scan cadences until ``stop()`` is
        called or a permanent transport error fires. Installs SIGTERM /
        SIGINT handlers so the Windows Service stop path is clean."""
        signal.signal(signal.SIGINT, lambda *_: self.stop())
        try:
            signal.signal(signal.SIGTERM, lambda *_: self.stop())
        except (AttributeError, ValueError):
            # SIGTERM isn't supported on Windows for non-main threads,
            # and pywin32's service wrapper handles it differently. The
            # SIGINT handler covers Ctrl+C in dev. Ignore + continue.
            pass

        log.info("pulse-agent %s starting against %s",
                 PULSE_VERSION, self.cfg.server_url)
        # Best-effort update check — never blocks startup. The agent
        # keeps running on the installed version even when the server
        # reports a newer one; surfacing the upgrade in the log is
        # enough for now (an in-app prompt + auto-download is the next
        # step on the roadmap).
        try:
            self._check_for_updates()
        except Exception as exc:
            log.debug("update check failed: %s", exc)
        while not self._stop:
            try:
                self.tick()
            except TransportError as exc:
                if exc.permanent:
                    log.error("permanent transport error — stopping: %s", exc)
                    self.stop()
                else:
                    log.warning("transient transport error: %s", exc)
            except Exception as exc:
                # Unknown error — log + sleep. Never crash the whole
                # process; a misbehaving rule shouldn't take the agent
                # down on a customer's host.
                log.exception("agent tick failed: %s", exc)
            # Sleep in 1s slices so stop() lands quickly.
            for _ in range(min(self.cfg.heartbeat_interval_sec, 60)):
                if self._stop:
                    break
                time.sleep(1)

        log.info("pulse-agent stopped")

    # --- One iteration -------------------------------------------------

    def tick(self) -> None:
        """One pass of the loop: heartbeat if due, scan if due. Public
        so tests can drive ticks without owning a thread."""
        now = self._clock()
        if (self._last_heartbeat_at is None
                or (now - self._last_heartbeat_at) >= self.cfg.heartbeat_interval_sec):
            self._do_heartbeat()
            self._last_heartbeat_at = now
        if (self._last_scan_at is None
                or (now - self._last_scan_at) >= self.cfg.scan_interval_sec):
            # Even when paused we keep _last_scan_at advanced so the
            # cadence stays steady once the operator unpauses us.
            if not self._paused:
                self._do_scan_and_ship()
            self._last_scan_at = now

    # --- Internals -----------------------------------------------------

    def _check_for_updates(self) -> None:
        """Probe ``/api/agent/latest`` once and log any version drift.
        TransportError swallowed by the caller — update checks are
        best-effort and must never gate the heartbeat / scan loop.

        Prefers the server-computed ``outdated`` flag (server compares
        against the version the agent *reported* on enrollment, which is
        the truthful "what's actually running on the host" answer). Falls
        back to a local string compare when the response is unauthenticated
        and the flag is absent."""
        info = self.transport.get_latest_version()
        latest = (info.get("version") or "").strip()
        if not latest:
            return
        outdated = info.get("outdated")
        if outdated is True:
            log.warning(
                "pulse-agent update available: running %s, latest %s — download: %s",
                info.get("current") or PULSE_VERSION, latest,
                info.get("download_url") or "(no url)",
            )
            return
        if outdated is False or latest == PULSE_VERSION:
            log.info("agent is up to date (version %s)", latest)
            return
        # Unauthenticated branch (no `outdated` flag) and the server's
        # latest doesn't match what this process is running — surface it.
        log.warning(
            "pulse-agent update available: running %s, latest %s — download: %s",
            PULSE_VERSION, latest, info.get("download_url") or "(no url)",
        )

    def _do_heartbeat(self) -> None:
        try:
            resp = self.transport.heartbeat(status="running")
        except TransportError as exc:
            # Heartbeat failures don't stop the loop on transient errors;
            # we'll try again next tick. A permanent error bubbles up to
            # run_forever and stops us.
            if exc.permanent:
                raise
            log.warning("heartbeat failed: %s", exc)
            return
        self._paused = bool(resp.get("paused"))

    def _do_scan_and_ship(self) -> None:
        try:
            scan_meta, findings = scan_for_findings(
                days=self.cfg.scan_days,
                channels=self.cfg.channels or None,
            )
        except RuntimeError as exc:
            # Most common path here: agent installed on a non-Windows
            # host. Don't spin — surface the error once and stop the
            # scan cadence; heartbeats keep going.
            log.error("scan unavailable on this host: %s", exc)
            self._last_scan_at = self._clock() + 24 * 3600  # cool off 24h
            return
        except Exception as exc:
            log.exception("scan failed: %s", exc)
            return

        log.info("scan complete: %d events, %d findings — shipping",
                 scan_meta.get("total_events", 0), len(findings))
        try:
            resp = self.transport.post_findings(scan_meta, findings)
        except TransportError as exc:
            if exc.permanent:
                raise
            log.warning("findings ship failed (will retry next scan): %s", exc)
            return
        if resp.get("status") == "paused":
            # Server confirms we're paused. Pick up the flag here too
            # so the next heartbeat doesn't briefly flip us back to
            # "running" before the heartbeat response refreshes it.
            self._paused = True


def enroll(cfg: AgentConfig, server_url: str, enrollment_token: str,
           *, name: str = "", config_path: Optional[str] = None) -> AgentConfig:
    """Trade an enrollment token for a long-lived agent token, then
    persist the result to disk so subsequent ``run`` calls pick up the
    creds without further user input.

    Returns the updated AgentConfig. Raises TransportError on failure
    (network or 4xx). Single-use on the server side — calling this twice
    with the same enrollment token will fail the second time.
    """
    cfg.server_url = server_url.rstrip("/")
    if name:
        cfg.name = name
    transport = AgentTransport(cfg.server_url, verify_tls=cfg.verify_tls)
    result = transport.exchange(
        enrollment_token,
        hostname=platform.node(),
        platform_str=platform.platform(),
        version=PULSE_VERSION,
    )
    cfg.agent_id      = int(result.get("agent_id") or 0) or None
    cfg.agent_token   = result.get("agent_token") or ""
    cfg.name          = result.get("name") or cfg.name
    cfg.enrolled_at   = time.strftime("%Y-%m-%d %H:%M:%S")
    if not cfg.agent_token:
        raise TransportError("server returned no agent_token")
    save_config(cfg, config_path)
    return cfg
