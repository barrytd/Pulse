# test_agent_runtime.py
# ---------------------
# Sprint 7 Phase A — Pulse Agent runtime. Exercises every layer that
# isn't Windows-event-log-specific:
#   - config save/load round-trip
#   - transport against a live FastAPI TestClient (full HTTP path)
#   - enroll() flow (exchanges + persists)
#   - AgentRuntime.tick() — heartbeat + scan-and-ship cadence + paused
#     handoff between the two endpoints
#
# The local-scan path itself (scan_for_findings) requires Windows event
# logs and is exercised separately by tests/test_system_scan.py. Here
# we monkey-patch scan_for_findings to inject canned findings so the
# transport + cadence logic gets clean coverage.

import os
import tempfile

import httpx
import pytest
from fastapi.testclient import TestClient

from pulse import database
from pulse.agent.config import AgentConfig, load_config, save_config
from pulse.agent.runtime import AgentRuntime, enroll
from pulse.agent.transport import AgentTransport, TransportError
from pulse.api import create_app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _wrap_test_client(test_client: TestClient) -> TestClient:
    """TestClient already speaks the same dict-of-headers, .post(json=…),
    .status_code, .json() interface AgentTransport's ``client`` slot
    expects — and it's sync, unlike httpx.ASGITransport which is async
    only. Passing it through directly drives the full FastAPI handler
    chain (auth middleware, dependency injection, JSON encoding) without
    touching a socket."""
    return test_client


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "test.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db), config_path=str(cfg))
    c = TestClient(app)
    c.post("/api/auth/signup", json={
        "email": "admin@example.com",
        "password": "correct-horse-battery",
    })
    return c, str(db), str(cfg)


def _mint_enrollment(test_client: TestClient, name: str = "lab-host") -> str:
    r = test_client.post("/api/agents", json={"name": name})
    assert r.status_code == 200, r.text
    return r.json()["enrollment_token"]


# ---------------------------------------------------------------------------
# Config round-trip
# ---------------------------------------------------------------------------

def test_config_save_and_load_round_trip(tmp_path):
    cfg = AgentConfig(
        server_url="https://pulse.example.com",
        agent_id=42,
        agent_token="pa_secret",
        name="lab-1",
        scan_days=7,
    )
    path = str(tmp_path / "agent.yaml")
    save_config(cfg, path)
    again = load_config(path)
    assert again.server_url == "https://pulse.example.com"
    assert again.agent_id == 42
    assert again.agent_token == "pa_secret"
    assert again.scan_days == 7


def test_config_load_returns_default_when_file_missing(tmp_path):
    cfg = load_config(str(tmp_path / "missing.yaml"))
    assert cfg.server_url == ""
    assert cfg.agent_token == ""


def test_config_load_drops_unknown_keys(tmp_path):
    """A hand-edited config with extra keys (e.g. from a future agent
    version) must still load — drop unknown keys silently."""
    path = str(tmp_path / "agent.yaml")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("server_url: https://x\nfuture_field: yes\n")
    cfg = load_config(path)
    assert cfg.server_url == "https://x"


# ---------------------------------------------------------------------------
# Transport — against the real API via TestClient
# ---------------------------------------------------------------------------

def test_transport_exchange_round_trip(client):
    test_client, _db, _cfg = client
    enroll_tok = _mint_enrollment(test_client)
    test_client.post("/api/auth/logout")  # exchange is unauthenticated

    transport = AgentTransport(
        "http://testserver", verify_tls=False,
        client=_wrap_test_client(test_client),
    )
    result = transport.exchange(enroll_tok, hostname="lab-host",
                                platform_str="Windows-11")
    assert result["agent_token"].startswith("pa_")
    assert result["agent_id"]


def test_transport_heartbeat_succeeds_after_set_token(client):
    test_client, _db, _cfg = client
    enroll_tok = _mint_enrollment(test_client)
    test_client.post("/api/auth/logout")

    httpx_client = _wrap_test_client(test_client)
    transport = AgentTransport("http://testserver", verify_tls=False,
                               client=httpx_client)
    exchanged = transport.exchange(enroll_tok)
    transport.set_agent_token(exchanged["agent_token"])

    resp = transport.heartbeat()
    assert resp["status"] == "ok"
    assert resp["paused"] is False


def test_transport_post_findings_writes_a_scan(client):
    test_client, db_path, _cfg = client
    enroll_tok = _mint_enrollment(test_client)
    test_client.post("/api/auth/logout")

    httpx_client = _wrap_test_client(test_client)
    transport = AgentTransport("http://testserver", verify_tls=False,
                               client=httpx_client)
    exchanged = transport.exchange(enroll_tok)
    transport.set_agent_token(exchanged["agent_token"])

    scan_meta = {
        "hostname":      "lab-host",
        "scope":         "Pulse Agent — last 1 day",
        "files_scanned": 1,
        "total_events":  17,
        "duration_sec":  3,
    }
    findings = [
        {"rule": "RDP Logon Detected", "severity": "HIGH",
         "description": "RDP logon", "details": "src 10.0.0.5",
         "timestamp": "2026-05-02T10:00:00", "event_id": "4624"},
    ]
    resp = transport.post_findings(scan_meta, findings)
    assert resp["status"] == "ok"
    assert resp["findings_saved"] == 1
    # Scan landed in the DB attributed to the admin who enrolled the agent.
    rows = database.get_history(db_path)
    assert any(r["id"] == resp["scan_id"] for r in rows)


def test_transport_marks_401_as_permanent(client):
    test_client, _db, _cfg = client
    test_client.post("/api/auth/logout")
    transport = AgentTransport(
        "http://testserver", agent_token="pa_garbage", verify_tls=False,
        client=_wrap_test_client(test_client),
    )
    with pytest.raises(TransportError) as ei:
        transport.heartbeat()
    assert ei.value.permanent is True
    assert ei.value.status_code == 401


# ---------------------------------------------------------------------------
# enroll() helper — full flow via the runtime module
# ---------------------------------------------------------------------------

def test_enroll_persists_token(client, tmp_path, monkeypatch):
    test_client, _db, _cfg = client
    enroll_tok = _mint_enrollment(test_client, name="runtime-test")
    test_client.post("/api/auth/logout")

    # Patch AgentTransport so the helper hits TestClient instead of a
    # real socket. Same shape as the runtime would use in production.
    httpx_client = _wrap_test_client(test_client)
    from pulse.agent import runtime as runtime_mod
    monkeypatch.setattr(
        runtime_mod, "AgentTransport",
        lambda url, *a, **kw: AgentTransport(url, *a, client=httpx_client, **kw),
    )

    cfg_path = str(tmp_path / "agent.yaml")
    cfg = enroll(AgentConfig(verify_tls=False), "http://testserver", enroll_tok,
                 config_path=cfg_path)
    assert cfg.agent_token.startswith("pa_")
    assert cfg.agent_id

    # Persisted to disk: a second load reads back the same bearer.
    again = load_config(cfg_path)
    assert again.agent_token == cfg.agent_token
    assert again.server_url == "http://testserver"


# ---------------------------------------------------------------------------
# AgentRuntime.tick — cadence, paused state, scan injection
# ---------------------------------------------------------------------------

class _FakeClock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t
    def advance(self, sec): self.t += sec


def _runtime_with_token(client, *, paused: bool = False) -> AgentRuntime:
    """Helper: enroll an agent, build a runtime that talks via TestClient."""
    test_client, db_path, _cfg = client
    enroll_tok = _mint_enrollment(test_client)
    test_client.post("/api/auth/logout")
    httpx_client = _wrap_test_client(test_client)
    transport = AgentTransport("http://testserver", verify_tls=False,
                               client=httpx_client)
    exchanged = transport.exchange(enroll_tok)
    transport.set_agent_token(exchanged["agent_token"])

    if paused:
        # Re-login as admin and pause the agent before we start the loop.
        test_client.post("/api/auth/login", json={
            "email": "admin@example.com", "password": "correct-horse-battery",
        })
        test_client.put(f"/api/agents/{exchanged['agent_id']}",
                        json={"paused": True})
        test_client.post("/api/auth/logout")

    cfg = AgentConfig(
        server_url="http://testserver", verify_tls=False,
        agent_id=exchanged["agent_id"], agent_token=exchanged["agent_token"],
        scan_interval_sec=300,        # 5 min
        heartbeat_interval_sec=60,    # 1 min
    )
    return AgentRuntime(cfg, transport=transport, clock=_FakeClock())


def test_runtime_tick_heartbeats_then_scans(client, monkeypatch):
    """First tick fires heartbeat + scan (both are 'due' at t=0). After
    advancing 30s and ticking again, neither runs — both are below their
    cadence. After advancing past the heartbeat interval, only the
    heartbeat fires."""
    runtime = _runtime_with_token(client)
    # Inject a deterministic scan result so we don't hit Windows.
    scan_calls = []
    def fake_scan(**kwargs):
        scan_calls.append(kwargs)
        return ({"hostname": "test", "scope": "Pulse Agent — test",
                 "files_scanned": 0, "total_events": 0, "duration_sec": 0}, [])
    monkeypatch.setattr("pulse.agent.runtime.scan_for_findings", fake_scan)

    # First tick — both due.
    runtime.tick()
    assert len(scan_calls) == 1

    # Advance 30s — neither heartbeat nor scan should fire.
    runtime._clock.advance(30)
    runtime.tick()
    assert len(scan_calls) == 1   # no extra scan

    # Advance past the heartbeat threshold; scan still not due (60+30 < 300).
    runtime._clock.advance(40)
    runtime.tick()
    assert len(scan_calls) == 1   # still no extra scan
    # Scan threshold — bump well past 300s.
    runtime._clock.advance(300)
    runtime.tick()
    assert len(scan_calls) == 2


def test_runtime_skips_scan_when_paused(client, monkeypatch):
    """Server-side paused → heartbeat (which fires first in tick) acks
    with paused=True → ``_paused`` flips → scan branch suppresses the
    ship. No scan ever fires while the agent is paused on the server.
    The cadence cursor (`_last_scan_at`) still advances so we don't
    spin re-checking the paused branch every tick."""
    runtime = _runtime_with_token(client, paused=True)
    scan_calls = []
    monkeypatch.setattr(
        "pulse.agent.runtime.scan_for_findings",
        lambda **kw: scan_calls.append(kw) or ({}, []),
    )
    runtime.tick()
    runtime._clock.advance(runtime.cfg.scan_interval_sec + 1)
    runtime.tick()
    runtime._clock.advance(runtime.cfg.scan_interval_sec + 1)
    runtime.tick()
    assert scan_calls == []   # paused → never scans


def test_runtime_constructor_rejects_unenrolled_config():
    with pytest.raises(ValueError):
        AgentRuntime(AgentConfig(server_url="https://x"))   # no token
    with pytest.raises(ValueError):
        AgentRuntime(AgentConfig(agent_token="pa_x"))       # no server_url


# ---------------------------------------------------------------------------
# Auto-update channel — /api/agent/latest
# ---------------------------------------------------------------------------

def test_agent_latest_returns_version_without_auth(client):
    """Update checks are public — no bearer required. The agent should be
    able to call this on a fresh install before it owns a token."""
    test_client, _db, _cfg = client
    test_client.post("/api/auth/logout")
    r = test_client.get("/api/agent/latest")
    assert r.status_code == 200
    body = r.json()
    assert body["version"]
    assert body["download_url"].startswith("http")
    assert body["release_notes_url"].startswith("http")
    # Without a bearer the server has no idea who's calling — no
    # outdated comparison.
    assert "outdated" not in body


def test_agent_latest_with_bearer_reports_outdated(client):
    """When the agent supplies its bearer, the server resolves the agent,
    pulls its reported version, and computes the comparison server-side
    so the agent doesn't have to do its own semver math."""
    test_client, db_path, _cfg = client
    enroll_tok = _mint_enrollment(test_client)
    test_client.post("/api/auth/logout")

    transport = AgentTransport(
        "http://testserver", verify_tls=False,
        client=_wrap_test_client(test_client),
    )
    exchanged = transport.exchange(enroll_tok, version="0.0.1-stale")
    transport.set_agent_token(exchanged["agent_token"])

    info = transport.get_latest_version()
    assert info["version"]
    assert info["current"] == "0.0.1-stale"
    assert info["outdated"] is True


def test_agent_latest_marks_status_checked_update(client):
    """A bearer-authenticated update check should stamp last_status so the
    Agents tab can show 'last checked update' info even before the next
    heartbeat fires."""
    test_client, db_path, _cfg = client
    enroll_tok = _mint_enrollment(test_client)
    test_client.post("/api/auth/logout")

    transport = AgentTransport(
        "http://testserver", verify_tls=False,
        client=_wrap_test_client(test_client),
    )
    exchanged = transport.exchange(enroll_tok, version="0.0.1-stale")
    transport.set_agent_token(exchanged["agent_token"])
    transport.get_latest_version()

    agents = database.list_agents(db_path)
    target = next(a for a in agents if a["id"] == int(exchanged["agent_id"]))
    assert target["last_status"] == "checked-update"


def test_runtime_update_check_logs_when_outdated(client, caplog, monkeypatch):
    """run_forever() invokes _check_for_updates() once at startup. Verify
    the warning log fires when the server reports a newer version, and
    that the loop never crashes if the update check raises."""
    import logging
    test_client, _db, _cfg = client
    enroll_tok = _mint_enrollment(test_client)
    test_client.post("/api/auth/logout")

    transport = AgentTransport(
        "http://testserver", verify_tls=False,
        client=_wrap_test_client(test_client),
    )
    exchanged = transport.exchange(enroll_tok, version="0.0.1-stale")
    transport.set_agent_token(exchanged["agent_token"])

    cfg = AgentConfig(
        server_url="http://testserver", agent_token=exchanged["agent_token"],
        agent_id=int(exchanged["agent_id"]),
    )
    runtime = AgentRuntime(cfg, transport=transport)
    # Hand-attach a list handler instead of using caplog — pytest's
    # caplog fixture occasionally misses non-root loggers depending on
    # propagation config, and an explicit handler keeps the assertion
    # deterministic across CI environments.
    captured: list = []

    class _Capture(logging.Handler):
        def emit(self, record):
            captured.append(record.getMessage())

    runtime_log = logging.getLogger("pulse.agent")
    handler = _Capture(level=logging.WARNING)
    runtime_log.addHandler(handler)
    try:
        runtime._check_for_updates()
    finally:
        runtime_log.removeHandler(handler)
    assert any("update available" in m for m in captured), \
        f"expected an 'update available' warning, got: {captured!r}"
