# tests/test_rate_limit.py
# ------------------------
# The rate limiter keys its buckets on the client IP. `X-Forwarded-For`
# is set by the caller, so trusting it blindly lets anyone rotate a fake
# value to mint a fresh bucket per request (dodging per-IP caps) or set a
# victim's IP to burn their budget. These tests pin the spoof-resistant
# behavior: ignore XFF unless we actually run behind trusted proxies
# (PULSE_TRUSTED_PROXY_HOPS), and even then read the client from the right
# end of the chain where a client can't forge it.

import types

import pytest
from fastapi.testclient import TestClient

from pulse import rate_limit
from pulse.api import create_app


def _fake_request(xff=None, peer="203.0.113.7"):
    """Minimal stand-in for the bits of Request that _client_ip reads."""
    headers = {}
    if xff is not None:
        headers["x-forwarded-for"] = xff
    client = types.SimpleNamespace(host=peer) if peer is not None else None
    return types.SimpleNamespace(headers=headers, client=client)


# ---------------------------------------------------------------------------
# _client_ip — no trusted proxy (default): XFF is ignored entirely
# ---------------------------------------------------------------------------

def test_ignores_xff_when_no_trusted_proxy(monkeypatch):
    monkeypatch.delenv("PULSE_TRUSTED_PROXY_HOPS", raising=False)
    req = _fake_request(xff="1.2.3.4", peer="10.0.0.9")
    # The spoofable header is ignored; we use the real socket peer.
    assert rate_limit._client_ip(req) == "10.0.0.9"


def test_uses_peer_when_no_xff(monkeypatch):
    monkeypatch.delenv("PULSE_TRUSTED_PROXY_HOPS", raising=False)
    req = _fake_request(xff=None, peer="10.0.0.9")
    assert rate_limit._client_ip(req) == "10.0.0.9"


def test_unknown_when_no_peer_and_no_trust(monkeypatch):
    monkeypatch.delenv("PULSE_TRUSTED_PROXY_HOPS", raising=False)
    req = _fake_request(xff="1.2.3.4", peer=None)
    assert rate_limit._client_ip(req) == "unknown"


def test_unparseable_hops_treated_as_zero(monkeypatch):
    monkeypatch.setenv("PULSE_TRUSTED_PROXY_HOPS", "not-a-number")
    req = _fake_request(xff="1.2.3.4", peer="10.0.0.9")
    assert rate_limit._client_ip(req) == "10.0.0.9"


# ---------------------------------------------------------------------------
# _client_ip — behind one trusted proxy (e.g. Render): hops=1
# ---------------------------------------------------------------------------

def test_one_hop_reads_real_client(monkeypatch):
    monkeypatch.setenv("PULSE_TRUSTED_PROXY_HOPS", "1")
    # The LB forwarded the real client in XFF; the socket peer is the LB.
    req = _fake_request(xff="9.9.9.9", peer="10.0.0.1")
    assert rate_limit._client_ip(req) == "9.9.9.9"


def test_one_hop_ignores_prepended_spoof(monkeypatch):
    monkeypatch.setenv("PULSE_TRUSTED_PROXY_HOPS", "1")
    # Attacker prepends a fake IP; the trusted LB appends the attacker's
    # REAL address (6.6.6.6). We read past one trusted hop and land on the
    # real one, never the forged 1.1.1.1.
    req = _fake_request(xff="1.1.1.1, 6.6.6.6", peer="10.0.0.1")
    assert rate_limit._client_ip(req) == "6.6.6.6"


def test_one_hop_falls_back_to_peer_without_xff(monkeypatch):
    monkeypatch.setenv("PULSE_TRUSTED_PROXY_HOPS", "1")
    req = _fake_request(xff=None, peer="10.0.0.1")
    assert rate_limit._client_ip(req) == "10.0.0.1"


def test_two_hops_skips_both_proxies(monkeypatch):
    monkeypatch.setenv("PULSE_TRUSTED_PROXY_HOPS", "2")
    # chain = [client, lb_outer] (XFF) + [lb_inner] (peer); two trusted hops.
    req = _fake_request(xff="9.9.9.9, 10.0.0.2", peer="10.0.0.1")
    assert rate_limit._client_ip(req) == "9.9.9.9"


# ---------------------------------------------------------------------------
# Integration: rotating XFF cannot evade a real per-IP rate limit
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_client(tmp_path):
    db_path = tmp_path / "test.db"
    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(db_path), config_path=str(cfg))
    client = TestClient(app)
    client.post("/api/auth/signup", json={
        "email": "admin@example.com",
        "password": "correct-horse-battery",
    })
    return client


def test_rotating_xff_does_not_evade_rate_limit(auth_client, monkeypatch):
    """Default deploy (no trusted proxy): a different fake X-Forwarded-For
    on every request must NOT mint a fresh bucket. 20 uploads pass the
    limiter (and 400 on the magic-byte check), the 21st 429s even though
    each request carried a unique spoofed client IP."""
    monkeypatch.delenv("PULSE_TRUSTED_PROXY_HOPS", raising=False)
    files = {"file": ("test.evtx", b"not a real evtx", "application/octet-stream")}

    for i in range(20):
        r = auth_client.post("/api/scan", files=files,
                             headers={"X-Forwarded-For": f"9.9.9.{i}"})
        assert r.status_code == 400, f"call {i + 1} returned {r.status_code}"

    r = auth_client.post("/api/scan", files=files,
                         headers={"X-Forwarded-For": "9.9.9.250"})
    assert r.status_code == 429
    assert "retry-after" in {k.lower() for k in r.headers.keys()}
