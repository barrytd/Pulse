# pulse/rate_limit.py
# --------------------
# Tiny in-process sliding-window rate limiter. Used on auth + feedback
# endpoints to slow down brute-force and spam without pulling in slowapi.
#
# Scope note: this is per-process, in-memory, per-IP. On a single-worker
# Render free-tier deploy that's enough. If Pulse ever scales horizontally
# or to multiple gunicorn workers, swap the backing dict for Redis.
#
# Not a DoS shield — an attacker with a botnet can trivially outrun a
# per-IP counter. The goal is to make online password guessing and form
# spam expensive for opportunistic abuse.

from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import Deque, Dict, Optional, Tuple

from fastapi import HTTPException, Request


# key -> (window_seconds, max_hits, deque[timestamps])
_BUCKETS: Dict[Tuple[str, str], Tuple[int, int, Deque[float]]] = {}
_LOCK = threading.Lock()


def _trusted_proxy_hops() -> int:
    """How many proxies sit in front of Pulse, from `PULSE_TRUSTED_PROXY_HOPS`.

    0 (the default) means Pulse is reached directly, so `X-Forwarded-For`
    is attacker-controlled and must be ignored. Set it to the number of
    trusted reverse proxies / load balancers in front of the app — `1` for
    a single LB like Render. Anything unparseable is treated as 0.
    """
    raw = os.environ.get("PULSE_TRUSTED_PROXY_HOPS", "").strip()
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _client_ip(request: Request) -> str:
    """Resolve the real client IP, resisting `X-Forwarded-For` spoofing.

    `X-Forwarded-For` is set by the caller, so a client can rotate a fake
    value every request to mint a fresh rate-limit bucket (dodging per-IP
    caps), or set it to a victim's IP to burn that victim's budget. We only
    trust it to the extent we actually run behind proxies.

    The address chain, ordered least-to-most trustworthy, is the XFF
    entries (left = what the client claimed) followed by the real TCP peer
    (`request.client.host`, appended by the closest proxy). We trust the
    last `hops` of them as our own proxies and read the client from the
    next entry to the left. A spoofed value can only be *prepended* by the
    client, so it stays to the left of the real entries and is skipped.

    With `hops == 0` we ignore XFF entirely and use the socket peer, which
    is the safe default for local / self-hosted / direct-exposed installs.
    """
    peer = ""
    if request.client and request.client.host:
        peer = request.client.host

    hops = _trusted_proxy_hops()
    if hops <= 0:
        # Not behind a trusted proxy: XFF is untrusted, use the socket peer.
        return peer or "unknown"

    xff = request.headers.get("x-forwarded-for", "")
    chain = [p.strip() for p in xff.split(",") if p.strip()]
    chain.append(peer or "unknown")

    # Walk past `hops` trusted proxies on the right; the client is next.
    idx = len(chain) - 1 - hops
    if idx < 0:
        # Fewer addresses than declared hops (XFF stripped, or misconfig).
        # Fall back to the left-most known address rather than a proxy IP.
        return chain[0]
    return chain[idx]


def hit(request: Request, name: str, *, window_sec: int, max_hits: int) -> None:
    """Record a hit for (client_ip, name). Raises 429 if over the limit.

    `name` namespaces the bucket so different endpoints don't share a
    budget — e.g. a user hitting login 5x shouldn't consume their feedback
    budget too.

    Window is sliding: old timestamps fall off as the clock advances.
    """
    ip = _client_ip(request)
    key = (ip, name)
    now = time.monotonic()
    cutoff = now - window_sec
    with _LOCK:
        entry = _BUCKETS.get(key)
        if entry is None:
            dq: Deque[float] = deque()
            _BUCKETS[key] = (window_sec, max_hits, dq)
        else:
            dq = entry[2]
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= max_hits:
            retry_after = max(1, int(window_sec - (now - dq[0])))
            raise HTTPException(
                status_code=429,
                detail=f"Too many requests. Try again in {retry_after}s.",
                headers={"Retry-After": str(retry_after)},
            )
        dq.append(now)


def check(request: Request, name: str, *, window_sec: int, max_hits: int,
          status_code: int = 429,
          detail: Optional[str] = None) -> None:
    """Raise if (client_ip, name) is already over the cap, WITHOUT
    recording a new hit. Used for the failed-login lockout pattern:
    ``check()`` before the credential test, ``hit()`` after the
    credential test FAILS, so successful logins never consume budget.

    ``status_code`` lets callers pick 423 (Locked) for account-lockout
    semantics rather than the default 429.
    """
    ip = _client_ip(request)
    key = (ip, name)
    now = time.monotonic()
    cutoff = now - window_sec
    with _LOCK:
        entry = _BUCKETS.get(key)
        if entry is None:
            return
        dq = entry[2]
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= max_hits:
            retry_after = max(1, int(window_sec - (now - dq[0])))
            raise HTTPException(
                status_code=status_code,
                detail=detail or (
                    f"Too many attempts. Try again in {retry_after}s."
                ),
                headers={"Retry-After": str(retry_after)},
            )


def record(request: Request, name: str, *, window_sec: int) -> None:
    """Record a hit without checking the cap. Pairs with ``check()``
    for the "only count failures" pattern: ``record()`` is called only
    on the unhappy path so a typo-then-correct-password user doesn't
    consume their own lockout budget.

    ``window_sec`` here only matters as a tie-breaker for the deque's
    sliding cleanup — the cap is enforced by the matching ``check()``
    call, not here.
    """
    ip = _client_ip(request)
    key = (ip, name)
    now = time.monotonic()
    cutoff = now - window_sec
    with _LOCK:
        entry = _BUCKETS.get(key)
        if entry is None:
            dq: Deque[float] = deque()
            # max_hits is irrelevant here; check() is the gate.
            _BUCKETS[key] = (window_sec, 10_000, dq)
        else:
            dq = entry[2]
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)


def reset_all_for_tests() -> None:
    """Clear every bucket. Only call this from test fixtures."""
    with _LOCK:
        _BUCKETS.clear()
