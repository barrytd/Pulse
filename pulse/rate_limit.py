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

import threading
import time
from collections import deque
from typing import Deque, Dict, Tuple

from fastapi import HTTPException, Request


# key -> (window_seconds, max_hits, deque[timestamps])
_BUCKETS: Dict[Tuple[str, str], Tuple[int, int, Deque[float]]] = {}
_LOCK = threading.Lock()


def _client_ip(request: Request) -> str:
    """Best-effort client IP extraction.

    Render (and most cloud load balancers) forward the real client IP in
    `X-Forwarded-For`. We trust the first hop because the LB sits in front
    of us; direct `request.client.host` would always be the LB.
    """
    xff = request.headers.get("x-forwarded-for", "").strip()
    if xff:
        # First entry is the original client; the rest are intermediate proxies.
        return xff.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


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


def reset_all_for_tests() -> None:
    """Clear every bucket. Only call this from test fixtures."""
    with _LOCK:
        _BUCKETS.clear()
