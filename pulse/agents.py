"""Pulse Agents — server-side enrollment + heartbeat orchestration.

The dashboard mints an enrollment token; the agent installer exchanges
it for a long-lived bearer (`agent_token`) and uses that token on every
subsequent /api/agent/* call. This module owns:

  - Token generation (URL-safe, no '/+=' so the agent installer can paste
    it without escaping).
  - Token hashing (sha256, same pattern as api_tokens).
  - The exchange flow (single-use enrollment, idempotent rejects).
  - Status computation for the agent list UI.

Storage lives in `pulse.database`; this file is the policy layer that
HTTP handlers in `pulse.api` call into.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from pulse import database as db


# Enrollment tokens are short-lived (1h) and single-use. Agent tokens are
# long-lived and only revoked when the operator deletes the agent row.
ENROLLMENT_TTL_MINUTES = 60

# Heartbeat windows that drive the status pill in the UI. Tuned for a
# default 60s heartbeat cadence: any agent that misses two beats reads
# as "stale", and a sustained miss flips to "offline".
ONLINE_WINDOW_SECONDS = 180       # heartbeat in last 3 min  -> online
STALE_WINDOW_SECONDS  = 60 * 60   # heartbeat in last 1 hour -> stale


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _gen_token(prefix: str) -> str:
    """Generate a URL-safe random token. The prefix lets us tell enrollment
    tokens (`pe_…`) and agent tokens (`pa_…`) apart at a glance in logs."""
    body = secrets.token_urlsafe(32)
    return f"{prefix}_{body}"


def mint_enrollment(db_path: str, *, user_id: int, name: str) -> dict:
    """Create a pending agent row and return the raw enrollment token.

    The raw token is shown to the operator exactly once — only the sha256
    is stored. Caller is responsible for surfacing the install command
    that includes the raw token (the API layer formats that snippet).

    Returns: ``{"agent_id": int, "enrollment_token": str, "expires_at": str}``.
    """
    name = (name or "").strip() or "Pulse Agent"
    raw = _gen_token("pe")
    expires = (datetime.now() + timedelta(minutes=ENROLLMENT_TTL_MINUTES)) \
        .strftime("%Y-%m-%d %H:%M:%S")
    agent_id = db.insert_agent(
        db_path,
        user_id=user_id,
        name=name,
        enrollment_token_sha256=_hash(raw),
        enrollment_expires_at=expires,
    )
    return {"agent_id": agent_id, "enrollment_token": raw, "expires_at": expires}


def exchange_enrollment(db_path: str, *, enrollment_token: str,
                        hostname: Optional[str] = None,
                        platform: Optional[str] = None,
                        version: Optional[str] = None) -> Optional[dict]:
    """Validate the enrollment token and mint the long-lived agent token.

    Returns the new agent record + raw agent_token, or None when the
    enrollment token is unknown / already exchanged / expired. The raw
    agent_token is shown only here — the agent stores it locally and uses
    it as a Bearer header thereafter.
    """
    if not enrollment_token:
        return None
    agent = db.find_agent_by_enrollment_hash(db_path, _hash(enrollment_token))
    if agent is None:
        return None

    # Expiry guard. We compare lexicographic strings because they're stored
    # as `YYYY-MM-DD HH:MM:SS` — sortable as strings.
    expires = agent.get("enrollment_expires_at")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not expires or expires < now:
        return None

    raw_agent_token = _gen_token("pa")
    last4 = raw_agent_token[-4:]
    ok = db.complete_agent_enrollment(
        db_path,
        agent["id"],
        agent_token_sha256=_hash(raw_agent_token),
        agent_token_last4=last4,
        hostname=hostname,
        platform=platform,
        version=version,
    )
    if not ok:
        return None
    return {
        "agent_id": agent["id"],
        "agent_token": raw_agent_token,
        "name": agent.get("name"),
    }


def authenticate_agent(db_path: str, raw_token: str) -> Optional[dict]:
    """Resolve a Bearer token to its agent row, or None if no match.
    Paused agents authenticate but the API layer should reject their
    findings ingest separately so the operator can quiet a noisy host
    without revoking the token."""
    if not raw_token:
        return None
    return db.find_agent_by_token_hash(db_path, _hash(raw_token))


def heartbeat(db_path: str, agent_id: int, *,
              status: Optional[str] = None,
              version: Optional[str] = None) -> None:
    db.record_agent_heartbeat(db_path, agent_id, status=status, version=version)


def compute_status(agent: dict, *, now: Optional[datetime] = None) -> str:
    """Map an agent row -> status pill string.

    States:
      pending  — enrollment token minted, never exchanged
      paused   — exchanged but operator paused it
      online   — heartbeat within ONLINE_WINDOW_SECONDS
      stale    — heartbeat older than online but within STALE_WINDOW_SECONDS
      offline  — exchanged but no heartbeat / heartbeat older than STALE
    """
    if not agent.get("agent_token_sha256"):
        return "pending"
    if agent.get("paused"):
        return "paused"
    last = agent.get("last_heartbeat_at")
    if not last:
        return "offline"
    try:
        last_dt = datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return "offline"
    delta = (now or datetime.now()) - last_dt
    secs = delta.total_seconds()
    if secs <= ONLINE_WINDOW_SECONDS:
        return "online"
    if secs <= STALE_WINDOW_SECONDS:
        return "stale"
    return "offline"


def public_view(agent: dict) -> dict:
    """Strip secret fields from an agent row before returning to the UI.
    Token hashes never leave the server; the last4 is fine to surface."""
    return {
        "id": agent.get("id"),
        "user_id": agent.get("user_id"),
        "name": agent.get("name"),
        "hostname": agent.get("hostname"),
        "platform": agent.get("platform"),
        "version": agent.get("version"),
        "agent_token_last4": agent.get("agent_token_last4"),
        "last_heartbeat_at": agent.get("last_heartbeat_at"),
        "last_status": agent.get("last_status"),
        "paused": bool(agent.get("paused")),
        "created_at": agent.get("created_at"),
        "enrolled_at": agent.get("enrolled_at"),
        "enrollment_expires_at": agent.get("enrollment_expires_at"),
        "status": compute_status(agent),
    }
