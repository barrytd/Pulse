# pulse/auth.py
# -------------
# Single-user authentication for the Pulse web dashboard.
#
# Everything here is stdlib — no new dependencies.
#   - Passwords hashed with hashlib.scrypt (memory-hard, OWASP recommended).
#   - Session cookies signed with HMAC-SHA256.
#   - Secret auto-generated on first boot and stored in pulse.yaml.
#
# Scope is deliberately small: one user, one browser session cookie, login
# page stays open so the owner can always get back in. No password reset
# flow, no 2FA, no CSRF token — SameSite=Lax covers the browser path for
# a local-deploy single-user app. Revisit before any multi-tenant deploy.

import base64
import hashlib
import hmac
import os
import secrets
import time
from typing import Optional

from fastapi import HTTPException, Request


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

_SCRYPT_N = 2 ** 14   # cpu/memory cost
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32


def hash_password(password: str) -> str:
    """Hash a password with scrypt + random salt. Returns a self-describing
    string so we can tune parameters later without breaking old hashes."""
    if not password:
        raise ValueError("password cannot be empty")
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
    )
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    """Timing-safe verify against a stored scrypt hash."""
    if not password or not stored:
        return False
    try:
        parts = stored.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return False
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = base64.b64decode(parts[4])
        expected = base64.b64decode(parts[5])
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt, n=n, r=r, p=p, dklen=len(expected),
        )
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Session cookies
# ---------------------------------------------------------------------------

SESSION_COOKIE_NAME = "pulse_session"
SESSION_MAX_AGE_SECONDS = 30 * 24 * 60 * 60   # 30 days


def ensure_session_secret(config: dict) -> str:
    """Return the session secret from config, generating one if missing.
    Caller is responsible for persisting the mutated config back to disk."""
    auth = config.setdefault("auth", {})
    secret = auth.get("session_secret")
    if not secret:
        secret = secrets.token_hex(32)
        auth["session_secret"] = secret
    return secret


def _sign(secret: str, payload: bytes) -> str:
    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")


def issue_session_cookie(secret: str, user_id: int, now: Optional[int] = None) -> str:
    """Build the signed cookie value for a logged-in user."""
    now = now if now is not None else int(time.time())
    payload = f"{int(user_id)}:{now}".encode("ascii")
    body = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    return f"{body}.{_sign(secret, payload)}"


def verify_session_cookie(secret: str, cookie_value: str,
                           now: Optional[int] = None,
                           max_age: int = SESSION_MAX_AGE_SECONDS) -> Optional[int]:
    """Return the user_id if the cookie is valid, else None."""
    if not cookie_value or "." not in cookie_value:
        return None
    try:
        body_b64, sig = cookie_value.rsplit(".", 1)
        # Re-pad for urlsafe_b64decode
        padded = body_b64 + "=" * (-len(body_b64) % 4)
        payload = base64.urlsafe_b64decode(padded)
        expected_sig = _sign(secret, payload)
        if not hmac.compare_digest(sig, expected_sig):
            return None
        parts = payload.decode("ascii").split(":")
        if len(parts) != 2:
            return None
        user_id = int(parts[0])
        issued = int(parts[1])
        now = now if now is not None else int(time.time())
        if now - issued > max_age:
            return None
        return user_id
    except Exception:
        return None


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

def require_login(request: Request) -> int:
    """FastAPI dependency that 401s unless a valid session cookie is present.

    Apps built with `disable_auth=True` (tests) set `app.state.auth_required
    = False`, in which case this is a no-op returning a sentinel user_id of 0.
    """
    if getattr(request.app.state, "auth_required", True) is False:
        return 0
    user_id = _resolve_user_id(request)
    if user_id is None:
        raise HTTPException(401, detail="Authentication required.")
    return user_id


def require_admin(request: Request) -> int:
    """FastAPI dependency: like require_login, but 403s unless the session
    belongs to a user whose role is 'admin'. In `disable_auth` mode we
    return 0 so unit tests that exercise admin endpoints don't need to
    stand up a real session."""
    if getattr(request.app.state, "auth_required", True) is False:
        return 0
    user_id = _resolve_user_id(request)
    if user_id is None:
        raise HTTPException(401, detail="Authentication required.")
    from pulse.database import get_user_by_id  # local import: avoid cycle
    db_path = getattr(request.app.state, "db_path", None)
    user = get_user_by_id(db_path, user_id) if db_path else None
    if not user or not user.get("active"):
        raise HTTPException(401, detail="Authentication required.")
    if user.get("role") != "admin":
        raise HTTPException(403, detail="Admin role required.")
    return user_id


def _resolve_user_id(request: Request):
    """Shared helper: returns the signed-in user id, or None. Checks the
    session cookie first, then falls back to an `Authorization: Bearer`
    API token. Deactivated users are rejected even if their cookie or
    token is otherwise valid."""
    secret = getattr(request.app.state, "session_secret", None)
    if not secret:
        raise HTTPException(500, detail="Session secret not configured.")
    db_path = getattr(request.app.state, "db_path", None)

    # Session cookie path (browser users).
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    user_id = verify_session_cookie(secret, cookie) if cookie else None

    # Bearer-token path (CI pipelines). Only consulted if there's no valid
    # cookie so browser sessions keep their fast path.
    if user_id is None:
        token = _extract_bearer_token(request)
        if token and db_path:
            from pulse.database import find_api_token_user, touch_api_token
            digest = hash_api_token(token)
            user_id = find_api_token_user(db_path, digest)
            if user_id is not None:
                touch_api_token(db_path, digest)

    if user_id is None:
        return None
    # Belt and braces: if the row was deactivated after the cookie was
    # issued, treat the session as invalid rather than trust the cookie.
    from pulse.database import get_user_by_id
    if db_path:
        user = get_user_by_id(db_path, user_id)
        if not user or not user.get("active"):
            return None
    return user_id


# ---------------------------------------------------------------------------
# API tokens (Bearer auth for CI / scripts)
# ---------------------------------------------------------------------------
#
# Token format is ``pulse_<32 hex chars>``. The ``pulse_`` prefix makes
# leaked tokens easy to grep for in logs / source, and the 128 bits of
# entropy afterwards makes them safe against brute force. We store only
# sha256(raw) plus the last 4 chars (for UI identification); the raw
# token is shown to the user exactly once on creation.

_TOKEN_PREFIX = "pulse_"


def generate_api_token() -> tuple[str, str, str]:
    """Mint a new API token. Returns ``(raw, sha256_hex, last4)`` — the
    caller should show ``raw`` to the user once and persist only the hash
    and last4 to the DB."""
    body = secrets.token_hex(16)  # 32 hex chars = 128 bits
    raw = _TOKEN_PREFIX + body
    return raw, hash_api_token(raw), raw[-4:]


def hash_api_token(raw: str) -> str:
    """sha256 hex digest of a raw token, used for DB lookup and storage."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _extract_bearer_token(request: Request) -> Optional[str]:
    """Pull the token out of an ``Authorization: Bearer ...`` header.
    Returns None if the header is missing or malformed."""
    header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not header:
        return None
    parts = header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None
