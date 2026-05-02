"""HTTP transport for the Pulse Agent.

Wraps the three agent endpoints (`/api/agent/exchange`, `/heartbeat`,
`/findings`) as plain ``httpx.Client`` calls. Network errors and non-2xx
responses raise ``TransportError`` so the runtime loop can distinguish
"server down, retry later" from "agent token revoked, stop trying".

We use ``httpx`` instead of ``requests`` because httpx is already in the
Pulse dependency tree (via FastAPI's TestClient) and the API surface we
need is essentially identical. Sync mode keeps the agent simple — no
event loop on the customer's host.
"""

from __future__ import annotations

import platform
from typing import Optional

import httpx

from pulse import __version__ as PULSE_VERSION


class TransportError(Exception):
    """Wraps both connectivity failures and 4xx/5xx responses. The
    ``status_code`` attribute is None for network errors, otherwise the
    HTTP status the server returned. ``permanent`` is True when the
    status indicates the agent's token is no longer valid — the runtime
    should stop trying instead of retrying forever."""

    def __init__(self, message: str, *, status_code: Optional[int] = None,
                 permanent: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.permanent = permanent


class AgentTransport:
    """Thin HTTP client wrapper. One instance per AgentRuntime."""

    def __init__(self, server_url: str, agent_token: Optional[str] = None,
                 *, verify_tls: bool = True, timeout_sec: int = 15,
                 client: Optional[httpx.Client] = None):
        if not server_url:
            raise ValueError("server_url is required")
        # Normalize trailing slash so callers can pass either form. Empty
        # path on the agent endpoints means we just join base + relative.
        self.server_url = server_url.rstrip("/")
        self.timeout_sec = timeout_sec
        # `client` is the test seam — pass an httpx.Client wrapping a
        # FastAPI TestClient transport and the runtime exercises every
        # network path without a live server.
        self.client = client or httpx.Client(verify=verify_tls, timeout=timeout_sec)
        self.client.headers.update({
            "User-Agent": f"pulse-agent/{PULSE_VERSION} ({platform.system()})",
            "Accept":     "application/json",
        })
        if agent_token:
            self.set_agent_token(agent_token)

    def set_agent_token(self, token: str) -> None:
        """Update the bearer header. Used after a successful exchange so
        the same client can flip from "no auth" to "authenticated"
        without tearing down the connection pool."""
        self.client.headers["Authorization"] = f"Bearer {token}"

    # --- Endpoints -----------------------------------------------------

    def exchange(self, enrollment_token: str, *, hostname: str = "",
                 platform_str: str = "", version: str = "") -> dict:
        """Trade an enrollment token (`pe_…`) for a long-lived agent
        token (`pa_…`). Returns ``{agent_id, agent_token, name}`` on
        success. Raises TransportError on network failure or 4xx/5xx."""
        body = {
            "enrollment_token": enrollment_token,
            "hostname":         hostname or platform.node(),
            "platform":         platform_str or platform.platform(),
            "version":          version or PULSE_VERSION,
        }
        return self._post("/api/agent/exchange", body, expects_auth=False)

    def heartbeat(self, *, status: str = "running",
                  version: Optional[str] = None) -> dict:
        """Single beacon. Returns the server's response so the caller
        can react to ``paused`` flips."""
        body = {"status": status, "version": version or PULSE_VERSION}
        return self._post("/api/agent/heartbeat", body)

    def post_findings(self, scan_meta: dict, findings: list) -> dict:
        """Ship a batch of findings tagged with scan metadata. Returns
        ``{status, scan_id, findings_saved, score}`` on success.
        Raises TransportError on failure or paused-rejection."""
        body = {"scan": scan_meta or {}, "findings": findings or []}
        return self._post("/api/agent/findings", body)

    def get_latest_version(self) -> dict:
        """Fetch the auto-update manifest. Returns the server's
        ``{version, download_url, release_notes_url}`` plus
        ``{current, outdated}`` when the agent's bearer is set (the
        server identifies the caller and computes the comparison)."""
        return self._get("/api/agent/latest", expects_auth=False)

    # --- Internals -----------------------------------------------------

    def _get(self, path: str, *, expects_auth: bool = True) -> dict:
        url = self.server_url + path
        if expects_auth and "Authorization" not in self.client.headers:
            raise TransportError(
                "agent token not set — run `pulse-agent enroll` first",
                permanent=True,
            )
        try:
            resp = self.client.get(url)
        except httpx.HTTPError as exc:
            raise TransportError(f"connection error: {exc}", status_code=None) from exc
        return self._handle_response(resp)

    def _post(self, path: str, body: dict, *, expects_auth: bool = True) -> dict:
        url = self.server_url + path
        if expects_auth and "Authorization" not in self.client.headers:
            raise TransportError(
                "agent token not set — run `pulse-agent enroll` first",
                permanent=True,
            )
        try:
            resp = self.client.post(url, json=body)
        except httpx.HTTPError as exc:
            # Network-level failure (DNS, connect, TLS, timeout). Always
            # transient from the agent's point of view — retry later.
            raise TransportError(f"connection error: {exc}", status_code=None) from exc
        return self._handle_response(resp)

    def _handle_response(self, resp: httpx.Response) -> dict:
        if resp.status_code >= 500:
            raise TransportError(
                f"server error: {resp.status_code}", status_code=resp.status_code,
            )
        if resp.status_code == 401 or resp.status_code == 403:
            # Token revoked or never accepted. Stop retrying — the
            # operator has to mint a fresh enrollment token.
            raise TransportError(
                "agent token rejected — re-enroll required",
                status_code=resp.status_code, permanent=True,
            )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail")
            except Exception:
                detail = resp.text[:200]
            raise TransportError(
                f"{resp.status_code}: {detail}",
                status_code=resp.status_code,
                # 4xx that aren't auth-related are usually validation
                # errors — bad payload shape, oversized batch, etc.
                # These won't recover by retrying the same payload.
                permanent=True,
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise TransportError(f"non-JSON response: {exc}") from exc
