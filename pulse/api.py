# pulse/api.py
# ------------
# REST API for Pulse built with FastAPI.
#
# WHAT IS A REST API?
# A REST API lets other programs talk to Pulse over HTTP. Instead of running
# `python main.py` on the command line, another tool (a web dashboard, a
# Slack bot, a scheduled job, anything that speaks HTTP) can send a request
# and get back findings as JSON.
#
# ENDPOINTS:
#   POST /api/scan          upload a .evtx file, get findings back
#   GET  /api/history       list past scans from the local database
#   GET  /api/report/{id}   get the findings for a specific past scan
#   GET  /api/health        check the API is alive
#
# HOW TO RUN:
#   python main.py --api              starts the API on http://127.0.0.1:8000
#   python main.py --api --port 9000  starts it on a different port
#
# AUTO-GENERATED DOCS:
#   Once the server is running, open http://127.0.0.1:8000/docs in a browser.
#   FastAPI generates an interactive Swagger UI with every endpoint, its
#   parameters, example requests, and a "Try it out" button — all for free.

import asyncio
import functools
import json
import os
import tempfile
from datetime import datetime
from typing import Optional

# Upload guards. .evtx files begin with the ASCII bytes "ElfFile" followed by
# a NUL; anything else is either a wrong file type or crafted garbage. Cap at
# 500 MB so a hostile client can't DoS the server by streaming forever.
_EVTX_MAGIC = b"ElfFile\x00"
_UPLOAD_MAX_BYTES = 500 * 1024 * 1024
_UPLOAD_CHUNK = 1024 * 1024

import yaml
from fastapi import Body, Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from pulse import __version__
from pulse.auth import (
    SESSION_COOKIE_NAME, SESSION_MAX_AGE_SECONDS,
    ensure_session_secret, hash_password, issue_session_cookie,
    require_admin, require_login, verify_password,
)
from pulse.database import (
    count_admins, count_users, create_user, delete_all_monitor_sessions,
    delete_monitor_session, delete_scans, delete_user, get_fleet_summary,
    get_history, get_monitor_session_findings, get_scan_findings,
    get_user_by_email, get_user_by_id, init_db,
    list_monitor_sessions, list_users, save_scan,
    set_finding_review, update_user_active, update_user_email,
    update_user_password, update_user_role,
)
from pulse.core.detections import run_all_detections
from pulse.firewall import firewall_config
from pulse.core.rules_config import (
    RULE_META, filter_by_enabled, get_disabled_rules,
    get_rule_names, set_rule_enabled,
)
from pulse.alerts.emailer import dispatch_alerts
from pulse.remediation import attach_remediation
from pulse.monitor.monitor_service import MonitorManager
from pulse.core.parser import parse_evtx
from pulse.reports.reporter import (
    _build_html_report, _build_json_report, _calculate_score,
    calculate_score_from_findings,
)
from pulse.monitor.scheduled_scan import (
    ScheduledScanRunner, compute_next_run, describe_schedule,
    normalize_schedule_config,
)
from pulse.monitor.system_scan import is_admin as _system_scan_is_admin
from pulse.monitor.system_scan import is_supported_platform as _system_scan_supported
from pulse.monitor.system_scan import scan_system
from pulse.whitelist import filter_whitelist


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
# We use a factory pattern (a function that builds and returns the app) so
# tests can construct a fresh app with a temporary database per test. The
# default call without arguments gives you the real production app.

def create_app(db_path: Optional[str] = None, config_path: Optional[str] = None,
               disable_auth: bool = False) -> FastAPI:
    """
    Build and return a configured FastAPI application.

    Parameters:
        db_path (str):      Path to the SQLite database. Defaults to pulse.db
                            in the current working directory.
        config_path (str):  Path to pulse.yaml. Defaults to the file next to
                            this module's package root.

    Returns:
        FastAPI: Ready-to-run app. Pass it to uvicorn or FastAPI's TestClient.
    """
    # PULSE_ENV=production signals a hosted deploy (Render, etc.). In that
    # mode we read secrets from env vars, pin pulse.db to an absolute path so
    # the working directory can't drift, and lock /docs + CORS down.
    _is_production = os.environ.get("PULSE_ENV", "").strip().lower() == "production"

    if db_path is None:
        # Use an absolute path rooted at the current working directory so
        # relative paths don't resolve differently once a background thread
        # or subprocess changes cwd. Matters on Render, where the service
        # runs from a specific working dir but spawned tasks may not.
        db_path = os.path.abspath("pulse.db")

    if config_path is None:
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "pulse.yaml",
        )

    # Make sure the database has its tables before any request comes in.
    init_db(db_path)

    # Swagger / ReDoc / OpenAPI endpoints are disabled in production by
    # default so a hosted deploy doesn't leak the full endpoint surface.
    # Locally, opt in with PULSE_DOCS=1 (Windows set or bash export).
    _docs_enabled = (
        not _is_production
        and os.environ.get("PULSE_DOCS", "").strip().lower() in ("1", "true", "yes", "on")
    )
    app = FastAPI(
        title="Pulse API",
        description="REST API for the Pulse Windows event log analyzer.",
        version=__version__,
        docs_url="/docs" if _docs_enabled else None,
        redoc_url="/redoc" if _docs_enabled else None,
        openapi_url="/openapi.json" if _docs_enabled else None,
    )

    # Attach config so route handlers can reach it without globals.
    app.state.db_path = db_path
    app.state.config_path = config_path
    app.state.auth_required = not disable_auth

    # Resolve (and if needed, generate + persist) the session signing secret
    # so every logged-in browser cookie can be verified on future requests.
    # In production the secret MUST come from the PULSE_SECRET env var — we
    # never want a random one-shot secret on a hosted deploy (sessions would
    # all invalidate on every restart) nor a secret persisted into pulse.yaml
    # on a filesystem that might not be writable.
    if app.state.auth_required:
        env_secret = os.environ.get("PULSE_SECRET", "").strip()
        if env_secret:
            app.state.session_secret = env_secret
        elif _is_production:
            raise RuntimeError(
                "PULSE_ENV=production but PULSE_SECRET is not set. "
                "Set PULSE_SECRET in the Render service env vars."
            )
        else:
            cfg = _read_config(config_path) or {}
            had_secret = bool((cfg.get("auth") or {}).get("session_secret"))
            secret = ensure_session_secret(cfg)
            app.state.session_secret = secret
            if not had_secret:
                _write_config(config_path, cfg)
    else:
        app.state.session_secret = "test-secret-not-used"

    # Live monitor — one MonitorManager per app. It owns the async polling
    # loop and fans out findings to SSE subscribers. Lazy: doesn't start
    # polling until POST /api/monitor/start is called.
    app.state.monitor = MonitorManager(
        db_path=db_path,
        config_path=config_path,
        config_getter=lambda: _read_config(config_path),
    )

    # Scheduled-scan runner. Reads scheduled_scan from pulse.yaml every loop,
    # computes the next fire time, sleeps until then, runs the system scan.
    # Started lazily on FastAPI startup so tests that never boot the app
    # don't leak background tasks.
    def _get_sched_cfg():
        return (_read_config(config_path) or {}).get("scheduled_scan") or {}

    async def _run_scheduled_scan(cfg):
        # Run the (blocking) parser + detection pipeline in a worker thread so
        # we don't stall the event loop for SSE clients during a scheduled run.
        full_cfg = _read_config(config_path) or {}
        days = int(cfg.get("days") or 7)
        send_alerts = (
            bool(cfg.get("alert_email"))
            or bool(cfg.get("alert_slack"))
            or bool(cfg.get("alert_discord"))
        )
        # If none of the alert channels are ticked we still save the scan.
        return await asyncio.to_thread(
            scan_system,
            app.state.db_path,
            full_cfg,
            days,
            send_alerts,
        )

    app.state.scheduled_scan = ScheduledScanRunner(
        get_config=_get_sched_cfg,
        run_once=_run_scheduled_scan,
    )

    @app.on_event("startup")
    async def _start_scheduler():
        app.state.scheduled_scan.start()
        # Admin-status hint — logged once so the operator sees it without
        # needing to poll /api/health. Only interesting on Windows.
        if _system_scan_supported():
            kind = "administrator" if _system_scan_is_admin() else "standard user"
            print(f"  [*] Pulse is running as a {kind}.")

    @app.on_event("shutdown")
    async def _stop_scheduler():
        await app.state.scheduled_scan.stop()

    # CORS — in production, lock to the Render domain set via
    # PULSE_ALLOWED_ORIGIN (e.g. https://pulse.onrender.com). Locally we
    # allow the dev host origins so `python main.py --api` still works
    # from a browser opened to 127.0.0.1. No wildcard in production ever.
    if _is_production:
        allowed = os.environ.get("PULSE_ALLOWED_ORIGIN", "").strip()
        allow_origins = [o.strip() for o in allowed.split(",") if o.strip()]
    else:
        allow_origins = ["http://127.0.0.1:8000", "http://localhost:8000"]
    if allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allow_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    _register_routes(app)

    # Mount the static directory for CSS, JS, and other frontend assets.
    # Served at /static/* and not behind auth so the login page and
    # pre-login redirects can still reference shared stylesheets.
    _static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

    # Auth middleware — rather than sprinkle Depends(require_login) onto every
    # existing endpoint, a single middleware 401s for unauthenticated requests
    # to /api/*. Exceptions are the login surface and the health check.
    _AUTH_EXEMPT_EXACT   = {"/api/health"}
    _AUTH_EXEMPT_PREFIX  = ("/api/auth/",)

    @app.middleware("http")
    async def _auth_middleware(request, call_next):
        if not app.state.auth_required:
            return await call_next(request)
        path = request.url.path
        needs_auth = (
            path.startswith("/api/")
            and path not in _AUTH_EXEMPT_EXACT
            and not any(path.startswith(p) for p in _AUTH_EXEMPT_PREFIX)
        )
        if needs_auth:
            from pulse.auth import verify_session_cookie
            cookie = request.cookies.get(SESSION_COOKIE_NAME)
            user_id = verify_session_cookie(app.state.session_secret, cookie) if cookie else None
            if user_id is None:
                return JSONResponse({"detail": "Authentication required."}, status_code=401)
            # Reject cookies whose user was deactivated after sign-in.
            user = get_user_by_id(app.state.db_path, user_id)
            if not user or not user.get("active"):
                return JSONResponse({"detail": "Authentication required."}, status_code=401)
        return await call_next(request)

    return app


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _scan_scope_for(app, user_id):
    """Resolve the `user_id` filter to pass into database scan-read helpers.

    Admins see every scan (returns ``None``). Viewers see only the scans they
    own (returns their integer id). When auth is disabled (test mode, CLI
    app) the scope is also unrestricted.

    Why we look up the role here rather than baking it into the dependency:
    `require_login` intentionally stays lightweight (cookie + active check)
    so routes can reuse it cheaply. Only the routes that actually need the
    per-user data-isolation scope pay for the extra DB hit.
    """
    if not getattr(app.state, "auth_required", True):
        return None
    if user_id is None:
        return None
    user = get_user_by_id(app.state.db_path, user_id)
    if not user:
        return int(user_id)
    return None if user.get("role") == "admin" else int(user_id)


def _audit_scan_delete(db_path, user_id, ids_int, deleted, *, source_page):
    """Record a scan-deletion in the audit log. Wrapped in try/except via
    blocker.log_audit so a logging failure never breaks the delete."""
    from pulse.firewall import blocker
    user_row = get_user_by_id(db_path, user_id) if user_id else None
    email = (user_row or {}).get("email") if user_row else None
    ids_preview = ",".join(str(i) for i in ids_int[:10])
    if len(ids_int) > 10:
        ids_preview += f",+{len(ids_int) - 10} more"
    blocker.log_audit(
        db_path,
        action="delete_scan",
        source="dashboard",
        user=email,
        detail=f"page={source_page} requested={len(ids_int)} deleted={deleted} ids={ids_preview}",
    )


def _register_routes(app: FastAPI) -> None:
    """Wire every endpoint onto the app."""

    # Path to the dashboard HTML file (relative to this module).
    _web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
    _dashboard_path = os.path.join(_web_dir, "index.html")
    _login_path     = os.path.join(_web_dir, "login.html")

    # -------------------------------------------------------------------
    # GET / — Web dashboard (requires login)
    # -------------------------------------------------------------------
    def _serve_dashboard(request: Request):
        """Shared handler for every SPA page path. Serves the dashboard
        HTML shell; client-side routing reads `location.pathname` on boot
        and renders the correct page. Falls back to the login redirect
        when auth is required and the session cookie is missing/invalid."""
        if app.state.auth_required:
            cookie = request.cookies.get(SESSION_COOKIE_NAME)
            from pulse.auth import verify_session_cookie
            user_id = verify_session_cookie(app.state.session_secret, cookie) if cookie else None
            if user_id is None:
                return RedirectResponse(url="/login", status_code=302)
        return FileResponse(_dashboard_path, media_type="text/html")

    @app.get("/", include_in_schema=False)
    def dashboard(request: Request):
        return _serve_dashboard(request)

    # Every top-level SPA page gets its own path so the browser's back /
    # forward buttons and hard refreshes land on the right page. The
    # client reads `location.pathname` on boot and navigates accordingly.
    # Order matters: these must be registered before any catch-all so
    # /login and /docs keep winning against `/{page}` matching.
    _SPA_PAGES = (
        "dashboard", "monitor", "scans", "reports", "history",
        "fleet", "firewall", "whitelist", "rules", "settings", "findings",
    )
    for _page in _SPA_PAGES:
        app.add_api_route(
            f"/{_page}",
            _serve_dashboard,
            methods=["GET"],
            include_in_schema=False,
        )

    # Individual scan detail view — /scans/123 maps to the same shell;
    # the client routes into viewScan() based on the numeric segment.
    @app.get("/scans/{scan_id:int}", include_in_schema=False)
    def spa_scan_detail(scan_id: int, request: Request):
        return _serve_dashboard(request)

    # -------------------------------------------------------------------
    # GET /login — public login/signup page
    # -------------------------------------------------------------------
    @app.get("/login", include_in_schema=False)
    def login_page():
        return FileResponse(_login_path, media_type="text/html")

    # -------------------------------------------------------------------
    # Auth endpoints (all public — these are how you get a session)
    # -------------------------------------------------------------------
    @app.get("/api/auth/status")
    def auth_status(request: Request):
        """Tell the login page whether to show login or first-user signup,
        and tell the dashboard whether the user is already signed in."""
        if not app.state.auth_required:
            return {"logged_in": True, "email": "local", "role": "admin", "needs_signup": False}
        needs_signup = count_users(app.state.db_path) == 0
        cookie = request.cookies.get(SESSION_COOKIE_NAME)
        from pulse.auth import verify_session_cookie
        user_id = verify_session_cookie(app.state.session_secret, cookie) if cookie else None
        if user_id:
            user = get_user_by_id(app.state.db_path, user_id)
            if user and user.get("active"):
                return {
                    "logged_in": True,
                    "email": user["email"],
                    "role": user.get("role", "admin"),
                    "needs_signup": False,
                }
        return {"logged_in": False, "email": None, "role": None, "needs_signup": needs_signup}

    @app.post("/api/auth/signup")
    async def auth_signup(request: Request):
        """Create the one and only user. 409s after the first row exists."""
        if count_users(app.state.db_path) > 0:
            raise HTTPException(409, detail="Signup is closed. An account already exists.")
        body = await request.json()
        email = (body.get("email") or "").strip().lower()
        password = body.get("password") or ""
        if "@" not in email or "." not in email:
            raise HTTPException(400, detail="Please enter a valid email address.")
        if len(password) < 8:
            raise HTTPException(400, detail="Password must be at least 8 characters.")
        user_id = create_user(app.state.db_path, email, hash_password(password))
        cookie = issue_session_cookie(app.state.session_secret, user_id)
        resp = JSONResponse({"status": "ok", "email": email})
        resp.set_cookie(
            SESSION_COOKIE_NAME, cookie,
            max_age=SESSION_MAX_AGE_SECONDS, httponly=True, samesite="lax",
        )
        return resp

    @app.post("/api/auth/login")
    async def auth_login(request: Request):
        body = await request.json()
        email = (body.get("email") or "").strip().lower()
        password = body.get("password") or ""
        user = get_user_by_email(app.state.db_path, email)
        if not user or not verify_password(password, user["password_hash"]):
            # Deliberately vague — don't leak whether the email exists.
            raise HTTPException(401, detail="Invalid email or password.")
        if not user.get("active"):
            raise HTTPException(403, detail="Account is deactivated.")
        cookie = issue_session_cookie(app.state.session_secret, user["id"])
        resp = JSONResponse({"status": "ok", "email": user["email"]})
        resp.set_cookie(
            SESSION_COOKIE_NAME, cookie,
            max_age=SESSION_MAX_AGE_SECONDS, httponly=True, samesite="lax",
        )
        return resp

    @app.post("/api/auth/logout")
    def auth_logout():
        resp = JSONResponse({"status": "ok"})
        resp.delete_cookie(SESSION_COOKIE_NAME)
        return resp

    @app.get("/api/me")
    def api_me(user_id: int = Depends(require_login)):
        """Return the signed-in user's profile including role. The dashboard
        uses this to gate admin-only UI (Users card, etc.)."""
        if not app.state.auth_required:
            return {"id": 0, "email": "local", "role": "admin", "active": True}
        user = get_user_by_id(app.state.db_path, user_id)
        if not user:
            raise HTTPException(401, detail="Authentication required.")
        return {
            "id": user["id"],
            "email": user["email"],
            "role": user.get("role", "admin"),
            "active": user.get("active", True),
            "created_at": user.get("created_at"),
        }

    @app.put("/api/auth/email")
    async def auth_update_email(request: Request, user_id: int = Depends(require_login)):
        body = await request.json()
        current_password = body.get("current_password") or ""
        new_email = (body.get("email") or "").strip().lower()
        if "@" not in new_email or "." not in new_email:
            raise HTTPException(400, detail="Please enter a valid email address.")
        user = get_user_by_id(app.state.db_path, user_id)
        if not user or not verify_password(current_password, user["password_hash"]):
            raise HTTPException(401, detail="Current password is incorrect.")
        # Make sure we're not colliding with another row (defensive; shouldn't
        # happen in the single-user case, but keeps the UNIQUE constraint
        # from exploding into a 500).
        existing = get_user_by_email(app.state.db_path, new_email)
        if existing and existing["id"] != user_id:
            raise HTTPException(409, detail="That email is already in use.")
        update_user_email(app.state.db_path, user_id, new_email)
        return {"status": "ok", "email": new_email}

    @app.put("/api/auth/password")
    async def auth_update_password(request: Request, user_id: int = Depends(require_login)):
        body = await request.json()
        current_password = body.get("current_password") or ""
        new_password = body.get("new_password") or ""
        if len(new_password) < 8:
            raise HTTPException(400, detail="New password must be at least 8 characters.")
        user = get_user_by_id(app.state.db_path, user_id)
        if not user or not verify_password(current_password, user["password_hash"]):
            raise HTTPException(401, detail="Current password is incorrect.")
        update_user_password(app.state.db_path, user_id, hash_password(new_password))
        return {"status": "ok"}

    # -------------------------------------------------------------------
    # Admin user management (/api/users)
    # -------------------------------------------------------------------
    # Every write here is audited so an admin can reconstruct who-invited-
    # whom-and-when later. The "don't lock yourself out" guard lives on
    # demote / deactivate / delete: if the request would leave zero active
    # admins, reject it with 409.
    def _public_user(u):
        return {
            "id":         u["id"],
            "email":      u["email"],
            "role":       u.get("role", "admin"),
            "active":     bool(u.get("active", True)),
            "created_at": u.get("created_at"),
        }

    def _audit_user_action(acting_user_id, action, *, target=None, detail=None):
        from pulse.firewall import blocker
        acting = get_user_by_id(app.state.db_path, acting_user_id) if acting_user_id else None
        blocker.log_audit(
            app.state.db_path,
            action=action,
            source="dashboard",
            user=(acting or {}).get("email"),
            detail=f"target={target}" + (f" {detail}" if detail else ""),
        )

    @app.get("/api/users")
    def api_list_users(user_id: int = Depends(require_admin)):
        return {"users": [_public_user(u) for u in list_users(app.state.db_path)]}

    @app.post("/api/users")
    async def api_create_user(request: Request, user_id: int = Depends(require_admin)):
        body = await request.json()
        email = (body.get("email") or "").strip().lower()
        password = body.get("password") or ""
        role = (body.get("role") or "viewer").strip().lower()
        if "@" not in email or "." not in email:
            raise HTTPException(400, detail="Please enter a valid email address.")
        if len(password) < 8:
            raise HTTPException(400, detail="Password must be at least 8 characters.")
        if role not in ("admin", "viewer"):
            raise HTTPException(400, detail="Role must be 'admin' or 'viewer'.")
        if get_user_by_email(app.state.db_path, email):
            raise HTTPException(409, detail="A user with that email already exists.")
        new_id = create_user(app.state.db_path, email, hash_password(password), role=role)
        _audit_user_action(user_id, "create_user", target=email, detail=f"role={role}")
        user = get_user_by_id(app.state.db_path, new_id)
        return _public_user(user)

    @app.put("/api/users/{target_id}/role")
    async def api_update_user_role(target_id: int, request: Request,
                                   user_id: int = Depends(require_admin)):
        body = await request.json()
        role = (body.get("role") or "").strip().lower()
        if role not in ("admin", "viewer"):
            raise HTTPException(400, detail="Role must be 'admin' or 'viewer'.")
        target = get_user_by_id(app.state.db_path, target_id)
        if not target:
            raise HTTPException(404, detail="User not found.")
        # Guard: demoting the last active admin would lock everyone out.
        if target.get("role") == "admin" and role == "viewer":
            if count_admins(app.state.db_path, active_only=True) <= 1:
                raise HTTPException(409, detail="Cannot demote the last active admin.")
        update_user_role(app.state.db_path, target_id, role)
        _audit_user_action(user_id, "update_user_role",
                           target=target["email"], detail=f"role={role}")
        return _public_user(get_user_by_id(app.state.db_path, target_id))

    @app.put("/api/users/{target_id}/active")
    async def api_update_user_active(target_id: int, request: Request,
                                     user_id: int = Depends(require_admin)):
        body = await request.json()
        active = bool(body.get("active"))
        target = get_user_by_id(app.state.db_path, target_id)
        if not target:
            raise HTTPException(404, detail="User not found.")
        if target_id == user_id and not active:
            raise HTTPException(409, detail="You cannot deactivate your own account.")
        if (not active and target.get("role") == "admin"
                and count_admins(app.state.db_path, active_only=True) <= 1):
            raise HTTPException(409, detail="Cannot deactivate the last active admin.")
        update_user_active(app.state.db_path, target_id, active)
        _audit_user_action(user_id, "update_user_active",
                           target=target["email"], detail=f"active={int(active)}")
        return _public_user(get_user_by_id(app.state.db_path, target_id))

    @app.delete("/api/users/{target_id}")
    def api_delete_user(target_id: int, user_id: int = Depends(require_admin)):
        target = get_user_by_id(app.state.db_path, target_id)
        if not target:
            raise HTTPException(404, detail="User not found.")
        if target_id == user_id:
            raise HTTPException(409, detail="You cannot delete your own account.")
        if (target.get("role") == "admin"
                and count_admins(app.state.db_path, active_only=True) <= 1):
            raise HTTPException(409, detail="Cannot delete the last active admin.")
        delete_user(app.state.db_path, target_id)
        _audit_user_action(user_id, "delete_user", target=target["email"])
        return {"status": "ok"}

    # -------------------------------------------------------------------
    # GET /api/health
    # -------------------------------------------------------------------
    @app.get("/api/health")
    def health():
        """Simple aliveness check. Returns version info + privilege hints
        so the dashboard can surface the "run as admin" banner."""
        return {
            "status":  "ok",
            "version": __version__,
            "platform_windows": _system_scan_supported(),
            "is_admin":         _system_scan_is_admin(),
        }

    # -------------------------------------------------------------------
    # POST /api/scan
    # -------------------------------------------------------------------
    @app.post("/api/scan")
    async def scan(file: UploadFile = File(...), user_id: int = Depends(require_login)):
        """
        Parse an uploaded .evtx file, run detections, and return findings.

        The uploaded file is saved to a temp location, parsed, and then
        deleted. Nothing from the upload is kept on the server — only the
        scan summary and findings are written to the local database so
        /api/history and /api/report/{id} can reference them later.
        """
        if not file.filename or not file.filename.lower().endswith(".evtx"):
            raise HTTPException(
                status_code=400,
                detail="Only .evtx files are accepted.",
            )

        # Stream the upload to a temp file in chunks so a malicious client
        # can't exhaust memory with a huge body. Reject at the size cap and
        # reject if the header doesn't match the .evtx magic so renamed junk
        # never hits the parser. delete=False lets us close the handle on
        # Windows before re-opening it for parsing.
        suffix = ".evtx"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        upload_started = datetime.now()
        try:
            written = 0
            header = b""
            while True:
                chunk = await file.read(_UPLOAD_CHUNK)
                if not chunk:
                    break
                if len(header) < len(_EVTX_MAGIC):
                    header += chunk[: len(_EVTX_MAGIC) - len(header)]
                written += len(chunk)
                if written > _UPLOAD_MAX_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds {_UPLOAD_MAX_BYTES // (1024 * 1024)} MB limit.",
                    )
                tmp.write(chunk)
            tmp.close()

            if not header.startswith(_EVTX_MAGIC):
                raise HTTPException(
                    status_code=400,
                    detail="File is not a valid .evtx log (header magic mismatch).",
                )

            events = parse_evtx(tmp.name)
            findings = run_all_detections(events)

            # Audit the live Windows Firewall policy on every API scan.
            # Findings are skipped silently on non-Windows or when netsh
            # is unavailable — the caller doesn't have to gate on OS.
            findings += firewall_config.scan_firewall_config()

            # Apply whitelist so the API gives the same answers as the CLI.
            findings = _filter_with_whitelist(findings, app.state.config_path)

            # Honor user-disabled rules from pulse.yaml. This runs after
            # whitelist so the disabled-rules list wins over noisy rules
            # even if the whitelist wouldn't have caught them.
            _cfg = _read_config(app.state.config_path)
            findings = filter_by_enabled(findings, get_disabled_rules(_cfg))

            score_data = calculate_score_from_findings(findings)

            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in findings:
                sev = f.get("severity", "LOW")
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            scan_stats = {
                "total_events": len(events),
                "files_scanned": 1,
            }
            duration_sec = max(0, int((datetime.now() - upload_started).total_seconds()))
            scan_id = save_scan(
                app.state.db_path,
                findings,
                scan_stats=scan_stats,
                score=score_data["score"],
                score_label=score_data["label"],
                filename=file.filename,
                scope="Manual upload",
                duration_sec=duration_sec,
                user_id=user_id,
            )

            # Audit the scan so the Audit Log page shows who uploaded
            # what. Failure never blocks the response — log_audit
            # swallows its own errors.
            from pulse.firewall import blocker as _blocker
            _user_row = get_user_by_id(app.state.db_path, user_id) if user_id else None
            _blocker.log_audit(
                app.state.db_path,
                action="scan",
                source="dashboard",
                user=(_user_row or {}).get("email") if _user_row else None,
                detail=f"scan_id={scan_id} filename={file.filename} findings={len(findings)}",
            )

            # Fire threshold-based alerts if configured. SMTP can be slow,
            # so run it in a worker thread. Failure never breaks the scan
            # response — dispatch_alerts swallows its own errors and
            # returns a summary dict.
            alert_summary = {"enabled": False, "sent": False}
            try:
                cfg = _read_config(app.state.config_path) or {}
                alert_summary = await asyncio.to_thread(
                    dispatch_alerts,
                    app.state.db_path,
                    findings,
                    cfg.get("email") or {},
                    cfg.get("alerts") or {},
                    cfg.get("webhook") or {},
                )
            except Exception:
                pass

            return {
                "scan_id": scan_id,
                "filename": file.filename,
                "total_events": len(events),
                "total_findings": len(findings),
                "score": score_data["score"],
                "score_label": score_data["label"],
                "grade": score_data["grade"],
                "severity_counts": sev_counts,
                "findings": attach_remediation(findings),
                "alert": alert_summary,
            }
        finally:
            # Always clean up the temp file, even if parsing raised.
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    # -------------------------------------------------------------------
    # GET /api/history
    # -------------------------------------------------------------------
    @app.get("/api/history")
    def history(limit: int = 20, user_id: int = Depends(require_login)):
        """Return the most recent scans stored in the local database."""
        if limit < 1 or limit > 200:
            raise HTTPException(
                status_code=400,
                detail="limit must be between 1 and 200.",
            )
        scope = _scan_scope_for(app, user_id)
        return {"scans": get_history(app.state.db_path, limit=limit, user_id=scope)}

    # -------------------------------------------------------------------
    # GET /api/fleet — per-host rollup (Sprint 4 Thread A)
    # -------------------------------------------------------------------
    @app.get("/api/fleet")
    def fleet(user_id: int = Depends(require_login)):
        """Return one row per tracked hostname with score, last scan, and
        finding totals. Powers the Fleet overview page."""
        scope = _scan_scope_for(app, user_id)
        return {"hosts": get_fleet_summary(app.state.db_path, user_id=scope)}

    # -------------------------------------------------------------------
    # GET /api/audit — dashboard view into the audit_log table
    # -------------------------------------------------------------------
    @app.get("/api/audit")
    def audit_get(limit: int = 200, user_id: int = Depends(require_login)):
        """Return the most recent audit entries newest-first. Powers the
        Audit Log page — every block / unblock / push / scan / delete
        passes through `blocker.log_audit` so one query gives the reviewer
        the complete 'who did what, when' picture."""
        if limit < 1 or limit > 1000:
            raise HTTPException(400, detail="limit must be between 1 and 1000.")
        from pulse.firewall import blocker
        return {"rows": blocker.get_audit_log(app.state.db_path, limit=limit)}

    # -------------------------------------------------------------------
    # GET /api/fleet/export.csv — downloadable one-row-per-host summary
    # -------------------------------------------------------------------
    @app.get("/api/fleet/export.csv")
    def fleet_export_csv(user_id: int = Depends(require_login)):
        """Stream the fleet summary as CSV so analysts can hand the list
        to a spreadsheet or ticketing system without scraping the UI.
        Columns mirror `get_fleet_summary` keys one-for-one."""
        import csv
        import io

        rows = get_fleet_summary(app.state.db_path, user_id=_scan_scope_for(app, user_id))
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "hostname",
            "scan_count",
            "last_scan_at",
            "total_findings",
            "latest_score",
            "latest_grade",
            "worst_severity",
        ])
        for r in rows:
            writer.writerow([
                r.get("hostname", ""),
                r.get("scan_count", 0),
                r.get("last_scan_at", "") or "",
                r.get("total_findings", 0),
                r.get("latest_score", "") if r.get("latest_score") is not None else "",
                r.get("latest_grade", "") or "",
                r.get("worst_severity", "") or "",
            ])
        filename = f"pulse-fleet-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # -------------------------------------------------------------------
    # Block list — stage / list / push / unblock
    # -------------------------------------------------------------------
    @app.get("/api/block-list")
    def block_list_get(user_id: int = Depends(require_login)):
        """Return every row in the Pulse IP block list."""
        from pulse.firewall import blocker
        return {
            "rows": blocker.list_blocks(app.state.db_path),
            "windows": blocker.is_windows(),
            "is_admin": blocker._is_admin(),
        }

    @app.post("/api/block-ip")
    async def block_ip_post(request: Request, user_id: int = Depends(require_login)):
        """Stage a source IP for blocking. Optional {confirm: true} pushes
        it to Windows Firewall immediately (Windows + admin required)."""
        from pulse.firewall import blocker

        body = await request.json() if await request.body() else {}
        ip = (body.get("ip") or "").strip()
        if not ip:
            raise HTTPException(400, detail="'ip' is required.")
        comment = body.get("comment")
        finding_id = body.get("finding_id")
        confirm = bool(body.get("confirm"))
        # `force=true` bypasses the RFC1918 safety check for the
        # insider-threat case. Hard refusals (loopback, link-local, self-
        # block) still apply server-side.
        force = bool(body.get("force"))

        user = get_user_by_id(app.state.db_path, user_id) or {}
        user_email = user.get("email")

        staged = blocker.stage_ip(
            app.state.db_path,
            ip,
            comment=comment,
            finding_id=finding_id,
            source="dashboard",
            user=user_email,
            force=force,
        )
        if not staged["ok"]:
            return JSONResponse({"ok": False, "message": staged["message"]}, status_code=400)

        push_result = None
        if confirm:
            push_result = blocker.push_pending(
                app.state.db_path, source="dashboard", user=user_email,
            )

        return {
            "ok": True,
            "row": staged["row"],
            "forced": staged.get("forced", False),
            "push": push_result,
        }

    @app.post("/api/block-list/push")
    def block_list_push(user_id: int = Depends(require_login)):
        from pulse.firewall import blocker
        user = get_user_by_id(app.state.db_path, user_id) or {}
        return blocker.push_pending(app.state.db_path, source="dashboard", user=user.get("email"))

    # Bulk unblock — mirrors the scans batch pattern. Body: {"ips": [...]}.
    # Each IP is fed through unblock_ip the same way the single-item
    # endpoint does so we pick up the same audit log and firewall
    # delete-rule logic. Returns {deleted, failed: [{ip, message}]}.
    # Registered BEFORE the /{ip:path} catch-all so "batch" doesn't get
    # swallowed as an IP string.
    @app.delete("/api/block-ip/batch")
    def block_ip_delete_batch(payload: dict = Body(...), user_id: int = Depends(require_login)):
        from pulse.firewall import blocker
        ips = payload.get("ips") if isinstance(payload, dict) else None
        if not isinstance(ips, list) or not ips:
            raise HTTPException(400, detail="Body must be {\"ips\": [...]}")
        user = get_user_by_id(app.state.db_path, user_id) or {}
        email = user.get("email")
        deleted = 0
        failed: list[dict] = []
        for raw in ips:
            ip = str(raw).strip()
            if not ip:
                continue
            result = blocker.unblock_ip(
                app.state.db_path, ip, source="dashboard", user=email,
            )
            if result.get("ok"):
                deleted += 1
            else:
                failed.append({"ip": ip, "message": result.get("message", "unblock failed")})
        return {"deleted": deleted, "failed": failed}

    @app.delete("/api/block-ip/{ip:path}")
    def block_ip_delete(ip: str, user_id: int = Depends(require_login)):
        from pulse.firewall import blocker
        user = get_user_by_id(app.state.db_path, user_id) or {}
        result = blocker.unblock_ip(
            app.state.db_path, ip, source="dashboard", user=user.get("email"),
        )
        status = 200 if result["ok"] else 400
        return JSONResponse(result, status_code=status)

    # -------------------------------------------------------------------
    # DELETE /api/scans — delete one or many scans (+ cascading findings)
    # -------------------------------------------------------------------
    @app.delete("/api/scans")
    def delete_scans_endpoint(
        payload: dict = Body(...),
        user_id: int = Depends(require_login),
    ):
        ids = payload.get("ids") if isinstance(payload, dict) else None
        if not isinstance(ids, list) or not ids:
            raise HTTPException(400, detail="Body must be {\"ids\": [...]}")
        try:
            ids_int = [int(i) for i in ids]
        except (TypeError, ValueError):
            raise HTTPException(400, detail="All ids must be integers.")
        deleted = delete_scans(app.state.db_path, ids_int, user_id=_scan_scope_for(app, user_id))
        _audit_scan_delete(app.state.db_path, user_id, ids_int, deleted, source_page="scans")
        return {"deleted": deleted}

    # History page deletes the same underlying rows — expose a matching
    # /batch route so the frontend module can speak in terms of its own
    # resource name without the scans module leaking across pages.
    @app.delete("/api/history/batch")
    def delete_history_batch(
        payload: dict = Body(...),
        user_id: int = Depends(require_login),
    ):
        ids = payload.get("ids") if isinstance(payload, dict) else None
        if not isinstance(ids, list) or not ids:
            raise HTTPException(400, detail="Body must be {\"ids\": [...]}")
        try:
            ids_int = [int(i) for i in ids]
        except (TypeError, ValueError):
            raise HTTPException(400, detail="All ids must be integers.")
        deleted = delete_scans(app.state.db_path, ids_int, user_id=_scan_scope_for(app, user_id))
        _audit_scan_delete(app.state.db_path, user_id, ids_int, deleted, source_page="history")
        return {"deleted": deleted}

    # -------------------------------------------------------------------
    # GET /api/report/{scan_id}
    # -------------------------------------------------------------------
    @app.get("/api/report/{scan_id}")
    def report(scan_id: int, format: str = "json", user_id: int = Depends(require_login)):
        """Return every finding recorded for a specific past scan.

        When ?format=pdf, a binary PDF is returned as an attachment so the
        dashboard can offer a one-click PDF download.
        """
        scope = _scan_scope_for(app, user_id)
        findings = get_scan_findings(app.state.db_path, scan_id, user_id=scope)
        # Distinguish "scan exists but zero findings" from "scan not found"
        # by checking the scans table.
        history_rows = get_history(app.state.db_path, limit=200, user_id=scope)
        scan_row = next((s for s in history_rows if s["id"] == scan_id), None)
        if not findings and scan_row is None:
            raise HTTPException(
                status_code=404,
                detail=f"Scan {scan_id} not found.",
            )

        decorated = attach_remediation(findings)

        if format == "pdf":
            from pulse.reports.pdf_report import build_pdf
            pdf_bytes = build_pdf(decorated, scan_meta=scan_row)
            display_num = (scan_row or {}).get("number") or scan_id
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="pulse_scan_{display_num}.pdf"'
                },
            )

        return {"scan_id": scan_id, "findings": decorated}

    # -------------------------------------------------------------------
    # PUT /api/finding/{id}/review — toggle reviewed / false_positive
    # -------------------------------------------------------------------
    @app.put("/api/finding/{finding_id}/review")
    def review_finding(finding_id: int, payload: dict = Body(...)):
        """Update a finding's review flags. The two flags are independent —
        an analyst can mark something reviewed, false-positive, both, or
        neither. Body: {"reviewed": bool, "false_positive": bool,
        "note": "..."}."""
        p = payload or {}
        if "reviewed" not in p or "false_positive" not in p:
            raise HTTPException(
                400,
                detail="body must include 'reviewed' and 'false_positive' booleans",
            )
        reviewed = bool(p.get("reviewed"))
        false_positive = bool(p.get("false_positive"))
        note = p.get("note")
        updated = set_finding_review(
            app.state.db_path, finding_id, reviewed, false_positive, note,
        )
        if updated is None:
            raise HTTPException(404, detail=f"Finding {finding_id} not found.")
        return updated

    # -------------------------------------------------------------------
    # GET /api/score/daily — aggregated daily scores
    # -------------------------------------------------------------------
    @app.get("/api/score/daily")
    def daily_scores(days: int = 30, user_id: int = Depends(require_login)):
        """Return deduplicated daily scores combining all scans per day."""
        if days < 1 or days > 365:
            raise HTTPException(400, detail="days must be between 1 and 365.")

        scope = _scan_scope_for(app, user_id)
        all_scans = get_history(app.state.db_path, limit=200, user_id=scope)

        date_groups = {}
        for scan in all_scans:
            date = (scan.get("scanned_at") or "")[:10]
            if not date:
                continue
            if date not in date_groups:
                date_groups[date] = []
            date_groups[date].append(scan)

        daily = []
        for date in sorted(date_groups.keys(), reverse=True)[:days]:
            group = date_groups[date]
            all_findings = []
            total_events = 0
            filenames = []
            for scan in group:
                findings = get_scan_findings(app.state.db_path, scan["id"], user_id=scope)
                all_findings.extend(findings)
                total_events += scan.get("total_events", 0)
                if scan.get("filename"):
                    filenames.append(scan["filename"])

            score_data = calculate_score_from_findings(all_findings)
            daily.append({
                "date": date,
                "score": score_data["score"],
                "grade": score_data["grade"],
                "label": score_data["label"],
                "colour": score_data["colour"],
                "scans": len(group),
                "files": list(set(filenames)),
                "total_events": total_events,
                "total_findings": len(all_findings),
                "unique_rules": len(score_data["deductions"]),
                "deductions": score_data["deductions"],
                "categories": score_data["categories"],
            })

        return {"daily_scores": daily}

    # -------------------------------------------------------------------
    # GET /api/compare?a=<id>&b=<id> — diff two scans
    # -------------------------------------------------------------------
    @app.get("/api/compare")
    def compare_scans(a: int, b: int, user_id: int = Depends(require_login)):
        """Return the new / resolved / shared findings between two scans."""
        if a == b:
            raise HTTPException(400, detail="a and b must be different scans.")

        scope = _scan_scope_for(app, user_id)
        history_rows = get_history(app.state.db_path, limit=200, user_id=scope)
        scan_a = next((s for s in history_rows if s["id"] == a), None)
        scan_b = next((s for s in history_rows if s["id"] == b), None)
        if scan_a is None:
            raise HTTPException(404, detail=f"Scan {a} not found.")
        if scan_b is None:
            raise HTTPException(404, detail=f"Scan {b} not found.")

        from pulse.reports.comparison import diff_findings
        findings_a = get_scan_findings(app.state.db_path, a, user_id=scope)
        findings_b = get_scan_findings(app.state.db_path, b, user_id=scope)
        diff = diff_findings(findings_a, findings_b)

        return {
            "scan_a": scan_a,
            "scan_b": scan_b,
            "new":      diff["new"],
            "resolved": diff["resolved"],
            "shared":   diff["shared"],
        }

    # -------------------------------------------------------------------
    # GET /api/export/{scan_id} — download report as HTML or JSON
    # -------------------------------------------------------------------
    @app.get("/api/export/{scan_id}")
    def export_report(scan_id: int, format: str = "html", user_id: int = Depends(require_login)):
        """Download a formatted report for a past scan (html | json | pdf)."""
        if format not in ("html", "json", "pdf"):
            raise HTTPException(400, detail="format must be 'html', 'json', or 'pdf'.")

        scope = _scan_scope_for(app, user_id)
        findings = get_scan_findings(app.state.db_path, scan_id, user_id=scope)
        history_rows = get_history(app.state.db_path, limit=200, user_id=scope)
        scan_row = next((s for s in history_rows if s["id"] == scan_id), None)
        if scan_row is None:
            raise HTTPException(404, detail=f"Scan {scan_id} not found.")

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        scan_stats = {
            "total_events": scan_row.get("total_events", 0),
            "files_scanned": scan_row.get("files_scanned", 1),
            "top_event_ids": [],
            "earliest": scan_row.get("scanned_at", "-"),
            "latest": scan_row.get("scanned_at", "-"),
        }

        display_num = (scan_row or {}).get("number") or scan_id

        if format == "json":
            content = _build_json_report(findings, sev_counts, scan_stats)
            return Response(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=pulse_scan_{display_num}.json"},
            )

        if format == "pdf":
            from pulse.reports.pdf_report import build_pdf
            pdf_bytes = build_pdf(attach_remediation(findings), scan_meta=scan_row)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="pulse_scan_{display_num}.pdf"'},
            )

        content = _build_html_report(findings, sev_counts, scan_stats)
        return HTMLResponse(
            content=content,
            headers={"Content-Disposition": f"attachment; filename=pulse_scan_{display_num}.html"},
        )

    # -------------------------------------------------------------------
    # GET /api/reports — list persisted reports on disk (reports/ dir)
    # -------------------------------------------------------------------
    @app.get("/api/reports")
    def list_reports():
        """
        List every file in the ``reports/`` directory. Returns filename,
        format (extension), byte size, and generated timestamp derived
        either from the filename (pulse_report_YYYYMMDD_HHMMSS.ext) or
        the file's mtime. No database tracking yet — this is a straight
        directory listing.
        """
        reports_dir = "reports"
        items: list[dict] = []
        if os.path.isdir(reports_dir):
            for name in os.listdir(reports_dir):
                path = os.path.join(reports_dir, name)
                if not os.path.isfile(path):
                    continue
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                ext = os.path.splitext(name)[1].lstrip(".").lower() or "?"
                # Best-effort: parse pulse_*_YYYYMMDD_HHMMSS into ISO
                ts = None
                import re as _re
                m = _re.search(r"(\d{8})_(\d{6})", name)
                if m:
                    d, t = m.group(1), m.group(2)
                    ts = f"{d[:4]}-{d[4:6]}-{d[6:8]} {t[:2]}:{t[2:4]}:{t[4:6]}"
                if not ts:
                    import datetime as _dt
                    ts = _dt.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                items.append({
                    "filename": name,
                    "format": ext,
                    "size_bytes": st.st_size,
                    "generated_at": ts,
                })
        items.sort(key=lambda r: r["generated_at"], reverse=True)
        return {"reports": items}

    # -------------------------------------------------------------------
    # DELETE /api/reports/batch — remove many persisted reports at once
    # Body: {"filenames": ["a.pdf", "b.html", ...]}. Registered before the
    # /{filename} route so "batch" isn't interpreted as a filename.
    # -------------------------------------------------------------------
    @app.delete("/api/reports/batch")
    def delete_reports_batch(payload: dict = Body(...)):
        names = payload.get("filenames") if isinstance(payload, dict) else None
        if not isinstance(names, list) or not names:
            raise HTTPException(400, detail="Body must be {\"filenames\": [...]}")
        deleted = 0
        failed: list[dict] = []
        root = os.path.realpath("reports")
        for raw in names:
            safe = os.path.basename(str(raw))
            if not safe or safe != str(raw):
                failed.append({"filename": str(raw), "message": "Invalid filename."})
                continue
            path = os.path.realpath(os.path.join("reports", safe))
            if not path.startswith(root + os.sep) and path != root:
                failed.append({"filename": safe, "message": "Invalid filename."})
                continue
            if not os.path.isfile(path):
                failed.append({"filename": safe, "message": "Report not found."})
                continue
            try:
                os.remove(path)
                deleted += 1
            except OSError as e:
                failed.append({"filename": safe, "message": str(e)})
        return {"deleted": deleted, "failed": failed}

    # -------------------------------------------------------------------
    # GET /api/reports/{filename} — download a persisted report
    # -------------------------------------------------------------------
    @app.get("/api/reports/{filename}")
    def download_report(filename: str):
        # Defence in depth: os.path.basename strips any path, then we
        # re-check the resolved path is still inside reports/ so a
        # crafted filename cannot escape the directory.
        safe = os.path.basename(filename)
        if not safe or safe != filename:
            raise HTTPException(400, detail="Invalid filename.")
        path = os.path.realpath(os.path.join("reports", safe))
        root = os.path.realpath("reports")
        if not path.startswith(root + os.sep) and path != root:
            raise HTTPException(400, detail="Invalid filename.")
        if not os.path.isfile(path):
            raise HTTPException(404, detail="Report not found.")
        return FileResponse(
            path,
            headers={"Content-Disposition": f'attachment; filename="{safe}"'},
        )

    # -------------------------------------------------------------------
    # DELETE /api/reports/{filename} — remove a persisted report from disk
    # -------------------------------------------------------------------
    @app.delete("/api/reports/{filename}")
    def delete_report(filename: str):
        safe = os.path.basename(filename)
        if not safe or safe != filename:
            raise HTTPException(400, detail="Invalid filename.")
        path = os.path.realpath(os.path.join("reports", safe))
        root = os.path.realpath("reports")
        if not path.startswith(root + os.sep) and path != root:
            raise HTTPException(400, detail="Invalid filename.")
        if not os.path.isfile(path):
            raise HTTPException(404, detail="Report not found.")
        try:
            os.remove(path)
        except OSError as e:
            raise HTTPException(500, detail=f"Could not delete: {e}")
        return {"deleted": safe}

    # -------------------------------------------------------------------
    # GET /api/config — read current whitelist + settings + email + alerts
    # -------------------------------------------------------------------
    @app.get("/api/config")
    def get_config():
        """
        Return the current pulse.yaml config for the dashboard to render.

        IMPORTANT: the email password is never returned. We send back a
        boolean `password_set` flag instead, so the UI can show a "Password
        is configured" badge without ever putting the secret on the wire.
        """
        config = _read_config(app.state.config_path)
        whitelist = config.get("whitelist", {}) or {}
        email = config.get("email", {}) or {}
        alerts = config.get("alerts", {}) or {}
        webhook = config.get("webhook", {}) or {}

        return {
            "whitelist": {
                "accounts": whitelist.get("accounts", []) or [],
                "rules": whitelist.get("rules", []) or [],
                "services": whitelist.get("services", []) or [],
                "ips": whitelist.get("ips", []) or [],
            },
            "settings": {
                "logs": config.get("logs", "logs"),
                "format": config.get("format", "txt"),
                "severity": config.get("severity", "LOW"),
            },
            "email": {
                "smtp_host": email.get("smtp_host") or "",
                "smtp_port": email.get("smtp_port") or 587,
                "sender":    email.get("sender") or "",
                "recipient": email.get("recipient") or "",
                "password_set": bool(email.get("password")),
            },
            "alerts": {
                "enabled":          bool(alerts.get("enabled", False)),
                "threshold":        alerts.get("threshold", "HIGH"),
                "recipient":        alerts.get("recipient") or "",
                "cooldown_minutes": int(alerts.get("cooldown_minutes", 60)),
                "monitor_enabled":          bool(alerts.get("monitor_enabled", False)),
                "monitor_interval_minutes": int(alerts.get("monitor_interval_minutes", 30)),
            },
            # The webhook URL is a credential (anyone who has it can post to
            # your Slack/Discord as Pulse), so we expose only a boolean
            # "url_set" — the raw URL never leaves the server.
            "webhook": {
                "enabled":  bool(webhook.get("enabled", False)),
                "flavor":   webhook.get("flavor") or "",
                "url_set":  bool((webhook.get("url") or "").strip()),
            },
            "scheduled_scan": _scheduled_scan_view(config),
        }

    # -------------------------------------------------------------------
    # PUT /api/config/email — update SMTP settings
    # -------------------------------------------------------------------
    @app.put("/api/config/email")
    async def update_email(request: Request):
        """
        Update the email section of pulse.yaml.

        Password handling:
          - If the request omits "password" or sends an empty string,
            the existing password is kept (no overwrite).
          - This lets the dashboard re-save other fields without forcing
            the user to retype the password every time.
        """
        body = await request.json()
        config = _read_config(app.state.config_path)
        email = config.get("email", {}) or {}

        for key in ("smtp_host", "sender", "recipient"):
            if key in body:
                email[key] = (body[key] or "").strip() or None

        if "smtp_port" in body:
            try:
                email["smtp_port"] = int(body["smtp_port"])
            except (TypeError, ValueError):
                raise HTTPException(400, detail="smtp_port must be an integer.")

        # Only overwrite the password if a new non-empty value was sent.
        if body.get("password"):
            email["password"] = body["password"]

        config["email"] = email
        _write_config(app.state.config_path, config)

        return {"status": "ok", "password_set": bool(email.get("password"))}

    # -------------------------------------------------------------------
    # PUT /api/config/alerts — update alert thresholds + cooldown
    # -------------------------------------------------------------------
    @app.put("/api/config/alerts")
    async def update_alerts(request: Request):
        """Update the alerts section of pulse.yaml."""
        body = await request.json()
        config = _read_config(app.state.config_path)
        alerts = config.get("alerts", {}) or {}

        if "enabled" in body:
            alerts["enabled"] = bool(body["enabled"])

        if "threshold" in body:
            threshold = (body["threshold"] or "HIGH").upper()
            if threshold not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                raise HTTPException(400, detail="threshold must be LOW, MEDIUM, HIGH, or CRITICAL.")
            alerts["threshold"] = threshold

        if "recipient" in body:
            # Empty string means "fall back to email.recipient" — store as null.
            alerts["recipient"] = (body["recipient"] or "").strip() or None

        if "cooldown_minutes" in body:
            try:
                cooldown = int(body["cooldown_minutes"])
            except (TypeError, ValueError):
                raise HTTPException(400, detail="cooldown_minutes must be an integer.")
            if cooldown < 0:
                raise HTTPException(400, detail="cooldown_minutes cannot be negative.")
            alerts["cooldown_minutes"] = cooldown

        if "monitor_enabled" in body:
            alerts["monitor_enabled"] = bool(body["monitor_enabled"])

        if "monitor_interval_minutes" in body:
            try:
                interval = int(body["monitor_interval_minutes"])
            except (TypeError, ValueError):
                raise HTTPException(400, detail="monitor_interval_minutes must be an integer.")
            if interval < 1:
                raise HTTPException(400, detail="monitor_interval_minutes must be at least 1.")
            alerts["monitor_interval_minutes"] = interval

        config["alerts"] = alerts
        _write_config(app.state.config_path, config)

        return {"status": "ok", "alerts": alerts}

    # -------------------------------------------------------------------
    # POST /api/alerts/test — fire a single dummy alert email
    # -------------------------------------------------------------------
    @app.post("/api/alerts/test")
    def send_test_alert():
        """
        Fire one synthetic alert email to verify SMTP credentials work.

        Bypasses the cooldown table and the alerts.enabled switch — the
        whole point is to test connectivity without flipping production
        settings on. Uses a fake CRITICAL finding so the email body
        clearly looks like a test.
        """
        from pulse.alerts.emailer import send_alert

        config = _read_config(app.state.config_path)
        email_cfg  = config.get("email", {}) or {}
        alerts_cfg = config.get("alerts", {}) or {}

        if not email_cfg.get("password"):
            raise HTTPException(400, detail="No SMTP password configured. Save your email settings first.")
        if not (alerts_cfg.get("recipient") or email_cfg.get("recipient")):
            raise HTTPException(400, detail="No recipient configured for alerts.")

        synthetic = [{
            "rule":     "Pulse Test Alert",
            "severity": "CRITICAL",
            "details":  "This is a test alert sent from the Pulse dashboard. "
                        "If you are reading this, your SMTP settings are working.",
        }]

        ok = send_alert(email_cfg, alerts_cfg, synthetic)
        if not ok:
            raise HTTPException(502, detail="SMTP send failed. Check the server logs for details.")

        return {
            "status":    "sent",
            "recipient": alerts_cfg.get("recipient") or email_cfg.get("recipient"),
        }

    # -------------------------------------------------------------------
    # PUT /api/config/webhook — update Slack/Discord webhook settings
    # -------------------------------------------------------------------
    @app.put("/api/config/webhook")
    async def update_webhook(request: Request):
        """
        Update the webhook section of pulse.yaml.

        URL handling mirrors email.password: an omitted or empty "url" leaves
        the stored value alone. This lets the UI resave enabled/flavor without
        forcing the user to repaste their webhook URL every time.
        """
        body = await request.json()
        config = _read_config(app.state.config_path)
        webhook = config.get("webhook", {}) or {}

        if "enabled" in body:
            webhook["enabled"] = bool(body["enabled"])

        if "flavor" in body:
            flavor = (body["flavor"] or "").strip().lower()
            if flavor and flavor not in ("slack", "discord"):
                raise HTTPException(400, detail="flavor must be 'slack' or 'discord'.")
            webhook["flavor"] = flavor or None

        # Only overwrite url if a new non-empty value was sent.
        if body.get("url"):
            url = body["url"].strip()
            if not url.startswith(("http://", "https://")):
                raise HTTPException(400, detail="webhook url must start with http:// or https://.")
            webhook["url"] = url

        config["webhook"] = webhook
        _write_config(app.state.config_path, config)

        return {"status": "ok", "url_set": bool(webhook.get("url"))}

    # -------------------------------------------------------------------
    # POST /api/webhook/test — fire a single synthetic webhook message
    # -------------------------------------------------------------------
    @app.post("/api/webhook/test")
    def send_test_webhook():
        """Fire one synthetic webhook to verify the URL and flavor work.

        Bypasses the enabled toggle — the whole point is to verify before
        turning alerts on. Uses a fake CRITICAL finding so the message body
        is clearly a test.
        """
        from pulse.alerts.webhook import send_webhook

        config = _read_config(app.state.config_path)
        webhook_cfg = config.get("webhook", {}) or {}

        url = (webhook_cfg.get("url") or "").strip()
        if not url:
            raise HTTPException(400, detail="No webhook URL configured. Save your webhook settings first.")

        synthetic = [{
            "rule":     "Pulse Test Alert",
            "severity": "CRITICAL",
            "details":  "This is a test notification from the Pulse dashboard. "
                        "If you see this message, your webhook is wired up correctly.",
        }]

        # Bypass the enabled flag for the test.
        test_cfg = {**webhook_cfg, "enabled": True}
        ok = send_webhook(test_cfg, synthetic)
        if not ok:
            raise HTTPException(502, detail="Webhook POST failed. Check the URL and try again.")

        return {"status": "sent"}

    # -------------------------------------------------------------------
    # POST /api/scan/system — one-shot scan of the local Windows event logs
    # -------------------------------------------------------------------
    @app.post("/api/scan/system")
    async def scan_system_endpoint(request: Request, user_id: int = Depends(require_login)):
        """Scan the local machine's C:\\Windows\\System32\\winevt\\Logs\\ directly.
        Body (all optional):
          days:   int 1-365, default 1
          alert:  bool, fire configured alerts when CRITICAL/HIGH findings hit
        """
        if not _system_scan_supported():
            raise HTTPException(400, detail="System scan requires Windows")

        try:
            body = await request.json()
        except Exception:
            body = {}

        try:
            days = int(body.get("days", 1) or 1)
        except (TypeError, ValueError):
            raise HTTPException(400, detail="days must be an integer")
        if days < 1 or days > 365:
            raise HTTPException(400, detail="days must be between 1 and 365")

        send_alerts = bool(body.get("alert", True))

        config = _read_config(app.state.config_path) or {}
        try:
            result = await asyncio.to_thread(
                functools.partial(
                    scan_system,
                    app.state.db_path,
                    config,
                    days=days,
                    send_alerts=send_alerts,
                    user_id=user_id,
                )
            )
        except RuntimeError as exc:
            # Platform guard from inside scan_system (belt-and-braces).
            raise HTTPException(400, detail=str(exc))
        except FileNotFoundError as exc:
            raise HTTPException(500, detail=str(exc))

        # Include admin status so the dashboard can warn when a scan comes
        # back empty because the Security.evtx log wasn't readable.
        result["is_admin"] = _system_scan_is_admin()
        return result

    # -------------------------------------------------------------------
    # GET /api/scheduler/status — read-only scheduler state for the dashboard
    # -------------------------------------------------------------------
    @app.get("/api/scheduler/status")
    def scheduler_status():
        cfg = (_read_config(app.state.config_path) or {}).get("scheduled_scan") or {}
        next_run = compute_next_run(cfg)
        return {
            "enabled":  bool(cfg.get("enabled")),
            "schedule": describe_schedule(cfg),
            "next_run": next_run.isoformat() if next_run else None,
            "platform_supported": _system_scan_supported(),
            "is_admin":            _system_scan_is_admin(),
        }

    # -------------------------------------------------------------------
    # POST /api/scheduler/config — save the scheduled-scan configuration
    # -------------------------------------------------------------------
    @app.post("/api/scheduler/config")
    async def scheduler_config(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        try:
            cleaned = normalize_schedule_config(body)
        except ValueError as exc:
            raise HTTPException(400, detail=str(exc))

        config = _read_config(app.state.config_path) or {}
        config["scheduled_scan"] = cleaned
        _write_config(app.state.config_path, config)

        # Nudge the running scheduler to re-read config so the next fire
        # time reflects the save without restarting the server.
        try:
            app.state.scheduled_scan.reload()
        except AttributeError:
            pass

        next_run = compute_next_run(cleaned)
        return {
            "status":   "ok",
            "config":   cleaned,
            "schedule": describe_schedule(cleaned),
            "next_run": next_run.isoformat() if next_run else None,
        }

    # -------------------------------------------------------------------
    # DELETE /api/whitelist/batch — remove many custom whitelist entries
    # in one request. Body: {"entries": [{"key": "services", "value": "foo"}]}.
    # Built-in entries aren't stored in pulse.yaml so nothing the caller
    # sends can touch them; the UI also hides checkboxes for built-ins so
    # they can't be selected.
    # -------------------------------------------------------------------
    @app.delete("/api/whitelist/batch")
    def delete_whitelist_batch(payload: dict = Body(...)):
        entries = payload.get("entries") if isinstance(payload, dict) else None
        if not isinstance(entries, list) or not entries:
            raise HTTPException(400, detail="Body must be {\"entries\": [{key,value},...]}")
        allowed_keys = {"accounts", "services", "ips", "rules"}
        # Group values-to-remove by key for a single save pass.
        remove: dict[str, set] = {k: set() for k in allowed_keys}
        for raw in entries:
            if not isinstance(raw, dict):
                raise HTTPException(400, detail="Each entry must be an object.")
            k = raw.get("key")
            v = raw.get("value")
            if k not in allowed_keys or not isinstance(v, str):
                raise HTTPException(400, detail="Invalid entry.")
            remove[k].add(v)

        config = _read_config(app.state.config_path)
        wl = config.get("whitelist", {}) or {}
        deleted = 0
        for k in allowed_keys:
            if not remove[k]:
                continue
            before = list(wl.get(k, []) or [])
            after = [v for v in before if v not in remove[k]]
            deleted += len(before) - len(after)
            wl[k] = after
        config["whitelist"] = wl
        _write_config(app.state.config_path, config)
        return {"deleted": deleted, "whitelist": wl}

    # -------------------------------------------------------------------
    # PUT /api/config/whitelist — update the whitelist
    # -------------------------------------------------------------------
    @app.put("/api/config/whitelist")
    async def update_whitelist(request: Request):
        """Update the whitelist section in pulse.yaml."""
        body = await request.json()

        config = _read_config(app.state.config_path)

        whitelist = config.get("whitelist", {}) or {}
        for key in ("accounts", "rules", "services", "ips"):
            if key in body:
                if not isinstance(body[key], list):
                    raise HTTPException(400, detail=f"{key} must be a list.")
                whitelist[key] = body[key]

        config["whitelist"] = whitelist
        _write_config(app.state.config_path, config)

        return {"status": "ok", "whitelist": whitelist}

    # -------------------------------------------------------------------
    # GET /api/rules — list all available detection rule names
    # -------------------------------------------------------------------
    @app.get("/api/rules")
    def list_rules():
        """Return the names of all detection rules Pulse can run."""
        return {"rules": _get_rule_names()}

    # -------------------------------------------------------------------
    # GET /api/rules/details — rules page payload (name, event_id,
    # severity, mitre, enabled). The dashboard uses this to render the
    # full Rules table; /api/rules keeps the lightweight name-only shape
    # the dashboard filter dropdowns already depend on.
    # -------------------------------------------------------------------
    @app.get("/api/rules/details")
    def list_rules_details():
        config = _read_config(app.state.config_path)
        disabled = set(get_disabled_rules(config))
        rows = []
        for name in _get_rule_names():
            meta = RULE_META.get(name, {})
            rows.append({
                "name":     name,
                "event_id": meta.get("event_id"),
                "severity": meta.get("severity", "LOW"),
                "mitre":    meta.get("mitre"),
                "enabled":  name not in disabled,
            })
        return {"rules": rows}

    # -------------------------------------------------------------------
    # PUT /api/rules/{name}/enabled — toggle a rule on/off in pulse.yaml
    # -------------------------------------------------------------------
    @app.put("/api/rules/{name}/enabled")
    async def set_rule_enabled_endpoint(name: str, request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        if "enabled" not in body:
            raise HTTPException(400, detail="Missing 'enabled' boolean in body.")
        enabled = bool(body.get("enabled"))

        if name not in RULE_META:
            raise HTTPException(404, detail=f"Unknown rule: {name}")

        config = _read_config(app.state.config_path)
        set_rule_enabled(config, name, enabled)
        _write_config(app.state.config_path, config)
        return {"name": name, "enabled": enabled}

    # -------------------------------------------------------------------
    # Live monitor endpoints
    # -------------------------------------------------------------------
    # The dashboard's live panel talks to these four endpoints plus the SSE
    # stream. Start/stop are POST (they change server state), status and
    # history are GET (they're read-only), and /stream is a long-lived GET
    # that fans out events in real time.

    @app.post("/api/monitor/start")
    async def monitor_start(request: Request):
        """Start or reconfigure the live monitor.

        Request body (all optional):
          poll_interval: int seconds (>=5)
          mode:          "live" (wevtutil, Windows-only) or "file"
          channels:      list of channel names for live mode
          log_folder:    path for file mode
        """
        try:
            body = await request.json()
        except Exception:
            body = {}

        status = await app.state.monitor.start(
            poll_interval=body.get("poll_interval"),
            mode=body.get("mode"),
            channels=body.get("channels"),
            log_folder=body.get("log_folder"),
        )
        return status

    @app.post("/api/monitor/stop")
    async def monitor_stop():
        """Stop the live monitor. Idempotent."""
        return await app.state.monitor.stop()

    @app.get("/api/monitor/status")
    def monitor_status():
        """Current monitor state — used by the dashboard on page load."""
        return app.state.monitor.status()

    @app.get("/api/monitor/history")
    def monitor_history(limit: int = 50):
        """Recent poll history — each entry is one check, with or without findings."""
        if limit < 1 or limit > 100:
            raise HTTPException(400, detail="limit must be between 1 and 100.")
        return {"checks": app.state.monitor.recent_checks(limit=limit)}

    # -------------------------------------------------------------------
    # Monitor sessions — one row per Start→Stop span, with linked findings
    # -------------------------------------------------------------------
    @app.get("/api/monitor/sessions")
    def monitor_sessions(limit: int = 100):
        """List monitor sessions, newest first."""
        if limit < 1 or limit > 500:
            raise HTTPException(400, detail="limit must be between 1 and 500.")
        return {"sessions": list_monitor_sessions(app.state.db_path, limit=limit)}

    @app.get("/api/monitor/sessions/{session_id}/findings")
    def monitor_session_findings(session_id: int):
        """All findings detected during one monitor session."""
        findings = get_monitor_session_findings(app.state.db_path, session_id)
        return {"session_id": session_id, "findings": attach_remediation(findings)}

    # Bulk delete — body {"ids": [...]}. Registered before the
    # /{session_id:int} route even though the typed path param already
    # rejects non-int matches; keeping it above for symmetry with the
    # other batch endpoints.
    @app.delete("/api/monitor/sessions/batch")
    def monitor_sessions_delete_batch(payload: dict = Body(...)):
        ids = payload.get("ids") if isinstance(payload, dict) else None
        if not isinstance(ids, list) or not ids:
            raise HTTPException(400, detail="Body must be {\"ids\": [...]}")
        try:
            ids_int = [int(i) for i in ids]
        except (TypeError, ValueError):
            raise HTTPException(400, detail="All ids must be integers.")
        # Refuse to delete the active session — same rule as the
        # single-item endpoint. Report as a failure rather than aborting
        # the whole batch.
        active_id = getattr(app.state.monitor, "session_id", None)
        deleted = 0
        failed: list[dict] = []
        for sid in ids_int:
            if active_id is not None and int(active_id) == sid:
                failed.append({"id": sid, "message": "Session is active."})
                continue
            if delete_monitor_session(app.state.db_path, sid):
                deleted += 1
            else:
                failed.append({"id": sid, "message": "Not found."})
        return {"deleted": deleted, "failed": failed}

    @app.delete("/api/monitor/sessions/{session_id}")
    def monitor_session_delete(session_id: int):
        """Delete one session plus its scans and findings."""
        # Refuse to delete the currently-active session so the dashboard
        # doesn't end up with a dangling session_id on fresh scans.
        active_id = getattr(app.state.monitor, "session_id", None)
        if active_id is not None and int(active_id) == int(session_id):
            raise HTTPException(400, detail="Stop monitoring before deleting the active session.")
        ok = delete_monitor_session(app.state.db_path, session_id)
        if not ok:
            raise HTTPException(404, detail="Session not found")
        return {"deleted": 1}

    @app.delete("/api/monitor/sessions")
    def monitor_sessions_clear():
        """Wipe every monitor session and its linked scans/findings.

        Active session is preserved — callers should stop monitoring first
        if they want a full reset.
        """
        active_id = getattr(app.state.monitor, "session_id", None)
        if active_id is not None:
            raise HTTPException(400, detail="Stop monitoring before clearing sessions.")
        count = delete_all_monitor_sessions(app.state.db_path)
        return {"deleted": count}

    @app.post("/api/monitor/test-alert")
    async def monitor_test_alert():
        """Inject a synthetic finding through the live-monitor fan-out.

        Useful for verifying that the full SSE + UI pipeline (stream ->
        EventSource -> slide-in + ding) is wired up correctly without
        having to wait for a real detection to fire.
        """
        manager = app.state.monitor
        if not manager.active:
            raise HTTPException(
                400,
                detail="Monitor is not active. Start monitoring first.",
            )
        await manager.inject_test_finding()
        return {"status": "sent"}

    @app.get("/api/monitor/stream")
    async def monitor_stream(request: Request):
        """Server-Sent Events stream.

        Each message is emitted as:
            event: {type}
            data:  {json}

        Event types:
          status   — monitor started/stopped or reconfigured
          finding  — a new detection was triggered
          check    — heartbeat after every poll (even when no findings)
          error    — poll failed
          ping     — keep-alive comment so proxies don't time us out
        """
        manager = app.state.monitor
        queue = manager.subscribe()

        async def event_generator():
            # Kick the connection off with the current status so the client
            # renders correctly even if it connected mid-session.
            yield _sse_format("status", {"status": manager.status()})
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15)
                    except asyncio.TimeoutError:
                        # Heartbeat: an SSE comment line keeps proxies from
                        # killing the idle connection without pushing a real
                        # event into the client's handler.
                        yield ": ping\n\n"
                        continue
                    etype = event.pop("type", "message")
                    yield _sse_format(etype, event)
            finally:
                manager.unsubscribe(queue)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",  # disable nginx buffering if present
                "Connection": "keep-alive",
            },
        )

    # -------------------------------------------------------------------
    # GET /api/whitelist/builtin — list the built-in known-good services
    # -------------------------------------------------------------------
    @app.get("/api/whitelist/builtin")
    def builtin_whitelist():
        """Return the built-in KNOWN_GOOD_SERVICES list the whitelist UI renders.

        These are always active and cannot be removed — the UI shows them
        as muted 'built-in' rows so users can see what's already covered.
        """
        from pulse.core.known_good import KNOWN_GOOD_SERVICES
        return {"services": list(KNOWN_GOOD_SERVICES)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sse_format(event_type, payload):
    """Format one message for an SSE stream.

    SSE framing is: `event: <name>\\n` + `data: <line>\\n` (repeat) + blank line.
    The data line must not contain raw newlines, so we json-dump to a single
    line and send that."""
    data = json.dumps(payload, default=str)
    return f"event: {event_type}\ndata: {data}\n\n"


def _read_config(config_path):
    """Read pulse.yaml and return the config dict."""
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return {}


def _write_config(config_path, config):
    """Write config dict back to pulse.yaml."""
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _get_rule_names():
    """Return a sorted list of all detection rule names."""
    return get_rule_names()


def _scheduled_scan_view(config):
    """Build the scheduled_scan slice of GET /api/config."""
    cfg = (config or {}).get("scheduled_scan") or {}
    next_run = compute_next_run(cfg)
    return {
        "enabled":       bool(cfg.get("enabled", False)),
        "days":          int(cfg.get("days", 7) or 7),
        "schedule":      cfg.get("schedule") or "daily",
        "time":          cfg.get("time") or "09:00",
        "weekday":       int(cfg.get("weekday", 1) or 0),
        "cron":          cfg.get("cron") or "",
        "alert_email":   bool(cfg.get("alert_email", True)),
        "alert_slack":   bool(cfg.get("alert_slack", False)),
        "alert_discord": bool(cfg.get("alert_discord", False)),
        "description":   describe_schedule(cfg),
        "next_run":      next_run.isoformat() if next_run else None,
        "platform_supported": _system_scan_supported(),
    }


def _filter_with_whitelist(findings, config_path):
    """
    Apply the same whitelist the CLI uses (pulse.yaml + built-in known-good
    services) so the API returns identical results to `python main.py`.
    """
    config = _read_config(config_path)
    whitelist = config.get("whitelist", {}) or {}
    return filter_whitelist(findings, whitelist)


# ---------------------------------------------------------------------------
# Entry point for `python main.py --api`
# ---------------------------------------------------------------------------

def run(host: str = "127.0.0.1", port: int = 8000, db_path: Optional[str] = None) -> None:
    """
    Start the API server with uvicorn. Blocks until Ctrl+C.

    Parameters:
        host (str):      Address to bind to. Default 127.0.0.1 (local only).
        port (int):      Port to listen on. Default 8000.
        db_path (str):   SQLite database path. Default pulse.db.
    """
    import uvicorn

    app = create_app(db_path=db_path)
    print(f"  Pulse API {__version__} starting on http://{host}:{port}")
    print(f"  Interactive docs: http://{host}:{port}/docs")
    print()
    uvicorn.run(app, host=host, port=port, log_level="info")
