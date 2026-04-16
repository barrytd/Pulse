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
import json
import os
import tempfile
from typing import Optional

import yaml
from fastapi import Body, Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from pulse import __version__
from pulse.auth import (
    SESSION_COOKIE_NAME, SESSION_MAX_AGE_SECONDS,
    ensure_session_secret, hash_password, issue_session_cookie,
    require_login, verify_password,
)
from pulse.database import (
    REVIEW_STATUSES,
    count_users, create_user, delete_scans, get_history, get_scan_findings,
    get_user_by_email, get_user_by_id, init_db, save_scan,
    set_finding_review, update_user_email, update_user_password,
)
from pulse.detections import run_all_detections
from pulse.emailer import dispatch_alerts
from pulse.remediation import attach_remediation
from pulse.monitor_service import MonitorManager
from pulse.parser import parse_evtx
from pulse.reporter import (
    _build_html_report, _build_json_report, _calculate_score,
    calculate_score_from_findings,
)
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
    if db_path is None:
        db_path = "pulse.db"

    if config_path is None:
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "pulse.yaml",
        )

    # Make sure the database has its tables before any request comes in.
    init_db(db_path)

    app = FastAPI(
        title="Pulse API",
        description="REST API for the Pulse Windows event log analyzer.",
        version=__version__,
    )

    # Attach config so route handlers can reach it without globals.
    app.state.db_path = db_path
    app.state.config_path = config_path
    app.state.auth_required = not disable_auth

    # Resolve (and if needed, generate + persist) the session signing secret
    # so every logged-in browser cookie can be verified on future requests.
    if app.state.auth_required:
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
        return await call_next(request)

    return app


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _register_routes(app: FastAPI) -> None:
    """Wire every endpoint onto the app."""

    # Path to the dashboard HTML file (relative to this module).
    _web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
    _dashboard_path = os.path.join(_web_dir, "index.html")
    _login_path     = os.path.join(_web_dir, "login.html")

    # -------------------------------------------------------------------
    # GET / — Web dashboard (requires login)
    # -------------------------------------------------------------------
    @app.get("/", include_in_schema=False)
    def dashboard(request: Request):
        """Serve the dashboard, redirecting to /login if not signed in."""
        if app.state.auth_required:
            cookie = request.cookies.get(SESSION_COOKIE_NAME)
            from pulse.auth import verify_session_cookie
            user_id = verify_session_cookie(app.state.session_secret, cookie) if cookie else None
            if user_id is None:
                return RedirectResponse(url="/login", status_code=302)
        return FileResponse(_dashboard_path, media_type="text/html")

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
            return {"logged_in": True, "email": "local", "needs_signup": False}
        needs_signup = count_users(app.state.db_path) == 0
        cookie = request.cookies.get(SESSION_COOKIE_NAME)
        from pulse.auth import verify_session_cookie
        user_id = verify_session_cookie(app.state.session_secret, cookie) if cookie else None
        if user_id:
            user = get_user_by_id(app.state.db_path, user_id)
            if user:
                return {"logged_in": True, "email": user["email"], "needs_signup": False}
        return {"logged_in": False, "email": None, "needs_signup": needs_signup}

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
    # GET /api/health
    # -------------------------------------------------------------------
    @app.get("/api/health")
    def health():
        """Simple aliveness check. Returns version info."""
        return {"status": "ok", "version": __version__}

    # -------------------------------------------------------------------
    # POST /api/scan
    # -------------------------------------------------------------------
    @app.post("/api/scan")
    async def scan(file: UploadFile = File(...)):
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

        # Write the upload to a temp file so the parser (which expects a
        # path, not a stream) can read it. delete=False lets us close the
        # handle on Windows before re-opening it for parsing.
        suffix = ".evtx"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        try:
            contents = await file.read()
            tmp.write(contents)
            tmp.close()

            events = parse_evtx(tmp.name)
            findings = run_all_detections(events)

            # Apply whitelist so the API gives the same answers as the CLI.
            findings = _filter_with_whitelist(findings, app.state.config_path)

            score_data = calculate_score_from_findings(findings)

            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in findings:
                sev = f.get("severity", "LOW")
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            scan_stats = {
                "total_events": len(events),
                "files_scanned": 1,
            }
            scan_id = save_scan(
                app.state.db_path,
                findings,
                scan_stats=scan_stats,
                score=score_data["score"],
                score_label=score_data["label"],
                filename=file.filename,
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
    def history(limit: int = 20):
        """Return the most recent scans stored in the local database."""
        if limit < 1 or limit > 200:
            raise HTTPException(
                status_code=400,
                detail="limit must be between 1 and 200.",
            )
        return {"scans": get_history(app.state.db_path, limit=limit)}

    # -------------------------------------------------------------------
    # DELETE /api/scans — delete one or many scans (+ cascading findings)
    # -------------------------------------------------------------------
    @app.delete("/api/scans")
    def delete_scans_endpoint(payload: dict = Body(...)):
        ids = payload.get("ids") if isinstance(payload, dict) else None
        if not isinstance(ids, list) or not ids:
            raise HTTPException(400, detail="Body must be {\"ids\": [...]}")
        try:
            ids_int = [int(i) for i in ids]
        except (TypeError, ValueError):
            raise HTTPException(400, detail="All ids must be integers.")
        deleted = delete_scans(app.state.db_path, ids_int)
        return {"deleted": deleted}

    # -------------------------------------------------------------------
    # GET /api/report/{scan_id}
    # -------------------------------------------------------------------
    @app.get("/api/report/{scan_id}")
    def report(scan_id: int, format: str = "json"):
        """Return every finding recorded for a specific past scan.

        When ?format=pdf, a binary PDF is returned as an attachment so the
        dashboard can offer a one-click PDF download.
        """
        findings = get_scan_findings(app.state.db_path, scan_id)
        # Distinguish "scan exists but zero findings" from "scan not found"
        # by checking the scans table.
        history_rows = get_history(app.state.db_path, limit=200)
        scan_row = next((s for s in history_rows if s["id"] == scan_id), None)
        if not findings and scan_row is None:
            raise HTTPException(
                status_code=404,
                detail=f"Scan {scan_id} not found.",
            )

        decorated = attach_remediation(findings)

        if format == "pdf":
            from pulse.pdf_report import build_pdf
            pdf_bytes = build_pdf(decorated, scan_meta=scan_row)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="pulse_scan_{scan_id}.pdf"'
                },
            )

        return {"scan_id": scan_id, "findings": decorated}

    # -------------------------------------------------------------------
    # PUT /api/finding/{id}/review — mark a finding reviewed / FP / new
    # -------------------------------------------------------------------
    @app.put("/api/finding/{finding_id}/review")
    def review_finding(finding_id: int, payload: dict = Body(...)):
        """Update the review status of a single finding. Body:
           {"status": "reviewed"|"false_positive"|"new", "note": "..."}"""
        status = (payload or {}).get("status")
        if status not in REVIEW_STATUSES:
            raise HTTPException(
                400,
                detail=f"status must be one of {list(REVIEW_STATUSES)}",
            )
        note = (payload or {}).get("note")
        updated = set_finding_review(app.state.db_path, finding_id, status, note)
        if updated is None:
            raise HTTPException(404, detail=f"Finding {finding_id} not found.")
        return updated

    # -------------------------------------------------------------------
    # GET /api/score/daily — aggregated daily scores
    # -------------------------------------------------------------------
    @app.get("/api/score/daily")
    def daily_scores(days: int = 30):
        """Return deduplicated daily scores combining all scans per day."""
        if days < 1 or days > 365:
            raise HTTPException(400, detail="days must be between 1 and 365.")

        all_scans = get_history(app.state.db_path, limit=200)

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
                findings = get_scan_findings(app.state.db_path, scan["id"])
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
    def compare_scans(a: int, b: int):
        """Return the new / resolved / shared findings between two scans."""
        if a == b:
            raise HTTPException(400, detail="a and b must be different scans.")

        history_rows = get_history(app.state.db_path, limit=200)
        scan_a = next((s for s in history_rows if s["id"] == a), None)
        scan_b = next((s for s in history_rows if s["id"] == b), None)
        if scan_a is None:
            raise HTTPException(404, detail=f"Scan {a} not found.")
        if scan_b is None:
            raise HTTPException(404, detail=f"Scan {b} not found.")

        from pulse.comparison import diff_findings
        findings_a = get_scan_findings(app.state.db_path, a)
        findings_b = get_scan_findings(app.state.db_path, b)
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
    def export_report(scan_id: int, format: str = "html"):
        """Download a formatted report for a past scan (html | json | pdf)."""
        if format not in ("html", "json", "pdf"):
            raise HTTPException(400, detail="format must be 'html', 'json', or 'pdf'.")

        findings = get_scan_findings(app.state.db_path, scan_id)
        history_rows = get_history(app.state.db_path, limit=200)
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

        if format == "json":
            content = _build_json_report(findings, sev_counts, scan_stats)
            return Response(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=pulse_scan_{scan_id}.json"},
            )

        if format == "pdf":
            from pulse.pdf_report import build_pdf
            pdf_bytes = build_pdf(attach_remediation(findings), scan_meta=scan_row)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="pulse_scan_{scan_id}.pdf"'},
            )

        content = _build_html_report(findings, sev_counts, scan_stats)
        return HTMLResponse(
            content=content,
            headers={"Content-Disposition": f"attachment; filename=pulse_scan_{scan_id}.html"},
        )

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
        from pulse.emailer import send_alert

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
        from pulse.webhook import send_webhook

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
        from pulse.known_good import KNOWN_GOOD_SERVICES
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
    return sorted([
        "Brute Force Attempt", "User Account Created", "Privilege Escalation",
        "Audit Log Cleared", "RDP Logon Detected", "Pass-the-Hash Attempt",
        "Service Installed", "Antivirus Disabled", "Firewall Disabled",
        "Firewall Rule Changed", "Account Lockout", "Scheduled Task Created",
        "Suspicious PowerShell", "Account Takeover Chain", "Malware Persistence Chain",
        "Kerberoasting", "Golden Ticket", "Credential Dumping",
        "Logon from Disabled Account", "After-Hours Logon",
        "Suspicious Registry Modification", "Lateral Movement via Network Share",
    ])


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
