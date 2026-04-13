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
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse

from pulse import __version__
from pulse.database import get_history, get_scan_findings, init_db, save_scan
from pulse.detections import run_all_detections
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

def create_app(db_path: Optional[str] = None, config_path: Optional[str] = None) -> FastAPI:
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

    # Live monitor — one MonitorManager per app. It owns the async polling
    # loop and fans out findings to SSE subscribers. Lazy: doesn't start
    # polling until POST /api/monitor/start is called.
    app.state.monitor = MonitorManager(
        db_path=db_path,
        config_path=config_path,
        config_getter=lambda: _read_config(config_path),
    )

    _register_routes(app)
    return app


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _register_routes(app: FastAPI) -> None:
    """Wire every endpoint onto the app."""

    # Path to the dashboard HTML file (relative to this module).
    _dashboard_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "web", "index.html"
    )

    # -------------------------------------------------------------------
    # GET / — Web dashboard
    # -------------------------------------------------------------------
    @app.get("/", include_in_schema=False)
    def dashboard():
        """Serve the single-page web dashboard."""
        return FileResponse(_dashboard_path, media_type="text/html")

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

            return {
                "scan_id": scan_id,
                "filename": file.filename,
                "total_events": len(events),
                "total_findings": len(findings),
                "score": score_data["score"],
                "score_label": score_data["label"],
                "grade": score_data["grade"],
                "severity_counts": sev_counts,
                "findings": findings,
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
    # GET /api/report/{scan_id}
    # -------------------------------------------------------------------
    @app.get("/api/report/{scan_id}")
    def report(scan_id: int):
        """Return every finding recorded for a specific past scan."""
        findings = get_scan_findings(app.state.db_path, scan_id)
        if not findings:
            # Could be a bad ID, or a scan with zero findings. Distinguish
            # by checking the scans table — if no row exists, 404.
            history_rows = get_history(app.state.db_path, limit=200)
            if not any(s["id"] == scan_id for s in history_rows):
                raise HTTPException(
                    status_code=404,
                    detail=f"Scan {scan_id} not found.",
                )
        return {"scan_id": scan_id, "findings": findings}

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
    # GET /api/export/{scan_id} — download report as HTML or JSON
    # -------------------------------------------------------------------
    @app.get("/api/export/{scan_id}")
    def export_report(scan_id: int, format: str = "html"):
        """Download a formatted report for a past scan."""
        if format not in ("html", "json"):
            raise HTTPException(400, detail="format must be 'html' or 'json'.")

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
