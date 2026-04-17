# test_api.py
# -----------
# Tests for the Pulse REST API in pulse/api.py.
#
# HOW THESE TESTS WORK:
# FastAPI ships a TestClient that lets us call endpoints without starting
# a real HTTP server. We build a fresh app with a temporary SQLite database
# for each test so nothing persists between runs.
#
# We don't have real .evtx files lying around, so for /api/scan we build
# one on the fly using python-evtx? No — python-evtx only reads, not writes.
# Instead we test the scan endpoint with a file that's deliberately not
# a valid .evtx (the parser returns [] for unreadable files) and check
# the API still returns a well-formed response. Edge cases around
# bad uploads (wrong extension, empty body) are tested directly.
#
# RUN:
#   python -m pytest test_api.py -v


import io
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    """Fresh app + isolated database for each test.

    `disable_auth=True` keeps the existing tests simple — auth is covered
    by test_auth.py. Without this flag every /api/* call would 401.
    """
    db_path = tmp_path / "test.db"
    config_path = tmp_path / "pulse.yaml"
    # Write a minimal config so the whitelist loader has something to read.
    config_path.write_text("whitelist:\n  accounts: []\n")

    app = create_app(db_path=str(db_path), config_path=str(config_path), disable_auth=True)
    return TestClient(app)


# ---------------------------------------------------------------------------
# /api/health
# ---------------------------------------------------------------------------

def test_health_returns_ok(client):
    """The health endpoint should always report status=ok."""
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"


def test_health_includes_version(client):
    """Health should report the Pulse version so clients know what they're talking to."""
    response = client.get("/api/health")
    body = response.json()
    assert "version" in body
    # Version should be a non-empty string like "1.1.0"
    assert isinstance(body["version"], str)
    assert len(body["version"]) > 0


# ---------------------------------------------------------------------------
# /api/scan
# ---------------------------------------------------------------------------

def test_scan_rejects_wrong_extension(client):
    """Uploading a .txt file should be refused with 400."""
    response = client.post(
        "/api/scan",
        files={"file": ("notes.txt", b"this is not an evtx file", "text/plain")},
    )
    assert response.status_code == 400
    assert "evtx" in response.json()["detail"].lower()


def test_scan_rejects_missing_file(client):
    """No file at all should fail with a 422 (FastAPI's default for missing body)."""
    response = client.post("/api/scan")
    assert response.status_code == 422


_EVTX_HEADER = b"ElfFile\x00"  # matches _EVTX_MAGIC in pulse/api.py


def test_scan_rejects_evtx_extension_with_wrong_magic(client):
    """A .evtx extension alone is not enough — the header must match too,
    so renamed junk never reaches the parser."""
    response = client.post(
        "/api/scan",
        files={"file": ("fake.evtx", b"not really an evtx file", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "evtx" in response.json()["detail"].lower()


def test_scan_accepts_valid_evtx_header(client):
    """A file with the ElfFile magic header is accepted. The parser returns
    an empty event list for truncated bodies, so we get a well-formed scan
    with zero findings."""
    response = client.post(
        "/api/scan",
        files={"file": ("fake.evtx", _EVTX_HEADER + b"\x00" * 100, "application/octet-stream")},
    )
    assert response.status_code == 200
    body = response.json()
    assert "scan_id" in body
    assert "findings" in body
    assert "score" in body
    assert body["filename"] == "fake.evtx"


def test_scan_rejects_oversize_upload(client):
    """Uploads larger than the 500 MB guard should be refused with 413.
    We don't actually send 500 MB — we patch the guard to a tiny value for
    the test and send a body just over that limit."""
    import pulse.api as api_mod
    original = api_mod._UPLOAD_MAX_BYTES
    api_mod._UPLOAD_MAX_BYTES = 1024  # 1 KB
    try:
        response = client.post(
            "/api/scan",
            files={"file": ("big.evtx", _EVTX_HEADER + b"\x00" * 4096, "application/octet-stream")},
        )
        assert response.status_code == 413
        assert "limit" in response.json()["detail"].lower()
    finally:
        api_mod._UPLOAD_MAX_BYTES = original


def test_scan_result_has_expected_shape(client):
    """Every scan response should include the standard fields so clients can rely on them."""
    response = client.post(
        "/api/scan",
        files={"file": ("x.evtx", _EVTX_HEADER, "application/octet-stream")},
    )
    body = response.json()
    for field in ("scan_id", "filename", "total_events", "total_findings",
                  "score", "score_label", "severity_counts", "findings"):
        assert field in body, f"missing field: {field}"

    # severity_counts should always have all four buckets
    assert set(body["severity_counts"].keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ---------------------------------------------------------------------------
# /api/history
# ---------------------------------------------------------------------------

def test_history_empty_when_no_scans(client):
    """A fresh database has no scans — history should return an empty list."""
    response = client.get("/api/history")
    assert response.status_code == 200
    assert response.json() == {"scans": []}


def test_history_returns_scans_after_scanning(client):
    """After one scan, /api/history should return one entry."""
    client.post("/api/scan", files={"file": ("a.evtx", _EVTX_HEADER, "application/octet-stream")})
    response = client.get("/api/history")
    scans = response.json()["scans"]
    assert len(scans) == 1
    assert scans[0]["files_scanned"] == 1


def test_history_newest_first(client):
    """Multiple scans should be returned newest-first (highest id first)."""
    client.post("/api/scan", files={"file": ("a.evtx", _EVTX_HEADER, "application/octet-stream")})
    client.post("/api/scan", files={"file": ("b.evtx", _EVTX_HEADER, "application/octet-stream")})
    client.post("/api/scan", files={"file": ("c.evtx", _EVTX_HEADER, "application/octet-stream")})

    scans = client.get("/api/history").json()["scans"]
    assert len(scans) == 3
    ids = [s["id"] for s in scans]
    assert ids == sorted(ids, reverse=True)


def test_history_respects_limit(client):
    """The ?limit= query parameter should cap the returned list."""
    for _ in range(5):
        client.post("/api/scan", files={"file": ("x.evtx", _EVTX_HEADER, "application/octet-stream")})

    scans = client.get("/api/history?limit=2").json()["scans"]
    assert len(scans) == 2


def test_delete_scans_removes_rows_and_cascades_findings(client):
    """DELETE /api/scans removes the selected scans and their findings."""
    for name in ("a.evtx", "b.evtx", "c.evtx"):
        client.post("/api/scan", files={"file": (name, _EVTX_HEADER, "application/octet-stream")})

    scans = client.get("/api/history").json()["scans"]
    assert len(scans) == 3
    ids_to_delete = [scans[0]["id"], scans[2]["id"]]

    resp = client.request("DELETE", "/api/scans", json={"ids": ids_to_delete})
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 2

    remaining = client.get("/api/history").json()["scans"]
    assert [s["id"] for s in remaining] == [scans[1]["id"]]


def test_delete_scans_rejects_empty_or_bad_body(client):
    assert client.request("DELETE", "/api/scans", json={}).status_code == 400
    assert client.request("DELETE", "/api/scans", json={"ids": []}).status_code == 400
    assert client.request("DELETE", "/api/scans", json={"ids": ["not-a-number"]}).status_code == 400


def test_history_rejects_bad_limit(client):
    """Limit outside [1, 200] should be rejected with 400."""
    assert client.get("/api/history?limit=0").status_code == 400
    assert client.get("/api/history?limit=9999").status_code == 400


# ---------------------------------------------------------------------------
# /api/report/{scan_id}
# ---------------------------------------------------------------------------

def test_report_not_found(client):
    """Requesting a non-existent scan ID should 404."""
    response = client.get("/api/report/9999")
    assert response.status_code == 404


def test_report_returns_findings_for_existing_scan(client):
    """A valid scan ID should return that scan's findings list (possibly empty)."""
    scan_response = client.post(
        "/api/scan",
        files={"file": ("x.evtx", _EVTX_HEADER, "application/octet-stream")},
    )
    scan_id = scan_response.json()["scan_id"]

    response = client.get(f"/api/report/{scan_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == scan_id
    assert "findings" in body
    assert isinstance(body["findings"], list)


# ---------------------------------------------------------------------------
# Temp file cleanup
# ---------------------------------------------------------------------------

def test_scan_cleans_up_temp_file(client):
    """The temp file created during /api/scan should not linger on disk afterwards."""
    tmp_dir_before = set(os.listdir(tempfile.gettempdir()))
    client.post("/api/scan", files={"file": ("x.evtx", _EVTX_HEADER, "application/octet-stream")})
    tmp_dir_after = set(os.listdir(tempfile.gettempdir()))

    # No new .evtx temp files left behind.
    new_files = tmp_dir_after - tmp_dir_before
    leftover_evtx = [f for f in new_files if f.endswith(".evtx")]
    assert leftover_evtx == []


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def test_dashboard_returns_html(client):
    """The root route should serve the web dashboard as HTML."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "PULSE" in response.text


# ---------------------------------------------------------------------------
# /api/config — email + alerts sections
# ---------------------------------------------------------------------------

def test_config_includes_email_and_alerts_sections(client):
    """GET /api/config should always return email and alerts blocks for the dashboard."""
    body = client.get("/api/config").json()
    assert "email" in body
    assert "alerts" in body
    # Email defaults: password should never be returned, only password_set bool.
    assert "password" not in body["email"]
    assert "password_set" in body["email"]
    # Alerts defaults
    assert body["alerts"]["enabled"] is False
    assert body["alerts"]["threshold"] == "HIGH"


def test_config_password_never_leaks(client, tmp_path):
    """Even when a password is set in pulse.yaml, GET /api/config must mask it."""
    config_path = tmp_path / "pulse.yaml"
    config_path.write_text(
        "email:\n"
        "  smtp_host: smtp.example.com\n"
        "  smtp_port: 587\n"
        "  sender: a@example.com\n"
        "  recipient: b@example.com\n"
        "  password: SuperSecret123\n"
    )
    db_path = tmp_path / "test.db"
    from pulse.api import create_app
    from fastapi.testclient import TestClient
    fresh = TestClient(create_app(db_path=str(db_path), config_path=str(config_path), disable_auth=True))

    body = fresh.get("/api/config").json()
    assert body["email"]["password_set"] is True
    # The literal secret must not appear anywhere in the response payload.
    assert "SuperSecret123" not in fresh.get("/api/config").text


# ---------------------------------------------------------------------------
# PUT /api/config/email
# ---------------------------------------------------------------------------

def test_put_email_persists_fields(client):
    """PUT /api/config/email should write back to pulse.yaml so subsequent reads see it."""
    payload = {
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "sender":    "alerts@me.com",
        "recipient": "ops@me.com",
        "password":  "newpass",
    }
    r = client.put("/api/config/email", json=payload)
    assert r.status_code == 200
    assert r.json()["password_set"] is True

    body = client.get("/api/config").json()
    assert body["email"]["smtp_host"] == "smtp.gmail.com"
    assert body["email"]["sender"]    == "alerts@me.com"
    assert body["email"]["password_set"] is True


def test_put_email_keeps_password_when_blank(client):
    """Saving with an empty password should NOT clear the existing one."""
    client.put("/api/config/email", json={
        "smtp_host": "smtp.x.com", "smtp_port": 587,
        "sender": "a@x.com", "recipient": "b@x.com",
        "password": "first-pass",
    })
    # Re-save without password — the original should survive.
    client.put("/api/config/email", json={"sender": "c@x.com", "password": ""})
    body = client.get("/api/config").json()
    assert body["email"]["sender"] == "c@x.com"
    assert body["email"]["password_set"] is True


def test_put_email_rejects_bad_port(client):
    r = client.put("/api/config/email", json={"smtp_port": "not a number"})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# PUT /api/config/alerts
# ---------------------------------------------------------------------------

def test_put_alerts_persists_fields(client):
    payload = {
        "enabled": True,
        "threshold": "CRITICAL",
        "recipient": "soc@me.com",
        "cooldown_minutes": 30,
    }
    r = client.put("/api/config/alerts", json=payload)
    assert r.status_code == 200

    body = client.get("/api/config").json()
    assert body["alerts"]["enabled"] is True
    assert body["alerts"]["threshold"] == "CRITICAL"
    assert body["alerts"]["recipient"] == "soc@me.com"
    assert body["alerts"]["cooldown_minutes"] == 30


def test_put_alerts_threshold_validation(client):
    r = client.put("/api/config/alerts", json={"threshold": "BANANA"})
    assert r.status_code == 400


def test_put_alerts_cooldown_validation(client):
    r = client.put("/api/config/alerts", json={"cooldown_minutes": -5})
    assert r.status_code == 400


def test_put_alerts_threshold_is_uppercased(client):
    """Lowercase threshold values should be normalised to uppercase."""
    r = client.put("/api/config/alerts", json={"threshold": "high"})
    assert r.status_code == 200
    body = client.get("/api/config").json()
    assert body["alerts"]["threshold"] == "HIGH"


def test_put_alerts_persists_monitor_fields(client):
    r = client.put("/api/config/alerts", json={
        "monitor_enabled": True,
        "monitor_interval_minutes": 15,
    })
    assert r.status_code == 200
    body = client.get("/api/config").json()
    assert body["alerts"]["monitor_enabled"] is True
    assert body["alerts"]["monitor_interval_minutes"] == 15


def test_put_alerts_monitor_interval_validation(client):
    r = client.put("/api/config/alerts", json={"monitor_interval_minutes": 0})
    assert r.status_code == 400


def test_config_defaults_include_monitor_fields(client):
    body = client.get("/api/config").json()
    assert "monitor_enabled" in body["alerts"]
    assert "monitor_interval_minutes" in body["alerts"]


# ---------------------------------------------------------------------------
# POST /api/alerts/test
# ---------------------------------------------------------------------------

def test_alerts_test_requires_password(client):
    """Without an SMTP password configured, the test endpoint should refuse."""
    r = client.post("/api/alerts/test")
    assert r.status_code == 400
    assert "password" in r.json()["detail"].lower()


def test_alerts_test_requires_recipient(client):
    """A configured password but no recipient anywhere should also refuse."""
    client.put("/api/config/email", json={
        "smtp_host": "smtp.x.com", "smtp_port": 587,
        "sender": "a@x.com", "recipient": "",
        "password": "p",
    })
    r = client.post("/api/alerts/test")
    assert r.status_code == 400
    assert "recipient" in r.json()["detail"].lower()


def test_alerts_test_calls_send_alert_when_configured(client, monkeypatch):
    """When config is valid, the endpoint should invoke send_alert and return success."""
    client.put("/api/config/email", json={
        "smtp_host": "smtp.x.com", "smtp_port": 587,
        "sender": "a@x.com", "recipient": "b@x.com",
        "password": "p",
    })

    captured = {}

    def fake_send_alert(email_cfg, alerts_cfg, findings, *a, **kw):
        captured["email_cfg"] = email_cfg
        captured["findings"]  = findings
        return True

    # Patch where api.py imports it (inside the endpoint, late import).
    monkeypatch.setattr("pulse.emailer.send_alert", fake_send_alert)

    r = client.post("/api/alerts/test")
    assert r.status_code == 200
    assert r.json()["status"] == "sent"
    assert captured["findings"][0]["rule"] == "Pulse Test Alert"
    assert captured["findings"][0]["severity"] == "CRITICAL"


def test_alerts_test_returns_502_when_smtp_fails(client, monkeypatch):
    """If send_alert returns False, the endpoint should bubble up a 502."""
    client.put("/api/config/email", json={
        "smtp_host": "smtp.x.com", "smtp_port": 587,
        "sender": "a@x.com", "recipient": "b@x.com",
        "password": "p",
    })
    monkeypatch.setattr("pulse.emailer.send_alert", lambda *a, **kw: False)
    r = client.post("/api/alerts/test")
    assert r.status_code == 502


# ---------------------------------------------------------------------------
# /api/config — webhook section
# ---------------------------------------------------------------------------

def test_config_includes_webhook_section(client):
    body = client.get("/api/config").json()
    assert "webhook" in body
    # Secret URL must never come back to the browser — only a boolean.
    assert "url" not in body["webhook"]
    assert "url_set" in body["webhook"]
    assert body["webhook"]["enabled"] is False
    assert body["webhook"]["url_set"] is False


def test_put_webhook_persists_fields(client):
    r = client.put("/api/config/webhook", json={
        "enabled": True,
        "flavor":  "slack",
        "url":     "https://hooks.slack.com/services/T/B/abc",
    })
    assert r.status_code == 200
    assert r.json()["url_set"] is True

    body = client.get("/api/config").json()
    assert body["webhook"]["enabled"] is True
    assert body["webhook"]["flavor"] == "slack"
    assert body["webhook"]["url_set"] is True


def test_put_webhook_keeps_url_when_blank(client):
    """Resaving with an empty url should NOT clear the stored URL."""
    client.put("/api/config/webhook", json={
        "enabled": True, "flavor": "slack",
        "url": "https://hooks.slack.com/services/T/B/abc",
    })
    client.put("/api/config/webhook", json={"enabled": False, "url": ""})
    body = client.get("/api/config").json()
    assert body["webhook"]["enabled"] is False
    assert body["webhook"]["url_set"] is True  # URL still on file


def test_put_webhook_rejects_bad_flavor(client):
    r = client.put("/api/config/webhook", json={"flavor": "teams"})
    assert r.status_code == 400


def test_put_webhook_rejects_non_http_url(client):
    r = client.put("/api/config/webhook", json={"url": "ftp://x/y"})
    assert r.status_code == 400


def test_webhook_test_requires_url(client):
    """Without a URL configured, the test endpoint should refuse."""
    r = client.post("/api/webhook/test")
    assert r.status_code == 400
    assert "url" in r.json()["detail"].lower()


def test_webhook_test_sends_when_configured(client, monkeypatch):
    client.put("/api/config/webhook", json={
        "enabled": False,   # test endpoint should bypass enabled flag
        "flavor":  "slack",
        "url":     "https://hooks.slack.com/services/T/B/abc",
    })

    captured = {}
    def fake_send_webhook(cfg, findings, **kw):
        captured["cfg"] = cfg
        captured["findings"] = findings
        return True
    monkeypatch.setattr("pulse.webhook.send_webhook", fake_send_webhook)

    r = client.post("/api/webhook/test")
    assert r.status_code == 200
    assert r.json()["status"] == "sent"
    assert captured["findings"][0]["rule"] == "Pulse Test Alert"
    # Even though saved as disabled, the test call forces enabled=True.
    assert captured["cfg"]["enabled"] is True


def test_webhook_test_returns_502_when_post_fails(client, monkeypatch):
    client.put("/api/config/webhook", json={
        "enabled": True, "flavor": "slack",
        "url":     "https://hooks.slack.com/services/T/B/abc",
    })
    monkeypatch.setattr("pulse.webhook.send_webhook", lambda *a, **kw: False)
    r = client.post("/api/webhook/test")
    assert r.status_code == 502


# ---------------------------------------------------------------------------
# PUT /api/finding/{id}/review
# ---------------------------------------------------------------------------

def _seed_finding(client):
    """Save a scan with one finding; return its id."""
    from pulse.database import save_scan, get_scan_findings
    db = client.app.state.db_path
    save_scan(db, [{
        "severity": "HIGH", "rule": "Brute Force Attempt", "event_id": 4625,
        "timestamp": "2026-04-15T10:00:00", "mitre": "T1110",
        "description": "desc", "details": "5 failed logins",
    }])
    return get_scan_findings(db, 1)[0]["id"]


def test_review_marks_finding_reviewed(client):
    fid = _seed_finding(client)
    r = client.put(f"/api/finding/{fid}/review",
                   json={"status": "reviewed", "note": "benign scanner"})
    assert r.status_code == 200
    body = r.json()
    assert body["review_status"] == "reviewed"
    assert body["review_note"]   == "benign scanner"
    assert body["reviewed_at"] is not None


def test_review_marks_false_positive(client):
    fid = _seed_finding(client)
    r = client.put(f"/api/finding/{fid}/review", json={"status": "false_positive"})
    assert r.status_code == 200
    assert r.json()["review_status"] == "false_positive"


def test_review_reset_clears_note_and_timestamp(client):
    fid = _seed_finding(client)
    client.put(f"/api/finding/{fid}/review", json={"status": "reviewed", "note": "x"})
    r = client.put(f"/api/finding/{fid}/review", json={"status": "new"})
    assert r.status_code == 200
    body = r.json()
    assert body["review_status"] == "new"
    assert body["reviewed_at"]   is None
    assert body["review_note"]   is None


def test_review_rejects_unknown_status(client):
    fid = _seed_finding(client)
    r = client.put(f"/api/finding/{fid}/review", json={"status": "wrong"})
    assert r.status_code == 400


def test_review_returns_404_for_missing_finding(client):
    r = client.put("/api/finding/9999/review", json={"status": "reviewed"})
    assert r.status_code == 404


def test_report_endpoint_includes_review_fields(client):
    """The report endpoint is what the dashboard reads; the drawer needs
    review_status / review_note / reviewed_at / id on each finding."""
    _seed_finding(client)
    r = client.get("/api/report/1")
    assert r.status_code == 200
    findings = r.json()["findings"]
    assert findings[0]["id"] is not None
    assert findings[0]["review_status"] == "new"
    assert "review_note" in findings[0]
    assert "reviewed_at" in findings[0]


# ---------------------------------------------------------------------------
# Remediation steps attached to findings
# ---------------------------------------------------------------------------

def test_report_endpoint_includes_remediation_steps(client):
    """Each finding returned by /api/report must carry a non-empty
    remediation list so the dashboard drawer can render it without
    maintaining its own lookup table."""
    _seed_finding(client)
    r = client.get("/api/report/1")
    assert r.status_code == 200
    findings = r.json()["findings"]
    steps = findings[0].get("remediation")
    assert isinstance(steps, list) and len(steps) > 0
    # Brute Force Attempt is a known rule — should match canonical steps.
    from pulse.remediation import REMEDIATION
    assert steps == REMEDIATION["Brute Force Attempt"]


# ---------------------------------------------------------------------------
# PDF export
# ---------------------------------------------------------------------------

def test_export_pdf_returns_pdf_bytes(client):
    """/api/export/{id}?format=pdf returns an attachment with PDF MIME."""
    _seed_finding(client)
    r = client.get("/api/export/1?format=pdf")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/pdf")
    assert "attachment" in r.headers["content-disposition"]
    assert "pulse_scan_1.pdf" in r.headers["content-disposition"]
    # Every PDF begins with the %PDF- magic bytes; this is the cheapest
    # integrity check that reportlab actually produced a valid file.
    assert r.content[:5] == b"%PDF-"


def test_export_pdf_for_unknown_scan_returns_404(client):
    r = client.get("/api/export/999?format=pdf")
    assert r.status_code == 404


def test_export_rejects_unknown_format(client):
    _seed_finding(client)
    r = client.get("/api/export/1?format=xml")
    assert r.status_code == 400


def test_report_endpoint_supports_pdf_format(client):
    """Back-compat: /api/report/{id}?format=pdf should also work so older
    clients hitting that route get PDFs just like /api/export does."""
    _seed_finding(client)
    r = client.get("/api/report/1?format=pdf")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/pdf")
    assert r.content[:5] == b"%PDF-"


# ---------------------------------------------------------------------------
# /api/compare — diff two scans
# ---------------------------------------------------------------------------

def _seed_scan_with(client, findings):
    """Save a scan of the given findings, return its scan id."""
    from pulse.database import save_scan, get_history
    save_scan(client.app.state.db_path, findings)
    return get_history(client.app.state.db_path, limit=1)[0]["id"]


def test_compare_returns_new_resolved_shared(client):
    a_id = _seed_scan_with(client, [
        {"severity": "HIGH", "rule": "Brute Force Attempt", "event_id": 4625,
         "description": "10 failed logins for alice"},
        {"severity": "LOW", "rule": "RDP Logon Detected", "event_id": 4624,
         "description": "RDP from 10.0.0.5"},
    ])
    b_id = _seed_scan_with(client, [
        {"severity": "HIGH", "rule": "Brute Force Attempt", "event_id": 4625,
         "description": "10 failed logins for alice"},
        {"severity": "CRITICAL", "rule": "Golden Ticket", "event_id": 4768,
         "description": "Unusual TGT lifetime"},
    ])
    r = client.get(f"/api/compare?a={a_id}&b={b_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["scan_a"]["id"] == a_id
    assert body["scan_b"]["id"] == b_id
    assert len(body["new"])      == 1
    assert body["new"][0]["rule"] == "Golden Ticket"
    assert len(body["resolved"]) == 1
    assert body["resolved"][0]["rule"] == "RDP Logon Detected"
    assert len(body["shared"])   == 1
    assert body["shared"][0]["rule"] == "Brute Force Attempt"
    # Decorated with remediation.
    assert isinstance(body["new"][0].get("remediation"), list)


def test_compare_rejects_same_scan(client):
    a_id = _seed_scan_with(client, [
        {"severity": "HIGH", "rule": "Brute Force Attempt", "event_id": 4625,
         "description": "x"},
    ])
    r = client.get(f"/api/compare?a={a_id}&b={a_id}")
    assert r.status_code == 400


def test_compare_unknown_scan_returns_404(client):
    a_id = _seed_scan_with(client, [
        {"severity": "HIGH", "rule": "Brute Force Attempt", "event_id": 4625,
         "description": "x"},
    ])
    r = client.get(f"/api/compare?a={a_id}&b=999")
    assert r.status_code == 404
