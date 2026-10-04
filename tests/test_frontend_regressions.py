# tests/test_frontend_regressions.py
# -----------------------------------
# The frontend is plain ES modules with no JS test runner, so these are
# source-level guards for two fixed UI bugs. They read the shipped JS and
# assert the corrected pattern is present and the buggy one is gone, so a
# future edit that reintroduces either bug fails the Python suite.
#
#   Bug 1 — Settings > Appearance: toggling the theme kicked you back to the
#           Profile tab. Root cause: the theme toggle re-renders via a bare
#           navigate('settings'), and navigation.js forced the tab to
#           'profile' whenever no tab was passed.
#   Bug 2 — Fleet "Generate Incident Report for this host" silently did
#           nothing. Root cause: generateIncidentReportForHost called the
#           async openGenerateReportModal WITHOUT returning its promise, so
#           fleet.js's .catch never saw async failures (unhandled rejection).

from pathlib import Path

JS_DIR = Path(__file__).resolve().parent.parent / "pulse" / "static" / "js"


def _read(name: str) -> str:
    return (JS_DIR / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Bug 1 — theme toggle must not reset the active settings tab
# ---------------------------------------------------------------------------

def test_navigate_settings_preserves_current_tab():
    """A bare navigate('settings') (fired by the Appearance theme toggle)
    must KEEP the current tab, not snap back to Profile."""
    src = _read("navigation.js")

    # The buggy line forced 'profile' on every tab-less settings navigation.
    assert "setActiveSettingsTab(settingsTab || 'profile')" not in src, (
        "navigation.js still forces the Profile tab on a bare "
        "navigate('settings') — this reintroduces the theme-toggle tab reset."
    )
    # The fix only sets the tab when one is explicitly provided.
    assert "if (settingsTab) setActiveSettingsTab(settingsTab)" in src, (
        "navigation.js is missing the guarded setActiveSettingsTab that "
        "preserves the current tab when no tab is passed."
    )


def test_set_active_settings_tab_ignores_invalid_names():
    """The guard above relies on setActiveSettingsTab being a no-op for
    empty/invalid names (so an omitted tab leaves the current one intact)."""
    src = _read("settings.js")
    assert "export function setActiveSettingsTab(name)" in src
    # It only assigns when the name matches a known tab id.
    assert "SETTINGS_TABS.some(function (t) { return t.id === name; })" in src


# ---------------------------------------------------------------------------
# Bug 2 — Fleet incident-report button must surface failures, not swallow them
# ---------------------------------------------------------------------------

def test_incident_report_entrypoints_return_the_modal_promise():
    """generateIncidentReportForHost / ...ForFindings must RETURN the
    openGenerateReportModal promise so a caller's .catch (fleet.js) can
    surface async failures instead of the button silently doing nothing."""
    src = _read("reports.js")
    assert (
        "return openGenerateReportModal('incident_investigation', { host: host })"
        in src
    ), (
        "generateIncidentReportForHost no longer returns the modal promise — "
        "async failures would again become silent unhandled rejections."
    )
    assert (
        "return openGenerateReportModal('incident_investigation', { finding_ids: ids })"
        in src
    ), "generateIncidentReportForFindings no longer returns the modal promise."


def test_fleet_incident_path_surfaces_errors():
    """fleet.js must keep its .catch that toasts + logs, so a rejected
    modal promise reaches the user instead of failing silently."""
    src = _read("fleet.js")
    assert "generateIncidentReportForHost" in src
    assert ".catch(" in src and "toastError(" in src, (
        "fleet.js's incident-report path lost its error surfacing (.catch + "
        "toastError), which combined with the promise fix keeps it non-silent."
    )


# ---------------------------------------------------------------------------
# Bug 3 — deep links to some pages 404'd on refresh
# ---------------------------------------------------------------------------
# The server only serves the SPA at paths listed in api._SPA_PAGES. Team,
# Security Advisor and Threat Intel were in navigation.js but not there, so
# refreshing those pages (or opening a link to them) returned
# {"detail":"Not Found"}. Every client page must have a server route.

def test_every_spa_page_has_a_server_route(tmp_path):
    import re
    from fastapi.testclient import TestClient
    from pulse.api import create_app

    src = _read("navigation.js")
    m = re.search(r"export const validPages = \[(.*?)\];", src)
    pages = re.findall(r"'([a-z]+)'", m.group(1))
    assert "automations" in pages

    cfg = tmp_path / "pulse.yaml"
    cfg.write_text("whitelist:\n  accounts: []\n")
    app = create_app(db_path=str(tmp_path / "t.db"), config_path=str(cfg),
                     disable_auth=True)
    client = TestClient(app)
    missing = [p for p in pages if client.get("/" + p).status_code == 404]
    assert missing == [], f"no server route for SPA page(s): {missing}"


# ---------------------------------------------------------------------------
# Upload / system scan: stay on the Dashboard with fresh data
# ---------------------------------------------------------------------------

def _scan_done_tail(src, marker):
    """The success branch of a scan handler, from its cache invalidation on."""
    start = src.index(marker)
    return src[start:start + 900]


def test_upload_lands_on_the_dashboard_with_fresh_data():
    """After an uploaded log finishes scanning the user stays on (or lands
    on) the Dashboard, not History, and the caches are dropped first so
    the new scan's score and findings render right away."""
    tail = _scan_done_tail(_read("upload.js"), "invalidateScansCache();\n  invalidateFindingsCache();")
    assert "navigate('dashboard')" in tail
    assert "navigate('history')" not in _read("upload.js")


def test_system_scan_refreshes_the_page_without_redirecting():
    """"Scan my system" re-renders the page the user is on (fresh data)
    and never sends them to History."""
    src = _read("system-scan.js")
    tail = _scan_done_tail(src, "invalidateScansCache();\n    invalidateFindingsCache();")
    assert "navigate(getCurrentPage())" in tail
    assert "navigate('history')" not in src


# ---------------------------------------------------------------------------
# Settings: Notifications = Pulse's own alerting; Integrations = outside services
# ---------------------------------------------------------------------------

def _panel(src, key):
    """The expression a Settings tab panel is composed from (up to the next key)."""
    start = src.index("    " + key + ":")
    nxt = re.search(r"\n    [a-z]+:\s", src[start + 5:])
    return src[start:start + 5 + nxt.start()] if nxt else src[start:]


import re  # noqa: E402


def test_integrations_tab_sits_in_configuration():
    src = _read("settings.js")
    assert re.search(r"\{ id: 'integrations',\s*label: 'Integrations',.*group: 'CONFIGURATION' \}", src)


def test_notifications_holds_only_pulse_alerting():
    notif = _panel(_read("settings.js"), "notifications")
    for part in ("thresholdAlertsHtml", "liveMonitorEmailsHtml", "weeklyBriefHtml"):
        assert part in notif
    for moved in ("webhookHtml", "threatIntelHtml", "_responseConnectorsHtml"):
        assert moved not in notif, moved


def test_integrations_groups_the_outside_services():
    src = _read("settings.js")
    integ = _panel(src, "integrations")
    order = [integ.index(x) for x in (
        "'Alert webhook'", "webhookHtml",
        "'Threat intelligence keys'", "threatIntelHtml",
        "'Playbook connectors'", "_responseConnectorsHtml")]
    assert order == sorted(order), "sections out of order"
    # The moved cards keep their save/test actions, still wired in app.js.
    app = _read("app.js")
    for action in ("saveWebhookSettings", "sendTestWebhook", "saveThreatIntelSettings",
                   "testThreatIntelKey", "saveTicketingSettings",
                   "saveOutboundWebhookSettings", "testResponseConnector"):
        assert 'data-action="%s"' % action in src, action
        assert re.search(r"\b%s\b" % action, app), action


def test_key_and_connector_links_open_integrations():
    for name in ("automations.js", "findings.js", "threat-intel.js"):
        src = _read(name)
        assert 'data-arg="settings:notifications"' not in src, name
        assert 'data-arg="settings:integrations"' in src, name
