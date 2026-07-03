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
