// app.js — the only entry point. Imports propagate to every other
// module, so index.html needs just one <script type="module"> tag.
// Owns the event-delegation action registry and DOMContentLoaded boot.
'use strict';

import { initTheme, toggleTheme, setThemeFromSelect } from './theme.js';
import { navigate, validPages } from './navigation.js';
import {
  openUploadModal,
  closeUploadModal,
  uploadAndScan,
  openTutorialModal,
  closeTutorialModal,
  switchTutorialTab,
  copyTutorialCmd,
} from './upload.js';
import {
  openSystemScanModal,
  closeSystemScanModal,
  runSystemScan,
} from './system-scan.js';
import {
  downloadReport,
  applyDashFilters,
  resetDashFilters,
  dashFilterQueryKey,
  openFindingDrawerByIdx,
  openAttentionFinding,
  clickStatCard,
} from './dashboard.js';
import {
  toggleScanSelect,
  toggleScanSelectAll,
  deleteSelectedScans,
  setScansSort,
  setScansQueryFromInput,
  setScansPageTab,
  viewScan,
  setFindingsSort,
  setFindingsFilter,
  setFindingsReviewFilter,
  setFindingsQueryFromInput,
  stopClickPropagation,
  viewScanFromLink,
  toggleFindingExpand,
  openFindingsPageDrawerByUid,
  closeFindingDrawer,
  openScanDetailFindingByIdx,
  markFindingReviewed,
  markFindingFalsePositive,
  openUnreviewedCriticalHigh,
} from './findings.js';
import { highlightHistoryScan, runHistoryCompare } from './history.js';
import { fleetOpenHost } from './fleet.js';
import {
  monitorClient,
  mountNavLiveIndicator,
  startMonitor,
  stopMonitor,
  sendMonitorTestAlert,
  updateMonIntervalLabel,
  toggleChannelDropdown,
  toggleChannelOption,
  toggleCustomChannelEnable,
  updateCustomChannels,
  openLiveFeedFinding,
  savePopoverInterval,
  toggleSessionExpand,
  openSessionFinding,
  deleteMonitorSession,
  clearMonitorSessions,
  toggleMonSettings,
  toggleMonGearDropdown,
  togglePollHistoryExpand,
  togglePollHistoryFilter,
} from './monitor.js';
import {
  toggleBuiltinWhitelist,
  setWhitelistAddType,
  whitelistAddValueKey,
  addWhitelistEntry,
  removeWhitelistRowBtn,
} from './whitelist.js';
import {
  saveAccount,
  signOut,
  onEmailProviderChange,
  saveEmailSettings,
  saveAlertSettings,
  sendTestAlert,
  saveWebhookSettings,
  sendTestWebhook,
  onScheduleKindChange,
  saveScheduleSettings,
  switchSettingsTab,
} from './settings.js';
import {
  setReportsQueryFromInput,
  deleteReport,
} from './reports.js';
import {
  toggleRuleEnabled,
} from './rules.js';
import {
  mountUserMenu,
  toggleUserMenu,
  openProfile,
  openAccountSettings,
  openDocs,
  openFeedback,
  logOutFromMenu,
  toggleDarkModeFromMenu,
} from './user-menu.js';

// Central action registry — replaces the old window[action] lookup.
// Every data-action / data-action-<event> string in the HTML or
// template strings must map to a function here.
const actions = {
  // theme + navigation
  navigate,
  toggleTheme,
  setThemeFromSelect,

  // upload + tutorial
  openUploadModal,
  closeUploadModal,
  uploadAndScan,
  openTutorialModal,
  closeTutorialModal,
  switchTutorialTab,
  copyTutorialCmd,

  // scan my system (additive — does not replace upload)
  openSystemScanModal,
  closeSystemScanModal,
  runSystemScan,

  // dashboard
  downloadReport,
  applyDashFilters,
  resetDashFilters,
  dashFilterQueryKey,
  openFindingDrawerByIdx,
  openAttentionFinding,
  clickStatCard,
  openUnreviewedCriticalHigh,

  // scans + findings
  toggleScanSelect,
  toggleScanSelectAll,
  deleteSelectedScans,
  setScansSort,
  setScansQueryFromInput,
  setScansPageTab,
  viewScan,
  setFindingsSort,
  setFindingsFilter,
  setFindingsReviewFilter,
  setFindingsQueryFromInput,
  stopClickPropagation,
  viewScanFromLink,
  toggleFindingExpand,
  openFindingsPageDrawerByUid,
  closeFindingDrawer,
  openScanDetailFindingByIdx,
  markFindingReviewed,
  markFindingFalsePositive,

  // history
  highlightHistoryScan,
  runHistoryCompare,

  // fleet
  fleetOpenHost,

  // monitor
  startMonitor,
  stopMonitor,
  sendMonitorTestAlert,
  updateMonIntervalLabel,
  toggleChannelDropdown,
  toggleChannelOption,
  toggleCustomChannelEnable,
  updateCustomChannels,
  openLiveFeedFinding,
  savePopoverInterval,
  toggleSessionExpand,
  openSessionFinding,
  deleteMonitorSession,
  clearMonitorSessions,
  toggleMonSettings,
  toggleMonGearDropdown,
  togglePollHistoryExpand,
  togglePollHistoryFilter,

  // whitelist
  toggleBuiltinWhitelist,
  setWhitelistAddType,
  whitelistAddValueKey,
  addWhitelistEntry,
  removeWhitelistRowBtn,

  // settings
  saveAccount,
  signOut,
  onEmailProviderChange,
  saveEmailSettings,
  saveAlertSettings,
  sendTestAlert,
  saveWebhookSettings,
  sendTestWebhook,
  onScheduleKindChange,
  saveScheduleSettings,
  switchSettingsTab,

  // reports
  setReportsQueryFromInput,
  deleteReport,

  // rules
  toggleRuleEnabled,

  // user menu
  toggleUserMenu,
  openProfile,
  openAccountSettings,
  openDocs,
  openFeedback,
  logOutFromMenu,
  toggleDarkModeFromMenu,

  // admin privilege banner
  dismissAdminBanner,
};

// Hide the banner for the rest of the session and persist the choice.
function dismissAdminBanner() {
  var el = document.getElementById('admin-banner');
  if (el) el.style.display = 'none';
  try { localStorage.setItem('pulseAdminBannerDismissed', '1'); } catch (e) {}
}

// Only show on Windows hosts where the process is not elevated. Hide
// unconditionally elsewhere so there's no flash on Linux/Mac.
async function _maybeShowAdminBanner() {
  var el = document.getElementById('admin-banner');
  if (!el) return;
  try {
    if (localStorage.getItem('pulseAdminBannerDismissed') === '1') return;
  } catch (e) { /* ignore — private mode blocks localStorage */ }
  try {
    var resp = await fetch('/api/health');
    if (!resp.ok) return;
    var info = await resp.json();
    if (info.platform_windows && !info.is_admin) {
      el.style.display = 'flex';
    }
  } catch (e) { /* health is best-effort */ }
}

// Event delegation. Any element with data-action="fnName" (or a per-event
// data-action-<evt>="fnName") gets routed to actions[fnName](arg, target, event).
// One delegator per event type covers click/change/input/submit/keydown/keyup.
// Template HTML rendered later via innerHTML is covered automatically.
function _installDelegator(eventName) {
  document.addEventListener(eventName, function (e) {
    var selector = eventName === 'click'
      ? '[data-action-click], [data-action]'
      : '[data-action-' + eventName + ']';
    var target = e.target.closest(selector);
    if (!target) return;
    // Per-event overrides beat the generic data-action. This lets a
    // single element bind different handlers to different events.
    var action = target.dataset['action' + eventName.charAt(0).toUpperCase() + eventName.slice(1)];
    if (!action && eventName === 'click') action = target.dataset.action;
    if (!action) return;
    var arg = target.dataset.arg;
    var fn = actions[action];
    if (typeof fn === 'function') {
      // Stop <a> from navigating to "#" or empty href — but leave real
      // links (http://..., target=_blank) alone so they still work.
      // Also honor data-default="allow" for any element that wants the
      // default action to run (e.g. links to external docs).
      if (eventName === 'click' && target.tagName === 'A') {
        var href = target.getAttribute('href');
        var allow = target.dataset.default === 'allow';
        if (!allow && (!href || href === '#')) e.preventDefault();
      }
      fn(arg, target, e);
    }
  });
}
['click', 'change', 'input', 'submit', 'keydown', 'keyup'].forEach(_installDelegator);

// Module scripts defer automatically, so the DOM is parsed by the time
// this runs — but we still wait for DOMContentLoaded to be safe across
// very old browsers and edge cases.
function _boot() {
  // Theme first so the UI doesn't flash.
  initTheme();

  // Resolve starting page from the hash; fall back to dashboard.
  var startPage = (location.hash || '').replace('#', '') || 'dashboard';
  var target = validPages.indexOf(startPage) >= 0 ? startPage : 'dashboard';
  navigate(target);

  // Kick off the live-monitor SSE client — fire-and-forget. The topbar
  // "Live" indicator subscribes immediately so it reflects state on
  // every page, not just the dashboard.
  monitorClient.init();
  mountNavLiveIndicator();

  // Hydrate Lucide icons once at startup. Sidebar nav, topbar user
  // menu, and the monitor gear dropdown all render from static markup
  // (or boot-time render) so a single pass covers them.
  try {
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons();
    }
  } catch (e) {}

  // Populate the topbar avatar with the signed-in user's initials.
  mountUserMenu();

  // Privilege banner — only fires on Windows hosts when the process
  // doesn't hold admin rights and the user hasn't already dismissed it.
  _maybeShowAdminBanner();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _boot);
} else {
  _boot();
}
