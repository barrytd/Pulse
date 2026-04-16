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
  downloadReport,
  applyDashFilters,
  resetDashFilters,
  dashFilterQueryKey,
  openFindingDrawerByIdx,
} from './dashboard.js';
import {
  toggleScanSelect,
  toggleScanSelectAll,
  deleteSelectedScans,
  setScansSort,
  setScansQueryFromInput,
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
  resetFindingReview,
} from './findings.js';
import { highlightHistoryScan, runHistoryCompare } from './history.js';
import {
  monitorClient,
  startMonitor,
  stopMonitor,
  sendMonitorTestAlert,
  updateMonIntervalLabel,
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
} from './settings.js';

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

  // dashboard
  downloadReport,
  applyDashFilters,
  resetDashFilters,
  dashFilterQueryKey,
  openFindingDrawerByIdx,

  // scans + findings
  toggleScanSelect,
  toggleScanSelectAll,
  deleteSelectedScans,
  setScansSort,
  setScansQueryFromInput,
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
  resetFindingReview,

  // history
  highlightHistoryScan,
  runHistoryCompare,

  // monitor
  startMonitor,
  stopMonitor,
  sendMonitorTestAlert,
  updateMonIntervalLabel,

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
};

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

  // Kick off the live-monitor SSE client — fire-and-forget. If the
  // page happens to be the dashboard, mountDashLivePanel() will pick
  // up state from monitorClient once init resolves.
  monitorClient.init();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _boot);
} else {
  _boot();
}
