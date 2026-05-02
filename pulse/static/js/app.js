// app.js — the only entry point. Imports propagate to every other
// module, so index.html needs just one <script type="module"> tag.
// Owns the event-delegation action registry and DOMContentLoaded boot.
'use strict';

import { initTheme, toggleTheme, setThemeFromSelect } from './theme.js';
import {
  applySeverityColors,
  severityColorInput,
  resetSeverityColors,
} from './severity-colors.js';
import { navigate, validPages, parsePath } from './navigation.js';
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
  dismissOnboarding,
  navigateOnboarding,
} from './dashboard.js';
import {
  viewScan,
  setFindingsSort,
  setFindingsQueryFromInput,
  toggleFindingsFilter,
  removeFindingsFilterChip,
  clearFindingsFilters,
  findingsCtxFilterFor,
  findingsCtxFilterOut,
  openFilterChip,
  openAddFilterMenu,
  addFilterDim,
  filterChipDdFind,
  clearFilterChip,
  dismissFilterChip,
  findingsKpiClick,
  toggleFindingsAutoRefresh,
  refreshFindings,
  exportFindingsCsv,
  toggleReviewedFromRow,
  toggleFindingSelect,
  toggleFindingSelectAll,
  selectAllMatchingFilter,
  clearFindingSelection,
  toggleBulkAssignMenu,
  bulkAssignPick,
  bulkAssignToMe,
  bulkUnassign,
  bulkMarkReviewed,
  toggleFpFromRow,
  stopClickPropagation,
  viewScanFromLink,
  toggleFindingExpand,
  openFindingsPageDrawerByUid,
  closeFindingDrawer,
  openScanDetailFindingByIdx,
  markFindingReviewed,
  markFindingFalsePositive,
  setFindingWorkflow,
  setFindingAssignee,
  assignFindingToMe,
  toggleAssignPicker,
  pickFindingAssignee,
  submitFindingNote,
  deleteFindingNote,
  openUnreviewedCriticalHigh,
  stageBlockFromFinding,
  blockNowFromFinding,
  openForceBlockModal,
  closeForceBlockModal,
  forceBlockInputCheck,
  confirmForceBlock,
} from './findings.js';
import {
  highlightHistoryScan,
  runHistoryCompare,
  setCompareTab,
  toggleHistorySelect,
  toggleHistorySelectAll,
  deleteSelectedHistory,
} from './history.js';
import { fleetOpenHost, exportFleetCsv, fleetFilterByKpi } from './fleet.js';
import {
  setFirewallTab,
  firewallPushOne,
  firewallPushAll,
  firewallUnblock,
  openAddBlockModal,
  closeAddBlockModal,
  addBlockInputCheck,
  submitAddBlock,
  toggleBlockSelect,
  toggleBlockSelectAll,
  deleteSelectedBlocks,
  firewallReviewPending,
  firewallDiscardPending,
  fwPathInput,
  fwPathKey,
  fwParseLog,
  fwUploadLog,
  fwSetFilter,
  fwSetSearch,
  fwBlockFromRow,
  fwLookupFromRow,
} from './firewall.js';
import {
  monitorClient,
  mountNavLiveIndicator,
  startMonitor,
  stopMonitor,
  sendMonitorTestAlert,
  sendMonitorTestAlertFromRail,
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
  toggleMonitorSessionSelect,
  toggleMonitorSessionSelectAll,
  deleteSelectedMonitorSessions,
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
  toggleWhitelistSelect,
  toggleWhitelistSelectAll,
  deleteSelectedWhitelist,
  focusWhitelistAddInput,
  toggleWhitelistLearnMore,
} from './whitelist.js';
import {
  saveAccount,
  signOut,
  onEmailProviderChange,
  saveEmailSettings,
  saveAlertSettings,
  sendTestAlert,
  sendWeeklyBriefNow,
  previewWeeklyBrief,
  saveWebhookSettings,
  sendTestWebhook,
  saveThreatIntelSettings,
  testThreatIntelKey,
  onScheduleKindChange,
  saveScheduleSettings,
  switchSettingsTab,
  resetSeverityPaletteAndRender,
  createUser,
  toggleUserRole,
  toggleUserActive,
  saveUserDisplayName,
  saveUserDisplayNameOnEnter,
  toggleUserRowMenu,
  deleteUserConfirm,
  uploadAvatarClick,
  onAvatarFileSelected,
  createToken,
  revokeTokenConfirm,
  enrollAgent,
  copyAgentEnrollToken,
  toggleAgentPause,
  deleteAgentConfirm,
  toggleFeedbackRow,
  toggleNoteAdminRow,
  deleteWaitlistSignup,
} from './settings.js';
import {
  setReportsQueryFromInput,
  deleteReport,
  toggleReportSelect,
  toggleReportSelectAll,
  deleteSelectedReports,
  openGenerateReportModal,
  closeGenerateReportModal,
  submitGenerateReport,
} from './reports.js';
import {
  toggleRuleEnabled,
  rulesShowTab,
  rulesClearFilter,
  filterByTechnique,
} from './rules.js';
import {
  openAuditDrawer,
  openAuditFinding,
  openAuditFindingByRef,
  auditSetQuery,
  auditClearFilters,
  auditDismissChip,
  auditToggleTimeFmt,
  auditOpenChip,
  auditOpenAddFilter,
  auditAddFilterDim,
  auditToggleFilter,
  auditPickTimeWindow,
  auditApplyFreeformFilter,
  auditExportToggle,
  auditExportRun,
} from './audit.js';
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
import { mountCommandPalette, openCommandPalette } from './command-palette.js';
import {
  threatIntelInputChange,
  threatIntelSubmit,
  threatIntelLookupRecent,
  threatIntelRefreshRecent,
} from './threat-intel.js';
import {
  openFeedbackModal,
  closeFeedbackModal,
  submitFeedback,
  setFeedbackKind,
} from './feedback.js';
import {
  toggleNotifMenu,
  openNotifTarget,
  mountNotifBell,
} from './notifications.js';

// Central action registry — replaces the old window[action] lookup.
// Every data-action / data-action-<event> string in the HTML or
// template strings must map to a function here.
const actions = {
  // theme + navigation
  navigate,
  toggleTheme,
  setThemeFromSelect,
  severityColorInput,
  resetSeverityColors,

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
  uploadFromTopbar,
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
  dismissOnboarding,
  navigateOnboarding,

  // findings + scan-detail
  viewScan,
  setFindingsSort,
  setFindingsQueryFromInput,
  toggleFindingsFilter,
  removeFindingsFilterChip,
  clearFindingsFilters,
  findingsCtxFilterFor,
  findingsCtxFilterOut,
  openFilterChip,
  openAddFilterMenu,
  addFilterDim,
  filterChipDdFind,
  clearFilterChip,
  dismissFilterChip,
  findingsKpiClick,
  toggleFindingsAutoRefresh,
  refreshFindings,
  exportFindingsCsv,
  toggleReviewedFromRow,
  toggleFindingSelect,
  toggleFindingSelectAll,
  selectAllMatchingFilter,
  clearFindingSelection,
  toggleBulkAssignMenu,
  bulkAssignPick,
  bulkAssignToMe,
  bulkUnassign,
  bulkMarkReviewed,
  toggleFpFromRow,
  stopClickPropagation,
  viewScanFromLink,
  toggleFindingExpand,
  openFindingsPageDrawerByUid,
  closeFindingDrawer,
  openScanDetailFindingByIdx,
  markFindingReviewed,
  markFindingFalsePositive,
  setFindingWorkflow,
  setFindingAssignee,
  assignFindingToMe,
  toggleAssignPicker,
  pickFindingAssignee,
  submitFindingNote,
  deleteFindingNote,
  stageBlockFromFinding,
  blockNowFromFinding,
  openForceBlockModal,
  closeForceBlockModal,
  forceBlockInputCheck,
  confirmForceBlock,

  // history
  highlightHistoryScan,
  runHistoryCompare,
  setCompareTab,
  toggleHistorySelect,
  toggleHistorySelectAll,
  deleteSelectedHistory,

  // fleet
  fleetOpenHost,
  exportFleetCsv,
  fleetFilterByKpi,

  // firewall
  setFirewallTab,
  firewallPushOne,
  firewallPushAll,
  firewallUnblock,
  openAddBlockModal,
  closeAddBlockModal,
  addBlockInputCheck,
  submitAddBlock,
  toggleBlockSelect,
  toggleBlockSelectAll,
  deleteSelectedBlocks,
  firewallReviewPending,
  firewallDiscardPending,
  fwPathInput,
  fwPathKey,
  fwParseLog,
  fwUploadLog,
  fwSetFilter,
  fwSetSearch,
  fwBlockFromRow,
  fwLookupFromRow,

  // monitor
  startMonitor,
  stopMonitor,
  sendMonitorTestAlert,
  sendMonitorTestAlertFromRail,
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
  toggleMonitorSessionSelect,
  toggleMonitorSessionSelectAll,
  deleteSelectedMonitorSessions,
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
  toggleWhitelistSelect,
  toggleWhitelistSelectAll,
  deleteSelectedWhitelist,
  focusWhitelistAddInput,
  toggleWhitelistLearnMore,

  // settings
  saveAccount,
  signOut,
  onEmailProviderChange,
  saveEmailSettings,
  saveAlertSettings,
  sendTestAlert,
  sendWeeklyBriefNow,
  previewWeeklyBrief,
  saveWebhookSettings,
  sendTestWebhook,
  saveThreatIntelSettings,
  testThreatIntelKey,
  onScheduleKindChange,
  saveScheduleSettings,
  switchSettingsTab,
  resetSeverityPaletteAndRender,
  createUser,
  toggleUserRole,
  toggleUserActive,
  saveUserDisplayName,
  saveUserDisplayNameOnEnter,
  toggleUserRowMenu,
  deleteUserConfirm,
  uploadAvatarClick,
  onAvatarFileSelected,
  createToken,
  revokeTokenConfirm,
  enrollAgent,
  copyAgentEnrollToken,
  toggleAgentPause,
  deleteAgentConfirm,
  toggleFeedbackRow,
  toggleNoteAdminRow,
  deleteWaitlistSignup,

  // reports
  setReportsQueryFromInput,
  deleteReport,
  toggleReportSelect,
  toggleReportSelectAll,
  deleteSelectedReports,
  openGenerateReportModal,
  closeGenerateReportModal,
  submitGenerateReport,

  // rules
  toggleRuleEnabled,
  rulesShowTab,
  rulesClearFilter,
  filterByTechnique,

  // audit log
  openAuditDrawer,
  openAuditFinding,
  openAuditFindingByRef,
  auditSetQuery,
  auditClearFilters,
  auditDismissChip,
  auditToggleTimeFmt,
  auditOpenChip,
  auditOpenAddFilter,
  auditAddFilterDim,
  auditToggleFilter,
  auditPickTimeWindow,
  auditApplyFreeformFilter,
  auditExportToggle,
  auditExportRun,

  // user menu
  toggleUserMenu,
  openProfile,
  openAccountSettings,
  openDocs,
  openFeedback,
  logOutFromMenu,
  toggleDarkModeFromMenu,

  // feedback modal
  openFeedbackModal,
  closeFeedbackModal,
  submitFeedback,
  setFeedbackKind,

  // admin privilege banner
  dismissAdminBanner,

  // command palette
  openCommandPalette,

  // notifications bell
  toggleNotifMenu,
  openNotifTarget,

  // threat intel — IOC lookup page
  threatIntelInputChange,
  threatIntelSubmit,
  threatIntelLookupRecent,
  threatIntelRefreshRecent,
};

// Topbar scan-button replacement on non-Windows hosts. We can't run a
// system scan against the local Windows event log from a Linux server,
// so the same button leads users to the upload-an-evtx flow instead.
// Navigate to Scans first so the freshly uploaded scan lands on the
// right page when it completes.
function uploadFromTopbar() {
  navigate('scans');
  // Wait one frame so the Scans page DOM is in place before the modal
  // anchors any click handlers; openUploadModal itself just toggles a
  // class on a globally-mounted modal so this is mostly cosmetic.
  requestAnimationFrame(function () { openUploadModal(); });
}

// Hide the banner for the rest of the session and persist the choice.
function dismissAdminBanner() {
  var el = document.getElementById('admin-banner');
  if (el) el.style.display = 'none';
  try { localStorage.setItem('pulseAdminBannerDismissed', '1'); } catch (e) {}
}

// One-shot health probe at boot. Drives two host-aware UI tweaks:
//   1) Admin banner — only on Windows hosts where the process isn't elevated
//      (and the user hasn't already dismissed it).
//   2) Topbar "Scan My System" button — repurposed to "Upload .evtx" on
//      non-Windows hosts (e.g. the Render-hosted dashboard) since the
//      local-system scanner relies on `wevtutil`. The label and click
//      action both swap so the button leads somewhere useful instead of
//      silently failing.
async function _applyHostPlatformGating() {
  var bannerEl = document.getElementById('admin-banner');
  var btnEl    = document.getElementById('topbar-scan-btn');
  var bannerDismissed = false;
  try {
    bannerDismissed = (localStorage.getItem('pulseAdminBannerDismissed') === '1');
  } catch (e) { /* ignore — private mode blocks localStorage */ }
  try {
    var resp = await fetch('/api/health');
    if (!resp.ok) return;
    var info = await resp.json();

    if (bannerEl && info.platform_windows && !info.is_admin && !bannerDismissed) {
      bannerEl.style.display = 'flex';
    }

    if (btnEl && !info.platform_windows) {
      btnEl.dataset.action = 'uploadFromTopbar';
      btnEl.title = 'Upload an .evtx file (this server can\'t read live Windows logs)';
      var label = btnEl.querySelector('.topbar-scan-label');
      if (label) label.textContent = 'Upload .evtx';
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
        // Any <a data-action> gets preventDefault by default — we're
        // handling the click ourselves and don't want hash/empty hrefs
        // to dirty the URL or trigger native nav. Opt back in with
        // data-default="allow" for real external links.
        if (!allow && (!href || href === '#' || href.charAt(0) === '#')) e.preventDefault();
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
  // Severity-color overrides ride on top of the theme block, so apply
  // them immediately after initTheme() to avoid a brief flash of the
  // default palette before the user's saved colors take effect.
  applySeverityColors();

  // Resolve starting page from the URL pathname. Back-compat: older
  // bookmarks used "#scans" style hashes — honour them by translating
  // into a pathname before routing.
  var path = location.pathname;
  if ((path === '/' || path === '') && location.hash) {
    var legacy = location.hash.replace('#', '');
    if (validPages.indexOf(legacy) >= 0) path = '/' + legacy;
  }
  var parsed = parsePath(path);
  // replace:true so the first history entry carries a real state object
  // and popstate from a later push returns here cleanly.
  navigate(parsed.page, { replace: true, scanId: parsed.scanId });

  // Kick off the live-monitor SSE client — fire-and-forget. The topbar
  // "Live" indicator subscribes immediately so it reflects state on
  // every page, not just the dashboard.
  monitorClient.init();
  mountNavLiveIndicator();

  // Hydrate Lucide icons at startup AND auto-hydrate on every render
  // afterward. A MutationObserver on #content catches every page render
  // (which always swaps innerHTML) and a coalesced rAF call replaces
  // any newly-injected `<i data-lucide="...">` placeholders. This means
  // page renderers don't need to remember to call createIcons themselves.
  function _hydrateLucide() {
    try {
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
      }
    } catch (e) {}
  }
  _hydrateLucide();
  var contentEl = document.getElementById('content');
  if (contentEl && typeof MutationObserver === 'function') {
    var pending = false;
    new MutationObserver(function () {
      if (pending) return;
      pending = true;
      requestAnimationFrame(function () {
        pending = false;
        _hydrateLucide();
      });
    }).observe(contentEl, { childList: true, subtree: true });
  }

  // Populate the topbar avatar with the signed-in user's initials.
  mountUserMenu();

  // Cmd+K / Ctrl+K command palette — cross-cutting launcher available
  // on every page once mounted.
  mountCommandPalette();

  // Single /api/health probe — lights the privilege banner on Windows
  // hosts that aren't elevated AND swaps the topbar "Scan My System"
  // button for "Upload .evtx" on non-Windows hosts.
  _applyHostPlatformGating();

  // Bell-icon notification feed — initial badge paint + 60s poll.
  mountNotifBell();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _boot);
} else {
  _boot();
}
