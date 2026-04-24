// navigation.js — swaps #content between pages and keeps the browser
// URL + history in sync using the History API. Every top-level page has
// its own path (/dashboard, /monitor, ...) so back / forward / refresh
// all behave the way a user expects from a normal website.
'use strict';

import { renderDashboardPage } from './dashboard.js';
import { renderMonitorPage } from './monitor.js';
import { renderScansPage, setScansPageTab, viewScan } from './findings.js';
import { renderHistoryPage } from './history.js';
import { renderFleetPage } from './fleet.js';
import { renderFirewallPage } from './firewall.js';
import { renderWhitelistPage } from './whitelist.js';
import { renderSettingsPage } from './settings.js';
import { renderReportsPage } from './reports.js';
import { renderRulesPage } from './rules.js';
import { renderAuditPage } from './audit.js';
import { renderCompliancePage } from './compliance.js';
import { renderTrendsPage } from './trends.js';

// "findings" is no longer a top-level page — it's a tab on Scans. Still
// in validPages so old /findings bookmarks and back-entries land right.
export const validPages = ['dashboard','monitor','scans','findings','reports','history','fleet','firewall','whitelist','rules','audit','compliance','trends','settings'];

// Current page — mutable module state. Exposed via getter so other
// modules can peek (see theme.js).
let _currentPage = 'dashboard';
export function getCurrentPage() { return _currentPage; }

// ----- URL <-> page -------------------------------------------------------
// parsePath('/fleet')       -> { page: 'fleet' }
// parsePath('/scans/123')   -> { page: 'scans', scanId: 123 }
// parsePath('/') / ''       -> { page: 'dashboard' }
export function parsePath(pathname) {
  var clean = (pathname || '/').replace(/\/+$/, '') || '/';
  if (clean === '/' || clean === '') return { page: 'dashboard' };
  var parts = clean.split('/').filter(Boolean);
  var first = parts[0];
  if (first === 'scans' && parts[1] && /^\d+$/.test(parts[1])) {
    return { page: 'scans', scanId: Number(parts[1]) };
  }
  if (validPages.indexOf(first) >= 0) return { page: first };
  return { page: 'dashboard' };
}

function _buildPath(page, scanId) {
  if (page === 'scans' && scanId) return '/scans/' + scanId;
  return '/' + page;
}

// ----- navigate -----------------------------------------------------------
// opts:
//   push    (default true) — write a new history entry. Set false when
//            responding to popstate so we don't recurse into history.
//   replace — write history.replaceState instead of pushState. Used on
//            first-load so there's a valid state object attached to the
//            initial entry (otherwise back from entry #2 returns to a
//            null-state entry #1 and popstate has nothing to read).
//   scanId  — sub-page parameter for /scans/{id}.
export function navigate(page, opts) {
  opts = opts || {};
  // "findings" legacy hash → Scans page with the All Findings tab active.
  if (page === 'findings') {
    _syncUrl('scans', null, opts);
    _currentPage = 'scans';
    _updateSidebarHighlight('scans');
    _updateTitle('Scans');
    setScansPageTab('findings');
    return;
  }

  _syncUrl(page, opts.scanId, opts);
  _currentPage = page;
  _updateSidebarHighlight(page);
  _updateTitle(_titleFor(page, opts.scanId));

  // Scan detail is a sub-page of Scans: show Scans highlighted in the
  // sidebar but render the detail view instead of the list.
  if (page === 'scans' && opts.scanId) {
    viewScan(opts.scanId, { push: false });
    return;
  }

  // When the user clicks Scans in the sidebar, reset to the Scans tab
  // so they don't land on All Findings by accident.
  if (page === 'scans') {
    setScansPageTab('scans');
    return;
  }

  var renderers = {
    dashboard: renderDashboardPage,
    monitor:   renderMonitorPage,
    history:   renderHistoryPage,
    fleet:     renderFleetPage,
    firewall:  renderFirewallPage,
    whitelist: renderWhitelistPage,
    settings:  renderSettingsPage,
    reports:   renderReportsPage,
    rules:     renderRulesPage,
    audit:     renderAuditPage,
    compliance: renderCompliancePage,
    trends:     renderTrendsPage,
  };
  (renderers[page] || renderDashboardPage)();
}

// Keep a thin back-compat shim — older callers pass a second arg meaning
// "push a history entry". navigate() already pushes by default, so the
// two end up identical. Left as an exported symbol in case anything
// downstream imports it.
export function navigateWithHistory(page) {
  navigate(page);
}

function _syncUrl(page, scanId, opts) {
  var path = _buildPath(page, scanId);
  // Preserve the existing query string — dashboard filters write to
  // ?time=... via a separate replaceState, and we don't want to clobber
  // that when we navigate between pages that share the same URL (e.g.
  // going from a filtered dashboard view to settings and back).
  var full = path + (location.search || '');
  var state = { page: page };
  if (scanId) state.scanId = scanId;

  if (opts.push === false) return; // responding to popstate; do nothing
  if (opts.replace) {
    history.replaceState(state, '', full);
    return;
  }
  if (location.pathname + (scanId ? '' : '') === path) {
    // Same path — replace rather than push so duplicate clicks on a
    // sidebar item don't stack history entries.
    history.replaceState(state, '', full);
    return;
  }
  history.pushState(state, '', full);
}

function _updateSidebarHighlight(page) {
  document.querySelectorAll('.sidebar-nav a').forEach(function (a) { a.classList.remove('active'); });
  var a = document.querySelector('.sidebar-nav a[data-arg="' + page + '"]');
  if (a) a.classList.add('active');
}

function _updateTitle(title) {
  var titleEl = document.getElementById('page-title');
  if (titleEl) titleEl.textContent = title;
}

function _titleFor(page, scanId) {
  if (page === 'scans' && scanId) return 'Scan #' + scanId;
  return page.charAt(0).toUpperCase() + page.slice(1);
}

// ----- back / forward -----------------------------------------------------
// popstate fires on browser back / forward. We trust state.page when
// present (set by our own push/replaceState) and fall back to parsing
// the URL for history entries that predate this session (e.g. another
// tab's entry promoted into this window).
window.addEventListener('popstate', function (event) {
  var st = event.state;
  var page, scanId;
  if (st && st.page) {
    page = st.page;
    scanId = st.scanId || null;
  } else {
    var parsed = parsePath(location.pathname);
    page = parsed.page;
    scanId = parsed.scanId || null;
  }
  navigate(page, { push: false, scanId: scanId });
});

// ---------------------------------------------------------------
// Sidebar collapse/expand
// ---------------------------------------------------------------
// Toggles body.sidebar-collapsed and persists the state. The inline
// boot script in index.html restores the class before first paint
// so the choice sticks across reloads without a visible flash.
export function toggleSidebar() {
  var body = document.body;
  var nowCollapsed = !body.classList.contains('sidebar-collapsed');
  body.classList.toggle('sidebar-collapsed', nowCollapsed);
  try {
    localStorage.setItem('pulseSidebarCollapsed', nowCollapsed ? '1' : '0');
  } catch (e) { /* localStorage disabled — state is session-only */ }
}
