// navigation.js — single source of truth for the app's top-level page
// router + sidebar highlight. Every page change flows through navigate():
//   1. URL is synced (pushState / replaceState)
//   2. body.dataset.page is updated (CSS hooks per page)
//   3. Active link in the sidebar is highlighted
//   4. The page's renderer runs
//
// Filters live inside each page's content area (top filter bars), so
// this module has no filter-pane awareness. There's no collapse state
// to manage either — the sidebar is always visible at 200px.
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
export function navigate(page, opts) {
  opts = opts || {};

  // "Findings" sidebar item is a sub-tab of the Scans page. Translate
  // the click into a Scans route with the All Findings tab active so
  // old /findings bookmarks still resolve correctly.
  if (page === 'findings') {
    _syncUrl('findings', null, opts);
    _currentPage = 'findings';
    _updateSidebarHighlight('findings');
    _updateTitle('Findings');
    document.body.dataset.page = 'findings';
    // renderScansPage will read scansPageTab = 'findings' and draw the
    // All Findings view inside the Scans shell.
    setScansPageTab('findings');
    return;
  }

  _syncUrl(page, opts.scanId, opts);
  _currentPage = page;
  _updateSidebarHighlight(page);
  _updateTitle(_titleFor(page, opts.scanId));
  document.body.dataset.page = page;

  // Scan detail is a sub-page of Scans: show Scans highlighted in the
  // sidebar but render the detail view instead of the list.
  if (page === 'scans' && opts.scanId) {
    viewScan(opts.scanId, { push: false });
    return;
  }

  // Clicking "Scans" in the sidebar resets to the list tab — don't
  // resume from whichever sub-tab was last visited.
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

// Back-compat shim — older callers pass a second arg meaning "push a
// history entry". navigate() already pushes by default.
export function navigateWithHistory(page) { navigate(page); }

function _syncUrl(page, scanId, opts) {
  var path = _buildPath(page, scanId);
  // Preserve the existing query string — dashboard filters write to
  // ?time=... via a separate replaceState, and we don't want to clobber
  // that when navigating between pages that share the same URL.
  var full = path + (location.search || '');
  var state = { page: page };
  if (scanId) state.scanId = scanId;

  if (opts.push === false) return;
  if (opts.replace) {
    history.replaceState(state, '', full);
    return;
  }
  if (location.pathname === path) {
    history.replaceState(state, '', full);
    return;
  }
  history.pushState(state, '', full);
}

function _updateSidebarHighlight(page) {
  document.querySelectorAll('.sidebar-nav').forEach(function (a) { a.classList.remove('active'); });
  var a = document.querySelector('.sidebar-nav[data-arg="' + page + '"]');
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
