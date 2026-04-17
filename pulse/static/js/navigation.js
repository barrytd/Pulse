// navigation.js — switches pages by rendering into #content. Render
// functions live in other modules; imported directly so script-tag
// ordering is irrelevant.
'use strict';

import { renderDashboardPage } from './dashboard.js';
import { renderMonitorPage } from './monitor.js';
import { renderScansPage, setScansPageTab } from './findings.js';
import { renderHistoryPage } from './history.js';
import { renderWhitelistPage } from './whitelist.js';
import { renderSettingsPage } from './settings.js';

// "findings" is no longer a top-level page — it's a tab on Scans.
// Still in validPages for hash-backcompat (old bookmarks land right).
export const validPages = ['dashboard','monitor','scans','findings','history','whitelist','settings'];

// Current page — mutable module state. Exposed via getter so other
// modules can peek (see theme.js).
let _currentPage = 'dashboard';
export function getCurrentPage() { return _currentPage; }

export function navigate(page) {
  // "findings" hash → merged Scans page with the All Findings tab active.
  if (page === 'findings') {
    _currentPage = 'scans';
    if (location.hash !== '#scans') history.replaceState(null, '', '#scans');
    _updateSidebarHighlight('scans');
    _updateTitle('Scans');
    // setScansPageTab both mutates tab state AND re-renders the page,
    // so no further call into renderers is needed.
    setScansPageTab('findings');
    return;
  }

  _currentPage = page;
  if (location.hash !== '#' + page) history.replaceState(null, '', '#' + page);
  _updateSidebarHighlight(page);
  _updateTitle(page.charAt(0).toUpperCase() + page.slice(1));

  // When the user clicks Scans in the sidebar, reset to the Scans tab
  // so it doesn't surprise them by landing on All Findings. Same deal —
  // setScansPageTab re-renders, so return without hitting the renderer map.
  if (page === 'scans') {
    setScansPageTab('scans');
    return;
  }

  var renderers = {
    dashboard: renderDashboardPage,
    monitor:   renderMonitorPage,
    history:   renderHistoryPage,
    whitelist: renderWhitelistPage,
    settings:  renderSettingsPage,
  };

  (renderers[page] || renderDashboardPage)();
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
