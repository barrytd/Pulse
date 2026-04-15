// navigation.js — switches pages by rendering into #content. Render
// functions live in other modules; imported directly so script-tag
// ordering is irrelevant.
'use strict';

import { renderDashboardPage } from './dashboard.js';
import { renderMonitorPage } from './monitor.js';
import { renderScansPage, renderFindingsPage } from './findings.js';
import { renderHistoryPage } from './history.js';
import { renderWhitelistPage } from './whitelist.js';
import { renderSettingsPage } from './settings.js';

export const validPages = ['dashboard','monitor','scans','findings','history','whitelist','settings'];

// Current page — mutable module state. Exposed via getter so other
// modules can peek (see theme.js).
let _currentPage = 'dashboard';
export function getCurrentPage() { return _currentPage; }

export function navigate(page) {
  _currentPage = page;
  if (location.hash !== '#' + page) history.replaceState(null, '', '#' + page);
  document.querySelectorAll('.sidebar-nav a').forEach(function (a) { a.classList.remove('active'); });
  var links = document.querySelectorAll('.sidebar-nav a');
  var pageNames = ['dashboard','monitor','scans','findings','history','whitelist','settings'];
  var idx = pageNames.indexOf(page);
  if (idx >= 0 && links[idx]) links[idx].classList.add('active');

  var titleEl = document.getElementById('page-title');
  if (titleEl) titleEl.textContent = page.charAt(0).toUpperCase() + page.slice(1);

  var renderers = {
    dashboard: renderDashboardPage,
    monitor:   renderMonitorPage,
    scans:     renderScansPage,
    findings:  renderFindingsPage,
    history:   renderHistoryPage,
    whitelist: renderWhitelistPage,
    settings:  renderSettingsPage,
  };

  (renderers[page] || renderDashboardPage)();
}
