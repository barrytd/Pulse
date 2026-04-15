// navigation.js — switches pages by rendering into #content. Render
// functions live in other modules; look them up on window at dispatch
// time so script-tag ordering doesn't matter.
(function () {
  'use strict';

  window.currentPage = 'dashboard';
  window.validPages  = ['dashboard','monitor','scans','findings','history','whitelist','settings'];

  function navigate(page) {
    window.currentPage = page;
    if (location.hash !== '#' + page) history.replaceState(null, '', '#' + page);
    document.querySelectorAll('.sidebar-nav a').forEach(function (a) { a.classList.remove('active'); });
    var links = document.querySelectorAll('.sidebar-nav a');
    var pageNames = ['dashboard','monitor','scans','findings','history','whitelist','settings'];
    var idx = pageNames.indexOf(page);
    if (idx >= 0 && links[idx]) links[idx].classList.add('active');

    var titleEl = document.getElementById('page-title');
    if (titleEl) titleEl.textContent = page.charAt(0).toUpperCase() + page.slice(1);

    var renderers = {
      dashboard: window.renderDashboardPage,
      monitor:   window.renderMonitorPage,
      scans:     window.renderScansPage,
      findings:  window.renderFindingsPage,
      history:   window.renderHistoryPage,
      whitelist: window.renderWhitelistPage,
      settings:  window.renderSettingsPage,
    };

    (renderers[page] || window.renderDashboardPage)();
  }

  window.navigate = navigate;
})();
