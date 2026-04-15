// theme.js — dark/light theme toggle. Persists to localStorage.
(function () {
  'use strict';

  function getTheme() { return localStorage.getItem('pulse-theme') || 'dark'; }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    var btn = document.getElementById('theme-btn');
    if (btn) btn.textContent = theme === 'dark' ? '\u2600' : '\u263D';
  }

  function toggleTheme() {
    var next = getTheme() === 'dark' ? 'light' : 'dark';
    localStorage.setItem('pulse-theme', next);
    applyTheme(next);
  }

  function initTheme() {
    applyTheme(getTheme());
  }

  function setThemeFromSelect(theme, target) {
    // When called via the delegator (data-action-change), theme is the
    // data-arg (undefined here) and target is the <select>. Pull the
    // live value off the element in that case.
    if ((theme === undefined || theme === null || typeof theme === 'string' && theme === '')
        && target && typeof target.value === 'string') {
      theme = target.value;
    }
    if (!theme) return;
    localStorage.setItem('pulse-theme', theme);
    applyTheme(theme);
    if (window.showToast) window.showToast('Theme updated');
    // Rebuild any chart that's currently visible to pick up new colors.
    if (window.currentPage === 'dashboard' || window.currentPage === 'history') {
      if (window.navigate) window.navigate(window.currentPage);
    }
  }

  window.getTheme           = getTheme;
  window.applyTheme         = applyTheme;
  window.toggleTheme        = toggleTheme;
  window.initTheme          = initTheme;
  window.setThemeFromSelect = setThemeFromSelect;
})();
