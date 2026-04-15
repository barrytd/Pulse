// theme.js — dark/light theme toggle. Persists to localStorage.
'use strict';

import { showToast } from './dashboard.js';
import { navigate } from './navigation.js';
import { getCurrentPage } from './navigation.js';

export function getTheme() { return localStorage.getItem('pulse-theme') || 'dark'; }

export function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  var btn = document.getElementById('theme-btn');
  if (btn) btn.textContent = theme === 'dark' ? '\u2600' : '\u263D';
}

export function toggleTheme() {
  var next = getTheme() === 'dark' ? 'light' : 'dark';
  localStorage.setItem('pulse-theme', next);
  applyTheme(next);
}

export function initTheme() {
  applyTheme(getTheme());
}

export function setThemeFromSelect(theme, target) {
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
  showToast('Theme updated');
  // Rebuild any chart that's currently visible to pick up new colors.
  var page = getCurrentPage();
  if (page === 'dashboard' || page === 'history') {
    navigate(page);
  }
}
