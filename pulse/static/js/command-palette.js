// command-palette.js — Ctrl+K / Cmd+K fuzzy launcher.
// Cross-cutting UX per the Pulse blueprint: one shortcut opens a 520-640px
// modal with a search input and up to 8 ranked results. Arrow keys navigate,
// Enter executes, Esc closes. Results are navigation targets + common
// actions (start/stop monitor, send test alert, toggle theme, etc.).
'use strict';

import { navigate } from './navigation.js';
import { toggleTheme } from './theme.js';
import { monitorClient } from './monitor.js';
import { openUploadModal } from './upload.js';
import { openSystemScanModal } from './system-scan.js';
import { setActiveSettingsTab } from './settings.js';

// Cached at boot via /api/health. `null` means "not yet probed" — fall
// back to assuming Windows so the local-scan command shows on first
// open if the probe is racing the keystroke. Updated to true/false once
// the fetch resolves.
let _platformWindows = null;
fetch('/api/health').then(function (r) { return r.ok ? r.json() : null; })
  .then(function (info) {
    if (info && typeof info.platform_windows === 'boolean') {
      _platformWindows = info.platform_windows;
    }
  })
  .catch(function () { /* health is best-effort */ });

// Each command declares: id, label (shown first), hint (meta text on the
// right), group (section header), keywords (extra tokens for fuzzy match),
// and run (invoked on Enter/click). All callbacks are closed over module
// imports so there's no string eval at dispatch time.
const _COMMANDS = [
  // Navigation
  { id: 'nav.dashboard',  label: 'Dashboard',       group: 'Go to', keywords: 'home overview', run: () => navigate('dashboard') },
  { id: 'nav.monitor',    label: 'Monitor',         group: 'Go to', keywords: 'live sse stream', run: () => navigate('monitor') },
  { id: 'nav.scans',      label: 'Scans',           group: 'Go to', keywords: 'scan history evtx', run: () => navigate('scans') },
  { id: 'nav.findings',   label: 'Findings',        group: 'Go to', keywords: 'alerts detections', run: () => navigate('findings') },
  { id: 'nav.reports',    label: 'Reports',         group: 'Go to', keywords: 'export pdf', run: () => navigate('reports') },
  { id: 'nav.history',    label: 'History',         group: 'Go to', keywords: 'timeline events', run: () => navigate('history') },
  { id: 'nav.fleet',      label: 'Fleet',           group: 'Go to', keywords: 'hosts endpoints', run: () => navigate('fleet') },
  { id: 'nav.firewall',   label: 'Firewall',        group: 'Go to', keywords: 'block list ip', run: () => navigate('firewall') },
  { id: 'nav.whitelist',  label: 'Whitelist',       group: 'Go to', keywords: 'allow list exceptions', run: () => navigate('whitelist') },
  { id: 'nav.rules',      label: 'Rules',           group: 'Go to', keywords: 'detection mitre', run: () => navigate('rules') },
  { id: 'nav.audit',      label: 'Audit log',       group: 'Go to', keywords: 'audit trail', run: () => navigate('audit') },
  { id: 'nav.compliance', label: 'Compliance',      group: 'Go to', keywords: 'nist iso 27001 csf', run: () => navigate('compliance') },
  { id: 'nav.trends',     label: 'Trends',          group: 'Go to', keywords: 'analytics chart', run: () => navigate('trends') },
  { id: 'nav.settings',   label: 'Settings',        group: 'Go to', keywords: 'account email webhook', run: () => navigate('settings') },

  // Actions
  { id: 'act.start_monitor', label: 'Start monitoring',     group: 'Actions', keywords: 'watch live begin', run: () => monitorClient.start() },
  { id: 'act.stop_monitor',  label: 'Stop monitoring',      group: 'Actions', keywords: 'halt end',          run: () => monitorClient.stop() },
  { id: 'act.test_alert',    label: 'Send test alert',      group: 'Actions', keywords: 'ping demo notify',  run: () => monitorClient.sendTestAlert() },
  { id: 'act.upload',        label: 'Upload .evtx file',    group: 'Actions', keywords: 'import log scan',   run: () => openUploadModal() },
  { id: 'act.system_scan',   label: 'Scan my system',       group: 'Actions', keywords: 'local run now',     run: () => openSystemScanModal(),
    condition: () => _platformWindows !== false },
  { id: 'act.download_agent', label: 'Install Pulse Agent', group: 'Actions', keywords: 'download agent windows host enroll',
    run: () => { setActiveSettingsTab('agents'); navigate('settings'); },
    condition: () => _platformWindows === false },
  { id: 'act.toggle_theme',  label: 'Toggle dark / light',  group: 'Actions', keywords: 'theme appearance',  run: () => toggleTheme() },
];

// Filter `_COMMANDS` against any per-entry `condition()` so the palette
// reflects host-platform gating (e.g. hide "Scan my system" on a non-
// Windows hosted server, surface "Install Pulse Agent" instead).
function _availableCommands() {
  return _COMMANDS.filter(function (c) {
    return typeof c.condition !== 'function' || c.condition();
  });
}

// Recent selections — stored as ids so labels can change without drifting.
const LS_RECENT = 'pulse.palette.recent';
const MAX_RECENT = 4;

function _readRecent() {
  try {
    var raw = localStorage.getItem(LS_RECENT);
    if (!raw) return [];
    var arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch (e) { return []; }
}
function _pushRecent(id) {
  try {
    var list = _readRecent().filter(function (x) { return x !== id; });
    list.unshift(id);
    localStorage.setItem(LS_RECENT, JSON.stringify(list.slice(0, MAX_RECENT)));
  } catch (e) {}
}

// Fuzzy scoring — every query char must appear in order in `haystack`.
// Higher score for earlier matches, runs of consecutive chars, and matches
// on word boundaries. Returns 0 when there's no match.
function _fuzzyScore(haystack, needle) {
  if (!needle) return 1;
  var h = haystack.toLowerCase();
  var n = needle.toLowerCase();
  var hi = 0, ni = 0, score = 0, run = 0;
  while (hi < h.length && ni < n.length) {
    if (h.charAt(hi) === n.charAt(ni)) {
      score += 10 + run * 4;
      if (hi === 0 || /\s|\W/.test(h.charAt(hi - 1))) score += 8;
      run++;
      ni++;
    } else {
      run = 0;
      score -= 1;
    }
    hi++;
  }
  if (ni < n.length) return 0;
  // Shorter haystacks win tiebreakers.
  return score - Math.floor(h.length / 10);
}

function _rank(query) {
  var recent = _readRecent();
  var available = _availableCommands();
  if (!query) {
    // No query: recents first, then the rest in declared order.
    var recentCmds = recent
      .map(function (id) { return available.find(function (c) { return c.id === id; }); })
      .filter(Boolean);
    var remaining = available.filter(function (c) { return recent.indexOf(c.id) < 0; });
    return recentCmds.concat(remaining).slice(0, 8);
  }
  return available
    .map(function (c) {
      var labelScore = _fuzzyScore(c.label, query);
      var kwScore    = _fuzzyScore(c.keywords || '', query);
      var groupScore = _fuzzyScore(c.group || '', query);
      var best = Math.max(labelScore * 2, kwScore, groupScore);
      if (recent.indexOf(c.id) >= 0) best += 5;
      return { cmd: c, score: best };
    })
    .filter(function (r) { return r.score > 0; })
    .sort(function (a, b) { return b.score - a.score; })
    .slice(0, 8)
    .map(function (r) { return r.cmd; });
}

let _state = {
  open: false,
  query: '',
  selectedIdx: 0,
  results: [],
  overlay: null,
  input: null,
  listEl: null,
};

function _ensureMounted() {
  if (_state.overlay) return;
  var overlay = document.createElement('div');
  overlay.className = 'cmdk-overlay';
  overlay.hidden = true;
  overlay.innerHTML =
    '<div class="cmdk-modal" role="dialog" aria-label="Command palette">' +
      '<div class="cmdk-search">' +
        '<svg class="cmdk-search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
          '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>' +
        '</svg>' +
        '<input class="cmdk-input" type="text" placeholder="Search pages and actions…" spellcheck="false" autocomplete="off" />' +
        '<span class="cmdk-kbd">Esc</span>' +
      '</div>' +
      '<div class="cmdk-list" role="listbox"></div>' +
      '<div class="cmdk-foot">' +
        '<span><span class="cmdk-kbd">↑↓</span> navigate</span>' +
        '<span><span class="cmdk-kbd">↵</span> select</span>' +
        '<span><span class="cmdk-kbd">Esc</span> close</span>' +
      '</div>' +
    '</div>';
  document.body.appendChild(overlay);

  _state.overlay = overlay;
  _state.input   = overlay.querySelector('.cmdk-input');
  _state.listEl  = overlay.querySelector('.cmdk-list');

  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) _close();
  });
  _state.input.addEventListener('input', function () {
    _state.query = _state.input.value;
    _state.selectedIdx = 0;
    _rerender();
  });
  _state.input.addEventListener('keydown', function (e) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      _state.selectedIdx = Math.min(_state.results.length - 1, _state.selectedIdx + 1);
      _rerender();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      _state.selectedIdx = Math.max(0, _state.selectedIdx - 1);
      _rerender();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      _execSelected();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      _close();
    }
  });
  _state.listEl.addEventListener('click', function (e) {
    var row = e.target.closest('[data-idx]');
    if (!row) return;
    _state.selectedIdx = parseInt(row.dataset.idx, 10) || 0;
    _execSelected();
  });
}

function _rerender() {
  _state.results = _rank(_state.query);
  if (_state.results.length === 0) {
    _state.listEl.innerHTML = '<div class="cmdk-empty">No results for “' + _escape(_state.query) + '”</div>';
    return;
  }
  var lastGroup = null;
  var html = _state.results.map(function (cmd, i) {
    var header = '';
    if (cmd.group !== lastGroup) {
      header = '<div class="cmdk-group">' + _escape(cmd.group || '') + '</div>';
      lastGroup = cmd.group;
    }
    var sel = i === _state.selectedIdx ? ' selected' : '';
    var enter = i === _state.selectedIdx ? '<span class="cmdk-kbd">↵</span>' : '';
    return header +
      '<div class="cmdk-row' + sel + '" data-idx="' + i + '" role="option" aria-selected="' + (i === _state.selectedIdx) + '">' +
        '<div class="cmdk-label">' + _escape(cmd.label) + '</div>' +
        '<div class="cmdk-hint">' + enter + '</div>' +
      '</div>';
  }).join('');
  _state.listEl.innerHTML = html;
  // Keep selected row in view.
  var selEl = _state.listEl.querySelector('.cmdk-row.selected');
  if (selEl && selEl.scrollIntoView) selEl.scrollIntoView({ block: 'nearest' });
}

function _execSelected() {
  var cmd = _state.results[_state.selectedIdx];
  if (!cmd) return;
  _pushRecent(cmd.id);
  _close();
  try { cmd.run(); }
  catch (e) { /* swallow — command failure shouldn't crash the palette */ }
}

function _open() {
  _ensureMounted();
  if (_state.open) return;
  _state.open = true;
  _state.query = '';
  _state.selectedIdx = 0;
  _state.input.value = '';
  _state.overlay.hidden = false;
  // Two rAF so the display flip has committed before the class change
  // so the CSS transition fires instead of snapping.
  requestAnimationFrame(function () {
    requestAnimationFrame(function () { _state.overlay.classList.add('open'); });
  });
  _rerender();
  setTimeout(function () { _state.input.focus(); }, 0);
}

function _close() {
  if (!_state.open) return;
  _state.open = false;
  _state.overlay.classList.remove('open');
  setTimeout(function () { if (!_state.open) _state.overlay.hidden = true; }, 160);
}

function _escape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Public API — app.js wires mountCommandPalette() into boot. Once mounted,
// the Ctrl+K / Cmd+K shortcut is captured document-wide.
export function mountCommandPalette() {
  document.addEventListener('keydown', function (e) {
    var isToggle = (e.key === 'k' || e.key === 'K') && (e.ctrlKey || e.metaKey);
    if (!isToggle) return;
    // Don't hijack when the user is in a text field that handles its own
    // Ctrl+K (e.g. contenteditable editors) — Pulse doesn't have any yet,
    // so the simpler rule is: always open.
    e.preventDefault();
    if (_state.open) _close();
    else _open();
  });
}

// Exposed so a topbar button can open the palette without a keypress.
export function openCommandPalette() { _open(); }
