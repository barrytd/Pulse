// dashboard.js — Dashboard page + shared HTML builders + utilities.
// Shared utils (escapeHtml, attrEscape, formatBytes, scoreColor...) live
// here because dashboard is the primary consumer; other modules import
// them from this file.
'use strict';

import {
  fetchScans,
  fetchFindings,
  fetchRuleNames,
  apiDailyScores,
  apiExportUrl,
  invalidateScansCache,
  apiGetOnboarding,
  apiDismissOnboarding,
} from './api.js';
import {
  openFindingDrawer,
  _statusDotHtml,
  isTouched,
  isReviewed,
  isFalsePositive,
} from './findings.js';

// ---------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------

// Splunk-style dashboard filter state. Persisted in URL query params.
// `from`/`to` are YYYY-MM-DD strings used only when `time === 'custom'`.
export let dashFilterState = { time: 'today', sev: 'all', rule: 'all', source: 'all', q: '', from: '', to: '' };
let dashFiltersHydrated = false;

// MITRE lookup used by multiple pages.
export const mitreMap = {
  'Brute Force Attempt': 'T1110', 'Account Lockout': 'T1110',
  'User Account Created': 'T1136.001', 'Privilege Escalation': 'T1078.002',
  'Audit Log Cleared': 'T1070.001', 'RDP Logon Detected': 'T1021.001',
  'Pass-the-Hash Attempt': 'T1550.002', 'Service Installed': 'T1543.003',
  'Scheduled Task Created': 'T1053.005', 'Suspicious PowerShell': 'T1059.001',
  'Antivirus Disabled': 'T1562.001', 'Firewall Disabled': 'T1562.004',
  'Firewall Rule Changed': 'T1562.004', 'Account Takeover Chain': 'T1078',
  'Malware Persistence Chain': 'T1543.003',
  'Kerberoasting': 'T1558.003', 'Golden Ticket': 'T1558.001',
  'Credential Dumping': 'T1003.001', 'Logon from Disabled Account': 'T1078',
  'After-Hours Logon': 'T1078', 'Suspicious Registry Modification': 'T1547.001',
  'Lateral Movement via Network Share': 'T1021.002',
};

// Per-rule remediation lives server-side (pulse/remediation.py) and
// is attached to each finding as finding.remediation (array of step
// strings). See findings.js::_remediationBlock for the renderer.

// ---------------------------------------------------------------
// Shared utilities
// ---------------------------------------------------------------
export function scoreColor(score) {
  if (score == null) return '#8b949e';
  if (score >= 90) return '#27ae60';
  if (score >= 75) return '#3498db';
  if (score >= 50) return '#e67e22';
  if (score >= 25) return '#e74c3c';
  return '#8e44ad';
}

export function scoreColorClass(score) {
  if (score == null) return '';
  if (score >= 90) return 'score-secure';
  if (score >= 75) return 'score-low';
  if (score >= 50) return 'score-medium';
  return 'score-critical';
}

export function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

export function escapeHtml(str) {
  var div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// Centralized severity pill helper so every page renders the same
// colored badge. No icon — the text + color communicates severity.
export function sevPillHtml(sev) {
  var up = String(sev || 'LOW').toUpperCase();
  var lo = up.toLowerCase();
  return '<span class="pill pill-' + lo + '">' + up + '</span>';
}

// Compact role badge — single-letter (A=admin) or two-letter (An=analyst,
// Mg=manager) tag rendered next to the user's name. Tooltip expands to
// the full word so the visual reads at a glance but stays accessible.
// Treats the legacy 'viewer' value as 'analyst' so old API responses
// still render with the right badge during the rollout window.
export function roleBadgeHtml(role, extraCls) {
  var r = (role || '').toLowerCase();
  if (r === 'viewer') r = 'analyst';
  var letter, label;
  if (r === 'admin')        { letter = 'A';  label = 'Admin'; }
  else if (r === 'manager') { letter = 'Mg'; label = 'Manager'; }
  else if (r === 'analyst') { letter = 'An'; label = 'Analyst'; }
  else { return ''; }
  var cls = 'role-badge role-badge-' + r + (extraCls ? ' ' + extraCls : '');
  return '<span class="' + cls + '" title="' + label + '">' + letter + '</span>';
}

// HTML-attribute-safe escape — escapes quotes so the string can sit
// inside a double-quoted attribute value without breaking out.
export function attrEscape(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

export function _extractTime(f) {
  var m = (f.details || '').match(/(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})/);
  return m ? m[1] + ' ' + m[2] : '';
}

// Tracks whether a filter search box was focused right before a re-render.
var _searchFocusId = null;

// Call this JUST BEFORE an innerHTML rewrite destroys the search input, so we
// can tell "the user was mid-typing" (restore focus afterward) from "fresh
// page load / navigation" (do NOT focus — auto-focusing an empty box makes
// the browser autofill the saved login email into it).
export function _captureSearchFocus() {
  var a = document.activeElement;
  _searchFocusId = (a && a.classList &&
    (a.classList.contains('filter-bar-search') ||
     a.classList.contains('dash-filter-search') ||
     a.classList.contains('fw-search-input')))
    ? a.id : null;
}

// innerHTML rewrite destroys the old <input> node, so restore focus + caret —
// but only when the user was actually typing in it (see _captureSearchFocus).
export function _restoreSearchFocus(id) {
  if (_searchFocusId !== id) return;
  _searchFocusId = null;
  var el = document.getElementById(id);
  if (!el) return;
  el.removeAttribute('readonly');   // they're typing; keep it editable
  el.focus();
  var len = el.value.length;
  try { el.setSelectionRange(len, len); } catch (e) {}
}

// Letter-grade bands: [minimum score, grade], highest first; below the
// last band is F. Must match GRADE_BANDS in pulse/reports/reporter.py
// (the backend grades every stored score with it); tests/test_grade_bands.py
// fails if the two drift apart. Where the backend already returns a
// `grade`, render that instead of recomputing.
export const GRADE_BANDS = [[90, 'A'], [75, 'B'], [50, 'C'], [25, 'D']];

export function _gradeFor(score) {
  if (score == null) return '';
  for (var i = 0; i < GRADE_BANDS.length; i++) {
    if (score >= GRADE_BANDS[i][0]) return GRADE_BANDS[i][1];
  }
  return 'F';
}

export function _gradeRank(score) {
  var g = _gradeFor(score);
  return { A: 5, B: 4, C: 3, D: 2, F: 1 }[g] || 0;
}

// Short relative time — "just now" / "3m ago" / "2h ago" / "5d ago" /
// "Apr 21" (or "Apr 21, 2025" if the year isn't the current one).
// Accepts ISO strings (DB stores local time as "YYYY-MM-DD HH:MM:SS").
//
// The 7-day cutoff is the user-experience inflection: anything within
// the last week is "I remember roughly when that was"; older than that
// the absolute date carries more meaning than "47d ago".
export function formatRelativeTime(iso) {
  if (!iso) return '—';
  var d = new Date(String(iso).replace(' ', 'T'));
  if (isNaN(d.getTime())) return String(iso);
  var sec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (sec < 45)        return 'just now';
  if (sec < 3600)      return Math.floor(sec / 60)  + 'm ago';
  if (sec < 86400)     return Math.floor(sec / 3600) + 'h ago';
  if (sec < 86400 * 7) return Math.floor(sec / 86400) + 'd ago';
  // ≥ 7 days: absolute month-day. Include the year when it isn't the
  // current calendar year so an entry from 18 months ago doesn't read
  // ambiguously as "Apr 21".
  var now = new Date();
  var sameYear = (d.getFullYear() === now.getFullYear());
  var opts = sameYear
    ? { month: 'short', day: 'numeric' }
    : { month: 'short', day: 'numeric', year: 'numeric' };
  try { return d.toLocaleDateString(undefined, opts); }
  catch (e) { return d.toISOString().slice(0, 10); }
}

// Wrapped form for direct use in templates — returns a `<span>` with
// the absolute timestamp as a hover tooltip and the relative value as
// the visible text. Accepts the same input as `formatRelativeTime`.
//
// `extraClass` adds class names (e.g. for muted-styled cells) without
// callers having to escape the wrapper themselves. The visible text is
// always `formatRelativeTime`-ed and HTML-escaped; the title is the
// raw input string so it shows the local-time value the DB stored.
export function relTimeHtml(iso, extraClass) {
  if (!iso) return '<span class="rel-time">—</span>';
  var rel  = formatRelativeTime(iso);
  var cls  = 'rel-time' + (extraClass ? ' ' + extraClass : '');
  return '<span class="' + cls + '" title="' + attrEscape(iso) + '">' +
           escapeHtml(rel) +
         '</span>';
}

// Refresh ticker for the Dashboard "Last updated" timestamp. Recreated
// every render; cleared on nav teardown so we don't leak intervals.
let _dashUpdatedTimer = null;
let _dashUpdatedIso = null;

export function _stopDashUpdatedTimer() {
  if (_dashUpdatedTimer) {
    clearInterval(_dashUpdatedTimer);
    _dashUpdatedTimer = null;
  }
  _dashUpdatedIso = null;
}

function _startDashUpdatedTimer(iso) {
  _stopDashUpdatedTimer();
  _dashUpdatedIso = iso;
  if (!iso) return;
  _dashUpdatedTimer = setInterval(function () {
    var el = document.getElementById('dash-updated-ts');
    if (!el) { _stopDashUpdatedTimer(); return; }
    el.textContent = 'Last updated ' + formatRelativeTime(_dashUpdatedIso);
  }, 60000);
}

export function showToast(msg, kind) {
  var toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = msg;
  toast.className = 'toast show ' + (kind === 'error' ? 'error' : 'success');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(function () { toast.className = 'toast'; }, 2500);
}
export function toastError(msg) { showToast(msg, 'error'); }

export function downloadReport(scanId, target, e) {
  // When invoked via data-action, scanId is a string from data-arg and
  // the format lives on data-format on the same element. Fall back to
  // a legacy two-arg call shape (scanId, fmt) so direct callers keep
  // working.
  var fmt;
  if (target && target.dataset && target.dataset.format) {
    fmt = target.dataset.format;
    scanId = Number(scanId);
  } else {
    fmt = target; // legacy: downloadReport(scanId, 'html')
  }
  var url = apiExportUrl(scanId, fmt);
  var a = document.createElement('a');
  a.href = url;
  // No `a.download` — let the server's Content-Disposition decide the
  // filename so it reflects the display number ("pulse_scan_1.pdf"),
  // not the raw DB id.
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

// ---------------------------------------------------------------
// Shared HTML builders
// ---------------------------------------------------------------
export function statCard(label, value, sub, colorClass) {
  return '<div class="stat-card">' +
    '<div class="label">' + label + '</div>' +
    '<div class="value ' + (colorClass || '') + '">' + value + '</div>' +
    '<div class="sub">' + (sub || '') + '</div></div>';
}

// ---------------------------------------------------------------
// Dashboard filter bar helpers (Splunk-style)
// ---------------------------------------------------------------

// Hydrate dashFilterState from URL query params on first load so a
// pasted/bookmarked link restores the filtered view.
export function parseDashFiltersFromURL() {
  if (dashFiltersHydrated) return;
  dashFiltersHydrated = true;
  try {
    var qp = new URLSearchParams(window.location.search);
    var validTime = ['today', '7d', '30d', '90d', 'custom'];
    var validSev  = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    if (qp.has('time')   && validTime.indexOf(qp.get('time'))   >= 0) dashFilterState.time   = qp.get('time');
    if (qp.has('sev')    && validSev.indexOf(qp.get('sev'))     >= 0) dashFilterState.sev    = qp.get('sev');
    if (qp.has('rule'))   dashFilterState.rule   = qp.get('rule')   || 'all';
    if (qp.has('source')) dashFilterState.source = qp.get('source') || 'all';
    if (qp.has('q'))      dashFilterState.q      = qp.get('q')      || '';
    if (qp.has('from'))   dashFilterState.from   = qp.get('from')   || '';
    if (qp.has('to'))     dashFilterState.to     = qp.get('to')     || '';
  } catch (e) {}
}

// Push current filter state back to the URL bar.
export function writeDashFiltersToURL() {
  var qp = new URLSearchParams();
  var st = dashFilterState;
  if (st.time   !== 'today') qp.set('time',   st.time);
  if (st.sev    !== 'all')   qp.set('sev',    st.sev);
  if (st.rule   !== 'all')   qp.set('rule',   st.rule);
  if (st.source !== 'all')   qp.set('source', st.source);
  if (st.q)                  qp.set('q',      st.q);
  if (st.time === 'custom') {
    if (st.from) qp.set('from', st.from);
    if (st.to)   qp.set('to',   st.to);
  }
  var qs = qp.toString();
  var url = window.location.pathname + (qs ? '?' + qs : '') + window.location.hash;
  history.replaceState({}, '', url);
}

// Cutoff Date object for "scan.scanned_at >= cutoff". Legacy helper —
// still used by callers that only need the lower bound.
export function _dashTimeCutoff(range) {
  return _dashTimeRange(range, dashFilterState.from, dashFilterState.to).start;
}

// Returns { start, end } for the selected range. Open-ended where the
// user hasn't picked a bound (e.g. custom with only a From date set).
export function _dashTimeRange(range, from, to) {
  var now = new Date();
  var farFuture = new Date(now.getTime() + 365 * 86400000);
  if (range === 'custom') {
    var s = from ? new Date(from + 'T00:00:00') : new Date(0);
    var e = to   ? new Date(to   + 'T23:59:59') : farFuture;
    if (isNaN(s.getTime())) s = new Date(0);
    if (isNaN(e.getTime())) e = farFuture;
    return { start: s, end: e };
  }
  var start;
  if (range === 'today') { start = new Date(now); start.setHours(0, 0, 0, 0); }
  else if (range === '7d')  start = new Date(now.getTime() - 7  * 86400000);
  else if (range === '30d') start = new Date(now.getTime() - 30 * 86400000);
  else if (range === '90d') start = new Date(now.getTime() - 90 * 86400000);
  else start = new Date(0);
  return { start: start, end: farFuture };
}

// Parse "YYYY-MM-DD HH:MM:SS" (local) into a Date. Tolerant of ISO too.
// Date-only strings like "YYYY-MM-DD" must be parsed as LOCAL midnight
// rather than UTC — otherwise Today's daily-score entry gets bucketed
// into yesterday for anyone west of UTC.
export function _parseScanDate(s) {
  if (!s) return null;
  var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (m) return new Date(+m[1], +m[2] - 1, +m[3]);
  var iso = s.indexOf('T') >= 0 ? s : s.replace(' ', 'T');
  var d = new Date(iso);
  return isNaN(d.getTime()) ? null : d;
}

// Filter the scans list by Time Range + Source.
export function filterScansByDashState(scans) {
  var range = _dashTimeRange(dashFilterState.time, dashFilterState.from, dashFilterState.to);
  var src = dashFilterState.source;
  return scans.filter(function (s) {
    var d = _parseScanDate(s.scanned_at);
    if (!d || d < range.start || d > range.end) return false;
    if (src !== 'all') {
      var who = s.hostname || s.filename || '';
      if (who !== src) return false;
    }
    return true;
  });
}

// Filter a list of findings by the severity + rule + free-text filter.
export function filterFindingsByDashState(findings) {
  var sev  = dashFilterState.sev;
  var rule = dashFilterState.rule;
  var q    = (dashFilterState.q || '').trim().toLowerCase();
  return (findings || []).filter(function (f) {
    if (sev  !== 'all' && (f.severity || '').toUpperCase() !== sev) return false;
    if (rule !== 'all' && (f.rule || '') !== rule) return false;
    if (q) {
      var hay = ((f.rule || '') + ' ' +
                 (f.description || '') + ' ' +
                 (f.details || '') + ' ' +
                 (f.event_id || '') + ' ' +
                 (f.mitre || '')).toLowerCase();
      if (hay.indexOf(q) < 0) return false;
    }
    return true;
  });
}

// Daily-score objects from /api/score/daily have `.date` like "YYYY-MM-DD".
export function filterDailyByDashState(daily) {
  var range = _dashTimeRange(dashFilterState.time, dashFilterState.from, dashFilterState.to);
  return (daily || []).filter(function (d) {
    var dt = _parseScanDate(d.date);
    return dt && dt >= range.start && dt <= range.end;
  });
}

export function _dashFilterBarHtml(rules, sources) {
  var timeOpts = [
    { v: 'today',  l: 'Today' },
    { v: '7d',     l: 'Last 7 days' },
    { v: '30d',    l: 'Last 30 days' },
    { v: '90d',    l: 'Last 90 days' },
    { v: 'custom', l: 'Custom range' },
  ];
  var sevOpts = [
    { v: 'all',      l: 'All' },
    { v: 'CRITICAL', l: 'Critical' },
    { v: 'HIGH',     l: 'High' },
    { v: 'MEDIUM',   l: 'Medium' },
    { v: 'LOW',      l: 'Low' },
  ];
  function opts(list, cur) {
    return list.map(function (o) {
      return '<option value="' + escapeHtml(o.v) + '"' +
             (o.v === cur ? ' selected' : '') + '>' +
             escapeHtml(o.l) + '</option>';
    }).join('');
  }
  var ruleOpts   = [{ v: 'all', l: 'All rules' }].concat(
    (rules || []).map(function (r) { return { v: r, l: r }; }));
  var sourceOpts = [{ v: 'all', l: 'All sources' }].concat(
    (sources || []).map(function (s) { return { v: s, l: s }; }));
  var st = dashFilterState;

  // Custom range inputs only render when the Time Range dropdown is set
  // to Custom. Change events on the <input type="date"> re-trigger apply.
  var customHtml = (st.time === 'custom')
    ? '<div class="dash-filter-group">' +
        '<label class="dash-filter-label">From</label>' +
        '<input type="date" class="dash-filter-date" id="f-from" value="' + escapeHtml(st.from || '') + '" ' +
          'data-action-change="applyDashFilters" />' +
      '</div>' +
      '<div class="dash-filter-group">' +
        '<label class="dash-filter-label">To</label>' +
        '<input type="date" class="dash-filter-date" id="f-to" value="' + escapeHtml(st.to || '') + '" ' +
          'data-action-change="applyDashFilters" />' +
      '</div>'
    : '';

  return '<div class="dash-filter-bar">' +
    '<div class="dash-filter-group">' +
      '<label class="dash-filter-label">Time Range</label>' +
      '<select class="dash-filter-select" id="f-time" data-action-change="applyDashFilters">' +
        opts(timeOpts, st.time) + '</select>' +
    '</div>' +
    customHtml +
    '<div class="dash-filter-group">' +
      '<label class="dash-filter-label">Severity</label>' +
      '<select class="dash-filter-select" id="f-severity" data-action-change="applyDashFilters">' +
        opts(sevOpts, st.sev) + '</select>' +
    '</div>' +
    '<div class="dash-filter-group">' +
      '<label class="dash-filter-label">Rule</label>' +
      '<select class="dash-filter-select" id="f-rule" data-action-change="applyDashFilters">' +
        opts(ruleOpts, st.rule) + '</select>' +
    '</div>' +
    '<div class="dash-filter-group">' +
      '<label class="dash-filter-label">Source</label>' +
      '<select class="dash-filter-select" id="f-source" data-action-change="applyDashFilters">' +
        opts(sourceOpts, st.source) + '</select>' +
    '</div>' +
    '<div class="dash-filter-group" style="flex:1; min-width:200px;">' +
      '<label class="dash-filter-label">Search</label>' +
      '<input type="search" class="dash-filter-search" id="f-query" ' +
        'placeholder="user, IP, event ID..." value="' + escapeHtml(st.q || '') + '" ' +
        'autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" ' +
        'name="dash-search-nofill" data-lpignore="true" data-1p-ignore data-form-type="other" ' +
        'readonly data-nofill="1" ' +
        'data-action-keydown="dashFilterQueryKey" />' +
    '</div>' +
    '<a class="dash-filter-reset" data-action="resetDashFilters">Reset</a>' +
  '</div>';
}

// Wired via data-action-keydown on the search input. Apply filters on Enter.
export function dashFilterQueryKey(arg, target, e) {
  if (e && e.key === 'Enter') applyDashFilters();
}

export function applyDashFilters() {
  var t = document.getElementById('f-time');
  var s = document.getElementById('f-severity');
  var r = document.getElementById('f-rule');
  var src = document.getElementById('f-source');
  var q   = document.getElementById('f-query');
  var from = document.getElementById('f-from');
  var to   = document.getElementById('f-to');
  var st = dashFilterState;
  if (t)    st.time   = t.value;
  if (s)    st.sev    = s.value;
  if (r)    st.rule   = r.value;
  if (src)  st.source = src.value;
  if (q)    st.q      = (q.value || '').trim();
  if (from) st.from   = from.value || '';
  if (to)   st.to     = to.value   || '';
  writeDashFiltersToURL();
  renderDashboardPage();
}

export function resetDashFilters() {
  dashFilterState = { time: 'today', sev: 'all', rule: 'all', source: 'all', q: '', from: '', to: '' };
  writeDashFiltersToURL();
  renderDashboardPage();
}

export function _dashSources(scans) {
  var set = {};
  (scans || []).forEach(function (s) {
    var who = s.hostname || s.filename;
    if (who) set[who] = true;
  });
  return Object.keys(set).sort();
}

// True if any filter is non-default.
export function _dashFiltersActive() {
  var st = dashFilterState;
  return st.time !== 'today' ||
         st.sev  !== 'all'   ||
         st.rule !== 'all'   ||
         st.source !== 'all' ||
         !!st.q;
}

// ---------------------------------------------------------------
// Trend + stat card helpers
// ---------------------------------------------------------------
export function _trendFor(current, previous, opts) {
  if (current == null || previous == null) return null;
  var diff = current - previous;
  if (diff === 0) return { diff: 0, pct: 0, direction: 'flat', upIsGood: !!(opts && opts.upIsGood) };
  var pct = previous === 0
    ? (current > 0 ? 100 : 0)
    : Math.round((diff / previous) * 100);
  return {
    diff: diff,
    pct: pct,
    direction: diff > 0 ? 'up' : 'down',
    upIsGood: !!(opts && opts.upIsGood),
  };
}

export function _renderTrend(t) {
  if (!t) return '';
  if (t.direction === 'flat') return '<div class="trend flat">\u2014 no change</div>';
  var arrow = t.direction === 'up' ? '\u2191' : '\u2193';
  var cls;
  if (t.upIsGood) {
    cls = t.direction === 'up' ? 'trend up good' : 'trend down bad';
  } else {
    cls = 'trend ' + t.direction;
  }
  var sign = t.diff > 0 ? '+' : '';
  return '<div class="' + cls + '">' + arrow + ' ' + sign + t.diff +
         ' (' + Math.abs(t.pct) + '%)</div>';
}

export function _trendStatCard(label, value, sub, trend, accentClass, valueColorClass, statKind) {
  var kindAttr = statKind
    ? ' data-action="clickStatCard" data-arg="' + statKind + '" data-stat-kind="' + statKind + '" role="button" tabindex="0"'
    : '';
  return '<div class="stat-card ' + (accentClass || 'accent-neutral') +
         (statKind ? ' stat-card-clickable' : '') + '"' + kindAttr + '>' +
    '<div class="label">' + label + '</div>' +
    '<div class="value ' + (valueColorClass || '') + '">' + value + '</div>' +
    _renderTrend(trend) +
    (sub ? '<div class="sub">' + sub + '</div>' : '') +
  '</div>';
}

// Which stat card is currently selected on the dashboard. Persists the
// visual selection across re-renders within the same page load.
var _selectedStatKind = null;

export function clickStatCard(kind) {
  var cards = document.querySelectorAll('.stat-card[data-stat-kind]');
  cards.forEach(function (c) { c.classList.remove('selected'); });
  var target = null;
  cards.forEach(function (c) { if (c.dataset.statKind === kind) target = c; });
  if (target) target.classList.add('selected');
  _selectedStatKind = kind;

  if (kind === 'score') {
    var panel = document.querySelector('.today-security-score');
    if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    return;
  }
  import('./navigation.js').then(function (m) {
    if (kind === 'rules') m.navigateWithHistory('rules');
    else if (kind === 'findings') m.navigateWithHistory('findings');
    else if (kind === 'scans') m.navigateWithHistory('scans');
  });
}

export function _accentForScore(score) {
  if (score == null) return 'accent-neutral';
  if (score >= 90) return 'accent-neutral';
  if (score >= 75) return 'accent-info';
  if (score >= 50) return 'accent-high';
  return 'accent-critical';
}


// ---------------------------------------------------------------
// Dashboard building blocks (2026-09 redesign)
// ---------------------------------------------------------------
// Four zones, one hero: (1) score + "needs attention" list, (2) a
// 4-stat strip, (3) score history + findings by severity, with the
// data-reduction funnel folded into one line. Only those zone
// containers are cards; everything inside them is borderless.
// See docs/2026-09-26-dashboard-redesign.md.

// Grade -> color token. Grades come from the backend (today.grade).
var _GRADE_TONE = {
  A: 'var(--status-ok)',
  B: 'var(--severity-low)',
  C: 'var(--severity-medium)',
  D: 'var(--severity-high)',
  F: 'var(--severity-critical)',
};
var _GRADE_LEAD = {
  A: 'Looking healthy.',
  B: 'Mostly healthy.',
  C: 'Needs attention.',
  D: 'At risk.',
  F: 'Critical risk.',
};
var _SEV_KEY = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

// The knowledge base's plain-language sentence, unless it's the generic
// fallback (rules without an entry), whose boilerplate refers to a
// details section the dashboard doesn't show.
function _plainLanguage(f) {
  var k = (f && f.knowledge) || {};
  return k.generic ? '' : (k.plain_language || '').trim();
}

function _sevKey(f) {
  return _SEV_KEY[(f && f.severity || '').toUpperCase()] || 'low';
}

// Local YYYY-MM-DD. Scan timestamps are stored in local time.
function _localDay(d) {
  var dt = d || new Date();
  var m = dt.getMonth() + 1, day = dt.getDate();
  return dt.getFullYear() + '-' + (m < 10 ? '0' : '') + m + '-' + (day < 10 ? '0' : '') + day;
}

function _shortDate(ymd) {
  var d = new Date(ymd + 'T00:00:00');
  if (isNaN(d)) return ymd;
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function _compactNum(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
  if (n >= 1e4) return Math.round(n / 1e3) + 'K';
  if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'K';
  return String(n);
}

// --- Hero, left: the score --------------------------------------

function _scoreGaugeSvg(score, tone) {
  var r = 76, c = 2 * Math.PI * r;
  var fill = score == null ? 0 : Math.max(0, Math.min(100, score)) / 100;
  return '<svg class="dash-gauge-svg" viewBox="0 0 176 176" aria-hidden="true">' +
    '<circle cx="88" cy="88" r="' + r + '" class="dash-gauge-track"/>' +
    (fill > 0
      ? '<circle cx="88" cy="88" r="' + r + '" class="dash-gauge-fill" ' +
          'style="stroke:' + tone + '" stroke-dasharray="' + c.toFixed(1) + '" ' +
          'stroke-dashoffset="' + (c * (1 - fill)).toFixed(1) + '" transform="rotate(-90 88 88)"/>'
      : '') +
  '</svg>';
}

// One plain-language line saying what is wrong. Prefers the knowledge
// base's plain-language sentence for the most urgent open finding.
function _verdictHtml(grade, top, uniqueRules) {
  var lead = '<b>' + escapeHtml(_GRADE_LEAD[grade] || '') + '</b> ';
  if (top) {
    var what = _plainLanguage(top) ||
               ((top.rule || 'A finding') + ' was detected.');
    var host = top.hostname || top._scan_host || '';
    return lead + escapeHtml(what) +
      (host ? ' <span class="dash-verdict-host">' + escapeHtml(host) + '</span>' : '');
  }
  if (!uniqueRules) return lead + 'No detection rules fired in this window.';
  return lead + uniqueRules + ' rule' + (uniqueRules === 1 ? '' : 's') +
    ' fired in this window. Nothing critical or high is waiting for review.';
}

function _scoreTrendChip(today, prev) {
  if (!today || !prev) return '';
  var diff = today.score - prev.score;
  var yesterday = _localDay(new Date(Date.now() - 86400000));
  var since = prev.date === yesterday ? 'yesterday' : _shortDate(prev.date);
  if (diff === 0) {
    return '<span class="dash-chip flat">No change since ' + escapeHtml(since) + '</span>';
  }
  var down = diff < 0;
  return '<span class="dash-chip ' + (down ? 'bad' : 'good') + '">' +
    (down ? '▼ down ' : '▲ up ') + Math.abs(diff) + ' pt' +
    (Math.abs(diff) === 1 ? '' : 's') + ' since ' + escapeHtml(since) + '</span>';
}

function _heroScoreHtml(opts) {
  var today = opts.today;
  if (!today) {
    // Scans exist, just none in this window. Say what to do, not "0".
    var actions = opts.filtersOn
      ? '<button class="btn btn-primary" data-action="resetDashFilters">Reset filters</button>'
      : '<button class="btn btn-primary" data-action="openSystemScanModal">Scan my system</button>' +
        '<button class="btn" data-action="openUploadModal">Upload a log</button>';
    return '<div class="dash-card dash-score today-security-score">' +
      '<div class="dash-eyebrow">Security posture</div>' +
      '<div class="dash-gauge">' + _scoreGaugeSvg(null, '') +
        '<div class="dash-gauge-label"><span class="dash-gauge-empty">No scans</span></div>' +
      '</div>' +
      '<div class="dash-verdict">' +
        (opts.filtersOn ? 'No scans match these filters.' : 'No scans in this window yet.') +
        ' Run a scan to score it.' +
      '</div>' +
      '<div class="dash-score-actions">' + actions + '</div>' +
    '</div>';
  }
  var grade = today.grade || _gradeFor(today.score);
  var tone = _GRADE_TONE[grade] || 'var(--text-dim)';
  return '<div class="dash-card dash-score today-security-score">' +
    '<div class="dash-eyebrow">Security posture · ' + escapeHtml(opts.windowLabel) + '</div>' +
    '<div class="dash-gauge">' + _scoreGaugeSvg(today.score, tone) +
      '<div class="dash-gauge-label">' +
        '<span class="dash-grade-letter" style="color:' + tone + '">' + escapeHtml(grade) + '</span>' +
        '<span class="dash-grade-num mono">' + today.score + ' / 100</span>' +
      '</div>' +
    '</div>' +
    '<div class="dash-verdict">' + _verdictHtml(grade, opts.top, today.unique_rules) + '</div>' +
    _scoreTrendChip(today, opts.prev) +
  '</div>';
}

// --- Hero, right: needs attention --------------------------------
// Unreviewed CRITICAL/HIGH findings from the last 7 days across every
// scan, independent of the filter bar so outstanding items stay visible.
// When that list is empty, the newest findings of the latest scan show
// instead so the panel never reads as blank.

var _attentionFindings = []; // unreviewed crit/high, last 7 days
var _openFindings = [];      // every unreviewed finding, last 7 days
var _latestFindings = [];    // fallback list (latest scan, newest first)
var _heroList = [];          // what the hero list currently shows

async function _fetchRecentFindings(allScans, findingsFor) {
  var cutoff = Date.now() - 7 * 86400000;
  var recent = (allScans || []).filter(function (s) {
    if (!s.total_findings) return false;
    var t = Date.parse(String(s.scanned_at || '').replace(' ', 'T'));
    return !isNaN(t) && t >= cutoff;
  });
  var batches = await Promise.all(recent.map(function (s) {
    return findingsFor(s.id).then(function (fs) {
      return fs.map(function (f) {
        return Object.assign({}, f, {
          _scan_id:     s.id,
          _scan_number: s.number,
          _scan_date:   s.scanned_at,
          _scan_host:   s.hostname || s.filename || '',
        });
      });
    });
  }));
  var all = [];
  batches.forEach(function (b) { all = all.concat(b); });
  return all.filter(function (f) { return !isTouched(f); });
}

function _attentionFrom(open) {
  var list = open.filter(function (f) {
    var sv = (f.severity || '').toUpperCase();
    return sv === 'CRITICAL' || sv === 'HIGH';
  });
  // CRITICAL before HIGH, then newest first.
  list.sort(function (a, b) {
    var sa = (a.severity || '').toUpperCase() === 'CRITICAL' ? 0 : 1;
    var sb = (b.severity || '').toUpperCase() === 'CRITICAL' ? 0 : 1;
    if (sa !== sb) return sa - sb;
    var at = a.timestamp || _extractTime(a) || a._scan_date || '';
    var bt = b.timestamp || _extractTime(b) || b._scan_date || '';
    return at < bt ? 1 : at > bt ? -1 : 0;
  });
  return list;
}

function _heroRowHtml(f, i) {
  var sk = _sevKey(f);
  var host = f.hostname || f._scan_host || '';
  var time = f.timestamp || _extractTime(f) || f._scan_date || '';
  var sub = (_plainLanguage(f) || f.description || f.details || '').trim();
  var fidAttr = (f.id != null) ? ' data-finding-id="' + escapeHtml(String(f.id)) + '"' : '';
  return '<div class="dash-att-row"' + fidAttr + ' data-action="openAttentionFinding" ' +
         'data-arg="' + i + '" role="button" tabindex="0">' +
    '<span class="dash-stripe sev-' + sk + '"></span>' +
    '<div class="dash-att-main">' +
      '<div class="dash-att-title">' + escapeHtml(f.rule || 'Unknown') + '</div>' +
      '<div class="dash-att-meta">' +
        (host ? '<span class="mono">' + escapeHtml(host) + '</span>' : '') +
        (time ? relTimeHtml(time) : '') +
        (sub ? '<span class="dash-att-sub">' + escapeHtml(sub) + '</span>' : '') +
      '</div>' +
    '</div>' +
    '<span class="dash-sev sev-' + sk + '">' + escapeHtml((f.severity || 'LOW').toUpperCase()) + '</span>' +
  '</div>';
}

export function _needsAttentionHtml() {
  var att = _attentionFindings;
  var head, rows, more = '';
  if (att.length) {
    _heroList = att.slice(0, 5);
    var crit = att.filter(function (f) { return _sevKey(f) === 'critical'; }).length;
    var high = att.length - crit;
    var parts = [];
    if (crit) parts.push(crit + ' critical');
    if (high) parts.push(high + ' high');
    head = parts.join(', ') + ', unreviewed';
    if (att.length > 5) {
      more = '<a class="dash-link dash-att-more" data-action="openUnreviewedCriticalHigh">' +
        '+ ' + (att.length - 5) + ' more →</a>';
    }
  } else {
    _heroList = _latestFindings.slice(0, 3);
    head = 'Nothing critical or high to review';
  }
  rows = _heroList.map(_heroRowHtml).join('');
  var sub = att.length
    ? 'Most urgent first · last 7 days'
    : (_heroList.length ? 'Newest findings from the latest scan' : 'No findings in the last 7 days');
  return '<div class="dash-att-head">' +
      '<div>' +
        '<div class="dash-eyebrow">Needs attention</div>' +
        '<h3 class="dash-att-heading">' + escapeHtml(head) + '</h3>' +
        '<div class="dash-sublabel">' + sub + '</div>' +
      '</div>' +
      '<a class="dash-link" data-action="' + (att.length ? 'openUnreviewedCriticalHigh' : 'navigate') +
        '" data-arg="findings">All findings →</a>' +
    '</div>' +
    (rows
      ? '<div class="dash-att-list">' + rows + '</div>'
      : '<div class="dash-att-clear">' +
          '<span class="dash-att-clear-dot"></span>' +
          'All clear. Nothing new has been detected in the last week.' +
        '</div>') +
    more;
}

export function openAttentionFinding(idx) {
  var f = _heroList[Number(idx)];
  if (f) openFindingDrawer(f);
}

// Kept for the app.js action table; the dashboard's finding rows all
// go through the hero list now.
export function openFindingDrawerByIdx(idx) {
  openAttentionFinding(idx);
}

// In-place refresh after a review toggle so the list and the two
// finding stats stay accurate without rebuilding the whole dashboard.
function _refreshNeedsAttentionFromCache() {
  _openFindings = _openFindings.filter(function (f) { return !isTouched(f); });
  _attentionFindings = _attentionFrom(_openFindings);
  var mount = document.getElementById('dash-needs-attention');
  if (mount) mount.innerHTML = _needsAttentionHtml();
  var stats = document.getElementById('dash-stats');
  if (stats) stats.outerHTML = _statStripHtml(_lastStatCtx);
}

function _onReviewToggled(ev) {
  if (!ev || !ev.detail) return;
  var id = ev.detail.id;
  var changed = false;
  _openFindings.forEach(function (f) {
    if (f.id != null && String(f.id) === String(id)) {
      f.reviewed = !!ev.detail.reviewed;
      f.false_positive = !!ev.detail.false_positive;
      changed = true;
    }
  });
  if (changed) _refreshNeedsAttentionFromCache();
}
document.addEventListener('pulse:review-toggled', _onReviewToggled);

// --- Stat strip ---------------------------------------------------

var _lastStatCtx = null;

function _statHtml(label, valueHtml, sub, subTone, attrs) {
  return '<div class="dash-stat"' + (attrs || '') + '>' +
    '<div class="dash-stat-k">' + label + '</div>' +
    '<div class="dash-stat-v mono">' + valueHtml + '</div>' +
    '<div class="dash-stat-d ' + (subTone || 'flat') + '">' + sub + '</div>' +
  '</div>';
}

function _statStripHtml(ctx) {
  _lastStatCtx = ctx;
  var today = _localDay();
  var open = _openFindings.length;
  var newToday = _openFindings.filter(function (f) {
    return String(f._scan_date || '').slice(0, 10) === today;
  }).length;
  var crit = _attentionFindings.filter(function (f) { return _sevKey(f) === 'critical'; }).length;
  var scansToday = ctx.allScans.filter(function (s) {
    return String(s.scanned_at || '').slice(0, 10) === today;
  });
  var mttd = _computeMTTDSeconds(_openFindings);
  var mttdHtml = '—';
  if (mttd != null) {
    var m = /^([\d.]+)(\D+)$/.exec(_formatDuration(mttd));
    var units = { s: ' sec', m: ' min', h: ' hr', d: ' days' };
    mttdHtml = m ? m[1] + '<small>' + (units[m[2]] || m[2]) + '</small>' : _formatDuration(mttd);
  }
  var clickable = function (kind) {
    return ' data-action="clickStatCard" data-arg="' + kind + '" data-stat-kind="' + kind +
           '" role="button" tabindex="0"';
  };
  return '<div class="dash-card dash-stats" id="dash-stats">' +
    _statHtml('Open findings', String(open),
      newToday ? '▲ ' + newToday + ' new today' : (open ? 'none new today' : 'nothing open'),
      newToday ? 'bad' : 'flat', clickable('findings')) +
    _statHtml('Critical, unreviewed',
      '<span' + (crit ? ' class="dash-stat-crit"' : '') + '>' + crit + '</span>',
      crit ? 'needs action now' : 'none waiting', crit ? 'bad' : 'good',
      ' data-action="openUnreviewedCriticalHigh" role="button" tabindex="0"') +
    _statHtml('Scans today', String(scansToday.length),
      scansToday.length ? 'last one ' + escapeHtml(formatRelativeTime(scansToday[0].scanned_at)) : 'none yet today',
      'flat', clickable('scans')) +
    _statHtml('Mean time to detect', mttdHtml,
      mttd == null ? 'needs timestamped findings' : 'event to detection, 7 days', 'flat') +
  '</div>';
}

// --- Row 3: score history + severity -----------------------------

function _historyPanelHtml(dailyScores, filtersOn) {
  var bLine = GRADE_BANDS[1][0];
  var body;
  if (!dailyScores.length) {
    body = '<div class="dash-panel-empty">' +
      (filtersOn
        ? 'No scores in this window. <a class="dash-link" data-action="resetDashFilters">Reset filters</a>'
        : 'Your score history starts with the first scan in this window.') +
    '</div>';
  } else {
    body = '<div class="dash-chart-wrap"><canvas id="score-line-chart"></canvas></div>';
  }
  var sub = dailyScores.length === 1
    ? 'One day so far · the line fills in as you scan on more days'
    : 'Daily posture · dashed line is the B grade (' + bLine + ')';
  return '<div class="dash-card dash-panel">' +
    '<div class="dash-panel-head">' +
      '<div><h3>Score history</h3><div class="dash-sublabel">' + sub + '</div></div>' +
      '<a class="dash-link" data-action="navigate" data-arg="history">Full history →</a>' +
    '</div>' +
    body +
  '</div>';
}

function _severityPanelHtml(windowFindings, scans) {
  var counts = { critical: 0, high: 0, medium: 0, low: 0 };
  windowFindings.forEach(function (f) { counts[_sevKey(f)]++; });
  var total = windowFindings.length;
  var events = 0;
  scans.forEach(function (s) { events += (s.total_events || 0); });

  var names = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  var order = ['critical', 'high', 'medium', 'low'];
  var body;
  if (!total) {
    // The sublabel already says whether anything was scanned; only add a
    // line when scans ran and came back clean.
    body = scans.length ? '<div class="dash-panel-empty">No findings in this window.</div>' : '';
  } else {
    body =
      '<div class="dash-sevbar" role="img" aria-label="' +
        order.map(function (k) { return counts[k] + ' ' + names[k]; }).join(', ') + '">' +
        order.filter(function (k) { return counts[k]; }).map(function (k) {
          return '<span class="sev-' + k + '" style="flex:' + counts[k] + '" ' +
                 'title="' + names[k] + ' · ' + counts[k] + '"></span>';
        }).join('') +
      '</div>' +
      '<div class="dash-sevkey">' +
        order.map(function (k) {
          return '<div class="dash-sevkey-row">' +
            '<span class="dash-sevkey-dot sev-' + k + '"></span>' +
            '<span class="dash-sevkey-lab">' + names[k] + '</span>' +
            '<span class="dash-sevkey-num mono">' + counts[k] + '</span>' +
          '</div>';
        }).join('') +
      '</div>';
  }
  // The old four-box data-reduction funnel, as one line.
  var funnel = total
    ? '<span class="mono">' + _compactNum(events) + '</span> events → ' +
      '<span class="mono">' + _compactNum(total) + '</span> findings → ' +
      '<span class="mono dash-stat-crit">' + counts.critical + '</span> critical'
    : (scans.length ? _compactNum(events) + ' events scanned in this window' : 'Nothing scanned in this window');
  return '<div class="dash-card dash-panel">' +
    '<h3>Findings by severity</h3>' +
    '<div class="dash-sublabel">' + funnel + '</div>' +
    body +
    '<div class="dash-eyebrow dash-offenders-label">Repeat offenders</div>' +
    _offendersHtml(scans) +
  '</div>';
}

// Top hosts by finding count in the filtered window.
function _offendersHtml(scans) {
  var agg = {};
  scans.forEach(function (s) {
    var host = s.hostname || s.filename || 'unknown';
    if (!agg[host]) agg[host] = { count: 0, last: '' };
    agg[host].count += (s.total_findings || 0);
    var ts = s.scanned_at || '';
    if (ts > agg[host].last) agg[host].last = ts;
  });
  var rows = Object.keys(agg).map(function (h) {
    return { host: h, count: agg[h].count, last: agg[h].last };
  }).filter(function (r) { return r.count > 0; })
    .sort(function (a, b) { return b.count - a.count; })
    .slice(0, 3);
  if (!rows.length) {
    return '<div class="dash-panel-empty dash-panel-empty-sm">No host activity in this window.</div>';
  }
  return '<div class="dash-offenders">' + rows.map(function (r, i) {
    return '<div class="dash-off-row">' +
      '<span class="dash-off-host mono">' + escapeHtml(r.host) + '</span>' +
      '<span class="dash-off-last">' + relTimeHtml(r.last) + '</span>' +
      '<span class="dash-off-ct' + (i === 0 ? ' top' : '') + '">' +
        r.count + ' finding' + (r.count === 1 ? '' : 's') + '</span>' +
    '</div>';
  }).join('') + '</div>';
}

// Mean time to detect — average delta between each finding's event
// timestamp and when the scan that surfaced it actually ran. Lower is
// better. Operates on findings that know their parent scan's scanned_at
// (inline `.scanned_at` or the hoisted `._scan_date`). Returns seconds,
// or null when there's nothing to compute from.
export function _computeMTTDSeconds(findings) {
  if (!Array.isArray(findings) || !findings.length) return null;
  var total = 0, n = 0;
  findings.forEach(function (f) {
    var evt = Date.parse(String(f.timestamp || _extractTime(f) || '').replace(' ', 'T'));
    var scanIso = f._scan_date || f.scanned_at || '';
    var scan = Date.parse(String(scanIso).replace(' ', 'T'));
    if (isNaN(evt) || isNaN(scan)) return;
    var delta = (scan - evt) / 1000;
    if (delta < 0) return;
    total += delta;
    n++;
  });
  return n ? (total / n) : null;
}

// Human-readable compact time: "42s", "7m", "3.2h", "1.5d".
export function _formatDuration(seconds) {
  if (seconds == null) return '—';
  if (seconds < 60)    return Math.round(seconds) + 's';
  if (seconds < 3600)  return Math.round(seconds / 60) + 'm';
  if (seconds < 86400) return (seconds / 3600).toFixed(1).replace(/\.0$/, '') + 'h';
  return (seconds / 86400).toFixed(1).replace(/\.0$/, '') + 'd';
}

// ---------------------------------------------------------------
// Score-over-time chart: one area line, faint grid, B-grade line.
// Canvas can't read CSS variables, so colors are resolved from the
// current theme's tokens at render time.
// ---------------------------------------------------------------
let _scoreChartInstance = null;

export function _initScoreLineChart(dailyScores) {
  if (typeof Chart === 'undefined') return;
  var canvas = document.getElementById('score-line-chart');
  if (!canvas) return;

  // Oldest -> newest (Chart.js plots left to right).
  var series = dailyScores.slice().reverse();
  var labels = series.map(function (d) { return _shortDate(d.date); });
  var scores = series.map(function (d) { return d.score; });

  var styles = getComputedStyle(document.documentElement);
  var tok = function (name, fallback) { return styles.getPropertyValue(name).trim() || fallback; };
  var brand = tok('--brand', '#12b981');
  var dim   = tok('--text-dim', '#8b949e');
  var grid  = tok('--bg-4', '#eaeef2');
  var surface = tok('--bg-1', '#ffffff');
  var bLine = GRADE_BANDS[1][0];

  if (_scoreChartInstance) { _scoreChartInstance.destroy(); }

  // Dashed B-grade reference line. Inline plugin so it doesn't leak
  // into other charts on the page.
  var bGradeLine = {
    id: 'bGradeLine',
    afterDatasetsDraw: function (chart) {
      var y = chart.scales.y, x = chart.scales.x;
      if (!y || !x) return;
      var py = y.getPixelForValue(bLine);
      var ctx = chart.ctx;
      ctx.save();
      ctx.strokeStyle = dim;
      ctx.setLineDash([4, 4]);
      ctx.lineWidth = 1.25;
      ctx.beginPath();
      ctx.moveTo(x.left, py);
      ctx.lineTo(x.right, py);
      ctx.stroke();
      ctx.restore();
    }
  };

  _scoreChartInstance = new Chart(canvas.getContext('2d'), {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        data: scores,
        borderColor: brand,
        backgroundColor: function (context) {
          var area = context.chart.chartArea;
          if (!area) return 'transparent';
          var g = context.chart.ctx.createLinearGradient(0, area.top, 0, area.bottom);
          g.addColorStop(0, brand + '47');
          g.addColorStop(1, brand + '00');
          return g;
        },
        borderWidth: 2.5,
        fill: true,
        tension: 0.3,
        pointRadius: function (ctx) { return ctx.dataIndex === scores.length - 1 ? 4.5 : 0; },
        pointHoverRadius: 5,
        pointBackgroundColor: brand,
        pointBorderColor: surface,
        pointBorderWidth: 2,
        clip: false,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      layout: { padding: { top: 6, right: 8, bottom: 2, left: 2 } },
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          displayColors: false,
          callbacks: {
            label: function (item) {
              return item.parsed.y + ' / 100 · grade ' + _gradeFor(item.parsed.y);
            },
          },
        },
      },
      scales: {
        x: {
          // One day of history: center the lone point instead of pinning it
          // to the left edge.
          offset: scores.length === 1,
          ticks: { color: dim, font: { size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 7 },
          grid:  { display: false },
          border: { display: false },
        },
        y: {
          min: 0, max: 100,
          ticks: { color: dim, font: { size: 10 }, stepSize: 25 },
          grid:  { color: grid, drawTicks: false },
          border: { display: false },
        }
      }
    },
    plugins: [bGradeLine],
  });
}

// ---------------------------------------------------------------
// PAGE: Dashboard
// ---------------------------------------------------------------
// ---------------------------------------------------------------
// Team Workload — manager oversight card
// ---------------------------------------------------------------
// One row per active analyst: open (unresolved assigned) count, a
// severity mini-bar, avg time-to-resolve, and oldest-unresolved age.
// Busiest analyst first. Clicking a row deep-links to that analyst's
// findings (Findings page filtered by assignee).

async function _fetchTeamWorkload() {
  var r = await fetch('/api/team-workload');
  if (!r.ok) return null;          // 403 for analysts -> card hidden
  var data = await r.json();
  return (data && data.analysts) || [];
}

// Compact "Nh" / "Nd" age label from a float hour count.
function _fmtAge(hours) {
  if (hours == null) return '—';
  if (hours < 1) return '<1h';
  if (hours < 48) return Math.round(hours) + 'h';
  return Math.round(hours / 24) + 'd';
}

// A four-segment severity bar (crit/high/med/low) scaled to the row's open
// count. Zero-width segments collapse cleanly.
function _sevBarHtml(mix, total) {
  if (!total) return '<div class="tw-sevbar tw-sevbar-empty"></div>';
  var order = [['CRITICAL', 'crit'], ['HIGH', 'high'], ['MEDIUM', 'med'], ['LOW', 'low']];
  var segs = order.map(function (o) {
    var n = mix[o[0]] || 0;
    if (!n) return '';
    var pct = (n / total) * 100;
    return '<span class="tw-seg tw-seg-' + o[1] + '" style="width:' + pct + '%;" ' +
           'title="' + n + ' ' + o[0].toLowerCase() + '"></span>';
  }).join('');
  return '<div class="tw-sevbar">' + segs + '</div>';
}

function _teamWorkloadCardHtml(analysts) {
  // Hide entirely when there's nothing to oversee (solo account, or an
  // analyst who got a 403). Only show people who have open work OR exist
  // as analysts — we render everyone returned so a manager can see who's
  // idle too, but suppress the whole card if the list is empty.
  if (!analysts || !analysts.length) return '';

  var rows = analysts.map(function (a) {
    var initials = (a.display_name || '?').trim().charAt(0).toUpperCase() || '?';
    var overdueCls = (a.oldest_hours != null && a.oldest_hours > 72) ? ' tw-stale' : '';
    return '<div class="tw-row" data-action="viewAnalystQueue" data-arg="' + a.user_id + '" ' +
        'role="button" tabindex="0" title="View ' + escapeHtml(a.display_name) + '’s findings">' +
      '<div class="tw-avatar">' + escapeHtml(initials) + '</div>' +
      '<div class="tw-who">' +
        '<div class="tw-name">' + escapeHtml(a.display_name) + roleBadgeHtml(a.role) + '</div>' +
        '<div class="tw-sub">' + _sevBarHtml(a.by_severity || {}, a.open_count) + '</div>' +
      '</div>' +
      '<div class="tw-stat"><div class="tw-stat-num">' + (a.open_count || 0) + '</div>' +
        '<div class="tw-stat-lbl">open</div></div>' +
      '<div class="tw-stat"><div class="tw-stat-num' + overdueCls + '">' +
        _fmtAge(a.oldest_hours) + '</div><div class="tw-stat-lbl">oldest</div></div>' +
      '<div class="tw-stat"><div class="tw-stat-num">' +
        (a.avg_resolve_hours != null ? _fmtAge(a.avg_resolve_hours) : '—') +
        '</div><div class="tw-stat-lbl">avg fix</div></div>' +
    '</div>';
  }).join('');

  return '<div class="card tw-card">' +
    '<div class="section-label">Team Workload' +
      '<span style="color:var(--text-muted); font-weight:400; margin-left:8px; font-size:11px;">' +
      analysts.length + ' analyst' + (analysts.length === 1 ? '' : 's') + '</span></div>' +
    '<div class="tw-rows">' + rows + '</div>' +
  '</div>';
}

// Dedicated "Team" page (manager/admin) — the Team Workload oversight view,
// moved off the Dashboard where it felt out of place. Backend already 403s
// analysts on /api/team-workload, and the sidebar hides the nav item for
// them (roles.js PAGE_MIN_ROLE.team = 'manager').
export async function renderTeamPage() {
  var c = document.getElementById('content');
  if (!c) return;
  c.innerHTML = '<div class="card"><div class="section-label">Team Workload</div>' +
    '<p style="color:var(--text-muted); margin:8px 0 0;">Loading the team…</p></div>';

  var analysts = null;
  try { analysts = await _fetchTeamWorkload(); } catch (e) { analysts = null; }

  if (analysts === null) {
    c.innerHTML = '<div class="card"><div class="section-label">Team Workload</div>' +
      '<p style="color:var(--text-muted); margin:8px 0 0;">You don’t have access to the ' +
      'team view. This page is for managers and admins.</p></div>';
    return;
  }
  if (!analysts.length) {
    c.innerHTML = '<div class="card"><div class="section-label">Team Workload</div>' +
      '<p style="color:var(--text-muted); margin:8px 0 0;">No analysts have assigned ' +
      'work yet. Assign findings from the Findings page and they’ll show up here.</p></div>';
    return;
  }
  c.innerHTML = _teamWorkloadCardHtml(analysts);
}

// Deep-link to an analyst's findings. Lazy-import navigation.js to avoid a
// module cycle (navigation.js imports this module).
export function viewAnalystQueue(userId) {
  if (!userId) return;
  window.history.replaceState(null, '', '/findings?assignee=' + encodeURIComponent(userId));
  import('./navigation.js').then(function (m) { m.navigate('findings'); });
}

export async function renderDashboardPage() {
  var c = document.getElementById('content');
  parseDashFiltersFromURL();

  // Bump fetch ceiling so 30/90-day filters have data to slice.
  invalidateScansCache();
  var allScans = await fetchScans(200);

  // Brand-new account: the whole dashboard is one call to action. No
  // gray zeros, no empty charts, no filter bar with nothing to filter.
  if (!allScans.length) {
    _stopDashUpdatedTimer();
    c.innerHTML = '<div class="dash-page">' + _firstRunHeroHtml() + '</div>';
    return;
  }

  var rules    = await fetchRuleNames();
  var dailyResp = await apiDailyScores(90);
  var allDaily  = dailyResp.daily_scores || [];

  // Onboarding checklist — best-effort fetch. Failure leaves the card
  // hidden; everything else on the page still renders.
  try {
    _onboardingState = await apiGetOnboarding();
  } catch (e) {
    _onboardingState = null;
  }

  var scans       = filterScansByDashState(allScans);
  var dailyScores = filterDailyByDashState(allDaily);
  var sourceList  = _dashSources(allScans);
  var filtersOn   = _dashFiltersActive();
  var today = dailyScores[0];

  // One fetch per scan per render, shared by every zone below.
  var cache = {};
  var findingsFor = function (id) {
    if (!cache[id]) cache[id] = fetchFindings(id).catch(function () { return []; });
    return cache[id];
  };

  // Findings in the filter window (severity bar + funnel line). Capped
  // so a 90-day window on a busy install stays one screenful of fetches.
  var windowScans = scans.filter(function (s) { return s.total_findings > 0; }).slice(0, 40);
  var windowBatches = await Promise.all(windowScans.map(function (s) { return findingsFor(s.id); }));
  var windowFindings = [];
  windowBatches.forEach(function (b) { windowFindings = windowFindings.concat(b); });
  windowFindings = filterFindingsByDashState(windowFindings);

  // Needs attention + the two finding stats use a fixed 7-day window
  // across every scan, independent of the filter bar.
  _openFindings = await _fetchRecentFindings(allScans, findingsFor);
  _attentionFindings = _attentionFrom(_openFindings);
  _latestFindings = [];
  var latestWithFindings = scans.find(function (s) { return s.total_findings > 0; });
  if (latestWithFindings) {
    var latest = await findingsFor(latestWithFindings.id);
    _latestFindings = filterFindingsByDashState(latest).slice().sort(function (a, b) {
      var at = a.timestamp || _extractTime(a) || '';
      var bt = b.timestamp || _extractTime(b) || '';
      return at < bt ? 1 : at > bt ? -1 : 0;
    });
  }

  var windowLabels = { today: 'today', '24h': 'last 24 hours', '7d': 'last 7 days',
                       '30d': 'last 30 days', '90d': 'last 90 days', all: 'all time', custom: 'custom range' };
  var windowLabel = windowLabels[dashFilterState.time] || 'this window';

  // "Last updated" reflects the newest scan overall, not the filter slice.
  var updatedIso = allScans[0].scanned_at || '';
  var dashMetaHtml =
    '<div class="dash-meta-row">' +
      '<span class="dash-updated" id="dash-updated-ts">' +
        escapeHtml('Last updated ' + formatRelativeTime(updatedIso)) + '</span>' +
    '</div>';

  var heroHtml =
    '<div class="dash-hero">' +
      _heroScoreHtml({
        today: today, prev: dailyScores[1], top: _attentionFindings[0],
        windowLabel: windowLabel, filtersOn: filtersOn,
      }) +
      '<div class="dash-card dash-attention" id="dash-needs-attention">' +
        _needsAttentionHtml() +
      '</div>' +
    '</div>';

  var rowHtml =
    '<div class="dash-row">' +
      _historyPanelHtml(dailyScores, filtersOn) +
      _severityPanelHtml(windowFindings, scans) +
    '</div>';

  c.innerHTML =
    '<div class="dash-page">' +
      dashMetaHtml +
      _dashFilterBarHtml(rules, sourceList) +
      heroHtml +
      _statStripHtml({ allScans: allScans }) +
      rowHtml +
      _onboardingCardHtml(_onboardingState) +
    '</div>';

  _initScoreLineChart(dailyScores);
  _startDashUpdatedTimer(updatedIso);
}

// ---------------------------------------------------------------
// Getting Started checklist — Dashboard onboarding card
// ---------------------------------------------------------------
//
// Five-step path the user walks the first few times they sign in. Card
// hides once every step is complete OR the user clicks Dismiss (which
// stamps `users.onboarding_dismissed_at`). Each uncompleted step is a
// link straight to the relevant page so the user can act, return, and
// see the row tick. Completed steps are inert with a green checkmark.
//
// The five items (kept in this order in the UI):
//   1) Upload your first .evtx        -> /history (where Upload now lives)
//   2) Review a finding               -> /findings (drawer-open marks done)
//   3) Set up email alerts            -> /settings#notifications
//   4) Invite a team member           -> /settings#users
//   5) Configure your first whitelist -> /whitelist

const ONBOARDING_STEPS = [
  {
    key:   'scans',
    title: 'Upload your first .evtx file',
    page:  'history',
  },
  {
    key:   'finding_viewed',
    title: 'Review a finding',
    page:  'findings',
  },
  {
    key:   'smtp',
    title: 'Set up email alerts',
    page:  'settings',
    tab:   'notifications',
  },
  {
    key:   'users',
    title: 'Invite a team member',
    page:  'settings',
    tab:   'users',
  },
  {
    key:   'whitelist',
    title: 'Configure your first whitelist entry',
    page:  'whitelist',
  },
];

// First-run hero — shown only when the user has never run a scan. A
// brand-new account opens to an empty dashboard, which reads as "broken"
// rather than "new". This replaces that void with one clear next step:
// run your first scan. Once any scan exists, this never shows again and
// the normal dashboard (plus the Getting Started checklist) takes over.
function _firstRunHeroHtml() {
  return '<div class="dash-card dash-firstrun">' +
    '<div class="dash-firstrun-gauge" aria-hidden="true">' +
      _scoreGaugeSvg(null, '') +
      '<div class="dash-gauge-label"><span class="dash-firstrun-q">?</span></div>' +
    '</div>' +
    '<div class="dash-firstrun-body">' +
      '<div class="dash-eyebrow">Security posture</div>' +
      '<h2 class="dash-firstrun-title">Run your first scan</h2>' +
      '<p class="dash-firstrun-sub">' +
        'Pulse hasn’t analyzed any logs yet, so there’s no score to show. ' +
        'Scan this computer or upload a Windows <span class="mono">.evtx</span> log, and ' +
        'this page fills in with your A–F grade, the findings that need attention, ' +
        'and what to do about each one.' +
      '</p>' +
      '<div class="dash-score-actions">' +
        '<button class="btn btn-primary" data-action="openSystemScanModal">Scan my system</button>' +
        '<button class="btn" data-action="openUploadModal">Upload a .evtx log</button>' +
      '</div>' +
      '<div class="dash-firstrun-hint">' +
        'No log handy? Upload any file from the <span class="mono">samples/</span> ' +
        'folder to see a fully populated dashboard.' +
      '</div>' +
    '</div>' +
  '</div>';
}

function _onboardingCardHtml(state) {
  if (!state || state.dismissed) return '';
  var complete = state.complete || {};
  var doneCount = ONBOARDING_STEPS.reduce(function (n, s) {
    return n + (complete[s.key] ? 1 : 0);
  }, 0);
  // Only render when there's still something for the user to do — once
  // all five tick the card disappears on the next render.
  if (doneCount >= ONBOARDING_STEPS.length) return '';

  var pct = Math.round((doneCount / ONBOARDING_STEPS.length) * 100);
  var rows = ONBOARDING_STEPS.map(function (step) {
    var done = !!complete[step.key];
    var rowCls = 'onboard-step' + (done ? ' is-done' : '');
    var icon = done
      // Filled green check.
      ? '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" ' +
          'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ' +
          'aria-hidden="true">' +
          '<circle cx="8" cy="8" r="7" fill="currentColor" stroke="none"/>' +
          '<polyline points="4.5,8 7,10.5 11.5,5.5" stroke="#0d1117"/>' +
        '</svg>'
      // Empty ring.
      : '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" ' +
          'stroke-width="1.5" aria-hidden="true">' +
          '<circle cx="8" cy="8" r="6.5"/>' +
        '</svg>';
    var label;
    if (done) {
      label = '<span class="onboard-step-label">' + escapeHtml(step.title) + '</span>';
    } else {
      // Clickable for uncompleted steps. The settings tab is encoded in
      // data-arg so the click runs through the existing navigate action
      // and the Settings page reads ?tab=… on render.
      var arg = step.tab
        ? (step.page + ':' + step.tab)
        : step.page;
      label = '<a class="onboard-step-link" ' +
                'data-action="navigateOnboarding" data-arg="' + escapeHtml(arg) + '">' +
                escapeHtml(step.title) +
              '</a>';
    }
    return '<li class="' + rowCls + '">' +
      '<span class="onboard-step-icon" aria-hidden="true">' + icon + '</span>' +
      label +
    '</li>';
  }).join('');

  return '<div class="card onboard-card">' +
    '<div class="onboard-head">' +
      '<div class="onboard-head-text">' +
        '<div class="onboard-title">Getting started</div>' +
        '<div class="onboard-progress-line">' +
          '<strong>' + doneCount + ' of ' + ONBOARDING_STEPS.length + '</strong> complete' +
        '</div>' +
      '</div>' +
      '<a class="onboard-dismiss" data-action="dismissOnboarding">Dismiss</a>' +
    '</div>' +
    '<div class="onboard-progress-bar" role="progressbar" ' +
        'aria-valuemin="0" aria-valuemax="100" aria-valuenow="' + pct + '">' +
      '<span class="onboard-progress-fill" style="width:' + pct + '%;"></span>' +
    '</div>' +
    '<ul class="onboard-list">' + rows + '</ul>' +
  '</div>';
}

// Module-level cache of the latest onboarding state. Lets the Dismiss
// click swap to "dismissed" without an extra round trip. Cleared on
// every full Dashboard render (see renderDashboardPage).
let _onboardingState = null;

export async function dismissOnboarding() {
  if (_onboardingState) _onboardingState.dismissed = true;
  // Optimistic — re-render now, then fire the POST.
  var card = document.querySelector('.onboard-card');
  if (card && card.parentElement) card.parentElement.removeChild(card);
  apiDismissOnboarding();
}

// Click handler for an onboarding row — accepts "page" or "page:tab"
// in data-arg. The Settings tab name is plumbed through query string;
// the rest just navigate to the page directly.
export function navigateOnboarding(arg) {
  var raw = String(arg || '');
  var parts = raw.split(':');
  var page = parts[0];
  if (!page) return;
  // Lazy-import navigation to avoid a circular module load between
  // dashboard.js and navigation.js (navigation already imports from
  // dashboard for its renderer dispatch).
  import('./navigation.js').then(function (m) {
    // "settings:notifications" style targets deep-link straight to the tab.
    m.navigate(page, { tab: parts[1] || undefined });
  });
}

// ---------------------------------------------------------------
// Dashboard = Archetype C (no filter pane). The top-of-page filter bar
// on the Dashboard owns severity/time/rule/source controls; there is
// no secondary sidebar filter. The prior Status + Severity sidebar
// filters were removed when the two-layer chrome landed.
