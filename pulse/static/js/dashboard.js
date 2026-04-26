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

// innerHTML rewrite destroys the old <input> node, so restore focus and
// caret to the new one if the search box was the active element.
export function _restoreSearchFocus(id) {
  var el = document.getElementById(id);
  if (!el) return;
  el.focus();
  var len = el.value.length;
  try { el.setSelectionRange(len, len); } catch (e) {}
}

export function _gradeFor(score) {
  if (score == null) return '';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

export function _gradeRank(score) {
  var g = _gradeFor(score);
  return { A: 5, B: 4, C: 3, D: 2, F: 1 }[g] || 0;
}

// Short relative time — "just now" / "3m ago" / "2h ago" / "5d ago".
// Accepts ISO strings (DB stores local time as "YYYY-MM-DD HH:MM:SS").
export function formatRelativeTime(iso) {
  if (!iso) return '—';
  var d = new Date(String(iso).replace(' ', 'T'));
  if (isNaN(d.getTime())) return String(iso);
  var sec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (sec < 45)    return 'just now';
  if (sec < 3600)  return Math.floor(sec / 60)  + 'm ago';
  if (sec < 86400) return Math.floor(sec / 3600) + 'h ago';
  return Math.floor(sec / 86400) + 'd ago';
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
export function sevBadge(level, count) {
  var colors = { CRITICAL: '#f85149', HIGH: '#f0883e', MEDIUM: '#d29922', LOW: '#3fb950' };
  var c = colors[level] || '#8b949e';
  var bg = count > 0 ? c + '22' : 'transparent';
  var textColor = count > 0 ? c : 'var(--text-muted)';
  return '<div style="text-align:center;">' +
    '<div style="background:' + bg + '; border:1px solid ' + (count > 0 ? c : 'var(--border)') + '; border-radius:6px; padding:6px 12px; min-width:50px;">' +
      '<div style="font-size:18px; font-weight:700; color:' + textColor + ';">' + count + '</div>' +
      '<div style="font-size:10px; text-transform:uppercase; letter-spacing:0.3px; color:' + textColor + '; opacity:0.8;">' + level + '</div>' +
    '</div>' +
  '</div>';
}

export function statCard(label, value, sub, colorClass) {
  return '<div class="stat-card">' +
    '<div class="label">' + label + '</div>' +
    '<div class="value ' + (colorClass || '') + '">' + value + '</div>' +
    '<div class="sub">' + (sub || '') + '</div></div>';
}

export function buildDailyScoreTable(dailyScores) {
  if (!dailyScores || dailyScores.length === 0) {
    return '<div style="text-align:center; padding:24px; color:var(--text-muted);">No daily scores yet.</div>';
  }
  return '<table class="history-table"><thead><tr>' +
    '<th>Date</th><th>Grade</th><th>Score</th><th>Rules</th><th>Trend</th>' +
    '</tr></thead><tbody>' +
    dailyScores.map(function (d, i) {
      var trend = '<span class="trend-flat">=</span>';
      if (i < dailyScores.length - 1) {
        var diff = d.score - dailyScores[i + 1].score;
        if (diff > 0) trend = '<span class="trend-up">\u2191 +' + diff + '</span>';
        else if (diff < 0) trend = '<span class="trend-down">\u2193 ' + diff + '</span>';
      }
      return '<tr>' +
        '<td>' + d.date + '</td>' +
        '<td><span class="grade-badge" style="background:' + d.colour + '; width:28px; height:28px; font-size:14px;">' + d.grade + '</span></td>' +
        '<td style="font-weight:600; color:' + d.colour + ';">' + d.score + '</td>' +
        '<td>' + d.unique_rules + ' rule' + (d.unique_rules !== 1 ? 's' : '') + '</td>' +
        '<td>' + trend + '</td>' +
      '</tr>';
    }).join('') +
    '</tbody></table>';
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

// Recompute MITRE categories object from a deductions list so the MITRE
// bars respect severity + rule filters.
export function _categoriesFromDeductions(deds) {
  var sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  var statusFor = { CRITICAL: 'critical', HIGH: 'critical', MEDIUM: 'medium', LOW: 'low' };
  var out = {};
  (deds || []).forEach(function (d) {
    var cat = d.category || 'Other';
    if (!out[cat]) out[cat] = { status: 'clear', rules_triggered: [], _worst: 0 };
    if (out[cat].rules_triggered.indexOf(d.rule) < 0) out[cat].rules_triggered.push(d.rule);
    var rank = sevRank[(d.severity || '').toUpperCase()] || 0;
    if (rank > out[cat]._worst) {
      out[cat]._worst = rank;
      out[cat].status = statusFor[(d.severity || '').toUpperCase()] || 'clear';
    }
  });
  return out;
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

// Horizontal bar chart of MITRE categories.
export function _mitreBarsHtml(cats, categories) {
  var counts = cats.map(function (c) {
    var info = categories[c] || { rules_triggered: [] };
    return (info.rules_triggered || []).length;
  });
  var max = Math.max.apply(null, counts.concat([1]));

  var statusColor = {
    critical: '#f85149',
    medium:   '#f0883e',
    low:      '#d29922',
    clear:    'var(--border)',
  };

  return '<div class="mitre-bars">' +
    cats.map(function (cat, i) {
      var info = categories[cat] || { status: 'clear', rules_triggered: [] };
      var count = counts[i];
      var color = statusColor[info.status] || statusColor.clear;
      var pct = count === 0 ? 0 : Math.max(6, Math.round((count / max) * 100));
      return '<div class="mitre-row">' +
        '<div class="label">' + cat + '</div>' +
        '<div class="mitre-bar-track">' +
          '<div class="mitre-bar-fill" style="width:' + pct + '%; background:' + color + ';"></div>' +
        '</div>' +
        '<div class="count">' + count + '</div>' +
      '</div>';
    }).join('') +
  '</div>';
}

// Shared by the Dashboard's Last Scan Findings card. Populated right
// before we render so the drawer can look up a finding by index.
let _dashRecentFindings = [];

// Compact "last 5 findings" list with colored severity left-borders.
export function _dashFindingsHtml(findings) {
  _dashRecentFindings = findings;
  return '<div class="dash-findings">' +
    findings.map(function (f, i) {
      var sev = (f.severity || 'LOW').toUpperCase();
      var rule = f.rule || 'Unknown';
      var details = f.details || f.description || '';
      var time = f.timestamp || _extractTime(f) || '-';
      var rowCls = 'dash-finding-row sev-' + sev.toLowerCase() +
                   (isTouched(f) ? ' row-reviewed' : '');
      var fidAttr = (f.id != null) ? ' data-finding-id="' + escapeHtml(String(f.id)) + '"' : '';
      return '<div class="' + rowCls + '"' + fidAttr + ' ' +
             'data-action="openFindingDrawerByIdx" data-arg="' + i + '" style="cursor:pointer;">' +
        '<div>' +
          '<div class="time">' + escapeHtml(time) + '</div>' +
        '</div>' +
        '<div>' +
          '<div class="rule">' + escapeHtml(rule) + '</div>' +
          '<div class="desc">' + escapeHtml(details) + '</div>' +
        '</div>' +
        '<div class="sev ' + sev.toLowerCase() + '">' + sev + '</div>' +
        '<div class="finding-status-col" data-status-slot="dot">' + _statusDotHtml(f) + '</div>' +
      '</div>';
    }).join('') +
  '</div>';
}

export function openFindingDrawerByIdx(idx, target) {
  var f = _dashRecentFindings[idx];
  if (!f) return;
  _selectDashFindingRow(target);
  openFindingDrawer(f);
}

function _selectDashFindingRow(target) {
  document.querySelectorAll('.dash-finding-row.selected').forEach(function (r) {
    if (r !== target) r.classList.remove('selected');
  });
  if (target) target.classList.add('selected');
}

// ---------------------------------------------------------------
// Needs Attention widget — unreviewed CRITICAL/HIGH in the last 7 days
// across every scan. Always uses a fixed 7-day window regardless of
// the dashboard filter bar so outstanding items stay visible while an
// analyst drills into narrower slices with the filters.
// ---------------------------------------------------------------

var _attentionFindings = []; // full list, shared with the drawer opener
var _lastFilteredScanCount = 0; // drives whether the green "clear" bar renders

async function _fetchAttentionFindings(allScans) {
  var cutoff = Date.now() - 7 * 86400000;
  var recent = (allScans || []).filter(function (s) {
    if (!s.total_findings) return false;
    var t = Date.parse(s.scanned_at || '');
    return !isNaN(t) && t >= cutoff;
  });
  if (recent.length === 0) return [];

  var batches = await Promise.all(recent.map(function (s) {
    return fetchFindings(s.id).then(function (fs) {
      return fs.map(function (f) {
        return Object.assign({}, f, {
          _scan_id:     s.id,
          _scan_number: s.number,
          _scan_date:   s.scanned_at,
          _scan_host:   s.hostname || s.filename || '',
        });
      });
    }).catch(function () { return []; });
  }));

  var all = [];
  batches.forEach(function (b) { all = all.concat(b); });

  // Unreviewed CRITICAL/HIGH only. "Touched" (reviewed or marked FP)
  // findings drop out of the attention list entirely.
  all = all.filter(function (f) {
    var sv = (f.severity || '').toUpperCase();
    if (sv !== 'CRITICAL' && sv !== 'HIGH') return false;
    return !isTouched(f);
  });

  // Most recent first, CRITICAL before HIGH as a stable tie-breaker so
  // the top of the list is always the most urgent thing.
  all.sort(function (a, b) {
    var sa = (a.severity || '').toUpperCase() === 'CRITICAL' ? 0 : 1;
    var sb = (b.severity || '').toUpperCase() === 'CRITICAL' ? 0 : 1;
    if (sa !== sb) return sa - sb;
    var at = a.timestamp || _extractTime(a) || a._scan_date || '';
    var bt = b.timestamp || _extractTime(b) || b._scan_date || '';
    return at < bt ? 1 : at > bt ? -1 : 0;
  });

  return all;
}

export function _needsAttentionHtml(findings, scansInWindow) {
  var total = findings.length;
  var hasScans = (scansInWindow == null)
    ? _lastFilteredScanCount > 0
    : scansInWindow > 0;

  if (total === 0) {
    // Positive confirmation only makes sense when the system has actually
    // scanned something in the selected window. Otherwise the widget hides.
    if (!hasScans) return '';
    return '<div class="needs-attention clear na-empty">' +
      '<span>No critical or high findings need attention</span>' +
    '</div>';
  }

  var hasCritical = findings.some(function (f) {
    return (f.severity || '').toUpperCase() === 'CRITICAL';
  });
  var accentCls = hasCritical ? 'accent-critical' : 'accent-high';

  var visible = findings.slice(0, 3);
  var rowsHtml = visible.map(function (f, i) {
    var sev  = (f.severity || 'HIGH').toUpperCase();
    var rule = f.rule || 'Unknown';
    var host = f._scan_host || '-';
    var time = f.timestamp || _extractTime(f) || (f._scan_date || '-');
    var fidAttr = (f.id != null) ? ' data-finding-id="' + escapeHtml(String(f.id)) + '"' : '';
    return '<div class="na-row"' + fidAttr + ' ' +
           'data-action="openAttentionFinding" data-arg="' + i + '" style="cursor:pointer;">' +
      '<span class="na-rule">' + escapeHtml(rule) + '</span>' +
      sevPillHtml(sev) +
      '<span class="na-host">' + escapeHtml(host) + '</span>' +
      '<span class="na-time">' + escapeHtml(time) + '</span>' +
    '</div>';
  }).join('');

  var moreLink = total > 3
    ? '<a class="na-more" data-action="openUnreviewedCriticalHigh" style="cursor:pointer;">' +
        'and ' + (total - 3) + ' more unreviewed finding' + (total - 3 === 1 ? '' : 's') + ' \u2192' +
      '</a>'
    : '';

  return '<div class="needs-attention ' + accentCls + '">' +
    '<div class="na-header">' +
      '<span class="na-title">Needs Attention</span>' +
      '<span class="na-sub">Unreviewed critical / high \u2014 last 7 days</span>' +
    '</div>' +
    '<div class="na-rows">' + rowsHtml + '</div>' +
    moreLink +
  '</div>';
}

export function openAttentionFinding(idx) {
  var f = _attentionFindings[Number(idx)];
  if (f) openFindingDrawer(f);
}

// In-place widget refresh. Called after a review toggle so the list
// stays accurate without rebuilding the whole dashboard. Mutates the
// cached finding's flags then re-renders just our container.
function _refreshNeedsAttentionFromCache() {
  var mount = document.getElementById('dash-needs-attention');
  if (!mount) return;
  var live = _attentionFindings.filter(function (f) {
    return !isTouched(f);
  });
  _attentionFindings = live;
  mount.innerHTML = _needsAttentionHtml(live);
}

function _onReviewToggled(ev) {
  if (!ev || !ev.detail) return;
  var id = ev.detail.id;
  var changed = false;
  _attentionFindings.forEach(function (f) {
    if (f.id != null && String(f.id) === String(id)) {
      f.reviewed = !!ev.detail.reviewed;
      f.false_positive = !!ev.detail.false_positive;
      changed = true;
    }
  });
  if (changed) _refreshNeedsAttentionFromCache();
}
document.addEventListener('pulse:review-toggled', _onReviewToggled);

// ---------------------------------------------------------------
// Standup polish — data-reduction funnel + top-hosts repeat offenders
// ---------------------------------------------------------------
// Shows how raw telemetry narrows down into triage-worthy alerts.
// Events come from scans.total_events; findings / crit+high / crit are
// aggregated across the filter window. Non-numeric / missing fields
// degrade to zero so a brand-new install still renders the row.
export function _dashFunnelHtml(scans, findings) {
  var events = 0;
  scans.forEach(function (s) { events += (s.total_events || 0); });
  var findingsTotal = findings.length;
  var critHigh = 0, critOnly = 0;
  findings.forEach(function (f) {
    var sv = (f.severity || '').toUpperCase();
    if (sv === 'CRITICAL' || sv === 'HIGH') critHigh++;
    if (sv === 'CRITICAL') critOnly++;
  });
  function fmt(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'K';
    return String(n);
  }
  var stages = [
    { label: 'Events',      value: events,         tone: 'neutral' },
    { label: 'Findings',    value: findingsTotal,  tone: 'info' },
    { label: 'Crit + High', value: critHigh,       tone: 'warn' },
    { label: 'Critical',    value: critOnly,       tone: 'error' },
  ];
  return '<div class="dash-funnel">' +
    stages.map(function (s, i) {
      var arrow = (i < stages.length - 1)
        ? '<span class="funnel-arrow" aria-hidden="true">&rarr;</span>'
        : '';
      return '<div class="funnel-stage tone-' + s.tone + '">' +
               '<div class="funnel-value">' + fmt(s.value) + '</div>' +
               '<div class="funnel-label">' + escapeHtml(s.label) + '</div>' +
             '</div>' + arrow;
    }).join('') +
  '</div>';
}

// Mean time to detect — average delta between each finding's event
// timestamp and when the scan that surfaced it actually ran. Lower is
// better. Operates on a list of findings that know their parent scan's
// scanned_at date (either inline `.scanned_at` or a hoisted `._scan_date`
// the attention fetch attaches). Returns seconds, or null when we have
// nothing to compute from.
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

// Severity-donut + legend block for the three-column chart row on the
// Dashboard. Pulls colors from the row-accent palette so it reads like
// every other sev-coloured surface.
export function _severityDonutHtml(sevCounts) {
  var sevs = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  var colors = { CRITICAL: '#f85149', HIGH: '#f0883e', MEDIUM: '#d29922', LOW: '#3fb950' };
  var total = sevs.reduce(function (s, k) { return s + (sevCounts[k] || 0); }, 0);
  var r = 44, cx = 60, cy = 60;
  var circ = 2 * Math.PI * r;
  var offset = 0;
  var arcs;
  if (total === 0) {
    arcs = '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" ' +
           'stroke="var(--border)" stroke-width="12" />';
  } else {
    arcs = '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" ' +
           'stroke="var(--border)" stroke-width="12" />';
    sevs.forEach(function (k) {
      var count = sevCounts[k] || 0;
      if (count === 0) return;
      var dash = (count / total) * circ;
      arcs += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" ' +
              'stroke="' + colors[k] + '" stroke-width="12" ' +
              'stroke-linecap="butt" ' +
              'stroke-dasharray="' + dash.toFixed(2) + ' ' + (circ - dash).toFixed(2) + '" ' +
              'stroke-dashoffset="' + (-offset).toFixed(2) + '" ' +
              'transform="rotate(-90 ' + cx + ' ' + cy + ')" />';
      offset += dash;
    });
  }
  var legend = sevs.map(function (k) {
    var count = sevCounts[k] || 0;
    return '<li>' +
      '<span class="sev-donut-dot" style="background:' + colors[k] + '"></span>' +
      '<span class="sev-donut-label">' + k + '</span>' +
      '<span class="sev-donut-count">' + count + '</span>' +
    '</li>';
  }).join('');
  return '<div class="sev-donut-wrap">' +
    '<svg class="sev-donut" viewBox="0 0 120 120" width="120" height="120">' +
      arcs +
    '</svg>' +
    '<div class="sev-donut-center">' +
      '<div class="sev-donut-total">' + total + '</div>' +
      '<div class="sev-donut-sub">FINDINGS</div>' +
    '</div>' +
    '<ul class="sev-donut-legend">' + legend + '</ul>' +
  '</div>';
}

// Top 5 hosts by finding count in the filtered scan window. Last-seen
// uses the most recent scanned_at for that host so stale hosts surface.
export function _dashTopHostsHtml(scans) {
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
    .slice(0, 5);
  if (rows.length === 0) {
    return '<div class="dash-empty-note" style="font-size:12px; margin:4px 0 0 0;">No host activity in this window.</div>';
  }
  var max = rows[0].count || 1;
  return '<div class="repeat-offenders">' +
    rows.map(function (r) {
      var pct = Math.round((r.count / max) * 100);
      return '<div class="offender-row">' +
               '<div class="offender-host mono">' + escapeHtml(r.host) + '</div>' +
               '<div class="offender-bar-wrap"><div class="offender-bar" style="width:' + pct + '%"></div></div>' +
               '<div class="offender-count">' + r.count + '</div>' +
               '<div class="offender-last">' + escapeHtml(formatRelativeTime(r.last) || '') + '</div>' +
             '</div>';
    }).join('') +
  '</div>';
}

// ---------------------------------------------------------------
// Score-over-time chart (shared by dashboard + history)
// ---------------------------------------------------------------
let _scoreChartInstance = null;

export function _initScoreLineChart(dailyScores) {
  if (typeof Chart === 'undefined') return;
  var canvas = document.getElementById('score-line-chart');
  if (!canvas) return;

  // Reverse so oldest -> newest (Chart.js plots left to right).
  var series = dailyScores.slice().reverse();
  var labels = series.map(function (d) { return d.date; });
  var scores = series.map(function (d) { return d.score; });

  var styles = getComputedStyle(document.documentElement);
  var accent     = styles.getPropertyValue('--accent').trim() || '#58a6ff';
  var textMuted  = styles.getPropertyValue('--text-muted').trim() || '#8b949e';
  var border     = styles.getPropertyValue('--border').trim() || '#30363d';

  // Points dropping below the B-grade threshold (70) are highlighted so
  // the regression jumps out at a glance. Red for <50, amber for 50-69.
  var CRIT  = '#f85149';
  var WARN  = '#d29922';
  var pointColors = scores.map(function (v) {
    if (v < 50) return CRIT;
    if (v < 70) return WARN;
    return accent;
  });

  if (_scoreChartInstance) { _scoreChartInstance.destroy(); }

  // afterDraw plugin: draws a dashed horizontal reference line at y=70
  // ("B grade threshold"). Kept inline — global Chart.register would
  // leak the line into every other chart on the page.
  var bGradeLine = {
    id: 'bGradeLine',
    afterDraw: function (chart) {
      var yScale = chart.scales.y;
      var xScale = chart.scales.x;
      if (!yScale || !xScale) return;
      var y = yScale.getPixelForValue(70);
      var ctx = chart.ctx;
      ctx.save();
      ctx.strokeStyle = textMuted;
      ctx.setLineDash([4, 4]);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(xScale.left, y);
      ctx.lineTo(xScale.right, y);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = textMuted;
      ctx.font = '10px sans-serif';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'bottom';
      ctx.fillText('B grade threshold', xScale.right - 2, y - 2);
      ctx.restore();
    }
  };

  _scoreChartInstance = new Chart(canvas.getContext('2d'), {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        data: scores,
        borderColor: accent,
        backgroundColor: accent + '22',
        borderWidth: 2,
        fill: true,
        tension: 0.3,
        pointRadius: 4,
        pointHoverRadius: 6,
        pointBackgroundColor: pointColors,
        pointBorderColor: pointColors,
        pointBorderWidth: 0,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { enabled: true } },
      scales: {
        x: {
          ticks: { color: textMuted, font: { size: 10 } },
          grid:  { display: false },
          border: { color: border },
        },
        y: {
          min: 0, max: 100,
          ticks: { color: textMuted, font: { size: 10 }, stepSize: 25 },
          grid:  { display: false },
          border: { color: border },
        }
      }
    },
    plugins: [bGradeLine],
  });
}

// ---------------------------------------------------------------
// PAGE: Dashboard
// ---------------------------------------------------------------
export async function renderDashboardPage() {
  var c = document.getElementById('content');
  parseDashFiltersFromURL();

  // Bump fetch ceiling so 30/90-day filters have data to slice.
  invalidateScansCache();
  var allScans = await fetchScans(200);
  var rules    = await fetchRuleNames();
  var dailyResp = await apiDailyScores(90);
  var allDaily  = dailyResp.daily_scores || [];

  var scans       = filterScansByDashState(allScans);
  var dailyScores = filterDailyByDashState(allDaily);
  var sourceList  = _dashSources(allScans);
  var filtersOn   = _dashFiltersActive();

  var today = dailyScores[0];

  var filteredDeductions = today ? filterFindingsByDashState(today.deductions || []) : [];
  var filteredCategories = filtersOn && today
    ? _categoriesFromDeductions(filteredDeductions)
    : (today && today.categories) || {};

  var scoreNum = today ? today.score : 100;
  var scoreLabel = today ? today.label : 'SECURE';
  var grade = today ? today.grade : 'A';
  var score = today ? today.score : '--';
  var totalFindings = scans.reduce(function (s, x) { return s + x.total_findings; }, 0);

  var scoreDesc = !today
    ? 'No scans yet in the selected window. Upload a log or start the live monitor to populate this panel.'
    : scoreNum >= 90
      ? 'No critical issues detected. Security posture is strong.'
      : scoreNum >= 75
        ? 'Minor issues found. Review findings and address high-severity items.'
        : scoreNum >= 50
          ? 'Significant findings detected. Multiple items need attention.'
          : 'Critical issues detected. Immediate investigation recommended.';

  var circumference = 2 * Math.PI * 58;
  var dashOffset = circumference * (1 - scoreNum / 100);

  var sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  filteredDeductions.forEach(function (d) {
    if (sevCounts[d.severity] !== undefined) sevCounts[d.severity]++;
  });

  var uniqueRulesFiltered = (function () {
    var set = {};
    filteredDeductions.forEach(function (d) { if (d.rule) set[d.rule] = true; });
    return Object.keys(set).length;
  })();

  var scoreTrend = _trendFor(today && today.score,
                             dailyScores[1] && dailyScores[1].score,
                             { upIsGood: true });
  var rulesTrend = _trendFor(uniqueRulesFiltered,
                             dailyScores[1] && dailyScores[1].unique_rules,
                             { upIsGood: false });
  var findTrend = _trendFor(scans[0] && scans[0].total_findings,
                            scans[1] && scans[1].total_findings,
                            { upIsGood: false });

  var mitreCats = ['Authentication', 'Persistence', 'Lateral Movement',
                   'Privilege Escalation', 'Execution'];
  var mitreBarsHtml = _mitreBarsHtml(mitreCats, filteredCategories);

  // Top triggered rules — aggregate deductions in the filtered window
  // and keep the worst severity seen per rule so the badge color maps
  // to how dangerous the rule is, not the severity of the last hit.
  var ruleAgg = {};
  filteredDeductions.forEach(function (d) {
    var r = d.rule || 'Unknown';
    if (!ruleAgg[r]) ruleAgg[r] = { count: 0, severity: 'LOW' };
    ruleAgg[r].count++;
    var sv = (d.severity || 'LOW').toUpperCase();
    var rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    if ((rank[sv] || 0) > (rank[ruleAgg[r].severity] || 0)) {
      ruleAgg[r].severity = sv;
    }
  });
  var topRules = Object.keys(ruleAgg).map(function (r) {
    return { rule: r, count: ruleAgg[r].count, severity: ruleAgg[r].severity };
  }).sort(function (a, b) {
    return b.count - a.count;
  }).slice(0, 5);
  var topRulesHtml = topRules.length === 0
    ? '<div class="dash-empty-note" style="font-size:12px; margin:4px 0 0 0;">No rules triggered in this window.</div>'
    : '<div class="top-rules-list">' +
        topRules.map(function (r) {
          return '<div class="top-rules-row">' +
            '<span class="top-rules-name">' + escapeHtml(r.rule) + '</span>' +
            '<span class="top-rules-count sev-' + r.severity.toLowerCase() + '">' + r.count + '</span>' +
          '</div>';
        }).join('') +
      '</div>';

  var latestWithFindings = scans.find(function (s) { return s.total_findings > 0; });
  var recentFindings = [];
  if (latestWithFindings) {
    var all = await fetchFindings(latestWithFindings.id);
    recentFindings = filterFindingsByDashState(all)
      .slice().sort(function (a, b) {
        var at = a.timestamp || _extractTime(a) || '';
        var bt = b.timestamp || _extractTime(b) || '';
        return at < bt ? 1 : at > bt ? -1 : 0;
      }).slice(0, 5);
  }

  var filterBarHtml = _dashFilterBarHtml(rules, sourceList);

  // "Last updated" reference is the newest scan we've seen — not the
  // newest scan in the filtered slice, so the timestamp reflects how
  // fresh the data is, not how old the filter window is.
  var newestScan = allScans[0];
  var updatedIso = newestScan ? (newestScan.scanned_at || '') : '';
  var updatedLabel = updatedIso
    ? ('Last updated ' + formatRelativeTime(updatedIso))
    : 'No scans yet';
  var dashMetaHtml =
    '<div class="dash-meta-row">' +
      '<span class="dash-updated" id="dash-updated-ts">' + escapeHtml(updatedLabel) + '</span>' +
    '</div>';

  // Needs Attention always uses a fixed 7-day window on the full scan
  // list, independent of the dashboard filter bar. Runs after the other
  // fetches since it reuses allScans and issues its own per-scan fetches.
  _lastFilteredScanCount = scans.length;
  _attentionFindings = await _fetchAttentionFindings(allScans);
  var attentionInner = _needsAttentionHtml(_attentionFindings, scans.length);
  var attentionHtml = '<div id="dash-needs-attention">' + attentionInner + '</div>';

  // Slim inline empty-state row. Only shown when no scans fall in the
  // selected filter window. Same visual height as the "Needs Attention"
  // clear bar — left-border accent flips to blue to differentiate.
  var emptyBannerHtml = '';
  if (scans.length === 0) {
    var bannerMsg = filtersOn
      ? 'No scans match these filters'
      : (dashFilterState.time === 'today'
          ? 'No scans yet today'
          : 'No scans in this window yet');
    var inboxIcon =
      '<svg class="dash-empty-ico" viewBox="0 0 24 24" width="14" height="14" ' +
        'fill="none" stroke="currentColor" stroke-width="2" ' +
        'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
        '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/>' +
        '<path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>' +
      '</svg>';
    var actionsHtml = filtersOn
      ? '<a class="dash-empty-link primary" data-action="resetDashFilters">Reset filters</a>'
      : '<a class="dash-empty-link primary" data-action="openUploadModal">Upload .evtx</a>' +
        '<span class="dash-empty-divider" aria-hidden="true"></span>' +
        '<a class="dash-empty-link secondary" data-action="navigate" data-arg="monitor">Open Monitor</a>';
    emptyBannerHtml =
      '<div class="dash-empty-inline">' +
        inboxIcon +
        '<span class="dash-empty-text">' + bannerMsg + '</span>' +
        '<span class="dash-empty-actions">' + actionsHtml + '</span>' +
      '</div>';
  }

  c.innerHTML =
    dashMetaHtml +
    filterBarHtml +
    emptyBannerHtml +
    attentionHtml +
    // Six-card KPI strip — fits on one row at 1440+. Daily Score on
    // the far left stays the primary anchor; MTTD + Open Findings slot
    // in on the right as the response-quality pair computed from the
    // existing attention-window fetch (see `_computeMTTDSeconds`).
    '<div class="stat-row stat-row-6">' +
      _trendStatCard('Daily Score',
                     score + ' <span style="font-size:14px; opacity:0.7;">(' + grade + ')</span>',
                     scoreLabel, scoreTrend, _accentForScore(scoreNum), scoreColorClass(scoreNum),
                     'score') +
      _trendStatCard('Unique Rules',
                     uniqueRulesFiltered,
                     filtersOn ? 'Matching filter' : 'Triggered today', rulesTrend,
                     uniqueRulesFiltered > 0 ? 'accent-high' : 'accent-neutral',
                     null, 'rules') +
      _trendStatCard('Total Findings', totalFindings,
                     filtersOn ? 'In filtered window' : 'Across all scans', findTrend, 'accent-info',
                     null, 'findings') +
      _trendStatCard('Scans Run', scans.length,
                     filtersOn ? 'In filtered window' : 'Since first install', null, 'accent-neutral',
                     null, 'scans') +
      _trendStatCard('MTTD',
                     _formatDuration(_computeMTTDSeconds(_attentionFindings)),
                     _attentionFindings.length ? 'Avg detection lag' : 'No findings to measure',
                     null, 'accent-info', null, null) +
      _trendStatCard('Open Findings',
                     _attentionFindings.length,
                     'Unreviewed crit / high', null,
                     _attentionFindings.length > 0 ? 'accent-high' : 'accent-neutral',
                     null, null) +
    '</div>' +

    '<div class="standup-row">' +
      '<div class="card standup-card">' +
        '<div class="section-label">Data reduction — events through to critical</div>' +
        _dashFunnelHtml(scans, filteredDeductions) +
      '</div>' +
      '<div class="card standup-card">' +
        '<div class="section-label">Repeat offenders — top hosts</div>' +
        _dashTopHostsHtml(scans) +
      '</div>' +
    '</div>' +

    // Three-column chart row: severity donut (left), compact score
    // ring + label (center), score history line chart (right).
    '<div class="dash-chart-row">' +

      '<div class="card dash-chart-card">' +
        '<div class="section-label">Severity Breakdown</div>' +
        _severityDonutHtml(sevCounts) +
      '</div>' +

      '<div class="card dash-chart-card today-security-score">' +
        '<div class="section-label">Today\u2019s Security Score</div>' +
        '<div class="score-display">' +
          '<div class="score-ring-container">' +
            '<svg class="score-ring" viewBox="0 0 140 140">' +
              '<circle class="track" cx="70" cy="70" r="58" />' +
              '<circle class="fill" cx="70" cy="70" r="58" ' +
                'stroke-dasharray="' + circumference + '" ' +
                'stroke-dashoffset="' + dashOffset + '" ' +
                'style="stroke:' + scoreColor(scoreNum) + '" ' +
                'transform="rotate(-90 70 70)" />' +
            '</svg>' +
            '<div class="score-ring-label">' +
              '<div class="number" style="color:' + scoreColor(scoreNum) + '">' + score + '</div>' +
              '<div class="out-of">/ 100</div>' +
            '</div>' +
          '</div>' +
          '<div class="score-info">' +
            '<div class="risk-label" style="color:' + scoreColor(scoreNum) + '">' +
              '<span class="grade-badge" style="background:' + scoreColor(scoreNum) + '; margin-right:8px;">' + grade + '</span>' +
              scoreLabel +
            '</div>' +
            '<div class="risk-desc">' + scoreDesc + '</div>' +
          '</div>' +
        '</div>' +

      '</div>' +

      '<div class="card dash-chart-card">' +
        '<div class="section-label">Score History</div>' +
        '<div class="score-chart-wrap"><canvas id="score-line-chart"></canvas></div>' +
        '<div class="history-footer"><a href="#" data-action="navigate" data-arg="history">View full history &rarr;</a></div>' +
      '</div>' +
    '</div>' +

    // MITRE categories + Top Triggered Rules row — full-width below
    // the chart band so the bars get horizontal room to breathe.
    '<div class="dash-mitre-row">' +
      '<div class="card">' +
        '<div class="section-label">MITRE ATT&amp;CK Categories</div>' +
        mitreBarsHtml +
      '</div>' +
      '<div class="card">' +
        '<div class="section-label">Top Triggered Rules</div>' +
        topRulesHtml +
      '</div>' +
    '</div>' +

    (recentFindings.length > 0
      ? '<div class="card">' +
          '<div class="section-label" style="display:flex; justify-content:space-between; align-items:center;">' +
            '<span>Last Scan Findings</span>' +
            '<a href="#" data-action="navigate" data-arg="findings" style="color:var(--accent); font-size:11px; font-weight:600; text-decoration:none;">View all findings &rarr;</a>' +
          '</div>' +
          _dashFindingsHtml(recentFindings) +
        '</div>'
      : (filtersOn && latestWithFindings
          ? '<div class="card"><div class="dash-empty-note">No findings match the current filters in the latest scan.</div></div>'
          : '')
    );

  _initScoreLineChart(dailyScores);
  _startDashUpdatedTimer(updatedIso);
}

// ---------------------------------------------------------------
// Dashboard = Archetype C (no filter pane). The top-of-page filter bar
// on the Dashboard owns severity/time/rule/source controls; there is
// no secondary sidebar filter. The prior Status + Severity sidebar
// filters were removed when the two-layer chrome landed.
