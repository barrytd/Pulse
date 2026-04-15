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
import { openFindingDrawer } from './findings.js';
import { mountDashLivePanel } from './monitor.js';

// ---------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------

// Splunk-style dashboard filter state. Persisted in URL query params.
export let dashFilterState = { time: 'today', sev: 'all', rule: 'all', source: 'all', q: '' };
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

// Rule -> remediation snippet (used by finding drawer and expand row).
export const REMEDIATION = {
  'Brute Force Attempt':       'Block the source IP, reset the targeted account, and review account-lockout policy. Enable MFA if not already.',
  'Account Takeover Chain':    'Disable the account, force a password reset, invalidate sessions, and review recent activity for data access.',
  'Account Lockout':           'Verify whether lockouts were from a legitimate user or an attacker. If attacker: block source, enable MFA.',
  'User Account Created':      'Confirm the account was created by an authorised admin. If unexpected, disable it and investigate the creator.',
  'Privilege Escalation':      'Audit the account\u2019s recent actions, remove elevated group membership if unexpected, and rotate admin credentials.',
  'Audit Log Cleared':         'Treat as incident. Collect surrounding logs from forwarders and examine processes running near the clear event.',
  'RDP Logon Detected':        'Verify the source IP is expected. Enforce Network Level Authentication and restrict RDP to VPN-only if exposed.',
  'Pass-the-Hash Attempt':     'Isolate the host, rotate NTLM credentials, and investigate LSASS access. Consider Credential Guard.',
  'Service Installed':         'Confirm the service is legitimate. Remove unknown services and inspect the binary path for persistence artifacts.',
  'Scheduled Task Created':    'Audit the task\u2019s action and author. Remove if unauthorised and scan the target binary.',
  'Suspicious PowerShell':     'Capture the full command line, look for obfuscation/encoding, and enable Script Block Logging if missing.',
  'Antivirus Disabled':        'Re-enable AV immediately. Check for parent process and tamper-protection policy. Investigate as likely compromise.',
  'Firewall Disabled':         'Re-enable the firewall and check GPO/local-policy for unauthorised changes.',
  'Firewall Rule Changed':     'Audit the rule. Remove if unauthorised. Require GPO-controlled rules where possible.',
  'Malware Persistence Chain': 'Isolate the host, collect memory + disk forensics, and review all persistence locations (services, tasks, Run keys).',
  'Kerberoasting':             'Rotate SPN account passwords to long randomised values. Flag the requesting account for review.',
  'Golden Ticket':             'Rotate krbtgt twice (24h apart) and hunt for other signs of Domain Controller compromise.',
  'Credential Dumping':        'Isolate the host, rotate all credentials used recently, and investigate LSASS access paths.',
  'Logon from Disabled Account': 'Confirm the account truly is disabled. If the logon succeeded, treat as major incident.',
  'After-Hours Logon':         'Verify with the account owner. If unexpected, disable account and investigate source IP.',
  'Suspicious Registry Modification': 'Review the key and values. Remove if unauthorised and audit the writing process.',
  'Lateral Movement via Network Share': 'Check the accessing account and source host; rotate credentials if suspicious.',
};

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
  a.download = 'pulse_scan_' + scanId + '.' + fmt;
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
    var validTime = ['today', '7d', '30d', '90d'];
    var validSev  = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    if (qp.has('time')   && validTime.indexOf(qp.get('time'))   >= 0) dashFilterState.time   = qp.get('time');
    if (qp.has('sev')    && validSev.indexOf(qp.get('sev'))     >= 0) dashFilterState.sev    = qp.get('sev');
    if (qp.has('rule'))   dashFilterState.rule   = qp.get('rule')   || 'all';
    if (qp.has('source')) dashFilterState.source = qp.get('source') || 'all';
    if (qp.has('q'))      dashFilterState.q      = qp.get('q')      || '';
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
  var qs = qp.toString();
  var url = window.location.pathname + (qs ? '?' + qs : '') + window.location.hash;
  history.replaceState({}, '', url);
}

// Cutoff Date object for "scan.scanned_at >= cutoff".
export function _dashTimeCutoff(range) {
  var now = new Date();
  if (range === 'today') {
    var d = new Date(now); d.setHours(0, 0, 0, 0); return d;
  }
  if (range === '7d')  return new Date(now.getTime() - 7  * 86400000);
  if (range === '30d') return new Date(now.getTime() - 30 * 86400000);
  if (range === '90d') return new Date(now.getTime() - 90 * 86400000);
  return new Date(0);
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
  var cutoff = _dashTimeCutoff(dashFilterState.time);
  var src = dashFilterState.source;
  return scans.filter(function (s) {
    var d = _parseScanDate(s.scanned_at);
    if (!d || d < cutoff) return false;
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
  var cutoff = _dashTimeCutoff(dashFilterState.time);
  return (daily || []).filter(function (d) {
    var dt = _parseScanDate(d.date);
    return dt && dt >= cutoff;
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
    { v: 'today', l: 'Today' },
    { v: '7d',    l: 'Last 7 days' },
    { v: '30d',   l: 'Last 30 days' },
    { v: '90d',   l: 'Last 90 days' },
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

  return '<div class="dash-filter-bar">' +
    '<div class="dash-filter-group">' +
      '<label class="dash-filter-label">Time Range</label>' +
      '<select class="dash-filter-select" id="f-time">' + opts(timeOpts, st.time) + '</select>' +
    '</div>' +
    '<div class="dash-filter-group">' +
      '<label class="dash-filter-label">Severity</label>' +
      '<select class="dash-filter-select" id="f-severity">' + opts(sevOpts, st.sev) + '</select>' +
    '</div>' +
    '<div class="dash-filter-group">' +
      '<label class="dash-filter-label">Rule</label>' +
      '<select class="dash-filter-select" id="f-rule">' + opts(ruleOpts, st.rule) + '</select>' +
    '</div>' +
    '<div class="dash-filter-group">' +
      '<label class="dash-filter-label">Source</label>' +
      '<select class="dash-filter-select" id="f-source">' + opts(sourceOpts, st.source) + '</select>' +
    '</div>' +
    '<div class="dash-filter-group" style="flex:1; min-width:200px;">' +
      '<label class="dash-filter-label">Search</label>' +
      '<input type="search" class="dash-filter-search" id="f-query" ' +
        'placeholder="user, IP, event ID..." value="' + escapeHtml(st.q || '') + '" ' +
        'data-action-keydown="dashFilterQueryKey" />' +
    '</div>' +
    '<button class="dash-filter-apply" data-action="applyDashFilters">Apply</button>' +
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
  var st = dashFilterState;
  if (t)   st.time   = t.value;
  if (s)   st.sev    = s.value;
  if (r)   st.rule   = r.value;
  if (src) st.source = src.value;
  if (q)   st.q      = (q.value || '').trim();
  writeDashFiltersToURL();
  renderDashboardPage();
}

export function resetDashFilters() {
  dashFilterState = { time: 'today', sev: 'all', rule: 'all', source: 'all', q: '' };
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

export function _trendStatCard(label, value, sub, trend, accentClass, valueColorClass) {
  return '<div class="stat-card ' + (accentClass || 'accent-neutral') + '">' +
    '<div class="label">' + label + '</div>' +
    '<div class="value ' + (valueColorClass || '') + '">' + value + '</div>' +
    _renderTrend(trend) +
    (sub ? '<div class="sub">' + sub + '</div>' : '') +
  '</div>';
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
      return '<div class="dash-finding-row sev-' + sev.toLowerCase() + '" ' +
             'data-action="openFindingDrawerByIdx" data-arg="' + i + '" style="cursor:pointer;">' +
        '<div>' +
          '<div class="time">' + escapeHtml(time) + '</div>' +
        '</div>' +
        '<div>' +
          '<div class="rule">' + escapeHtml(rule) + '</div>' +
          '<div class="desc">' + escapeHtml(details) + '</div>' +
        '</div>' +
        '<div class="sev ' + sev.toLowerCase() + '">' + sev + '</div>' +
      '</div>';
    }).join('') +
  '</div>';
}

export function openFindingDrawerByIdx(idx) {
  var f = _dashRecentFindings[idx];
  if (f) openFindingDrawer(f);
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

  if (_scoreChartInstance) { _scoreChartInstance.destroy(); }

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
        pointRadius: 3,
        pointBackgroundColor: accent,
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
    }
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

  var latestWithFindings = scans.find(function (s) { return s.total_findings > 0; });
  var recentFindings = [];
  if (latestWithFindings) {
    var all = await fetchFindings(latestWithFindings.id);
    recentFindings = filterFindingsByDashState(all).slice().sort(function (a, b) {
      var at = a.timestamp || _extractTime(a) || '';
      var bt = b.timestamp || _extractTime(b) || '';
      return at < bt ? 1 : at > bt ? -1 : 0;
    }).slice(0, 5);
  }

  var filterBarHtml = _dashFilterBarHtml(rules, sourceList);

  var emptyBannerHtml = '';
  if (scans.length === 0) {
    var bannerMsg = filtersOn
      ? 'No scans match these filters. Try a wider time range or click Reset.'
      : (dashFilterState.time === 'today'
          ? 'No scans yet today. Upload a log or start the live monitor to get started.'
          : 'No scans in this window yet.');
    emptyBannerHtml =
      '<div class="card" style="margin-bottom:16px; display:flex; justify-content:space-between; align-items:center; gap:16px; flex-wrap:wrap;">' +
        '<div class="dash-empty-note" style="margin:0;">' + bannerMsg + '</div>' +
        '<div style="display:flex; gap:10px;">' +
          (filtersOn
            ? '<a class="btn" data-action="resetDashFilters" style="cursor:pointer;">Reset filters</a>'
            : '<a class="btn btn-primary" data-action="openUploadModal" style="cursor:pointer;">Upload .evtx</a>' +
              '<a class="btn" data-action="navigate" data-arg="monitor" style="cursor:pointer;">Open Monitor</a>') +
        '</div>' +
      '</div>';
  }

  c.innerHTML =
    filterBarHtml +
    emptyBannerHtml +
    '<div class="stat-row">' +
      _trendStatCard('Daily Score',
                     score + ' <span style="font-size:14px; opacity:0.7;">(' + grade + ')</span>',
                     scoreLabel, scoreTrend, _accentForScore(scoreNum), scoreColorClass(scoreNum)) +
      _trendStatCard('Unique Rules',
                     uniqueRulesFiltered,
                     filtersOn ? 'Matching filter' : 'Triggered today', rulesTrend,
                     uniqueRulesFiltered > 0 ? 'accent-high' : 'accent-neutral') +
      _trendStatCard('Total Findings', totalFindings,
                     filtersOn ? 'In filtered window' : 'Across all scans', findTrend, 'accent-info') +
      _trendStatCard('Scans Run', scans.length,
                     filtersOn ? 'In filtered window' : 'Since first install', null, 'accent-neutral') +
    '</div>' +

    '<div id="dash-live-panel"></div>' +

    '<div class="middle-row">' +

      '<div class="card">' +
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

        '<div style="margin-top:16px; border-top:1px solid var(--border); padding-top:16px;">' +
          '<div class="section-label">Severity Breakdown</div>' +
          '<div style="display:flex; gap:12px;">' +
            sevBadge('CRITICAL', sevCounts.CRITICAL) +
            sevBadge('HIGH', sevCounts.HIGH) +
            sevBadge('MEDIUM', sevCounts.MEDIUM) +
            sevBadge('LOW', sevCounts.LOW) +
          '</div>' +
        '</div>' +

        '<div style="margin-top:16px; border-top:1px solid var(--border); padding-top:16px;">' +
          '<div class="section-label">MITRE ATT&amp;CK Categories</div>' +
          mitreBarsHtml +
        '</div>' +
      '</div>' +

      '<div class="card">' +
        '<div class="section-label">Score History</div>' +
        '<div class="score-chart-wrap"><canvas id="score-line-chart"></canvas></div>' +
        buildDailyScoreTable(dailyScores.slice(0, 7)) +
        '<div class="history-footer"><a href="#" data-action="navigate" data-arg="history">View full history \u2192</a></div>' +
      '</div>' +
    '</div>' +

    (recentFindings.length > 0
      ? '<div class="card">' +
          '<div class="section-label" style="display:flex; justify-content:space-between; align-items:center;">' +
            '<span>Last Scan Findings</span>' +
            '<a href="#" data-action="navigate" data-arg="findings" style="color:var(--accent); font-size:11px; font-weight:600; text-decoration:none;">View all findings \u2192</a>' +
          '</div>' +
          _dashFindingsHtml(recentFindings) +
        '</div>'
      : (filtersOn && latestWithFindings
          ? '<div class="card"><div class="dash-empty-note">No findings match the current filters in the latest scan.</div></div>'
          : '')
    );

  _initScoreLineChart(dailyScores);

  mountDashLivePanel();
}
