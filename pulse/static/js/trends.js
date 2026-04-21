// trends.js — Trend Analytics page. Rolling-window aggregates pulled
// from /api/analytics/trends: window-over-window delta, daily finding
// line chart, severity breakdown, top rules and top hosts. The window
// is a 7 / 30 / 90 day dropdown; every refresh hits the backend so
// delete-scan actions elsewhere show up here on the next visit.
'use strict';

import { apiGetTrends } from './api.js';
import { escapeHtml } from './dashboard.js';

let _windowDays = 30;
let _dailyChart = null;
let _rulesChart = null;

export async function renderTrendsPage() {
  var c = document.getElementById('content');
  c.innerHTML = '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading...</div>';

  var data;
  try {
    data = await apiGetTrends(_windowDays);
  } catch (e) {
    c.innerHTML =
      '<div class="card" style="border-color:var(--severity-high, #e67e22);">' +
        '<div class="section-label" style="color:var(--severity-high, #e67e22);">Failed to load trends</div>' +
        '<p style="color:var(--text-muted); font-size:13px; margin:0;">' +
          escapeHtml(e && e.message ? e.message : String(e)) +
        '</p>' +
      '</div>';
    return;
  }

  var totals = data.totals || { this_window: 0, prev_window: 0, delta_pct: null };
  var deltaHtml = _renderDelta(totals.delta_pct);
  var windowLabel = 'last ' + data.window_days + ' days';
  var sev = data.severity_breakdown || {};

  c.innerHTML =
    '<div class="page-head">' +
      '<div class="page-head-title">' +
        '<strong>' + totals.this_window + '</strong> finding' +
          (totals.this_window === 1 ? '' : 's') + ' in the ' + escapeHtml(windowLabel) +
      '</div>' +
      '<div class="page-head-actions">' +
        '<select id="trends-window" oninput="window.__trendsChangeWindow(this.value)" ' +
                'style="padding:6px 10px; border-radius:6px; background:var(--bg); ' +
                'color:var(--text); border:1px solid var(--border);">' +
          _windowOpt(7,  _windowDays) +
          _windowOpt(30, _windowDays) +
          _windowOpt(90, _windowDays) +
        '</select>' +
      '</div>' +
    '</div>' +

    '<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-bottom:16px;">' +
      _statCard('This window',      totals.this_window, 'findings in ' + windowLabel) +
      _statCard('Previous window',  totals.prev_window, 'same length, one step back') +
      _deltaCard(totals.delta_pct) +
      _statCard('CRITICAL + HIGH',  (sev.CRITICAL || 0) + (sev.HIGH || 0), 'top-severity findings in window') +
    '</div>' +

    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">Daily finding volume</div>' +
      '<div style="height:260px; position:relative;">' +
        '<canvas id="trends-daily-chart"></canvas>' +
      '</div>' +
    '</div>' +

    '<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr)); gap:16px;">' +
      '<div class="card">' +
        '<div class="section-label">Severity breakdown</div>' +
        _renderSeverityTable(sev) +
      '</div>' +
      '<div class="card">' +
        '<div class="section-label">Top hosts</div>' +
        _renderHostsTable(data.top_hosts || []) +
      '</div>' +
    '</div>' +

    '<div class="card" style="margin-top:16px;">' +
      '<div class="section-label">Top rules</div>' +
      '<div style="height:' + Math.max(240, (data.top_rules || []).length * 26) + 'px; position:relative;">' +
        '<canvas id="trends-rules-chart"></canvas>' +
      '</div>' +
    '</div>';

  // Delta badge is rendered inline above; no extra work needed here.
  void deltaHtml;

  window.__trendsChangeWindow = function (v) {
    var n = Number(v);
    if (!isFinite(n) || n <= 0) return;
    _windowDays = n;
    renderTrendsPage();
  };

  _drawDailyChart(data.daily_counts || []);
  _drawRulesChart(data.top_rules || []);
}

function _windowOpt(n, cur) {
  var sel = (n === cur) ? ' selected' : '';
  return '<option value="' + n + '"' + sel + '>Last ' + n + ' days</option>';
}

function _statCard(label, value, sub) {
  return '<div style="border:1px solid var(--border); border-radius:6px; padding:14px; background:var(--bg);">' +
           '<div style="color:var(--text-muted); font-size:11px; text-transform:uppercase; letter-spacing:1px;">' +
             escapeHtml(label) +
           '</div>' +
           '<div style="font-size:26px; font-weight:700; color:var(--accent); margin:4px 0 2px;">' +
             escapeHtml(String(value)) +
           '</div>' +
           '<div style="color:var(--text-muted); font-size:12px;">' + escapeHtml(sub) + '</div>' +
         '</div>';
}

function _deltaCard(pct) {
  var body;
  if (pct === null || pct === undefined) {
    body = '<div style="font-size:26px; font-weight:700; color:var(--text-muted); margin:4px 0 2px;">n/a</div>' +
           '<div style="color:var(--text-muted); font-size:12px;">no prior-window data</div>';
  } else {
    var up = pct > 0;
    // More findings isn't necessarily bad (it could mean Pulse is seeing
    // more log data), but for a security dashboard "up" usually reads as
    // worse — so paint the arrow red when findings climb.
    var color = up ? 'var(--severity-high, #f85149)' : (pct < 0 ? 'var(--severity-low, #10b981)' : 'var(--text-muted)');
    var arrow = up ? '\u2191' : (pct < 0 ? '\u2193' : '\u2192');
    var sign = (pct > 0) ? '+' : '';
    body = '<div style="font-size:26px; font-weight:700; color:' + color + '; margin:4px 0 2px;">' +
             arrow + ' ' + sign + pct + '%' +
           '</div>' +
           '<div style="color:var(--text-muted); font-size:12px;">vs. previous window</div>';
  }
  return '<div style="border:1px solid var(--border); border-radius:6px; padding:14px; background:var(--bg);">' +
           '<div style="color:var(--text-muted); font-size:11px; text-transform:uppercase; letter-spacing:1px;">Window delta</div>' +
           body +
         '</div>';
}

function _renderDelta(pct) { return _deltaCard(pct); }

function _renderSeverityTable(sev) {
  var order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  var total = order.reduce(function (a, k) { return a + (sev[k] || 0); }, 0) || 1;
  var rows = order.map(function (k) {
    var n = sev[k] || 0;
    var pct = Math.round((n / total) * 100);
    return '<tr>' +
      '<td style="padding:6px 10px;"><span class="badge badge-' + k.toLowerCase() + '">' + k + '</span></td>' +
      '<td style="padding:6px 10px; text-align:right; font-variant-numeric:tabular-nums;"><strong>' + n + '</strong></td>' +
      '<td style="padding:6px 10px; width:55%;">' +
        '<div style="height:8px; background:var(--bg); border-radius:4px; overflow:hidden;">' +
          '<div style="width:' + pct + '%; height:100%; background:var(--accent);"></div>' +
        '</div>' +
      '</td>' +
    '</tr>';
  }).join('');
  return '<table style="width:100%; border-collapse:collapse;">' + rows + '</table>';
}

function _renderHostsTable(hosts) {
  if (!hosts.length) {
    return '<p style="color:var(--text-muted); font-size:13px; margin:0;">No host data in this window.</p>';
  }
  var max = hosts[0].count || 1;
  var rows = hosts.map(function (h) {
    var pct = Math.round((h.count / max) * 100);
    return '<tr>' +
      '<td style="padding:6px 10px; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' +
        escapeHtml(h.hostname || '(unknown)') +
      '</td>' +
      '<td style="padding:6px 10px; text-align:right; font-variant-numeric:tabular-nums;"><strong>' + h.count + '</strong></td>' +
      '<td style="padding:6px 10px; width:45%;">' +
        '<div style="height:6px; background:var(--bg); border-radius:3px; overflow:hidden;">' +
          '<div style="width:' + pct + '%; height:100%; background:var(--accent);"></div>' +
        '</div>' +
      '</td>' +
    '</tr>';
  }).join('');
  return '<table style="width:100%; border-collapse:collapse;">' + rows + '</table>';
}

function _drawDailyChart(daily) {
  if (typeof Chart === 'undefined') return;
  var canvas = document.getElementById('trends-daily-chart');
  if (!canvas) return;
  var styles = getComputedStyle(document.documentElement);
  var accent    = (styles.getPropertyValue('--accent')    || '#58a6ff').trim();
  var textMuted = (styles.getPropertyValue('--text-muted')|| '#8b949e').trim();
  var border    = (styles.getPropertyValue('--border')    || '#30363d').trim();

  if (_dailyChart) { _dailyChart.destroy(); }
  _dailyChart = new Chart(canvas.getContext('2d'), {
    type: 'line',
    data: {
      labels: daily.map(function (d) { return d.date; }),
      datasets: [{
        data: daily.map(function (d) { return d.count; }),
        borderColor: accent,
        backgroundColor: accent + '22',
        borderWidth: 2,
        fill: true,
        tension: 0.3,
        pointRadius: 2,
        pointHoverRadius: 5,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { enabled: true } },
      scales: {
        x: { ticks: { color: textMuted, maxRotation: 0, autoSkip: true, maxTicksLimit: 10 },
             grid: { color: border + '55' } },
        y: { beginAtZero: true, ticks: { color: textMuted, precision: 0 },
             grid: { color: border + '55' } },
      },
    },
  });
}

function _drawRulesChart(rules) {
  if (typeof Chart === 'undefined') return;
  var canvas = document.getElementById('trends-rules-chart');
  if (!canvas) return;
  if (!rules.length) {
    canvas.parentElement.innerHTML =
      '<p style="color:var(--text-muted); font-size:13px; margin:0;">No rule findings in this window.</p>';
    return;
  }
  var styles = getComputedStyle(document.documentElement);
  var accent    = (styles.getPropertyValue('--accent')    || '#58a6ff').trim();
  var textMuted = (styles.getPropertyValue('--text-muted')|| '#8b949e').trim();
  var border    = (styles.getPropertyValue('--border')    || '#30363d').trim();

  var sevColor = {
    CRITICAL: '#f85149',
    HIGH:     '#e67e22',
    MEDIUM:   '#d29922',
    LOW:      '#58a6ff',
  };
  var colors = rules.map(function (r) { return sevColor[(r.severity || '').toUpperCase()] || accent; });

  if (_rulesChart) { _rulesChart.destroy(); }
  _rulesChart = new Chart(canvas.getContext('2d'), {
    type: 'bar',
    data: {
      labels: rules.map(function (r) { return r.rule; }),
      datasets: [{
        data: rules.map(function (r) { return r.count; }),
        backgroundColor: colors,
        borderWidth: 0,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { enabled: true } },
      scales: {
        x: { beginAtZero: true, ticks: { color: textMuted, precision: 0 },
             grid: { color: border + '55' } },
        y: { ticks: { color: textMuted }, grid: { display: false } },
      },
    },
  });
}
