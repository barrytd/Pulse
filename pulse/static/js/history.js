// history.js — Score history page. Uses its own chart instance
// (separate from dashboard's score chart) so the two can coexist.
'use strict';

import {
  fetchScans,
  apiCompareScans,
  apiDeleteHistory,
  invalidateScansCache,
  invalidateFindingsCache,
} from './api.js';
import {
  escapeHtml,
  scoreColor,
  scoreColorClass,
  showToast,
  toastError,
  _gradeFor,
  _trendStatCard,
  _accentForScore,
} from './dashboard.js';
import { buildFindingsTable } from './findings.js';

let _historyChartInstance = null;
let _historyHighlightIdx  = -1;
// scan id -> true. Matches the Scans page selection model.
let _selectedHistory = {};

export async function renderHistoryPage() {
  var c = document.getElementById('content');
  var scans = await fetchScans(200);

  if (scans.length === 0) {
    _selectedHistory = {};
    c.innerHTML =
      '<div class="empty-state cta">' +
        '<div class="empty-icon">&#128200;</div>' +
        '<h3>No history yet</h3>' +
        '<p>Run your first scan to start tracking your security posture over time.</p>' +
        '<button class="btn btn-primary" data-action="openUploadModal">Upload .evtx</button>' +
      '</div>';
    return;
  }

  // Prune selections pointing at scans that no longer exist.
  var known = {};
  scans.forEach(function (s) { known[s.id] = true; });
  Object.keys(_selectedHistory).forEach(function (k) {
    if (!known[k]) delete _selectedHistory[k];
  });

  var withScore = scans.filter(function (s) { return s.score != null; });
  var avg  = withScore.length
    ? Math.round(withScore.reduce(function (a, s) { return a + s.score; }, 0) / withScore.length)
    : '-';
  var best = withScore.length
    ? Math.max.apply(null, withScore.map(function (s) { return s.score; }))
    : '-';
  var worst = withScore.length
    ? Math.min.apply(null, withScore.map(function (s) { return s.score; }))
    : '-';

  var nSelected = Object.keys(_selectedHistory).length;
  var deleteBarStyle = nSelected > 0 ? 'flex' : 'none';

  c.innerHTML =
    '<div class="page-head">' +
      '<div class="page-head-title"><strong>' + scans.length + '</strong> scans tracked</div>' +
    '</div>' +

    '<div class="summary-row">' +
      _trendStatCard('Average Score', avg, 'Across all scans', null, _accentForScore(avg === '-' ? null : avg), scoreColorClass(avg === '-' ? null : avg)) +
      _trendStatCard('Best Score',  best, 'Highest recorded', null, 'accent-info', scoreColorClass(best === '-' ? null : best)) +
      _trendStatCard('Worst Score', worst, 'Lowest recorded', null, 'accent-critical', scoreColorClass(worst === '-' ? null : worst)) +
      _trendStatCard('Total Scans', scans.length, 'Runs to date', null, 'accent-neutral') +
    '</div>' +

    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">Security Score Trend</div>' +
      '<div class="score-chart-wrap" style="height:220px;"><canvas id="history-line-chart"></canvas></div>' +
    '</div>' +

    _buildComparePanel(scans) +

    '<div id="history-delete-bar" class="bulk-bar" style="display:' + deleteBarStyle + ';">' +
      '<span class="bulk-bar-count">' + nSelected + ' selected</span>' +
      '<button class="btn btn-danger" id="history-delete-btn" data-action="deleteSelectedHistory">' +
        'Delete ' + nSelected + ' scan' + (nSelected === 1 ? '' : 's') +
      '</button>' +
      '<a class="bulk-bar-clear" data-action="toggleHistorySelectAll" data-arg="false">Clear selection</a>' +
    '</div>' +

    '<div class="card" style="padding:0; overflow:hidden;">' +
      _buildHistoryTable(scans) +
    '</div>';

  _initHistoryLineChart(scans);
}

function _buildComparePanel(scans) {
  if (!scans || scans.length < 2) return '';
  var options = scans.map(function (s) {
    var num = s.number != null ? s.number : s.id;
    var label = '#' + num + ' \u00b7 ' + (s.scanned_at || '') +
                ' \u00b7 ' + (s.filename || 'Unknown') +
                ' \u00b7 ' + s.total_findings + ' finding(s)';
    return '<option value="' + s.id + '">' + escapeHtml(label) + '</option>';
  }).join('');
  var defaultA = scans[1] ? scans[1].id : '';
  var defaultB = scans[0] ? scans[0].id : '';

  return '<div class="card" style="margin-bottom:16px;">' +
    '<div class="section-label">Compare scans</div>' +
    '<div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">' +
      '<label style="font-size:11px; text-transform:uppercase; letter-spacing:0.7px; color:var(--text-muted);">Before</label>' +
      '<select id="cmp-a" class="dash-filter-select" style="min-width:260px;">' + options.replace('value="' + defaultA + '"', 'value="' + defaultA + '" selected') + '</select>' +
      '<label style="font-size:11px; text-transform:uppercase; letter-spacing:0.7px; color:var(--text-muted);">After</label>' +
      '<select id="cmp-b" class="dash-filter-select" style="min-width:260px;">' + options.replace('value="' + defaultB + '"', 'value="' + defaultB + '" selected') + '</select>' +
      '<button class="btn btn-primary" data-action="runHistoryCompare">Compare</button>' +
    '</div>' +
    '<div id="cmp-results" style="margin-top:14px;"></div>' +
  '</div>';
}

export async function runHistoryCompare() {
  var a = document.getElementById('cmp-a');
  var b = document.getElementById('cmp-b');
  var out = document.getElementById('cmp-results');
  if (!a || !b || !out) return;
  var idA = Number(a.value);
  var idB = Number(b.value);
  if (!idA || !idB) {
    out.innerHTML = '<div style="color:var(--text-muted);">Pick two scans to compare.</div>';
    return;
  }
  if (idA === idB) {
    out.innerHTML = '<div style="color:var(--text-muted);">Pick two different scans.</div>';
    return;
  }
  out.innerHTML = '<div style="color:var(--text-muted);">Loading diff\u2026</div>';
  try {
    var diff = await apiCompareScans(idA, idB);
    out.innerHTML = _renderDiff(diff);
  } catch (err) {
    out.innerHTML = '<div style="color:var(--severity-critical, #f85149);">' +
      escapeHtml(err && err.message ? err.message : 'Comparison failed.') + '</div>';
  }
}

function _renderDiff(diff) {
  var a = diff.scan_a || {};
  var b = diff.scan_b || {};
  var meta =
    '<div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:12px; font-size:12px; color:var(--text-muted);">' +
      '<span><strong>Before:</strong> #' + (a.number != null ? a.number : a.id) + ' \u00b7 ' + escapeHtml(a.scanned_at || '') + ' \u00b7 ' + (a.total_findings || 0) + ' finding(s)</span>' +
      '<span><strong>After:</strong> #' + (b.number != null ? b.number : b.id) + ' \u00b7 ' + escapeHtml(b.scanned_at || '') + ' \u00b7 ' + (b.total_findings || 0) + ' finding(s)</span>' +
    '</div>';
  return meta +
    '<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr)); gap:14px;">' +
      _diffColumn('New', diff.new || [], '#e74c3c', 'Present in After, absent from Before.') +
      _diffColumn('Shared', diff.shared || [], 'var(--text-muted)', 'Present in both scans.') +
      _diffColumn('Resolved', diff.resolved || [], '#3fb950', 'Present in Before, absent from After.') +
    '</div>';
}

function _diffColumn(label, findings, accent, hint) {
  var body = findings.length
    ? buildFindingsTable(findings)
    : '<div style="padding:14px; text-align:center; color:var(--text-muted);">None</div>';
  return '<div class="card" style="padding:0; overflow:hidden; margin:0;">' +
    '<div style="padding:10px 14px; border-bottom:1px solid var(--border); ' +
    'display:flex; align-items:center; justify-content:space-between;">' +
      '<span style="font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.8px; color:' + accent + ';">' +
        label + ' \u00b7 ' + findings.length +
      '</span>' +
      '<span style="font-size:11px; color:var(--text-muted);">' + escapeHtml(hint) + '</span>' +
    '</div>' +
    body +
  '</div>';
}

function _buildHistoryTable(scans) {
  var allSelected = scans.length > 0 && scans.every(function (s) {
    return _selectedHistory[s.id];
  });
  return '<table class="data-table">' +
    '<thead><tr>' +
      '<th style="width:32px;"><input type="checkbox" id="history-select-all" ' +
        (allSelected ? 'checked ' : '') +
        'data-action="toggleHistorySelectAll" aria-label="Select all scans" /></th>' +
      '<th>Date / Time</th><th>File</th><th>Findings</th><th>Score</th><th>Grade</th><th>Trend</th>' +
    '</tr></thead><tbody>' +
    scans.map(function (scan, i) {
      var grade = _gradeFor(scan.score);
      var trend = '<span class="trend-flat">=</span>';
      if (i < scans.length - 1 && scan.score != null && scans[i + 1].score != null) {
        var diff = scan.score - scans[i + 1].score;
        if (diff > 0) trend = '<span class="trend-up">\u2191 +' + diff + '</span>';
        else if (diff < 0) trend = '<span class="trend-down">\u2193 ' + diff + '</span>';
      }
      var checked = _selectedHistory[scan.id] ? 'checked' : '';
      return '<tr class="clickable history-row" data-scan-id="' + scan.id + '" ' +
        'data-action="highlightHistoryScan" data-arg="' + scan.id + '">' +
        '<td data-action="stopClickPropagation" style="width:32px;">' +
          '<input type="checkbox" ' + checked +
            ' data-action="toggleHistorySelect" data-arg="' + scan.id + '" ' +
            'aria-label="Select scan ' + scan.id + '" /></td>' +
        '<td>' + escapeHtml(scan.scanned_at || '-') + '</td>' +
        '<td style="color:var(--text-muted);">' + escapeHtml(scan.filename || 'Unknown') + '</td>' +
        '<td>' + scan.total_findings + '</td>' +
        '<td style="font-weight:700; color:' + scoreColor(scan.score) + '">' +
          (scan.score != null ? scan.score : '-') + '</td>' +
        '<td>' + (grade ? '<span class="grade-pill grade-' + grade + '">' + grade + '</span>' : '-') + '</td>' +
        '<td>' + trend + '</td>' +
      '</tr>';
    }).join('') +
    '</tbody></table>';
}

export function toggleHistorySelect(id, target, ev) {
  if (ev) ev.stopPropagation();
  id = String(id);
  if (_selectedHistory[id]) delete _selectedHistory[id];
  else _selectedHistory[id] = true;
  renderHistoryPage();
}

export async function toggleHistorySelectAll(arg, target) {
  var checked;
  if (target && typeof target.checked === 'boolean') checked = target.checked;
  else checked = (arg === true || arg === 'true');
  _selectedHistory = {};
  if (checked) {
    var scans = await fetchScans(200);
    scans.forEach(function (s) { _selectedHistory[s.id] = true; });
  }
  renderHistoryPage();
}

export async function deleteSelectedHistory() {
  var ids = Object.keys(_selectedHistory).map(function (k) { return +k; });
  if (ids.length === 0) return;
  var msg = 'Delete ' + ids.length + ' scan' + (ids.length === 1 ? '' : 's') +
            ' and all associated findings? This cannot be undone.';
  if (!window.confirm(msg)) return;
  var result = await apiDeleteHistory(ids);
  if (!result.ok) {
    toastError('Delete failed: ' + ((result.data && result.data.detail) || 'network error'));
    return;
  }
  var deleted = result.data && typeof result.data.deleted === 'number' ? result.data.deleted : ids.length;
  showToast('Deleted ' + deleted + ' scan' + (deleted === 1 ? '' : 's'), 'success');
  _selectedHistory = {};
  invalidateScansCache();
  invalidateFindingsCache();
  renderHistoryPage();
}

// Clicking a table row highlights the matching point on the chart.
export function highlightHistoryScan(scanId, rowEl) {
  // scanId may arrive as a string via data-arg; normalize to number.
  scanId = Number(scanId);
  document.querySelectorAll('.history-row.highlight').forEach(function (r) {
    if (r !== rowEl) r.classList.remove('highlight');
  });
  var isAlready = rowEl.classList.toggle('highlight');

  if (!_historyChartInstance) return;

  if (!isAlready) {
    _historyHighlightIdx = -1;
  } else {
    var labels = _historyChartInstance.data._scanIds || [];
    _historyHighlightIdx = labels.indexOf(scanId);
  }
  _historyChartInstance.update('none');
}

function _initHistoryLineChart(scans) {
  if (typeof Chart === 'undefined') return;
  var canvas = document.getElementById('history-line-chart');
  if (!canvas) return;

  var series = scans.slice().reverse();
  var labels = series.map(function (s) { return (s.scanned_at || '').split(' ')[0] || '-'; });
  var scores = series.map(function (s) { return s.score; });
  var scanIds = series.map(function (s) { return s.id; });

  var styles = getComputedStyle(document.documentElement);
  var accent     = styles.getPropertyValue('--accent').trim() || '#58a6ff';
  var textMuted  = styles.getPropertyValue('--text-muted').trim() || '#8b949e';
  var border     = styles.getPropertyValue('--border').trim() || '#30363d';

  if (_historyChartInstance) { _historyChartInstance.destroy(); }

  _historyChartInstance = new Chart(canvas.getContext('2d'), {
    type: 'line',
    data: {
      labels: labels,
      _scanIds: scanIds,
      datasets: [{
        data: scores,
        borderColor: accent,
        backgroundColor: accent + '22',
        borderWidth: 2,
        fill: true,
        tension: 0.3,
        pointBackgroundColor: function (ctx) {
          return ctx.dataIndex === _historyHighlightIdx ? '#f85149' : accent;
        },
        pointBorderColor: function (ctx) {
          return ctx.dataIndex === _historyHighlightIdx ? '#f85149' : accent;
        },
        pointRadius: function (ctx) {
          return ctx.dataIndex === _historyHighlightIdx ? 6 : 3;
        },
        pointHoverRadius: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend:  { display: false },
        tooltip: {
          callbacks: {
            title: function (items) {
              var i = items[0].dataIndex;
              return series[i].scanned_at || '';
            },
            label: function (item) {
              return 'Score: ' + item.parsed.y;
            }
          }
        }
      },
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
