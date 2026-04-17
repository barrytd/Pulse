// reports.js — Reports page. Lists every file in the server's
// reports/ directory with Download + Delete controls. Search box
// filters client-side by filename or generated date.
'use strict';

import { escapeHtml, showToast, toastError } from './dashboard.js';

var _reportsCache = [];
var _reportsQuery = '';

async function _fetchReports() {
  var resp = await fetch('/api/reports');
  if (!resp.ok) throw new Error('Failed to load reports: HTTP ' + resp.status);
  var body = await resp.json();
  return body.reports || [];
}

function _formatBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
  return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

function _formatBadgeClass(fmt) {
  var f = (fmt || '').toLowerCase();
  if (f === 'html') return 'fmt-html';
  if (f === 'pdf')  return 'fmt-pdf';
  if (f === 'json') return 'fmt-json';
  if (f === 'csv')  return 'fmt-csv';
  return 'fmt-other';
}

function _applyQuery(rows, q) {
  if (!q) return rows;
  var needle = q.toLowerCase();
  return rows.filter(function (r) {
    var hay = (r.filename + ' ' + r.generated_at + ' ' + r.format).toLowerCase();
    return hay.indexOf(needle) >= 0;
  });
}

function _renderTable() {
  var rows = _applyQuery(_reportsCache, _reportsQuery);
  var body = document.getElementById('reports-tbody');
  var countEl = document.getElementById('reports-count');
  if (countEl) {
    countEl.textContent = rows.length + ' of ' + _reportsCache.length + ' reports';
  }
  if (!body) return;

  if (rows.length === 0) {
    var msg = _reportsCache.length === 0
      ? 'No reports yet. Generate one from a scan or run <code>python main.py --logs \u2026 --format html</code>.'
      : 'No reports match your search.';
    body.innerHTML = '<tr><td colspan="5"><div class="dash-empty-note" style="margin:0;">' + msg + '</div></td></tr>';
    return;
  }

  body.innerHTML = rows.map(function (r) {
    var href = '/api/reports/' + encodeURIComponent(r.filename);
    return '<tr data-report-filename="' + escapeHtml(r.filename) + '">' +
      '<td class="mono">' + escapeHtml(r.generated_at) + '</td>' +
      '<td class="mono">' + escapeHtml(r.filename) + '</td>' +
      '<td><span class="fmt-badge ' + _formatBadgeClass(r.format) + '">' + escapeHtml((r.format || '?').toUpperCase()) + '</span></td>' +
      '<td class="mono num">' + _formatBytes(r.size_bytes || 0) + '</td>' +
      '<td class="col-actions">' +
        '<a class="btn btn-sm" href="' + href + '" data-default="allow" download>Download</a> ' +
        '<button class="btn btn-sm btn-danger" data-action="deleteReport" data-arg="' + escapeHtml(r.filename) + '">Delete</button>' +
      '</td>' +
    '</tr>';
  }).join('');
}

export function setReportsQueryFromInput(arg, target) {
  _reportsQuery = (target && target.value) || '';
  _renderTable();
}

export async function deleteReport(filename) {
  if (!filename) return;
  if (!window.confirm('Delete "' + filename + '" from disk? This cannot be undone.')) return;
  try {
    var resp = await fetch('/api/reports/' + encodeURIComponent(filename), { method: 'DELETE' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    _reportsCache = _reportsCache.filter(function (r) { return r.filename !== filename; });
    _renderTable();
    showToast('Report deleted.');
  } catch (e) {
    toastError('Failed to delete report: ' + e.message);
  }
}

export async function renderReportsPage() {
  var c = document.getElementById('content');
  c.innerHTML = '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading reports\u2026</div>';

  try {
    _reportsCache = await _fetchReports();
  } catch (e) {
    c.innerHTML = '<div class="card"><div class="dash-empty-note">' + escapeHtml(e.message) + '</div></div>';
    return;
  }

  c.innerHTML =
    '<div class="card">' +
      '<div class="section-label" style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">' +
        '<span>Generated Reports <span id="reports-count" style="color:var(--text-muted); font-weight:400; margin-left:8px; font-size:11px;"></span></span>' +
        '<input type="search" id="reports-search" placeholder="Filter by filename or date\u2026" ' +
          'class="search-box" ' +
          'data-action-input="setReportsQueryFromInput" ' +
          'value="' + escapeHtml(_reportsQuery) + '" />' +
      '</div>' +
      '<div style="overflow-x:auto;">' +
        '<table class="data-table reports-table">' +
          '<thead><tr>' +
            '<th>Generated</th>' +
            '<th>Filename</th>' +
            '<th>Format</th>' +
            '<th>Size</th>' +
            '<th>Actions</th>' +
          '</tr></thead>' +
          '<tbody id="reports-tbody"></tbody>' +
        '</table>' +
      '</div>' +
    '</div>';

  _renderTable();
}
