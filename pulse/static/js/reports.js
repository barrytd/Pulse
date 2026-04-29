// reports.js — Reports page. Lists every file in the server's
// reports/ directory with Download + Delete controls. Search box
// filters client-side by filename or generated date. Bulk-select
// replicates the Scans page pattern: a per-row checkbox + select-all
// header + sticky action bar with a single confirmation prompt.
'use strict';

import { apiDeleteReports } from './api.js';
import { escapeHtml, showToast, toastError, relTimeHtml } from './dashboard.js';

var _reportsCache = [];
var _reportsQuery = '';
// filename -> true. Keyed by filename since the backend identifies each
// report by its on-disk name; no numeric id to hang selection on.
var _selected = {};

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

function _selectedFilenames() {
  return Object.keys(_selected);
}

function _updateDeleteBar() {
  var bar = document.getElementById('reports-delete-bar');
  var btn = document.getElementById('reports-delete-btn');
  var n = _selectedFilenames().length;
  if (!bar || !btn) return;
  if (n > 0) {
    bar.style.display = 'flex';
    bar.querySelector('.bulk-bar-count').textContent = n + ' selected';
    btn.textContent = 'Delete ' + n + ' report' + (n === 1 ? '' : 's');
  } else {
    bar.style.display = 'none';
  }
}

function _renderTable() {
  var rows = _applyQuery(_reportsCache, _reportsQuery);
  // Drop selections that no longer match any visible row — otherwise
  // the bulk bar keeps claiming rows that the user can't see.
  var visible = {};
  rows.forEach(function (r) { visible[r.filename] = true; });
  Object.keys(_selected).forEach(function (k) {
    if (!visible[k]) delete _selected[k];
  });

  var body = document.getElementById('reports-tbody');
  var countEl = document.getElementById('reports-count');
  if (countEl) {
    countEl.textContent = rows.length + ' of ' + _reportsCache.length + ' reports';
  }
  // Header "select-all" reflects whether every currently-visible row is
  // selected. Matches the scans pattern exactly.
  var headCb = document.getElementById('reports-select-all');
  if (headCb) {
    headCb.checked = rows.length > 0 && rows.every(function (r) { return _selected[r.filename]; });
  }
  if (!body) return;

  if (rows.length === 0) {
    var msg = _reportsCache.length === 0
      ? 'No reports yet. Generate one from a scan or run <code>python main.py --logs \u2026 --format html</code>.'
      : 'No reports match your search.';
    body.innerHTML = '<tr><td colspan="6"><div class="dash-empty-note" style="margin:0;">' + msg + '</div></td></tr>';
    _updateDeleteBar();
    return;
  }

  body.innerHTML = rows.map(function (r) {
    var href = '/api/reports/' + encodeURIComponent(r.filename);
    var fn = r.filename;
    var fnAttr = escapeHtml(fn);
    var checked = _selected[fn] ? 'checked' : '';
    return '<tr data-report-filename="' + fnAttr + '">' +
      '<td data-action="stopClickPropagation" style="width:32px;">' +
        '<input type="checkbox" ' + checked +
          ' data-action="toggleReportSelect" data-arg="' + fnAttr + '" ' +
          'aria-label="Select ' + fnAttr + '" /></td>' +
      '<td>' + relTimeHtml(r.generated_at) + '</td>' +
      '<td class="mono">' + fnAttr + '</td>' +
      '<td><span class="fmt-badge ' + _formatBadgeClass(r.format) + '">' + escapeHtml((r.format || '?').toUpperCase()) + '</span></td>' +
      '<td class="mono num">' + _formatBytes(r.size_bytes || 0) + '</td>' +
      '<td class="col-actions">' +
        '<a class="btn btn-sm btn-with-icon" href="' + href + '" data-default="allow" download><i data-lucide="download"></i><span>Download</span></a> ' +
        '<button class="btn btn-sm btn-danger btn-with-icon" data-action="deleteReport" data-arg="' + fnAttr + '"><i data-lucide="trash-2"></i><span>Delete</span></button>' +
      '</td>' +
    '</tr>';
  }).join('');
  _updateDeleteBar();
}

export function setReportsQueryFromInput(arg, target) {
  _reportsQuery = (target && target.value) || '';
  _renderTable();
}

// Per-row checkbox click. Stops propagation so the row itself doesn't
// get interpreted as a click-to-open (reports don't have a row action
// but the convention matches scans for consistency).
export function toggleReportSelect(filename, target, ev) {
  if (ev) ev.stopPropagation();
  if (!filename) return;
  if (_selected[filename]) delete _selected[filename];
  else _selected[filename] = true;
  _updateDeleteBar();
  // Keep the select-all header in sync after a row toggle.
  var headCb = document.getElementById('reports-select-all');
  if (headCb) {
    var rows = _applyQuery(_reportsCache, _reportsQuery);
    headCb.checked = rows.length > 0 && rows.every(function (r) { return _selected[r.filename]; });
  }
}

// Header checkbox.
export function toggleReportSelectAll(arg, target) {
  var checked;
  if (target && typeof target.checked === 'boolean') checked = target.checked;
  else checked = (arg === true || arg === 'true');
  _selected = {};
  if (checked) {
    _applyQuery(_reportsCache, _reportsQuery).forEach(function (r) {
      _selected[r.filename] = true;
    });
  }
  _renderTable();
}

export async function deleteSelectedReports() {
  var names = _selectedFilenames();
  if (names.length === 0) return;
  var msg = 'Delete ' + names.length + ' report' + (names.length === 1 ? '' : 's') +
            ' from disk? This cannot be undone.';
  if (!window.confirm(msg)) return;
  var result = await apiDeleteReports(names);
  if (!result.ok) {
    toastError('Delete failed: ' + ((result.data && result.data.detail) || 'network error'));
    return;
  }
  var deleted = result.data && typeof result.data.deleted === 'number' ? result.data.deleted : names.length;
  showToast('Deleted ' + deleted + ' report' + (deleted === 1 ? '' : 's'), 'success');
  _selected = {};
  _reportsCache = _reportsCache.filter(function (r) { return names.indexOf(r.filename) === -1; });
  _renderTable();
}

export async function deleteReport(filename) {
  if (!filename) return;
  if (!window.confirm('Delete "' + filename + '" from disk? This cannot be undone.')) return;
  try {
    var resp = await fetch('/api/reports/' + encodeURIComponent(filename), { method: 'DELETE' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    delete _selected[filename];
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

  // Prune selections pointing at files that no longer exist on disk.
  var known = {};
  _reportsCache.forEach(function (r) { known[r.filename] = true; });
  Object.keys(_selected).forEach(function (k) {
    if (!known[k]) delete _selected[k];
  });

  var nSelected = _selectedFilenames().length;
  var deleteBarStyle = nSelected > 0 ? 'flex' : 'none';

  c.innerHTML =
    '<div id="reports-delete-bar" class="bulk-bar" style="display:' + deleteBarStyle + ';">' +
      '<span class="bulk-bar-count">' + nSelected + ' selected</span>' +
      '<button class="btn btn-danger" id="reports-delete-btn" data-action="deleteSelectedReports">' +
        'Delete ' + nSelected + ' report' + (nSelected === 1 ? '' : 's') +
      '</button>' +
      '<a class="bulk-bar-clear" data-action="toggleReportSelectAll" data-arg="false">Clear selection</a>' +
    '</div>' +
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
            '<th style="width:32px;"><input type="checkbox" id="reports-select-all" ' +
              'data-action="toggleReportSelectAll" aria-label="Select all reports" /></th>' +
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
