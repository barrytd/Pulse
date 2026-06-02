// reports.js — Reports page.
//
// Reports are now persisted in the DB (reports table, BLOB-backed). This
// page lists every report visible to the caller's org, surfaces KPIs at
// the top, lets the user filter by format / scan / generator / time
// range, download from the DB, and bulk-delete.
'use strict';

import { apiDeleteReports, fetchScans } from './api.js';
import {
  escapeHtml, showToast, toastError, relTimeHtml,
  downloadReport, formatRelativeTime,
} from './dashboard.js';

var _reportsCache = [];
var _kpisCache    = { total: 0, pdf: 0, this_week: 0, storage_bytes: 0 };
var _retentionDays = 90;
var _reportsQuery = '';
// Active filter chips. Keyed by dimension; null means "no chip".
var _filters = {
  format:     null,  // 'pdf' | 'html' | 'json' | 'csv'
  scan:       null,  // scan_id (number)
  generator:  null,  // user_id (number)
  timeRange:  null,  // '7d' | '30d' | '90d' | 'all'
};
// filename -> true
var _selected = {};

async function _fetchReports() {
  var resp = await fetch('/api/reports');
  if (!resp.ok) throw new Error('Failed to load reports: HTTP ' + resp.status);
  var body = await resp.json();
  return body;
}

function _formatBytes(n) {
  n = n || 0;
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

function _timeRangeCutoff(range) {
  // Returns a Date the row's generated_at must be >= for the row to pass.
  if (!range || range === 'all') return null;
  var days = parseInt(range.replace('d', ''), 10);
  if (!days || days <= 0) return null;
  var d = new Date();
  d.setDate(d.getDate() - days);
  return d;
}

function _passesFilters(r) {
  if (_filters.format && (r.format || '').toLowerCase() !== _filters.format) return false;
  if (_filters.scan != null && r.scan_id !== _filters.scan) return false;
  if (_filters.generator != null && r.generated_by !== _filters.generator) return false;
  if (_filters.timeRange) {
    var cutoff = _timeRangeCutoff(_filters.timeRange);
    if (cutoff) {
      var t = new Date(String(r.generated_at || '').replace(' ', 'T'));
      if (isNaN(t) || t < cutoff) return false;
    }
  }
  if (_reportsQuery) {
    var hay = ((r.filename || '') + ' ' + (r.generated_at || '') + ' ' +
               (r.format || '') + ' ' + (r.generated_by_name || '') + ' ' +
               (r.scan_hostname || '')).toLowerCase();
    if (hay.indexOf(_reportsQuery.toLowerCase()) < 0) return false;
  }
  return true;
}

function _filteredRows() {
  return _reportsCache.filter(_passesFilters);
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

function _kpiTilesHtml() {
  var k = _kpisCache || {};
  // Icon + number + label, matching the Findings + Fleet KPI tile
  // component so the Reports page reads as part of the same app.
  function tile(icon, num, label) {
    return '<div class="reports-kpi">' +
      '<div class="reports-kpi-icon"><i data-lucide="' + icon + '"></i></div>' +
      '<div class="reports-kpi-text">' +
        '<div class="reports-kpi-num">' + num + '</div>' +
        '<div class="reports-kpi-label">' + label + '</div>' +
      '</div>' +
    '</div>';
  }
  return '<div class="reports-kpi-strip">' +
    tile('file-text',        (k.total || 0),          'Total reports') +
    tile('file-badge',       (k.pdf || 0),            'PDF reports') +
    tile('calendar-days',    (k.this_week || 0),      'This week') +
    tile('database',         _formatBytes(k.storage_bytes), 'Storage used') +
  '</div>';
}

function _filterChipsHtml() {
  // Build unique value lists from the cache so chips reflect what's
  // actually available, not a hardcoded list.
  var formats = {}, scans = {}, generators = {};
  _reportsCache.forEach(function (r) {
    if (r.format) formats[r.format.toLowerCase()] = true;
    if (r.scan_id != null) scans[r.scan_id] = (r.scan_number != null ? r.scan_number : r.scan_id);
    if (r.generated_by != null) generators[r.generated_by] = r.generated_by_name || ('user #' + r.generated_by);
  });
  var fmtOpts = Object.keys(formats).sort().map(function (f) {
    var on = _filters.format === f;
    return '<button class="filter-chip' + (on ? ' active' : '') + '" ' +
      'data-action="setReportFilter" data-arg="format|' + f + '">' +
      escapeHtml(f.toUpperCase()) + '</button>';
  }).join('');
  var scanOpts = Object.keys(scans).sort().map(function (sid) {
    var on = _filters.scan === Number(sid);
    return '<button class="filter-chip' + (on ? ' active' : '') + '" ' +
      'data-action="setReportFilter" data-arg="scan|' + sid + '">' +
      'Scan #' + escapeHtml(String(scans[sid])) + '</button>';
  }).join('');
  var genOpts = Object.keys(generators).sort().map(function (uid) {
    var on = _filters.generator === Number(uid);
    return '<button class="filter-chip' + (on ? ' active' : '') + '" ' +
      'data-action="setReportFilter" data-arg="generator|' + uid + '">' +
      escapeHtml(String(generators[uid])) + '</button>';
  }).join('');
  var ranges = [['7d', '7 days'], ['30d', '30 days'], ['90d', '90 days'], ['all', 'All time']];
  var timeOpts = ranges.map(function (r) {
    var on = _filters.timeRange === r[0] || (r[0] === 'all' && !_filters.timeRange);
    return '<button class="filter-chip' + (on ? ' active' : '') + '" ' +
      'data-action="setReportFilter" data-arg="timeRange|' + r[0] + '">' +
      escapeHtml(r[1]) + '</button>';
  }).join('');

  // "Clear all" appears only when something is active.
  var anyActive = !!(_filters.format || _filters.scan != null ||
                      _filters.generator != null ||
                      (_filters.timeRange && _filters.timeRange !== 'all'));
  var clearBtn = anyActive
    ? '<button class="filter-chip filter-chip-clear" data-action="clearReportFilters">Clear all</button>'
    : '';

  return '<div class="reports-filters">' +
    (fmtOpts   ? '<div class="filter-group"><span class="filter-group-label">Format</span>' + fmtOpts + '</div>' : '') +
    (scanOpts  ? '<div class="filter-group"><span class="filter-group-label">Scan</span>' + scanOpts + '</div>' : '') +
    (genOpts   ? '<div class="filter-group"><span class="filter-group-label">Generated by</span>' + genOpts + '</div>' : '') +
    '<div class="filter-group"><span class="filter-group-label">Time</span>' + timeOpts + '</div>' +
    clearBtn +
  '</div>';
}

function _renderTable() {
  var rows = _filteredRows();
  var countEl = document.getElementById('reports-count');
  if (countEl) {
    countEl.textContent = rows.length + ' of ' + _reportsCache.length + ' reports';
  }
  // Prune selections that fell off the filtered view.
  var visible = {};
  rows.forEach(function (r) { visible[r.filename] = true; });
  Object.keys(_selected).forEach(function (k) {
    if (!visible[k]) delete _selected[k];
  });
  var headCb = document.getElementById('reports-select-all');
  if (headCb) {
    headCb.checked = rows.length > 0 && rows.every(function (r) { return _selected[r.filename]; });
  }
  var body = document.getElementById('reports-tbody');
  if (!body) return;

  if (rows.length === 0) {
    var msg = _reportsCache.length === 0
      ? ''
      : 'No reports match your filters.';
    body.innerHTML = msg
      ? '<tr><td colspan="7"><div class="dash-empty-note" style="margin:0;">' + msg + '</div></td></tr>'
      : '';
    _updateDeleteBar();
    return;
  }

  body.innerHTML = rows.map(function (r) {
    var href = '/api/reports/' + encodeURIComponent(r.filename);
    var fn = r.filename;
    var fnAttr = escapeHtml(fn);
    var checked = _selected[fn] ? 'checked' : '';
    var scanCell = r.scan_id != null
      ? '<a href="#" data-action="viewScan" data-arg="' + r.scan_id + '" ' +
          'style="color:var(--accent); text-decoration:none;">' +
          'Scan #' + escapeHtml(String(r.scan_number != null ? r.scan_number : r.scan_id)) +
        '</a>' +
        (r.scan_scanned_at
          ? '<div style="font-size:10px; color:var(--text-muted);">' +
            escapeHtml((r.scan_scanned_at || '').split(' ')[0] || '') + '</div>'
          : '')
      : '<span class="muted">—</span>';
    var genName = escapeHtml(r.generated_by_name || (r.generated_by != null ? 'user #' + r.generated_by : '—'));
    return '<tr data-report-filename="' + fnAttr + '">' +
      '<td data-action="stopClickPropagation" style="width:32px;">' +
        '<input type="checkbox" ' + checked +
          ' data-action="toggleReportSelect" data-arg="' + fnAttr + '" ' +
          'aria-label="Select ' + fnAttr + '" /></td>' +
      '<td>' + relTimeHtml(r.generated_at) + '</td>' +
      '<td>' + scanCell + '</td>' +
      '<td><span class="fmt-badge ' + _formatBadgeClass(r.format) + '">' + escapeHtml((r.format || '?').toUpperCase()) + '</span></td>' +
      '<td class="mono num">' + _formatBytes(r.file_size || r.size_bytes || 0) + '</td>' +
      '<td>' + genName + '</td>' +
      '<td class="col-actions">' +
        '<a class="btn btn-sm btn-icon" href="' + href + '" data-default="allow" download title="Download"><i data-lucide="download"></i></a> ' +
        '<button class="btn btn-sm btn-icon btn-danger" data-action="deleteReport" data-arg="' + fnAttr + '" title="Delete"><i data-lucide="trash-2"></i></button>' +
      '</td>' +
    '</tr>';
  }).join('');
  _updateDeleteBar();
}

export function setReportsQueryFromInput(arg, target) {
  _reportsQuery = (target && target.value) || '';
  _renderTable();
}

export function setReportFilter(spec) {
  if (!spec) return;
  var parts = String(spec).split('|');
  var dim = parts[0], val = parts.slice(1).join('|');
  if (dim === 'format') {
    _filters.format = (_filters.format === val) ? null : val;
  } else if (dim === 'scan') {
    var sid = Number(val);
    _filters.scan = (_filters.scan === sid) ? null : sid;
  } else if (dim === 'generator') {
    var gid = Number(val);
    _filters.generator = (_filters.generator === gid) ? null : gid;
  } else if (dim === 'timeRange') {
    _filters.timeRange = (val === 'all') ? null : val;
  }
  _rerender();
}

export function clearReportFilters() {
  _filters = { format: null, scan: null, generator: null, timeRange: null };
  _reportsQuery = '';
  _rerender();
}

export function toggleReportSelect(filename, target, ev) {
  if (ev) ev.stopPropagation();
  if (!filename) return;
  if (_selected[filename]) delete _selected[filename];
  else _selected[filename] = true;
  _updateDeleteBar();
  var headCb = document.getElementById('reports-select-all');
  if (headCb) {
    var rows = _filteredRows();
    headCb.checked = rows.length > 0 && rows.every(function (r) { return _selected[r.filename]; });
  }
}

export function toggleReportSelectAll(arg, target) {
  var checked;
  if (target && typeof target.checked === 'boolean') checked = target.checked;
  else checked = (arg === true || arg === 'true');
  _selected = {};
  if (checked) {
    _filteredRows().forEach(function (r) { _selected[r.filename] = true; });
  }
  _renderTable();
}

export async function deleteSelectedReports() {
  var names = _selectedFilenames();
  if (names.length === 0) return;
  var msg = 'Delete ' + names.length + ' report' + (names.length === 1 ? '' : 's') +
            '? This cannot be undone.';
  if (!window.confirm(msg)) return;
  var result = await apiDeleteReports(names);
  if (!result.ok) {
    toastError('Delete failed: ' + ((result.data && result.data.detail) || 'network error'));
    return;
  }
  var deleted = result.data && typeof result.data.deleted === 'number'
    ? result.data.deleted : names.length;
  showToast('Deleted ' + deleted + ' report' + (deleted === 1 ? '' : 's'), 'success');
  _selected = {};
  // Refetch to keep KPIs accurate.
  await _refresh();
}

export async function deleteReport(filename) {
  if (!filename) return;
  if (!window.confirm('Delete "' + filename + '"? This cannot be undone.')) return;
  try {
    var resp = await fetch('/api/reports/' + encodeURIComponent(filename), { method: 'DELETE' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    delete _selected[filename];
    showToast('Report deleted.');
    await _refresh();
  } catch (e) {
    toastError('Failed to delete report: ' + e.message);
  }
}

function _rerender() {
  var chipsEl = document.getElementById('reports-filter-chips');
  if (chipsEl) chipsEl.outerHTML = _filterChipsHtml().replace('class="reports-filters"',
    'class="reports-filters" id="reports-filter-chips"');
  if (window.lucide && window.lucide.createIcons) {
    try { window.lucide.createIcons(); } catch (e) {}
  }
  _renderTable();
}

async function _refresh() {
  try {
    var body = await _fetchReports();
    _reportsCache  = body.reports || [];
    _kpisCache     = body.kpis || _kpisCache;
    _retentionDays = body.retention_days || 90;
  } catch (e) {
    toastError(e.message);
  }
  renderReportsPage();
}

export async function renderReportsPage() {
  var c = document.getElementById('content');
  if (!c) return;
  c.innerHTML = '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading reports…</div>';

  try {
    var body = await _fetchReports();
    _reportsCache  = body.reports || [];
    _kpisCache     = body.kpis || _kpisCache;
    _retentionDays = body.retention_days || 90;
  } catch (e) {
    c.innerHTML = '<div class="card"><div class="dash-empty-note">' + escapeHtml(e.message) + '</div></div>';
    return;
  }

  // Prune selections that no longer exist.
  var known = {};
  _reportsCache.forEach(function (r) { known[r.filename] = true; });
  Object.keys(_selected).forEach(function (k) {
    if (!known[k]) delete _selected[k];
  });

  var nSelected = _selectedFilenames().length;
  var deleteBarStyle = nSelected > 0 ? 'flex' : 'none';

  var headHtml =
    '<div class="page-head">' +
      '<div class="page-head-title">Reports</div>' +
      '<div class="page-head-actions">' +
        '<button class="btn btn-primary btn-with-icon" data-action="openGenerateReportModal" data-arg="threat_detection_summary">' +
          '<i data-lucide="file-plus-2"></i><span>Generate Report</span></button>' +
      '</div>' +
    '</div>';

  // Template catalog — Phase 1 ships exactly one template. The
  // markup is structured so dropping in more templates later (and
  // grouping them under more category headers) is a copy-paste job.
  //
  // Vertical card layout: icon -> title -> description (full width) ->
  // Generate button anchored at the bottom. The card's left-border
  // accent comes from a CSS custom property so each category can have
  // its own color without duplicating selectors.
  function templateCardHtml(opts) {
    var styleAttr = opts.accent
      ? ' style="--report-accent:' + opts.accent + ';"'
      : '';
    return '<div class="report-template-card"' + styleAttr + '>' +
      '<div class="report-template-icon" aria-hidden="true">' +
        '<i data-lucide="' + opts.icon + '"></i>' +
      '</div>' +
      '<div class="report-template-name">' + opts.name + '</div>' +
      '<div class="report-template-desc">' + opts.desc + '</div>' +
      '<div class="report-template-actions">' +
        '<button class="btn btn-primary btn-with-icon" ' +
          'data-action="openGenerateReportModal" data-arg="' + opts.slug + '">' +
          '<i data-lucide="file-plus-2"></i><span>Generate</span>' +
        '</button>' +
      '</div>' +
    '</div>';
  }

  var templateCatalogHtml =
    '<div class="report-catalog-section">' +
      '<div class="report-category-label">Threat Detection</div>' +
      '<div class="report-catalog-grid">' +
        templateCardHtml({
          slug:   'threat_detection_summary',
          name:   'Threat Detection Summary',
          icon:   'shield-alert',
          accent: '#ef4444',
          desc:   'Complete summary of detected threats grouped by MITRE tactic, ' +
                  'with attack timeline and repeat offenders. ' +
                  'For security analysts and teams.',
        }) +
      '</div>' +
    '</div>' +
    '<div class="report-catalog-section">' +
      '<div class="report-category-label">Executive</div>' +
      '<div class="report-catalog-grid">' +
        templateCardHtml({
          slug:   'executive_summary',
          name:   'Executive Summary',
          icon:   'briefcase',
          accent: '#8b5cf6',
          desc:   'One-page security overview in plain language for ' +
                  'leadership and stakeholders. No technical jargon.',
        }) +
      '</div>' +
    '</div>' +
    '<div class="report-catalog-section">' +
      '<div class="report-category-label">Compliance</div>' +
      '<div class="report-catalog-grid">' +
        templateCardHtml({
          slug:   'nist_csf_coverage',
          name:   'NIST CSF Coverage Report',
          icon:   'list-checks',
          accent: '#3b82f6',
          desc:   'Detection coverage mapped to the five NIST ' +
                  'Cybersecurity Framework functions, with findings ' +
                  'per function and coverage gaps. For compliance ' +
                  'officers and auditors.',
        }) +
        templateCardHtml({
          slug:   'iso_27001_annex_a',
          name:   'ISO 27001 Annex A Report',
          icon:   'badge-check',
          accent: '#3b82f6',
          desc:   'Detection coverage and findings mapped to ISO 27001 ' +
                  'Annex A controls. For ISO 27001 certification and ' +
                  'audit preparation.',
        }) +
      '</div>' +
    '</div>';

  // First-run empty state — KPIs + filters get rendered too so the
  // page still looks like itself even with zero data.
  if (_reportsCache.length === 0) {
    c.innerHTML =
      headHtml +
      _kpiTilesHtml() +
      templateCatalogHtml +
      '<div class="reports-empty">' +
        '<div class="reports-empty-icon" aria-hidden="true">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
            'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">' +
            '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>' +
            '<polyline points="14 3 14 9 20 9"/>' +
            '<line x1="8" y1="13" x2="16" y2="13"/>' +
            '<line x1="8" y1="17" x2="13" y2="17"/>' +
          '</svg>' +
        '</div>' +
        '<h3 class="reports-empty-title">No reports generated yet</h3>' +
        '<p class="reports-empty-subtitle">' +
          'Generate a report from any completed scan to create a downloadable ' +
          'security assessment. Reports are saved here for ' + _retentionDays +
          ' days so your team can access them anytime.' +
        '</p>' +
        '<div class="reports-empty-actions">' +
          '<button class="btn btn-primary btn-with-icon" data-action="openGenerateReportModal">' +
            '<i data-lucide="file-plus-2"></i><span>Generate your first report</span></button>' +
        '</div>' +
      '</div>';
    return;
  }

  c.innerHTML =
    headHtml +
    _kpiTilesHtml() +
    templateCatalogHtml +
    '<div class="report-history-label">Generated Reports</div>' +
    _filterChipsHtml().replace('class="reports-filters"',
      'class="reports-filters" id="reports-filter-chips"') +
    '<div id="reports-delete-bar" class="bulk-bar" style="display:' + deleteBarStyle + ';">' +
      '<span class="bulk-bar-count">' + nSelected + ' selected</span>' +
      '<button class="btn btn-danger" id="reports-delete-btn" data-action="deleteSelectedReports">' +
        'Delete ' + nSelected + ' report' + (nSelected === 1 ? '' : 's') +
      '</button>' +
      '<a class="bulk-bar-clear" data-action="toggleReportSelectAll" data-arg="false">Clear selection</a>' +
    '</div>' +
    '<div class="card">' +
      '<div class="section-label" style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">' +
        '<span>Saved reports <span id="reports-count" style="color:var(--text-muted); font-weight:400; margin-left:8px; font-size:11px;"></span></span>' +
        '<input type="search" id="reports-search" placeholder="Filter by filename, host, or generator…" ' +
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
            '<th>Scan</th>' +
            '<th>Format</th>' +
            '<th>Size</th>' +
            '<th>Generated by</th>' +
            '<th>Actions</th>' +
          '</tr></thead>' +
          '<tbody id="reports-tbody"></tbody>' +
        '</table>' +
      '</div>' +
      '<div style="margin-top:10px; font-size:11px; color:var(--text-muted);">' +
        'Reports are retained for ' + _retentionDays + ' days.' +
      '</div>' +
    '</div>';

  _renderTable();
}

// -----------------------------------------------------------------
// Generate Report modal — template-driven (Phase 1: Threat Detection
// Summary). The same modal handles "single scan" vs "recent activity"
// scope via the radio group in index.html.
// -----------------------------------------------------------------

// Per-template metadata. Keys: title + subtitle shown in the modal,
// scope_default ("scan" or "recent") for which radio gets pre-selected,
// scope_only set when a template only makes sense over a time window
// (executive summary needs comparison periods, so per-scan is hidden).
var _TEMPLATES = {
  threat_detection_summary: {
    title:    'Generate Threat Detection Summary',
    subtitle: 'Pulse rolls your finding data into a tactic-grouped ' +
              'assessment with attack timeline and repeat offenders. ' +
              'Saves to the Reports page and streams to your downloads.',
    scope_default: 'scan',
  },
  executive_summary: {
    title:    'Generate Executive Summary',
    subtitle: 'A one-page plain-language overview for leadership: ' +
              'overall grade, what it means, top risks, and recommendations. ' +
              'Pick the reporting period; Pulse compares it to the previous ' +
              'period of the same length.',
    scope_default: 'recent',
    scope_only:    'recent',  // hide the per-scan radio for this template
  },
  nist_csf_coverage: {
    title:    'Generate NIST CSF Coverage Report',
    subtitle: 'Detection coverage mapped to the five NIST Cybersecurity ' +
              'Framework functions, with findings per function and ' +
              'coverage gaps. Pick the reporting period and format.',
    scope_default: 'recent',
    scope_only:    'recent',
  },
  iso_27001_annex_a: {
    title:    'Generate ISO 27001 Annex A Report',
    subtitle: 'Detection coverage mapped to ISO 27001 Annex A controls, ' +
              'with findings per control and clauses lacking coverage. ' +
              'Pick the reporting period and format.',
    scope_default: 'recent',
    scope_only:    'recent',
  },
};

export async function openGenerateReportModal(templateSlug) {
  var modal = document.getElementById('generate-report-modal');
  if (!modal) return;
  var slug = templateSlug || 'threat_detection_summary';
  var tmpl = _TEMPLATES[slug] || _TEMPLATES.threat_detection_summary;
  var titleEl = document.getElementById('genrep-title');
  var subEl   = document.getElementById('genrep-subtitle');
  var tmplEl  = document.getElementById('genrep-template');
  if (titleEl) titleEl.textContent = tmpl.title;
  if (subEl)   subEl.textContent   = tmpl.subtitle;
  if (tmplEl)  tmplEl.value        = slug;

  // Per-template scope behavior: some templates (executive summary)
  // only make sense over a date range, so we hide the per-scan radio
  // entirely for those. Others default to per-scan but allow switching.
  var defaultScope = tmpl.scope_default || 'scan';
  var scopeOnly    = tmpl.scope_only;       // optional pin
  var scanLabelEl = document.querySelector(
    'input[name="genrep-scope"][value="scan"]'
  );
  var recentLabelEl = document.querySelector(
    'input[name="genrep-scope"][value="recent"]'
  );
  if (scanLabelEl) {
    var scanWrap = scanLabelEl.closest('label');
    if (scanWrap) {
      scanWrap.style.display = (scopeOnly === 'recent') ? 'none' : '';
    }
  }
  if (recentLabelEl) {
    var recentWrap = recentLabelEl.closest('label');
    if (recentWrap) {
      recentWrap.style.display = (scopeOnly === 'scan') ? 'none' : '';
    }
  }
  var pick = document.querySelector(
    'input[name="genrep-scope"][value="' + defaultScope + '"]'
  );
  if (pick) pick.checked = true;
  onGenrepScopeChange();

  var sel = document.getElementById('genrep-scan');
  if (sel) sel.innerHTML = '<option>Loading scans…</option>';
  modal.classList.add('open');
  try {
    var scans = await fetchScans(200);
    if (!scans.length) {
      if (sel) sel.innerHTML = '<option value="">No completed scans yet — upload one first.</option>';
      return;
    }
    if (sel) {
      sel.innerHTML = scans.map(function (s) {
        var num = s.number != null ? s.number : s.id;
        var label = '#' + num + ' · ' + (s.filename || 'Unknown') + ' · ' +
                    formatRelativeTime(s.scanned_at) + ' · ' +
                    (s.total_findings || 0) + ' finding' +
                    ((s.total_findings || 0) === 1 ? '' : 's');
        return '<option value="' + s.id + '">' + escapeHtml(label) + '</option>';
      }).join('');
    }
  } catch (e) {
    if (sel) sel.innerHTML = '<option value="">Failed to load scans.</option>';
  }
}

export function onGenrepScopeChange() {
  var scopeEl = document.querySelector('input[name="genrep-scope"]:checked');
  var scope = scopeEl ? scopeEl.value : 'scan';
  var scanRow = document.getElementById('genrep-scan-row');
  var daysRow = document.getElementById('genrep-days-row');
  var customRow = document.getElementById('genrep-custom-row');
  if (scanRow)   scanRow.style.display   = (scope === 'scan') ? '' : 'none';
  if (daysRow)   daysRow.style.display   = (scope === 'recent') ? '' : 'none';
  if (customRow) customRow.style.display = 'none';
  // When in recent mode, the days dropdown might already be on "custom".
  if (scope === 'recent') {
    var daysEl = document.getElementById('genrep-days');
    if (daysEl && daysEl.value === 'custom' && customRow) {
      customRow.style.display = '';
    }
  }
}

export function onGenrepDaysChange() {
  var daysEl = document.getElementById('genrep-days');
  var customRow = document.getElementById('genrep-custom-row');
  if (!customRow) return;
  customRow.style.display = (daysEl && daysEl.value === 'custom') ? '' : 'none';
}

export function closeGenerateReportModal() {
  var modal = document.getElementById('generate-report-modal');
  if (modal) modal.classList.remove('open');
}

export async function submitGenerateReport() {
  var tmplEl = document.getElementById('genrep-template');
  var template = tmplEl ? tmplEl.value : 'threat_detection_summary';
  var scopeEl = document.querySelector('input[name="genrep-scope"]:checked');
  var scopeKind = scopeEl ? scopeEl.value : 'scan';
  var fmtEl = document.querySelector('input[name="genrep-format"]:checked');
  var fmt = fmtEl ? fmtEl.value : 'pdf';
  var scope = {};
  if (scopeKind === 'scan') {
    var sel = document.getElementById('genrep-scan');
    var scanId = sel ? Number(sel.value) : 0;
    if (!scanId) { toastError('Pick a scan to generate from.'); return; }
    scope.scan_id = scanId;
  } else {
    var daysEl = document.getElementById('genrep-days');
    var rawDays = daysEl ? daysEl.value : '30';
    if (rawDays === 'custom') {
      var customEl = document.getElementById('genrep-custom-days');
      var customDays = customEl ? Number(customEl.value) : 0;
      if (!customDays || customDays < 1 || customDays > 365) {
        toastError('Custom range must be 1 to 365 days.');
        return;
      }
      scope.days = customDays;
    } else {
      scope.days = Number(rawDays) || 30;
    }
  }

  showToast('Generating report…');
  try {
    var resp = await fetch('/api/reports/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ template: template, format: fmt, scope: scope }),
    });
    if (!resp.ok) {
      var detail;
      try { detail = (await resp.json()).detail; } catch (e) { detail = 'HTTP ' + resp.status; }
      throw new Error(detail || 'Generate failed');
    }
    var blob = await resp.blob();
    // Pull the filename out of Content-Disposition so the download
    // matches what got saved to the Reports table.
    var cd = resp.headers.get('content-disposition') || '';
    var m = /filename="?([^";]+)/.exec(cd);
    var filename = (m && m[1]) || 'pulse_report.' + fmt;
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    showToast('Report saved and downloaded. View it anytime on the Reports page.',
              'success');
    closeGenerateReportModal();
    // Refresh the page if we're already on it so the new row appears.
    if (location.pathname === '/reports' || location.hash === '#reports' ||
        document.querySelector('.report-template-card')) {
      renderReportsPage();
    }
  } catch (e) {
    toastError('Could not generate report: ' + e.message);
  }
}

// Click-outside-to-close + Escape — mirrors the upload modal pattern.
(function _wireGenerateReportModal() {
  var modal = document.getElementById('generate-report-modal');
  if (!modal) return;
  modal.addEventListener('click', function (e) {
    if (e.target === this) closeGenerateReportModal();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && modal.classList.contains('open')) {
      closeGenerateReportModal();
    }
  });
})();
