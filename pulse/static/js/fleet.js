// fleet.js — Fleet overview page.
// A constrained, sortable host table with a top filter bar (search + risk +
// status) and KPI tiles that pre-filter by risk. Clicking a row opens an
// enriched host drawer (posture + severity breakdown + findings list + real
// actions). Styling follows .claude/skills/pulse-design.md.
'use strict';

import { fetchFleet } from './api.js';
import { navigate } from './navigation.js';
import { escapeHtml, scoreColorClass, _gradeFor, sevPillHtml, relTimeHtml, showToast, toastError } from './dashboard.js';
import { openDrawer, closeDrawer } from './drawer.js';

var _fleetCache = [];
var _search = '';
var _riskFilter = 'all';    // all | critical | high | fair | secure
var _statusFilter = 'all';  // all | online | stale | offline
var _sortKey = 'risk';      // risk | host | score | scans | findings | lastscan
var _sortDir = 'asc';       // for 'risk', asc = worst-first

// --- classification ------------------------------------------------------
// One risk model drives both the KPI tiles and the Risk dropdown so they
// never disagree. Bands by latest score: <40 critical, 40-59 high, 60-79
// fair, 80+ secure. Hosts with no score yet are 'unknown' (counted only in
// Total / "All risk").
function _riskBand(h) {
  if (h.latest_score == null) return 'unknown';
  var s = h.latest_score;
  if (s < 40) return 'critical';
  if (s < 60) return 'high';
  if (s < 80) return 'fair';
  return 'secure';
}
var _RISK_RANK = { critical: 0, high: 1, fair: 2, secure: 3, unknown: 4 };

// online = scanned within 24h, stale = scanned but older, offline = never.
function _statusOf(h) {
  if (!h.last_scan_at) return 'offline';
  var t = Date.parse(String(h.last_scan_at).replace(' ', 'T'));
  if (isNaN(t)) return 'offline';
  return (Date.now() - t) < (24 * 3600 * 1000) ? 'online' : 'stale';
}

function _num(v) { return (v == null || isNaN(v)) ? -1 : Number(v); }
function _ts(v) { var t = v ? Date.parse(String(v).replace(' ', 'T')) : NaN; return isNaN(t) ? 0 : t; }

// --- KPI tiles -----------------------------------------------------------
function _buildKpis(hosts) {
  var c = { critical: 0, high: 0, fair: 0, secure: 0 };
  hosts.forEach(function (h) { var b = _riskBand(h); if (c[b] != null) c[b] += 1; });
  return [
    { key: 'all',      label: 'Total Hosts', value: hosts.length, tone: 'info' },
    { key: 'critical', label: 'Critical',    value: c.critical,   tone: 'error' },
    { key: 'high',     label: 'High Risk',   value: c.high,       tone: 'warn' },
    { key: 'fair',     label: 'Fair',        value: c.fair,       tone: 'warn' },
    { key: 'secure',   label: 'Secure',      value: c.secure,     tone: 'ok' },
  ];
}

function _kpiStripHtml(kpis) {
  return '<div class="fleet-kpi-strip">' + kpis.map(function (k) {
    var active = k.key === _riskFilter ? ' active' : '';
    return '<button class="fleet-kpi-tile tone-' + k.tone + active + '" ' +
      'data-action="fleetFilterByKpi" data-arg="' + escapeHtml(k.key) + '">' +
      '<div class="fleet-kpi-label">' + escapeHtml(k.label) + '</div>' +
      '<div class="fleet-kpi-value">' + k.value + '</div></button>';
  }).join('') + '</div>';
}

// --- filter bar ----------------------------------------------------------
function _selectOptions(opts, current) {
  return opts.map(function (o) {
    return '<option value="' + o[0] + '"' + (o[0] === current ? ' selected' : '') + '>' + o[1] + '</option>';
  }).join('');
}

function _filterBarHtml() {
  var risk = [['all', 'All risk'], ['critical', 'Critical'], ['high', 'High'], ['fair', 'Fair'], ['secure', 'Secure']];
  var status = [['all', 'All status'], ['online', 'Online'], ['stale', 'Stale'], ['offline', 'Offline']];
  return '<div class="fleet-filter-bar">' +
    '<input type="search" id="fleet-search" class="dash-filter-search fleet-search" ' +
      'placeholder="Filter by hostname…" value="' + escapeHtml(_search) + '" ' +
      'autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" ' +
      'name="fleet-search-nofill" data-lpignore="true" data-1p-ignore readonly data-nofill="1" ' +
      'data-action-input="fleetSearchInput">' +
    '<label class="fleet-filter-field"><span>Risk</span>' +
      '<select class="dash-filter-select" data-action-change="fleetSetRisk">' + _selectOptions(risk, _riskFilter) + '</select></label>' +
    '<label class="fleet-filter-field"><span>Status</span>' +
      '<select class="dash-filter-select" data-action-change="fleetSetStatus">' + _selectOptions(status, _statusFilter) + '</select></label>' +
    '<button class="btn fleet-export-btn" data-action="exportFleetCsv">Export CSV</button>' +
  '</div>';
}

// --- table ---------------------------------------------------------------
function _applyFilters(hosts) {
  var q = _search.trim().toLowerCase();
  return hosts.filter(function (h) {
    if (q && String(h.hostname || '').toLowerCase().indexOf(q) === -1) return false;
    if (_riskFilter !== 'all' && _riskBand(h) !== _riskFilter) return false;
    if (_statusFilter !== 'all' && _statusOf(h) !== _statusFilter) return false;
    return true;
  });
}

function _sortHosts(hosts) {
  var arr = hosts.slice();
  arr.sort(function (a, b) {
    var d = 0;
    switch (_sortKey) {
      case 'host':     d = String(a.hostname || '').localeCompare(String(b.hostname || '')); break;
      case 'score':    d = _num(a.latest_score) - _num(b.latest_score); break;
      case 'scans':    d = (a.scan_count || 0) - (b.scan_count || 0); break;
      case 'findings': d = (a.total_findings || 0) - (b.total_findings || 0); break;
      case 'lastscan': d = _ts(a.last_scan_at) - _ts(b.last_scan_at); break;
      default: // 'risk' — worst band first, lower score breaks ties
        d = _RISK_RANK[_riskBand(a)] - _RISK_RANK[_riskBand(b)] ||
            (_num(a.latest_score) - _num(b.latest_score));
    }
    return _sortDir === 'desc' ? -d : d;
  });
  return arr;
}

function _sortArrow(key) {
  if (_sortKey !== key) return '';
  return ' <span class="fleet-sort-arrow">' + (_sortDir === 'asc' ? '▲' : '▼') + '</span>';
}

function _statusDotHtml(h) {
  var st = _statusOf(h);
  var title = st === 'online' ? 'Online — scanned within 24h'
            : st === 'stale'  ? 'Stale — last scan over 24h ago'
            : 'Offline — no scan on record';
  return '<span class="status-dot status-' + st + '" title="' + title + '"></span>';
}

function _buildFleetTable(hosts) {
  if (!hosts.length) return '<div class="fleet-empty-note">No hosts match these filters.</div>';
  var rows = hosts.map(function (h) {
    var score = (h.latest_score == null) ? '—' : h.latest_score;
    var label = h.latest_grade || '';
    var scoreCls = h.latest_score != null ? scoreColorClass(h.latest_score) : '';
    var worst = h.worst_severity || 'NONE';
    var hn = escapeHtml(h.hostname);
    return '<tr class="clickable" data-action="fleetOpenHost" data-arg="' + hn + '">' +
      '<td class="fleet-col-host">' + _statusDotHtml(h) + '<span class="fleet-host-name">' + hn + '</span></td>' +
      '<td class="' + scoreCls + '"><span class="fleet-score-num">' + score + '</span>' +
        (label ? ' <span class="muted">(' + escapeHtml(label) + ')</span>' : '') + '</td>' +
      '<td>' + sevPillHtml(worst) + '</td>' +
      '<td class="fleet-col-num">' + (h.scan_count || 0) + '</td>' +
      '<td class="fleet-col-num">' + (h.total_findings || 0) + '</td>' +
      '<td class="fleet-col-right">' + relTimeHtml(h.last_scan_at) + '</td>' +
      '</tr>';
  }).join('');

  function th(key, label, cls) {
    return '<th class="sortable' + (cls ? ' ' + cls : '') + (_sortKey === key ? ' sorted' : '') + '" ' +
      'data-action="fleetSort" data-arg="' + key + '">' + label + _sortArrow(key) + '</th>';
  }

  return '<table class="data-table fleet-table">' +
    '<colgroup>' +
      '<col style="width:28%"><col style="width:16%"><col style="width:16%">' +
      '<col style="width:10%"><col style="width:11%"><col style="width:19%">' +
    '</colgroup>' +
    '<thead><tr>' +
      th('host', 'Host') +
      th('score', 'Latest Score') +
      '<th>Worst Severity</th>' +
      th('scans', 'Scans', 'fleet-col-num') +
      th('findings', 'Findings', 'fleet-col-num') +
      th('lastscan', 'Last Scan', 'fleet-col-right') +
    '</tr></thead><tbody>' + rows + '</tbody></table>';
}

// --- render helpers ------------------------------------------------------
function _renderTable() {
  var body = document.getElementById('fleet-body');
  if (body) body.innerHTML = _buildFleetTable(_sortHosts(_applyFilters(_fleetCache)));
}
function _renderStrip() {
  var w = document.getElementById('fleet-kpi-strip-wrap');
  if (w) w.innerHTML = _kpiStripHtml(_buildKpis(_fleetCache));
}
function _renderFilterBar() {
  var w = document.getElementById('fleet-filter-bar-wrap');
  if (w) w.innerHTML = _filterBarHtml();
}

export async function renderFleetPage() {
  var c = document.getElementById('content');
  _fleetCache = await fetchFleet();

  if (!_fleetCache.length) {
    c.innerHTML =
      '<div class="empty-state cta">' +
        '<div class="empty-icon">&#128187;</div>' +
        '<h3>No hosts yet</h3>' +
        '<p>Run a scan or upload a .evtx file — hosts appear here once Pulse tags findings with a computer name.</p>' +
        '<button class="btn btn-primary" data-action="openUploadModal">Upload .evtx</button>' +
      '</div>';
    return;
  }

  c.innerHTML =
    '<div class="fleet-wrap">' +
      '<div class="page-head">' +
        '<div class="page-head-title"><strong>' + _fleetCache.length + '</strong> host' +
          (_fleetCache.length === 1 ? '' : 's') + ' tracked</div>' +
      '</div>' +
      '<div id="fleet-kpi-strip-wrap">' + _kpiStripHtml(_buildKpis(_fleetCache)) + '</div>' +
      '<div id="fleet-filter-bar-wrap">' + _filterBarHtml() + '</div>' +
      '<div class="card fleet-table-card">' +
        '<div id="fleet-body">' + _buildFleetTable(_sortHosts(_applyFilters(_fleetCache))) + '</div>' +
      '</div>' +
      '<div class="fleet-legend">' +
        '<span class="status-dot status-online"></span> Online (scanned &lt;24h)' +
        '<span class="fleet-legend-sep">·</span>' +
        '<span class="status-dot status-stale"></span> Stale (&gt;24h)' +
        '<span class="fleet-legend-sep">·</span>' +
        '<span class="status-dot status-offline"></span> Offline (never scanned)' +
      '</div>' +
    '</div>';
}

// --- actions -------------------------------------------------------------
export function fleetFilterByKpi(key) {
  _riskFilter = key || 'all';
  _renderStrip();
  _renderFilterBar();   // keep the Risk dropdown in sync with the tiles
  _renderTable();
}
export function fleetSetRisk(arg, target) {
  _riskFilter = (target && target.value) || 'all';
  _renderStrip();       // keep the active tile in sync with the dropdown
  _renderTable();
}
export function fleetSetStatus(arg, target) {
  _statusFilter = (target && target.value) || 'all';
  _renderTable();
}
export function fleetSearchInput(arg, target) {
  _search = (target && target.value) || '';
  _renderTable();       // table only, so the search box keeps focus
}
export function fleetSort(key) {
  if (_sortKey === key) {
    _sortDir = _sortDir === 'asc' ? 'desc' : 'asc';
  } else {
    _sortKey = key;
    _sortDir = 'asc';
  }
  _renderTable();
}
export function exportFleetCsv() {
  window.location.href = '/api/fleet/export.csv';
}

// Deep-link into the Findings page filtered to a single host. _syncUrl in
// navigation.js preserves location.search, so setting it before navigate()
// lands on /findings?host=… and the Findings page hydrates the host filter.
function _gotoFindingsForHost(hostname) {
  if (!hostname) return;
  try { closeDrawer(); } catch (e) {}
  try {
    window.history.replaceState(null, '', '/findings?host=' + encodeURIComponent(hostname));
  } catch (e) {}
  navigate('findings');
}
export function fleetViewFindings(hostname) { _gotoFindingsForHost(hostname); }

/** Launch the Incident Investigation Report modal pre-scoped to a host. */
export function fleetGenerateIncidentReport(host) {
  if (!host) { toastError('Could not determine which host to report on.'); return; }
  import('./reports.js')
    .then(function (m) {
      if (!m || typeof m.generateIncidentReportForHost !== 'function') {
        throw new Error('report module missing generateIncidentReportForHost');
      }
      return m.generateIncidentReportForHost(host);
    })
    .catch(function (err) {
      console.error('Fleet incident report failed for host', host, err);
      toastError('Could not open the incident report dialog: ' +
        ((err && err.message) || 'unknown error'));
    });
}

// --- host drawer ---------------------------------------------------------
function _sevBreakdownHtml(bySev) {
  var order = [['CRITICAL', 'critical'], ['HIGH', 'high'], ['MEDIUM', 'medium'], ['LOW', 'low']];
  var sum = order.reduce(function (a, o) { return a + (bySev[o[0]] || 0); }, 0);
  if (!sum) return '<div class="fleet-drawer-muted">No findings on this host.</div>';
  var bar = order.map(function (o) {
    var n = bySev[o[0]] || 0;
    if (!n) return '';
    return '<span class="fleet-sevbar-seg sev-' + o[1] + '" style="width:' + ((n / sum) * 100) + '%" ' +
      'title="' + n + ' ' + o[0] + '"></span>';
  }).join('');
  var counts = order.map(function (o) {
    var n = bySev[o[0]] || 0;
    var name = o[0].charAt(0) + o[0].slice(1).toLowerCase();
    return '<span class="fleet-sevcount"><span class="fleet-sevdot sev-' + o[1] + '"></span>' +
      '<strong>' + n + '</strong> ' + name + '</span>';
  }).join('');
  return '<div class="fleet-sevbar">' + bar + '</div><div class="fleet-sevcounts">' + counts + '</div>';
}

function _findingsListHtml(findings, hostname, total) {
  if (!findings.length) return '<div class="fleet-drawer-muted">No findings recorded for this host.</div>';
  var shown = findings.slice(0, 8);
  var rows = shown.map(function (f) {
    var sev = String(f.severity || 'LOW').toLowerCase();
    return '<div class="fleet-finding-row" role="button" tabindex="0" ' +
      'data-action="fleetViewFindings" data-arg="' + escapeHtml(hostname) + '">' +
      '<span class="fleet-finding-dot sev-' + sev + '"></span>' +
      '<span class="fleet-finding-rule">' + escapeHtml(f.rule || 'Unknown') + '</span>' +
      '<span class="fleet-finding-time">' + relTimeHtml(f.timestamp) + '</span></div>';
  }).join('');
  var more = (total > shown.length)
    ? '<a class="fleet-viewall" data-action="fleetViewFindings" data-arg="' + escapeHtml(hostname) + '">' +
        'View all ' + total + ' findings for this host →</a>'
    : '';
  return '<div class="fleet-finding-list">' + rows + '</div>' + more;
}

export async function fleetOpenHost(hostname) {
  if (!hostname) return;
  var host = _fleetCache.find(function (h) { return h.hostname === hostname; });
  if (!host) return;

  var detail = null;
  try {
    var r = await fetch('/api/fleet/host/' + encodeURIComponent(hostname), { credentials: 'same-origin' });
    if (r.ok) detail = await r.json();
  } catch (e) { detail = null; }
  var bySev = (detail && detail.by_severity) || {};
  var findings = (detail && detail.findings) || [];
  var total = (detail && typeof detail.total === 'number') ? detail.total : (host.total_findings || 0);

  var score = (host.latest_score == null) ? '—' : host.latest_score;
  var grade = host.latest_grade || (host.latest_score != null ? _gradeFor(host.latest_score) : '');
  var worst = (host.worst_severity || 'NONE').toUpperCase();
  var tone  = worst === 'CRITICAL' ? 'critical' : worst === 'HIGH' ? 'high'
            : worst === 'MEDIUM' ? 'medium' : worst === 'LOW' ? 'low' : 'info';
  var st = _statusOf(host);
  var statusText = st === 'online' ? 'Online' : st === 'stale' ? 'Stale' : 'Offline';
  var statusTone = st === 'online' ? 'ok' : st === 'stale' ? 'warn' : 'off';

  openDrawer({
    title: host.hostname,
    subtitle: 'Fleet host overview',
    badges: [
      { text: statusText, tone: statusTone },
      { text: (worst === 'NONE' ? 'No alerts' : worst), tone: tone },
    ],
    sections: [
      {
        label: 'Posture',
        html: '<div class="kv">' +
          '<div class="k">Latest score</div><div class="v">' + escapeHtml(String(score)) +
            (grade ? ' <span class="muted">(' + escapeHtml(grade) + ')</span>' : '') + '</div>' +
          '<div class="k">Worst severity</div><div class="v">' + sevPillHtml(worst) + '</div>' +
          '<div class="k">Scans recorded</div><div class="v">' + (host.scan_count || 0) + '</div>' +
          '<div class="k">Total findings</div><div class="v">' + (host.total_findings || 0) + '</div>' +
          '<div class="k">Last scan</div><div class="v">' + relTimeHtml(host.last_scan_at) + '</div>' +
        '</div>',
      },
      { label: 'Severity breakdown', html: _sevBreakdownHtml(bySev) },
      { label: 'Findings on this host', html: _findingsListHtml(findings, host.hostname, total) },
    ],
    actions: [
      { label: 'Generate report', variant: 'primary',
        onClick: function () { closeDrawer(); fleetGenerateIncidentReport(host.hostname); } },
      { label: 'View all findings', variant: 'secondary',
        onClick: function () { _gotoFindingsForHost(host.hostname); } },
      { label: 'Close', variant: 'secondary', onClick: closeDrawer },
    ],
  });
}
