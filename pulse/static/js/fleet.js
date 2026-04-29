// fleet.js — Fleet overview page.
// Blueprint priority 5: KPI strip up top (clickable tiles that pre-filter
// the list) and a host-detail drawer (click a row) instead of drilling
// straight through to a filtered Dashboard. A "View on Dashboard" action
// inside the drawer preserves the old jump-to-filter workflow.
'use strict';

import { fetchFleet } from './api.js';
import { dashFilterState, writeDashFiltersToURL } from './dashboard.js';
import { navigate } from './navigation.js';
import { escapeHtml, scoreColorClass, _gradeFor, sevPillHtml, relTimeHtml } from './dashboard.js';
import { openDrawer, closeDrawer } from './drawer.js';

var _fleetCache = [];
var _activeKpi  = 'total';     // which KPI tile is currently filtering the table

function _isOnline(h) {
  if (!h.last_scan_at) return false;
  var t = Date.parse(String(h.last_scan_at).replace(' ', 'T'));
  if (isNaN(t)) return false;
  return (Date.now() - t) < (24 * 3600 * 1000);
}

function _isAtRisk(h) {
  return h.latest_score != null && h.latest_score < 50;
}

function _isCritical(h) {
  var s = (h.worst_severity || '').toUpperCase();
  return s === 'CRITICAL';
}

function _isNewlyEnrolled(h) {
  return (h.scan_count || 0) === 1;
}

function _buildKpis(hosts) {
  var online = 0, offline = 0, atRisk = 0, critical = 0, newly = 0;
  hosts.forEach(function (h) {
    if (_isOnline(h)) online += 1; else offline += 1;
    if (_isAtRisk(h)) atRisk += 1;
    if (_isCritical(h)) critical += 1;
    if (_isNewlyEnrolled(h)) newly += 1;
  });
  return [
    { key: 'total',    label: 'Total',            value: hosts.length, tone: 'neutral' },
    { key: 'online',   label: 'Online (24h)',     value: online,       tone: 'ok' },
    { key: 'offline',  label: 'Offline >24h',     value: offline,      tone: 'off' },
    { key: 'atrisk',   label: 'At risk',          value: atRisk,       tone: 'warn' },
    { key: 'critical', label: 'Critical severity',value: critical,     tone: 'error' },
    { key: 'newly',    label: 'Newly enrolled',   value: newly,        tone: 'info' },
  ];
}

function _applyKpiFilter(hosts) {
  switch (_activeKpi) {
    case 'online':   return hosts.filter(_isOnline);
    case 'offline':  return hosts.filter(function (h) { return !_isOnline(h); });
    case 'atrisk':   return hosts.filter(_isAtRisk);
    case 'critical': return hosts.filter(_isCritical);
    case 'newly':    return hosts.filter(_isNewlyEnrolled);
    default:         return hosts;
  }
}

function _kpiStripHtml(kpis) {
  return '<div class="fleet-kpi-strip">' +
    kpis.map(function (k) {
      var active = k.key === _activeKpi ? ' active' : '';
      return '<button class="fleet-kpi-tile tone-' + k.tone + active + '" ' +
               'data-action="fleetFilterByKpi" data-arg="' + escapeHtml(k.key) + '">' +
               '<div class="fleet-kpi-label">' + escapeHtml(k.label) + '</div>' +
               '<div class="fleet-kpi-value">' + k.value + '</div>' +
             '</button>';
    }).join('') +
  '</div>';
}

function _buildFleetTable(hosts) {
  if (hosts.length === 0) {
    return '<div class="dash-empty-note">No hosts match this filter.</div>';
  }
  var rows = hosts.map(function (h) {
    var score = (h.latest_score == null) ? '-' : h.latest_score;
    var grade = h.latest_grade || (h.latest_score != null ? _gradeFor(h.latest_score) : '');
    var worst = h.worst_severity || 'NONE';
    var scoreCls = h.latest_score != null ? scoreColorClass(h.latest_score) : '';
    var statusCls = _isOnline(h) ? 'status-dot status-online' : 'status-dot status-offline';
    var statusTitle = _isOnline(h) ? 'Online — scanned within 24h' : 'No scan in the last 24h';

    return '<tr class="clickable" data-action="fleetOpenHost" ' +
           'data-arg="' + escapeHtml(h.hostname) + '" style="cursor:pointer;">' +
      '<td><span class="' + statusCls + '" title="' + statusTitle + '"></span> ' + escapeHtml(h.hostname) + '</td>' +
      '<td class="' + scoreCls + '">' + score + (grade ? ' <span class="muted">(' + grade + ')</span>' : '') + '</td>' +
      '<td>' + sevPillHtml(worst) + '</td>' +
      '<td>' + h.scan_count + '</td>' +
      '<td>' + h.total_findings + '</td>' +
      '<td>' + relTimeHtml(h.last_scan_at) + '</td>' +
      '</tr>';
  }).join('');

  return '<table class="findings-table"><thead><tr>' +
    '<th>Host</th><th>Latest Score</th><th>Worst Severity</th>' +
    '<th>Scans</th><th>Findings</th><th>Last Scan</th>' +
    '</tr></thead><tbody>' + rows + '</tbody></table>';
}

function _renderBody() {
  var body = document.getElementById('fleet-body');
  if (body) body.innerHTML = _buildFleetTable(_applyKpiFilter(_fleetCache));
  var stripWrap = document.getElementById('fleet-kpi-strip-wrap');
  if (stripWrap) stripWrap.innerHTML = _kpiStripHtml(_buildKpis(_fleetCache));
}

export async function renderFleetPage() {
  var c = document.getElementById('content');
  _fleetCache = await fetchFleet();

  if (!_fleetCache.length) {
    c.innerHTML =
      '<div class="empty-state cta">' +
        '<div class="empty-icon">&#128187;</div>' +
        '<h3>No hosts yet</h3>' +
        '<p>Run a scan or upload a .evtx file — hosts will appear here once Pulse has tagged findings with a Computer name.</p>' +
        '<button class="btn btn-primary btn-with-icon" data-action="openUploadModal"><i data-lucide="upload"></i><span>Upload .evtx</span></button>' +
      '</div>';
    return;
  }

  var filtered = _applyKpiFilter(_fleetCache);
  var kpis = _buildKpis(_fleetCache);

  c.innerHTML =
    '<div class="page-head">' +
      '<div class="page-head-title"><strong>' + _fleetCache.length + '</strong> host' +
        (_fleetCache.length === 1 ? '' : 's') + ' tracked</div>' +
      '<div class="page-head-actions">' +
        '<button class="btn btn-secondary btn-with-icon" data-action="exportFleetCsv"><i data-lucide="download"></i><span>Export CSV</span></button>' +
      '</div>' +
    '</div>' +
    '<div id="fleet-kpi-strip-wrap">' + _kpiStripHtml(kpis) + '</div>' +
    '<div class="card" style="padding:0; overflow:hidden;">' +
      '<div id="fleet-body">' + _buildFleetTable(filtered) + '</div>' +
    '</div>';
}

export function fleetFilterByKpi(key) {
  _activeKpi = key || 'total';
  _renderBody();
}

export function exportFleetCsv() {
  window.location.href = '/api/fleet/export.csv';
}

// Opens the universal drawer with a host overview. The blueprint calls
// for tabs (Overview / Alerts / Timeline / ...) — phase 1 ships the
// Overview tab with a "View on Dashboard" action that preserves the
// old jump-to-filter drill-in.
export function fleetOpenHost(hostname) {
  if (!hostname) return;
  var host = _fleetCache.find(function (h) { return h.hostname === hostname; });
  if (!host) return;

  var score = (host.latest_score == null) ? '—' : host.latest_score;
  var grade = host.latest_grade || (host.latest_score != null ? _gradeFor(host.latest_score) : '');
  var worst = (host.worst_severity || 'NONE').toUpperCase();
  var tone  = worst === 'CRITICAL' ? 'critical'
            : worst === 'HIGH'     ? 'high'
            : worst === 'MEDIUM'   ? 'medium'
            : worst === 'LOW'      ? 'low' : 'info';
  var onlineTone = _isOnline(host) ? 'ok' : 'off';
  var onlineText = _isOnline(host) ? 'Online' : 'Offline >24h';

  openDrawer({
    title: host.hostname,
    subtitle: 'Fleet host overview',
    badges: [
      { text: onlineText, tone: onlineTone },
      { text: (worst === 'NONE' ? 'No alerts' : worst), tone: tone },
    ],
    sections: [
      {
        label: 'Posture',
        html: '<div class="kv">' +
                '<div class="k">Latest score</div>' +
                '<div class="v">' + escapeHtml(String(score)) + (grade ? ' <span class="muted">(' + escapeHtml(grade) + ')</span>' : '') + '</div>' +
                '<div class="k">Worst severity</div>' +
                '<div class="v">' + sevPillHtml(worst) + '</div>' +
                '<div class="k">Scans recorded</div>' +
                '<div class="v">' + (host.scan_count || 0) + '</div>' +
                '<div class="k">Total findings</div>' +
                '<div class="v">' + (host.total_findings || 0) + '</div>' +
                '<div class="k">Last scan</div>' +
                '<div class="v">' + relTimeHtml(host.last_scan_at) + '</div>' +
              '</div>',
      },
      {
        label: 'Next steps',
        html: '<div style="color:var(--text-dim); font-size:12px; line-height:1.5;">' +
                'Use <em>View on Dashboard</em> to drill into this host’s findings, or run a fresh scan from the system-scan panel.' +
              '</div>',
      },
    ],
    actions: [
      {
        label: 'View on Dashboard',
        variant: 'primary',
        onClick: function () {
          closeDrawer();
          dashFilterState.source = host.hostname;
          dashFilterState.time   = 'today';
          dashFilterState.from   = '';
          dashFilterState.to     = '';
          navigate('dashboard');
          writeDashFiltersToURL();
        },
      },
      { label: 'Close', variant: 'secondary', onClick: closeDrawer },
    ],
  });
}
