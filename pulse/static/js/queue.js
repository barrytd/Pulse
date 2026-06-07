// queue.js — My Queue page.
//
// The analyst's day-to-day landing surface: every unresolved finding
// assigned to them, sorted priority -> severity -> oldest, with KPI
// tiles (in queue / overdue / due today / resolved today). Clicking a
// row jumps to the source scan where the finding drawer lives.
'use strict';

import { escapeHtml, toastError, relTimeHtml } from './dashboard.js';

var _cache = null;

async function _fetchQueue() {
  var resp = await fetch('/api/queue');
  if (!resp.ok) throw new Error('Failed to load your queue: HTTP ' + resp.status);
  return await resp.json();
}

function _priorityPill(p) {
  if (!p) return '<span class="q-pri q-pri-none" title="No priority set">—</span>';
  var label = String(p).toUpperCase();
  return '<span class="q-pri q-pri-' + label.toLowerCase() + '">' + escapeHtml(label) + '</span>';
}

function _sevPill(sev) {
  var s = (sev || 'LOW').toUpperCase();
  return '<span class="pill pill-' + s.toLowerCase() + '">' + escapeHtml(s) + '</span>';
}

// Due-date cell with urgency color: overdue = red, due today = amber,
// future = muted, none = dash.
function _dueCell(due) {
  if (!due) return '<span class="muted">—</span>';
  var dueDay = String(due).slice(0, 10);
  var today = new Date();
  var todayStr = today.toISOString().slice(0, 10);
  var cls = 'q-due';
  var note = '';
  if (dueDay < todayStr) { cls += ' q-due-over'; note = ' (overdue)'; }
  else if (dueDay === todayStr) { cls += ' q-due-today'; note = ' (today)'; }
  return '<span class="' + cls + '">' + escapeHtml(dueDay) + note + '</span>';
}

function _kpiTilesHtml(k) {
  k = k || {};
  function tile(icon, num, label, cls) {
    return '<div class="q-kpi ' + (cls || '') + '">' +
      '<div class="q-kpi-icon"><i data-lucide="' + icon + '"></i></div>' +
      '<div class="q-kpi-text"><div class="q-kpi-num">' + num + '</div>' +
      '<div class="q-kpi-label">' + label + '</div></div></div>';
  }
  return '<div class="q-kpi-strip">' +
    tile('inbox',        (k.in_queue || 0),       'In queue', '') +
    tile('alert-circle', (k.overdue || 0),        'Overdue', (k.overdue ? 'q-kpi-red' : '')) +
    tile('calendar-clock', (k.due_today || 0),    'Due today', (k.due_today ? 'q-kpi-amber' : '')) +
    tile('check-circle-2', (k.resolved_today || 0), 'Resolved today', 'q-kpi-green') +
  '</div>';
}

function _rowsHtml(rows) {
  if (!rows || !rows.length) {
    return '<tr><td colspan="6"><div class="dash-empty-note" style="margin:0;">' +
      'Nothing in your queue right now. Findings assigned to you that ' +
      'aren’t resolved yet will show up here.</div></td></tr>';
  }
  return rows.map(function (r) {
    var scanNum = r.scan_number != null ? r.scan_number : r.scan_id;
    var status = (r.workflow_status || 'new');
    return '<tr class="clickable" data-action="viewScan" data-arg="' + r.scan_id + '" style="cursor:pointer;">' +
      '<td>' + _priorityPill(r.priority) + '</td>' +
      '<td>' + _sevPill(r.severity) + '</td>' +
      '<td><div class="q-rule">' + escapeHtml(r.rule || 'Unknown') + '</div>' +
        '<div class="q-sub muted">Scan #' + escapeHtml(String(scanNum)) +
        (r.assigned_by_name ? ' · assigned by ' + escapeHtml(r.assigned_by_name) : '') +
        '</div></td>' +
      '<td>' + escapeHtml(r.hostname || '—') + '</td>' +
      '<td>' + _dueCell(r.due_date) + '</td>' +
      '<td><span class="q-status q-status-' + escapeHtml(status) + '">' +
        escapeHtml(status) + '</span></td>' +
    '</tr>';
  }).join('');
}

export async function renderMyQueuePage() {
  var c = document.getElementById('content');
  if (!c) return;
  c.innerHTML = '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading your queue…</div>';
  try {
    _cache = await _fetchQueue();
  } catch (e) {
    toastError(e.message);
    c.innerHTML = '<div class="card"><div class="dash-empty-note">' + escapeHtml(e.message) + '</div></div>';
    return;
  }
  var rows = _cache.queue || [];
  c.innerHTML =
    '<div class="page-head">' +
      '<div class="page-head-title">My Queue</div>' +
    '</div>' +
    _kpiTilesHtml(_cache.kpis) +
    '<div class="card">' +
      '<div class="section-label">Assigned to me — unresolved' +
        '<span style="color:var(--text-muted); font-weight:400; margin-left:8px; font-size:11px;">' +
        rows.length + ' finding' + (rows.length === 1 ? '' : 's') + '</span></div>' +
      '<div style="overflow-x:auto;">' +
        '<table class="data-table">' +
          '<thead><tr>' +
            '<th>Priority</th><th>Severity</th><th>Rule</th>' +
            '<th>Host</th><th>Due</th><th>Status</th>' +
          '</tr></thead>' +
          '<tbody>' + _rowsHtml(rows) + '</tbody>' +
        '</table>' +
      '</div>' +
    '</div>';
  if (window.lucide && window.lucide.createIcons) {
    try { window.lucide.createIcons(); } catch (e) {}
  }
}
