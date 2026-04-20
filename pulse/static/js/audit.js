// audit.js — Audit Log page. Renders the audit_log table newest-first
// so a reviewer can see who performed which sensitive action and when.
// Rows are populated by pulse/blocker.log_audit() from the scan / delete
// / block / unblock / push code paths; this page is purely a viewer.
'use strict';

import { fetchAudit } from './api.js';
import { escapeHtml } from './dashboard.js';

var _auditCache = [];
var _auditQuery = '';

export async function renderAuditPage() {
  var c = document.getElementById('content');
  _auditCache = await fetchAudit(500);

  c.innerHTML =
    '<div class="page-head">' +
      '<div class="page-head-title"><strong>' + _auditCache.length + '</strong> entr' +
        (_auditCache.length === 1 ? 'y' : 'ies') + '</div>' +
      '<div class="page-head-actions">' +
        '<input type="text" class="search-input" placeholder="Filter action, user, detail..." ' +
               'oninput="window.__auditFilter(this.value)" ' +
               'value="' + escapeHtml(_auditQuery) + '">' +
      '</div>' +
    '</div>' +
    '<div class="card" style="padding:0; overflow:hidden;">' +
      '<div id="audit-table-wrap">' + _buildTable(_applyQuery(_auditCache, _auditQuery)) + '</div>' +
    '</div>';

  // Client-side filter — small table, no paging, no need to re-fetch.
  window.__auditFilter = function (q) {
    _auditQuery = q || '';
    var wrap = document.getElementById('audit-table-wrap');
    if (wrap) wrap.innerHTML = _buildTable(_applyQuery(_auditCache, _auditQuery));
  };
}

function _applyQuery(rows, q) {
  if (!q) return rows;
  var needle = q.toLowerCase();
  return rows.filter(function (r) {
    var hay = [r.ts, r.action, r.user, r.ip_address, r.comment, r.detail, r.source]
      .filter(Boolean).join(' ').toLowerCase();
    return hay.indexOf(needle) >= 0;
  });
}

function _buildTable(rows) {
  if (!rows.length) {
    return '<div style="padding:48px 20px; text-align:center; color:var(--text-muted);">' +
             'No audit entries match.' +
           '</div>';
  }
  var body = rows.map(function (r) {
    return '<tr>' +
      '<td><code>' + escapeHtml(r.ts || '') + '</code></td>' +
      '<td>' + _actionBadge(r.action) + '</td>' +
      '<td>' + escapeHtml(r.user || r.source || '-') + '</td>' +
      '<td>' + escapeHtml(r.ip_address || '') + '</td>' +
      '<td class="muted">' + escapeHtml(r.detail || r.comment || '') + '</td>' +
      '</tr>';
  }).join('');
  return '<table class="findings-table"><thead><tr>' +
           '<th>Time</th><th>Action</th><th>User / Source</th><th>IP</th><th>Detail</th>' +
         '</tr></thead><tbody>' + body + '</tbody></table>';
}

// Tint the action so a reviewer can scan the column quickly. Keeps
// destructive actions (delete_scan, unblock) visually distinct from
// additive ones (stage, push, scan).
function _actionBadge(action) {
  var a = (action || '').toLowerCase();
  var cls = 'sev-pill sev-low';
  if (a === 'push' || a === 'stage' || a === 'scan')       cls = 'sev-pill sev-medium';
  else if (a === 'unblock' || a === 'delete_scan')         cls = 'sev-pill sev-high';
  else if (a.endsWith('_failed'))                          cls = 'sev-pill sev-critical';
  return '<span class="' + cls + '">' + escapeHtml(action || '-') + '</span>';
}
