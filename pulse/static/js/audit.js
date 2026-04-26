// audit.js — Audit Log page with read-only detail drawer.
//
// Rows are populated server-side by pulse/firewall/blocker.log_audit() from the
// scan / delete / block / unblock / push / user-management code paths.  This
// page is a viewer only — no audit entry is ever edited or deleted from here.
//
// Click a row to open a 480px right-side drawer (Esc to close; j/k to jump
// between entries while it's open).  Each drawer surfaces:
//   - header + action-type chip + full timestamp (local + UTC)
//   - label/value event details with quick-filter links
//   - structured breakdown of the free-form `detail` string
//   - context timeline (same actor, 3-5 entries before/after)
//   - related entries (shared IP / target)
//   - collapsible raw JSON with copy button
// Footer actions: Copy as JSON, Filter to actor / IP / target.
'use strict';

import { fetchAudit, apiListUsers } from './api.js';
import { escapeHtml, _restoreSearchFocus } from './dashboard.js';
import { openDrawer, closeDrawer, isDrawerOpen } from './drawer.js';

// Newest-first cache of every audit row the API returned last refresh.
// _filteredRows mirrors whatever _applyQuery produced on the most recent
// render so the j/k handler and drawer navigation use the same list the
// user is looking at.
var _auditCache = [];
var _filteredRows = [];
var _auditQuery = '';
var _drawerIdx = -1;      // index within _filteredRows while drawer is open
var _jkHandler = null;    // keyboard listener installed while drawer is open

// Sentinel-style filter chips state. Multi-select dimensions are Sets
// of selected values; time_window is a single radio-style value.
var _auditFilters = {
  actions:      new Set(),  // action strings
  users:        new Set(),  // display name (or email when no display name)
  target_types: new Set(),  // 'finding' | 'ip' | 'host' | 'user' | 'scan' | 'rule'
  time_window:  'all',      // '24h' | '7d' | '30d' | '90d' | 'all'
  ip:           '',         // free-text IP filter (via "+ Add filter")
  finding_ref:  '',         // ref-id substring filter (via "+ Add filter")
};
// Tracks secondary filter dims the user revealed via "+ Add filter" so
// we don't lose the chip when its value momentarily clears.
var _auditAddedDims = new Set();
// Time format toggle for the Time column. 'relative' = "3h ago",
// 'absolute' = full timestamp. Persisted across re-renders only.
var _auditTimeFmt = 'relative';

// { userId: displayName|email } — populated on mount for name resolution
// in legacy audit rows that stored assignee_user_id before we switched
// to writing the name directly on the server.
var _userIdNameMap = {};

async function _ensureUserIdNameMap() {
  try {
    var lu = await apiListUsers();
    (lu.users || []).forEach(function (u) {
      if (!u || u.id == null) return;
      var name = (u.display_name || '').trim() || (u.email || '').split('@')[0] || ('user #' + u.id);
      _userIdNameMap[String(u.id)] = name;
    });
  } catch (e) {
    // Viewers 403 /api/users — fall through; legacy rows will show
    // "user #N" as a fallback. Not worth blocking the whole page.
  }
}

function _userName(userId) {
  var key = String(userId);
  return _userIdNameMap[key] || ('user #' + userId);
}

// Action classification → color scheme.  See .claude/skills/pulse-design.md:
// the row-accent severity set is used for left borders and for chip fills.
//   blue   — read actions: scan, review, *_failed reads
//   amber  — write actions: assign, stage, push, set_workflow_state
//   red    — destructive: delete*, unblock, revoke, deactivate, *_failed
//   green  — create / additive: add_note, create_user, create_token, signup
function _actionTone(action) {
  var a = (action || '').toLowerCase();
  if (!a) return 'neutral';
  // Destructive — checked first so '*_failed' beats blue/amber matchers.
  if (a === 'unblock' || a.indexOf('delete') === 0 || a.indexOf('_failed') >= 0 ||
      a.indexOf('deactivate') >= 0 || a === 'revoke' || a.indexOf('revoke_') === 0) return 'red';
  // Create / additive
  if (a.indexOf('create') >= 0 || a === 'signup' || a === 'register' ||
      a === 'add_note' || a === 'submit_feedback') return 'green';
  // Reads
  if (a === 'scan' || a === 'review' || a === 'review_finding' ||
      a.indexOf('review_') === 0) return 'blue';
  // Writes (everything else that mutates state lands here)
  if (a === 'stage' || a === 'stage_forced' || a === 'push' ||
      a === 'assign_finding' || a === 'unassign_finding' ||
      a.indexOf('bulk_') === 0 ||
      a === 'set_workflow_state' ||
      a.indexOf('update_user') === 0) return 'amber';
  return 'neutral';
}

// Category labels for the distribution-bar legend + drawer header chip.
function _toneLabel(tone) {
  switch (tone) {
    case 'blue':  return 'Read';
    case 'amber': return 'Write';
    case 'red':   return 'Destructive';
    case 'green': return 'Create';
    default:      return 'Other';
  }
}

// Humanised action title for the drawer header.  The raw action string
// (stage_forced) is kept in the body as a data field so the reviewer can
// still see the literal value that was logged.
function _actionTitle(action) {
  var a = action || 'unknown';
  var map = {
    scan:          'Scan performed',
    stage:         'IP staged for block',
    stage_forced:  'IP staged (private address override)',
    push:          'Block pushed to firewall',
    push_failed:   'Block push failed',
    unblock:       'IP unblocked',
    unblock_failed:'Unblock failed',
    delete_scan:   'Scan deleted',
    review:        'Finding reviewed',
    user_create:   'User account created',
    user_update:   'User account updated',
    user_delete:   'User account deleted',
    user_deactivate:'User deactivated',
    token_create:  'API token created',
    token_revoke:  'API token revoked',
  };
  return map[a] || a.replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
}

export async function renderAuditPage() {
  var c = document.getElementById('content');
  // Run both fetches in parallel — the user-id→name map is only used
  // for legacy audit rows, so even if it 403s for viewers the page
  // still renders. Rows with modern server-written names (e.g.
  // "assigned to Robert") bypass the lookup entirely.
  var auditP = fetchAudit(500);
  var usersP = _ensureUserIdNameMap();
  _auditCache = await auditP;
  await usersP;

  _renderAuditShell();
}

// Re-render the page shell (header zones + table). Filter handlers call
// this after every chip toggle so the KPIs / distribution bar / table
// all reflect the current filtered slice consistently.
function _renderAuditShell() {
  var c = document.getElementById('content');
  if (!c) return;
  c.innerHTML =
    '<div class="findings-page">' +
      _auditPageHeaderHtml() +
      '<div class="findings-page-body">' +
        '<div id="audit-bulk-bar"></div>' +
        '<div class="card" style="padding:0; overflow:hidden;">' +
          '<div id="audit-table-wrap">' + _renderTable() + '</div>' +
        '</div>' +
      '</div>' +
    '</div>' +
    '<div class="filter-chip-dd" id="filter-chip-dd" hidden></div>' +
    '<div class="audit-export-menu" id="audit-export-menu" hidden></div>';
  _mountAuditFilterDropdown();
  _mountAuditExportMenu();
  // Auto-focus the search input on entry — mirrors the Findings / Scans
  // pages so the user can start typing immediately. _restoreSearchFocus
  // is also focus-safe across re-renders, preserving the caret position
  // when chip toggles trigger _renderAuditShell().
  _restoreSearchFocus('audit-search-box');
}

// ---------------------------------------------------------------------------
// Page header — Sentinel-style: breadcrumb / title-block / KPIs /
// action-distribution bar / sticky filter bar. Reuses the primitives in
// components.css that the Findings rebuild established.
// ---------------------------------------------------------------------------

function _auditPageHeaderHtml() {
  var filtered = _filterAuditRows(_auditCache);
  return '<div class="page-header">' +
    _auditBreadcrumbHtml() +
    _auditTitleBlockHtml(filtered.length, _auditCache.length) +
    _auditKpiRowHtml(filtered) +
    _auditDistributionBarHtml(filtered) +
    _auditFilterBarHtml() +
  '</div>';
}

function _auditBreadcrumbHtml() {
  return '<nav class="page-breadcrumb" aria-label="Breadcrumb">' +
    '<span class="page-breadcrumb-item">Pulse</span>' +
    '<span class="page-breadcrumb-sep" aria-hidden="true">›</span>' +
    '<span class="page-breadcrumb-item">Configuration</span>' +
    '<span class="page-breadcrumb-sep" aria-hidden="true">›</span>' +
    '<span class="page-breadcrumb-current">Audit Log</span>' +
  '</nav>';
}

function _auditTitleBlockHtml(visible, total) {
  // Lock indicator next to the title — signals to auditors that the
  // log is integrity-protected. Pure visual marker; the backend
  // doesn't expose any mutation endpoints either way.
  var anyFilter = _auditAnyFilterActive();
  var countLabel = anyFilter ? (visible + ' of ' + total) : String(total);
  return '<div class="page-title-block">' +
    '<h1 class="page-title">Audit Log <span class="page-title-count">(' + countLabel + ')</span>' +
      '<span class="audit-lock" title="This log is append-only and cannot be modified or deleted">' +
        '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" ' +
          'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
          '<rect x="3" y="7" width="10" height="7" rx="1.4"/>' +
          '<path d="M5.5 7V4.5a2.5 2.5 0 0 1 5 0V7"/>' +
        '</svg>' +
        '<span class="audit-lock-text">Append-only log</span>' +
      '</span>' +
    '</h1>' +
    '<div class="page-title-actions">' +
      '<button class="btn btn-compact btn-with-icon" data-action="auditExportToggle" ' +
        'title="Export current view">' +
        '<i data-lucide="download"></i><span>Export</span>' +
        '<i data-lucide="chevron-down" style="margin-left:2px;"></i>' +
      '</button>' +
    '</div>' +
  '</div>';
}

// ---------------------------------------------------------------------------
// KPI tiles
// ---------------------------------------------------------------------------

function _auditKpiRowHtml(filtered) {
  var now = Date.now();
  var DAY_MS = 86400000;
  var last24h = 0, failed = 0;
  var users = new Set(), targets = new Set();
  filtered.forEach(function (r) {
    var t = Date.parse((r.ts || '').replace(' ', 'T'));
    if (!isNaN(t) && (now - t) <= DAY_MS) last24h++;
    var a = (r.action || '').toLowerCase();
    if (a.indexOf('_failed') >= 0 || a.indexOf('denied') >= 0) failed++;
    var u = (r.user_display_name || r.user || r.source || '').trim();
    if (u) users.add(u);
    if (r.ip_address) targets.add('ip:' + r.ip_address);
    if (r.comment)    targets.add(r.comment);
  });
  function tile(label, n, sub) {
    return '<div class="kpi-tile" style="cursor:default;">' +
      '<div class="kpi-tile-number">' + n.toLocaleString() + '</div>' +
      '<div class="kpi-tile-label">' + escapeHtml(label) + '</div>' +
      '<div class="kpi-tile-sub">' + escapeHtml(sub) + '</div>' +
    '</div>';
  }
  return '<div class="kpi-row">' +
    tile('Events last 24h',  last24h, 'inside the current view') +
    tile('Failed actions',   failed,  'denials / errors') +
    tile('Distinct users',   users.size,   'unique actors') +
    tile('Distinct targets', targets.size, 'IPs / hosts / findings') +
  '</div>';
}

// ---------------------------------------------------------------------------
// Action-type distribution bar — same shape as the findings severity bar
// but split four ways instead of by severity.
// ---------------------------------------------------------------------------

function _auditDistributionBarHtml(filtered) {
  var counts = { blue: 0, amber: 0, red: 0, green: 0, neutral: 0 };
  filtered.forEach(function (r) { counts[_actionTone(r.action)] = (counts[_actionTone(r.action)] || 0) + 1; });
  var total = counts.blue + counts.amber + counts.red + counts.green + counts.neutral;
  if (total === 0) return '';

  var TONE = {
    blue:  '#58a6ff',
    amber: '#f0883e',
    red:   '#f85149',
    green: '#3fb950',
    neutral: '#6b7280',
  };

  function dot(tone, label) {
    if (!counts[tone]) return '';
    return '<span class="sev-bar-legend-item">' +
      '<span class="sev-bar-legend-dot" style="background:' + TONE[tone] + '"></span>' +
      label + ' <strong>' + counts[tone] + '</strong>' +
    '</span>';
  }
  function seg(tone) {
    if (!counts[tone]) return '';
    return '<div class="sev-bar-seg" style="flex:' + counts[tone] +
      '; background:' + TONE[tone] + '" title="' + _toneLabel(tone) + ': ' + counts[tone] + '"></div>';
  }
  return '<div class="sev-bar-wrap">' +
    '<div class="sev-bar-legend">' +
      dot('blue',    'Reads') +
      dot('amber',   'Writes') +
      dot('red',     'Destructive') +
      dot('green',   'Creates') +
      dot('neutral', 'Other') +
    '</div>' +
    '<div class="sev-bar" role="img" aria-label="Activity by category">' +
      seg('blue') + seg('amber') + seg('red') + seg('green') + seg('neutral') +
    '</div>' +
  '</div>';
}

// ---------------------------------------------------------------------------
// Filter bar — multi-select chips for Action / User / Target Type and a
// radio-style chip for Time Range. + Add filter exposes IP and ref-ID
// freeform filters.
// ---------------------------------------------------------------------------

function _auditFilterDims() {
  return [
    { id: 'actions',      label: 'Action',      primary: true,  multi: true,  source: 'actions' },
    { id: 'users',        label: 'User',        primary: true,  multi: true,  source: 'users' },
    { id: 'target_types', label: 'Target',      primary: true,  multi: true,  source: 'targets' },
    { id: 'time_window',  label: 'Time range',  primary: true,  multi: false, source: 'time' },
    { id: 'ip',           label: 'IP',          primary: false, multi: false, source: 'ip' },
    { id: 'finding_ref',  label: 'Finding ID',  primary: false, multi: false, source: 'finding_ref' },
  ];
}

function _auditAnyFilterActive() {
  if (_auditFilters.actions.size) return true;
  if (_auditFilters.users.size) return true;
  if (_auditFilters.target_types.size) return true;
  if (_auditFilters.time_window && _auditFilters.time_window !== 'all') return true;
  if (_auditFilters.ip) return true;
  if (_auditFilters.finding_ref) return true;
  if (_auditQuery) return true;
  return false;
}

function _auditFilterBarHtml() {
  var dims = _auditFilterDims();
  var chips = dims.map(function (d) {
    var n = _auditChipCount(d.id);
    if (!d.primary && !n && !_auditAddedDims.has(d.id)) return '';
    return _auditChipWrapHtml(d, n);
  }).join('');
  var hidden = dims.filter(function (d) {
    if (d.primary) return false;
    if (_auditAddedDims.has(d.id)) return false;
    return _auditChipCount(d.id) === 0;
  });
  var addBtn = hidden.length === 0 ? '' :
    '<div class="filter-chip-wrap filter-chip-wrap-add">' +
      '<button type="button" class="filter-chip-add" data-action="auditOpenAddFilter">' +
        '<span aria-hidden="true">+</span> Add filter' +
      '</button>' +
      '<div class="filter-chip-dd" hidden></div>' +
    '</div>';
  var clearAll = _auditAnyFilterActive()
    ? '<a class="filter-chip-clear-all" data-action="auditClearFilters">Clear all</a>'
    : '';
  return '<div class="filter-bar">' +
    '<input type="search" id="audit-search-box" class="filter-bar-search" ' +
      'placeholder="Search action, user, detail..." ' +
      'value="' + escapeHtml(_auditQuery) + '" ' +
      'data-action-input="auditSetQuery" />' +
    '<div class="filter-bar-chips">' + chips + addBtn + '</div>' +
    clearAll +
  '</div>';
}

function _auditChipCount(dimId) {
  if (dimId === 'time_window') {
    return (_auditFilters.time_window && _auditFilters.time_window !== 'all') ? 1 : 0;
  }
  if (dimId === 'ip')          return _auditFilters.ip ? 1 : 0;
  if (dimId === 'finding_ref') return _auditFilters.finding_ref ? 1 : 0;
  var slot = _auditFilters[dimId];
  return slot && slot.size ? slot.size : 0;
}

function _auditChipWrapHtml(dim, n) {
  var label = dim.label;
  var cls = 'filter-chip';
  if (n > 0) {
    cls += ' is-active';
    if (dim.id === 'time_window') {
      label += ': ' + _timeWindowLabel(_auditFilters.time_window);
    } else if (dim.id === 'ip') {
      label += ': ' + _auditFilters.ip;
    } else if (dim.id === 'finding_ref') {
      label += ': ' + _auditFilters.finding_ref;
    } else {
      label += ': ' + n + ' selected';
    }
  }
  if (!dim.primary) cls += ' has-dismiss';
  var dismissBtn = !dim.primary
    ? '<button type="button" class="filter-chip-dismiss" ' +
        'data-action="auditDismissChip" data-arg="' + dim.id + '" ' +
        'aria-label="Remove filter" title="Remove filter">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" ' +
          'stroke-linecap="round" stroke-linejoin="round" class="filter-chip-x-svg" aria-hidden="true">' +
          '<line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line>' +
        '</svg>' +
      '</button>'
    : '';
  return '<div class="filter-chip-wrap" data-dim="' + escapeHtml(dim.id) + '">' +
    '<button type="button" class="' + cls + '" ' +
      'data-action="auditOpenChip" data-arg="' + dim.id + '">' +
      '<span class="filter-chip-label">' + escapeHtml(label) + '</span>' +
      '<span class="filter-chip-caret" aria-hidden="true">▾</span>' +
    '</button>' +
    dismissBtn +
    '<div class="filter-chip-dd" hidden></div>' +
  '</div>';
}

function _timeWindowLabel(v) {
  switch (v) {
    case '24h': return 'Last 24h';
    case '7d':  return 'Last 7 days';
    case '30d': return 'Last 30 days';
    case '90d': return 'Last 90 days';
    default:    return 'All time';
  }
}

function _renderTable() {
  _filteredRows = _filterAuditRows(_auditCache);
  if (!_filteredRows.length) {
    return '<div style="padding:48px 20px; text-align:center; color:var(--text-muted);">' +
             'No audit entries match.' +
           '</div>';
  }
  var body = _filteredRows.map(function (r) {
    var tone = _actionTone(r.action);
    var tsCell = _renderTimeCell(r.ts);
    return '<tr class="clickable audit-row audit-edge-' + tone + '" ' +
               'data-action="openAuditDrawer" data-arg="' + escapeHtml(String(r.id)) + '">' +
      '<td>' + tsCell + '</td>' +
      '<td>' + _actionChip(r.action, tone) + '</td>' +
      '<td>' + _actorCell(r) + '</td>' +
      '<td>' + (r.ip_address ? '<code>' + escapeHtml(r.ip_address) + '</code>' : '') + '</td>' +
      '<td class="audit-detail-cell" title="' + escapeHtml(r.detail || r.comment || '') + '" ' +
        'style="max-width:420px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' +
        _targetPill(r) +
        '<span class="audit-detail-human">' + escapeHtml(_formatAuditDetail(r)) + '</span>' +
      '</td>' +
      '</tr>';
  }).join('');
  // Time column header gets a small toggle: relative ↔ absolute. Click
  // re-renders just the table without re-running the filter pipeline.
  var timeHeader =
    '<th class="audit-time-header">' +
      '<span>Time</span>' +
      '<button type="button" class="audit-time-toggle" data-action="auditToggleTimeFmt" ' +
        'title="Toggle between relative and absolute timestamps" ' +
        'aria-label="Toggle time format">' +
        (_auditTimeFmt === 'relative' ? 'rel' : 'abs') +
      '</button>' +
    '</th>';
  return '<table class="findings-table"><thead><tr>' +
           timeHeader +
           '<th>Action</th><th>User / Source</th><th>IP</th><th>Detail</th>' +
         '</tr></thead><tbody>' + body + '</tbody></table>';
}

// Apply every audit filter chip + the search query + drop everything
// that doesn't match. Returns the filtered list.
function _filterAuditRows(rows) {
  var f = _auditFilters;
  var out = rows || [];
  if (f.actions.size) {
    out = out.filter(function (r) { return f.actions.has((r.action || '').toLowerCase()); });
  }
  if (f.users.size) {
    out = out.filter(function (r) {
      var u = (r.user_display_name || r.user || r.source || '').trim().toLowerCase();
      return f.users.has(u);
    });
  }
  if (f.target_types.size) {
    out = out.filter(function (r) { return f.target_types.has(_targetType(r)); });
  }
  if (f.time_window && f.time_window !== 'all') {
    var sizes = { '24h': 1, '7d': 7, '30d': 30, '90d': 90 };
    var days = sizes[f.time_window];
    if (days) {
      var cutoff = Date.now() - days * 86400000;
      out = out.filter(function (r) {
        var t = Date.parse((r.ts || '').replace(' ', 'T'));
        return !isNaN(t) && t >= cutoff;
      });
    }
  }
  if (f.ip)          out = out.filter(function (r) { return (r.ip_address || '') === f.ip; });
  if (f.finding_ref) {
    var ref = f.finding_ref.toLowerCase();
    out = out.filter(function (r) { return (r.detail || '').toLowerCase().indexOf(ref) >= 0; });
  }
  if (_auditQuery) out = _applyQuery(out, _auditQuery);
  return out;
}

function _targetType(r) {
  var c = (r.comment || '').toLowerCase();
  if (c.indexOf('finding:') === 0) return 'finding';
  var a = (r.action || '').toLowerCase();
  if (a.indexOf('scan') >= 0)  return 'scan';
  if (r.ip_address) return 'ip';
  if (a.indexOf('user') >= 0)  return 'user';
  if (a.indexOf('rule') >= 0)  return 'rule';
  return 'other';
}

function _renderTimeCell(ts) {
  if (!ts) return '<code class="muted">—</code>';
  var d = new Date(String(ts).replace(' ', 'T'));
  if (isNaN(d.getTime())) return '<code>' + escapeHtml(ts) + '</code>';
  var abs = d.toLocaleString();
  if (_auditTimeFmt === 'absolute') {
    return '<code title="' + escapeHtml(abs) + '">' + escapeHtml(ts) + '</code>';
  }
  // Relative formatter — "3h ago" / "yesterday" / "2025-04-22".
  var diff = Math.max(0, Date.now() - d.getTime());
  var s = Math.floor(diff / 1000);
  var label;
  if (s < 60)        label = 'just now';
  else if (s < 3600) label = Math.floor(s / 60) + 'm ago';
  else if (s < 86400) label = Math.floor(s / 3600) + 'h ago';
  else if (s < 172800) label = 'yesterday';
  else if (s < 604800) label = Math.floor(s / 86400) + 'd ago';
  else label = d.toISOString().slice(0, 10);
  return '<span class="audit-time-rel" title="' + escapeHtml(abs) + '">' +
           escapeHtml(label) +
         '</span>';
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

function _actionChip(action, tone) {
  return '<span class="audit-chip audit-chip-' + tone + '">' +
           escapeHtml(action || '-') +
         '</span>';
}

// Extract the numeric finding id from an audit row's `comment` field.
// _audit_finding_action stores comments as "finding:<id>" for every
// finding-level action; anything else returns null.
function _parseFindingId(comment) {
  if (!comment) return null;
  var m = /^finding:(\d+)$/.exec(String(comment).trim());
  return m ? Number(m[1]) : null;
}

// Render a clickable "Finding N" pill next to the detail text when the
// audit row targets a specific finding. Swallows the row-level click so
// the drawer doesn't steal the pill click.
function _targetPill(r) {
  var fid = _parseFindingId(r.comment);
  if (!fid) return '';
  return '<a class="audit-target-pill" ' +
           'data-action="openAuditFinding" data-arg="' + fid + '" ' +
           'data-default="allow" ' +
           'title="Open this finding">' +
           'Finding ' + fid +
         '</a> ';
}

// Navigate to the Findings page and open the drawer for the given id.
// Exported so the action registry can wire it from both the table row
// pill and the drawer's footer button.
export async function openAuditFinding(findingId) {
  var id = Number(findingId);
  if (!id) return;
  // Dynamic imports avoid a circular static import with navigation.js /
  // findings.js at module load time.
  var [nav, findings] = await Promise.all([
    import('./navigation.js'),
    import('./findings.js'),
  ]);
  // Close any open audit drawer first so the finding drawer doesn't
  // open behind it.
  var universalDrawer = document.getElementById('drawer-root');
  if (universalDrawer) universalDrawer.setAttribute('hidden', '');
  nav.navigateWithHistory('findings');
  // Poll briefly for the findings cache to populate, then open the drawer.
  var attempts = 0;
  var timer = setInterval(function () {
    attempts++;
    var cache = (findings.findingsState && findings.findingsState.raw) || [];
    var f = cache.find(function (x) { return Number(x.id) === id; });
    if (f) {
      clearInterval(timer);
      findings.openFindingDrawer(f);
    } else if (attempts > 40) {   // ~4s max
      clearInterval(timer);
    }
  }, 100);
}

// Open one finding by its short ref-id (e.g., "PTH-0142") — used by the
// clickable ref-id chips in the audit drawer's bulk-action breakdown.
export async function openAuditFindingByRef(refId) {
  if (!refId) return;
  var ref = String(refId).trim();
  // Look up the underlying numeric id by ref so we can reuse the
  // existing openAuditFinding flow (which polls the findings cache).
  try {
    var resp = await fetch('/api/audit?limit=1');
    if (!resp.ok) return;
  } catch (e) { /* offline — fall through */ }
  // Fast path: search the current findingsState cache by ref_id.
  var findings = await import('./findings.js');
  var cache = (findings.findingsState && findings.findingsState.raw) || [];
  var f = cache.find(function (x) { return x && x.ref_id === ref; });
  if (f) {
    var nav = await import('./navigation.js');
    var ud = document.getElementById('drawer-root');
    if (ud) ud.setAttribute('hidden', '');
    nav.navigateWithHistory('findings');
    setTimeout(function () { findings.openFindingDrawer(f); }, 200);
    return;
  }
  // Slow path: navigate to findings, then poll for the row.
  var nav2 = await import('./navigation.js');
  var ud2 = document.getElementById('drawer-root');
  if (ud2) ud2.setAttribute('hidden', '');
  nav2.navigateWithHistory('findings');
  var attempts = 0;
  var timer = setInterval(function () {
    attempts++;
    var c = (findings.findingsState && findings.findingsState.raw) || [];
    var hit = c.find(function (x) { return x && x.ref_id === ref; });
    if (hit) {
      clearInterval(timer);
      findings.openFindingDrawer(hit);
    } else if (attempts > 40) {
      clearInterval(timer);
    }
  }, 100);
}

// ---------------------------------------------------------------------------
// Filter-bar action handlers (Sentinel-style chip dropdowns)
// ---------------------------------------------------------------------------

export function auditSetQuery(_arg, target) {
  _auditQuery = (target && target.value) || '';
  _renderAuditShell();
}

export function auditClearFilters() {
  _auditFilters.actions.clear();
  _auditFilters.users.clear();
  _auditFilters.target_types.clear();
  _auditFilters.time_window = 'all';
  _auditFilters.ip = '';
  _auditFilters.finding_ref = '';
  _auditAddedDims.clear();
  _auditQuery = '';
  _renderAuditShell();
}

export function auditDismissChip(dimId) {
  if (dimId === 'ip')          _auditFilters.ip = '';
  else if (dimId === 'finding_ref') _auditFilters.finding_ref = '';
  else if (dimId === 'time_window') _auditFilters.time_window = 'all';
  else if (_auditFilters[dimId] && _auditFilters[dimId].clear) _auditFilters[dimId].clear();
  _auditAddedDims.delete(dimId);
  _renderAuditShell();
}

export function auditToggleTimeFmt() {
  _auditTimeFmt = (_auditTimeFmt === 'relative') ? 'absolute' : 'relative';
  // Only the time column changed — re-render just the table to keep
  // the page header / KPIs / filter bar steady.
  var wrap = document.getElementById('audit-table-wrap');
  if (wrap) wrap.innerHTML = _renderTable();
}

// Open the chip dropdown for a given dim. Populates the dropdown's
// inner content + reveals it; the .filter-chip-wrap that contains the
// chip + dropdown establishes the absolute-positioning context (see
// findings.js for the same pattern).
export function auditOpenChip(dimId, target) {
  if (!dimId) return;
  var wrap = (target && target.closest && target.closest('.filter-chip-wrap[data-dim="' + dimId + '"]')) ||
             document.querySelector('.filter-chip-wrap[data-dim="' + dimId + '"]');
  if (!wrap) return;
  var dd = wrap.querySelector('.filter-chip-dd');
  if (!dd) return;
  // Toggle: clicking the same chip while its dropdown is open closes it.
  // Mirrors the Findings page's openFilterChip behaviour.
  var alreadyOpen = !dd.hidden;
  _auditCloseAllChipDropdowns();
  if (alreadyOpen) return;
  dd.innerHTML = _auditChipDdContent(dimId);
  dd.hidden = false;
  // Right-edge flip — same logic the findings filter chips use.
  dd.classList.remove('is-flip-right');
  var rect = dd.getBoundingClientRect();
  if (rect.right > window.innerWidth - 8) dd.classList.add('is-flip-right');
  var first = dd.querySelector('input,button');
  if (first) first.focus();
}

export function auditOpenAddFilter(_arg, target) {
  var wrap = (target && target.closest && target.closest('.filter-chip-wrap-add')) ||
             document.querySelector('.filter-chip-wrap-add');
  if (!wrap) return;
  var dd = wrap.querySelector('.filter-chip-dd');
  if (!dd) return;
  // Toggle: re-clicking +Add filter while the menu is open closes it.
  var alreadyOpen = !dd.hidden;
  _auditCloseAllChipDropdowns();
  if (alreadyOpen) return;
  var dims = _auditFilterDims().filter(function (d) {
    if (d.primary) return false;
    if (_auditAddedDims.has(d.id)) return false;
    return _auditChipCount(d.id) === 0;
  });
  if (!dims.length) return;
  dd.innerHTML = '<div class="filter-chip-dd-add-list">' +
    dims.map(function (d) {
      return '<button type="button" class="filter-chip-dd-add-item" ' +
        'data-action="auditAddFilterDim" data-arg="' + escapeHtml(d.id) + '">' +
        escapeHtml(d.label) +
      '</button>';
    }).join('') +
  '</div>';
  dd.hidden = false;
  var rect = dd.getBoundingClientRect();
  if (rect.right > window.innerWidth - 8) dd.classList.add('is-flip-right');
}

export function auditAddFilterDim(dimId) {
  if (!dimId) return;
  _auditAddedDims.add(dimId);
  _renderAuditShell();
  setTimeout(function () { auditOpenChip(dimId, null); }, 0);
}

// Toggle a value in a multi-select dim. Re-renders the page so KPIs +
// distribution bar pick up the change. data-arg = "dim|value".
export function auditToggleFilter(arg, target) {
  if (!arg) return;
  var parts = String(arg).split('|');
  var dim = parts[0], value = parts.slice(1).join('|');
  var slot = _auditFilters[dim];
  if (!slot || !slot.add) return;
  var checked = !!(target && target.checked);
  if (checked) slot.add(value); else slot.delete(value);
  _renderAuditShell();
  setTimeout(function () { auditOpenChip(dim, null); }, 0);
}

export function auditPickTimeWindow(arg) {
  _auditFilters.time_window = arg || 'all';
  _renderAuditShell();
}

export function auditApplyFreeformFilter(_arg, target) {
  // Used by IP / finding_ref chips. The triggering button carries
  // data-arg="<dim>" and the dropdown's input carries the value.
  var dd = target && target.closest && target.closest('.filter-chip-dd');
  if (!dd) return;
  var input = dd.querySelector('input[type="text"], input[type="search"]');
  var dim   = dd.getAttribute('data-dim') || target.getAttribute('data-arg');
  if (!dim || !input) return;
  _auditFilters[dim] = (input.value || '').trim();
  if (_auditFilters[dim]) _auditAddedDims.add(dim);
  _renderAuditShell();
}

function _auditChipDdContent(dimId) {
  if (dimId === 'time_window') {
    var values = ['24h', '7d', '30d', '90d', 'all'];
    return '<ul class="filter-chip-dd-list">' +
      values.map(function (v) {
        var checked = (_auditFilters.time_window === v) ? ' checked' : '';
        return '<li><label>' +
          '<input type="radio" name="audit-time-window"' + checked + ' ' +
            'data-action-change="auditPickTimeWindow" data-arg="' + v + '" />' +
          '<span class="filter-chip-dd-value">' + _timeWindowLabel(v) + '</span>' +
        '</label></li>';
      }).join('') +
    '</ul>';
  }
  if (dimId === 'ip' || dimId === 'finding_ref') {
    var current = _auditFilters[dimId] || '';
    var ph = dimId === 'ip' ? 'e.g. 203.0.113.42' : 'e.g. PTH-0142';
    return '<div class="filter-chip-dd-head" data-dim="' + dimId + '">' +
      '<input type="search" class="filter-chip-dd-search" placeholder="' + ph + '" ' +
        'value="' + escapeHtml(current) + '" autocomplete="off" />' +
      '<button type="button" class="filter-chip-dd-apply" ' +
        'data-action="auditApplyFreeformFilter" data-arg="' + dimId + '">Apply</button>' +
    '</div>';
  }
  // Multi-select with counts. Items come from the unfiltered cache so
  // toggling one value doesn't hide the others.
  var dim = _auditFilterDims().find(function (d) { return d.id === dimId; });
  if (!dim) return '';
  var bucket = {};
  _auditCache.forEach(function (r) {
    var v;
    if (dim.id === 'actions')      v = (r.action || '').toLowerCase();
    else if (dim.id === 'users')   v = (r.user_display_name || r.user || r.source || '').trim().toLowerCase();
    else if (dim.id === 'target_types') v = _targetType(r);
    if (!v) return;
    bucket[v] = (bucket[v] || 0) + 1;
  });
  var items = Object.keys(bucket).sort(function (a, b) { return bucket[b] - bucket[a]; });
  var slot = _auditFilters[dim.id];
  return '<ul class="filter-chip-dd-list">' +
    items.map(function (v) {
      var checked = slot.has(v) ? ' checked' : '';
      return '<li><label>' +
        '<input type="checkbox"' + checked + ' ' +
          'data-action-change="auditToggleFilter" ' +
          'data-arg="' + escapeHtml(dim.id) + '|' + escapeHtml(v) + '" />' +
        '<span class="filter-chip-dd-value" title="' + escapeHtml(v) + '">' + escapeHtml(v) + '</span>' +
        '<span class="filter-chip-dd-count">' + bucket[v] + '</span>' +
      '</label></li>';
    }).join('') +
  '</ul>';
}

function _auditCloseAllChipDropdowns() {
  document.querySelectorAll('.filter-chip-wrap .filter-chip-dd').forEach(function (dd) {
    dd.hidden = true;
    dd.classList.remove('is-flip-right');
    dd.innerHTML = '';
  });
}

function _mountAuditFilterDropdown() {
  // Outside-click + Escape close. Uses named handlers so re-renders
  // don't stack listeners.
  document.removeEventListener('click', _auditChipOutsideClick);
  document.addEventListener('click', _auditChipOutsideClick);
  document.removeEventListener('keydown', _auditChipEscape);
  document.addEventListener('keydown', _auditChipEscape);
}
function _auditChipOutsideClick(e) {
  // Listener stays attached after a navigate() — guard so we don't
  // close findings / dashboard chips with a handler that doesn't know
  // about their triggers. (Each page has its own scoped listener.)
  if (document.body.dataset.page !== 'audit') return;
  var trigger = e.target.closest('[data-action="auditOpenChip"], [data-action="auditOpenAddFilter"]');
  if (trigger) return;
  if (e.target.closest('.filter-chip-dd')) return;
  _auditCloseAllChipDropdowns();
}
function _auditChipEscape(e) {
  if (e.key !== 'Escape') return;
  if (document.body.dataset.page !== 'audit') return;
  _auditCloseAllChipDropdowns();
}

// ---------------------------------------------------------------------------
// Export dropdown — CSV / JSON / NDJSON, all server-side filtered.
// ---------------------------------------------------------------------------

function _mountAuditExportMenu() {
  document.removeEventListener('click', _auditExportOutsideClick);
  document.addEventListener('click', _auditExportOutsideClick);
}
function _auditExportOutsideClick(e) {
  var menu = document.getElementById('audit-export-menu');
  if (!menu || menu.hidden) return;
  if (e.target.closest('[data-action="auditExportToggle"]')) return;
  if (menu.contains(e.target)) return;
  menu.hidden = true;
}

export function auditExportToggle(_arg, target) {
  var menu = document.getElementById('audit-export-menu');
  if (!menu) return;
  if (!menu.hidden) { menu.hidden = true; return; }
  menu.innerHTML =
    '<button type="button" class="audit-export-item" data-action="auditExportRun" data-arg="csv">' +
      '<i data-lucide="file-spreadsheet"></i><span>Export as CSV</span>' +
    '</button>' +
    '<button type="button" class="audit-export-item" data-action="auditExportRun" data-arg="json">' +
      '<i data-lucide="file-json"></i><span>Export as JSON</span>' +
    '</button>' +
    '<button type="button" class="audit-export-item" data-action="auditExportRun" data-arg="ndjson">' +
      '<i data-lucide="file-text"></i><span>Export as NDJSON</span>' +
      '<span class="audit-export-hint">SIEM-friendly</span>' +
    '</button>';
  // Anchor to the trigger button — bottom-right alignment.
  var rect = (target || document.querySelector('[data-action="auditExportToggle"]')).getBoundingClientRect();
  menu.style.position = 'fixed';
  menu.style.top  = (rect.bottom + 6) + 'px';
  menu.style.left = Math.max(8, rect.right - 220) + 'px';
  menu.hidden = false;
}

export function auditExportRun(format) {
  if (!format) return;
  var qs = _auditExportQueryString();
  var url = '/api/audit/export.' + format + (qs ? ('?' + qs) : '');
  var menu = document.getElementById('audit-export-menu');
  if (menu) menu.hidden = true;
  // Same-window navigation triggers Content-Disposition: attachment.
  window.location.href = url;
}

function _auditExportQueryString() {
  var f = _auditFilters;
  var params = [];
  function add(key, value) {
    if (!value) return;
    params.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
  }
  if (f.actions.size)      add('actions',      Array.from(f.actions).join(','));
  if (f.users.size)        add('users',        Array.from(f.users).join(','));
  if (f.target_types.size) add('target_types', Array.from(f.target_types).join(','));
  if (f.time_window && f.time_window !== 'all') add('time_window', f.time_window);
  if (f.ip)          add('ip',          f.ip);
  if (f.finding_ref) add('finding_ref', f.finding_ref);
  return params.join('&');
}

function _actorCell(r) {
  // Prefer the admin-set display_name (joined by get_audit_log), fall
  // back to the raw email, fall back to the source label. The hover
  // title always shows the email for disambiguation.
  var dn = (r.user_display_name || '').trim();
  var email = r.user || '';
  var label = dn || email || r.source || '-';
  var isHuman = !!(email && /@/.test(email));
  var icon = isHuman ? '&#128100;' : '&#9881;';
  var title = isHuman
    ? (email || 'User')
    : (r.source || 'Automation');
  return '<span class="audit-actor" title="' + escapeHtml(title) + '">' +
           '<span class="audit-actor-ic">' + icon + '</span>' +
           escapeHtml(label) +
         '</span>';
}

// ---------------------------------------------------------------------------
// Drawer
// ---------------------------------------------------------------------------

export function openAuditDrawer(rowId) {
  var id = Number(rowId);
  var idx = _filteredRows.findIndex(function (r) { return Number(r.id) === id; });
  if (idx < 0) return;
  _drawerIdx = idx;
  _mountDrawerFor(_filteredRows[idx]);
  _installJkHandler();
}

function _mountDrawerFor(row) {
  var tone = _actionTone(row.action);
  var sections = [
    { label: 'Summary',         html: _sectionSummary(row) },
    { label: 'Event details',   html: _sectionEventDetails(row) },
    { label: 'Detail breakdown',html: _sectionDetailBreakdown(row) },
    { label: 'Context timeline',html: _sectionTimeline(row) },
    { label: 'Related entries', html: _sectionRelated(row) },
    { label: 'Raw JSON',        html: _sectionRaw(row) },
  ];
  var actions = [
    { label: 'Copy as JSON',    variant: 'secondary', onClick: function () { _copyJson(row); } },
    { label: 'Filter to actor', variant: 'secondary', onClick: function () { _applyFilter(row.user || row.source || ''); } },
  ];
  if (row.ip_address) {
    actions.push({ label: 'Filter to IP',    variant: 'secondary', onClick: function () { _applyFilter(row.ip_address); } });
  }
  var tgt = _parseTarget(row);
  if (tgt) {
    actions.push({ label: 'Filter to target', variant: 'secondary', onClick: function () { _applyFilter(tgt); } });
  }

  openDrawer({
    title: _actionTitle(row.action),
    subtitle: _timestampHtml(row.ts),
    badges: [{ text: row.action || 'unknown', tone: _toneToBadge(tone) }],
    sections: sections,
    actions: actions,
    onClose: function () {
      _drawerIdx = -1;
      _removeJkHandler();
    },
  });
}

// The universal drawer's badge tones are severity-themed; map our four action
// buckets onto the closest tone so the chip colour in the header matches the
// row's left-edge tint.
function _toneToBadge(tone) {
  if (tone === 'red')    return 'critical';
  if (tone === 'amber')  return 'high';
  if (tone === 'blue')   return 'info';
  if (tone === 'green')  return 'ok';
  return 'off';
}

function _timestampHtml(ts) {
  if (!ts) return '';
  // The server stores audit timestamps as local-time ISO strings (see
  // pulse/firewall/blocker.py log_audit() — CURRENT_TIMESTAMP on SQLite).
  // Surface both local and UTC so a reviewer looking at this across time
  // zones (or across the Postgres / Render deployment) has the full picture.
  var d = new Date(ts);
  if (isNaN(d.getTime())) return '<code>' + escapeHtml(ts) + '</code>';
  return '<code>' + escapeHtml(d.toLocaleString()) + '</code> · ' +
         '<span class="muted">UTC ' + escapeHtml(d.toISOString().replace('T', ' ').replace('Z', '')) + '</span>';
}

function _sectionSummary(row) {
  var human = _formatAuditDetail(row);
  if (!human) return '<div class="muted">No summary available.</div>';
  return '<div class="audit-summary-line">' + escapeHtml(human) + '</div>';
}

function _sectionEventDetails(row) {
  var isHuman = !!(row.user && /@/.test(row.user));
  var actorIcon = isHuman ? '&#128100;' : '&#9881;';
  // Prefer the admin-set display_name. For humans we drop the email +
  // "(user)" suffix entirely — the icon already signals "human", and
  // the email is available on the Actor-cell tooltip in the table if
  // disambiguation is ever needed. Automations keep their source label
  // since there's no name to substitute.
  var actorName = (row.user_display_name || '').trim() || row.user || '-';
  var actorHtml = '<span class="audit-actor-ic">' + actorIcon + '</span> ' +
                  escapeHtml(actorName);
  if (!isHuman) {
    actorHtml += ' <span class="muted">(' + escapeHtml(row.source || 'automation') + ')</span>';
  }
  var kv = [
    ['Action',   '<code>' + escapeHtml(row.action || '-') + '</code>'],
    ['Actor',    actorHtml],
    ['Source',   escapeHtml(row.source || '-')],
  ];
  if (row.ip_address) {
    kv.push(['IP',
      '<code class="audit-ip-mono">' + escapeHtml(row.ip_address) + '</code> ' +
      '<a class="audit-inline-link" onclick="window.__auditFilterBy(\'' +
        _attrEscape(row.ip_address) + '\')">filter</a>']);
  }
  kv.push(['Entry ID',
    '<code class="audit-id-chip" title="Click to copy" ' +
       'onclick="window.__auditCopyId(' + Number(row.id) + ')">' +
       'AUD-' + String(row.id).padStart(6, '0') +
    '</code>']);
  // Finding target gets its own clickable row so the reviewer can jump
  // straight to the drawer for that finding.
  var fid = _parseFindingId(row.comment);
  if (fid) {
    kv.push(['Target',
      '<a class="audit-target-pill audit-target-pill-lg" ' +
         'data-action="openAuditFinding" data-arg="' + fid + '" ' +
         'data-default="allow" ' +
         'title="Open this finding">Finding ' + fid + ' &rarr;</a>']);
  } else if (row.comment) {
    kv.push(['Comment', escapeHtml(row.comment)]);
  }
  return '<div class="kv">' + kv.map(function (p) {
    return '<div class="k">' + p[0] + '</div><div class="v">' + p[1] + '</div>';
  }).join('') + '</div>';
}

// The `detail` field is a free-form string the server composes per action.
// We parse the patterns produced by pulse/api.py + pulse/firewall/blocker.py
// into labelled kv pairs; anything we can't parse drops back to a raw line.
function _sectionDetailBreakdown(row) {
  var detail = row.detail || '';
  if (!detail) return '<div class="muted">No structured detail recorded.</div>';

  // Newer audit writes store structured JSON. Render the meaningful
  // fields as a key/value grid with clickable ref-IDs for bulk actions.
  var jd = _parseJsonDetail(detail);
  if (jd && typeof jd === 'object') {
    var rows = [];
    if (jd.from || jd.to) {
      function _stateLabel(v) {
        if (v == null) return '<span class="muted">—</span>';
        if (typeof v === 'object') return escapeHtml(v.name || ('user #' + v.id));
        return escapeHtml(String(v));
      }
      if (jd.from !== undefined) rows.push(['From', _stateLabel(jd.from)]);
      if (jd.to   !== undefined) rows.push(['To',   _stateLabel(jd.to)]);
    }
    if (jd.count != null) rows.push(['Count', String(jd.count)]);
    if (jd.reviewed != null)       rows.push(['Reviewed',       jd.reviewed       ? 'yes' : 'no']);
    if (jd.false_positive != null) rows.push(['False positive', jd.false_positive ? 'yes' : 'no']);
    if (Array.isArray(jd.ref_ids) && jd.ref_ids.length) {
      var chips = jd.ref_ids.map(function (ref) {
        return '<a class="audit-refid-chip" data-action="openAuditFindingByRef" ' +
                  'data-arg="' + escapeHtml(ref) + '" data-default="allow" ' +
                  'title="Open finding ' + escapeHtml(ref) + '">' +
          escapeHtml(ref) +
        '</a>';
      }).join(' ');
      rows.push(['Affected findings', '<div class="audit-refid-chips">' + chips + '</div>']);
    }
    if (rows.length) {
      return '<div class="kv">' + rows.map(function (p) {
        return '<div class="k">' + escapeHtml(p[0]) + '</div>' +
               '<div class="v">' + p[1] + '</div>';
      }).join('') + '</div>';
    }
    // JSON parsed but had no recognized fields — fall through.
  }

  var parsed = _parseDetail(row.action, detail);
  if (!parsed.length) {
    return '<div class="kv"><div class="k">Detail</div>' +
           '<div class="v"><code style="white-space:pre-wrap;">' + escapeHtml(detail) + '</code></div></div>';
  }
  return '<div class="kv">' + parsed.map(function (p) {
    return '<div class="k">' + escapeHtml(p[0]) + '</div>' +
           '<div class="v">' + p[1] + '</div>';
  }).join('') + '</div>';
}

// ---------------------------------------------------------------
// Human-readable audit detail renderer
// ---------------------------------------------------------------
//
// The `audit_log.detail` column is a compact key=value string chosen
// for searchability + DB-level grep ("assignee_user_id=12 count=5").
// That's fine for the stored form, but it reads terribly in the
// reviewer UI. This helper translates each action type into a short
// sentence ("Assigned 5 findings to Robert") and falls back to the
// raw detail when no mapping applies. The raw string is always still
// available in the drawer's Detail Breakdown + Raw JSON sections.
// Try to parse the detail field as JSON. Newer audit writes use a
// structured JSON shape so the formatter can surface before/after state
// and bulk ref_ids. Older rows (key=value or freeform) return null and
// fall through to the legacy parsers below.
function _parseJsonDetail(detail) {
  if (!detail || typeof detail !== 'string') return null;
  var s = detail.trim();
  if (!s.startsWith('{') && !s.startsWith('[')) return null;
  try { return JSON.parse(s); } catch (e) { return null; }
}

// Format a list of ref_ids for the table cell. Up to `head` IDs are
// listed inline; more than that gets a "and N more" suffix that opens
// in the drawer's full breakdown.
function _formatRefIdsInline(refIds, head) {
  if (!refIds || !refIds.length) return '';
  head = head || 5;
  if (refIds.length <= head) return refIds.join(', ');
  return refIds.slice(0, head).join(', ') +
    ', and ' + (refIds.length - head) + ' more';
}

function _formatAuditDetail(row) {
  var action = (row.action || '').toLowerCase();
  var detail = row.detail || '';
  var comment = row.comment || '';
  var jd = _parseJsonDetail(detail);
  var kv = jd ? null : _kvPairs(detail);

  // Bulk assign / unassign ----------------------------------------------
  if (action === 'bulk_assign_findings') {
    if (jd) {
      var name = (jd.to && jd.to.name) || 'user';
      var noun = 'finding' + (jd.count === 1 ? '' : 's');
      var refs = _formatRefIdsInline(jd.ref_ids, 5);
      var base = 'Assigned ' + jd.count + ' ' + noun + ' to ' + name;
      return refs ? base + ': ' + refs : base;
    }
    var n = _kvNum(kv, 'count');
    var legacyName = _extractAssignee(detail, kv);
    return 'Assigned ' + n + ' finding' + (n === 1 ? '' : 's') + ' to ' + legacyName;
  }
  if (action === 'bulk_unassign_findings') {
    if (jd) {
      var refsU = _formatRefIdsInline(jd.ref_ids, 5);
      var baseU = 'Unassigned ' + jd.count + ' finding' + (jd.count === 1 ? '' : 's');
      return refsU ? baseU + ': ' + refsU : baseU;
    }
    var un = _kvNum(kv, 'count');
    return 'Unassigned ' + un + ' finding' + (un === 1 ? '' : 's');
  }
  if (action === 'bulk_review_findings') {
    if (jd) {
      var refsR = _formatRefIdsInline(jd.ref_ids, 5);
      var baseR = 'Marked ' + jd.count + ' finding' + (jd.count === 1 ? '' : 's') + ' as reviewed';
      return refsR ? baseR + ': ' + refsR : baseR;
    }
    var rn = _kvNum(kv, 'count');
    return 'Marked ' + rn + ' finding' + (rn === 1 ? '' : 's') + ' reviewed';
  }
  if (action === 'bulk_unreview_findings') {
    if (jd) {
      var refsRu = _formatRefIdsInline(jd.ref_ids, 5);
      var baseRu = 'Cleared review on ' + jd.count + ' finding' + (jd.count === 1 ? '' : 's');
      return refsRu ? baseRu + ': ' + refsRu : baseRu;
    }
    var un2 = _kvNum(kv, 'count');
    return 'Cleared review on ' + un2 + ' finding' + (un2 === 1 ? '' : 's');
  }

  // Per-finding assign / unassign ---------------------------------------
  if (action === 'assign_finding') {
    if (jd && jd.to) {
      var to = jd.to.name || 'user';
      if (jd.from && jd.from.name) {
        return 'Reassigned from ' + jd.from.name + ' to ' + to;
      }
      return 'Assigned to ' + to + ' (was unassigned)';
    }
    return 'Assigned to ' + _extractAssignee(detail, kv);
  }
  if (action === 'unassign_finding') {
    if (jd && jd.from && jd.from.name) {
      return 'Unassigned (was ' + jd.from.name + ')';
    }
    return 'Unassigned';
  }

  // Review toggle -------------------------------------------------------
  if (action === 'review_finding') {
    if (jd) {
      if (jd.false_positive) return 'Marked as false positive';
      if (jd.reviewed)       return 'Marked as reviewed';
      return 'Cleared review flags';
    }
    var rev = _kvBool(kv, 'reviewed');
    var fp  = _kvBool(kv, 'false_positive');
    if (fp)  return 'Marked as false positive';
    if (rev) return 'Marked as reviewed';
    return 'Cleared review flags';
  }

  // Workflow state ------------------------------------------------------
  if (action === 'set_workflow_state') {
    if (jd && jd.to) {
      var fromState = jd.from ? _titleCase(jd.from) : null;
      var toState   = _titleCase(jd.to);
      return fromState
        ? 'Status changed from ' + fromState + ' to ' + toState
        : 'Status changed to ' + toState;
    }
    var ws = (kv && kv.workflow_status) || '';
    return 'Status changed to ' + _titleCase(ws || 'new');
  }

  // Notes ---------------------------------------------------------------
  if (action === 'add_note') {
    var len = _kvNum(kv, 'len');
    return 'Added note (' + len + ' char' + (len === 1 ? '' : 's') + ')';
  }
  if (action === 'delete_note') {
    return 'Deleted note';
  }

  // User identity changes -----------------------------------------------
  if (action === 'update_user_display_name') {
    // detail is "display_name=<repr>" (Python repr → includes quotes).
    var raw = (detail.match(/display_name=(.+)$/) || [,''])[1];
    var cleaned = raw.replace(/^['"]|['"]$/g, '').replace(/\\'/g, "'");
    if (!cleaned || cleaned === 'None') {
      return 'Cleared display name for ' + (row.comment || 'user');
    }
    return 'Set display name to ' + cleaned;
  }

  if (action === 'create_user') {
    return 'Created user ' + (comment || '') +
           (kv.role ? ' (' + kv.role + ')' : '');
  }
  if (action === 'delete_user') {
    return 'Deleted user ' + (comment || '');
  }
  if (action === 'update_user_role') {
    return 'Changed role of ' + (comment || 'user') +
           (kv.role ? ' to ' + kv.role : '');
  }
  if (action === 'update_user_active') {
    return (kv.active === '1' || kv.active === 'true')
      ? 'Reactivated ' + (comment || 'user')
      : 'Deactivated ' + (comment || 'user');
  }

  // Scan lifecycle ------------------------------------------------------
  if (action === 'scan') {
    var host = kv.hostname || '';
    var found = _kvNum(kv, 'findings');
    var parts = [];
    if (host) parts.push(host);
    var sent = 'Scanned' + (host ? ' ' + host : ' system');
    return sent + ' (' + found + ' finding' + (found === 1 ? '' : 's') + ')';
  }
  if (action === 'delete_scan') {
    var d = _kvNum(kv, 'deleted');
    return 'Deleted ' + d + ' scan' + (d === 1 ? '' : 's');
  }

  // Firewall actions ---------------------------------------------------
  if (action === 'unblock') {
    // detail is the Pulse-managed rule name. Strip the prefix to leave the IP.
    var ip = detail.replace(/^Pulse-managed:\s*/, '').trim();
    return 'Unblocked ' + (ip || detail);
  }
  if (action === 'block') {
    return 'Blocked ' + (kv.ip_address || row.ip_address || 'IP');
  }
  if (action === 'push') {
    return 'Pushed firewall rules';
  }
  if (action === 'stage') {
    return 'Staged rule: ' + detail;
  }
  if (action === 'stage_forced') {
    // User specified this stays as-is — stage_forced with the rule name
    // already reads clearly.
    return 'Stage-forced: ' + detail;
  }

  // Feedback ------------------------------------------------------------
  if (action === 'submit_feedback') {
    return 'Submitted feedback' + (kv.kind ? ' (' + kv.kind + ')' : '');
  }

  // Default: raw detail, which the drawer will also show structured.
  return detail || comment || '';
}

// Parse "a=1 b=two c='three words'" into { a:'1', b:'two' ... }. Naive
// splitter: handles bare tokens + quoted values (single-quoted from
// Python repr strings). Values with embedded spaces need quoting to
// parse correctly; we never produce those from our own log calls.
function _kvPairs(s) {
  var out = {};
  if (!s) return out;
  var re = /([a-zA-Z_][\w]*)=(?:'([^']*)'|"([^"]*)"|([^\s]+))/g;
  var m;
  while ((m = re.exec(s))) {
    out[m[1]] = m[2] != null ? m[2] : (m[3] != null ? m[3] : m[4]);
  }
  return out;
}

function _kvNum(kv, key) {
  var n = Number(kv[key]);
  return isFinite(n) ? n : 0;
}
function _kvBool(kv, key) {
  var v = kv[key];
  return v === '1' || v === 'true' || v === 'True';
}
function _titleCase(s) {
  return String(s || '').replace(/(^|\s)[a-z]/g, function (c) { return c.toUpperCase(); });
}

// Assignment detail resolution. Modern server-side logs already say
// "assigned to <name>"; legacy rows store "assignee_user_id=N" which
// we look up in the cached user map. Falls back to "user #N".
function _extractAssignee(detail, kv) {
  // Modern form — "assigned to <name>" appears after the count.
  var modern = /assigned to (.+?)(?:\s*$|\s+[a-zA-Z_]+=)/.exec(detail);
  if (modern) return modern[1].trim();
  if (kv.assignee_user_id) return _userName(kv.assignee_user_id);
  return 'a user';
}

function _parseDetail(action, detail) {
  var a = (action || '').toLowerCase();
  var pairs = [];
  var kvMatches = detail.match(/([a-zA-Z_]+)=([^\s]+)/g) || [];
  kvMatches.forEach(function (m) {
    var eq = m.indexOf('=');
    var k = m.slice(0, eq);
    var v = m.slice(eq + 1);
    pairs.push([_prettyKey(k), '<code>' + escapeHtml(v) + '</code>']);
  });
  // push / stage log the plain rule name as detail (no `=` token).
  if (!pairs.length && (a === 'push' || a === 'stage' || a === 'stage_forced')) {
    pairs.push(['Rule name', '<code>' + escapeHtml(detail) + '</code>']);
  }
  return pairs;
}

function _prettyKey(k) {
  var map = {
    scan_id:   'Scan ID',
    filename:  'File name',
    findings:  'Findings',
    page:      'Page',
    requested: 'Requested',
    deleted:   'Deleted',
    ids:       'IDs',
    target:    'Target',
    rule:      'Rule',
  };
  return map[k] || k.replace(/_/g, ' ');
}

// Parse out whatever "target" identifier this action operated on so the
// Filter-to-target footer button is meaningful.  Scans point at scan_id,
// deletes point at ids, user actions point at target=..., staging uses the
// IP itself.
function _parseTarget(row) {
  var detail = row.detail || '';
  var m = detail.match(/\btarget=(\S+)/);
  if (m) return m[1];
  m = detail.match(/\bscan_id=(\S+)/);
  if (m) return 'scan_id=' + m[1];
  var a = (row.action || '').toLowerCase();
  if (a === 'push' || a === 'stage' || a === 'stage_forced' || a === 'unblock') {
    return row.ip_address || null;
  }
  return null;
}

// Timeline: last 3 and next 3 entries from the same actor (user or source
// fallback) so the reviewer can see what that actor was doing around this
// moment.  Current row is highlighted and not clickable.
function _sectionTimeline(row) {
  var actorKey = (row.user || row.source || '').toLowerCase();
  if (!actorKey) return '<div class="muted">Actor unknown — no timeline available.</div>';
  var sameActor = _auditCache.filter(function (r) {
    return (r.user || r.source || '').toLowerCase() === actorKey;
  });
  var idx = sameActor.findIndex(function (r) { return Number(r.id) === Number(row.id); });
  if (idx < 0) return '<div class="muted">Not found in actor timeline.</div>';
  var start = Math.max(0, idx - 3);
  var end   = Math.min(sameActor.length, idx + 4);
  var slice = sameActor.slice(start, end);
  if (slice.length <= 1) return '<div class="muted">No surrounding activity for this actor.</div>';
  var items = slice.map(function (r) {
    var tone = _actionTone(r.action);
    var here = Number(r.id) === Number(row.id);
    var cls = 'audit-tl-item audit-tl-' + tone + (here ? ' audit-tl-here' : '');
    var onClick = here ? '' :
      ' onclick="window.__auditJumpTo(' + Number(r.id) + ')"';
    return '<div class="' + cls + '"' + onClick + '>' +
             '<div class="audit-tl-dot"></div>' +
             '<div class="audit-tl-body">' +
               '<div class="audit-tl-top">' +
                 '<code>' + escapeHtml(r.ts || '') + '</code>' +
               '</div>' +
               '<div class="audit-tl-bot">' +
                 escapeHtml(_actionTitle(r.action)) +
                 (r.ip_address ? ' <span class="muted">· ' + escapeHtml(r.ip_address) + '</span>' : '') +
               '</div>' +
             '</div>' +
           '</div>';
  }).join('');
  return '<div class="audit-timeline">' + items + '</div>';
}

// Related entries: anything with the same IP, or the same parsed target.
function _sectionRelated(row) {
  var tgt = _parseTarget(row);
  var ip  = row.ip_address || '';
  var rel = _auditCache.filter(function (r) {
    if (Number(r.id) === Number(row.id)) return false;
    if (ip && r.ip_address === ip) return true;
    var t = _parseTarget(r);
    return !!(tgt && t && t === tgt);
  }).slice(0, 6);
  if (!rel.length) return '<div class="muted">No other entries share this IP or target.</div>';
  return '<div class="audit-related">' + rel.map(function (r) {
    var tone = _actionTone(r.action);
    return '<div class="audit-related-row audit-edge-' + tone + '" ' +
               'onclick="window.__auditJumpTo(' + Number(r.id) + ')">' +
             '<div class="audit-related-top">' +
               '<code>' + escapeHtml(r.ts || '') + '</code> · ' +
               '<strong>' + escapeHtml(_actionTitle(r.action)) + '</strong>' +
             '</div>' +
             '<div class="muted" style="font-size:12px;">' +
               escapeHtml(r.user || r.source || '-') +
               (r.ip_address ? ' · <code>' + escapeHtml(r.ip_address) + '</code>' : '') +
             '</div>' +
           '</div>';
  }).join('') + '</div>';
}

function _sectionRaw(row) {
  var json = JSON.stringify(row, null, 2);
  return '<details class="audit-raw">' +
           '<summary>Show raw JSON <button type="button" class="audit-raw-copy" ' +
             'onclick="event.stopPropagation(); window.__auditCopyRaw(' + Number(row.id) + ')">Copy</button></summary>' +
           '<pre class="audit-raw-pre"><code>' + escapeHtml(json) + '</code></pre>' +
         '</details>';
}

// ---------------------------------------------------------------------------
// Drawer helpers (copy, jump, filter, keyboard navigation)
// ---------------------------------------------------------------------------

function _copyJson(row) {
  var text = JSON.stringify(row, null, 2);
  _clipboardWrite(text);
}

function _applyFilter(val) {
  if (!val) return;
  _auditQuery = String(val);
  var input = document.querySelector('.page-head-actions .search-input');
  if (input) input.value = _auditQuery;
  var wrap = document.getElementById('audit-table-wrap');
  if (wrap) wrap.innerHTML = _renderTable();
  closeDrawer();
}

window.__auditFilterBy = function (val) { _applyFilter(val); };
window.__auditJumpTo = function (rowId) {
  var idx = _filteredRows.findIndex(function (r) { return Number(r.id) === Number(rowId); });
  if (idx < 0) {
    // Row not in current filter — drop the filter and try again.
    _auditQuery = '';
    var input = document.querySelector('.page-head-actions .search-input');
    if (input) input.value = '';
    var wrap = document.getElementById('audit-table-wrap');
    if (wrap) wrap.innerHTML = _renderTable();
    idx = _filteredRows.findIndex(function (r) { return Number(r.id) === Number(rowId); });
    if (idx < 0) return;
  }
  _drawerIdx = idx;
  _mountDrawerFor(_filteredRows[idx]);
};
window.__auditCopyId = function (rowId) {
  _clipboardWrite('AUD-' + String(rowId).padStart(6, '0'));
};
window.__auditCopyRaw = function (rowId) {
  var row = _auditCache.find(function (r) { return Number(r.id) === Number(rowId); });
  if (row) _clipboardWrite(JSON.stringify(row, null, 2));
};

function _clipboardWrite(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text);
      return;
    }
  } catch (e) { /* fall through to legacy path */ }
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } catch (e) {}
  document.body.removeChild(ta);
}

function _installJkHandler() {
  if (_jkHandler) return;
  _jkHandler = function (e) {
    if (!isDrawerOpen()) return;
    // Ignore j/k if the user is typing in an input (Esc is handled by the
    // drawer primitive, so we only need to guard the alpha keys).
    var tag = (e.target && e.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea') return;
    if (e.key === 'j' || e.key === 'J') {
      e.preventDefault();
      _stepDrawer(+1);
    } else if (e.key === 'k' || e.key === 'K') {
      e.preventDefault();
      _stepDrawer(-1);
    }
  };
  document.addEventListener('keydown', _jkHandler);
}

function _removeJkHandler() {
  if (!_jkHandler) return;
  document.removeEventListener('keydown', _jkHandler);
  _jkHandler = null;
}

function _stepDrawer(delta) {
  if (_drawerIdx < 0 || !_filteredRows.length) return;
  var next = _drawerIdx + delta;
  if (next < 0 || next >= _filteredRows.length) return;
  _drawerIdx = next;
  _mountDrawerFor(_filteredRows[next]);
}

// Attribute-safe escape for values we inject into inline onclick handlers.
// We prefer data-action delegation for new handlers, but the quick-filter
// inline link is simple enough that a one-off attribute escape is clearer
// than registering a fifth action name.
function _attrEscape(s) {
  return String(s == null ? '' : s)
    .replace(/\\/g, '\\\\')
    .replace(/'/g,  "\\'")
    .replace(/"/g,  '&quot;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;');
}
