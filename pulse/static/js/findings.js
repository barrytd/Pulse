// findings.js — Findings page, Scans page, shared finding drawer,
// scan-detail view. Scans page lives here because it shares the
// finding drawer and buildFindingsTable helper.
'use strict';

import {
  fetchScans,
  fetchFindings,
  apiDeleteScans,
  apiSetFindingReview,
  apiSetFindingWorkflow,
  apiSetFindingAssignee,
  apiFindingsBatch,
  apiListUsers,
  apiGetMe,
  apiListFindingNotes,
  apiCreateFindingNote,
  apiDeleteFindingNote,
  apiFetchIntel,
  apiMarkFirstFindingViewed,
  invalidateScansCache,
  invalidateFindingsCache,
} from './api.js';
import {
  escapeHtml,
  scoreColor,
  scoreColorClass,
  statCard,
  showToast,
  toastError,
  mitreMap,
  _extractTime,
  _restoreSearchFocus,
  _gradeFor,
  _gradeRank,
  sevPillHtml,
  formatRelativeTime,
  relTimeHtml,
  roleBadgeHtml,
} from './dashboard.js';
import { navigate } from './navigation.js';

// ---------------------------------------------------------------
// Scan-detail (`/scans/{id}`) — the sole survivor of the old standalone
// Scans page. The list of all scans now lives on History, and the
// "All Findings" view is its own page (renderFindingsPage below). Only
// `viewScan` and the per-finding drawer logic remain in this file.
// ---------------------------------------------------------------



export async function viewScan(scanId, opts) {
  // scanId may arrive as string via data-arg; normalize.
  scanId = Number(scanId);
  opts = opts || {};
  // Push /scans/{id} into history when the user initiated the nav, so
  // browser Back returns to the scans list. When popstate called us,
  // the URL is already correct and push:false skips the write.
  if (opts.push !== false) {
    var path = '/scans/' + scanId;
    var state = { page: 'scans', scanId: scanId };
    if (location.pathname !== path) {
      history.pushState(state, '', path + (location.search || ''));
    } else {
      history.replaceState(state, '', path + (location.search || ''));
    }
  }
  var c = document.getElementById('content');
  var scans = await fetchScans(50);
  var scan = scans.find(function (s) { return s.id === scanId; });
  var findings = await fetchFindings(scanId);
  var fname = scan ? (scan.filename || 'Unknown') : 'Unknown';
  var displayNum = scan && scan.number != null ? scan.number : scanId;
  document.getElementById('page-title').textContent = fname + ' \u2014 Scan #' + displayNum;

  c.innerHTML =
    '<div class="back-link" data-action="navigate" data-arg="history">\u2190 Back to History</div>' +
    '<div class="scan-header">' +
      statCard('File', fname, scan ? (scan.hostname || '') : '', '') +
      statCard('Score', scan ? (scan.score != null ? scan.score : '-') : '-', scan ? (scan.score_label || '') : '', scan ? scoreColorClass(scan.score) : '') +
      statCard('Findings', findings.length, 'In this scan', '') +
      statCard('Date', scan ? relTimeHtml(scan.scanned_at) : '-', '', '') +
    '</div>' +
    '<div class="card">' +
      '<div class="card-title" style="justify-content:space-between;">' +
        '<span>Findings \u2014 ' + escapeHtml(fname) + '</span>' +
        '<div style="display:flex; gap:8px;">' +
          '<button class="btn-small btn-with-icon" data-action="downloadReport" data-arg="' + scanId + '" data-format="html"><i data-lucide="download"></i><span>Export HTML</span></button>' +
          '<button class="btn-small btn-with-icon" data-action="downloadReport" data-arg="' + scanId + '" data-format="pdf" style="background:var(--border); color:var(--text);"><i data-lucide="download"></i><span>Export PDF</span></button>' +
          '<button class="btn-small btn-with-icon" data-action="downloadReport" data-arg="' + scanId + '" data-format="json" style="background:var(--border); color:var(--text);"><i data-lucide="download"></i><span>Export JSON</span></button>' +
        '</div>' +
      '</div>' +
      (findings.length > 0
        ? buildFindingsTable(findings)
        : '<div style="text-align:center; padding:32px; color:var(--text-muted);">No findings in this scan. All clear.</div>') +
    '</div>';
}

// ---------------------------------------------------------------
// Findings page
// ---------------------------------------------------------------
// --------------------------------------------------------------------
// Filter shape — every dimension carries an `include` Set ("show only
// values in this set") and an `exclude` Set ("hide values in this set").
// A row passes a dimension iff:
//   (include.size === 0 OR include.has(value)) AND NOT exclude.has(value)
// The pane checkboxes drive the include axis. The right-click context
// menu drives both axes ("Filter for this value" → include, "Filter
// out this value" → exclude). Empty Sets on both axes = no filter.
// --------------------------------------------------------------------
function _makeFindingsFilters() {
  return {
    severity: { include: new Set(), exclude: new Set() },
    status:   { include: new Set(), exclude: new Set() },
    assignee: { include: new Set(), exclude: new Set() },
    host:     { include: new Set(), exclude: new Set() },
    rule:     { include: new Set(), exclude: new Set() },
    mitre:    { include: new Set(), exclude: new Set() },
    scan:     { include: new Set(), exclude: new Set() },
  };
}

export const findingsState = {
  raw:          [],
  sortCol:      'time',
  sortDir:      'desc',
  query:        '',
  expanded:     null,
  filters:      _makeFindingsFilters(),
  // Bulk-select state: a Set of finding ids currently checked. Separate
  // from row expansion so toggling the drawer doesn't disturb selection.
  selected:     Object.create(null),
  // The last computed filtered+sorted slice, kept so the bulk bar can
  // offer "Select all matching filter" without redoing the filter math.
  _lastVisible: [],
  // Per-section UI flags (collapsed / show-all-rules) — session only.
  _paneSectionCollapsed: new Set(),
  _ruleSectionExpanded:  false,
  // Secondary dims (mitre, scan) that the user "added" via "+ Add
  // filter" but hasn't yet picked a value for. Keeps the chip visible
  // in the bar so the user can either pick a value or click × to drop
  // it. Cleared when the chip's × is hit or "Clear all" runs.
  _addedSecondaryDims:   new Set(),
};

var SEV_WEIGHT = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

// One-shot filter handoff — lets other pages (e.g. the Dashboard "Needs
// Attention" widget) deep-link into the Findings page with pre-set
// filters. The shape mirrors `findingsState.filters` — each dim is an
// `{ include: [...], exclude: [...] }` literal that renderFindingsPage
// hydrates into Sets.
var _pendingFindingsFilter = null;

export function openUnreviewedCriticalHigh() {
  // Review-status pre-filter is gone (UI no longer offers it); we just
  // narrow to CRITICAL+HIGH. The label "Unreviewed" lives on the widget
  // because most attention-window findings are by definition unreviewed.
  _pendingFindingsFilter = {
    severity: { include: ['CRITICAL', 'HIGH'] },
  };
  navigate('findings');
}

export async function renderFindingsPage() {
  var c = document.getElementById('content');
  var scans = await fetchScans(200);

  var allFindings = [];
  var withFindings = scans.filter(function (s) { return s.total_findings > 0; });
  if (withFindings.length > 0) {
    var batches = await Promise.all(withFindings.map(function (s) {
      return fetchFindings(s.id).then(function (fs) {
        return fs.map(function (f, idx) {
          return Object.assign({}, f, {
            _scan_id:     s.id,
            _scan_number: s.number,
            _scan_date:   s.scanned_at,
            _scan_host:   s.hostname || s.filename || '',
            _uid:         s.id + '-' + idx,
          });
        });
      });
    }));
    batches.forEach(function (b) { allFindings = allFindings.concat(b); });
  }

  findingsState.raw     = allFindings;
  findingsState.sortCol = 'time';
  findingsState.sortDir = 'desc';
  findingsState.query   = '';
  findingsState.expanded = null;
  findingsState.selected = Object.create(null);
  findingsState.filters = _makeFindingsFilters();
  findingsState._addedSecondaryDims = new Set();
  // Stale state from the old left-pane build — keep the keys around so
  // any errant reference is a no-op rather than a crash, but they're
  // unused by the Sentinel-style header.
  findingsState._paneSectionCollapsed = new Set();
  findingsState._ruleSectionExpanded  = false;

  // Drop any leftover body class from the previous left-pane build.
  document.body.classList.remove('findings-pane-collapsed');
  try { localStorage.removeItem('pulseFindingsPaneCollapsed'); } catch (e) {}

  // Consume a one-shot pre-set filter handoff. Each entry on the pending
  // object is `{ include: [...], exclude: [...] }` for one dimension.
  if (_pendingFindingsFilter) {
    Object.keys(_pendingFindingsFilter).forEach(function (dim) {
      var slot = findingsState.filters[dim];
      if (!slot) return;
      var src = _pendingFindingsFilter[dim] || {};
      (src.include || []).forEach(function (v) { slot.include.add(v); });
      (src.exclude || []).forEach(function (v) { slot.exclude.add(v); });
    });
    _pendingFindingsFilter = null;
  }

  if (allFindings.length === 0) {
    c.innerHTML =
      '<div class="empty-state cta">' +
        '<div class="empty-icon">&#10003;</div>' +
        '<h3>No findings</h3>' +
        '<p>Every scan is clean so far. Upload a new log to check again.</p>' +
        '<button class="btn btn-primary btn-with-icon" data-action="openUploadModal"><i data-lucide="upload"></i><span>Upload .evtx</span></button>' +
      '</div>';
    return;
  }

  applyFindingsView();
}

export function setFindingsSort(col) {
  var s = findingsState;
  if (s.sortCol === col) {
    s.sortDir = (s.sortDir === 'desc') ? 'asc' : 'desc';
  } else {
    s.sortCol = col;
    s.sortDir = 'desc';
  }
  applyFindingsView();
}

export function setFindingsQuery(q) {
  findingsState.query    = q || '';
  findingsState.expanded = null;
  applyFindingsView();
}

// Delegator wrapper — pulls the live value from the input element.
export function setFindingsQueryFromInput(arg, target) {
  setFindingsQuery(target && target.value);
}

// Stop the click bubbling up to a row-level handler. Used for embedded
// links inside rows (MITRE links, scan links) so clicking them doesn't
// also toggle the row's expand/view.
export function stopClickPropagation(arg, target, e) {
  if (e) e.stopPropagation();
}

// Click on a scan link inside a row — stop propagation and navigate.
export function viewScanFromLink(arg, target, e) {
  if (e) e.stopPropagation();
  viewScan(Number(arg));
}

export function toggleFindingExpand(uid) {
  findingsState.expanded = (findingsState.expanded === uid) ? null : uid;
  applyFindingsView();
}

// Project a finding into the value used for each filter dimension.
// Centralized so the filter engine, count aggregator, and the right-
// click context menu all read the same key off a row.
function _findingDimValue(f, dim) {
  switch (dim) {
    case 'severity': return (f.severity || 'LOW').toUpperCase();
    case 'status':   return (f.workflow_status || 'new').toLowerCase();
    case 'assignee': return f.assigned_to == null ? 'unassigned' : String(f.assigned_to);
    case 'host':     return f._scan_host || '-';
    case 'rule':     return f.rule || 'Unknown';
    case 'mitre':    return (f.mitre || mitreMap[f.rule] || '') || '—';
    case 'scan':     return String(f._scan_id == null ? '' : f._scan_id);
    default:         return null;
  }
}

// Test a row against one filter dimension's include + exclude sets.
function _passesDimension(f, dim, slot) {
  if (!slot) return true;
  if (slot.include.size === 0 && slot.exclude.size === 0) return true;
  var v = _findingDimValue(f, dim);
  if (v == null) return slot.include.size === 0;
  if (slot.exclude.has(v)) return false;
  if (slot.include.size === 0) return true;
  return slot.include.has(v);
}

// True when any filter has at least one include or exclude entry.
function _hasAnyFindingsFilter() {
  var f = findingsState.filters;
  for (var k in f) {
    if (f[k].include.size > 0 || f[k].exclude.size > 0) return true;
  }
  return false;
}

export function applyFindingsView() {
  // Re-rendering the whole content div wipes scroll position, which
  // jerks the user back to the top every time they expand a row, flip
  // a filter, or run a bulk action. Capture scrollY up-front and
  // restore it after the DOM is rebuilt so the page feels static.
  var _scrollY = window.scrollY;
  var s = findingsState;
  var rows = s.raw.slice();

  // Pane-driven filters — each dimension carries an include + exclude
  // axis, and a row must pass every dimension to make it through.
  var fdims = ['severity','status','assignee','host','rule','mitre','scan'];
  fdims.forEach(function (dim) {
    var slot = s.filters[dim];
    if (!slot || (slot.include.size === 0 && slot.exclude.size === 0)) return;
    rows = rows.filter(function (f) { return _passesDimension(f, dim, slot); });
  });

  var q = s.query.trim().toLowerCase();
  if (q) {
    rows = rows.filter(function (f) {
      var hay = (f.rule || '') + ' ' + (f.details || '') + ' ' + (f.description || '') + ' ' + (f.mitre || '') + ' ' + (f._scan_host || '');
      return hay.toLowerCase().indexOf(q) >= 0;
    });
  }

  var dir = s.sortDir === 'asc' ? 1 : -1;
  rows.sort(function (a, b) {
    var av, bv;
    switch (s.sortCol) {
      case 'severity':
        av = SEV_WEIGHT[(a.severity || 'LOW').toUpperCase()] || 0;
        bv = SEV_WEIGHT[(b.severity || 'LOW').toUpperCase()] || 0;
        break;
      case 'rule':
        av = (a.rule || '').toLowerCase();
        bv = (b.rule || '').toLowerCase();
        break;
      case 'scan':
        av = a._scan_date || ''; bv = b._scan_date || ''; break;
      case 'host':
        av = (a._scan_host || '').toLowerCase();
        bv = (b._scan_host || '').toLowerCase();
        break;
      default:
        av = a.timestamp || _extractTime(a) || '';
        bv = b.timestamp || _extractTime(b) || '';
    }
    if (av < bv) return -1 * dir;
    if (av > bv) return  1 * dir;
    return 0;
  });

  // Page title — "Findings (32)" when unfiltered, "(12 of 32)" otherwise.
  var total   = s.raw.length;
  var visible = rows.length;
  var anyFilter = _hasAnyFindingsFilter() || !!q;
  var countLabel = anyFilter ? (visible + ' of ' + total) : String(total);
  var titleEl = document.getElementById('page-title');
  if (titleEl) titleEl.textContent = 'Findings (' + countLabel + ')';

  // Stash the pre-render visible slice BEFORE we might short-circuit
  // into the empty-state branch — the bulk bar reads this to compute
  // "Select all matching filter" counts.
  s._lastVisible = rows;

  // Auto-refresh self-pauses when the user is actively filtering or has
  // the detail flyout open — the new render would otherwise interrupt
  // their work. We re-arm whenever applyFindingsView runs in the
  // unfiltered, drawer-closed steady state.
  _findingsAutoRefreshTick();

  var c = document.getElementById('content');
  c.innerHTML =
    '<div class="findings-page">' +
      _findingsPageHeaderHtml(total, visible) +
      '<div class="findings-page-body">' +
        '<div class="card" style="padding:0; overflow:hidden;">' +
          (rows.length === 0
            ? '<div style="text-align:center; padding:32px; color:var(--text-muted);">No findings match the current filters.</div>'
            : _buildFindingsTable(rows)) +
        '</div>' +
        _renderBulkBarHtml(visible, total, anyFilter) +
      '</div>' +
    '</div>' +
    // Right-click context menu — fresh node per render avoids leaking
    // listeners. (The chip-dropdown popover lives INSIDE the filter
    // bar so it can position absolute relative to that container.)
    '<div class="findings-ctx-menu" id="findings-ctx-menu" hidden></div>';

  _restoreSearchFocus('findings-search-box');
  _mountBulkBarUsers();
  _mountFindingsContextMenu();
  _mountFilterChipDropdown();
  // Paired with the scrollY capture at the top of this function —
  // `instant` so the page doesn't animate back into place.
  window.scrollTo({ top: _scrollY, left: 0, behavior: 'instant' });
}

// ---------------------------------------------------------------
// Filter dimensions — drive both the chip bar and the per-chip
// dropdown popover. Each entry: { id, label, build } where build(raw)
// returns [{ value, label, count, dotColor? }, ...] sorted as the
// user expects. The chip-dim distinction matters for the "+ Add
// filter" menu — `primary: true` is shown directly in the bar; the
// rest are accessible via "+ Add filter".
function _findingsFilterDims() {
  return [
    { id: 'severity', label: 'Severity',     primary: true,  build: _sectionItemsSeverity },
    { id: 'status',   label: 'Status',       primary: true,  build: _sectionItemsStatus },
    { id: 'assignee', label: 'Assignment',   primary: true,  build: _sectionItemsAssignee },
    { id: 'host',     label: 'Host',         primary: true,  build: _sectionItemsHost },
    { id: 'rule',     label: 'Rule',         primary: true,  build: _sectionItemsRule },
    { id: 'mitre',    label: 'MITRE Tactic', primary: false, build: _sectionItemsMitre },
    { id: 'scan',     label: 'Scan',         primary: false, build: _sectionItemsScan },
  ];
}

var _SEV_DOT = {
  CRITICAL: '#f85149',
  HIGH:     '#f0883e',
  MEDIUM:   '#d29922',
  LOW:      '#3fb950',
};

function _sectionItemsSeverity(raw) {
  var counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  raw.forEach(function (f) {
    var sv = (f.severity || 'LOW').toUpperCase();
    if (counts[sv] !== undefined) counts[sv]++;
  });
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(function (k) {
    return { value: k, label: k.charAt(0) + k.slice(1).toLowerCase(),
             count: counts[k], dotColor: _SEV_DOT[k] };
  });
}

function _sectionItemsStatus(raw) {
  var labels = { new: 'New', acknowledged: 'Acknowledged',
                 investigating: 'Investigating', resolved: 'Resolved' };
  var counts = { new: 0, acknowledged: 0, investigating: 0, resolved: 0 };
  raw.forEach(function (f) {
    var st = (f.workflow_status || 'new').toLowerCase();
    if (counts[st] !== undefined) counts[st]++;
  });
  return Object.keys(labels).map(function (k) {
    return { value: k, label: labels[k], count: counts[k] };
  });
}

function _sectionItemsAssignee(raw) {
  // Group by user id. Unassigned rows bucket under the literal
  // 'unassigned' value so the filter and the chip can round-trip.
  var bucket = {};
  raw.forEach(function (f) {
    var key = f.assigned_to == null ? 'unassigned' : String(f.assigned_to);
    var label = f.assigned_to == null
      ? 'Unassigned'
      : (f.assignee_display_name || f.assignee_email || ('user #' + f.assigned_to));
    if (!bucket[key]) bucket[key] = { value: key, label: label, count: 0 };
    bucket[key].count++;
  });
  // Unassigned always pinned to the top, then named analysts by
  // descending count.
  var rest = Object.keys(bucket)
    .filter(function (k) { return k !== 'unassigned'; })
    .map(function (k) { return bucket[k]; })
    .sort(function (a, b) { return b.count - a.count; });
  var head = bucket.unassigned ? [bucket.unassigned] : [];
  return head.concat(rest);
}

function _sectionItemsHost(raw) {
  var bucket = {};
  raw.forEach(function (f) {
    var h = f._scan_host || '-';
    if (!bucket[h]) bucket[h] = { value: h, label: h, count: 0 };
    bucket[h].count++;
  });
  return Object.values(bucket).sort(function (a, b) { return b.count - a.count; });
}

function _sectionItemsRule(raw) {
  var bucket = {};
  raw.forEach(function (f) {
    var r = f.rule || 'Unknown';
    if (!bucket[r]) bucket[r] = { value: r, label: r, count: 0 };
    bucket[r].count++;
  });
  return Object.values(bucket).sort(function (a, b) { return b.count - a.count; });
}

function _sectionItemsMitre(raw) {
  var bucket = {};
  raw.forEach(function (f) {
    var m = (f.mitre || mitreMap[f.rule] || '') || '—';
    if (!bucket[m]) bucket[m] = { value: m, label: m, count: 0 };
    bucket[m].count++;
  });
  return Object.values(bucket).sort(function (a, b) { return b.count - a.count; });
}

function _sectionItemsScan(raw) {
  // Group by scan id, label as "Scan #N", sort by date desc (newest first).
  var bucket = {};
  raw.forEach(function (f) {
    var key = String(f._scan_id == null ? '' : f._scan_id);
    if (!bucket[key]) {
      bucket[key] = {
        value: key,
        label: 'Scan #' + (f._scan_number != null ? f._scan_number : f._scan_id),
        count: 0,
        _date: f._scan_date || '',
      };
    }
    bucket[key].count++;
  });
  return Object.values(bucket).sort(function (a, b) {
    return (a._date < b._date) ? 1 : (a._date > b._date ? -1 : 0);
  });
}

// ---------------------------------------------------------------
// Sentinel-style page header — five stacked zones (breadcrumb,
// title block, KPI tile row, severity bar, sticky filter bar).
// All HTML builders are intentionally framework-free strings so
// re-rendering the page costs nothing more than an innerHTML swap.
// ---------------------------------------------------------------

function _findingsPageHeaderHtml(total, visible) {
  return '<div class="page-header">' +
    _breadcrumbHtml(['Pulse', 'Threat Management', 'Findings']) +
    _findingsTitleBlockHtml(total, visible) +
    _findingsKpiRowHtml() +
    _findingsSeverityBarHtml() +
    _findingsFilterBarHtml() +
  '</div>';
}

function _breadcrumbHtml(crumbs) {
  return '<nav class="page-breadcrumb" aria-label="Breadcrumb">' +
    crumbs.map(function (c, i) {
      var sep = i === crumbs.length - 1
        ? ''
        : '<span class="page-breadcrumb-sep" aria-hidden="true">›</span>';
      var cls = i === crumbs.length - 1 ? 'page-breadcrumb-current' : 'page-breadcrumb-item';
      return '<span class="' + cls + '">' + escapeHtml(c) + '</span>' + sep;
    }).join('') +
  '</nav>';
}

function _findingsTitleBlockHtml(total, visible) {
  // Count surfaces in the title itself per the spec — no separate
  // count row competing for attention. When filters are active we
  // show "(12 of 216)" so the analyst sees both numbers at a glance.
  var s = findingsState;
  var anyFilter = _hasAnyFindingsFilter() || !!s.query.trim();
  var countLabel = anyFilter ? (visible + ' of ' + total) : String(total);
  var refreshing = _autoRefreshState.busy ? ' is-busy' : '';
  return '<div class="page-title-block">' +
    '<h1 class="page-title">Findings <span class="page-title-count">(' + countLabel + ')</span></h1>' +
    '<div class="page-title-actions">' +
      '<label class="toggle-switch" title="Refresh data every 30s">' +
        '<input type="checkbox" id="findings-auto-refresh" ' +
          (_autoRefreshState.enabled ? ' checked' : '') +
          ' data-action-change="toggleFindingsAutoRefresh" />' +
        '<span class="toggle-switch-track" aria-hidden="true"></span>' +
        '<span class="toggle-switch-label">Auto-refresh</span>' +
      '</label>' +
      '<button class="btn btn-compact btn-with-icon' + refreshing + '" ' +
        'data-action="refreshFindings" title="Refresh now">' +
        '<i data-lucide="refresh-cw"></i><span>Refresh</span></button>' +
      '<button class="btn btn-compact btn-with-icon" data-action="exportFindingsCsv" ' +
        'title="Download all findings as CSV">' +
        '<i data-lucide="download"></i><span>Export CSV</span></button>' +
    '</div>' +
  '</div>';
}

// ----- KPI tiles -----------------------------------------------
// 4 reusable .kpi-tile cards above the severity bar. Each tile is a
// button so the whole card is keyboard-clickable; clicking pre-fills
// the Status filter to match the tile's bucket.

function _findingsKpiRowHtml() {
  var counts = _findingsStatusCounts();
  // "Open" rolls up new + acknowledged + investigating — i.e. anything
  // that isn't resolved yet. The other three buckets pin to specific
  // workflow_status values so the filter chip lands cleanly.
  var open = counts.new + counts.acknowledged + counts.investigating;
  return '<div class="kpi-row">' +
    _kpiTileHtml('open',     'Open findings',     open,                 'all open workflow states') +
    _kpiTileHtml('new',      'New findings',      counts.new,           'untriaged') +
    _kpiTileHtml('active',   'Active findings',   counts.investigating, 'currently being investigated') +
    _kpiTileHtml('resolved', 'Resolved findings', counts.resolved,      'closed out') +
  '</div>';
}

function _kpiTileHtml(bucket, label, n, sub) {
  // The active class + accent border land when the corresponding
  // status filter is currently set to this tile's bucket exactly
  // — a clear visual handshake between tile and filter chip.
  var s = findingsState;
  var statusSlot = s.filters.status;
  var active = false;
  if (bucket === 'open') {
    var openSet = new Set(['new', 'acknowledged', 'investigating']);
    active = statusSlot.include.size > 0 &&
             Array.from(statusSlot.include).every(function (v) { return openSet.has(v); }) &&
             statusSlot.include.size === openSet.size;
  } else {
    active = statusSlot.include.size === 1 && statusSlot.include.has(bucket);
  }
  return '<button class="kpi-tile' + (active ? ' is-active' : '') +
         '" data-action="findingsKpiClick" data-arg="' + bucket + '">' +
    '<div class="kpi-tile-number">' + n.toLocaleString() + '</div>' +
    '<div class="kpi-tile-label">' + escapeHtml(label) + '</div>' +
    '<div class="kpi-tile-sub">' + escapeHtml(sub) + '</div>' +
  '</button>';
}

function _findingsStatusCounts() {
  var counts = { new: 0, acknowledged: 0, investigating: 0, resolved: 0 };
  (findingsState.raw || []).forEach(function (f) {
    var st = (f.workflow_status || 'new').toLowerCase();
    if (counts[st] !== undefined) counts[st]++;
  });
  return counts;
}

// ----- Severity bar --------------------------------------------
// 6px stacked horizontal bar with legend dots + counts above. Reads
// off the unfiltered raw counts so the analyst sees the absolute
// distribution, not whatever the current filter narrows to.

function _findingsSeverityBarHtml() {
  var counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  (findingsState.raw || []).forEach(function (f) {
    var sv = (f.severity || 'LOW').toUpperCase();
    if (counts[sv] !== undefined) counts[sv]++;
  });
  var total = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW;
  if (total === 0) return ''; // nothing to draw

  function legendDot(sev, label) {
    var color = _SEV_DOT[sev];
    return '<span class="sev-bar-legend-item">' +
      '<span class="sev-bar-legend-dot" style="background:' + color + '"></span>' +
      escapeHtml(label) + ' <strong>' + counts[sev] + '</strong>' +
    '</span>';
  }
  function seg(sev) {
    var n = counts[sev];
    if (n === 0) return '';
    return '<div class="sev-bar-seg" style="flex:' + n + '; background:' + _SEV_DOT[sev] + '" ' +
           'title="' + sev.charAt(0) + sev.slice(1).toLowerCase() + ': ' + n + '"></div>';
  }
  return '<div class="sev-bar-wrap">' +
    '<div class="sev-bar-legend">' +
      legendDot('CRITICAL', 'Critical') +
      legendDot('HIGH',     'High') +
      legendDot('MEDIUM',   'Medium') +
      legendDot('LOW',      'Low') +
    '</div>' +
    '<div class="sev-bar" role="img" aria-label="Severity distribution">' +
      seg('CRITICAL') + seg('HIGH') + seg('MEDIUM') + seg('LOW') +
    '</div>' +
  '</div>';
}

// ----- Sticky filter bar ---------------------------------------
// Search input, primary chip dropdowns, "+ Add filter" entry, and
// a "Clear all" link aligned right when any filter is active.

function _findingsFilterBarHtml() {
  var s = findingsState;
  var dims = _findingsFilterDims();
  var active = _hasAnyFindingsFilter();

  // Each chip is wrapped in its own .filter-chip-wrap that establishes
  // the positioning context for the chip's dropdown. Secondary dims
  // (mitre / scan) only render their wrap once active OR after the
  // user has explicitly added them via "+ Add filter".
  var chipsHtml = dims.map(function (dim) {
    var slot = s.filters[dim.id];
    var n = slot.include.size + slot.exclude.size;
    if (!dim.primary && n === 0 && !s._addedSecondaryDims.has(dim.id)) return '';
    return _filterChipWrapHtml(dim, slot, n);
  }).join('');

  // "+ Add filter" lists secondary dims that aren't already shown as
  // a chip in the bar — same predicate the chip-render rule uses.
  var hidden = dims.filter(function (d) {
    if (d.primary) return false;
    if (s._addedSecondaryDims.has(d.id)) return false;
    var slot = s.filters[d.id];
    return slot.include.size + slot.exclude.size === 0;
  });
  var addWrap = hidden.length === 0 ? '' :
    '<div class="filter-chip-wrap filter-chip-wrap-add">' +
      '<button type="button" class="filter-chip-add" data-action="openAddFilterMenu">' +
        '<span aria-hidden="true">+</span> Add filter' +
      '</button>' +
      // Empty dropdown — populated by openAddFilterMenu when clicked.
      '<div class="filter-chip-dd" hidden></div>' +
    '</div>';

  var clearAll = active
    ? '<a class="filter-chip-clear-all" data-action="clearFindingsFilters">Clear all</a>'
    : '';

  return '<div class="filter-bar">' +
    '<input type="search" id="findings-search-box" class="filter-bar-search" ' +
      'placeholder="Search rule, description, or MITRE..." ' +
      'value="' + escapeHtml(s.query) + '" ' +
      'data-action-input="setFindingsQueryFromInput" />' +
    '<div class="filter-bar-chips">' + chipsHtml + addWrap + '</div>' +
    clearAll +
  '</div>';
}

function _filterChipWrapHtml(dim, slot, n) {
  // Per-chip wrap — establishes a positioning context for the chip's
  // own dropdown. The dropdown is rendered empty here and populated
  // when the user clicks the chip; this keeps the initial render
  // cheap (we don't build N dropdowns just to leave them hidden).
  //
  // Primary dims (Severity / Status / Assignment / Host / Rule) are
  // permanent fixtures of the bar — they show a caret (▾) only.
  // Secondary dims (MITRE / Scan) were added via "+ Add filter" and
  // get a small × button rendered as a SIBLING of the chip (not a
  // child) so the dismiss click never bubbles into openFilterChip.
  var label = dim.label;
  var cls = 'filter-chip';
  if (n > 0) {
    cls += ' is-active';
    label += ': ' + n + ' selected';
  }
  if (!dim.primary) cls += ' has-dismiss'; // remove right-rounded corners on the chip
  // Inline SVG (not Lucide) so the icon paints synchronously on first
  // render, and pointer-events:none on the svg + the .filter-chip-x-svg
  // <line>s guarantees every click on the button area lands on the
  // <button> itself — closest('[data-action]') always returns it.
  var dismissBtn = !dim.primary
    ? '<button type="button" class="filter-chip-dismiss" ' +
        'data-action="dismissFilterChip" data-arg="' + dim.id + '" ' +
        'aria-label="Remove filter" title="Remove filter">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
          'stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" ' +
          'class="filter-chip-x-svg" aria-hidden="true">' +
          '<line x1="18" y1="6" x2="6" y2="18"></line>' +
          '<line x1="6" y1="6" x2="18" y2="18"></line>' +
        '</svg>' +
      '</button>'
    : '';
  return '<div class="filter-chip-wrap" data-dim="' + escapeHtml(dim.id) + '">' +
    '<button type="button" class="' + cls + '" ' +
      'data-action="openFilterChip" data-arg="' + dim.id + '">' +
      '<span class="filter-chip-label">' + escapeHtml(label) + '</span>' +
      '<span class="filter-chip-caret" aria-hidden="true">▾</span>' +
    '</button>' +
    dismissBtn +
    '<div class="filter-chip-dd" hidden></div>' +
  '</div>';
}

// ---------------------------------------------------------------
// Filter chip dropdown — populated inside the chip's own .filter-chip-
// wrap. Positioning is pure CSS: position: absolute, top: 100%, left: 0
// against the wrap. Right-edge flip is a single class toggle. No
// JS coordinate math, no document.body insertion, no offsetParent
// surprises.
// ---------------------------------------------------------------

function _mountFilterChipDropdown() {
  var bar = document.querySelector('.filter-bar');
  if (!bar) return;
  // Outside-click and Escape close. Document-level listeners are
  // re-registered every applyFindingsView; the named functions below
  // dedupe so we never end up with N listeners from N renders.
  document.removeEventListener('click', _filterChipOutsideClick);
  document.addEventListener('click', _filterChipOutsideClick);
  document.removeEventListener('keydown', _filterChipEscapeClose);
  document.addEventListener('keydown', _filterChipEscapeClose);
}

function _filterChipOutsideClick(e) {
  // Stale listener from a previous render of this page: if the user
  // has navigated to a different page (Audit, Dashboard, ...), this
  // handler must not act on chips that belong to that new page —
  // otherwise it'd close them right after they opened.
  if (document.body.dataset.page !== 'findings') return;
  // A click on a trigger button is handled by its own action handler;
  // skip the close pass so the same click doesn't both open and close.
  var trigger = e.target.closest('[data-action="openFilterChip"], [data-action="openAddFilterMenu"]');
  if (trigger) return;
  // Click inside any open dropdown — let it through.
  if (e.target.closest('.filter-chip-dd')) return;
  _closeAllFilterChipDropdowns();
}

function _filterChipEscapeClose(e) {
  if (e.key !== 'Escape') return;
  if (document.body.dataset.page !== 'findings') return;
  _closeAllFilterChipDropdowns();
}

function _closeAllFilterChipDropdowns() {
  document.querySelectorAll('.filter-chip-dd').forEach(function (dd) {
    dd.hidden = true;
    dd.classList.remove('is-flip-right');
    dd.innerHTML = ''; // free the contents so the next open is clean
  });
}

// data-arg = dim id. Renders the checkbox list into the dropdown
// living inside this chip's own .filter-chip-wrap. CSS handles the
// "directly below the chip" placement.
export function openFilterChip(dimId, target) {
  if (!dimId) return;
  // Find the wrap that owns this dim. When called from inside the
  // +Add filter menu (target is an .add-item button), we look up the
  // wrap by the dim attribute instead of walking up from the click.
  var wrap = (target && target.closest && target.closest('.filter-chip-wrap[data-dim="' + dimId + '"]')) ||
             document.querySelector('.filter-chip-wrap[data-dim="' + dimId + '"]');
  if (!wrap) return;
  var dd = wrap.querySelector('.filter-chip-dd');
  if (!dd) return;

  // Toggle off if the same chip is clicked twice.
  var alreadyOpen = !dd.hidden;
  _closeAllFilterChipDropdowns();
  if (alreadyOpen) return;

  var dim = _findingsFilterDims().find(function (d) { return d.id === dimId; });
  if (!dim) return;
  var items = dim.build(findingsState.raw) || [];
  var slot = findingsState.filters[dim.id];

  dd.innerHTML =
    '<div class="filter-chip-dd-head">' +
      '<input type="search" class="filter-chip-dd-search" ' +
        'placeholder="Find ' + escapeHtml(dim.label.toLowerCase()) + '..." ' +
        'data-action-input="filterChipDdFind" />' +
    '</div>' +
    '<ul class="filter-chip-dd-list">' +
      items.map(function (it) {
        var checked = slot.include.has(it.value);
        var dot = it.dotColor
          ? '<span class="filter-chip-dd-dot" style="background:' + it.dotColor + '"></span>'
          : '';
        return '<li>' +
          '<label>' +
            '<input type="checkbox"' + (checked ? ' checked' : '') + ' ' +
              'data-action-change="toggleFindingsFilter" ' +
              'data-arg="' + escapeHtml(dim.id) + '|' + escapeHtml(String(it.value)) + '" />' +
            dot +
            '<span class="filter-chip-dd-value" title="' + escapeHtml(it.label) + '">' +
              escapeHtml(it.label) +
            '</span>' +
            '<span class="filter-chip-dd-count">' + it.count + '</span>' +
          '</label>' +
        '</li>';
      }).join('') +
    '</ul>';

  dd.hidden = false;
  _maybeFlipRight(dd, wrap);
  var firstInput = dd.querySelector('input');
  if (firstInput) firstInput.focus();
}

// "+ Add filter" → render a mini menu in the +Add wrap's local dropdown
// listing inactive secondary dims. Clicking one closes this menu and
// opens that dim's chip dropdown via openFilterChip.
export function openAddFilterMenu(_arg, target) {
  var wrap = target && target.closest
    ? target.closest('.filter-chip-wrap-add')
    : document.querySelector('.filter-chip-wrap-add');
  if (!wrap) return;
  var dd = wrap.querySelector('.filter-chip-dd');
  if (!dd) return;

  var alreadyOpen = !dd.hidden;
  _closeAllFilterChipDropdowns();
  if (alreadyOpen) return;

  var s = findingsState;
  var dims = _findingsFilterDims().filter(function (d) {
    if (d.primary) return false;
    if (s._addedSecondaryDims.has(d.id)) return false;
    var slot = s.filters[d.id];
    return slot.include.size + slot.exclude.size === 0;
  });
  if (dims.length === 0) return;

  dd.innerHTML =
    '<div class="filter-chip-dd-add-list">' +
      dims.map(function (d) {
        // Once chosen, addFilterDim re-renders the bar so the chip
        // appears, then opens its dropdown. Going through addFilterDim
        // (rather than openFilterChip directly) means the secondary
        // chip exists in the DOM by the time we try to open it.
        return '<button type="button" class="filter-chip-dd-add-item" ' +
          'data-action="addFilterDim" data-arg="' + escapeHtml(d.id) + '">' +
          escapeHtml(d.label) +
        '</button>';
      }).join('') +
    '</div>';

  dd.hidden = false;
  _maybeFlipRight(dd, wrap);
}

// Surface a secondary dim as a chip in the bar (initially with no
// active selections), then open its dropdown so the user can pick one.
export function addFilterDim(dimId) {
  var slot = findingsState.filters[dimId];
  if (!slot) return;
  // Mark the dim as "added" so applyFindingsView's render rule keeps
  // its chip visible even before the user selects a value. Clearing
  // the chip via × removes the dim from this set, sending it back
  // under the "+ Add filter" menu.
  findingsState._addedSecondaryDims.add(dimId);
  applyFindingsView();
  // Now the chip wrap exists; open its dropdown anchored to it.
  setTimeout(function () { openFilterChip(dimId, null); }, 0);
}

// Right-edge overflow check: if the dropdown's right edge would land
// past the viewport (minus 8px gutter), flip it via .is-flip-right
// (CSS swaps left:0 → right:0).
function _maybeFlipRight(dd, wrap) {
  dd.classList.remove('is-flip-right');
  var ddRect   = dd.getBoundingClientRect();
  if (ddRect.right > window.innerWidth - 8) {
    dd.classList.add('is-flip-right');
  }
}

// "Find filter..." input inside the popover — narrows the visible
// rows by label substring. Same UX as the old pane's find-filter.
export function filterChipDdFind(_arg, target) {
  var dd = target && target.closest('.filter-chip-dd');
  if (!dd) return;
  var needle = String((target && target.value) || '').trim().toLowerCase();
  dd.querySelectorAll('.filter-chip-dd-list li').forEach(function (li) {
    var label = (li.querySelector('.filter-chip-dd-value') || {}).textContent || '';
    li.style.display = !needle || label.toLowerCase().indexOf(needle) >= 0 ? '' : 'none';
  });
}

// Chip × — wipes both axes of one dim (filter-bar quick clear).
export function clearFilterChip(dimId, _target, ev) {
  if (ev) ev.stopPropagation();
  var slot = findingsState.filters[dimId];
  if (!slot) return;
  slot.include.clear();
  slot.exclude.clear();
  // Drop from the "user added me" set so secondary chips disappear
  // back into the +Add filter menu when their × is hit.
  findingsState._addedSecondaryDims.delete(dimId);
  applyFindingsView();
}

// Same effect as clearFilterChip but only fires from the small × icon
// rendered on secondary chips (MITRE / Scan). The two paths are kept
// separate so the chip's main click target (open dropdown) and the
// dismiss target are unambiguous in the action registry.
export function dismissFilterChip(dimId, _target, ev) {
  if (ev) ev.stopPropagation();
  var slot = findingsState.filters[dimId];
  if (!slot) return;
  slot.include.clear();
  slot.exclude.clear();
  findingsState._addedSecondaryDims.delete(dimId);
  applyFindingsView();
}

// ---------------------------------------------------------------
// KPI tile click — pre-fills the Status filter to the tile's bucket.
// ---------------------------------------------------------------

export function findingsKpiClick(bucket) {
  var slot = findingsState.filters.status;
  if (!slot) return;
  // Tile clicks always REPLACE the status filter (rather than toggle
  // each bucket individually), so multiple clicks act like a radio
  // group: "show me the open ones, now show me only resolved".
  slot.include.clear();
  slot.exclude.clear();
  if (bucket === 'open') {
    slot.include.add('new');
    slot.include.add('acknowledged');
    slot.include.add('investigating');
  } else if (bucket === 'new' || bucket === 'resolved') {
    slot.include.add(bucket);
  } else if (bucket === 'active') {
    slot.include.add('investigating');
  }
  applyFindingsView();
}

// ---------------------------------------------------------------
// Refresh / Export CSV / Auto-refresh
// ---------------------------------------------------------------

var _autoRefreshState = {
  enabled:    false,    // user toggle
  intervalId: null,     // window.setInterval handle
  busy:       false,    // currently in the middle of a refresh fetch
};

function _findingsAutoRefreshTick() {
  // Pause when the user is filtering or has the drawer open — both are
  // active-attention states where a re-render would feel intrusive.
  var paused = _hasAnyFindingsFilter() ||
               !!findingsState.query.trim() ||
               document.getElementById('finding-drawer')?.classList.contains('open');
  if (_autoRefreshState.intervalId) {
    clearInterval(_autoRefreshState.intervalId);
    _autoRefreshState.intervalId = null;
  }
  if (_autoRefreshState.enabled && !paused) {
    _autoRefreshState.intervalId = setInterval(refreshFindings, 30000);
  }
}

export function toggleFindingsAutoRefresh(_arg, target) {
  _autoRefreshState.enabled = !!(target && target.checked);
  _findingsAutoRefreshTick();
}

export async function refreshFindings() {
  if (_autoRefreshState.busy) return;
  _autoRefreshState.busy = true;
  try {
    invalidateScansCache();
    invalidateFindingsCache();
    await renderFindingsPage();
  } finally {
    _autoRefreshState.busy = false;
  }
}

// CSV export reuses the Fleet pattern — bare-bones navigation to an
// /api endpoint that streams a Content-Disposition: attachment file.
export function exportFindingsCsv() {
  window.location.href = '/api/findings/export.csv';
}

// data-arg = "dim|value". Checkbox change toggles include membership.
// Switching to "include" auto-clears any matching "exclude" entry so
// the user doesn't have to deal with conflicting state.
export function toggleFindingsFilter(arg, target) {
  if (!arg) return;
  var parts = String(arg).split('|');
  var dim = parts[0], value = parts.slice(1).join('|');
  var slot = findingsState.filters[dim];
  if (!slot) return;
  var checked = !!(target && target.checked);
  if (checked) {
    slot.include.add(value);
    slot.exclude.delete(value);
  } else {
    slot.include.delete(value);
  }
  applyFindingsView();
  // Multi-select UX: reopen the same chip's dropdown after the
  // re-render so the user can keep ticking boxes in one motion.
  // Without this the dropdown closes after every click, making
  // the popover effectively single-select.
  setTimeout(function () { openFilterChip(dim, null); }, 0);
}

// Chip × — data-arg is "dim|kind|value" (kind is 'include' or 'exclude').
export function removeFindingsFilterChip(arg) {
  if (!arg) return;
  var parts = String(arg).split('|');
  var dim = parts[0], kind = parts[1], value = parts.slice(2).join('|');
  var slot = findingsState.filters[dim];
  if (!slot) return;
  if (kind === 'exclude') slot.exclude.delete(value);
  else slot.include.delete(value);
  applyFindingsView();
}

export function clearFindingsFilters() {
  var f = findingsState.filters;
  Object.keys(f).forEach(function (k) {
    f[k].include.clear();
    f[k].exclude.clear();
  });
  findingsState._addedSecondaryDims.clear();
  applyFindingsView();
}

// ---------------------------------------------------------------
// Right-click context menu
// ---------------------------------------------------------------
// Mounts a single contextmenu listener on the findings table area.
// When a target carries data-filter-dim + data-filter-value, the
// menu opens with "Filter for / Filter out [value]" actions that
// dispatch into the same filter slots the pane drives.

function _mountFindingsContextMenu() {
  var page = document.querySelector('.findings-page');
  var menu = document.getElementById('findings-ctx-menu');
  if (!page || !menu) return;

  page.addEventListener('contextmenu', function (e) {
    var cell = e.target.closest('[data-filter-dim][data-filter-value]');
    if (!cell) return;
    e.preventDefault();
    var dim   = cell.getAttribute('data-filter-dim');
    var value = cell.getAttribute('data-filter-value');
    var label = cell.getAttribute('data-filter-label') || value;
    _openFindingsCtxMenu(menu, e.clientX, e.clientY, dim, value, label);
  });

  // Click anywhere outside or hit Escape closes the menu.
  document.addEventListener('click', function (e) {
    if (menu.hidden) return;
    if (!menu.contains(e.target)) menu.hidden = true;
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !menu.hidden) menu.hidden = true;
  });
}

function _openFindingsCtxMenu(menu, x, y, dim, value, label) {
  // QRadar-style two-action menu. The action handler reads dim + value
  // out of data-arg (joined by '|') and toggles the right slot.
  var arg = dim + '|' + value;
  menu.innerHTML =
    '<button type="button" class="findings-ctx-item" ' +
      'data-action="findingsCtxFilterFor" ' +
      'data-arg="' + escapeHtml(arg) + '">' +
      'Filter for &ldquo;' + escapeHtml(label) + '&rdquo;' +
    '</button>' +
    '<button type="button" class="findings-ctx-item findings-ctx-item-exclude" ' +
      'data-action="findingsCtxFilterOut" ' +
      'data-arg="' + escapeHtml(arg) + '">' +
      'Filter out &ldquo;' + escapeHtml(label) + '&rdquo;' +
    '</button>';
  // Show offscreen first so we can measure, then clamp inside viewport.
  menu.style.left = '0px';
  menu.style.top  = '0px';
  menu.hidden = false;
  var rect = menu.getBoundingClientRect();
  var maxX = window.innerWidth - rect.width - 8;
  var maxY = window.innerHeight - rect.height - 8;
  menu.style.left = Math.max(8, Math.min(x, maxX)) + 'px';
  menu.style.top  = Math.max(8, Math.min(y, maxY)) + 'px';
}

export function findingsCtxFilterFor(arg) {
  if (!arg) return;
  var parts = String(arg).split('|');
  var dim = parts[0], value = parts.slice(1).join('|');
  var slot = findingsState.filters[dim];
  if (!slot) return;
  slot.include.add(value);
  slot.exclude.delete(value);
  var menu = document.getElementById('findings-ctx-menu');
  if (menu) menu.hidden = true;
  applyFindingsView();
}

export function findingsCtxFilterOut(arg) {
  if (!arg) return;
  var parts = String(arg).split('|');
  var dim = parts[0], value = parts.slice(1).join('|');
  var slot = findingsState.filters[dim];
  if (!slot) return;
  slot.exclude.add(value);
  slot.include.delete(value);
  var menu = document.getElementById('findings-ctx-menu');
  if (menu) menu.hidden = true;
  applyFindingsView();
}


// ---------------------------------------------------------------
// Findings bulk-select state
// ---------------------------------------------------------------

export function toggleFindingSelect(id, target, ev) {
  if (ev) ev.stopPropagation();
  if (id == null) return;
  var key = String(id);
  if (findingsState.selected[key]) delete findingsState.selected[key];
  else findingsState.selected[key] = true;
  _updateBulkBar();
}

// Header checkbox — toggles every visible row.
export function toggleFindingSelectAll(arg, target) {
  var checked;
  if (target && typeof target.checked === 'boolean') checked = target.checked;
  else checked = (arg === true || arg === 'true');
  if (!checked) {
    findingsState.selected = Object.create(null);
  } else {
    (findingsState._lastVisible || []).forEach(function (f) {
      if (f && f.id != null) findingsState.selected[String(f.id)] = true;
    });
  }
  applyFindingsView();
}

// "Select all matching filter" — same as toggling the header box when the
// visible slice is already what the filters would produce. Kept as a
// separate action so the bulk bar can offer an explicit one-click link.
export function selectAllMatchingFilter() {
  (findingsState._lastVisible || []).forEach(function (f) {
    if (f && f.id != null) findingsState.selected[String(f.id)] = true;
  });
  applyFindingsView();
}

export function clearFindingSelection() {
  findingsState.selected = Object.create(null);
  applyFindingsView();
}

function _selectedFindingIds() {
  return Object.keys(findingsState.selected).map(function (k) { return Number(k); });
}

// ---------------------------------------------------------------
// Bulk action bar — appears at the bottom of the Findings page when
// any rows are selected. Pattern matches the scans bulk-delete bar.
// ---------------------------------------------------------------

function _renderBulkBarHtml(visibleCount, totalCount, filtered) {
  var ids = _selectedFindingIds();
  var n = ids.length;
  var display = n > 0 ? 'flex' : 'none';
  // "Select all matching filter" only useful when filters narrow the
  // view and there's at least one un-selected visible row.
  var vis = findingsState._lastVisible || [];
  var selectable = vis.filter(function (f) { return f && f.id != null; });
  var allVisibleSelected = selectable.length > 0 && selectable.every(function (f) {
    return findingsState.selected[String(f.id)];
  });
  var showSelectAll = filtered && selectable.length > n && !allVisibleSelected;
  var selectAllLink = showSelectAll
    ? '<a class="bulk-bar-link" data-action="selectAllMatchingFilter">' +
        'Select all ' + selectable.length + ' matching filter' +
      '</a>'
    : '';

  return (
    '<div id="findings-bulk-bar" class="bulk-bar bulk-bar-sticky" style="display:' + display + ';">' +
      '<span class="bulk-bar-count">' + n + ' finding' + (n === 1 ? '' : 's') + ' selected</span>' +
      selectAllLink +
      '<span class="bulk-bar-spacer"></span>' +
      // Assign-to dropdown using the canonical .pulse-dropdown pattern
      // from pulse-design.md. Menu floats above the trigger because the
      // bulk bar itself is docked at the bottom of the viewport.
      '<div class="bulk-bar-assign">' +
        '<button type="button" class="btn btn-secondary btn-sm btn-with-icon" data-action="toggleBulkAssignMenu" ' +
          'aria-haspopup="menu" aria-expanded="false">' +
          '<i data-lucide="user-plus"></i><span>Assign to…</span></button>' +
        '<div id="bulk-bar-assign-menu" class="pulse-dropdown bulk-bar-assign-menu" hidden>' +
          '<div class="pulse-dropdown-section" id="bulk-bar-assign-list">' +
            '<div style="padding:4px 10px; color:var(--text-muted); font-size:12px;">' +
              'Loading users…' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<button class="btn btn-secondary btn-sm btn-with-icon" data-action="bulkAssignToMe"><i data-lucide="user-check"></i><span>Assign to me</span></button>' +
      '<button class="btn btn-secondary btn-sm btn-with-icon" data-action="bulkUnassign"><i data-lucide="user-x"></i><span>Unassign</span></button>' +
      '<span class="bulk-bar-divider" aria-hidden="true"></span>' +
      '<button class="btn btn-secondary btn-sm btn-with-icon" data-action="bulkMarkReviewed"><i data-lucide="check-circle-2"></i><span>Mark reviewed</span></button>' +
      '<a class="bulk-bar-clear" data-action="clearFindingSelection">Clear selection</a>' +
    '</div>'
  );
}

async function _mountBulkBarUsers() {
  // Populate the "Assign to..." dropdown once the users list is ready.
  // Viewers get a 403 on /api/users — fall back to "me" only so they
  // can still self-assign via the dropdown.
  var list = document.getElementById('bulk-bar-assign-list');
  if (!list) return;
  var users = await _ensureAssignableUsers();
  var me = await _ensureMe();
  if (users.length === 0 && me && me.id) {
    users = [{ id: me.id, email: me.email || 'me', display_name: me.display_name, active: true }];
  }
  if (!users.length) {
    list.innerHTML = '<div style="padding:6px 10px; color:var(--text-muted); font-size:12px;">' +
                      'No active users' +
                    '</div>';
    return;
  }
  list.innerHTML = users.map(function (u) {
    var display = (u.display_name || '').trim() ||
                  ((u.email || '').split('@')[0] || ('user #' + u.id));
    var isMe = (me && u.id === me.id);
    var primary = display + (isMe ? ' (me)' : '');
    var secondary = (u.display_name && u.email && u.email !== display) ? u.email : '';
    return '<a class="pulse-dropdown-item bulk-bar-assign-item" ' +
             'data-action="bulkAssignPick" data-arg="' + u.id + '|' + _escAttr(display) + '">' +
             '<span class="bulk-bar-assign-item-main">' +
               '<span class="bulk-bar-assign-item-name">' + escapeHtml(primary) + '</span>' +
               (secondary
                 ? '<span class="bulk-bar-assign-item-email">' + escapeHtml(secondary) + '</span>'
                 : '') +
             '</span>' +
           '</a>';
  }).join('');
}

function _escAttr(s) {
  return String(s || '').replace(/"/g, '&quot;').replace(/\|/g, '&#124;');
}

export function toggleBulkAssignMenu(arg, target) {
  var menu = document.getElementById('bulk-bar-assign-menu');
  if (!menu || !target) return;
  // Use the native `hidden` property — matches the .pulse-dropdown
  // contract (see pulse-design.md "Use the hidden attribute for open
  // / close — do not toggle inline display").
  var open = !menu.hidden;
  menu.hidden = open;
  target.setAttribute('aria-expanded', open ? 'false' : 'true');
}

// Close the bulk-bar assign menu on outside click / Esc.
document.addEventListener('click', function (e) {
  var wrap = document.querySelector('.bulk-bar-assign');
  if (!wrap) return;
  if (wrap.contains(e.target)) return;
  var menu = document.getElementById('bulk-bar-assign-menu');
  if (menu && !menu.hidden) {
    menu.hidden = true;
    var trigger = wrap.querySelector('[data-action="toggleBulkAssignMenu"]');
    if (trigger) trigger.setAttribute('aria-expanded', 'false');
  }
});
document.addEventListener('keydown', function (e) {
  if (e.key !== 'Escape') return;
  var menu = document.getElementById('bulk-bar-assign-menu');
  if (menu && !menu.hidden) {
    menu.hidden = true;
    var trigger = document.querySelector('.bulk-bar-assign [data-action="toggleBulkAssignMenu"]');
    if (trigger) trigger.setAttribute('aria-expanded', 'false');
  }
});

async function _runBulk(op, extras) {
  var ids = _selectedFindingIds();
  if (!ids.length) return;
  var r = await apiFindingsBatch(op, ids, extras && extras.assignee_user_id);
  if (!r || !r.ok) {
    toastError((r && r.data && r.data.detail) || 'Bulk action failed.');
    return null;
  }
  return r.data || { updated: 0, skipped: 0 };
}

export async function bulkAssignPick(arg) {
  // data-arg format: "<user_id>|<display name>"
  var parts = String(arg || '').split('|');
  var uid = Number(parts[0]);
  var display = parts.slice(1).join('|') || 'user';
  if (!uid) return;
  var result = await _runBulk('assign', { assignee_user_id: uid });
  if (!result) return;
  showToast('Assigned ' + result.updated + ' finding' +
            (result.updated === 1 ? '' : 's') + ' to ' + display);
  await _reconcileAfterBulk(ids => ({ assigned_to: uid }));
  _closeBulkAssignMenu();
}

export async function bulkAssignToMe() {
  var me = await _ensureMe();
  if (!me || !me.id) { toastError('Could not identify current user.'); return; }
  var display = (me.display_name || '').trim() ||
                ((me.email || '').split('@')[0]) || 'me';
  var result = await _runBulk('assign', { assignee_user_id: me.id });
  if (!result) return;
  showToast('Assigned ' + result.updated + ' finding' +
            (result.updated === 1 ? '' : 's') + ' to ' + display);
  await _reconcileAfterBulk(function () { return { assigned_to: me.id }; });
}

export async function bulkUnassign() {
  var result = await _runBulk('unassign');
  if (!result) return;
  showToast('Unassigned ' + result.updated + ' finding' +
            (result.updated === 1 ? '' : 's'));
  await _reconcileAfterBulk(function () { return { assigned_to: null }; });
}

export async function bulkMarkReviewed() {
  var result = await _runBulk('review');
  if (!result) return;
  showToast('Marked ' + result.updated + ' finding' +
            (result.updated === 1 ? '' : 's') + ' reviewed');
  await _reconcileAfterBulk(function () { return { reviewed: true }; });
}

// After a successful bulk op, refresh cached finding rows so the visible
// table shows the new state without a full refetch. Clears selection at
// the end (matches the scans bulk-delete flow).
async function _reconcileAfterBulk(deltaFn) {
  // Re-fetch /api/me for display_name so assignee cells render fresh.
  var me = null;
  try { me = await apiGetMe(); } catch (e) {}
  var cache = findingsState.raw || [];
  var sel = findingsState.selected;
  cache.forEach(function (f) {
    if (!f || f.id == null) return;
    if (!sel[String(f.id)]) return;
    var d = deltaFn ? deltaFn(f) : {};
    if ('assigned_to' in d) {
      f.assigned_to = d.assigned_to;
      if (d.assigned_to == null) {
        f.assignee_email = null;
        f.assignee_display_name = null;
      } else if (me && me.id === d.assigned_to) {
        f.assignee_email = me.email;
        f.assignee_display_name = me.display_name || null;
      } else {
        // Look up the user in our cached list if we have it.
        var u = (_assignableUsers || []).find(function (x) { return x.id === d.assigned_to; });
        f.assignee_email = u ? u.email : null;
        f.assignee_display_name = u ? u.display_name : null;
      }
    }
    if ('reviewed' in d) {
      f.reviewed = !!d.reviewed;
      if (d.reviewed) f.reviewed_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
    }
  });
  findingsState.selected = Object.create(null);
  applyFindingsView();
}

function _closeBulkAssignMenu() {
  var menu = document.getElementById('bulk-bar-assign-menu');
  if (menu) menu.hidden = true;
  var trigger = document.querySelector('.bulk-bar-assign [data-action="toggleBulkAssignMenu"]');
  if (trigger) trigger.setAttribute('aria-expanded', 'false');
}

function _updateBulkBar() {
  // Cheap in-place update: if the row count hasn't moved between zero
  // and non-zero, just refresh the counter. Otherwise full re-render so
  // the bar appears / disappears with the right layout.
  var ids = _selectedFindingIds();
  var bar = document.getElementById('findings-bulk-bar');
  if (!bar) { applyFindingsView(); return; }
  var visible = ids.length > 0;
  var wasVisible = bar.style.display !== 'none';
  if (visible !== wasVisible) { applyFindingsView(); return; }
  var counter = bar.querySelector('.bulk-bar-count');
  if (counter) {
    counter.textContent = ids.length + ' finding' + (ids.length === 1 ? '' : 's') + ' selected';
  }
  // Also refresh the header checkbox state in case the user picked the
  // last unchecked row.
  var head = document.querySelector('.data-table .col-select input[type="checkbox"]');
  var vis = findingsState._lastVisible || [];
  var selectable = vis.filter(function (f) { return f && f.id != null; });
  var allSel = selectable.length > 0 && selectable.every(function (f) {
    return findingsState.selected[String(f.id)];
  });
  if (head) head.checked = allSel;
}

function _sortArrow(col) {
  var s = findingsState;
  var active = (s.sortCol === col);
  if (!active) return '<span class="sort-arrow inactive">\u21C5</span>';
  return '<span class="sort-arrow">' + (s.sortDir === 'desc' ? '\u25BC' : '\u25B2') + '</span>';
}

// Client-side fallback for the short reference ID. Newly saved findings
// arrive with `ref_id` set by the backend; for legacy rows that predate
// the backfill we synthesize the same format here so the pill is never
// blank.
function _refIdFor(f) {
  if (f && f.ref_id) return f.ref_id;
  var rule = (f && f.rule) || '';
  var id = (f && f.id) != null ? f.id : null;
  var words = [];
  rule.split(/[^A-Za-z]+/).forEach(function (w) { if (w) words.push(w); });
  var prefix;
  if (words.length >= 3)       prefix = words[0][0] + words[1][0] + words[2][0];
  else if (words.length === 2) prefix = words[0][0] + (words[0][1] || 'X') + words[1][0];
  else if (words.length === 1) prefix = (words[0] + 'XX').slice(0, 3);
  else                         prefix = 'RUL';
  prefix = prefix.toUpperCase();
  if (id == null) return prefix + '-\u2014';
  var padded = ('0000' + id).slice(-4);
  return prefix + '-' + padded;
}

function _refIdPill(f) {
  return '<span class="ref-id-pill mono" title="Finding reference ID">' +
    escapeHtml(_refIdFor(f)) +
  '</span>';
}

// Eye / check / flag quick-actions in each row. Inline SVGs so re-renders
// don't need a Lucide rescan pass.
function _rowActionsHtml(f) {
  var hasId = f && f.id != null;
  var idAttr = hasId ? (' data-arg="' + escapeHtml(String(f.id)) + '"') : '';
  var uidAttr = ' data-arg="' + escapeHtml(f._uid || '') + '"';
  var reviewedCls = 'row-action' + (isReviewed(f) ? ' active review-check' : '');
  var fpCls       = 'row-action' + (isFalsePositive(f) ? ' active review-flag' : '');
  var reviewedPressed = isReviewed(f) ? ' aria-pressed="true"' : '';
  var fpPressed       = isFalsePositive(f) ? ' aria-pressed="true"' : '';

  var eyeSvg =
    '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8Z"/>' +
      '<circle cx="12" cy="12" r="3"/>' +
    '</svg>';
  var checkSvg =
    '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" ' +
    'stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      '<polyline points="20 6 9 17 4 12"/>' +
    '</svg>';
  var flagSvg =
    '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      '<path d="M4 22V4a1 1 0 0 1 1-1h11l-2 4 2 4H5"/>' +
      '<line x1="4" y1="15" x2="4" y2="22"/>' +
    '</svg>';

  var reviewedBtn = hasId
    ? '<button type="button" class="' + reviewedCls + '" title="Mark reviewed" aria-label="Mark reviewed"' + reviewedPressed + ' ' +
      'data-action="toggleReviewedFromRow"' + idAttr + '>' + checkSvg + '</button>'
    : '<button type="button" class="row-action" title="Save a scan to enable review" disabled>' + checkSvg + '</button>';
  var fpBtn = hasId
    ? '<button type="button" class="' + fpCls + '" title="Mark false positive" aria-label="Mark false positive"' + fpPressed + ' ' +
      'data-action="toggleFpFromRow"' + idAttr + '>' + flagSvg + '</button>'
    : '<button type="button" class="row-action" title="Save a scan to enable review" disabled>' + flagSvg + '</button>';

  return '<div class="row-actions" data-action="stopClickPropagation">' +
    '<button type="button" class="row-action" title="Open details" aria-label="Open details" ' +
      'data-action="openFindingsPageDrawerByUid"' + uidAttr + '>' + eyeSvg + '</button>' +
    reviewedBtn +
    fpBtn +
  '</div>';
}

function _buildFindingsTable(findings) {
  // Stash the filtered slice so "Select all matching filter" in the bulk
  // bar can target exactly what's visible after current filters.
  findingsState._lastVisible = findings;
  var expanded = findingsState.expanded;
  var th = function (col, label) {
    return '<th class="sortable" data-action="setFindingsSort" data-arg="' + col + '">' + label + _sortArrow(col) + '</th>';
  };

  // Header checkbox — checked only when every visible row is selected.
  var selectableFindings = findings.filter(function (f) { return f && f.id != null; });
  var allVisibleSelected = selectableFindings.length > 0 &&
    selectableFindings.every(function (f) {
      return findingsState.selected[String(f.id)];
    });
  var headCheckbox = '<th class="col-select" style="width:32px;">' +
    '<input type="checkbox"' + (allVisibleSelected ? ' checked' : '') +
    ' data-action="toggleFindingSelectAll" aria-label="Select all visible findings" />' +
  '</th>';

  // Severity now reads off the 4px coloured left border on each <tr>
  // (sev-row class), so we drop the dedicated severity column. Saves
  // a column and matches the Sentinel pattern: severity is at-a-glance
  // chrome, not data the user reads as a value.
  return '<table class="data-table">' +
    '<thead><tr>' +
      headCheckbox +
      th('time', 'Timestamp') +
      th('rule', 'Rule') +
      th('scan', 'Scan') +
      '<th>Assigned To</th>' +
      '<th>Status</th>' +
      '<th class="col-actions" aria-label="Quick actions"></th>' +
    '</tr></thead>' +
    '<tbody>' +
    findings.map(function (f) {
      var sev = (f.severity || 'LOW').toUpperCase();
      var rule = f.rule || 'Unknown';
      var mitre = f.mitre || mitreMap[rule] || '';
      var mitreTag = mitre
        ? '<span class="mitre-tag"><a href="https://attack.mitre.org/techniques/' +
          mitre.replace('.', '/') + '/" target="_blank" data-action="stopClickPropagation" data-default="allow">' + mitre + '</a></span>'
        : '-';
      var details = f.details || f.description || '';
      var shortDetails = details.length > 100 ? details.substring(0, 100) + '\u2026' : details;
      var time = f.timestamp || _extractTime(f) || '';
      var timeCell = time ? relTimeHtml(time) : '<span class="rel-time">—</span>';
      var isOpen = expanded === f._uid;

      var rowCls = 'clickable sev-row sev-' + sev.toLowerCase();
      if (isTouched(f)) rowCls += ' row-reviewed';
      var fidAttr = (f.id != null) ? ' data-finding-id="' + escapeHtml(String(f.id)) + '"' : '';

      var selectable = (f && f.id != null);
      var selected = selectable && !!findingsState.selected[String(f.id)];
      if (selected) rowCls += ' is-selected';
      var checkboxCell = selectable
        ? '<td class="col-select" data-action="stopClickPropagation">' +
            '<input type="checkbox"' + (selected ? ' checked' : '') +
              ' data-action="toggleFindingSelect" data-arg="' + f.id + '" ' +
              ' aria-label="Select finding ' + f.id + '" />' +
          '</td>'
        : '<td class="col-select"></td>';

      // data-filter-dim/value annotations let the right-click context
      // menu read the cell's filter axis without a second lookup.
      var assigneeKey = f.assigned_to == null ? 'unassigned' : String(f.assigned_to);
      var assigneeLabel = f.assigned_to == null
        ? 'Unassigned'
        : (f.assignee_display_name || f.assignee_email || ('user #' + f.assigned_to));
      // Row click opens the push flyout per the Sentinel spec — inline
      // expansion is gone (the flyout already shows everything).
      var main = '<tr class="' + rowCls + '"' + fidAttr + ' ' +
                 'data-action="openFindingsPageDrawerByUid" data-arg="' + f._uid + '" ' +
                 'data-filter-dim="severity" data-filter-value="' + sev + '" ' +
                 'data-filter-label="' + escapeHtml(sev) + '">' +
        checkboxCell +
        '<td class="col-time">' + timeCell + '</td>' +
        '<td class="col-rule" data-filter-dim="rule" data-filter-value="' + escapeHtml(rule) + '" ' +
          'data-filter-label="' + escapeHtml(rule) + '">' +
          '<div class="rule-cell">' +
            '<span class="rule-name">' + escapeHtml(rule) + '</span>' +
            _refIdPill(f) +
            _wfChipInline(f) +
            _notesBadgeInline(f) +
          '</div>' +
        '</td>' +
        '<td class="col-scan" data-filter-dim="scan" data-filter-value="' + f._scan_id + '" ' +
          'data-filter-label="Scan #' + (f._scan_number != null ? f._scan_number : f._scan_id) + '">' +
          '<a href="#" data-action="viewScanFromLink" data-arg="' + f._scan_id + '" ' +
          'style="color:var(--accent); text-decoration:none; font-size:12px;">#' + (f._scan_number != null ? f._scan_number : f._scan_id) + '</a>' +
          '<div style="font-size:10px; color:var(--text-muted);">' + escapeHtml((f._scan_date || '').split(' ')[0] || '') + '</div></td>' +
        '<td class="col-assigned" data-filter-dim="assignee" data-filter-value="' + escapeHtml(assigneeKey) + '" ' +
          'data-filter-label="' + escapeHtml(assigneeLabel) + '">' + _assigneeCellHtml(f) + '</td>' +
        '<td class="col-status" data-status-slot="pill">' + _statusPillHtml(f) + '</td>' +
        '<td class="col-actions">' + _rowActionsHtml(f) + '</td>' +
      '</tr>';

      if (!isOpen) return main;
      // 7 columns: checkbox + time + rule + scan + assigned + status + actions.
      // Severity moved to the row's left-border accent (sev-row class).
      return main + _expandRow(f, 7);
    }).join('') +
    '</tbody></table>';
}

// Quick-action handlers fired from the eye/check/flag buttons. They hit
// the same review endpoint the drawer uses, then re-render so the status
// dropdown counts stay in sync. `id` arrives as a string via data-arg.
export async function toggleReviewedFromRow(id, target, e) {
  if (e) e.stopPropagation();
  var f = _findFindingById(id);
  if (!f) return;
  await _applyRowReview(f, !isReviewed(f), isFalsePositive(f), target);
}

export async function toggleFpFromRow(id, target, e) {
  if (e) e.stopPropagation();
  var f = _findFindingById(id);
  if (!f) return;
  await _applyRowReview(f, isReviewed(f), !isFalsePositive(f), target);
}

function _findFindingById(id) {
  var numeric = Number(id);
  return (findingsState.raw || []).find(function (x) {
    return x && x.id != null && Number(x.id) === numeric;
  });
}

async function _applyRowReview(f, nextReviewed, nextFp, target) {
  if (target) target.disabled = true;
  var r = await apiSetFindingReview(f.id, {
    reviewed: nextReviewed,
    falsePositive: nextFp,
    note: f.review_note || '',
  });
  if (target) target.disabled = false;
  if (!r.ok) {
    toastError((r.data && r.data.detail) || 'Review update failed.');
    return;
  }
  f.reviewed       = !!r.data.reviewed;
  f.false_positive = !!r.data.false_positive;
  f.review_note    = r.data.review_note;
  f.reviewed_at    = r.data.reviewed_at;
  invalidateFindingsCache();
  _notifyFindingStatusChanged(f.id, {
    reviewed: f.reviewed,
    false_positive: f.false_positive,
  });
  applyFindingsView();
  showToast(
    f.reviewed && f.false_positive ? 'Marked reviewed and false positive' :
    f.reviewed                     ? 'Marked reviewed' :
    f.false_positive               ? 'Marked false positive' :
                                     'Review cleared'
  );
}

export function _expandRow(f, colspan) {
  var rule = f.rule || 'Unknown';
  var mitre = f.mitre || mitreMap[rule] || '';
  var desc = f.description || '';
  var details = f.details || '';
  var rawXml = f.raw_xml || '';
  var xmlBtn = rawXml
    ? '<button class="btn btn-secondary" style="margin-top:10px; font-size:12px;" ' +
      'data-action="openFindingsPageDrawerByUid" data-arg="' + escapeHtml(f._uid) + '">View raw event XML</button>'
    : '';

  return '<tr class="expand-row"><td colspan="' + colspan + '">' +
    '<div class="expand-grid">' +
      _expandField('Rule', escapeHtml(rule)) +
      _expandField('Severity', (f.severity || 'LOW').toUpperCase()) +
      _expandField('Timestamp', escapeHtml(f.timestamp || _extractTime(f) || '-'), 'mono') +
      _expandField('Event ID', escapeHtml(f.event_id || '-'), 'mono') +
      _expandField('MITRE ATT&amp;CK', mitre
        ? '<a href="https://attack.mitre.org/techniques/' + mitre.replace('.', '/') + '/" target="_blank" style="color:var(--accent); text-decoration:none;" class="mono">' + mitre + '</a>'
        : '-') +
      _expandField('Source Scan',
        '<a href="#" data-action="viewScan" data-arg="' + f._scan_id + '" style="color:var(--accent); text-decoration:none;">#' + (f._scan_number != null ? f._scan_number : f._scan_id) + '</a> \u2014 ' + escapeHtml(f._scan_date || '')) +
    '</div>' +
    (desc ? '<div class="expand-field" style="margin-bottom:10px;"><div class="label">Description</div><div class="val">' + escapeHtml(desc) + '</div></div>' : '') +
    (details ? '<div class="expand-field" style="margin-bottom:10px;"><div class="label">Event Details</div><div class="val mono" style="white-space:pre-wrap;">' + escapeHtml(details) + '</div></div>' : '') +
    _remediationBlock(f) +
    xmlBtn +
  '</td></tr>';
}

// Render the remediation card. Findings carry `remediation` (array of step
// strings) and `mitigations` (array of {id, name} dicts) attached server-side.
// Falls back to a generic default when `remediation` is missing (older
// cached responses, etc).
export function _remediationBlock(f) {
  var steps = Array.isArray(f.remediation) && f.remediation.length
    ? f.remediation
    : [
        'Investigate the event in its surrounding context.',
        'Correlate with other logs from the same host and timeframe.',
      ];
  var items = steps.map(function (s) { return '<li>' + escapeHtml(s) + '</li>'; }).join('');

  var chipsHtml = '';
  if (Array.isArray(f.mitigations) && f.mitigations.length) {
    var chips = f.mitigations.map(function (m) {
      return '<a class="mitre-chip" href="https://attack.mitre.org/mitigations/' +
        escapeHtml(m.id) + '/" target="_blank" rel="noopener noreferrer" title="' +
        escapeHtml(m.name) + '">' +
        '<span class="mitre-chip-id">' + escapeHtml(m.id) + '</span>' +
        '<span class="mitre-chip-name">' + escapeHtml(m.name) + '</span>' +
      '</a>';
    }).join('');
    chipsHtml = '<div class="mitre-chips">' + chips + '</div>';
  }

  return '<div class="remediation">' +
    '<div class="rem-label">Remediation</div>' +
    chipsHtml +
    '<ol class="rem-steps">' + items + '</ol>' +
  '</div>';
}

export function openFindingsPageDrawerByUid(uid) {
  var f = (findingsState.raw || []).find(function (x) { return x._uid === uid; });
  if (f) openFindingDrawer(f);
}

export function _expandField(label, htmlVal, extraCls) {
  return '<div class="expand-field">' +
    '<div class="label">' + label + '</div>' +
    '<div class="val ' + (extraCls || '') + '">' + htmlVal + '</div>' +
  '</div>';
}

// ---------------------------------------------------------------
// Finding drawer — shared slide-in detail panel
// ---------------------------------------------------------------
// Track the finding object currently shown in the drawer so the review
// buttons can mutate its review flags without needing the caller to
// thread the id through every handler invocation.
let _drawerFinding = null;

// `reviewed` and `false_positive` are independent booleans — a finding
// can be either, both, or neither. Every consumer reads these helpers
// rather than re-implementing the truthiness check inline.
export function isReviewed(f)       { return !!(f && f.reviewed); }
export function isFalsePositive(f)  { return !!(f && f.false_positive); }
export function isTouched(f)        { return isReviewed(f) || isFalsePositive(f); }

function _reviewBadge(f) {
  var parts = [];
  if (isReviewed(f))      parts.push('<span class="review-badge review-reviewed">Reviewed</span>');
  if (isFalsePositive(f)) parts.push('<span class="review-badge review-fp">False positive</span>');
  return parts.join('');
}

// Small colored dot (compact lists) / pill (full tables) rendered for any
// finding row so the UI can show review state at a glance. Both flags
// can show simultaneously since they're independent.
export function _statusDotHtml(f) {
  var out = '';
  if (isReviewed(f)) {
    out += '<span class="finding-status-dot status-reviewed" title="Reviewed" aria-label="Reviewed"></span>';
  }
  if (isFalsePositive(f)) {
    out += '<span class="finding-status-dot status-fp" title="False positive" aria-label="False positive"></span>';
  }
  if (!out) {
    out = '<span class="finding-status-dot status-unreviewed" title="Unreviewed" aria-label="Unreviewed"></span>';
  }
  return out;
}

export function _statusPillHtml(f) {
  // The cell always reserves enough room for both pills side-by-side via
  // an invisible placeholder sized to the widest state. Any visible pills
  // sit absolutely on top. This keeps the column width identical whether
  // a finding is untouched, only reviewed, only FP, or both — toggling
  // a flag from the drawer no longer nudges neighbouring columns.
  var pills = '';
  if (isReviewed(f))      pills += '<span class="status-pill status-reviewed">Reviewed</span>';
  if (isFalsePositive(f)) pills += (pills ? ' ' : '') + '<span class="status-pill status-fp">False positive</span>';
  if (!pills) {
    pills = '<span class="finding-status-dot status-unreviewed" title="Unreviewed" aria-label="Unreviewed"></span>';
  }
  return '<span class="status-pill-slot">' +
           '<span class="status-pill-placeholder" aria-hidden="true">' +
             '<span class="status-pill status-reviewed">Reviewed</span> ' +
             '<span class="status-pill status-fp">False positive</span>' +
           '</span>' +
           '<span class="status-pill-live">' + pills + '</span>' +
         '</span>';
}

// Re-render status widgets + muted row state for every DOM element carrying
// `data-finding-id === id`. Called when the drawer toggles a flag so the
// tables behind it update in place without a full re-render.
function _notifyFindingStatusChanged(id, flags) {
  if (id == null) return;
  var touched = !!(flags.reviewed || flags.false_positive);
  var rows = document.querySelectorAll('[data-finding-id="' + id + '"]');
  rows.forEach(function (row) {
    if (touched) row.classList.add('row-reviewed');
    else         row.classList.remove('row-reviewed');
    row.querySelectorAll('[data-status-slot]').forEach(function (slot) {
      var variant = slot.getAttribute('data-status-slot');
      slot.innerHTML = variant === 'pill' ? _statusPillHtml(flags) : _statusDotHtml(flags);
    });
  });
  // Broadcast so listeners that show their own derived view (e.g. the
  // Dashboard "Needs Attention" widget, which removes touched items
  // entirely rather than just muting them) can re-render.
  try {
    document.dispatchEvent(new CustomEvent('pulse:review-toggled', {
      detail: {
        id: id,
        reviewed: !!flags.reviewed,
        false_positive: !!flags.false_positive,
      },
    }));
  } catch (e) { /* no-op — old browsers without CustomEvent */ }
}

// Rules whose findings carry a source IP worth blocking at the firewall.
// Anything outside this set doesn't get a "Stage Block" button — a
// privilege escalation finding inside your own forest rarely has an
// attackable remote IP, for example.
const _BLOCKABLE_RULES = {
  'Brute Force Attempt': true,
  'RDP Logon Detected': true,
  'Pass-the-Hash Attempt': true,
};

// Classify an IPv4 so the UI can decide whether to offer a block button
// or show an explanatory note. Returns one of: 'public', 'loopback',
// 'private', 'link-local', 'multicast', 'unspecified', 'reserved', or null
// for a malformed string. Mirrors the backend validation in blocker.py.
function _classifyIpv4(ip) {
  if (!ip) return null;
  var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  var a = +m[1], b = +m[2], c = +m[3], d = +m[4];
  if (a > 255 || b > 255 || c > 255 || d > 255) return null;
  if (a === 0) return 'unspecified';
  if (a === 127) return 'loopback';
  if (a === 10) return 'private';
  if (a === 192 && b === 168) return 'private';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 169 && b === 254) return 'link-local';
  if (a >= 224 && a <= 239) return 'multicast';
  if (a >= 240) return 'reserved';
  return 'public';
}

// Pull the first IPv4 out of a blob of text. Unlike the old helper we do
// NOT filter by class here — the caller classifies and decides whether to
// offer a block, a warning, or nothing.
function _extractSourceIp(text) {
  if (!text) return null;
  var rx = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
  var m;
  while ((m = rx.exec(text)) !== null) {
    if (_classifyIpv4(m[0])) return m[0];
  }
  return null;
}

// ---------------------------------------------------------------------
// Threat-intel section (AbuseIPDB) — rendered into the finding drawer
// just before the "Block Source IP" block so the analyst sees reputation
// data before deciding to block.
//
// Returns '' (skipped section) for any finding whose details + description
// don't yield a public IPv4 address. Private / reserved IPs intentionally
// never get sent off-host; the backend rejects them too.
// ---------------------------------------------------------------------

function _renderIntelSection(f) {
  if (!f) return '';
  var ip = _extractSourceIp(f.details || '') || _extractSourceIp(f.description || '');
  if (!ip || _classifyIpv4(ip) !== 'public') return '';
  return '<div class="finding-drawer-section" id="drawer-intel-wrap" data-intel-ip="' + escapeHtml(ip) + '">' +
    '<div class="sec-label">Threat Intelligence</div>' +
    '<div id="drawer-intel-body" class="intel-loading" style="font-size:12px; color:var(--text-muted);">' +
      'Looking up ' + escapeHtml(ip) + ' on AbuseIPDB…' +
    '</div>' +
  '</div>';
}

function _intelScoreClass(score) {
  // Buckets follow AbuseIPDB convention: 75+ is "high confidence abuse",
  // 25–74 is "some reports", below that is "clean / unknown". The buckets
  // also drive the badge color so the drawer reads at a glance.
  if (score == null) return 'intel-score-na';
  if (score >= 75)  return 'intel-score-high';
  if (score >= 25)  return 'intel-score-med';
  return 'intel-score-low';
}

function _intelScoreLabel(score) {
  if (score == null) return 'No data';
  if (score >= 75) return 'Malicious';
  if (score >= 25) return 'Suspicious';
  return 'Clean';
}

async function _loadDrawerIntel(f) {
  var wrap = document.getElementById('drawer-intel-wrap');
  if (!wrap) return;
  var body = document.getElementById('drawer-intel-body');
  var ip = wrap.getAttribute('data-intel-ip');
  if (!ip || !body) return;

  var resp = await apiFetchIntel(ip);
  // Drawer may have been closed/replaced during the fetch — bail if the
  // section we were going to write into is gone.
  if (!document.body.contains(body)) return;

  if (resp.status === 400) {
    // No API key configured. Tell the user how to enable it instead of
    // hiding the section silently — the value is in discoverability.
    body.classList.remove('intel-loading');
    body.innerHTML =
      '<div class="intel-empty">' +
        'Threat-intel lookups are off. Add an AbuseIPDB API key under ' +
        '<a href="#" data-action="navigate" data-arg="settings" ' +
        'style="color:var(--accent); text-decoration:none;">Settings &rsaquo; Notifications</a> ' +
        'to enrich source IPs.' +
      '</div>';
    return;
  }
  if (!resp.ok || !resp.data) {
    body.classList.remove('intel-loading');
    body.innerHTML = '<div class="intel-error">Could not reach AbuseIPDB. Try again later.</div>';
    return;
  }

  var d = resp.data;
  var score   = d.score;
  var sclass  = _intelScoreClass(score);
  var slabel  = _intelScoreLabel(score);
  var country = d.country ? escapeHtml(d.country) : '—';
  var isp     = d.isp     ? escapeHtml(d.isp)     : '—';
  var reports = d.total_reports != null ? d.total_reports.toLocaleString() : '—';
  var lastReported = d.last_reported
    ? escapeHtml(String(d.last_reported).replace('T', ' ').slice(0, 19))
    : 'Never reported';
  var cached = d.cached
    ? '<span class="intel-cache-flag" title="Served from local cache">cached</span>'
    : '';

  body.classList.remove('intel-loading');
  body.innerHTML =
    '<div class="intel-header">' +
      '<div class="intel-score-block ' + sclass + '">' +
        '<div class="intel-score">' + (score == null ? '—' : score) + '</div>' +
        '<div class="intel-score-label">' + escapeHtml(slabel) + '</div>' +
      '</div>' +
      '<div class="intel-meta">' +
        '<div class="intel-meta-row"><span class="k">IP</span><span class="v intel-mono">' + escapeHtml(ip) + '</span>' + cached + '</div>' +
        '<div class="intel-meta-row"><span class="k">Country</span><span class="v">' + country + '</span></div>' +
        '<div class="intel-meta-row"><span class="k">ISP</span><span class="v">' + isp + '</span></div>' +
        '<div class="intel-meta-row"><span class="k">Reports (90d)</span><span class="v">' + reports + '</span></div>' +
        '<div class="intel-meta-row"><span class="k">Last reported</span><span class="v">' + lastReported + '</span></div>' +
      '</div>' +
    '</div>' +
    '<div class="intel-footer">' +
      'Source: <a href="https://www.abuseipdb.com/check/' + encodeURIComponent(ip) + '" ' +
        'target="_blank" rel="noopener" data-default="allow" ' +
        'style="color:var(--accent); text-decoration:none;">AbuseIPDB report &rsaquo;</a>' +
    '</div>';
}

function _stageBlockSection(f) {
  if (!f || !_BLOCKABLE_RULES[f.rule]) return '';
  var ip = _extractSourceIp(f.details || '') || _extractSourceIp(f.description || '');
  if (!ip) return '';
  var cls = _classifyIpv4(ip);
  var date = (f.timestamp || _extractTime(f) || '').split(' ')[0] || 'today';
  var comment = (f.rule || '') + ' on ' + date + ' (finding #' + (f.id || '?') + ')';
  var ipEsc = escapeHtml(ip);
  var fidEsc = escapeHtml(String(f.id == null ? '' : f.id));
  var cEsc = escapeHtml(comment);
  var shared =
    'data-arg="' + ipEsc + '" ' +
    'data-finding-id="' + fidEsc + '" ' +
    'data-comment="' + cEsc + '"';

  // Non-public IPs are safety-rejected by the backend. Render the same
  // section so the operator sees the extracted IP, but with disabled
  // buttons and a concrete explanation of why Pulse won't block it.
  // RFC1918 ("private") is a *soft* refusal: insider-threat scenarios can
  // justify blocking an internal host, so we surface an amber override
  // link that opens a type-to-confirm modal. Everything else (loopback,
  // link-local, multicast, reserved, unspecified) is a hard refusal.
  if (cls !== 'public') {
    var reason = {
      'loopback':    'loopback address (127.0.0.0/8) — blocking would cut off local services',
      'private':     'private LAN address (RFC1918) — blocking would cut off internal hosts',
      'link-local':  'link-local address (169.254.0.0/16) — used for auto-configuration',
      'multicast':   'multicast address — not an individual attacker',
      'reserved':    'reserved address range — not routable',
      'unspecified': 'unspecified address (0.0.0.0)',
    }[cls] || 'non-routable address';
    var overrideHtml = '';
    var altHtml = '';
    if (cls === 'private') {
      overrideHtml =
        '<a class="stage-block-override" ' +
          'data-action="openForceBlockModal" ' + shared + '>' +
          'Override and block this internal IP' +
        '</a>';
      altHtml =
        '<div class="stage-block-alt">' +
          'For stronger isolation consider: disabling the AD account, ' +
          'switch port shutdown by your network admin, or Microsoft Defender ' +
          'device isolation.' +
        '</div>';
    }
    return '<div class="finding-drawer-section">' +
      '<div class="sec-label">Block Source IP</div>' +
      '<div class="stage-block-row stage-block-row-muted">' +
        '<div class="stage-block-meta">' +
          '<div class="stage-block-ip">' + ipEsc + '</div>' +
          '<div class="stage-block-hint">' +
            '<strong>Not blockable:</strong> ' + escapeHtml(reason) + '. ' +
            'Pulse refuses these to prevent self-lockouts.' +
          '</div>' +
          overrideHtml +
        '</div>' +
        '<div class="stage-block-actions">' +
          '<button type="button" class="btn btn-secondary stage-block-btn staged" disabled>Not blockable</button>' +
        '</div>' +
      '</div>' +
      altHtml +
    '</div>';
  }

  return '<div class="finding-drawer-section">' +
    '<div class="sec-label">Block Source IP</div>' +
    '<div class="stage-block-row">' +
      '<div class="stage-block-meta">' +
        '<div class="stage-block-ip" data-block-ip="' + ipEsc + '">' + ipEsc + '</div>' +
        '<div class="stage-block-hint">Adds an inbound deny rule tagged <code>Pulse-managed</code>. ' +
          '<strong>Block Now</strong> requires admin; <strong>Stage</strong> queues it for later push.</div>' +
      '</div>' +
      '<div class="stage-block-actions">' +
        '<button type="button" class="btn btn-secondary stage-block-btn" ' +
          'data-action="stageBlockFromFinding" ' + shared + '>Stage</button>' +
        '<button type="button" class="btn btn-primary stage-block-btn" ' +
          'data-action="blockNowFromFinding" ' + shared + '>Block Now</button>' +
      '</div>' +
    '</div>' +
  '</div>';
}

function _blockButtonGroup(target) {
  // Find the sibling button so a click on one disables both.
  var row = target.closest('.stage-block-row');
  if (!row) return [target];
  return Array.prototype.slice.call(row.querySelectorAll('.stage-block-btn'));
}

async function _submitBlock(ip, target, confirm, force) {
  if (!ip || !target) return;
  if (target.disabled) return;
  var comment = target.getAttribute('data-comment') || '';
  var fidRaw  = target.getAttribute('data-finding-id') || '';
  var findingId = fidRaw === '' ? null : Number(fidRaw);
  var group = _blockButtonGroup(target);
  group.forEach(function (b) { b.disabled = true; });
  var originalText = target.textContent;
  target.textContent = confirm ? 'Blocking…' : 'Staging…';
  try {
    var resp = await fetch('/api/block-ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ip: ip,
        comment: comment,
        finding_id: findingId,
        confirm: !!confirm,
        force: !!force,
      }),
    });
    var data = {};
    try { data = await resp.json(); } catch (e) {}
    if (!resp.ok) {
      var msg = (data && data.message) || (data && data.detail) || 'Could not stage block';
      toastError(msg);
      group.forEach(function (b) { b.disabled = false; });
      target.textContent = originalText;
      return false;
    }
    var wasForced = !!(data && data.forced);
    var forcedSuffix = wasForced ? ' (forced override \u2014 internal IP)' : '';
    var stagedCls = wasForced ? 'staged staged-forced' : 'staged';
    // Stage succeeded. If this was Block Now, inspect the push result.
    var push = data && data.push;
    if (confirm && push && push.ok === false) {
      // Staged but push failed — surface the real reason (admin, etc.).
      toastError('Staged ' + ip + ', but push failed: ' + (push.message || 'see CLI'));
      group.forEach(function (b) {
        b.disabled = true;
        b.className = b.className.replace(/\bstaged(-forced)?\b/g, '').trim();
        stagedCls.split(' ').forEach(function (c) { b.classList.add(c); });
      });
      target.textContent = 'Staged \u2014 push failed';
      return true;
    }
    if (confirm && push && push.ok) {
      showToast('Blocked ' + ip + forcedSuffix);
      group.forEach(function (b) {
        b.disabled = true;
        stagedCls.split(' ').forEach(function (c) { b.classList.add(c); });
      });
      target.textContent = wasForced ? 'Blocked (forced)' : 'Blocked';
      return true;
    }
    // Stage-only path (or Block Now where push was skipped for some reason).
    showToast('Staged ' + ip + ' for blocking' + forcedSuffix);
    group.forEach(function (b) {
      b.disabled = true;
      stagedCls.split(' ').forEach(function (c) { b.classList.add(c); });
    });
    target.textContent = wasForced ? 'Staged (forced)' : 'Staged \u2014 pending push';
    return true;
  } catch (e) {
    toastError('Network error while blocking');
    group.forEach(function (b) { b.disabled = false; });
    target.textContent = originalText;
    return false;
  }
}

export function stageBlockFromFinding(ip, target) {
  return _submitBlock(ip, target, false, false);
}

export function blockNowFromFinding(ip, target) {
  return _submitBlock(ip, target, true, false);
}

// -----------------------------------------------------------------------
// Force-block modal (type-to-confirm override for RFC1918 addresses)
// -----------------------------------------------------------------------
// The modal element lives in the base template. We remember the originating
// button so we can mutate it on success (disabled + "Staged (forced)" amber
// state, same contract as the normal stage path).
var _forceBlockSource = null;

export function openForceBlockModal(ip, target) {
  if (!ip) return;
  var modal = document.getElementById('force-block-modal');
  if (!modal) return;
  _forceBlockSource = {
    ip: ip,
    comment: target ? (target.getAttribute('data-comment') || '') : '',
    findingId: target ? (target.getAttribute('data-finding-id') || '') : '',
  };
  var ipLabel = document.getElementById('force-block-ip-label');
  if (ipLabel) ipLabel.textContent = ip;
  var input = document.getElementById('force-block-input');
  if (input) {
    input.value = '';
    input.setAttribute('placeholder', ip);
  }
  var btn = document.getElementById('force-block-confirm-btn');
  if (btn) btn.disabled = true;
  modal.classList.add('open');
  if (input) setTimeout(function () { input.focus(); }, 30);
}

export function closeForceBlockModal() {
  var modal = document.getElementById('force-block-modal');
  if (modal) modal.classList.remove('open');
  _forceBlockSource = null;
}

// Input handler — enables the "Block anyway" button only when the typed
// value matches the IP exactly.
export function forceBlockInputCheck(arg, target) {
  var btn = document.getElementById('force-block-confirm-btn');
  if (!btn || !_forceBlockSource) return;
  btn.disabled = (target && target.value.trim() === _forceBlockSource.ip) ? false : true;
}

export async function confirmForceBlock() {
  if (!_forceBlockSource) return;
  var btn = document.getElementById('force-block-confirm-btn');
  if (!btn || btn.disabled) return;
  var src = _forceBlockSource;
  // Locate the originating "Not blockable" button in the drawer so we can
  // flip it to "Staged (forced)" on success. The muted button has no
  // data-action of its own, so we match by the surrounding row's IP label.
  var targetBtn = null;
  var rows = document.querySelectorAll('.stage-block-row-muted');
  rows.forEach(function (row) {
    var ipEl = row.querySelector('.stage-block-ip');
    if (ipEl && ipEl.textContent.trim() === src.ip) {
      targetBtn = row.querySelector('.stage-block-btn');
    }
  });
  if (!targetBtn) {
    // Fall back to a synthetic target so _submitBlock still runs; we just
    // can't visually update the button state.
    targetBtn = document.createElement('button');
  }
  targetBtn.setAttribute('data-comment', src.comment);
  targetBtn.setAttribute('data-finding-id', src.findingId);
  targetBtn.disabled = false;
  btn.disabled = true;
  btn.textContent = 'Blocking\u2026';
  // confirm=true: stage + push in one click. If the process isn't elevated
  // the backend still stages, then surfaces the push failure via toast —
  // the user doesn't have to know what the CLI is.
  var ok = await _submitBlock(src.ip, targetBtn, true, true);
  if (ok) {
    closeForceBlockModal();
  } else {
    btn.textContent = 'Block anyway';
  }
}

// Beacon flag — only fire the first-finding-viewed POST once per page
// load. The endpoint itself is idempotent (the DB column uses COALESCE)
// but skipping the redundant network call keeps the dev tools quiet.
let _firstFindingViewBeaconed = false;

export function openFindingDrawer(f) {
  if (!f) return;
  _drawerFinding = f;
  if (!_firstFindingViewBeaconed) {
    _firstFindingViewBeaconed = true;
    apiMarkFirstFindingViewed();
  }
  var sev  = (f.severity || 'LOW').toUpperCase();
  var rule = f.rule || 'Unknown';
  var mitre = f.mitre || mitreMap[rule] || '';
  var mitreLink = mitre
    ? '<a class="mitre-tag" href="https://attack.mitre.org/techniques/' +
      encodeURIComponent(mitre.replace('.', '/')) + '" target="_blank" rel="noopener">' +
      escapeHtml(mitre) + '</a>'
    : '<span style="color:var(--text-muted); font-size:12px;">\u2014</span>';

  var ruleEl = document.getElementById('drawer-rule');
  ruleEl.innerHTML = escapeHtml(rule) + _refIdPill(f);
  document.getElementById('drawer-sev-line').innerHTML =
    '<span class="sev-pill sev-' + sev.toLowerCase() + '">' + sev + '</span>' +
    mitreLink +
    _reviewBadge(f);

  var time = f.timestamp || _extractTime(f) || '\u2014';
  var eid  = (f.event_id != null && f.event_id !== '') ? f.event_id : '\u2014';
  var desc = f.description || '';
  var details = f.details || '';
  var rawXml = f.raw_xml || '';

  document.getElementById('drawer-body').innerHTML =
    '<div class="finding-drawer-section">' +
      '<div class="sec-label">Metadata</div>' +
      '<div class="finding-drawer-grid">' +
        '<div><div class="k">Timestamp</div><div class="v">' + escapeHtml(String(time)) + '</div></div>' +
        '<div><div class="k">Event ID</div><div class="v">' + escapeHtml(String(eid)) + '</div></div>' +
      '</div>' +
    '</div>' +

    (desc ? '<div class="finding-drawer-section">' +
      '<div class="sec-label">Description</div>' +
      '<div style="font-size:13px; color:var(--text); line-height:1.5;">' + escapeHtml(desc) + '</div>' +
    '</div>' : '') +

    (details ? '<div class="finding-drawer-section">' +
      '<div class="sec-label">Event Details</div>' +
      '<div class="finding-drawer-details">' + escapeHtml(details) + '</div>' +
    '</div>' : '') +

    // Threat Intel slots between Event Details and Remediation so the
    // analyst sees IP reputation while triaging — before deciding what
    // to do about it. Section returns '' when no public IP is present.
    _renderIntelSection(f) +

    (rawXml ? '<div class="finding-drawer-section">' +
      '<details class="raw-xml-toggle">' +
        '<summary class="sec-label" style="cursor:pointer;">Raw Event XML</summary>' +
        '<div class="finding-drawer-details" style="max-height:320px; margin-top:8px;">' + escapeHtml(rawXml) + '</div>' +
      '</details>' +
    '</div>' : '') +

    '<div class="finding-drawer-section">' +
      '<div class="sec-label">Remediation</div>' +
      _remediationBlock(f) +
    '</div>' +

    _stageBlockSection(f) +

    _renderWorkflowSection(f) +

    _renderAssignSection(f) +

    _renderNotesSection(f) +

    _renderReviewSection(f);

  // (Previously called _updateReviewButtonStates here — that helper was
  // removed when the review buttons stopped persisting an .active state.
  // The buttons render in their default visual state on every drawer
  // open; the brief 3s confirmation flash is fired by _flashReviewConfirm
  // from inside _submitReview, not on drawer mount.)

  document.getElementById('finding-drawer').classList.add('open');
  // Push layout: the table stays interactive (clicking another row
  // updates the drawer in place), so we don't dim the page or lock
  // scroll. body.flyout-push-open is the CSS hook that compresses
  // the findings-page so the drawer no longer overlays the table.
  document.body.classList.add('flyout-push-open');

  // Fire the notes + assignee fetches after the drawer mounts so the
  // open animation isn't blocked on DB / user-list round-trips.
  if (f && f.id != null) {
    _loadDrawerNotes(f.id).catch(function () {
      var list = document.getElementById('drawer-notes-list');
      if (list) list.innerHTML = '<p class="notes-empty">Could not load notes.</p>';
    });
    _loadDrawerAssign(f).catch(function () {
      var wrap = document.getElementById('drawer-assign-wrap');
      if (wrap) wrap.innerHTML = '<p style="color:var(--text-muted); font-size:12px; margin:0;">Could not load users.</p>';
    });
  }
  // Threat-intel lookup. Section only renders when a public source IP
  // was extracted, so this no-ops on findings without one.
  _loadDrawerIntel(f);

}

// Workflow states — the incident-response axis. Orthogonal to review
// flags: "how far along is the response?" not "is this real?".
const _WF_STATES = [
  { id: 'new',           label: 'New' },
  { id: 'acknowledged',  label: 'Acknowledged' },
  { id: 'investigating', label: 'Investigating' },
  { id: 'resolved',      label: 'Resolved' },
];

export function _workflowChipHtml(state) {
  var s = (state || 'new').toLowerCase();
  if (!_WF_STATES.some(function (w) { return w.id === s; })) s = 'new';
  var label = _WF_STATES.find(function (w) { return w.id === s; }).label;
  return '<span class="wf-chip wf-chip-' + s + '">' + escapeHtml(label) + '</span>';
}

// Prefer the admin-set display_name, fall back to the email local-part
// so an unnamed user still gets a readable handle.
function _displayFromAssignee(f) {
  if (!f) return '';
  var dn = (f.assignee_display_name || '').trim();
  if (dn) return dn;
  var email = f.assignee_email || '';
  if (!email) return '';
  return email.split('@')[0] || email;
}

// Assignee cell for list rows. Renders the display name as a chip, with
// the email as the hover title for disambiguation.
function _assigneeCellHtml(f) {
  var display = _displayFromAssignee(f);
  if (!display) {
    return '<span class="assignee-empty">Unassigned</span>';
  }
  var email = (f && f.assignee_email) || '';
  return '<span class="assignee-chip" title="' + escapeHtml(email || display) + '">' +
    escapeHtml(display) + '</span>';
}

// Inline chip for list rows. Hidden when the state is still 'new' so
// untouched findings stay visually quiet; only actively-triaged items
// get the ack/investigating/resolved badge next to the rule name.
function _wfChipInline(f) {
  var s = (f && f.workflow_status || 'new').toLowerCase();
  if (s === 'new') return '';
  return ' ' + _workflowChipHtml(s);
}

// Notes-count badge for list rows. Hidden when the count is 0 so rows
// without analyst activity stay clean.
function _notesBadgeInline(f) {
  var n = Number(f && f.note_count || 0);
  if (!n) return '';
  var bubbleSvg =
    '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" ' +
      'stroke="currentColor" stroke-width="2" stroke-linecap="round" ' +
      'stroke-linejoin="round" aria-hidden="true">' +
      '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>' +
    '</svg>';
  return ' <span class="notes-chip" title="' + n + ' note' + (n === 1 ? '' : 's') + '" ' +
         'aria-label="' + n + ' note' + (n === 1 ? '' : 's') + '">' +
    bubbleSvg + '<span class="notes-chip-count">' + n + '</span>' +
  '</span>';
}

// ---------------------------------------------------------------
// Assignment — who is actively working a finding
// ---------------------------------------------------------------

// Cached once per page load; the drawer reuses this to populate the
// assignee dropdown without a refetch per open.
let _assignableUsers = null;
let _meCache = null;

async function _ensureAssignableUsers() {
  if (_assignableUsers !== null) return _assignableUsers;
  try {
    var lu = await apiListUsers();
    _assignableUsers = (lu && lu.users || []).filter(function (u) { return u && u.active; });
  } catch (e) {
    // Viewers get a 403 from /api/users — fall back to just "me" so they
    // can still self-assign. Admins see the full list.
    _assignableUsers = [];
  }
  return _assignableUsers;
}

async function _ensureMe() {
  if (_meCache !== null) return _meCache;
  try { _meCache = await apiGetMe(); } catch (e) { _meCache = {}; }
  return _meCache;
}

function _renderAssignSection(f) {
  var hasId = f && f.id != null;
  if (!hasId) {
    return '<div class="finding-drawer-section">' +
      '<div class="sec-label">Assigned to</div>' +
      '<p style="color:var(--text-muted); font-size:12px; margin:0;">' +
        'Save this scan to enable assignment.' +
      '</p>' +
    '</div>';
  }
  return '<div class="finding-drawer-section">' +
    '<div class="sec-label">Assigned to</div>' +
    '<div id="drawer-assign-wrap">' +
      '<div style="font-size:12px; color:var(--text-muted);">Loading users…</div>' +
    '</div>' +
  '</div>';
}

async function _loadDrawerAssign(f) {
  var mount = document.getElementById('drawer-assign-wrap');
  if (!mount || !f) return;
  var users = await _ensureAssignableUsers();
  var me = await _ensureMe();
  // If /api/users 403s (viewer), the list is empty — inject `me` so they
  // can at least self-assign.
  if (users.length === 0 && me && me.id) {
    users = [{ id: me.id, email: me.email || 'me', active: true }];
  }
  var current = f.assigned_to != null ? String(f.assigned_to) : '';
  var assignedAt = f.assigned_at ? '<div class="assign-meta">Assigned <strong>' +
    relTimeHtml(f.assigned_at) + '</strong></div>' : '';
  var meBtn = (me && me.id && current !== String(me.id))
    ? '<button type="button" class="btn-link-sm btn-with-icon" data-action="assignFindingToMe"><i data-lucide="user-check"></i><span>Assign to me</span></button>'
    : '';

  // Options are display_name primary, email secondary (muted) so a team
  // with real names reads clean. A <select> can't render rich HTML inside
  // <option>, so the custom list below is what the user actually sees; the
  // native <select> stays screen-reader friendly and holds the source of
  // truth for the selection.
  var options = ['<option value="">— Unassigned —</option>'];
  var listItems = [
    '<li class="assign-item' + (current === '' ? ' is-selected' : '') + '" ' +
      'data-action="pickFindingAssignee" data-arg="">' +
      '<span class="assign-item-name">— Unassigned —</span>' +
    '</li>',
  ];
  users.forEach(function (u) {
    var sel = (String(u.id) === current) ? ' selected' : '';
    var display = (u.display_name || '').trim() ||
                  ((u.email || '').split('@')[0] || ('user #' + u.id));
    var isMe = (me && u.id === me.id);
    var primary = display + (isMe ? ' (me)' : '');
    var secondary = (u.display_name && u.email && u.email !== display) ? u.email : '';
    options.push('<option value="' + escapeHtml(String(u.id)) + '"' + sel + '>' +
                 escapeHtml(primary + (secondary ? ' — ' + secondary : '')) +
                 '</option>');
    listItems.push(
      '<li class="assign-item' + (String(u.id) === current ? ' is-selected' : '') + '" ' +
        'data-action="pickFindingAssignee" data-arg="' + escapeHtml(String(u.id)) + '">' +
        '<span class="assign-item-name">' + escapeHtml(primary) + '</span>' +
        roleBadgeHtml(u.role) +
        (secondary
          ? '<span class="assign-item-email">' + escapeHtml(secondary) + '</span>'
          : '') +
      '</li>'
    );
  });
  mount.innerHTML =
    '<div class="assign-row">' +
      '<div class="assign-picker">' +
        '<button type="button" class="assign-trigger" data-action="toggleAssignPicker" ' +
          'aria-haspopup="listbox" aria-expanded="false">' +
          '<span class="assign-trigger-label">' +
            escapeHtml(
              _drawerFinding && _displayFromAssignee(_drawerFinding) ||
              '— Unassigned —'
            ) +
          '</span>' +
          '<span class="assign-trigger-caret" aria-hidden="true">▾</span>' +
        '</button>' +
        '<ul class="assign-menu" role="listbox" hidden>' + listItems.join('') + '</ul>' +
        // Hidden native select keeps the value + fires change for screen readers.
        '<select id="drawer-assign-select" class="sr-only" ' +
          'data-action-change="setFindingAssignee">' +
          options.join('') +
        '</select>' +
      '</div>' +
      meBtn +
    '</div>' +
    assignedAt;
}

// Toggle the custom assign picker popover.
export function toggleAssignPicker(arg, target) {
  var menu = target ? target.parentElement.querySelector('.assign-menu') : null;
  if (!menu) return;
  var open = !menu.hasAttribute('hidden');
  if (open) {
    menu.setAttribute('hidden', '');
    target.setAttribute('aria-expanded', 'false');
  } else {
    menu.removeAttribute('hidden');
    target.setAttribute('aria-expanded', 'true');
  }
}

// Clicking an item in the custom menu commits the selection.
export async function pickFindingAssignee(userId) {
  var select = document.getElementById('drawer-assign-select');
  if (!select) return;
  select.value = userId || '';
  // Close the popover before the request fires so the UI feels snappy.
  var menu = document.querySelector('.assign-picker .assign-menu');
  var trigger = document.querySelector('.assign-picker .assign-trigger');
  if (menu) menu.setAttribute('hidden', '');
  if (trigger) trigger.setAttribute('aria-expanded', 'false');
  return setFindingAssignee();
}

// Close the assign popover on outside click / Esc — mirrors the pattern
// used by the user-avatar menu.
document.addEventListener('click', function (e) {
  var picker = document.querySelector('.assign-picker');
  if (!picker) return;
  if (picker.contains(e.target)) return;
  var menu = picker.querySelector('.assign-menu');
  var trigger = picker.querySelector('.assign-trigger');
  if (menu && !menu.hasAttribute('hidden')) menu.setAttribute('hidden', '');
  if (trigger) trigger.setAttribute('aria-expanded', 'false');
});
document.addEventListener('keydown', function (e) {
  if (e.key !== 'Escape') return;
  var menu = document.querySelector('.assign-picker .assign-menu');
  var trigger = document.querySelector('.assign-picker .assign-trigger');
  if (menu && !menu.hasAttribute('hidden')) {
    menu.setAttribute('hidden', '');
    if (trigger) trigger.setAttribute('aria-expanded', 'false');
  }
});

export async function setFindingAssignee(arg, target) {
  if (!_drawerFinding || _drawerFinding.id == null) return;
  var select = document.getElementById('drawer-assign-select');
  var val = select ? select.value : '';
  var r = await apiSetFindingAssignee(_drawerFinding.id, val || null);
  if (!r || !r.ok) {
    toastError((r && r.data && r.data.detail) || 'Could not update assignment.');
    // Roll back the dropdown to the pre-change value so the UI stays honest.
    if (select) {
      select.value = _drawerFinding.assigned_to != null ? String(_drawerFinding.assigned_to) : '';
    }
    return;
  }
  _drawerFinding.assigned_to           = r.data.assigned_to;
  _drawerFinding.assigned_at           = r.data.assigned_at;
  _drawerFinding.assignee_email        = r.data.assignee_email;
  _drawerFinding.assignee_display_name = r.data.assignee_display_name;
  _loadDrawerAssign(_drawerFinding);
  document.dispatchEvent(new CustomEvent('pulse:assignee-changed', {
    detail: {
      id: _drawerFinding.id,
      assigned_to: r.data.assigned_to,
      assignee_email: r.data.assignee_email,
      assignee_display_name: r.data.assignee_display_name,
    },
  }));
  var nm = _displayFromAssignee(_drawerFinding);
  showToast(r.data.assigned_to ? ('Assigned to ' + (nm || 'user')) : 'Unassigned');
}

export async function assignFindingToMe() {
  var me = await _ensureMe();
  if (!me || !me.id) { toastError('Could not identify current user.'); return; }
  var select = document.getElementById('drawer-assign-select');
  if (select) select.value = String(me.id);
  return setFindingAssignee();
}


// ---------------------------------------------------------------
// Analyst notes — append-only thread per finding
// ---------------------------------------------------------------

function _renderNotesSection(f) {
  // Skeleton only — real content loaded async after the drawer mounts
  // so the drawer opens instantly even on slow connections.
  var hasId = f && f.id != null;
  if (!hasId) {
    return '<div class="finding-drawer-section">' +
      '<div class="sec-label">Notes</div>' +
      '<p style="color:var(--text-muted); font-size:12px; margin:0;">' +
        'Save this scan to enable analyst notes.' +
      '</p>' +
    '</div>';
  }
  return '<div class="finding-drawer-section">' +
    '<div class="sec-label">Notes</div>' +
    '<div id="drawer-notes-list" class="notes-thread">' +
      '<div class="notes-loading" style="font-size:12px; color:var(--text-muted);">Loading notes...</div>' +
    '</div>' +
    '<div class="notes-compose">' +
      '<textarea id="drawer-note-input" class="notes-compose-input" rows="2" maxlength="4000" ' +
        'placeholder="Add a note — what you saw, what you did, what\'s next..."></textarea>' +
      '<div class="notes-compose-actions">' +
        '<span class="notes-compose-count"><span id="drawer-note-count">0</span> / 4000</span>' +
        '<button type="button" class="btn btn-primary btn-sm btn-with-icon" data-action="submitFindingNote"><i data-lucide="send"></i><span>Post note</span></button>' +
      '</div>' +
    '</div>' +
  '</div>';
}

async function _loadDrawerNotes(findingId) {
  var list = document.getElementById('drawer-notes-list');
  if (!list) return;
  var r = await apiListFindingNotes(findingId);
  var notes = (r && r.notes) || [];
  _renderNotesThread(notes);
}

function _renderNotesThread(notes) {
  var list = document.getElementById('drawer-notes-list');
  if (!list) return;
  if (!notes || notes.length === 0) {
    list.innerHTML =
      '<p class="notes-empty">No notes yet. Add the first one below.</p>';
    return;
  }
  list.innerHTML = notes.map(function (n) {
    var dn = (n.display_name || '').trim();
    var author = dn || n.email || ('user #' + (n.user_id || '?'));
    var when = n.created_at || '';
    var body = String(n.body || '');
    return '<div class="note-item" data-note-id="' + escapeHtml(String(n.id)) + '">' +
      '<div class="note-meta">' +
        '<span class="note-author">' + escapeHtml(author) + '</span>' +
        roleBadgeHtml(n.role) +
        relTimeHtml(when, 'note-time') +
        '<button type="button" class="note-delete" aria-label="Delete note" ' +
          'title="Delete note" data-action="deleteFindingNote" ' +
          'data-arg="' + escapeHtml(String(n.id)) + '">&times;</button>' +
      '</div>' +
      '<div class="note-body">' + escapeHtml(body) + '</div>' +
    '</div>';
  }).join('');
}

// Module-level cache so delete can update without a re-fetch.
let _drawerNotes = [];

async function _refetchDrawerNotes() {
  if (!_drawerFinding || _drawerFinding.id == null) return;
  var r = await apiListFindingNotes(_drawerFinding.id);
  _drawerNotes = (r && r.notes) || [];
  _renderNotesThread(_drawerNotes);
  // Refresh the list-row note badge via event so every consumer stays in sync.
  document.dispatchEvent(new CustomEvent('pulse:notes-changed', {
    detail: { id: _drawerFinding.id, count: _drawerNotes.length },
  }));
}

export async function submitFindingNote() {
  if (!_drawerFinding || _drawerFinding.id == null) return;
  var input = document.getElementById('drawer-note-input');
  var body = (input && input.value || '').trim();
  if (!body) {
    if (input) input.focus();
    return;
  }
  var btn = document.querySelector('[data-action="submitFindingNote"]');
  if (btn) btn.disabled = true;
  try {
    var r = await apiCreateFindingNote(_drawerFinding.id, body);
    if (!r || !r.ok) {
      toastError((r && r.data && r.data.detail) || 'Could not post note.');
      return;
    }
    if (input) input.value = '';
    var countEl = document.getElementById('drawer-note-count');
    if (countEl) countEl.textContent = '0';
    await _refetchDrawerNotes();
    showToast('Note posted');
  } finally {
    if (btn) btn.disabled = false;
  }
}

export async function deleteFindingNote(noteId) {
  if (!_drawerFinding || _drawerFinding.id == null) return;
  if (!confirm('Delete this note?')) return;
  var r = await apiDeleteFindingNote(_drawerFinding.id, noteId);
  if (!r || !r.ok) {
    toastError((r && r.data && r.data.detail) || 'Could not delete note.');
    return;
  }
  await _refetchDrawerNotes();
  showToast('Note deleted');
}

// Live character counter on the compose textarea.
document.addEventListener('input', function (e) {
  var t = e.target;
  if (t && t.id === 'drawer-note-input') {
    var c = document.getElementById('drawer-note-count');
    if (c) c.textContent = String((t.value || '').length);
  }
});

function _renderWorkflowSection(f) {
  var current = (f && f.workflow_status) || 'new';
  var updatedLine = f && f.workflow_updated_at
    ? '<div class="wf-meta">Updated <strong>' + relTimeHtml(f.workflow_updated_at) + '</strong></div>'
    : '';
  var pills = _WF_STATES.map(function (w) {
    var on = (w.id === current);
    return '<button type="button" class="wf-pill wf-pill-' + w.id + (on ? ' is-selected' : '') + '" ' +
             'data-action="setFindingWorkflow" data-arg="' + w.id + '" ' +
             'aria-pressed="' + (on ? 'true' : 'false') + '">' +
             escapeHtml(w.label) +
           '</button>';
  }).join('');
  return '<div class="finding-drawer-section">' +
    '<div class="sec-label">Workflow</div>' +
    '<div class="wf-pill-row">' + pills + '</div>' +
    updatedLine +
  '</div>';
}

function _renderReviewSection(f) {
  var touched = isTouched(f);
  var reviewed = isReviewed(f);
  var fp = isFalsePositive(f);
  var reviewedAtHtml = (touched && f.reviewed_at)
    ? '<div class="review-meta-prominent" id="drawer-review-meta">' +
        '<span class="review-meta-icon">\u29BF</span>' +
        '<span>Last reviewed <strong>' + relTimeHtml(f.reviewed_at) + '</strong></span>' +
      '</div>'
    : '<div class="review-meta-prominent" id="drawer-review-meta" style="display:none;"></div>';

  // The buttons stay in their default visual state across renders.
  // Clicking either flashes a brief 3s confirmation (.is-confirming)
  // that fades back via opacity transition — see _flashReviewConfirm.
  // The persistent "is this finding reviewed?" indicator lives in the
  // reviewedAtHtml strip above and on the row pill in the table.
  return '<div class="finding-drawer-section">' +
    '<div class="sec-label">Review</div>' +
    reviewedAtHtml +
    '<div class="review-toggles">' +
      '<button type="button" class="review-toggle review-toggle-reviewed" ' +
        'data-action="markFindingReviewed" id="btn-review-reviewed" ' +
        'aria-pressed="' + (reviewed ? 'true' : 'false') + '">' +
        '<span class="review-check" aria-hidden="true"></span>' +
        '<span class="review-label">Mark reviewed</span>' +
      '</button>' +
      '<button type="button" class="review-toggle review-toggle-fp" ' +
        'data-action="markFindingFalsePositive" id="btn-review-fp" ' +
        'aria-pressed="' + (fp ? 'true' : 'false') + '">' +
        '<span class="review-check" aria-hidden="true"></span>' +
        '<span class="review-label">False positive</span>' +
      '</button>' +
    '</div>' +
  '</div>';
}

// Briefly flash the just-clicked button as a confirmation, then fade
// it back to default. Only the button whose flag was JUST flipped on
// gets the flash — flipping a flag off (or no change) leaves both
// buttons in their default state.
//
// 3s window matches the toast lifetime; CSS handles the 300ms opacity
// fade via the .is-confirming class.
var _reviewFlashTimers = { reviewed: null, fp: null };
function _flashReviewConfirm(nextReviewed, nextFalsePositive) {
  function flash(buttonId, key, on) {
    var btn = document.getElementById(buttonId);
    if (!btn) return;
    if (_reviewFlashTimers[key]) {
      clearTimeout(_reviewFlashTimers[key]);
      _reviewFlashTimers[key] = null;
    }
    if (!on) {
      btn.classList.remove('is-confirming', 'is-fading');
      btn.setAttribute('aria-pressed', 'false');
      return;
    }
    btn.classList.remove('is-fading');
    btn.classList.add('is-confirming');
    btn.setAttribute('aria-pressed', 'true');
    _reviewFlashTimers[key] = setTimeout(function () {
      btn.classList.add('is-fading');
      // Wait for the 300ms opacity transition to finish, then drop both
      // classes so the next click starts from a clean slate.
      _reviewFlashTimers[key] = setTimeout(function () {
        btn.classList.remove('is-confirming', 'is-fading');
        _reviewFlashTimers[key] = null;
      }, 320);
    }, 3000);
  }
  flash('btn-review-reviewed', 'reviewed', !!nextReviewed);
  flash('btn-review-fp',       'fp',       !!nextFalsePositive);
}

// Rebuild the prominent "Last reviewed at" line in place so the drawer
// updates without re-rendering the whole review section.
function _updateReviewMeta(reviewedAt, touched) {
  var el = document.getElementById('drawer-review-meta');
  if (!el) return;
  if (touched && reviewedAt) {
    el.style.display = '';
    el.innerHTML =
      '<span class="review-meta-icon">\u29BF</span>' +
      '<span>Last reviewed <strong>' + relTimeHtml(reviewedAt) + '</strong></span>';
  } else {
    el.style.display = 'none';
    el.innerHTML = '';
  }
}

// Submit the full desired state (both flags at once) so the server sees a
// consistent snapshot. Each button computes the new pair locally by
// flipping only its own flag.
async function _submitReview(nextReviewed, nextFalsePositive) {
  if (!_drawerFinding || _drawerFinding.id == null) {
    toastError('This finding has no id yet — save a scan first.');
    return;
  }
  // Review note textarea was removed in favor of the dedicated Notes
  // thread. Omit `note` from the payload so the server leaves any legacy
  // review_note untouched rather than nulling it.
  var r = await apiSetFindingReview(_drawerFinding.id, {
    reviewed: nextReviewed,
    falsePositive: nextFalsePositive,
  });
  if (!r.ok) {
    toastError((r.data && r.data.detail) || 'Review update failed.');
    return;
  }
  _drawerFinding.reviewed = !!r.data.reviewed;
  _drawerFinding.false_positive = !!r.data.false_positive;
  _drawerFinding.review_note = r.data.review_note;
  _drawerFinding.reviewed_at = r.data.reviewed_at;

  // Re-render the sev-line badges. Both pills can show at once now, so
  // strip any prior review badges and rebuild from the fresh finding.
  var sevLine = document.getElementById('drawer-sev-line');
  if (sevLine) {
    var pill = sevLine.querySelector('.sev-pill');
    var mitreEl = sevLine.querySelector('.mitre-tag');
    sevLine.innerHTML = '';
    if (pill) sevLine.appendChild(pill);
    if (mitreEl) sevLine.appendChild(mitreEl);
    var badgeHtml = _reviewBadge(_drawerFinding);
    if (badgeHtml) sevLine.insertAdjacentHTML('beforeend', badgeHtml);
  }

  _flashReviewConfirm(nextReviewed, nextFalsePositive);
  _updateReviewMeta(_drawerFinding.reviewed_at, isTouched(_drawerFinding));
  _notifyFindingStatusChanged(_drawerFinding.id, {
    reviewed: _drawerFinding.reviewed,
    false_positive: _drawerFinding.false_positive,
  });

  invalidateFindingsCache();

  // Toast reflects the final state — the pair of flags now on the finding.
  var toast;
  if (nextReviewed && nextFalsePositive) {
    toast = 'Marked reviewed and false positive';
  } else if (nextReviewed) {
    toast = 'Marked reviewed';
  } else if (nextFalsePositive) {
    toast = 'Marked false positive';
  } else {
    toast = 'Review cleared';
  }
  showToast(toast);
}

// Each button toggles ONLY its own flag, preserving the other. An analyst
// can mark a finding reviewed AND false-positive independently because
// they answer different questions.
export function markFindingReviewed() {
  if (!_drawerFinding) return;
  var nextR = !isReviewed(_drawerFinding);
  var keepFP = isFalsePositive(_drawerFinding);
  _submitReview(nextR, keepFP);
}
export function markFindingFalsePositive() {
  if (!_drawerFinding) return;
  var keepR = isReviewed(_drawerFinding);
  var nextFP = !isFalsePositive(_drawerFinding);
  _submitReview(keepR, nextFP);
}

// Workflow-state pill click handler. Registered via data-action in the
// drawer; `state` is the pill's data-arg value.
export async function setFindingWorkflow(state) {
  if (!_drawerFinding) return;
  if (!_drawerFinding.id) return;
  var current = (_drawerFinding.workflow_status || 'new');
  if (current === state) return;
  // Optimistic update — flip the UI first so the click feels instant,
  // then reconcile with the server's canonical response.
  _drawerFinding.workflow_status = state;
  _repaintWorkflowPills(state, _drawerFinding.workflow_updated_at);
  var r = await apiSetFindingWorkflow(_drawerFinding.id, state);
  if (!r || !r.ok || !r.data) {
    // Roll back on failure.
    _drawerFinding.workflow_status = current;
    _repaintWorkflowPills(current, _drawerFinding.workflow_updated_at);
    toastError('Could not update workflow state.');
    return;
  }
  _drawerFinding.workflow_status = r.data.workflow_status || state;
  _drawerFinding.workflow_updated_at = r.data.workflow_updated_at || '';
  _repaintWorkflowPills(_drawerFinding.workflow_status, _drawerFinding.workflow_updated_at);
  // Broadcast so list rows can repaint their chip without a full refetch.
  document.dispatchEvent(new CustomEvent('pulse:workflow-changed', {
    detail: {
      id: _drawerFinding.id,
      workflow_status: _drawerFinding.workflow_status,
      workflow_updated_at: _drawerFinding.workflow_updated_at,
    },
  }));
  showToast('Marked ' + (state === 'new' ? 'New' :
                         state === 'acknowledged' ? 'Acknowledged' :
                         state === 'investigating' ? 'Investigating' :
                         'Resolved'));
}

function _repaintWorkflowPills(state, updatedAt) {
  var pills = document.querySelectorAll('.wf-pill');
  pills.forEach(function (p) {
    var on = (p.getAttribute('data-arg') === state);
    p.classList.toggle('is-selected', on);
    p.setAttribute('aria-pressed', on ? 'true' : 'false');
  });
  // Refresh the "Updated ..." meta line if present.
  var wrap = document.querySelector('.finding-drawer-section .wf-pill-row');
  if (!wrap) return;
  var meta = wrap.parentElement.querySelector('.wf-meta');
  if (updatedAt) {
    if (!meta) {
      meta = document.createElement('div');
      meta.className = 'wf-meta';
      wrap.parentElement.appendChild(meta);
    }
    meta.innerHTML = 'Updated <strong>' + relTimeHtml(updatedAt) + '</strong>';
  }
}

export function closeFindingDrawer() {
  document.getElementById('finding-drawer').classList.remove('open');
  document.body.classList.remove('flyout-push-open');
  _drawerFinding = null;
}

// Esc closes the drawer.
document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') {
    var drawer = document.getElementById('finding-drawer');
    if (drawer && drawer.classList.contains('open')) closeFindingDrawer();
  }
});

// Assignee sync — when the drawer changes assignment, update the
// list-row cell + cached state so the rest of the page stays honest.
document.addEventListener('pulse:assignee-changed', function (ev) {
  if (!ev || !ev.detail || ev.detail.id == null) return;
  var email = ev.detail.assignee_email || '';
  var dn    = (ev.detail.assignee_display_name || '').trim();
  var display = dn || (email ? (email.split('@')[0] || email) : '');
  var rows = document.querySelectorAll(
    '[data-finding-id="' + String(ev.detail.id) + '"]'
  );
  rows.forEach(function (row) {
    var cell = row.querySelector('.col-assigned');
    if (!cell) return;
    if (!display) {
      cell.innerHTML = '<span class="assignee-empty">Unassigned</span>';
    } else {
      cell.innerHTML = '<span class="assignee-chip" title="' +
        escapeHtml(email || display) + '">' +
        escapeHtml(display) + '</span>';
    }
  });
  var cache = findingsState && findingsState.raw;
  if (Array.isArray(cache)) {
    for (var i = 0; i < cache.length; i++) {
      if (cache[i] && String(cache[i].id) === String(ev.detail.id)) {
        cache[i].assigned_to = ev.detail.assigned_to;
        cache[i].assignee_email = ev.detail.assignee_email;
        cache[i].assignee_display_name = ev.detail.assignee_display_name;
      }
    }
  }
});

// Notes count sync — when the drawer adds/deletes a note, bump the
// inline notes badge on every visible row for that finding.
document.addEventListener('pulse:notes-changed', function (ev) {
  if (!ev || !ev.detail || ev.detail.id == null) return;
  var count = Number(ev.detail.count || 0);
  var rows = document.querySelectorAll(
    '[data-finding-id="' + String(ev.detail.id) + '"]'
  );
  rows.forEach(function (row) {
    var cell = row.querySelector('.rule-cell');
    if (!cell) return;
    var existing = cell.querySelector('.notes-chip');
    if (count === 0) {
      if (existing) existing.remove();
      return;
    }
    // Rebuild the badge by dispatching through the same helper. Relying
    // on innerHTML here would drop event listeners from sibling chips.
    var bubble =
      '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" ' +
        'stroke="currentColor" stroke-width="2" stroke-linecap="round" ' +
        'stroke-linejoin="round" aria-hidden="true">' +
        '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>' +
      '</svg>';
    var html = '<span class="notes-chip" title="' + count + ' note' + (count === 1 ? '' : 's') + '">' +
      bubble + '<span class="notes-chip-count">' + count + '</span>' +
    '</span>';
    if (existing) {
      existing.outerHTML = html;
    } else {
      cell.insertAdjacentHTML('beforeend', ' ' + html);
    }
  });
  // Keep cached list state in sync.
  var cache = findingsState && findingsState.raw;
  if (Array.isArray(cache)) {
    for (var i = 0; i < cache.length; i++) {
      if (cache[i] && String(cache[i].id) === String(ev.detail.id)) {
        cache[i].note_count = count;
      }
    }
  }
});

// Workflow chip sync — when the drawer changes workflow state, patch the
// inline chip on every visible row for that finding id without a full
// list re-render. Keeps the flash-of-stale-state window to a frame.
document.addEventListener('pulse:workflow-changed', function (ev) {
  if (!ev || !ev.detail || ev.detail.id == null) return;
  var state = (ev.detail.workflow_status || 'new').toLowerCase();
  var rows = document.querySelectorAll(
    '[data-finding-id="' + String(ev.detail.id) + '"]'
  );
  rows.forEach(function (row) {
    // Update any cached finding object on list modules so future renders
    // stay correct. Handled by findings-page state below.
    var cell = row.querySelector('.rule-cell');
    if (!cell) return;
    var existing = cell.querySelector('.wf-chip');
    if (state === 'new') {
      if (existing) existing.remove();
      return;
    }
    var wfLabel = (_WF_STATES.find(function (w) { return w.id === state; }) || {}).label || 'New';
    var html = '<span class="wf-chip wf-chip-' + state + '">' + escapeHtml(wfLabel) + '</span>';
    if (existing) {
      existing.outerHTML = html;
    } else {
      cell.insertAdjacentHTML('beforeend', ' ' + html);
    }
  });
  // Keep cached findings list in sync so subsequent scroll / filter
  // re-renders preserve the new state.
  var cache = findingsState && findingsState.raw;
  if (Array.isArray(cache)) {
    for (var i = 0; i < cache.length; i++) {
      if (cache[i] && String(cache[i].id) === String(ev.detail.id)) {
        cache[i].workflow_status = state;
        cache[i].workflow_updated_at = ev.detail.workflow_updated_at || '';
      }
    }
  }
});

// ---------------------------------------------------------------
// Scan-detail findings table (used by viewScan)
// ---------------------------------------------------------------
let _scanDetailFindings = [];

export function openScanDetailFindingByIdx(idx) {
  var f = _scanDetailFindings[idx];
  if (f) openFindingDrawer(f);
}

export function buildFindingsTable(findings) {
  _scanDetailFindings = findings;
  return '<table class="findings-table"><thead><tr>' +
    '<th>Time</th><th>Severity</th><th>Rule</th><th>MITRE ATT&CK</th><th>Description</th><th>Status</th>' +
    '</tr></thead><tbody>' +
    findings.map(function (f, i) {
      var sev = (f.severity || 'LOW').toUpperCase();
      var rule = f.rule || 'Unknown';
      var mitre = f.mitre || mitreMap[rule] || '';
      var mitreLink = mitre
        ? '<span class="mitre-tag"><a href="https://attack.mitre.org/techniques/' +
          mitre.replace('.', '/') + '/" target="_blank" data-action="stopClickPropagation" data-default="allow">' + mitre + '</a></span>'
        : '-';
      var details = f.details || f.description || '';
      var shortDetails = details.length > 120 ? details.substring(0, 120) + '...' : details;
      var timeMatch = details.match(/(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})/);
      var time = f.timestamp || (timeMatch ? timeMatch[1] + ' ' + timeMatch[2] : '');
      var rowCls = 'clickable' + (isTouched(f) ? ' row-reviewed' : '');
      var fidAttr = (f.id != null) ? ' data-finding-id="' + escapeHtml(String(f.id)) + '"' : '';
      var timeCell = time ? relTimeHtml(time) : '<span class="rel-time">—</span>';

      return '<tr class="' + rowCls + '"' + fidAttr + ' ' +
             'data-action="openScanDetailFindingByIdx" data-arg="' + i + '" style="cursor:pointer;">' +
        '<td class="col-time">' + timeCell + '</td>' +
        '<td class="col-severity">' + sevPillHtml(sev) + '</td>' +
        '<td class="col-rule">' + rule + '</td>' +
        '<td class="col-mitre">' + mitreLink + '</td>' +
        '<td>' + escapeHtml(shortDetails) + '</td>' +
        '<td class="col-status" data-status-slot="pill">' + _statusPillHtml(f) + '</td></tr>';
    }).join('') +
    '</tbody></table>';
}

