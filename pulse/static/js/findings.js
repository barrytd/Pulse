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
} from './dashboard.js';
import { navigate } from './navigation.js';

// ---------------------------------------------------------------
// Scans page state — now with a tab for "All Findings"
// ---------------------------------------------------------------
export const scansState = {
  raw:      [],
  query:    '',
  sortCol:  'date',
  sortDir:  'desc',
  selected: {},
};

// Which tab is active on the merged Scans page. Persisted so
// navigating away and back remembers where you were.
let scansPageTab = 'scans'; // 'scans' | 'findings'

export function getScansPageTab() { return scansPageTab; }

export function setScansPageTab(tab) {
  if (tab !== 'scans' && tab !== 'findings') return;
  scansPageTab = tab;
  renderScansPage();
}

function _scansTabsBarHtml() {
  function tab(key, label) {
    var active = scansPageTab === key;
    return '<div class="scans-tab' + (active ? ' active' : '') + '" ' +
           'data-action="setScansPageTab" data-arg="' + key + '">' +
      escapeHtml(label) +
    '</div>';
  }
  return '<div class="scans-tabs">' +
    tab('scans',    'Scans') +
    tab('findings', 'All Findings') +
  '</div>';
}

// Called via data-action on the per-row checkbox. Second arg is the
// clicked element, third is the event — stop propagation so the row
// click (viewScan) doesn't also fire.
export function toggleScanSelect(id, target, ev) {
  if (ev) ev.stopPropagation();
  id = String(id);
  if (scansState.selected[id]) delete scansState.selected[id];
  else scansState.selected[id] = true;
  _updateScanDeleteBar();
}

// "Select all" header checkbox — the delegator passes data-arg ('true'/
// 'false') plus the checkbox element, so read the live checked state.
export function toggleScanSelectAll(arg, target) {
  var checked;
  if (target && typeof target.checked === 'boolean') checked = target.checked;
  else checked = (arg === true || arg === 'true');
  scansState.selected = {};
  if (checked) {
    (scansState._visible || []).forEach(function (s) {
      scansState.selected[String(s.id)] = true;
    });
  }
  applyScansView();
}

function _selectedScanIds() {
  return Object.keys(scansState.selected).map(function (k) { return +k; });
}

function _updateScanDeleteBar() {
  var bar = document.getElementById('scans-delete-bar');
  var btn = document.getElementById('scans-delete-btn');
  var n = _selectedScanIds().length;
  if (!bar || !btn) return;
  if (n > 0) {
    bar.style.display = 'flex';
    btn.textContent = 'Delete ' + n + ' scan' + (n === 1 ? '' : 's');
  } else {
    bar.style.display = 'none';
  }
}

export async function deleteSelectedScans() {
  var ids = _selectedScanIds();
  if (ids.length === 0) return;
  var msg = 'Delete ' + ids.length + ' scan' + (ids.length === 1 ? '' : 's') +
            ' and all associated findings? This cannot be undone.';
  if (!confirm(msg)) return;
  var result = await apiDeleteScans(ids);
  if (!result.ok) {
    if (result.error) {
      showToast('Delete failed: ' + (result.error.message || 'network error'), 'error');
    } else {
      showToast('Delete failed (' + result.status + ')', 'error');
    }
    return;
  }
  showToast('Deleted ' + result.data.deleted + ' scan' + (result.data.deleted === 1 ? '' : 's'), 'success');
  scansState.selected = {};
  invalidateScansCache();
  invalidateFindingsCache();
  scansState.raw = await fetchScans(200);
  if (scansState.raw.length === 0) { renderScansPage(); return; }
  applyScansView();
}

export async function renderScansPage() {
  // When the "All Findings" tab is active, delegate to the findings
  // loader but render it under the shared tab bar (see renderFindingsPage).
  if (scansPageTab === 'findings') {
    return renderFindingsPage();
  }

  var c = document.getElementById('content');
  scansState.raw = await fetchScans(200);

  if (scansState.raw.length === 0) {
    c.innerHTML =
      _scansTabsBarHtml() +
      '<div class="empty-state cta">' +
        '<div class="empty-icon">&#128269;</div>' +
        '<h3>No scans yet</h3>' +
        '<p>Upload a .evtx file to get started.</p>' +
        '<button class="btn btn-primary" data-action="openUploadModal">Upload .evtx</button>' +
      '</div>';
    return;
  }

  applyScansView();
}

export function setScansSort(col) {
  var s = scansState;
  if (s.sortCol === col) {
    s.sortDir = (s.sortDir === 'desc') ? 'asc' : 'desc';
  } else {
    s.sortCol = col;
    s.sortDir = 'desc';
  }
  applyScansView();
}

export function setScansQuery(q) {
  scansState.query = q || '';
  applyScansView();
}

// Delegator wrapper — pulls the live value from the input element.
export function setScansQueryFromInput(arg, target) {
  setScansQuery(target && target.value);
}

export function applyScansView() {
  var s = scansState;
  var q = s.query.trim().toLowerCase();

  var rows = s.raw.slice();
  if (q) {
    rows = rows.filter(function (sc) {
      var fname = (sc.filename || '').toLowerCase();
      var when  = (sc.scanned_at || '').toLowerCase();
      var host  = (sc.hostname || '').toLowerCase();
      return fname.indexOf(q) >= 0 || when.indexOf(q) >= 0 || host.indexOf(q) >= 0;
    });
  }

  var dir = s.sortDir === 'asc' ? 1 : -1;
  rows.sort(function (a, b) {
    var av, bv;
    switch (s.sortCol) {
      case 'files':    av = a.files_scanned || 0;  bv = b.files_scanned || 0; break;
      case 'events':   av = a.total_events || 0;   bv = b.total_events || 0;  break;
      case 'findings': av = a.total_findings || 0; bv = b.total_findings || 0; break;
      case 'score':    av = a.score != null ? a.score : -1; bv = b.score != null ? b.score : -1; break;
      case 'grade':    av = _gradeRank(a.score);   bv = _gradeRank(b.score); break;
      default:         av = a.scanned_at || '';    bv = b.scanned_at || '';
    }
    if (av < bv) return -1 * dir;
    if (av > bv) return  1 * dir;
    return 0;
  });

  s._visible = rows;
  var nSelected = _selectedScanIds().length;
  var deleteBarStyle = nSelected > 0 ? 'flex' : 'none';

  var c = document.getElementById('content');
  c.innerHTML =
    _scansTabsBarHtml() +
    '<div class="page-head">' +
      '<div class="page-head-title"><strong>' + rows.length + '</strong> of ' + s.raw.length + ' scans</div>' +
      '<div class="page-head-actions">' +
        '<button class="btn btn-primary" data-action="openUploadModal">Upload .evtx</button>' +
      '</div>' +
    '</div>' +
    '<div class="filter-bar">' +
      '<input type="search" id="scans-search-box" class="search-box" placeholder="Search by filename, date, or host..." ' +
        'value="' + escapeHtml(s.query) + '" data-action-input="setScansQueryFromInput" />' +
    '</div>' +
    '<div id="scans-delete-bar" class="bulk-bar" style="display:' + deleteBarStyle + ';">' +
      '<span class="bulk-bar-count">' + nSelected + ' selected</span>' +
      '<button class="btn btn-danger" id="scans-delete-btn" data-action="deleteSelectedScans">' +
        'Delete ' + nSelected + ' scan' + (nSelected === 1 ? '' : 's') +
      '</button>' +
      '<a class="bulk-bar-clear" data-action="toggleScanSelectAll" data-arg="false">Clear selection</a>' +
    '</div>' +
    '<div class="card" style="padding:0; overflow:hidden;">' +
      (rows.length === 0
        ? '<div style="text-align:center; padding:32px; color:var(--text-muted);">No scans match your search.</div>'
        : _buildScansTable(rows)) +
    '</div>';
  _restoreSearchFocus('scans-search-box');
}

// Pick what to show in the Scope column. Back-compat: older scans predate
// the `scope` column and will have null — fall back to the filename, and
// finally to an em dash so the cell is never blank.
function _scopeLabel(row) {
  if (row && row.scope) return row.scope;
  if (row && row.filename === 'System Scan') return 'System scan';
  if (row && row.filename) return row.filename;
  return '\u2014';
}

function _buildScansTable(rows) {
  var s = scansState;
  var sortable = function (col, label, style) {
    var active = (s.sortCol === col);
    var arrow = active
      ? '<span class="sort-arrow">' + (s.sortDir === 'desc' ? '\u25BC' : '\u25B2') + '</span>'
      : '<span class="sort-arrow inactive">\u21C5</span>';
    return '<th class="sortable"' + (style ? ' style="' + style + '"' : '') +
           ' data-action="setScansSort" data-arg="' + col + '">' + label + arrow + '</th>';
  };

  var allSelected = rows.length > 0 && rows.every(function (r) {
    return s.selected[String(r.id)];
  });
  var headCheckbox = '<th style="width:32px;"><input type="checkbox" ' +
    (allSelected ? 'checked ' : '') +
    'data-action="toggleScanSelectAll" aria-label="Select all scans" /></th>';

  return '<table class="data-table">' +
    '<thead><tr>' +
      headCheckbox +
      sortable('date',     'Date / Time') +
      sortable('files',    'Files') +
      sortable('events',   'Events') +
      sortable('findings', 'Findings') +
      sortable('score',    'Score') +
      sortable('grade',    'Grade') +
      '<th>Scope</th>' +
    '</tr></thead>' +
    '<tbody>' +
    rows.map(function (row) {
      var grade = _gradeFor(row.score);
      var checked = s.selected[String(row.id)] ? 'checked' : '';
      return '<tr class="clickable" data-action="viewScan" data-arg="' + row.id + '">' +
        '<td data-action="stopClickPropagation"><input type="checkbox" ' + checked +
          ' data-action="toggleScanSelect" data-arg="' + row.id + '" aria-label="Select scan ' + row.id + '" /></td>' +
        '<td><div style="font-weight:500;">' + escapeHtml(row.scanned_at || '-') + '</div>' +
          '<div style="font-size:11px; color:var(--text-muted);">' +
            escapeHtml(row.filename || 'Unknown') +
            (row.hostname ? ' \u2022 ' + escapeHtml(row.hostname) : '') +
          '</div></td>' +
        '<td>' + (row.files_scanned || 0) + '</td>' +
        '<td>' + (row.total_events || 0).toLocaleString() + '</td>' +
        '<td>' + row.total_findings + '</td>' +
        '<td style="font-weight:700; color:' + scoreColor(row.score) + '">' +
          (row.score != null ? row.score : '-') + '</td>' +
        '<td>' + (grade ? '<span class="grade-pill grade-' + grade + '">' + grade + '</span>' : '-') + '</td>' +
        '<td style="color:var(--text-muted);">' + escapeHtml(_scopeLabel(row)) + '</td>' +
      '</tr>';
    }).join('') +
    '</tbody></table>';
}

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
    '<div class="back-link" data-action="navigate" data-arg="scans">\u2190 Back to Scans</div>' +
    '<div class="scan-header">' +
      statCard('File', fname, scan ? (scan.hostname || '') : '', '') +
      statCard('Score', scan ? (scan.score != null ? scan.score : '-') : '-', scan ? (scan.score_label || '') : '', scan ? scoreColorClass(scan.score) : '') +
      statCard('Findings', findings.length, 'In this scan', '') +
      statCard('Date', scan ? scan.scanned_at : '-', '', '') +
    '</div>' +
    '<div class="card">' +
      '<div class="card-title" style="justify-content:space-between;">' +
        '<span>Findings \u2014 ' + escapeHtml(fname) + '</span>' +
        '<div style="display:flex; gap:8px;">' +
          '<button class="btn-small" data-action="downloadReport" data-arg="' + scanId + '" data-format="html">Export HTML</button>' +
          '<button class="btn-small" data-action="downloadReport" data-arg="' + scanId + '" data-format="pdf" style="background:var(--border); color:var(--text);">Export PDF</button>' +
          '<button class="btn-small" data-action="downloadReport" data-arg="' + scanId + '" data-format="json" style="background:var(--border); color:var(--text);">Export JSON</button>' +
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
export const findingsState = {
  raw:          [],
  sortCol:      'time',
  sortDir:      'desc',
  sevFilter:    'ALL',
  reviewFilter: 'ALL', // ALL | OPEN (hide reviewed + fp) | REVIEWED | FP
  assignFilter: 'ALL', // ALL | ME (only findings assigned to the current user)
  query:        '',
  expanded:     null,
  // Bulk-select state: a Set of finding ids currently checked. Separate
  // from row expansion so toggling the drawer doesn't disturb selection.
  selected:     Object.create(null),
  // The last computed filtered+sorted slice, kept so the bulk bar can
  // offer "Select all matching filter" without redoing the filter math.
  _lastVisible: [],
};

var SEV_WEIGHT = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

// One-shot filter handoff — lets other pages (e.g. the Dashboard "Needs
// Attention" widget) deep-link into the Findings page with pre-set sev/
// review filters. renderFindingsPage() consumes and clears it so manual
// navigation back to the page shows the default (All / All) view.
var _pendingFindingsFilter = null;

export function openUnreviewedCriticalHigh() {
  _pendingFindingsFilter = { sev: 'CRITICAL_HIGH', review: 'OPEN' };
  navigate('findings');
}

export async function renderFindingsPage() {
  // Entering this view also pins the merged Scans page to the findings
  // tab so the tab bar highlights correctly and the back-button hash
  // (#scans) keeps the tab when the user returns.
  scansPageTab = 'findings';
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

  findingsState.raw          = allFindings;
  findingsState.sortCol      = 'time';
  findingsState.sortDir      = 'desc';
  findingsState.sevFilter    = 'ALL';
  findingsState.reviewFilter = 'ALL';
  findingsState.assignFilter = 'ALL';
  findingsState.query        = '';
  findingsState.expanded     = null;
  findingsState.selected     = Object.create(null);

  // Consume a one-shot pre-set filter handoff (e.g. "Needs Attention"
  // widget on the Dashboard deep-links into unreviewed CRITICAL+HIGH).
  if (_pendingFindingsFilter) {
    if (_pendingFindingsFilter.sev)    findingsState.sevFilter    = _pendingFindingsFilter.sev;
    if (_pendingFindingsFilter.review) findingsState.reviewFilter = _pendingFindingsFilter.review;
    _pendingFindingsFilter = null;
  }

  if (allFindings.length === 0) {
    c.innerHTML =
      _scansTabsBarHtml() +
      '<div class="empty-state cta">' +
        '<div class="empty-icon">&#10003;</div>' +
        '<h3>No findings</h3>' +
        '<p>Every scan is clean so far. Upload a new log to check again.</p>' +
        '<button class="btn btn-primary" data-action="openUploadModal">Upload .evtx</button>' +
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

export function setFindingsFilter(sev) {
  findingsState.sevFilter = sev;
  findingsState.expanded  = null;
  applyFindingsView();
}

export function setFindingsReviewFilter(mode) {
  findingsState.reviewFilter = mode || 'ALL';
  findingsState.expanded     = null;
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

export function applyFindingsView() {
  var s = findingsState;
  var rows = s.raw.slice();

  if (s.sevFilter !== 'ALL') {
    rows = rows.filter(function (f) {
      var sv = (f.severity || 'LOW').toUpperCase();
      if (s.sevFilter === 'CRITICAL_HIGH') return sv === 'CRITICAL' || sv === 'HIGH';
      return sv === s.sevFilter;
    });
  }

  if (s.reviewFilter && s.reviewFilter !== 'ALL') {
    rows = rows.filter(function (f) {
      // Flags are independent, so filters count anything where that
      // flag is on — a finding marked BOTH reviewed and FP shows up
      // under both pills.
      if (s.reviewFilter === 'OPEN')     return !isTouched(f);
      if (s.reviewFilter === 'REVIEWED') return isReviewed(f);
      if (s.reviewFilter === 'FP')       return isFalsePositive(f);
      return true;
    });
  }

  if (s.assignFilter === 'ME' && _meCache && _meCache.id) {
    var myId = Number(_meCache.id);
    rows = rows.filter(function (f) {
      return Number(f.assigned_to) === myId;
    });
  }

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

  var counts = { ALL: s.raw.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  s.raw.forEach(function (f) {
    var sv = (f.severity || 'LOW').toUpperCase();
    if (counts[sv] !== undefined) counts[sv]++;
  });

  var pills = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(function (sev) {
    var isActive = s.sevFilter === sev;
    var cls = 'filter-pill' + (isActive ? ' active' : '');
    if (isActive && sev !== 'ALL') cls += ' sev-' + sev.toLowerCase();
    return '<div class="' + cls + '" data-action="setFindingsFilter" data-arg="' + sev + '">' +
      sev + ' <span style="opacity:0.7;">(' + counts[sev] + ')</span></div>';
  }).join('') +
  // "Assigned to me" lives in the same filter row as the severity pills so
  // all list-level filters read as one horizontal group.
  '<div class="filter-pill-divider" aria-hidden="true"></div>' +
  '<div class="filter-pill assigned-to-me-pill' +
    (s.assignFilter === 'ME' ? ' active' : '') + '" ' +
    'data-action="toggleAssignedToMeFilter" ' +
    'aria-pressed="' + (s.assignFilter === 'ME' ? 'true' : 'false') + '" ' +
    'title="Show only findings assigned to you">' +
    '<span class="assigned-to-me-dot" aria-hidden="true"></span>' +
    'Assigned to me' +
  '</div>';

  var reviewCounts = { ALL: s.raw.length, OPEN: 0, REVIEWED: 0, FP: 0 };
  s.raw.forEach(function (f) {
    if (!isTouched(f))       reviewCounts.OPEN++;
    if (isReviewed(f))       reviewCounts.REVIEWED++;
    if (isFalsePositive(f))  reviewCounts.FP++;
  });
  // Status filter is a dropdown now — one compact control that surfaces the
  // per-state count next to each label, Defense.com-style.
  var reviewOptions = [
    { k: 'ALL',      label: 'All'            },
    { k: 'OPEN',     label: 'Unreviewed'     },
    { k: 'REVIEWED', label: 'Reviewed'       },
    { k: 'FP',       label: 'False Positive' },
  ].map(function (p) {
    var sel = s.reviewFilter === p.k ? ' selected' : '';
    return '<option value="' + p.k + '"' + sel + '>' +
      escapeHtml(p.label) + ' (' + reviewCounts[p.k] + ')' +
    '</option>';
  }).join('');
  var reviewDropdown =
    '<div class="status-filter">' +
      '<label class="status-filter-label" for="findings-status-filter">STATUS</label>' +
      '<select id="findings-status-filter" class="status-filter-select" data-action-change="setFindingsReviewFilterFromSelect">' +
        reviewOptions +
      '</select>' +
    '</div>';

  // Assigned-to-me toggle now lives in the severity pill row; nothing
  // extra to render here.

  // Page title + header count — "Findings (32)" when unfiltered,
  // "Findings (12 of 32)" when filters narrow the view.
  var total = s.raw.length;
  var visible = rows.length;
  var filtered = (s.sevFilter !== 'ALL') ||
                 (s.reviewFilter && s.reviewFilter !== 'ALL') ||
                 (s.assignFilter === 'ME') ||
                 !!q;
  var countLabel = filtered ? (visible + ' of ' + total) : String(total);
  var titleEl = document.getElementById('page-title');
  if (titleEl) titleEl.textContent = 'Findings (' + countLabel + ')';

  // Stash the pre-render visible slice BEFORE we might short-circuit
  // into the empty-state branch — the bulk bar reads this to compute
  // "Select all matching filter" counts.
  s._lastVisible = rows;

  var c = document.getElementById('content');
  c.innerHTML =
    _scansTabsBarHtml() +
    '<div class="page-head">' +
      '<div class="page-head-title"><strong>' + visible + '</strong> of ' + total + ' findings</div>' +
    '</div>' +
    '<div class="filter-bar">' +
      '<div class="filter-pills">' + pills + '</div>' +
      reviewDropdown +
      '<input type="search" id="findings-search-box" class="search-box" placeholder="Search rule, description, or MITRE..." ' +
        'value="' + escapeHtml(s.query) + '" data-action-input="setFindingsQueryFromInput" />' +
    '</div>' +
    '<div class="card" style="padding:0; overflow:hidden;">' +
      (rows.length === 0
        ? '<div style="text-align:center; padding:32px; color:var(--text-muted);">No findings match the current filters.</div>'
        : _buildFindingsTable(rows)) +
    '</div>' +
    _renderBulkBarHtml(visible, total, filtered);
  _restoreSearchFocus('findings-search-box');
  _mountBulkBarUsers();
}

// Delegator wrapper for the status <select> — pulls the live value.
export function setFindingsReviewFilterFromSelect(arg, target) {
  setFindingsReviewFilter(target && target.value);
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
      // Assign-to custom dropdown (users populated async after mount)
      '<div class="bulk-bar-assign">' +
        '<button type="button" class="btn btn-secondary btn-sm" data-action="toggleBulkAssignMenu" ' +
          'aria-haspopup="listbox" aria-expanded="false">Assign to…</button>' +
        '<ul id="bulk-bar-assign-menu" class="assign-menu bulk-bar-assign-menu" role="listbox" hidden>' +
          '<li class="assign-item" style="color:var(--text-muted);">Loading users…</li>' +
        '</ul>' +
      '</div>' +
      '<button class="btn btn-secondary btn-sm" data-action="bulkAssignToMe">Assign to me</button>' +
      '<button class="btn btn-secondary btn-sm" data-action="bulkUnassign">Unassign</button>' +
      '<span class="bulk-bar-divider" aria-hidden="true"></span>' +
      '<button class="btn btn-secondary btn-sm" data-action="bulkMarkReviewed">Mark reviewed</button>' +
      '<a class="bulk-bar-clear" data-action="clearFindingSelection">Clear selection</a>' +
    '</div>'
  );
}

async function _mountBulkBarUsers() {
  // Populate the "Assign to..." dropdown once the users list is ready.
  // Fails soft for viewers (who 403 /api/users) — the menu still shows
  // their own account so they can self-assign via the dropdown too.
  var menu = document.getElementById('bulk-bar-assign-menu');
  if (!menu) return;
  var users = await _ensureAssignableUsers();
  var me = await _ensureMe();
  if (users.length === 0 && me && me.id) {
    users = [{ id: me.id, email: me.email || 'me', display_name: me.display_name, active: true }];
  }
  if (!users.length) {
    menu.innerHTML = '<li class="assign-item" style="color:var(--text-muted);">No active users</li>';
    return;
  }
  menu.innerHTML = users.map(function (u) {
    var display = (u.display_name || '').trim() ||
                  ((u.email || '').split('@')[0] || ('user #' + u.id));
    var isMe = (me && u.id === me.id);
    var primary = display + (isMe ? ' (me)' : '');
    var secondary = (u.display_name && u.email && u.email !== display) ? u.email : '';
    return '<li class="assign-item" ' +
             'data-action="bulkAssignPick" data-arg="' + u.id + '|' + _escAttr(display) + '">' +
             '<span class="assign-item-name">' + escapeHtml(primary) + '</span>' +
             (secondary
               ? '<span class="assign-item-email">' + escapeHtml(secondary) + '</span>'
               : '') +
           '</li>';
  }).join('');
}

function _escAttr(s) {
  return String(s || '').replace(/"/g, '&quot;').replace(/\|/g, '&#124;');
}

export function toggleBulkAssignMenu(arg, target) {
  var menu = document.getElementById('bulk-bar-assign-menu');
  if (!menu || !target) return;
  var open = !menu.hasAttribute('hidden');
  if (open) {
    menu.setAttribute('hidden', '');
    target.setAttribute('aria-expanded', 'false');
  } else {
    menu.removeAttribute('hidden');
    target.setAttribute('aria-expanded', 'true');
  }
}

// Close the bulk-bar assign menu on outside click / Esc.
document.addEventListener('click', function (e) {
  var wrap = document.querySelector('.bulk-bar-assign');
  if (!wrap) return;
  if (wrap.contains(e.target)) return;
  var menu = document.getElementById('bulk-bar-assign-menu');
  if (menu && !menu.hasAttribute('hidden')) {
    menu.setAttribute('hidden', '');
    var trigger = wrap.querySelector('[data-action="toggleBulkAssignMenu"]');
    if (trigger) trigger.setAttribute('aria-expanded', 'false');
  }
});
document.addEventListener('keydown', function (e) {
  if (e.key !== 'Escape') return;
  var menu = document.getElementById('bulk-bar-assign-menu');
  if (menu && !menu.hasAttribute('hidden')) {
    menu.setAttribute('hidden', '');
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
  if (menu) menu.setAttribute('hidden', '');
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

export async function toggleAssignedToMeFilter() {
  // Need `me.id` before we can filter — load it once on the first flip.
  await _ensureMe();
  findingsState.assignFilter = (findingsState.assignFilter === 'ME') ? 'ALL' : 'ME';
  findingsState.expanded = null;
  applyFindingsView();
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

  return '<table class="data-table">' +
    '<thead><tr>' +
      headCheckbox +
      th('time', 'Timestamp') +
      th('severity', 'Severity') +
      th('rule', 'Rule') +
      '<th>MITRE ATT&amp;CK</th>' +
      '<th>Description</th>' +
      th('host', 'Host') +
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
      var time = f.timestamp || _extractTime(f) || '-';
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

      var main = '<tr class="' + rowCls + '"' + fidAttr + ' ' +
                 'data-action="toggleFindingExpand" data-arg="' + f._uid + '">' +
        checkboxCell +
        '<td class="col-time">' + escapeHtml(time) + '</td>' +
        '<td>' + sevPillHtml(sev) + '</td>' +
        '<td class="col-rule">' +
          '<div class="rule-cell">' +
            '<span class="rule-name">' + escapeHtml(rule) + '</span>' +
            _refIdPill(f) +
            _wfChipInline(f) +
            _notesBadgeInline(f) +
          '</div>' +
        '</td>' +
        '<td>' + mitreTag + '</td>' +
        '<td style="color:var(--text-muted);">' + escapeHtml(shortDetails) + '</td>' +
        '<td class="col-host">' + escapeHtml(f._scan_host || '-') + '</td>' +
        '<td><a href="#" data-action="viewScanFromLink" data-arg="' + f._scan_id + '" ' +
          'style="color:var(--accent); text-decoration:none; font-size:12px;">#' + (f._scan_number != null ? f._scan_number : f._scan_id) + '</a>' +
          '<div style="font-size:10px; color:var(--text-muted);">' + escapeHtml((f._scan_date || '').split(' ')[0] || '') + '</div></td>' +
        '<td class="col-assigned">' + _assigneeCellHtml(f) + '</td>' +
        '<td class="col-status" data-status-slot="pill">' + _statusPillHtml(f) + '</td>' +
        '<td class="col-actions">' + _rowActionsHtml(f) + '</td>' +
      '</tr>';

      if (!isOpen) return main;
      return main + _expandRow(f, 11);
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

export function openFindingDrawer(f) {
  if (!f) return;
  _drawerFinding = f;
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

  _updateReviewButtonStates(f);

  document.getElementById('finding-drawer').classList.add('open');
  document.getElementById('finding-drawer-backdrop').classList.add('open');
  document.body.style.overflow = 'hidden';

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
    escapeHtml(f.assigned_at) + '</strong></div>' : '';
  var meBtn = (me && me.id && current !== String(me.id))
    ? '<button type="button" class="btn-link-sm" data-action="assignFindingToMe">Assign to me</button>'
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
        '<button type="button" class="btn btn-primary btn-sm" data-action="submitFindingNote">Post note</button>' +
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
        '<span class="note-time" title="' + escapeHtml(when) + '">' +
          escapeHtml(formatRelativeTime(when) || when) +
        '</span>' +
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
    ? '<div class="wf-meta">Updated <strong>' + escapeHtml(f.workflow_updated_at) + '</strong></div>'
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
        '<span>Last reviewed at <strong>' + escapeHtml(f.reviewed_at) + '</strong></span>' +
      '</div>'
    : '<div class="review-meta-prominent" id="drawer-review-meta" style="display:none;"></div>';

  return '<div class="finding-drawer-section">' +
    '<div class="sec-label">Review</div>' +
    reviewedAtHtml +
    '<div class="review-toggles">' +
      '<button type="button" class="review-toggle review-toggle-reviewed' +
        (reviewed ? ' active' : '') + '" ' +
        'data-action="markFindingReviewed" id="btn-review-reviewed" ' +
        'aria-pressed="' + (reviewed ? 'true' : 'false') + '">' +
        '<span class="review-check" aria-hidden="true"></span>' +
        '<span class="review-label">' +
          (reviewed ? 'Reviewed' : 'Mark reviewed') +
        '</span>' +
      '</button>' +
      '<button type="button" class="review-toggle review-toggle-fp' +
        (fp ? ' active' : '') + '" ' +
        'data-action="markFindingFalsePositive" id="btn-review-fp" ' +
        'aria-pressed="' + (fp ? 'true' : 'false') + '">' +
        '<span class="review-check" aria-hidden="true"></span>' +
        '<span class="review-label">' +
          (fp ? 'False Positive' : 'False positive') +
        '</span>' +
      '</button>' +
    '</div>' +
  '</div>';
}

function _updateReviewButtonStates(f) {
  var reviewed = document.getElementById('btn-review-reviewed');
  var fp       = document.getElementById('btn-review-fp');
  if (reviewed) {
    var isR = isReviewed(f);
    reviewed.classList.toggle('active', isR);
    reviewed.setAttribute('aria-pressed', isR ? 'true' : 'false');
    var rLabel = reviewed.querySelector('.review-label');
    if (rLabel) rLabel.textContent = isR ? 'Reviewed' : 'Mark reviewed';
  }
  if (fp) {
    var isF = isFalsePositive(f);
    fp.classList.toggle('active', isF);
    fp.setAttribute('aria-pressed', isF ? 'true' : 'false');
    var fLabel = fp.querySelector('.review-label');
    if (fLabel) fLabel.textContent = isF ? 'False Positive' : 'False positive';
  }
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
      '<span>Last reviewed at <strong>' + escapeHtml(reviewedAt) + '</strong></span>';
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

  _updateReviewButtonStates(_drawerFinding);
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
    meta.innerHTML = 'Updated <strong>' + escapeHtml(updatedAt) + '</strong>';
  }
}

export function closeFindingDrawer() {
  document.getElementById('finding-drawer').classList.remove('open');
  document.getElementById('finding-drawer-backdrop').classList.remove('open');
  document.body.style.overflow = '';
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
      var time = f.timestamp || (timeMatch ? timeMatch[1] + ' ' + timeMatch[2] : '-');
      var rowCls = 'clickable' + (isTouched(f) ? ' row-reviewed' : '');
      var fidAttr = (f.id != null) ? ' data-finding-id="' + escapeHtml(String(f.id)) + '"' : '';

      return '<tr class="' + rowCls + '"' + fidAttr + ' ' +
             'data-action="openScanDetailFindingByIdx" data-arg="' + i + '" style="cursor:pointer;">' +
        '<td class="col-time">' + time + '</td>' +
        '<td class="col-severity">' + sevPillHtml(sev) + '</td>' +
        '<td class="col-rule">' + rule + '</td>' +
        '<td class="col-mitre">' + mitreLink + '</td>' +
        '<td>' + escapeHtml(shortDetails) + '</td>' +
        '<td class="col-status" data-status-slot="pill">' + _statusPillHtml(f) + '</td></tr>';
    }).join('') +
    '</tbody></table>';
}
