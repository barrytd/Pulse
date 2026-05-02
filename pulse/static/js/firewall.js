// firewall.js — Firewall page (Block List + Firewall Rules tabs).
// The Block List tab shows every row in the Pulse IP block list with
// per-row Push / Unblock actions, plus a top action bar for bulk push
// and manual add. The Firewall Rules tab is a placeholder for the
// pfirewall.log parser landing in a later sprint.
'use strict';

import { escapeHtml, showToast, toastError, relTimeHtml, sevPillHtml } from './dashboard.js';
import { apiUnblockBatch, apiFirewallLogGet, apiFirewallLogUpload, apiFetchIntel } from './api.js';

// Tab state persists across navigation so a user who switched to
// "Firewall Rules" and went elsewhere comes back to the same tab.
let _firewallTab = 'block-list'; // 'block-list' | 'rules'
let _blockListCache = { rows: [], windows: false, is_admin: false };
// ip -> true. Matches the Scans page selection model.
let _selectedIps = {};

// Firewall Rules tab state. Cache survives tab switches so the parsed
// log doesn't re-fetch when the user toggles back from Block List.
let _fwLog = {
  loaded:    false,
  loading:   false,
  available: false,
  source:    'path',
  path:      '',
  entries:   [],
  summary:   { total: 0, allowed: 0, dropped: 0, unique_sources: 0 },
  suspicious: [],
  error:     null,
  // Filters
  fAction:    'all',  // all | ALLOW | DROP
  fProtocol:  'all',  // all | TCP | UDP | ICMP
  fDirection: 'all',  // all | in | out
  fQuery:     '',     // free-text IP search
  // Path input draft (echoes the input element's current value).
  pathInput:  '',
};

function _tabsBarHtml() {
  function tab(key, label) {
    var active = _firewallTab === key;
    return '<div class="scans-tab' + (active ? ' active' : '') + '" ' +
           'data-action="setFirewallTab" data-arg="' + key + '">' +
      escapeHtml(label) +
    '</div>';
  }
  return '<div class="scans-tabs">' +
    tab('block-list', 'Block List') +
    tab('rules',      'Firewall Rules') +
  '</div>';
}

export function setFirewallTab(tab) {
  if (tab !== 'block-list' && tab !== 'rules') return;
  _firewallTab = tab;
  renderFirewallPage();
}

export async function renderFirewallPage() {
  var c = document.getElementById('content');
  if (_firewallTab === 'rules') {
    // First-mount default for the path input so the user can hit Parse
    // immediately without typing anything.
    if (!_fwLog.pathInput) _fwLog.pathInput = FW_DEFAULT_LOG_PATH;
    c.innerHTML = _tabsBarHtml() + _renderRulesTab();
    _hydrateLucide();
    return;
  }

  c.innerHTML = _tabsBarHtml() +
    '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading block list\u2026</div>';

  try {
    var resp = await fetch('/api/block-list');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    _blockListCache = await resp.json();
  } catch (e) {
    c.innerHTML = _tabsBarHtml() +
      '<div class="card"><div style="padding:24px; color:var(--text-muted);">' +
        'Failed to load block list: ' + escapeHtml(e.message) +
      '</div></div>';
    return;
  }

  c.innerHTML = _tabsBarHtml() + _renderBlockListTab();
  _hydrateLucide();
}

// -----------------------------------------------------------------------
// Block List tab
// -----------------------------------------------------------------------
function _renderBlockListTab() {
  var rows = _blockListCache.rows || [];
  var total = rows.length;
  var pending = rows.filter(function (r) { return r.status === 'pending'; }).length;
  var active = rows.filter(function (r) { return r.status === 'active'; }).length;

  // Drop selections pointing at rows that no longer exist.
  var known = {};
  rows.forEach(function (r) { known[r.ip_address] = true; });
  Object.keys(_selectedIps).forEach(function (k) {
    if (!known[k]) delete _selectedIps[k];
  });

  var pendingBanner = '';
  if (pending > 0) {
    pendingBanner =
      '<div class="pending-banner">' +
        '<div class="pending-banner-text">' +
          '<strong>' + pending + '</strong> pending change' + (pending === 1 ? '' : 's') +
          ' — IPs staged but not yet pushed to Windows Firewall.' +
        '</div>' +
        '<div class="pending-banner-actions">' +
          '<button class="btn btn-sm btn-with-icon" data-action="firewallReviewPending"><i data-lucide="eye"></i><span>Review</span></button>' +
          '<button class="btn btn-sm btn-primary btn-with-icon" data-action="firewallPushAll"><i data-lucide="send"></i><span>Push now</span></button>' +
          '<button class="btn btn-sm btn-danger btn-with-icon" data-action="firewallDiscardPending"><i data-lucide="trash-2"></i><span>Discard</span></button>' +
        '</div>' +
      '</div>';
  }

  var kpiStrip =
    '<div class="firewall-kpi-strip">' +
      '<div class="firewall-kpi-tile tone-ok">' +
        '<div class="firewall-kpi-label">Active</div>' +
        '<div class="firewall-kpi-value">' + active + '</div>' +
      '</div>' +
      '<div class="firewall-kpi-tile tone-warn">' +
        '<div class="firewall-kpi-label">Pending push</div>' +
        '<div class="firewall-kpi-value">' + pending + '</div>' +
      '</div>' +
      '<div class="firewall-kpi-tile tone-neutral">' +
        '<div class="firewall-kpi-label">Total entries</div>' +
        '<div class="firewall-kpi-value">' + total + '</div>' +
      '</div>' +
    '</div>';

  var head =
    '<div class="page-head">' +
      '<div class="page-head-title">Block list</div>' +
      '<div class="page-head-actions">' +
        '<button class="btn" data-action="firewallPushAll"' +
          (pending === 0 ? ' disabled' : '') + '>Push all pending</button>' +
        '<button class="btn btn-primary btn-with-icon" data-action="openAddBlockModal"><i data-lucide="plus"></i><span>Add IP manually</span></button>' +
      '</div>' +
    '</div>' +
    pendingBanner +
    kpiStrip;

  if (total === 0) return head + _renderBlockListEmpty();

  var nSelected = Object.keys(_selectedIps).length;
  var deleteBarStyle = nSelected > 0 ? 'flex' : 'none';

  return head +
    '<div id="firewall-delete-bar" class="bulk-bar" style="display:' + deleteBarStyle + ';">' +
      '<span class="bulk-bar-count">' + nSelected + ' selected</span>' +
      '<button class="btn btn-danger" id="firewall-delete-btn" data-action="deleteSelectedBlocks">' +
        'Unblock ' + nSelected + ' IP' + (nSelected === 1 ? '' : 's') +
      '</button>' +
      '<a class="bulk-bar-clear" data-action="toggleBlockSelectAll" data-arg="false">Clear selection</a>' +
    '</div>' +
    '<div class="card" style="padding:0; overflow:hidden;">' +
      _buildBlockListTable(rows) +
    '</div>' +
    _renderAddBlockModal();
}

function _renderBlockListEmpty() {
  return '<div class="card firewall-empty">' +
    '<div class="firewall-empty-icon"><i data-lucide="shield-off"></i></div>' +
    '<h3>No IPs blocked</h3>' +
    '<p>Block source IPs from the finding detail drawer or add them manually.</p>' +
    '<button class="btn btn-primary btn-with-icon" data-action="openAddBlockModal"><i data-lucide="plus"></i><span>Add IP manually</span></button>' +
  '</div>' + _renderAddBlockModal();
}

function _buildBlockListTable(rows) {
  var allSelected = rows.length > 0 && rows.every(function (r) {
    return _selectedIps[r.ip_address];
  });
  return '<table class="data-table">' +
    '<thead><tr>' +
      '<th style="width:32px;"><input type="checkbox" id="firewall-select-all" ' +
        (allSelected ? 'checked ' : '') +
        'data-action="toggleBlockSelectAll" aria-label="Select all blocked IPs" /></th>' +
      '<th>IP Address</th>' +
      '<th>Status</th>' +
      '<th>Comment</th>' +
      '<th>Added</th>' +
      '<th>Pushed</th>' +
      '<th>Source</th>' +
      '<th style="text-align:right;">Actions</th>' +
    '</tr></thead>' +
    '<tbody>' +
    rows.map(_buildBlockListRow).join('') +
    '</tbody></table>';
}

function _buildBlockListRow(row) {
  var status = row.status || 'pending';
  var pillCls = status === 'active' ? 'pill-low' : 'pill-medium';
  var pill = '<span class="pill ' + pillCls + '">' + escapeHtml(status) + '</span>';
  var comment = row.comment ? escapeHtml(row.comment) :
                '<span style="color:var(--text-light);">\u2014</span>';
  var added = row.added_at ? relTimeHtml(row.added_at) :
              '<span style="color:var(--text-light);">\u2014</span>';
  var pushed = row.pushed_at ? relTimeHtml(row.pushed_at) :
               '<span style="color:var(--text-light);">\u2014</span>';
  var source = row.source ? escapeHtml(row.source) :
               '<span style="color:var(--text-light);">\u2014</span>';

  var ipEsc = escapeHtml(row.ip_address);
  var actions = '';
  if (status === 'pending') {
    actions += '<button class="btn btn-sm btn-primary" data-action="firewallPushOne" ' +
      'data-arg="' + ipEsc + '">Push to Firewall</button> ';
  }
  actions += '<button class="btn btn-sm btn-danger" data-action="firewallUnblock" ' +
    'data-arg="' + ipEsc + '">Unblock</button>';

  var checked = _selectedIps[row.ip_address] ? 'checked' : '';

  return '<tr>' +
    '<td data-action="stopClickPropagation" style="width:32px;">' +
      '<input type="checkbox" ' + checked +
        ' data-action="toggleBlockSelect" data-arg="' + ipEsc + '" ' +
        'aria-label="Select ' + ipEsc + '" /></td>' +
    '<td class="mono" style="font-weight:600;">' + ipEsc + '</td>' +
    '<td>' + pill + '</td>' +
    '<td>' + comment + '</td>' +
    '<td class="mono" style="font-size:12px;">' + added + '</td>' +
    '<td class="mono" style="font-size:12px;">' + pushed + '</td>' +
    '<td style="font-size:12px; color:var(--text-muted);">' + source + '</td>' +
    '<td style="text-align:right; white-space:nowrap;">' + actions + '</td>' +
  '</tr>';
}

export function toggleBlockSelect(ip, target, ev) {
  if (ev) ev.stopPropagation();
  if (!ip) return;
  if (_selectedIps[ip]) delete _selectedIps[ip];
  else _selectedIps[ip] = true;
  renderFirewallPage();
}

export function toggleBlockSelectAll(arg, target) {
  var checked;
  if (target && typeof target.checked === 'boolean') checked = target.checked;
  else checked = (arg === true || arg === 'true');
  _selectedIps = {};
  if (checked) {
    (_blockListCache.rows || []).forEach(function (r) {
      _selectedIps[r.ip_address] = true;
    });
  }
  renderFirewallPage();
}

// Tiered confirmation.
//   <= 10 rows  -> a normal confirm dialog
//   11 to 50    -> confirm dialog with explicit consequence text
//   > 50        -> typed confirmation: user must type "DELETE N ENTRIES"
// Keeps the cheap path cheap while making catastrophic ops explicit.
function _confirmBulkUnblock(count) {
  if (count <= 10) {
    return window.confirm('Unblock ' + count + ' IP' + (count === 1 ? '' : 's') +
      '? The Windows Firewall rules will be removed.');
  }
  if (count <= 50) {
    return window.confirm('Unblock ' + count + ' IPs?\n\n' +
      'This removes ' + count + ' deny rules from Windows Firewall. The rules are ' +
      'not recoverable from Pulse — you would need to re-add each IP manually.');
  }
  var expected = 'DELETE ' + count + ' ENTRIES';
  var entered = window.prompt(
    'You are about to unblock ' + count + ' IPs. This cannot be undone.\n\n' +
    'Type "' + expected + '" exactly to confirm.'
  );
  return entered === expected;
}

export async function deleteSelectedBlocks() {
  var ips = Object.keys(_selectedIps);
  if (ips.length === 0) return;
  if (!_confirmBulkUnblock(ips.length)) return;
  var result = await apiUnblockBatch(ips);
  if (!result.ok) {
    toastError('Unblock failed: ' + ((result.data && result.data.detail) || 'network error'));
    return;
  }
  var deleted = result.data && typeof result.data.deleted === 'number' ? result.data.deleted : ips.length;
  showToast('Unblocked ' + deleted + ' IP' + (deleted === 1 ? '' : 's'), 'success');
  (result.data && result.data.failed || []).forEach(function (f) {
    toastError(f.ip + ': ' + (f.message || 'unblock failed'));
  });
  _selectedIps = {};
  renderFirewallPage();
}

// -----------------------------------------------------------------------
// Firewall Rules tab — pfirewall.log parser surface.
//
// Two ingest paths:
//  - Path-based (Windows host): user provides the on-disk path to the
//    log; backend reads + parses it. Default value is the canonical
//    Windows location.
//  - Upload-based (Linux / hosted): user uploads a pfirewall.log file;
//    backend streams it to a temp file, parses, returns + deletes.
//
// Filters live in module state (`_fwLog.f*`) so re-renders are cheap.
// -----------------------------------------------------------------------

const FW_DEFAULT_LOG_PATH = 'C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log';

function _renderRulesTab() {
  return _fwToolbarHtml() +
         _fwBodyHtml();
}

function _fwToolbarHtml() {
  // Path input + Parse button. Below it: file upload form for
  // hosted Linux deploys where the path-based read won't work.
  var path = _fwLog.pathInput || _fwLog.path || FW_DEFAULT_LOG_PATH;
  var parseDisabled = _fwLog.loading ? ' disabled' : '';
  return '<div class="card fw-toolbar">' +
    '<div class="fw-toolbar-row">' +
      '<label class="fw-toolbar-label" for="fw-path-input">Log file path</label>' +
      '<input type="text" id="fw-path-input" class="fw-path-input" ' +
        'value="' + escapeHtml(path) + '" ' +
        'placeholder="' + escapeHtml(FW_DEFAULT_LOG_PATH) + '" ' +
        'spellcheck="false" autocomplete="off" ' +
        'data-action-input="fwPathInput" data-action-keydown="fwPathKey" />' +
      '<button class="btn btn-primary btn-with-icon"' + parseDisabled + ' ' +
        'data-action="fwParseLog">' +
        '<i data-lucide="play"></i><span>Parse Log</span></button>' +
    '</div>' +
    '<p class="fw-toolbar-hint">' +
      'Default path is <code>' + escapeHtml(FW_DEFAULT_LOG_PATH) + '</code> ' +
      '(only readable on the Windows host running Pulse). On hosted / Linux ' +
      'deployments, upload the file instead — Pulse parses it in memory and ' +
      'never persists raw firewall logs.' +
    '</p>' +
    '<div class="fw-toolbar-row">' +
      '<label class="fw-toolbar-label">Or upload</label>' +
      '<input type="file" id="fw-upload-input" accept=".log,.txt" ' +
        'data-action-change="fwUploadLog" />' +
    '</div>' +
  '</div>';
}

function _fwBodyHtml() {
  if (_fwLog.loading) {
    return '<div class="card" style="text-align:center; padding:32px; color:var(--text-muted);">' +
      'Parsing firewall log…' +
    '</div>';
  }
  if (_fwLog.error) {
    return '<div class="card" style="border-color:var(--severity-high, #f0883e);">' +
      '<div class="section-label" style="color:var(--severity-high, #f0883e);">Could not parse log</div>' +
      '<p style="color:var(--text-muted); font-size:13px; margin:0;">' +
        escapeHtml(_fwLog.error) +
      '</p>' +
    '</div>';
  }
  if (!_fwLog.loaded) {
    return _fwIdleStateHtml();
  }
  if (!_fwLog.available) {
    return '<div class="card" style="text-align:center; padding:32px; color:var(--text-muted);">' +
      'No log file at <code>' + escapeHtml(_fwLog.path || '') + '</code>. ' +
      'Enable firewall logging in Windows Defender Firewall ' +
      '(Properties → Logging → "Log dropped packets" + "Log successful connections"), ' +
      'or upload a pfirewall.log file above.' +
    '</div>';
  }

  return _fwKpiStripHtml() +
         _fwSuspiciousHtml() +
         _fwFilterBarHtml() +
         _fwTableHtml();
}

function _fwIdleStateHtml() {
  return '<div class="card" style="text-align:center; padding:48px 24px;">' +
    '<div class="firewall-empty-icon" style="margin-bottom:14px;">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
        'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' +
        '<path d="M12 2 4 6v6c0 5 3.5 9 8 10 4.5-1 8-5 8-10V6z"/>' +
      '</svg>' +
    '</div>' +
    '<h3 style="margin:0 0 8px; font-size:16px; font-weight:600;">Parse a firewall log</h3>' +
    '<p style="color:var(--text-muted); max-width:520px; margin:0 auto; line-height:1.55;">' +
      'Click <strong>Parse Log</strong> above to read from the configured path, ' +
      'or upload a <code>pfirewall.log</code> file. ' +
      'Pulse extracts blocked + allowed connections, flags port scans and ' +
      'sensitive-port probes, and lets you stage suspicious source IPs to the block list.' +
    '</p>' +
  '</div>';
}

function _fwKpiStripHtml() {
  var s = _fwLog.summary;
  function tile(label, value, tone) {
    return '<div class="fw-kpi-tile tone-' + tone + '">' +
      '<div class="fw-kpi-label">' + escapeHtml(label) + '</div>' +
      '<div class="fw-kpi-value">' + escapeHtml(String(value)) + '</div>' +
    '</div>';
  }
  return '<div class="fw-kpi-strip">' +
    tile('Total Entries',     s.total.toLocaleString(),          'neutral') +
    tile('Allowed',           s.allowed.toLocaleString(),        'ok') +
    tile('Dropped',           s.dropped.toLocaleString(),        'error') +
    tile('Unique Source IPs', s.unique_sources.toLocaleString(), 'info') +
  '</div>';
}

function _fwSuspiciousHtml() {
  if (!_fwLog.suspicious || _fwLog.suspicious.length === 0) return '';
  var rows = _fwLog.suspicious.slice(0, 20).map(function (f) {
    var sev = (f.severity || 'MEDIUM').toUpperCase();
    return '<div class="fw-susp-row">' +
      sevPillHtml(sev) +
      '<div class="fw-susp-body">' +
        '<div class="fw-susp-rule">' + escapeHtml(f.rule || 'Suspicious activity') + '</div>' +
        '<div class="fw-susp-detail">' + escapeHtml(f.details || '') + '</div>' +
      '</div>' +
    '</div>';
  }).join('');
  return '<div class="card fw-susp-card">' +
    '<div class="section-label">Suspicious activity</div>' +
    '<p class="fw-susp-blurb">' +
      'Patterns extracted from the parsed log: port scans (10+ distinct ports in 5 min), ' +
      'repeated drops from the same source, and probes against high-risk ports ' +
      '(3389/RDP, 22/SSH, 445/SMB, 3306/MySQL, 5985/WinRM).' +
    '</p>' +
    rows +
  '</div>';
}

function _fwFilterBarHtml() {
  function chip(key, label, value) {
    var active = (_fwLog[key] === value) ? ' is-active' : '';
    return '<button type="button" class="fw-chip' + active + '" ' +
             'data-action="fwSetFilter" data-arg="' + key + ':' + value + '">' +
             escapeHtml(label) +
           '</button>';
  }
  return '<div class="fw-filter-bar">' +
    '<div class="fw-filter-group">' +
      '<span class="fw-filter-label">Action</span>' +
      chip('fAction', 'All',   'all') +
      chip('fAction', 'Allow', 'ALLOW') +
      chip('fAction', 'Drop',  'DROP') +
    '</div>' +
    '<div class="fw-filter-group">' +
      '<span class="fw-filter-label">Protocol</span>' +
      chip('fProtocol', 'All',  'all') +
      chip('fProtocol', 'TCP',  'TCP') +
      chip('fProtocol', 'UDP',  'UDP') +
      chip('fProtocol', 'ICMP', 'ICMP') +
    '</div>' +
    '<div class="fw-filter-group">' +
      '<span class="fw-filter-label">Direction</span>' +
      chip('fDirection', 'All',  'all') +
      chip('fDirection', 'In',   'in') +
      chip('fDirection', 'Out',  'out') +
    '</div>' +
    '<div class="fw-filter-group fw-filter-search">' +
      '<input type="search" class="fw-search-input" ' +
        'placeholder="Filter by IP…" ' +
        'value="' + escapeHtml(_fwLog.fQuery) + '" ' +
        'data-action-input="fwSetSearch" />' +
    '</div>' +
  '</div>';
}

// Inferred direction — the W3C default fields don't carry one, so we
// classify by IP topology: incoming if dst is private and src is public,
// outgoing if src is private and dst is public, otherwise unknown.
function _fwInferDirection(row) {
  var src = String(row.src_ip || '');
  var dst = String(row.dst_ip || '');
  var srcPrivate = _fwIsPrivate(src);
  var dstPrivate = _fwIsPrivate(dst);
  if (!srcPrivate && dstPrivate) return 'in';
  if (srcPrivate && !dstPrivate) return 'out';
  return '';
}

function _fwIsPrivate(ip) {
  if (!ip || ip === '-') return false;
  if (/^127\./.test(ip)) return true;          // loopback
  if (/^10\./.test(ip))  return true;          // 10/8
  if (/^192\.168\./.test(ip)) return true;     // 192.168/16
  // 172.16/12
  var m = /^172\.(\d+)\./.exec(ip);
  if (m) {
    var n = parseInt(m[1], 10);
    if (n >= 16 && n <= 31) return true;
  }
  if (/^169\.254\./.test(ip)) return true;     // link-local
  if (/^fe80:/i.test(ip)) return true;         // IPv6 link-local
  if (/^::1$/.test(ip)) return true;           // IPv6 loopback
  return false;
}

function _fwIsPublic(ip) {
  if (!ip || ip === '-') return false;
  // Any IP that's not private/loopback/link-local. We treat unparseable
  // strings as not-public so the Block button never offers up a junk IP.
  if (_fwIsPrivate(ip)) return false;
  // Reject obvious malformed strings — must look like an IPv4.
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
}

function _fwApplyFilters(rows) {
  var q = (_fwLog.fQuery || '').trim().toLowerCase();
  return rows.filter(function (r) {
    if (_fwLog.fAction !== 'all' && (r.action || '') !== _fwLog.fAction) return false;
    if (_fwLog.fProtocol !== 'all' && (r.protocol || '') !== _fwLog.fProtocol) return false;
    if (_fwLog.fDirection !== 'all') {
      if (_fwInferDirection(r) !== _fwLog.fDirection) return false;
    }
    if (q) {
      var hay = ((r.src_ip || '') + ' ' + (r.dst_ip || '')).toLowerCase();
      if (hay.indexOf(q) < 0) return false;
    }
    return true;
  });
}

function _fwTableHtml() {
  var visible = _fwApplyFilters(_fwLog.entries);
  var capNote = _fwLog.summary.total > _fwLog.entries.length
    ? '<span style="color:var(--text-muted); font-size:11px;"> · ' +
        'showing newest ' + _fwLog.entries.length.toLocaleString() +
        ' of ' + _fwLog.summary.total.toLocaleString() + '</span>'
    : '';
  if (visible.length === 0) {
    return '<div class="card" style="margin-top:16px;">' +
      '<div class="section-label">Entries' + capNote + '</div>' +
      '<p style="color:var(--text-muted); font-size:13px; margin:0;">No entries match the current filters.</p>' +
    '</div>';
  }
  var rowsHtml = visible.map(_fwRowHtml).join('');
  return '<div class="card fw-entries-card">' +
    '<div class="section-label">Entries' + capNote +
      '<span style="color:var(--text-muted); font-weight:400; margin-left:8px; font-size:11px;">' +
        ' · ' + visible.length.toLocaleString() + ' visible' +
      '</span>' +
    '</div>' +
    '<div class="table-wrap">' +
      '<table class="fw-entries-table">' +
        '<thead><tr>' +
          '<th>Timestamp</th><th>Action</th><th>Protocol</th>' +
          '<th>Source IP</th><th>Src Port</th>' +
          '<th>Destination IP</th><th>Dst Port</th>' +
          '<th>Dir</th><th>Size</th>' +
          '<th class="fw-cell-actions" aria-label="Quick actions"></th>' +
        '</tr></thead><tbody>' +
        rowsHtml +
      '</tbody></table>' +
    '</div>' +
  '</div>';
}

function _fwRowHtml(r) {
  var action = r.action || '';
  var actionCls = action === 'ALLOW' ? 'fw-act-allow'
                : action === 'DROP'  ? 'fw-act-drop'
                : 'fw-act-other';
  var dir = _fwInferDirection(r);
  var dirIcon = dir === 'in'  ? '↓'
              : dir === 'out' ? '↑'
              : '—';
  var dirLabel = dir === 'in' ? 'IN' : dir === 'out' ? 'OUT' : '';
  // Per-row actions: Block (DROP rows w/ public source) + Lookup
  // (anything with a public source). Both rendered always but
  // visible only on row hover via CSS.
  var publicSrc = _fwIsPublic(r.src_ip);
  var actionsHtml = '';
  if (publicSrc) {
    if (action === 'DROP') {
      actionsHtml +=
        '<button type="button" class="fw-row-action" ' +
          'data-action="fwBlockFromRow" data-arg="' + escapeHtml(r.src_ip) + '" ' +
          'title="Stage ' + escapeHtml(r.src_ip) + ' to the block list" ' +
          'aria-label="Block source IP">' +
          '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" ' +
            'stroke-linecap="round" stroke-linejoin="round">' +
            '<circle cx="8" cy="8" r="6"/><line x1="3.7" y1="3.7" x2="12.3" y2="12.3"/>' +
          '</svg>' +
        '</button>';
    }
    actionsHtml +=
      '<button type="button" class="fw-row-action" ' +
        'data-action="fwLookupFromRow" data-arg="' + escapeHtml(r.src_ip) + '" ' +
        'title="Threat-intel lookup for ' + escapeHtml(r.src_ip) + '" ' +
        'aria-label="Threat intel lookup">' +
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" ' +
          'stroke-linecap="round" stroke-linejoin="round">' +
          '<circle cx="7" cy="7" r="4"/><line x1="10" y1="10" x2="13.5" y2="13.5"/>' +
        '</svg>' +
      '</button>';
  }
  return '<tr>' +
    '<td class="fw-cell-ts">' + escapeHtml(r.ts || '—') + '</td>' +
    '<td><span class="fw-action-chip ' + actionCls + '">' + escapeHtml(action || '—') + '</span></td>' +
    '<td>' + escapeHtml(r.protocol || '—') + '</td>' +
    '<td class="mono">' + escapeHtml(r.src_ip || '—') + '</td>' +
    '<td>' + escapeHtml(r.src_port || '—') + '</td>' +
    '<td class="mono">' + escapeHtml(r.dst_ip || '—') + '</td>' +
    '<td>' + escapeHtml(r.dst_port || '—') + '</td>' +
    '<td title="' + dirLabel + '">' + dirIcon + '</td>' +
    '<td>' + escapeHtml(r.size || '—') + '</td>' +
    '<td class="fw-cell-actions">' + actionsHtml + '</td>' +
  '</tr>';
}

// ---- Action handlers ---------------------------------------------------

export function fwPathInput(arg, target) {
  if (target) _fwLog.pathInput = target.value;
}

export function fwPathKey(arg, target, ev) {
  if (ev && ev.key === 'Enter') fwParseLog();
}

export async function fwParseLog() {
  var path = (_fwLog.pathInput || _fwLog.path || '').trim();
  _fwLog.loading = true;
  _fwLog.error = null;
  renderFirewallPage();
  try {
    var data = await apiFirewallLogGet(path);
    _fwLog.loaded     = true;
    _fwLog.available  = !!data.available;
    _fwLog.path       = data.path || path;
    _fwLog.pathInput  = data.path || path;
    _fwLog.entries    = data.entries || [];
    _fwLog.summary    = data.summary || _fwLog.summary;
    _fwLog.suspicious = data.suspicious || [];
    _fwLog.source     = 'path';
  } catch (e) {
    _fwLog.error = (e && e.message) ? e.message : String(e);
  } finally {
    _fwLog.loading = false;
    renderFirewallPage();
  }
}

export async function fwUploadLog(arg, target) {
  var f = target && target.files && target.files[0];
  if (!f) return;
  _fwLog.loading = true;
  _fwLog.error = null;
  renderFirewallPage();
  try {
    var data = await apiFirewallLogUpload(f);
    _fwLog.loaded     = true;
    _fwLog.available  = !!data.available;
    _fwLog.path       = data.path || f.name;
    _fwLog.entries    = data.entries || [];
    _fwLog.summary    = data.summary || _fwLog.summary;
    _fwLog.suspicious = data.suspicious || [];
    _fwLog.source     = 'upload';
  } catch (e) {
    _fwLog.error = (e && e.message) ? e.message : String(e);
  } finally {
    _fwLog.loading = false;
    if (target) target.value = '';  // reset so the same file re-triggers
    renderFirewallPage();
  }
}

export function fwSetFilter(arg) {
  // arg = "fAction:DROP" / "fProtocol:TCP" / etc.
  var parts = String(arg || '').split(':');
  var key = parts[0], value = parts[1];
  if (!key || !(key in _fwLog)) return;
  _fwLog[key] = value;
  renderFirewallPage();
}

export function fwSetSearch(arg, target) {
  _fwLog.fQuery = (target && target.value) || '';
  // Don't full-rerender on each keystroke — only repaint the table body.
  // Cheap enough for 5000 rows; if we ever need to debounce we can.
  var card = document.querySelector('.fw-entries-card');
  if (card && card.parentNode) {
    var newHtml = _fwTableHtml();
    var wrap = document.createElement('div');
    wrap.innerHTML = newHtml;
    card.parentNode.replaceChild(wrap.firstElementChild, card);
  }
}

export function fwBlockFromRow(ip) {
  if (!ip) return;
  // Open the existing add-block modal pre-filled with this IP. Reuses
  // the established Block-list staging flow rather than duplicating it.
  _fwLog._stagedFromIp = String(ip);
  // Switch to Block List tab and open the add modal there.
  _firewallTab = 'block-list';
  renderFirewallPage().then(function () {
    var modal = document.getElementById('add-block-modal');
    var ipInput = document.getElementById('add-block-ip');
    var commentInput = document.getElementById('add-block-comment');
    if (modal) modal.classList.add('open');
    if (ipInput) {
      ipInput.value = String(ip);
      ipInput.dispatchEvent(new Event('input'));  // re-validate
    }
    if (commentInput && !commentInput.value) {
      commentInput.value = 'Staged from firewall log: dropped probe';
    }
  });
}

export async function fwLookupFromRow(ip) {
  if (!ip) return;
  showToast('Looking up ' + ip + '…');
  try {
    var resp = await apiFetchIntel(String(ip));
    if (resp.status === 400) {
      toastError('Threat intel is off — add an AbuseIPDB API key in Settings.');
      return;
    }
    if (!resp.ok || !resp.data) {
      toastError('Lookup failed for ' + ip);
      return;
    }
    var d = resp.data;
    var label = d.score == null ? 'no data'
              : d.score >= 75 ? 'malicious'
              : d.score >= 25 ? 'suspicious'
              : 'clean';
    showToast(ip + ' — score ' + (d.score == null ? '—' : d.score) +
              ' (' + label + ')' +
              (d.country ? ' · ' + d.country : ''));
  } catch (e) {
    toastError('Lookup failed: ' + (e && e.message ? e.message : String(e)));
  }
}

// -----------------------------------------------------------------------
// Add IP manually modal
// -----------------------------------------------------------------------
function _renderAddBlockModal() {
  return '<div class="modal-overlay" id="add-block-modal" role="dialog" aria-label="Add IP to block list">' +
    '<div class="modal">' +
      '<h3>Add IP to block list</h3>' +
      '<p style="font-size:13px; color:var(--text-muted); line-height:1.55; margin:8px 0 14px;">' +
        'Stages an inbound deny rule for this IP. It will be pushed to Windows Firewall ' +
        'on the next <strong>Push all pending</strong>, or immediately if you tick ' +
        '<em>Push immediately</em> below (requires admin).' +
      '</p>' +
      '<label class="add-block-label" for="add-block-ip">IP address</label>' +
      '<input type="text" id="add-block-ip" class="add-block-input" autocomplete="off" ' +
        'spellcheck="false" placeholder="e.g. 203.0.113.5" ' +
        'data-action-input="addBlockInputCheck" />' +
      '<label class="add-block-label" for="add-block-comment">Comment (optional)</label>' +
      '<input type="text" id="add-block-comment" class="add-block-input" autocomplete="off" ' +
        'placeholder="Reason this IP is being blocked" />' +
      '<label class="add-block-checkbox">' +
        '<input type="checkbox" id="add-block-push" /> ' +
        '<span>Push immediately (admin required)</span>' +
      '</label>' +
      '<div class="modal-actions">' +
        '<button class="btn btn-with-icon" data-action="closeAddBlockModal"><i data-lucide="x"></i><span>Cancel</span></button>' +
        '<button class="btn btn-primary btn-with-icon" id="add-block-submit" ' +
          'data-action="submitAddBlock" disabled><i data-lucide="shield-plus"></i><span>Stage block</span></button>' +
      '</div>' +
    '</div>' +
  '</div>';
}

export function openAddBlockModal() {
  var m = document.getElementById('add-block-modal');
  if (!m) return;
  var ipEl = document.getElementById('add-block-ip');
  var cmEl = document.getElementById('add-block-comment');
  var pEl  = document.getElementById('add-block-push');
  var btn  = document.getElementById('add-block-submit');
  if (ipEl) ipEl.value = '';
  if (cmEl) cmEl.value = '';
  if (pEl)  pEl.checked = false;
  if (btn)  btn.disabled = true;
  m.classList.add('open');
  if (ipEl) setTimeout(function () { ipEl.focus(); }, 30);
}

export function closeAddBlockModal() {
  var m = document.getElementById('add-block-modal');
  if (m) m.classList.remove('open');
}

// Enables the submit button as soon as the IP field has a non-empty value.
// The backend does real validation — the frontend just guards against an
// obviously-empty submission.
export function addBlockInputCheck(arg, target) {
  var btn = document.getElementById('add-block-submit');
  if (!btn) return;
  btn.disabled = !(target && target.value.trim().length > 0);
}

export async function submitAddBlock() {
  var ip = (document.getElementById('add-block-ip') || {}).value || '';
  var comment = (document.getElementById('add-block-comment') || {}).value || '';
  var push = !!(document.getElementById('add-block-push') || {}).checked;
  ip = ip.trim();
  if (!ip) return;

  var btn = document.getElementById('add-block-submit');
  if (btn) { btn.disabled = true; btn.textContent = push ? 'Blocking\u2026' : 'Staging\u2026'; }

  try {
    var resp = await fetch('/api/block-ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip, comment: comment, confirm: push }),
    });
    var data = {};
    try { data = await resp.json(); } catch (e) {}
    if (!resp.ok) {
      toastError((data && data.message) || 'Could not add IP to block list.');
      if (btn) { btn.disabled = false; btn.textContent = 'Stage block'; }
      return;
    }
    var pushInfo = data && data.push;
    if (push && pushInfo && pushInfo.ok === false) {
      toastError('Staged ' + ip + ', but push failed: ' + (pushInfo.message || 'see CLI'));
    } else if (push && pushInfo && pushInfo.ok) {
      showToast('Blocked ' + ip);
    } else {
      showToast('Staged ' + ip + ' for blocking');
    }
    closeAddBlockModal();
    renderFirewallPage();
  } catch (e) {
    toastError('Network error while adding IP.');
    if (btn) { btn.disabled = false; btn.textContent = 'Stage block'; }
  }
}

// -----------------------------------------------------------------------
// Row-level actions
// -----------------------------------------------------------------------
export async function firewallPushOne(ip) {
  if (!ip) return;
  // Push all pending is the only API — pushing one row means pushing
  // every pending row, which is fine because rows already active stay
  // untouched. The result message makes this clear to the user.
  await _pushPending('Pushing ' + ip + '\u2026');
}

export async function firewallPushAll() {
  var pending = (_blockListCache.rows || []).filter(function (r) { return r.status === 'pending'; });
  if (pending.length === 0) return;
  var msg = 'Push ' + pending.length + ' pending IP' +
            (pending.length === 1 ? '' : 's') + ' to Windows Firewall now?';
  if (!window.confirm(msg)) return;
  await _pushPending('Pushing ' + pending.length + ' rule' +
    (pending.length === 1 ? '' : 's') + '\u2026');
}

// "Review" from the pending-changes banner — scrolls to the first
// pending row so the user can scan the staged IPs before committing.
export function firewallReviewPending() {
  var rows = (_blockListCache.rows || []);
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].status === 'pending') {
      var target = document.querySelectorAll('.data-table tbody tr')[i];
      if (target && target.scrollIntoView) {
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
        target.classList.add('pending-flash');
        setTimeout(function () { target.classList.remove('pending-flash'); }, 1200);
      }
      return;
    }
  }
}

// "Discard" from the pending-changes banner — drops every staged row
// via the same batch endpoint the bulk-unblock bar uses, so pending
// IPs never reach Windows Firewall. Tiered confirm keeps large discards
// from being single-click mistakes.
export async function firewallDiscardPending() {
  var pendingIps = (_blockListCache.rows || [])
    .filter(function (r) { return r.status === 'pending'; })
    .map(function (r) { return r.ip_address; });
  if (pendingIps.length === 0) return;
  if (!_confirmBulkUnblock(pendingIps.length)) return;
  var result = await apiUnblockBatch(pendingIps);
  if (!result.ok) {
    toastError('Discard failed: ' + ((result.data && result.data.detail) || 'network error'));
    return;
  }
  var deleted = result.data && typeof result.data.deleted === 'number' ? result.data.deleted : pendingIps.length;
  showToast('Discarded ' + deleted + ' pending change' + (deleted === 1 ? '' : 's'), 'success');
  _selectedIps = {};
  renderFirewallPage();
}

async function _pushPending(progressToast) {
  try {
    showToast(progressToast);
    var resp = await fetch('/api/block-list/push', { method: 'POST' });
    var data = {};
    try { data = await resp.json(); } catch (e) {}
    if (!resp.ok || data.ok === false) {
      toastError((data && data.message) || 'Push failed.');
    } else {
      showToast(data.message || 'Push complete.');
    }
    (data.failures || []).forEach(function (f) {
      toastError(f.ip + ': ' + (f.error || 'push failed'));
    });
  } catch (e) {
    toastError('Network error while pushing block list.');
  }
  renderFirewallPage();
}

export async function firewallUnblock(ip) {
  if (!ip) return;
  if (!window.confirm('Unblock ' + ip + '? The Windows Firewall rule will be removed.')) return;
  try {
    var resp = await fetch('/api/block-ip/' + encodeURIComponent(ip), { method: 'DELETE' });
    var data = {};
    try { data = await resp.json(); } catch (e) {}
    if (!resp.ok || data.ok === false) {
      toastError((data && data.message) || 'Unblock failed.');
      return;
    }
    showToast(data.message || ('Unblocked ' + ip));
  } catch (e) {
    toastError('Network error while unblocking.');
    return;
  }
  renderFirewallPage();
}

// Lucide icons inside the tab panel and empty states aren't present at
// _boot() time — they're rendered by renderFirewallPage, so we need a
// second createIcons() pass after every render.
function _hydrateLucide() {
  try {
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons();
    }
  } catch (e) { /* ignore */ }
}
