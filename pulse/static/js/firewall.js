// firewall.js — Firewall page (Block List + Firewall Rules tabs).
// The Block List tab shows every row in the Pulse IP block list with
// per-row Push / Unblock actions, plus a top action bar for bulk push
// and manual add. The Firewall Rules tab is a placeholder for the
// pfirewall.log parser landing in a later sprint.
'use strict';

import { escapeHtml, showToast, toastError } from './dashboard.js';
import { apiUnblockBatch } from './api.js';

// Tab state persists across navigation so a user who switched to
// "Firewall Rules" and went elsewhere comes back to the same tab.
let _firewallTab = 'block-list'; // 'block-list' | 'rules'
let _blockListCache = { rows: [], windows: false, is_admin: false };
// ip -> true. Matches the Scans page selection model.
let _selectedIps = {};

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
          '<button class="btn btn-sm" data-action="firewallReviewPending">Review</button>' +
          '<button class="btn btn-sm btn-primary" data-action="firewallPushAll">Push now</button>' +
          '<button class="btn btn-sm btn-danger" data-action="firewallDiscardPending">Discard</button>' +
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
        '<button class="btn btn-primary" data-action="openAddBlockModal">Add IP manually</button>' +
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
    '<button class="btn btn-primary" data-action="openAddBlockModal">Add IP manually</button>' +
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
  var added = row.added_at ? escapeHtml(row.added_at) :
              '<span style="color:var(--text-light);">\u2014</span>';
  var pushed = row.pushed_at ? escapeHtml(row.pushed_at) :
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
// Firewall Rules tab — placeholder for the pfirewall.log parser work
// -----------------------------------------------------------------------
function _renderRulesTab() {
  return '<div class="card firewall-empty">' +
    '<div class="firewall-empty-icon"><i data-lucide="clock"></i></div>' +
    '<h3>Firewall Rules</h3>' +
    '<p>Firewall log parsing coming in Sprint 4. Once enabled, blocked and ' +
      'allowed connections from <span class="mono">pfirewall.log</span> will appear here.</p>' +
  '</div>';
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
        '<button class="btn" data-action="closeAddBlockModal">Cancel</button>' +
        '<button class="btn btn-primary" id="add-block-submit" ' +
          'data-action="submitAddBlock" disabled>Stage block</button>' +
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
