// whitelist.js — Whitelist page. Reads config, posts changes via
// api.js wrappers, and renders a typed table with optional built-ins.
// Bulk-select mirrors the Scans page pattern — per-row checkbox plus a
// sticky action bar — but only custom rows carry a checkbox since
// built-ins live in code and can't be removed at runtime.
'use strict';

import {
  apiGetConfig,
  apiWhitelistBuiltin,
  apiSaveWhitelist,
  apiDeleteWhitelistEntries,
} from './api.js';
import {
  escapeHtml,
  attrEscape,
  showToast,
  toastError,
} from './dashboard.js';

const WL_TYPES = [
  { key: 'accounts', label: 'Account', plural: 'accounts' },
  { key: 'services', label: 'Service', plural: 'services' },
  { key: 'ips',      label: 'IP',      plural: 'ips' },
  { key: 'rules',    label: 'Rule',    plural: 'rules' },
];

// Module-scoped state. Was window.whitelistState in the IIFE era.
const whitelistState = {
  showBuiltin: false,
  addType: 'accounts',
  addValue: '',
  // Selected custom entries, keyed "<type>|<value>" so the same value
  // appearing under different types doesn't collide.
  selected: {},
};

function _selectionKey(key, value) {
  return key + '|' + value;
}

function _selectedEntries() {
  return Object.keys(whitelistState.selected).map(function (k) {
    var i = k.indexOf('|');
    return { key: k.slice(0, i), value: k.slice(i + 1) };
  });
}

export async function renderWhitelistPage() {
  var c = document.getElementById('content');
  c.innerHTML = '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading...</div>';

  var config = await apiGetConfig();
  var wl = config.whitelist || { accounts: [], services: [], ips: [], rules: [] };

  var bi = await apiWhitelistBuiltin();
  var builtin = bi.services || [];

  // Flatten custom entries into one list for the table.
  var customRows = [];
  WL_TYPES.forEach(function (t) {
    (wl[t.key] || []).forEach(function (v) {
      customRows.push({ type: t.label, key: t.key, value: v, origin: 'custom' });
    });
  });

  // Optional built-in rows (services-only).
  var builtinRows = builtin.map(function (s) {
    return { type: 'Service', key: 'services', value: s, origin: 'builtin' };
  });

  var rows = customRows.concat(whitelistState.showBuiltin ? builtinRows : []);

  // Drop any selections that no longer correspond to a current custom row.
  var validKeys = {};
  customRows.forEach(function (r) { validKeys[_selectionKey(r.key, r.value)] = true; });
  Object.keys(whitelistState.selected).forEach(function (k) {
    if (!validKeys[k]) delete whitelistState.selected[k];
  });

  var typeOpts = WL_TYPES.map(function (t) {
    var sel = whitelistState.addType === t.key ? ' selected' : '';
    return '<option value="' + t.key + '"' + sel + '>' + t.label + '</option>';
  }).join('');

  var nSelected = _selectedEntries().length;
  var deleteBarStyle = nSelected > 0 ? 'flex' : 'none';

  // Per-type counts for the KPI strip. The blueprint calls for an
  // anti-sprawl row here — total / expiring / never-expire / etc — but
  // until the whitelist schema grows expiration metadata, the type
  // breakdown is the highest-signal view we can render.
  var counts = {
    accounts: (wl.accounts || []).length,
    services: (wl.services || []).length,
    ips:      (wl.ips || []).length,
    rules:    (wl.rules || []).length,
  };
  var kpiStripHtml =
    '<div class="whitelist-kpi-strip">' +
      '<div class="whitelist-kpi-tile tone-neutral">' +
        '<div class="whitelist-kpi-label">Custom entries</div>' +
        '<div class="whitelist-kpi-value">' + customRows.length + '</div>' +
      '</div>' +
      '<div class="whitelist-kpi-tile tone-info">' +
        '<div class="whitelist-kpi-label">Accounts</div>' +
        '<div class="whitelist-kpi-value">' + counts.accounts + '</div>' +
      '</div>' +
      '<div class="whitelist-kpi-tile tone-info">' +
        '<div class="whitelist-kpi-label">Services</div>' +
        '<div class="whitelist-kpi-value">' + counts.services + '</div>' +
      '</div>' +
      '<div class="whitelist-kpi-tile tone-info">' +
        '<div class="whitelist-kpi-label">IPs</div>' +
        '<div class="whitelist-kpi-value">' + counts.ips + '</div>' +
      '</div>' +
      '<div class="whitelist-kpi-tile tone-info">' +
        '<div class="whitelist-kpi-label">Rules</div>' +
        '<div class="whitelist-kpi-value">' + counts.rules + '</div>' +
      '</div>' +
      '<div class="whitelist-kpi-tile tone-off">' +
        '<div class="whitelist-kpi-label">Built-in</div>' +
        '<div class="whitelist-kpi-value">' + builtin.length + '</div>' +
      '</div>' +
    '</div>';

  c.innerHTML =
    '<div class="page-head">' +
      '<div class="page-head-title">Whitelist</div>' +
      '<div class="page-head-actions">' +
        '<label class="form-checkbox" style="font-size:12px;">' +
          '<input type="checkbox"' + (whitelistState.showBuiltin ? ' checked' : '') +
          ' data-action-change="toggleBuiltinWhitelist" /> Show built-in entries' +
        '</label>' +
      '</div>' +
    '</div>' +
    kpiStripHtml +

    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">Add Entry</div>' +
      '<div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">' +
        '<select id="wl-add-type" data-action-change="setWhitelistAddType" style="padding:8px 10px; background:var(--card-bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-size:13px;">' +
          typeOpts +
        '</select>' +
        '<input type="text" id="wl-add-value" class="search-box" style="flex:1;" placeholder="Value (e.g. service name, account, IP)" ' +
          'data-action-keydown="whitelistAddValueKey" />' +
        '<button class="btn btn-primary btn-with-icon" data-action="addWhitelistEntry"><i data-lucide="plus"></i><span>Add</span></button>' +
      '</div>' +
      '<p style="font-size:11px; color:var(--text-muted); margin-top:8px;">' +
        'Changes save to <span class="mono" style="color:var(--accent);">pulse.yaml</span> immediately. Built-in entries are always active and cannot be removed.' +
      '</p>' +
    '</div>' +

    '<div id="whitelist-delete-bar" class="bulk-bar" style="display:' + deleteBarStyle + ';">' +
      '<span class="bulk-bar-count">' + nSelected + ' selected</span>' +
      '<button class="btn btn-danger" id="whitelist-delete-btn" data-action="deleteSelectedWhitelist">' +
        'Delete ' + nSelected + ' entr' + (nSelected === 1 ? 'y' : 'ies') +
      '</button>' +
      '<a class="bulk-bar-clear" data-action="toggleWhitelistSelectAll" data-arg="false">Clear selection</a>' +
    '</div>' +

    (customRows.length === 0
      // Empty state — shown when the user has no custom entries. The
      // table card still appears below if the operator has toggled
      // "Show built-in entries" on, so they can browse the 100+ rows
      // of always-on services without losing the onboarding panel.
      ? _whitelistEmptyStateHtml(builtin.length) +
        (whitelistState.showBuiltin && builtinRows.length > 0
          ? '<div class="card" style="padding:0; overflow:hidden; margin-top:16px;">' +
              _buildWhitelistTable(builtinRows, customRows) +
            '</div>'
          : '')
      : '<div class="card" style="padding:0; overflow:hidden;">' +
          _buildWhitelistTable(rows, customRows) +
        '</div>');
}

// First-run / cleared-out empty state for the Whitelist page. Reads as
// "here's what this is for and why you'd add one" — the old single-line
// "No whitelist entries yet." gave operators no on-ramp.
function _whitelistEmptyStateHtml(builtinCount) {
  // Inline SVG instead of Lucide — Lucide is reserved for sidebar nav,
  // user-avatar dropdown, and Settings tab nav (per project convention).
  // Filter-funnel glyph reads as "suppress" without leaning on a brand.
  var iconSvg =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
      'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" ' +
      'aria-hidden="true">' +
      '<path d="M3 5h18l-7 9v6l-4-2v-4z"/>' +
    '</svg>';
  // Built-in count is dynamic — the constant 137 in the spec was a
  // representative figure; this stays accurate as KNOWN_GOOD_SERVICES
  // grows. The note hides the literal number when something has gone
  // wrong fetching built-ins so we don't show "0 built-in entries".
  var builtinLine = builtinCount > 0
    ? '<p class="wl-empty-builtin">' +
        '<strong>' + builtinCount + ' built-in entries</strong> are always active. ' +
        'Toggle <em>Show built-in entries</em> to see them.' +
      '</p>'
    : '';
  return '<div class="wl-empty">' +
    '<div class="wl-empty-icon">' + iconSvg + '</div>' +
    '<h3 class="wl-empty-title">No custom whitelist entries yet</h3>' +
    '<p class="wl-empty-subtitle">' +
      'Suppress known-good activity that triggers false positives. For example, ' +
      'whitelist a service account like <code>SYSTEM</code> or a backup agent IP ' +
      'that triggers <em>Scheduled Task Created</em> or <em>Brute Force</em> rules.' +
    '</p>' +
    '<div class="wl-empty-actions">' +
      '<button class="btn btn-primary" data-action="focusWhitelistAddInput">' +
        'Add your first entry' +
      '</button>' +
      '<button class="btn btn-secondary" data-action="toggleWhitelistLearnMore" ' +
        'aria-expanded="false" aria-controls="wl-learn-more">' +
        'Learn more' +
      '</button>' +
    '</div>' +
    '<div id="wl-learn-more" class="wl-empty-learn" hidden>' +
      '<dl>' +
        '<dt>Account</dt>' +
        '<dd>A Windows user or service account name (e.g. <code>SYSTEM</code>, ' +
          '<code>backup-svc$</code>). Suppresses findings whose <em>Account</em> ' +
          'field matches.</dd>' +
        '<dt>Service</dt>' +
        '<dd>A Windows service name (e.g. <code>WinDefend</code>). Suppresses ' +
          '<em>Service Installed</em> findings for that service.</dd>' +
        '<dt>IP</dt>' +
        '<dd>An IPv4 address or CIDR. Suppresses authentication and lateral-' +
          'movement findings whose source IP matches — useful for backup agents ' +
          'and scanners.</dd>' +
        '<dt>Rule</dt>' +
        '<dd>A detection rule name (e.g. <code>Scheduled Task Created</code>). ' +
          'Disables that rule entirely. Use sparingly — the more targeted ' +
          'Account / Service / IP forms are usually a better fit.</dd>' +
      '</dl>' +
    '</div>' +
    builtinLine +
  '</div>';
}

function _buildWhitelistTable(rows, customRows) {
  var allCustomSelected = customRows.length > 0 && customRows.every(function (r) {
    return whitelistState.selected[_selectionKey(r.key, r.value)];
  });
  var headCheckbox = '<th style="width:32px;">' +
    (customRows.length > 0
      ? '<input type="checkbox" id="whitelist-select-all" ' +
        (allCustomSelected ? 'checked ' : '') +
        'data-action="toggleWhitelistSelectAll" aria-label="Select all custom entries" />'
      : '') +
    '</th>';

  return '<table class="data-table">' +
    '<thead><tr>' +
      headCheckbox +
      '<th>Type</th><th>Value</th><th>Source</th><th style="width:60px; text-align:right;">Actions</th>' +
    '</tr></thead><tbody>' +
    rows.map(function (r) {
      var badge = r.origin === 'builtin'
        ? '<span class="origin-badge builtin">built-in</span>'
        : '<span class="origin-badge custom">custom</span>';
      var action = r.origin === 'custom'
        ? '<button class="icon-btn" title="Remove" data-wl-key="' + escapeHtml(r.key) +
          '" data-wl-value="' + attrEscape(r.value) + '" data-action="removeWhitelistRowBtn">\u2715</button>'
        : '';
      var selectCell = '';
      if (r.origin === 'custom') {
        var k = _selectionKey(r.key, r.value);
        var checked = whitelistState.selected[k] ? 'checked' : '';
        selectCell = '<input type="checkbox" ' + checked +
          ' data-action="toggleWhitelistSelect" data-arg="' + attrEscape(k) +
          '" aria-label="Select entry" />';
      }
      return '<tr>' +
        '<td data-action="stopClickPropagation" style="width:32px;">' + selectCell + '</td>' +
        '<td>' + r.type + '</td>' +
        '<td class="mono">' + escapeHtml(r.value) + '</td>' +
        '<td>' + badge + '</td>' +
        '<td style="text-align:right;">' + action + '</td>' +
      '</tr>';
    }).join('') +
    '</tbody></table>';
}

export function toggleBuiltinWhitelist(show, target) {
  // When called via data-action-change, `show` is the data-arg (undef)
  // and the checkbox is the target. Read the live checked state.
  if (show === undefined && target && typeof target.checked === 'boolean') {
    show = target.checked;
  }
  whitelistState.showBuiltin = !!show;
  renderWhitelistPage();
}

export function toggleWhitelistSelect(key, target, ev) {
  if (ev) ev.stopPropagation();
  if (!key) return;
  if (whitelistState.selected[key]) delete whitelistState.selected[key];
  else whitelistState.selected[key] = true;
  // Re-render just enough to update the bulk bar + header-checkbox —
  // a full page re-render would re-fetch config. The bar count is
  // stored in-DOM so patch it directly.
  renderWhitelistPage();
}

export async function toggleWhitelistSelectAll(arg, target) {
  var checked;
  if (target && typeof target.checked === 'boolean') checked = target.checked;
  else checked = (arg === true || arg === 'true');
  whitelistState.selected = {};
  if (checked) {
    var config = await apiGetConfig();
    var wl = config.whitelist || {};
    WL_TYPES.forEach(function (t) {
      (wl[t.key] || []).forEach(function (v) {
        whitelistState.selected[_selectionKey(t.key, v)] = true;
      });
    });
  }
  renderWhitelistPage();
}

// Tiered confirmation matching the Firewall page — cheap path stays
// cheap; catastrophic bulk deletes require a typed confirmation so a
// stray click can't wipe the whole whitelist.
function _confirmBulkWhitelistDelete(count) {
  if (count <= 10) {
    return window.confirm('Delete ' + count + ' whitelist entr' +
      (count === 1 ? 'y' : 'ies') + '? This cannot be undone.');
  }
  if (count <= 50) {
    return window.confirm('Delete ' + count + ' whitelist entries?\n\n' +
      'Findings previously suppressed by these entries will start alerting again ' +
      'on the next scan. This cannot be undone.');
  }
  var expected = 'DELETE ' + count + ' ENTRIES';
  var entered = window.prompt(
    'You are about to delete ' + count + ' whitelist entries. This cannot be undone.\n\n' +
    'Type "' + expected + '" exactly to confirm.'
  );
  return entered === expected;
}

export async function deleteSelectedWhitelist() {
  var entries = _selectedEntries();
  if (entries.length === 0) return;
  if (!_confirmBulkWhitelistDelete(entries.length)) return;
  var result = await apiDeleteWhitelistEntries(entries);
  if (!result.ok) {
    toastError('Delete failed: ' + ((result.data && result.data.detail) || 'network error'));
    return;
  }
  var deleted = result.data && typeof result.data.deleted === 'number' ? result.data.deleted : entries.length;
  showToast('Removed ' + deleted + ' entr' + (deleted === 1 ? 'y' : 'ies'), 'success');
  whitelistState.selected = {};
  renderWhitelistPage();
}

// Empty-state CTA: scroll to the Add Entry card and put focus inside the
// value input so the user can start typing immediately.
export function focusWhitelistAddInput() {
  var input = document.getElementById('wl-add-value');
  if (!input) return;
  input.scrollIntoView({ behavior: 'smooth', block: 'center' });
  // Defer one frame so the smooth-scroll doesn't fight the focus-jump.
  requestAnimationFrame(function () {
    try { input.focus({ preventScroll: true }); } catch (e) { input.focus(); }
  });
}

// Empty-state CTA: toggle the inline "Account / Service / IP / Rule"
// reference block under the empty state. Avoids navigating away to docs
// — the explanation lives next to the form so it's there when the user
// is actively deciding what to add.
export function toggleWhitelistLearnMore(arg, target) {
  var box = document.getElementById('wl-learn-more');
  if (!box) return;
  var open = !box.hidden;
  box.hidden = open;
  if (target) target.setAttribute('aria-expanded', open ? 'false' : 'true');
}

// Wired via data-action-change on the type <select>.
export function setWhitelistAddType(arg, target) {
  if (target && typeof target.value === 'string') {
    whitelistState.addType = target.value;
  }
}

// Wired via data-action-keydown on the value input. Submit on Enter.
export function whitelistAddValueKey(arg, target, e) {
  if (e && e.key === 'Enter') addWhitelistEntry();
}

export async function addWhitelistEntry() {
  var type  = document.getElementById('wl-add-type').value;
  var input = document.getElementById('wl-add-value');
  var value = input.value.trim();
  if (!value) return;

  var config = await apiGetConfig();
  var items = (config.whitelist && config.whitelist[type]) || [];
  if (items.indexOf(value) !== -1) {
    toastError('Already in whitelist.');
    return;
  }
  items.push(value);

  var body = {};
  body[type] = items;
  try {
    var r = await apiSaveWhitelist(body);
    if (!r.ok) throw new Error('Save failed');
    showToast('Added to whitelist');
    input.value = '';
    renderWhitelistPage();
  } catch (e) {
    toastError('Could not save whitelist.');
  }
}

export async function removeWhitelistRow(key, value) {
  try {
    var config = await apiGetConfig();
    var items = ((config.whitelist && config.whitelist[key]) || []).filter(function (v) { return v !== value; });
    var body = {};
    body[key] = items;
    var r = await apiSaveWhitelist(body);
    if (!r.ok) throw new Error('Save failed');
    delete whitelistState.selected[_selectionKey(key, value)];
    showToast('Removed');
    renderWhitelistPage();
  } catch (e) {
    toastError('Could not remove entry.');
  }
}

export function removeWhitelistRowBtn(arg, target) {
  // Delegator hands us (arg, target, event). Fall back to arg being
  // the button itself so legacy callers keep working.
  var btn = (target && target.getAttribute) ? target : arg;
  if (!btn || !btn.getAttribute) return;
  return removeWhitelistRow(btn.getAttribute('data-wl-key'), btn.getAttribute('data-wl-value'));
}
