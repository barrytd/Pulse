// whitelist.js — Whitelist page. Reads config, posts changes via
// api.js wrappers, and renders a typed table with optional built-ins.
'use strict';

import {
  apiGetConfig,
  apiWhitelistBuiltin,
  apiSaveWhitelist,
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
};

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

  var typeOpts = WL_TYPES.map(function (t) {
    var sel = whitelistState.addType === t.key ? ' selected' : '';
    return '<option value="' + t.key + '"' + sel + '>' + t.label + '</option>';
  }).join('');

  c.innerHTML =
    '<div class="page-head">' +
      '<div class="page-head-title"><strong>' + customRows.length + '</strong> custom, ' +
        builtin.length + ' built-in</div>' +
      '<div class="page-head-actions">' +
        '<label class="form-checkbox" style="font-size:12px;">' +
          '<input type="checkbox"' + (whitelistState.showBuiltin ? ' checked' : '') +
          ' data-action-change="toggleBuiltinWhitelist" /> Show built-in entries' +
        '</label>' +
      '</div>' +
    '</div>' +

    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">Add Entry</div>' +
      '<div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">' +
        '<select id="wl-add-type" data-action-change="setWhitelistAddType" style="padding:8px 10px; background:var(--card-bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-size:13px;">' +
          typeOpts +
        '</select>' +
        '<input type="text" id="wl-add-value" class="search-box" style="flex:1;" placeholder="Value (e.g. service name, account, IP)" ' +
          'data-action-keydown="whitelistAddValueKey" />' +
        '<button class="btn btn-primary" data-action="addWhitelistEntry">Add</button>' +
      '</div>' +
      '<p style="font-size:11px; color:var(--text-muted); margin-top:8px;">' +
        'Changes save to <span class="mono" style="color:var(--accent);">pulse.yaml</span> immediately. Built-in entries are always active and cannot be removed.' +
      '</p>' +
    '</div>' +

    '<div class="card" style="padding:0; overflow:hidden;">' +
      (rows.length === 0
        ? '<div style="text-align:center; padding:32px; color:var(--text-muted);">No whitelist entries yet.</div>'
        : _buildWhitelistTable(rows)) +
    '</div>';
}

function _buildWhitelistTable(rows) {
  return '<table class="data-table">' +
    '<thead><tr>' +
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
      return '<tr>' +
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

// Wired via data-action-change on the type <select>. Mirrors the old
// inline "whitelistState.addType = this.value" onchange.
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
