// notifications.js — Bell-icon feed in the topbar.
//
// Lifecycle:
//   1. `mountNotifBell()` runs once at boot (app.js DOMContentLoaded).
//      It does an initial fetch + paint of the badge and starts a 60s
//      poll for the unread count.
//   2. `toggleNotifMenu()` opens / closes the dropdown panel. Opening
//      issues a single fetch for the latest 50 rows, fires a mark-as-read
//      POST, and zeroes the badge.
//   3. Clicking outside the dropdown or pressing Escape closes it.
//
// State is module-scoped (no class) — there's only one bell on the page.
'use strict';

import {
  apiListNotifications,
  apiMarkNotificationsRead,
} from './api.js';
import { escapeHtml, relTimeHtml } from './dashboard.js';
import { navigate } from './navigation.js';

let _open = false;
let _pollTimer = null;

const POLL_MS = 60_000;

// type -> { icon, kind } where icon is a Lucide name. The bell, the user
// avatar, and the Settings tab nav are the three places we're allowed to
// use Lucide; the dropdown row icons sit alongside the bell so they're
// part of that same surface.
const TYPE_META = {
  scan_complete:    { icon: 'file-check-2',  label: 'scan'      },
  finding_assigned: { icon: 'user-check',    label: 'assigned'  },
  monitor_alert:    { icon: 'activity',      label: 'live'      },
  scheduled_scan:   { icon: 'calendar-clock',label: 'scheduled' },
  firewall_block:   { icon: 'shield',        label: 'firewall'  },
};

function _setBadge(count) {
  var el = document.getElementById('notif-bell-badge');
  if (!el) return;
  if (count && count > 0) {
    el.textContent = count > 99 ? '99+' : String(count);
    el.hidden = false;
  } else {
    el.hidden = true;
  }
}

function _setSub(unread, total) {
  var el = document.getElementById('notif-dropdown-sub');
  if (!el) return;
  if (total === 0) {
    el.textContent = 'No notifications';
  } else if (unread > 0) {
    el.textContent = unread + ' unread · ' + total + ' recent';
  } else {
    el.textContent = total + ' recent';
  }
}

function _renderList(rows) {
  var list = document.getElementById('notif-dropdown-list');
  if (!list) return;
  if (!rows || rows.length === 0) {
    list.innerHTML = '<div class="notif-empty">No notifications yet.</div>';
    return;
  }
  list.innerHTML = rows.map(function (n, i) {
    var meta = TYPE_META[n.type] || { icon: 'bell', label: 'event' };
    var unreadCls = n.read ? '' : ' is-unread';
    var msg = escapeHtml(n.message || '');
    return '<button type="button" class="notif-row' + unreadCls + '" ' +
      'data-action="openNotifTarget" data-arg="' + i + '">' +
      '<span class="notif-row-icon" data-kind="' + escapeHtml(n.type) + '">' +
        '<i data-lucide="' + meta.icon + '"></i>' +
      '</span>' +
      '<span class="notif-row-body">' +
        '<span class="notif-row-msg">' + msg + '</span>' +
        '<span class="notif-row-time">' + relTimeHtml(n.created_at) + '</span>' +
      '</span>' +
      '<span class="notif-row-dot" aria-hidden="true"></span>' +
    '</button>';
  }).join('');
  // Hydrate Lucide icons for the freshly-injected rows.
  try {
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons();
    }
  } catch (e) {}
}

// Cached rows so a click can resolve a target without another fetch.
let _lastRows = [];

async function _refreshBadge() {
  try {
    var data = await apiListNotifications(1);
    _setBadge(data.unread_count || 0);
  } catch (e) { /* best-effort */ }
}

async function _refreshFull() {
  try {
    var data = await apiListNotifications(50);
    _lastRows = data.notifications || [];
    _renderList(_lastRows);
    _setSub(data.unread_count || 0, _lastRows.length);
  } catch (e) {
    var list = document.getElementById('notif-dropdown-list');
    if (list) list.innerHTML = '<div class="notif-empty">Failed to load notifications.</div>';
  }
}

function _close() {
  _open = false;
  var dd = document.getElementById('notif-dropdown');
  if (dd) dd.hidden = true;
  document.removeEventListener('click', _outsideClick, true);
  document.removeEventListener('keydown', _onKey, true);
}

function _outsideClick(e) {
  var menu = document.getElementById('notif-menu');
  if (menu && !menu.contains(e.target)) _close();
}

function _onKey(e) {
  if (e.key === 'Escape') _close();
}

export function toggleNotifMenu() {
  var dd = document.getElementById('notif-dropdown');
  if (!dd) return;
  if (_open) { _close(); return; }
  _open = true;
  dd.hidden = false;
  // Fetch + paint, then mark all read so the badge clears on the next
  // poll. Optimistic clear of the local badge so the click feels instant.
  _refreshFull();
  apiMarkNotificationsRead().then(function () {
    _setBadge(0);
    // Refresh sub-line after the read flip so "unread X" disappears.
    _refreshFull();
  }).catch(function () { /* best-effort */ });
  // Defer the outside-click listener by one tick so the click that
  // opened the menu doesn't immediately close it.
  setTimeout(function () {
    document.addEventListener('click', _outsideClick, true);
    document.addEventListener('keydown', _onKey, true);
  }, 0);
}

// Click on a notification row — navigate to a sensible target if we can.
export function openNotifTarget(idx) {
  var n = _lastRows[Number(idx)];
  if (!n) { _close(); return; }
  _close();
  // Mapping is deliberately conservative: send the user to the page that
  // most likely shows the relevant context. Per-row deep-linking can
  // arrive later (e.g. open the specific finding drawer) without a wire
  // change — this surface only depends on the action name.
  if (n.ref_kind === 'finding') {
    navigate('findings');
    return;
  }
  if (n.ref_kind === 'scan' && n.ref_id) {
    navigate('scans', { scanId: n.ref_id });
    return;
  }
  if (n.type === 'monitor_alert' || n.ref_kind === 'session') {
    navigate('monitor');
    return;
  }
  if (n.type === 'firewall_block' || n.ref_kind === 'firewall') {
    navigate('firewall');
    return;
  }
  navigate('scans');
}

export function mountNotifBell() {
  // Initial paint + start polling.
  _refreshBadge();
  if (_pollTimer) clearInterval(_pollTimer);
  _pollTimer = setInterval(_refreshBadge, POLL_MS);
}
