// sidebar-filters.js — Contextual filter panel that lives under the
// nav in the left sidebar. Each page registers its filter config once
// (group definitions + how selections map back into the page's state);
// on navigation, `updateSidebarFilters()` looks up the current page
// and renders the matching panel.
//
// This pass wires up the Findings page (Severity / Status / Assigned
// To / Host). Other pages register empty configs and the panel stays
// hidden on them — they can adopt this module in follow-up work.
'use strict';

import { escapeHtml } from './dashboard.js';

// --------------------------------------------------------------------
// Per-group collapse state (persisted) so the user's last open/closed
// choice survives navigation + reloads. Keyed per (page + groupId).
// --------------------------------------------------------------------
const _COLLAPSE_KEY = 'pulseSidebarFilterCollapsed';

function _loadCollapseMap() {
  try {
    var raw = localStorage.getItem(_COLLAPSE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch (e) { return {}; }
}
function _saveCollapseMap(map) {
  try { localStorage.setItem(_COLLAPSE_KEY, JSON.stringify(map)); } catch (e) {}
}
let _collapseMap = _loadCollapseMap();

function _isCollapsed(page, groupId) {
  return !!(_collapseMap[page] && _collapseMap[page][groupId]);
}
function _setCollapsed(page, groupId, collapsed) {
  if (!_collapseMap[page]) _collapseMap[page] = {};
  _collapseMap[page][groupId] = !!collapsed;
  _saveCollapseMap(_collapseMap);
}

// --------------------------------------------------------------------
// Page registry. Each entry is a function that returns either `null`
// (panel hidden on this page) or an object:
//   {
//     clearActive: bool,         // any filter currently applied?
//     onClear: () => void,       // wipe all filters for this page
//     groups: [{
//       id: string,
//       label: string,
//       items: [{ id, label, count, dotColor?, checked }],
//       onToggle: (itemId, checked) => void,
//     }]
//   }
// --------------------------------------------------------------------
const _pageConfigs = Object.create(null);

export function registerSidebarFilterConfig(page, buildFn) {
  _pageConfigs[page] = buildFn;
}

// Read the current page from navigation.js (imported lazily to avoid
// a cycle with navigation → dashboard → this module).
async function _getCurrentPage() {
  try {
    var nav = await import('./navigation.js');
    return nav.getCurrentPage ? nav.getCurrentPage() : (nav.currentPage || 'dashboard');
  } catch (e) {
    return 'dashboard';
  }
}

// --------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------

// Called by navigation.js after every page change and by page render
// functions whose filter state changed (so counts stay fresh).
export async function updateSidebarFilters() {
  var mount = document.getElementById('sidebar-filters');
  if (!mount) return;
  var page = await _getCurrentPage();
  var build = _pageConfigs[page];
  var cfg = build ? build() : null;
  if (!cfg || !cfg.groups || !cfg.groups.length) {
    mount.hidden = true;
    mount.innerHTML = '';
    return;
  }
  mount.hidden = false;
  mount.innerHTML = _renderConfig(page, cfg);
  _bindHandlers(mount, page, cfg);
}

function _renderConfig(page, cfg) {
  var clearLink = cfg.clearActive
    ? '<a class="sidebar-filter-clear" data-action="clearSidebarFilters">Clear filters</a>'
    : '';
  var groupsHtml = cfg.groups.map(function (g) {
    var collapsed = _isCollapsed(page, g.id);
    var itemsHtml = g.items.map(function (item, idx) {
      var dot = item.dotColor
        ? '<span class="sidebar-filter-dot" style="background:' + item.dotColor + '"></span>'
        : '';
      return '<li data-group="' + escapeHtml(g.id) + '" data-item="' + escapeHtml(String(item.id)) + '">' +
        '<input type="checkbox"' + (item.checked ? ' checked' : '') + ' />' +
        dot +
        '<span class="sidebar-filter-label" title="' + escapeHtml(item.label) + '">' +
          escapeHtml(item.label) +
        '</span>' +
        '<span class="sidebar-filter-count">' + (item.count != null ? item.count : '') + '</span>' +
      '</li>';
    }).join('');
    var activeCount = g.items.filter(function (i) { return i.checked; }).length;
    var badge = activeCount ? '<span class="sidebar-filter-group-badge">' + activeCount + '</span>' : '';
    return '<div class="sidebar-filter-group' + (collapsed ? ' is-collapsed' : '') + '" ' +
      'data-group="' + escapeHtml(g.id) + '">' +
      '<button type="button" class="sidebar-filter-group-head" ' +
        'data-action="toggleSidebarFilterGroup" data-arg="' + escapeHtml(g.id) + '">' +
        '<span class="sidebar-filter-chevron" aria-hidden="true">' +
          '<svg viewBox="0 0 12 12" width="12" height="12" fill="none" ' +
            'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
            '<path d="M3 4.5 L6 7.5 L9 4.5"/>' +
          '</svg>' +
        '</span>' +
        '<span class="sidebar-filter-group-label">' + escapeHtml(g.label) + '</span>' +
        badge +
      '</button>' +
      '<ul class="sidebar-filter-list">' + itemsHtml + '</ul>' +
    '</div>';
  }).join('');
  return clearLink + groupsHtml;
}

function _bindHandlers(mount, page, cfg) {
  // Checkbox toggles — delegate one listener across the whole panel.
  mount.addEventListener('change', function (e) {
    var t = e.target;
    if (!t || t.type !== 'checkbox') return;
    var li = t.closest('li[data-group]');
    if (!li) return;
    var groupId = li.getAttribute('data-group');
    var itemId  = li.getAttribute('data-item');
    var group = cfg.groups.find(function (g) { return g.id === groupId; });
    if (!group || typeof group.onToggle !== 'function') return;
    group.onToggle(itemId, t.checked);
    // Re-render to refresh counts + the Clear Filters link.
    updateSidebarFilters();
  });
}

// Expose group-collapse + clear handlers to the global action registry.
// app.js imports these and wires them up via data-action.
export function toggleSidebarFilterGroup(groupId) {
  _getCurrentPage().then(function (page) {
    _setCollapsed(page, groupId, !_isCollapsed(page, groupId));
    updateSidebarFilters();
  });
}

export function clearSidebarFilters() {
  _getCurrentPage().then(function (page) {
    var build = _pageConfigs[page];
    var cfg = build ? build() : null;
    if (cfg && typeof cfg.onClear === 'function') cfg.onClear();
    updateSidebarFilters();
  });
}
