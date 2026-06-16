// roles.js — front-end role model: which pages a role may see, the default
// landing page per role, and sidebar gating. The BACKEND is the real gate
// (every admin/manager endpoint enforces its role); this is the UX layer so
// users don't see nav they can't use and land somewhere useful.
'use strict';

var ROLE_RANK = { analyst: 1, manager: 2, admin: 3 };

// Pages that require a role ABOVE analyst. Anything not listed is visible to
// every signed-in user (analyst+). Response actions + config + the audit log
// are manager / admin only.
var PAGE_MIN_ROLE = {
  firewall:  'manager',   // blocking/unblocking is a response action
  whitelist: 'manager',   // detection config
  rules:     'manager',   // detection config
  audit:     'admin',     // security audit log
};

// Current role, resolved once at boot. null = unknown (treat as full access
// so a failed /api/me never locks anyone out — the backend still enforces).
var _currentRole = null;

export function normalizeRole(role) {
  var r = String(role || '').toLowerCase();
  if (r === 'viewer') r = 'analyst';   // legacy alias
  return ROLE_RANK[r] ? r : null;
}

export function setCurrentRole(role) { _currentRole = normalizeRole(role); }
export function getCurrentRole() { return _currentRole; }

// Can `role` reach `page`? Unknown role (null) passes — fail open in the UI,
// the backend still blocks the actual data.
export function canAccessPage(page, role) {
  role = normalizeRole(role);
  if (!role) return true;
  var need = PAGE_MIN_ROLE[page];
  if (!need) return true;
  return (ROLE_RANK[role] || 0) >= (ROLE_RANK[need] || 0);
}

// Where each role lands when they open the app at the bare root: analysts
// open straight into their queue; managers/admins get the dashboard.
export function defaultLanding(role) {
  return normalizeRole(role) === 'analyst' ? 'queue' : 'dashboard';
}

// Paint the topbar role pill so the signed-in role is always visible.
export function paintRoleBadge(role) {
  var el = document.getElementById('topbar-role-badge');
  if (!el) return;
  role = normalizeRole(role);
  if (!role) { el.hidden = true; el.textContent = ''; return; }
  el.textContent = role === 'admin' ? 'Admin'
                 : role === 'manager' ? 'Manager'
                 : 'Analyst';
  el.className = 'topbar-role-badge role-' + role;
  el.hidden = false;
}

// Hide sidebar nav items the role can't use, and collapse any group whose
// items all became hidden so no label is left orphaned.
export function applyRoleToSidebar(role) {
  role = normalizeRole(role);
  document.querySelectorAll('.sidebar-nav[data-arg]').forEach(function (a) {
    var page = a.getAttribute('data-arg');
    a.style.display = canAccessPage(page, role) ? '' : 'none';
  });
  document.querySelectorAll('.sidebar-group').forEach(function (g) {
    var items = g.querySelectorAll('.sidebar-nav');
    var anyVisible = Array.prototype.some.call(items, function (a) {
      return a.style.display !== 'none';
    });
    g.style.display = anyVisible ? '' : 'none';
  });
}
