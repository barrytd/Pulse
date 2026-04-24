// user-menu.js — Topbar avatar + account dropdown. The trigger is a
// circular button with the user's initial; clicking opens a shared
// `.pulse-dropdown` that groups Account / Appearance / Support /
// Session actions. Outside click + Escape close it.
'use strict';

import { apiGetAuthStatus, apiGetMe } from './api.js';
import { navigate } from './navigation.js';
import { toggleTheme } from './theme.js';
import { signOut, setActiveSettingsTab } from './settings.js';
import { openFeedbackModal } from './feedback.js';

const GITHUB_REPO = 'https://github.com/barrytd/Pulse';

function _initialFromIdentity(displayName, email) {
  // Prefer the display name's first letter — that's what lines up with
  // the greeting. Fall back to the email local-part's first letter.
  var source = (displayName || '').trim() || String(email || '').split('@')[0];
  return (source.charAt(0) || 'P').toUpperCase();
}

function _firstNameFromIdentity(displayName, email) {
  // If an admin has set a display_name, use the first whitespace-delimited
  // token ("Robert Perez" -> "Robert"). Otherwise fall back to the email
  // local-part. Returns 'there' when we have nothing usable so the greeting
  // still reads naturally.
  var dn = (displayName || '').trim();
  if (dn) {
    return dn.split(/\s+/)[0];
  }
  if (!email || email === 'local') return 'there';
  var local = String(email).split('@')[0] || email;
  // Title-case so "robert" -> "Robert" without mangling mixed case.
  return local.charAt(0).toUpperCase() + local.slice(1);
}

// Populate the avatar and the greeting once at boot. The avatar markup
// lives statically in index.html so styles apply even before this runs.
export async function mountUserMenu() {
  var email = '';
  var displayName = '';
  try {
    var s = await apiGetAuthStatus();
    email = (s && s.email) || '';
  } catch (e) { /* offline or auth disabled — keep defaults */ }

  // /api/me is the canonical source of display_name; /api/auth/status
  // only returns the session email. Fetch both so the greeting prefers
  // the admin-set name without falling back to email on every boot.
  try {
    var me = await apiGetMe();
    if (me) {
      displayName = me.display_name || '';
      if (!email && me.email) email = me.email;
      if (me.has_avatar) refreshUserMenuAvatar();
    }
  } catch (e) { /* no-op — corner keeps the initial */ }

  var avatar = document.getElementById('user-avatar-initials');
  if (avatar) avatar.textContent = _initialFromIdentity(displayName, email);
  var greet = document.getElementById('user-dropdown-name');
  if (greet) greet.textContent = _firstNameFromIdentity(displayName, email);
}

// Re-fetch /api/me and repaint the greeting + initial. Called after an
// admin saves their own display_name so the topbar updates without a
// page reload.
export async function refreshUserMenuIdentity() {
  try {
    var me = await apiGetMe();
    if (!me) return;
    var dn = me.display_name || '';
    var email = me.email || '';
    var avatar = document.getElementById('user-avatar-initials');
    // Only repaint initial if the corner is still showing text — an
    // uploaded avatar replaces the inner HTML with an <img>, which we
    // shouldn't clobber.
    if (avatar && avatar.tagName === 'SPAN') {
      avatar.textContent = _initialFromIdentity(dn, email);
    }
    var greet = document.getElementById('user-dropdown-name');
    if (greet) greet.textContent = _firstNameFromIdentity(dn, email);
  } catch (e) { /* keep stale — better than flicker */ }
}

// Called after a fresh avatar upload so the corner picks up the new
// image without a page reload. `bust` cache-busts the <img> src.
export function refreshUserMenuAvatar(bust) {
  var btn = document.querySelector('#user-menu .user-avatar');
  if (!btn) return;
  var url = '/api/me/avatar' + (bust ? ('?v=' + bust) : '');
  btn.innerHTML =
    '<img src="' + url + '" alt="Avatar" ' +
         'style="width:100%; height:100%; border-radius:50%; object-fit:cover;"/>';
}

export function toggleUserMenu(arg, target, event) {
  if (event && event.stopPropagation) event.stopPropagation();
  var dd = document.getElementById('user-dropdown');
  if (!dd) return;
  dd.hidden = !dd.hidden;
}

export function openProfile() {
  _closeUserMenu();
  setActiveSettingsTab('profile');
  navigate('settings');
}

export function openAccountSettings() {
  _closeUserMenu();
  setActiveSettingsTab('profile');
  navigate('settings');
}

export function openDocs() {
  _closeUserMenu();
  window.open(GITHUB_REPO + '#readme', '_blank', 'noopener');
}

export function openFeedback() {
  _closeUserMenu();
  openFeedbackModal();
}

// Dedicated wrapper so the dropdown closes before the signOut POST
// kicks off — feels snappier than waiting for the redirect.
export function logOutFromMenu() {
  _closeUserMenu();
  return signOut();
}

export function toggleDarkModeFromMenu() {
  toggleTheme();
  // Don't close the dropdown — users often want to flip the toggle and
  // immediately confirm the change visually.
}

function _closeUserMenu() {
  var dd = document.getElementById('user-dropdown');
  if (dd) dd.hidden = true;
}

// One-shot global listeners. Installed at module load so they cover
// every avatar open/close cycle.
document.addEventListener('click', function (e) {
  var dd = document.getElementById('user-dropdown');
  if (!dd || dd.hidden) return;
  var wrap = document.getElementById('user-menu');
  if (wrap && wrap.contains(e.target)) return;
  dd.hidden = true;
});

document.addEventListener('keydown', function (e) {
  if (e.key !== 'Escape') return;
  var dd = document.getElementById('user-dropdown');
  if (dd && !dd.hidden) dd.hidden = true;
});
