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

function _initialFromEmail(email) {
  if (!email) return 'P';
  var name = String(email).split('@')[0] || 'P';
  return (name.charAt(0) || 'P').toUpperCase();
}

function _displayName(email) {
  if (!email || email === 'local') return 'there';
  var name = String(email).split('@')[0] || email;
  // Capitalise the first letter only — leave the rest as-is so
  // usernames like "johnDoe42" keep their shape.
  return name.charAt(0).toUpperCase() + name.slice(1);
}

// Populate the avatar and the greeting once at boot. The avatar markup
// lives statically in index.html so styles apply even before this runs.
export async function mountUserMenu() {
  try {
    var s = await apiGetAuthStatus();
    var initials = _initialFromEmail(s && s.email);
    var name = _displayName(s && s.email);
    var avatar = document.getElementById('user-avatar-initials');
    if (avatar) avatar.textContent = initials;
    var greet = document.getElementById('user-dropdown-name');
    if (greet) greet.textContent = name;
  } catch (e) { /* offline or auth disabled — keep defaults */ }

  // Swap the initial for an <img> when the user has uploaded an avatar.
  // Done separately from the greeting so a /api/me 401 doesn't take the
  // initial fallback down with it.
  try {
    var me = await apiGetMe();
    if (me && me.has_avatar) refreshUserMenuAvatar();
  } catch (e) { /* no-op — corner keeps the initial */ }
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
