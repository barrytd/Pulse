// pin.js — security PIN step-up.
//
// Sensitive actions (block an IP, deactivate/delete a user, change a role)
// are gated server-side: if the user has a PIN, the endpoint returns
// 403 {detail:{code:'pin_required'}}. `pinGuard` wraps such a call, pops the
// PIN prompt on that response, and retries once after a correct PIN grants a
// short elevation cookie. Self-contained (no app imports) to avoid cycles.
'use strict';

function _esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

// Promise that resolves true once the session is elevated, false on cancel.
var _pendingResolve = null;

function _setStatus(msg, isErr) {
  var el = document.getElementById('pin-status');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'assign-status' + (isErr ? ' assign-status-err' : '');
}

function _closePinPrompt() {
  var overlay = document.getElementById('pin-modal');
  if (overlay) overlay.classList.remove('open');
  var input = document.getElementById('pin-input');
  if (input) input.value = '';
  _setStatus('');
}

function _promptForPin() {
  return new Promise(function (resolve) {
    var overlay = document.getElementById('pin-modal');
    if (!overlay) { resolve(false); return; }
    _pendingResolve = resolve;
    _setStatus('');
    var input = document.getElementById('pin-input');
    if (input) input.value = '';
    overlay.classList.add('open');
    if (window.lucide && window.lucide.createIcons) {
      try { window.lucide.createIcons(); } catch (e) {}
    }
    if (input) setTimeout(function () { input.focus(); }, 30);
  });
}

export async function submitPinPrompt() {
  var input = document.getElementById('pin-input');
  var pin = (input && input.value || '').trim();
  if (!pin) { _setStatus('Enter your PIN.', true); return; }
  var btn = document.getElementById('pin-submit-btn');
  if (btn) btn.disabled = true;
  _setStatus('Confirming…');
  try {
    var resp = await fetch('/api/me/pin/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin: pin }),
    });
    if (btn) btn.disabled = false;
    if (resp.ok) {
      var resolve = _pendingResolve; _pendingResolve = null;
      _closePinPrompt();
      if (resolve) resolve(true);
      return;
    }
    var data = await resp.json().catch(function () { return {}; });
    var detail = (data && data.detail) || {};
    _setStatus(detail.message || 'Incorrect PIN.', true);
  } catch (e) {
    if (btn) btn.disabled = false;
    _setStatus('Could not verify PIN.', true);
  }
}

export function cancelPinPrompt() {
  var resolve = _pendingResolve; _pendingResolve = null;
  _closePinPrompt();
  if (resolve) resolve(false);
}

// Eye toggle: show/hide the PIN input inside the same wrapper, swapping the
// eye / eye-off icon. `target` is the button (the data-action element).
export function togglePinReveal(arg, target) {
  if (!target) return;
  var wrap = target.closest('.pin-input-wrap');
  if (!wrap) return;
  var input = wrap.querySelector('input');
  if (!input) return;
  var reveal = (input.type === 'password');
  input.type = reveal ? 'text' : 'password';
  target.setAttribute('aria-label', reveal ? 'Hide PIN' : 'Show PIN');
  var icon = target.querySelector('[data-lucide], svg');
  if (icon) {
    var fresh = document.createElement('i');
    fresh.setAttribute('data-lucide', reveal ? 'eye-off' : 'eye');
    icon.replaceWith(fresh);
    if (window.lucide && window.lucide.createIcons) {
      try { window.lucide.createIcons(); } catch (e) {}
    }
  }
  input.focus();
}

// Run a fetch-returning thunk; on a 403 pin_required, prompt + retry once.
// `thunk` must be a function returning a Promise<Response> so we can re-run it
// with the elevation cookie in place.
export async function pinGuard(thunk) {
  var resp = await thunk();
  if (resp && resp.status === 403) {
    var data = {};
    try { data = await resp.clone().json(); } catch (e) { data = {}; }
    var code = data && data.detail && data.detail.code;
    if (code === 'pin_required') {
      var ok = await _promptForPin();
      if (ok) return await thunk();   // retry once, now elevated
    }
  }
  return resp;
}

// Close on backdrop click + Esc, matching the other modals.
document.addEventListener('click', function (e) {
  if (e.target && e.target.id === 'pin-modal') cancelPinPrompt();
});
document.addEventListener('keydown', function (e) {
  var overlay = document.getElementById('pin-modal');
  if (!overlay || !overlay.classList.contains('open')) return;
  if (e.key === 'Escape') cancelPinPrompt();
  if (e.key === 'Enter') submitPinPrompt();
});

// ---------------------------------------------------------------
// Settings → Account: PIN set / change / remove
// ---------------------------------------------------------------

export async function fetchPinStatus() {
  try {
    var r = await fetch('/api/me/pin');
    if (!r.ok) return { pin_set: false };
    return await r.json();
  } catch (e) { return { pin_set: false }; }
}

// Set or change the PIN. Reads the inputs rendered by the settings card.
export async function savePin() {
  var pinEl = document.getElementById('pin-new');
  var pwEl = document.getElementById('pin-current-password');
  var statusEl = document.getElementById('pin-setup-status');
  var pin = (pinEl && pinEl.value || '').trim();
  var pw = (pwEl && pwEl.value || '');
  function setMsg(m, err) {
    if (statusEl) { statusEl.textContent = m || ''; statusEl.className = 'assign-status' + (err ? ' assign-status-err' : ''); }
  }
  if (!/^\d{4,12}$/.test(pin)) { setMsg('PIN must be 4-12 digits.', true); return; }
  if (!pw) { setMsg('Enter your account password to confirm.', true); return; }
  setMsg('Saving…');
  try {
    var r = await fetch('/api/me/pin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin: pin, current_password: pw }),
    });
    var data = await r.json().catch(function () { return {}; });
    if (!r.ok) { setMsg((data && data.detail) || 'Could not save PIN.', true); return; }
    setMsg('');
    // Re-render the settings page so the card reflects the new state.
    import('./settings.js').then(function (m) { m.renderSettingsPage(); });
  } catch (e) { setMsg('Could not save PIN.', true); }
}

export async function removePin() {
  var pwEl = document.getElementById('pin-current-password');
  var statusEl = document.getElementById('pin-setup-status');
  var pw = (pwEl && pwEl.value || '');
  function setMsg(m, err) {
    if (statusEl) { statusEl.textContent = m || ''; statusEl.className = 'assign-status' + (err ? ' assign-status-err' : ''); }
  }
  if (!pw) { setMsg('Enter your account password to remove the PIN.', true); return; }
  setMsg('Removing…');
  try {
    var r = await fetch('/api/me/pin', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ current_password: pw }),
    });
    var data = await r.json().catch(function () { return {}; });
    if (!r.ok) { setMsg((data && data.detail) || 'Could not remove PIN.', true); return; }
    import('./settings.js').then(function (m) { m.renderSettingsPage(); });
  } catch (e) { setMsg('Could not remove PIN.', true); }
}

// Card HTML for the Account tab. `status` from fetchPinStatus().
export function pinCardHtml(status) {
  var isSet = !!(status && status.pin_set);
  var stateLine = isSet
    ? '<span class="pin-state pin-state-on"><i data-lucide="shield-check"></i> PIN is on</span>'
    : '<span class="pin-state pin-state-off"><i data-lucide="shield"></i> No PIN set</span>';
  return '<div class="card" style="margin-bottom:16px;">' +
    '<div class="section-label">Security PIN</div>' +
    '<p style="color:var(--text-muted); font-size:13px; margin-bottom:12px;">' +
      'A second confirmation before destructive actions (blocking an IP, ' +
      'removing a user, changing a role). Protects your account if your ' +
      'session is ever stolen. ' + stateLine +
    '</p>' +
    '<div class="form-row"><label>' + (isSet ? 'New PIN' : 'PIN') + '</label>' +
      '<div class="pin-input-wrap">' +
        '<input type="password" id="pin-new" inputmode="numeric" autocomplete="off" ' +
          'maxlength="12" placeholder="4-12 digits"/>' +
        '<button type="button" class="pin-reveal-btn" data-action="togglePinReveal" ' +
          'aria-label="Show PIN" title="Show / hide" tabindex="-1"><i data-lucide="eye"></i></button>' +
      '</div></div>' +
    '<div class="form-row"><label>Account password</label>' +
      '<input type="password" id="pin-current-password" autocomplete="current-password" ' +
        'placeholder="confirm it’s you"/></div>' +
    '<div class="assign-status" id="pin-setup-status"></div>' +
    '<div class="form-actions">' +
      '<button class="btn btn-primary btn-with-icon" data-action="savePin">' +
        '<i data-lucide="shield-check"></i><span>' + (isSet ? 'Change PIN' : 'Set PIN') + '</span></button>' +
      (isSet
        ? '<button class="btn btn-with-icon" data-action="removePin"><i data-lucide="shield-off"></i><span>Remove PIN</span></button>'
        : '') +
    '</div>' +
  '</div>';
}
