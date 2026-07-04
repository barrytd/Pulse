// twofa.js — authenticator-app 2FA (TOTP) enrollment + management card for
// Settings → Profile. Self-contained; loaded via app.js, so the csrf.js
// window.fetch wrapper attaches the X-Pulse-Request header to its POSTs.
'use strict';

function _esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
function _msg(id, m, err) {
  var el = document.getElementById(id);
  if (el) { el.textContent = m || ''; el.className = 'assign-status' + (err ? ' assign-status-err' : ''); }
}
function _rerender() { import('./settings.js').then(function (m) { m.renderSettingsPage(); }); }

export async function fetch2faStatus() {
  try {
    var r = await fetch('/api/2fa/status');
    if (!r.ok) return { enabled: false, recovery_codes_remaining: 0 };
    return await r.json();
  } catch (e) { return { enabled: false, recovery_codes_remaining: 0 }; }
}

export async function start2faSetup() {
  var area = document.getElementById('twofa-setup-area');
  if (!area) return;
  area.innerHTML = '<p class="muted" style="font-size:13px; margin-top:10px;">Generating…</p>';
  try {
    var r = await fetch('/api/2fa/setup', { method: 'POST' });
    var d = await r.json().catch(function () { return {}; });
    if (!r.ok) {
      area.innerHTML = '<div class="assign-status assign-status-err">' +
        _esc((d && d.detail) || 'Could not start setup.') + '</div>';
      return;
    }
    area.innerHTML =
      '<p style="font-size:13px; color:var(--text-muted); margin:12px 0;">Scan this with your authenticator app (Google Authenticator, Authy, 1Password…), or type the key in manually.</p>' +
      '<div style="display:flex; gap:16px; align-items:flex-start; flex-wrap:wrap;">' +
        '<img src="' + _esc(d.qr) + '" alt="2FA QR code" width="160" height="160" style="border-radius:8px; background:#fff; padding:6px;"/>' +
        '<div style="flex:1; min-width:200px;">' +
          '<label style="font-size:12px; color:var(--text-muted);">Manual key</label>' +
          '<div style="font-family:monospace; font-size:13px; word-break:break-all; background:var(--bg); padding:8px; border-radius:6px; border:1px solid var(--border); margin:4px 0 12px;">' + _esc(d.secret) + '</div>' +
          '<label for="twofa-confirm-code" style="font-size:12px; color:var(--text-muted);">Enter the 6-digit code to confirm</label>' +
          '<input type="text" id="twofa-confirm-code" inputmode="numeric" maxlength="6" placeholder="123456" style="width:100%; letter-spacing:6px; text-align:center; font-size:18px; margin-top:4px;"/>' +
        '</div>' +
      '</div>' +
      '<div class="assign-status" id="twofa-setup-status"></div>' +
      '<div class="settings-actions">' +
        '<button class="btn btn-primary" data-action="confirm2faSetup">Confirm &amp; enable</button>' +
        '<button class="btn" data-action="cancel2faSetup">Cancel</button>' +
      '</div>';
    var i = document.getElementById('twofa-confirm-code');
    if (i) i.focus();
  } catch (e) {
    area.innerHTML = '<div class="assign-status assign-status-err">Network error.</div>';
  }
}

export async function confirm2faSetup() {
  var code = ((document.getElementById('twofa-confirm-code') || {}).value || '').trim();
  if (!/^\d{6}$/.test(code)) { _msg('twofa-setup-status', 'Enter the 6-digit code.', true); return; }
  _msg('twofa-setup-status', 'Confirming…');
  try {
    var r = await fetch('/api/2fa/confirm', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: code }),
    });
    var d = await r.json().catch(function () { return {}; });
    if (!r.ok) {
      var det = d && d.detail;
      _msg('twofa-setup-status', (det && det.message) || (typeof det === 'string' ? det : 'That code did not match.'), true);
      return;
    }
    // Show the 8 recovery codes ONCE.
    var area = document.getElementById('twofa-setup-area');
    if (area) {
      area.innerHTML =
        '<div class="assign-status" style="color:var(--ok, #10b981); margin-top:10px;">Two-factor authentication is on. Save these 8 recovery codes now — each works once if you lose your device. You won’t see them again.</div>' +
        '<div style="font-family:monospace; font-size:14px; background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:12px; margin:10px 0; columns:2; line-height:1.9;">' +
          (d.recovery_codes || []).map(function (c) { return _esc(c); }).join('<br/>') +
        '</div>' +
        '<div class="settings-actions"><button class="btn btn-primary" data-action="ack2faRecovery">I’ve saved them</button></div>';
    }
  } catch (e) { _msg('twofa-setup-status', 'Network error.', true); }
}

export function cancel2faSetup() { _rerender(); }
export function ack2faRecovery() { _rerender(); }

export async function disable2fa() {
  var code = ((document.getElementById('twofa-disable-code') || {}).value || '').trim();
  if (!code) { _msg('twofa-disable-status', 'Enter a current code to turn 2FA off.', true); return; }
  _msg('twofa-disable-status', 'Disabling…');
  try {
    var r = await fetch('/api/2fa/disable', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: code }),
    });
    var d = await r.json().catch(function () { return {}; });
    if (!r.ok) { _msg('twofa-disable-status', (d && d.detail) || 'That code is incorrect.', true); return; }
    _rerender();
  } catch (e) { _msg('twofa-disable-status', 'Network error.', true); }
}

// Card HTML for Settings → Profile. `status` from fetch2faStatus().
export function twofaCardHtml(status) {
  var on = !!(status && status.enabled);
  var remaining = (status && status.recovery_codes_remaining) || 0;
  var state = on
    ? '<span class="pin-state pin-state-on"><i data-lucide="shield-check"></i> 2FA is on</span>'
    : '<span class="pin-state pin-state-off"><i data-lucide="shield"></i> 2FA is off</span>';
  var body;
  if (on) {
    body =
      '<p style="font-size:13px; color:var(--text-muted);">Recovery codes remaining: <strong>' + remaining + '</strong>.</p>' +
      '<div class="settings-grid"><div class="settings-field">' +
        '<label for="twofa-disable-code">Authenticator or recovery code</label>' +
        '<input type="text" id="twofa-disable-code" inputmode="text" autocomplete="off" maxlength="24" placeholder="required to turn off"/>' +
      '</div></div>' +
      '<div class="assign-status" id="twofa-disable-status"></div>' +
      '<div class="settings-actions"><button class="btn btn-with-icon" data-action="disable2fa"><i data-lucide="shield-off"></i><span>Disable 2FA</span></button></div>';
  } else {
    body =
      '<div class="settings-actions"><button class="btn btn-primary btn-with-icon" data-action="start2faSetup"><i data-lucide="shield-check"></i><span>Enable 2FA</span></button></div>' +
      '<div id="twofa-setup-area"></div>';
  }
  return '<div class="card" style="margin-bottom:16px;">' +
    '<div class="section-label">Two-factor authentication</div>' +
    '<p style="color:var(--text-muted); font-size:13px; margin-bottom:12px;">An authenticator-app code (TOTP) required at login, on top of your password — protects your account even if your password leaks. ' + state + '</p>' +
    body +
  '</div>';
}
