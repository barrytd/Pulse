// settings.js — Settings page: account, email, alerts, scan defaults,
// appearance, detection rules.
(function () {
  'use strict';

  // Map the "Email provider" dropdown back to host+port so users never
  // have to know those exist for Gmail/Outlook/Yahoo.
  var EMAIL_PROVIDER_PRESETS = {
    gmail:   { host: 'smtp.gmail.com',        port: 587, help: 'https://myaccount.google.com/apppasswords' },
    outlook: { host: 'smtp-mail.outlook.com', port: 587, help: 'https://support.microsoft.com/account-billing/5896ed9b-4263-e681-128a-a6f2979a7944' },
    yahoo:   { host: 'smtp.mail.yahoo.com',   port: 587, help: 'https://help.yahoo.com/kb/SLN15241.html' },
    other:   { host: '',                      port: 587, help: '' }
  };

  async function renderSettingsPage() {
    var c = document.getElementById('content');
    c.innerHTML = '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading...</div>';

    var config = await window.apiGetConfig();
    var rules  = await window.apiGetRules();
    var auth   = await window.apiGetAuthStatus();

    var em = config.email || {};
    var al = config.alerts || {};
    var pwStatus = em.password_set
      ? '<span class="password-status set">\u2713 App password saved</span>'
      : '<span class="password-status">No app password saved yet</span>';

    // Map the saved SMTP host to a provider dropdown choice.
    var providers = [
      { id: 'gmail',   label: 'Gmail',            host: 'smtp.gmail.com',         port: 587, help: 'https://myaccount.google.com/apppasswords' },
      { id: 'outlook', label: 'Outlook / Hotmail', host: 'smtp-mail.outlook.com', port: 587, help: '' },
      { id: 'yahoo',   label: 'Yahoo Mail',       host: 'smtp.mail.yahoo.com',    port: 587, help: '' },
      { id: 'other',   label: 'Other (custom SMTP)', host: '',                    port: 587, help: '' }
    ];
    var currentProvider = 'other';
    for (var i = 0; i < providers.length; i++) {
      if (providers[i].host && providers[i].host === em.smtp_host) {
        currentProvider = providers[i].id;
        break;
      }
    }
    if (!em.smtp_host) currentProvider = 'gmail';
    var providerOpts = providers.map(function (p) {
      var sel = (p.id === currentProvider) ? ' selected' : '';
      return '<option value="' + p.id + '"' + sel + '>' + p.label + '</option>';
    }).join('');

    var thresholdOpts = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(function (t) {
      var sel = (al.threshold === t) ? ' selected' : '';
      return '<option value="' + t + '"' + sel + '>' + t + '</option>';
    }).join('');

    var monitorInterval = (al.monitor_interval_minutes != null) ? al.monitor_interval_minutes : 30;
    var intervalChoices = [
      { v: 5,   label: 'Every 5 minutes' },
      { v: 15,  label: 'Every 15 minutes' },
      { v: 30,  label: 'Every 30 minutes' },
      { v: 60,  label: 'Every hour' },
      { v: 120, label: 'Every 2 hours' },
      { v: 240, label: 'Every 4 hours' }
    ];
    var intervalOpts = intervalChoices.map(function (ch) {
      var sel = (monitorInterval === ch.v) ? ' selected' : '';
      return '<option value="' + ch.v + '"' + sel + '>' + ch.label + '</option>';
    }).join('');

    var currentTheme = window.getTheme();

    c.innerHTML =
      '<div class="page-head">' +
        '<div class="page-head-title">Configure Pulse</div>' +
      '</div>' +

      '<div class="card" style="margin-bottom:16px;">' +
        '<div class="section-label">My Account</div>' +
        '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
          'The email and password you use to sign in to Pulse.' +
        '</p>' +
        '<div class="form-row"><label>Account email</label>' +
          '<input type="email" id="account-email" value="' + window.escapeHtml(auth.email || '') + '"/></div>' +
        '<div class="form-row"><label>New password</label>' +
          '<input type="password" id="account-new-password" placeholder="leave blank to keep current" autocomplete="new-password"/></div>' +
        '<div class="form-row"><label>Current password</label>' +
          '<input type="password" id="account-current-password" placeholder="required to change email or password" autocomplete="current-password"/></div>' +
        '<div class="form-actions">' +
          '<button class="btn btn-primary" data-action="saveAccount">Save account changes</button>' +
          '<button class="btn" data-action="signOut">Sign out</button>' +
        '</div>' +
      '</div>' +

      '<div class="card" style="margin-bottom:16px;">' +
        '<div class="section-label">Email Notifications</div>' +
        '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
          'Connect Pulse to your mailbox so it can send you threat alert emails. ' +
          'If your provider requires 2-factor authentication (Gmail, Outlook), you\u2019ll need an ' +
          '<strong>app password</strong> instead of your normal one.' +
        '</p>' +
        '<div class="form-row"><label>Email provider</label>' +
          '<select id="email-provider" data-action-change="onEmailProviderChange">' + providerOpts + '</select></div>' +
        '<div class="form-row" id="email-custom-host-row" style="display:' + (currentProvider === 'other' ? 'flex' : 'none') + ';">' +
          '<label>Outgoing mail server</label>' +
          '<input type="text" id="email-smtp_host" value="' + window.escapeHtml(em.smtp_host || '') + '" placeholder="smtp.example.com"/></div>' +
        '<div class="form-row" id="email-custom-port-row" style="display:' + (currentProvider === 'other' ? 'flex' : 'none') + ';">' +
          '<label>Server port</label>' +
          '<input type="number" id="email-smtp_port" value="' + (em.smtp_port || 587) + '"/></div>' +
        '<div class="form-row"><label>Your email</label>' +
          '<input type="email" id="email-sender" value="' + window.escapeHtml(em.sender || '') + '" placeholder="you@example.com"/></div>' +
        '<div class="form-row"><label>App password</label>' +
          '<input type="password" id="email-password" placeholder="' + (em.password_set ? 'leave blank to keep current' : '16-character app password') + '" autocomplete="new-password"/></div>' +
        '<div class="form-row"><span></span><span>' + pwStatus + ' <a id="email-help-link" href="#" target="_blank" style="color:var(--accent); text-decoration:none; margin-left:12px; display:none;">How do I get an app password?</a></span></div>' +
        '<div class="form-actions">' +
          '<button class="btn btn-primary" data-action="saveEmailSettings">Save email settings</button>' +
        '</div>' +
      '</div>' +

      '<div class="card" style="margin-bottom:16px;">' +
        '<div class="section-label">Threshold Alerts</div>' +
        '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
          'Pulse fires an automatic alert email when a scan finds a finding at or above the threshold. ' +
          'Cooldown prevents the same rule from re-alerting within the window.' +
        '</p>' +
        '<div class="form-row"><label>Enable alerts</label>' +
          '<label class="form-checkbox"><input type="checkbox" id="alert-enabled"' + (al.enabled ? ' checked' : '') + '/> Send alerts when threshold is met</label></div>' +
        '<div class="form-row"><label>Threshold</label>' +
          '<select id="alert-threshold">' + thresholdOpts + '</select></div>' +
        '<div class="form-row"><label>Recipient</label>' +
          '<input type="email" id="alert-recipient" value="' + window.escapeHtml(al.recipient || '') + '" placeholder="leave blank to use email recipient"/></div>' +
        '<div class="form-row"><label>Cooldown (min)</label>' +
          '<input type="number" id="alert-cooldown" value="' + (al.cooldown_minutes != null ? al.cooldown_minutes : 60) + '" min="0"/></div>' +
        '<div class="form-actions">' +
          '<button class="btn btn-primary" data-action="saveAlertSettings">Save alert settings</button>' +
          '<button class="btn" data-action="sendTestAlert">Send test alert</button>' +
        '</div>' +
      '</div>' +

      '<div class="card" style="margin-bottom:16px;">' +
        '<div class="section-label">Live Monitor Emails</div>' +
        '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
          'Send email alerts for findings detected by the live monitor. The interval ' +
          'is the minimum gap between monitor emails \u2014 the per-rule cooldown above ' +
          'still applies on top, so noisy rules never spam you.' +
        '</p>' +
        '<div class="form-row"><label>Email during monitoring</label>' +
          '<label class="form-checkbox"><input type="checkbox" id="alert-monitor-enabled"' + (al.monitor_enabled ? ' checked' : '') + '/> Send monitor findings by email</label></div>' +
        '<div class="form-row"><label>Email interval</label>' +
          '<select id="alert-monitor-interval">' + intervalOpts + '</select></div>' +
        '<div class="form-actions">' +
          '<button class="btn btn-primary" data-action="saveAlertSettings">Save alert settings</button>' +
        '</div>' +
      '</div>' +

      '<div class="card" style="margin-bottom:16px;">' +
        '<div class="section-label">Scan Defaults</div>' +
        '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
          'Defaults used when no CLI flags are provided. Edit in ' +
          '<span class="mono" style="color:var(--accent);">pulse.yaml</span> for now \u2014 ' +
          'inline editing arrives in a later release.' +
        '</p>' +
        '<div class="form-row"><label>Default log folder</label>' +
          '<input type="text" value="' + window.escapeHtml(config.settings.logs || '') + '" readonly style="background:var(--bg); color:var(--text-muted);"/></div>' +
        '<div class="form-row"><label>Default format</label>' +
          '<input type="text" value="' + window.escapeHtml((config.settings.format || '').toUpperCase()) + '" readonly style="background:var(--bg); color:var(--text-muted);"/></div>' +
        '<div class="form-row"><label>Default severity</label>' +
          '<input type="text" value="' + window.escapeHtml(config.settings.severity || '') + '" readonly style="background:var(--bg); color:var(--text-muted);"/></div>' +
      '</div>' +

      '<div class="card" style="margin-bottom:16px;">' +
        '<div class="section-label">Appearance</div>' +
        '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
          'Your theme choice is saved to this browser and applied on every visit.' +
        '</p>' +
        '<div class="form-row"><label>Theme</label>' +
          '<select id="appearance-theme" data-action-change="setThemeFromSelect">' +
            '<option value="dark"'  + (currentTheme === 'dark'  ? ' selected' : '') + '>Dark (default)</option>' +
            '<option value="light"' + (currentTheme === 'light' ? ' selected' : '') + '>Light</option>' +
          '</select></div>' +
      '</div>' +

      '<div class="card" style="margin-bottom:16px;">' +
        '<div class="section-label">Available Detection Rules (' + rules.rules.length + ')</div>' +
        '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
          'All rules Pulse runs during a scan. Suppress any rule by adding it to the whitelist.' +
        '</p>' +
        '<div>' +
          rules.rules.map(function (r) {
            return '<span class="whitelist-item">' + window.escapeHtml(r) + '</span>';
          }).join('') +
        '</div>' +
      '</div>' +

      '<div class="card">' +
        '<div class="section-label">Resources</div>' +
        '<p><a href="/docs" target="_blank" style="color:var(--accent); text-decoration:none;">\u2192 API Documentation (Swagger)</a></p>' +
      '</div>';

    onEmailProviderChange();
  }

  async function saveAccount() {
    var newEmail = document.getElementById('account-email').value.trim();
    var newPw    = document.getElementById('account-new-password').value;
    var curPw    = document.getElementById('account-current-password').value;
    if (!curPw) {
      window.toastError('Enter your current password to make changes.');
      return;
    }
    try {
      var changed = false;
      if (newEmail) {
        var r1 = await window.apiChangeEmail(newEmail, curPw);
        if (!r1.ok) {
          window.toastError((r1.data && r1.data.detail) || 'Email update failed.');
          return;
        }
        changed = true;
      }
      if (newPw) {
        var r2 = await window.apiChangePassword(newPw, curPw);
        if (!r2.ok) {
          window.toastError((r2.data && r2.data.detail) || 'Password update failed.');
          return;
        }
        changed = true;
      }
      if (!changed) {
        window.toastError('Nothing to save \u2014 enter a new email or new password.');
        return;
      }
      window.showToast('Account updated');
      document.getElementById('account-new-password').value = '';
      document.getElementById('account-current-password').value = '';
      renderSettingsPage();
    } catch (e) {
      window.toastError('Network error: ' + e.message);
    }
  }

  async function signOut() {
    await window.apiLogout();
    window.location.href = '/login';
  }

  function onEmailProviderChange() {
    var sel = document.getElementById('email-provider');
    if (!sel) return;
    var p = sel.value;
    var isCustom = (p === 'other');
    document.getElementById('email-custom-host-row').style.display = isCustom ? 'flex' : 'none';
    document.getElementById('email-custom-port-row').style.display = isCustom ? 'flex' : 'none';
    var preset = EMAIL_PROVIDER_PRESETS[p];
    var helpLink = document.getElementById('email-help-link');
    if (preset && preset.help) {
      helpLink.href = preset.help;
      helpLink.style.display = 'inline';
    } else {
      helpLink.style.display = 'none';
    }
  }

  async function saveEmailSettings() {
    var sel = document.getElementById('email-provider');
    var provider = sel ? sel.value : 'other';
    var preset = EMAIL_PROVIDER_PRESETS[provider] || EMAIL_PROVIDER_PRESETS.other;
    var host, port;
    if (provider === 'other') {
      host = document.getElementById('email-smtp_host').value;
      port = document.getElementById('email-smtp_port').value;
    } else {
      host = preset.host;
      port = preset.port;
    }
    var sender = document.getElementById('email-sender').value;
    var body = {
      smtp_host: host,
      smtp_port: port,
      sender:    sender,
      // Default recipient to sender so alerts go to the user's own
      // inbox unless overridden in Threshold Alerts -> Recipient.
      recipient: sender,
      password:  document.getElementById('email-password').value,
    };
    try {
      var r = await window.apiSaveEmailConfig(body);
      if (!r.ok) {
        var err = await r.json().catch(function () { return {}; });
        window.toastError(err.detail || 'Save failed.');
        return;
      }
      window.showToast('Email settings saved');
      document.getElementById('email-password').value = '';
      renderSettingsPage();
    } catch (e) {
      window.toastError('Network error: ' + e.message);
    }
  }

  async function saveAlertSettings() {
    var body = {
      enabled:                  document.getElementById('alert-enabled').checked,
      threshold:                document.getElementById('alert-threshold').value,
      recipient:                document.getElementById('alert-recipient').value,
      cooldown_minutes:         document.getElementById('alert-cooldown').value,
      monitor_enabled:          document.getElementById('alert-monitor-enabled').checked,
      monitor_interval_minutes: document.getElementById('alert-monitor-interval').value,
    };
    try {
      var r = await window.apiSaveAlertsConfig(body);
      if (!r.ok) {
        var err = await r.json().catch(function () { return {}; });
        window.toastError(err.detail || 'Save failed.');
        return;
      }
      window.showToast('Alert settings saved');
    } catch (e) {
      window.toastError('Network error: ' + e.message);
    }
  }

  async function sendTestAlert() {
    window.showToast('Sending test alert...');
    try {
      var r = await window.apiSendTestAlert();
      if (!r.ok) {
        window.toastError((r.data && r.data.detail) || 'Test failed.');
        return;
      }
      window.showToast('Test alert sent to ' + r.data.recipient);
    } catch (e) {
      window.toastError('Network error: ' + e.message);
    }
  }

  window.renderSettingsPage    = renderSettingsPage;
  window.saveAccount           = saveAccount;
  window.signOut               = signOut;
  window.onEmailProviderChange = onEmailProviderChange;
  window.saveEmailSettings     = saveEmailSettings;
  window.saveAlertSettings     = saveAlertSettings;
  window.sendTestAlert         = sendTestAlert;
})();
