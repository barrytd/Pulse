// settings.js — Settings page: account, email, alerts, scan defaults,
// appearance, detection rules.
'use strict';

import {
  apiGetConfig,
  apiGetRules,
  apiGetAuthStatus,
  apiGetMe,
  apiListUsers,
  apiCreateUser,
  apiUpdateUserRole,
  apiUpdateUserActive,
  apiDeleteUser,
  apiChangeEmail,
  apiChangePassword,
  apiLogout,
  apiSaveEmailConfig,
  apiSaveAlertsConfig,
  apiSendTestAlert,
  apiSaveWebhookConfig,
  apiSendTestWebhook,
  apiSaveSchedulerConfig,
  apiUploadAvatar,
} from './api.js';
import { escapeHtml, showToast, toastError } from './dashboard.js';
import { getTheme } from './theme.js';
import { refreshUserMenuAvatar } from './user-menu.js';

// Map the "Email provider" dropdown back to host+port so users never
// have to know those exist for Gmail/Outlook/Yahoo.
const EMAIL_PROVIDER_PRESETS = {
  gmail:   { host: 'smtp.gmail.com',        port: 587, help: 'https://myaccount.google.com/apppasswords' },
  outlook: { host: 'smtp-mail.outlook.com', port: 587, help: 'https://support.microsoft.com/account-billing/5896ed9b-4263-e681-128a-a6f2979a7944' },
  yahoo:   { host: 'smtp.mail.yahoo.com',   port: 587, help: 'https://help.yahoo.com/kb/SLN15241.html' },
  other:   { host: '',                      port: 587, help: '' }
};

// Left-nav tab layout — each tab maps to a builder that returns the
// right-hand content HTML. Kept module-level so `setActiveSettingsTab`
// can pre-select a tab before navigate('settings') runs.
const SETTINGS_TABS = [
  { id: 'profile',       label: 'Profile',         icon: 'user' },
  { id: 'notifications', label: 'Notifications',   icon: 'bell' },
  { id: 'scheduled',     label: 'Scheduled Scans', icon: 'calendar' },
  { id: 'appearance',    label: 'Appearance',      icon: 'palette' },
  { id: 'users',         label: 'Users',           icon: 'users', adminOnly: true },
  { id: 'advanced',      label: 'Advanced',        icon: 'sliders' },
];
let _activeSettingsTab = 'profile';
let _avatarCacheBuster = '';

export function setActiveSettingsTab(name) {
  if (SETTINGS_TABS.some(function (t) { return t.id === name; })) {
    _activeSettingsTab = name;
  }
}

export function switchSettingsTab(arg) {
  if (!arg) return;
  setActiveSettingsTab(arg);
  renderSettingsPage();
}

export async function renderSettingsPage() {
  var c = document.getElementById('content');
  c.innerHTML = '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading...</div>';

  // Fetch every endpoint in parallel with its own catch so one slow /
  // failing endpoint can't leave the whole page stuck on "Loading...".
  // Each result falls back to a safe default shape the renderer accepts.
  // Per-call timeout: Render free tier cold-starts can be slow, but a
  // request that hasn't returned in 15s is almost certainly wedged.
  function _withTimeout(p, label) {
    return Promise.race([
      p,
      new Promise(function (_, reject) {
        setTimeout(function () {
          reject(new Error('timed out after 15s'));
        }, 15000);
      }),
    ]).catch(function (err) {
      throw new Error(label + ' ' + (err && err.message ? err.message : err));
    });
  }
  var settled = await Promise.allSettled([
    _withTimeout(apiGetConfig(),     '/api/config'),
    _withTimeout(apiGetRules(),      '/api/rules'),
    _withTimeout(apiGetAuthStatus(), '/api/auth/status'),
    _withTimeout(apiGetMe(),         '/api/me'),
  ]);
  function _val(i, fallback) {
    var r = settled[i];
    return (r && r.status === 'fulfilled' && r.value) ? r.value : fallback;
  }
  var failures = settled
    .map(function (r, i) {
      if (r.status !== 'rejected') return null;
      var name = ['/api/config', '/api/rules', '/api/auth/status', '/api/me'][i];
      var msg = (r.reason && r.reason.message) ? r.reason.message : String(r.reason);
      return name + ': ' + msg;
    })
    .filter(Boolean);

  var config = _val(0, {});
  var rules  = _val(1, { rules: [] });
  var auth   = _val(2, { email: '' });
  var me     = _val(3, { role: null });
  if (!rules || !Array.isArray(rules.rules)) rules = { rules: [] };
  var isAdmin = (me && me.role === 'admin');

  // Admin-only users fetch — skip the round-trip for non-admins. The
  // server would 403 anyway, but avoiding it keeps the Network tab clean.
  var usersList = [];
  if (isAdmin) {
    try {
      var lu = await apiListUsers();
      usersList = lu.users || [];
    } catch (e) { usersList = []; }
  }

  // Filter tabs by role. If a viewer somehow lands on the Users tab (e.g.
  // a saved URL), fall back to Profile so we don't render an empty panel.
  var visibleTabs = SETTINGS_TABS.filter(function (t) {
    return !t.adminOnly || isAdmin;
  });
  if (!visibleTabs.some(function (t) { return t.id === _activeSettingsTab; })) {
    _activeSettingsTab = 'profile';
  }

  var em = config.email || {};
  var al = config.alerts || {};
  var wh = config.webhook || {};
  var scanDefaults = config.settings || {};
  var whFlavor = wh.flavor || '';
  var flavorOpts = [
    { v: '',        label: 'Auto-detect from URL' },
    { v: 'slack',   label: 'Slack' },
    { v: 'discord', label: 'Discord' },
  ].map(function (o) {
    var sel = (whFlavor === o.v) ? ' selected' : '';
    return '<option value="' + o.v + '"' + sel + '>' + o.label + '</option>';
  }).join('');
  var whUrlStatus = wh.url_set
    ? '<span class="password-status set">\u2713 Webhook URL saved</span>'
    : '<span class="password-status">No webhook URL saved yet</span>';
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

  var sched = config.scheduled_scan || {};
  var schedKind = sched.schedule || 'daily';
  var schedEnabled = !!sched.enabled;
  var schedSupported = sched.platform_supported !== false;
  var schedWeekday = (sched.weekday != null) ? Number(sched.weekday) : 1;
  var schedTime = sched.time || '09:00';
  var schedDays = sched.days || 7;
  var schedCron = sched.cron || '';
  var schedNextRun = sched.next_run || '';
  var schedDesc = sched.description || 'Disabled';
  var webhookConfigured = !!wh.url_set;
  var emailConfigured   = !!em.password_set;

  var rangeChoices = [
    { v: 1,  label: 'Last 24 hours' },
    { v: 3,  label: 'Last 3 days' },
    { v: 7,  label: 'Last 7 days' },
    { v: 30, label: 'Last 30 days' },
  ];
  var rangeOpts = rangeChoices.map(function (ch) {
    var sel = (schedDays === ch.v) ? ' selected' : '';
    return '<option value="' + ch.v + '"' + sel + '>' + ch.label + '</option>';
  }).join('');
  // If the stored value doesn't match one of the presets, add a "custom" option.
  var hasPreset = rangeChoices.some(function (ch) { return ch.v === schedDays; });
  if (!hasPreset) {
    rangeOpts += '<option value="' + schedDays + '" selected>Custom (' + schedDays + ' days)</option>';
  }

  var kindOpts = [
    { v: 'daily',  label: 'Daily' },
    { v: 'weekly', label: 'Weekly' },
    { v: 'custom', label: 'Custom (cron)' },
  ].map(function (o) {
    var sel = (schedKind === o.v) ? ' selected' : '';
    return '<option value="' + o.v + '"' + sel + '>' + o.label + '</option>';
  }).join('');

  var weekdayOpts = [
    'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'
  ].map(function (name, i) {
    var sel = (schedWeekday === i) ? ' selected' : '';
    return '<option value="' + i + '"' + sel + '>' + name + '</option>';
  }).join('');

  var currentTheme = getTheme();

  // --- Profile tab ----------------------------------------------------
  // Avatar card — browser caches GET /api/me/avatar, so when the user
  // uploads a replacement we append ?v=<mtime> to dodge the cache.
  var avatarCacheBuster = (typeof _avatarCacheBuster !== 'undefined') ? _avatarCacheBuster : '';
  var avatarImg = (me && me.has_avatar)
    ? '<img id="profile-avatar-img" src="/api/me/avatar' + (avatarCacheBuster ? ('?v=' + avatarCacheBuster) : '') + '" alt="Avatar" style="width:72px; height:72px; border-radius:50%; object-fit:cover; border:2px solid var(--accent);"/>'
    : '<div id="profile-avatar-img" style="width:72px; height:72px; border-radius:50%; background:var(--bg); border:2px solid var(--border); display:flex; align-items:center; justify-content:center; color:var(--text-muted); font-size:24px;">' + escapeHtml((auth.email || '?').charAt(0).toUpperCase()) + '</div>';
  var avatarHtml =
    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">Profile Picture</div>' +
      '<div style="display:flex; align-items:center; gap:18px;">' +
        avatarImg +
        '<div style="display:flex; flex-direction:column; gap:6px;">' +
          '<button class="btn btn-secondary" data-action="uploadAvatarClick" type="button">Upload Avatar</button>' +
          '<span style="color:var(--text-muted); font-size:12px;">Max size 2MB. Formats: JPG, PNG.</span>' +
        '</div>' +
        '<input type="file" id="profile-avatar-input" accept="image/png,image/jpeg" style="display:none;" data-action-change="onAvatarFileSelected"/>' +
      '</div>' +
    '</div>';

  var profileHtml =
    avatarHtml +
    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">My Account</div>' +
      '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
        'The email and password you use to sign in to Pulse.' +
      '</p>' +
      '<div class="form-row"><label>Account email</label>' +
        '<input type="email" id="account-email" value="' + escapeHtml(auth.email || '') + '"/></div>' +
      '<div class="form-row"><label>New password</label>' +
        '<input type="password" id="account-new-password" placeholder="leave blank to keep current" autocomplete="new-password"/></div>' +
      '<div class="form-row"><label>Current password</label>' +
        '<input type="password" id="account-current-password" placeholder="required to change email or password" autocomplete="current-password"/></div>' +
      '<div class="form-actions">' +
        '<button class="btn btn-primary" data-action="saveAccount">Save account changes</button>' +
        '<button class="btn" data-action="signOut">Sign out</button>' +
      '</div>' +
    '</div>';

  // --- Notifications tab ---------------------------------------------
  var emailSmtpHtml =
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
        '<input type="text" id="email-smtp_host" value="' + escapeHtml(em.smtp_host || '') + '" placeholder="smtp.example.com"/></div>' +
      '<div class="form-row" id="email-custom-port-row" style="display:' + (currentProvider === 'other' ? 'flex' : 'none') + ';">' +
        '<label>Server port</label>' +
        '<input type="number" id="email-smtp_port" value="' + (em.smtp_port || 587) + '"/></div>' +
      '<div class="form-row"><label>Your email</label>' +
        '<input type="email" id="email-sender" value="' + escapeHtml(em.sender || '') + '" placeholder="you@example.com"/></div>' +
      '<div class="form-row"><label>App password</label>' +
        '<input type="password" id="email-password" placeholder="' + (em.password_set ? 'leave blank to keep current' : '16-character app password') + '" autocomplete="new-password"/></div>' +
      '<div class="form-row"><span></span><span>' + pwStatus + ' <a id="email-help-link" href="#" target="_blank" style="color:var(--accent); text-decoration:none; margin-left:12px; display:none;">How do I get an app password?</a></span></div>' +
      '<div class="form-actions">' +
        '<button class="btn btn-primary" data-action="saveEmailSettings">Save email settings</button>' +
      '</div>' +
    '</div>';

  var thresholdAlertsHtml =
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
        '<input type="email" id="alert-recipient" value="' + escapeHtml(al.recipient || '') + '" placeholder="leave blank to use email recipient"/></div>' +
      '<div class="form-row"><label>Cooldown (min)</label>' +
        '<input type="number" id="alert-cooldown" value="' + (al.cooldown_minutes != null ? al.cooldown_minutes : 60) + '" min="0"/></div>' +
      '<div class="form-actions">' +
        '<button class="btn btn-primary" data-action="saveAlertSettings">Save alert settings</button>' +
        '<button class="btn" data-action="sendTestAlert">Send test alert</button>' +
      '</div>' +
    '</div>';

  var liveMonitorEmailsHtml =
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
    '</div>';

  // --- Scheduled Scans tab -------------------------------------------
  var scheduledHtml =
    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">Scheduled Scans</div>' +
      '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
        'Automatically scan your local Windows event logs on a schedule. ' +
        (schedSupported
          ? 'Findings are saved to history and can fire the alert methods below.'
          : '<strong>This host is not Windows \u2014 system scans are disabled.</strong>') +
      '</p>' +

      '<div class="form-row"><label>Scheduled scanning</label>' +
        '<label class="form-checkbox"><input type="checkbox" id="sched-enabled"' +
          (schedEnabled ? ' checked' : '') +
          (schedSupported ? '' : ' disabled') +
          '/> Enable automated scans</label></div>' +

      '<div class="form-row"><label>Time range</label>' +
        '<select id="sched-days">' + rangeOpts + '</select></div>' +

      '<div class="form-row"><label>Schedule</label>' +
        '<select id="sched-kind" data-action-change="onScheduleKindChange">' + kindOpts + '</select></div>' +

      '<div class="form-row" id="sched-daily-row" style="display:' + (schedKind === 'daily' ? 'flex' : 'none') + ';">' +
        '<label>Time of day</label>' +
        '<input type="time" id="sched-time-daily" value="' + escapeHtml(schedTime) + '"/></div>' +

      '<div class="form-row" id="sched-weekly-row" style="display:' + (schedKind === 'weekly' ? 'flex' : 'none') + ';">' +
        '<label>Day &amp; time</label>' +
        '<div style="display:flex; gap:8px; flex:1;">' +
          '<select id="sched-weekday" style="flex:1;">' + weekdayOpts + '</select>' +
          '<input type="time" id="sched-time-weekly" value="' + escapeHtml(schedTime) + '"/>' +
        '</div></div>' +

      '<div class="form-row" id="sched-cron-row" style="display:' + (schedKind === 'custom' ? 'flex' : 'none') + ';">' +
        '<label>Cron expression</label>' +
        '<input type="text" id="sched-cron" value="' + escapeHtml(schedCron) + '" placeholder="0 9 * * 1-5" autocomplete="off"/></div>' +
      '<div class="form-row" id="sched-cron-help" style="display:' + (schedKind === 'custom' ? 'flex' : 'none') + ';">' +
        '<span></span>' +
        '<span style="font-size:12px; color:var(--text-muted);">5 fields: minute hour day-of-month month day-of-week (Monday=0). Supports <span class="mono">*</span>, plain numbers, commas, and <span class="mono">*/N</span> steps.</span>' +
      '</div>' +

      '<div class="form-row"><label>Alert methods</label>' +
        '<div style="display:flex; gap:16px; flex-wrap:wrap;">' +
          '<label class="form-checkbox"><input type="checkbox" id="sched-alert-email"' +
            (sched.alert_email ? ' checked' : '') + (emailConfigured ? '' : ' disabled') +
            '/> Email' + (emailConfigured ? '' : ' (not configured)') + '</label>' +
          '<label class="form-checkbox"><input type="checkbox" id="sched-alert-slack"' +
            (sched.alert_slack ? ' checked' : '') + (webhookConfigured ? '' : ' disabled') +
            '/> Slack / Discord' + (webhookConfigured ? '' : ' (no webhook)') + '</label>' +
        '</div>' +
      '</div>' +

      '<div class="form-row"><label>Next scan</label>' +
        '<span id="sched-next-run" style="color:var(--text-muted); font-size:13px;">' +
          escapeHtml(schedDesc) + (schedNextRun ? ' \u2014 ' + escapeHtml(_formatNextRun(schedNextRun)) : '') +
        '</span></div>' +

      '<div class="form-actions">' +
        '<button class="btn btn-primary" data-action="saveScheduleSettings"' +
          (schedSupported ? '' : ' disabled') + '>Save schedule</button>' +
      '</div>' +
    '</div>';

  var webhookHtml =
    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">Slack / Discord Notifications</div>' +
      '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
        'Post threat findings to a Slack or Discord channel via incoming webhook. ' +
        'Fires alongside email when the alert threshold is met. ' +
        'Paste the webhook URL from your channel\u2019s integration settings.' +
      '</p>' +
      '<div class="form-row"><label>Enable webhook</label>' +
        '<label class="form-checkbox"><input type="checkbox" id="webhook-enabled"' + (wh.enabled ? ' checked' : '') + '/> Send alerts to webhook</label></div>' +
      '<div class="form-row"><label>Service</label>' +
        '<select id="webhook-flavor">' + flavorOpts + '</select></div>' +
      '<div class="form-row"><label>Webhook URL</label>' +
        '<input type="password" id="webhook-url" placeholder="' + (wh.url_set ? 'leave blank to keep current' : 'https://hooks.slack.com/...') + '" autocomplete="new-password"/></div>' +
      '<div class="form-row"><span></span><span>' + whUrlStatus + '</span></div>' +
      '<div class="form-actions">' +
        '<button class="btn btn-primary" data-action="saveWebhookSettings">Save webhook settings</button>' +
        '<button class="btn" data-action="sendTestWebhook">Send test notification</button>' +
      '</div>' +
    '</div>';

  // --- Advanced tab --------------------------------------------------
  var scanDefaultsHtml =
    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">Scan Defaults</div>' +
      '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
        'Defaults used when no CLI flags are provided. Edit in ' +
        '<span class="mono" style="color:var(--accent);">pulse.yaml</span> for now \u2014 ' +
        'inline editing arrives in a later release.' +
      '</p>' +
      '<div class="form-row"><label>Default log folder</label>' +
        '<input type="text" value="' + escapeHtml(scanDefaults.logs || '') + '" readonly style="background:var(--bg); color:var(--text-muted);"/></div>' +
      '<div class="form-row"><label>Default format</label>' +
        '<input type="text" value="' + escapeHtml((scanDefaults.format || '').toUpperCase()) + '" readonly style="background:var(--bg); color:var(--text-muted);"/></div>' +
      '<div class="form-row"><label>Default severity</label>' +
        '<input type="text" value="' + escapeHtml(scanDefaults.severity || '') + '" readonly style="background:var(--bg); color:var(--text-muted);"/></div>' +
    '</div>';

  // --- Appearance tab ------------------------------------------------
  var appearanceHtml =
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
    '</div>';

  var rulesCardHtml =
    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">Available Detection Rules (' + rules.rules.length + ')</div>' +
      '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
        'All rules Pulse runs during a scan. Suppress any rule by adding it to the whitelist.' +
      '</p>' +
      '<div>' +
        rules.rules.map(function (r) {
          return '<span class="whitelist-item">' + escapeHtml(r) + '</span>';
        }).join('') +
      '</div>' +
    '</div>';

  var resourcesHtml =
    '<div class="card">' +
      '<div class="section-label">Resources</div>' +
      '<p><a href="/docs" target="_blank" data-default="allow" style="color:var(--accent); text-decoration:none;">\u2192 API Documentation (Swagger)</a></p>' +
    '</div>';

  // --- Users tab (admins only) --------------------------------------
  var usersHtml = isAdmin ? _renderUsersPanel(me, usersList) : '';

  // --- Compose tab panels --------------------------------------------
  var panels = {
    profile:       profileHtml,
    notifications: thresholdAlertsHtml + liveMonitorEmailsHtml + webhookHtml,
    scheduled:     scheduledHtml,
    appearance:    appearanceHtml,
    users:         usersHtml,
    // SMTP is powerful but noisy — tucked behind a <details> so the
    // Advanced tab reads as a configuration inventory, not a form wall.
    advanced:
      '<details class="settings-collapsible" style="margin-bottom:16px;">' +
        '<summary><span class="settings-collapsible-title">SMTP Server</span>' +
          '<span class="settings-collapsible-hint">Outbound email for threshold + monitor alerts</span>' +
        '</summary>' +
        emailSmtpHtml +
      '</details>' +
      scanDefaultsHtml +
      rulesCardHtml +
      resourcesHtml,
  };

  var tabNavHtml = '<nav class="settings-tab-nav">' +
    visibleTabs.map(function (t) {
      var active = (t.id === _activeSettingsTab) ? ' active' : '';
      return '<a class="settings-tab-link' + active + '" ' +
               'data-action="switchSettingsTab" data-arg="' + t.id + '">' +
        '<i data-lucide="' + t.icon + '"></i>' +
        '<span>' + escapeHtml(t.label) + '</span>' +
      '</a>';
    }).join('') +
  '</nav>';

  var activeTab = visibleTabs.find(function (t) { return t.id === _activeSettingsTab; }) || visibleTabs[0];

  // Visible failure banner so Render/production issues are obvious
  // instead of silently degrading into empty fields + hang-looking UX.
  var failureBanner = failures.length
    ? '<div class="card" style="margin-bottom:16px; border-color:var(--severity-high, #e67e22);">' +
        '<div class="section-label" style="color:var(--severity-high, #e67e22);">' +
          'Some settings could not load' +
        '</div>' +
        '<p style="color:var(--text-muted); font-size:13px; margin:0 0 8px;">' +
          'Pulse reached the page, but the following endpoints failed. Check Render\u2019s logs for details.' +
        '</p>' +
        '<ul style="margin:0; padding-left:18px; color:var(--text-muted); font-size:12px;">' +
          failures.map(function (f) { return '<li>' + escapeHtml(f) + '</li>'; }).join('') +
        '</ul>' +
      '</div>'
    : '';

  c.innerHTML =
    '<div class="page-head">' +
      '<div class="page-head-title">' + escapeHtml(activeTab.label) + '</div>' +
    '</div>' +
    failureBanner +
    '<div class="settings-layout">' +
      tabNavHtml +
      '<div class="settings-tab-content">' + (panels[_activeSettingsTab] || panels.profile) + '</div>' +
    '</div>';

  // Rehydrate the Lucide tab icons — these are rendered dynamically so
  // they missed the boot-time createIcons() call.
  try {
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons();
    }
  } catch (e) {}

  // The SMTP provider presets fan out to rows that default to hidden
  // — only the Notifications/Advanced tabs render them, so gate the
  // sync so it doesn't throw on Profile/Scheduled.
  if (document.getElementById('email-provider')) onEmailProviderChange();
}

// ------------------------------------------------------------------------
// Users tab (admin-only)
// ------------------------------------------------------------------------

function _renderUsersPanel(me, users) {
  var rowsHtml = (users || []).map(function (u) {
    var isSelf = (u.id === me.id);
    var roleBadge = u.role === 'admin'
      ? '<span class="badge badge-high">admin</span>'
      : '<span class="badge badge-medium">viewer</span>';
    var activeBadge = u.active
      ? '<span class="badge badge-low">active</span>'
      : '<span class="badge" style="background:rgba(255,255,255,0.08); color:var(--text-muted);">disabled</span>';
    // Self-rows get no action buttons — the backend rejects self-demotion
    // and self-deactivation anyway, but dimming the controls keeps the
    // UI honest.
    var actions = isSelf
      ? '<span style="color:var(--text-muted); font-size:12px;">(you)</span>'
      : (
        '<button class="btn btn-secondary btn-sm" data-action="toggleUserRole" data-arg="' +
            u.id + '|' + (u.role === 'admin' ? 'viewer' : 'admin') +
          '">Make ' + (u.role === 'admin' ? 'viewer' : 'admin') + '</button> ' +
        '<button class="btn btn-secondary btn-sm" data-action="toggleUserActive" data-arg="' +
            u.id + '|' + (u.active ? '0' : '1') +
          '">' + (u.active ? 'Disable' : 'Enable') + '</button> ' +
        '<button class="btn btn-danger btn-sm" data-action="deleteUserConfirm" data-arg="' +
            u.id + '|' + encodeURIComponent(u.email) +
          '">Delete</button>'
      );
    return (
      '<tr>' +
        '<td>' + escapeHtml(u.email) + '</td>' +
        '<td>' + roleBadge + '</td>' +
        '<td>' + activeBadge + '</td>' +
        '<td style="color:var(--text-muted); font-size:12px;">' + escapeHtml(u.created_at || '') + '</td>' +
        '<td>' + actions + '</td>' +
      '</tr>'
    );
  }).join('');

  var tableHtml = users && users.length
    ? '<div class="table-wrap"><table class="table">' +
        '<thead><tr><th>Email</th><th>Role</th><th>Status</th><th>Created</th><th></th></tr></thead>' +
        '<tbody>' + rowsHtml + '</tbody>' +
      '</table></div>'
    : '<p style="color:var(--text-muted); font-size:13px;">No other users yet.</p>';

  return (
    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">Invite a User</div>' +
      '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
        'Admins can create additional accounts. Viewers can see scans and findings but cannot ' +
        'change settings, block IPs, or manage users.' +
      '</p>' +
      '<div class="form-row"><label>Email</label>' +
        '<input type="email" id="new-user-email" placeholder="user@example.com" autocomplete="off"/></div>' +
      '<div class="form-row"><label>Temporary password</label>' +
        '<input type="password" id="new-user-password" placeholder="at least 8 characters" autocomplete="new-password"/></div>' +
      '<div class="form-row"><label>Role</label>' +
        '<select id="new-user-role">' +
          '<option value="viewer" selected>Viewer (read-only)</option>' +
          '<option value="admin">Admin (full access)</option>' +
        '</select></div>' +
      '<div class="form-actions">' +
        '<button class="btn btn-primary" data-action="createUser">Create user</button>' +
      '</div>' +
    '</div>' +
    '<div class="card">' +
      '<div class="section-label">Accounts (' + (users || []).length + ')</div>' +
      tableHtml +
    '</div>'
  );
}

export async function createUser() {
  var email    = (document.getElementById('new-user-email').value || '').trim();
  var password = document.getElementById('new-user-password').value || '';
  var role     = document.getElementById('new-user-role').value || 'viewer';
  if (!email || !password) {
    toastError('Email and temporary password are both required.');
    return;
  }
  try {
    var r = await apiCreateUser({ email: email, password: password, role: role });
    if (!r.ok) {
      var err = await r.json().catch(function () { return {}; });
      toastError(err.detail || 'Create failed.');
      return;
    }
    showToast('Created ' + email);
    renderSettingsPage();
  } catch (e) {
    toastError('Network error: ' + e.message);
  }
}

export async function toggleUserRole(arg) {
  // arg format: "<id>|<newRole>" — encoded in the data-arg attribute so
  // the central action registry can pass it through unchanged.
  var parts = String(arg || '').split('|');
  var id = Number(parts[0]), role = parts[1];
  if (!id || !role) return;
  try {
    var r = await apiUpdateUserRole(id, role);
    if (!r.ok) {
      var err = await r.json().catch(function () { return {}; });
      toastError(err.detail || 'Role update failed.');
      return;
    }
    showToast('Role updated');
    renderSettingsPage();
  } catch (e) {
    toastError('Network error: ' + e.message);
  }
}

export async function toggleUserActive(arg) {
  var parts = String(arg || '').split('|');
  var id = Number(parts[0]), active = parts[1] === '1';
  if (!id) return;
  try {
    var r = await apiUpdateUserActive(id, active);
    if (!r.ok) {
      var err = await r.json().catch(function () { return {}; });
      toastError(err.detail || 'Status update failed.');
      return;
    }
    showToast(active ? 'Account enabled' : 'Account disabled');
    renderSettingsPage();
  } catch (e) {
    toastError('Network error: ' + e.message);
  }
}

export async function deleteUserConfirm(arg) {
  var parts = String(arg || '').split('|');
  var id = Number(parts[0]);
  var email = decodeURIComponent(parts[1] || '');
  if (!id) return;
  if (!window.confirm('Delete account ' + email + '? This cannot be undone.')) return;
  try {
    var r = await apiDeleteUser(id);
    if (!r.ok) {
      var err = await r.json().catch(function () { return {}; });
      toastError(err.detail || 'Delete failed.');
      return;
    }
    showToast('Deleted ' + email);
    renderSettingsPage();
  } catch (e) {
    toastError('Network error: ' + e.message);
  }
}


export async function saveAccount() {
  var newEmail = document.getElementById('account-email').value.trim();
  var newPw    = document.getElementById('account-new-password').value;
  var curPw    = document.getElementById('account-current-password').value;
  if (!curPw) {
    toastError('Enter your current password to make changes.');
    return;
  }
  try {
    var changed = false;
    if (newEmail) {
      var r1 = await apiChangeEmail(newEmail, curPw);
      if (!r1.ok) {
        toastError((r1.data && r1.data.detail) || 'Email update failed.');
        return;
      }
      changed = true;
    }
    if (newPw) {
      var r2 = await apiChangePassword(newPw, curPw);
      if (!r2.ok) {
        toastError((r2.data && r2.data.detail) || 'Password update failed.');
        return;
      }
      changed = true;
    }
    if (!changed) {
      toastError('Nothing to save \u2014 enter a new email or new password.');
      return;
    }
    showToast('Account updated');
    document.getElementById('account-new-password').value = '';
    document.getElementById('account-current-password').value = '';
    renderSettingsPage();
  } catch (e) {
    toastError('Network error: ' + e.message);
  }
}

export async function signOut() {
  await apiLogout();
  window.location.href = '/login';
}

export function onEmailProviderChange() {
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

export async function saveEmailSettings() {
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
    var r = await apiSaveEmailConfig(body);
    if (!r.ok) {
      var err = await r.json().catch(function () { return {}; });
      toastError(err.detail || 'Save failed.');
      return;
    }
    showToast('Email settings saved');
    document.getElementById('email-password').value = '';
    renderSettingsPage();
  } catch (e) {
    toastError('Network error: ' + e.message);
  }
}

export async function saveAlertSettings() {
  var body = {
    enabled:                  document.getElementById('alert-enabled').checked,
    threshold:                document.getElementById('alert-threshold').value,
    recipient:                document.getElementById('alert-recipient').value,
    cooldown_minutes:         document.getElementById('alert-cooldown').value,
    monitor_enabled:          document.getElementById('alert-monitor-enabled').checked,
    monitor_interval_minutes: document.getElementById('alert-monitor-interval').value,
  };
  try {
    var r = await apiSaveAlertsConfig(body);
    if (!r.ok) {
      var err = await r.json().catch(function () { return {}; });
      toastError(err.detail || 'Save failed.');
      return;
    }
    showToast('Alert settings saved');
  } catch (e) {
    toastError('Network error: ' + e.message);
  }
}

export async function sendTestAlert() {
  showToast('Sending test alert...');
  try {
    var r = await apiSendTestAlert();
    if (!r.ok) {
      toastError((r.data && r.data.detail) || 'Test failed.');
      return;
    }
    showToast('Test alert sent to ' + r.data.recipient);
  } catch (e) {
    toastError('Network error: ' + e.message);
  }
}

export async function saveWebhookSettings() {
  var body = {
    enabled: document.getElementById('webhook-enabled').checked,
    flavor:  document.getElementById('webhook-flavor').value,
    url:     document.getElementById('webhook-url').value,
  };
  try {
    var r = await apiSaveWebhookConfig(body);
    if (!r.ok) {
      var err = await r.json().catch(function () { return {}; });
      toastError(err.detail || 'Save failed.');
      return;
    }
    showToast('Webhook settings saved');
    document.getElementById('webhook-url').value = '';
    renderSettingsPage();
  } catch (e) {
    toastError('Network error: ' + e.message);
  }
}

export async function sendTestWebhook() {
  showToast('Sending test notification...');
  try {
    var r = await apiSendTestWebhook();
    if (!r.ok) {
      toastError((r.data && r.data.detail) || 'Test failed.');
      return;
    }
    showToast('Test notification posted');
  } catch (e) {
    toastError('Network error: ' + e.message);
  }
}

// Swap the time/weekday/cron rows on schedule-kind change.
export function onScheduleKindChange() {
  var sel = document.getElementById('sched-kind');
  if (!sel) return;
  var kind = sel.value;
  var show = function (id, on) {
    var el = document.getElementById(id);
    if (el) el.style.display = on ? 'flex' : 'none';
  };
  show('sched-daily-row',  kind === 'daily');
  show('sched-weekly-row', kind === 'weekly');
  show('sched-cron-row',   kind === 'custom');
  show('sched-cron-help',  kind === 'custom');
}

export async function saveScheduleSettings() {
  var kind = document.getElementById('sched-kind').value;
  var time;
  if (kind === 'daily') {
    time = document.getElementById('sched-time-daily').value || '09:00';
  } else if (kind === 'weekly') {
    time = document.getElementById('sched-time-weekly').value || '09:00';
  } else {
    time = '09:00';
  }
  var body = {
    enabled:       document.getElementById('sched-enabled').checked,
    days:          Number(document.getElementById('sched-days').value) || 7,
    schedule:      kind,
    time:          time,
    weekday:       Number(document.getElementById('sched-weekday').value || 1),
    cron:          (document.getElementById('sched-cron').value || '').trim(),
    alert_email:   document.getElementById('sched-alert-email').checked,
    alert_slack:   document.getElementById('sched-alert-slack').checked,
    // Slack and Discord share a single webhook channel in Pulse, so the
    // UI exposes one toggle — keep the backend contract both flags so
    // future per-service toggles don't need a schema change.
    alert_discord: document.getElementById('sched-alert-slack').checked,
  };
  try {
    var r = await apiSaveSchedulerConfig(body);
    if (!r.ok) {
      toastError((r.data && r.data.detail) || 'Save failed.');
      return;
    }
    showToast('Schedule saved');
    var span = document.getElementById('sched-next-run');
    if (span && r.data) {
      var desc = r.data.schedule || 'Scheduled';
      var nx = r.data.next_run ? ' \u2014 ' + _formatNextRun(r.data.next_run) : '';
      span.textContent = desc + nx;
    }
  } catch (e) {
    toastError('Network error: ' + e.message);
  }
}

function _formatNextRun(iso) {
  if (!iso) return '';
  try {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return 'next run ' + d.toLocaleString();
  } catch (e) {
    return iso;
  }
}

// ------------------------------------------------------------------------
// Profile avatar
// ------------------------------------------------------------------------

export function uploadAvatarClick() {
  var input = document.getElementById('profile-avatar-input');
  if (input) input.click();
}

export async function onAvatarFileSelected(_arg, target) {
  var input = target || document.getElementById('profile-avatar-input');
  var file = input && input.files && input.files[0];
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) {
    toastError('Avatar must be 2MB or smaller.');
    input.value = '';
    return;
  }
  try {
    await apiUploadAvatar(file);
    _avatarCacheBuster = String(Date.now());
    refreshUserMenuAvatar(_avatarCacheBuster);
    showToast('Profile picture updated.');
    renderSettingsPage();
  } catch (e) {
    toastError('Upload failed: ' + (e && e.message ? e.message : e));
  } finally {
    if (input) input.value = '';
  }
}
