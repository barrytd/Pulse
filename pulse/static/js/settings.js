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
  apiUpdateUserDisplayName,
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
  apiListTokens,
  apiCreateToken,
  apiRevokeToken,
  apiListFeedback,
  apiListAllNotes,
} from './api.js';
import { escapeHtml, showToast, toastError, formatRelativeTime } from './dashboard.js';
import { getTheme } from './theme.js';
import { refreshUserMenuAvatar, refreshUserMenuIdentity } from './user-menu.js';

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
  { id: 'tokens',        label: 'API Tokens',      icon: 'key' },
  { id: 'users',         label: 'Users',           icon: 'users', adminOnly: true },
  { id: 'feedback',      label: 'Feedback',        icon: 'message-square', adminOnly: true },
  { id: 'notes',         label: 'Notes',           icon: 'sticky-note', adminOnly: true },
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

  // API tokens for the current user — always fetched (every signed-in
  // user can manage their own CI tokens). A failure here renders the
  // tab as empty rather than blocking the rest of the page.
  var tokensList = [];
  try {
    var tl = await apiListTokens();
    tokensList = tl.tokens || [];
  } catch (e) { tokensList = []; }

  // Admin-only feedback submissions — same "skip for viewers" pattern
  // as the users list so the Network tab stays clean.
  var feedbackRows = [];
  if (isAdmin) {
    try {
      var fb = await apiListFeedback(500);
      feedbackRows = (fb && fb.rows) || [];
    } catch (e) { feedbackRows = []; }
  }

  // Admin-only cross-finding notes feed.
  var notesRows = [];
  if (isAdmin) {
    try {
      var nl = await apiListAllNotes(500);
      notesRows = (nl && nl.notes) || [];
    } catch (e) { notesRows = []; }
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

  // Display name is admin-editable only (Settings > Users). Show the
  // current value here as a read-only row so the user can see their
  // own name without leaving the Profile tab.
  var displayNameValue = (me && me.display_name) ? String(me.display_name).trim() : '';
  var displayNameHtml = displayNameValue
    ? escapeHtml(displayNameValue)
    : '<span style="color:var(--text-light); font-style:italic;">— not set —</span>';
  // Admins get a nudge that the edit control lives on the Users tab;
  // non-admins get a "contact an admin" hint. Single-user installs are
  // always admins so they see the direct link.
  var nameHint = isAdmin
    ? '<a class="profile-name-hint" data-action="switchSettingsTab" data-arg="users">' +
        'Edit on the Users tab' +
      '</a>'
    : '<span class="profile-name-hint muted">Ask an admin to change this</span>';

  var profileHtml =
    avatarHtml +
    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">My Account</div>' +
      '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
        'The email and password you use to sign in to Pulse.' +
      '</p>' +
      '<div class="form-row"><label>Display name</label>' +
        '<div class="profile-name-row">' +
          '<span class="profile-name-value">' + displayNameHtml + '</span>' +
          nameHint +
        '</div>' +
      '</div>' +
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
  var feedbackHtml = isAdmin ? _renderFeedbackPanel(feedbackRows) : '';
  var notesHtml = isAdmin ? _renderNotesAdminPanel(notesRows) : '';

  // --- API tokens tab -----------------------------------------------
  var tokensHtml = _renderTokensPanel(tokensList);

  // --- Compose tab panels --------------------------------------------
  var panels = {
    profile:       profileHtml,
    notifications: thresholdAlertsHtml + liveMonitorEmailsHtml + webhookHtml,
    scheduled:     scheduledHtml,
    appearance:    appearanceHtml,
    tokens:        tokensHtml,
    users:         usersHtml,
    feedback:      feedbackHtml,
    notes:         notesHtml,
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

    // Role: pill badge. Admin = accent blue, viewer = neutral grey.
    // Using the canonical .pill styling from pulse-design.md; a new
    // .pill-admin / .pill-viewer modifier keeps it distinct from the
    // severity-pill set.
    var rolePill = u.role === 'admin'
      ? '<span class="pill pill-admin">Admin</span>'
      : '<span class="pill pill-viewer">Viewer</span>';

    // Status: dot + label. Green dot + "Active", red dot + "Disabled".
    var statusCell = u.active
      ? '<span class="user-status user-status-active">' +
          '<span class="user-status-dot" aria-hidden="true"></span>Active' +
        '</span>'
      : '<span class="user-status user-status-disabled">' +
          '<span class="user-status-dot" aria-hidden="true"></span>Disabled' +
        '</span>';

    // Name: inline editable input (admins only touch this panel so all
    // viewers here have edit rights). data-prior-value is seeded so the
    // save handler can detect no-ops.
    var dnVal = escapeHtml(u.display_name || '');
    var nameInput =
      '<input type="text" class="user-dn-input" placeholder="— not set —" ' +
        'value="' + dnVal + '" maxlength="100" data-user-id="' + u.id + '" ' +
        'data-prior-value="' + dnVal + '" ' +
        'data-action-change="saveUserDisplayName" data-action-keydown="saveUserDisplayNameOnEnter" />';

    // Per-row 3-dot menu using the canonical .pulse-dropdown pattern.
    // The self row still gets the menu so the admin can flip their own
    // role (the backend guards the last-admin case); Disable + Delete
    // are hidden since those would lock them out.
    var menuItems = (
      // Change role — always shown; wording flips based on current role.
      '<a class="pulse-dropdown-item" data-action="toggleUserRole" data-arg="' +
          u.id + '|' + (u.role === 'admin' ? 'viewer' : 'admin') + '">' +
        '<i data-lucide="shield"></i>' +
        '<span>Make ' + (u.role === 'admin' ? 'viewer' : 'admin') + '</span>' +
      '</a>'
    ) + (isSelf ? '' : (
      '<a class="pulse-dropdown-item" data-action="toggleUserActive" data-arg="' +
          u.id + '|' + (u.active ? '0' : '1') + '">' +
        '<i data-lucide="' + (u.active ? 'user-minus' : 'user-check') + '"></i>' +
        '<span>' + (u.active ? 'Disable account' : 'Enable account') + '</span>' +
      '</a>' +
      '<div class="pulse-dropdown-divider"></div>' +
      '<a class="pulse-dropdown-item pulse-dropdown-item-danger" ' +
         'data-action="deleteUserConfirm" data-arg="' +
         u.id + '|' + encodeURIComponent(u.email) + '">' +
        '<i data-lucide="trash-2"></i>' +
        '<span>Delete account</span>' +
      '</a>'
    ));

    var actionsCell = (
      '<div class="user-actions-wrap">' +
        '<button type="button" class="user-actions-trigger" ' +
          'data-action="toggleUserRowMenu" data-arg="' + u.id + '" ' +
          'aria-haspopup="menu" aria-expanded="false" ' +
          'aria-label="Row actions">' +
          '<span class="user-actions-dots" aria-hidden="true">⋯</span>' +
        '</button>' +
        '<div class="pulse-dropdown user-actions-menu" id="user-actions-menu-' + u.id + '" hidden>' +
          '<div class="pulse-dropdown-section">' +
            menuItems +
          '</div>' +
        '</div>' +
      '</div>'
    );

    return (
      '<tr class="user-row' + (isSelf ? ' is-self' : '') + '">' +
        '<td class="user-cell-name">' + nameInput +
          (isSelf ? ' <span class="user-self-badge">you</span>' : '') + '</td>' +
        '<td class="user-cell-email">' + escapeHtml(u.email) + '</td>' +
        '<td class="user-cell-role">' + rolePill + '</td>' +
        '<td class="user-cell-status">' + statusCell + '</td>' +
        '<td class="user-cell-created">' + escapeHtml(u.created_at || '') + '</td>' +
        '<td class="user-cell-actions">' + actionsCell + '</td>' +
      '</tr>'
    );
  }).join('');

  var tableHtml = users && users.length
    ? '<div class="table-wrap"><table class="users-table">' +
        '<thead><tr>' +
          '<th>Name</th><th>Email</th><th>Role</th><th>Status</th>' +
          '<th>Created</th><th class="user-cell-actions" aria-label="Actions"></th>' +
        '</tr></thead>' +
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
      '<div class="form-row"><label>Display name</label>' +
        '<input type="text" id="new-user-display-name" placeholder="e.g. Robert Perez" ' +
          'autocomplete="off" maxlength="100"/></div>' +
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

// Render the API Tokens tab. Every signed-in user sees their own tokens
// here — there's no admin view that lists other users' tokens. The tab
// has two parts: a create form (name only, token is minted server-side),
// and a table of existing tokens with name, last4, created_at, last_used,
// and a Revoke button.
function _renderTokensPanel(tokens) {
  var rowsHtml = (tokens || []).map(function (t) {
    var lastUsed = t.last_used_at
      ? escapeHtml(t.last_used_at)
      : '<span style="color:var(--text-muted);">never</span>';
    return (
      '<tr>' +
        '<td>' + escapeHtml(t.name || '') + '</td>' +
        '<td style="font-family:monospace; color:var(--text-muted);">\u2026' + escapeHtml(t.last4 || '') + '</td>' +
        '<td style="color:var(--text-muted); font-size:12px;">' + escapeHtml(t.created_at || '') + '</td>' +
        '<td style="color:var(--text-muted); font-size:12px;">' + lastUsed + '</td>' +
        '<td>' +
          '<button class="btn btn-danger btn-sm" data-action="revokeTokenConfirm" data-arg="' +
            t.id + '|' + encodeURIComponent(t.name || '') +
          '">Revoke</button>' +
        '</td>' +
      '</tr>'
    );
  }).join('');

  var tableHtml = tokens && tokens.length
    ? '<div class="table-wrap"><table class="table">' +
        '<thead><tr><th>Name</th><th>Token</th><th>Created</th><th>Last used</th><th></th></tr></thead>' +
        '<tbody>' + rowsHtml + '</tbody>' +
      '</table></div>'
    : '<p style="color:var(--text-muted); font-size:13px;">No API tokens yet.</p>';

  return (
    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">Create a Token</div>' +
      '<p style="color:var(--text-muted); font-size:13px; margin-bottom:14px;">' +
        'API tokens let CI pipelines and scripts hit Pulse endpoints without a browser login. ' +
        'Send the token as an <code>Authorization: Bearer &lt;token&gt;</code> header. ' +
        'Tokens inherit your role \u2014 treat them like a password.' +
      '</p>' +
      '<div class="form-row"><label>Name</label>' +
        '<input type="text" id="new-token-name" placeholder="e.g. Jenkins prod" autocomplete="off" maxlength="64"/></div>' +
      '<div class="form-actions">' +
        '<button class="btn btn-primary" data-action="createToken">Create Token</button>' +
      '</div>' +
    '</div>' +
    '<div class="card">' +
      '<div class="section-label">Active Tokens (' + (tokens || []).length + ')</div>' +
      tableHtml +
    '</div>'
  );
}

// Admin-only panel listing in-app feedback submissions. Structure:
//   1. KPI strip (Total / Bugs / Ideas / General / Hot page) — matches the
//      Fleet/Whitelist clickable-tile pattern from the UX blueprint
//   2. Table of submissions with kind chip, relative time, author, page,
//      truncated message preview.
// Messages expand inline on click so admins can read long notes without
// leaving the page.
function _renderFeedbackPanel(rows) {
  var total = rows.length;
  var counts = { bug: 0, idea: 0, general: 0 };
  var pageHits = {};
  rows.forEach(function (r) {
    var k = (r.kind || 'general').toLowerCase();
    if (counts[k] !== undefined) counts[k]++;
    var p = (r.page_hint || '').trim();
    if (p) pageHits[p] = (pageHits[p] || 0) + 1;
  });
  var hottestPage = '';
  var hottestCount = 0;
  Object.keys(pageHits).forEach(function (p) {
    if (pageHits[p] > hottestCount) { hottestCount = pageHits[p]; hottestPage = p; }
  });

  function _tile(label, value, accent) {
    return '<div class="feedback-kpi' + (accent ? ' feedback-kpi-' + accent : '') + '">' +
      '<div class="feedback-kpi-value">' + escapeHtml(String(value)) + '</div>' +
      '<div class="feedback-kpi-label">' + escapeHtml(label) + '</div>' +
    '</div>';
  }

  var kpiHtml =
    '<div class="feedback-kpi-strip">' +
      _tile('Total', total, '') +
      _tile('Bugs', counts.bug, 'bug') +
      _tile('Ideas', counts.idea, 'idea') +
      _tile('General', counts.general, 'general') +
      _tile('Top Page', hottestPage ? '/' + hottestPage : '—', 'muted') +
    '</div>';

  if (total === 0) {
    return (
      '<div class="card" style="margin-bottom:16px;">' +
        '<div class="section-label">Feedback</div>' +
        '<p style="color:var(--text-muted); font-size:13px; margin:0 0 14px;">' +
          'Submissions from the in-app feedback modal land here. Nothing yet — ' +
          'the FAB in the bottom-right corner of every page lets users file bugs, ideas, and general thoughts.' +
        '</p>' +
        kpiHtml +
      '</div>'
    );
  }

  var rowsHtml = rows.map(function (r, i) {
    var kind = (r.kind || 'general').toLowerCase();
    var submittedAt = r.submitted_at || '';
    var rel = formatRelativeTime(submittedAt);
    var email = r.email || ('user #' + (r.user_id || '?'));
    var page = r.page_hint ? '/' + r.page_hint : '—';
    var msg = String(r.message || '');
    var preview = msg.length > 140 ? msg.slice(0, 140) + '…' : msg;
    return (
      '<tr class="feedback-row" data-action="toggleFeedbackRow" data-arg="' + i + '">' +
        '<td class="feedback-when" title="' + escapeHtml(submittedAt) + '">' +
          escapeHtml(rel) +
        '</td>' +
        '<td><span class="feedback-chip feedback-chip-' + kind + '">' + escapeHtml(kind) + '</span></td>' +
        '<td class="feedback-from">' + escapeHtml(email) + '</td>' +
        '<td><span class="mono feedback-page">' + escapeHtml(page) + '</span></td>' +
        '<td class="feedback-message">' +
          '<div class="feedback-message-preview">' + escapeHtml(preview) + '</div>' +
          '<div class="feedback-message-full" hidden>' + escapeHtml(msg) + '</div>' +
        '</td>' +
      '</tr>'
    );
  }).join('');

  return (
    kpiHtml +
    '<div class="card" style="padding:0; overflow:hidden;">' +
      '<div class="section-label" style="padding:16px 20px 8px;">' +
        'Submissions (' + total + ')' +
      '</div>' +
      '<div class="table-wrap"><table class="data-table">' +
        '<thead><tr>' +
          '<th>When</th><th>Kind</th><th>From</th><th>Page</th><th>Message</th>' +
        '</tr></thead>' +
        '<tbody>' + rowsHtml + '</tbody>' +
      '</table></div>' +
    '</div>'
  );
}

// Click a row to expand the full message. Re-click collapses.
export function toggleFeedbackRow(arg, target) {
  var row = target && target.closest ? target.closest('.feedback-row') : null;
  if (!row) return;
  var preview = row.querySelector('.feedback-message-preview');
  var full    = row.querySelector('.feedback-message-full');
  if (!preview || !full) return;
  var expanded = !full.hasAttribute('hidden');
  if (expanded) {
    full.setAttribute('hidden', '');
    preview.removeAttribute('hidden');
    row.classList.remove('is-expanded');
  } else {
    preview.setAttribute('hidden', '');
    full.removeAttribute('hidden');
    row.classList.add('is-expanded');
  }
}

// Admin-only cross-finding Notes feed. Mirrors _renderFeedbackPanel: a
// 4-tile KPI strip + a submissions table. Row click expands the note body
// inline; the "Open finding" link in each row navigates to the parent scan
// so the admin can read the note in its finding context.
function _renderNotesAdminPanel(rows) {
  var total = rows.length;

  // KPI math: notes in last 7 days, unique authors, top-noted rule.
  var weekCutoff = Date.now() - 7 * 86400000;
  var weekCount = 0;
  var authors = {};
  var ruleAgg = {};
  rows.forEach(function (r) {
    var t = Date.parse((r.created_at || '').replace(' ', 'T'));
    if (!isNaN(t) && t >= weekCutoff) weekCount++;
    if (r.email) authors[r.email] = true;
    if (r.rule) ruleAgg[r.rule] = (ruleAgg[r.rule] || 0) + 1;
  });
  var topRule = '';
  var topRuleCount = 0;
  Object.keys(ruleAgg).forEach(function (k) {
    if (ruleAgg[k] > topRuleCount) { topRuleCount = ruleAgg[k]; topRule = k; }
  });

  function _tile(label, value, accent) {
    return '<div class="feedback-kpi' + (accent ? ' feedback-kpi-' + accent : '') + '">' +
      '<div class="feedback-kpi-value">' + escapeHtml(String(value)) + '</div>' +
      '<div class="feedback-kpi-label">' + escapeHtml(label) + '</div>' +
    '</div>';
  }

  var kpiHtml =
    '<div class="feedback-kpi-strip">' +
      _tile('Total Notes', total, '') +
      _tile('Last 7 Days', weekCount, 'idea') +
      _tile('Authors', Object.keys(authors).length, 'general') +
      _tile('Top Rule', topRule || '—', 'muted') +
    '</div>';

  if (total === 0) {
    return (
      '<div class="card" style="margin-bottom:16px;">' +
        '<div class="section-label">Notes</div>' +
        '<p style="color:var(--text-muted); font-size:13px; margin:0 0 14px;">' +
          'Every analyst note posted on any finding will appear here, newest-first. ' +
          'Nothing yet — notes are added from the Notes section of the finding drawer.' +
        '</p>' +
        kpiHtml +
      '</div>'
    );
  }

  var rowsHtml = rows.map(function (r, i) {
    var sev = (r.severity || 'LOW').toUpperCase();
    var sevCls = 'badge badge-' + sev.toLowerCase();
    var ref = r.ref_id || ('#' + r.finding_id);
    var rule = r.rule || 'Unknown rule';
    var author = (r.display_name && r.display_name.trim()) ||
                 r.email || ('user #' + (r.user_id || '?'));
    var when = r.created_at || '';
    var rel = (function () {
      // Lightweight relative-time; mirrors dashboard formatRelativeTime.
      var t = Date.parse((when || '').replace(' ', 'T'));
      if (isNaN(t)) return when;
      var sec = Math.max(0, Math.floor((Date.now() - t) / 1000));
      if (sec < 45)    return 'just now';
      if (sec < 3600)  return Math.floor(sec / 60)  + 'm ago';
      if (sec < 86400) return Math.floor(sec / 3600) + 'h ago';
      return Math.floor(sec / 86400) + 'd ago';
    })();
    var body = String(r.body || '');
    var preview = body.length > 140 ? body.slice(0, 140) + '…' : body;
    var scanHref = r.scan_id ? ('/scans/' + r.scan_id) : '#';
    return (
      '<tr class="feedback-row note-admin-row" data-action="toggleNoteAdminRow" data-arg="' + i + '">' +
        '<td class="feedback-when" title="' + escapeHtml(when) + '">' +
          escapeHtml(rel) +
        '</td>' +
        '<td><span class="' + sevCls + '">' + escapeHtml(sev) + '</span></td>' +
        '<td class="feedback-from">' + escapeHtml(author) + '</td>' +
        '<td>' +
          '<a href="' + escapeHtml(scanHref) + '" data-action="viewScanFromLink" ' +
             'data-arg="' + escapeHtml(String(r.scan_id || '')) + '" ' +
             'class="note-rule-link">' +
             escapeHtml(rule) + ' <span class="mono">' + escapeHtml(ref) + '</span>' +
          '</a>' +
        '</td>' +
        '<td class="feedback-message">' +
          '<div class="feedback-message-preview">' + escapeHtml(preview) + '</div>' +
          '<div class="feedback-message-full" hidden>' + escapeHtml(body) + '</div>' +
        '</td>' +
      '</tr>'
    );
  }).join('');

  return (
    kpiHtml +
    '<div class="card" style="padding:0; overflow:hidden;">' +
      '<div class="section-label" style="padding:16px 20px 8px;">' +
        'Notes (' + total + ')' +
      '</div>' +
      '<div class="table-wrap"><table class="data-table">' +
        '<thead><tr>' +
          '<th>When</th><th>Sev</th><th>Author</th><th>Finding</th><th>Note</th>' +
        '</tr></thead>' +
        '<tbody>' + rowsHtml + '</tbody>' +
      '</table></div>' +
    '</div>'
  );
}

// Expand/collapse the body preview. Same pattern as toggleFeedbackRow.
export function toggleNoteAdminRow(arg, target, e) {
  // Don't toggle when the click originated on the rule link (that navigates).
  if (e && e.target && e.target.closest && e.target.closest('.note-rule-link')) return;
  var row = target && target.closest ? target.closest('.note-admin-row') : null;
  if (!row) return;
  var preview = row.querySelector('.feedback-message-preview');
  var full    = row.querySelector('.feedback-message-full');
  if (!preview || !full) return;
  var expanded = !full.hasAttribute('hidden');
  if (expanded) {
    full.setAttribute('hidden', '');
    preview.removeAttribute('hidden');
    row.classList.remove('is-expanded');
  } else {
    preview.setAttribute('hidden', '');
    full.removeAttribute('hidden');
    row.classList.add('is-expanded');
  }
}

export async function createToken() {
  var input = document.getElementById('new-token-name');
  var name = (input && input.value ? input.value : '').trim();
  if (!name) {
    toastError('Token name is required.');
    return;
  }
  try {
    var r = await apiCreateToken(name);
    // Raw token is only available here — once this modal closes the user
    // can never see it again. The prompt is deliberately blocking so the
    // user has to consciously copy it.
    window.prompt(
      'Copy this token now \u2014 it will not be shown again:',
      r.token
    );
    if (input) input.value = '';
    showToast('Token "' + name + '" created.');
    renderSettingsPage();
  } catch (e) {
    toastError('Could not create token: ' + (e && e.message ? e.message : String(e)));
  }
}

export async function revokeTokenConfirm(arg) {
  // arg = "<id>|<url-encoded-name>"
  var parts = String(arg || '').split('|');
  var id   = parts[0];
  var name = decodeURIComponent(parts[1] || '');
  if (!id) return;
  if (!window.confirm('Revoke token "' + name + '"? Any script using it will start getting 401s.')) return;
  try {
    await apiRevokeToken(id);
    showToast('Token revoked.');
    renderSettingsPage();
  } catch (e) {
    toastError('Could not revoke token: ' + (e && e.message ? e.message : String(e)));
  }
}

export async function createUser() {
  var email    = (document.getElementById('new-user-email').value || '').trim();
  var password = document.getElementById('new-user-password').value || '';
  var role     = document.getElementById('new-user-role').value || 'viewer';
  var dnEl     = document.getElementById('new-user-display-name');
  var displayName = dnEl ? (dnEl.value || '').trim() : '';
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
    // If the admin typed a display name on the invite form, apply it in
    // a follow-up call. Keeping the create endpoint as-is (email +
    // password + role only) means no backend changes for this UX add.
    if (displayName) {
      try {
        var created = await r.json();
        if (created && created.id) {
          await apiUpdateUserDisplayName(created.id, displayName);
        }
      } catch (e) { /* non-fatal — name can still be set from the row */ }
    }
    showToast('Created ' + (displayName || email));
    renderSettingsPage();
  } catch (e) {
    toastError('Network error: ' + e.message);
  }
}

// Per-row actions dropdown toggle. Closes any other open menu first so
// only one row's menu is visible at a time.
export function toggleUserRowMenu(arg, target) {
  var id = String(arg || '');
  var menu = document.getElementById('user-actions-menu-' + id);
  if (!menu) return;
  var open = !menu.hidden;
  // Close every other open menu so the page never has two dropdowns up.
  document.querySelectorAll('.user-actions-menu').forEach(function (m) {
    if (m !== menu) m.hidden = true;
  });
  document.querySelectorAll('.user-actions-trigger').forEach(function (b) {
    if (b !== target) b.setAttribute('aria-expanded', 'false');
  });
  menu.hidden = open;
  if (target) target.setAttribute('aria-expanded', open ? 'false' : 'true');
  // Rehydrate the Lucide icons inside the menu since the HTML was
  // injected during the settings render and icons haven't replaced
  // their placeholder <i> tags yet on first open.
  if (!open && window.lucide && window.lucide.createIcons) {
    window.lucide.createIcons();
  }
}

// Close any open user row menu on outside click / Esc.
document.addEventListener('click', function (e) {
  var t = e.target;
  if (t && t.closest && t.closest('.user-actions-wrap')) return;
  document.querySelectorAll('.user-actions-menu').forEach(function (m) { m.hidden = true; });
  document.querySelectorAll('.user-actions-trigger').forEach(function (b) {
    b.setAttribute('aria-expanded', 'false');
  });
});
document.addEventListener('keydown', function (e) {
  if (e.key !== 'Escape') return;
  document.querySelectorAll('.user-actions-menu').forEach(function (m) { m.hidden = true; });
  document.querySelectorAll('.user-actions-trigger').forEach(function (b) {
    b.setAttribute('aria-expanded', 'false');
  });
});

// Saves on blur (change event) and on Enter. Other keys are ignored.
// Bound via data-action-keydown so the registry hands us the event.
export function saveUserDisplayNameOnEnter(arg, target, e) {
  if (e && e.key === 'Enter' && target) {
    target.blur();
  }
}

export async function saveUserDisplayName(arg, target) {
  if (!target) return;
  var id = Number(target.getAttribute('data-user-id'));
  if (!id) return;
  var prior = target.getAttribute('data-prior-value');
  if (prior === null) prior = target.defaultValue || '';
  var next = (target.value || '').trim();
  if (next === prior) return; // no-op
  target.disabled = true;
  try {
    var r = await apiUpdateUserDisplayName(id, next || null);
    if (!r || !r.ok) {
      toastError((r && r.data && r.data.detail) || 'Could not save name.');
      target.value = prior;
      return;
    }
    target.setAttribute('data-prior-value', next);
    showToast(next ? 'Name saved' : 'Name cleared');
    // If the admin just renamed themselves, refresh the topbar greeting
    // so "Hey, Robert!" lands without a page reload.
    try {
      var me = await apiGetMe();
      if (me && Number(me.id) === id) {
        refreshUserMenuIdentity();
      }
    } catch (e) { /* best effort */ }
  } finally {
    target.disabled = false;
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
