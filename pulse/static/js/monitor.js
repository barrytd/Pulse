// monitor.js — Live monitor SSE client + Monitor page + dashboard-embedded
// live panel. The EventSource itself stays here (it's not fetch()); all
// HTTP calls route through api.js wrappers.
'use strict';

import {
  apiMonitorStatus,
  apiMonitorHistory,
  apiMonitorStart,
  apiMonitorStop,
  apiMonitorTestAlert,
  apiMonitorSessions,
  apiMonitorSessionFindings,
  apiDeleteMonitorSession,
  apiClearMonitorSessions,
} from './api.js';
import { escapeHtml, toastError, showToast } from './dashboard.js';
import { openFindingDrawer } from './findings.js';

// Module-level refs that used to live on window as _dashLiveUnsub /
// _monPageUnsub / _dingCtx.
let _dingCtx         = null;
let _dashLiveUnsub   = null;
let _monPageUnsub    = null;
// Preserve whether the dashboard gear popover was open across re-renders
// so an incoming SSE event doesn't yank it closed mid-interaction.
let _livePopoverOpen = false;

// ---------------------------------------------------------------
// Channel multi-select — persistent across sessions
// ---------------------------------------------------------------
export const BUILTIN_CHANNELS = [
  'Security',
  'System',
  'Application',
  'Windows PowerShell',
  'Microsoft-Windows-PowerShell/Operational',
  'Microsoft-Windows-TaskScheduler/Operational',
];
const DEFAULT_CHECKED = ['Security', 'System'];
const LS_CHANNELS = 'pulse.monitor.channels.builtin';
const LS_CUSTOM   = 'pulse.monitor.channels.custom';
const LS_INTERVAL = 'pulse.monitor.interval';

export function getStoredInterval() {
  try {
    var raw = localStorage.getItem(LS_INTERVAL);
    var n = parseInt(raw, 10);
    return (isFinite(n) && n >= 5 && n <= 300) ? n : null;
  } catch (e) { return null; }
}

function _saveStoredInterval(n) {
  try { localStorage.setItem(LS_INTERVAL, String(n)); } catch (e) {}
}

export function getCheckedBuiltinChannels() {
  try {
    var raw = localStorage.getItem(LS_CHANNELS);
    if (raw == null) return DEFAULT_CHECKED.slice();
    var arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.filter(function (c) { return BUILTIN_CHANNELS.indexOf(c) >= 0; }) : DEFAULT_CHECKED.slice();
  } catch (e) { return DEFAULT_CHECKED.slice(); }
}

function _saveCheckedBuiltinChannels(arr) {
  try { localStorage.setItem(LS_CHANNELS, JSON.stringify(arr)); } catch (e) {}
}

export function getCustomChannels() {
  try {
    var raw = localStorage.getItem(LS_CUSTOM);
    if (!raw) return [];
    return raw.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
  } catch (e) { return []; }
}

function _saveCustomChannelsRaw(raw) {
  try { localStorage.setItem(LS_CUSTOM, raw || ''); } catch (e) {}
}

// Full effective channel list for starting the monitor.
export function getSelectedChannels() {
  var combined = getCheckedBuiltinChannels().concat(getCustomChannels());
  // De-dupe, preserve order.
  var seen = {};
  return combined.filter(function (c) {
    if (seen[c]) return false;
    seen[c] = true;
    return true;
  });
}

// Summary string for the closed dropdown button.
function _channelSummary() {
  var sel = getSelectedChannels();
  if (sel.length === 0) return 'No channels selected';
  if (sel.length <= 2) return sel.join(', ');
  return sel.slice(0, 2).join(', ') + ' +' + (sel.length - 2) + ' more';
}

export function channelMultiSelectHtml(opts) {
  opts = opts || {};
  var disabled = !!opts.disabled;
  var checked = getCheckedBuiltinChannels();
  var customRaw = localStorage.getItem(LS_CUSTOM) || '';
  var customEnabled = customRaw.length > 0;

  var items = BUILTIN_CHANNELS.map(function (name) {
    var isChecked = checked.indexOf(name) >= 0;
    return '<label class="channel-option">' +
      '<input type="checkbox" data-action="toggleChannelOption" data-arg="' +
        escapeHtml(name) + '"' + (isChecked ? ' checked' : '') +
        (disabled ? ' disabled' : '') + ' />' +
      '<span>' + escapeHtml(name) + '</span>' +
    '</label>';
  }).join('');

  return '<div class="channel-select" id="channel-select" data-channel-select>' +
    '<button type="button" class="channel-select-btn" ' +
      'data-action="toggleChannelDropdown"' + (disabled ? ' disabled' : '') + '>' +
      '<span class="channel-select-summary" id="channel-select-summary">' +
        escapeHtml(_channelSummary()) +
      '</span>' +
      '<span class="channel-select-arrow">\u25BE</span>' +
    '</button>' +
    '<div class="channel-select-menu" id="channel-select-menu">' +
      items +
      '<div class="channel-select-divider"></div>' +
      '<label class="channel-option">' +
        '<input type="checkbox" id="channel-custom-toggle" ' +
          'data-action="toggleCustomChannelEnable"' +
          (customEnabled ? ' checked' : '') +
          (disabled ? ' disabled' : '') + ' />' +
        '<span>Custom\u2026</span>' +
      '</label>' +
      '<input type="text" class="channel-custom-input" id="channel-custom-input" ' +
        'placeholder="Comma-separated channel names" ' +
        'value="' + escapeHtml(customRaw) + '" ' +
        'data-action-input="updateCustomChannels"' +
        (customEnabled ? '' : ' style="display:none;"') +
        (disabled ? ' disabled' : '') + ' />' +
    '</div>' +
  '</div>';
}

function _refreshChannelSummary() {
  var el = document.getElementById('channel-select-summary');
  if (el) el.textContent = _channelSummary();
}

export function toggleChannelDropdown(arg, target) {
  var root = target && target.closest('.channel-select');
  if (!root) return;
  root.classList.toggle('open');
}

export function toggleChannelOption(arg, target) {
  if (!target) return;
  var name = target.dataset.arg;
  if (!name) return;
  var checked = getCheckedBuiltinChannels();
  if (target.checked) {
    if (checked.indexOf(name) < 0) checked.push(name);
  } else {
    checked = checked.filter(function (c) { return c !== name; });
  }
  _saveCheckedBuiltinChannels(checked);
  _refreshChannelSummary();
}

export function toggleCustomChannelEnable(arg, target) {
  var input = document.getElementById('channel-custom-input');
  if (!input) return;
  if (target.checked) {
    input.style.display = '';
    input.focus();
  } else {
    input.style.display = 'none';
    input.value = '';
    _saveCustomChannelsRaw('');
    _refreshChannelSummary();
  }
}

export function updateCustomChannels(arg, target) {
  _saveCustomChannelsRaw(target.value || '');
  _refreshChannelSummary();
}

// Close dropdown/popover on outside click — installed once at module load.
// The gear button sits outside the popover, so skip the handler when the
// click target IS the gear (its own toggle handles open/close).
document.addEventListener('click', function (e) {
  document.querySelectorAll('.channel-select.open').forEach(function (el) {
    if (!el.contains(e.target)) el.classList.remove('open');
  });
  if (e.target.closest('[data-action="toggleLiveSettingsPopover"]')) return;
  var pop = document.querySelector('.live-settings-popover.open');
  if (pop && !pop.contains(e.target)) {
    pop.classList.remove('open');
    _livePopoverOpen = false;
  }
});

// Subtle two-tone chime when a new finding arrives. Uses Web Audio so
// there's no asset to ship.
export function playDing() {
  try {
    var Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return;
    if (!_dingCtx) _dingCtx = new Ctx();
    var ctx = _dingCtx;
    var now = ctx.currentTime;
    [[880, 0], [659.25, 0.09]].forEach(function (pair) {
      var osc  = ctx.createOscillator();
      var gain = ctx.createGain();
      osc.type            = 'sine';
      osc.frequency.value = pair[0];
      var t = now + pair[1];
      gain.gain.setValueAtTime(0, t);
      gain.gain.linearRampToValueAtTime(0.08, t + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.001, t + 0.25);
      osc.connect(gain).connect(ctx.destination);
      osc.start(t);
      osc.stop(t + 0.3);
    });
  } catch (e) { /* audio unavailable — swallow */ }
}

// The global singleton that owns the EventSource connection and
// rolling state (feed, checks, stats). Pages subscribe to it so
// switching between Dashboard and Monitor doesn't drop incoming
// alerts.
export const monitorClient = {
  status: null,
  feed:   [],
  checks: [],
  _source: null,
  _subscribers: [],
  _initialized: false,
  _tickTimer: null,

  async init() {
    if (this._initialized) return;
    this._initialized = true;
    try {
      var s = await apiMonitorStatus();
      this.status = s;
      var h = await apiMonitorHistory(50);
      this.checks = h.checks || [];
      if (s.active) {
        this._connect();
      } else if (localStorage.getItem('pulse.monitor.autoResume') === '1') {
        // Backend restarted since last session — pick up where we left off.
        await this.start();
      }
    } catch (e) { /* monitor endpoints unreachable — ignore */ }

    // 1-second ticker so "time since last check" labels keep flowing.
    var self = this;
    this._tickTimer = setInterval(function () { self._notify('tick'); }, 1000);
  },

  subscribe(fn) {
    this._subscribers.push(fn);
    try { fn('init'); } catch (e) {}
  },

  unsubscribe(fn) {
    this._subscribers = this._subscribers.filter(function (x) { return x !== fn; });
  },

  _notify(type, data) {
    this._subscribers.forEach(function (fn) {
      try { fn(type, data); } catch (e) {}
    });
  },

  async start(cfgOverride) {
    var cfg = cfgOverride || this._readSettingsForm();
    try {
      var s = await apiMonitorStart(cfg || {});
      this.status = s;
      localStorage.setItem('pulse.monitor.autoResume', '1');
      this._connect();
      this._notify('status');
    } catch (e) {
      toastError('Failed to start monitor');
    }
  },

  async stop() {
    try {
      var s = await apiMonitorStop();
      this.status = s;
      localStorage.removeItem('pulse.monitor.autoResume');
      this._disconnect();
      this._notify('status');
    } catch (e) {
      toastError('Failed to stop monitor');
    }
  },

  async sendTestAlert() {
    try {
      var r = await apiMonitorTestAlert();
      if (!r.ok) {
        toastError((r.data && r.data.detail) || 'Test alert failed');
      }
    } catch (e) {
      toastError('Test alert failed');
    }
  },

  // Pull start-time settings from whichever of the two sliders is live
  // (Monitor page full slider, or the dashboard gear-popover slider),
  // falling back to the persistent localStorage value so the dashboard
  // Start button works even when no slider is mounted.
  _readSettingsForm() {
    var intervalInput = document.getElementById('mon-interval')
      || document.getElementById('popover-interval');
    var cfg = { channels: getSelectedChannels() };
    if (intervalInput) cfg.poll_interval = parseInt(intervalInput.value, 10) || 30;
    else {
      var stored = getStoredInterval();
      if (stored != null) cfg.poll_interval = stored;
    }
    return cfg;
  },

  _connect() {
    if (this._source) return;
    var self = this;
    var src = new EventSource('/api/monitor/stream');
    this._source = src;

    src.addEventListener('status', function (e) {
      try {
        var d = JSON.parse(e.data);
        if (d.status) self.status = d.status;
        self._notify('status');
      } catch (err) {}
    });

    src.addEventListener('finding', function (e) {
      try {
        var d = JSON.parse(e.data);
        self.feed.unshift({ finding: d.finding, at: d.at });
        if (self.feed.length > 50) self.feed.length = 50;
        self._mergeStats(d.stats);
        playDing();
        self._notify('finding', d);
      } catch (err) {}
    });

    src.addEventListener('check', function (e) {
      try {
        var d = JSON.parse(e.data);
        if (d.check) self.checks.unshift(d.check);
        if (self.checks.length > 100) self.checks.length = 100;
        self._mergeStats(d.stats);
        self._notify('check', d);
      } catch (err) {}
    });

    // Connection errors — browser auto-reconnects.
    src.onerror = function () { self._notify('disconnected'); };
  },

  _disconnect() {
    if (this._source) { this._source.close(); this._source = null; }
  },

  _mergeStats(stats) {
    if (!stats || !this.status) return;
    this.status.poll_count         = stats.poll_count;
    this.status.events_checked     = stats.events_checked;
    this.status.findings_detected  = stats.findings_detected;
    this.status.last_check_at      = stats.last_check_at;
  },
};

function _liveHeaderHtml(status, opts) {
  opts = opts || {};
  var active   = status && status.active;
  var interval = (status && status.poll_interval) || getStoredInterval() || 30;
  var gearBtn  = opts.showGear
    ? '<button class="live-btn gear" data-action="toggleLiveSettingsPopover" ' +
      'title="Monitor settings" aria-label="Monitor settings">\u2699</button>'
    : '';
  return '<div class="live-header">' +
    '<div class="live-dot ' + (active ? '' : 'idle') + '"></div>' +
    '<div class="live-badge ' + (active ? '' : 'idle') + '">' + (active ? 'LIVE' : 'IDLE') + '</div>' +
    (active
      ? '<div class="live-interval">Polling every ' + interval + 's</div>'
      : '<div class="live-interval">Not monitoring</div>') +
    (active
      ? '<button class="live-btn" style="margin-left:auto;" data-action="sendMonitorTestAlert">Test Alert</button>' +
        '<button class="live-btn stop" style="margin-left:8px;" data-action="stopMonitor">Stop</button>' +
        gearBtn
      : '<button class="live-btn start" style="margin-left:auto;" data-action="startMonitor">Start Monitoring</button>' +
        gearBtn) +
  '</div>';
}

// Compact inline popover anchored below the gear icon. Two controls:
// poll-interval slider + channel multi-select. Saves to localStorage
// so the Monitor page sees the same values on next render.
function _liveSettingsPopoverHtml(status) {
  var active   = status && status.active;
  var interval = (status && status.poll_interval) || getStoredInterval() || 30;
  return '<div class="live-settings-popover" id="live-settings-popover">' +
    '<div class="live-settings-head">Monitor Settings' +
      '<button class="live-settings-close" data-action="toggleLiveSettingsPopover" ' +
        'aria-label="Close">&times;</button>' +
    '</div>' +
    '<div class="live-settings-row">' +
      '<label>Poll Interval</label>' +
      '<input type="range" id="popover-interval" min="5" max="300" step="5" ' +
        'value="' + interval + '"' +
        (active ? ' disabled' : '') +
        ' data-action-input="updatePopoverIntervalLabel" ' +
        ' data-action-change="savePopoverInterval" />' +
      '<div class="hint"><span id="popover-interval-label">' + interval + 's</span> between polls</div>' +
    '</div>' +
    '<div class="live-settings-row">' +
      '<label>Channels</label>' +
      channelMultiSelectHtml({ disabled: active }) +
    '</div>' +
    (active
      ? '<div class="hint" style="margin-top:8px; color:#d29922;">Stop the monitor to change these \u2014 they apply on next start.</div>'
      : '<div class="hint" style="margin-top:8px;">Saved automatically. Click Start Monitoring to apply.</div>') +
  '</div>';
}

function _liveMetaHtml(status) {
  if (!status || !status.active) return '';
  var mode = status.mode === 'live' ? 'Live (wevtutil)' : 'File scan';
  return '<div class="live-meta">' +
    '<div class="item"><div class="k">Mode</div><div class="v">' + mode + '</div></div>' +
    '<div class="item"><div class="k">Events Checked</div><div class="v">' + (status.events_checked || 0) + '</div></div>' +
    '<div class="item"><div class="k">Findings</div><div class="v">' + (status.findings_detected || 0) + '</div></div>' +
    '<div class="item"><div class="k">Last Check</div><div class="v">' + _timeSince(status.last_check_at) + '</div></div>' +
  '</div>';
}

function _timeSince(iso) {
  if (!iso) return '\u2014';
  var d = new Date(iso.replace(' ', 'T'));
  if (isNaN(d.getTime())) return iso;
  var sec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (sec < 60)   return sec + 's ago';
  if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
  return Math.floor(sec / 3600) + 'h ago';
}

// The cached snapshot the click handler indexes into. Reset on every
// render so the index in data-arg always maps to the same finding the
// user just saw.
let _liveFeedSnapshot = [];

function _liveFeedHtml(feed) {
  _liveFeedSnapshot = (feed || []).slice(0, 20);
  if (_liveFeedSnapshot.length === 0) {
    return '<div class="live-feed empty">Waiting for events \u2014 alerts will appear here as they\u2019re detected.</div>';
  }
  return '<div class="live-feed">' +
    _liveFeedSnapshot.map(function (item, i) {
      var f   = item.finding || {};
      var sev = (f.severity || 'LOW').toUpperCase();
      return '<div class="dash-finding-row sev-' + sev.toLowerCase() + '" ' +
             'data-action="openLiveFeedFinding" data-arg="' + i + '" style="cursor:pointer;">' +
        '<div><div class="time">' + escapeHtml(item.at || '') + '</div></div>' +
        '<div>' +
          '<div class="rule">' + escapeHtml(f.rule || 'Unknown') + '</div>' +
          '<div class="desc">' + escapeHtml(f.details || f.description || '') + '</div>' +
        '</div>' +
        '<div class="sev ' + sev.toLowerCase() + '">' + sev + '</div>' +
      '</div>';
    }).join('') +
  '</div>';
}

// Click handler wired via data-action on each live-feed row. Looks up
// the finding in the snapshot captured at render time and opens the
// shared slide-in drawer so live alerts get the same detail view as
// the Findings page and the Dashboard's Last Scan Findings list.
export function openLiveFeedFinding(arg) {
  var i = parseInt(arg, 10);
  var item = _liveFeedSnapshot[i];
  if (item && item.finding) openFindingDrawer(item.finding);
}

function _monitorChecksHtml(checks) {
  if (!checks || checks.length === 0) {
    return '<div style="text-align:center; padding:24px; color:var(--text-muted);">No polls yet.</div>';
  }
  return '<table class="monitor-checks-table"><thead><tr>' +
    '<th>Time</th><th>Events</th><th>Event IDs</th><th>Findings</th>' +
    '</tr></thead><tbody>' +
    checks.slice(0, 50).map(function (c) {
      var ids = (c.event_ids || []).join(', ') || '\u2014';
      return '<tr>' +
        '<td>' + escapeHtml(c.at || '') + '</td>' +
        '<td class="num">' + (c.events || 0) + '</td>' +
        '<td class="num" style="font-family:monospace;">' + escapeHtml(ids) + '</td>' +
        '<td class="num' + (c.findings > 0 ? ' hit' : '') + '">' + (c.findings || 0) + '</td>' +
      '</tr>';
    }).join('') +
    '</tbody></table>';
}

// ---------- Dashboard-embedded live panel ----------
export function renderDashLivePanel() {
  var mount = document.getElementById('dash-live-panel');
  if (!mount) return;
  var s      = monitorClient.status;
  var active = s && s.active;
  mount.innerHTML = '<div class="live-panel ' + (active ? '' : 'idle') + '">' +
    _liveHeaderHtml(s, { showGear: true }) +
    _liveSettingsPopoverHtml(s) +
    _liveMetaHtml(s) +
    (active ? _liveFeedHtml(monitorClient.feed) : '') +
  '</div>';
  if (_livePopoverOpen) {
    var pop = document.getElementById('live-settings-popover');
    if (pop) pop.classList.add('open');
  }
}

export function toggleLiveSettingsPopover() {
  var pop = document.getElementById('live-settings-popover');
  if (!pop) return;
  _livePopoverOpen = !pop.classList.contains('open');
  pop.classList.toggle('open', _livePopoverOpen);
}

// Live label update while dragging the popover slider — mirrors
// updateMonIntervalLabel on the Monitor page.
export function updatePopoverIntervalLabel(arg, target) {
  var lbl = document.getElementById('popover-interval-label');
  if (lbl && target) lbl.textContent = target.value + 's';
}

// Commit the popover slider value to localStorage on change so Start
// picks it up and the Monitor page slider mirrors it on next render.
export function savePopoverInterval(arg, target) {
  if (!target) return;
  var n = parseInt(target.value, 10);
  if (isFinite(n)) _saveStoredInterval(n);
}

export function mountDashLivePanel() {
  renderDashLivePanel();
  if (_dashLiveUnsub) _dashLiveUnsub();
  function onUpdate(type) {
    if (!document.getElementById('dash-live-panel')) {
      if (_dashLiveUnsub) _dashLiveUnsub();
      return;
    }
    if (type === 'tick') {
      var metaEl = document.querySelector('#dash-live-panel .live-meta .item:last-child .v');
      if (metaEl) metaEl.textContent = _timeSince(monitorClient.status && monitorClient.status.last_check_at);
      return;
    }
    renderDashLivePanel();
  }
  monitorClient.subscribe(onUpdate);
  _dashLiveUnsub = function () { monitorClient.unsubscribe(onUpdate); };
}

// ---------------------------------------------------------------
// PAGE: Monitor
// ---------------------------------------------------------------
export async function renderMonitorPage() {
  var c = document.getElementById('content');
  c.innerHTML = '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading monitor\u2026</div>';

  await monitorClient.init();

  function render() {
    var s      = monitorClient.status || {};
    var active = s.active;

    c.innerHTML =
      '<div id="monitor-page-root">' +
      '<div class="live-panel ' + (active ? '' : 'idle') + '" style="margin-bottom:16px;">' +
        _liveHeaderHtml(s) +
        _liveMetaHtml(s) +
      '</div>' +

      '<div class="card" style="margin-bottom:16px;">' +
        '<div class="section-label">Monitor Settings</div>' +
        '<div class="monitor-settings">' +
          '<div>' +
            '<label>Poll Interval</label>' +
            '<input type="range" id="mon-interval" min="5" max="300" step="5" ' +
              'value="' + (s.poll_interval || getStoredInterval() || 30) + '"' +
              (active ? ' disabled' : '') +
              ' data-action-input="updateMonIntervalLabel" ' +
              ' data-action-change="savePopoverInterval" />' +
            '<div class="hint"><span id="mon-interval-label">' + (s.poll_interval || getStoredInterval() || 30) + 's</span> between polls</div>' +
          '</div>' +
          '<div>' +
            '<label>Channels</label>' +
            channelMultiSelectHtml({ disabled: active }) +
            '<div class="hint">Pick which Windows event logs to watch. Custom lets you add one by name.</div>' +
          '</div>' +
        '</div>' +
        (s.platform_supports_live === false
          ? '<div class="hint" style="margin-top:10px; color:#d29922;">Live mode requires Windows \u2014 falling back to file mode.</div>'
          : '') +
      '</div>' +

      '<div class="card" style="margin-bottom:16px;">' +
        '<div class="section-label">Live Feed</div>' +
        _liveFeedHtml(monitorClient.feed) +
      '</div>' +

      '<div class="card" style="margin-bottom:16px;">' +
        '<div class="section-label">Poll History</div>' +
        _monitorChecksHtml(monitorClient.checks) +
      '</div>' +

      '<div class="card" id="monitor-sessions-section">' +
        _sessionsSectionHtml() +
      '</div>' +
      '</div>';
  }

  // Kick off an initial sessions load so the section populates when the
  // page first mounts. Fire-and-forget — the section re-renders itself.
  _loadMonitorSessions();

  render();

  if (_monPageUnsub) _monPageUnsub();
  // Track previous active state so we can refresh the sessions list exactly
  // when the monitor transitions from running to stopped — that's when a
  // new session row is closed out in the DB and should show up in the list.
  var prevActive = !!(monitorClient.status && monitorClient.status.active);
  function onUpdate(type) {
    if (!document.getElementById('monitor-page-root')) {
      if (_monPageUnsub) _monPageUnsub();
      return;
    }
    if (type === 'tick') {
      var metaEl = document.querySelector('#monitor-page-root .live-meta .item:last-child .v');
      if (metaEl) metaEl.textContent = _timeSince(monitorClient.status && monitorClient.status.last_check_at);
      return;
    }
    var nowActive = !!(monitorClient.status && monitorClient.status.active);
    render();
    if (prevActive && !nowActive) {
      // Monitor just stopped — pull the refreshed session list.
      _loadMonitorSessions();
    }
    prevActive = nowActive;
  }
  monitorClient.subscribe(onUpdate);
  _monPageUnsub = function () { monitorClient.unsubscribe(onUpdate); };
}

// ---------------------------------------------------------------
// Monitor Sessions — DVR-style record of Start→Stop spans
// ---------------------------------------------------------------
// Module state kept across Monitor-page re-renders so expanded cards and
// fetched findings don't get wiped every time an SSE event arrives.
let _monitorSessions         = [];
let _expandedSessionId       = null;
let _sessionFindingsCache    = {};   // { [id]: [finding, ...] }
let _sessionFindingsLoading  = {};   // { [id]: true } while in-flight

async function _loadMonitorSessions() {
  _monitorSessions = await apiMonitorSessions(200);
  _renderSessionsSection();
}

function _sessionFindingKey(f) { return 'sess-' + (f.id || Math.random()); }

function _humanDuration(sec) {
  if (sec == null || sec < 0) return '—';
  if (sec < 60) return sec + 's';
  var m = Math.floor(sec / 60);
  var s = sec % 60;
  if (m < 60) return s ? m + 'm ' + s + 's' : m + ' min';
  var h = Math.floor(m / 60);
  var rm = m % 60;
  return rm ? h + 'h ' + rm + 'm' : h + 'h';
}

function _sessionHeaderLabel(sess) {
  // "Apr 16 21:15 – 21:35 · 20 min · 3 findings"
  var start = sess.started_at || '';
  var end   = sess.ended_at   || '';
  var dur   = _humanDuration(sess.duration_sec);
  var findings = sess.findings_count || 0;
  var starts = start.split(' ');
  var ends   = end.split(' ');
  var label = '';
  if (starts.length >= 2) {
    // "YYYY-MM-DD HH:MM:SS" → "Mon DD HH:MM"
    var d = starts[0];
    var t = (starts[1] || '').slice(0, 5);
    label = _shortDate(d) + ' ' + t;
    if (ends[1]) label += ' – ' + ends[1].slice(0, 5);
    else         label += ' – (active)';
  } else {
    label = start || 'Session ' + sess.id;
  }
  label += ' · ' + dur + ' · ' + findings + ' finding' + (findings === 1 ? '' : 's');
  return label;
}

function _shortDate(ymd) {
  // "2026-04-16" → "Apr 16". Purely cosmetic; falls back to the raw text.
  var parts = (ymd || '').split('-');
  if (parts.length !== 3) return ymd || '';
  var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  var mi = parseInt(parts[1], 10) - 1;
  if (!(mi >= 0 && mi < 12)) return ymd;
  return months[mi] + ' ' + (parts[2] || '').replace(/^0/, '');
}

function _sessionsSectionHtml() {
  if (!_monitorSessions || _monitorSessions.length === 0) {
    return '<div class="section-label" style="display:flex; justify-content:space-between; align-items:center;">' +
        '<span>Monitor Sessions</span>' +
      '</div>' +
      '<div style="text-align:center; padding:24px; color:var(--text-muted);">' +
        'No sessions yet. Start monitoring and one will appear here when you stop.' +
      '</div>';
  }
  var cards = _monitorSessions.map(_sessionCardHtml).join('');
  return '<div class="section-label" style="display:flex; justify-content:space-between; align-items:center;">' +
      '<span>Monitor Sessions</span>' +
      '<button class="btn-small" data-action="clearMonitorSessions" ' +
        'style="background:var(--border); color:var(--text);">Clear all</button>' +
    '</div>' +
    '<div class="monitor-sessions">' + cards + '</div>';
}

function _sessionCardHtml(sess) {
  var isOpen = _expandedSessionId === sess.id;
  var isActive = !sess.ended_at;
  var badge = isActive
    ? '<span class="session-badge active">Active</span>'
    : '';
  var body = '';
  if (isOpen) {
    if (_sessionFindingsLoading[sess.id]) {
      body = '<div class="session-body"><div style="padding:16px; color:var(--text-muted); text-align:center;">Loading findings…</div></div>';
    } else {
      body = '<div class="session-body">' + _sessionFindingsTableHtml(sess) + '</div>';
    }
  }
  return '<div class="session-card' + (isOpen ? ' open' : '') + '">' +
    '<div class="session-head" data-action="toggleSessionExpand" data-arg="' + sess.id + '">' +
      '<span class="session-caret">' + (isOpen ? '\u25BE' : '\u25B8') + '</span>' +
      '<span class="session-label">' + escapeHtml(_sessionHeaderLabel(sess)) + '</span>' +
      badge +
      (isActive
        ? ''
        : '<button class="session-delete" data-action="deleteMonitorSession" data-arg="' + sess.id + '" ' +
          'aria-label="Delete session" title="Delete session">\u00D7</button>') +
    '</div>' +
    body +
  '</div>';
}

function _sessionFindingsTableHtml(sess) {
  var findings = _sessionFindingsCache[sess.id] || [];
  if (findings.length === 0) {
    return '<div style="padding:16px; color:var(--text-muted); text-align:center;">' +
      'No findings recorded during this session.' +
    '</div>';
  }
  // Stash a per-session index on the module so the click handler can
  // look the finding up without re-fetching.
  return '<table class="session-findings-table"><thead><tr>' +
      '<th>Time</th><th>Severity</th><th>Rule</th><th>Description</th>' +
    '</tr></thead><tbody>' +
    findings.map(function (f, i) {
      var sev  = (f.severity || 'LOW').toUpperCase();
      var desc = f.description || f.details || '';
      if (desc.length > 140) desc = desc.substring(0, 140) + '\u2026';
      var time = f.timestamp || '';
      return '<tr class="clickable" data-action="openSessionFinding" ' +
        'data-arg="' + sess.id + ':' + i + '">' +
        '<td class="col-time">' + escapeHtml(time) + '</td>' +
        '<td><span class="pill pill-' + sev.toLowerCase() + '">' + sev + '</span></td>' +
        '<td style="font-weight:500;">' + escapeHtml(f.rule || '') + '</td>' +
        '<td style="color:var(--text-muted);">' + escapeHtml(desc) + '</td>' +
      '</tr>';
    }).join('') +
    '</tbody></table>';
}

function _renderSessionsSection() {
  var el = document.getElementById('monitor-sessions-section');
  if (!el) return;
  el.innerHTML = _sessionsSectionHtml();
}

export async function toggleSessionExpand(arg) {
  var id = parseInt(arg, 10);
  if (!isFinite(id)) return;
  if (_expandedSessionId === id) {
    _expandedSessionId = null;
    _renderSessionsSection();
    return;
  }
  _expandedSessionId = id;
  if (!_sessionFindingsCache[id]) {
    _sessionFindingsLoading[id] = true;
    _renderSessionsSection();
    var findings = await apiMonitorSessionFindings(id);
    _sessionFindingsCache[id] = findings;
    delete _sessionFindingsLoading[id];
  }
  _renderSessionsSection();
}

// Called from data-action on a session findings row. Arg is "sessId:idx".
export function openSessionFinding(arg) {
  var parts = String(arg || '').split(':');
  var id  = parseInt(parts[0], 10);
  var idx = parseInt(parts[1], 10);
  var list = _sessionFindingsCache[id];
  if (!list) return;
  var f = list[idx];
  if (f) openFindingDrawer(f);
}

export async function deleteMonitorSession(arg) {
  var id = parseInt(arg, 10);
  if (!isFinite(id)) return;
  if (!confirm('Delete this monitor session and all its findings? This cannot be undone.')) return;
  var r = await apiDeleteMonitorSession(id);
  if (!r.ok) {
    toastError((r.data && r.data.detail) || 'Delete failed.');
    return;
  }
  // Drop cached state for this session and refresh the list.
  if (_expandedSessionId === id) _expandedSessionId = null;
  delete _sessionFindingsCache[id];
  delete _sessionFindingsLoading[id];
  showToast('Session deleted', 'success');
  await _loadMonitorSessions();
}

export async function clearMonitorSessions() {
  if (!_monitorSessions || _monitorSessions.length === 0) return;
  if (!confirm('Delete every monitor session and its findings? This cannot be undone.')) return;
  var r = await apiClearMonitorSessions();
  if (!r.ok) {
    toastError((r.data && r.data.detail) || 'Clear failed.');
    return;
  }
  _expandedSessionId      = null;
  _sessionFindingsCache   = {};
  _sessionFindingsLoading = {};
  showToast('Sessions cleared', 'success');
  await _loadMonitorSessions();
}

// Wrapper-style top-level entry points some onclick handlers use.
export function startMonitor() { return monitorClient.start(); }
export function stopMonitor()  { return monitorClient.stop(); }

// Wired via data-action-input on the poll-interval slider; keeps the
// visible label in sync with the slider value as the user drags.
export function updateMonIntervalLabel(arg, target) {
  var lbl = document.getElementById('mon-interval-label');
  if (lbl && target) lbl.textContent = target.value + 's';
}
// Settings page also has a "sendTestAlert" for the threshold-alert flow
// (different endpoint), so expose the monitor-side alert under a name
// that doesn't collide.
export function sendMonitorTestAlert() { return monitorClient.sendTestAlert(); }
