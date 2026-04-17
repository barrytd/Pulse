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
} from './api.js';
import { escapeHtml, toastError } from './dashboard.js';

// Module-level refs that used to live on window as _dashLiveUnsub /
// _monPageUnsub / _dingCtx.
let _dingCtx       = null;
let _dashLiveUnsub = null;
let _monPageUnsub  = null;

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
  // Notify other mounted instances (dashboard popover <-> monitor page) to redraw.
  monitorClient._notify('channels');
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

// Close dropdown on outside click — installed once at module load.
document.addEventListener('click', function (e) {
  var openEls = document.querySelectorAll('.channel-select.open');
  openEls.forEach(function (el) {
    if (!el.contains(e.target)) el.classList.remove('open');
  });
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

  // Pull start-time settings from the Monitor page form if the user
  // is on that page; otherwise fall back to whatever the persistent
  // channel multi-select has stored so the dashboard Start button works.
  _readSettingsForm() {
    var intervalInput = document.getElementById('mon-interval');
    var cfg = { channels: getSelectedChannels() };
    if (intervalInput) cfg.poll_interval = parseInt(intervalInput.value, 10) || 30;
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

function _liveHeaderHtml(status) {
  var active   = status && status.active;
  var interval = (status && status.poll_interval) || 30;
  return '<div class="live-header">' +
    '<div class="live-dot ' + (active ? '' : 'idle') + '"></div>' +
    '<div class="live-badge ' + (active ? '' : 'idle') + '">' + (active ? 'LIVE' : 'IDLE') + '</div>' +
    (active
      ? '<div class="live-interval">Polling every ' + interval + 's</div>'
      : '<div class="live-interval">Not monitoring</div>') +
    (active
      ? '<button class="live-btn" style="margin-left:auto;" data-action="sendMonitorTestAlert">Test Alert</button>' +
        '<button class="live-btn stop" style="margin-left:8px;" data-action="stopMonitor">Stop</button>'
      : '<button class="live-btn start" data-action="startMonitor">Start Monitoring</button>') +
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

function _liveFeedHtml(feed) {
  if (!feed || feed.length === 0) {
    return '<div class="live-feed empty">Waiting for events \u2014 alerts will appear here as they\u2019re detected.</div>';
  }
  return '<div class="live-feed">' +
    feed.slice(0, 20).map(function (item) {
      var f   = item.finding || {};
      var sev = (f.severity || 'LOW').toUpperCase();
      return '<div class="dash-finding-row sev-' + sev.toLowerCase() + '">' +
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
    _liveHeaderHtml(s) +
    _liveMetaHtml(s) +
    (active ? _liveFeedHtml(monitorClient.feed) : '') +
  '</div>';
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
            '<input type="range" id="mon-interval" min="5" max="300" step="5" value="' + (s.poll_interval || 30) + '"' +
              (active ? ' disabled' : '') +
              ' data-action-input="updateMonIntervalLabel" />' +
            '<div class="hint"><span id="mon-interval-label">' + (s.poll_interval || 30) + 's</span> between polls</div>' +
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

      '<div class="card">' +
        '<div class="section-label">Poll History</div>' +
        _monitorChecksHtml(monitorClient.checks) +
      '</div>' +
      '</div>';
  }

  render();

  if (_monPageUnsub) _monPageUnsub();
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
    render();
  }
  monitorClient.subscribe(onUpdate);
  _monPageUnsub = function () { monitorClient.unsubscribe(onUpdate); };
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
