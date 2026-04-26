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
  apiDeleteMonitorSessionsBatch,
} from './api.js';
import { escapeHtml, toastError, showToast, sevPillHtml } from './dashboard.js';
import { openFindingDrawer } from './findings.js';

// Module-level refs that used to live on window as _monPageUnsub / _dingCtx.
let _dingCtx         = null;
let _monPageUnsub    = null;
// Whether the Monitor page's Settings section is expanded. Collapsed
// by default so the page opens clean; the one-line summary above the
// chevron tells the user what's currently configured at a glance.
let _monSettingsExpanded = false;
// Poll History card is collapsed by default — on an idle system every
// poll is a zero-event row and it dominates the page. When expanded,
// the zero-event rows are hidden unless the user flips the toggle.
let _pollHistoryExpanded = false;
let _pollHistoryShowAll  = false;

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
// Friendly labels shown in the UI. The raw Windows channel name stays as
// the stored/transport value so the monitor backend still receives what
// wevtutil expects; only the label the user sees is shortened.
const CHANNEL_LABELS = {
  'Security':                                     'Security',
  'System':                                       'System',
  'Application':                                  'Application',
  'Windows PowerShell':                           'PowerShell (Classic)',
  'Microsoft-Windows-PowerShell/Operational':     'PowerShell (Operational)',
  'Microsoft-Windows-TaskScheduler/Operational':  'Task Scheduler',
};
function _channelLabel(name) {
  return CHANNEL_LABELS[name] || name;
}
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
  var sel = getSelectedChannels().map(_channelLabel);
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
      '<span>' + escapeHtml(_channelLabel(name)) + '</span>' +
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

// Inline 2-column grid of the six built-in channels for the compact
// Settings panel. No dropdown wrapper, no custom-channel input — just
// the checkboxes, always visible, so nothing opens in a direction that
// can fall off-screen.
export function channelInlineGridHtml(opts) {
  opts = opts || {};
  var disabled = !!opts.disabled;
  var checked = getCheckedBuiltinChannels();
  var items = BUILTIN_CHANNELS.map(function (name) {
    var isChecked = checked.indexOf(name) >= 0;
    return '<label class="channel-chip">' +
      '<input type="checkbox" data-action="toggleChannelOption" data-arg="' +
        escapeHtml(name) + '"' + (isChecked ? ' checked' : '') +
        (disabled ? ' disabled' : '') + ' />' +
      '<span>' + escapeHtml(_channelLabel(name)) + '</span>' +
    '</label>';
  }).join('');
  return '<div class="channel-inline-grid">' + items + '</div>';
}

// 2x3 pill grid used inside the gear dropdown. Selected pills use the
// accent blue tint; unselected show muted text with a neutral border.
// The underlying input is a hidden checkbox so `toggleChannelOption`
// still picks up the change event and persists via localStorage.
export function channelPillGridHtml(opts) {
  opts = opts || {};
  var disabled = !!opts.disabled;
  var checked = getCheckedBuiltinChannels();
  var items = BUILTIN_CHANNELS.map(function (name) {
    var isChecked = checked.indexOf(name) >= 0;
    return '<label class="channel-pill' + (isChecked ? ' selected' : '') + (disabled ? ' disabled' : '') + '">' +
      '<input type="checkbox" data-action="toggleChannelOption" data-arg="' +
        escapeHtml(name) + '"' + (isChecked ? ' checked' : '') +
        (disabled ? ' disabled' : '') + ' />' +
      '<span>' + escapeHtml(_channelLabel(name)) + '</span>' +
    '</label>';
  }).join('');
  return '<div class="channel-pill-grid">' + items + '</div>';
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
  // Keep the pill visual in sync with the hidden checkbox and refresh
  // the "Security, System +3 more · every 5s" subtitle immediately.
  var pill = target.closest && target.closest('.channel-pill');
  if (pill) pill.classList.toggle('selected', !!target.checked);
  _refreshLiveSubtitle();
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

// Close any open channel dropdown on outside click. Installed once at
// module load.
document.addEventListener('click', function (e) {
  document.querySelectorAll('.channel-select.open').forEach(function (el) {
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

// Muted subtitle shown directly under the LIVE/IDLE badge — summarises
// the current channels + poll interval so a user always knows what the
// monitor is watching without opening the gear dropdown.
function _liveSubtitleText(status) {
  var active   = !!(status && status.active);
  var interval = (status && status.poll_interval) || getStoredInterval() || 30;
  var labels   = getSelectedChannels().map(_channelLabel);
  var chanPart = labels.length === 0
    ? 'No channels selected'
    : (labels.length <= 2
        ? labels.join(', ')
        : labels.slice(0, 2).join(', ') + ' +' + (labels.length - 2) + ' more');
  return active
    ? chanPart + ' \u00B7 every ' + interval + 's'
    : 'Not monitoring \u00B7 ' + chanPart;
}

function _refreshLiveSubtitle() {
  var el = document.getElementById('mon-live-subtitle');
  if (el) el.textContent = _liveSubtitleText(monitorClient.status);
}

// One-line header for the unified Live panel. Left cluster: pulsing dot +
// LIVE/IDLE badge stacked above a muted subtitle of channels/interval.
// Middle: inline Mode/Events/Findings/Last Check stats (hidden when
// idle). Right: Test Alert + Stop (or Start Monitoring) followed by the
// gear dropdown that owns interval + channel configuration.
function _liveUnifiedHeaderHtml(status) {
  var active   = status && status.active;
  var interval = (status && status.poll_interval) || getStoredInterval() || 30;
  var mode     = status && status.mode === 'live' ? 'Live (wevtutil)' : 'File scan';

  var stats = active
    ? '<div class="live-stats-inline">' +
        '<span class="live-stat"><span class="k">Mode</span><span class="v" id="mon-mode-val">' + escapeHtml(mode) + '</span></span>' +
        '<span class="live-stat"><span class="k">Events</span><span class="v" id="mon-events-val">' + (status.events_checked || 0) + '</span></span>' +
        '<span class="live-stat"><span class="k">Findings</span><span class="v" id="mon-findings-val">' + (status.findings_detected || 0) + '</span></span>' +
        '<span class="live-stat"><span class="k">Last Check</span><span class="v" id="mon-last-check">' + _timeSince(status.last_check_at) + '</span></span>' +
      '</div>'
    : '';

  var controls = active
    ? '<button class="live-btn btn-with-icon" data-action="sendMonitorTestAlert"><i data-lucide="send"></i><span>Test Alert</span></button>' +
      '<button class="live-btn stop btn-with-icon" data-action="stopMonitor"><i data-lucide="square"></i><span>Stop</span></button>'
    : '<button class="live-btn start btn-with-icon" data-action="startMonitor"><i data-lucide="play"></i><span>Start Monitoring</span></button>';

  var gear =
    '<div class="mon-gear-wrap" data-mon-gear>' +
      '<button class="live-btn gear" data-action="toggleMonGearDropdown" ' +
        'aria-label="Monitor settings" title="Monitor settings" type="button">\u2699</button>' +
      '<div class="pulse-dropdown mon-gear-dropdown" id="mon-gear-dropdown" hidden>' +
        '<div class="pulse-dropdown-section">' +
          '<div class="pulse-dropdown-header">Poll Interval</div>' +
          '<div class="gear-slider-row">' +
            '<input type="range" id="mon-interval" min="5" max="300" step="5" ' +
              'value="' + interval + '"' +
              (active ? ' disabled' : '') +
              ' data-action-input="updateMonIntervalLabel"' +
              ' data-action-change="savePopoverInterval" />' +
            '<span class="gear-slider-value" id="mon-interval-label">' + interval + 's</span>' +
          '</div>' +
        '</div>' +
        '<div class="pulse-dropdown-divider"></div>' +
        '<div class="pulse-dropdown-section">' +
          '<div class="pulse-dropdown-header">Channels</div>' +
          channelPillGridHtml({ disabled: active }) +
        '</div>' +
      '</div>' +
    '</div>';

  return '<div class="live-unified-header">' +
    '<div class="live-header-left-stack">' +
      '<div class="live-header-left">' +
        '<div class="live-dot ' + (active ? '' : 'idle') + '"></div>' +
        '<div class="live-badge ' + (active ? '' : 'idle') + '">' + (active ? 'LIVE' : 'IDLE') + '</div>' +
      '</div>' +
      '<div class="live-subtitle" id="mon-live-subtitle">' + escapeHtml(_liveSubtitleText(status)) + '</div>' +
    '</div>' +
    stats +
    '<div class="live-header-controls">' + controls + gear + '</div>' +
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

// Keyed map of feed items currently rendered (or renderable) in the
// page. Stable keys let us append new rows incrementally without
// re-rendering the entire feed on every poll — the old index-based
// approach caused a visible blink every 5 seconds.
let _liveFeedSnapshot = new Map();

function _feedKey(item) {
  var f = item.finding || {};
  return [f.id || '', item.at || '', f.rule || '', f.timestamp || '', f.details || f.description || ''].join('::');
}

function _feedRowHtml(item, key) {
  var f   = item.finding || {};
  var sev = (f.severity || 'LOW').toUpperCase();
  return '<div class="dash-finding-row sev-' + sev.toLowerCase() + '" ' +
         'data-action="openLiveFeedFinding" data-arg="' + escapeHtml(key) + '" ' +
         'data-feed-key="' + escapeHtml(key) + '" style="cursor:pointer;">' +
    '<div><div class="time">' + escapeHtml(item.at || '') + '</div></div>' +
    '<div>' +
      '<div class="rule">' + escapeHtml(f.rule || 'Unknown') + '</div>' +
      '<div class="desc">' + escapeHtml(f.details || f.description || '') + '</div>' +
    '</div>' +
    '<div class="sev ' + sev.toLowerCase() + '">' + sev + '</div>' +
  '</div>';
}

// Friendly zero-state for the Monitor page when no live session has been
// started and no feed has been accumulated. Three-card stats line + a
// short list of recent sessions + a tip.
function _monitorIdlePanelHtml(sessions) {
  sessions = sessions || [];
  // Sessions this week — last 7 days rolling, inclusive of today. Uses a
  // numeric cutoff so we don't have to parse every started_at string twice.
  var now = Date.now();
  var weekCutoff = now - 7 * 24 * 60 * 60 * 1000;
  var weekSessions = sessions.filter(function (s) {
    var t = Date.parse(s.started_at || '');
    return !isNaN(t) && t >= weekCutoff;
  });
  // All-time findings across every recorded session.
  var findingsAllTime = sessions.reduce(function (n, s) {
    return n + (parseInt(s.findings_count, 10) || 0);
  }, 0);
  // Channels the user currently has configured for the monitor. Reads
  // from the same persisted list the Start button will use.
  var configuredChannels = getSelectedChannels().length;

  var statCard = function (label, value) {
    return '<div class="mon-idle-stat">' +
      '<div class="mon-idle-stat-val">' + escapeHtml(String(value)) + '</div>' +
      '<div class="mon-idle-stat-label">' + escapeHtml(label) + '</div>' +
    '</div>';
  };

  var recent = sessions.slice(0, 3);
  var recentHtml = recent.length === 0
    ? '<div class="mon-idle-recent-empty">No sessions recorded yet.</div>'
    : recent.map(function (s) {
        var started = s.started_at || '';
        var findings = parseInt(s.findings_count, 10) || 0;
        var dur = _humanDuration(s.duration_sec);
        var isActive = !s.ended_at;
        return '<div class="mon-idle-recent-row">' +
          '<span class="mon-idle-recent-when">' + escapeHtml(started) + '</span>' +
          '<span class="mon-idle-recent-meta">' +
            (isActive ? 'active' : escapeHtml(dur)) + ' \u00b7 ' +
            findings + ' finding' + (findings === 1 ? '' : 's') +
          '</span>' +
        '</div>';
      }).join('');

  return '<div class="live-feed empty mon-idle-panel" id="mon-live-feed">' +
    '<div class="mon-idle-stats">' +
      statCard('Sessions this week', weekSessions.length) +
      statCard('Findings all time', findingsAllTime) +
      statCard('Channels configured', configuredChannels) +
    '</div>' +
    '<div class="mon-idle-recent">' +
      '<div class="mon-idle-recent-title">Recent Sessions</div>' +
      recentHtml +
    '</div>' +
    '<div class="mon-idle-tip">Start monitoring to watch your Windows event channels in real time.</div>' +
  '</div>';
}

function _liveFeedHtml(feed, opts) {
  opts = opts || {};
  _liveFeedSnapshot = new Map();
  var items = (feed || []).slice(0, 20);
  if (items.length === 0) {
    if (opts.idleMode) {
      return _monitorIdlePanelHtml(_monitorSessions || []);
    }
    return '<div class="live-feed empty" id="mon-live-feed">Waiting for events \u2014 alerts will appear here as they\u2019re detected.</div>';
  }
  var rows = items.map(function (item) {
    var key = _feedKey(item);
    _liveFeedSnapshot.set(key, item);
    return _feedRowHtml(item, key);
  }).join('');
  return '<div class="live-feed" id="mon-live-feed">' + rows + '</div>';
}

// Prepend a single new finding to the existing feed without touching
// the rows already in the DOM. Returns true if the row was added, false
// if the key was already present (duplicate suppression).
function _prependFeedRow(item) {
  var key = _feedKey(item);
  if (_liveFeedSnapshot.has(key)) return false;
  var feed = document.getElementById('mon-live-feed');
  if (!feed) return false;
  _liveFeedSnapshot.set(key, item);
  if (feed.classList.contains('empty')) {
    feed.classList.remove('empty');
    feed.innerHTML = '';
  }
  feed.insertAdjacentHTML('afterbegin', _feedRowHtml(item, key));
  // Cap visible rows at 20 to match the initial render.
  var rows = feed.querySelectorAll('.dash-finding-row');
  for (var i = 20; i < rows.length; i++) {
    var k = rows[i].dataset.feedKey;
    if (k) _liveFeedSnapshot.delete(k);
    rows[i].remove();
  }
  return true;
}

// Update header stat values in place — avoids the full-card re-render
// that used to flash on every poll.
function _updateHeaderStats(status) {
  if (!status) return;
  var ev = document.getElementById('mon-events-val');
  if (ev) ev.textContent = status.events_checked || 0;
  var fd = document.getElementById('mon-findings-val');
  if (fd) fd.textContent = status.findings_detected || 0;
  var lc = document.getElementById('mon-last-check');
  if (lc) lc.textContent = _timeSince(status.last_check_at);
}

// Click handler wired via data-action on each live-feed row. Looks up
// the finding in the snapshot by stable key — append-only rendering
// means index-based lookups would drift as new rows come in.
export function openLiveFeedFinding(arg) {
  var item = _liveFeedSnapshot.get(arg);
  if (item && item.finding) openFindingDrawer(item.finding);
}

function _pollHistorySummary(checks) {
  var total = (checks || []).length;
  var hits  = (checks || []).filter(function (c) { return (c.events || 0) > 0; }).length;
  if (total === 0) return 'No polls yet';
  var last = (checks && checks[0]) || null;
  var lastTxt = last ? _timeSince(last.at) : '\u2014';
  return hits + ' of ' + total + ' polls had events \u00B7 last poll ' + lastTxt;
}

function _monitorChecksHtml(checks) {
  if (!checks || checks.length === 0) {
    return '<div style="text-align:center; padding:24px; color:var(--text-muted);">No polls yet.</div>';
  }
  var rows = checks.slice(0, 200);
  if (!_pollHistoryShowAll) {
    rows = rows.filter(function (c) { return (c.events || 0) > 0 || (c.findings || 0) > 0; });
  }
  rows = rows.slice(0, 50);

  var toggleLabel = _pollHistoryShowAll
    ? 'Show only polls with events'
    : 'Show all polls (including empty)';
  var toggle =
    '<div style="display:flex; justify-content:flex-end; padding:0 0 8px;">' +
      '<a data-action="togglePollHistoryFilter" ' +
         'style="color:var(--text-muted); font-size:11px; cursor:pointer;">' +
        escapeHtml(toggleLabel) +
      '</a>' +
    '</div>';

  if (rows.length === 0) {
    return toggle +
      '<div style="text-align:center; padding:24px; color:var(--text-muted);">' +
        'No polls with events in the last ' + checks.length + ' checks. ' +
        '<a data-action="togglePollHistoryFilter" style="color:var(--accent); cursor:pointer;">Show all</a>' +
      '</div>';
  }

  return toggle +
    '<table class="monitor-checks-table"><thead><tr>' +
    '<th>Time</th><th>Events</th><th>Event IDs</th><th>Findings</th>' +
    '</tr></thead><tbody>' +
    rows.map(function (c) {
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

export function togglePollHistoryExpand() {
  _pollHistoryExpanded = !_pollHistoryExpanded;
  if (document.getElementById('monitor-page-root')) renderMonitorPage();
}

export function togglePollHistoryFilter() {
  _pollHistoryShowAll = !_pollHistoryShowAll;
  if (document.getElementById('monitor-page-root')) renderMonitorPage();
}

// ---------- Topbar live-monitor indicator ----------
// Small green pulsing dot + "Live" text shown on every page when the
// monitor is active. Hidden when idle. The anchor itself lives in
// index.html inside .topbar-actions; we only flip display here.
function _updateNavLiveIndicator() {
  var el = document.getElementById('nav-live-indicator');
  if (!el) return;
  var active = !!(monitorClient.status && monitorClient.status.active);
  el.style.display = active ? 'inline-flex' : 'none';
}

export function mountNavLiveIndicator() {
  _updateNavLiveIndicator();
  monitorClient.subscribe(function (type) {
    if (type === 'tick') return;
    _updateNavLiveIndicator();
  });
}

// Kept as an exported stub so app.js's action registry still resolves
// while any stale markup from an older page render exists. The old
// Settings accordion has been replaced by the gear dropdown inside the
// live-panel header — see toggleMonGearDropdown below.
export function toggleMonSettings() { /* deprecated — noop */ }

// Open/close the live-panel gear dropdown. Toggles the `hidden`
// attribute so CSS `[hidden]` hides it; outside-click and Escape
// handlers below close it.
export function toggleMonGearDropdown(arg, target, event) {
  if (event && event.stopPropagation) event.stopPropagation();
  var dd = document.getElementById('mon-gear-dropdown');
  if (!dd) return;
  if (dd.hidden) dd.hidden = false;
  else dd.hidden = true;
}

// Outside click closes the gear dropdown. A single listener at document
// level covers every re-render since the dropdown is always in place
// with the same id.
document.addEventListener('click', function (e) {
  var dd = document.getElementById('mon-gear-dropdown');
  if (!dd || dd.hidden) return;
  var wrap = dd.closest('[data-mon-gear]');
  if (wrap && wrap.contains(e.target)) return;
  dd.hidden = true;
});

document.addEventListener('keydown', function (e) {
  if (e.key !== 'Escape') return;
  var dd = document.getElementById('mon-gear-dropdown');
  if (dd && !dd.hidden) dd.hidden = true;
});

// Commit the popover slider value to localStorage on change so Start
// picks it up and the Monitor page slider mirrors it on next render.
export function savePopoverInterval(arg, target) {
  if (!target) return;
  var n = parseInt(target.value, 10);
  if (isFinite(n)) _saveStoredInterval(n);
  _refreshLiveSubtitle();
}


// ---------------------------------------------------------------
// Monitor v1.6 — three-band layout helpers (KPI + histogram + rail)
// ---------------------------------------------------------------

// Connection state for the SSE stream. 'idle' is the default before any
// connect attempt. 'live' means at least one event has arrived. 'reconnecting'
// is set after an error; 'disconnected' is set after the retry-limit has
// been exhausted. The initial state is recomputed inside renderMonitorPage
// from monitorClient._source.
let _monConnState = 'idle';

function _readConnState() {
  var status = monitorClient.status;
  if (!status || !status.active) return 'idle';
  var src = monitorClient._source;
  if (!src) return 'reconnecting';
  // EventSource.readyState: 0 CONNECTING, 1 OPEN, 2 CLOSED
  if (src.readyState === 1) return 'live';
  if (src.readyState === 0) return 'reconnecting';
  return 'disconnected';
}

// Parse a check/finding's timestamp into a JS millisecond value. The
// backend stores "YYYY-MM-DD HH:MM:SS" in local time, so we normalize
// to ISO first. NaN -> 0 so downstream arithmetic stays finite.
function _tsMs(s) {
  if (!s) return 0;
  var t = Date.parse(String(s).replace(' ', 'T'));
  return isNaN(t) ? 0 : t;
}

// Test-alert counter — bucketed by local YYYY-MM-DD so it resets each day.
const LS_TESTS_TODAY = 'pulse.monitor.testsToday';
function _todayKey() {
  var d = new Date();
  var m = String(d.getMonth() + 1).padStart(2, '0');
  var day = String(d.getDate()).padStart(2, '0');
  return d.getFullYear() + '-' + m + '-' + day;
}
export function getTestAlertsToday() {
  try {
    var raw = localStorage.getItem(LS_TESTS_TODAY);
    if (!raw) return 0;
    var obj = JSON.parse(raw);
    return (obj && obj.date === _todayKey()) ? (parseInt(obj.count, 10) || 0) : 0;
  } catch (e) { return 0; }
}
function _incTestAlertsToday() {
  try {
    var next = getTestAlertsToday() + 1;
    localStorage.setItem(LS_TESTS_TODAY, JSON.stringify({ date: _todayKey(), count: next }));
  } catch (e) {}
}

// Compute per-severity totals for the most recent 1h of the feed.
function _severityCountsLastHour(feed) {
  var cutoff = Date.now() - 60 * 60 * 1000;
  var counts = { critical: 0, high: 0, medium: 0, low: 0 };
  (feed || []).forEach(function (item) {
    if (_tsMs(item.at) < cutoff) return;
    var sev = ((item.finding && item.finding.severity) || 'low').toLowerCase();
    if (counts[sev] != null) counts[sev]++;
  });
  return counts;
}

// Roll the poll checks up into an events-per-minute rate and a 10-minute
// sparkline. Checks are stored newest-first, and each `events` value is the
// total inspected during that poll.
function _eventRateStats(checks) {
  var now = Date.now();
  var windowMs = 10 * 60 * 1000;
  var cutoff = now - windowMs;
  var bucketCount = 10;
  var spark = new Array(bucketCount).fill(0);
  var totalEvents = 0;
  var oldestMs = now;
  (checks || []).forEach(function (c) {
    var t = _tsMs(c.at);
    if (!t || t < cutoff) return;
    totalEvents += (c.events || 0);
    oldestMs = Math.min(oldestMs, t);
    var idx = bucketCount - 1 - Math.floor((now - t) / (windowMs / bucketCount));
    if (idx >= 0 && idx < bucketCount) spark[idx] += (c.events || 0);
  });
  var minsCovered = Math.max(1, (now - oldestMs) / 60000);
  return { rate: totalEvents / minsCovered, spark: spark, totalEvents: totalEvents };
}

// Poll success = % of recent polls that returned without an implicit error.
// Proxy until the backend exposes a success flag: any poll row present in
// `checks` is considered successful. We still want the ratio shown in the
// KPI tile so the user can sanity-check streaming health, so compute
// polls-with-events / total-polls as a hit-rate fallback.
function _pollSuccessStats(checks) {
  var recent = (checks || []).slice(0, 20);
  if (recent.length === 0) return { pct: null, hits: 0, total: 0 };
  var hits = recent.filter(function (c) { return (c.events || 0) > 0; }).length;
  return { pct: Math.round((hits / recent.length) * 100), hits: hits, total: recent.length };
}

function _computeKpiStats() {
  var feed    = monitorClient.feed;
  var checks  = monitorClient.checks;
  var status  = monitorClient.status || {};
  var rate    = _eventRateStats(checks);
  var sev1h   = _severityCountsLastHour(feed);
  var worst   = sev1h.critical ? 'critical'
              : sev1h.high     ? 'high'
              : sev1h.medium   ? 'medium'
              : sev1h.low      ? 'low' : '';
  var alerts1h = sev1h.critical + sev1h.high + sev1h.medium + sev1h.low;
  var poll    = _pollSuccessStats(checks);
  var active  = !!status.active;
  return {
    eventsPerMin: Math.round(rate.rate * 10) / 10,
    eventsSpark:  rate.spark,
    eventsTotal:  rate.totalEvents,
    activeSessions: active ? 1 : 0,
    alerts1h: alerts1h,
    alertsWorst: worst,
    pollPct: poll.pct,
    pollHits: poll.hits,
    pollTotal: poll.total,
    testsToday: getTestAlertsToday(),
    connState: _monConnState,
  };
}

// Tiny SVG sparkline — N points, max-normalised, single stroke.
function _sparklineSvg(values, w, h, color) {
  w = w || 60;
  h = h || 18;
  color = color || 'var(--accent)';
  var vals = values && values.length ? values : [0];
  var max  = Math.max.apply(null, vals);
  if (max === 0) max = 1;
  var stepX = w / Math.max(1, vals.length - 1);
  var pts = vals.map(function (v, i) {
    var x = i * stepX;
    var y = h - (v / max) * (h - 2) - 1;
    return x.toFixed(1) + ',' + y.toFixed(1);
  }).join(' ');
  return '<svg class="mon-kpi-spark" width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">' +
    '<polyline points="' + pts + '" fill="none" stroke="' + color + '" stroke-width="1.5" stroke-linejoin="round"/>' +
  '</svg>';
}

function _kpiTile(label, valueHtml, subHtml, sparkHtml) {
  return '<div class="mon-kpi-tile">' +
    '<div class="mon-kpi-label">' + label + '</div>' +
    '<div class="mon-kpi-value">' + valueHtml + '</div>' +
    (subHtml ? '<div class="mon-kpi-sub">' + subHtml + '</div>' : '') +
    (sparkHtml || '') +
  '</div>';
}

function _connTile(state) {
  var dotCls = state;
  var label = ({
    live: 'LIVE',
    reconnecting: 'RECONNECTING',
    disconnected: 'DISCONNECTED',
    idle: 'IDLE',
  })[state] || 'IDLE';
  var valCls = ({
    live: 'ok', reconnecting: 'medium', disconnected: 'crit', idle: 'off',
  })[state] || 'off';
  return '<div class="mon-kpi-tile">' +
    '<div class="mon-kpi-label"><span class="mon-conn-dot ' + dotCls + '"></span>Stream</div>' +
    '<div class="mon-kpi-value small ' + valCls + '">' + label + '</div>' +
    '<div class="mon-kpi-sub">SSE /api/monitor/stream</div>' +
  '</div>';
}

function _kpiStripHtml() {
  var k = _computeKpiStats();
  var worstCls = k.alertsWorst || 'off';
  var rateLabel = (k.eventsPerMin || 0).toFixed(k.eventsPerMin >= 10 ? 0 : 1);
  var rateSub   = k.eventsTotal + ' events in last 10 min';
  var alertsSub = k.alerts1h === 0
    ? 'last hour'
    : 'worst: ' + (k.alertsWorst || 'low').toUpperCase();
  var pollVal   = k.pollPct == null ? '—' : (k.pollPct + '%');
  var pollSub   = k.pollTotal
    ? k.pollHits + ' of ' + k.pollTotal + ' polls hit'
    : 'no polls yet';
  var tiles = [
    _kpiTile('Events / min', '<span>' + rateLabel + '</span>', rateSub,
             _sparklineSvg(k.eventsSpark, 56, 18, 'var(--accent)')),
    _kpiTile('Active sessions',
             '<span class="' + (k.activeSessions ? 'ok' : 'off') + '">' + k.activeSessions + '</span>',
             k.activeSessions ? 'SSE connected' : 'not monitoring'),
    _kpiTile('Alerts (1h)',
             '<span class="' + worstCls + '">' + k.alerts1h + '</span>',
             alertsSub),
    _kpiTile('Poll success', '<span class="' + (k.pollPct == null ? 'off' : (k.pollPct >= 50 ? 'ok' : 'medium')) + '">' + pollVal + '</span>', pollSub),
    _kpiTile('Test alerts today',
             '<span class="' + (k.testsToday ? '' : 'off') + '">' + k.testsToday + '</span>',
             'resets at midnight'),
    _connTile(k.connState),
  ].join('');
  return '<div class="mon-kpi-strip">' + tiles + '</div>';
}

// ---------- Histogram ----------
// 24 buckets of 5 minutes = last 2 hours. Stacked per-severity.
function _histogramHtml() {
  var feed = monitorClient.feed || [];
  var now = Date.now();
  var totalMs = 2 * 60 * 60 * 1000;
  var bucketCount = 24;
  var bucketMs = totalMs / bucketCount;
  var buckets = [];
  for (var i = 0; i < bucketCount; i++) {
    buckets.push({ critical: 0, high: 0, medium: 0, low: 0 });
  }
  var anyHit = false;
  feed.forEach(function (item) {
    var t = _tsMs(item.at);
    if (!t) return;
    var delta = now - t;
    if (delta < 0 || delta >= totalMs) return;
    var idx = bucketCount - 1 - Math.floor(delta / bucketMs);
    if (idx < 0 || idx >= bucketCount) return;
    var sev = ((item.finding && item.finding.severity) || 'low').toLowerCase();
    if (buckets[idx][sev] != null) { buckets[idx][sev]++; anyHit = true; }
  });
  var maxStack = 1;
  buckets.forEach(function (b) {
    var s = b.critical + b.high + b.medium + b.low;
    if (s > maxStack) maxStack = s;
  });

  var w = 1000; // virtual viewBox width; scales to container
  var h = 72;
  var gap = 2;
  var bw = (w - gap * (bucketCount - 1)) / bucketCount;
  var sevColors = {
    critical: 'var(--severity-critical, #f87171)',
    high:     'var(--severity-high, #fb923c)',
    medium:   'var(--severity-medium, #fbbf24)',
    low:      'var(--severity-low, #60a5fa)',
  };
  var sevOrder = ['critical', 'high', 'medium', 'low'];

  var bars = buckets.map(function (b, i) {
    var x = i * (bw + gap);
    var y = h;
    var segs = '';
    sevOrder.forEach(function (sev) {
      var n = b[sev];
      if (!n) return;
      var sh = (n / maxStack) * (h - 2);
      y -= sh;
      segs += '<rect x="' + x.toFixed(1) + '" y="' + y.toFixed(1) +
              '" width="' + bw.toFixed(1) + '" height="' + sh.toFixed(1) +
              '" fill="' + sevColors[sev] + '" rx="1"/>';
    });
    return segs || ('<rect x="' + x.toFixed(1) + '" y="' + (h - 1) +
            '" width="' + bw.toFixed(1) + '" height="1" fill="var(--border)"/>');
  }).join('');

  var body = anyHit
    ? '<svg class="mon-histogram-svg" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' + bars + '</svg>'
    : '<div class="mon-histogram-empty">No alerts in the last 2 hours.</div>';

  return '<div class="mon-histogram-card" id="mon-histogram">' +
    '<div class="mon-histogram-header">' +
      '<div class="mon-histogram-title">Last 2 hours — alerts by severity</div>' +
      '<div class="mon-histogram-meta">' + feed.length + ' event' + (feed.length === 1 ? '' : 's') + ' in buffer</div>' +
    '</div>' +
    body +
  '</div>';
}

// ---------- Right rail cards ----------
function _throughputCard() {
  var k = _computeKpiStats();
  var delta = null;
  // crude baseline: compare last 5 min to previous 5 min
  var spark = k.eventsSpark || [];
  if (spark.length >= 10) {
    var recent = spark.slice(5).reduce(function (a, b) { return a + b; }, 0);
    var prior  = spark.slice(0, 5).reduce(function (a, b) { return a + b; }, 0);
    if (prior > 0) delta = (recent / prior).toFixed(1) + 'x baseline';
    else if (recent > 0) delta = 'no prior baseline';
  }
  return '<div class="mon-rail-card">' +
    '<div class="mon-rail-title">Throughput' +
      '<span class="mon-rail-hint">' + (k.eventsPerMin || 0) + '/min</span>' +
    '</div>' +
    _sparklineSvg(spark, 280, 36, 'var(--accent)').replace('mon-kpi-spark', 'mon-rail-spark').replace('width="280"', 'width="100%"') +
    (delta ? '<div class="mon-rail-empty" style="margin-top:6px;">' + escapeHtml(delta) + '</div>' : '') +
  '</div>';
}

function _topSourcesCard() {
  var feed = monitorClient.feed || [];
  var cutoff = Date.now() - 60 * 60 * 1000;
  var counts = {};
  feed.forEach(function (item) {
    if (_tsMs(item.at) < cutoff) return;
    var f = item.finding || {};
    var src = f.hostname || f.source || f.host || 'unknown';
    counts[src] = (counts[src] || 0) + 1;
  });
  var rows = Object.keys(counts).map(function (k) {
    return { name: k, count: counts[k] };
  }).sort(function (a, b) { return b.count - a.count; }).slice(0, 5);

  var max = rows.length ? rows[0].count : 1;
  var body = rows.length === 0
    ? '<div class="mon-rail-empty">No events in the last hour.</div>'
    : '<div class="mon-top-list">' +
        rows.map(function (r) {
          var pct = Math.max(6, Math.round((r.count / max) * 100));
          return '<div class="mon-top-row">' +
            '<div class="mon-top-name">' + escapeHtml(r.name) + '</div>' +
            '<div class="mon-top-count">' + r.count + '</div>' +
            '<div class="mon-top-bar"><span style="width:' + pct + '%"></span></div>' +
          '</div>';
        }).join('') +
      '</div>';
  return '<div class="mon-rail-card">' +
    '<div class="mon-rail-title">Top Sources<span class="mon-rail-hint">last hour</span></div>' +
    body +
  '</div>';
}

function _severityDonutCard() {
  var feed = monitorClient.feed || [];
  var cutoff = Date.now() - 2 * 60 * 60 * 1000;
  var counts = { critical: 0, high: 0, medium: 0, low: 0 };
  feed.forEach(function (item) {
    if (_tsMs(item.at) < cutoff) return;
    var sev = ((item.finding && item.finding.severity) || 'low').toLowerCase();
    if (counts[sev] != null) counts[sev]++;
  });
  var total = counts.critical + counts.high + counts.medium + counts.low;
  var colors = {
    critical: 'var(--severity-critical, #f87171)',
    high:     'var(--severity-high, #fb923c)',
    medium:   'var(--severity-medium, #fbbf24)',
    low:      'var(--severity-low, #60a5fa)',
  };
  var order = ['critical', 'high', 'medium', 'low'];
  var cx = 36, cy = 36, r = 28, stroke = 10;
  var circ = 2 * Math.PI * r;
  var svg = '<svg class="mon-donut" viewBox="0 0 72 72">' +
    '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="var(--border)" stroke-width="' + stroke + '"/>';
  if (total > 0) {
    var offset = 0;
    order.forEach(function (sev) {
      var n = counts[sev];
      if (!n) return;
      var len = (n / total) * circ;
      svg += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '"' +
             ' fill="none" stroke="' + colors[sev] + '" stroke-width="' + stroke + '"' +
             ' stroke-dasharray="' + len.toFixed(2) + ' ' + circ.toFixed(2) + '"' +
             ' stroke-dashoffset="' + (-offset).toFixed(2) + '"' +
             ' transform="rotate(-90 ' + cx + ' ' + cy + ')"/>';
      offset += len;
    });
  }
  svg += '</svg>';
  var legend = order.map(function (sev) {
    return '<div class="row">' +
      '<span class="dot" style="background:' + colors[sev] + '"></span>' +
      '<span>' + sev.charAt(0).toUpperCase() + sev.slice(1) + '</span>' +
      '<span class="count">' + counts[sev] + '</span>' +
    '</div>';
  }).join('');
  return '<div class="mon-rail-card">' +
    '<div class="mon-rail-title">Severity<span class="mon-rail-hint">last 2h</span></div>' +
    '<div class="mon-donut-wrap">' + svg + '<div class="mon-donut-legend">' + legend + '</div></div>' +
  '</div>';
}

function _patternsCard() {
  var feed = monitorClient.feed || [];
  var cutoff = Date.now() - 2 * 60 * 60 * 1000;
  var counts = {};
  var total = 0;
  feed.forEach(function (item) {
    if (_tsMs(item.at) < cutoff) return;
    var f = item.finding || {};
    var rule = f.rule || 'Unknown';
    counts[rule] = (counts[rule] || 0) + 1;
    total++;
  });
  var rows = Object.keys(counts).map(function (k) {
    return { name: k, count: counts[k] };
  }).sort(function (a, b) { return b.count - a.count; }).slice(0, 3);
  var topSum = rows.reduce(function (n, r) { return n + r.count; }, 0);
  var hint = total > 0
    ? rows.length + ' pattern' + (rows.length === 1 ? '' : 's') + ' = ' + Math.round((topSum / total) * 100) + '%'
    : '';
  var body = rows.length === 0
    ? '<div class="mon-rail-empty">No alerts to cluster yet.</div>'
    : rows.map(function (r) {
        return '<div class="mon-pattern-row">' +
          '<div class="mon-pattern-name">' + escapeHtml(r.name) + '</div>' +
          '<div class="mon-pattern-count">' + r.count + '</div>' +
        '</div>';
      }).join('');
  return '<div class="mon-rail-card">' +
    '<div class="mon-rail-title">Patterns<span class="mon-rail-hint">' + escapeHtml(hint) + '</span></div>' +
    body +
  '</div>';
}

function _sessionsMiniCard() {
  var active = !!(monitorClient.status && monitorClient.status.active);
  var last = (_monitorSessions && _monitorSessions[0]) || null;
  var lastHtml;
  if (active) {
    lastHtml = '<div class="mon-rail-empty" style="color:var(--text);">Session in progress</div>';
  } else if (last) {
    var started = last.started_at || '—';
    var findings = parseInt(last.findings_count, 10) || 0;
    lastHtml = '<div class="mon-rail-empty">Last: ' + escapeHtml(started) + ' · ' +
               findings + ' finding' + (findings === 1 ? '' : 's') + '</div>';
  } else {
    lastHtml = '<div class="mon-rail-empty">No sessions recorded yet.</div>';
  }
  var testBtn = '<button class="live-btn" data-action="sendMonitorTestAlertFromRail" ' +
                (active ? '' : 'disabled title="Start monitor to send a test alert"') +
                '>Send test alert</button>';
  return '<div class="mon-rail-card">' +
    '<div class="mon-rail-title">Sessions<span class="mon-rail-hint">' +
      (_monitorSessions ? _monitorSessions.length : 0) + ' total</span></div>' +
    lastHtml +
    '<div style="margin-top:10px;">' + testBtn + '</div>' +
  '</div>';
}

// Wrapper used by the rail's "Send test alert" button so we can bump the
// per-day counter before handing off to the existing backend call. The
// sidebar/header button also increments through this wrapper.
export async function sendMonitorTestAlertFromRail() {
  _incTestAlertsToday();
  await monitorClient.sendTestAlert();
  _scheduleMonRerender();
}

function _rightRailHtml() {
  return '<div class="mon-right-rail" id="mon-right-rail">' +
    _throughputCard() +
    _topSourcesCard() +
    _severityDonutCard() +
    _patternsCard() +
    _sessionsMiniCard() +
  '</div>';
}

// ---------- New feed renderer (3-band layout) ----------
function _monFeedRowHtml2(item, key) {
  var f   = item.finding || {};
  var sev = (f.severity || 'LOW').toUpperCase();
  var src = f.hostname || f.source || f.host || 'unknown';
  var at  = item.at || '';
  var time = at.length >= 19 ? at.slice(11, 19) : at;
  var desc = f.details || f.description || '';
  if (desc.length > 100) desc = desc.substring(0, 100) + '…';
  return '<div class="mon-feed-row sev-' + sev.toLowerCase() + '" ' +
         'data-action="openLiveFeedFinding" data-arg="' + escapeHtml(key) + '" ' +
         'data-feed-key="' + escapeHtml(key) + '">' +
    '<div class="ts">' + escapeHtml(time) + '</div>' +
    '<div><span class="src-chip">' + escapeHtml(src) + '</span></div>' +
    '<div class="msg"><span class="rule">' + escapeHtml(f.rule || 'Unknown') + '</span>' +
      '<span class="detail">' + escapeHtml(desc) + '</span></div>' +
    '<div><span class="sev-pill">' + sev + '</span></div>' +
  '</div>';
}

function _monFeedCardHtml(feed, active) {
  _liveFeedSnapshot = new Map();
  var items = (feed || []).slice(0, 50);
  var rows = items.map(function (item) {
    var key = _feedKey(item);
    _liveFeedSnapshot.set(key, item);
    return _monFeedRowHtml2(item, key);
  }).join('');

  var body;
  if (items.length === 0) {
    if (!active) {
      body = '<div class="mon-feed-body empty" id="mon-live-feed">' +
        'Monitor is idle. Start monitoring to stream live events from your Windows channels.' +
      '</div>';
    } else {
      body = '<div class="mon-feed-body empty" id="mon-live-feed">' +
        'All quiet — waiting for events. The feed will update as alerts stream in.' +
      '</div>';
    }
  } else {
    body = '<div class="mon-feed-body" id="mon-live-feed">' + rows + '</div>';
  }

  var controls = active
    ? '<button class="live-btn stop btn-with-icon" data-action="stopMonitor"><i data-lucide="square"></i><span>Stop</span></button>'
    : '<button class="live-btn start btn-with-icon" data-action="startMonitor"><i data-lucide="play"></i><span>Start Monitoring</span></button>';
  var gear =
    '<div class="mon-gear-wrap" data-mon-gear>' +
      '<button class="live-btn gear" data-action="toggleMonGearDropdown" ' +
        'aria-label="Monitor settings" title="Monitor settings" type="button">⚙</button>' +
      '<div class="pulse-dropdown mon-gear-dropdown" id="mon-gear-dropdown" hidden>' +
        '<div class="pulse-dropdown-section">' +
          '<div class="pulse-dropdown-header">Poll Interval</div>' +
          '<div class="gear-slider-row">' +
            '<input type="range" id="mon-interval" min="5" max="300" step="5" ' +
              'value="' + ((monitorClient.status && monitorClient.status.poll_interval) || getStoredInterval() || 30) + '"' +
              (active ? ' disabled' : '') +
              ' data-action-input="updateMonIntervalLabel"' +
              ' data-action-change="savePopoverInterval" />' +
            '<span class="gear-slider-value" id="mon-interval-label">' +
              ((monitorClient.status && monitorClient.status.poll_interval) || getStoredInterval() || 30) + 's</span>' +
          '</div>' +
        '</div>' +
        '<div class="pulse-dropdown-divider"></div>' +
        '<div class="pulse-dropdown-section">' +
          '<div class="pulse-dropdown-header">Channels</div>' +
          channelPillGridHtml({ disabled: active }) +
        '</div>' +
      '</div>' +
    '</div>';

  return '<div class="mon-feed-card">' +
    '<div class="mon-feed-head">' +
      '<div class="mon-feed-head-left">' +
        '<div class="live-dot ' + (active ? '' : 'idle') + '"></div>' +
        '<div class="live-badge ' + (active ? '' : 'idle') + '">' + (active ? 'LIVE' : 'IDLE') + '</div>' +
        '<div class="mon-feed-title">Event feed</div>' +
      '</div>' +
      '<div class="mon-feed-controls">' + controls + gear + '</div>' +
    '</div>' +
    body +
  '</div>';
}

// Coalesced render — many SSE events in quick succession collapse into a
// single paint. Also used by the rail's test-alert button.
let _monRenderScheduled = false;
let _monRenderFn = null;
function _scheduleMonRerender() {
  if (!_monRenderFn || _monRenderScheduled) return;
  _monRenderScheduled = true;
  requestAnimationFrame(function () {
    _monRenderScheduled = false;
    if (document.getElementById('monitor-page-root')) _monRenderFn();
  });
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

    // Warning banner only matters when the host can't actually run
    // live mode — surface it just above the live panel so users see it
    // before they hit Start.
    var platformWarning = (s.platform_supports_live === false)
      ? '<div class="card" style="padding:10px 16px; margin-bottom:16px; color:#d29922; font-size:12px;">Live mode requires Windows \u2014 falling back to file mode.</div>'
      : '';

    c.innerHTML =
      '<div id="monitor-page-root">' +

      platformWarning +

      // Band 1: 6-tile KPI strip
      _kpiStripHtml() +

      // Band 2: 2-hour stacked histogram
      _histogramHtml() +

      // Band 3: feed (left) + right rail
      '<div class="mon-band3">' +
        _monFeedCardHtml(monitorClient.feed, active) +
        _rightRailHtml() +
      '</div>' +

      // Supporting cards below the hero bands — detail history
      // (Poll History, Sessions) stays out of the top-of-page bands.
      '<div class="card mon-settings-card" style="margin-bottom:16px;">' +
        '<div class="mon-settings-row ' + (_pollHistoryExpanded ? 'open' : '') + '" ' +
             'data-action="togglePollHistoryExpand" role="button" tabindex="0" ' +
             'aria-expanded="' + (_pollHistoryExpanded ? 'true' : 'false') + '">' +
          '<div class="mon-settings-title">Poll History</div>' +
          '<div class="mon-settings-summary" id="mon-poll-summary">' + escapeHtml(_pollHistorySummary(monitorClient.checks)) + '</div>' +
          '<div class="mon-settings-caret">' + (_pollHistoryExpanded ? '\u25B2' : '\u25BC') + '</div>' +
        '</div>' +
        (_pollHistoryExpanded
          ? '<div class="mon-settings-body" id="mon-poll-body">' + _monitorChecksHtml(monitorClient.checks) + '</div>'
          : '') +
      '</div>' +

      '<div class="card" id="monitor-sessions-section">' +
        _sessionsSectionHtml() +
      '</div>' +
      '</div>';
  }

  _monRenderFn = render;

  // Kick off an initial sessions load so the section populates when the
  // page first mounts. Fire-and-forget — the section re-renders itself.
  _loadMonitorSessions();

  render();

  if (_monPageUnsub) _monPageUnsub();
  var prevActive = !!(monitorClient.status && monitorClient.status.active);
  function onUpdate(type, data) {
    if (!document.getElementById('monitor-page-root')) {
      if (_monPageUnsub) _monPageUnsub();
      _monRenderFn = null;
      return;
    }
    if (type === 'tick') {
      // Cheap heartbeat: only repaint when the connection tile would change.
      var desired = _readConnState();
      if (desired !== _monConnState) {
        _monConnState = desired;
        _scheduleMonRerender();
      }
      return;
    }
    var nowActive = !!(monitorClient.status && monitorClient.status.active);

    // Any SSE event affects KPIs, histogram, and rail — re-render
    // via the raf-coalesced helper so bursts collapse into one paint.
    _scheduleMonRerender();

    if (prevActive && !nowActive) {
      // Monitor just stopped — pull the refreshed session list.
      _loadMonitorSessions();
    }
    prevActive = nowActive;
  }
  monitorClient.subscribe(onUpdate);
  _monPageUnsub = function () { monitorClient.unsubscribe(onUpdate); _monRenderFn = null; };
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
// session id -> true. Active sessions can't be selected (backend refuses
// to delete them) so they're filtered out before adding here.
let _selectedSessions        = {};

async function _loadMonitorSessions() {
  _monitorSessions = await apiMonitorSessions(200);
  _renderSessionsSection();
  _refreshIdlePanelIfVisible();
}

// If the Monitor page is showing its idle panel (feed card in idle mode),
// re-render just that card in place using the freshly loaded sessions.
// Leaves the sessions card, poll history card, and header untouched.
function _refreshIdlePanelIfVisible() {
  var feedEl = document.getElementById('mon-live-feed');
  if (!feedEl || !feedEl.classList.contains('mon-idle-panel')) return;
  feedEl.outerHTML = _monitorIdlePanelHtml(_monitorSessions || []);
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

  // Prune selections against the current inactive-session list.
  var inactive = _monitorSessions.filter(function (s) { return !!s.ended_at; });
  var inactiveIds = {};
  inactive.forEach(function (s) { inactiveIds[s.id] = true; });
  Object.keys(_selectedSessions).forEach(function (k) {
    if (!inactiveIds[k]) delete _selectedSessions[k];
  });

  var nSelected = Object.keys(_selectedSessions).length;
  var deleteBarStyle = nSelected > 0 ? 'flex' : 'none';
  var allSelected = inactive.length > 0 && inactive.every(function (s) {
    return _selectedSessions[s.id];
  });

  var cards = _monitorSessions.map(_sessionCardHtml).join('');
  return '<div class="section-label" style="display:flex; justify-content:space-between; align-items:center;">' +
      '<span>Monitor Sessions</span>' +
      '<label style="display:flex; align-items:center; gap:6px; font-size:11px; color:var(--text-muted); cursor:pointer;">' +
        '<input type="checkbox" id="sessions-select-all" ' +
          (allSelected ? 'checked ' : '') +
          'data-action="toggleMonitorSessionSelectAll" aria-label="Select all sessions" />' +
        'Select all' +
      '</label>' +
    '</div>' +
    '<div id="sessions-delete-bar" class="bulk-bar" style="display:' + deleteBarStyle + ';">' +
      '<span class="bulk-bar-count">' + nSelected + ' selected</span>' +
      '<button class="btn btn-danger" id="sessions-delete-btn" data-action="deleteSelectedMonitorSessions">' +
        'Delete ' + nSelected + ' session' + (nSelected === 1 ? '' : 's') +
      '</button>' +
      '<a class="bulk-bar-clear" data-action="toggleMonitorSessionSelectAll" data-arg="false">Clear selection</a>' +
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
  var selectCell = '';
  if (!isActive) {
    var checked = _selectedSessions[sess.id] ? 'checked' : '';
    selectCell = '<input type="checkbox" class="session-select" ' + checked +
      ' data-action="toggleMonitorSessionSelect" data-arg="' + sess.id + '" ' +
      'aria-label="Select session" />';
  }
  return '<div class="session-card' + (isOpen ? ' open' : '') + '">' +
    '<div class="session-head">' +
      '<span data-action="stopClickPropagation" style="display:inline-flex; align-items:center; margin-right:8px;">' + selectCell + '</span>' +
      '<span class="session-expand" data-action="toggleSessionExpand" data-arg="' + sess.id + '" ' +
        'style="display:flex; align-items:center; gap:8px; flex:1; cursor:pointer;">' +
        '<span class="session-caret">' + (isOpen ? '\u25BE' : '\u25B8') + '</span>' +
        '<span class="session-label">' + escapeHtml(_sessionHeaderLabel(sess)) + '</span>' +
        badge +
      '</span>' +
      (isActive
        ? ''
        : '<button class="session-delete" data-action="deleteMonitorSession" data-arg="' + sess.id + '" ' +
          'aria-label="Delete session" title="Delete session">&times;</button>') +
    '</div>' +
    body +
  '</div>';
}

export function toggleMonitorSessionSelect(arg, target, ev) {
  if (ev) ev.stopPropagation();
  var id = parseInt(arg, 10);
  if (!isFinite(id)) return;
  // Active sessions cannot be selected — backend refuses to delete them.
  var sess = _monitorSessions.find(function (s) { return s.id === id; });
  if (!sess || !sess.ended_at) return;
  if (_selectedSessions[id]) delete _selectedSessions[id];
  else _selectedSessions[id] = true;
  _renderSessionsSection();
}

export function toggleMonitorSessionSelectAll(arg, target) {
  var checked;
  if (target && typeof target.checked === 'boolean') checked = target.checked;
  else checked = (arg === true || arg === 'true');
  _selectedSessions = {};
  if (checked) {
    _monitorSessions.forEach(function (s) {
      if (s.ended_at) _selectedSessions[s.id] = true;
    });
  }
  _renderSessionsSection();
}

export async function deleteSelectedMonitorSessions() {
  var ids = Object.keys(_selectedSessions).map(function (k) { return +k; });
  if (ids.length === 0) return;
  var msg = 'Delete ' + ids.length + ' monitor session' + (ids.length === 1 ? '' : 's') +
            ' and all linked findings? This cannot be undone.';
  if (!window.confirm(msg)) return;
  var r = await apiDeleteMonitorSessionsBatch(ids);
  if (!r.ok) {
    toastError((r.data && r.data.detail) || 'Delete failed.');
    return;
  }
  var deleted = r.data && typeof r.data.deleted === 'number' ? r.data.deleted : ids.length;
  (r.data && r.data.failed || []).forEach(function (f) {
    toastError('Session ' + f.id + ': ' + (f.message || 'delete failed'));
  });
  ids.forEach(function (id) {
    if (_expandedSessionId === id) _expandedSessionId = null;
    delete _sessionFindingsCache[id];
    delete _sessionFindingsLoading[id];
  });
  _selectedSessions = {};
  showToast('Deleted ' + deleted + ' session' + (deleted === 1 ? '' : 's'), 'success');
  await _loadMonitorSessions();
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
        '<td>' + sevPillHtml(sev) + '</td>' +
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
// that doesn't collide. Every path goes through _incTestAlertsToday so the
// Monitor page's "Test alerts today" KPI tile stays in sync regardless of
// which button the user pressed.
export async function sendMonitorTestAlert() {
  _incTestAlertsToday();
  await monitorClient.sendTestAlert();
  _scheduleMonRerender();
}
