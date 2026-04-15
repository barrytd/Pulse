// monitor.js — Live monitor SSE client + Monitor page + dashboard-embedded
// live panel. The EventSource itself stays here (it's not fetch()); all
// HTTP calls route through api.js wrappers.
(function () {
  'use strict';

  // Subtle two-tone chime when a new finding arrives. Uses Web Audio so
  // there's no asset to ship.
  function playDing() {
    try {
      var Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      var ctx = window._dingCtx || (window._dingCtx = new Ctx());
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
  var monitorClient = {
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
        var s = await window.apiMonitorStatus();
        this.status = s;
        var h = await window.apiMonitorHistory(50);
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
        var s = await window.apiMonitorStart(cfg || {});
        this.status = s;
        localStorage.setItem('pulse.monitor.autoResume', '1');
        this._connect();
        this._notify('status');
      } catch (e) {
        window.toastError('Failed to start monitor');
      }
    },

    async stop() {
      try {
        var s = await window.apiMonitorStop();
        this.status = s;
        localStorage.removeItem('pulse.monitor.autoResume');
        this._disconnect();
        this._notify('status');
      } catch (e) {
        window.toastError('Failed to stop monitor');
      }
    },

    async sendTestAlert() {
      try {
        var r = await window.apiMonitorTestAlert();
        if (!r.ok) {
          window.toastError((r.data && r.data.detail) || 'Test alert failed');
        }
      } catch (e) {
        window.toastError('Test alert failed');
      }
    },

    // Pull start-time settings from the Monitor page form if the user
    // is on that page; otherwise send {} and let the server keep its
    // existing config.
    _readSettingsForm() {
      var intervalInput = document.getElementById('mon-interval');
      var channelsInput = document.getElementById('mon-channels');
      if (!intervalInput && !channelsInput) return {};
      var cfg = {};
      if (intervalInput) cfg.poll_interval = parseInt(intervalInput.value, 10) || 30;
      if (channelsInput) {
        cfg.channels = channelsInput.value.split(',')
          .map(function (s) { return s.trim(); })
          .filter(Boolean);
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
          '<div><div class="time">' + window.escapeHtml(item.at || '') + '</div></div>' +
          '<div>' +
            '<div class="rule">' + window.escapeHtml(f.rule || 'Unknown') + '</div>' +
            '<div class="desc">' + window.escapeHtml(f.details || f.description || '') + '</div>' +
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
          '<td>' + window.escapeHtml(c.at || '') + '</td>' +
          '<td class="num">' + (c.events || 0) + '</td>' +
          '<td class="num" style="font-family:monospace;">' + window.escapeHtml(ids) + '</td>' +
          '<td class="num' + (c.findings > 0 ? ' hit' : '') + '">' + (c.findings || 0) + '</td>' +
        '</tr>';
      }).join('') +
      '</tbody></table>';
  }

  // ---------- Dashboard-embedded live panel ----------
  function renderDashLivePanel() {
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

  function mountDashLivePanel() {
    renderDashLivePanel();
    if (window._dashLiveUnsub) window._dashLiveUnsub();
    function onUpdate(type) {
      if (!document.getElementById('dash-live-panel')) {
        if (window._dashLiveUnsub) window._dashLiveUnsub();
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
    window._dashLiveUnsub = function () { monitorClient.unsubscribe(onUpdate); };
  }

  // ---------------------------------------------------------------
  // PAGE: Monitor
  // ---------------------------------------------------------------
  async function renderMonitorPage() {
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
              '<input type="text" id="mon-channels" value="' +
                window.escapeHtml((s.channels || ['Security','System']).join(', ')) + '"' +
                (active ? ' disabled' : '') + ' />' +
              '<div class="hint">Comma-separated Windows log channels (live mode)</div>' +
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

    if (window._monPageUnsub) window._monPageUnsub();
    function onUpdate(type) {
      if (!document.getElementById('monitor-page-root')) {
        if (window._monPageUnsub) window._monPageUnsub();
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
    window._monPageUnsub = function () { monitorClient.unsubscribe(onUpdate); };
  }

  // Wrapper-style top-level entry points some onclick handlers use.
  function startMonitor() { return monitorClient.start(); }
  function stopMonitor()  { return monitorClient.stop(); }

  // Wired via data-action-input on the poll-interval slider; keeps the
  // visible label in sync with the slider value as the user drags.
  function updateMonIntervalLabel(arg, target) {
    var lbl = document.getElementById('mon-interval-label');
    if (lbl && target) lbl.textContent = target.value + 's';
  }
  // Settings page also has a "sendTestAlert" for the threshold-alert flow
  // (different endpoint), so expose the monitor-side alert under a name
  // that doesn't collide.
  function sendMonitorTestAlert() { return monitorClient.sendTestAlert(); }

  window.monitorClient         = monitorClient;
  window.playDing              = playDing;
  window.renderDashLivePanel   = renderDashLivePanel;
  window.mountDashLivePanel    = mountDashLivePanel;
  window.renderMonitorPage     = renderMonitorPage;
  window.startMonitor          = startMonitor;
  window.stopMonitor           = stopMonitor;
  window.sendMonitorTestAlert  = sendMonitorTestAlert;
  window.updateMonIntervalLabel = updateMonIntervalLabel;
})();
