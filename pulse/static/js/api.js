// api.js — the only module that calls fetch(). All network access is
// funneled through named wrappers on window so other modules stay
// transport-agnostic. Cached API blobs live here too.
(function () {
  'use strict';

  // ---------------------------------------------------------------
  // Shared cached API data so pages don't re-fetch every click.
  // Exposed on window so other modules can read/invalidate.
  // ---------------------------------------------------------------
  window.cachedScans    = null;
  window.cachedFindings = null;
  window.cachedRules    = null;

  // ---------------------------------------------------------------
  // Scans / findings
  // ---------------------------------------------------------------
  async function fetchScans(limit) {
    if (window.cachedScans && window.cachedScans.length >= (limit || 10)) return window.cachedScans;
    try {
      var resp = await fetch('/api/history?limit=' + (limit || 50));
      var data = await resp.json();
      window.cachedScans = data.scans || [];
      return window.cachedScans;
    } catch (e) { return []; }
  }

  async function fetchFindings(scanId) {
    try {
      var resp = await fetch('/api/report/' + scanId);
      var data = await resp.json();
      return data.findings || [];
    } catch (e) { return []; }
  }

  async function fetchRuleNames() {
    if (window.cachedRules) return window.cachedRules;
    try {
      var resp = await fetch('/api/rules');
      var data = await resp.json();
      window.cachedRules = (data.rules || []).slice().sort();
      return window.cachedRules;
    } catch (e) { return []; }
  }

  // POST a single file to /api/scan. Returns { ok, status, data }.
  async function apiScan(file) {
    var form = new FormData();
    form.append('file', file);
    try {
      var resp = await fetch('/api/scan', { method: 'POST', body: form });
      var data = await resp.json();
      return { ok: resp.ok, status: resp.status, data: data };
    } catch (e) {
      return { ok: false, status: 0, data: null, error: e };
    }
  }

  // DELETE /api/scans with a list of ids. Returns { ok, status, data }.
  async function apiDeleteScans(ids) {
    try {
      var resp = await fetch('/api/scans', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: ids }),
      });
      var data = resp.ok ? await resp.json() : null;
      return { ok: resp.ok, status: resp.status, data: data };
    } catch (e) {
      return { ok: false, status: 0, data: null, error: e };
    }
  }

  // ---------------------------------------------------------------
  // Config / whitelist / rules list
  // ---------------------------------------------------------------
  async function apiGetConfig() {
    var resp = await fetch('/api/config');
    return resp.json();
  }

  async function apiGetRules() {
    var resp = await fetch('/api/rules');
    return resp.json();
  }

  async function apiGetAuthStatus() {
    try {
      var resp = await fetch('/api/auth/status');
      return resp.json();
    } catch (e) {
      return { email: '' };
    }
  }

  async function apiWhitelistBuiltin() {
    try {
      var resp = await fetch('/api/whitelist/builtin');
      return resp.json();
    } catch (e) {
      return { services: [] };
    }
  }

  // PUT body into /api/config/whitelist. Returns raw Response so
  // callers can branch on status.
  async function apiSaveWhitelist(body) {
    return fetch('/api/config/whitelist', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  async function apiSaveEmailConfig(body) {
    return fetch('/api/config/email', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  async function apiSaveAlertsConfig(body) {
    return fetch('/api/config/alerts', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  async function apiSendTestAlert() {
    var resp = await fetch('/api/alerts/test', { method: 'POST' });
    var data = await resp.json();
    return { ok: resp.ok, status: resp.status, data: data };
  }

  // ---------------------------------------------------------------
  // Daily scores
  // ---------------------------------------------------------------
  async function apiDailyScores(days) {
    var d = days || 90;
    var resp = await fetch('/api/score/daily?days=' + d);
    return resp.json();
  }

  // ---------------------------------------------------------------
  // Auth
  // ---------------------------------------------------------------
  async function apiChangeEmail(newEmail, currentPassword) {
    var resp = await fetch('/api/auth/email', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: newEmail, current_password: currentPassword }),
    });
    var data = resp.ok ? null : await resp.json().catch(function () { return {}; });
    return { ok: resp.ok, status: resp.status, data: data };
  }

  async function apiChangePassword(newPassword, currentPassword) {
    var resp = await fetch('/api/auth/password', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ new_password: newPassword, current_password: currentPassword }),
    });
    var data = resp.ok ? null : await resp.json().catch(function () { return {}; });
    return { ok: resp.ok, status: resp.status, data: data };
  }

  async function apiLogout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch (_) { /* best-effort */ }
  }

  // ---------------------------------------------------------------
  // Monitor
  // ---------------------------------------------------------------
  async function apiMonitorStatus() {
    var resp = await fetch('/api/monitor/status');
    return resp.json();
  }

  async function apiMonitorHistory(limit) {
    var l = limit || 50;
    var resp = await fetch('/api/monitor/history?limit=' + l);
    return resp.json();
  }

  async function apiMonitorStart(cfg) {
    var resp = await fetch('/api/monitor/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg || {}),
    });
    return resp.json();
  }

  async function apiMonitorStop() {
    var resp = await fetch('/api/monitor/stop', { method: 'POST' });
    return resp.json();
  }

  async function apiMonitorTestAlert() {
    var resp = await fetch('/api/monitor/test-alert', { method: 'POST' });
    var body = resp.ok ? null : await resp.json().catch(function () { return {}; });
    return { ok: resp.ok, status: resp.status, data: body };
  }

  // ---------------------------------------------------------------
  // Report export URL builder — the <a download> flow doesn't go
  // through fetch(), but the URL gets constructed here so api.js
  // stays the single owner of endpoint shapes.
  // ---------------------------------------------------------------
  function apiExportUrl(scanId, fmt) {
    return '/api/export/' + scanId + '?format=' + fmt;
  }

  // ---------------------------------------------------------------
  // Expose
  // ---------------------------------------------------------------
  window.fetchScans           = fetchScans;
  window.fetchFindings        = fetchFindings;
  window.fetchRuleNames       = fetchRuleNames;
  window.apiScan              = apiScan;
  window.apiDeleteScans       = apiDeleteScans;
  window.apiGetConfig         = apiGetConfig;
  window.apiGetRules          = apiGetRules;
  window.apiGetAuthStatus     = apiGetAuthStatus;
  window.apiWhitelistBuiltin  = apiWhitelistBuiltin;
  window.apiSaveWhitelist     = apiSaveWhitelist;
  window.apiSaveEmailConfig   = apiSaveEmailConfig;
  window.apiSaveAlertsConfig  = apiSaveAlertsConfig;
  window.apiSendTestAlert     = apiSendTestAlert;
  window.apiDailyScores       = apiDailyScores;
  window.apiChangeEmail       = apiChangeEmail;
  window.apiChangePassword    = apiChangePassword;
  window.apiLogout            = apiLogout;
  window.apiMonitorStatus     = apiMonitorStatus;
  window.apiMonitorHistory    = apiMonitorHistory;
  window.apiMonitorStart      = apiMonitorStart;
  window.apiMonitorStop       = apiMonitorStop;
  window.apiMonitorTestAlert  = apiMonitorTestAlert;
  window.apiExportUrl         = apiExportUrl;
})();
