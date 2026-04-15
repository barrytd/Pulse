// api.js — the only module that calls fetch(). All network access is
// funneled through named exports so other modules stay transport-agnostic.
// Cached API blobs live here too.
'use strict';

// ---------------------------------------------------------------
// Shared cached API data so pages don't re-fetch every click.
// Module-level state; invalidators live on the exported setters below.
// ---------------------------------------------------------------
export let cachedScans    = null;
export let cachedFindings = null;
export let cachedRules    = null;

// Setters so other modules can invalidate caches (ES module bindings
// are read-only from outside).
export function invalidateScansCache()    { cachedScans = null; }
export function invalidateFindingsCache() { cachedFindings = null; }
export function invalidateRulesCache()    { cachedRules = null; }

// ---------------------------------------------------------------
// Scans / findings
// ---------------------------------------------------------------
export async function fetchScans(limit) {
  if (cachedScans && cachedScans.length >= (limit || 10)) return cachedScans;
  try {
    var resp = await fetch('/api/history?limit=' + (limit || 50));
    var data = await resp.json();
    cachedScans = data.scans || [];
    return cachedScans;
  } catch (e) { return []; }
}

export async function fetchFindings(scanId) {
  try {
    var resp = await fetch('/api/report/' + scanId);
    var data = await resp.json();
    return data.findings || [];
  } catch (e) { return []; }
}

export async function fetchRuleNames() {
  if (cachedRules) return cachedRules;
  try {
    var resp = await fetch('/api/rules');
    var data = await resp.json();
    cachedRules = (data.rules || []).slice().sort();
    return cachedRules;
  } catch (e) { return []; }
}

// POST a single file to /api/scan. Returns { ok, status, data }.
export async function apiScan(file) {
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
export async function apiDeleteScans(ids) {
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
export async function apiGetConfig() {
  var resp = await fetch('/api/config');
  return resp.json();
}

export async function apiGetRules() {
  var resp = await fetch('/api/rules');
  return resp.json();
}

export async function apiGetAuthStatus() {
  try {
    var resp = await fetch('/api/auth/status');
    return resp.json();
  } catch (e) {
    return { email: '' };
  }
}

export async function apiWhitelistBuiltin() {
  try {
    var resp = await fetch('/api/whitelist/builtin');
    return resp.json();
  } catch (e) {
    return { services: [] };
  }
}

// PUT body into /api/config/whitelist. Returns raw Response so
// callers can branch on status.
export async function apiSaveWhitelist(body) {
  return fetch('/api/config/whitelist', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export async function apiSaveEmailConfig(body) {
  return fetch('/api/config/email', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export async function apiSaveAlertsConfig(body) {
  return fetch('/api/config/alerts', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export async function apiSendTestAlert() {
  var resp = await fetch('/api/alerts/test', { method: 'POST' });
  var data = await resp.json();
  return { ok: resp.ok, status: resp.status, data: data };
}

export async function apiSaveWebhookConfig(body) {
  return fetch('/api/config/webhook', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export async function apiSendTestWebhook() {
  var resp = await fetch('/api/webhook/test', { method: 'POST' });
  var data = await resp.json();
  return { ok: resp.ok, status: resp.status, data: data };
}

// ---------------------------------------------------------------
// Daily scores
// ---------------------------------------------------------------
export async function apiDailyScores(days) {
  var d = days || 90;
  var resp = await fetch('/api/score/daily?days=' + d);
  return resp.json();
}

// ---------------------------------------------------------------
// Auth
// ---------------------------------------------------------------
export async function apiChangeEmail(newEmail, currentPassword) {
  var resp = await fetch('/api/auth/email', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: newEmail, current_password: currentPassword }),
  });
  var data = resp.ok ? null : await resp.json().catch(function () { return {}; });
  return { ok: resp.ok, status: resp.status, data: data };
}

export async function apiChangePassword(newPassword, currentPassword) {
  var resp = await fetch('/api/auth/password', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ new_password: newPassword, current_password: currentPassword }),
  });
  var data = resp.ok ? null : await resp.json().catch(function () { return {}; });
  return { ok: resp.ok, status: resp.status, data: data };
}

export async function apiLogout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } catch (_) { /* best-effort */ }
}

// ---------------------------------------------------------------
// Monitor
// ---------------------------------------------------------------
export async function apiMonitorStatus() {
  var resp = await fetch('/api/monitor/status');
  return resp.json();
}

export async function apiMonitorHistory(limit) {
  var l = limit || 50;
  var resp = await fetch('/api/monitor/history?limit=' + l);
  return resp.json();
}

export async function apiMonitorStart(cfg) {
  var resp = await fetch('/api/monitor/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cfg || {}),
  });
  return resp.json();
}

export async function apiMonitorStop() {
  var resp = await fetch('/api/monitor/stop', { method: 'POST' });
  return resp.json();
}

export async function apiMonitorTestAlert() {
  var resp = await fetch('/api/monitor/test-alert', { method: 'POST' });
  var body = resp.ok ? null : await resp.json().catch(function () { return {}; });
  return { ok: resp.ok, status: resp.status, data: body };
}

// ---------------------------------------------------------------
// Report export URL builder — the <a download> flow doesn't go
// through fetch(), but the URL gets constructed here so api.js
// stays the single owner of endpoint shapes.
// ---------------------------------------------------------------
export function apiExportUrl(scanId, fmt) {
  return '/api/export/' + scanId + '?format=' + fmt;
}
