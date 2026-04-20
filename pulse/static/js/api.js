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

export async function fetchFleet() {
  try {
    var resp = await fetch('/api/fleet');
    var data = await resp.json();
    return data.hosts || [];
  } catch (e) { return []; }
}

export async function fetchAudit(limit) {
  try {
    var resp = await fetch('/api/audit?limit=' + (limit || 200));
    var data = await resp.json();
    return data.rows || [];
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

// POST /api/scan/system — kicks off a local Windows event-log scan.
// Body: { days: int, alert: bool }. 400 on non-Windows hosts.
export async function apiScanSystem(days, alert) {
  try {
    var resp = await fetch('/api/scan/system', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ days: days, alert: !!alert }),
    });
    var data = await resp.json().catch(function () { return {}; });
    return { ok: resp.ok, status: resp.status, data: data };
  } catch (e) {
    return { ok: false, status: 0, data: null, error: e };
  }
}

// GET /api/scheduler/status — current schedule + next-run.
export async function apiSchedulerStatus() {
  try {
    var resp = await fetch('/api/scheduler/status');
    return resp.json();
  } catch (e) {
    return {};
  }
}

// POST /api/scheduler/config — save the scheduled-scan config.
export async function apiSaveSchedulerConfig(body) {
  try {
    var resp = await fetch('/api/scheduler/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    var data = await resp.json().catch(function () { return {}; });
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

// Shared helper for the batch DELETE endpoints. Keeps every bulk-delete
// path on the dashboard speaking the same response envelope so the
// page modules that consume it stay near-identical.
async function _apiBatchDelete(url, body) {
  try {
    var resp = await fetch(url, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    var data = null;
    try { data = await resp.json(); } catch (_) { data = null; }
    return { ok: resp.ok, status: resp.status, data: data };
  } catch (e) {
    return { ok: false, status: 0, data: null, error: e };
  }
}

// DELETE /api/history/batch with a list of scan ids — delegates to the
// scans batch endpoint server-side but keeps the module's own resource
// name in the URL so the history page isn't leaking /api/scans details.
export async function apiDeleteHistory(ids) {
  return _apiBatchDelete('/api/history/batch', { ids: ids });
}

// DELETE /api/reports/batch with a list of filenames.
export async function apiDeleteReports(filenames) {
  return _apiBatchDelete('/api/reports/batch', { filenames: filenames });
}

// DELETE /api/block-ip/batch with a list of IPs.
export async function apiUnblockBatch(ips) {
  return _apiBatchDelete('/api/block-ip/batch', { ips: ips });
}

// DELETE /api/monitor/sessions/batch with a list of session ids.
export async function apiDeleteMonitorSessionsBatch(ids) {
  return _apiBatchDelete('/api/monitor/sessions/batch', { ids: ids });
}

// DELETE /api/whitelist/batch with a list of {key, value} entries.
export async function apiDeleteWhitelistEntries(entries) {
  return _apiBatchDelete('/api/whitelist/batch', { entries: entries });
}

// ---------------------------------------------------------------
// Config / whitelist / rules list
// ---------------------------------------------------------------
export async function apiGetConfig() {
  var resp = await fetch('/api/config');
  if (!resp.ok) throw new Error('HTTP ' + resp.status);
  return resp.json();
}

export async function apiGetRules() {
  var resp = await fetch('/api/rules');
  if (!resp.ok) throw new Error('HTTP ' + resp.status);
  return resp.json();
}

// Diff two past scans: returns { scan_a, scan_b, new, resolved, shared }.
export async function apiCompareScans(idA, idB) {
  var resp = await fetch('/api/compare?a=' + idA + '&b=' + idB);
  if (!resp.ok) throw new Error('compare failed: ' + resp.status);
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

// --- Current user + admin user management --------------------------------

export async function apiGetMe() {
  try {
    var resp = await fetch('/api/me');
    if (!resp.ok) return { role: null };
    return resp.json();
  } catch (e) { return { role: null }; }
}

export async function apiListUsers() {
  var resp = await fetch('/api/users');
  if (!resp.ok) return { users: [] };
  return resp.json();
}

export async function apiCreateUser(body) {
  return fetch('/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export async function apiUpdateUserRole(userId, role) {
  return fetch('/api/users/' + Number(userId) + '/role', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: role }),
  });
}

export async function apiUpdateUserActive(userId, active) {
  return fetch('/api/users/' + Number(userId) + '/active', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ active: !!active }),
  });
}

export async function apiDeleteUser(userId) {
  return fetch('/api/users/' + Number(userId), { method: 'DELETE' });
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
// Finding review status (mark reviewed / false positive)
// ---------------------------------------------------------------
export async function apiSetFindingReview(findingId, flags) {
  // flags: { reviewed: bool, falsePositive: bool, note: string }. The two
  // flags go over the wire independently so each button can toggle on its
  // own without clobbering the other.
  var body = {
    reviewed: !!(flags && flags.reviewed),
    false_positive: !!(flags && flags.falsePositive),
    note: (flags && flags.note) || '',
  };
  var resp = await fetch('/api/finding/' + encodeURIComponent(findingId) + '/review', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  var data = await resp.json().catch(function () { return {}; });
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

// Monitor sessions — DVR-style record of every Start→Stop span.
export async function apiMonitorSessions(limit) {
  try {
    var resp = await fetch('/api/monitor/sessions?limit=' + (limit || 100));
    var data = await resp.json();
    return data.sessions || [];
  } catch (e) { return []; }
}

export async function apiMonitorSessionFindings(sessionId) {
  try {
    var resp = await fetch('/api/monitor/sessions/' + encodeURIComponent(sessionId) + '/findings');
    var data = await resp.json();
    return data.findings || [];
  } catch (e) { return []; }
}

export async function apiDeleteMonitorSession(sessionId) {
  try {
    var resp = await fetch('/api/monitor/sessions/' + encodeURIComponent(sessionId), {
      method: 'DELETE',
    });
    var data = await resp.json().catch(function () { return {}; });
    return { ok: resp.ok, status: resp.status, data: data };
  } catch (e) {
    return { ok: false, status: 0, data: null, error: e };
  }
}

export async function apiClearMonitorSessions() {
  try {
    var resp = await fetch('/api/monitor/sessions', { method: 'DELETE' });
    var data = await resp.json().catch(function () { return {}; });
    return { ok: resp.ok, status: resp.status, data: data };
  } catch (e) {
    return { ok: false, status: 0, data: null, error: e };
  }
}

// ---------------------------------------------------------------
// Report export URL builder — the <a download> flow doesn't go
// through fetch(), but the URL gets constructed here so api.js
// stays the single owner of endpoint shapes.
// ---------------------------------------------------------------
export function apiExportUrl(scanId, fmt) {
  return '/api/export/' + scanId + '?format=' + fmt;
}
