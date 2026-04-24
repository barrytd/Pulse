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

// Per-framework compliance coverage summary. Returns { nist_csf, iso_27001, rules }.
export async function apiGetCompliance() {
  var resp = await fetch('/api/compliance');
  if (!resp.ok) throw new Error('HTTP ' + resp.status);
  return resp.json();
}

// Trend analytics — rolling-window aggregates for the Trends page.
// ``days`` sets the window length (7 / 30 / 90 on the UI; backend
// accepts any positive int).
export async function apiGetTrends(days) {
  var q = (days && Number(days) > 0) ? ('?days=' + Number(days)) : '';
  var resp = await fetch('/api/analytics/trends' + q);
  if (!resp.ok) throw new Error('HTTP ' + resp.status);
  return resp.json();
}

// Organisation branding — logo + display name that overrides the
// default "PULSE / Threat Detection" sidebar lockup. Reads are open to
// any authenticated user (the sidebar shows the brand); writes are
// admin-only on the server.
export async function apiGetBranding() {
  var resp = await fetch('/api/branding');
  if (!resp.ok) return { organization_name: null, has_logo: false };
  return resp.json();
}

export async function apiSaveBrandingName(name) {
  var resp = await fetch('/api/branding', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ organization_name: name == null ? null : String(name) }),
  });
  var data = await resp.json().catch(function () { return {}; });
  return { ok: resp.ok, status: resp.status, data: data };
}

export async function apiUploadBrandingLogo(file) {
  var fd = new FormData();
  fd.append('file', file);
  var resp = await fetch('/api/branding/logo', { method: 'POST', body: fd });
  var data = await resp.json().catch(function () { return {}; });
  return { ok: resp.ok, status: resp.status, data: data };
}

export async function apiDeleteBrandingLogo() {
  var resp = await fetch('/api/branding/logo', { method: 'DELETE' });
  var data = await resp.json().catch(function () { return {}; });
  return { ok: resp.ok, status: resp.status, data: data };
}

// Admin-only: every analyst note across every finding, newest-first.
// Powers the Settings > Notes tab so admins see the full investigation
// thread without clicking into each finding.
export async function apiListAllNotes(limit) {
  var q = (limit && Number(limit) > 0) ? ('?limit=' + Number(limit)) : '';
  var resp = await fetch('/api/notes' + q);
  if (!resp.ok) return { notes: [] };
  return resp.json();
}

// Admin-only: list feedback submissions newest-first. Returns [] if the
// caller isn't an admin so the tab can render an empty state instead of
// blowing up the Settings render.
export async function apiListFeedback(limit) {
  var q = (limit && Number(limit) > 0) ? ('?limit=' + Number(limit)) : '';
  var resp = await fetch('/api/feedback' + q);
  if (!resp.ok) return { rows: [] };
  return resp.json();
}

// Submit in-app feedback (bug / idea / general). Server validates length
// + kind; throws on non-2xx so the modal can surface the message.
export async function apiSubmitFeedback(payload) {
  var resp = await fetch('/api/feedback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload || {}),
  });
  if (!resp.ok) {
    var msg = 'HTTP ' + resp.status;
    try { var j = await resp.json(); if (j && j.detail) msg = j.detail; } catch (e) {}
    throw new Error(msg);
  }
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

// Upload an avatar image (File/Blob). Returns the parsed JSON body on
// success, or throws with the server's error detail so callers can show
// it in a toast.
export async function apiUploadAvatar(file) {
  var fd = new FormData();
  fd.append('file', file);
  var resp = await fetch('/api/me/avatar', { method: 'POST', body: fd });
  var body = null;
  try { body = await resp.json(); } catch (e) { /* non-JSON error page */ }
  if (!resp.ok) {
    var msg = (body && body.detail) ? body.detail : ('HTTP ' + resp.status);
    throw new Error(msg);
  }
  return body || { status: 'ok' };
}

// --- API tokens (CI bearer auth) -----------------------------------------

export async function apiListTokens() {
  var resp = await fetch('/api/tokens');
  if (!resp.ok) return { tokens: [] };
  return resp.json();
}

// Returns { id, name, last4, token } — the raw token string is only
// present in the creation response; list/GET never includes it.
export async function apiCreateToken(name) {
  var resp = await fetch('/api/tokens', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: name }),
  });
  var body = null;
  try { body = await resp.json(); } catch (e) { /* non-JSON error page */ }
  if (!resp.ok) {
    var msg = (body && body.detail) ? body.detail : ('HTTP ' + resp.status);
    throw new Error(msg);
  }
  return body;
}

export async function apiRevokeToken(id) {
  var resp = await fetch('/api/tokens/' + encodeURIComponent(id), { method: 'DELETE' });
  if (!resp.ok) {
    var msg = ('HTTP ' + resp.status);
    try { var body = await resp.json(); if (body && body.detail) msg = body.detail; } catch (e) {}
    throw new Error(msg);
  }
  return true;
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

// Admin-only: set/clear a user's display_name. Pass null (or empty
// string) to clear. Returns the updated public_user payload.
export async function apiUpdateUserDisplayName(userId, displayName) {
  var resp = await fetch('/api/users/' + Number(userId) + '/display_name', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      display_name: (displayName == null || displayName === '') ? null : String(displayName),
    }),
  });
  var data = await resp.json().catch(function () { return {}; });
  return { ok: resp.ok, status: resp.status, data: data };
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
  };
  // Only include `note` when the caller explicitly passed one. Omitting
  // it signals the server to leave the existing review_note untouched.
  if (flags && Object.prototype.hasOwnProperty.call(flags, 'note')) {
    body.note = String(flags.note || '');
  }
  var resp = await fetch('/api/finding/' + encodeURIComponent(findingId) + '/review', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  var data = await resp.json().catch(function () { return {}; });
  return { ok: resp.ok, status: resp.status, data: data };
}

// Analyst notes on a finding — append-only thread. List returns notes
// oldest-first so the UI reads top-to-bottom. Create/delete throw via
// their truthy .ok field so callers can surface server detail strings.
export async function apiListFindingNotes(findingId) {
  var resp = await fetch('/api/finding/' + encodeURIComponent(findingId) + '/notes');
  if (!resp.ok) return { notes: [] };
  return resp.json();
}

export async function apiCreateFindingNote(findingId, body) {
  var resp = await fetch('/api/finding/' + encodeURIComponent(findingId) + '/notes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ body: body || '' }),
  });
  var data = await resp.json().catch(function () { return {}; });
  return { ok: resp.ok, status: resp.status, data: data };
}

export async function apiDeleteFindingNote(findingId, noteId) {
  var resp = await fetch(
    '/api/finding/' + encodeURIComponent(findingId) +
    '/notes/' + encodeURIComponent(noteId),
    { method: 'DELETE' }
  );
  var data = await resp.json().catch(function () { return {}; });
  return { ok: resp.ok, status: resp.status, data: data };
}

// Bulk assign / unassign / review-toggle across many findings. `op` is
// one of 'assign' | 'unassign' | 'review' | 'unreview'. For op='assign'
// pass assigneeUserId. Returns {updated, skipped}.
export async function apiFindingsBatch(op, findingIds, assigneeUserId) {
  var body = { op: op, finding_ids: (findingIds || []).map(Number) };
  if (op === 'assign') body.assignee_user_id = Number(assigneeUserId);
  var resp = await fetch('/api/findings/batch', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  var data = await resp.json().catch(function () { return {}; });
  return { ok: resp.ok, status: resp.status, data: data };
}

// Set or clear a finding's assignee. Pass null / undefined / '' for
// `assigneeUserId` to unassign. Returns the full updated finding on
// success (same shape as review + workflow endpoints).
export async function apiSetFindingAssignee(findingId, assigneeUserId) {
  var resp = await fetch('/api/finding/' + encodeURIComponent(findingId) + '/assign', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      assignee_user_id: (assigneeUserId === '' || assigneeUserId == null) ? null : Number(assigneeUserId),
    }),
  });
  var data = await resp.json().catch(function () { return {}; });
  return { ok: resp.ok, status: resp.status, data: data };
}

// Incident workflow state. Orthogonal to the review flags — "how far along
// is the response?" vs. "is this real?". States: new, acknowledged,
// investigating, resolved. Returns the full updated finding on success.
export async function apiSetFindingWorkflow(findingId, state) {
  var resp = await fetch('/api/finding/' + encodeURIComponent(findingId) + '/workflow', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ workflow_status: state }),
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
