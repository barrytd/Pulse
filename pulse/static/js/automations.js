// automations.js — Automations page (SOAR playbooks, phase 2).
//
// Sections, top to bottom:
//   1. Waiting for approval: response steps (block an IP, post a message)
//      a playbook proposed. Approve asks for the security PIN when the
//      user has one; nothing runs until a person approves it.
//   2. Playbooks: the org's stored recipes, with on/off and delete (admin).
//   3. Recent runs: every run, click a row for its step-by-step log.
//   4. Add a playbook (admin): built-in examples + a JSON paste box,
//      mirroring the SIGMA import on the Rules page.
//   5. Connectors: which integrations playbooks may use, per org.
//
// runStepsHtml / runStatusPill / approvePlaybookRun / denyPlaybookRun are
// shared with the finding drawer (findings.js), which shows the runs a
// finding triggered.
'use strict';

import { escapeHtml, showToast, toastError, relTimeHtml } from './dashboard.js';
import { apiGetMe } from './api.js';
import { pinGuard } from './pin.js';
import { builderHtml } from './playbook-builder.js';

var _isAdmin = false;
var _openRunId = null;
var _data = { playbooks: [], runs: [], awaiting: [], templates: [], connectors: [] };

// ---------------------------------------------------------------
// Shared bits (also used by the finding drawer)
// ---------------------------------------------------------------

var _RUN_STATUS = {
  running:           { label: 'Running',              tone: 'info' },
  awaiting_approval: { label: 'Waiting for approval', tone: 'warn' },
  completed:         { label: 'Completed',            tone: 'ok' },
  denied:            { label: 'Denied',               tone: 'muted' },
  failed:            { label: 'Failed',               tone: 'error' },
};

var _STEP_STATUS = {
  done:              { label: 'Done',          tone: 'ok' },
  no_result:         { label: 'No result',     tone: 'muted' },
  skipped:           { label: 'Skipped',       tone: 'muted' },
  running:           { label: 'Running',       tone: 'info' },
  awaiting_approval: { label: 'Needs approval', tone: 'warn' },
  approved:          { label: 'Approved',      tone: 'info' },
  denied:            { label: 'Denied',        tone: 'muted' },
  failed:            { label: 'Failed',        tone: 'error' },
};

export function runStatusPill(status) {
  var s = _RUN_STATUS[status] || { label: status || 'Unknown', tone: 'muted' };
  return '<span class="soar-pill soar-' + s.tone + '">' + escapeHtml(s.label) + '</span>';
}

function _stepPill(status) {
  var s = _STEP_STATUS[status] || { label: status || '?', tone: 'muted' };
  return '<span class="soar-pill soar-' + s.tone + '">' + escapeHtml(s.label) + '</span>';
}

function _inputsHtml(inputs) {
  if (!inputs) return '';
  var keys = Object.keys(inputs);
  if (!keys.length) return '';
  return '<div class="soar-inputs">' + keys.map(function (k) {
    var v = inputs[k];
    return '<span class="soar-input"><span class="k">' + escapeHtml(k) + '</span> ' +
      '<span class="v mono">' + escapeHtml(v == null ? '—' : String(v)) + '</span></span>';
  }).join('') + '</div>';
}

// Short, human summary of an enrichment result for the step log.
function _resultSummary(step) {
  var r = step.result;
  if (!r || typeof r !== 'object') return '';
  if (step.connector === 'abuseipdb' && r.score != null) {
    return 'AbuseIPDB score ' + r.score + '/100' + (r.country ? ' · ' + escapeHtml(r.country) : '');
  }
  if (step.connector === 'virustotal') {
    return r.found ? (r.malicious + ' of ' + r.engines + ' engines flag it') : 'Not in VirusTotal';
  }
  return '';
}

export function runStepsHtml(run, opts) {
  opts = opts || {};
  var steps = run.steps || [];
  if (!steps.length) return '<div class="muted soar-empty">No steps have run yet.</div>';
  var items = steps.map(function (s) {
    var summary = _resultSummary(s);
    var who = s.approved_by
      ? '<div class="soar-step-who">' + (s.status === 'denied' ? 'Denied' : 'Approved') +
          ' by ' + escapeHtml(s.approved_by) + '</div>'
      : '';
    return '<li class="soar-step soar-step-' + escapeHtml(s.status || '') + '">' +
      '<div class="soar-step-head">' +
        '<span class="soar-step-label">' + escapeHtml(s.label || (s.connector + ': ' + s.action)) + '</span>' +
        _stepPill(s.status) +
      '</div>' +
      (s.kind === 'response' || s.status === 'awaiting_approval' ? _inputsHtml(s.inputs) : '') +
      (summary ? '<div class="soar-step-msg">' + summary + '</div>' : '') +
      (s.message ? '<div class="soar-step-msg">' + escapeHtml(s.message) + '</div>' : '') +
      who +
    '</li>';
  }).join('');
  var actions = '';
  if (run.status === 'awaiting_approval' && opts.canApprove !== false) {
    actions =
      '<div class="soar-approve-row">' +
        '<button class="btn btn-primary btn-sm" data-action="approvePlaybookRun" data-arg="' + run.id + '">Approve</button>' +
        '<button class="btn btn-sm" data-action="denyPlaybookRun" data-arg="' + run.id + '">Deny</button>' +
        '<span class="muted soar-approve-note">Approving runs this step with the values shown.</span>' +
      '</div>';
  }
  return '<ol class="soar-steps">' + items + '</ol>' + actions;
}

function _findingLine(run) {
  var f = run.finding || {};
  var bits = [];
  if (f.rule) bits.push(escapeHtml(f.rule));
  if (f.hostname) bits.push('<span class="mono">' + escapeHtml(f.hostname) + '</span>');
  if (f.source_ip) bits.push('<span class="mono">' + escapeHtml(f.source_ip) + '</span>');
  return bits.join(' · ') || '<span class="muted">—</span>';
}

function _changed() {
  document.dispatchEvent(new CustomEvent('pulse:playbook-run-updated'));
}

export async function approvePlaybookRun(runId) {
  var resp = await pinGuard(function () {
    return fetch('/api/playbook-runs/' + Number(runId) + '/approve', { method: 'POST' });
  });
  var body = await resp.json().catch(function () { return {}; });
  if (!resp.ok) {
    var d = body.detail;
    toastError((d && d.message) || d || 'Approval failed.');
    _changed();
    return;
  }
  var last = (body.steps || []).filter(function (s) { return s.status !== 'awaiting_approval'; }).pop();
  if (last && last.status === 'failed') toastError(last.message || 'The action failed.');
  else showToast(body.status === 'awaiting_approval' ? 'Approved. The next step also needs approval.'
                                                     : 'Approved.');
  _changed();
}

export async function denyPlaybookRun(runId) {
  if (!window.confirm('Deny this step? The rest of the run stops.')) return;
  var resp = await fetch('/api/playbook-runs/' + Number(runId) + '/deny', { method: 'POST' });
  var body = await resp.json().catch(function () { return {}; });
  if (!resp.ok) { toastError(body.detail || 'Could not deny.'); _changed(); return; }
  showToast('Denied. The run was stopped.');
  _changed();
}

// ---------------------------------------------------------------
// Page
// ---------------------------------------------------------------

async function _getJson(url) {
  var r = await fetch(url);
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

async function _load() {
  var res = await Promise.all([
    _getJson('/api/playbooks'),
    _getJson('/api/playbook-runs?limit=50'),
    _getJson('/api/playbook-runs?status=awaiting_approval&limit=50'),
    _getJson('/api/playbooks/templates'),
    _getJson('/api/connectors'),
  ]);
  _data = {
    playbooks: res[0].playbooks || [],
    runs: res[1].runs || [],
    awaiting: res[2].runs || [],
    templates: res[3].templates || [],
    connectors: res[4].connectors || [],
  };
}

export async function renderAutomationsPage() {
  var c = document.getElementById('content');
  c.innerHTML = '<div class="muted" style="padding:32px; text-align:center;">Loading automations…</div>';
  try {
    var me = await apiGetMe();
    _isAdmin = !!(me && me.role === 'admin');
    await _load();
  } catch (e) {
    c.innerHTML = '<div class="card"><div class="dash-empty-note">Could not load automations (' +
      escapeHtml(e.message) + ').</div></div>';
    return;
  }
  _render();
}

function _render() {
  var c = document.getElementById('content');
  if (!c) return;
  c.innerHTML =
    '<div class="automations-page" id="automations-page">' +
      '<div class="page-title-block">' +
        '<h1 class="page-title">Automations' +
          '<span class="page-title-count">' + _data.playbooks.length + '</span></h1>' +
        (_isAdmin
          ? '<div class="page-title-actions"><button class="btn btn-primary" data-action="builderOpen">New playbook</button></div>'
          : '') +
      '</div>' +
      '<p class="muted soar-intro">Playbooks react to new findings on their own: they look ' +
        'attackers up right away, and propose responses like blocking an IP. ' +
        'A response never runs until someone approves it here or in the finding.</p>' +
      (_isAdmin ? builderHtml() : '') +
      _awaitingHtml() +
      _playbooksHtml() +
      _runsHtml() +
      (_isAdmin ? _addHtml() : '') +
      _connectorsHtml() +
    '</div>';
}

function _awaitingHtml() {
  if (!_data.awaiting.length) return '';
  var cards = _data.awaiting.map(function (run) {
    return '<div class="soar-await">' +
      '<div class="soar-await-head">' +
        '<div><div class="soar-await-title">' + escapeHtml(run.playbook_name) + '</div>' +
          '<div class="muted soar-await-sub">' + _findingLine(run) + ' · ' +
            relTimeHtml(run.created_at) + '</div></div>' +
        runStatusPill(run.status) +
      '</div>' +
      runStepsHtml(run) +
    '</div>';
  }).join('');
  return '<div class="card soar-card soar-card-await">' +
    '<div class="section-label">Waiting for approval (' + _data.awaiting.length + ')</div>' +
    cards +
  '</div>';
}

function _conditionText(c) {
  var v = Array.isArray(c.value) ? c.value.join(', ') : String(c.value);
  var ops = {
    eq: 'is', ne: 'is not', in: 'is one of', not_in: 'is not one of', contains: 'contains',
    gt: '>', gte: '≥', lt: '<', lte: '≤', severity_at_least: 'is at least',
    is_public: c.value ? 'is a public IP' : 'is not a public IP',
    exists: c.value ? 'is present' : 'is missing',
  };
  var op = ops[c.op] || c.op;
  var hasValue = c.op !== 'is_public' && c.op !== 'exists';
  return escapeHtml(c.field.replace('_', ' ')) + ' ' + escapeHtml(op) +
    (hasValue ? ' <span class="mono">' + escapeHtml(v) + '</span>' : '');
}

function _playbooksHtml() {
  if (!_data.playbooks.length) {
    return '<div class="card soar-card"><div class="section-label">Playbooks</div>' +
      '<div class="dash-empty-note">No playbooks yet. ' +
      (_isAdmin ? 'Add a built-in example or paste one below.' : 'Ask an admin to add one.') +
      '</div></div>';
  }
  var rows = _data.playbooks.map(function (p) {
    var when = p.conditions.length
      ? p.conditions.map(_conditionText).join(p.match === 'any' ? ' <b>or</b> ' : ' <b>and</b> ')
      : 'every new finding';
    var steps = p.steps.map(function (s) {
      return '<span class="soar-chip' + (s.kind === 'response' ? ' soar-chip-response' : '') + '"' +
        (s.requires_approval ? ' title="Waits for approval"' : '') + '>' +
        (s.conditional ? 'if… ' : '') + escapeHtml(s.label) +
        (s.requires_approval ? ' · approval' : '') + '</span>';
    }).join('');
    var status;
    if (_isAdmin) {
      status =
        '<button class="rule-toggle' + (p.enabled ? ' on' : ' off') + '" role="switch" aria-pressed="' +
          (p.enabled ? 'true' : 'false') + '" data-action="togglePlaybook" data-arg="' + p.id + '">' +
          '<span class="rule-toggle-track"><span class="rule-toggle-thumb"></span></span>' +
          '<span class="rule-toggle-label">' + (p.enabled ? 'On' : 'Off') + '</span>' +
        '</button> ' +
        '<button class="btn btn-ghost btn-sm" data-action="editPlaybook" data-arg="' + p.id + '">Edit</button> ' +
        '<button class="btn btn-ghost btn-sm" data-action="deletePlaybook" data-arg="' + p.id + '">Delete</button>';
    } else {
      status = '<span class="muted">' + (p.enabled ? 'On' : 'Off') + '</span>';
    }
    return '<tr' + (p.enabled ? '' : ' class="rule-row-disabled"') + '>' +
      '<td><div class="rule-name">' + escapeHtml(p.name) + (p.valid ? '' :
          ' <span class="soar-pill soar-error">Invalid</span>') + '</div>' +
        (p.description ? '<div class="rule-subline muted">' + escapeHtml(p.description) + '</div>' : '') +
        '<div class="soar-chips">' + steps + '</div></td>' +
      '<td class="soar-when">When ' + when + '</td>' +
      '<td class="soar-runs">' + p.runs + (p.awaiting ? ' <span class="soar-pill soar-warn">' +
          p.awaiting + ' waiting</span>' : '') +
        (p.last_run_at ? '<div class="muted">' + relTimeHtml(p.last_run_at) + '</div>' : '') + '</td>' +
      '<td class="col-actions">' + status + '</td>' +
    '</tr>';
  }).join('');
  return '<div class="card soar-card"><div class="section-label">Playbooks</div>' +
    '<div style="overflow-x:auto;"><table class="data-table soar-table">' +
      '<thead><tr><th>Playbook</th><th>Trigger</th><th>Runs</th><th>Status</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div></div>';
}

function _runsHtml() {
  if (!_data.runs.length) {
    return '<div class="card soar-card"><div class="section-label">Recent runs</div>' +
      '<div class="dash-empty-note">No runs yet. Runs appear when a new finding matches a playbook.</div></div>';
  }
  var rows = _data.runs.map(function (run) {
    var open = _openRunId === run.id;
    var done = (run.steps || []).filter(function (s) {
      return s.status !== 'awaiting_approval' && s.status !== 'running';
    }).length;
    return '<tr class="soar-run-row' + (open ? ' open' : '') + '" data-action="toggleRunDetail" ' +
        'data-arg="' + run.id + '" role="button" tabindex="0">' +
      '<td class="mono muted">#' + run.id + '</td>' +
      '<td>' + escapeHtml(run.playbook_name) + '</td>' +
      '<td>' + _findingLine(run) + '</td>' +
      '<td>' + runStatusPill(run.status) + '</td>' +
      '<td class="mono">' + done + '/' + run.total_steps + '</td>' +
      '<td>' + relTimeHtml(run.created_at) + '</td>' +
    '</tr>' +
    (open ? '<tr class="soar-run-detail"><td colspan="6">' + runStepsHtml(run) + '</td></tr>' : '');
  }).join('');
  return '<div class="card soar-card"><div class="section-label">Recent runs</div>' +
    '<div style="overflow-x:auto;"><table class="data-table soar-table">' +
      '<thead><tr><th>Run</th><th>Playbook</th><th>Finding</th><th>Status</th><th>Steps</th><th>Started</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div></div>';
}

function _addHtml() {
  var tpl = _data.templates.map(function (t) {
    return '<div class="soar-template">' +
      '<div class="soar-template-name">' + escapeHtml(t.name) + '</div>' +
      '<div class="muted soar-template-sum">' + escapeHtml(t.summary) + '</div>' +
      '<button class="btn btn-sm" data-action="addPlaybookTemplate" data-arg="' + escapeHtml(t.key) + '">Add</button>' +
    '</div>';
  }).join('');
  var example = JSON.stringify((_data.templates[0] || {}).recipe || {}, null, 2);
  return '<div class="card soar-card">' +
    '<div class="section-label">Start from an example or JSON</div>' +
    '<p class="muted" style="margin:0 0 8px 0;">Or use <b>New playbook</b> at the top to build one by clicking, no JSON needed.</p>' +
    '<div class="soar-subhead">Built-in examples</div>' +
    '<div class="soar-templates">' + tpl + '</div>' +
    '<div class="soar-subhead">Or paste one (JSON)</div>' +
    '<p class="muted" style="margin:0 0 8px 0;">A playbook is a trigger, optional conditions and ' +
      'ordered steps. Steps can use <span class="mono">{{ finding.source_ip }}</span> and results ' +
      'saved by earlier steps. Response steps always wait for approval.</p>' +
    '<textarea id="playbook-json-input" rows="14" class="textarea-mono" placeholder="' +
      escapeHtml(example) + '"></textarea>' +
    '<div id="playbook-import-feedback" class="sigma-feedback muted" style="margin-top:8px; min-height:1.2em;"></div>' +
    '<div style="display:flex; gap:8px; margin-top:8px;">' +
      '<button class="btn btn-secondary" data-action="validatePlaybook">Check</button>' +
      '<button class="btn btn-primary" data-action="importPlaybook">Import</button>' +
    '</div>' +
  '</div>';
}

function _connectorsHtml() {
  var rows = _data.connectors.map(function (c) {
    var toggle = _isAdmin
      ? '<button class="rule-toggle' + (c.enabled ? ' on' : ' off') + '" role="switch" aria-pressed="' +
          (c.enabled ? 'true' : 'false') + '" data-action="toggleConnector" data-arg="' + escapeHtml(c.key) + '">' +
          '<span class="rule-toggle-track"><span class="rule-toggle-thumb"></span></span>' +
          '<span class="rule-toggle-label">' + (c.enabled ? 'On' : 'Off') + '</span></button>'
      : '<span class="muted">' + (c.enabled ? 'On' : 'Off') + '</span>';
    return '<tr>' +
      '<td><div class="rule-name">' + escapeHtml(c.name) + '</div>' +
        '<div class="rule-subline muted mono">' + escapeHtml(c.actions.join(', ')) + '</div></td>' +
      '<td>' + (c.kind === 'response' ? 'Response (needs approval)' : 'Lookup') + '</td>' +
      '<td>' + (c.configured ? '<span class="soar-pill soar-ok">Set up</span>'
                             : '<span class="soar-pill soar-muted">Not set up</span>') + '</td>' +
      '<td class="col-actions">' + toggle + '</td>' +
    '</tr>';
  }).join('');
  return '<div class="card soar-card"><div class="section-label">Connectors</div>' +
    '<p class="muted" style="margin:0 0 8px 0;">API keys and webhooks are set under ' +
      '<a href="#" data-action="navigate" data-arg="settings:notifications" class="link">Settings</a>. ' +
      'Switch a connector off to stop every playbook in your organization from using it.</p>' +
    '<div style="overflow-x:auto;"><table class="data-table soar-table">' +
      '<thead><tr><th>Connector</th><th>Kind</th><th>Status</th><th>Enabled</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div></div>';
}

// ---------------------------------------------------------------
// Actions
// ---------------------------------------------------------------

async function _refresh() {
  if (!document.getElementById('automations-page')) return;
  try { await _load(); _render(); } catch (e) { /* keep what's on screen */ }
}

document.addEventListener('pulse:playbook-run-updated', _refresh);
// The builder saved a playbook.
document.addEventListener('pulse:playbooks-changed', _refresh);

export function toggleRunDetail(runId) {
  runId = Number(runId);
  _openRunId = _openRunId === runId ? null : runId;
  _render();
}

function _setFeedback(html, kind) {
  var el = document.getElementById('playbook-import-feedback');
  if (!el) return;
  el.className = 'sigma-feedback ' + (kind || 'muted');
  el.innerHTML = html || '';
}

function _errorHtml(body) {
  var d = body && body.detail;
  if (d && d.errors) {
    return escapeHtml(d.message) + '<ul class="soar-errors">' +
      d.errors.map(function (e) { return '<li>' + escapeHtml(e) + '</li>'; }).join('') + '</ul>';
  }
  return escapeHtml((d && d.message) || d || 'Something went wrong.');
}

async function _postPlaybook(url) {
  var ta = document.getElementById('playbook-json-input');
  var text = ta ? ta.value : '';
  if (!text.trim()) { _setFeedback('Paste a playbook first.', 'warn'); return null; }
  var resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ json: text }),
  });
  var body = await resp.json().catch(function () { return {}; });
  if (!resp.ok) { _setFeedback(_errorHtml(body), 'error'); return null; }
  return body;
}

export async function validatePlaybook() {
  var body = await _postPlaybook('/api/playbooks/validate');
  if (body) {
    _setFeedback('Looks good: ' + escapeHtml(body.name) + ' (' + body.steps + ' steps, ' +
                 body.approval_steps + ' need approval).', 'ok');
  }
}

export async function importPlaybook() {
  var body = await _postPlaybook('/api/playbooks');
  if (!body) return;
  showToast('Playbook imported: ' + body.name);
  await _refresh();
}

export async function addPlaybookTemplate(key) {
  var resp = await fetch('/api/playbooks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ template: key }),
  });
  var body = await resp.json().catch(function () { return {}; });
  if (!resp.ok) { toastError(body.detail || 'Could not add it.'); return; }
  showToast('Added: ' + body.name);
  await _refresh();
}

export async function togglePlaybook(id) {
  var p = _data.playbooks.find(function (x) { return x.id === Number(id); });
  if (!p) return;
  var resp = await fetch('/api/playbooks/' + Number(id) + '/enabled', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled: !p.enabled }),
  });
  if (!resp.ok) { toastError('Could not change it.'); return; }
  await _refresh();
}

export async function deletePlaybook(id) {
  var p = _data.playbooks.find(function (x) { return x.id === Number(id); });
  if (!window.confirm('Delete "' + (p ? p.name : 'this playbook') + '"? Its past runs stay in the log.')) return;
  var resp = await fetch('/api/playbooks/' + Number(id), { method: 'DELETE' });
  if (!resp.ok) { toastError('Could not delete it.'); return; }
  showToast('Playbook deleted.');
  await _refresh();
}

export async function toggleConnector(key) {
  var c = _data.connectors.find(function (x) { return x.key === key; });
  if (!c) return;
  var resp = await fetch('/api/connectors/' + encodeURIComponent(key), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled: !c.enabled }),
  });
  if (!resp.ok) { toastError('Could not change it.'); return; }
  await _refresh();
}
