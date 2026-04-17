// rules.js — Rules page. Lists every detection rule with its event
// ID, severity, MITRE technique, and an enable/disable toggle that
// writes to pulse.yaml via the API.
'use strict';

import { escapeHtml, showToast, toastError, mitreMap } from './dashboard.js';

var _rulesCache = [];

async function _fetchRules() {
  var resp = await fetch('/api/rules/details');
  if (!resp.ok) throw new Error('Failed to load rules: HTTP ' + resp.status);
  var body = await resp.json();
  return body.rules || [];
}

function _fmtEventId(eid) {
  if (eid == null) return '<span class="muted">chain</span>';
  if (Array.isArray(eid)) return eid.join(', ');
  return String(eid);
}

function _mitreLink(mitre) {
  if (!mitre) return '<span class="muted">\u2014</span>';
  var url = 'https://attack.mitre.org/techniques/' + mitre.replace('.', '/') + '/';
  return '<a href="' + escapeHtml(url) + '" target="_blank" rel="noopener" ' +
         'data-default="allow" class="mono">' + escapeHtml(mitre) + '</a>';
}

function _renderTable() {
  var body = document.getElementById('rules-tbody');
  if (!body) return;
  if (_rulesCache.length === 0) {
    body.innerHTML = '<tr><td colspan="5"><div class="dash-empty-note">No rules loaded.</div></td></tr>';
    return;
  }
  body.innerHTML = _rulesCache.map(function (r) {
    var sevCls = 'pill-' + (r.severity || 'low').toLowerCase();
    var toggleCls = 'rule-toggle' + (r.enabled ? ' on' : ' off');
    var ariaPressed = r.enabled ? 'true' : 'false';
    return '<tr class="' + (r.enabled ? '' : 'rule-row-disabled') + '">' +
      '<td style="font-weight:500;">' + escapeHtml(r.name) + '</td>' +
      '<td class="mono">' + _fmtEventId(r.event_id) + '</td>' +
      '<td><span class="pill ' + sevCls + '">' + escapeHtml(r.severity || 'LOW') + '</span></td>' +
      '<td>' + _mitreLink(r.mitre) + '</td>' +
      '<td class="col-actions">' +
        '<button class="' + toggleCls + '" role="switch" aria-pressed="' + ariaPressed + '" ' +
          'data-action="toggleRuleEnabled" data-arg="' + escapeHtml(r.name) + '">' +
          '<span class="rule-toggle-track"><span class="rule-toggle-thumb"></span></span>' +
          '<span class="rule-toggle-label">' + (r.enabled ? 'Enabled' : 'Disabled') + '</span>' +
        '</button>' +
      '</td>' +
    '</tr>';
  }).join('');
}

export async function toggleRuleEnabled(name) {
  if (!name) return;
  var row = _rulesCache.find(function (r) { return r.name === name; });
  if (!row) return;
  var newEnabled = !row.enabled;
  try {
    var resp = await fetch('/api/rules/' + encodeURIComponent(name) + '/enabled', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: newEnabled }),
    });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    row.enabled = newEnabled;
    _renderTable();
    showToast(name + ' ' + (newEnabled ? 'enabled' : 'disabled') + '.');
  } catch (e) {
    toastError('Could not update rule: ' + e.message);
  }
}

export async function renderRulesPage() {
  var c = document.getElementById('content');
  c.innerHTML = '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading rules\u2026</div>';

  try {
    _rulesCache = await _fetchRules();
  } catch (e) {
    c.innerHTML = '<div class="card"><div class="dash-empty-note">' + escapeHtml(e.message) + '</div></div>';
    return;
  }

  var enabledCount = _rulesCache.filter(function (r) { return r.enabled; }).length;

  c.innerHTML =
    '<div class="card">' +
      '<div class="section-label" style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">' +
        '<span>Detection Rules <span style="color:var(--text-muted); font-weight:400; margin-left:8px; font-size:11px;">' +
          enabledCount + ' of ' + _rulesCache.length + ' enabled' +
        '</span></span>' +
        '<span style="font-size:11px; color:var(--text-muted);">Disabled rules are skipped during every scan (CLI and dashboard).</span>' +
      '</div>' +
      '<div style="overflow-x:auto;">' +
        '<table class="data-table rules-table">' +
          '<thead><tr>' +
            '<th>Rule Name</th>' +
            '<th>Event ID</th>' +
            '<th>Severity</th>' +
            '<th>MITRE ATT&amp;CK</th>' +
            '<th>Status</th>' +
          '</tr></thead>' +
          '<tbody id="rules-tbody"></tbody>' +
        '</table>' +
      '</div>' +
    '</div>';

  _renderTable();

  // Quiet a linter about the unused import — keeping the symbol live
  // because future enhancements may show category icons driven by it.
  void mitreMap;
}
