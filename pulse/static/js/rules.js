// rules.js — Rules page.
// Two tabs: the Rules table with per-rule performance stats (24h hits
// sparkline, last fired, FP rate) and a MITRE ATT&CK Coverage matrix
// showing tactics × techniques with cell intensity = number of enabled
// rules. Blueprint priority 4.
'use strict';

import { escapeHtml, showToast, toastError, mitreMap } from './dashboard.js';

var _rulesCache = [];
var _activeTab  = 'rules';          // 'rules' | 'coverage'
var _activeTechniqueFilter = null;  // e.g. "T1110" to restrict the Rules table

// Technique -> tactic mapping for the techniques Pulse rules reference.
// MITRE ATT&CK links each technique to one-or-more tactics; we pick the
// single most load-bearing tactic for the matrix so each rule lands in
// exactly one column. Kept here because the rules metadata itself only
// stores the technique ID.
var _techniqueTactic = {
  'T1110':     'Credential Access',
  'T1136.001': 'Persistence',
  'T1078':     'Persistence',
  'T1078.002': 'Privilege Escalation',
  'T1070.001': 'Defense Evasion',
  'T1021.001': 'Lateral Movement',
  'T1021.002': 'Lateral Movement',
  'T1550.002': 'Lateral Movement',
  'T1543.003': 'Persistence',
  'T1053.005': 'Execution',
  'T1059.001': 'Execution',
  'T1562.001': 'Defense Evasion',
  'T1562.004': 'Defense Evasion',
  'T1558.001': 'Credential Access',
  'T1558.003': 'Credential Access',
  'T1003.001': 'Credential Access',
  'T1547.001': 'Persistence',
};

var _tacticOrder = [
  'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command and Control', 'Exfiltration', 'Impact',
];

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

function _mitreChips(mitre) {
  if (!mitre) return '<span class="muted">—</span>';
  var items = Array.isArray(mitre) ? mitre : [mitre];
  var visible = items.slice(0, 2);
  var rest = items.length - visible.length;
  var html = visible.map(function (m) {
    return '<span class="mitre-chip mono">' + escapeHtml(m) + '</span>';
  }).join('');
  if (rest > 0) html += '<span class="mitre-chip more">+' + rest + '</span>';
  return html;
}

function _sparkline(values, color) {
  if (!values || !values.length) return '<span class="muted">—</span>';
  var max = 0;
  for (var i = 0; i < values.length; i++) if (values[i] > max) max = values[i];
  if (max <= 0) return '<span class="spark-empty">flat</span>';
  var w = 96, h = 22, step = w / (values.length - 1 || 1);
  var pts = values.map(function (v, idx) {
    var x = idx * step;
    var y = h - (v / max) * (h - 2) - 1;
    return x.toFixed(1) + ',' + y.toFixed(1);
  }).join(' ');
  return '<svg class="rule-spark" width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '" aria-hidden="true">' +
           '<polyline points="' + pts + '" fill="none" stroke="' + color + '" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" />' +
         '</svg>';
}

function _relativeTime(iso) {
  if (!iso) return '<span class="muted">never</span>';
  var t;
  try { t = new Date(String(iso).replace(' ', 'T')); }
  catch (e) { return '<span class="muted">—</span>'; }
  if (isNaN(t)) return '<span class="muted">—</span>';
  var diffSec = Math.floor((Date.now() - t.getTime()) / 1000);
  if (diffSec < 60)   return '<span title="' + escapeHtml(iso) + '">' + diffSec + 's ago</span>';
  if (diffSec < 3600) return '<span title="' + escapeHtml(iso) + '">' + Math.floor(diffSec / 60) + 'm ago</span>';
  if (diffSec < 86400) return '<span title="' + escapeHtml(iso) + '">' + Math.floor(diffSec / 3600) + 'h ago</span>';
  return '<span title="' + escapeHtml(iso) + '">' + Math.floor(diffSec / 86400) + 'd ago</span>';
}

function _fpRate(fp, total) {
  if (!total) return '<span class="muted">—</span>';
  var pct = Math.round((fp / total) * 100);
  var cls = pct > 30 ? 'fp-hot' : (pct > 10 ? 'fp-warm' : 'fp-cold');
  return '<span class="fp-rate ' + cls + '">' + pct + '%</span>';
}

function _filteredRules() {
  if (!_activeTechniqueFilter) return _rulesCache;
  var needle = _activeTechniqueFilter;
  return _rulesCache.filter(function (r) {
    if (!r.mitre) return false;
    var items = Array.isArray(r.mitre) ? r.mitre : [r.mitre];
    return items.indexOf(needle) >= 0;
  });
}

function _severityTone(sev) {
  var s = (sev || '').toLowerCase();
  if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low' || s === 'info') return s;
  return 'info';
}

function _renderTable() {
  var body = document.getElementById('rules-tbody');
  if (!body) return;
  var rows = _filteredRules();
  if (rows.length === 0) {
    var msg = _activeTechniqueFilter
      ? 'No rules reference ' + escapeHtml(_activeTechniqueFilter) + '.'
      : 'No rules loaded.';
    body.innerHTML = '<tr><td colspan="8"><div class="dash-empty-note">' + msg + '</div></td></tr>';
    return;
  }
  body.innerHTML = rows.map(function (r) {
    var tone = _severityTone(r.severity);
    var toggleCls = 'rule-toggle' + (r.enabled ? ' on' : ' off');
    var ariaPressed = r.enabled ? 'true' : 'false';
    var sparkColor = 'var(--severity-' + tone + ')';
    var spark = _sparkline(r.spark_24h || [], sparkColor);
    var total = (r.fp_count || 0) + (r.tp_count || 0);
    return '<tr class="rule-row sev-edge-' + tone + (r.enabled ? '' : ' rule-row-disabled') + '">' +
      '<td class="rule-name-cell"><div class="rule-name">' + escapeHtml(r.name) + '</div>' +
        '<div class="rule-subline mono">ID ' + _fmtEventId(r.event_id) + '</div></td>' +
      '<td><span class="pill pill-' + tone + '">' + escapeHtml(r.severity || 'LOW') + '</span></td>' +
      '<td class="mitre-cell">' + _mitreChips(r.mitre) + '</td>' +
      '<td class="hits-cell"><div class="hits-row"><span class="hits-num">' + (r.hits_24h || 0) + '</span>' + spark + '</div>' +
        '<div class="hits-sub muted">24h • ' + (r.hits_total || 0) + ' total</div></td>' +
      '<td class="last-fired-cell">' + _relativeTime(r.last_fired) + '</td>' +
      '<td class="fp-cell">' + _fpRate(r.fp_count || 0, total) + '</td>' +
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
    _updateHeaderCount();
    showToast(name + ' ' + (newEnabled ? 'enabled' : 'disabled') + '.');
  } catch (e) {
    toastError('Could not update rule: ' + e.message);
  }
}

function _updateHeaderCount() {
  var span = document.getElementById('rules-enabled-count');
  if (!span) return;
  var enabledCount = _rulesCache.filter(function (r) { return r.enabled; }).length;
  span.textContent = enabledCount + ' of ' + _rulesCache.length + ' enabled';
}

// -----------------------------------------------------------------
// MITRE Coverage matrix — groups rules by (inferred) tactic and lists
// the techniques inside. Cell intensity = enabled-rule count for that
// technique; click a cell to filter the Rules tab to it.
// -----------------------------------------------------------------
function _buildCoverage() {
  // { tactic: { technique: {enabled, total, rules: []} } }
  var grid = {};
  _rulesCache.forEach(function (r) {
    if (!r.mitre) return;
    var items = Array.isArray(r.mitre) ? r.mitre : [r.mitre];
    items.forEach(function (tid) {
      var tactic = _techniqueTactic[tid] || 'Other';
      if (!grid[tactic]) grid[tactic] = {};
      if (!grid[tactic][tid]) grid[tactic][tid] = { enabled: 0, total: 0, rules: [] };
      grid[tactic][tid].total += 1;
      if (r.enabled) grid[tactic][tid].enabled += 1;
      grid[tactic][tid].rules.push(r.name);
    });
  });
  return grid;
}

function _coverageHtml() {
  var grid = _buildCoverage();
  var tacticsPresent = _tacticOrder.filter(function (t) { return grid[t]; });
  if (grid['Other']) tacticsPresent.push('Other');
  if (tacticsPresent.length === 0) {
    return '<div class="dash-empty-note">No MITRE-tagged rules loaded.</div>';
  }
  var cols = tacticsPresent.map(function (tactic) {
    var techs = grid[tactic];
    var techIds = Object.keys(techs).sort();
    var cells = techIds.map(function (tid) {
      var cell = techs[tid];
      var intensity = cell.enabled === 0 ? 0 : Math.min(4, Math.ceil(cell.enabled));
      var url = 'https://attack.mitre.org/techniques/' + tid.replace('.', '/') + '/';
      var title = cell.enabled + ' of ' + cell.total + ' rules enabled — ' + cell.rules.join(', ');
      return '<div class="mc-cell mc-i' + intensity + '" data-action="filterByTechnique" data-arg="' + escapeHtml(tid) + '" title="' + escapeHtml(title) + '">' +
               '<div class="mc-tid mono">' + escapeHtml(tid) + '</div>' +
               '<div class="mc-count">' + cell.enabled + '/' + cell.total + '</div>' +
               '<a class="mc-external" href="' + escapeHtml(url) + '" target="_blank" rel="noopener" data-default="allow" aria-label="Open ' + escapeHtml(tid) + ' on MITRE">↗</a>' +
             '</div>';
    }).join('');
    return '<div class="mc-col">' +
             '<div class="mc-col-head">' + escapeHtml(tactic) + '</div>' +
             '<div class="mc-col-cells">' + cells + '</div>' +
           '</div>';
  }).join('');
  return '<div class="mitre-coverage">' + cols + '</div>';
}

export function filterByTechnique(tid) {
  _activeTechniqueFilter = tid;
  _activeTab = 'rules';
  _renderPage();
}

function _clearTechniqueFilter() {
  _activeTechniqueFilter = null;
  _renderPage();
}

export function rulesShowTab(tab) {
  _activeTab = (tab === 'coverage') ? 'coverage' : 'rules';
  _renderPage();
}

export function rulesClearFilter() { _clearTechniqueFilter(); }

function _renderPage() {
  var c = document.getElementById('content');
  if (!c) return;
  var enabledCount = _rulesCache.filter(function (r) { return r.enabled; }).length;
  var tabRulesCls = 'rules-tab' + (_activeTab === 'rules' ? ' active' : '');
  var tabCovCls   = 'rules-tab' + (_activeTab === 'coverage' ? ' active' : '');
  var filterBanner = '';
  if (_activeTab === 'rules' && _activeTechniqueFilter) {
    filterBanner = '<div class="rules-filter-banner">' +
                     'Showing rules for <span class="mono">' + escapeHtml(_activeTechniqueFilter) + '</span>. ' +
                     '<a data-action="rulesClearFilter" class="link">Clear</a>' +
                   '</div>';
  }
  var body;
  if (_activeTab === 'coverage') {
    body = _coverageHtml();
  } else {
    body =
      '<div style="overflow-x:auto;">' +
        '<table class="data-table rules-table">' +
          '<thead><tr>' +
            '<th>Rule</th>' +
            '<th>Severity</th>' +
            '<th>MITRE ATT&amp;CK</th>' +
            '<th>Hits (24h)</th>' +
            '<th>Last fired</th>' +
            '<th>FP rate</th>' +
            '<th>Status</th>' +
          '</tr></thead>' +
          '<tbody id="rules-tbody"></tbody>' +
        '</table>' +
      '</div>';
  }
  c.innerHTML =
    '<div class="card">' +
      '<div class="section-label" style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">' +
        '<span>Detection Rules <span id="rules-enabled-count" style="color:var(--text-muted); font-weight:400; margin-left:8px; font-size:11px;">' +
          enabledCount + ' of ' + _rulesCache.length + ' enabled' +
        '</span></span>' +
        '<div class="rules-tabs">' +
          '<button class="' + tabRulesCls + '" data-action="rulesShowTab" data-arg="rules">Rules</button>' +
          '<button class="' + tabCovCls + '" data-action="rulesShowTab" data-arg="coverage">MITRE Coverage</button>' +
        '</div>' +
      '</div>' +
      filterBanner +
      body +
    '</div>';
  if (_activeTab === 'rules') _renderTable();
  void mitreMap;
}

export async function renderRulesPage() {
  var c = document.getElementById('content');
  c.innerHTML = '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading rules…</div>';

  try {
    _rulesCache = await _fetchRules();
  } catch (e) {
    c.innerHTML = '<div class="card"><div class="dash-empty-note">' + escapeHtml(e.message) + '</div></div>';
    return;
  }
  _renderPage();
}
