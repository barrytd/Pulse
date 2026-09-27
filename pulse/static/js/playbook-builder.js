// playbook-builder.js — click-together playbook builder (Automations page).
//
// Lets a non-coder build a playbook without touching JSON: pick the
// trigger, add condition rows from a fixed safe set, and add ordered
// steps (connector + action + inputs, with a picker for values like the
// finding's source IP or an earlier step's result).
//
// It saves exactly the JSON recipe the engine already runs. The
// vocabulary (condition kinds, connectors, inputs, placeholders) comes
// from GET /api/playbooks/builder, and every save goes through the same
// server validation as a pasted playbook, so the builder can't produce
// anything the engine wouldn't accept. Response steps always need
// approval: shown here as a fixed badge, enforced by the server on save.
//
// State lives in `_b`; the builder repaints only its own mount
// (#pb-builder-mount), and text fields update state without repainting,
// so typing never loses focus.
'use strict';

import { escapeHtml, showToast } from './dashboard.js';

var _schema = null;
var _b = null;

// ---------------------------------------------------------------
// Schema helpers
// ---------------------------------------------------------------

async function _loadSchema() {
  if (_schema) return _schema;
  var r = await fetch('/api/playbooks/builder');
  if (!r.ok) throw new Error('HTTP ' + r.status);
  _schema = await r.json();
  return _schema;
}

function _kind(key) {
  return (_schema.condition_kinds || []).find(function (k) { return k.key === key; });
}

function _connector(key) {
  return (_schema.connectors || []).find(function (c) { return c.key === key; });
}

function _action(connKey, actionKey) {
  var c = _connector(connKey);
  return c && (c.actions || []).find(function (a) { return a.key === actionKey; });
}

function _defaultValue(kind) {
  var v = kind.value || {};
  if (v.type === 'choice') return v.default || (v.options || [])[0] || '';
  if (v.type === 'multi') return [];
  if (v.type === 'fixed') return v.value;
  return '';
}

// A save_as name for a new step's results: the connector key, made unique.
function _saveAsFor(connKey, steps, skip) {
  var base = connKey.replace(/[^A-Za-z0-9_]/g, '_');
  var used = {};
  steps.forEach(function (s, i) { if (i !== skip && s.save_as) used[s.save_as] = true; });
  if (!used[base]) return base;
  for (var n = 2; ; n++) if (!used[base + '_' + n]) return base + '_' + n;
}

function _newStep(connKey, steps) {
  var c = _connector(connKey) ||
    _schema.connectors.find(function (x) { return x.kind === 'enrichment'; }) || _schema.connectors[0];
  var a = c.actions[0];
  var step = { connector: c.key, action: a.key, with: {}, save_as: null };
  a.inputs.forEach(function (inp) {
    // Sensible default: an IP input starts as the finding's source IP.
    if (inp.name === 'ip') step.with.ip = '{{ finding.source_ip }}';
  });
  if (c.kind !== 'response') step.save_as = _saveAsFor(c.key, steps.concat([step]), steps.length);
  return step;
}

// ---------------------------------------------------------------
// Recipe <-> builder state
// ---------------------------------------------------------------

function _toRecipe() {
  var recipe = {
    name: (_b.name || '').trim(),
    enabled: !!_b.enabled,
    trigger: { on: 'finding_created' },
    match: _b.match,
    conditions: _b.conditions.map(function (row) {
      var k = _kind(row.kind);
      return { field: k.field, op: k.op, value: row.value };
    }),
    steps: _b.steps.map(function (s) {
      var c = _connector(s.connector);
      var out = { connector: s.connector, action: s.action, with: {} };
      Object.keys(s.with || {}).forEach(function (k) {
        var v = s.with[k];
        if (v != null && String(v).trim() !== '') out.with[k] = String(v);
      });
      if (s.save_as) out.save_as = s.save_as;
      if (s.label) out.label = s.label;
      if (c && c.kind === 'response') out.requires_approval = true;
      return out;
    }),
  };
  if ((_b.description || '').trim()) recipe.description = _b.description.trim();
  return recipe;
}

// Existing playbook -> builder state, or null when it uses something the
// builder can't show (an `if` block, or a condition outside the safe set).
function _fromRecipe(id, recipe) {
  var conditions = [];
  var ok = (recipe.conditions || []).every(function (c) {
    var k = (_schema.condition_kinds || []).find(function (kind) {
      return kind.field === c.field && kind.op === c.op &&
        (kind.value.type !== 'fixed' || kind.value.value === c.value);
    });
    if (!k) return false;
    conditions.push({ kind: k.key, value: c.value });
    return true;
  });
  if (!ok) return null;
  var steps = [];
  ok = (recipe.steps || []).every(function (s) {
    if (s['if'] || !_action(s.connector, s.action)) return false;
    steps.push({ connector: s.connector, action: s.action, with: Object.assign({}, s['with'] || {}),
                 save_as: s.save_as || null, label: s.label || null });
    return true;
  });
  if (!ok) return null;
  return { id: id, name: recipe.name || '', description: recipe.description || '',
           enabled: recipe.enabled !== false, match: recipe.match === 'any' ? 'any' : 'all',
           conditions: conditions, steps: steps, errors: [], notice: '' };
}

// ---------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------

export function builderHtml() {
  return '<div id="pb-builder-mount">' + (_b ? _formHtml() : '') + '</div>';
}

function _paint() {
  var mount = document.getElementById('pb-builder-mount');
  if (mount) mount.innerHTML = _b ? _formHtml() : '';
}

function _errorRows() {
  // Server / client errors name rows as "Condition 2" or "Step 3".
  var marks = { cond: {}, step: {} };
  (_b.errors || []).forEach(function (e) {
    var m;
    if ((m = /^Condition (\d+)/.exec(e))) marks.cond[Number(m[1]) - 1] = true;
    if ((m = /^Step (\d+)/.exec(e))) marks.step[Number(m[1]) - 1] = true;
  });
  return marks;
}

function _conditionRowHtml(row, i, marks) {
  var k = _kind(row.kind);
  var kinds = _schema.condition_kinds.map(function (kind) {
    return '<option value="' + escapeHtml(kind.key) + '"' + (kind.key === row.kind ? ' selected' : '') + '>' +
      escapeHtml(kind.label) + '</option>';
  }).join('');
  var v = k.value || {}, control = '';
  if (v.type === 'choice') {
    control = '<select class="pb-input" aria-label="Value" data-action-change="builderCondValue" data-arg="' + i + '">' +
      v.options.map(function (o) {
        return '<option' + (o === row.value ? ' selected' : '') + '>' + escapeHtml(o) + '</option>';
      }).join('') + '</select>';
  } else if (v.type === 'multi') {
    var chosen = Array.isArray(row.value) ? row.value : [];
    control = '<select class="pb-input pb-multi" multiple size="' + Math.min(6, v.options.length) + '" ' +
      'aria-label="Values (hold Ctrl or Shift to pick several)" data-action-change="builderCondValue" data-arg="' + i + '">' +
      v.options.map(function (o) {
        return '<option' + (chosen.indexOf(o) >= 0 ? ' selected' : '') + '>' + escapeHtml(o) + '</option>';
      }).join('') + '</select>' +
      '<div class="pb-hint">' + (chosen.length ? chosen.length + ' selected' : 'Pick one or more (Ctrl or Shift to select several)') + '</div>';
  } else if (v.type === 'text') {
    control = '<input class="pb-input" type="text" aria-label="Value" value="' + escapeHtml(row.value || '') + '" ' +
      'data-action-input="builderCondValue" data-arg="' + i + '"/>';
  }
  return '<div class="pb-row' + (marks.cond[i] ? ' pb-row-error' : '') + '">' +
    '<select class="pb-input pb-kind" aria-label="Condition" data-action-change="builderCondKind" data-arg="' + i + '">' + kinds + '</select>' +
    '<div class="pb-value">' + control + '</div>' +
    '<button class="btn btn-ghost btn-sm" data-action="builderRemoveCondition" data-arg="' + i + '" aria-label="Remove condition">Remove</button>' +
  '</div>';
}

function _placeholderOptions(stepIndex) {
  var html = '<option value="">Insert a value…</option><optgroup label="This finding">' +
    _schema.finding_placeholders.map(function (p) {
      return '<option value="{{ ' + escapeHtml(p.path) + ' }}">' + escapeHtml(p.label) + '</option>';
    }).join('') + '</optgroup>';
  for (var j = 0; j < stepIndex; j++) {
    var s = _b.steps[j], c = _connector(s.connector);
    if (!s.save_as || !c || !(c.result_fields || []).length) continue;
    html += '<optgroup label="Step ' + (j + 1) + ' (' + escapeHtml(c.name) + ') result">' +
      c.result_fields.map(function (f) {
        return '<option value="{{ ' + escapeHtml(s.save_as + '.' + f.key) + ' }}">' + escapeHtml(f.label) + '</option>';
      }).join('') + '</optgroup>';
  }
  return html;
}

function _stepHtml(s, i, marks) {
  var c = _connector(s.connector);
  var a = _action(s.connector, s.action) || c.actions[0];
  var conns = _schema.connectors.map(function (x) {
    return '<option value="' + escapeHtml(x.key) + '"' + (x.key === s.connector ? ' selected' : '') + '>' +
      escapeHtml(x.name) + (x.kind === 'response' ? ' (response)' : '') + '</option>';
  }).join('');
  var actions = c.actions.map(function (x) {
    return '<option value="' + escapeHtml(x.key) + '"' + (x.key === a.key ? ' selected' : '') + '>' + escapeHtml(x.label) + '</option>';
  }).join('');
  var badge = c.requires_approval
    ? '<span class="soar-pill soar-warn" title="Response steps always wait for a manager or admin to approve them.">Response · needs approval</span>'
    : '<span class="soar-pill soar-info">Lookup · runs on its own</span>';
  var inputs = a.inputs.map(function (inp) {
    var id = 'pb-in-' + i + '-' + inp.name;
    var val = (s['with'] || {})[inp.name] || '';
    var field = inp.multiline
      ? '<textarea id="' + id + '" class="pb-input" rows="3" data-action-input="builderStepInput" data-arg="' + i + ':' + escapeHtml(inp.name) + '">' + escapeHtml(val) + '</textarea>'
      : '<input id="' + id + '" class="pb-input" type="text" value="' + escapeHtml(val) + '" data-action-input="builderStepInput" data-arg="' + i + ':' + escapeHtml(inp.name) + '"/>';
    return '<div class="pb-field">' +
      '<label for="' + id + '">' + escapeHtml(inp.label) + (inp.required ? ' <span class="pb-req" title="Required">*</span>' : '') + '</label>' +
      '<div class="pb-field-row">' + field +
        '<select class="pb-input pb-picker" aria-label="Insert a value into ' + escapeHtml(inp.label) + '" ' +
          'data-action-change="builderInsertPlaceholder" data-arg="' + i + ':' + escapeHtml(inp.name) + '">' +
          _placeholderOptions(i) + '</select>' +
      '</div>' +
    '</div>';
  }).join('');
  var n = _b.steps.length;
  return '<div class="pb-step' + (marks.step[i] ? ' pb-row-error' : '') + '">' +
    '<div class="pb-step-head">' +
      '<span class="pb-step-num">Step ' + (i + 1) + '</span>' + badge +
      '<span class="pb-step-tools">' +
        '<button class="btn btn-ghost btn-sm" data-action="builderMoveStep" data-arg="' + i + ':-1"' + (i === 0 ? ' disabled' : '') + ' aria-label="Move step up">Up</button>' +
        '<button class="btn btn-ghost btn-sm" data-action="builderMoveStep" data-arg="' + i + ':1"' + (i === n - 1 ? ' disabled' : '') + ' aria-label="Move step down">Down</button>' +
        '<button class="btn btn-ghost btn-sm" data-action="builderRemoveStep" data-arg="' + i + '">Remove</button>' +
      '</span>' +
    '</div>' +
    '<div class="pb-row">' +
      '<select class="pb-input" aria-label="Connector" data-action-change="builderStepConnector" data-arg="' + i + '">' + conns + '</select>' +
      '<select class="pb-input" aria-label="Action" data-action-change="builderStepAction" data-arg="' + i + '">' + actions + '</select>' +
    '</div>' +
    inputs +
    (s.save_as && (c.result_fields || []).length
      ? '<div class="pb-hint">Later steps can use this step’s result (for example ' +
        '<span class="mono">{{ ' + escapeHtml(s.save_as + '.' + c.result_fields[0].key) + ' }}</span>).</div>'
      : '') +
  '</div>';
}

function _formHtml() {
  var marks = _errorRows();
  var editing = _b.id != null;
  return '<div class="card soar-card pb-card" id="pb-builder">' +
    '<div class="section-label">' + (editing ? 'Edit playbook' : 'Build a playbook') + '</div>' +
    '<div class="pb-grid">' +
      '<label for="pb-name">Name</label>' +
      '<input id="pb-name" class="pb-input" type="text" maxlength="' + _schema.limits.max_name + '" value="' + escapeHtml(_b.name) + '" ' +
        'placeholder="e.g. Look up attackers on critical findings" data-action-input="builderSet" data-arg="name"/>' +
      '<label for="pb-desc">Description</label>' +
      '<input id="pb-desc" class="pb-input" type="text" value="' + escapeHtml(_b.description) + '" ' +
        'placeholder="Optional: what this playbook is for" data-action-input="builderSet" data-arg="description"/>' +
      '<label for="pb-trigger">Trigger</label>' +
      '<select id="pb-trigger" class="pb-input">' + _schema.triggers.map(function (t) {
        return '<option value="' + escapeHtml(t.key) + '">' + escapeHtml(t.label) + '</option>';
      }).join('') + '</select>' +
    '</div>' +

    '<div class="pb-section">' +
      '<div class="pb-section-head">Run only when ' +
        '<select class="pb-input pb-inline" aria-label="Match all or any" data-action-change="builderSet" data-arg="match">' +
          '<option value="all"' + (_b.match === 'all' ? ' selected' : '') + '>all</option>' +
          '<option value="any"' + (_b.match === 'any' ? ' selected' : '') + '>any</option>' +
        '</select> of these are true</div>' +
      (_b.conditions.length
        ? _b.conditions.map(function (row, i) { return _conditionRowHtml(row, i, marks); }).join('')
        : '<div class="pb-hint">No conditions: this playbook runs on every new finding.</div>') +
      '<button class="btn btn-sm" data-action="builderAddCondition">+ Add condition</button>' +
    '</div>' +

    '<div class="pb-section">' +
      '<div class="pb-section-head">Then do these steps, in order</div>' +
      (_b.steps.length
        ? _b.steps.map(function (s, i) { return _stepHtml(s, i, marks); }).join('')
        : '<div class="pb-hint">Add at least one step. Lookups run on their own; responses wait for approval.</div>') +
      (_b.steps.length < _schema.limits.max_steps
        ? '<button class="btn btn-sm" data-action="builderAddStep">+ Add step</button>' : '') +
    '</div>' +

    '<label class="form-checkbox pb-enable"><input type="checkbox"' + (_b.enabled ? ' checked' : '') +
      ' data-action-change="builderSet" data-arg="enabled"/> Turn this playbook on when it’s saved</label>' +

    (_b.errors.length
      ? '<div class="pb-errors" role="alert"><strong>Fix these before saving:</strong><ul>' +
          _b.errors.map(function (e) { return '<li>' + escapeHtml(e) + '</li>'; }).join('') + '</ul></div>'
      : '') +
    (_b.notice ? '<div class="pb-notice" role="status">' + escapeHtml(_b.notice) + '</div>' : '') +

    '<details class="pb-json"><summary>Show the JSON this saves</summary>' +
      '<pre class="mono" id="pb-json-preview">' + escapeHtml(JSON.stringify(_toRecipe(), null, 2)) + '</pre></details>' +

    '<div class="form-actions">' +
      '<button class="btn btn-secondary" data-action="builderCheck">Check</button>' +
      '<button class="btn btn-primary" data-action="builderSave">' + (editing ? 'Save changes' : 'Save playbook') + '</button>' +
      '<button class="btn btn-ghost" data-action="builderCancel">Cancel</button>' +
    '</div>' +
  '</div>';
}

function _refreshPreview() {
  var pre = document.getElementById('pb-json-preview');
  if (pre) pre.textContent = JSON.stringify(_toRecipe(), null, 2);
}

// ---------------------------------------------------------------
// Validation
// ---------------------------------------------------------------

// Quick checks with friendly wording; the server re-validates everything.
function _clientErrors() {
  var errs = [];
  if (!(_b.name || '').trim()) errs.push('Give the playbook a name.');
  _b.conditions.forEach(function (row, i) {
    var k = _kind(row.kind), t = k.value.type;
    if (t === 'multi' && !(row.value || []).length) errs.push('Condition ' + (i + 1) + ': pick at least one value.');
    if (t === 'text' && !String(row.value || '').trim()) errs.push('Condition ' + (i + 1) + ': enter a value.');
  });
  if (!_b.steps.length) errs.push('Add at least one step.');
  _b.steps.forEach(function (s, i) {
    var a = _action(s.connector, s.action);
    (a ? a.inputs : []).forEach(function (inp) {
      if (inp.required && !String((s['with'] || {})[inp.name] || '').trim()) {
        errs.push('Step ' + (i + 1) + ': “' + inp.label + '” is required.');
      }
    });
  });
  return errs;
}

// "steps[2].with.ip: ..." -> "Step 3 (IP address): ..."; "conditions[0]: ..." -> "Condition 1: ..."
function _friendly(msg) {
  return String(msg)
    .replace(/^steps\[(\d+)\](?:\.with\.(\w+))?:?\s*/, function (_, n, input) {
      return 'Step ' + (Number(n) + 1) + (input ? ' (' + input + ')' : '') + ': ';
    })
    .replace(/^conditions\[(\d+)\]:?\s*/, function (_, n) { return 'Condition ' + (Number(n) + 1) + ': '; });
}

async function _serverCheck(url, method) {
  var resp = await fetch(url, {
    method: method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recipe: _toRecipe() }),
  });
  var body = await resp.json().catch(function () { return {}; });
  if (resp.ok) return { ok: true, body: body };
  var d = body.detail;
  var errs = d && d.errors ? d.errors.map(_friendly) : [(d && d.message) || d || 'The server rejected this playbook.'];
  return { ok: false, errors: errs };
}

// ---------------------------------------------------------------
// Actions (registered in app.js)
// ---------------------------------------------------------------

export async function builderOpen() {
  try { await _loadSchema(); } catch (e) { showToast('Could not load the builder.', 'error'); return; }
  _b = { id: null, name: '', description: '', enabled: true, match: 'all',
         conditions: [{ kind: 'severity_at_least', value: 'HIGH' }], steps: [], errors: [], notice: '' };
  _b.steps.push(_newStep('abuseipdb', _b.steps));
  _paint();
  var el = document.getElementById('pb-builder');
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

export async function editPlaybook(id) {
  try { await _loadSchema(); } catch (e) { showToast('Could not load the builder.', 'error'); return; }
  var r = await fetch('/api/playbooks/' + Number(id));
  if (!r.ok) { showToast('Could not load that playbook.', 'error'); return; }
  var pb = await r.json();
  var state = _fromRecipe(pb.id, pb.recipe || {});
  if (!state) {
    showToast('This playbook uses an “if” block or a condition the builder can’t show yet. Change it as JSON: delete it and import the edited JSON.', 'error');
    return;
  }
  _b = state;
  _paint();
  var el = document.getElementById('pb-builder');
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

export function builderCancel() {
  _b = null;
  _paint();
}

export function builderSet(arg, target) {
  if (!_b) return;
  if (arg === 'enabled') _b.enabled = !!target.checked;
  else if (arg === 'name' || arg === 'description' || arg === 'match') _b[arg] = target.value;
  _refreshPreview();
}

export function builderAddCondition() {
  var k = _schema.condition_kinds[0];
  _b.conditions.push({ kind: k.key, value: _defaultValue(k) });
  _paint();
}

export function builderRemoveCondition(i) {
  _b.conditions.splice(Number(i), 1);
  _paint();
}

export function builderCondKind(i, target) {
  var k = _kind(target.value);
  _b.conditions[Number(i)] = { kind: k.key, value: _defaultValue(k) };
  _paint();
}

export function builderCondValue(i, target) {
  var row = _b.conditions[Number(i)];
  if (target.multiple) {
    row.value = Array.prototype.map.call(target.selectedOptions, function (o) { return o.value; });
    _paint();
  } else {
    row.value = target.value;
    _refreshPreview();
  }
}

export function builderAddStep() {
  _b.steps.push(_newStep('abuseipdb', _b.steps));
  _paint();
}

export function builderRemoveStep(i) {
  _b.steps.splice(Number(i), 1);
  _paint();
}

export function builderMoveStep(arg) {
  var parts = String(arg).split(':'), i = Number(parts[0]), j = i + Number(parts[1]);
  if (j < 0 || j >= _b.steps.length) return;
  var tmp = _b.steps[i];
  _b.steps[i] = _b.steps[j];
  _b.steps[j] = tmp;
  _paint();
}

export function builderStepConnector(i, target) {
  i = Number(i);
  var fresh = _newStep(target.value, _b.steps.slice(0, i).concat(_b.steps.slice(i + 1)));
  _b.steps[i] = fresh;
  _paint();
}

export function builderStepAction(i, target) {
  var s = _b.steps[Number(i)];
  s.action = target.value;
  var a = _action(s.connector, s.action);
  var kept = {};
  a.inputs.forEach(function (inp) { if (s['with'][inp.name] != null) kept[inp.name] = s['with'][inp.name]; });
  s['with'] = kept;
  _paint();
}

export function builderStepInput(arg, target) {
  var parts = String(arg).split(':');
  _b.steps[Number(parts[0])]['with'][parts[1]] = target.value;
  _refreshPreview();
}

export function builderInsertPlaceholder(arg, target) {
  var value = target.value;
  target.value = '';
  if (!value) return;
  var parts = String(arg).split(':'), i = Number(parts[0]), name = parts[1];
  var field = document.getElementById('pb-in-' + i + '-' + name);
  var current = _b.steps[i]['with'][name] || '';
  // Appends (the field has lost focus to the picker, so its caret isn't
  // reliable); the user can move the text afterward.
  var next = current ? current + (/\s$/.test(current) ? '' : ' ') + value : value;
  _b.steps[i]['with'][name] = next;
  if (field) { field.value = next; field.focus(); }
  _refreshPreview();
}

export async function builderCheck() {
  _b.notice = '';
  _b.errors = _clientErrors();
  if (!_b.errors.length) {
    var res = await _serverCheck('/api/playbooks/validate', 'POST');
    if (res.ok) {
      _b.notice = 'Looks good: ' + res.body.steps + ' step' + (res.body.steps === 1 ? '' : 's') +
        (res.body.approval_steps ? ', ' + res.body.approval_steps + ' needing approval' : '') + '.';
    } else {
      _b.errors = res.errors;
    }
  }
  _paint();
}

export async function builderSave() {
  _b.notice = '';
  _b.errors = _clientErrors();
  if (_b.errors.length) { _paint(); return; }
  var editing = _b.id != null;
  var res = await _serverCheck(editing ? '/api/playbooks/' + Number(_b.id) : '/api/playbooks',
                               editing ? 'PUT' : 'POST');
  if (!res.ok) { _b.errors = res.errors; _paint(); return; }
  showToast((editing ? 'Saved: ' : 'Playbook created: ') + res.body.name);
  _b = null;
  document.dispatchEvent(new CustomEvent('pulse:playbooks-changed'));
}
