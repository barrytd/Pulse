// assign-dialog.js — the assignment dialog.
//
// A manager hands one or more findings to an analyst with a triage
// priority + due date (and an optional context note) in a single step.
// Opened from the finding drawer (single finding) and the Findings bulk
// bar (many). On submit it does ONE batch call (assignee + priority +
// due date) plus, when a note is present, one note per finding.
'use strict';

import { escapeHtml, showToast, toastError } from './dashboard.js';
import { apiFindingsBatch } from './api.js';

// Mirror of the server's SEVERITY_DEFAULT_PRIORITY so "Auto" resolves the
// same way client-side for the default selection. The server is still the
// source of truth — this only drives the pre-selected dropdown value.
var SEV_DEFAULT_PRIORITY = {
  CRITICAL: 'P1', HIGH: 'P2', MEDIUM: 'P3', LOW: 'P4',
};

// Dialog state for the currently open invocation.
var _state = { findingIds: [], severity: null, onDone: null };

// Cache the assignable-users list across opens (it rarely changes).
var _usersCache = null;

async function _loadAssignableUsers() {
  if (_usersCache) return _usersCache;
  var users = [];
  try {
    var r = await fetch('/api/users');
    if (r.ok) {
      var data = await r.json();
      users = (Array.isArray(data) ? data : (data.users || []))
        .filter(function (u) { return u && (u.active === undefined || u.active); });
    }
  } catch (e) { /* fall through to me-only */ }
  // Viewers get 403 on /api/users — fall back to self-assign only.
  if (!users.length) {
    try {
      var rm = await fetch('/api/me');
      if (rm.ok) {
        var me = await rm.json();
        if (me && me.id) {
          users = [{ id: me.id, email: me.email, display_name: me.display_name }];
        }
      }
    } catch (e) { /* ignore */ }
  }
  _usersCache = users;
  return users;
}

function _userLabel(u) {
  var name = (u.display_name || '').trim() || ((u.email || '').split('@')[0]) || ('user #' + u.id);
  var role = u.role ? ' · ' + u.role : '';
  return name + role;
}

function _setStatus(msg, isErr) {
  var el = document.getElementById('assign-status');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'assign-status' + (isErr ? ' assign-status-err' : '');
}

// Open the dialog. opts = { findingIds:[int], severity?:str,
//                           currentAssignee?:int, onDone?:fn }
export async function openAssignDialog(opts) {
  opts = opts || {};
  var ids = (opts.findingIds || []).map(Number).filter(Boolean);
  if (!ids.length) { toastError('No findings selected to assign.'); return; }
  _state = { findingIds: ids, severity: (opts.severity || '').toUpperCase(), onDone: opts.onDone || null };

  var overlay = document.getElementById('assign-modal');
  if (!overlay) return;

  // Header reflects how many findings are being assigned.
  var n = ids.length;
  var plural = document.getElementById('assign-modal-plural');
  if (plural) plural.textContent = (n === 1 ? '' : 's');
  var sub = document.getElementById('assign-modal-sub');
  if (sub) {
    sub.textContent = (n === 1)
      ? 'Hand this finding to an analyst and set its priority.'
      : 'Hand these ' + n + ' findings to an analyst and set their priority.';
  }

  // Populate the assignee dropdown.
  var sel = document.getElementById('assign-assignee');
  if (sel) {
    var users = await _loadAssignableUsers();
    if (!users.length) {
      sel.innerHTML = '<option value="">No assignable users</option>';
    } else {
      sel.innerHTML = users.map(function (u) {
        var selected = (opts.currentAssignee && u.id === opts.currentAssignee) ? ' selected' : '';
        return '<option value="' + u.id + '"' + selected + '>' + escapeHtml(_userLabel(u)) + '</option>';
      }).join('');
    }
  }

  // Default the priority dropdown to "Auto" (resolves from severity), and
  // show the analyst what Auto means via the option label.
  var prioSel = document.getElementById('assign-priority');
  if (prioSel) {
    var auto = SEV_DEFAULT_PRIORITY[_state.severity] || 'P3';
    var autoOpt = prioSel.querySelector('option[value="__auto__"]');
    if (autoOpt) autoOpt.textContent = 'Auto (' + auto + ' from severity)';
    prioSel.value = '__auto__';
  }
  var dueEl = document.getElementById('assign-due');
  if (dueEl) dueEl.value = '';
  var noteEl = document.getElementById('assign-note');
  if (noteEl) noteEl.value = '';
  _setStatus('');

  overlay.classList.add('open');
  if (window.lucide && window.lucide.createIcons) {
    try { window.lucide.createIcons(); } catch (e) {}
  }
  if (sel) sel.focus();
}

export function closeAssignDialog() {
  var overlay = document.getElementById('assign-modal');
  if (overlay) overlay.classList.remove('open');
}

// Resolve the priority dropdown value into what the API expects:
//   '__auto__' -> the severity default (or null if unknown)
//   ''         -> null (explicitly no priority)
//   'P1'..'P4' -> as-is
function _resolvePriority() {
  var prioSel = document.getElementById('assign-priority');
  var v = prioSel ? prioSel.value : '__auto__';
  if (v === '__auto__') return SEV_DEFAULT_PRIORITY[_state.severity] || null;
  if (v === '') return null;
  return v;
}

export async function submitAssignDialog() {
  var ids = _state.findingIds;
  if (!ids.length) { closeAssignDialog(); return; }
  var sel = document.getElementById('assign-assignee');
  var assignee = sel ? Number(sel.value) : 0;
  if (!assignee) { _setStatus('Pick someone to assign to.', true); return; }

  var priority = _resolvePriority();
  var dueEl = document.getElementById('assign-due');
  var due = (dueEl && dueEl.value) ? dueEl.value : null;
  var noteEl = document.getElementById('assign-note');
  var note = (noteEl && noteEl.value || '').trim();

  var btn = document.getElementById('assign-submit-btn');
  if (btn) btn.disabled = true;
  _setStatus('Assigning…');

  try {
    var r = await apiFindingsBatch('assign', ids, assignee,
                                   { priority: priority, due_date: due });
    if (!r || !r.ok) {
      _setStatus((r && r.data && r.data.detail) || 'Assignment failed.', true);
      if (btn) btn.disabled = false;
      return;
    }
    // Optional note: append to each assigned finding so the analyst sees
    // the manager's context in the notes thread. Best-effort — a failed
    // note doesn't undo the assignment.
    if (note) {
      await Promise.all(ids.map(function (fid) {
        return fetch('/api/finding/' + encodeURIComponent(fid) + '/notes', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ body: note }),
        }).catch(function () {});
      }));
    }
    var updated = (r.data && r.data.updated) || ids.length;
    var label = (sel && sel.options[sel.selectedIndex]) ? sel.options[sel.selectedIndex].textContent : 'analyst';
    showToast('Assigned ' + updated + ' finding' + (updated === 1 ? '' : 's') +
              ' to ' + label + (priority ? ' (' + priority + ')' : ''));
    closeAssignDialog();
    if (typeof _state.onDone === 'function') {
      try { _state.onDone({ assignee: assignee, priority: priority, due_date: due, updated: updated }); }
      catch (e) {}
    }
  } catch (e) {
    _setStatus('Assignment failed: ' + (e.message || e), true);
    if (btn) btn.disabled = false;
  }
}

// Close on backdrop click + Esc, matching the other modals.
document.addEventListener('click', function (e) {
  if (e.target && e.target.id === 'assign-modal') closeAssignDialog();
});
document.addEventListener('keydown', function (e) {
  if (e.key !== 'Escape') return;
  var overlay = document.getElementById('assign-modal');
  if (overlay && overlay.classList.contains('open')) closeAssignDialog();
});
