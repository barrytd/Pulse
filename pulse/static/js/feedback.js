// feedback.js — In-app "Send feedback" modal. Replaces the external
// GitHub-issues link so feedback stays inside Pulse and lands in the
// `feedback` table. Admins see submissions via GET /api/feedback.
'use strict';

import { apiSubmitFeedback } from './api.js';
import { showToast, toastError } from './dashboard.js';

// Module-level selected kind. Pills update this via setFeedbackKind.
let _selectedKind = 'bug';

function _modal()    { return document.getElementById('feedback-modal'); }
function _msgEl()    { return document.getElementById('feedback-message'); }
function _statusEl() { return document.getElementById('feedback-status'); }
function _submitBtn(){ return document.getElementById('feedback-submit-btn'); }

function _currentPageHint() {
  // SPA route is the first path segment — "/dashboard", "/monitor/123",
  // etc. Keep it short so the hint stays useful at a glance.
  var path = window.location.pathname || '';
  var trimmed = path.replace(/^\/+|\/+$/g, '');
  return trimmed || 'dashboard';
}

export function openFeedbackModal() {
  var m = _modal();
  if (!m) return;
  var msg = _msgEl();
  if (msg) msg.value = '';
  _setSelectedKind('bug');
  _setStatus('');
  _setCount(0);

  var hint = _currentPageHint();
  var lbl = document.getElementById('feedback-page-hint-label');
  if (lbl) lbl.textContent = '/' + hint;

  m.classList.add('open');
  setTimeout(function () { if (msg) msg.focus(); }, 0);
}

export function closeFeedbackModal() {
  var m = _modal();
  if (m) m.classList.remove('open');
}

// Pill click handler — registered via data-action="setFeedbackKind".
export function setFeedbackKind(kind) {
  _setSelectedKind(kind);
}

function _setSelectedKind(kind) {
  if (kind !== 'bug' && kind !== 'idea' && kind !== 'general') kind = 'bug';
  _selectedKind = kind;
  var pills = document.querySelectorAll('.feedback-type-pill');
  pills.forEach(function (p) {
    var on = (p.getAttribute('data-arg') === kind);
    p.classList.toggle('is-selected', on);
    p.setAttribute('aria-pressed', on ? 'true' : 'false');
  });
}

export async function submitFeedback() {
  var msg = _msgEl();
  var raw = (msg && msg.value || '').trim();
  if (!raw) {
    _setStatus('Write something before sending.', 'error');
    if (msg) msg.focus();
    return;
  }

  var btn = _submitBtn();
  if (btn) { btn.disabled = true; btn.textContent = 'Sending...'; }
  try {
    await apiSubmitFeedback({
      kind: _selectedKind,
      message: raw,
      page_hint: _currentPageHint(),
    });
    closeFeedbackModal();
    showToast('Thanks — feedback sent.');
  } catch (e) {
    _setStatus(String(e && e.message || e), 'error');
    toastError('Feedback failed to send.');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Send Feedback'; }
  }
}

// Wired via the one listener here rather than data-action-input so the
// counter updates without needing an extra registry entry. Keyed off the
// textarea id, no cost when other inputs fire.
document.addEventListener('input', function (e) {
  var t = e.target;
  if (t && t.id === 'feedback-message') {
    _setCount(t.value.length);
  }
});

// Esc closes the feedback modal when it's the frontmost thing.
document.addEventListener('keydown', function (e) {
  if (e.key !== 'Escape') return;
  var m = _modal();
  if (m && m.classList.contains('open')) closeFeedbackModal();
});

function _setStatus(text, kind) {
  var el = _statusEl();
  if (!el) return;
  el.textContent = text || '';
  el.className = 'upload-status' + (kind === 'error' ? ' error' : '');
}

function _setCount(n) {
  var el = document.getElementById('feedback-count');
  if (el) el.textContent = String(n || 0);
}
