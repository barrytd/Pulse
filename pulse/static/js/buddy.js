// buddy.js — "Pip", the floating Security Buddy chat widget.
//
// Renders a small robot circle in the bottom-right corner. Click it to open
// a chat panel and ask Pip anything — what a finding means, whether
// something looks dangerous, general security questions. Questions are
// answered by Claude Haiku, proxied server-side through /api/buddy/ask (the
// API key never touches the browser). Each user gets a few free questions
// per day; the counter is shown in the panel.
//
// Self-contained on purpose (no app.js imports) — it builds its own DOM and
// wires its own events, so it can't be broken by the page's view-swapping.
// Other modules can attach finding context via window.PulsePip.setContext().
'use strict';

var DAILY_DEFAULT = 3;

// Conversation state for the current panel session.
var _history = [];        // [{role:'user'|'assistant', content}]
var _context = null;      // finding context text sent with questions (or null)
var _contextLabel = null; // short label (rule name) shown in the "Looking at" pill
var _busy = false;
var _questionsLeft = null;
var _available = true;
var _built = false;
var _lastSuggestions = [];

// Persist the conversation across page refreshes so a reload doesn't wipe
// what Pip said (and make you re-ask, wasting a question). Stored per-browser
// in localStorage; forgotten after a day since the daily question count
// resets anyway.
var _STORE_KEY = 'pulsePipChat';
var _STORE_TTL_MS = 24 * 60 * 60 * 1000;

function _saveChat() {
  try {
    localStorage.setItem(_STORE_KEY, JSON.stringify({
      v: 1, ts: Date.now(), history: _history, suggestions: _lastSuggestions,
    }));
  } catch (e) { /* storage full / disabled — chat just won't persist */ }
}

function _restoreChat() {
  var raw;
  try { raw = JSON.parse(localStorage.getItem(_STORE_KEY) || 'null'); } catch (e) { raw = null; }
  if (!raw || !Array.isArray(raw.history) || !raw.history.length) return false;
  if (raw.ts && (Date.now() - raw.ts) > _STORE_TTL_MS) { _clearChat(); return false; }
  _history = raw.history.filter(function (t) {
    return t && (t.role === 'user' || t.role === 'assistant') && typeof t.content === 'string';
  });
  _lastSuggestions = Array.isArray(raw.suggestions) ? raw.suggestions : [];
  return _history.length > 0;
}

function _clearChat() {
  _history = [];
  _lastSuggestions = [];
  try { localStorage.removeItem(_STORE_KEY); } catch (e) {}
}

function _esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

// Pip's mascot — a friendly little robot head. Uses currentColor so it
// inherits whatever color the button/header sets (white on the accent FAB,
// accent-colored in the header).
function _robotSvg(size) {
  var s = size || 26;
  return '' +
    '<svg viewBox="0 0 32 32" width="' + s + '" height="' + s + '" fill="none" ' +
    'stroke="currentColor" stroke-width="2" stroke-linecap="round" ' +
    'stroke-linejoin="round" aria-hidden="true">' +
    '<line x1="16" y1="4" x2="16" y2="8"></line>' +
    '<circle cx="16" cy="3" r="1.4" fill="currentColor" stroke="none"></circle>' +
    '<rect x="6" y="8" width="20" height="16" rx="5"></rect>' +
    '<circle cx="12" cy="16" r="1.7" fill="currentColor" stroke="none"></circle>' +
    '<circle cx="20" cy="16" r="1.7" fill="currentColor" stroke="none"></circle>' +
    '<path d="M13 20.5h6"></path>' +
    '<path d="M6 14H4v4h2"></path>' +
    '<path d="M26 14h2v4h-2"></path>' +
    '</svg>';
}

// Very small, safe formatter: escape everything first, then turn **bold**,
// `code`, bullet lines, and blank-line paragraph breaks into HTML. No raw
// model HTML is ever inserted.
function _formatAnswer(text) {
  var safe = _esc(text);
  safe = safe.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  safe = safe.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Linkify plain URLs (e.g. the GitHub repo) so they're clickable. Runs on
  // already-escaped text; trailing sentence punctuation is left outside.
  safe = safe.replace(/(https?:\/\/[^\s<]+[^\s<.,;:!?)])/g,
    '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>');
  var lines = safe.split('\n');
  var html = '';
  var inList = false;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    var isBullet = /^([-*•]|\d+\.)\s+/.test(line);
    if (isBullet) {
      if (!inList) { html += '<ul>'; inList = true; }
      html += '<li>' + line.replace(/^([-*•]|\d+\.)\s+/, '') + '</li>';
    } else {
      if (inList) { html += '</ul>'; inList = false; }
      if (line) html += '<p>' + line + '</p>';
    }
  }
  if (inList) html += '</ul>';
  return html || '<p>' + safe + '</p>';
}

function _el(id) { return document.getElementById(id); }

function _scrollDown() {
  var log = _el('pip-log');
  if (log) log.scrollTop = log.scrollHeight;
}

// Scroll so the TOP of a given message sits near the top of the log, so the
// user starts reading a long reply from its beginning instead of its end.
function _scrollToMsgTop(el) {
  var log = _el('pip-log');
  if (!log || !el) return;
  var delta = el.getBoundingClientRect().top - log.getBoundingClientRect().top;
  log.scrollTop += delta - 12;   // 12px of breathing room above the message
}

function _renderCounter() {
  var el = _el('pip-counter');
  if (!el) return;
  if (!_available) { el.textContent = 'Pip is offline'; return; }
  if (_questionsLeft == null) { el.textContent = ''; return; }
  var n = _questionsLeft;
  el.textContent = n + ' question' + (n === 1 ? '' : 's') + ' left today';
}

function _appendBubble(role, html, extraClass) {
  var log = _el('pip-log');
  if (!log) return null;
  var wrap = document.createElement('div');
  wrap.className = 'pip-msg pip-msg-' + role + (extraClass ? ' ' + extraClass : '');
  if (role === 'pip') {
    wrap.innerHTML = '<span class="pip-msg-avatar">' + _robotSvg(18) + '</span>' +
      '<div class="pip-bubble">' + html + '</div>';
  } else {
    wrap.innerHTML = '<div class="pip-bubble">' + html + '</div>';
  }
  log.appendChild(wrap);
  _scrollDown();
  return wrap;
}

// Render tappable follow-up chips after Pip's latest message. Replaces any
// previous suggestion row, so they always reflect the most recent answer.
function _renderSuggestions(list) {
  var log = _el('pip-log');
  if (!log) return;
  var existing = log.querySelector('.pip-suggest');
  if (existing) existing.remove();
  if (!list || !list.length) return;
  var row = document.createElement('div');
  row.className = 'pip-suggest';
  var html = '';
  for (var i = 0; i < list.length; i++) {
    var q = String(list[i]);
    html += '<button type="button" class="pip-chip" data-q="' + _esc(q) + '">' + _esc(q) + '</button>';
  }
  row.innerHTML = html;
  log.appendChild(row);
  _scrollDown();
}

// Drop any finding context if the finding drawer isn't actually open right
// now. The single source of truth is the live DOM, not a stale variable, so
// context can never linger after the drawer is closed or the user navigates
// away by any path.
function _syncContextToDrawer() {
  var drawerOpen = !!document.querySelector('#finding-drawer.open');
  if (!drawerOpen) {
    // No finding open — make sure we're not still docked-left or holding a
    // stale "Looking at <finding>" context (e.g. after navigating away).
    var root = document.getElementById('pip-root');
    if (root) root.classList.remove('pip-docked');
    if (_context || _contextLabel) {
      _context = null;
      _contextLabel = null;
      _renderContextBanner();
    }
  }
}

// Show/hide the "Looking at: <finding>" pill so it's always clear when Pip
// has the open finding's details (vs. only knowing what the user typed).
function _renderContextBanner() {
  var el = _el('pip-context');
  if (!el) return;
  if (_context && _contextLabel) {
    el.innerHTML =
      '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" ' +
      'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
      '<path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path></svg>' +
      '<span>Looking at <strong>' + _esc(_contextLabel) + '</strong></span>';
    el.style.display = 'flex';
  } else {
    el.innerHTML = '';
    el.style.display = 'none';
  }
}

// Rebuild the visible chat from saved history (after a refresh).
function _renderTranscript() {
  var log = _el('pip-log');
  if (!log) return;
  log.innerHTML = '';
  for (var i = 0; i < _history.length; i++) {
    var t = _history[i];
    _appendBubble(t.role === 'user' ? 'user' : 'pip', _formatAnswer(t.content));
  }
  _renderSuggestions(_lastSuggestions);
}

function _greeting() {
  var log = _el('pip-log');
  if (log) log.innerHTML = '';
  _appendBubble('pip',
    "<p>Hi, I'm Pip, your security buddy. Ask me what a finding means, " +
    "whether something looks risky, or any security question you've got.</p>");
  // Starter prompts to get going; these get replaced by context-aware
  // follow-ups once Pip answers something.
  _renderSuggestions(['Where do I start?', 'What’s an event log?', 'How do I read a finding?']);
}

async function _refreshStatus() {
  try {
    var r = await fetch('/api/buddy/status', { credentials: 'same-origin' });
    if (!r.ok) return;
    var d = await r.json();
    _available = !!d.available;
    _questionsLeft = (typeof d.questions_left === 'number') ? d.questions_left : DAILY_DEFAULT;
    _renderCounter();
    _reflectAvailability();
  } catch (e) { /* leave defaults */ }
}

function _reflectAvailability() {
  var input = _el('pip-input');
  var send = _el('pip-send');
  var disabled = !_available || _busy || (_questionsLeft != null && _questionsLeft <= 0);
  if (input) input.disabled = disabled && !_available;
  if (send) send.disabled = disabled;
  var note = _el('pip-offline-note');
  if (note) note.style.display = _available ? 'none' : 'block';
}

async function _send(question) {
  question = (question || '').trim();
  if (!question || _busy) return;
  if (_questionsLeft != null && _questionsLeft <= 0) return;

  _busy = true;
  _reflectAvailability();
  var input = _el('pip-input');
  if (input) input.value = '';

  // Clear the old follow-up chips — they belonged to the previous answer.
  _renderSuggestions([]);
  _appendBubble('user', _formatAnswer(question));
  var thinking = _appendBubble('pip', '<span class="pip-typing"><i></i><i></i><i></i></span>', 'pip-thinking');

  var payload = { question: question, history: _history.slice(-8) };
  // Only ever send finding context if the drawer is genuinely open right now.
  // This guarantees a previously-viewed finding can never bleed into a later,
  // unrelated question (the "scheduled task on Leviathan" ghost).
  _syncContextToDrawer();
  if (_context) payload.finding_context = _context;

  var data = null;
  try {
    var r = await fetch('/api/buddy/ask', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (r.status === 429) {
      data = await r.json().catch(function () { return {}; });
      var msg = (data && data.detail && data.detail.message) ||
        "You're out of questions for today. They reset at midnight UTC.";
      if (thinking) thinking.remove();
      _appendBubble('pip', '<p>' + _esc(msg) + '</p>', 'pip-warn');
      _questionsLeft = 0;
      _renderCounter();
      _busy = false; _reflectAvailability();
      return;
    }
    data = await r.json();
  } catch (e) {
    if (thinking) thinking.remove();
    _appendBubble('pip', '<p>I couldn’t reach the server. Check your connection and try again.</p>', 'pip-warn');
    _busy = false; _reflectAvailability();
    return;
  }

  if (thinking) thinking.remove();

  if (!data || data.ok === false || !data.answer) {
    var fail = (data && data.message) || "I couldn't answer that just now. Please try again.";
    _appendBubble('pip', '<p>' + _esc(fail) + '</p>', 'pip-warn');
  } else {
    var answerEl = _appendBubble('pip', _formatAnswer(data.answer));
    _history.push({ role: 'user', content: question });
    _history.push({ role: 'assistant', content: data.answer });
    if (_history.length > 16) _history = _history.slice(-16);
    _lastSuggestions = Array.isArray(data.suggestions) ? data.suggestions : [];
    _renderSuggestions(_lastSuggestions);
    _saveChat();   // persist so a refresh doesn't lose the conversation
    // Land the user at the START of Pip's reply, not scrolled to the bottom.
    _scrollToMsgTop(answerEl);
  }
  if (data && typeof data.questions_left === 'number') _questionsLeft = data.questions_left;
  _renderCounter();
  _busy = false;
  _reflectAvailability();
}

function _openPanel() {
  var panel = _el('pip-panel');
  var fab = _el('pip-fab');
  if (!panel) return;
  panel.classList.add('open');
  if (fab) fab.setAttribute('aria-expanded', 'true');
  var log = _el('pip-log');
  if (log && !log.children.length) {
    if (_history.length) _renderTranscript();   // restored from a refresh
    else _greeting();
  }
  _syncContextToDrawer();   // clear any stale finding context first
  _renderContextBanner();   // then reflect a finding that's genuinely open
  _refreshStatus();
  var input = _el('pip-input');
  if (input) setTimeout(function () { input.focus(); }, 80);
}

function _closePanel() {
  var panel = _el('pip-panel');
  var fab = _el('pip-fab');
  if (panel) panel.classList.remove('open');
  if (fab) fab.setAttribute('aria-expanded', 'false');
}

function _togglePanel() {
  var panel = _el('pip-panel');
  if (panel && panel.classList.contains('open')) _closePanel();
  else _openPanel();
}

function _build() {
  if (_built || document.getElementById('pip-root')) return;
  _built = true;

  var root = document.createElement('div');
  root.id = 'pip-root';
  root.innerHTML =
    '<div id="pip-panel" class="pip-panel" role="dialog" aria-label="Security Buddy chat">' +
      '<div class="pip-head">' +
        '<span class="pip-head-icon">' + _robotSvg(22) + '</span>' +
        '<div class="pip-head-text"><strong>Pip</strong><span>Security Buddy</span></div>' +
        '<button id="pip-newchat" class="pip-headbtn" type="button" aria-label="New chat" title="Start a new chat">' +
          '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" ' +
          'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
          '<path d="M12 5v14M5 12h14"></path></svg>' +
        '</button>' +
        '<button id="pip-close" class="pip-close" type="button" aria-label="Close chat">&times;</button>' +
      '</div>' +
      '<div id="pip-context" class="pip-context" style="display:none"></div>' +
      '<div id="pip-log" class="pip-log" aria-live="polite"></div>' +
      '<div id="pip-offline-note" class="pip-offline" style="display:none">' +
        'Pip isn’t set up on this server yet. An administrator needs to add an ANTHROPIC_API_KEY.' +
      '</div>' +
      '<form id="pip-form" class="pip-input-row" autocomplete="off">' +
        '<input id="pip-input" class="pip-input" type="text" maxlength="500" ' +
          'autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" ' +
          'name="pip-input-nofill" data-lpignore="true" data-1p-ignore readonly data-nofill="1" ' +
          'placeholder="Ask Pip anything…" aria-label="Ask Pip a question">' +
        '<button id="pip-send" class="pip-send" type="submit" aria-label="Send">' +
          '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" ' +
          'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
          '<line x1="22" y1="2" x2="11" y2="13"></line>' +
          '<polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>' +
        '</button>' +
      '</form>' +
      '<div class="pip-foot"><span id="pip-counter" class="pip-counter"></span>' +
        '<span class="pip-disclosure">Chats are sent to Anthropic’s Claude to answer.</span></div>' +
    '</div>' +
    '<button id="pip-fab" class="pip-fab" type="button" aria-label="Open Security Buddy" aria-expanded="false">' +
      _robotSvg(28) +
    '</button>';
  document.body.appendChild(root);

  _el('pip-fab').addEventListener('click', _togglePanel);
  _el('pip-close').addEventListener('click', _closePanel);
  _el('pip-newchat').addEventListener('click', function () {
    _clearChat();
    _greeting();
    var inp = _el('pip-input');
    if (inp) inp.focus();
  });
  _el('pip-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var input = _el('pip-input');
    if (input) _send(input.value);
  });
  // The input renders readonly to block browser autofill; drop that the
  // instant the user focuses it so typing works normally.
  var pipInput = _el('pip-input');
  if (pipInput) pipInput.addEventListener('focus', function () {
    pipInput.removeAttribute('readonly');
  });
  // Follow-up suggestion chips are rendered into the message log after each
  // answer, so delegate clicks from the log itself.
  var log = _el('pip-log');
  if (log) log.addEventListener('click', function (e) {
    var btn = e.target.closest('.pip-chip');
    if (btn && !_busy) _send(btn.getAttribute('data-q'));
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      var panel = _el('pip-panel');
      if (panel && panel.classList.contains('open')) _closePanel();
    }
  });

  // Public hooks for other modules (e.g. the finding drawer).
  window.PulsePip = {
    open: _openPanel,
    // Slide the whole widget left so it sits beside the finding drawer
    // instead of underneath it — Pip stays usable while a finding is open.
    setDocked: function (docked) {
      var root = document.getElementById('pip-root');
      if (!root) return;
      root.classList.toggle('pip-docked', !!docked);
    },
    // Give Pip the open finding's details (text) + a short label for the
    // "Looking at" pill. Pass (null) to clear it. Shown transparently so the
    // user always knows when Pip can see the current finding.
    setContext: function (text, label) {
      _context = text ? String(text) : null;
      _contextLabel = (_context && label) ? String(label) : null;
      _renderContextBanner();
    },
  };

  // Bring back a saved conversation from a previous page load (rendered into
  // the hidden panel so it's ready the moment the user opens Pip).
  if (_restoreChat()) _renderTranscript();

  _refreshStatus();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _build);
} else {
  _build();
}

export { _build as initBuddy };
