// advisor.js — Security Advisor page.
//
// Pulse's audience often does not have a SOC analyst on staff. This page
// is the "what's wrong, what do I do, what does this mean" landing for
// non-experts: a plain-language posture summary, a prioritized concern
// list, expandable attack-concept cards, and a hardening checklist.
'use strict';

import { escapeHtml, toastError } from './dashboard.js';

var _cache = null;

async function _fetchOverview() {
  var resp = await fetch('/api/advisor/overview');
  if (!resp.ok) throw new Error('Failed to load advisor data: HTTP ' + resp.status);
  return await resp.json();
}

function _diffPill(diff) {
  var d = (diff || 'medium').toLowerCase();
  var label = d.charAt(0).toUpperCase() + d.slice(1);
  return '<span class="advisor-diff-pill advisor-diff-' + d + '">' + label + '</span>';
}

function _postureCard(p) {
  var t = p.totals || {};
  return '<div class="advisor-page-card">' +
    '<div class="advisor-page-posture">' + escapeHtml(p.posture || '') + '</div>' +
    '<div class="advisor-totals">' +
      '<div class="advisor-total"><span class="advisor-total-num">' + (t.critical || 0) + '</span>' +
        '<span class="advisor-total-label sev-critical">Critical</span></div>' +
      '<div class="advisor-total"><span class="advisor-total-num">' + (t.high || 0) + '</span>' +
        '<span class="advisor-total-label sev-high">High</span></div>' +
      '<div class="advisor-total"><span class="advisor-total-num">' + (t.medium || 0) + '</span>' +
        '<span class="advisor-total-label sev-medium">Medium</span></div>' +
      '<div class="advisor-total"><span class="advisor-total-num">' + (t.low || 0) + '</span>' +
        '<span class="advisor-total-label sev-low">Low</span></div>' +
    '</div>' +
  '</div>';
}

function _concernsCard(concerns) {
  if (!concerns || !concerns.length) {
    return '<div class="advisor-page-card">' +
      '<div class="advisor-page-section-label">Top concerns</div>' +
      '<div class="advisor-empty">No unresolved findings right now. Nothing demands attention.</div>' +
    '</div>';
  }
  var rows = concerns.map(function (c, idx) {
    var actions = (c.immediate_actions || []).slice(0, 3).map(function (s) {
      return '<li>' + escapeHtml(s) + '</li>';
    }).join('');
    return '<div class="advisor-concern">' +
      '<div class="advisor-concern-head">' +
        '<span class="advisor-concern-rank">' + (idx + 1) + '</span>' +
        '<span class="advisor-concern-name">' + escapeHtml(c.rule) + '</span>' +
        '<span class="advisor-concern-count">' + c.count + ' open</span>' +
        '<span class="pill pill-' + (c.severity || 'LOW').toLowerCase() + '">' +
          escapeHtml(c.severity || 'LOW') + '</span>' +
        _diffPill(c.difficulty) +
      '</div>' +
      (c.plain_language
        ? '<div class="advisor-concern-plain">' + escapeHtml(c.plain_language) + '</div>'
        : '') +
      (actions
        ? '<div class="advisor-concern-actions"><div class="advisor-section-label">What to do now</div>' +
          '<ol class="advisor-steps">' + actions + '</ol></div>'
        : '') +
    '</div>';
  }).join('');
  return '<div class="advisor-page-card">' +
    '<div class="advisor-page-section-label">Top concerns (ranked by impact and how easy they are to pull off)</div>' +
    rows +
  '</div>';
}

function _conceptsCard(concepts) {
  if (!concepts || !concepts.length) return '';
  var cards = concepts.map(function (c) {
    var links = (c.learn_more || []).map(function (l) {
      return '<a class="advisor-link" href="' + escapeHtml(l.url) + '" target="_blank" rel="noopener noreferrer">' +
        escapeHtml(l.label) + ' ↗</a>';
    }).join('');
    return '<details class="advisor-concept">' +
      '<summary>' +
        '<span class="advisor-concept-name">' + escapeHtml(c.name) + '</span>' +
        _diffPill(c.difficulty) +
      '</summary>' +
      '<div class="advisor-body">' +
        '<div class="advisor-concept-plain">' + escapeHtml(c.plain_language) + '</div>' +
        '<div class="advisor-concept-why">' + escapeHtml(c.why_it_matters || '') + '</div>' +
        (links ? '<div class="advisor-links">' + links + '</div>' : '') +
      '</div>' +
    '</details>';
  }).join('');
  return '<div class="advisor-page-card">' +
    '<div class="advisor-page-section-label">Security concepts (read before you need them)</div>' +
    cards +
  '</div>';
}

function _checklistCard(items) {
  if (!items || !items.length) return '';
  var rows = items.map(function (i) {
    var status, cls;
    if (i.auto) {
      // open=true means the rule fired -> the practice is NOT being observed.
      if (i.open) { status = 'Action needed'; cls = 'advisor-check-open'; }
      else        { status = 'Looks good';   cls = 'advisor-check-ok'; }
    } else {
      status = 'Verify yourself'; cls = 'advisor-check-manual';
    }
    return '<div class="advisor-check ' + cls + '">' +
      '<span class="advisor-check-mark" aria-hidden="true">' +
        (cls === 'advisor-check-ok' ? '✓' :
         cls === 'advisor-check-open' ? '!' : '?') +
      '</span>' +
      '<span class="advisor-check-label">' + escapeHtml(i.label) + '</span>' +
      '<span class="advisor-check-status">' + status + '</span>' +
    '</div>';
  }).join('');
  return '<div class="advisor-page-card">' +
    '<div class="advisor-page-section-label">Hardening checklist (Windows essentials)</div>' +
    rows +
  '</div>';
}

export async function renderSecurityAdvisorPage() {
  var c = document.getElementById('content');
  if (!c) return;
  c.innerHTML = '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading Security Advisor…</div>';
  try {
    _cache = await _fetchOverview();
  } catch (e) {
    toastError(e.message);
    c.innerHTML = '<div class="card"><div class="dash-empty-note">' + escapeHtml(e.message) + '</div></div>';
    return;
  }
  c.innerHTML =
    '<div class="advisor-page">' +
      '<div class="advisor-page-header">' +
        '<h2 class="advisor-page-title">Security Advisor</h2>' +
        '<div class="advisor-page-sub">Pulse explains what your findings mean and what to do about them.</div>' +
      '</div>' +
      _postureCard(_cache) +
      _concernsCard(_cache.top_concerns) +
      _conceptsCard(_cache.concepts) +
      _checklistCard(_cache.checklist) +
    '</div>';
}
