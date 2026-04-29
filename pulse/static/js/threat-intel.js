// threat-intel.js — Threat Intel page (a.k.a. IOC Lookup).
//
// Standalone page accessible from the sidebar under the Threat
// Management group. The analyst pastes an IP (hash support is a
// follow-up — needs a separate VirusTotal integration), hits Lookup,
// and gets the same AbuseIPDB confidence/country/ISP card the finding
// drawer renders, plus a list of recent cached lookups so they don't
// have to retype anything they investigated this week.
'use strict';

import { escapeHtml, relTimeHtml } from './dashboard.js';
import { apiFetchIntel } from './api.js';

// Module state — persists across re-renders during the session.
//   _lastLookup: the most recent successful lookup result
//   _lastError:  human-readable error string for the most recent failed lookup
//   _input:      whatever's in the IP input field (so re-render preserves it)
//   _intelKeyMissing: true once we've seen a 400 "no key configured" reply,
//                     used to show the configure-prompt banner.
var _lastLookup = null;
var _lastError  = null;
var _input      = '';
var _intelKeyMissing = false;
var _busy = false;

// ---------------------------------------------------------------
// Page render
// ---------------------------------------------------------------

export async function renderThreatIntelPage() {
  var c = document.getElementById('content');
  if (!c) return;

  // Initial paint: shell + skeleton "Recent" row. The recent-lookups
  // list comes from /api/intel/recent which is one DB read — fire it
  // alongside the first paint so the page lands populated.
  c.innerHTML = _shellHtml(_recentLoadingHtml());
  _hydrateRecent();
}

function _shellHtml(recentHtml) {
  return '<div class="findings-page">' +
    _pageHeaderHtml() +
    '<div class="findings-page-body">' +
      '<div class="ti-grid">' +
        '<div class="ti-lookup-col">' +
          _lookupCardHtml() +
          _resultCardHtml() +
        '</div>' +
        '<aside class="ti-recent-col">' +
          '<div class="card ti-recent-card">' +
            '<div class="ti-recent-head">' +
              '<span class="section-label">Recent lookups</span>' +
              '<button type="button" class="btn btn-sm btn-with-icon" ' +
                'data-action="threatIntelRefreshRecent" title="Refresh">' +
                '<i data-lucide="refresh-cw"></i>' +
              '</button>' +
            '</div>' +
            '<div class="ti-recent-list" id="ti-recent-list">' +
              recentHtml +
            '</div>' +
          '</div>' +
        '</aside>' +
      '</div>' +
    '</div>' +
  '</div>';
}

function _pageHeaderHtml() {
  return '<div class="page-header">' +
    '<nav class="page-breadcrumb" aria-label="Breadcrumb">' +
      '<span class="page-breadcrumb-item">Pulse</span>' +
      '<span class="page-breadcrumb-sep" aria-hidden="true">›</span>' +
      '<span class="page-breadcrumb-item">Threat Management</span>' +
      '<span class="page-breadcrumb-sep" aria-hidden="true">›</span>' +
      '<span class="page-breadcrumb-current">Threat Intel</span>' +
    '</nav>' +
    '<div class="page-title-block">' +
      '<h1 class="page-title">Threat Intel</h1>' +
      '<div class="page-title-actions">' +
        '<a class="btn btn-compact btn-with-icon" ' +
          'data-action="navigate" data-arg="settings" ' +
          'title="Configure AbuseIPDB API key under Settings &rsaquo; Notifications">' +
          '<i data-lucide="settings"></i><span>Settings</span>' +
        '</a>' +
      '</div>' +
    '</div>' +
    '<p class="ti-page-blurb">' +
      'Paste a public IPv4 / IPv6 address to query AbuseIPDB. Results are ' +
      'cached for 24 hours so repeat lookups don’t burn quota — ' +
      'the cache also drives the score badge in the finding-drawer.' +
    '</p>' +
  '</div>';
}

function _lookupCardHtml() {
  var disabled = _busy ? ' disabled' : '';
  return '<div class="card ti-lookup-card">' +
    '<form class="ti-lookup-form" data-action-submit="threatIntelSubmit">' +
      '<label class="ti-lookup-label" for="ti-input">IP address</label>' +
      '<div class="ti-lookup-row">' +
        '<input type="search" id="ti-input" class="ti-lookup-input" ' +
          'placeholder="e.g. 8.8.8.8 or 2606:4700:4700::1111" ' +
          'autocomplete="off" spellcheck="false" ' +
          'value="' + escapeHtml(_input) + '" ' +
          'data-action-input="threatIntelInputChange"' + disabled + ' />' +
        '<button type="submit" class="btn btn-primary btn-with-icon"' + disabled + '>' +
          (_busy ? '<i data-lucide="loader-2" class="ti-spin"></i><span>Looking up…</span>'
                 : '<i data-lucide="search"></i><span>Lookup</span>') +
        '</button>' +
      '</div>' +
      _intelKeyBannerHtml() +
    '</form>' +
  '</div>';
}

function _intelKeyBannerHtml() {
  if (!_intelKeyMissing) return '';
  return '<div class="ti-banner">' +
    '<i data-lucide="info"></i>' +
    '<span>Threat-intel lookups are off. ' +
      '<a href="#" data-action="navigate" data-arg="settings">' +
        'Add an AbuseIPDB API key in Settings' +
      '</a> to enable.' +
    '</span>' +
  '</div>';
}

function _resultCardHtml() {
  if (_lastError) {
    return '<div class="card ti-result-card ti-result-error">' +
      '<i data-lucide="alert-triangle"></i>' +
      '<div>' +
        '<div class="ti-result-error-head">Lookup failed</div>' +
        '<div class="ti-result-error-body">' + escapeHtml(_lastError) + '</div>' +
      '</div>' +
    '</div>';
  }
  if (!_lastLookup) {
    return '<div class="card ti-result-empty">' +
      '<div class="ti-result-empty-icon"><i data-lucide="shield-search"></i></div>' +
      '<div class="ti-result-empty-title">No lookup yet</div>' +
      '<div class="ti-result-empty-sub">' +
        'Paste a public IP above and hit Lookup. The result will appear here.' +
      '</div>' +
    '</div>';
  }
  return _renderResult(_lastLookup);
}

function _renderResult(d) {
  var score = d.score;
  var sclass = _scoreClass(score);
  var slabel = _scoreLabel(score);
  var country = d.country ? escapeHtml(d.country) : '—';
  var isp     = d.isp     ? escapeHtml(d.isp)     : '—';
  var reports = d.total_reports != null ? d.total_reports.toLocaleString() : '—';
  var lastReported = d.last_reported
    ? relTimeHtml(d.last_reported)
    : 'Never reported';
  var fetched = d.fetched_at
    ? relTimeHtml(d.fetched_at)
    : '—';
  var cached = d.cached
    ? '<span class="ti-cache-flag" title="Served from local cache">cached</span>'
    : '<span class="ti-cache-flag ti-cache-flag-fresh" title="Fresh fetch from AbuseIPDB">fresh</span>';
  return '<div class="card ti-result-card">' +
    '<div class="ti-result-head">' +
      '<div class="ti-result-score-block ' + sclass + '">' +
        '<div class="ti-result-score">' + (score == null ? '—' : score) + '</div>' +
        '<div class="ti-result-score-label">' + escapeHtml(slabel) + '</div>' +
      '</div>' +
      '<div class="ti-result-meta">' +
        '<div class="ti-result-row"><span class="k">IP</span>' +
          '<span class="v ti-mono">' + escapeHtml(d.ip) + '</span>' + cached + '</div>' +
        '<div class="ti-result-row"><span class="k">Country</span><span class="v">' + country + '</span></div>' +
        '<div class="ti-result-row"><span class="k">ISP</span><span class="v">' + isp + '</span></div>' +
        '<div class="ti-result-row"><span class="k">Reports (90d)</span><span class="v">' + reports + '</span></div>' +
        '<div class="ti-result-row"><span class="k">Last reported</span><span class="v">' + lastReported + '</span></div>' +
        '<div class="ti-result-row"><span class="k">Fetched</span><span class="v">' + fetched + '</span></div>' +
      '</div>' +
    '</div>' +
    '<div class="ti-result-foot">' +
      '<a href="https://www.abuseipdb.com/check/' + encodeURIComponent(d.ip) + '" ' +
        'target="_blank" rel="noopener" data-default="allow" ' +
        'class="ti-result-link">' +
        '<i data-lucide="external-link"></i>' +
        '<span>Open the AbuseIPDB report</span>' +
      '</a>' +
    '</div>' +
  '</div>';
}

// Score buckets follow AbuseIPDB convention: 75+ malicious, 25–74
// suspicious, <25 clean. Same palette as the row-accent severity set.
function _scoreClass(s) {
  if (s == null)  return 'ti-score-na';
  if (s >= 75)    return 'ti-score-high';
  if (s >= 25)    return 'ti-score-med';
  return 'ti-score-low';
}
function _scoreLabel(s) {
  if (s == null) return 'No data';
  if (s >= 75)   return 'Malicious';
  if (s >= 25)   return 'Suspicious';
  return 'Clean';
}

// ---------------------------------------------------------------
// Recent-lookups panel
// ---------------------------------------------------------------

function _recentLoadingHtml() {
  return '<div class="ti-recent-loading">Loading…</div>';
}

async function _hydrateRecent() {
  var list = document.getElementById('ti-recent-list');
  if (!list) return;
  try {
    var resp = await fetch('/api/intel/recent?limit=20');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    var data = await resp.json();
    list.innerHTML = _recentListHtml(data.rows || []);
  } catch (e) {
    list.innerHTML = '<div class="ti-recent-empty">Could not load recent lookups.</div>';
  }
}

function _recentListHtml(rows) {
  if (!rows.length) {
    return '<div class="ti-recent-empty">' +
      'No cached lookups yet. Run one above to populate this panel.' +
    '</div>';
  }
  return rows.map(function (r) {
    var sc = _scoreClass(r.score);
    var label = r.score == null ? '—' : String(r.score);
    var fetched = r.fetched_at ? relTimeHtml(r.fetched_at) : '';
    return '<button type="button" class="ti-recent-row" ' +
        'data-action="threatIntelLookupRecent" ' +
        'data-arg="' + escapeHtml(r.ip) + '">' +
      '<span class="ti-recent-score ' + sc + '">' + escapeHtml(label) + '</span>' +
      '<span class="ti-recent-ip ti-mono">' + escapeHtml(r.ip) + '</span>' +
      '<span class="ti-recent-meta">' +
        (r.country ? escapeHtml(r.country) + ' · ' : '') +
        fetched +
      '</span>' +
    '</button>';
  }).join('');
}

// ---------------------------------------------------------------
// Action handlers (registered in app.js)
// ---------------------------------------------------------------

export function threatIntelInputChange(_arg, target) {
  _input = (target && target.value) || '';
}

export async function threatIntelSubmit(_arg, target, ev) {
  if (ev && ev.preventDefault) ev.preventDefault();
  var raw = (_input || '').trim();
  if (!raw) return;
  await _runLookup(raw);
}

// Click on a "Recent lookups" row — re-runs the lookup for that IP so
// the user sees the most up-to-date data + populates the input field.
export async function threatIntelLookupRecent(ip) {
  if (!ip) return;
  _input = String(ip);
  await _runLookup(_input);
}

export async function threatIntelRefreshRecent() {
  var list = document.getElementById('ti-recent-list');
  if (list) list.innerHTML = _recentLoadingHtml();
  await _hydrateRecent();
}

async function _runLookup(ip) {
  _busy = true;
  _lastError = null;
  _rerender();
  var resp = await apiFetchIntel(ip);
  _busy = false;
  if (resp.status === 404) {
    _lastError = 'That IP isn’t routable (private, loopback, or invalid). ' +
                 'Try a public IP like 1.1.1.1.';
    _lastLookup = null;
  } else if (resp.status === 400) {
    _intelKeyMissing = true;
    _lastError = 'No AbuseIPDB API key is configured. Set one under Settings.';
    _lastLookup = null;
  } else if (!resp.ok || !resp.data) {
    _lastError = 'Lookup failed. Check the IP and try again ' +
                 '(AbuseIPDB may also be rate-limiting).';
    _lastLookup = null;
  } else {
    _lastLookup = resp.data;
    _intelKeyMissing = false;
  }
  _rerender();
  // Refresh the recent panel so the new (or refreshed) entry surfaces.
  await _hydrateRecent();
}

function _rerender() {
  // Targeted re-paint of just the lookup card + result card so the
  // recent-lookups list keeps its scroll position and we don't reflow
  // the page header on every keystroke.
  var col = document.querySelector('.ti-lookup-col');
  if (col) col.innerHTML = _lookupCardHtml() + _resultCardHtml();
  // Restore focus to the input after the render so the user can keep
  // typing / hit Enter without re-clicking the field.
  var input = document.getElementById('ti-input');
  if (input && document.activeElement !== input) {
    input.focus();
    var v = input.value;
    input.value = '';
    input.value = v; // moves cursor to end
  }
}
