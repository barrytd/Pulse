// audit.js — Audit Log page with read-only detail drawer.
//
// Rows are populated server-side by pulse/firewall/blocker.log_audit() from the
// scan / delete / block / unblock / push / user-management code paths.  This
// page is a viewer only — no audit entry is ever edited or deleted from here.
//
// Click a row to open a 480px right-side drawer (Esc to close; j/k to jump
// between entries while it's open).  Each drawer surfaces:
//   - header + action-type chip + full timestamp (local + UTC)
//   - label/value event details with quick-filter links
//   - structured breakdown of the free-form `detail` string
//   - context timeline (same actor, 3-5 entries before/after)
//   - related entries (shared IP / target)
//   - collapsible raw JSON with copy button
// Footer actions: Copy as JSON, Filter to actor / IP / target.
'use strict';

import { fetchAudit } from './api.js';
import { escapeHtml } from './dashboard.js';
import { openDrawer, closeDrawer, isDrawerOpen } from './drawer.js';

// Newest-first cache of every audit row the API returned last refresh.
// _filteredRows mirrors whatever _applyQuery produced on the most recent
// render so the j/k handler and drawer navigation use the same list the
// user is looking at.
var _auditCache = [];
var _filteredRows = [];
var _auditQuery = '';
var _drawerIdx = -1;      // index within _filteredRows while drawer is open
var _jkHandler = null;    // keyboard listener installed while drawer is open

// Action classification → color scheme.  See .claude/skills/pulse-design.md:
// the row-accent severity set is used for left borders and for chip fills.
//   blue   — scan, review, scan-adjacent reads
//   amber  — stage / stage_forced / push (staging mutations)
//   red    — unblock / any delete_ / *_failed (destructive / error)
//   green  — create / user_create / token_create (additive)
function _actionTone(action) {
  var a = (action || '').toLowerCase();
  if (!a) return 'neutral';
  if (a === 'scan' || a === 'review' || a.indexOf('review_') === 0) return 'blue';
  if (a === 'stage' || a === 'stage_forced' || a === 'push') return 'amber';
  if (a === 'unblock' || a.indexOf('delete') === 0 || a.indexOf('_failed') >= 0 ||
      a.indexOf('deactivate') >= 0 || a === 'revoke' || a.indexOf('revoke_') === 0) return 'red';
  if (a.indexOf('create') >= 0 || a === 'signup' || a === 'register') return 'green';
  return 'neutral';
}

// Humanised action title for the drawer header.  The raw action string
// (stage_forced) is kept in the body as a data field so the reviewer can
// still see the literal value that was logged.
function _actionTitle(action) {
  var a = action || 'unknown';
  var map = {
    scan:          'Scan performed',
    stage:         'IP staged for block',
    stage_forced:  'IP staged (private address override)',
    push:          'Block pushed to firewall',
    push_failed:   'Block push failed',
    unblock:       'IP unblocked',
    unblock_failed:'Unblock failed',
    delete_scan:   'Scan deleted',
    review:        'Finding reviewed',
    user_create:   'User account created',
    user_update:   'User account updated',
    user_delete:   'User account deleted',
    user_deactivate:'User deactivated',
    token_create:  'API token created',
    token_revoke:  'API token revoked',
  };
  return map[a] || a.replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
}

export async function renderAuditPage() {
  var c = document.getElementById('content');
  _auditCache = await fetchAudit(500);

  c.innerHTML =
    '<div class="page-head">' +
      '<div class="page-head-title"><strong>' + _auditCache.length + '</strong> entr' +
        (_auditCache.length === 1 ? 'y' : 'ies') + '</div>' +
      '<div class="page-head-actions">' +
        '<input type="text" class="search-input" placeholder="Filter action, user, detail..." ' +
               'oninput="window.__auditFilter(this.value)" ' +
               'value="' + escapeHtml(_auditQuery) + '">' +
      '</div>' +
    '</div>' +
    '<div class="card" style="padding:0; overflow:hidden;">' +
      '<div id="audit-table-wrap">' + _renderTable() + '</div>' +
    '</div>';

  window.__auditFilter = function (q) {
    _auditQuery = q || '';
    var wrap = document.getElementById('audit-table-wrap');
    if (wrap) wrap.innerHTML = _renderTable();
  };
}

function _renderTable() {
  _filteredRows = _applyQuery(_auditCache, _auditQuery);
  if (!_filteredRows.length) {
    return '<div style="padding:48px 20px; text-align:center; color:var(--text-muted);">' +
             'No audit entries match.' +
           '</div>';
  }
  var body = _filteredRows.map(function (r) {
    var tone = _actionTone(r.action);
    return '<tr class="clickable audit-row audit-edge-' + tone + '" ' +
               'data-action="openAuditDrawer" data-arg="' + escapeHtml(String(r.id)) + '">' +
      '<td><code>' + escapeHtml(r.ts || '') + '</code></td>' +
      '<td>' + _actionChip(r.action, tone) + '</td>' +
      '<td>' + _actorCell(r) + '</td>' +
      '<td>' + (r.ip_address ? '<code>' + escapeHtml(r.ip_address) + '</code>' : '') + '</td>' +
      '<td class="muted" style="max-width:380px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' +
        _targetPill(r) +
        escapeHtml(r.detail || (_parseFindingId(r.comment) ? '' : (r.comment || ''))) +
      '</td>' +
      '</tr>';
  }).join('');
  return '<table class="findings-table"><thead><tr>' +
           '<th>Time</th><th>Action</th><th>User / Source</th><th>IP</th><th>Detail</th>' +
         '</tr></thead><tbody>' + body + '</tbody></table>';
}

function _applyQuery(rows, q) {
  if (!q) return rows;
  var needle = q.toLowerCase();
  return rows.filter(function (r) {
    var hay = [r.ts, r.action, r.user, r.ip_address, r.comment, r.detail, r.source]
      .filter(Boolean).join(' ').toLowerCase();
    return hay.indexOf(needle) >= 0;
  });
}

function _actionChip(action, tone) {
  return '<span class="audit-chip audit-chip-' + tone + '">' +
           escapeHtml(action || '-') +
         '</span>';
}

// Extract the numeric finding id from an audit row's `comment` field.
// _audit_finding_action stores comments as "finding:<id>" for every
// finding-level action; anything else returns null.
function _parseFindingId(comment) {
  if (!comment) return null;
  var m = /^finding:(\d+)$/.exec(String(comment).trim());
  return m ? Number(m[1]) : null;
}

// Render a clickable "Finding N" pill next to the detail text when the
// audit row targets a specific finding. Swallows the row-level click so
// the drawer doesn't steal the pill click.
function _targetPill(r) {
  var fid = _parseFindingId(r.comment);
  if (!fid) return '';
  return '<a class="audit-target-pill" ' +
           'data-action="openAuditFinding" data-arg="' + fid + '" ' +
           'data-default="allow" ' +
           'title="Open this finding">' +
           'Finding ' + fid +
         '</a> ';
}

// Navigate to the Findings page and open the drawer for the given id.
// Exported so the action registry can wire it from both the table row
// pill and the drawer's footer button.
export async function openAuditFinding(findingId) {
  var id = Number(findingId);
  if (!id) return;
  // Dynamic imports avoid a circular static import with navigation.js /
  // findings.js at module load time.
  var [nav, findings] = await Promise.all([
    import('./navigation.js'),
    import('./findings.js'),
  ]);
  // Close any open audit drawer first so the finding drawer doesn't
  // open behind it.
  var universalDrawer = document.getElementById('drawer-root');
  if (universalDrawer) universalDrawer.setAttribute('hidden', '');
  nav.navigateWithHistory('findings');
  // Poll briefly for the findings cache to populate, then open the drawer.
  var attempts = 0;
  var timer = setInterval(function () {
    attempts++;
    var cache = (findings.findingsState && findings.findingsState.raw) || [];
    var f = cache.find(function (x) { return Number(x.id) === id; });
    if (f) {
      clearInterval(timer);
      findings.openFindingDrawer(f);
    } else if (attempts > 40) {   // ~4s max
      clearInterval(timer);
    }
  }, 100);
}

function _actorCell(r) {
  // Prefer the admin-set display_name (joined by get_audit_log), fall
  // back to the raw email, fall back to the source label. The hover
  // title always shows the email for disambiguation.
  var dn = (r.user_display_name || '').trim();
  var email = r.user || '';
  var label = dn || email || r.source || '-';
  var isHuman = !!(email && /@/.test(email));
  var icon = isHuman ? '&#128100;' : '&#9881;';
  var title = isHuman
    ? (email || 'User')
    : (r.source || 'Automation');
  return '<span class="audit-actor" title="' + escapeHtml(title) + '">' +
           '<span class="audit-actor-ic">' + icon + '</span>' +
           escapeHtml(label) +
         '</span>';
}

// ---------------------------------------------------------------------------
// Drawer
// ---------------------------------------------------------------------------

export function openAuditDrawer(rowId) {
  var id = Number(rowId);
  var idx = _filteredRows.findIndex(function (r) { return Number(r.id) === id; });
  if (idx < 0) return;
  _drawerIdx = idx;
  _mountDrawerFor(_filteredRows[idx]);
  _installJkHandler();
}

function _mountDrawerFor(row) {
  var tone = _actionTone(row.action);
  var sections = [
    { label: 'Event details',   html: _sectionEventDetails(row) },
    { label: 'Detail breakdown',html: _sectionDetailBreakdown(row) },
    { label: 'Context timeline',html: _sectionTimeline(row) },
    { label: 'Related entries', html: _sectionRelated(row) },
    { label: 'Raw JSON',        html: _sectionRaw(row) },
  ];
  var actions = [
    { label: 'Copy as JSON',    variant: 'secondary', onClick: function () { _copyJson(row); } },
    { label: 'Filter to actor', variant: 'secondary', onClick: function () { _applyFilter(row.user || row.source || ''); } },
  ];
  if (row.ip_address) {
    actions.push({ label: 'Filter to IP',    variant: 'secondary', onClick: function () { _applyFilter(row.ip_address); } });
  }
  var tgt = _parseTarget(row);
  if (tgt) {
    actions.push({ label: 'Filter to target', variant: 'secondary', onClick: function () { _applyFilter(tgt); } });
  }

  openDrawer({
    title: _actionTitle(row.action),
    subtitle: _timestampHtml(row.ts),
    badges: [{ text: row.action || 'unknown', tone: _toneToBadge(tone) }],
    sections: sections,
    actions: actions,
    onClose: function () {
      _drawerIdx = -1;
      _removeJkHandler();
    },
  });
}

// The universal drawer's badge tones are severity-themed; map our four action
// buckets onto the closest tone so the chip colour in the header matches the
// row's left-edge tint.
function _toneToBadge(tone) {
  if (tone === 'red')    return 'critical';
  if (tone === 'amber')  return 'high';
  if (tone === 'blue')   return 'info';
  if (tone === 'green')  return 'ok';
  return 'off';
}

function _timestampHtml(ts) {
  if (!ts) return '';
  // The server stores audit timestamps as local-time ISO strings (see
  // pulse/firewall/blocker.py log_audit() — CURRENT_TIMESTAMP on SQLite).
  // Surface both local and UTC so a reviewer looking at this across time
  // zones (or across the Postgres / Render deployment) has the full picture.
  var d = new Date(ts);
  if (isNaN(d.getTime())) return '<code>' + escapeHtml(ts) + '</code>';
  return '<code>' + escapeHtml(d.toLocaleString()) + '</code> · ' +
         '<span class="muted">UTC ' + escapeHtml(d.toISOString().replace('T', ' ').replace('Z', '')) + '</span>';
}

function _sectionEventDetails(row) {
  var isHuman = !!(row.user && /@/.test(row.user));
  var actorIcon = isHuman ? '&#128100;' : '&#9881;';
  var actorKind = isHuman ? 'user' : (row.source || 'automation');
  // Prefer display_name; show email muted on a second line for humans.
  var actorName = (row.user_display_name || '').trim() || row.user || '-';
  var actorExtra = (row.user_display_name && row.user)
    ? ' <span class="muted">' + escapeHtml(row.user) + '</span>'
    : '';
  var kv = [
    ['Action',   '<code>' + escapeHtml(row.action || '-') + '</code>'],
    ['Actor',    '<span class="audit-actor-ic">' + actorIcon + '</span> ' +
                 escapeHtml(actorName) + actorExtra +
                 ' <span class="muted">(' + escapeHtml(actorKind) + ')</span>'],
    ['Source',   escapeHtml(row.source || '-')],
  ];
  if (row.ip_address) {
    kv.push(['IP',
      '<code class="audit-ip-mono">' + escapeHtml(row.ip_address) + '</code> ' +
      '<a class="audit-inline-link" onclick="window.__auditFilterBy(\'' +
        _attrEscape(row.ip_address) + '\')">filter</a>']);
  }
  kv.push(['Entry ID',
    '<code class="audit-id-chip" title="Click to copy" ' +
       'onclick="window.__auditCopyId(' + Number(row.id) + ')">' +
       'AUD-' + String(row.id).padStart(6, '0') +
    '</code>']);
  // Finding target gets its own clickable row so the reviewer can jump
  // straight to the drawer for that finding.
  var fid = _parseFindingId(row.comment);
  if (fid) {
    kv.push(['Target',
      '<a class="audit-target-pill audit-target-pill-lg" ' +
         'data-action="openAuditFinding" data-arg="' + fid + '" ' +
         'data-default="allow" ' +
         'title="Open this finding">Finding ' + fid + ' &rarr;</a>']);
  } else if (row.comment) {
    kv.push(['Comment', escapeHtml(row.comment)]);
  }
  return '<div class="kv">' + kv.map(function (p) {
    return '<div class="k">' + p[0] + '</div><div class="v">' + p[1] + '</div>';
  }).join('') + '</div>';
}

// The `detail` field is a free-form string the server composes per action.
// We parse the patterns produced by pulse/api.py + pulse/firewall/blocker.py
// into labelled kv pairs; anything we can't parse drops back to a raw line.
function _sectionDetailBreakdown(row) {
  var detail = row.detail || '';
  if (!detail) return '<div class="muted">No structured detail recorded.</div>';
  var parsed = _parseDetail(row.action, detail);
  if (!parsed.length) {
    return '<div class="kv"><div class="k">Detail</div>' +
           '<div class="v"><code style="white-space:pre-wrap;">' + escapeHtml(detail) + '</code></div></div>';
  }
  return '<div class="kv">' + parsed.map(function (p) {
    return '<div class="k">' + escapeHtml(p[0]) + '</div>' +
           '<div class="v">' + p[1] + '</div>';
  }).join('') + '</div>';
}

function _parseDetail(action, detail) {
  var a = (action || '').toLowerCase();
  var pairs = [];
  var kvMatches = detail.match(/([a-zA-Z_]+)=([^\s]+)/g) || [];
  kvMatches.forEach(function (m) {
    var eq = m.indexOf('=');
    var k = m.slice(0, eq);
    var v = m.slice(eq + 1);
    pairs.push([_prettyKey(k), '<code>' + escapeHtml(v) + '</code>']);
  });
  // push / stage log the plain rule name as detail (no `=` token).
  if (!pairs.length && (a === 'push' || a === 'stage' || a === 'stage_forced')) {
    pairs.push(['Rule name', '<code>' + escapeHtml(detail) + '</code>']);
  }
  return pairs;
}

function _prettyKey(k) {
  var map = {
    scan_id:   'Scan ID',
    filename:  'File name',
    findings:  'Findings',
    page:      'Page',
    requested: 'Requested',
    deleted:   'Deleted',
    ids:       'IDs',
    target:    'Target',
    rule:      'Rule',
  };
  return map[k] || k.replace(/_/g, ' ');
}

// Parse out whatever "target" identifier this action operated on so the
// Filter-to-target footer button is meaningful.  Scans point at scan_id,
// deletes point at ids, user actions point at target=..., staging uses the
// IP itself.
function _parseTarget(row) {
  var detail = row.detail || '';
  var m = detail.match(/\btarget=(\S+)/);
  if (m) return m[1];
  m = detail.match(/\bscan_id=(\S+)/);
  if (m) return 'scan_id=' + m[1];
  var a = (row.action || '').toLowerCase();
  if (a === 'push' || a === 'stage' || a === 'stage_forced' || a === 'unblock') {
    return row.ip_address || null;
  }
  return null;
}

// Timeline: last 3 and next 3 entries from the same actor (user or source
// fallback) so the reviewer can see what that actor was doing around this
// moment.  Current row is highlighted and not clickable.
function _sectionTimeline(row) {
  var actorKey = (row.user || row.source || '').toLowerCase();
  if (!actorKey) return '<div class="muted">Actor unknown — no timeline available.</div>';
  var sameActor = _auditCache.filter(function (r) {
    return (r.user || r.source || '').toLowerCase() === actorKey;
  });
  var idx = sameActor.findIndex(function (r) { return Number(r.id) === Number(row.id); });
  if (idx < 0) return '<div class="muted">Not found in actor timeline.</div>';
  var start = Math.max(0, idx - 3);
  var end   = Math.min(sameActor.length, idx + 4);
  var slice = sameActor.slice(start, end);
  if (slice.length <= 1) return '<div class="muted">No surrounding activity for this actor.</div>';
  var items = slice.map(function (r) {
    var tone = _actionTone(r.action);
    var here = Number(r.id) === Number(row.id);
    var cls = 'audit-tl-item audit-tl-' + tone + (here ? ' audit-tl-here' : '');
    var onClick = here ? '' :
      ' onclick="window.__auditJumpTo(' + Number(r.id) + ')"';
    return '<div class="' + cls + '"' + onClick + '>' +
             '<div class="audit-tl-dot"></div>' +
             '<div class="audit-tl-body">' +
               '<div class="audit-tl-top">' +
                 '<code>' + escapeHtml(r.ts || '') + '</code>' +
               '</div>' +
               '<div class="audit-tl-bot">' +
                 escapeHtml(_actionTitle(r.action)) +
                 (r.ip_address ? ' <span class="muted">· ' + escapeHtml(r.ip_address) + '</span>' : '') +
               '</div>' +
             '</div>' +
           '</div>';
  }).join('');
  return '<div class="audit-timeline">' + items + '</div>';
}

// Related entries: anything with the same IP, or the same parsed target.
function _sectionRelated(row) {
  var tgt = _parseTarget(row);
  var ip  = row.ip_address || '';
  var rel = _auditCache.filter(function (r) {
    if (Number(r.id) === Number(row.id)) return false;
    if (ip && r.ip_address === ip) return true;
    var t = _parseTarget(r);
    return !!(tgt && t && t === tgt);
  }).slice(0, 6);
  if (!rel.length) return '<div class="muted">No other entries share this IP or target.</div>';
  return '<div class="audit-related">' + rel.map(function (r) {
    var tone = _actionTone(r.action);
    return '<div class="audit-related-row audit-edge-' + tone + '" ' +
               'onclick="window.__auditJumpTo(' + Number(r.id) + ')">' +
             '<div class="audit-related-top">' +
               '<code>' + escapeHtml(r.ts || '') + '</code> · ' +
               '<strong>' + escapeHtml(_actionTitle(r.action)) + '</strong>' +
             '</div>' +
             '<div class="muted" style="font-size:12px;">' +
               escapeHtml(r.user || r.source || '-') +
               (r.ip_address ? ' · <code>' + escapeHtml(r.ip_address) + '</code>' : '') +
             '</div>' +
           '</div>';
  }).join('') + '</div>';
}

function _sectionRaw(row) {
  var json = JSON.stringify(row, null, 2);
  return '<details class="audit-raw">' +
           '<summary>Show raw JSON <button type="button" class="audit-raw-copy" ' +
             'onclick="event.stopPropagation(); window.__auditCopyRaw(' + Number(row.id) + ')">Copy</button></summary>' +
           '<pre class="audit-raw-pre"><code>' + escapeHtml(json) + '</code></pre>' +
         '</details>';
}

// ---------------------------------------------------------------------------
// Drawer helpers (copy, jump, filter, keyboard navigation)
// ---------------------------------------------------------------------------

function _copyJson(row) {
  var text = JSON.stringify(row, null, 2);
  _clipboardWrite(text);
}

function _applyFilter(val) {
  if (!val) return;
  _auditQuery = String(val);
  var input = document.querySelector('.page-head-actions .search-input');
  if (input) input.value = _auditQuery;
  var wrap = document.getElementById('audit-table-wrap');
  if (wrap) wrap.innerHTML = _renderTable();
  closeDrawer();
}

window.__auditFilterBy = function (val) { _applyFilter(val); };
window.__auditJumpTo = function (rowId) {
  var idx = _filteredRows.findIndex(function (r) { return Number(r.id) === Number(rowId); });
  if (idx < 0) {
    // Row not in current filter — drop the filter and try again.
    _auditQuery = '';
    var input = document.querySelector('.page-head-actions .search-input');
    if (input) input.value = '';
    var wrap = document.getElementById('audit-table-wrap');
    if (wrap) wrap.innerHTML = _renderTable();
    idx = _filteredRows.findIndex(function (r) { return Number(r.id) === Number(rowId); });
    if (idx < 0) return;
  }
  _drawerIdx = idx;
  _mountDrawerFor(_filteredRows[idx]);
};
window.__auditCopyId = function (rowId) {
  _clipboardWrite('AUD-' + String(rowId).padStart(6, '0'));
};
window.__auditCopyRaw = function (rowId) {
  var row = _auditCache.find(function (r) { return Number(r.id) === Number(rowId); });
  if (row) _clipboardWrite(JSON.stringify(row, null, 2));
};

function _clipboardWrite(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text);
      return;
    }
  } catch (e) { /* fall through to legacy path */ }
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } catch (e) {}
  document.body.removeChild(ta);
}

function _installJkHandler() {
  if (_jkHandler) return;
  _jkHandler = function (e) {
    if (!isDrawerOpen()) return;
    // Ignore j/k if the user is typing in an input (Esc is handled by the
    // drawer primitive, so we only need to guard the alpha keys).
    var tag = (e.target && e.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea') return;
    if (e.key === 'j' || e.key === 'J') {
      e.preventDefault();
      _stepDrawer(+1);
    } else if (e.key === 'k' || e.key === 'K') {
      e.preventDefault();
      _stepDrawer(-1);
    }
  };
  document.addEventListener('keydown', _jkHandler);
}

function _removeJkHandler() {
  if (!_jkHandler) return;
  document.removeEventListener('keydown', _jkHandler);
  _jkHandler = null;
}

function _stepDrawer(delta) {
  if (_drawerIdx < 0 || !_filteredRows.length) return;
  var next = _drawerIdx + delta;
  if (next < 0 || next >= _filteredRows.length) return;
  _drawerIdx = next;
  _mountDrawerFor(_filteredRows[next]);
}

// Attribute-safe escape for values we inject into inline onclick handlers.
// We prefer data-action delegation for new handlers, but the quick-filter
// inline link is simple enough that a one-off attribute escape is clearer
// than registering a fifth action name.
function _attrEscape(s) {
  return String(s == null ? '' : s)
    .replace(/\\/g, '\\\\')
    .replace(/'/g,  "\\'")
    .replace(/"/g,  '&quot;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;');
}
