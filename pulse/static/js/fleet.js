// fleet.js — Fleet overview page. One row per tracked hostname with its
// latest score, last scan time, scan count, total findings, and worst
// severity seen. Clicking a row jumps to the Dashboard filtered to that
// host so the user can drill in.
'use strict';

import { fetchFleet } from './api.js';
import { dashFilterState, writeDashFiltersToURL } from './dashboard.js';
import { navigate } from './navigation.js';
import { escapeHtml, scoreColorClass, _gradeFor, sevPillHtml } from './dashboard.js';

export async function renderFleetPage() {
  var c = document.getElementById('content');
  var hosts = await fetchFleet();

  if (!hosts.length) {
    c.innerHTML =
      '<div class="empty-state cta">' +
        '<div class="empty-icon">&#128187;</div>' +
        '<h3>No hosts yet</h3>' +
        '<p>Run a scan or upload a .evtx file — hosts will appear here once Pulse has tagged findings with a Computer name.</p>' +
        '<button class="btn btn-primary" data-action="openUploadModal">Upload .evtx</button>' +
      '</div>';
    return;
  }

  c.innerHTML =
    '<div class="page-head">' +
      '<div class="page-head-title"><strong>' + hosts.length + '</strong> host' +
        (hosts.length === 1 ? '' : 's') + ' tracked</div>' +
    '</div>' +

    '<div class="card" style="padding:0; overflow:hidden;">' +
      _buildFleetTable(hosts) +
    '</div>';
}

function _buildFleetTable(hosts) {
  var rows = hosts.map(function (h) {
    var score = (h.latest_score == null) ? '-' : h.latest_score;
    var grade = h.latest_grade || (h.latest_score != null ? _gradeFor(h.latest_score) : '');
    var worst = h.worst_severity || 'NONE';
    var scoreCls = h.latest_score != null ? scoreColorClass(h.latest_score) : '';

    return '<tr class="clickable" data-action="fleetOpenHost" ' +
           'data-arg="' + escapeHtml(h.hostname) + '" style="cursor:pointer;">' +
      '<td>' + escapeHtml(h.hostname) + '</td>' +
      '<td class="' + scoreCls + '">' + score + (grade ? ' <span class="muted">(' + grade + ')</span>' : '') + '</td>' +
      '<td>' + sevPillHtml(worst) + '</td>' +
      '<td>' + h.scan_count + '</td>' +
      '<td>' + h.total_findings + '</td>' +
      '<td>' + escapeHtml(h.last_scan_at || '-') + '</td>' +
      '</tr>';
  }).join('');

  return '<table class="findings-table"><thead><tr>' +
    '<th>Host</th><th>Latest Score</th><th>Worst Severity</th>' +
    '<th>Scans</th><th>Findings</th><th>Last Scan</th>' +
    '</tr></thead><tbody>' + rows + '</tbody></table>';
}

// Action target — registered in app.js. Drills from Fleet into the
// Dashboard with the SOURCE filter pre-set to this host, so the user
// lands on a view showing only that machine's posture. Time range
// always resets to Today so switching between hosts is predictable —
// the per-device view initializes its own time range independently.
export function fleetOpenHost(hostname) {
  if (!hostname) return;
  dashFilterState.source = hostname;
  dashFilterState.time   = 'today';
  dashFilterState.from   = '';
  dashFilterState.to     = '';
  navigate('dashboard');
  // navigate() rewrites the URL to drop the query string, so push
  // filter state back afterwards so the URL is bookmarkable.
  writeDashFiltersToURL();
}
