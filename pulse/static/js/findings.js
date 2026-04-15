// findings.js — Findings page, Scans page, shared finding drawer,
// scan-detail view. Scans page lives here because it shares the
// finding drawer and buildFindingsTable helper.
(function () {
  'use strict';

  // ---------------------------------------------------------------
  // Scans page state
  // ---------------------------------------------------------------
  window.scansState = {
    raw:      [],
    query:    '',
    sortCol:  'date',
    sortDir:  'desc',
    selected: {},
  };

  // Called via data-action on the per-row checkbox. Second arg is the
  // clicked element, third is the event — stop propagation so the row
  // click (viewScan) doesn't also fire.
  function toggleScanSelect(id, target, ev) {
    if (ev) ev.stopPropagation();
    id = String(id);
    if (window.scansState.selected[id]) delete window.scansState.selected[id];
    else window.scansState.selected[id] = true;
    _updateScanDeleteBar();
  }

  // "Select all" header checkbox — the delegator passes data-arg ('true'/
  // 'false') plus the checkbox element, so read the live checked state.
  function toggleScanSelectAll(arg, target) {
    var checked;
    if (target && typeof target.checked === 'boolean') checked = target.checked;
    else checked = (arg === true || arg === 'true');
    window.scansState.selected = {};
    if (checked) {
      (window.scansState._visible || []).forEach(function (s) {
        window.scansState.selected[String(s.id)] = true;
      });
    }
    applyScansView();
  }

  function _selectedScanIds() {
    return Object.keys(window.scansState.selected).map(function (k) { return +k; });
  }

  function _updateScanDeleteBar() {
    var bar = document.getElementById('scans-delete-bar');
    var btn = document.getElementById('scans-delete-btn');
    var n = _selectedScanIds().length;
    if (!bar || !btn) return;
    if (n > 0) {
      bar.style.display = 'flex';
      btn.textContent = 'Delete ' + n + ' scan' + (n === 1 ? '' : 's');
    } else {
      bar.style.display = 'none';
    }
  }

  async function deleteSelectedScans() {
    var ids = _selectedScanIds();
    if (ids.length === 0) return;
    var msg = 'Delete ' + ids.length + ' scan' + (ids.length === 1 ? '' : 's') +
              ' and all associated findings? This cannot be undone.';
    if (!confirm(msg)) return;
    var result = await window.apiDeleteScans(ids);
    if (!result.ok) {
      if (result.error) {
        window.showToast('Delete failed: ' + (result.error.message || 'network error'), 'error');
      } else {
        window.showToast('Delete failed (' + result.status + ')', 'error');
      }
      return;
    }
    window.showToast('Deleted ' + result.data.deleted + ' scan' + (result.data.deleted === 1 ? '' : 's'), 'success');
    window.scansState.selected = {};
    window.cachedScans = null;
    window.cachedFindings = null;
    window.scansState.raw = await window.fetchScans(200);
    if (window.scansState.raw.length === 0) { renderScansPage(); return; }
    applyScansView();
  }

  async function renderScansPage() {
    var c = document.getElementById('content');
    window.scansState.raw = await window.fetchScans(200);

    if (window.scansState.raw.length === 0) {
      c.innerHTML =
        '<div class="empty-state cta">' +
          '<div class="empty-icon">&#128269;</div>' +
          '<h3>No scans yet</h3>' +
          '<p>Upload a .evtx file to get started.</p>' +
          '<button class="btn btn-primary" data-action="openUploadModal">Upload .evtx</button>' +
        '</div>';
      return;
    }

    applyScansView();
  }

  function setScansSort(col) {
    var s = window.scansState;
    if (s.sortCol === col) {
      s.sortDir = (s.sortDir === 'desc') ? 'asc' : 'desc';
    } else {
      s.sortCol = col;
      s.sortDir = 'desc';
    }
    applyScansView();
  }

  function setScansQuery(q) {
    window.scansState.query = q || '';
    applyScansView();
  }

  // Delegator wrapper — pulls the live value from the input element.
  function setScansQueryFromInput(arg, target) {
    setScansQuery(target && target.value);
  }

  function applyScansView() {
    var s = window.scansState;
    var q = s.query.trim().toLowerCase();

    var rows = s.raw.slice();
    if (q) {
      rows = rows.filter(function (sc) {
        var fname = (sc.filename || '').toLowerCase();
        var when  = (sc.scanned_at || '').toLowerCase();
        var host  = (sc.hostname || '').toLowerCase();
        return fname.indexOf(q) >= 0 || when.indexOf(q) >= 0 || host.indexOf(q) >= 0;
      });
    }

    var dir = s.sortDir === 'asc' ? 1 : -1;
    rows.sort(function (a, b) {
      var av, bv;
      switch (s.sortCol) {
        case 'files':    av = a.files_scanned || 0;  bv = b.files_scanned || 0; break;
        case 'events':   av = a.total_events || 0;   bv = b.total_events || 0;  break;
        case 'findings': av = a.total_findings || 0; bv = b.total_findings || 0; break;
        case 'score':    av = a.score != null ? a.score : -1; bv = b.score != null ? b.score : -1; break;
        case 'grade':    av = window._gradeRank(a.score);   bv = window._gradeRank(b.score); break;
        default:         av = a.scanned_at || '';    bv = b.scanned_at || '';
      }
      if (av < bv) return -1 * dir;
      if (av > bv) return  1 * dir;
      return 0;
    });

    s._visible = rows;
    var nSelected = _selectedScanIds().length;
    var deleteBarStyle = nSelected > 0 ? 'flex' : 'none';

    var c = document.getElementById('content');
    c.innerHTML =
      '<div class="page-head">' +
        '<div class="page-head-title"><strong>' + rows.length + '</strong> of ' + s.raw.length + ' scans</div>' +
        '<div class="page-head-actions">' +
          '<button class="btn btn-primary" data-action="openUploadModal">Upload .evtx</button>' +
        '</div>' +
      '</div>' +
      '<div class="filter-bar">' +
        '<input type="search" id="scans-search-box" class="search-box" placeholder="Search by filename, date, or host..." ' +
          'value="' + window.escapeHtml(s.query) + '" data-action-input="setScansQueryFromInput" />' +
      '</div>' +
      '<div id="scans-delete-bar" class="bulk-bar" style="display:' + deleteBarStyle + ';">' +
        '<span class="bulk-bar-count">' + nSelected + ' selected</span>' +
        '<button class="btn btn-danger" id="scans-delete-btn" data-action="deleteSelectedScans">' +
          'Delete ' + nSelected + ' scan' + (nSelected === 1 ? '' : 's') +
        '</button>' +
        '<a class="bulk-bar-clear" data-action="toggleScanSelectAll" data-arg="false">Clear selection</a>' +
      '</div>' +
      '<div class="card" style="padding:0; overflow:hidden;">' +
        (rows.length === 0
          ? '<div style="text-align:center; padding:32px; color:var(--text-muted);">No scans match your search.</div>'
          : _buildScansTable(rows)) +
      '</div>';
    window._restoreSearchFocus('scans-search-box');
  }

  function _buildScansTable(rows) {
    var s = window.scansState;
    var sortable = function (col, label, style) {
      var active = (s.sortCol === col);
      var arrow = active
        ? '<span class="sort-arrow">' + (s.sortDir === 'desc' ? '\u25BC' : '\u25B2') + '</span>'
        : '<span class="sort-arrow inactive">\u21C5</span>';
      return '<th class="sortable"' + (style ? ' style="' + style + '"' : '') +
             ' data-action="setScansSort" data-arg="' + col + '">' + label + arrow + '</th>';
    };

    var allSelected = rows.length > 0 && rows.every(function (r) {
      return s.selected[String(r.id)];
    });
    var headCheckbox = '<th style="width:32px;"><input type="checkbox" ' +
      (allSelected ? 'checked ' : '') +
      'data-action="toggleScanSelectAll" aria-label="Select all scans" /></th>';

    return '<table class="data-table">' +
      '<thead><tr>' +
        headCheckbox +
        sortable('date',     'Date / Time') +
        sortable('files',    'Files') +
        sortable('events',   'Events') +
        sortable('findings', 'Findings') +
        sortable('score',    'Score') +
        sortable('grade',    'Grade') +
        '<th>Duration</th>' +
      '</tr></thead>' +
      '<tbody>' +
      rows.map(function (row) {
        var grade = window._gradeFor(row.score);
        var checked = s.selected[String(row.id)] ? 'checked' : '';
        return '<tr class="clickable" data-action="viewScan" data-arg="' + row.id + '">' +
          '<td data-action="stopClickPropagation"><input type="checkbox" ' + checked +
            ' data-action="toggleScanSelect" data-arg="' + row.id + '" aria-label="Select scan ' + row.id + '" /></td>' +
          '<td><div style="font-weight:500;">' + window.escapeHtml(row.scanned_at || '-') + '</div>' +
            '<div style="font-size:11px; color:var(--text-muted);">' +
              window.escapeHtml(row.filename || 'Unknown') +
              (row.hostname ? ' \u2022 ' + window.escapeHtml(row.hostname) : '') +
            '</div></td>' +
          '<td>' + (row.files_scanned || 0) + '</td>' +
          '<td>' + (row.total_events || 0).toLocaleString() + '</td>' +
          '<td>' + row.total_findings + '</td>' +
          '<td style="font-weight:700; color:' + window.scoreColor(row.score) + '">' +
            (row.score != null ? row.score : '-') + '</td>' +
          '<td>' + (grade ? '<span class="grade-pill grade-' + grade + '">' + grade + '</span>' : '-') + '</td>' +
          '<td style="color:var(--text-muted);">\u2014</td>' +
        '</tr>';
      }).join('') +
      '</tbody></table>';
  }

  async function viewScan(scanId) {
    // scanId may arrive as string via data-arg; normalize.
    scanId = Number(scanId);
    var c = document.getElementById('content');
    var scans = await window.fetchScans(50);
    var scan = scans.find(function (s) { return s.id === scanId; });
    var findings = await window.fetchFindings(scanId);
    var fname = scan ? (scan.filename || 'Unknown') : 'Unknown';
    document.getElementById('page-title').textContent = fname + ' \u2014 Scan #' + scanId;

    c.innerHTML =
      '<div class="back-link" data-action="navigate" data-arg="scans">\u2190 Back to Scans</div>' +
      '<div class="scan-header">' +
        window.statCard('File', fname, scan ? (scan.hostname || '') : '', '') +
        window.statCard('Score', scan ? (scan.score != null ? scan.score : '-') : '-', scan ? (scan.score_label || '') : '', scan ? window.scoreColorClass(scan.score) : '') +
        window.statCard('Findings', findings.length, 'In this scan', '') +
        window.statCard('Date', scan ? scan.scanned_at : '-', '', '') +
      '</div>' +
      '<div class="card">' +
        '<div class="card-title" style="justify-content:space-between;">' +
          '<span>Findings \u2014 ' + window.escapeHtml(fname) + '</span>' +
          '<div style="display:flex; gap:8px;">' +
            '<button class="btn-small" data-action="downloadReport" data-arg="' + scanId + '" data-format="html">Export HTML</button>' +
            '<button class="btn-small" data-action="downloadReport" data-arg="' + scanId + '" data-format="json" style="background:var(--border); color:var(--text);">Export JSON</button>' +
          '</div>' +
        '</div>' +
        (findings.length > 0
          ? buildFindingsTable(findings)
          : '<div style="text-align:center; padding:32px; color:var(--text-muted);">No findings in this scan. All clear.</div>') +
      '</div>';
  }

  // ---------------------------------------------------------------
  // Findings page
  // ---------------------------------------------------------------
  window.findingsState = {
    raw:       [],
    sortCol:   'time',
    sortDir:   'desc',
    sevFilter: 'ALL',
    query:     '',
    expanded:  null,
  };

  var SEV_WEIGHT = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

  async function renderFindingsPage() {
    var c = document.getElementById('content');
    var scans = await window.fetchScans(200);

    var allFindings = [];
    var withFindings = scans.filter(function (s) { return s.total_findings > 0; });
    if (withFindings.length > 0) {
      var batches = await Promise.all(withFindings.map(function (s) {
        return window.fetchFindings(s.id).then(function (fs) {
          return fs.map(function (f, idx) {
            return Object.assign({}, f, {
              _scan_id:   s.id,
              _scan_date: s.scanned_at,
              _uid:       s.id + '-' + idx,
            });
          });
        });
      }));
      batches.forEach(function (b) { allFindings = allFindings.concat(b); });
    }

    window.findingsState.raw       = allFindings;
    window.findingsState.sortCol   = 'time';
    window.findingsState.sortDir   = 'desc';
    window.findingsState.sevFilter = 'ALL';
    window.findingsState.query     = '';
    window.findingsState.expanded  = null;

    if (allFindings.length === 0) {
      c.innerHTML =
        '<div class="empty-state cta">' +
          '<div class="empty-icon">&#10003;</div>' +
          '<h3>No findings</h3>' +
          '<p>Every scan is clean so far. Upload a new log to check again.</p>' +
          '<button class="btn btn-primary" data-action="openUploadModal">Upload .evtx</button>' +
        '</div>';
      return;
    }

    applyFindingsView();
  }

  function setFindingsSort(col) {
    var s = window.findingsState;
    if (s.sortCol === col) {
      s.sortDir = (s.sortDir === 'desc') ? 'asc' : 'desc';
    } else {
      s.sortCol = col;
      s.sortDir = 'desc';
    }
    applyFindingsView();
  }

  function setFindingsFilter(sev) {
    window.findingsState.sevFilter = sev;
    window.findingsState.expanded  = null;
    applyFindingsView();
  }

  function setFindingsQuery(q) {
    window.findingsState.query    = q || '';
    window.findingsState.expanded = null;
    applyFindingsView();
  }

  // Delegator wrapper — pulls the live value from the input element.
  function setFindingsQueryFromInput(arg, target) {
    setFindingsQuery(target && target.value);
  }

  // Stop the click bubbling up to a row-level handler. Used for embedded
  // links inside rows (MITRE links, scan links) so clicking them doesn't
  // also toggle the row's expand/view.
  function stopClickPropagation(arg, target, e) {
    if (e) e.stopPropagation();
  }

  // Click on a scan link inside a row — stop propagation and navigate.
  function viewScanFromLink(arg, target, e) {
    if (e) e.stopPropagation();
    window.viewScan(Number(arg));
  }

  function toggleFindingExpand(uid) {
    window.findingsState.expanded = (window.findingsState.expanded === uid) ? null : uid;
    applyFindingsView();
  }

  function applyFindingsView() {
    var s = window.findingsState;
    var rows = s.raw.slice();

    if (s.sevFilter !== 'ALL') {
      rows = rows.filter(function (f) {
        return (f.severity || 'LOW').toUpperCase() === s.sevFilter;
      });
    }

    var q = s.query.trim().toLowerCase();
    if (q) {
      rows = rows.filter(function (f) {
        var hay = (f.rule || '') + ' ' + (f.details || '') + ' ' + (f.description || '') + ' ' + (f.mitre || '');
        return hay.toLowerCase().indexOf(q) >= 0;
      });
    }

    var dir = s.sortDir === 'asc' ? 1 : -1;
    rows.sort(function (a, b) {
      var av, bv;
      switch (s.sortCol) {
        case 'severity':
          av = SEV_WEIGHT[(a.severity || 'LOW').toUpperCase()] || 0;
          bv = SEV_WEIGHT[(b.severity || 'LOW').toUpperCase()] || 0;
          break;
        case 'rule':
          av = (a.rule || '').toLowerCase();
          bv = (b.rule || '').toLowerCase();
          break;
        case 'scan':
          av = a._scan_date || ''; bv = b._scan_date || ''; break;
        default:
          av = a.timestamp || window._extractTime(a) || '';
          bv = b.timestamp || window._extractTime(b) || '';
      }
      if (av < bv) return -1 * dir;
      if (av > bv) return  1 * dir;
      return 0;
    });

    var counts = { ALL: s.raw.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    s.raw.forEach(function (f) {
      var sv = (f.severity || 'LOW').toUpperCase();
      if (counts[sv] !== undefined) counts[sv]++;
    });

    var pills = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(function (sev) {
      var isActive = s.sevFilter === sev;
      var cls = 'filter-pill' + (isActive ? ' active' : '');
      if (isActive && sev !== 'ALL') cls += ' sev-' + sev.toLowerCase();
      return '<div class="' + cls + '" data-action="setFindingsFilter" data-arg="' + sev + '">' +
        sev + ' <span style="opacity:0.7;">(' + counts[sev] + ')</span></div>';
    }).join('');

    var c = document.getElementById('content');
    c.innerHTML =
      '<div class="page-head">' +
        '<div class="page-head-title"><strong>' + rows.length + '</strong> of ' + s.raw.length + ' findings</div>' +
      '</div>' +
      '<div class="filter-bar">' +
        '<div class="filter-pills">' + pills + '</div>' +
        '<input type="search" id="findings-search-box" class="search-box" placeholder="Search rule, description, or MITRE..." ' +
          'value="' + window.escapeHtml(s.query) + '" data-action-input="setFindingsQueryFromInput" />' +
      '</div>' +
      '<div class="card" style="padding:0; overflow:hidden;">' +
        (rows.length === 0
          ? '<div style="text-align:center; padding:32px; color:var(--text-muted);">No findings match the current filters.</div>'
          : _buildFindingsTable(rows)) +
      '</div>';
    window._restoreSearchFocus('findings-search-box');
  }

  function _sortArrow(col) {
    var s = window.findingsState;
    var active = (s.sortCol === col);
    if (!active) return '<span class="sort-arrow inactive">\u21C5</span>';
    return '<span class="sort-arrow">' + (s.sortDir === 'desc' ? '\u25BC' : '\u25B2') + '</span>';
  }

  function _buildFindingsTable(findings) {
    var expanded = window.findingsState.expanded;
    var th = function (col, label) {
      return '<th class="sortable" data-action="setFindingsSort" data-arg="' + col + '">' + label + _sortArrow(col) + '</th>';
    };

    return '<table class="data-table">' +
      '<thead><tr>' +
        th('time', 'Timestamp') +
        '<th>Event ID</th>' +
        th('severity', 'Severity') +
        th('rule', 'Rule') +
        '<th>MITRE ATT&amp;CK</th>' +
        '<th>Description</th>' +
        th('scan', 'Scan') +
      '</tr></thead>' +
      '<tbody>' +
      findings.map(function (f) {
        var sev = (f.severity || 'LOW').toUpperCase();
        var rule = f.rule || 'Unknown';
        var mitre = f.mitre || window.mitreMap[rule] || '';
        var mitreTag = mitre
          ? '<span class="mitre-tag"><a href="https://attack.mitre.org/techniques/' +
            mitre.replace('.', '/') + '/" target="_blank" data-action="stopClickPropagation" data-default="allow">' + mitre + '</a></span>'
          : '-';
        var details = f.details || f.description || '';
        var shortDetails = details.length > 100 ? details.substring(0, 100) + '\u2026' : details;
        var time = f.timestamp || window._extractTime(f) || '-';
        var isOpen = expanded === f._uid;

        var main = '<tr class="clickable sev-row sev-' + sev.toLowerCase() + '" ' +
                   'data-action="toggleFindingExpand" data-arg="' + f._uid + '">' +
          '<td class="col-time">' + window.escapeHtml(time) + '</td>' +
          '<td class="mono">' + window.escapeHtml(f.event_id || '-') + '</td>' +
          '<td><span class="pill pill-' + sev.toLowerCase() + '">' + sev + '</span></td>' +
          '<td style="font-weight:500;">' + window.escapeHtml(rule) + '</td>' +
          '<td>' + mitreTag + '</td>' +
          '<td style="color:var(--text-muted);">' + window.escapeHtml(shortDetails) + '</td>' +
          '<td><a href="#" data-action="viewScanFromLink" data-arg="' + f._scan_id + '" ' +
            'style="color:var(--accent); text-decoration:none; font-size:12px;">#' + f._scan_id + '</a>' +
            '<div style="font-size:10px; color:var(--text-muted);">' + window.escapeHtml((f._scan_date || '').split(' ')[0] || '') + '</div></td>' +
        '</tr>';

        if (!isOpen) return main;
        return main + _expandRow(f, 7);
      }).join('') +
      '</tbody></table>';
  }

  function _expandRow(f, colspan) {
    var rule = f.rule || 'Unknown';
    var mitre = f.mitre || window.mitreMap[rule] || '';
    var rem = window.REMEDIATION[rule] || 'Investigate the event in its surrounding context. Correlate with other logs from the same host and timeframe.';
    var desc = f.description || '';
    var details = f.details || '';
    var rawXml = f.raw_xml || '';
    var xmlBtn = rawXml
      ? '<button class="btn btn-secondary" style="margin-top:10px; font-size:12px;" ' +
        'data-action="openFindingsPageDrawerByUid" data-arg="' + window.escapeHtml(f._uid) + '">View raw event XML</button>'
      : '';

    return '<tr class="expand-row"><td colspan="' + colspan + '">' +
      '<div class="expand-grid">' +
        _expandField('Rule', window.escapeHtml(rule)) +
        _expandField('Severity', (f.severity || 'LOW').toUpperCase()) +
        _expandField('Timestamp', window.escapeHtml(f.timestamp || window._extractTime(f) || '-'), 'mono') +
        _expandField('Event ID', window.escapeHtml(f.event_id || '-'), 'mono') +
        _expandField('MITRE ATT&amp;CK', mitre
          ? '<a href="https://attack.mitre.org/techniques/' + mitre.replace('.', '/') + '/" target="_blank" style="color:var(--accent); text-decoration:none;" class="mono">' + mitre + '</a>'
          : '-') +
        _expandField('Source Scan',
          '<a href="#" data-action="viewScan" data-arg="' + f._scan_id + '" style="color:var(--accent); text-decoration:none;">#' + f._scan_id + '</a> \u2014 ' + window.escapeHtml(f._scan_date || '')) +
      '</div>' +
      (desc ? '<div class="expand-field" style="margin-bottom:10px;"><div class="label">Description</div><div class="val">' + window.escapeHtml(desc) + '</div></div>' : '') +
      (details ? '<div class="expand-field" style="margin-bottom:10px;"><div class="label">Event Details</div><div class="val mono" style="white-space:pre-wrap;">' + window.escapeHtml(details) + '</div></div>' : '') +
      '<div class="remediation">' +
        '<div class="rem-label">Remediation</div>' +
        window.escapeHtml(rem) +
      '</div>' +
      xmlBtn +
    '</td></tr>';
  }

  function openFindingsPageDrawerByUid(uid) {
    var f = (window.findingsState.raw || []).find(function (x) { return x._uid === uid; });
    if (f) openFindingDrawer(f);
  }

  function _expandField(label, htmlVal, extraCls) {
    return '<div class="expand-field">' +
      '<div class="label">' + label + '</div>' +
      '<div class="val ' + (extraCls || '') + '">' + htmlVal + '</div>' +
    '</div>';
  }

  // ---------------------------------------------------------------
  // Finding drawer — shared slide-in detail panel
  // ---------------------------------------------------------------
  function openFindingDrawer(f) {
    if (!f) return;
    var sev  = (f.severity || 'LOW').toUpperCase();
    var rule = f.rule || 'Unknown';
    var mitre = f.mitre || window.mitreMap[rule] || '';
    var mitreLink = mitre
      ? '<a class="mitre-tag" href="https://attack.mitre.org/techniques/' +
        encodeURIComponent(mitre.replace('.', '/')) + '" target="_blank" rel="noopener">' +
        window.escapeHtml(mitre) + '</a>'
      : '<span style="color:var(--text-muted); font-size:12px;">\u2014</span>';

    document.getElementById('drawer-rule').textContent = rule;
    document.getElementById('drawer-sev-line').innerHTML =
      '<span class="sev-pill sev-' + sev.toLowerCase() + '">' + sev + '</span>' +
      mitreLink;

    var rem = window.REMEDIATION[rule] || 'Investigate the event in its surrounding context. Correlate with other logs from the same host and timeframe.';
    var time = f.timestamp || window._extractTime(f) || '\u2014';
    var eid  = (f.event_id != null && f.event_id !== '') ? f.event_id : '\u2014';
    var desc = f.description || '';
    var details = f.details || '';
    var rawXml = f.raw_xml || '';

    document.getElementById('drawer-body').innerHTML =
      '<div class="finding-drawer-section">' +
        '<div class="sec-label">Metadata</div>' +
        '<div class="finding-drawer-grid">' +
          '<div><div class="k">Timestamp</div><div class="v">' + window.escapeHtml(String(time)) + '</div></div>' +
          '<div><div class="k">Event ID</div><div class="v">' + window.escapeHtml(String(eid)) + '</div></div>' +
        '</div>' +
      '</div>' +

      (desc ? '<div class="finding-drawer-section">' +
        '<div class="sec-label">Description</div>' +
        '<div style="font-size:13px; color:var(--text); line-height:1.5;">' + window.escapeHtml(desc) + '</div>' +
      '</div>' : '') +

      (details ? '<div class="finding-drawer-section">' +
        '<div class="sec-label">Event Details</div>' +
        '<div class="finding-drawer-details">' + window.escapeHtml(details) + '</div>' +
      '</div>' : '') +

      (rawXml ? '<div class="finding-drawer-section">' +
        '<details class="raw-xml-toggle">' +
          '<summary class="sec-label" style="cursor:pointer; list-style:revert;">Raw Event XML</summary>' +
          '<div class="finding-drawer-details" style="max-height:320px; margin-top:8px;">' + window.escapeHtml(rawXml) + '</div>' +
        '</details>' +
      '</div>' : '') +

      '<div class="finding-drawer-section">' +
        '<div class="sec-label">Remediation</div>' +
        '<div class="remediation">' +
          '<div class="rem-label">Recommended action</div>' +
          window.escapeHtml(rem) +
        '</div>' +
      '</div>';

    document.getElementById('finding-drawer').classList.add('open');
    document.getElementById('finding-drawer-backdrop').classList.add('open');
    document.body.style.overflow = 'hidden';
  }

  function closeFindingDrawer() {
    document.getElementById('finding-drawer').classList.remove('open');
    document.getElementById('finding-drawer-backdrop').classList.remove('open');
    document.body.style.overflow = '';
  }

  // Esc closes the drawer.
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      var drawer = document.getElementById('finding-drawer');
      if (drawer && drawer.classList.contains('open')) closeFindingDrawer();
    }
  });

  // ---------------------------------------------------------------
  // Scan-detail findings table (used by viewScan)
  // ---------------------------------------------------------------
  var _scanDetailFindings = [];

  function openScanDetailFindingByIdx(idx) {
    var f = _scanDetailFindings[idx];
    if (f) openFindingDrawer(f);
  }

  function buildFindingsTable(findings) {
    _scanDetailFindings = findings;
    return '<table class="findings-table"><thead><tr>' +
      '<th>Time</th><th>Severity</th><th>Rule</th><th>MITRE ATT&CK</th><th>Description</th>' +
      '</tr></thead><tbody>' +
      findings.map(function (f, i) {
        var sev = (f.severity || 'LOW').toUpperCase();
        var rule = f.rule || 'Unknown';
        var mitre = f.mitre || window.mitreMap[rule] || '';
        var mitreLink = mitre
          ? '<span class="mitre-tag"><a href="https://attack.mitre.org/techniques/' +
            mitre.replace('.', '/') + '/" target="_blank" data-action="stopClickPropagation" data-default="allow">' + mitre + '</a></span>'
          : '-';
        var details = f.details || f.description || '';
        var shortDetails = details.length > 120 ? details.substring(0, 120) + '...' : details;
        var timeMatch = details.match(/(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})/);
        var time = f.timestamp || (timeMatch ? timeMatch[1] + ' ' + timeMatch[2] : '-');

        return '<tr class="clickable" data-action="openScanDetailFindingByIdx" data-arg="' + i + '" style="cursor:pointer;">' +
          '<td class="col-time">' + time + '</td>' +
          '<td class="col-severity"><span class="pill pill-' + sev.toLowerCase(1) + '">' + sev + '</span></td>' +
          '<td class="col-rule">' + rule + '</td>' +
          '<td class="col-mitre">' + mitreLink + '</td>' +
          '<td>' + window.escapeHtml(shortDetails) + '</td></tr>';
      }).join('') +
      '</tbody></table>';
  }

  // ---------------------------------------------------------------
  // Expose
  // ---------------------------------------------------------------
  window.toggleScanSelect             = toggleScanSelect;
  window.toggleScanSelectAll          = toggleScanSelectAll;
  window.deleteSelectedScans          = deleteSelectedScans;
  window.renderScansPage              = renderScansPage;
  window.setScansSort                 = setScansSort;
  window.setScansQuery                = setScansQuery;
  window.setScansQueryFromInput       = setScansQueryFromInput;
  window.setFindingsQueryFromInput    = setFindingsQueryFromInput;
  window.stopClickPropagation         = stopClickPropagation;
  window.viewScanFromLink             = viewScanFromLink;
  window.applyScansView               = applyScansView;
  window.viewScan                     = viewScan;
  window.renderFindingsPage           = renderFindingsPage;
  window.setFindingsSort              = setFindingsSort;
  window.setFindingsFilter            = setFindingsFilter;
  window.setFindingsQuery             = setFindingsQuery;
  window.toggleFindingExpand          = toggleFindingExpand;
  window.applyFindingsView            = applyFindingsView;
  window._expandField                 = _expandField;
  window._expandRow                   = _expandRow;
  window.openFindingsPageDrawerByUid  = openFindingsPageDrawerByUid;
  window.openFindingDrawer            = openFindingDrawer;
  window.closeFindingDrawer           = closeFindingDrawer;
  window.openScanDetailFindingByIdx   = openScanDetailFindingByIdx;
  window.buildFindingsTable           = buildFindingsTable;
})();
