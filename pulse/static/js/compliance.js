// compliance.js — Compliance page. Shows per-framework coverage for
// NIST Cybersecurity Framework (Identify / Protect / Detect / Respond /
// Recover) and ISO 27001 Annex A, plus a per-rule lookup table so the
// analyst can see which Pulse rules back each control.
'use strict';

import { apiGetCompliance } from './api.js';
import { escapeHtml } from './dashboard.js';

export async function renderCompliancePage() {
  var c = document.getElementById('content');
  c.innerHTML = '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading...</div>';

  var data;
  try {
    data = await apiGetCompliance();
  } catch (e) {
    c.innerHTML =
      '<div class="card" style="border-color:var(--severity-high, #e67e22);">' +
        '<div class="section-label" style="color:var(--severity-high, #e67e22);">Failed to load compliance data</div>' +
        '<p style="color:var(--text-muted); font-size:13px; margin:0;">' +
          escapeHtml(e && e.message ? e.message : String(e)) +
        '</p>' +
      '</div>';
    return;
  }

  var nistCards = _renderNistCards(data.nist_csf || {});
  var isoCards  = _renderIsoCards(data.iso_27001 || {});
  var rulesTable = _renderRulesTable(data.rules || []);
  var hero = _renderHero(data.rules || []);

  c.innerHTML =
    '<div class="page-head">' +
      '<div class="page-head-title">Coverage across compliance frameworks</div>' +
    '</div>' +
    hero +
    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">NIST Cybersecurity Framework</div>' +
      '<p style="color:var(--text-muted); font-size:13px; margin:0 0 14px;">' +
        'Detection rules grouped by the five CSF functions. A rule counts as ' +
        '<em>enabled</em> when it\u2019s not in <code>disabled_rules</code> ' +
        'in <code>pulse.yaml</code>.' +
      '</p>' +
      '<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:12px;">' +
        nistCards +
      '</div>' +
    '</div>' +
    '<div class="card" style="margin-bottom:16px;">' +
      '<div class="section-label">ISO 27001 Annex A</div>' +
      '<p style="color:var(--text-muted); font-size:13px; margin:0 0 14px;">' +
        'Pulse rules grouped by Annex A clause. Blank clauses mean no current ' +
        'detection rule maps there \u2014 an open area for future coverage.' +
      '</p>' +
      '<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(260px, 1fr)); gap:12px;">' +
        isoCards +
      '</div>' +
    '</div>' +
    '<div class="card" style="padding:0; overflow:hidden;">' +
      '<div class="section-label" style="padding:16px 20px 8px;">Per-rule mappings</div>' +
      rulesTable +
    '</div>';
}

function _renderHero(rules) {
  var total    = rules.length;
  var enabled  = 0;
  var disabled = 0;
  for (var i = 0; i < rules.length; i++) {
    if (rules[i].enabled) { enabled++; } else { disabled++; }
  }
  // Pulse does not currently model Waived / N/A control states, so those
  // segments ship as zero-width placeholders with a small note below the bar.
  var waived = 0;
  var na     = 0;
  var pct = total ? Math.round((enabled / total) * 100) : 0;
  var circumference = 2 * Math.PI * 56; // r = 56
  var dash = (pct / 100) * circumference;
  var ringColor =
    pct >= 80 ? 'var(--severity-low, #10b981)' :
    pct >= 50 ? 'var(--severity-medium, #d29922)' :
                'var(--severity-high, #f85149)';
  var enabledPct  = total ? (enabled  / total) * 100 : 0;
  var disabledPct = total ? (disabled / total) * 100 : 0;

  return '<div class="card compliance-hero" style="margin-bottom:16px;">' +
    '<div class="compliance-gauge">' +
      '<svg viewBox="0 0 140 140" width="140" height="140">' +
        '<circle cx="70" cy="70" r="56" fill="none" stroke="var(--bg-3, #30363d)" stroke-width="12"></circle>' +
        '<circle cx="70" cy="70" r="56" fill="none" stroke="' + ringColor + '" stroke-width="12" ' +
          'stroke-linecap="round" ' +
          'stroke-dasharray="' + dash.toFixed(2) + ' ' + circumference.toFixed(2) + '" ' +
          'transform="rotate(-90 70 70)"></circle>' +
      '</svg>' +
      '<div class="compliance-gauge-label">' +
        '<div class="compliance-gauge-pct">' + pct + '%</div>' +
        '<div class="compliance-gauge-sub">COVERAGE</div>' +
      '</div>' +
    '</div>' +
    '<div class="compliance-hero-body">' +
      '<div class="section-label">Overall rule coverage</div>' +
      '<div style="font-size:13px; color:var(--text-muted); margin-bottom:10px;">' +
        '<strong style="color:var(--text-high);">' + enabled + '</strong> of ' +
        '<strong style="color:var(--text-high);">' + total + '</strong> detection rules are enabled across all frameworks.' +
      '</div>' +
      '<div class="compliance-stack-bar">' +
        '<div class="stack-seg stack-enabled"  style="width:' + enabledPct.toFixed(2)  + '%;" title="Enabled: ' + enabled + '"></div>' +
        '<div class="stack-seg stack-disabled" style="width:' + disabledPct.toFixed(2) + '%;" title="Disabled: ' + disabled + '"></div>' +
      '</div>' +
      '<div class="compliance-stack-legend">' +
        '<span><i class="dot dot-enabled"></i> Enabled <strong>' + enabled + '</strong></span>' +
        '<span><i class="dot dot-disabled"></i> Disabled <strong>' + disabled + '</strong></span>' +
        '<span class="muted"><i class="dot dot-waived"></i> Waived <strong>' + waived + '</strong></span>' +
        '<span class="muted"><i class="dot dot-na"></i> N/A <strong>' + na + '</strong></span>' +
      '</div>' +
      '<div style="font-size:11px; color:var(--text-dim); margin-top:6px;">' +
        'Waived and N/A are placeholders — Pulse does not yet track formally waived controls.' +
      '</div>' +
    '</div>' +
  '</div>';
}

function _renderNistCards(nist) {
  var order = ['Identify', 'Protect', 'Detect', 'Respond', 'Recover'];
  return order.map(function (label) {
    var bucket = nist[label] || { subcategories: {}, rules: [], enabled: 0, disabled: 0 };
    var total = bucket.enabled + bucket.disabled;
    var subs = Object.keys(bucket.subcategories || {}).sort();
    var subList = subs.length
      ? '<ul style="margin:6px 0 0; padding-left:18px; color:var(--text-muted); font-size:12px;">' +
          subs.map(function (s) {
            return '<li><code>' + escapeHtml(s) + '</code> \u2014 ' +
                     bucket.subcategories[s].length + ' rule' +
                     (bucket.subcategories[s].length === 1 ? '' : 's') +
                   '</li>';
          }).join('') +
        '</ul>'
      : '<p style="color:var(--text-muted); font-size:12px; margin:6px 0 0;">No rules mapped.</p>';
    return '<div style="border:1px solid var(--border); border-radius:6px; padding:14px; background:var(--bg);">' +
             '<div style="font-weight:600; font-size:14px;">' + escapeHtml(label) + '</div>' +
             '<div style="font-size:22px; font-weight:700; color:' + (total ? 'var(--accent)' : 'var(--text-muted)') + '; margin:4px 0 2px;">' +
               bucket.enabled + ' / ' + total +
             '</div>' +
             '<div style="color:var(--text-muted); font-size:11px; text-transform:uppercase; letter-spacing:1px;">rules enabled</div>' +
             subList +
           '</div>';
  }).join('');
}

function _renderIsoCards(iso) {
  var labels = Object.keys(iso).sort();
  if (!labels.length) {
    return '<p style="color:var(--text-muted); font-size:13px; margin:0;">No ISO 27001 mappings defined.</p>';
  }
  return labels.map(function (label) {
    var bucket = iso[label];
    var total = bucket.enabled + bucket.disabled;
    var ctrls = Object.keys(bucket.controls || {}).sort();
    var ctrlList = ctrls.length
      ? '<ul style="margin:6px 0 0; padding-left:18px; color:var(--text-muted); font-size:12px;">' +
          ctrls.map(function (c) {
            return '<li><code>' + escapeHtml(c) + '</code> \u2014 ' +
                     bucket.controls[c].length + ' rule' +
                     (bucket.controls[c].length === 1 ? '' : 's') +
                   '</li>';
          }).join('') +
        '</ul>'
      : '';
    return '<div style="border:1px solid var(--border); border-radius:6px; padding:14px; background:var(--bg);">' +
             '<div style="font-weight:600; font-size:14px;">' + escapeHtml(label) + '</div>' +
             '<div style="font-size:22px; font-weight:700; color:var(--accent); margin:4px 0 2px;">' +
               bucket.enabled + ' / ' + total +
             '</div>' +
             '<div style="color:var(--text-muted); font-size:11px; text-transform:uppercase; letter-spacing:1px;">rules enabled</div>' +
             ctrlList +
           '</div>';
  }).join('');
}

function _renderRulesTable(rules) {
  if (!rules.length) {
    return '<div style="padding:32px 20px; text-align:center; color:var(--text-muted);">No rules defined.</div>';
  }
  var rows = rules.map(function (r) {
    var sev = (r.severity || '').toUpperCase();
    var sevClass = 'badge badge-' + (sev.toLowerCase() || 'low');
    var statusBadge = r.enabled
      ? '<span class="badge badge-low">enabled</span>'
      : '<span class="badge" style="background:rgba(255,255,255,0.08); color:var(--text-muted);">disabled</span>';
    return '<tr>' +
      '<td>' + escapeHtml(r.name) + '</td>' +
      '<td><span class="' + sevClass + '">' + escapeHtml(sev || 'LOW') + '</span></td>' +
      '<td><code>' + escapeHtml(r.nist_csf || '\u2014') + '</code></td>' +
      '<td><code>' + escapeHtml(r.iso_27001 || '\u2014') + '</code></td>' +
      '<td><code>' + escapeHtml(r.mitre || '\u2014') + '</code></td>' +
      '<td>' + statusBadge + '</td>' +
    '</tr>';
  }).join('');

  return '<table class="data-table" style="width:100%;">' +
    '<thead><tr>' +
      '<th>Rule</th>' +
      '<th>Severity</th>' +
      '<th>NIST CSF</th>' +
      '<th>ISO 27001</th>' +
      '<th>MITRE</th>' +
      '<th>Status</th>' +
    '</tr></thead>' +
    '<tbody>' + rows + '</tbody>' +
  '</table>';
}
