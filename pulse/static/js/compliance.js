// compliance.js — Compliance page. Shows per-framework coverage for
// NIST Cybersecurity Framework (Identify / Protect / Detect / Respond /
// Recover) and ISO 27001 Annex A, plus a per-rule lookup table so the
// analyst can see which Pulse rules back each control.
'use strict';

import { apiGetCompliance, apiGetRulesDetails } from './api.js';
import { escapeHtml } from './dashboard.js';

// Thresholds for the Coverage Gaps panel. Tuned for an install that's
// been running long enough to have meaningful counts; small installs
// where every rule has 0–2 hits will read as "all silent" — that's
// accurate, the operator just hasn't accumulated signal yet.
const NOISY_MIN_HITS  = 20;   // rule must fire this often to count as noisy
const NOISY_MIN_FP_RATE = 0.4; // and have at least 40% of reviewed hits be FPs

export async function renderCompliancePage() {
  var c = document.getElementById('content');
  c.innerHTML = '<div style="text-align:center; padding:48px; color:var(--text-muted);">Loading...</div>';

  var data, ruleDetails;
  try {
    var settled = await Promise.allSettled([apiGetCompliance(), apiGetRulesDetails()]);
    if (settled[0].status !== 'fulfilled') throw settled[0].reason;
    data = settled[0].value;
    // Rule-details enriches the page with hits / FP counts so the
    // Coverage Gaps section can flag silent and noisy rules. If it
    // fails we still render the rest of the page \u2014 gaps just degrades
    // to "MITRE uncovered only".
    ruleDetails = settled[1].status === 'fulfilled'
      ? (settled[1].value.rules || [])
      : [];
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
  var gaps = _computeCoverageGaps(ruleDetails.length ? ruleDetails : (data.rules || []));
  var gapKpi = _renderGapKpi(gaps);
  var gapsCard = _renderCoverageGaps(gaps);

  c.innerHTML =
    '<div class="page-head">' +
      '<div class="page-head-title">Coverage across compliance frameworks</div>' +
    '</div>' +
    gapKpi +
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
    gapsCard +
    '<div class="card" style="padding:0; overflow:hidden;">' +
      '<div class="section-label" style="padding:16px 20px 8px;">Per-rule mappings</div>' +
      rulesTable +
    '</div>';
}

// ---------------------------------------------------------------
// Coverage Gaps \u2014 the actionable companion to the static framework cards
// ---------------------------------------------------------------
//
// Three signals, all derived from the rule catalog itself:
//   1. Uncovered MITRE techniques \u2014 techniques referenced by any rule
//      in the catalog but not by any *enabled* rule. The fix is to
//      re-enable a rule, not to write new detection code.
//   2. Silent rules \u2014 enabled rules that have never fired across the
//      visible scan history. Either truly nothing matches or the rule's
//      pattern is wrong; either way the operator should review it.
//   3. Noisy rules \u2014 enabled rules with high hit count AND high FP rate.
//      The detection is firing but analysts keep marking it false-positive,
//      which usually means the threshold needs tuning or a whitelist
//      entry would suppress the noise more cleanly.

function _computeCoverageGaps(rules) {
  // Build the set of MITRE techniques present in the catalog vs covered
  // by an enabled rule. Rules with no mitre tag at all are skipped \u2014 they
  // can't contribute to coverage either way.
  var allTechniques = {};   // technique id -> { rule_count, name (best-effort) }
  var coveredTechniques = {}; // technique id -> true
  rules.forEach(function (r) {
    var tech = (r.mitre || '').trim();
    if (!tech) return;
    if (!allTechniques[tech]) allTechniques[tech] = { rule_count: 0, sample_rule: r.name };
    allTechniques[tech].rule_count += 1;
    if (r.enabled) coveredTechniques[tech] = true;
  });
  var uncovered = Object.keys(allTechniques)
    .filter(function (t) { return !coveredTechniques[t]; })
    .sort()
    .map(function (t) {
      return { id: t, sample_rule: allTechniques[t].sample_rule };
    });

  // Silent + noisy use rule_details fields. If hits_total / fp_count are
  // missing (unenriched fallback), all rules will look silent \u2014 that's
  // OK, the table will just say "no hit data available" downstream.
  var silent = rules
    .filter(function (r) { return r.enabled && (r.hits_total || 0) === 0; })
    .map(function (r) { return { name: r.name, last_fired: r.last_fired || null }; })
    .sort(function (a, b) { return a.name.localeCompare(b.name); });

  var noisy = rules
    .filter(function (r) {
      if (!r.enabled) return false;
      var hits = r.hits_total || 0;
      if (hits < NOISY_MIN_HITS) return false;
      var fp = r.fp_count || 0;
      var tp = r.tp_count || 0;
      var reviewed = fp + tp;
      // Need at least a few reviewed findings before we can call the
      // FP rate meaningful \u2014 otherwise a single FP on a 30-hit rule
      // would register as 100% noise.
      if (reviewed < 3) return false;
      var rate = fp / reviewed;
      return rate >= NOISY_MIN_FP_RATE;
    })
    .map(function (r) {
      var fp = r.fp_count || 0;
      var tp = r.tp_count || 0;
      var reviewed = fp + tp;
      return {
        name: r.name,
        hits: r.hits_total || 0,
        fp: fp,
        reviewed: reviewed,
        fp_rate: reviewed > 0 ? (fp / reviewed) : 0,
      };
    })
    .sort(function (a, b) { return b.fp_rate - a.fp_rate; });

  return {
    uncovered: uncovered,
    silent:    silent,
    noisy:     noisy,
    have_hit_data: rules.some(function (r) { return r.hits_total !== undefined; }),
  };
}

function _renderGapKpi(gaps) {
  var n = gaps.uncovered.length;
  var label = n + ' technique' + (n === 1 ? '' : 's') + ' uncovered';
  var sub = n === 0
    ? 'Every catalog technique is backed by at least one enabled rule.'
    : 'Re-enable a rule below or write a new detection to close the gap.';
  // Amber/orange when there are gaps; muted neutral when fully covered.
  var tone = n > 0 ? 'tone-warn' : 'tone-ok';
  return '<div class="compliance-gap-kpi ' + tone + '">' +
    '<div class="compliance-gap-kpi-label">Coverage gaps</div>' +
    '<div class="compliance-gap-kpi-value">' + escapeHtml(label) + '</div>' +
    '<div class="compliance-gap-kpi-sub">' + escapeHtml(sub) + '</div>' +
  '</div>';
}

function _renderCoverageGaps(gaps) {
  // Three sub-panels stacked. Each renders its own empty-state copy so a
  // clean install (zero of any kind) reads as "you're good" rather than
  // an unexplained absence of content.
  return '<div class="card" style="margin-bottom:16px;">' +
    '<div class="section-label">Coverage gaps</div>' +
    '<p style="color:var(--text-muted); font-size:13px; margin:0 0 14px;">' +
      'Three signals worth reviewing. Compliance percentages above only count ' +
      '<em>mapped</em> rules \u2014 these lists tell you whether those rules are ' +
      'actually doing the job.' +
    '</p>' +
    _renderUncoveredTechniques(gaps.uncovered) +
    _renderSilentRules(gaps.silent, gaps.have_hit_data) +
    _renderNoisyRules(gaps.noisy, gaps.have_hit_data) +
  '</div>';
}

function _renderUncoveredTechniques(uncovered) {
  if (uncovered.length === 0) {
    return '<div class="gap-block">' +
      '<div class="gap-block-head">' +
        '<span class="gap-block-title">Uncovered techniques</span>' +
        '<span class="gap-block-count gap-block-count-ok">0</span>' +
      '</div>' +
      '<p class="gap-block-empty">' +
        'Every MITRE technique referenced by a rule in the catalog is backed ' +
        'by at least one enabled rule.' +
      '</p>' +
    '</div>';
  }
  var rows = uncovered.map(function (u) {
    return '<li>' +
      '<code class="gap-tech-id">' + escapeHtml(u.id) + '</code> ' +
      '<span class="gap-tech-sample">disabled rule: ' +
        escapeHtml(u.sample_rule || '\u2014') +
      '</span>' +
    '</li>';
  }).join('');
  return '<div class="gap-block">' +
    '<div class="gap-block-head">' +
      '<span class="gap-block-title">Uncovered techniques</span>' +
      '<span class="gap-block-count gap-block-count-warn">' + uncovered.length + '</span>' +
    '</div>' +
    '<p class="gap-block-hint">' +
      'These MITRE ATT&amp;CK techniques have a rule in the catalog but no <em>enabled</em> ' +
      'rule covering them. Re-enable a rule from the Rules page to close each gap.' +
    '</p>' +
    '<ul class="gap-list">' + rows + '</ul>' +
  '</div>';
}

function _renderSilentRules(silent, have_hit_data) {
  if (!have_hit_data) {
    return '<div class="gap-block">' +
      '<div class="gap-block-head">' +
        '<span class="gap-block-title">Silent rules</span>' +
      '</div>' +
      '<p class="gap-block-empty">No hit data available.</p>' +
    '</div>';
  }
  if (silent.length === 0) {
    return '<div class="gap-block">' +
      '<div class="gap-block-head">' +
        '<span class="gap-block-title">Silent rules</span>' +
        '<span class="gap-block-count gap-block-count-ok">0</span>' +
      '</div>' +
      '<p class="gap-block-empty">' +
        'Every enabled rule has fired at least once across the recorded scans.' +
      '</p>' +
    '</div>';
  }
  var rows = silent.map(function (r) {
    return '<li>' +
      '<span class="gap-rule-name">' + escapeHtml(r.name) + '</span>' +
      '<span class="gap-rule-meta">No hits across recorded scans</span>' +
    '</li>';
  }).join('');
  return '<div class="gap-block">' +
    '<div class="gap-block-head">' +
      '<span class="gap-block-title">Silent rules, may need configuration review</span>' +
      '<span class="gap-block-count gap-block-count-warn">' + silent.length + '</span>' +
    '</div>' +
    '<p class="gap-block-hint">' +
      'Enabled rules that have never matched. Either nothing in your environment ' +
      'triggers them (fine) or the rule\u2019s pattern needs review.' +
    '</p>' +
    '<ul class="gap-list">' + rows + '</ul>' +
  '</div>';
}

function _renderNoisyRules(noisy, have_hit_data) {
  if (!have_hit_data) return '';
  if (noisy.length === 0) {
    return '<div class="gap-block">' +
      '<div class="gap-block-head">' +
        '<span class="gap-block-title">Noisy rules</span>' +
        '<span class="gap-block-count gap-block-count-ok">0</span>' +
      '</div>' +
      '<p class="gap-block-empty">' +
        'No rule has hit the noisy threshold (' + NOISY_MIN_HITS +
        '+ hits and \u2265' + Math.round(NOISY_MIN_FP_RATE * 100) + '% false-positive rate).' +
      '</p>' +
    '</div>';
  }
  var rows = noisy.map(function (r) {
    var pct = Math.round(r.fp_rate * 100);
    return '<li>' +
      '<span class="gap-rule-name">' + escapeHtml(r.name) + '</span>' +
      '<span class="gap-rule-meta">' +
        r.hits + ' hits \u00b7 ' +
        '<span class="gap-fp-rate">' + pct + '% FP</span> ' +
        '<span class="muted">(' + r.fp + '/' + r.reviewed + ' reviewed)</span>' +
      '</span>' +
    '</li>';
  }).join('');
  return '<div class="gap-block">' +
    '<div class="gap-block-head">' +
      '<span class="gap-block-title">Noisy rules, consider tuning</span>' +
      '<span class="gap-block-count gap-block-count-warn">' + noisy.length + '</span>' +
    '</div>' +
    '<p class="gap-block-hint">' +
      'Rules that fire often AND are frequently marked false-positive. ' +
      'Tighten the rule\u2019s threshold or add whitelist entries for the ' +
      'specific accounts / IPs / services that keep tripping it.' +
    '</p>' +
    '<ul class="gap-list">' + rows + '</ul>' +
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
