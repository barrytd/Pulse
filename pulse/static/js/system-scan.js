// system-scan.js — Quick "Scan My System" modal that POSTs /api/scan/system
// and refreshes the dashboard on completion. Lives alongside upload.js;
// does NOT touch the .evtx upload flow.
'use strict';

import {
  apiScanSystem,
  invalidateScansCache,
  invalidateFindingsCache,
} from './api.js';
import { navigate, getCurrentPage } from './navigation.js';
import { showToast, toastError } from './dashboard.js';

export function openSystemScanModal() {
  var modal = document.getElementById('system-scan-modal');
  if (!modal) return;
  var status = document.getElementById('sys-scan-status');
  status.textContent = '';
  status.className = 'upload-status';
  document.getElementById('sys-scan-run').disabled = false;
  document.getElementById('sys-scan-range').value = '7';
  document.getElementById('sys-scan-custom-row').style.display = 'none';
  document.getElementById('sys-scan-alert').checked = true;
  modal.classList.add('open');
}

export function closeSystemScanModal() {
  var modal = document.getElementById('system-scan-modal');
  if (modal) modal.classList.remove('open');
}

function _computeDays() {
  var range = document.getElementById('sys-scan-range').value;
  if (range !== 'custom') {
    return parseInt(range, 10);
  }
  var amount = parseInt(document.getElementById('sys-scan-custom-amount').value, 10);
  if (isNaN(amount) || amount < 1) return 1;
  var unit = document.getElementById('sys-scan-custom-unit').value;
  if (unit === 'hours') {
    // API takes whole days — convert hours up, min 1.
    return Math.max(1, Math.ceil(amount / 24));
  }
  return Math.min(365, amount);
}

export async function runSystemScan() {
  var status = document.getElementById('sys-scan-status');
  var runBtn = document.getElementById('sys-scan-run');
  runBtn.disabled = true;
  status.textContent = 'Scanning local Windows event logs...';
  status.className = 'upload-status';

  var days  = _computeDays();
  var alert = document.getElementById('sys-scan-alert').checked;

  try {
    var result = await apiScanSystem(days, alert);
    if (!result.ok) {
      var detail = (result.data && result.data.detail) || 'System scan failed.';
      status.textContent = detail;
      status.className = 'upload-status error';
      runBtn.disabled = false;
      toastError(detail);
      return;
    }
    var r = result.data;
    status.textContent =
      r.total_findings + ' finding(s) from ' +
      r.total_events + ' event(s) across ' +
      r.files_scanned + ' file(s). Score: ' + r.score;
    status.className = 'upload-status success';
    invalidateScansCache();
    invalidateFindingsCache();
    showToast('System scan complete \u2014 ' + r.total_findings + ' finding(s)');
    setTimeout(function () {
      closeSystemScanModal();
      navigate(getCurrentPage());
    }, 1500);
  } catch (e) {
    status.textContent = 'Network error: ' + e.message;
    status.className = 'upload-status error';
    runBtn.disabled = false;
  }
}

// Click-outside-to-close + Custom-range reveal.
(function wireUp() {
  var modal = document.getElementById('system-scan-modal');
  if (modal) {
    modal.addEventListener('click', function (e) {
      if (e.target === this) closeSystemScanModal();
    });
  }
  var rangeSel = document.getElementById('sys-scan-range');
  if (rangeSel) {
    rangeSel.addEventListener('change', function () {
      var isCustom = rangeSel.value === 'custom';
      document.getElementById('sys-scan-custom-row').style.display = isCustom ? 'flex' : 'none';
    });
  }
})();
