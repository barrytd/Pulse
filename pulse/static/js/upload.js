// upload.js — upload modal, drop zone, tutorial modal.
// Scan requests go through api.js wrappers.
'use strict';

import {
  apiScan,
  invalidateScansCache,
  invalidateFindingsCache,
} from './api.js';
import { formatBytes } from './dashboard.js';
import { navigate, getCurrentPage } from './navigation.js';

let selectedFiles = [];

export function openUploadModal() {
  document.getElementById('upload-modal').classList.add('open');
  document.getElementById('upload-status').textContent = '';
  document.getElementById('upload-status').className = 'upload-status';
  document.getElementById('scan-btn').disabled = true;
  document.getElementById('drop-zone').querySelector('.drop-text').innerHTML =
    'Drop .evtx files here or <strong>browse</strong>';
  selectedFiles = [];
}

export function closeUploadModal() {
  document.getElementById('upload-modal').classList.remove('open');
  document.getElementById('file-input').value = '';
  selectedFiles = [];
}

// Tutorial modal — teaches new users how to export their own .evtx files.
// Remembers first-time visitors in localStorage so the upload modal can
// auto-open the tutorial the first time they click Upload.
export function openTutorialModal() {
  document.getElementById('tutorial-modal').classList.add('open');
  try { localStorage.setItem('pulseTutorialSeen', '1'); } catch (e) {}
}
export function closeTutorialModal() {
  document.getElementById('tutorial-modal').classList.remove('open');
}
export function switchTutorialTab(name) {
  var tabs = document.querySelectorAll('.tutorial-tab');
  tabs.forEach(function (t) { t.classList.remove('active'); });
  var panes = document.querySelectorAll('.tutorial-pane');
  panes.forEach(function (p) { p.classList.remove('active'); });
  var idx = { easy: 0, fast: 1, full: 2 }[name] || 0;
  if (tabs[idx]) tabs[idx].classList.add('active');
  var pane = document.getElementById('tutorial-pane-' + name);
  if (pane) pane.classList.add('active');
}
export function copyTutorialCmd(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  var text = el.textContent;
  var done = function () {
    var original = btn.textContent;
    btn.textContent = 'Copied';
    btn.classList.add('copied');
    setTimeout(function () {
      btn.textContent = original;
      btn.classList.remove('copied');
    }, 1500);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, function () {});
  } else {
    var ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); done(); } catch (e) {}
    document.body.removeChild(ta);
  }
}

export function updateFileDisplay() {
  var text = document.getElementById('drop-zone').querySelector('.drop-text');
  if (selectedFiles.length === 1) {
    text.innerHTML = '<strong>' + selectedFiles[0].name + '</strong> (' +
      formatBytes(selectedFiles[0].size) + ')';
  } else {
    var totalSize = selectedFiles.reduce(function (s, f) { return s + f.size; }, 0);
    text.innerHTML = '<strong>' + selectedFiles.length + ' files</strong> selected (' +
      formatBytes(totalSize) + ')';
  }
  document.getElementById('scan-btn').disabled = false;
}

export async function uploadAndScan() {
  if (selectedFiles.length === 0) return;
  var status = document.getElementById('upload-status');
  var scanBtn = document.getElementById('scan-btn');
  scanBtn.disabled = true;

  var totalFindings = 0;
  var completed = 0;
  var failed = 0;

  for (var i = 0; i < selectedFiles.length; i++) {
    var file = selectedFiles[i];
    status.textContent = 'Scanning file ' + (i + 1) + ' of ' + selectedFiles.length + '...';
    status.className = 'upload-status';

    var result = await apiScan(file);
    if (!result.ok || !result.data) {
      failed++;
      continue;
    }
    totalFindings += result.data.total_findings;
    completed++;
  }

  if (failed > 0 && completed === 0) {
    status.textContent = 'All ' + failed + ' file(s) failed to scan.';
    status.className = 'upload-status error';
    scanBtn.disabled = false;
    return;
  }

  var msg = completed + ' file(s) scanned \u2014 ' + totalFindings + ' finding(s)';
  if (failed > 0) msg += ' (' + failed + ' failed)';
  status.textContent = msg;
  status.className = 'upload-status success';
  invalidateScansCache();
  invalidateFindingsCache();
  setTimeout(function () { closeUploadModal(); navigate(getCurrentPage()); }, 1500);
}

// Wire up DOM listeners. Module scripts are deferred, so target
// elements exist by the time this runs.
(function wireUp() {
  var fileInput = document.getElementById('file-input');
  if (fileInput) {
    fileInput.addEventListener('change', function (e) {
      if (e.target.files.length > 0) {
        selectedFiles = Array.from(e.target.files);
        updateFileDisplay();
      }
    });
  }

  var dropZone = document.getElementById('drop-zone');
  if (dropZone) {
    // Stage 3: replaces the former inline click handler on the drop zone.
    dropZone.addEventListener('click', function () {
      var fi = document.getElementById('file-input');
      if (fi) fi.click();
    });
    dropZone.addEventListener('dragover', function (e) {
      e.preventDefault(); dropZone.classList.add('drag-over');
    });
    dropZone.addEventListener('dragleave', function () {
      dropZone.classList.remove('drag-over');
    });
    dropZone.addEventListener('drop', function (e) {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
      if (e.dataTransfer.files.length > 0) {
        selectedFiles = Array.from(e.dataTransfer.files).filter(function (f) {
          return f.name.toLowerCase().endsWith('.evtx');
        });
        if (selectedFiles.length > 0) {
          updateFileDisplay();
        }
      }
    });
  }

  var uploadModal = document.getElementById('upload-modal');
  if (uploadModal) {
    uploadModal.addEventListener('click', function (e) {
      if (e.target === this) closeUploadModal();
    });
  }

  // Click-outside-to-close for the tutorial modal.
  var tm = document.getElementById('tutorial-modal');
  if (tm) {
    tm.addEventListener('click', function (e) {
      if (e.target === this) closeTutorialModal();
    });
  }
})();
