// drawer.js — universal right-side drawer primitive.
// Blueprint priority 3: one drawer shape used by every page that needs to
// surface a detail view (finding, host, rule, scan, etc.). Pages pass a
// small config and the module handles the DOM, animation, focus, and
// Escape-to-close plumbing.
//
// Config shape passed to openDrawer():
//   {
//     title:    string            (required)
//     subtitle: string | html      (optional — smaller line under the title)
//     badges:   Array<{text, tone}> (optional — severity pills etc.
//                                     tone ∈ critical|high|medium|low|info|ok|warn|off)
//     sections: Array<{label, html}> (body — each section is a titled block)
//     actions:  Array<{label, variant, onClick}> (footer buttons;
//                                     variant ∈ primary|secondary|danger)
//     onClose:  () => void         (optional — fires after close animation)
//   }
//
// The existing finding-drawer in findings.css/js predates this module and is
// intentionally left in place so the current Findings page keeps working.
// New pages (and future Findings refactors) should call openDrawer() instead.
'use strict';

let _state = {
  mounted: false,
  open: false,
  overlay: null,
  panel: null,
  titleEl: null,
  subtitleEl: null,
  badgesEl: null,
  bodyEl: null,
  footEl: null,
  closeBtn: null,
  onClose: null,
  keyHandler: null,
};

function _ensureMounted() {
  if (_state.mounted) return;
  var overlay = document.createElement('div');
  overlay.className = 'drawer-overlay';
  overlay.hidden = true;
  overlay.innerHTML =
    '<aside class="drawer-panel" role="dialog" aria-modal="true" aria-label="Detail drawer">' +
      '<header class="drawer-head">' +
        '<div class="drawer-head-text">' +
          '<h2 class="drawer-title"></h2>' +
          '<div class="drawer-subtitle"></div>' +
          '<div class="drawer-badges"></div>' +
        '</div>' +
        '<button class="drawer-close" type="button" aria-label="Close">×</button>' +
      '</header>' +
      '<div class="drawer-body"></div>' +
      '<footer class="drawer-foot"></footer>' +
    '</aside>';
  document.body.appendChild(overlay);

  _state.overlay    = overlay;
  _state.panel      = overlay.querySelector('.drawer-panel');
  _state.titleEl    = overlay.querySelector('.drawer-title');
  _state.subtitleEl = overlay.querySelector('.drawer-subtitle');
  _state.badgesEl   = overlay.querySelector('.drawer-badges');
  _state.bodyEl     = overlay.querySelector('.drawer-body');
  _state.footEl     = overlay.querySelector('.drawer-foot');
  _state.closeBtn   = overlay.querySelector('.drawer-close');

  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closeDrawer();
  });
  _state.closeBtn.addEventListener('click', closeDrawer);

  _state.mounted = true;
}

function _escape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function _renderBadges(badges) {
  if (!badges || !badges.length) { _state.badgesEl.innerHTML = ''; return; }
  _state.badgesEl.innerHTML = badges.map(function (b) {
    var tone = (b.tone || 'info').toLowerCase();
    return '<span class="drawer-badge tone-' + _escape(tone) + '">' + _escape(b.text || '') + '</span>';
  }).join('');
}

function _renderSections(sections) {
  if (!sections || !sections.length) { _state.bodyEl.innerHTML = ''; return; }
  _state.bodyEl.innerHTML = sections.map(function (s) {
    var label = s.label ? '<div class="drawer-sec-label">' + _escape(s.label) + '</div>' : '';
    return '<section class="drawer-section">' + label +
             '<div class="drawer-sec-body">' + (s.html || '') + '</div>' +
           '</section>';
  }).join('');
}

function _renderActions(actions) {
  _state.footEl.innerHTML = '';
  if (!actions || !actions.length) { _state.footEl.hidden = true; return; }
  _state.footEl.hidden = false;
  actions.forEach(function (a, i) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'drawer-btn variant-' + (a.variant || 'secondary');
    btn.textContent = a.label || 'Action ' + (i + 1);
    if (typeof a.onClick === 'function') {
      btn.addEventListener('click', function (e) { a.onClick(e); });
    }
    _state.footEl.appendChild(btn);
  });
}

export function openDrawer(config) {
  _ensureMounted();
  config = config || {};
  _state.titleEl.textContent = config.title || '';
  if (config.subtitle) {
    _state.subtitleEl.innerHTML = config.subtitle;
    _state.subtitleEl.hidden = false;
  } else {
    _state.subtitleEl.innerHTML = '';
    _state.subtitleEl.hidden = true;
  }
  _renderBadges(config.badges);
  _renderSections(config.sections);
  _renderActions(config.actions);
  _state.onClose = typeof config.onClose === 'function' ? config.onClose : null;

  if (!_state.open) {
    _state.open = true;
    _state.overlay.hidden = false;
    _state.keyHandler = function (e) {
      if (e.key === 'Escape') { e.preventDefault(); closeDrawer(); }
    };
    document.addEventListener('keydown', _state.keyHandler);
    requestAnimationFrame(function () {
      requestAnimationFrame(function () { _state.overlay.classList.add('open'); });
    });
    // Focus the close button so Enter/Space can dismiss immediately.
    setTimeout(function () { _state.closeBtn && _state.closeBtn.focus(); }, 0);
  }
}

export function closeDrawer() {
  if (!_state.mounted || !_state.open) return;
  _state.open = false;
  _state.overlay.classList.remove('open');
  if (_state.keyHandler) {
    document.removeEventListener('keydown', _state.keyHandler);
    _state.keyHandler = null;
  }
  var onClose = _state.onClose;
  _state.onClose = null;
  setTimeout(function () {
    if (!_state.open) _state.overlay.hidden = true;
    if (typeof onClose === 'function') { try { onClose(); } catch (e) {} }
  }, 220);
}

export function isDrawerOpen() { return _state.open; }
