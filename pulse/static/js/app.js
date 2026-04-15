// app.js — the only file with DOMContentLoaded. Wires up the theme,
// resolves the start page from location.hash, and fires up the
// monitor client. Everything else is attached via onclick handlers
// defined in the individual page modules.
(function () {
  'use strict';

  // Event delegation. Any element with data-action="fnName" (and optionally
  // data-arg="...") gets routed to window[fnName](arg, target, event). We
  // register one delegator per event type so we cover onclick, onchange,
  // oninput, onsubmit, onkeydown, onkeyup in a single place. Template HTML
  // rendered later via innerHTML is covered automatically.
  function _installDelegator(eventName) {
    document.addEventListener(eventName, function (e) {
      var selector = eventName === 'click'
        ? '[data-action-click], [data-action]'
        : '[data-action-' + eventName + ']';
      var target = e.target.closest(selector);
      if (!target) return;
      // Per-event overrides beat the generic data-action. This lets a
      // single element bind different handlers to different events.
      var action = target.dataset['action' + eventName.charAt(0).toUpperCase() + eventName.slice(1)];
      if (!action && eventName === 'click') action = target.dataset.action;
      if (!action) return;
      var arg = target.dataset.arg;
      var fn = window[action];
      if (typeof fn === 'function') {
        // Stop <a> from navigating to "#" or empty href — but leave real
        // links (http://..., target=_blank) alone so they still work.
        // Also honor data-default="allow" for any element that wants the
        // default action to run (e.g. links to external docs).
        if (eventName === 'click' && target.tagName === 'A') {
          var href = target.getAttribute('href');
          var allow = target.dataset.default === 'allow';
          if (!allow && (!href || href === '#')) e.preventDefault();
        }
        fn(arg, target, e);
      }
    });
  }
  ['click', 'change', 'input', 'submit', 'keydown', 'keyup'].forEach(_installDelegator);

  document.addEventListener('DOMContentLoaded', function () {
    // Theme first so the UI doesn't flash.
    if (window.initTheme) window.initTheme();

    // Resolve starting page from the hash; fall back to dashboard.
    var startPage = (location.hash || '').replace('#', '') || 'dashboard';
    var valid = window.validPages || ['dashboard','monitor','scans','findings','history','whitelist','settings'];
    var target = valid.indexOf(startPage) >= 0 ? startPage : 'dashboard';
    if (window.navigate) window.navigate(target);

    // Kick off the live-monitor SSE client — fire-and-forget. If the
    // page happens to be the dashboard, mountDashLivePanel() will pick
    // up state from monitorClient once init resolves.
    if (window.monitorClient && window.monitorClient.init) {
      window.monitorClient.init();
    }
  });
})();
