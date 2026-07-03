// csrf.js — CSRF defense (client half).
//
// The backend rejects any mutating request (POST/PUT/PATCH/DELETE) that
// doesn't carry the custom `X-Pulse-Request` header. A cross-site page can
// make the browser auto-send our session cookie, but it cannot set a custom
// header without a CORS preflight that its origin fails — so this header is
// proof the request came from our own app, not a forged cross-site form.
//
// Rather than touch every fetch() call site, we wrap window.fetch once and
// attach the header to same-origin mutating requests. Importing this module
// (first, from app.js) installs the wrapper before any request is made.
'use strict';

(function installCsrfHeader() {
  if (typeof window === 'undefined' || !window.fetch || window.__pulseCsrfWrapped) {
    return;
  }
  var _origFetch = window.fetch.bind(window);
  var MUTATING = { POST: 1, PUT: 1, PATCH: 1, DELETE: 1 };

  window.fetch = function (input, init) {
    init = init || {};
    // Method can live on init or on a Request object passed as input.
    var method = (init.method
      || (input && typeof input !== 'string' && input.method)
      || 'GET').toUpperCase();
    if (MUTATING[method]) {
      var headers = new Headers(
        init.headers
        || (input && typeof input !== 'string' && input.headers)
        || {}
      );
      if (!headers.has('X-Pulse-Request')) {
        headers.set('X-Pulse-Request', '1');
      }
      init.headers = headers;
    }
    return _origFetch(input, init);
  };
  window.__pulseCsrfWrapped = true;
})();
