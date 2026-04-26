// severity-colors.js — per-browser overrides for the four severity hues.
// Stored in localStorage as a JSON map. Empty / missing entries fall
// back to the theme defaults defined in base.css. Designed for users
// with color-vision differences who need a palette that reads to them.
'use strict';

const STORAGE_KEY = 'pulse-severity-colors';
const KEYS = ['critical', 'high', 'medium', 'low'];

// Theme defaults — must match base.css. Used by the Settings UI to
// pre-fill color inputs when the user has no override saved, so the
// reset state is immediately visible instead of empty.
export const SEVERITY_DEFAULTS = {
  light: {
    critical: '#ef4444',
    high:     '#f97316',
    medium:   '#f59e0b',
    low:      '#3b82f6',
  },
  dark: {
    critical: '#f87171',
    high:     '#fb923c',
    medium:   '#fbbf24',
    low:      '#60a5fa',
  },
};

function _isHex(s) {
  return typeof s === 'string' && /^#[0-9a-fA-F]{6}$/.test(s);
}

export function getSeverityColors() {
  try {
    var raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    var obj = JSON.parse(raw) || {};
    var out = {};
    KEYS.forEach(function (k) { if (_isHex(obj[k])) out[k] = obj[k]; });
    return out;
  } catch (e) {
    return {};
  }
}

// Convert "#RRGGBB" + alpha → "rgba(r, g, b, a)" so the *-bg variant
// keeps its 10% alpha after a custom solid color is applied.
function _hexToRgba(hex, alpha) {
  var r = parseInt(hex.slice(1, 3), 16);
  var g = parseInt(hex.slice(3, 5), 16);
  var b = parseInt(hex.slice(5, 7), 16);
  return 'rgba(' + r + ', ' + g + ', ' + b + ', ' + alpha + ')';
}

// Push the saved overrides onto :root as inline custom properties. They
// win over the [data-theme] block thanks to specificity, so any CSS
// rule that resolves --severity-* picks them up automatically.
export function applySeverityColors() {
  var saved = getSeverityColors();
  var root = document.documentElement;
  KEYS.forEach(function (k) {
    var solid = '--severity-' + k;
    var bg    = '--severity-' + k + '-bg';
    if (saved[k]) {
      root.style.setProperty(solid, saved[k]);
      root.style.setProperty(bg, _hexToRgba(saved[k], 0.10));
    } else {
      root.style.removeProperty(solid);
      root.style.removeProperty(bg);
    }
  });
}

export function setSeverityColor(key, hex) {
  if (KEYS.indexOf(key) < 0) return;
  if (!_isHex(hex)) return;
  var current = getSeverityColors();
  current[key] = hex;
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(current)); } catch (e) {}
  applySeverityColors();
}

export function resetSeverityColors() {
  try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
  applySeverityColors();
}

// Wired via data-action-input on the <input type="color"> rows. Updates
// live as the user drags the picker so they can preview against the
// running UI before settling. Also refreshes the matching hex label so
// the displayed code stays in sync without re-rendering the page.
export function severityColorInput(key, target) {
  if (!target || !target.value) return;
  setSeverityColor(key, target.value);
  var label = document.querySelector('[data-sev-hex="' + key + '"]');
  if (label) label.textContent = String(target.value).toUpperCase();
}
