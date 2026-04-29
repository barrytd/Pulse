// dashboard-layout.js — User-customizable dashboard widget layout.
// Stores widget order + visibility per browser in localStorage so each
// analyst can hide panels they don't care about and reorder the rest.
'use strict';

const STORAGE_KEY = 'pulseDashWidgets';

// Source-of-truth registry. Order here is the default order; label is
// shown in the "hidden widgets" tray when a widget is toggled off.
export const WIDGETS = [
  { id: 'kpi',      label: 'KPI strip' },
  { id: 'standup',  label: 'Standup row (funnel + top hosts)' },
  { id: 'charts',   label: 'Charts (severity, score ring, history)' },
  { id: 'mitre',    label: 'MITRE categories + top rules' },
  { id: 'findings', label: 'Last scan findings' },
];

const VALID_IDS = new Set(WIDGETS.map(function (w) { return w.id; }));

let _editMode = false;

// Layout shape: [{ id, visible }, ...]. Persisted as JSON. On load we
// reconcile against WIDGETS so a new release that adds a widget shows
// it (visible, at end) and a removed widget gets dropped silently.
function _defaultLayout() {
  return WIDGETS.map(function (w) { return { id: w.id, visible: true }; });
}

export function loadLayout() {
  try {
    var raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return _defaultLayout();
    var parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return _defaultLayout();
    var seen = {};
    var out = [];
    parsed.forEach(function (entry) {
      if (!entry || !VALID_IDS.has(entry.id) || seen[entry.id]) return;
      seen[entry.id] = true;
      out.push({ id: entry.id, visible: entry.visible !== false });
    });
    // Append any widget that exists in code but isn't in the saved layout.
    WIDGETS.forEach(function (w) {
      if (!seen[w.id]) out.push({ id: w.id, visible: true });
    });
    return out;
  } catch (e) {
    return _defaultLayout();
  }
}

export function saveLayout(layout) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(layout));
  } catch (e) { /* private mode / quota — non-fatal */ }
}

export function resetLayout() {
  try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
}

export function isEditMode() { return _editMode; }
export function setEditMode(on) { _editMode = !!on; }

// Move srcId so it lands immediately before dstId in the saved order.
// dstId === null means "drop at end". No-op if srcId === dstId.
export function moveWidget(srcId, dstId) {
  if (srcId === dstId) return;
  var layout = loadLayout();
  var srcIdx = layout.findIndex(function (e) { return e.id === srcId; });
  if (srcIdx < 0) return;
  var entry = layout.splice(srcIdx, 1)[0];
  if (dstId == null) {
    layout.push(entry);
  } else {
    var dstIdx = layout.findIndex(function (e) { return e.id === dstId; });
    if (dstIdx < 0) layout.push(entry);
    else layout.splice(dstIdx, 0, entry);
  }
  saveLayout(layout);
}

export function setWidgetVisible(id, visible) {
  var layout = loadLayout();
  var entry = layout.find(function (e) { return e.id === id; });
  if (!entry) return;
  entry.visible = !!visible;
  saveLayout(layout);
}

export function widgetLabel(id) {
  var w = WIDGETS.find(function (x) { return x.id === id; });
  return w ? w.label : id;
}
