# Pulse Backlog

Features validated by SOC/SIEM research but not yet committed to a sprint. Ordered roughly by impact-to-effort ratio inside each section.

See [ROADMAP.md](ROADMAP.md) for shipped + in-flight work, and [CHANGELOG.md](CHANGELOG.md) for the commit-level history. When a backlog item is picked up, move it from here into the appropriate sprint section in `ROADMAP.md`.

Items previously listed here under **Detection depth**, **Operational health** (API rate limiting, retention), **Incident response** (evidence export), and **Platform hardening** (webhook signing, encrypted secrets, session hardening) have been promoted into [ROADMAP.md](ROADMAP.md)'s Sprint 8/9/10 plans and are no longer duplicated here.

---

## Remote collection

- [ ] **Remote log collection via WinRM** — enter a hostname or IP, Pulse connects via Windows Remote Management (WinRM), pulls Security/Application/System event logs remotely, and runs detections against them just like a local scan. Requires: credential management (store WinRM credentials per host or use domain auth), WinRM prerequisite checker (test connectivity before scan), progress indicator during remote pull, error handling for unreachable/unauthorized hosts, and timeout configuration. This complements the Sprint 7 agent model (agent pushes findings, WinRM pulls logs) and gives analysts an on-demand way to investigate a suspicious host without deploying an agent first. Natural pairing: add a "Scan this host" button on the Fleet page for any host that has been scanned before.

---

## Operational health

- [ ] **Alert fatigue metrics** — surface detection-pipeline health data: alerts suppressed by throttling this week, reviewed vs ignored ratio, dead rules (never triggered), noisy rules (high fire rate + high false-positive rate); display as a card on Dashboard or a section on Trends

---

## Branding + white-label

- [ ] **Custom branding (v2)** — admin uploads a company logo + sets an organization name, but both render as a SUBTITLE under the Pulse brand (not as a replacement). Keep the Pulse logo + "PULSE" title always visible so the product identity stays intact. A first pass was shipped then reverted on 2026-04-24 because replacing the Pulse lockup with just the company name lost too much brand recognition. The empty `branding` table from the v1 schema is still in the DB — reuse it rather than recreating. Also reach into HTML/PDF report headers for the same subtitle treatment

---

## Polish & UX

- [ ] **Customizable dashboard layout (v2)** — drag-and-drop reorder + hide/restore for the major dashboard panels (KPI strip, standup row, charts, MITRE, last-scan findings). The `localStorage`-backed implementation shipped on 2026-04-28 worked end-to-end but was reverted on 2026-04-29 because the "Customize layout" button surfaced before there was a clear use case. Revisit when there's a specific user signal: e.g. analysts who want to hide the standup row, or admins who want a pinned ordering across an org. Avoid surfacing a button until the use case justifies it
- [ ] **Sidebar filter configs for Dashboard / Monitor / Fleet / Audit Log / Firewall** — the per-page sidebar-filter framework (`pulse/static/js/sidebar-filters.js`) shipped on 2026-04-24 with the Findings page wired up. Each remaining page just needs to call `registerSidebarFilterConfig(pageId, builder)` with the dimensions that make sense for that surface (severity / time / actor / host etc.). Pick up alongside the next pass on each page rather than as a single sprint
- [ ] **Findings sidebar — Rule filter** — the rule list on the Findings page sidebar can grow long; needs a dedicated top-N (10–15 rules) plus a "Show all" affordance before it ships, otherwise the sidebar overflows on a noisy install. Deferred from the 2026-04-24 sidebar-filter ship
