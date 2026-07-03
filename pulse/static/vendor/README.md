# Vendored front-end dependencies

These third-party browser libraries are **committed to the repo and served
locally** (`/static/vendor/...`) instead of loaded from a CDN. Pulse is a
self-hosted security tool, so this keeps the dashboard:

- **Air-gapped / offline friendly** — it renders with no internet access.
- **Private** — no user IP / referer is leaked to a CDN on every page load.
- **Supply-chain safe** — versions are pinned, so a CDN can't silently ship
  new (or compromised) code into the dashboard. (The previous `lucide@latest`
  reference pulled whatever unpkg served at load time — the exact risk this
  removes.)

| File | Library | Pinned version | Source URL |
|---|---|---|---|
| `chart.umd.min.js` | [Chart.js](https://www.chartjs.org/) | **4.4.0** | https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js |
| `lucide.min.js` | [Lucide](https://lucide.dev/) icons | **1.23.0** | https://unpkg.com/lucide@1.23.0/dist/umd/lucide.min.js |

Fonts: the UI uses a **system font stack** (`--font-body` in
`static/css/base.css`), not an external webfont — so there is nothing to
vendor and nothing to fetch from `fonts.googleapis.com`. (It previously pulled
Inter from Google Fonts.)

## Updating a pinned version

1. Download the new pinned version to the same filename, e.g.:
   ```bash
   curl -sL https://cdn.jsdelivr.net/npm/chart.js@X.Y.Z/dist/chart.umd.min.js \
     -o pulse/static/vendor/chart.umd.min.js
   ```
2. Bump the version in the table above.
3. Test the dashboard (charts render, icons render) **with the network
   disconnected** to confirm nothing silently fell back to a CDN.

Do **not** reintroduce a `@latest` / unpinned reference, and do **not** add a
new external `<script>`/`<link>`/font — keep everything the dashboard needs
inside the repo.
