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
| `inter/` | [Inter](https://rsms.me/inter/) font, variable weight 100–900, Latin + Latin Extended subsets (`inter-latin-wght-normal.woff2`, `inter-latin-ext-wght-normal.woff2`), SIL OFL 1.1 (`inter/LICENSE.txt`) | **5.3.0** (`@fontsource-variable/inter`) | https://cdn.jsdelivr.net/npm/@fontsource-variable/inter@5.3.0/files/ |

Fonts: the UI uses **Inter**, bundled in `inter/` and declared in
`inter/inter.css` (two `@font-face` rules pointing at the local `.woff2`
files). Every HTML shell (`pulse/web/index.html`, `login.html`,
`landing.html`) links that stylesheet, and `--font-body` in
`static/css/base.css` starts with `'Inter'`, so every page picks it up.
Nothing is fetched from `fonts.googleapis.com` or any other font host;
scripts outside Latin / Latin Extended fall back to the system fonts later in
the stack. `tests/test_ui_foundation.py` fails if a font CDN or remote
stylesheet creeps back in.

## Updating a pinned version

1. Download the new pinned version to the same filename, e.g.:
   ```bash
   curl -sL https://cdn.jsdelivr.net/npm/chart.js@X.Y.Z/dist/chart.umd.min.js \
     -o pulse/static/vendor/chart.umd.min.js
   ```
   For Inter, download both `files/inter-latin*-wght-normal.woff2` files
   and `LICENSE` (saved as `LICENSE.txt`) from the pinned
   `@fontsource-variable/inter@X.Y.Z` package into `inter/`, and copy the
   two `unicode-range` lines from that package's `wght.css` into
   `inter/inter.css`.
2. Bump the version in the table above.
3. Test the dashboard (charts render, icons render, text is in Inter) **with the network
   disconnected** to confirm nothing silently fell back to a CDN.

Do **not** reintroduce a `@latest` / unpinned reference, and do **not** add a
new external `<script>`/`<link>`/font — keep everything the dashboard needs
inside the repo.
