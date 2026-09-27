# Pulse: Dashboard Redesign

Date: 2026-09-26
Author: Robert Perez (direction), designed with Claude
Status: Build spec. Visual target is `docs/dashboard-redesign-mockup.html` (open it in a browser).

> Make the dashboard calmer and sharper without losing information. The problem today is not missing features, it is that every panel is an equal-weight bordered box, so nothing leads and it reads as busy, especially when empty.

---

## Goals

1. **One hero.** The security score leads. Everything else is smaller.
2. **Fewer panels.** Four zones instead of a dozen bordered boxes.
3. **Color means something.** Severity colors do the work; one accent for the brand. No color as decoration.
4. **Drop most borders.** Whitespace and a soft shadow on the few real cards, not an outline on every block.
5. **Never look empty.** Empty states say what to do next, not just "0".

The visual target is `docs/dashboard-redesign-mockup.html`. Open it and toggle light/dark. Match its hierarchy and spacing, not its exact fonts (see constraints).

## Hard constraints (do not break these)

- **No CDNs, no web fonts.** Pulse renders fully offline and air-gapped on purpose (`static/vendor/` is vendored, fonts use a system stack). The mockup uses Google Fonts for convenience; the real build must keep the existing `--font-body` system stack in `base.css`. Do not add Sora, Manrope, or any Google font.
- **Reuse the existing token system.** `base.css` already has `--bg-0…--bg-4`, `--text-high/body/dim`, `--severity-*`, `--status-*`, and a `[data-theme="dark"]` block. Build on those tokens. Do not invent a parallel palette.
- **Keep it a string-built SPA.** The dashboard renders via `innerHTML` in `pulse/static/js/dashboard.js` with helpers like `statCard`, `sevBadge`, `buildDailyScoreTable`. Refactor those, do not switch frameworks.
- **Chart.js is already vendored.** Use it for the score-history chart rather than hand-rolled SVG if that is simpler; either is fine as long as it stays offline.

## Files to touch

- `pulse/static/js/dashboard.js` — the render structure (KPI row, funnel, score, history, offenders).
- `pulse/static/css/dashboard.css` — the layout and card styling (this file is large; change the dashboard grid, card, and stat rules).
- `pulse/static/css/base.css` — only if a token is missing (for example a dedicated brand-accent green). Add, do not rename existing tokens.

## Layout changes

Replace the current stack (6 KPI tiles, then a 4-box funnel, then a gauge, then history, then offenders, all bordered) with four zones:

1. **Hero row, two columns.**
   - Left: the security score as the dominant element. Big grade letter, the number under it, colored by grade, and one plain-language line saying what is wrong ("A brute-force sign-in succeeded on this domain controller"). A small trend chip ("down 22 pts since yesterday").
   - Right: "Needs attention" — the top 3 to 5 findings as a compact list with a severity stripe down the left edge, newest first, each row clickable into the drawer. This makes the working content the star.

2. **One stat strip.** Cut from 6 tiles to 4 that matter: Open findings, Critical unreviewed, Scans today, Mean time to detect. Borderless, separated by thin dividers inside one panel, not 6 outlined boxes.

3. **One row, two panels.** Left: score history as one area line with a faint grid and the B-grade threshold marked. Right: findings by severity as one horizontal stacked bar with a small key, then repeat offenders as a short list.

4. Drop the standalone 4-box "data reduction funnel" from the top. If it is worth keeping, it becomes a single compact line ("12,480 events → 14 findings → 3 critical"), not four bordered boxes.

## Card and color rules

- A card gets a border or shadow only when it is a distinct object. Use one soft shadow and a large radius on the few real cards; remove the outline from inner blocks.
- Stat values use the mono font and tabular numbers so columns line up.
- Severity stripe on each finding row: critical red, high orange, medium amber, low blue, from `--severity-*`.
- Pick one brand accent (the Pulse green from the logo) for the score ring, links, and the one highlighted number. Keep it to that. Add it as a token (for example `--brand`) rather than reusing `--accent` (currently blue) if you want to keep both.
- Empty state: when there are no scans, the hero says "Run your first scan" with the upload action, not a gray "0 / SECURE" that looks broken.

## Fix while you are in here

The grade bands disagree between front and back end, so the same score can show two different letters:
- `pulse/static/js/dashboard.js` `_gradeFor`: A 90, B 80, C 70, D 60.
- `pulse/reports/reporter.py` `_score_grade`: A 90, B 75, C 50, D 25.

Pick one source of truth (the backend bands) and make the frontend match, or have the frontend read the grade the backend already returns instead of recomputing it. Add a test that pins them together so they cannot drift again. Note: if the separate scoring-model change (`docs/2026-09-26-scoring-model-review.md`) lands, align to whatever bands that settles on.

## Check before calling it done

Open a real finding and the dashboard in the browser, in both light and dark, with a sample scan loaded and again with an empty account. Confirm the hero leads, nothing overflows on a narrow window, and the grade letter matches the number.
