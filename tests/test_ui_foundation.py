# tests/test_ui_foundation.py
# ---------------------------
# Look-and-feel foundation: the bundled Inter font and the shared surface
# kit (.ui-* classes in components.css) the dashboard is built from.
#
# No browser in the suite, so these read the static files: the font is
# local and reachable, nothing points at a font CDN, and every kit class
# the dashboard uses is defined once, in components.css.

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pulse.api import create_app

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "pulse" / "static"
CSS = STATIC / "css"
INTER = STATIC / "vendor" / "inter"
SHELLS = [ROOT / "pulse" / "web" / n for n in ("index.html", "login.html", "landing.html")]
FONT_LINK = '<link rel="stylesheet" href="/static/vendor/inter/inter.css">'


def _read(p):
    return Path(p).read_text(encoding="utf-8")


def _css_rules_without_comments(text):
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


# ---------------------------------------------------------------------------
# Bundled Inter
# ---------------------------------------------------------------------------

class TestBundledInter:
    def test_font_files_are_real_woff2_with_license(self):
        fonts = sorted(INTER.glob("*.woff2"))
        assert [f.name for f in fonts] == ["inter-latin-ext-wght-normal.woff2",
                                           "inter-latin-wght-normal.woff2"]
        for f in fonts:
            assert f.read_bytes()[:4] == b"wOF2", f.name
        assert "SIL Open Font License" in _read(INTER / "LICENSE.txt")

    def test_font_face_points_only_at_local_files(self):
        css = _css_rules_without_comments(_read(INTER / "inter.css"))
        urls = re.findall(r"url\(\s*['\"]?([^'\")]+)", css)
        assert urls
        for u in urls:
            assert "://" not in u and not u.startswith("//"), u
            assert (INTER / u).is_file(), u
        assert css.count("@font-face") == 2
        assert "font-family: 'Inter'" in css

    def test_base_font_token_starts_with_inter(self):
        m = re.search(r"--font-body:\s*([^;]+);", _read(CSS / "base.css"))
        assert m and m.group(1).strip().startswith("'Inter'")
        # System fonts stay as the fallback for other scripts.
        assert "system-ui" in m.group(1)

    @pytest.mark.parametrize("shell", SHELLS, ids=lambda p: p.name)
    def test_every_page_links_the_bundled_font(self, shell):
        html = _read(shell)
        assert FONT_LINK in html
        assert "'Inter'" in html or shell.name == "index.html"   # index gets it via base.css

    @pytest.mark.parametrize("path", SHELLS + sorted(CSS.glob("*.css")) + [INTER / "inter.css"],
                             ids=lambda p: p.name)
    def test_no_font_cdn_or_remote_stylesheet(self, path):
        text = _read(path)
        for host in ("fonts.googleapis.com", "fonts.gstatic.com", "use.typekit.net",
                     "fonts.bunny.net", "rsms.me"):
            assert host not in text, (path.name, host)
        assert not re.search(r"@import\s+(url\()?['\"]?(https?:)?//", text)
        assert not re.search(r"<link[^>]+href=['\"](https?:)?//", text)
        assert not re.search(r"url\(\s*['\"]?(https?:)?//", _css_rules_without_comments(text))

    def test_font_is_served(self, tmp_path):
        cfg = tmp_path / "pulse.yaml"
        cfg.write_text("whitelist:\n  accounts: []\n")
        c = TestClient(create_app(db_path=str(tmp_path / "t.db"), config_path=str(cfg)))
        assert c.get("/static/vendor/inter/inter.css").status_code == 200
        r = c.get("/static/vendor/inter/inter-latin-wght-normal.woff2")
        assert r.status_code == 200 and r.content[:4] == b"wOF2"

    def test_headings_are_tracked_tighter(self):
        base = _read(CSS / "base.css")
        assert re.search(r"--tracking-heading:\s*-0\.\d+em", base)
        assert re.search(r"h1, h2, h3, h4, h5, h6,[^{]*\{\s*letter-spacing:\s*var\(--tracking-heading\)", base)


# ---------------------------------------------------------------------------
# Shared surface kit
# ---------------------------------------------------------------------------

def _defined_classes(css_text, prefix):
    css = _css_rules_without_comments(css_text)
    selectors = re.findall(r"([^{}]+)\{", css)
    return {c for sel in selectors for c in re.findall(r"\.(" + prefix + r"[a-z0-9-]*)", sel)}


class TestSurfaceKit:
    def test_every_kit_class_the_dashboard_uses_is_defined(self):
        used = set(re.findall(r"\b(ui-[a-z0-9-]+)", _read(STATIC / "js" / "dashboard.js")))
        defined = _defined_classes(_read(CSS / "components.css"), "ui-")
        assert used, "dashboard.js no longer uses the shared kit"
        assert used <= defined, sorted(used - defined)

    def test_kit_lives_only_in_components_css(self):
        for f in CSS.glob("*.css"):
            if f.name == "components.css":
                continue
            assert not _defined_classes(_read(f), "ui-"), f.name

    def test_dashboard_no_longer_keeps_its_own_copies(self):
        dash = _defined_classes(_read(CSS / "dashboard.css"), "dash-")
        moved = {"dash-card", "dash-eyebrow", "dash-sublabel", "dash-link", "dash-panel",
                 "dash-panel-head", "dash-panel-empty", "dash-stats", "dash-stat", "dash-stat-k",
                 "dash-stat-v", "dash-stat-d", "dash-stat-crit", "dash-sev", "dash-meta-row"}
        assert not (dash & moved), sorted(dash & moved)

    def test_kit_uses_tokens_not_raw_colors(self):
        kit = _read(CSS / "components.css").split("Shared surface kit", 1)[1]
        kit = _css_rules_without_comments(kit)
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", kit)
        for token in ("--gap-section", "--pad-card", "--aside-w", "--font-size-sm",
                      "--font-size-title", "--font-size-stat"):
            assert re.search(re.escape(token) + r":", _read(CSS / "base.css")), token

    def test_dashboard_is_capped_centered_and_tiled(self):
        js = _read(STATIC / "js" / "dashboard.js")
        kit = _css_rules_without_comments(_read(CSS / "components.css").split("Shared surface kit", 1)[1])
        # Content stops stretching on wide monitors: #content is the capped,
        # centered .ui-page frame, so every page (dashboard included) gets it.
        assert '<div class="content ui-page" id="content">' in _read(SHELLS[0])
        assert js.count('"ui-stack dash-page"') == 2
        assert re.search(r"\.ui-page\s*\{[^}]*max-width:\s*calc\(var\(--content-max\)[^}]*margin-inline:\s*auto", kit)
        m = re.search(r"--content-max:\s*(\d+)px", _read(CSS / "base.css"))
        assert m and 1200 <= int(m.group(1)) <= 1300
        # Four stats as separate tiles; history + severity as an even two-up.
        assert '"ui-stats ui-stats-tiles" id="dash-stats"' in js
        assert '"ui-card ui-stat"' in js
        assert '"ui-split ui-split-even dash-row"' in js
        assert re.search(r"\.ui-split\.ui-split-even\s*\{\s*grid-template-columns:\s*repeat\(2,", kit)

    def test_every_page_shares_the_kit_look(self):
        # Part 2 foundation: the legacy shared classes every page uses take
        # the kit's look, so all pages match the dashboard without
        # per-page copies.
        kit = _css_rules_without_comments(_read(CSS / "components.css").split("Shared surface kit", 1)[1])
        assert re.search(r"\.ui-card,\s*\.card\s*\{", kit)
        assert re.search(r"\.ui-eyebrow,\s*\.section-label\s*\{", kit)
        assert re.search(r"\.ui-page-head,\s*\.page-head\s*\{", kit)
        assert re.search(r"\.ui-page-title,\s*\.page-title,\s*\.page-head-title\s*\{", kit)
        # No page stylesheet re-declares the old uppercase page-head title.
        assert ".page-head .page-head-title" not in _css_rules_without_comments(_read(CSS / "dashboard.css"))
        # Sections inside #content sit one --gap-section apart.
        comp = _css_rules_without_comments(_read(CSS / "components.css"))
        assert re.search(r"\.content > \* \+ \*,\s*\.content-stack > \* \+ \*\s*\{\s*margin-top:\s*var\(--gap-section\)", comp)

    def test_score_ring_is_the_biggest_thing_on_the_page(self):
        dash = _css_rules_without_comments(_read(CSS / "dashboard.css"))
        gauge = re.search(r"\.dash-gauge\s*\{[^}]*width:\s*(\d+)px", dash)
        grade = re.search(r"\.dash-grade-letter\s*\{[^}]*font-size:\s*(\d+)px", dash)
        assert gauge and int(gauge.group(1)) >= 200
        assert grade and int(grade.group(1)) >= 64

    def test_kit_has_theme_aware_edges_and_narrow_rules(self):
        kit = _read(CSS / "components.css").split("Shared surface kit", 1)[1]
        # The card edge is a token ring, defined for light and dark.
        assert re.search(r"\.ui-card(?:,\s*\.card)?\s*\{[^}]*box-shadow:[^;]*var\(--card-edge\)", kit)
        base = _read(CSS / "base.css")
        dark = base.split('[data-theme="dark"] {', 1)[1]
        assert "--card-edge:" in base.split('[data-theme="dark"] {', 1)[0] and "--card-edge:" in dark
        assert "@media (max-width: 640px)" in kit and "@media (max-width: 1180px)" in kit


# ---------------------------------------------------------------------------
# App shell: one continuous surface
# ---------------------------------------------------------------------------

def _block(css, selector):
    m = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", _css_rules_without_comments(css))
    assert m, selector
    return m.group(1)


class TestAppShell:
    def test_sidebar_topbar_and_page_share_one_ground(self):
        base = _read(CSS / "base.css")
        light, dark = base.split('[data-theme="dark"] {', 1)
        for theme in (light, dark):
            assert re.search(r"--bg:\s*var\(--bg-0\)", theme)
            assert re.search(r"--topbar-bg:\s*var\(--bg-0\)", theme)
        assert re.search(r"--shell-bg:\s*var\(--bg-0\)", light)
        # Light ground is the soft warm off-white, cards are white.
        assert re.search(r"--bg-0:\s*#f6f5f2", light, re.I)
        assert re.search(r"--bg-1:\s*#ffffff", light, re.I)
        assert "var(--shell-bg)" in _block(_read(CSS / "sidebar.css"), ".sidebar")
        assert "var(--shell-bg)" in _block(_read(CSS / "components.css"), ".app-topbar")
        assert "var(--bg)" in _block(base, "body")

    def test_sidebar_is_themed_not_a_dark_block(self):
        sidebar = _css_rules_without_comments(_read(CSS / "sidebar.css"))
        # Every color comes from a token, so it follows light and dark.
        assert not re.search(r"#[0-9a-fA-F]{3,8}|rgba?\(", sidebar)
        assert "1px solid var(--shell-line)" in _block(sidebar, ".sidebar")

    def test_active_nav_is_a_soft_green_pill(self):
        sidebar = _read(CSS / "sidebar.css")
        nav = _block(sidebar, ".sidebar-nav")
        assert "border-radius" in nav and "border-left" not in nav
        active = _block(sidebar, ".sidebar-nav.active")
        assert "var(--nav-active-bg)" in active
        assert re.search(r"--nav-active-bg:\s*var\(--brand-soft\)", _read(CSS / "base.css"))


# ---------------------------------------------------------------------------
# Part 2, batch 2: My Queue, Team, Findings, finding drawer
# ---------------------------------------------------------------------------

JS = STATIC / "js"


class TestBatch2:
    def test_queue_uses_kit_tiles_without_icons(self):
        q = _read(JS / "queue.js")
        assert '"ui-stats ui-stats-tiles"' in q and '"ui-card ui-stat"' in q
        assert "q-kpi" not in q and "data-lucide" not in q
        # The one-off KPI styles are gone.
        for f in CSS.glob("*.css"):
            assert "q-kpi" not in _read(f), f.name

    def test_shared_stat_helpers_render_kit_tiles(self):
        d = _read(JS / "dashboard.js")
        for fn in ("export function statCard(", "export function _trendStatCard("):
            body = d.split(fn, 1)[1].split("\n}\n", 1)[0]
            assert "ui-card ui-stat stat-card" in body and "ui-stat-k" in body and "ui-stat-v" in body
        assert '"ui-stats ui-stats-tiles scan-header"' in _read(JS / "findings.js")

    def test_team_page_has_a_page_title(self):
        d = _read(JS / "dashboard.js")
        team = d.split("export async function renderTeamPage(", 1)[1].split("\n}\n", 1)[0]
        assert '<h1 class="ui-page-title">Team</h1>' in team
        assert team.count("head +") == 4       # loading, no access, empty, list

    def test_tables_are_the_kit_table(self):
        kit = _css_rules_without_comments(_read(CSS / "components.css").split("Shared surface kit", 1)[1])
        assert re.search(r"\.ui-table,\s*\.data-table\s*\{", kit)
        # Hairline rows, no zebra striping anywhere for .data-table.
        for f in CSS.glob("*.css"):
            assert not re.search(r"\.data-table tbody tr:nth-child\(even\)", _read(f)), f.name

    def test_list_filter_bar_wraps_instead_of_overflowing(self):
        comp = _css_rules_without_comments(_read(CSS / "components.css"))
        bars = re.findall(r"\.filter-bar\s*\{([^}]*)\}", comp)
        sticky = next(b for b in bars if "sticky" in b)
        assert "flex-wrap: wrap" in sticky
        assert not re.search(r"(?<!-)height:\s*40px", sticky)
        assert "var(--card-edge)" in sticky

    def test_drawer_overlays_where_it_cannot_push(self):
        f = _css_rules_without_comments(_read(CSS / "findings.css"))
        m = re.search(r"@media \(max-width: (\d+)px\)\s*\{\s*body\.flyout-push-open \.findings-page\s*\{\s*padding-right:\s*0", f)
        assert m and int(m.group(1)) >= 900
        assert "body.flyout-push-open .finding-drawer-backdrop { display: block; }" in f
