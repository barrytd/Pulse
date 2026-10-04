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
    def test_page_is_a_sheet_floating_on_a_gray_ground(self):
        base = _read(CSS / "base.css")
        light, dark = base.split('[data-theme="dark"] {', 1)
        # Sidebar + topbar sit on the ground; "the page surface" is the sheet.
        for theme in (light, dark):
            assert re.search(r"--bg:\s*var\(--sheet-bg\)", theme)
            assert re.search(r"--topbar-bg:\s*var\(--bg-0\)", theme)
            assert re.search(r"--sheet-bg:\s*#[0-9a-f]{6}", theme, re.I)
        assert re.search(r"--shell-bg:\s*var\(--bg-0\)", light)
        assert "var(--bg-0)" in _block(base, "body")

        def lum(hexv):
            r, g, b = (int(hexv[i:i + 2], 16) / 255 for i in (0, 2, 4))
            return 0.2126 * r + 0.7152 * g + 0.0722 * b
        light_ground = re.search(r"--bg-0:\s*#([0-9a-f]{6})", light, re.I).group(1)
        light_sheet = re.search(r"--sheet-bg:\s*#([0-9a-f]{6})", light, re.I).group(1)
        dark_ground = re.search(r"--bg-0:\s*#([0-9a-f]{6})", dark, re.I).group(1)
        dark_sheet = re.search(r"--sheet-bg:\s*#([0-9a-f]{6})", dark, re.I).group(1)
        # Plainly visible contrast, not near-white on near-white.
        assert lum(light_sheet) - lum(light_ground) >= 0.08
        assert lum(dark_sheet) > lum(dark_ground)

        main = _block(_read(CSS / "sidebar.css"), ".main")
        for need in ("var(--sheet-bg)", "var(--sheet-radius)", "var(--sheet-shadow)", "var(--sheet-gap)"):
            assert need in main, need
        gap = int(re.search(r"--sheet-gap:\s*(\d+)px", light).group(1))
        assert 16 <= gap <= 24

    def test_no_divider_lines_in_the_shell(self):
        sidebar = _read(CSS / "sidebar.css")
        assert "border-right: none" in _block(sidebar, ".sidebar")
        assert "border-top: none" in _block(sidebar, ".sidebar-footer")
        assert "border-bottom: none" in _block(_read(CSS / "components.css"), ".app-topbar")

    def test_page_names_live_in_the_sheet_not_the_top_bar(self):
        assert "display: none" in _block(_read(CSS / "components.css"), ".app-page-crumb")
        d = _read(JS_DIR / "dashboard.js")
        assert d.count('<h1 class="ui-page-title">Dashboard</h1>') == 2
        # The scan-detail view titles itself in the sheet too.
        assert """class="ui-page-title">' + escapeHtml(fname)""" in _read(JS_DIR / "findings.js")

    def test_logo_is_the_pulse_wordmark_without_a_tagline(self):
        html = _read(SHELLS[0])
        assert '<span class="sidebar-brand-name">PULSE</span>' in html
        assert "Threat Detection</span>" not in html and "sidebar-brand-sep" not in html
        assert re.search(r"font-size:\s*1[89]px", _block(_read(CSS / "sidebar.css"), ".sidebar-brand-name"))

    def test_sidebar_is_themed_not_a_dark_block(self):
        sidebar = _css_rules_without_comments(_read(CSS / "sidebar.css"))
        # Every color comes from a token, so it follows light and dark.
        assert not re.search(r"#[0-9a-fA-F]{3,8}|rgba?\(", sidebar)

    def test_active_nav_is_a_soft_green_pill(self):
        sidebar = _read(CSS / "sidebar.css")
        nav = _block(sidebar, ".sidebar-nav")
        assert "border-radius" in nav and "border-left" not in nav
        active = _block(sidebar, ".sidebar-nav.active")
        assert "var(--nav-active-bg)" in active
        assert re.search(r"--nav-active-bg:\s*var\(--brand-soft\)", _read(CSS / "base.css"))

    def test_reports_grid_lines_up_with_the_empty_card(self):
        d = _read(CSS / "dashboard.css")
        grid = _block(d, ".report-catalog-grid")
        assert re.search(r"minmax\(\d+px, 1fr\)", grid)     # columns fill the row
        empty = _block(d, ".reports-empty")
        assert "var(--radius-card)" in empty and "var(--card-edge)" in empty


JS_DIR = STATIC / "js"


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

    def test_drawer_overlays_at_every_width(self):
        # The finding drawer floats over the page at desktop widths too, so
        # the Findings table keeps its full columns when it opens: nothing
        # pads, margins or shrinks the page while the drawer is open.
        for f in CSS.glob("*.css"):
            css = _css_rules_without_comments(_read(f))
            for sel, body in re.findall(r"([^{}]*flyout-push-open[^{}]*)\{([^}]*)\}", css):
                assert not re.search(r"padding-right|margin-right|width|max-width", body), (f.name, sel.strip())
        drawer = _css_rules_without_comments(_read(CSS / "findings.css"))
        base = re.search(r"\.finding-drawer\s*\{([^}]*)\}", drawer).group(1)
        assert "position: fixed" in base and "box-shadow" in base

    def test_no_other_drawer_pushes_the_page(self):
        # The shared drawer (Fleet, Audit Log) and Pip float as fixed layers;
        # no stylesheet shifts page content to make room for a side panel.
        for f in CSS.glob("*.css"):
            css = _css_rules_without_comments(_read(f))
            assert not re.search(r"(drawer|panel|pip|flyout)[\w-]*-open[^{]*\{[^}]*(padding|margin)-right:\s*[1-9]", css), f.name
        shared = _css_rules_without_comments(_read(CSS / "modals.css"))
        assert "position: fixed" in re.search(r"\.drawer-panel\s*\{([^}]*)\}", shared).group(1)


# ---------------------------------------------------------------------------
# Part 2, batch 3: Monitor, Security Advisor, Threat Intel
# ---------------------------------------------------------------------------

class TestBatch3:
    def test_monitor_uses_kit_tiles_cards_and_a_title(self):
        m = _read(JS / "monitor.js")
        assert '"ui-stats ui-stats-tiles ui-stats-auto mon-kpi-strip"' in m
        assert m.count("ui-card ui-stat mon-kpi-tile") == 2
        assert m.count('ui-card ui-panel mon-rail-card') == 5
        assert '"ui-card ui-panel mon-histogram-card"' in m and '"ui-card mon-feed-card"' in m
        assert '<h1 class="ui-page-title">Monitor</h1>' in m
        assert 'id="monitor-page-root" class="ui-stack"' in m
        d = _css_rules_without_comments(_read(CSS / "dashboard.css"))
        for cls in (".mon-kpi-tile", ".mon-rail-card", ".mon-histogram-card", ".mon-feed-card"):
            for body in re.findall(re.escape(cls) + r"\s*\{([^}]*)\}", d):
                assert "border:" not in body and "background:" not in body, cls

    def test_advisor_uses_the_frame_and_kit_tiles(self):
        a = _read(JS / "advisor.js")
        assert '"ui-stack advisor-page"' in a and '<h1 class="ui-page-title">Security Advisor</h1>' in a
        assert '"ui-stats ui-stats-tiles advisor-totals"' in a
        for tone in ("ui-text-critical", "ui-text-high", "ui-text-medium", "ui-text-low"):
            assert tone in a
        f = _css_rules_without_comments(_read(CSS / "findings.css"))
        assert "max-width: 960px" not in f      # no private narrower column
        assert ".advisor-total {" not in f

    def test_auto_fit_tile_strip_is_in_the_kit(self):
        kit = _css_rules_without_comments(_read(CSS / "components.css").split("Shared surface kit", 1)[1])
        assert re.search(r"\.ui-stats\.ui-stats-auto\s*\{\s*grid-template-columns:\s*repeat\(auto-fit", kit)
        for tone in ("high", "medium", "low"):
            assert re.search(r"\.ui-text-%s\s*\{\s*color:\s*var\(--severity-%s\)" % (tone, tone), kit)


# ---------------------------------------------------------------------------
# Part 2, batch 4: Reports, History, Trends, Compliance
# ---------------------------------------------------------------------------

class TestBatch4:
    @pytest.mark.parametrize("page,title", [("reports", "Reports"), ("history", "History"),
                                            ("trends", "Trends"), ("compliance", "Compliance")])
    def test_page_title_is_the_page_name(self, page, title):
        assert '<h1 class="ui-page-title">%s</h1>' % title in _read(JS / (page + ".js"))

    @pytest.mark.parametrize("page", ["reports", "history", "trends"])
    def test_kpi_strip_is_kit_tiles(self, page):
        assert "ui-stats ui-stats-tiles" in _read(JS / (page + ".js"))

    def test_one_off_strips_and_inline_boxes_are_gone(self):
        assert "reports-kpi" not in _read(JS / "reports.js")
        assert not re.search(r"\.reports-kpi|\.summary-row\s*\{", _read(CSS / "dashboard.css"))
        assert "summary-row {" not in _read(CSS / "base.css") and ".summary-row { grid" not in _read(CSS / "base.css")
        t = _read(JS / "trends.js")
        old_box = "border:1px solid var(--border); border-radius:6px; padding:14px"
        assert old_box not in t
        c = _read(JS / "compliance.js")
        assert old_box not in c and c.count('class="ui-inset"') == 2
        # Top-level cards rely on the page rhythm, not their own margins.
        for page in ("trends", "history", "compliance"):
            assert "margin-bottom:16px" not in _read(JS / (page + ".js")), page

    def test_trends_severity_bars_use_severity_colors(self):
        t = _read(JS / "trends.js")
        fn = t.split("function _renderSeverityTable(sev)", 1)[1].split("\n}", 1)[0]
        assert "var(--severity-' + k.toLowerCase() + ')" in fn

    def test_kit_inset_block(self):
        kit = _css_rules_without_comments(_read(CSS / "components.css").split("Shared surface kit", 1)[1])
        assert re.search(r"\.ui-inset,\s*\.ui-card \.card,\s*\.card \.card\s*\{", kit)


# ---------------------------------------------------------------------------
# Part 2, batch 5: Fleet, Firewall, Whitelist, Rules, Audit Log
# ---------------------------------------------------------------------------

class TestBatch5:
    @pytest.mark.parametrize("page,title", [("fleet", "Fleet"), ("firewall", "Firewall"), ("rules", "Rules")])
    def test_page_title_is_the_page_name(self, page, title):
        assert '<h1 class="ui-page-title">%s</h1>' % title in _read(JS / (page + ".js"))

    @pytest.mark.parametrize("page", ["audit", "firewall", "whitelist"])
    def test_kpi_strips_are_kit_tiles(self, page):
        js = _read(JS / (page + ".js"))
        assert "ui-stats ui-stats-tiles" in js and "ui-card ui-stat" in js

    def test_one_off_kpi_families_are_gone(self):
        pattern = re.compile(r"(?<![\w-])(kpi-row|kpi-tile|firewall-kpi|fw-kpi|whitelist-kpi)")
        for f in list(CSS.glob("*.css")) + [JS / "audit.js", JS / "firewall.js", JS / "whitelist.js"]:
            assert not pattern.search(_css_rules_without_comments(_read(f))), f.name

    def test_fleet_filters_wrap_and_table_scrolls_in_its_card(self):
        assert '"ui-card ui-toolbar fleet-filter-bar"' in _read(JS / "fleet.js")
        d = _css_rules_without_comments(_read(CSS / "dashboard.css"))
        assert re.search(r"\.fleet-table\s*\{[^}]*min-width:\s*\d+px", d)
        assert re.search(r"\.fleet-table-card\s*\{\s*overflow-x:\s*auto", d)
        kit = _css_rules_without_comments(_read(CSS / "components.css").split("Shared surface kit", 1)[1])
        assert re.search(r"\.ui-toolbar\s*\{[^}]*flex-wrap:\s*wrap", kit)


# ---------------------------------------------------------------------------
# Part 2, batch 6: Automations, Settings, modals
# ---------------------------------------------------------------------------

class TestBatch6:
    def test_settings_stacks_on_narrow_screens(self):
        # The logged bug: the 200px tab rail stayed put at every width and
        # squeezed each Settings card to ~128px at 420px.
        comp = _css_rules_without_comments(_read(CSS / "components.css"))
        m = re.search(r"@media \(max-width: (\d+)px\)\s*\{\s*\.settings-layout\s*\{\s*grid-template-columns:\s*minmax\(0, 1fr\)", comp)
        assert m and int(m.group(1)) >= 640
        narrow = comp[m.start():m.start() + 800]
        assert "overflow-x: auto" in narrow and ".settings-tab-group-label { display: none; }" in narrow
        assert re.search(r"\.settings-layout > \*\s*\{\s*min-width:\s*0", comp)

    def test_settings_tabs_use_the_sidebar_pill(self):
        comp = _css_rules_without_comments(_read(CSS / "components.css"))
        active = re.search(r"\.settings-tab-link\.active\s*\{([^}]*)\}", comp).group(1)
        assert "var(--nav-active-bg)" in active

    def test_wide_tables_scroll_in_their_card_and_actions_wrap(self):
        kit = _css_rules_without_comments(_read(CSS / "components.css").split("Shared surface kit", 1)[1])
        assert re.search(r"\.ui-table-scroll,\s*\.table-wrap\s*\{\s*overflow-x:\s*auto", kit)
        comp = _css_rules_without_comments(_read(CSS / "components.css"))
        assert re.search(r"\.form-actions\s*\{[^}]*flex-wrap:\s*wrap", comp)

    def test_settings_kpi_strips_are_kit_tiles(self):
        s = _read(JS / "settings.js")
        assert "feedback-kpi" not in s and s.count('"ui-stats ui-stats-tiles ui-stats-auto"') == 3
        for f in CSS.glob("*.css"):
            assert "feedback-kpi" not in _read(f), f.name

    def test_modal_uses_the_kit_surface(self):
        m = _css_rules_without_comments(_read(CSS / "modals.css"))
        body = re.search(r"\.modal\s*\{([^}]*)\}", m).group(1)
        assert "var(--radius-card)" in body and "var(--card-edge)" in body and "border: none" in body
