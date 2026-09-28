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
        # Content stops stretching on wide monitors (both the populated and
        # first-run pages).
        assert js.count('"ui-stack ui-page dash-page"') == 2
        assert re.search(r"\.ui-page\s*\{[^}]*max-width:\s*var\(--content-max\)[^}]*margin-inline:\s*auto", kit)
        m = re.search(r"--content-max:\s*(\d+)px", _read(CSS / "base.css"))
        assert m and 1200 <= int(m.group(1)) <= 1300
        # Four stats as separate tiles; history + severity as an even two-up.
        assert '"ui-stats ui-stats-tiles" id="dash-stats"' in js
        assert '"ui-card ui-stat"' in js
        assert '"ui-split ui-split-even dash-row"' in js
        assert re.search(r"\.ui-split\.ui-split-even\s*\{\s*grid-template-columns:\s*repeat\(2,", kit)

    def test_score_ring_is_the_biggest_thing_on_the_page(self):
        dash = _css_rules_without_comments(_read(CSS / "dashboard.css"))
        gauge = re.search(r"\.dash-gauge\s*\{[^}]*width:\s*(\d+)px", dash)
        grade = re.search(r"\.dash-grade-letter\s*\{[^}]*font-size:\s*(\d+)px", dash)
        assert gauge and int(gauge.group(1)) >= 200
        assert grade and int(grade.group(1)) >= 64

    def test_kit_has_dark_mode_and_narrow_rules(self):
        kit = _read(CSS / "components.css").split("Shared surface kit", 1)[1]
        assert '[data-theme="dark"] .ui-card' in kit
        assert "@media (max-width: 640px)" in kit and "@media (max-width: 1180px)" in kit
