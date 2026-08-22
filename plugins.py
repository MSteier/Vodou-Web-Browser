"""Curated plugin catalog and manager.

Vodou runs on QtWebEngine, which cannot load Chrome Web Store extensions, and
letting users paste arbitrary scripts would be a security hole. Instead this
module ships a small catalog of *reviewed* plugins — the trusted source — that
the user simply switches on or off.

Security model:
  * All plugin code lives here, in Vodou's reviewed source. Users never supply
    code; they only toggle catalog entries.
  * The persisted state (~/.vodou/plugins.json) is a list of enabled plugin
    IDs — it carries no executable content, so tampering with it can at most
    enable/disable vetted plugins, never inject new behaviour.
  * Each plugin declares a host allowlist and only runs on matching sites
    (least privilege). Injection happens in the isolated ApplicationWorld, so
    page scripts can neither see nor call it.
  * Each plugin exposes a SHA-256 fingerprint of its code so its identity is
    visible and tamper-evident in the UI.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

PLUGINS_FILE = Path.home() / ".vodou" / "plugins.json"


@dataclass(frozen=True)
class Plugin:
    id: str
    name: str
    description: str
    version: str
    author: str
    matches: tuple[str, ...]   # host patterns: "*", "example.com", "*.foo.com"
    css: str = ""
    js: str = ""

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(
            (self.css + "\0" + self.js).encode("utf-8")).hexdigest()
        return digest[:16]

    @property
    def sites_label(self) -> str:
        if "*" in self.matches:
            return "All sites"
        return ", ".join(self.matches)


# -- The curated, reviewed catalog ------------------------------------------
# Keep every entry small, auditable, and side-effect-free beyond its stated
# purpose. Anything added here has been read line by line.

# A "Dark Mode Everywhere" plugin lived here until v1.8.0. Forcing a dark
# scheme onto arbitrary sites means inverting them, which fights any styling
# the site already has: it turned already-dark pages light, masked site theme
# settings, and distorted page colours generally. Detecting "is this page
# already dark?" only narrowed the damage — the approach itself is wrong, so
# it was removed rather than patched further. Sites' own dark themes and the
# ☰ → Appearance chrome themes cover the need without touching page content.
# PluginManager drops unknown IDs on load, so a stale enable of it is inert.

_CATALOG_LIST: list[Plugin] = [
    Plugin(
        id="cookie-zapper",
        name="Cookie Banner Zapper",
        description="Hides common cookie-consent banners and their scroll "
                    "locks. Cosmetic only — it does not click 'accept'.",
        version="1.0",
        author="Vodou (verified)",
        matches=("*",),
        css="""
[id*="cookie" i][class*="banner" i], [class*="cookie-consent" i],
[id*="cookie-consent" i], [aria-label*="cookie" i][role="dialog"],
.cc-window, #onetrust-banner-sdk, #cookie-law-info-bar,
.cookie-notice, .gdpr, .cmp-container {
    display: none !important;
}
html, body { overflow: auto !important; }
""",
    ),
    Plugin(
        id="deflicker-blur",
        name="Glass Blur Deflicker",
        description="Removes CSS 'frosted glass' (backdrop-filter blur) "
                    "effects, which flicker badly in Qt WebEngine on "
                    "Windows — e.g. the chat input and bubbles on "
                    "my.replika.ai. Sites keep their translucent panels, "
                    "just without the blur.",
        version="1.0",
        author="Vodou (verified)",
        matches=("*",),
        css="""
*, *::before, *::after {
    backdrop-filter: none !important;
    -webkit-backdrop-filter: none !important;
}
""",
    ),
    Plugin(
        id="youtube-ad-skip",
        name="YouTube Ad Skip",
        description="Auto-clicks 'Skip Ad', fast-forwards unskippable video "
                    "ads to their end, and hides overlay/banner/display ads on "
                    "YouTube. Leaves your login and the video itself untouched. "
                    "YouTube changes its player often, so this may need "
                    "updates and can trip YouTube's anti-ad-block notices.",
        version="1.1",
        author="Vodou (verified)",
        matches=("youtube.com", "*.youtube.com"),
        css="""
.ytp-ad-overlay-container, .ytp-ad-overlay-slot, .ytp-ad-overlay-image,
.ytp-ad-text, .ytp-ad-overlay-close-container,
.ytp-ad-player-overlay, .ytp-ad-player-overlay-layout,
.ytp-suggested-action,
ytd-display-ad-renderer, ytd-ad-slot-renderer,
ytd-in-feed-ad-layout-renderer, ytd-companion-slot-renderer,
ytd-banner-promo-renderer, ytd-statement-banner-renderer,
#masthead-ad, #player-ads {
    display: none !important;
}
""",
        js="""
// DOM-level ad skipper. YouTube serves ads from the same hosts as the video,
// so they can't be network-blocked; this clicks Skip, jumps unskippable ads to
// their end, and self-heals across the player's frequent markup changes.
var SKIP = [
    '.ytp-ad-skip-button',
    '.ytp-ad-skip-button-modern',
    '.ytp-skip-ad-button',
    '.ytp-ad-skip-button-container button'
];
var mutedByUs = false;   // only unmute what WE muted, never the user's choice.
var getVideo = function () {
    return document.querySelector('video.html5-main-video')
           || document.querySelector('video');
};
var clickSkip = function () {
    for (var i = 0; i < SKIP.length; i++) {
        var btn = document.querySelector(SKIP[i]);
        if (btn) { btn.click(); return true; }
    }
    // Fallback for renamed variants: any Skip control inside the ad UI.
    var cands = document.querySelectorAll(
        '[class*="ytp-ad-skip" i], [class*="skip-ad" i]');
    for (var j = 0; j < cands.length; j++) {
        var el = cands[j];
        if (el.tagName === 'BUTTON' || el.getAttribute('role') === 'button') {
            el.click(); return true;
        }
    }
    return false;
};
var tick = function () {
    try {
        var player = document.querySelector('.html5-video-player');
        var adShowing = !!(player && player.classList.contains('ad-showing'));
        clickSkip();
        var video = getVideo();
        if (adShowing) {
            if (video && isFinite(video.duration) && video.duration > 0) {
                // Mute only while jumping, so a live ad can't blast audio.
                if (!video.muted) { video.muted = true; mutedByUs = true; }
                video.currentTime = video.duration;   // jump past the ad
            }
        } else if (mutedByUs) {
            // Ad's gone — undo the mute we applied (leave user mutes alone).
            if (video) { video.muted = false; }
            mutedByUs = false;
        }
    } catch (e) {}
};
setInterval(tick, 250);
try {
    var mo = new MutationObserver(tick);
    mo.observe(document.documentElement, {childList: true, subtree: true});
} catch (e) {}
tick();
""",
    ),
    Plugin(
        id="selection-unlock",
        name="Text Selection Unlocker",
        description="Re-enables selecting and copying text on sites that "
                    "block it.",
        version="1.0",
        author="Vodou (verified)",
        matches=("*",),
        css="""
* { user-select: text !important; -webkit-user-select: text !important; }
""",
        js="""
for (const ev of ['contextmenu','selectstart','copy','cut','dragstart']) {
    document.addEventListener(ev, e => e.stopPropagation(), true);
}
""",
    ),
]

CATALOG: dict[str, Plugin] = {p.id: p for p in _CATALOG_LIST}


def catalog() -> list[Plugin]:
    return list(_CATALOG_LIST)


class PluginManager:
    """Tracks which catalog plugins are enabled; persists IDs only."""

    def __init__(self, path: Path = PLUGINS_FILE):
        self.path = path
        self._enabled: set[str] = set()
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            # Keep only IDs that exist in the trusted catalog.
            self._enabled = {pid for pid in data if pid in CATALOG}
        except (OSError, ValueError, TypeError):
            self._enabled = set()

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(sorted(self._enabled)),
                           encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass

    def is_enabled(self, plugin_id: str) -> bool:
        return plugin_id in self._enabled

    def set_enabled(self, plugin_id: str, enabled: bool) -> None:
        if plugin_id not in CATALOG:
            return
        if enabled:
            self._enabled.add(plugin_id)
        else:
            self._enabled.discard(plugin_id)
        self._save()

    def enabled_plugins(self) -> list[Plugin]:
        return [p for p in _CATALOG_LIST if p.id in self._enabled]


def wrap_plugin_source(plugin: Plugin) -> str:
    """Build the injected source for a plugin: a self-contained IIFE that runs
    only on allowed hosts, applies the CSS, then runs the plugin JS — each in
    its own try/catch so a failure can't break the page or other plugins.

    matches and css are passed as JSON literals (safely escaped). The plugin JS
    is trusted catalog code and is embedded directly.
    """
    matches_json = json.dumps(list(plugin.matches))
    css_json = json.dumps(plugin.css)
    return f"""
(function() {{
    "use strict";
    var MATCHES = {matches_json};
    var h = (location.hostname || "").toLowerCase();
    function hostOk(pat) {{
        pat = pat.toLowerCase();
        if (pat === "*") return true;
        if (pat.slice(0, 2) === "*.") {{
            var base = pat.slice(2);
            return h === base || h.endsWith("." + base);
        }}
        return h === pat;
    }}
    if (!MATCHES.some(hostOk)) return;
    try {{
        var css = {css_json};
        if (css) {{
            var el = document.createElement("style");
            el.setAttribute("data-vodou-plugin", "{plugin.id}");
            el.textContent = css;
            (document.head || document.documentElement).appendChild(el);
        }}
    }} catch (e) {{}}
    try {{
{plugin.js}
    }} catch (e) {{}}
}})();
"""
