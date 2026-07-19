"""Vodou — a privacy-centric browser with a built-in password manager.

Privacy design:
  * Off-the-record profile: history, cookies, and cache live in RAM only and
    vanish when the window closes. Nothing browsing-related touches disk.
  * Tracker/ad blocking via a request interceptor (see privacy.py).
  * DNT + Global Privacy Control headers on every request.
  * Generic Chrome user agent instead of advertising QtWebEngine.
  * WebRTC restricted to the public interface so it can't leak local IPs.
  * HTTPS-first address bar; local SearXNG instance as the search engine
    (searches never leave your machine except as SearXNG's own upstream
    queries, which it strips of identifying data).

Password manager:
  * scrypt + Fernet encrypted vault on disk (see vault.py).
  * Fill is always user-initiated: Ctrl+Shift+F or the key button.

Run:  python main.py
"""

import json
import os
import sys
from pathlib import Path

# Graphics profile. The default is tuned for integrated graphics:
#   --disable-direct-composition  stops the input-field blink — Windows'
#                                 overlay compositor misbehaves with many
#                                 Intel/AMD iGPU drivers
#   --use-angle=d3d11             pin the stable ANGLE backend explicitly
#   --enable-gpu-rasterization    paint pages on the GPU
#   --enable-zero-copy            iGPUs share system RAM, so textures can be
#                                 used in place instead of copied — faster
#                                 WebGL on integrated graphics
# WebGL stays fully hardware-accelerated. If anything misbehaves, fall back:
#   python main.py --gfx vanilla   # plain Chromium defaults
#   python main.py --gfx compat    # software compositing, WebGL stays on GPU
#   python main.py --gfx gl        # native OpenGL instead of ANGLE->D3D11
#   python main.py --gfx warp      # Microsoft WARP software rasterizer
#   python main.py --gfx software  # no GPU at all (WebGL slow but stable)
GFX_MODES = {
    "default": ("--disable-direct-composition "
                "--use-angle=d3d11 "
                "--enable-gpu-rasterization "
                "--enable-zero-copy"),
    "vanilla": "",
    "compat": "--disable-gpu-compositing",
    "gl": "--use-angle=gl",
    "warp": "--use-angle=warp",
    "software": "--disable-gpu",
}


GFX_FILE = Path.home() / ".vodou" / "graphics.json"
GFX_MODE = "default"  # the mode actually in effect; set by _gfx_flags()


def _load_saved_gfx() -> str:
    try:
        mode = json.loads(GFX_FILE.read_text(encoding="utf-8")).get("mode")
    except (OSError, ValueError, AttributeError):
        return "default"
    return mode if mode in GFX_MODES else "default"


def save_gfx_mode(mode: str) -> None:
    try:
        GFX_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = GFX_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"mode": mode}), encoding="utf-8")
        tmp.replace(GFX_FILE)
    except OSError:
        pass


def _gfx_flags() -> str:
    global GFX_MODE
    mode = _load_saved_gfx()          # ☰ menu → Graphics choice, if any
    if "--gfx" in sys.argv:           # per-launch CLI override wins
        i = sys.argv.index("--gfx")
        if i + 1 >= len(sys.argv) or sys.argv[i + 1] not in GFX_MODES:
            print(f"--gfx must be one of: {', '.join(GFX_MODES)}")
            sys.exit(2)
        mode = sys.argv[i + 1]
        del sys.argv[i:i + 2]  # keep Qt from seeing our custom args
    GFX_MODE = mode
    return GFX_MODES[mode]


# Must be set before Qt WebEngine initializes. The WebRTC policy stops local
# IP enumeration (a classic IP-leak / fingerprinting vector).
os.environ.setdefault(
    "QTWEBENGINE_CHROMIUM_FLAGS",
    "--force-webrtc-ip-handling-policy=default_public_interface_only "
    + _gfx_flags())

import platform
import secrets
from urllib.parse import quote

from PyQt6.QtCore import QEvent, QSize, Qt, QTimer, QUrl, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QAction, QActionGroup, QKeySequence, QShortcut
from PyQt6.QtWebEngineCore import (
    QWebEngineDownloadRequest,
    QWebEnginePage,
    QWebEngineProfile,
    QWebEngineScript,
    QWebEngineSettings,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTabBar,
    QTextBrowser,
    QToolBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from autofill import PROBE_JS, build_capture_script, build_fill_script
from blockstats import BlockStats
from blockstats_ui import BlockingReportWindow
from bookmarks import Bookmarks
from cookies import CookieKeeper
from cookies_ui import CookieSitesDialog
from favicons import FaviconStore
from icons import icon_set, make_icon
from bookmarks_ui import BookmarksManagerDialog
from downloads_ui import DownloadsDialog
from plugins import PluginManager, wrap_plugin_source
from plugins_ui import PluginsDialog
from importers import parse_bookmarks_html, parse_password_csv
from privacy import (
    FIREFOX_QUIRK_JS,
    GENERIC_USER_AGENT,
    WEBAUTHN_SHIM_JS,
    PrivacyInterceptor,
    apply_ua_quirk,
    ua_quirk_needed,
)
from ai_search import (
    OllamaSummarizer,
    is_search_results,
    load_config as load_ai_config,
    query_from_url,
    results_script,
    save_config as save_ai_config,
)
from safebrowsing import SafeBrowsing
from session import clear_snapshot, load_snapshot, save_snapshot
from shred import shred_dir
from spoofcheck import (
    SENTINEL_HOST,
    download_risk,
    interstitial_html,
    safe_download_name,
)
from spoofcheck import inspect as spoof_inspect
from about import (
    REPO_URL,
    VERSION_DISPLAY,
    AboutDialog,
    UpdateChecker,
    engine_versions,
)
from theme import THEMES, apply_theme, build_palette, load_prefs, save_prefs
from vault import LEGACY_VAULT_DIR, VAULT_DIR, Entry, Vault, normalize_site
from vault_ui import (
    EntryDialog,
    PickEntryDialog,
    VaultDialog,
    clear_copied_secrets,
    ensure_unlocked,
)


def migrate_config_dir(old: Path = LEGACY_VAULT_DIR,
                       new: Path = VAULT_DIR) -> bool:
    """One-time move of ~/.privacy_browser -> ~/.vodou (vault + blocklist).

    Never merges or overwrites: if the new directory already exists, the old
    one is left untouched for the user to reconcile manually.
    """
    if old.is_dir() and not new.exists():
        try:
            old.rename(new)
        except OSError as error:
            # A locked file (AV scan, sync client) must not stop the browser
            # from starting; the old vault stays intact where it was.
            print(f"warning: could not migrate {old} -> {new}: {error}",
                  file=sys.stderr)
            return False
        return True
    return False

def _searxng_base() -> str:
    """Where Vodou's search lives. Defaults to the bundled Docker stack
    (https://localhost/searxng); override with the VODOU_SEARXNG_URL
    environment variable or ~/.vodou/config.json {"searxng_url": "..."} to
    point at your own SearXNG. See docker/README.md."""
    url = os.environ.get("VODOU_SEARXNG_URL", "").strip()
    if not url:
        try:
            data = json.loads(
                (Path.home() / ".vodou" / "config.json").read_text("utf-8"))
            url = str(data.get("searxng_url", "")).strip()
        except (OSError, ValueError, TypeError):
            url = ""
    return (url or "https://localhost/searxng").rstrip("/")


SEARXNG_BASE = _searxng_base()
HOME_URL = SEARXNG_BASE

# On-disk half of the hybrid profile: capped HTTP cache + site storage.
# Created by the engine at startup, shredded on every exit and at the next
# startup after a crash. ~/.vodou is outside any cloud-synced folder.
PROFILE_DIR = Path.home() / ".vodou" / "profile"

# Chrome's zoom ladder; the engine accepts factors from 0.25 to 5.0.
ZOOM_LEVELS = (0.25, 0.33, 0.5, 0.67, 0.75, 0.8, 0.9, 1.0,
               1.1, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0, 5.0)
SEARCH_URL = SEARXNG_BASE + "/search?q={}"

# Hosts allowed to use a self-signed/invalid TLS certificate (the local
# SearXNG instance). Certificate errors anywhere else are still fatal.
CERT_EXEMPT_HOSTS = {"localhost", "127.0.0.1"}

# Re-lock the password vault after this much inactivity.
VAULT_AUTOLOCK_MINUTES = 5

# Isolated JS world for our own scripts: page scripts can't see or tamper
# with anything we inject there (the DOM itself is still shared).
APP_WORLD = QWebEngineScript.ScriptWorldId.ApplicationWorld.value


def plain_message(parent, icon, title, text,
                  buttons=QMessageBox.StandardButton.Ok,
                  default=QMessageBox.StandardButton.NoButton):
    """A QMessageBox that renders as PLAIN text.

    QMessageBox auto-detects HTML; several call sites interpolate
    attacker-controlled strings (hostnames, usernames, filenames, certificate
    fields), so rich-text rendering could trigger remote resource loads or
    misleading markup. Forcing plain text closes that off.
    """
    box = QMessageBox(parent)
    box.setIcon(icon)
    box.setWindowTitle(title)
    box.setText(text)
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.setStandardButtons(buttons)
    if default != QMessageBox.StandardButton.NoButton:
        box.setDefaultButton(default)
    return box.exec()


def to_url(text: str) -> QUrl:
    """Address-bar text -> URL (HTTPS-first) or search query."""
    text = text.strip()
    if not text:
        return QUrl(HOME_URL)
    if text.startswith(("http://", "https://", "about:", "file:")):
        return QUrl(text)
    looks_like_host = " " not in text and (
        "." in text or text.startswith("localhost"))
    if looks_like_host:
        return QUrl("https://" + text)
    return QUrl(SEARCH_URL.format(QUrl.toPercentEncoding(text).data().decode()))


class WebPage(QWebEnginePage):
    """Page that turns token-prefixed console messages into capture events.

    Capture messages are consumed here and NEVER forwarded to the default
    handler, so submitted passwords cannot end up on stderr or in logs.
    """

    captured = pyqtSignal(str, str)  # username, password

    def __init__(self, browser: "BrowserWindow", view: "WebView"):
        super().__init__(browser.profile, view)
        self.browser = browser
        self._view = view
        self._capture_prefix = browser.capture_prefix
        # True while the deceptive-site interstitial occupies this page, so its
        # own load and links aren't themselves re-inspected.
        self._interstitial_active = False

    def acceptNavigationRequest(self, url, nav_type, is_main_frame) -> bool:
        host = url.host()

        # The interstitial's own buttons navigate to the reserved sentinel
        # host; catch those two paths before anything else and never let them
        # load. The interstitial's base URL (/warning) shares this host, so it
        # must fall through and be allowed to render.
        if is_main_frame and host == SENTINEL_HOST:
            if url.path() in ("/continue", "/back"):
                self._handle_interstitial_choice(url)
                return False
            return super().acceptNavigationRequest(url, nav_type,
                                                   is_main_frame)

        # Deceptive-site / Safe-Browsing check: block a main-frame navigation
        # to a look-alike / mixed-script / typosquatting host, or one on the
        # local reported-phishing/malware list, and show a warning in its
        # place — unless the user already chose to continue this host this
        # session. spoof_inspect is a cheap pure check; the Safe Browsing
        # lookup is a cached in-memory set membership.
        if (is_main_frame and not self._interstitial_active
                and not self.browser.spoof_allowed(host)):
            verdict = (spoof_inspect(host)
                       or self.browser.safe_browsing.is_dangerous(host))
            if verdict is not None:
                self._interstitial_active = True
                pending = QUrl(url)
                QTimer.singleShot(0, lambda p=pending, v=verdict:
                                  self.browser.show_spoof_interstitial(
                                      self._view, v, p))
                return False

        # The identity must be right BEFORE the request leaves: letting the
        # navigation race the deferred switch meant the first sign-in attempt
        # could reach Google with a half-switched identity (headers vs
        # navigator.userAgent), failing until retried. So when a switch is
        # needed, hold this navigation, switch, then re-issue it. Mutating
        # the profile from inside this callback re-enters QtWebEngine and
        # aborts the process, hence the one-tick deferral.
        if is_main_frame and ua_quirk_needed(self.profile(), host):
            QTimer.singleShot(
                0, lambda u=QUrl(url): self._apply_ua_quirk(u))
            return False
        return super().acceptNavigationRequest(url, nav_type, is_main_frame)

    def _handle_interstitial_choice(self, url: QUrl) -> None:
        """React to the interstitial's Go-back / Continue links."""
        self._interstitial_active = False
        view = self._view
        pending = getattr(view, "_spoof_pending", None)
        view._spoof_pending = None
        if url.path() == "/continue" and pending is not None:
            # Trust this host for the rest of the session, then proceed.
            self.browser.spoof_allow(pending.host())
            QTimer.singleShot(0, lambda t=QUrl(pending): self._reissue(t))
        else:
            QTimer.singleShot(0, lambda: self.browser.spoof_leave(view))

    def _apply_ua_quirk(self, url: QUrl) -> None:
        try:
            changed = apply_ua_quirk(self.profile(), url.host())
        except RuntimeError:
            return  # page torn down before the deferred call fired
        # Re-issue the held navigation. On re-entry the identity already
        # matches, so acceptNavigationRequest lets it through — no loop.
        # After an actual switch, wait a beat first: the new UA propagates
        # to the renderer asynchronously, and loading immediately could
        # still expose the old navigator.userAgent to the page.
        reissue = lambda u=QUrl(url): self._reissue(u)
        QTimer.singleShot(150 if changed else 0, reissue)

    def _reissue(self, url: QUrl) -> None:
        try:
            self.setUrl(url)
        except RuntimeError:
            pass

    def javaScriptConsoleMessage(self, level, message, line, source_id):
        if message.startswith(self._capture_prefix):
            try:
                data = json.loads(message[len(self._capture_prefix):])
                username = str(data.get("u", ""))[:256]
                password = str(data.get("p", ""))[:256]
            except (ValueError, TypeError, AttributeError):
                return
            if password:
                self.captured.emit(username, password)
        # Everything else is dropped instead of forwarded: the default
        # handler writes page console output (which routinely includes
        # user data) to stderr/logs. DevTools has its own console feed,
        # so nothing is lost for debugging.


class BookmarkBar(QToolBar):
    """A strip of the user's bookmarks under the address bar, kept in
    alphabetical order. Being a QToolBar, it grows a '»' overflow menu on its
    own when there are more bookmarks than fit the width."""

    def __init__(self, bookmarks, open_url, favicon, fallback, parent=None):
        super().__init__(parent)
        self.setObjectName("bookmarkBar")
        self.setMovable(False)
        self.setFloatable(False)
        self.setToolButtonStyle(
            Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self._bookmarks = bookmarks
        self._open_url = open_url
        self._favicon = favicon        # host -> QIcon | None (captured icons)
        self._fallback = fallback      # () -> QIcon (generic globe)
        self.refresh()

    def refresh(self) -> None:
        self.clear()
        items = sorted(
            self._bookmarks.all(),
            key=lambda b: ((b.title or b.url).strip().lower(), b.url.lower()))
        for b in items:
            host = QUrl(b.url).host().lower()
            icon = self._favicon(host) if host else None
            if icon is None or icon.isNull():
                icon = self._fallback()
            title = (b.title or b.url).strip()
            label = title if len(title) <= 22 else title[:21] + "…"
            # QAction text/tooltip are plain text, so an imported bookmark
            # title carrying markup can't render as rich text here.
            act = self.addAction(icon, label)
            act.setToolTip(f"{title}\n{b.url}")
            act.triggered.connect(lambda _=False, u=b.url: self._open_url(u))
        self.setVisible(bool(items))


class NotifyBar(QFrame):
    """Slim, non-modal offer bar under the toolbar (fill / save / update)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("notifyBar")
        self.host = ""  # host the current offer belongs to
        self._accept_cb = None
        self._dismiss_cb = None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 6)
        self.label = QLabel()
        # Never interpret the message as rich text: it contains the page's
        # host and a captured username, both attacker-controlled. Rich text
        # would let e.g. <img src=http://evil> silently make a network call.
        self.label.setTextFormat(Qt.TextFormat.PlainText)
        self.accept_button = QPushButton()
        self.accept_button.setObjectName("notifyAccept")
        self.dismiss_button = QPushButton("Not now")
        layout.addWidget(self.label, 1)
        layout.addWidget(self.accept_button)
        layout.addWidget(self.dismiss_button)

        self.accept_button.clicked.connect(self._accept)
        self.dismiss_button.clicked.connect(self._dismiss)
        self.hide()

    def offer(self, host: str, text: str, accept_label: str,
              on_accept, on_dismiss=None) -> None:
        self.host = host
        self.label.setText(text)
        self.accept_button.setText(accept_label)
        self._accept_cb = on_accept
        self._dismiss_cb = on_dismiss
        self.show()

    def _accept(self) -> None:
        self.hide()
        callback, self._accept_cb, self._dismiss_cb = self._accept_cb, None, None
        if callback:
            callback()

    def _dismiss(self) -> None:
        self.hide()
        callback = self._dismiss_cb
        self._accept_cb = self._dismiss_cb = None
        if callback:
            callback()


class VersionLabel(QLabel):
    """Footer version tag; clicking opens the GitHub repo in a new tab.

    Sourced from about.APP_VERSION so it always matches the About screen —
    bumping the version there updates the footer automatically.
    """

    def __init__(self, browser: "BrowserWindow"):
        super().__init__(f"Vodou v{VERSION_DISPLAY} ")
        self.browser = browser
        self._update_available = False
        self.setObjectName("versionLabel")
        self.setToolTip(f"Open Vodou's GitHub repository\n{REPO_URL}")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def show_update_available(self, what: str) -> None:
        """Turn the tag into an update notice; clicking now opens About,
        where one click installs both parts."""
        self._update_available = True
        self.setText(f"Vodou v{VERSION_DISPLAY} — update available ⬆ ")
        self.setToolTip(f"Update available: {what}\n"
                        f"Click to open About Vodou and update")
        self.browser._center_version()  # width changed; keep it centred

    def show_up_to_date(self, restart_needed: bool = False) -> None:
        """Confirmed-current state: after a check found nothing newer, or
        right after the one-click updater ran ('updated' until the restart
        actually loads the new version)."""
        self._update_available = False
        if restart_needed:
            self.setText(f"Vodou v{VERSION_DISPLAY} — updated ✓ ")
            self.setToolTip("Update installed — close and reopen Vodou to "
                            "finish.\nClick to open the GitHub repository")
        else:
            self.setText(f"Vodou v{VERSION_DISPLAY} — up to date ✓ ")
            self.setToolTip("You are using the most current version.\n"
                            f"Click to open the GitHub repository\n{REPO_URL}")
        self.browser._center_version()  # width changed; keep it centred

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            if self._update_available:
                self.browser.show_about()
            else:
                self.browser.add_tab(QUrl(REPO_URL))
        super().mousePressEvent(event)


class WebView(QWebEngineView):
    """A tab's web view; opens popups/target=_blank as new tabs."""

    def __init__(self, browser: "BrowserWindow"):
        super().__init__()
        self.browser = browser
        # Set on crash-restored background tabs: the URL to load the first
        # time the tab is actually activated (see _load_pending).
        self.pending_url: QUrl | None = None
        # Set when a deceptive-site interstitial is showing in this tab: the
        # real URL to load if the user chooses "Continue anyway".
        self._spoof_pending: QUrl | None = None
        page = WebPage(browser, self)
        page.certificateError.connect(self._on_certificate_error)
        self.setPage(page)
        self._apply_settings(page.settings())

    @staticmethod
    def _on_certificate_error(error) -> None:
        if error.url().host() in CERT_EXEMPT_HOSTS:
            error.acceptCertificate()
        else:
            error.rejectCertificate()

    @staticmethod
    def _apply_settings(settings: QWebEngineSettings) -> None:
        attr = QWebEngineSettings.WebAttribute
        settings.setAttribute(attr.PluginsEnabled, False)
        settings.setAttribute(attr.ScreenCaptureEnabled, False)
        settings.setAttribute(attr.DnsPrefetchEnabled, False)
        settings.setAttribute(attr.HyperlinkAuditingEnabled, False)
        settings.setAttribute(attr.JavascriptCanAccessClipboard, False)
        settings.setAttribute(attr.FullScreenSupportEnabled, True)
        # Pin these explicitly rather than trusting Qt defaults: web content
        # must never reach local files, and HTTPS pages must not run
        # plaintext-HTTP scripts.
        settings.setAttribute(attr.LocalContentCanAccessRemoteUrls, False)
        settings.setAttribute(attr.LocalContentCanAccessFileUrls, False)
        settings.setAttribute(attr.AllowRunningInsecureContent, False)
        settings.setAttribute(attr.ScrollAnimatorEnabled, True)

    def createWindow(self, _type):
        return self.browser.add_tab()

    # Wheel events land on the engine's internal render widget, not on this
    # view — so Ctrl+wheel zoom is caught by filtering that child, grabbed
    # here the moment it is added.
    def childEvent(self, event) -> None:
        super().childEvent(event)
        if (event.type() == QEvent.Type.ChildAdded
                and event.child().isWidgetType()):
            event.child().installEventFilter(self)

    def eventFilter(self, obj, event) -> bool:
        if (event.type() == QEvent.Type.Wheel
                and event.modifiers() & Qt.KeyboardModifier.ControlModifier):
            delta = event.angleDelta().y()
            if delta:
                self.browser.zoom_view(self, 1 if delta > 0 else -1)
            return True  # don't also scroll the page
        return super().eventFilter(obj, event)


class BrowserWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vodou Browser — private")
        self.resize(1280, 830)

        # Hybrid profile. Fully off-the-record forced Chromium's HTTP cache
        # into RAM, which starves smaller machines during heavy browsing.
        # Instead, the bulky but low-sensitivity artifacts (HTTP cache, site
        # storage) live in a size-capped folder on disk, while cookies stay
        # memory-only. Everything under PROFILE_DIR is shredded — overwritten
        # with random bytes, then deleted (see shred.py) — on every exit, and
        # again at startup to cover a run that crashed before its wipe.
        self.profile = QWebEngineProfile("vodou", self)
        self.profile.setCachePath(str(PROFILE_DIR / "cache"))
        self.profile.setPersistentStoragePath(str(PROFILE_DIR / "storage"))
        self.profile.setHttpCacheType(
            QWebEngineProfile.HttpCacheType.DiskHttpCache)
        self.profile.setHttpCacheMaximumSize(512 * 1024 * 1024)
        self.profile.setPersistentCookiesPolicy(
            QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)
        self.profile.setHttpUserAgent(GENERIC_USER_AGENT)

        # Cookie exceptions: cookies stay memory-only except for sites the
        # user allowlists (☰ → Settings → Cookie exceptions…) — those are
        # mirrored to an encrypted jar and restored here at startup.
        self.cookie_keeper = CookieKeeper(self.profile.cookieStore(), self)
        self.cookie_keeper.restore()

        self.interceptor = PrivacyInterceptor(self)
        self.profile.setUrlRequestInterceptor(self.interceptor)
        self.profile.downloadRequested.connect(self._on_download)

        # Hosts the user explicitly chose to visit past a deceptive-site
        # warning. Session-only on purpose: the warning returns next launch.
        self._spoof_allowed_hosts: set[str] = set()

        # Local, privacy-preserving Safe Browsing: reported phishing/malware
        # hosts are checked entirely offline (see safebrowsing.py). Started
        # a little after launch so the first list fetch doesn't compete with
        # the initial page load.
        self.safe_browsing = SafeBrowsing(self)
        self.safe_browsing.updated.connect(
            lambda n: self.statusBar().showMessage(
                f"Safe Browsing: {n:,} reported unsafe sites loaded.", 5000))
        QTimer.singleShot(12000, self.safe_browsing.start)

        # On-demand AI summaries of search results via a local Ollama instance
        # (see ai_search.py). Entirely on-device; Vodou is only an HTTP client
        # of Ollama and never alters its models or config. Built lazily.
        self.ai_cfg = load_ai_config()
        self.ai_summarizer = OllamaSummarizer(self)
        self.ai_summarizer.chunk.connect(self._on_ai_chunk)
        self.ai_summarizer.thinking.connect(self._on_ai_thinking)
        self.ai_summarizer.finished.connect(self._on_ai_finished)
        self.ai_summarizer.failed.connect(self._on_ai_failed)
        self._ai_panel = None
        self._ai_last: tuple[str, list] | None = None

        # Credential capture: random per-session token so pages can't forge
        # capture messages; script runs in the isolated ApplicationWorld.
        self.capture_prefix = f"__vodou_{secrets.token_urlsafe(16)}__:"
        capture_script = QWebEngineScript()
        capture_script.setName("vodou-capture")
        capture_script.setInjectionPoint(
            QWebEngineScript.InjectionPoint.DocumentCreation)
        capture_script.setWorldId(APP_WORLD)
        capture_script.setRunsOnSubFrames(False)
        capture_script.setSourceCode(
            build_capture_script(self.capture_prefix))
        self.profile.scripts().insert(capture_script)

        # Firefox-identity JS quirk for Google's sign-in pages (see
        # privacy.FIREFOX_QUIRK_JS). Main world on purpose: it changes what
        # the page's own scripts observe; the script self-limits to the
        # auth hosts.
        ff_quirk = QWebEngineScript()
        ff_quirk.setName("vodou-ff-quirk")
        ff_quirk.setInjectionPoint(
            QWebEngineScript.InjectionPoint.DocumentCreation)
        ff_quirk.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        ff_quirk.setRunsOnSubFrames(True)
        ff_quirk.setSourceCode(FIREFOX_QUIRK_JS)
        self.profile.scripts().insert(ff_quirk)

        # WebAuthn capability shim for the engine's never-settling
        # getClientCapabilities() (see privacy.WEBAUTHN_SHIM_JS). All sites:
        # the bug breaks any passkey flow that awaits capability detection.
        webauthn_shim = QWebEngineScript()
        webauthn_shim.setName("vodou-webauthn-shim")
        webauthn_shim.setInjectionPoint(
            QWebEngineScript.InjectionPoint.DocumentCreation)
        webauthn_shim.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        webauthn_shim.setRunsOnSubFrames(True)
        webauthn_shim.setSourceCode(WEBAUTHN_SHIM_JS)
        self.profile.scripts().insert(webauthn_shim)

        # Reviewed, opt-in plugins injected into the isolated world. State is
        # ID-only (no code from disk); each plugin self-limits to its hosts.
        self.plugins = PluginManager()
        self._plugin_scripts: list[QWebEngineScript] = []
        self._apply_plugins()

        self._fill_offer_dismissed: set[str] = set()        # hosts
        self._capture_dismissed: set[tuple[str, str]] = set()  # (host, user)
        # Last zoom the user chose; new tabs inherit it so zooming once
        # sticks for the whole session (resets to 100% on restart).
        self._zoom = 1.0

        self.vault = Vault()
        self.bookmarks = Bookmarks()
        self._vault_lock_timer = QTimer(self)
        self._vault_lock_timer.setSingleShot(True)
        self._vault_lock_timer.setInterval(VAULT_AUTOLOCK_MINUTES * 60 * 1000)
        self._vault_lock_timer.timeout.connect(self._autolock_vault)
        # The vault window is modeless, so it outlives the call that opened
        # it; this holds the live one (None when closed).
        self._vault_dialog: VaultDialog | None = None

        self.blocked_count = 0
        # Aggregated per-day history behind the ☰ → Blocking report window.
        self.block_stats = BlockStats(self)
        self._report_window: BlockingReportWindow | None = None
        self.interceptor.blocked.connect(self._on_blocked)
        # Ad-heavy pages can block dozens of requests per second; coalesce
        # the label repaints instead of doing one per request.
        self._shield_timer = QTimer(self)
        self._shield_timer.setSingleShot(True)
        self._shield_timer.setInterval(250)
        self._shield_timer.timeout.connect(self._refresh_shield)

        # Crash-recovery snapshot of the open tabs. Navigation bursts are
        # coalesced into one debounced disk write; the file is deleted on
        # clean exit, so its presence at startup means the last run crashed.
        self._session_timer = QTimer(self)
        self._session_timer.setSingleShot(True)
        self._session_timer.setInterval(1000)
        self._session_timer.timeout.connect(self._write_session)

        self._build_ui()
        self._build_shortcuts()
        if not self._offer_crash_restore():
            self.add_tab(QUrl(HOME_URL))

        # Quiet startup update check (GitHub + PyPI, anonymous GETs of public
        # files). Delayed so it never competes with first-page load; failures
        # stay silent.
        self._update_checker = UpdateChecker(self)
        self._update_checker.finished.connect(self._on_update_check)
        QTimer.singleShot(10000, self._update_checker.start)

    # -- UI ---------------------------------------------------------------

    def _build_ui(self) -> None:
        # Needed before any theme-colored icon is generated below; the
        # Appearance menu loads the same prefs again later (harmless).
        self._theme_name, self._mode = load_prefs()

        # Toolbar/address-bar icons are painted vectors in the theme color
        # (icons.py), not glyphs or image files. Build the cache first; every
        # widget below pulls its icon from it, and a theme switch regenerates
        # it (see _rebuild_icon_cache / _refresh_chrome_icons).
        self._icon_targets: list[tuple[object, str]] = []
        self._rebuild_icon_cache()

        # The tab bar is decoupled from the page area (a QTabBar driving a
        # QStackedWidget) so the address bar and bookmark bar can sit BETWEEN
        # the tabs and the page — the vertical order top to bottom is:
        # tabs · address bar · bookmarks bar · page.
        self.tab_bar = QTabBar()
        self.tab_bar.setObjectName("mainTabBar")
        self.tab_bar.setTabsClosable(True)
        self.tab_bar.setMovable(True)
        self.tab_bar.setDocumentMode(True)
        self.tab_bar.setExpanding(False)
        self.tab_bar.setUsesScrollButtons(True)
        self.tab_bar.setElideMode(Qt.TextElideMode.ElideRight)
        self.tab_bar.currentChanged.connect(self._on_tab_changed)
        self.tab_bar.tabCloseRequested.connect(self.close_tab)
        self.tab_bar.tabMoved.connect(self._on_tab_moved)
        self.tab_bar.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu)
        self.tab_bar.customContextMenuRequested.connect(self._tab_context_menu)
        self.tab_stack = QStackedWidget()

        # "+" opens a new tab, sitting just to the right of the last tab.
        self.plus_button = QToolButton()
        self.plus_button.setObjectName("newTabButton")
        self.plus_button.setIcon(self._icons["plus"])
        self.plus_button.setIconSize(QSize(18, 18))
        self.plus_button.setToolTip("New tab (Ctrl+T)")
        self.plus_button.clicked.connect(lambda: self.add_tab(QUrl(HOME_URL)))
        self._icon_targets.append((self.plus_button, "plus"))

        tab_strip = QWidget()
        tab_strip.setObjectName("tabStrip")
        strip = QHBoxLayout(tab_strip)
        strip.setContentsMargins(6, 4, 6, 0)
        strip.setSpacing(4)
        strip.addWidget(self.tab_bar)
        strip.addWidget(self.plus_button)
        strip.addStretch(1)

        # Page area: the stack of tab pages, with the DevTools panel docking to
        # the right of this splitter when developer tools are enabled.
        self._split = QSplitter(Qt.Orientation.Horizontal)
        self._split.setChildrenCollapsible(False)
        self._split.addWidget(self.tab_stack)

        self.notify_bar = NotifyBar()
        # Favicons for the bookmarks bar: captured from pages you browse /
        # bookmark, cached only for bookmarked hosts (see favicons.py).
        self.favicons = FaviconStore(Path.home() / ".vodou" / "favicons")
        self._bmk_hosts: set[str] = set()
        self.bookmark_bar = BookmarkBar(
            self.bookmarks, self._open_bookmark, self.favicons.get,
            lambda: self._bookmark_fallback)

        toolbar = QToolBar("Navigation")
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(20, 20))

        container = QWidget()
        vbox = QVBoxLayout(container)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        vbox.addWidget(tab_strip)          # tabs + "+"          (top)
        vbox.addWidget(toolbar)            # address / navigation
        vbox.addWidget(self.bookmark_bar)  # bookmarks bar
        vbox.addWidget(self.notify_bar)    # save/fill offer bar
        vbox.addWidget(self._split, 1)     # page area           (fills)
        self.setCentralWidget(container)

        def action(icon_name: str, tip: str, slot,
                   shortcut: str | None = None):
            act = QAction(self)
            act.setToolTip(tip)
            act.triggered.connect(slot)
            if shortcut:
                act.setShortcut(QKeySequence(shortcut))
            toolbar.addAction(act)
            self._icon_targets.append((act, icon_name))
            return act

        action("back", "Back (Alt+Left)", lambda: self.current_view().back())
        action("forward", "Forward (Alt+Right)",
               lambda: self.current_view().forward())
        action("reload", "Reload (Ctrl+R)", self.reload_page)
        action("home", "Home",
               lambda: self.current_view().setUrl(QUrl(HOME_URL)))

        self.url_bar = QLineEdit()
        self.url_bar.setObjectName("urlBar")
        self.url_bar.setPlaceholderText(
            "Search SearXNG or enter address (HTTPS-first)")
        self.url_bar.returnPressed.connect(self._navigate)
        # Security pill: the lock lives inside the address bar as a leading,
        # clickable icon whose colour carries the state (green closed / red
        # open / muted info). Clicking it shows the certificate.
        self.lock_action = self.url_bar.addAction(
            self._lock_icons["neutral"],
            QLineEdit.ActionPosition.LeadingPosition)
        self.lock_action.setToolTip("Internal page")
        self.lock_action.triggered.connect(self.show_certificate)
        self._lock_state = "neutral"
        toolbar.addWidget(self.url_bar)

        # AI-summary button: accent-coloured sparkle, sits just right of the
        # address bar (before the bookmark star). Icon set directly rather than
        # through the theme-text set so it keeps the accent colour; a theme
        # switch repaints it in _refresh_chrome_icons.
        self.ai_action = QAction(self)
        self.ai_action.setIcon(self._ai_icon)
        self.ai_action.setToolTip(
            "Summarize these search results with local AI (Ollama) — "
            "on-device, nothing sent out")
        self.ai_action.triggered.connect(self.summarize_search)
        toolbar.addAction(self.ai_action)

        self.star_button = QToolButton()
        self.star_button.setObjectName("starButton")
        self.star_button.setIcon(self._star_off)
        self.star_button.setToolTip("Bookmark this page (Ctrl+D)")
        self.star_button.clicked.connect(self.toggle_bookmark)
        toolbar.addWidget(self.star_button)

        self.bookmarks_button = QToolButton()
        self.bookmarks_button.setToolTip("Bookmarks")
        self.bookmarks_button.setPopupMode(
            QToolButton.ToolButtonPopupMode.InstantPopup)
        self._bookmarks_menu = QMenu(self.bookmarks_button)
        self._bookmarks_menu.aboutToShow.connect(
            lambda: self._populate_bookmarks_menu(self._bookmarks_menu))
        self.bookmarks_button.setMenu(self._bookmarks_menu)
        toolbar.addWidget(self.bookmarks_button)
        self._icon_targets.append((self.bookmarks_button, "bookmarks"))

        action("key", "Fill saved login on this page (Ctrl+Shift+F)",
               self.fill_login)
        action("save", "Save a login for this site", self.save_login_for_site)
        action("vault", "Open password vault (Ctrl+Shift+V)", self.open_vault)

        menu_button = QToolButton()
        menu_button.setToolTip("Menu")
        menu_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self._icon_targets.append((menu_button, "menu"))
        menu = QMenu(menu_button)
        clear_action = menu.addAction("Clear history & memory\tCtrl+Shift+Del",
                                      self.clear_browsing_data)
        clear_action.setToolTip(
            "Erase visited-link history, the HTTP cache, cookies (including "
            "the saved ones for allowlisted sites), the recorded blocking "
            "statistics, and each tab's back/forward navigation memory")
        menu.addSeparator()
        hamburger_bookmarks = menu.addMenu("Bookmarks")
        hamburger_bookmarks.aboutToShow.connect(
            lambda: self._populate_bookmarks_menu(hamburger_bookmarks))
        self._build_appearance_menu(menu.addMenu("Appearance"))
        zoom_menu = menu.addMenu("Zoom")
        zoom_menu.addAction("Zoom in\tCtrl++", self.zoom_in)
        zoom_menu.addAction("Zoom out\tCtrl+-", self.zoom_out)
        zoom_menu.addAction("Reset zoom\tCtrl+0", self.zoom_reset)
        settings_menu = menu.addMenu("Settings")
        self._build_graphics_menu(settings_menu.addMenu("Graphics"))
        self.pause_blocking_action = settings_menu.addAction(
            "Pause tracker blocking")
        self.pause_blocking_action.setCheckable(True)
        self.pause_blocking_action.setToolTip(
            "Let tracker/ad requests through until resumed — for sites "
            "that break with blocking on. Blocking resumes on restart.")
        self.pause_blocking_action.toggled.connect(self._set_blocking_paused)
        settings_menu.addAction("Cookie exceptions…", self.manage_cookie_sites)
        self.safe_browsing_action = settings_menu.addAction(
            "Safe Browsing")
        self.safe_browsing_action.setCheckable(True)
        self.safe_browsing_action.setChecked(self.safe_browsing.enabled)
        self.safe_browsing_action.setToolTip(
            "Warn before opening sites on public phishing/malware lists. "
            "Checked entirely on your device — nothing about your browsing "
            "is ever sent out.")
        self.safe_browsing_action.toggled.connect(self._set_safe_browsing)
        settings_menu.addAction("Safe Browsing status…",
                                self.show_safe_browsing_status)
        self.ai_search_action = settings_menu.addAction(
            "AI search summaries (Ollama)")
        self.ai_search_action.setCheckable(True)
        self.ai_search_action.setChecked(bool(self.ai_cfg.get("enabled")))
        self.ai_search_action.setToolTip(
            "Show a 'Summarize' button on search results that summarizes them "
            "with your local Ollama model. Runs entirely on your device; "
            "nothing about your search is ever sent out.")
        self.ai_search_action.toggled.connect(self._set_ai_search)
        settings_menu.addAction("AI summary options…", self.show_ai_options)
        menu.addSeparator()
        report = menu.addAction("Blocking report…", self.show_blocking_report)
        report.setToolTip(
            "Charts of how many trackers and ads were blocked per day, "
            "and which ones came up most")
        menu.addAction("Downloads…\tCtrl+J", self.show_downloads)
        menu.addSeparator()
        menu.addAction("Password vault…\tCtrl+Shift+V", self.open_vault)
        menu.addAction("Import passwords (.csv)…", self.import_passwords)
        menu.addSeparator()
        menu.addAction("Plugins…", self.open_plugins)
        menu.addAction("Developer tools\tF12", self.open_dev_tools)
        menu.addSeparator()
        help_menu = menu.addMenu("Help")
        report = help_menu.addAction("Report an issue…", self.report_issue)
        report.setToolTip(
            "Open a new GitHub issue with the version, commit, and "
            "platform details pre-filled")
        help_menu.addAction("View on GitHub",
                            lambda: self.add_tab(QUrl(REPO_URL)))
        help_menu.addSeparator()
        help_menu.addAction("About Vodou…", self.show_about)
        menu_button.setMenu(menu)
        toolbar.addWidget(menu_button)
        self._apply_static_icons()

        # The version tag floats as a direct child of the status bar (outside
        # its layout) so it can sit dead-centre in the footer; an event filter
        # re-centres it whenever the bar resizes.
        self.version_label = VersionLabel(self)
        self.version_label.setParent(self.statusBar())
        self.version_label.show()

        # The tracker counter lives at the right as a permanent widget; the
        # status-bar layout keeps it right-aligned as its text grows. Clicking
        # it toggles tracker-blocking pause.
        self.shield_label = QLabel(" 🛡 0 trackers blocked ")
        self.shield_label.setObjectName("shieldLabel")
        self.shield_label.setToolTip("Click to pause/resume tracker blocking")
        self.shield_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.shield_label.installEventFilter(self)  # click toggles pause
        self.statusBar().addPermanentWidget(self.shield_label)

        self.statusBar().installEventFilter(self)
        self.statusBar().showMessage(
            "Private session: history, cookies and cache are memory-only "
            "and erased on exit.", 8000)
        self._center_version()
        # Seed the bookmarked-host set and drop favicons for bookmarks that
        # were removed in a previous session.
        self._bookmarks_changed()

    def _build_shortcuts(self) -> None:
        bindings = {
            "Ctrl+T": lambda: self.add_tab(QUrl(HOME_URL)),
            "Ctrl+W": lambda: self.close_tab(self.tab_bar.currentIndex()),
            "Ctrl+L": self._focus_url_bar,
            "Ctrl+R": self.reload_page,
            "F5": self.reload_page,
            "Ctrl+Shift+F": self.fill_login,
            "Ctrl+Shift+V": self.open_vault,
            "Ctrl+Shift+Del": self.clear_browsing_data,
            "Ctrl+D": self.toggle_bookmark,
            "Ctrl+J": self.show_downloads,
            "Ctrl+Tab": self._next_tab,
            "F12": self.open_dev_tools,
            # Ctrl+= is the unshifted key Ctrl++ lives on; bind both so
            # zooming works without holding Shift.
            "Ctrl+=": self.zoom_in,
            "Ctrl++": self.zoom_in,
            "Ctrl+-": self.zoom_out,
            "Ctrl+0": self.zoom_reset,
        }
        for keys, slot in bindings.items():
            QShortcut(QKeySequence(keys), self, activated=slot)

    def _focus_url_bar(self) -> None:
        self.url_bar.setFocus()
        self.url_bar.selectAll()

    def _next_tab(self) -> None:
        count = self.tab_bar.count()
        if count:
            self.tab_bar.setCurrentIndex(
                (self.tab_bar.currentIndex() + 1) % count)

    # -- tabs ---------------------------------------------------------------

    def add_tab(self, url: QUrl | None = None) -> WebView:
        view = WebView(self)
        if self._zoom != 1.0:
            view.setZoomFactor(self._zoom)
        # Keep the tab bar and the page stack index-aligned: both append.
        index = self.tab_stack.addWidget(view)
        self.tab_bar.insertTab(index, "New tab")
        self.tab_bar.setCurrentIndex(index)
        self.tab_stack.setCurrentIndex(index)

        view.urlChanged.connect(lambda u, v=view: self._on_url_changed(v, u))
        view.titleChanged.connect(lambda t, v=view: self._on_title_changed(v, t))
        view.iconChanged.connect(
            lambda icon, v=view: self._on_icon_changed(v, icon))
        view.page().fullScreenRequested.connect(self._on_fullscreen)
        view.loadFinished.connect(
            lambda ok, v=view: self._maybe_offer_fill(v, ok))
        view.page().captured.connect(
            lambda user, pw, v=view: self._on_captured(v, user, pw))

        if url is not None:
            view.setUrl(url)
        return view

    def close_tab(self, index: int) -> None:
        if self.tab_bar.count() == 1:
            self.close()
            return
        view = self.tab_stack.widget(index)
        self.tab_bar.removeTab(index)
        if view is not None:
            self.tab_stack.removeWidget(view)
            view.deleteLater()
        self._schedule_session_save()

    def _tab_context_menu(self, pos) -> None:
        """Right-click on the tab bar: act on the tab under the cursor."""
        index = self.tab_bar.tabAt(pos)
        menu = QMenu(self)
        menu.addAction("New tab", lambda: self.add_tab(QUrl(HOME_URL)))
        if index >= 0:
            menu.addSeparator()
            menu.addAction("Close tab", lambda i=index: self.close_tab(i))
            others = menu.addAction(
                "Close other tabs", lambda i=index: self._close_other_tabs(i))
            others.setEnabled(self.tab_bar.count() > 1)
        menu.exec(self.tab_bar.mapToGlobal(pos))

    def _close_other_tabs(self, keep_index: int) -> None:
        # Close by widget identity so shifting indices can't close the wrong
        # tab as the list shrinks.
        keep = self.tab_stack.widget(keep_index)
        for i in range(self.tab_bar.count() - 1, -1, -1):
            if self.tab_stack.widget(i) is not keep:
                self.close_tab(i)

    def _on_tab_moved(self, frm: int, to: int) -> None:
        """A dragged tab: reorder the page stack to match, keeping the two
        index-aligned, then re-sync the current page."""
        view = self.tab_stack.widget(frm)
        if view is not None:
            self.tab_stack.removeWidget(view)
            self.tab_stack.insertWidget(to, view)
        self.tab_stack.setCurrentIndex(self.tab_bar.currentIndex())
        self._schedule_session_save()

    def current_view(self) -> WebView:
        return self.tab_stack.currentWidget()

    def _open_bookmark(self, url: str) -> None:
        self.add_tab(QUrl(url))

    def _on_icon_changed(self, view: WebView, icon) -> None:
        index = self.tab_stack.indexOf(view)
        if index >= 0:
            self.tab_bar.setTabIcon(index, icon)
        # Capture the favicon for the bookmarks bar, but only for hosts the
        # user has bookmarked — never a broader record of where you've been.
        host = view.url().host().lower()
        if host in self._bmk_hosts and self.favicons.put(host, icon):
            self.bookmark_bar.refresh()

    def _bookmarked_hosts(self) -> set[str]:
        hosts = set()
        for b in self.bookmarks.all():
            host = QUrl(b.url).host().lower()
            if host:
                hosts.add(host)
        return hosts

    def _bookmarks_changed(self) -> None:
        """Keep the bookmarks bar, the host set, and the favicon cache in step
        after any add / remove / import."""
        self._bmk_hosts = self._bookmarked_hosts()
        self.favicons.prune(self._bmk_hosts)
        self.bookmark_bar.refresh()

    def reload_page(self) -> None:
        """Reload the current tab, bypassing the HTTP cache.

        Vodou's disk cache exists to spare RAM, not to speed up reloads —
        and pages whose content depends on a cookie (SearXNG's theme, many
        preference pages) carry no Cache-Control/Vary, so a cache-allowed
        reload can serve a stale copy after you change a setting. An
        explicit reload should always show the live page, so it fetches
        fresh; the cache still serves ordinary re-navigation."""
        view = self.current_view()
        if view is not None:
            view.page().triggerAction(
                QWebEnginePage.WebAction.ReloadAndBypassCache)

    # -- zoom ---------------------------------------------------------------

    def zoom_view(self, view: WebView, direction: int) -> None:
        """Step one view up/down the zoom ladder from its current factor."""
        current = view.zoomFactor()
        nearest = min(range(len(ZOOM_LEVELS)),
                      key=lambda i: abs(ZOOM_LEVELS[i] - current))
        stepped = max(0, min(len(ZOOM_LEVELS) - 1, nearest + direction))
        self._set_zoom(view, ZOOM_LEVELS[stepped])

    def zoom_in(self) -> None:
        self.zoom_view(self.current_view(), +1)

    def zoom_out(self) -> None:
        self.zoom_view(self.current_view(), -1)

    def zoom_reset(self) -> None:
        self._set_zoom(self.current_view(), 1.0)

    def _set_zoom(self, view: WebView, factor: float) -> None:
        view.setZoomFactor(factor)
        self._zoom = factor
        self.statusBar().showMessage(f"Zoom: {round(factor * 100)}%", 2500)

    def _on_fullscreen(self, request) -> None:
        request.accept()
        self.statusBar().showMessage(
            "A site entered full-screen mode — press Esc to leave.", 4000)

    def closeEvent(self, event) -> None:
        clear_copied_secrets()  # no passwords left on the clipboard
        self.ai_summarizer.cancel()  # drop any in-flight Ollama request
        self._session_timer.stop()
        clear_snapshot()  # clean exit — a leftover file means "crashed"
        self.cookie_keeper.flush()  # capture last cookie updates in the jar
        # The vault window has no parent (so it can fall behind), which also
        # means it won't be torn down with this one — close it explicitly or
        # it would outlive the browser and keep the process alive.
        if self._vault_dialog is not None:
            self._vault_dialog.close()
        if self._report_window is not None:
            self._report_window.close()
        # Blocking stats are in-memory only; they simply go with the process.
        super().closeEvent(event)

    def manage_cookie_sites(self) -> None:
        dialog = CookieSitesDialog(self.cookie_keeper.sites, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.cookie_keeper.set_sites(dialog.sites())
            n = len(self.cookie_keeper.sites)
            self.statusBar().showMessage(
                f"Cookie exceptions saved ({n} site{'s' if n != 1 else ''}). "
                "Reload a site (or sign in again) to capture its cookies.",
                6000)

    def _set_safe_browsing(self, on: bool) -> None:
        self.safe_browsing.set_enabled(on)
        self.statusBar().showMessage(
            "Safe Browsing on — updating the list…" if on
            else "Safe Browsing off.", 5000)

    def show_safe_browsing_status(self) -> None:
        sb = self.safe_browsing
        when = sb.last_updated()
        when_txt = when.strftime("%d %b %Y, %H:%M") if when else "not yet"
        state = "on" if sb.enabled else "off"
        plain_message(
            self, QMessageBox.Icon.Information, "Safe Browsing",
            f"Safe Browsing is {state}.\n\n"
            f"Reported unsafe sites loaded: {sb.count():,}\n"
            f"List last updated: {when_txt}\n\n"
            "Sites are checked entirely on your device against public "
            "phishing/malware lists — nothing about your browsing is ever "
            "sent out. The only network activity is a periodic anonymous "
            "download of the public lists.\n\n"
            "Add your own hosts in ~/.vodou/safebrowsing_extra.txt, or set "
            "custom list URLs in ~/.vodou/safebrowsing_sources.txt.",
            QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.Ok)
        sb.refresh()

    # -- crash recovery ---------------------------------------------------

    def _offer_crash_restore(self) -> bool:
        """If the last run ended unexpectedly, offer those tabs back.

        Returns True when tabs were restored, so the caller skips opening
        the usual home tab. Restored background tabs are NOT loaded up
        front — each starts loading the first time it's activated, so
        recovering a big session costs one page load, not one per tab.
        """
        snapshot = load_snapshot()
        if snapshot is None:
            return False
        urls, current = snapshot
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Restore session?")
        n = len(urls)
        box.setText(
            "Vodou didn't shut down cleanly last time.\n\nPick up where "
            f"you left off and reopen {'that tab' if n == 1 else f'those {n} tabs'}?")
        restore = box.addButton(
            "Restore tabs", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Start fresh", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is not restore:
            clear_snapshot()
            return False
        for u in urls:
            view = self.add_tab(None)
            view.pending_url = QUrl(u)
            # Label the unloaded tab with its host so it's recognizable.
            self.tab_bar.setTabText(self.tab_stack.indexOf(view),
                                    view.pending_url.host() or u)
        self.tab_bar.setCurrentIndex(current)
        self._load_pending(self.tab_stack.widget(current))
        return True

    @staticmethod
    def _load_pending(view: WebView | None) -> None:
        if view is not None and view.pending_url is not None:
            url, view.pending_url = view.pending_url, None
            view.setUrl(url)

    def _schedule_session_save(self) -> None:
        if not self._session_timer.isActive():
            self._session_timer.start()

    def _write_session(self) -> None:
        urls: list[str] = []
        current = 0
        cur = self.tab_stack.currentWidget()
        for i in range(self.tab_stack.count()):
            view = self.tab_stack.widget(i)
            url = view.pending_url or view.url()
            text = url.toString()
            if (text and url.scheme() in ("http", "https", "file")
                    and url.host() != SENTINEL_HOST):
                if view is cur:
                    current = len(urls)
                urls.append(text)
        save_snapshot(urls, current)

    def _on_tab_changed(self, index: int) -> None:
        self.notify_bar.hide()
        self._schedule_session_save()
        if index < 0:
            return
        self.tab_stack.setCurrentIndex(index)
        view = self.tab_stack.widget(index)
        self._load_pending(view)
        if view is not None:
            # A tab parked on the deceptive-site interstitial reflects the
            # blocked host, not the internal sentinel URL.
            if view.url().host() == SENTINEL_HOST:
                self._on_url_changed(view, view.url())
                return
            self.url_bar.setText(view.url().toString())
            self._update_security_indicator(view.url())
            self._update_star(view.url())
            # Keep docked DevTools pointed at whichever tab is now active.
            if getattr(self, "_devtools_open", False):
                view.page().setDevToolsPage(self._devtools_view.page())

    def _on_url_changed(self, view: WebView, url: QUrl) -> None:
        self._schedule_session_save()
        if view is not self.current_view():
            return
        # The deceptive-site interstitial: show the blocked host itself in the
        # address bar (so the user sees what was refused) with a danger lock,
        # not the internal sentinel URL the page is actually based on.
        if url.host() == SENTINEL_HOST:
            pending = view._spoof_pending
            self.url_bar.setText(pending.toString() if pending else "")
            self.url_bar.setCursorPosition(0)
            self.lock_action.setIcon(self._lock_icons["insecure"])
            self.lock_action.setToolTip("Deceptive site — blocked by Vodou")
            self._lock_state = "insecure"
            self.notify_bar.hide()
            return
        self.url_bar.setText(url.toString())
        self.url_bar.setCursorPosition(0)
        self._update_security_indicator(url)
        self._update_star(url)
        # Keep save/update offers alive across same-site navigation
        # (logging in usually navigates); drop them when leaving.
        if url.host().removeprefix("www.") != self.notify_bar.host:
            self.notify_bar.hide()

    # -- deceptive-site (spoof) protection --------------------------------

    @staticmethod
    def _norm_host(host: str) -> str:
        return host.strip().rstrip(".").lower()

    def spoof_allowed(self, host: str) -> bool:
        return self._norm_host(host) in self._spoof_allowed_hosts

    def spoof_allow(self, host: str) -> None:
        self._spoof_allowed_hosts.add(self._norm_host(host))

    def show_spoof_interstitial(self, view: "WebView", verdict,
                                pending_url: QUrl) -> None:
        """Replace the blocked page with a full-page deceptive-site warning.
        The page is generated locally (inline CSS, escaped host/brand) and its
        buttons navigate to the sentinel host handled in acceptNavigationRequest.
        """
        try:
            page = view.page()
        except RuntimeError:
            return
        view._spoof_pending = pending_url
        p = build_palette(self._theme_name, self._mode)
        colors = {
            "bg": p.bg, "surface": p.surface, "text": p.text,
            "muted": p.muted, "border": p.border, "danger": p.danger,
            "ok": p.ok, "accent": p.accent, "on_accent": p.on_accent,
        }
        html = interstitial_html(verdict, colors)
        # Base the page on the sentinel host so its identity is unambiguous and
        # the address bar can show the deceptive host itself (_on_url_changed).
        page.setHtml(html, QUrl(f"https://{SENTINEL_HOST}/warning"))
        if view is self.current_view():
            self.statusBar().showMessage(
                "Blocked a suspected deceptive site.", 6000)

    def spoof_leave(self, view: "WebView") -> None:
        """'Go back (safe)': return to the previous page, or home if none."""
        try:
            if view.history().canGoBack():
                view.back()
            else:
                view.setUrl(QUrl(HOME_URL))
        except RuntimeError:
            pass

    # -- security indicator / certificate viewer ---------------------------

    def _update_security_indicator(self, url: QUrl) -> None:
        scheme = url.scheme()
        if scheme == "https":
            state = "secure"
            tip = (f"Secure connection to {url.host()}\n"
                   f"Click to view the certificate")
        elif scheme == "http":
            state = "insecure"
            tip = ("Not secure — this connection is unencrypted.\n"
                   "Anything you send can be read in transit.")
        else:
            state = "neutral"
            tip = "Internal page"
        self.lock_action.setIcon(self._lock_icons[state])
        self.lock_action.setToolTip(tip)
        self._lock_state = state

    def show_certificate(self) -> None:
        url = self.current_view().url()
        host = url.host()
        if url.scheme() != "https" or not host:
            if url.scheme() == "http":
                QMessageBox.warning(
                    self, "Not secure",
                    f"The connection to {host or 'this page'} is not "
                    f"encrypted — there is no certificate to show.")
            else:
                QMessageBox.information(
                    self, "Internal page",
                    "This is an internal page with no network connection.")
            return

        # Deferred import: keeps ssl/x509 parsing out of the startup path.
        from cert_viewer import CertificateDialog, fetch_certificate

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            probe = fetch_certificate(host, url.port(443))
        except Exception as error:
            QApplication.restoreOverrideCursor()
            plain_message(
                self, QMessageBox.Icon.Warning, "Certificate unavailable",
                f"Could not retrieve the certificate for {host}:\n{error}")
            return
        finally:
            QApplication.restoreOverrideCursor()
        CertificateDialog(host, probe, self).exec()

    def _on_title_changed(self, view: WebView, title: str) -> None:
        index = self.tab_stack.indexOf(view)
        short = title if len(title) <= 25 else title[:24] + "…"
        self.tab_bar.setTabText(index, short or "New tab")
        self.tab_bar.setTabToolTip(index, title)
        if view is self.current_view():
            self.setWindowTitle(f"{title} — Vodou (private)")

    def _navigate(self) -> None:
        self.current_view().setUrl(to_url(self.url_bar.text()))
        self.current_view().setFocus()

    # -- bookmarks --------------------------------------------------------

    # -- theme-colored chrome icons ---------------------------------------

    def _rebuild_icon_cache(self) -> None:
        """(Re)generate the vector icon set in the active theme colours.

        Called once at build time and again on every live theme/mode switch
        so the chrome icons follow the theme. Static icons come straight from
        the shared set; the state-dependent ones (a filled bookmark star in
        the accent, the three security-pill locks) are pre-rendered here in
        their state colours so the hot paths just swap a cached QIcon."""
        p = build_palette(self._theme_name, self._mode)
        self._icons = icon_set(p.text)
        self._star_off = self._icons["star"]
        self._star_on = make_icon("star-filled", p.accent)
        # AI-summary sparkle: painted in the accent colour so it stands out
        # from the monochrome navigation icons.
        self._ai_icon = make_icon("sparkle", p.accent)
        # Generic mark for a bookmark with no captured favicon yet.
        self._bookmark_fallback = make_icon("globe", p.muted)
        self._lock_icons = {
            "secure": make_icon("lock", p.ok),
            "insecure": make_icon("lock-open", p.danger),
            "neutral": make_icon("info", p.muted),
        }

    def _apply_static_icons(self) -> None:
        for widget, name in self._icon_targets:
            widget.setIcon(self._icons[name])

    def _refresh_chrome_icons(self) -> None:
        """Repaint every chrome icon after a theme switch, then restore the
        state-dependent ones for the current page."""
        self._rebuild_icon_cache()
        self._apply_static_icons()
        self.ai_action.setIcon(self._ai_icon)  # accent-coloured, set directly
        self.bookmark_bar.refresh()  # recolour the globe fallback
        view = self.current_view()
        if view is not None:
            self._update_star(view.url())
            self._update_security_indicator(view.url())

    def _update_star(self, url: QUrl) -> None:
        marked = self.bookmarks.contains(url.toString())
        self.star_button.setIcon(self._star_on if marked else self._star_off)
        self.star_button.setToolTip(
            "Remove bookmark (Ctrl+D)" if marked
            else "Bookmark this page (Ctrl+D)")

    def toggle_bookmark(self) -> None:
        view = self.current_view()
        url = view.url().toString()
        if not url or view.url().scheme() not in ("http", "https"):
            self.statusBar().showMessage(
                "This page can't be bookmarked.", 3000)
            return
        now_marked = self.bookmarks.toggle(view.title() or url, url)
        if now_marked:
            # Grab the page's current favicon right away so the new bookmark
            # isn't stuck on the generic globe until the next visit.
            self.favicons.put(view.url().host().lower(), view.icon())
        self._update_star(view.url())
        self._bookmarks_changed()
        self.statusBar().showMessage(
            "Bookmarked." if now_marked else "Bookmark removed.", 3000)

    def _populate_bookmarks_menu(self, menu: QMenu) -> None:
        """Fill a bookmarks menu (shared by the ▤ toolbar button and the ☰
        hamburger submenu); rebuilt each time it's shown so it stays current."""
        menu.clear()
        menu.addAction("Bookmark this page\tCtrl+D", self.toggle_bookmark)
        menu.addAction("Manage bookmarks…", self.open_bookmarks_manager)
        menu.addSeparator()
        items = self.bookmarks.all()
        if not items:
            empty = menu.addAction("No bookmarks yet")
            empty.setEnabled(False)
        else:
            for b in items:
                label = b.title if len(b.title) <= 48 else b.title[:47] + "…"
                menu.addAction(label, lambda _=False, u=b.url:
                               self.current_view().setUrl(QUrl(u)))
        menu.addSeparator()
        menu.addAction("Import bookmarks (.html)…", self.import_bookmarks)

    def open_bookmarks_manager(self) -> None:
        def open_url(url: str) -> None:
            self.current_view().setUrl(QUrl(url))
        BookmarksManagerDialog(self.bookmarks, self, open_url=open_url).exec()
        # A rename/delete/add may change whether the current page is marked.
        self._update_star(self.current_view().url())
        self._bookmarks_changed()

    # -- import -----------------------------------------------------------

    def import_bookmarks(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Import bookmarks", str(Path.home()),
            "Bookmark files (*.html *.htm);;All files (*)")
        if not path:
            return
        try:
            found = parse_bookmarks_html(Path(path))
        except OSError as error:
            # plain text: the error embeds the filename, which for a
            # downloaded file was chosen by a website.
            plain_message(self, QMessageBox.Icon.Warning, "Import failed",
                          f"Could not read the file:\n{error}")
            return
        added = self.bookmarks.add_many(found)
        self._update_star(self.current_view().url())
        self._bookmarks_changed()
        QMessageBox.information(
            self, "Bookmarks imported",
            f"Found {len(found)} bookmark(s) in the file.\n"
            f"Added {added} new; skipped {len(found) - added} already "
            f"present.")

    def import_passwords(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Import passwords (CSV)", str(Path.home()),
            "CSV files (*.csv);;All files (*)")
        if not path:
            return
        QMessageBox.information(
            self, "Import passwords",
            "The CSV holds passwords in plain text. They'll be encrypted "
            "into your vault, after which you should delete the CSV file.\n\n"
            "You'll be asked to unlock the vault next.")
        if not self._unlock_vault():
            return
        try:
            entries, skipped = parse_password_csv(Path(path))
        except OSError as error:
            plain_message(self, QMessageBox.Icon.Warning, "Import failed",
                          f"Could not read the file:\n{error}")
            return
        if not entries:
            QMessageBox.warning(
                self, "Nothing imported",
                "No usable rows found. The CSV needs at least a password "
                "column plus a url or name column (Chrome, Edge, Firefox, "
                "Brave and Bitwarden exports all work).")
            return

        existing = {(normalize_site(e.site), e.username)
                    for e in self.vault.entries()}
        to_add = []
        for entry in entries:
            key = (normalize_site(entry.site), entry.username)
            if key in existing:
                continue
            existing.add(key)
            to_add.append(entry)
        added = self.vault.add_many(to_add)
        QMessageBox.information(
            self, "Passwords imported",
            f"Imported {added} login(s) into the vault.\n"
            f"Skipped {len(entries) - added} duplicate(s) and {skipped} "
            f"unusable row(s).\n\nRemember to delete the CSV file now — it "
            f"still contains your passwords in plain text.")

    def _build_appearance_menu(self, appearance: QMenu) -> None:
        """Theme picker + dark/light toggle, reflecting the saved choice."""
        self._theme_name, self._mode = load_prefs()

        theme_group = QActionGroup(self)
        theme_group.setExclusive(True)
        for name in THEMES:
            act = appearance.addAction(name)
            act.setCheckable(True)
            act.setChecked(name == self._theme_name)
            act.setActionGroup(theme_group)
            act.triggered.connect(lambda _c, n=name: self._set_theme(n))

        appearance.addSeparator()
        mode_group = QActionGroup(self)
        mode_group.setExclusive(True)
        for label, mode in (("🌙  Dark mode", "dark"),
                            ("☀  Light mode", "light")):
            act = appearance.addAction(label)
            act.setCheckable(True)
            act.setChecked(mode == self._mode)
            act.setActionGroup(mode_group)
            act.triggered.connect(lambda _c, m=mode: self._set_mode(m))

    _GFX_MENU_ITEMS = (
        ("Hardware (fastest)", "default"),
        ("Compatibility — fixes flicker on some sites", "compat"),
        ("Software (most stable, slowest)", "software"),
    )

    def _build_graphics_menu(self, gfx: QMenu) -> None:
        """Compositor profile picker. The flags are consumed when the web
        engine starts, so a change only takes effect on the next launch."""
        group = QActionGroup(self)
        group.setExclusive(True)
        for label, mode in self._GFX_MENU_ITEMS:
            act = gfx.addAction(label)
            act.setCheckable(True)
            act.setChecked(mode == GFX_MODE)
            act.setActionGroup(group)
            act.triggered.connect(lambda _c, m=mode: self._set_gfx_mode(m))

    def _set_gfx_mode(self, mode: str) -> None:
        save_gfx_mode(mode)
        if mode == GFX_MODE:
            self.statusBar().showMessage(
                "Graphics mode unchanged — already in effect.", 5000)
            return
        QMessageBox.information(
            self, "Graphics mode saved",
            "The new graphics mode takes effect the next time Vodou "
            "starts.")

    def _set_theme(self, name: str) -> None:
        self._theme_name = name
        self._apply_appearance()

    def _set_mode(self, mode: str) -> None:
        self._mode = mode
        self._apply_appearance()

    def _apply_appearance(self) -> None:
        app = QApplication.instance()
        apply_theme(app, self._theme_name, self._mode)
        save_prefs(self._theme_name, self._mode)
        self._refresh_chrome_icons()
        self.statusBar().showMessage(
            f"Theme: {self._theme_name} · {self._mode.capitalize()} mode", 4000)

    def show_about(self) -> None:
        dialog = AboutDialog(self)
        dialog.update_finished.connect(self._on_update_finished)
        dialog.exec()

    def report_issue(self) -> None:
        """Open GitHub's new-issue page with the environment pre-filled,
        so every report carries the exact version + commit it's about."""
        details = "\n".join(
            f"- {name}: {version}"
            for name, version in engine_versions().items())
        body = (
            "**What happened?**\n\n\n**Steps to reproduce**\n\n\n"
            f"---\n**Environment**\n{details}\n"
            f"- OS: {platform.platform()}\n")
        self.add_tab(QUrl(f"{REPO_URL}/issues/new?body={quote(body)}"))

    def _on_update_finished(self, updated: bool, trouble: bool) -> None:
        if trouble:
            return  # keep whatever state the tag was in
        self.version_label.show_up_to_date(restart_needed=updated)

    def _on_update_check(self, vodou_ver, engine_ver) -> None:
        if not vodou_ver and not engine_ver:
            self.version_label.show_up_to_date()
            return
        parts = []
        if vodou_ver:
            parts.append(f"Vodou v{vodou_ver}")
        if engine_ver:
            parts.append(f"browser engine {engine_ver}")
        what = " and ".join(parts)
        self.version_label.show_update_available(what)
        self.statusBar().showMessage(
            f"Update available: {what} — click the version tag or open "
            f"☰ → About Vodou to install.", 15000)

    # -- plugins ----------------------------------------------------------

    def _apply_plugins(self) -> None:
        """Rebuild the injected plugin scripts from the enabled set. Applies
        to pages loaded afterwards; open tabs pick it up on reload."""
        collection = self.profile.scripts()
        for script in self._plugin_scripts:
            collection.remove(script)
        self._plugin_scripts = []
        for plugin in self.plugins.enabled_plugins():
            script = QWebEngineScript()
            script.setName(f"vodou-plugin-{plugin.id}")
            script.setInjectionPoint(
                QWebEngineScript.InjectionPoint.DocumentReady)
            script.setWorldId(APP_WORLD)
            script.setRunsOnSubFrames(False)
            script.setSourceCode(wrap_plugin_source(plugin))
            collection.insert(script)
            self._plugin_scripts.append(script)

    def open_plugins(self) -> None:
        PluginsDialog(self.plugins, self, on_change=self._apply_plugins).exec()

    def _ensure_devtools(self) -> None:
        """Build the docked DevTools panel (header with a close button + the
        inspector view) once, lazily."""
        if getattr(self, "_devtools_panel", None) is not None:
            return
        self._devtools_view = QWebEngineView()
        # Same off-the-record profile, so DevTools leaves nothing on disk.
        devtools_page = QWebEnginePage(self.profile, self._devtools_view)
        self._devtools_view.setPage(devtools_page)
        # DevTools' own ✕ (inside the inspector toolbar) asks its window to
        # close rather than closing anything itself; honor it like our header
        # button.
        devtools_page.windowCloseRequested.connect(self._close_dev_tools)

        header = QWidget()
        header.setObjectName("devtoolsHeader")
        header.setFixedHeight(32)
        hb = QHBoxLayout(header)
        hb.setContentsMargins(12, 0, 6, 0)
        hb.setSpacing(6)
        title = QLabel("DEVELOPER TOOLS")
        title.setObjectName("devtoolsTitle")
        close_btn = QToolButton()
        close_btn.setObjectName("devtoolsClose")
        close_btn.setText("✕")
        close_btn.setFixedSize(24, 24)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setToolTip("Close developer tools (Esc)")
        close_btn.clicked.connect(self._close_dev_tools)
        hb.addWidget(title)
        hb.addStretch()
        hb.addWidget(close_btn)

        self._devtools_panel = QWidget()
        pv = QVBoxLayout(self._devtools_panel)
        pv.setContentsMargins(0, 0, 0, 0)
        pv.setSpacing(0)
        pv.addWidget(header)
        pv.addWidget(self._devtools_view)
        self._split.addWidget(self._devtools_panel)
        self._devtools_panel.hide()
        self._devtools_open = False

        # Esc closes DevTools, but only while it's open — disabled the rest of
        # the time so Esc still reaches web pages normally.
        self._devtools_esc = QShortcut(QKeySequence(Qt.Key.Key_Escape), self,
                                       activated=self._close_dev_tools)
        self._devtools_esc.setEnabled(False)

    def open_dev_tools(self) -> None:
        """Toggle Chromium DevTools docked to the right of the window. F12 or
        the menu entry flips it; it always inspects the current tab."""
        view = self.current_view()
        if view is None:
            return
        self._ensure_devtools()
        if self._devtools_open:
            self._close_dev_tools()
            return
        view.page().setDevToolsPage(self._devtools_view.page())
        self._devtools_panel.show()
        self._devtools_open = True
        self._devtools_esc.setEnabled(True)
        # Split roughly 62/38 so the page keeps most of the width.
        total = self._split.width() or self.width() or 1280
        self._split.setSizes([int(total * 0.62), int(total * 0.38)])

    def _close_dev_tools(self) -> None:
        if not getattr(self, "_devtools_open", False):
            return
        view = self.current_view()
        if view is not None:
            view.page().setDevToolsPage(None)
        self._devtools_panel.hide()
        self._devtools_open = False
        self._devtools_esc.setEnabled(False)

    # -- AI search summaries (local Ollama) --------------------------------

    def _ensure_ai_panel(self) -> None:
        """Build the docked summary panel once, lazily (mirrors DevTools)."""
        if self._ai_panel is not None:
            return
        header = QWidget()
        header.setObjectName("aiHeader")
        header.setFixedHeight(32)
        hb = QHBoxLayout(header)
        hb.setContentsMargins(12, 0, 6, 0)
        hb.setSpacing(6)
        title = QLabel("AI SUMMARY")
        title.setObjectName("aiTitle")
        # Model picker, populated from the local Ollama's installed models.
        self._ai_model_combo = QComboBox()
        self._ai_model_combo.setObjectName("aiModelCombo")
        self._ai_model_combo.setToolTip(
            "Model used to summarize — the list is your local Ollama's "
            "installed models")
        self._populate_model_combo([self.ai_cfg.get("model", "")])
        self._ai_model_combo.currentTextChanged.connect(
            self._on_ai_model_changed)
        close_btn = QToolButton()
        close_btn.setObjectName("aiClose")
        close_btn.setText("✕")
        close_btn.setFixedSize(24, 24)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setToolTip("Close the summary panel")
        close_btn.clicked.connect(self._close_ai_panel)
        hb.addWidget(title)
        hb.addWidget(self._ai_model_combo)
        hb.addStretch()
        hb.addWidget(close_btn)

        self._ai_status = QLabel("")
        self._ai_status.setObjectName("aiStatus")
        self._ai_status.setWordWrap(True)

        self._ai_text = QTextBrowser()
        self._ai_text.setObjectName("aiSummary")
        self._ai_text.setOpenExternalLinks(False)
        # Clicking a citation link opens it in a new tab rather than trying to
        # load inside the read-only summary view.
        self._ai_text.setOpenLinks(False)
        self._ai_text.anchorClicked.connect(
            lambda u: self.add_tab(QUrl(u)))

        bar = QHBoxLayout()
        bar.setContentsMargins(10, 4, 10, 8)
        bar.setSpacing(6)
        self._ai_regen = QPushButton("Regenerate")
        self._ai_regen.clicked.connect(self.summarize_search)
        self._ai_stop = QPushButton("Stop")
        self._ai_stop.clicked.connect(self._stop_ai)
        self._ai_stop.setEnabled(False)
        bar.addWidget(self._ai_regen)
        bar.addWidget(self._ai_stop)
        bar.addStretch()

        self._ai_panel = QWidget()
        self._ai_panel.setObjectName("aiPanel")
        pv = QVBoxLayout(self._ai_panel)
        pv.setContentsMargins(0, 0, 0, 0)
        pv.setSpacing(0)
        pv.addWidget(header)
        pv.addWidget(self._ai_status)
        pv.addWidget(self._ai_text, 1)
        pv.addLayout(bar)
        self._split.addWidget(self._ai_panel)
        self._ai_panel.hide()

    def _show_ai_panel(self) -> None:
        self._ensure_ai_panel()
        # Refresh the model list from Ollama each time the panel opens (cheap,
        # and picks up models installed since last time).
        self.ai_summarizer.list_models(self.ai_cfg, self._on_ai_models_listed)
        self._ai_panel.show()
        total = self._split.width() or self.width() or 1280
        self._split.setSizes([int(total * 0.62), int(total * 0.38)])

    def _populate_model_combo(self, models: list) -> None:
        """Fill the picker with `models`, keeping the configured model selected
        (and present even if Ollama didn't list it)."""
        combo = self._ai_model_combo
        current = str(self.ai_cfg.get("model", ""))
        names = list(dict.fromkeys(m for m in (models or []) if m))
        if current and current not in names:
            names.insert(0, current)
        combo.blockSignals(True)   # don't treat repopulation as a user choice
        combo.clear()
        combo.addItems(names)
        idx = combo.findText(current)
        if idx >= 0:
            combo.setCurrentIndex(idx)
        combo.blockSignals(False)

    def _on_ai_models_listed(self, names: list) -> None:
        if self._ai_panel is None or not names:
            return
        self._populate_model_combo(names)

    def _on_ai_model_changed(self, name: str) -> None:
        name = (name or "").strip()
        if not name or name == self.ai_cfg.get("model"):
            return
        self.ai_cfg["model"] = name
        save_ai_config(self.ai_cfg)
        # If a summary is already on screen, nudge the user to re-run with the
        # newly chosen model.
        if self._ai_last is not None and not self.ai_summarizer.busy:
            self._set_ai_status(
                f"Model set to {name} — click Regenerate to re-summarize.")

    def _close_ai_panel(self) -> None:
        self.ai_summarizer.cancel()
        if self._ai_panel is not None:
            self._ai_panel.hide()

    def summarize_search(self) -> None:
        """Read the current search results and summarize them with Ollama."""
        if not self.ai_cfg.get("enabled"):
            self.statusBar().showMessage(
                "AI search summaries are off — enable them in "
                "☰ → Settings.", 6000)
            return
        view = self.current_view()
        if view is None:
            return
        url = view.url()
        if not is_search_results(url):
            self.statusBar().showMessage(
                "Run a search first, then use the ✨ button to summarize the "
                "results.", 6000)
            return
        query = query_from_url(url)
        self._show_ai_panel()
        self._ai_text.clear()
        self._set_ai_status("Reading the results on this page…")
        self._ai_stop.setEnabled(True)
        self._ai_regen.setEnabled(False)
        script = results_script(self.ai_cfg.get("max_results", 6))
        view.page().runJavaScript(
            script, APP_WORLD,
            lambda res, q=query: self._on_ai_results(q, res))

    def _on_ai_results(self, query: str, results) -> None:
        if not results:
            self._set_ai_status(
                "Couldn't find any results to summarize on this page.")
            self._ai_stop.setEnabled(False)
            self._ai_regen.setEnabled(True)
            return
        self._ai_last = (query, results)
        model = self.ai_cfg.get("model", "")
        self._set_ai_status(
            f"Summarizing {len(results)} results with {model} — on your "
            f"device…")
        self.ai_summarizer.summarize(query, results, self.ai_cfg)

    def _stop_ai(self) -> None:
        self.ai_summarizer.cancel()
        self._set_ai_status("Stopped.")
        self._ai_stop.setEnabled(False)
        self._ai_regen.setEnabled(True)

    def _set_ai_status(self, text: str) -> None:
        if self._ai_panel is not None:
            self._ai_status.setText(text)

    def _on_ai_chunk(self, text: str) -> None:
        if self._ai_panel is None:
            return
        self._ai_text.setMarkdown(text)
        sb = self._ai_text.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_ai_thinking(self, thinking: bool) -> None:
        if thinking:
            self._set_ai_status("Reasoning…")
        else:
            self._set_ai_status("Writing the summary…")

    def _on_ai_finished(self, text: str) -> None:
        if self._ai_panel is None:
            return
        self._ai_text.setMarkdown(
            text or "*(the model returned an empty summary)*")
        self._set_ai_status(
            f"Done · {self.ai_cfg.get('model', '')} · on-device")
        self._ai_stop.setEnabled(False)
        self._ai_regen.setEnabled(True)

    def _on_ai_failed(self, message: str) -> None:
        if self._ai_panel is None:
            return
        self._set_ai_status("Summary failed.")
        self._ai_text.setMarkdown(f"**Couldn't summarize.** {message}")
        self._ai_stop.setEnabled(False)
        self._ai_regen.setEnabled(True)

    def _set_ai_search(self, on: bool) -> None:
        self.ai_cfg["enabled"] = bool(on)
        save_ai_config(self.ai_cfg)
        if not on:
            self._close_ai_panel()
        self.statusBar().showMessage(
            f"AI search summaries {'on' if on else 'off'}.", 4000)

    def show_ai_options(self) -> None:
        cfg = self.ai_cfg
        from ai_search import CONFIG_FILE
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle("AI summary options")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(
            "AI search summaries run entirely on your device: Vodou reads the "
            "results from the local SearXNG page and sends them to your local "
            "Ollama instance. Nothing about your search leaves the machine, "
            "and Vodou never changes Ollama's models or settings.\n\n"
            f"Enabled:      {'yes' if cfg.get('enabled') else 'no'}\n"
            f"Model:        {cfg.get('model')}\n"
            f"Ollama URL:   {cfg.get('endpoint')}\n"
            f"Results used: {cfg.get('max_results')}\n"
            f"Keep-alive:   {cfg.get('keep_alive')}  "
            "(how long Ollama keeps the model in memory after a summary)\n\n"
            "Change any of these by editing:\n"
            f"{CONFIG_FILE}\n\n"
            "Tip: set \"model\" to whichever model you already keep loaded to "
            "avoid a VRAM swap.")
        box.exec()

    def clear_browsing_data(self) -> None:
        """Wipe the cache, cookies, visited-link history, blocking stats, and
        each open tab's back/forward navigation memory.

        Not redundant with quitting, despite the memory-only session: exit
        deliberately *keeps* the saved cookie jar for allowlisted sites, so
        this is the only control that destroys it — and the only way to drop
        cookies without losing open tabs. (Blocking stats are in-memory only
        now, so they also go on exit; clearing just drops them sooner.)

        The engine clears its on-disk cache with ordinary deletion here (it
        holds the files open, so they can't be overwritten mid-session);
        the secure shred of the whole profile folder runs at exit."""
        self.profile.clearHttpCache()
        self.profile.cookieStore().deleteAllCookies()
        self.cookie_keeper.clear()  # saved jar too — clearing means all of it
        # Blocking counts imply where you were, so they go with the history.
        self.block_stats.clear()
        self.blocked_count = 0
        self._refresh_shield()
        if self._report_window is not None:
            self._report_window.refresh()
        self.profile.clearAllVisitedLinks()
        # Clear each tab's in-memory back/forward navigation history so the
        # trail of pages you moved through this session is dropped too.
        for i in range(self.tab_stack.count()):
            view = self.tab_stack.widget(i)
            if view is not None:
                view.history().clear()
        self.statusBar().showMessage("History and memory cleared.", 6000)
        # This summary must name the *persistent* cookie jar too. Quitting
        # keeps it (closeEvent flushes it), so this is the only control that
        # destroys it — saying "nothing was written to disk" here, as an
        # earlier version did, would be a lie about data the user may be
        # relying on.
        QMessageBox.information(
            self, "History & memory cleared",
            "✅ Cleared:\n\n"
            "  •  Visited-link history\n"
            "  •  Back/forward navigation memory (every open tab)\n"
            "  •  HTTP cache (memory and disk)\n"
            "  •  Cookies (you are now signed out of all sites)\n"
            "  •  Saved cookies for your allowlisted sites — those sites "
            "are signed out too, though the exceptions list itself is "
            "kept\n"
            "  •  Blocking statistics (this session's counts)\n\n"
            "The disk cache is securely shredded when Vodou closes.")

    # -- privacy status -------------------------------------------------

    @pyqtSlot(str)
    def _on_blocked(self, host: str) -> None:
        self.blocked_count += 1
        self.block_stats.record(host)  # dict bump; its writes are debounced
        if not self._shield_timer.isActive():
            self._shield_timer.start()

    def _set_blocking_paused(self, paused: bool) -> None:
        # Session-only on purpose: pausing is a "this site is broken right
        # now" escape hatch, so protection always comes back on restart.
        self.interceptor.paused = paused
        self.shield_label.setProperty("paused", paused)
        style = self.shield_label.style()
        style.unpolish(self.shield_label)
        style.polish(self.shield_label)
        self._refresh_shield()
        self.statusBar().showMessage(
            "Tracker blocking paused — reload the page for it to take "
            "effect." if paused else "Tracker blocking resumed.", 5000)

    def _refresh_shield(self) -> None:
        if self.interceptor.paused:
            self.shield_label.setText(" ⏸ tracker blocking paused ")
        else:
            self.shield_label.setText(
                f" 🛡 {self.blocked_count} trackers blocked ")

    def _center_version(self) -> None:
        bar = self.statusBar()
        self.version_label.adjustSize()
        self.version_label.move(
            (bar.width() - self.version_label.width()) // 2,
            (bar.height() - self.version_label.height()) // 2)

    def eventFilter(self, obj, event) -> bool:
        if obj is self.statusBar() and event.type() == QEvent.Type.Resize:
            self._center_version()
        elif (obj is self.shield_label
                and event.type() == QEvent.Type.MouseButtonRelease
                and event.button() == Qt.MouseButton.LeftButton):
            self.pause_blocking_action.toggle()
        return super().eventFilter(obj, event)

    # -- downloads --------------------------------------------------------

    def _on_download(self, item: QWebEngineDownloadRequest) -> None:
        # Never accept silently: a page must not be able to drop files on
        # disk without the user agreeing (drive-by download).
        downloads = Path.home() / "Downloads"
        # Sanitise the server-suggested name: strip directories, NTFS
        # alternate-data-stream colons, reserved device names, and trailing
        # dots/spaces (see spoofcheck.safe_download_name).
        safe_name = safe_download_name(item.downloadFileName())
        origin = item.url().host() or "this page"
        risky = download_risk(safe_name)
        if risky:
            # Executable/installer payloads are the sharp end of a drive-by
            # download: a page handing you one of these can run code on your
            # machine. Warn harder — Warning icon, blunt wording, default No.
            answer = plain_message(
                self, QMessageBox.Icon.Warning, "Dangerous download",
                f"“{safe_name}” from {origin} is a {risky} file that can run "
                f"programs on your computer.\n\nOnly keep it if you trust "
                f"{origin} and meant to download it. Save it anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
        else:
            answer = plain_message(
                self, QMessageBox.Icon.Question, "Download file?",
                f"Save “{safe_name}” from {origin} to your Downloads folder?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            item.cancel()
            return
        item.setDownloadFileName(safe_name)
        item.setDownloadDirectory(str(downloads))
        item.accept()
        self._downloads_dialog().add(item)

    def _downloads_dialog(self) -> DownloadsDialog:
        if getattr(self, "_downloads", None) is None:
            self._downloads = DownloadsDialog(self)
        return self._downloads

    def show_downloads(self) -> None:
        dialog = self._downloads_dialog()
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    # -- password manager --------------------------------------------------

    def _unlock_vault(self) -> bool:
        """Unlock interactively and (re)start the auto-lock countdown."""
        if not ensure_unlocked(self.vault, self):
            return False
        self._vault_lock_timer.start()
        return True

    def _autolock_vault(self) -> None:
        if QApplication.activeModalWidget() is not None:
            self._vault_lock_timer.start()  # vault UI in use; retry later
            return
        if self.vault.unlocked:
            # The vault window no longer blocks the app, so it can be left
            # open and forgotten in the background — close it here or
            # auto-lock would be defeated by simply leaving it up.
            if self._vault_dialog is not None:
                self._vault_dialog.close()
            self.vault.lock()
            self.statusBar().showMessage(
                f"Password vault auto-locked after {VAULT_AUTOLOCK_MINUTES} "
                f"minutes of inactivity.", 6000)

    def open_vault(self) -> None:
        if self._vault_dialog is not None:
            # Already open — surface it rather than stacking a second copy.
            self._vault_dialog.showNormal()
            self._vault_dialog.raise_()
            self._vault_dialog.activateWindow()
            return
        if not self._unlock_vault():
            return
        host = self.current_view().url().host().removeprefix("www.")
        # Deliberately unparented: on Windows an *owned* window is always
        # z-ordered above its owner, so parenting this to the browser would
        # pin it on top even though it's modeless. With no owner it behaves
        # like any other window — it drops behind when you click elsewhere
        # and returns when you click it or its taskbar button. The app-level
        # window icon (theme.apply_theme) still applies. Its own child
        # dialogs (add/edit/reveal) stay modal to it, which keeps auto-lock
        # deferred while one is open (see _autolock_vault).
        dialog = VaultDialog(self.vault, None, current_site=host)
        dialog.setWindowFlags(Qt.WindowType.Window)
        dialog.setModal(False)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.finished.connect(self._on_vault_dialog_closed)
        self._vault_dialog = dialog
        dialog.show()

    def _on_vault_dialog_closed(self, _result: int = 0) -> None:
        self._vault_dialog = None
        if self.vault.unlocked:
            self._vault_lock_timer.start()  # fresh countdown after use

    def show_blocking_report(self) -> None:
        if self._report_window is not None:
            self._report_window.showNormal()
            self._report_window.raise_()
            self._report_window.activateWindow()
            return
        # Unparented for the same reason as the vault window: an owned
        # window is pinned above its owner on Windows.
        window = BlockingReportWindow(self.block_stats, None)
        window.setWindowFlags(Qt.WindowType.Window)
        window.setModal(False)
        window.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        window.finished.connect(self._on_report_closed)
        self._report_window = window
        window.show()
        # Keep the figures live while the user watches them.
        self._report_timer = QTimer(window)
        self._report_timer.setInterval(2000)
        self._report_timer.timeout.connect(window.refresh)
        self._report_timer.start()

    def _on_report_closed(self, _result: int = 0) -> None:
        self._report_window = None

    def save_login_for_site(self) -> None:
        if not self._unlock_vault():
            return
        host = self.current_view().url().host().removeprefix("www.")
        dialog = EntryDialog(self, site=host)
        if dialog.exec():
            self.vault.add(dialog.result_entry())
            self.statusBar().showMessage(f"Saved login for {host}", 4000)

    # -- autofill offer / capture -----------------------------------------

    def _maybe_offer_fill(self, view: WebView, ok: bool) -> None:
        """After a page loads, offer to fill if the vault can help."""
        if not ok or view is not self.current_view():
            return
        url = view.url()
        host = url.host().removeprefix("www.")
        if url.scheme() != "https" or not host or not self.vault.exists():
            return
        if host in self._fill_offer_dismissed:
            return

        def probed(has_password_field: bool) -> None:
            try:
                if not has_password_field or view is not self.current_view():
                    return
            except RuntimeError:  # tab closed before the probe returned
                return
            if self.vault.unlocked:
                if not self.vault.entries_for_host(host):
                    return
                text = (f"🔑 Vodou has a saved login for {host}. "
                        f"Autofill username and password?")
                label = "Autofill"
            else:
                text = (f"🔑 This page has a login form. Unlock your vault "
                        f"to autofill a saved login for {host}?")
                label = "Unlock && autofill"
            self.notify_bar.offer(
                host, text, label,
                on_accept=self.fill_login,
                on_dismiss=lambda: self._fill_offer_dismissed.add(host))

        view.page().runJavaScript(PROBE_JS, APP_WORLD, probed)

    def _on_captured(self, view: WebView, username: str,
                     password: str) -> None:
        """A login was submitted: offer to save it or update a changed one."""
        if view is not self.current_view():
            return
        host = view.url().host().removeprefix("www.")
        if not host or (host, username) in self._capture_dismissed:
            return
        dismiss = lambda: self._capture_dismissed.add((host, username))
        who = f"“{username}” on {host}" if username else host

        if not self.vault.unlocked:
            self.notify_bar.offer(
                host,
                f"💾 Save the login you just used for {who} in your vault?",
                "Unlock && save",
                on_accept=lambda: self._save_captured(host, username, password),
                on_dismiss=dismiss)
            return

        existing = self._find_entry(host, username)
        if existing is None:
            text = f"💾 Save the login you just used for {who} in your vault?"
            label = "Save"
        elif self.vault.reveal(existing[0]) != password:
            text = (f"🔄 The password for {who} has changed. "
                    f"Update the one saved in your vault?")
            label = "Update"
        else:
            return  # already saved, unchanged
        self.notify_bar.offer(
            host, text, label,
            on_accept=lambda: self._save_captured(host, username, password),
            on_dismiss=dismiss)

    def _find_entry(self, host: str, username: str):
        """(index, entry) for host+username, or None."""
        for index, entry in enumerate(self.vault.entries()):
            site = normalize_site(entry.site)
            if ((host == site or host.endswith("." + site))
                    and entry.username == username):
                return index, entry
        return None

    def _save_captured(self, host: str, username: str,
                       password: str) -> None:
        if not self._unlock_vault():
            return
        existing = self._find_entry(host, username)
        if existing is not None:
            index, entry = existing
            if self.vault.reveal(index) == password:
                return
            entry.password = password
            self.vault.update(index, entry)
            self.statusBar().showMessage(
                f"Updated saved password for {username or host}", 5000)
            return
        self.vault.add(Entry(site=host, username=username,
                             password=password))
        self.statusBar().showMessage(f"Saved login for {host}", 5000)

    def fill_login(self) -> None:
        view = self.current_view()
        url = view.url()
        if url.scheme() != "https":
            answer = QMessageBox.warning(
                self, "Insecure page",
                "This page is not HTTPS — anything typed or filled here "
                "can be read in transit. Fill anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return
        if not self._unlock_vault():
            return

        host = url.host().removeprefix("www.")
        matches = self.vault.entries_for_host(host)  # list[(index, Entry)]
        if not matches:
            answer = plain_message(
                self, QMessageBox.Icon.Question, "No saved login",
                f"No saved login for {host}. Add one now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if answer == QMessageBox.StandardButton.Yes:
                self.save_login_for_site()
            return

        if len(matches) == 1:
            index, entry = matches[0]
        else:
            picker = PickEntryDialog(matches, self, vault=self.vault)
            if not picker.exec() or picker.choice is None:
                return
            index, entry = picker.choice

        # Confirm parent-domain matches: an entry saved for a shared-suffix
        # domain (e.g. github.io) would otherwise fill on any stranger's
        # subdomain of it.
        site = normalize_site(entry.site)
        if host != site:
            answer = plain_message(
                self, QMessageBox.Icon.Question, "Confirm fill",
                f"This login was saved for “{site}”, but the current page "
                f"is “{host}”.\n\nIf {site} hosts pages for different "
                f"people (like *.github.io), this page may not belong to "
                f"the site you saved the login for.\n\nFill anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return

        # Decrypt the password only now, at the point of use.
        script = build_fill_script(entry.username, self.vault.reveal(index))
        view.page().runJavaScript(script, APP_WORLD, self._on_fill_result)

    def _on_fill_result(self, result: str) -> None:
        messages = {
            "ok": "Login filled.",
            "password-only": "Password filled (no username field found).",
            "no-password-field": "No password field found on this page.",
        }
        self.statusBar().showMessage(
            messages.get(result, "Fill finished."), 5000)


def main() -> None:
    migrate_config_dir()
    # A leftover profile folder means the last run ended before its exit
    # wipe (crash/kill) — shred it before the engine starts and recreates it.
    shred_dir(PROFILE_DIR)
    app = QApplication(sys.argv)
    app.setApplicationName("Vodou Browser")
    apply_theme(app)
    window = BrowserWindow()
    window.show()
    code = app.exec()
    # Engine shutdown can keep the odd cache file locked for a moment;
    # anything skipped here is caught by the startup shred on the next run.
    shred_dir(PROFILE_DIR)
    sys.exit(code)


if __name__ == "__main__":
    main()
