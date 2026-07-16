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

import os
import sys

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


def _gfx_flags() -> str:
    mode = "default"
    if "--gfx" in sys.argv:
        i = sys.argv.index("--gfx")
        if i + 1 >= len(sys.argv) or sys.argv[i + 1] not in GFX_MODES:
            print(f"--gfx must be one of: {', '.join(GFX_MODES)}")
            sys.exit(2)
        mode = sys.argv[i + 1]
        del sys.argv[i:i + 2]  # keep Qt from seeing our custom args
    return GFX_MODES[mode]


# Must be set before Qt WebEngine initializes. The WebRTC policy stops local
# IP enumeration (a classic IP-leak / fingerprinting vector).
os.environ.setdefault(
    "QTWEBENGINE_CHROMIUM_FLAGS",
    "--force-webrtc-ip-handling-policy=default_public_interface_only "
    + _gfx_flags())

import json
import secrets
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, QUrl, pyqtSignal, pyqtSlot
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
    QTabWidget,
    QToolBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from autofill import PROBE_JS, build_capture_script, build_fill_script
from bookmarks import Bookmarks
from bookmarks_ui import BookmarksManagerDialog
from plugins import PluginManager, wrap_plugin_source
from plugins_ui import PluginsDialog
from importers import parse_bookmarks_html, parse_password_csv
from privacy import GENERIC_USER_AGENT, PrivacyInterceptor, apply_ua_quirk
from about import APP_VERSION, REPO_URL, AboutDialog, UpdateChecker
from theme import THEMES, apply_theme, load_prefs, save_prefs
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

HOME_URL = "https://localhost/searxng"
SEARCH_URL = "https://localhost/searxng/search?q={}"

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

    def __init__(self, profile: QWebEngineProfile, capture_prefix: str,
                 parent=None):
        super().__init__(profile, parent)
        self._capture_prefix = capture_prefix

    def acceptNavigationRequest(self, url, nav_type, is_main_frame) -> bool:
        # Mutating the profile from inside this callback re-enters QtWebEngine
        # and aborts the process, so the identity switch is deferred one event
        # loop tick.
        if is_main_frame:
            QTimer.singleShot(
                0, lambda u=QUrl(url): self._apply_ua_quirk(u))
        return super().acceptNavigationRequest(url, nav_type, is_main_frame)

    def _apply_ua_quirk(self, url: QUrl) -> None:
        try:
            if apply_ua_quirk(self.profile(), url.host()):
                # A UA change makes QtWebEngine reload the current page, which
                # cancels the navigation that triggered the switch — re-issue
                # it. The re-entry is a no-op (identity already matches), so
                # this cannot loop.
                self.setUrl(url)
        except RuntimeError:
            pass  # page torn down before the deferred call fired

    def javaScriptConsoleMessage(self, level, message, line, source_id):
        if message.startswith(self._capture_prefix):
            try:
                data = json.loads(message[len(self._capture_prefix):])
                username = str(data.get("u", ""))[:256]
                password = str(data.get("p", ""))[:256]
            except (ValueError, TypeError):
                return
            if password:
                self.captured.emit(username, password)
            return
        super().javaScriptConsoleMessage(level, message, line, source_id)


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
        super().__init__(f"Vodou v{APP_VERSION} ")
        self.browser = browser
        self._update_available = False
        self.setObjectName("versionLabel")
        self.setToolTip(f"Open Vodou's GitHub repository\n{REPO_URL}")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def show_update_available(self, what: str) -> None:
        """Turn the tag into an update notice; clicking now opens About,
        where one click installs both parts."""
        self._update_available = True
        self.setText(f"Vodou v{APP_VERSION} — update available ⬆ ")
        self.setToolTip(f"Update available: {what}\n"
                        f"Click to open About Vodou and update")

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
        page = WebPage(browser.profile, browser.capture_prefix, self)
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


class BrowserWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vodou Browser — private")
        self.resize(1280, 830)

        # Off-the-record profile: no storage name, no persistent path ->
        # cookies/cache/history stay in memory and die with the process.
        self.profile = QWebEngineProfile(self)
        self.profile.setHttpUserAgent(GENERIC_USER_AGENT)
        self.interceptor = PrivacyInterceptor(self)
        self.profile.setUrlRequestInterceptor(self.interceptor)
        self.profile.downloadRequested.connect(self._on_download)

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

        # Reviewed, opt-in plugins injected into the isolated world. State is
        # ID-only (no code from disk); each plugin self-limits to its hosts.
        self.plugins = PluginManager()
        self._plugin_scripts: list[QWebEngineScript] = []
        self._apply_plugins()

        self._fill_offer_dismissed: set[str] = set()        # hosts
        self._capture_dismissed: set[tuple[str, str]] = set()  # (host, user)

        self.vault = Vault()
        self.bookmarks = Bookmarks()
        self._vault_lock_timer = QTimer(self)
        self._vault_lock_timer.setSingleShot(True)
        self._vault_lock_timer.setInterval(VAULT_AUTOLOCK_MINUTES * 60 * 1000)
        self._vault_lock_timer.timeout.connect(self._autolock_vault)

        self.blocked_count = 0
        self.interceptor.blocked.connect(self._on_blocked)

        self._build_ui()
        self._build_shortcuts()
        self.add_tab(QUrl(HOME_URL))

        # Quiet startup update check (GitHub + PyPI, anonymous GETs of public
        # files). Delayed so it never competes with first-page load; failures
        # stay silent.
        self._update_checker = UpdateChecker(self)
        self._update_checker.finished.connect(self._on_update_check)
        QTimer.singleShot(10000, self._update_checker.start)

    # -- UI ---------------------------------------------------------------

    def _build_ui(self) -> None:
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self._on_tab_changed)

        # Tabs on the left; the DevTools panel (added lazily) docks to the
        # right of this splitter when developer tools are enabled.
        self._split = QSplitter(Qt.Orientation.Horizontal)
        self._split.setChildrenCollapsible(False)
        self._split.addWidget(self.tabs)

        self.notify_bar = NotifyBar()
        container = QWidget()
        vbox = QVBoxLayout(container)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        vbox.addWidget(self.notify_bar)
        vbox.addWidget(self._split)
        self.setCentralWidget(container)

        toolbar = QToolBar("Navigation")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        def action(text: str, tip: str, slot, shortcut: str | None = None):
            act = QAction(text, self)
            act.setToolTip(tip)
            act.triggered.connect(slot)
            if shortcut:
                act.setShortcut(QKeySequence(shortcut))
            toolbar.addAction(act)
            return act

        action("←", "Back (Alt+Left)", lambda: self.current_view().back())
        action("→", "Forward (Alt+Right)",
               lambda: self.current_view().forward())
        action("⟳", "Reload (Ctrl+R)", lambda: self.current_view().reload())
        action("⌂", "Home", lambda: self.current_view().setUrl(QUrl(HOME_URL)))

        self.lock_button = QToolButton()
        self.lock_button.setObjectName("lockButton")
        self.lock_button.setText("ⓘ")
        self.lock_button.setProperty("state", "neutral")
        self.lock_button.clicked.connect(self.show_certificate)
        toolbar.addWidget(self.lock_button)

        self.url_bar = QLineEdit()
        self.url_bar.setObjectName("urlBar")
        self.url_bar.setPlaceholderText(
            "Search SearXNG or enter address (HTTPS-first)")
        self.url_bar.returnPressed.connect(self._navigate)
        toolbar.addWidget(self.url_bar)

        self.star_button = QToolButton()
        self.star_button.setObjectName("starButton")
        self.star_button.setText("☆")
        self.star_button.setToolTip("Bookmark this page (Ctrl+D)")
        self.star_button.clicked.connect(self.toggle_bookmark)
        toolbar.addWidget(self.star_button)

        self.bookmarks_button = QToolButton()
        self.bookmarks_button.setText("▤")
        self.bookmarks_button.setToolTip("Bookmarks")
        self.bookmarks_button.setPopupMode(
            QToolButton.ToolButtonPopupMode.InstantPopup)
        self._bookmarks_menu = QMenu(self.bookmarks_button)
        self._bookmarks_menu.aboutToShow.connect(
            lambda: self._populate_bookmarks_menu(self._bookmarks_menu))
        self.bookmarks_button.setMenu(self._bookmarks_menu)
        toolbar.addWidget(self.bookmarks_button)

        action("＋", "New tab (Ctrl+T)", lambda: self.add_tab(QUrl(HOME_URL)))
        action("🔑", "Fill saved login on this page (Ctrl+Shift+F)",
               self.fill_login)
        action("💾", "Save a login for this site", self.save_login_for_site)
        action("🗄", "Open password vault (Ctrl+Shift+V)", self.open_vault)

        menu_button = QToolButton()
        menu_button.setText("☰")
        menu_button.setToolTip("Menu")
        menu_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(menu_button)
        clear_action = menu.addAction("Clear history & memory\tCtrl+Shift+Del",
                                      self.clear_browsing_data)
        clear_action.setToolTip(
            "Erase visited-link history, the HTTP cache, cookies, and each "
            "tab's back/forward navigation memory")
        menu.addSeparator()
        hamburger_bookmarks = menu.addMenu("Bookmarks")
        hamburger_bookmarks.aboutToShow.connect(
            lambda: self._populate_bookmarks_menu(hamburger_bookmarks))
        self._build_appearance_menu(menu.addMenu("Appearance"))
        menu.addSeparator()
        menu.addAction("Password vault…\tCtrl+Shift+V", self.open_vault)
        menu.addAction("Import passwords (.csv)…", self.import_passwords)
        menu.addSeparator()
        menu.addAction("Plugins…", self.open_plugins)
        menu.addAction("Developer tools\tF12", self.open_dev_tools)
        menu.addSeparator()
        menu.addAction("About Vodou…", self.show_about)
        menu_button.setMenu(menu)
        toolbar.addWidget(menu_button)

        self.shield_label = QLabel(" 🛡 0 trackers blocked ")
        self.shield_label.setObjectName("shieldLabel")
        self.statusBar().addPermanentWidget(self.shield_label)

        self.version_label = VersionLabel(self)
        self.statusBar().addPermanentWidget(self.version_label)
        self.statusBar().showMessage(
            "Private session: history, cookies and cache are memory-only "
            "and erased on exit.", 8000)

    def _build_shortcuts(self) -> None:
        bindings = {
            "Ctrl+T": lambda: self.add_tab(QUrl(HOME_URL)),
            "Ctrl+W": lambda: self.close_tab(self.tabs.currentIndex()),
            "Ctrl+L": self._focus_url_bar,
            "Ctrl+R": lambda: self.current_view().reload(),
            "F5": lambda: self.current_view().reload(),
            "Ctrl+Shift+F": self.fill_login,
            "Ctrl+Shift+V": self.open_vault,
            "Ctrl+Shift+Del": self.clear_browsing_data,
            "Ctrl+D": self.toggle_bookmark,
            "Ctrl+Tab": self._next_tab,
            "F12": self.open_dev_tools,
        }
        for keys, slot in bindings.items():
            QShortcut(QKeySequence(keys), self, activated=slot)

    def _focus_url_bar(self) -> None:
        self.url_bar.setFocus()
        self.url_bar.selectAll()

    def _next_tab(self) -> None:
        count = self.tabs.count()
        if count:
            self.tabs.setCurrentIndex((self.tabs.currentIndex() + 1) % count)

    # -- tabs ---------------------------------------------------------------

    def add_tab(self, url: QUrl | None = None) -> WebView:
        view = WebView(self)
        index = self.tabs.addTab(view, "New tab")
        self.tabs.setCurrentIndex(index)

        view.urlChanged.connect(lambda u, v=view: self._on_url_changed(v, u))
        view.titleChanged.connect(lambda t, v=view: self._on_title_changed(v, t))
        view.iconChanged.connect(
            lambda icon, v=view: self.tabs.setTabIcon(
                self.tabs.indexOf(v), icon))
        view.page().fullScreenRequested.connect(self._on_fullscreen)
        view.loadFinished.connect(
            lambda ok, v=view: self._maybe_offer_fill(v, ok))
        view.page().captured.connect(
            lambda user, pw, v=view: self._on_captured(v, user, pw))

        if url is not None:
            view.setUrl(url)
        return view

    def close_tab(self, index: int) -> None:
        if self.tabs.count() == 1:
            self.close()
            return
        view = self.tabs.widget(index)
        self.tabs.removeTab(index)
        view.deleteLater()

    def current_view(self) -> WebView:
        return self.tabs.currentWidget()

    def _on_fullscreen(self, request) -> None:
        request.accept()
        self.statusBar().showMessage(
            "A site entered full-screen mode — press Esc to leave.", 4000)

    def closeEvent(self, event) -> None:
        clear_copied_secrets()  # no passwords left on the clipboard
        super().closeEvent(event)

    def _on_tab_changed(self, index: int) -> None:
        self.notify_bar.hide()
        view = self.tabs.widget(index)
        if view is not None:
            self.url_bar.setText(view.url().toString())
            self._update_security_indicator(view.url())
            self._update_star(view.url())
            # Keep docked DevTools pointed at whichever tab is now active.
            if getattr(self, "_devtools_open", False):
                view.page().setDevToolsPage(self._devtools_view.page())

    def _on_url_changed(self, view: WebView, url: QUrl) -> None:
        if view is self.current_view():
            self.url_bar.setText(url.toString())
            self.url_bar.setCursorPosition(0)
            self._update_security_indicator(url)
            self._update_star(url)
            # Keep save/update offers alive across same-site navigation
            # (logging in usually navigates); drop them when leaving.
            if url.host().removeprefix("www.") != self.notify_bar.host:
                self.notify_bar.hide()

    # -- security indicator / certificate viewer ---------------------------

    def _update_security_indicator(self, url: QUrl) -> None:
        scheme = url.scheme()
        if scheme == "https":
            state, text = "secure", "🔒"
            tip = (f"Secure connection to {url.host()}\n"
                   f"Click to view the certificate")
        elif scheme == "http":
            state, text = "insecure", "🔓"
            tip = ("Not secure — this connection is unencrypted.\n"
                   "Anything you send can be read in transit.")
        else:
            state, text = "neutral", "ⓘ"
            tip = "Internal page"
        self.lock_button.setText(text)
        self.lock_button.setToolTip(tip)
        if self.lock_button.property("state") != state:
            self.lock_button.setProperty("state", state)
            style = self.lock_button.style()
            style.unpolish(self.lock_button)
            style.polish(self.lock_button)

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
        index = self.tabs.indexOf(view)
        short = title if len(title) <= 25 else title[:24] + "…"
        self.tabs.setTabText(index, short or "New tab")
        if view is self.current_view():
            self.setWindowTitle(f"{title} — Vodou (private)")

    def _navigate(self) -> None:
        self.current_view().setUrl(to_url(self.url_bar.text()))
        self.current_view().setFocus()

    # -- bookmarks --------------------------------------------------------

    def _update_star(self, url: QUrl) -> None:
        marked = self.bookmarks.contains(url.toString())
        self.star_button.setText("★" if marked else "☆")
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
        self._update_star(view.url())
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
            QMessageBox.warning(self, "Import failed",
                                f"Could not read the file:\n{error}")
            return
        added = self.bookmarks.add_many(found)
        self._update_star(self.current_view().url())
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
            QMessageBox.warning(self, "Import failed",
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
        added = 0
        for entry in entries:
            if (normalize_site(entry.site), entry.username) in existing:
                continue
            self.vault.add(entry)
            existing.add((normalize_site(entry.site), entry.username))
            added += 1
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
        self.statusBar().showMessage(
            f"Theme: {self._theme_name} · {self._mode.capitalize()} mode", 4000)

    def show_about(self) -> None:
        AboutDialog(self).exec()

    def _on_update_check(self, vodou_ver, engine_ver) -> None:
        if not vodou_ver and not engine_ver:
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

    def clear_browsing_data(self) -> None:
        """Wipe the session's (memory-only) cache, cookies, visited-link
        history, and each open tab's back/forward navigation memory."""
        self.profile.clearHttpCache()
        self.profile.cookieStore().deleteAllCookies()
        self.profile.clearAllVisitedLinks()
        # Clear each tab's in-memory back/forward navigation history so the
        # trail of pages you moved through this session is dropped too.
        for i in range(self.tabs.count()):
            view = self.tabs.widget(i)
            if view is not None:
                view.history().clear()
        self.statusBar().showMessage("History and memory cleared.", 6000)
        QMessageBox.information(
            self, "History & memory cleared",
            "✅ Your in-memory data has been cleared:\n\n"
            "  •  Visited-link history\n"
            "  •  Back/forward navigation memory (every open tab)\n"
            "  •  HTTP cache\n"
            "  •  Cookies (you are now signed out of all sites)\n\n"
            "This session was memory-only to begin with — nothing had "
            "been written to disk.")

    # -- privacy status -------------------------------------------------

    @pyqtSlot(str)
    def _on_blocked(self, host: str) -> None:
        self.blocked_count += 1
        self.shield_label.setText(
            f" 🛡 {self.blocked_count} trackers blocked ")

    # -- downloads --------------------------------------------------------

    def _on_download(self, item: QWebEngineDownloadRequest) -> None:
        # Never accept silently: a page must not be able to drop files on
        # disk without the user agreeing (drive-by download).
        downloads = Path.home() / "Downloads"
        safe_name = Path(item.downloadFileName()).name or "download"
        origin = item.url().host() or "this page"
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
        self.statusBar().showMessage(
            f"Downloading {safe_name} to {downloads}", 6000)

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
            self.vault.lock()
            self.statusBar().showMessage(
                f"Password vault auto-locked after {VAULT_AUTOLOCK_MINUTES} "
                f"minutes of inactivity.", 6000)

    def open_vault(self) -> None:
        if not self._unlock_vault():
            return
        host = self.current_view().url().host().removeprefix("www.")
        VaultDialog(self.vault, self, current_site=host).exec()
        self._vault_lock_timer.start()

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
            picker = PickEntryDialog(matches, self)
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
    app = QApplication(sys.argv)
    app.setApplicationName("Vodou Browser")
    apply_theme(app)
    window = BrowserWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
