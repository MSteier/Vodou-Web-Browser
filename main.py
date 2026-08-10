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

import hashlib
import hmac
import json
import os
import sys
import time
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


PRIVACY_FILE = Path.home() / ".vodou" / "privacy.json"


def load_location_guard() -> bool:
    """Whether Location Guard (block precise geolocation) is on. On by default
    — Vodou is privacy-first, and precise location is rarely needed."""
    try:
        data = json.loads(PRIVACY_FILE.read_text(encoding="utf-8"))
        return bool(data.get("location_guard", True))
    except (OSError, ValueError, AttributeError):
        return True


def save_location_guard(on: bool) -> None:
    try:
        PRIVACY_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        try:
            data = json.loads(PRIVACY_FILE.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                data = {}
        except (OSError, ValueError):
            data = {}
        data["location_guard"] = bool(on)
        tmp = PRIVACY_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(PRIVACY_FILE)
    except OSError:
        pass


def load_block_webcam() -> bool:
    """Whether webcam (camera) access is blocked. On by default — Vodou is
    privacy-first, and a page rarely has a legitimate need for the camera."""
    try:
        data = json.loads(PRIVACY_FILE.read_text(encoding="utf-8"))
        return bool(data.get("block_webcam", True))
    except (OSError, ValueError, AttributeError):
        return True


def save_block_webcam(on: bool) -> None:
    try:
        PRIVACY_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        try:
            data = json.loads(PRIVACY_FILE.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                data = {}
        except (OSError, ValueError):
            data = {}
        data["block_webcam"] = bool(on)
        tmp = PRIVACY_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(PRIVACY_FILE)
    except OSError:
        pass


def load_block_microphone() -> bool:
    """Whether microphone access is blocked. On by default — Vodou is
    privacy-first, and a page rarely has a legitimate need for the mic."""
    try:
        data = json.loads(PRIVACY_FILE.read_text(encoding="utf-8"))
        return bool(data.get("block_microphone", True))
    except (OSError, ValueError, AttributeError):
        return True


def save_block_microphone(on: bool) -> None:
    try:
        PRIVACY_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        try:
            data = json.loads(PRIVACY_FILE.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                data = {}
        except (OSError, ValueError):
            data = {}
        data["block_microphone"] = bool(on)
        tmp = PRIVACY_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(PRIVACY_FILE)
    except OSError:
        pass


def _capture_label(camera: bool, mic: bool) -> str:
    """Human name for a media request, e.g. 'camera and microphone'."""
    if camera and mic:
        return "camera and microphone"
    return "camera" if camera else "microphone"


PREFS_FILE = Path.home() / ".vodou" / "prefs.json"
PREFS_KEY_FILE = Path.home() / ".vodou" / "prefs.key"

# Prefs that are integrity-protected against start-page/search hijacking. A
# value changed on disk by anything other than Vodou's own Settings dialog
# (adware, a synced edit, a script) won't carry a valid HMAC signature, so it's
# reverted to the private default on the next startup. See _prefs_sig.
_SIGNED_KEYS = ("start_page", "search_engine", "startup_page")
# Older Vodou signed a smaller key set. A file carrying one of these historical
# signatures is still trusted (and re-signed under the current set on its next
# write), so adding a signed key never silently discards a saved start page.
_LEGACY_SIGNED_KEY_SETS = (
    ("start_page", "search_engine"),
)
# A start page may only be a normal web page: file:/chrome:/about:/data:/
# javascript:/blob: are refused, so even a tampered value can't reach local
# files, engine-internal pages, or script.
_SAFE_START_SCHEMES = ("http://", "https://")


def _prefs_key() -> bytes:
    """Per-install secret used to sign prefs; created once on first use and
    kept owner-only. A homepage hijacker that blindly overwrites prefs.json
    can't forge the signature without this key."""
    try:
        return bytes.fromhex(PREFS_KEY_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        pass
    key = secrets.token_bytes(32)
    try:
        PREFS_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = PREFS_KEY_FILE.with_suffix(".key.tmp")
        tmp.write_text(key.hex(), encoding="utf-8")
        tmp.replace(PREFS_KEY_FILE)
        if os.name == "posix":
            os.chmod(PREFS_KEY_FILE, 0o600)
    except OSError:
        pass
    return key


def _prefs_sig_over(data: dict, keys) -> str:
    """HMAC-SHA256 over `keys` of the prefs, canonicalised so mere key-order
    changes can't alter the signature."""
    signed = {k: str(data.get(k, "")) for k in keys}
    payload = json.dumps(signed, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return hmac.new(_prefs_key(), payload, hashlib.sha256).hexdigest()


def _prefs_sig(data: dict) -> str:
    """The signature over the current signed-key set — what a fresh write uses."""
    return _prefs_sig_over(data, _SIGNED_KEYS)


def _load_prefs() -> dict:
    """Raw prefs dict (including its signature) from ~/.vodou/prefs.json."""
    try:
        data = json.loads(PREFS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_prefs(data: dict) -> None:
    """Write prefs.json atomically with a fresh signature over _SIGNED_KEYS."""
    try:
        PREFS_FILE.parent.mkdir(parents=True, exist_ok=True)
        out = {k: v for k, v in data.items() if k != "_sig"}
        out["_sig"] = _prefs_sig(out)
        tmp = PREFS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(out), encoding="utf-8")
        tmp.replace(PREFS_FILE)
    except OSError:
        pass


def _save_pref(key: str, value: str) -> None:
    data = _load_prefs()
    data[key] = value
    _write_prefs(data)


def _prefs_trusted(data: dict) -> bool:
    """Whether the file's stored signature matches its signed values — i.e.
    Vodou itself wrote them and nothing has changed them since. A signature
    from an older Vodou (a smaller signed-key set) is also accepted, so adding
    a signed key doesn't invalidate an existing file."""
    want = str(data.get("_sig", ""))
    if not want:
        return False
    if hmac.compare_digest(want, _prefs_sig(data)):
        return True
    return any(hmac.compare_digest(want, _prefs_sig_over(data, keys))
               for keys in _LEGACY_SIGNED_KEY_SETS)


def _normalize_url(text: str) -> str:
    """A start-page string the user typed -> a loadable URL (HTTPS-first)."""
    text = text.strip()
    if not text:
        return text
    if text.startswith(
            ("http://", "https://", "about:", "file:", "chrome://")):
        return text
    return "https://" + text


def _safe_start_page(url: str) -> str:
    """The URL if it's a normal http(s) web page, else '' (use the default)."""
    url = url.strip()
    return url if url.startswith(_SAFE_START_SCHEMES) else ""


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

from PyQt6.QtCore import (
    QEvent, QMimeData, QObject, QPoint, QProcess, QSize, Qt, QTimer, QUrl,
    QVariantAnimation, pyqtSignal, pyqtSlot,
)
from PyQt6.QtGui import (
    QAction, QActionGroup, QColor, QCursor, QDrag, QKeySequence, QShortcut,
)
from PyQt6.QtWebEngineCore import (
    QWebEngineContextMenuRequest,
    QWebEngineDownloadRequest,
    QWebEnginePage,
    QWebEnginePermission,
    QWebEngineProfile,
    QWebEngineScript,
    QWebEngineSettings,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtNetwork import (
    QNetworkAccessManager,
    QNetworkProxy,
    QNetworkReply,
    QNetworkRequest,
)
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSpinBox,
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
    LOCATION_GUARD_JS,
    WEBAUTHN_SHIM_JS,
    PrivacyInterceptor,
    apply_ua_quirk,
    ua_quirk_needed,
)
from ai_search import (
    OllamaClient,
    is_search_results,
    load_config as load_ai_config,
    query_from_url,
    results_script,
    save_config as save_ai_config,
)
import celebrate
import content_credentials
from safebrowsing import SafeBrowsing
from session import (
    clear_snapshot, consume_restart, load_snapshot, mark_restart,
    save_snapshot,
)
from shred import shred_dir
from splitview import TAB_MIME, SplitView
from spoofcheck import (
    SENTINEL_HOST,
    download_risk,
    interstitial_html,
    safe_download_name,
)
from spoofcheck import inspect as spoof_inspect
from about import (
    APP_VERSION,
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

def secure_config_dir(path: Path = VAULT_DIR) -> None:
    """Create ~/.vodou owner-only, before anything else writes into it.

    A dozen modules create this directory on demand with plain
    mkdir(parents=True), which takes the process umask — typically 0o755 on
    POSIX, i.e. readable by every other local account. What sits inside is not
    all encrypted: dpapi.py falls back to writing the cookie jar in PLAINTEXT
    off Windows, session.json holds open-tab URLs, and even the vault leaks its
    salt and ciphertext to anyone who can copy it for an offline attack.
    Doing this once here fixes all of them, because mkdir(exist_ok=True) never
    changes the mode of a directory that already exists.

    A no-op on Windows, where the profile inherits the user's ACL already.
    """
    try:
        path.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(path, 0o700)
    except OSError:
        pass  # a locked or exotic filesystem must not stop the browser


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

# The address bar sends searches to SEARCH_URL, with {} where the query goes.
# SearXNG (local) keeps queries on your machine; the rest are external
# services. Offered in the Settings ▸ Search engine menu, plus a Custom option.
SEARCH_ENGINES = {
    "SearXNG (local, private)": SEARXNG_BASE + "/search?q={}",
    "DuckDuckGo": "https://duckduckgo.com/?q={}",
    "Startpage": "https://www.startpage.com/sp/search?query={}",
    "Brave Search": "https://search.brave.com/search?q={}",
    "Google": "https://www.google.com/search?q={}",
}

# Apply the user's saved Settings ▸ start-page / search-engine overrides — but
# ONLY if the file's signature verifies. A start page or search engine changed
# on disk by anything other than Vodou (a homepage hijacker, adware, a stray
# edit) can't carry a valid signature, so we ignore it, keep the private
# SearXNG defaults set just above, re-sign a clean file, and leave a one-time
# notice for the window to show. Both fall back to the SearXNG defaults.
# The startup page — what a fresh launch opens — is set independently of the
# start page (new tabs / Home button). A blank startup page follows the start
# page, so decoupling is opt-in and existing setups are unchanged.
STARTUP_URL = HOME_URL
PREFS_RESET_NOTICE = None
_prefs = _load_prefs()
_has_overrides = any(str(_prefs.get(k, "")).strip() for k in _SIGNED_KEYS)
if _has_overrides and not _prefs_trusted(_prefs):
    PREFS_RESET_NOTICE = (
        "Your saved start page, startup page and search engine couldn't be "
        "verified, so Vodou restored the private defaults. If you customized "
        "them, set them again from ☰ → Settings.")
    _write_prefs({"start_page": "", "search_engine": "", "startup_page": ""})
elif _has_overrides:
    _saved_start = _safe_start_page(
        _normalize_url(str(_prefs.get("start_page", ""))))
    if _saved_start:
        HOME_URL = _saved_start
    _saved_engine = str(_prefs.get("search_engine", "")).strip()
    if "{}" in _saved_engine:
        SEARCH_URL = _saved_engine
    _saved_startup = _safe_start_page(
        _normalize_url(str(_prefs.get("startup_page", ""))))
    STARTUP_URL = _saved_startup or HOME_URL

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


def _process_working_set_mb(pid: int) -> float | None:
    """A process's working-set (resident RAM) in MB, or None if unreadable.

    Windows-only (uses GetProcessMemoryInfo); returns None elsewhere or on any
    failure so callers can just skip the figure. Note a Chromium renderer is
    shared by same-site tabs, so several tabs can report the same process.
    """
    if sys.platform != "win32" or not pid or pid <= 0:
        return None
    import ctypes
    from ctypes import wintypes

    class _PMC(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t)]

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFO
    if not handle:
        return None
    try:
        counters = _PMC()
        counters.cb = ctypes.sizeof(_PMC)
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(
            handle, ctypes.byref(counters), counters.cb)
        if not ok:
            return None
        return counters.WorkingSetSize / (1024 * 1024)
    finally:
        kernel32.CloseHandle(handle)


def _as_local_path(text: str) -> str | None:
    """Turn address-bar text into an absolute local filesystem path, or None if
    it isn't file-ish (so the caller falls through to host/search handling).

    Handles what people actually type on Windows: an explicit ``file:`` scheme
    with any mix of slashes and backslashes (``file://``, ``file:///``,
    ``file:\\``), a bare drive path (``C:\\...`` or ``C:/...``), or a UNC share
    (``\\host\share``). Backslashes are normalised to forward slashes and a
    drive-less ``file:`` path (e.g. ``file://users\pacma\...``) is anchored to
    the system drive so it resolves to the intended ``C:/users/pacma/...``.
    Bare text without a scheme is only treated as a file when it clearly is a
    drive or UNC path, so ordinary searches aren't hijacked.
    """
    scheme = text[:5].lower() == "file:"
    raw = text[5:] if scheme else text
    if scheme:
        raw = raw.lstrip("/\\")           # eat file://, file:///, file:\\ ...
    raw = raw.replace("\\", "/")
    if not raw:
        return None
    drive = len(raw) >= 2 and raw[1] == ":" and raw[0].isalpha()
    if drive:                             # C:/Users/...  (with or without scheme)
        return os.path.normpath(raw)
    if raw.startswith("//"):              # //host/share UNC path
        return os.path.normpath(raw)
    if scheme:                            # file://users/... -> anchor to C:/
        system_drive = os.environ.get("SystemDrive", "C:")
        return os.path.normpath(os.path.join(system_drive + "/", raw))
    return None                           # not file-ish -> host or search


def to_url(text: str) -> QUrl:
    """Address-bar text -> URL (HTTPS-first) or search query."""
    text = text.strip()
    if not text:
        return QUrl(HOME_URL)
    # A local file/folder (file:// or a plain Windows path) opens directly.
    # QUrl.fromLocalFile builds the file:///C:/... form QtWebEngine needs.
    local = _as_local_path(text)
    if local is not None:
        return QUrl.fromLocalFile(local)
    # chrome:// reaches the engine's own diagnostic pages (chrome://gpu is the
    # one worth knowing — it reports what's hardware-accelerated and which
    # driver workarounds are active). Without it here, such an address has no
    # dot and no known scheme, so it falls through to the search branch below
    # and gets sent to SearXNG as a query instead of opening.
    if text.startswith(("http://", "https://", "about:", "chrome://")):
        return QUrl(text)
    looks_like_host = " " not in text and (
        "." in text or text.startswith("localhost"))
    if looks_like_host:
        return QUrl("https://" + text)
    return QUrl(SEARCH_URL.format(QUrl.toPercentEncoding(text).data().decode()))


def _guess_image_mime(url: QUrl) -> str:
    """Best-effort image MIME from a URL's extension (fallback image/jpeg)."""
    name = url.fileName()
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return {
        "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
        "webp": "image/webp", "gif": "image/gif", "tif": "image/tiff",
        "tiff": "image/tiff", "avif": "image/avif", "heic": "image/heic",
        "heif": "image/heif",
    }.get(ext, "image/jpeg")


def _decode_data_url(s: str) -> tuple[bytes | None, str]:
    """Bytes + MIME from a data: URL, or (None, ...) if it can't be parsed."""
    import base64
    import urllib.parse
    try:
        header, _, payload = s[len("data:"):].partition(",")
        mime = (header.split(";")[0] or "image/jpeg").strip()
        if ";base64" in header:
            return base64.b64decode(payload), mime
        return urllib.parse.unquote_to_bytes(payload), mime
    except Exception:  # noqa: BLE001
        return None, "image/jpeg"


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
        # Gate camera/mic/etc. permission prompts. QtWebEngine denies any
        # permission that no slot resolves, so by owning this signal we keep
        # Vodou's default of granting nothing unless the user opts in.
        self.permissionRequested.connect(self._on_permission_requested)
        # Answer proxy sign-in challenges (auto from the vault, else prompt).
        self.proxyAuthenticationRequired.connect(browser._on_proxy_auth)

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

    def _on_permission_requested(self, permission) -> None:
        """Decide on a page's request to use a device/capability.

        Camera and microphone are each gated on their own setting (Block
        Webcam / Block Microphone): a guarded device is denied outright,
        otherwise the user is asked. A combined audio+video request is one
        atomic permission, so it is denied if EITHER device is blocked and
        only offered to the user when both are allowed. Every other
        permission (screen capture, notifications, clipboard, fonts,
        geolocation) is denied — Vodou grants nothing on its own, and this
        simply makes that long-standing default explicit now that we own the
        signal. Geolocation stays additionally shielded by Location Guard's
        JS shim.
        """
        ptype = QWebEnginePermission.PermissionType
        pt = permission.permissionType()
        wants_camera = pt in (ptype.MediaVideoCapture,
                              ptype.MediaAudioVideoCapture)
        wants_mic = pt in (ptype.MediaAudioCapture,
                           ptype.MediaAudioVideoCapture)
        if not (wants_camera or wants_mic):
            permission.deny()
            return
        blocked = ((wants_camera and self.browser._block_webcam)
                   or (wants_mic and self.browser._block_microphone))
        what = _capture_label(wants_camera, wants_mic)
        if blocked:
            permission.deny()
            self.browser._note_capture_blocked(
                permission.origin().host(), what)
            return
        self.browser._prompt_capture(permission, what)


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
        # monotonic() timestamp of when this tab was last hidden, or None while
        # it is visible. Drives background-tab freeze/discard (see
        # BrowserWindow._sweep_tab_lifecycle).
        self._hidden_since: float | None = None
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

    def contextMenuEvent(self, event) -> None:
        """Standard right-click menu, plus a 'Check content credentials' entry
        on images so their C2PA provenance can be verified on-device."""
        menu = self.createStandardContextMenu()
        req = self.lastContextMenuRequest()
        image = QWebEngineContextMenuRequest.MediaType.MediaTypeImage
        if (req is not None and req.mediaType() == image
                and content_credentials.available()):
            url = QUrl(req.mediaUrl())
            if url.isValid() and not url.isEmpty():
                menu.addSeparator()
                act = menu.addAction("Check content credentials…")
                act.setToolTip(
                    "Verify this image's signed provenance on-device — who "
                    "signed it, whether it declares itself AI-generated, and "
                    "whether it is untampered. Not a deepfake detector.")
                act.triggered.connect(
                    lambda _=False, u=url:
                    self.browser.check_content_credentials(u))
        menu.exec(event.globalPos())

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


class ButtonPulser:
    """Pulses a toolbar QToolButton's background to draw the eye to it.

    Runs ~4 in-and-out accent-coloured pulses, then leaves a gentle steady
    tint while it stays active so the cue persists for a user who looked
    away. set_active is idempotent, so re-probing the same page doesn't
    restart the pulse. The accent is read fresh each time it activates
    (via accent_provider) so it always matches the live theme.
    """

    def __init__(self, button, accent_provider):
        self._button = button
        self._accent = accent_provider   # callable -> "#rrggbb"
        self._active = False
        self._rgb = (0, 0, 0)
        self._anim = QVariantAnimation(button)
        self._anim.setDuration(700)          # one in-out pulse
        self._anim.setStartValue(0.0)
        self._anim.setKeyValueAt(0.5, 1.0)
        self._anim.setEndValue(0.0)
        self._anim.setLoopCount(4)           # ~2.8s of pulsing, then rest
        self._anim.valueChanged.connect(lambda v: self._paint(float(v)))
        self._anim.finished.connect(self._settle)

    @property
    def active(self) -> bool:
        return self._active

    def set_active(self, on: bool) -> None:
        if self._button is None or on == self._active:
            return
        self._active = on
        self._anim.stop()
        if on:
            hexc = self._accent()
            self._rgb = (int(hexc[1:3], 16), int(hexc[3:5], 16),
                         int(hexc[5:7], 16))
            self._anim.start()   # pulse, then _settle leaves a steady tint
        else:
            self._button.setStyleSheet("")

    def _paint(self, value: float) -> None:
        r, g, b = self._rgb
        alpha = int(40 + 150 * value)   # subtle at the trough, bright at peak
        self._button.setStyleSheet(
            f"QToolButton {{ background: rgba({r},{g},{b},{alpha}); "
            f"border-radius: 4px; }}")

    def _settle(self) -> None:
        if self._active:
            self._paint(0.35)
        else:
            self._button.setStyleSheet("")


# A single drop can carry a whole selection of links; cap it so a dropped
# multi-URL payload can't spawn an unbounded burst of tabs.
MAX_DROP_TABS = 20


def _acceptable_drop_url(url: QUrl) -> bool:
    """Keep a dropped URL only if it's real and safe to open in a fresh tab.
    javascript: is refused outright — a page can seed a drag with a
    javascript: payload, and it has no business running just because something
    was dropped onto the window."""
    return (url.isValid() and not url.isEmpty()
            and url.scheme().lower() != "javascript")


def _urls_from_drop(mime: QMimeData) -> list[QUrl]:
    """URLs to open from a drag dropped on the window, or [] if it isn't an
    external link drag. Our own tab tear-off (TAB_MIME) is never treated as a
    URL drop, so tab reordering and Split-View tear-off keep working."""
    if mime.hasFormat(TAB_MIME):
        return []
    urls: list[QUrl] = []
    if mime.hasUrls():
        urls = [u for u in mime.urls() if _acceptable_drop_url(u)]
    elif mime.hasText():
        text = mime.text().strip()
        if text:
            # Plain text (a selected URL, or words) goes through the same
            # address-bar parsing as typing it: a URL opens, anything else
            # becomes a search.
            candidate = to_url(text)
            if _acceptable_drop_url(candidate):
                urls = [candidate]
    return urls[:MAX_DROP_TABS]


class _LinkDropZone(QWidget):
    """A chrome region (the tab strip) that opens a link dragged in from another
    app in a new tab. Making the strip itself the drop target means a link
    released anywhere along it lands reliably — the bare QTabBar is only as wide
    as its tabs, so most of the strip is this widget, not the bar. Our own tab
    tear-off (TAB_MIME) yields no URLs here, so it's ignored and passes through
    to Split View unaffected."""

    def dragEnterEvent(self, event) -> None:
        if _urls_from_drop(event.mimeData()):
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event) -> None:
        if _urls_from_drop(event.mimeData()):
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event) -> None:
        urls = _urls_from_drop(event.mimeData())
        window = self.window()
        add_tab = getattr(window, "add_tab", None)
        if not urls or add_tab is None:
            super().dropEvent(event)
            return
        for i, url in enumerate(urls):
            add_tab(url, background=(i < len(urls) - 1))
        window.activateWindow()
        window.raise_()
        event.acceptProposedAction()


class DraggableTabBar(QTabBar):
    """The main tab bar, with a tear-off drag so a tab can be dropped into a
    Split View pane or out into another app (Chrome's tab strip, the desktop).

    Ordinary left-right reordering is untouched: QTabBar's built-in movable
    behaviour keeps the pointer inside the bar and the window, so it never arms
    the tear-off. A clear downward drag (toward the page area) or a drag that
    leaves the window starts a QDrag carrying both the tab's index (for Split
    View) and the page's URL (for an external target). The index is resolved
    against the live view list at drop time, so a concurrent reorder can't
    misfire."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._press_pos: QPoint | None = None
        self._press_index = -1

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._press_pos = event.position().toPoint()
            self._press_index = self.tabAt(self._press_pos)
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if (self._press_pos is not None and self._press_index >= 0
                and event.buttons() & Qt.MouseButton.LeftButton):
            # Arm the tear-off on a decisive move below the strip (toward the
            # page area — for Split View) OR when the pointer leaves the window
            # entirely (dragging the tab out to another app, e.g. Chrome's tab
            # strip, to open the page there). Horizontal reordering keeps the
            # pointer inside the bar and the window, so it's never intercepted.
            pos = event.position().toPoint()
            left_window = not self.window().frameGeometry().contains(
                event.globalPosition().toPoint())
            if pos.y() - self.rect().bottom() > 24 or left_window:
                self._start_tear_off()
                return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        self._press_pos = None
        self._press_index = -1
        super().mouseReleaseEvent(event)

    def _start_tear_off(self) -> None:
        index = self._press_index
        self._press_pos = None
        self._press_index = -1
        drag = QDrag(self)
        mime = QMimeData()
        mime.setData(TAB_MIME, str(index).encode("ascii"))
        # Also carry the page's URL, so the tab can be dropped into another app
        # — Chrome's tab strip, the desktop — to open that page there. A Split
        # View pane keys off TAB_MIME and ignores the URL; an external target
        # keys off the URL and ignores TAB_MIME. Only real web/file pages are
        # shared (not internal or blank tabs).
        window = self.window()
        views = getattr(window, "_views", None)
        if views is not None and 0 <= index < len(views):
            url = views[index].url()
            if (url.isValid() and not url.isEmpty()
                    and url.scheme() in ("http", "https", "file")):
                mime.setUrls([url])
                mime.setText(url.toString())
        drag.setMimeData(mime)
        # Move for the internal Split-View case; Copy so an external app (which
        # can't "move" a Vodou tab) still accepts the URL and opens it.
        drag.exec(Qt.DropAction.MoveAction | Qt.DropAction.CopyAction)


# Background-tab memory reclamation. A tab hidden this long is frozen (its
# JavaScript and timers pause); hidden past the discard timeout, it is
# discarded — the render process is killed and the page reloads when the user
# returns. Every transition is clamped to the page's own recommendedState(), so
# Chromium vetoes anything unsafe (an audible tab, an active download, WebRTC,
# recent input); pinned and not-yet-loaded tabs are never touched. This is the
# single biggest RAM lever in a multi-tab Chromium browser.
TAB_FREEZE_AFTER_S = 60
TAB_LIFECYCLE_SWEEP_MS = 30_000

# The discard timeout is user-configurable (☰ → Settings → Idle tab memory):
# label -> seconds of idle before a background tab is discarded; 0 means never
# discard (freezing still applies). Persisted unsigned in tabs.json — it is not
# security-sensitive, so it stays out of the integrity-protected prefs.json.
TABS_FILE = Path.home() / ".vodou" / "tabs.json"
TAB_DISCARD_OPTIONS = (
    ("Never (freeze only)", 0),
    ("After 5 minutes", 5 * 60),
    ("After 10 minutes", 10 * 60),
    ("After 30 minutes", 30 * 60),
    ("After 1 hour", 60 * 60),
)
TAB_DISCARD_DEFAULT_S = 10 * 60


def _load_discard_after_s() -> int:
    """Saved discard timeout in seconds (0 = never), or the default. An
    unrecognized value falls back to the default rather than trusting it."""
    try:
        val = json.loads(TABS_FILE.read_text(encoding="utf-8")).get(
            "discard_after_s")
    except (OSError, ValueError, AttributeError):
        return TAB_DISCARD_DEFAULT_S
    valid = {sec for _, sec in TAB_DISCARD_OPTIONS}
    return val if isinstance(val, int) and val in valid else TAB_DISCARD_DEFAULT_S


def save_discard_after_s(seconds: int) -> None:
    try:
        TABS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = TABS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"discard_after_s": seconds}),
                       encoding="utf-8")
        tmp.replace(TABS_FILE)
    except OSError:
        pass


# Proxy configuration (☰ → Settings → Network → Proxy…). The non-secret parts
# live in proxy.json; any username/password lives encrypted in the vault (see
# Vault.set_proxy_credential) and is supplied on demand by _on_proxy_auth.
PROXY_FILE = Path.home() / ".vodou" / "proxy.json"
PROXY_TYPES = {"http": "HTTP", "socks5": "SOCKS5"}  # key -> display label


def _load_proxy_conf() -> dict:
    try:
        data = json.loads(PROXY_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_proxy_conf(conf: dict) -> None:
    try:
        PROXY_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = PROXY_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(conf), encoding="utf-8")
        tmp.replace(PROXY_FILE)
    except OSError:
        pass


def _build_qnetwork_proxy(conf: dict) -> QNetworkProxy:
    """Turn a saved proxy.json dict into a QNetworkProxy (NoProxy if disabled
    or incomplete). Credentials are NOT baked in here — QtWebEngine asks for
    them through proxyAuthenticationRequired, answered by _on_proxy_auth."""
    if not conf.get("enabled") or not conf.get("host"):
        return QNetworkProxy(QNetworkProxy.ProxyType.NoProxy)
    is_socks = conf.get("type") == "socks5"
    proxy = QNetworkProxy(
        QNetworkProxy.ProxyType.Socks5Proxy if is_socks
        else QNetworkProxy.ProxyType.HttpProxy,
        str(conf.get("host", "")), int(conf.get("port") or 0))
    if is_socks:
        # SOCKS5 can resolve hostnames at the proxy, keeping DNS off the local
        # resolver; honour the user's remote-DNS choice explicitly.
        caps = proxy.capabilities()
        flag = QNetworkProxy.Capability.HostNameLookupCapability
        if conf.get("remote_dns", True):
            caps |= flag
        else:
            caps &= ~flag
        proxy.setCapabilities(caps)
    return proxy


class BrowserWindow(QMainWindow):
    # A link dragged in from another browser (its address-bar site icon, or a
    # link on a page) or a file from the file manager opens in a new tab. The
    # drop is handled here at the window level, not on the tab bar: with
    # setExpanding(False) the QTabBar is only as wide as its tabs, so the empty
    # part of the tab strip belongs to the window — dropping there must still
    # work. Dropping on a page instead falls through to the web view, which
    # navigates it, matching how Chrome treats a drop on the page vs the strip.
    def dragEnterEvent(self, event) -> None:
        if _urls_from_drop(event.mimeData()):
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event) -> None:
        if _urls_from_drop(event.mimeData()):
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event) -> None:
        urls = _urls_from_drop(event.mimeData())
        if not urls:
            super().dropEvent(event)
            return
        # Focus the last so the window surfaces the page just handed to it.
        # add_tab routes through the normal navigation path, so a dropped URL
        # still meets the spoof / Safe-Browsing interstitial like any other.
        for i, url in enumerate(urls):
            self.add_tab(url, background=(i < len(urls) - 1))
        self.activateWindow()
        self.raise_()
        event.acceptProposedAction()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vodou Browser — private")
        self.resize(1280, 830)
        self.setAcceptDrops(True)   # open links dragged in from other apps

        # Route traffic through the configured proxy (if any) before any page
        # loads. An authenticating proxy's credentials are supplied on demand
        # by _on_proxy_auth — auto from the vault when unlocked, else prompted.
        self._proxy_auth_cache: tuple[str, str] | None = None
        self._proxy_last_offered: dict[str, tuple[str, str]] = {}
        self._proxy_auth_failcount: dict[str, int] = {}
        self._apply_proxy()

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

        # Fetches an image's bytes on demand so its C2PA Content Credential can
        # be verified locally (right-click image → Check content credentials).
        self._cc_nam = QNetworkAccessManager(self)

        # On-demand local AI via a local Ollama instance (see ai_search.py):
        # summaries of search results, and free-form "ask anything" chat.
        # Entirely on-device; Vodou is only an HTTP client of Ollama and never
        # alters its models or config. The panel is built lazily.
        self.ai_cfg = load_ai_config()
        self.ai_client = OllamaClient(self)
        self.ai_client.chunk.connect(self._on_ai_chunk)
        self.ai_client.thinking.connect(self._on_ai_thinking)
        self.ai_client.finished.connect(self._on_ai_finished)
        self.ai_client.failed.connect(self._on_ai_failed)
        self._ai_panel = None
        self._ai_mode = "ask"                    # "ask" | "summary"
        self._ai_last: tuple[str, list] | None = None   # last summarized search
        self._ai_chat: list[dict] = []           # ask-mode conversation
        self._ai_stream = ""                     # reply being streamed in

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

        # Location Guard: block precise geolocation (see privacy.LOCATION_GUARD
        # _JS). Toggled from Settings; kept as a member so it can be inserted /
        # removed live. Main world at DocumentCreation so it replaces the API
        # the page sees before any page script can call it.
        self._location_guard_script = QWebEngineScript()
        self._location_guard_script.setName("vodou-location-guard")
        self._location_guard_script.setInjectionPoint(
            QWebEngineScript.InjectionPoint.DocumentCreation)
        self._location_guard_script.setWorldId(
            QWebEngineScript.ScriptWorldId.MainWorld)
        self._location_guard_script.setRunsOnSubFrames(True)
        self._location_guard_script.setSourceCode(LOCATION_GUARD_JS)
        self._location_guard_on = load_location_guard()
        if self._location_guard_on:
            self.profile.scripts().insert(self._location_guard_script)

        # Block Webcam / Block Microphone: deny page requests for the camera
        # and/or mic. Enforced per-page in WebPage._on_permission_requested;
        # kept here so every page reads one live flag each. On by default
        # (privacy-first).
        self._block_webcam = load_block_webcam()
        self._block_microphone = load_block_microphone()
        # Throttles the "capture blocked" status note so a page that hammers
        # getUserMedia can't spam the status bar.
        self._capture_note_at = 0.0

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

        # Poll each tab's renderer memory and show it in the tab label.
        self._mem_timer = QTimer(self)
        self._mem_timer.setInterval(4000)
        self._mem_timer.timeout.connect(self._poll_tab_memory)
        self._mem_timer.start()

        # Reclaim RAM from idle background tabs: freeze, then discard. The
        # discard timeout is user-configurable (Settings ▸ Idle tab memory);
        # see _sweep_tab_lifecycle.
        self._discard_after_s = _load_discard_after_s()
        self._lifecycle_timer = QTimer(self)
        self._lifecycle_timer.setInterval(TAB_LIFECYCLE_SWEEP_MS)
        self._lifecycle_timer.timeout.connect(self._sweep_tab_lifecycle)
        self._lifecycle_timer.start()

        self._restarting = False   # set true only for an intentional restart
        self._build_ui()
        self._build_shortcuts()
        # An intentional restart (e.g. applying a graphics change) silently
        # reopens the tabs; otherwise a leftover snapshot means a crash and we
        # offer them back. Either falls through to a fresh home tab.
        if consume_restart() and self._resume_after_restart():
            pass
        elif not self._offer_crash_restore():
            self.add_tab(QUrl(STARTUP_URL))   # launch page (may differ from HOME_URL)

        # First launch after an update: a one-time confetti/fireworks page.
        # Checked after the normal tabs are in place so it opens as an extra
        # foreground tab, and only once per version (celebrate.mark_seen).
        if celebrate.due(APP_VERSION):
            self._show_update_celebration()

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
        self.tab_bar = DraggableTabBar()
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

        # Ordered source of truth for the open tabs, index-aligned with the tab
        # bar. It is kept separate from tab_stack's own child list because Split
        # View borrows a couple of views out of the stack: the list still names
        # every tab in order while those views live in the split panes.
        self._views: list[WebView] = []
        self._active_view: WebView | None = None
        # (url, pinned) for tabs the user closed, most-recent last — powers
        # "Reopen closed tab" / Ctrl+Shift+T. Session-only and capped.
        self._closed_tabs: list[tuple[str, bool]] = []
        self._split_view: SplitView | None = None
        self._pre_split_active: WebView | None = None
        # Top-level windows created by "Move tab to new window"; they share
        # this window's profile, so they're closed with it.
        self._detached_windows: list["DetachedWindow"] = []

        # "+" opens a new tab, sitting just to the right of the last tab.
        self.plus_button = QToolButton()
        self.plus_button.setObjectName("newTabButton")
        self.plus_button.setIcon(self._icons["plus"])
        self.plus_button.setIconSize(QSize(18, 18))
        self.plus_button.setToolTip("New tab (Ctrl+T)")
        self.plus_button.clicked.connect(lambda: self.add_tab(QUrl(HOME_URL)))
        self._icon_targets.append((self.plus_button, "plus"))

        tab_strip = _LinkDropZone()
        tab_strip.setObjectName("tabStrip")
        tab_strip.setAcceptDrops(True)   # links dragged in open in a new tab
        strip = QHBoxLayout(tab_strip)
        strip.setContentsMargins(6, 4, 6, 0)
        strip.setSpacing(4)
        strip.addWidget(self.tab_bar)
        strip.addWidget(self.plus_button)
        strip.addStretch(1)

        # Page area: a small stack that flips between the normal single-tab
        # view (tab_stack) and Split View. Wrapping them keeps the DevTools / AI
        # panels docking to the right of whichever is showing, unchanged.
        self.page_area = QStackedWidget()
        self.page_area.addWidget(self.tab_stack)      # index 0: normal

        # DevTools / AI panels dock to the right of the page area in this
        # splitter when enabled.
        self._split = QSplitter(Qt.Orientation.Horizontal)
        self._split.setChildrenCollapsible(False)
        self._split.addWidget(self.page_area)

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

        # Local-AI button: accent-coloured sparkle, sits just right of the
        # address bar (before the bookmark star). Icon set directly rather than
        # through the theme-text set so it keeps the accent colour; a theme
        # switch repaints it in _refresh_chrome_icons.
        self.ai_action = QAction(self)
        self.ai_action.setIcon(self._ai_icon)
        self.ai_action.setToolTip(
            "Local AI (Ctrl+Shift+A) — summarize these search results, or "
            "ask anything. On-device; nothing sent out.")
        self.ai_action.triggered.connect(self.open_ai_panel)
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

        self.key_action = action(
            "key", "Fill saved login on this page (Ctrl+Shift+F)",
            self.fill_login)
        action("save", "Save a login for this site", self.save_login_for_site)
        self.vault_action = action(
            "vault", "Open password vault (Ctrl+Shift+V)", self.open_vault)
        # The toolbar renders each QAction as a QToolButton; grab the key and
        # vault widgets so detected login forms can pulse them (key = a saved
        # login is here to fill; vault = unlock first), and so the vault button
        # can carry a locked/unlocked state indicator.
        self.key_button = toolbar.widgetForAction(self.key_action)
        self.vault_button = toolbar.widgetForAction(self.vault_action)
        self._setup_button_pulsers()

        menu_button = QToolButton()
        menu_button.setToolTip("Menu")
        menu_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self._icon_targets.append((menu_button, "menu"))
        menu = QMenu(menu_button)

        # --- Content & tools you reach often ---
        hamburger_bookmarks = menu.addMenu("Bookmarks")
        hamburger_bookmarks.aboutToShow.connect(
            lambda: self._populate_bookmarks_menu(hamburger_bookmarks))
        menu.addAction("Downloads…\tCtrl+J", self.show_downloads)
        menu.addAction("Ask local AI…\tCtrl+Shift+A", self.ask_ai)

        # --- Passwords ---
        menu.addSeparator()
        menu.addAction("Password vault…\tCtrl+Shift+V", self.open_vault)
        lock_action = menu.addAction("Lock vault (log out)\tCtrl+Shift+L",
                                     self.lock_vault_now)
        lock_action.setToolTip(
            "Lock the password vault now, clearing its key from memory. "
            "You'll need the master password to open it again.")
        menu.addAction("Import passwords (.csv)…", self.import_passwords)

        # --- View & configuration ---
        menu.addSeparator()
        self._build_appearance_menu(menu.addMenu("Appearance"))
        zoom_menu = menu.addMenu("Zoom")
        zoom_menu.addAction("Zoom in\tCtrl++", self.zoom_in)
        zoom_menu.addAction("Zoom out\tCtrl+-", self.zoom_out)
        zoom_menu.addAction("Reset zoom\tCtrl+0", self.zoom_reset)

        settings_menu = menu.addMenu("Settings")

        # --- Privacy & security -------------------------------------------
        # The browser's headline concern, so it leads. Internally grouped by
        # separators: tracker blocking, then deceptive-site protection, then
        # per-site permissions.
        privacy_menu = settings_menu.addMenu("Privacy & security")
        self.pause_blocking_action = privacy_menu.addAction(
            "Pause tracker blocking")
        self.pause_blocking_action.setCheckable(True)
        self.pause_blocking_action.setToolTip(
            "Let tracker/ad requests through until resumed — for sites "
            "that break with blocking on. Blocking resumes on restart.")
        self.pause_blocking_action.toggled.connect(self._set_blocking_paused)
        blocking_report = privacy_menu.addAction(
            "Blocking report…", self.show_blocking_report)
        blocking_report.setToolTip(
            "Charts of how many trackers and ads were blocked per day, "
            "and which ones came up most")
        privacy_menu.addSeparator()
        self.safe_browsing_action = privacy_menu.addAction("Safe Browsing")
        self.safe_browsing_action.setCheckable(True)
        self.safe_browsing_action.setChecked(self.safe_browsing.enabled)
        self.safe_browsing_action.setToolTip(
            "Warn before opening sites on public phishing/malware lists. "
            "Checked entirely on your device — nothing about your browsing "
            "is ever sent out.")
        self.safe_browsing_action.toggled.connect(self._set_safe_browsing)
        privacy_menu.addAction("Safe Browsing status…",
                               self.show_safe_browsing_status)
        privacy_menu.addSeparator()
        privacy_menu.addAction("Cookie exceptions…", self.manage_cookie_sites)
        self.location_guard_action = privacy_menu.addAction("Location Guard")
        self.location_guard_action.setCheckable(True)
        self.location_guard_action.setChecked(self._location_guard_on)
        self.location_guard_action.setToolTip(
            "Block websites from reading your precise (GPS/Wi-Fi) location. "
            "Sites can at most estimate your area from your IP address. "
            "Reload open pages after changing this.")
        self.location_guard_action.toggled.connect(self._set_location_guard)
        self.block_webcam_action = privacy_menu.addAction("Block Webcam")
        self.block_webcam_action.setCheckable(True)
        self.block_webcam_action.setChecked(self._block_webcam)
        self.block_webcam_action.setToolTip(
            "Stop websites from using your camera. Denied automatically while "
            "on; turn off to be asked for each site instead. Takes effect on "
            "the next camera request — no reload needed.")
        self.block_webcam_action.toggled.connect(self._set_block_webcam)
        self.block_microphone_action = privacy_menu.addAction(
            "Block Microphone")
        self.block_microphone_action.setCheckable(True)
        self.block_microphone_action.setChecked(self._block_microphone)
        self.block_microphone_action.setToolTip(
            "Stop websites from using your microphone. Denied automatically "
            "while on; turn off to be asked for each site instead. Takes "
            "effect on the next microphone request — no reload needed.")
        self.block_microphone_action.toggled.connect(
            self._set_block_microphone)

        # --- Start page & search ------------------------------------------
        search_menu = settings_menu.addMenu("Start page & search")
        start_action = search_menu.addAction(
            "Set start page…", self.set_start_page)
        start_action.setToolTip(
            "Choose the page new tabs and the Home button open. Leave it "
            "blank to restore the private SearXNG start page.")
        startup_action = search_menu.addAction(
            "Set startup page…", self.set_startup_page)
        startup_action.setToolTip(
            "Choose the page Vodou opens when it launches — separately from "
            "new tabs. Leave it blank to open your start page on launch too.")
        self._build_search_engine_menu(search_menu.addMenu("Search engine"))

        # --- Idle tab memory ----------------------------------------------
        self._build_discard_menu(settings_menu.addMenu("Idle tab memory"))

        # --- Network -------------------------------------------------------
        network_menu = settings_menu.addMenu("Network")
        proxy_action = network_menu.addAction("Proxy…", self._show_proxy_dialog)
        proxy_action.setToolTip(
            "Route Vodou's traffic through an HTTP or SOCKS5 proxy. SOCKS5 can "
            "resolve DNS at the proxy. Any username/password is kept in your "
            "encrypted vault.")

        # --- Local AI ------------------------------------------------------
        ai_menu = settings_menu.addMenu("Local AI")
        self.ai_search_action = ai_menu.addAction("Local AI (Ollama)")
        self.ai_search_action.setCheckable(True)
        self.ai_search_action.setChecked(bool(self.ai_cfg.get("enabled")))
        self.ai_search_action.setToolTip(
            "Enable the ✨ button: summarize search results, and ask your "
            "local Ollama model anything. Runs entirely on your device; "
            "nothing is ever sent out.")
        self.ai_search_action.toggled.connect(self._set_ai_search)
        ai_menu.addAction("Local AI options…", self.show_ai_options)
        ai_menu.addAction("Set up Local AI…", self.show_ollama_setup)

        # --- Display -------------------------------------------------------
        self._build_graphics_menu(settings_menu.addMenu("Graphics"))

        # --- Extend --------------------------------------------------------
        settings_menu.addSeparator()
        settings_menu.addAction("Plugins…", self.open_plugins)

        # --- Data & diagnostics ---
        menu.addSeparator()
        clear_action = menu.addAction("Clear history & memory\tCtrl+Shift+Del",
                                      self.clear_browsing_data)
        clear_action.setToolTip(
            "Erase visited-link history, the HTTP cache, cookies (including "
            "the saved ones for allowlisted sites), the recorded blocking "
            "statistics, and each tab's back/forward navigation memory")
        menu.addAction("Developer tools\tF12", self.open_dev_tools)

        # --- Help ---
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
        self._refresh_vault_indicator()   # vault state icon over the neutral one

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
        # A start page / search engine tampered with on disk was reverted at
        # startup; tell the user once (deferred so it lands after the window
        # is shown).
        if PREFS_RESET_NOTICE:
            QTimer.singleShot(0, lambda: plain_message(
                self, QMessageBox.Icon.Warning, "Start page protected",
                PREFS_RESET_NOTICE))

    def _build_shortcuts(self) -> None:
        bindings = {
            "Ctrl+T": lambda: self.add_tab(QUrl(HOME_URL)),
            "Ctrl+W": lambda: self.close_tab(self.tab_bar.currentIndex()),
            "Ctrl+Shift+T": self.reopen_closed_tab,
            "Ctrl+L": self._focus_url_bar,
            "Ctrl+R": self.reload_page,
            "F5": self.reload_page,
            "Ctrl+Shift+A": self.ask_ai,
            "Ctrl+Shift+F": self.fill_login,
            "Ctrl+Shift+V": self.open_vault,
            "Ctrl+Shift+L": self.lock_vault_now,
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

    def add_tab(self, url: QUrl | None = None, *,
                at: int | None = None, background: bool = False) -> WebView:
        view = WebView(self)
        view._short_title = "New tab"   # tab label pieces (see _update_tab_label)
        view._full_title = ""
        view._mem_mb = None
        view._pinned = False
        if self._zoom != 1.0:
            view.setZoomFactor(self._zoom)
        # tab_stack is the parking/display surface; self._views is the ordered
        # source of truth. Insert into the list first so any signal fired by
        # insertTab (e.g. the first tab's currentChanged) already sees it.
        self.tab_stack.addWidget(view)
        index = len(self._views) if at is None else max(0, min(at, len(self._views)))
        self._views.insert(index, view)
        self.tab_bar.insertTab(index, "New tab")

        view.urlChanged.connect(lambda u, v=view: self._on_url_changed(v, u))
        view.titleChanged.connect(lambda t, v=view: self._on_title_changed(v, t))
        view.iconChanged.connect(
            lambda icon, v=view: self._on_icon_changed(v, icon))
        view.page().fullScreenRequested.connect(self._on_fullscreen)
        view.page().audioMutedChanged.connect(
            lambda _m, v=view: self._update_tab_label(v))
        view.loadFinished.connect(
            lambda ok, v=view: self._maybe_offer_fill(v, ok))
        view.page().captured.connect(
            lambda user, pw, v=view: self._on_captured(v, user, pw))

        if not background:
            self.tab_bar.setCurrentIndex(index)
            self._on_tab_changed(index)   # covers the no-signal (unchanged) case
        if url is not None:
            view.setUrl(url)
        return view

    def close_tab(self, index: int) -> None:
        if not (0 <= index < len(self._views)):
            return
        if len(self._views) == 1:
            self.close()
            return
        view = self._views[index]
        # A tab shown in Split View is dismantled from the split first (the
        # other pane's tab returns to the strip) so nothing is left dangling.
        if self._split_view is not None and view in self._split_view.views():
            self._teardown_split()
        self._remember_closed(view)
        closing_active = view is self._active_view
        self._views.pop(index)
        if self.tab_stack.indexOf(view) >= 0:
            self.tab_stack.removeWidget(view)
        # Keep the tab bar consistent with the (already updated) view list
        # without a mid-state currentChanged firing against stale indices.
        self.tab_bar.blockSignals(True)
        self.tab_bar.removeTab(index)
        self.tab_bar.blockSignals(False)
        view.deleteLater()
        if closing_active:
            self._on_tab_changed(self.tab_bar.currentIndex())
        self._schedule_session_save()

    def _remember_closed(self, view: WebView) -> None:
        url = view.pending_url or view.url()
        text = url.toString()
        if (text and url.scheme() in ("http", "https", "file")
                and url.host() != SENTINEL_HOST):
            self._closed_tabs.append((text, getattr(view, "_pinned", False)))
            del self._closed_tabs[:-25]     # keep only the most recent 25

    def reopen_closed_tab(self) -> None:
        """Reopen the most recently closed tab (Ctrl+Shift+T)."""
        if not self._closed_tabs:
            self.statusBar().showMessage("No recently closed tabs.", 3000)
            return
        url, pinned = self._closed_tabs.pop()
        view = self.add_tab(QUrl(url))
        if pinned:
            self._set_pinned(view, True)

    def _close_other_tabs(self, keep_index: int) -> None:
        # Close by identity so shifting indices can't close the wrong tab as
        # the list shrinks; pinned tabs are protected, matching Chrome.
        keep = self._views[keep_index]
        for view in list(self._views):
            if view is not keep and not getattr(view, "_pinned", False):
                self.close_tab(self._index_of(view))

    def _close_tabs_to_right(self, index: int) -> None:
        anchor = self._views[index]
        # Snapshot the tabs to the right now; closing shifts the list.
        doomed = [v for v in self._views[self._index_of(anchor) + 1:]
                  if not getattr(v, "_pinned", False)]
        for view in doomed:
            self.close_tab(self._index_of(view))

    def _on_tab_moved(self, frm: int, to: int) -> None:
        """A dragged tab reordered the strip: mirror it in the view list.
        Display is by widget identity now, so the stack needs no reordering."""
        if 0 <= frm < len(self._views):
            view = self._views.pop(frm)
            self._views.insert(to, view)
        self._schedule_session_save()

    def _index_of(self, view: WebView) -> int:
        try:
            return self._views.index(view)
        except ValueError:
            return -1

    def current_view(self) -> WebView | None:
        return self._active_view

    # -- tab context menu ---------------------------------------------------

    def _tab_context_menu(self, pos) -> None:
        """Right-click on a tab: a Chrome-equivalent menu acting on that tab.
        Items that don't apply are disabled or hidden, as in a modern browser.
        """
        index = self.tab_bar.tabAt(pos)
        menu = QMenu(self)
        menu.addAction("New tab", lambda: self.add_tab(QUrl(HOME_URL)))
        reopen = menu.addAction("Reopen closed tab", self.reopen_closed_tab)
        reopen.setEnabled(bool(self._closed_tabs))

        if index >= 0:
            view = self._views[index]
            pinned = getattr(view, "_pinned", False)
            muted = view.page().isAudioMuted()
            count = len(self._views)
            in_split = (self._split_view is not None
                        and view in self._split_view.views())

            menu.addSeparator()
            menu.addAction("Reload", lambda v=view: self._reload_view(v))
            menu.addAction("Duplicate",
                           lambda i=index: self._duplicate_tab(i))
            menu.addAction("Unpin tab" if pinned else "Pin tab",
                           lambda v=view: self._set_pinned(v, not pinned))
            menu.addAction("Unmute site" if muted else "Mute site",
                           lambda v=view: self._toggle_mute(v))

            menu.addSeparator()
            # Open / manage Split View for this tab.
            if in_split:
                menu.addAction("Exit split view",
                               lambda: self._exit_split_view(restore=True))
            else:
                split_menu = menu.addMenu("Open in split view")
                added = False
                for other in self._views:
                    if other is view:
                        continue
                    title = self._tab_menu_title(other)
                    split_menu.addAction(
                        title,
                        lambda o=other, i=index: self._open_in_split(i, o))
                    added = True
                if not added:
                    empty = split_menu.addAction("Open another tab first")
                    empty.setEnabled(False)

            move_menu = menu.addMenu("Move tab")
            to_start = move_menu.addAction(
                "To beginning", lambda i=index: self._move_tab(i, "start"))
            to_start.setEnabled(index > 0)
            to_end = move_menu.addAction(
                "To end", lambda i=index: self._move_tab(i, "end"))
            to_end.setEnabled(index < count - 1)
            move_menu.addSeparator()
            move_menu.addAction(
                "To new window",
                lambda i=index: self._move_tab_to_new_window(i))

            menu.addSeparator()
            menu.addAction("Close tab", lambda i=index: self.close_tab(i))
            others = menu.addAction(
                "Close other tabs", lambda i=index: self._close_other_tabs(i))
            others.setEnabled(
                any(v is not view and not getattr(v, "_pinned", False)
                    for v in self._views))
            to_right = menu.addAction(
                "Close tabs to the right",
                lambda i=index: self._close_tabs_to_right(i))
            to_right.setEnabled(
                any(not getattr(v, "_pinned", False)
                    for v in self._views[index + 1:]))
        menu.exec(self.tab_bar.mapToGlobal(pos))

    def _tab_menu_title(self, view: WebView) -> str:
        base = (getattr(view, "_short_title", "") or view.url().host()
                or "New tab")
        return base if len(base) <= 40 else base[:39] + "…"

    def _reload_view(self, view: WebView) -> None:
        view.page().triggerAction(
            QWebEnginePage.WebAction.ReloadAndBypassCache)

    def _duplicate_tab(self, index: int) -> None:
        if not (0 <= index < len(self._views)):
            return
        src = self._views[index]
        url = src.pending_url or src.url()
        new = self.add_tab(None, at=index + 1)
        if url is not None and url.toString():
            new.setUrl(url)

    def _toggle_mute(self, view: WebView) -> None:
        page = view.page()
        page.setAudioMuted(not page.isAudioMuted())
        # audioMutedChanged relabels the tab; nothing else to do.

    def _set_pinned(self, view: WebView, pinned: bool) -> None:
        view._pinned = pinned
        # Pinned tabs cluster on the left, preserving relative order.
        ordered = ([v for v in self._views if getattr(v, "_pinned", False)]
                   + [v for v in self._views
                      if not getattr(v, "_pinned", False)])
        self._reorder_tabs(ordered)
        self._update_tab_label(view)
        self._schedule_session_save()

    def _move_tab(self, index: int, where: str) -> None:
        if not (0 <= index < len(self._views)):
            return
        view = self._views[index]
        ordered = list(self._views)
        ordered.pop(index)
        ordered.insert(0 if where == "start" else len(ordered), view)
        self._reorder_tabs(ordered)
        self._schedule_session_save()

    def _reorder_tabs(self, ordered: list) -> None:
        """Rearrange the strip to match `ordered` (a permutation of the current
        views), keeping tab_bar and the view list in lock-step. Signals are
        blocked so the moves don't re-enter _on_tab_moved."""
        self.tab_bar.blockSignals(True)
        for target, view in enumerate(ordered):
            cur = self._index_of(view)
            if cur < 0 or cur == target:
                continue
            self.tab_bar.moveTab(cur, target)
            self._views.insert(target, self._views.pop(cur))
        # moveTab keeps the active tab selected; re-assert its highlight.
        if self._active_view is not None:
            self.tab_bar.setCurrentIndex(self._index_of(self._active_view))
        self.tab_bar.blockSignals(False)

    def _move_tab_to_new_window(self, index: int) -> None:
        """Detach the tab into its own top-level window that shares this
        window's profile (so the very page keeps running — no reload, no second
        engine profile to collide on disk). Closing it, or this window, tidies
        up. See DetachedWindow."""
        if not (0 <= index < len(self._views)) or len(self._views) == 1:
            return
        view = self._views[index]
        if self._split_view is not None and view in self._split_view.views():
            self._teardown_split()
        was_active = view is self._active_view
        # Remove from the strip WITHOUT deleting the view.
        self._views.pop(index)
        if self.tab_stack.indexOf(view) >= 0:
            self.tab_stack.removeWidget(view)
        self.tab_bar.blockSignals(True)
        self.tab_bar.removeTab(index)
        self.tab_bar.blockSignals(False)
        if was_active:
            self._on_tab_changed(self.tab_bar.currentIndex())
        win = DetachedWindow(self, view)
        self._detached_windows.append(win)
        win.show()
        self._schedule_session_save()

    def reattach_detached(self, window: "DetachedWindow", view: WebView) -> None:
        """Bring a detached tab back into the main strip (called when the
        detached window is closed via its Return button)."""
        if window in self._detached_windows:
            self._detached_windows.remove(window)
        if view is None:
            return
        self.tab_stack.addWidget(view)
        index = len(self._views)
        self._views.append(view)
        self.tab_bar.insertTab(index, "New tab")
        self._update_tab_label(view)
        idx = self._index_of(view)
        if self.tab_bar.tabIcon(idx).isNull():
            self.tab_bar.setTabIcon(idx, view.icon())
        self.tab_bar.setCurrentIndex(index)
        self._on_tab_changed(index)
        self._schedule_session_save()

    def forget_detached(self, window: "DetachedWindow") -> None:
        """The detached window closed for good (its tab is being destroyed)."""
        if window in self._detached_windows:
            self._detached_windows.remove(window)
        self._schedule_session_save()

    # -- split view ---------------------------------------------------------

    def _ensure_split_view(self) -> SplitView:
        if self._split_view is None:
            sv = SplitView()
            sv.set_accent(self.palette().highlight().color())
            sv.exit_requested.connect(
                lambda: self._exit_split_view(restore=True))
            sv.swap_requested.connect(self._swap_split)
            sv.focus_changed.connect(self._on_split_focus)
            sv.replace_requested.connect(self._replace_split_pane)
            sv.return_requested.connect(self._return_split_view_to_strip)
            sv.tab_dropped.connect(self._on_tab_dropped_on_pane)
            self.page_area.addWidget(sv)         # index 1
            self._split_view = sv
        return self._split_view

    def _open_in_split(self, base_index: int, other: WebView) -> None:
        if not (0 <= base_index < len(self._views)):
            return
        base = self._views[base_index]
        if base is other or other not in self._views:
            return
        self._enter_split_view(base, other)

    def _enter_split_view(self, left: WebView, right: WebView) -> None:
        sv = self._ensure_split_view()
        # Remember what to restore to when the split closes.
        self._pre_split_active = self._active_view
        for v in (left, right):
            if self.tab_stack.indexOf(v) >= 0:
                self.tab_stack.removeWidget(v)
        sv.mount([left, right])
        self._refresh_split_titles()
        self.page_area.setCurrentWidget(sv)
        for v in (left, right):     # add the split marker to their tabs
            self._update_tab_label(v)
        self._on_split_focus(left)
        self.statusBar().showMessage(
            "Split view — click a pane to focus it; drag the divider to "
            "resize.", 5000)

    def _teardown_split(self) -> None:
        """Dismantle the split UI and hand both views back to the stack. Does
        NOT change the current selection — callers decide what to show next."""
        if (self._split_view is None
                or self.page_area.currentWidget() is not self._split_view):
            return
        views = self._split_view.unmount()
        for v in views:
            if v is not None and self.tab_stack.indexOf(v) < 0:
                self.tab_stack.addWidget(v)
        self.page_area.setCurrentWidget(self.tab_stack)
        for v in views:                 # drop the split markers
            self._update_tab_label(v)

    def _exit_split_view(self, restore: bool = True) -> None:
        if (self._split_view is None
                or self.page_area.currentWidget() is not self._split_view):
            return
        target = getattr(self, "_pre_split_active", None) if restore \
            else self._active_view
        self._teardown_split()
        if target is None or target not in self._views:
            target = (self._active_view if self._active_view in self._views
                      else (self._views[0] if self._views else None))
        if target is not None:
            idx = self._index_of(target)
            if self.tab_bar.currentIndex() == idx:
                self._on_tab_changed(idx)
            else:
                self.tab_bar.setCurrentIndex(idx)

    def _swap_split(self) -> None:
        if self._split_view is None:
            return
        self._split_view.swap()
        self._refresh_split_titles()
        self._schedule_session_save()

    def _refresh_split_titles(self) -> None:
        if self._split_view is None:
            return
        titles = {}
        for v in self._split_view.views():
            titles[v] = (getattr(v, "_full_title", "")
                         or getattr(v, "_short_title", "")
                         or v.url().host() or "New tab")
        self._split_view.set_titles(titles)

    def _on_split_focus(self, view: WebView) -> None:
        self._active_view = view
        self._thaw(view)
        idx = self._index_of(view)
        if idx >= 0:
            self.tab_bar.blockSignals(True)
            self.tab_bar.setCurrentIndex(idx)
            self.tab_bar.blockSignals(False)
        self._sync_chrome_to(view)

    def _replace_split_pane(self, pane) -> None:
        """The ⇄ button on a pane: pick another tab to show there."""
        if self._split_view is None:
            return
        shown = set(self._split_view.views())
        menu = QMenu(self)
        added = False
        for v in self._views:
            if v in shown:
                continue
            menu.addAction(self._tab_menu_title(v),
                           lambda vv=v, pp=pane: self._put_view_in_pane(pp, vv))
            added = True
        if not added:
            menu.addAction("No other tabs").setEnabled(False)
        menu.exec(QCursor.pos())

    def _put_view_in_pane(self, pane, view: WebView) -> None:
        if self._split_view is None or view not in self._views:
            return
        other = self._split_view.other_pane(pane)
        if other is not None and other.view is view:
            self._swap_split()          # it's the other pane's tab -> swap
            return
        outgoing = pane.view
        if outgoing is view:
            return
        if self.tab_stack.indexOf(view) >= 0:
            self.tab_stack.removeWidget(view)
        detached = pane.take_view()
        if detached is not None and self.tab_stack.indexOf(detached) < 0:
            self.tab_stack.addWidget(detached)
        self._split_view.set_view_in_pane(pane, view)
        self._refresh_split_titles()
        if detached is not None:
            self._update_tab_label(detached)
        self._update_tab_label(view)
        self._schedule_session_save()

    def _return_split_view_to_strip(self, view: WebView) -> None:
        # Returning one pane collapses the split; keep that tab active.
        self._pre_split_active = view
        self._exit_split_view(restore=True)

    def _on_tab_dropped_on_pane(self, pane, src_index: int) -> None:
        if (self._split_view is None
                or self.page_area.currentWidget() is not self._split_view):
            return
        if not (0 <= src_index < len(self._views)):
            return
        self._put_view_in_pane(pane, self._views[src_index])

    def _open_bookmark(self, url: str) -> None:
        self.add_tab(QUrl(url))

    def _on_icon_changed(self, view: WebView, icon) -> None:
        index = self._index_of(view)
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
        self.ai_client.cancel()  # drop any in-flight Ollama request
        self._session_timer.stop()
        # Clean exit clears the snapshot (a leftover file means "crashed"); an
        # intentional restart keeps it so the new instance can reopen the tabs.
        if not self._restarting:
            clear_snapshot()
        self.cookie_keeper.flush()  # capture last cookie updates in the jar
        # The vault window has no parent (so it can fall behind), which also
        # means it won't be torn down with this one — close it explicitly or
        # it would outlive the browser and keep the process alive.
        if self._vault_dialog is not None:
            self._vault_dialog.close()
        if self._report_window is not None:
            self._report_window.close()
        # Detached tab windows share this window's profile, so they must not
        # outlive it — close them (destroying their views) before teardown.
        for win in list(self._detached_windows):
            win.close_for_shutdown()
        self._detached_windows.clear()
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

    def _set_location_guard(self, on: bool) -> None:
        """Turn precise-geolocation blocking on/off by inserting or removing
        the main-world shim. Applies to pages loaded from here on."""
        if on == getattr(self, "_location_guard_on", None):
            return
        self._location_guard_on = on
        save_location_guard(on)
        scripts = self.profile.scripts()
        if on:
            scripts.insert(self._location_guard_script)
        else:
            for script in scripts.find("vodou-location-guard"):
                scripts.remove(script)
        self.statusBar().showMessage(
            "Location Guard on — precise location blocked. Reload open pages "
            "to apply." if on else
            "Location Guard off — sites may request your precise location. "
            "Reload open pages to apply.", 6000)

    def _set_block_webcam(self, on: bool) -> None:
        """Turn webcam blocking on/off. Takes effect on the next camera
        request — no reload needed, since the gate is checked live."""
        if on == getattr(self, "_block_webcam", None):
            return
        self._block_webcam = on
        save_block_webcam(on)
        self.statusBar().showMessage(
            "Block Webcam on — sites can't use your camera." if on else
            "Block Webcam off — Vodou will ask before a site uses your "
            "camera.", 6000)

    def _set_block_microphone(self, on: bool) -> None:
        """Turn microphone blocking on/off. Takes effect on the next
        microphone request — no reload needed, since the gate is checked
        live."""
        if on == getattr(self, "_block_microphone", None):
            return
        self._block_microphone = on
        save_block_microphone(on)
        self.statusBar().showMessage(
            "Block Microphone on — sites can't use your microphone." if on else
            "Block Microphone off — Vodou will ask before a site uses your "
            "microphone.", 6000)

    def _note_capture_blocked(self, host: str, what: str) -> None:
        """Briefly tell the user a camera/mic request was just denied,
        rate-limited so a page that retries in a loop can't flood the status
        bar. `what` names the device(s), e.g. 'camera and microphone'."""
        now = time.monotonic()
        if now - self._capture_note_at < 4.0:
            return
        self._capture_note_at = now
        who = host or "A site"
        self.statusBar().showMessage(
            f"Blocked a {what} request from {who}. Adjust Block Webcam / "
            "Block Microphone in Settings to allow it.", 5000)

    def _prompt_capture(self, permission, what: str) -> None:
        """Ask the user whether to grant a camera/mic request (the relevant
        guard is off). Kept per-request so the choice is never remembered
        silently. `what` names the device(s) being requested."""
        host = permission.origin().host() or "This site"
        answer = plain_message(
            self, QMessageBox.Icon.Question, "Device access",
            f"{host} wants to use your {what}.\n\n"
            f"Allow it to access your {what} for this request?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        try:
            if answer == QMessageBox.StandardButton.Yes:
                permission.grant()
            else:
                permission.deny()
        except RuntimeError:
            pass  # page navigated away while the prompt was open

    # -- Start page & search engine -----------------------------------------

    def set_start_page(self) -> None:
        """Let the user pick the page new tabs and Home open. Blank restores
        the private SearXNG default. Takes effect on the next new tab / Home."""
        global HOME_URL
        text, ok = QInputDialog.getText(
            self, "Set start page",
            "Start page URL (leave blank for the private SearXNG page):",
            QLineEdit.EchoMode.Normal, HOME_URL)
        if not ok:
            return
        value = _normalize_url(text)
        if value and not _safe_start_page(value):
            plain_message(
                self, QMessageBox.Icon.Warning, "Set start page",
                "The start page must be a normal web page (http:// or "
                "https://). Nothing was changed.")
            return
        if value:
            HOME_URL = value
            _save_pref("start_page", value)
            self.statusBar().showMessage(
                f"Start page set to {value} — opens on the next new tab.", 5000)
        else:
            HOME_URL = SEARXNG_BASE
            _save_pref("start_page", "")
            self.statusBar().showMessage(
                "Start page reset to the private SearXNG page.", 5000)

    def set_startup_page(self) -> None:
        """Let the user pick the page a fresh launch opens, independently of the
        start page (new tabs / Home). Blank follows the start page. Takes effect
        on the next launch."""
        global STARTUP_URL
        # Show what launch currently opens; a blank value means "follow the
        # start page", so present that case as an empty field.
        current = "" if STARTUP_URL == HOME_URL else STARTUP_URL
        text, ok = QInputDialog.getText(
            self, "Set startup page",
            "Startup page URL (leave blank to open your start page on launch):",
            QLineEdit.EchoMode.Normal, current)
        if not ok:
            return
        value = _normalize_url(text)
        if value and not _safe_start_page(value):
            plain_message(
                self, QMessageBox.Icon.Warning, "Set startup page",
                "The startup page must be a normal web page (http:// or "
                "https://). Nothing was changed.")
            return
        if value:
            STARTUP_URL = value
            _save_pref("startup_page", value)
            self.statusBar().showMessage(
                f"Startup page set to {value} — opens on the next launch.", 5000)
        else:
            STARTUP_URL = HOME_URL
            _save_pref("startup_page", "")
            self.statusBar().showMessage(
                "Startup page now follows your start page.", 5000)

    def _build_search_engine_menu(self, menu) -> None:
        """Populate the Settings ▸ Search engine submenu: one exclusive radio
        per built-in engine, plus a Custom option."""
        menu.setToolTip(
            "Where address-bar searches go. SearXNG (local) keeps queries on "
            "your machine; the others are external services.")
        group = QActionGroup(self)
        group.setExclusive(True)
        self._engine_actions = {}
        for name, template in SEARCH_ENGINES.items():
            act = menu.addAction(name)
            act.setCheckable(True)
            act.triggered.connect(
                lambda _checked, t=template: self._set_search_engine(t))
            group.addAction(act)
            self._engine_actions[template] = act
        menu.addSeparator()
        self._custom_engine_action = menu.addAction("Custom…")
        self._custom_engine_action.setCheckable(True)
        self._custom_engine_action.triggered.connect(self._set_custom_engine)
        group.addAction(self._custom_engine_action)
        self._sync_engine_check()

    def _sync_engine_check(self) -> None:
        """Tick the radio matching the active SEARCH_URL (Custom if none do)."""
        matched = False
        for template, act in self._engine_actions.items():
            on = (template == SEARCH_URL)
            act.setChecked(on)
            matched = matched or on
        self._custom_engine_action.setChecked(not matched)

    def _set_search_engine(self, template: str) -> None:
        global SEARCH_URL
        SEARCH_URL = template
        _save_pref("search_engine", template)
        self._sync_engine_check()
        name = next((n for n, t in SEARCH_ENGINES.items() if t == template),
                    template)
        self.statusBar().showMessage(f"Search engine set to {name}.", 5000)

    def _set_custom_engine(self) -> None:
        """Prompt for a custom search-URL template (must contain {})."""
        global SEARCH_URL
        text, ok = QInputDialog.getText(
            self, "Custom search engine",
            "Search URL template — put {} where the query goes, e.g.\n"
            "https://example.com/search?q={}",
            QLineEdit.EchoMode.Normal, SEARCH_URL)
        if not ok:
            self._sync_engine_check()   # cancelled — restore the real choice
            return
        template = text.strip().replace("%s", "{}")
        if "{}" not in template:
            plain_message(
                self, QMessageBox.Icon.Warning, "Custom search engine",
                "The template must contain {} where the search query should "
                "go. Nothing was changed.")
            self._sync_engine_check()
            return
        SEARCH_URL = template
        _save_pref("search_engine", template)
        self._sync_engine_check()
        self.statusBar().showMessage("Custom search engine set.", 5000)

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
        self._restore_snapshot_tabs(urls, current)
        return True

    def _resume_after_restart(self) -> bool:
        """Silently reopen the tabs saved just before an intentional restart."""
        snapshot = load_snapshot()
        if snapshot is None:
            return False
        self._restore_snapshot_tabs(*snapshot)
        return True

    def _restore_snapshot_tabs(self, urls: list[str], current: int) -> None:
        """Open a snapshot's tabs lazily and select the one that was active."""
        for u in urls:
            view = self.add_tab(None, background=True)
            view.pending_url = QUrl(u)
            # Label the unloaded tab with its host so it's recognizable (store
            # it as the title piece so the memory poll doesn't overwrite it).
            view._short_title = view.pending_url.host() or u
            self._update_tab_label(view)
        if 0 <= current < len(self._views):
            self.tab_bar.setCurrentIndex(current)
            self._on_tab_changed(current)

    def _show_update_celebration(self) -> None:
        """Open the one-time confetti/fireworks 'latest version' page in a fresh
        foreground tab, then record this version so it shows only once. Rendered
        with setHtml under the sentinel host — self-contained, no file on disk,
        no network."""
        view = self.add_tab()
        view.page().setHtml(celebrate.html(APP_VERSION),
                            QUrl(f"https://{SENTINEL_HOST}/updated"))
        celebrate.mark_seen(APP_VERSION)

    def _prompt_restart(self, change: str) -> None:
        """Ask whether to restart now so a just-changed setting takes effect."""
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Restart to apply")
        box.setText(f"{change}\n\nThis takes effect after a restart. Restart "
                    "Vodou now? Your open tabs will be reopened.")
        restart = box.addButton("Restart now",
                                QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Later", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(restart)
        box.exec()
        if box.clickedButton() is restart:
            self._restart_app()

    def _restart_app(self) -> None:
        """Relaunch Vodou (reopening the current tabs) and close this window."""
        self._write_session()          # snapshot the open tabs
        mark_restart()                 # new instance reopens them silently
        self._restarting = True        # closeEvent keeps the snapshot
        script = str(Path(__file__).resolve())
        # PyQt6's 3-arg startDetached returns (started, pid).
        started, _pid = QProcess.startDetached(
            sys.executable, [script] + sys.argv[1:], str(Path(script).parent))
        if not started:
            self._restarting = False   # relaunch failed — don't lose the tabs
            QMessageBox.warning(
                self, "Couldn't restart",
                "Vodou couldn't relaunch itself. Please close and reopen it "
                "to apply the change.")
            return
        self.close()

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
        cur = self._active_view
        for view in self._views:
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
        # The login cues belong to the tab that raised them; clear them on
        # switch (the newly-shown tab isn't re-probed until its next load).
        self._clear_login_cues()
        self._schedule_session_save()
        if not (0 <= index < len(self._views)):
            return
        view = self._views[index]
        # Selecting one of the two split tabs focuses that pane rather than
        # collapsing the split; selecting any other tab leaves the split.
        if self._split_view is not None and view in self._split_view.views():
            self._split_view.set_focused_view(view)   # -> _on_split_focus
            return
        if (self._split_view is not None
                and self.page_area.currentWidget() is self._split_view):
            self._teardown_split()
        self._active_view = view
        self.page_area.setCurrentWidget(self.tab_stack)
        self.tab_stack.setCurrentWidget(view)
        self._thaw(view)
        self._load_pending(view)
        self._sync_chrome_to(view)

    def _sync_chrome_to(self, view: WebView | None) -> None:
        """Point the address bar, security indicator, star, window title, and
        docked DevTools at `view` (the focused tab, split or not)."""
        if view is None:
            return
        # A tab parked on the deceptive-site interstitial reflects the blocked
        # host, not the internal sentinel URL.
        if view.url().host() == SENTINEL_HOST:
            self._on_url_changed(view, view.url())
            return
        self.url_bar.setText(view.url().toString())
        self.url_bar.setCursorPosition(0)
        self._update_security_indicator(view.url())
        self._update_star(view.url())
        title = getattr(view, "_full_title", "") or view.url().host()
        if title:
            self.setWindowTitle(f"{title} — Vodou (private)")
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

    def check_content_credentials(self, url: QUrl) -> None:
        """Fetch an image and verify its C2PA Content Credential on-device.
        data: images are read inline; http(s)/file images are re-fetched (from
        the same place the page already loaded them). Other schemes can't be
        read, so we say so rather than guess."""
        scheme = url.scheme().lower()
        if scheme == "data":
            data, mime = _decode_data_url(url.toString())
            if data is None:
                plain_message(self, QMessageBox.Icon.Warning,
                              "Content Credentials",
                              "This inline image couldn't be read to check it.")
                return
            self._show_credential_result(
                content_credentials.verify_image(data, mime))
            return
        if scheme not in ("http", "https", "file"):
            plain_message(self, QMessageBox.Icon.Information,
                          "Content Credentials",
                          "This image can't be fetched to check — only http(s), "
                          "local files, and inline images are supported.")
            return
        self.statusBar().showMessage("Checking content credentials…")
        reply = self._cc_nam.get(QNetworkRequest(url))
        reply.finished.connect(lambda r=reply, u=url: self._on_cc_reply(r, u))

    def _on_cc_reply(self, reply, url: QUrl) -> None:
        self.statusBar().clearMessage()
        ok = reply.error() == QNetworkReply.NetworkError.NoError
        data = bytes(reply.readAll())
        ctype = reply.header(QNetworkRequest.KnownHeaders.ContentTypeHeader)
        reply.deleteLater()
        if not ok or not data:
            plain_message(self, QMessageBox.Icon.Warning, "Content Credentials",
                          "Couldn't download this image to check it.")
            return
        mime = (str(ctype).split(";")[0].strip() if ctype
                else _guess_image_mime(url))
        self._show_credential_result(
            content_credentials.verify_image(data, mime or "image/jpeg"))

    def _show_credential_result(self, result) -> None:
        """Present a CredentialResult honestly. Text is PlainText (the signer /
        generator are attacker-controlled), and the closing note makes clear
        that 'no credential' means unknown, never 'authentic'."""
        icon = {
            "trusted": QMessageBox.Icon.Information,
            "untrusted": QMessageBox.Icon.Warning,
            "invalid": QMessageBox.Icon.Critical,
            "none": QMessageBox.Icon.Information,
        }.get(result.status, QMessageBox.Icon.Warning)
        lines = [result.headline, "", result.detail]
        if result.status in ("trusted", "untrusted", "invalid"):
            if result.ai_generated:
                lines += ["", "⚠ This credential declares the image was "
                              "AI / algorithmically generated."]
            if result.signer:
                lines += ["", f"Signer: {result.signer}"]
            if result.signed_time:
                lines += [f"Signed: {result.signed_time}"]
            if result.generator:
                lines += [f"Created with: {result.generator}"]
        lines += ["", "— Vodou verifies signed provenance (C2PA) on your "
                      "device. It cannot detect a fake that carries no "
                      "credential: “no credential” means unknown, not "
                      "authentic."]
        plain_message(self, icon, "Content Credentials", "\n".join(lines))

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
        index = self._index_of(view)
        short = title if len(title) <= 25 else title[:24] + "…"
        view._short_title = short or "New tab"
        view._full_title = title
        if index >= 0:
            self.tab_bar.setTabToolTip(index, title)
        self._update_tab_label(view)  # re-adds a memory line if one is known
        self._refresh_split_titles()
        if view is self.current_view():
            self.setWindowTitle(f"{title} — Vodou (private)")

    def _update_tab_label(self, view: WebView) -> None:
        """Set the tab text to the page title plus its renderer memory, e.g.
        'GitHub · 142 MB', with pin / mute / split markers prefixed. Memory is
        appended only once known."""
        index = self._index_of(view)
        if index < 0:
            return
        title = getattr(view, "_short_title", None) or "New tab"
        markers = ""
        if getattr(view, "_pinned", False):
            markers += "📌 "
        if view.page().isAudioMuted():
            markers += "🔇 "
        if (self._split_view is not None
                and view in self._split_view.views()):
            markers += "◫ "
        mb = getattr(view, "_mem_mb", None)
        body = f"{title}  ·  {mb:.0f} MB" if mb is not None else title
        self.tab_bar.setTabText(index, markers + body)
        if mb is not None:
            full = getattr(view, "_full_title", "") or title
            self.tab_bar.setTabToolTip(
                index, f"{full}\nRenderer memory: {mb:.0f} MB")

    def _poll_tab_memory(self) -> None:
        """Refresh every tab's renderer-memory figure (see the timer)."""
        for view in self._views:
            pid = view.page().renderProcessPid()
            view._mem_mb = _process_working_set_mb(pid)
            self._update_tab_label(view)

    def _visible_views(self) -> set["WebView"]:
        """Views currently on screen — never candidates for freeze/discard."""
        if (self._split_view is not None
                and self.page_area.currentWidget() is self._split_view):
            return set(self._split_view.views())
        w = self.tab_stack.currentWidget()
        return {w} if isinstance(w, WebView) else set()

    def _thaw(self, view: "WebView") -> None:
        """Return a tab to Active — resuming a frozen page, reloading a
        discarded one — and reset its idle clock. Called the moment a tab
        becomes visible so the switch feels instant rather than waiting for
        the next lifecycle sweep."""
        view._hidden_since = None
        page = view.page()
        if page.lifecycleState() != QWebEnginePage.LifecycleState.Active:
            page.setLifecycleState(QWebEnginePage.LifecycleState.Active)

    @staticmethod
    def _less_aggressive(a, b):
        """The tamer of two lifecycle states (Active < Frozen < Discarded)."""
        order = {QWebEnginePage.LifecycleState.Active: 0,
                 QWebEnginePage.LifecycleState.Frozen: 1,
                 QWebEnginePage.LifecycleState.Discarded: 2}
        return a if order[a] <= order[b] else b

    def _sweep_tab_lifecycle(self) -> None:
        """Freeze tabs idle past TAB_FREEZE_AFTER_S and discard those past the
        user's configured timeout (self._discard_after_s; 0 disables discard),
        so background tabs stop pinning a full render process in RAM.

        Safety comes from three layers: not-yet-loaded and pinned tabs are
        skipped outright; every target is clamped to the page's own
        recommendedState(), which Chromium keeps at Active for anything that
        must keep running (audible media, an active download, WebRTC, recent
        input); and discard is only ever reached from Frozen, never straight
        from Active. Visible tabs are held Active."""
        State = QWebEnginePage.LifecycleState
        now = time.monotonic()
        visible = self._visible_views()
        for view in self._views:
            if view in visible:
                view._hidden_since = None
                page = view.page()
                if page.lifecycleState() != State.Active:
                    page.setLifecycleState(State.Active)
                continue
            # Crash/session-restored tabs never opened this run hold no render
            # process yet — nothing to reclaim, and touching them would force
            # the load we deliberately deferred.
            if view.pending_url is not None:
                continue
            if getattr(view, "_pinned", False):
                continue
            hidden_since = view._hidden_since
            if hidden_since is None:
                view._hidden_since = now
                continue
            idle = now - hidden_since
            if self._discard_after_s and idle >= self._discard_after_s:
                target = State.Discarded
            elif idle >= TAB_FREEZE_AFTER_S:
                target = State.Frozen
            else:
                continue
            page = view.page()
            # Never exceed what the engine says is safe right now...
            target = self._less_aggressive(target, page.recommendedState())
            # ...and reach Discarded only via Frozen, never straight from
            # Active (Qt forbids the direct jump).
            if target == State.Discarded and page.lifecycleState() == State.Active:
                target = State.Frozen
            if page.lifecycleState() != target:
                page.setLifecycleState(target)

    def _build_discard_menu(self, menu) -> None:
        """Populate Settings ▸ Idle tab memory: one exclusive radio per discard
        timeout. A background tab is frozen after a minute either way; this sets
        how long after that it is discarded (render process freed, reloads on
        return). 'Never' keeps every tab in memory."""
        menu.setToolTip(
            "How long a background tab may sit idle before Vodou frees its "
            "memory. It reloads when you return to it. 'Never' keeps every tab "
            "in memory (they are still frozen after a minute).")
        group = QActionGroup(self)
        group.setExclusive(True)
        self._discard_actions = {}
        for label, seconds in TAB_DISCARD_OPTIONS:
            act = menu.addAction(label)
            act.setCheckable(True)
            act.setChecked(seconds == self._discard_after_s)
            act.triggered.connect(
                lambda _checked, s=seconds: self._set_discard_after(s))
            group.addAction(act)
            self._discard_actions[seconds] = act

    def _set_discard_after(self, seconds: int) -> None:
        """Apply and persist a new discard timeout; takes effect on the next
        lifecycle sweep (within TAB_LIFECYCLE_SWEEP_MS)."""
        self._discard_after_s = seconds
        save_discard_after_s(seconds)
        act = self._discard_actions.get(seconds)
        if act is not None:
            act.setChecked(True)
        if seconds:
            label = next(l for l, s in TAB_DISCARD_OPTIONS if s == seconds)
            self.statusBar().showMessage(
                f"Idle background tabs will be discarded {label.lower()}.",
                5000)
        else:
            self.statusBar().showMessage(
                "Idle background tabs will be frozen but never discarded.",
                5000)

    # -- proxy --------------------------------------------------------------

    def _apply_proxy(self) -> None:
        """(Re)apply the saved proxy to the whole application and reset the
        per-session auth state so new settings take effect immediately."""
        QNetworkProxy.setApplicationProxy(_build_qnetwork_proxy(_load_proxy_conf()))
        self._proxy_auth_cache = None
        self._proxy_last_offered = {}
        self._proxy_auth_failcount = {}

    def _on_proxy_auth(self, request_url, authenticator, proxy_host) -> None:
        """Supply credentials when the proxy demands sign-in.

        Order: the session cache, then the vault (if unlocked), else a prompt.
        When Qt re-emits with the same username we just tried, that attempt was
        rejected, so we prompt afresh; a small consecutive-failure cap makes a
        wrong password fail the load cleanly instead of looping forever."""
        host = proxy_host or ""
        offered = self._proxy_last_offered.get(host)
        rejected = offered is not None and authenticator.user() == offered[0]
        if rejected:
            fails = self._proxy_auth_failcount.get(host, 0) + 1
            self._proxy_auth_failcount[host] = fails
            self._proxy_auth_cache = None
            self._proxy_last_offered.pop(host, None)
            if fails > 3:
                self._proxy_auth_failcount[host] = 0
                return  # give up this round; the load fails cleanly
            creds = self._prompt_proxy_credentials(proxy_host, rejected=True)
        else:
            # A fresh challenge means any previous credential was accepted.
            self._proxy_auth_failcount[host] = 0
            creds = self._proxy_auth_cache
            if creds is None and self.vault.unlocked:
                creds = self.vault.proxy_credential()
            if creds is None:
                creds = self._prompt_proxy_credentials(proxy_host, rejected=False)
        if creds is None:
            return
        self._proxy_auth_cache = creds
        self._proxy_last_offered[host] = creds
        authenticator.setUser(creds[0])
        authenticator.setPassword(creds[1])

    def _prompt_proxy_credentials(self, proxy_host, rejected):
        """Ask the user for proxy credentials (username prefilled from the saved
        config). Returns (user, password) or None if cancelled."""
        conf = _load_proxy_conf()
        lead = ("The proxy rejected those credentials.\n\n" if rejected else "")
        user, ok = QInputDialog.getText(
            self, "Proxy sign-in",
            f"{lead}The proxy {proxy_host or ''} requires a username and "
            "password.\nUsername:",
            QLineEdit.EchoMode.Normal, conf.get("username", ""))
        if not ok:
            return None
        pw, ok = QInputDialog.getText(
            self, "Proxy sign-in", "Password:", QLineEdit.EchoMode.Password)
        if not ok:
            return None
        return (user.strip(), pw)

    def _show_proxy_dialog(self) -> None:
        """Settings ▸ Network ▸ Proxy…: choose no proxy or a manual HTTP/SOCKS5
        proxy, with an optional username/password saved in the vault."""
        conf = _load_proxy_conf()
        dlg = QDialog(self)
        dlg.setWindowTitle("Proxy")
        dlg.setMinimumWidth(440)
        outer = QVBoxLayout(dlg)

        none_radio = QRadioButton("No proxy (direct connection)")
        manual_radio = QRadioButton("Manual proxy")
        outer.addWidget(none_radio)
        outer.addWidget(manual_radio)

        box = QGroupBox()
        form = QFormLayout(box)
        type_combo = QComboBox()
        for key, label in PROXY_TYPES.items():
            type_combo.addItem(label, key)
        host_edit = QLineEdit(str(conf.get("host", "")))
        host_edit.setPlaceholderText("e.g. 127.0.0.1")
        port_spin = QSpinBox()
        port_spin.setRange(1, 65535)
        port_spin.setValue(int(conf.get("port") or 8080))
        remote_dns = QCheckBox("Resolve DNS at the proxy (SOCKS5 only)")
        remote_dns.setChecked(bool(conf.get("remote_dns", True)))
        user_edit = QLineEdit(str(conf.get("username", "")))
        pass_edit = QLineEdit()
        pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        if self.vault.file_has_proxy_credential():
            pass_edit.setPlaceholderText(
                "saved in vault — leave blank to keep it")
        show = QCheckBox("Show")
        show.toggled.connect(lambda on: pass_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        pass_row = QHBoxLayout()
        pass_row.addWidget(pass_edit)
        pass_row.addWidget(show)
        pass_holder = QWidget()
        pass_holder.setLayout(pass_row)

        form.addRow("Type:", type_combo)
        form.addRow("Host:", host_edit)
        form.addRow("Port:", port_spin)
        form.addRow("", remote_dns)
        form.addRow("Username:", user_edit)
        form.addRow("Password:", pass_holder)
        note = QLabel("The proxy password is stored in your encrypted vault, "
                      "never in plain text. You'll be asked to unlock the "
                      "vault to save it.")
        note.setWordWrap(True)
        form.addRow(note)
        outer.addWidget(box)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        outer.addWidget(buttons)

        idx = type_combo.findData(conf.get("type", "http"))
        type_combo.setCurrentIndex(idx if idx >= 0 else 0)

        def sync_enabled() -> None:
            on = manual_radio.isChecked()
            box.setEnabled(on)
            remote_dns.setEnabled(on and type_combo.currentData() == "socks5")

        manual_radio.toggled.connect(lambda _: sync_enabled())
        type_combo.currentIndexChanged.connect(lambda _: sync_enabled())
        (manual_radio if conf.get("enabled") else none_radio).setChecked(True)
        sync_enabled()

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        if none_radio.isChecked():
            save_proxy_conf({"enabled": False})
            self._apply_proxy()
            self.statusBar().showMessage(
                "Proxy disabled — direct connection.", 5000)
            return

        host = host_edit.text().strip()
        if not host:
            plain_message(self, QMessageBox.Icon.Warning, "Proxy",
                          "Enter the proxy host (e.g. 127.0.0.1). Nothing was "
                          "changed.")
            return
        ptype = type_combo.currentData()
        username = user_edit.text().strip()
        save_proxy_conf({
            "enabled": True, "type": ptype, "host": host,
            "port": int(port_spin.value()), "username": username,
            "remote_dns": bool(remote_dns.isChecked())})

        pw = pass_edit.text()
        if pw:
            if ensure_unlocked(self.vault, self):
                self.vault.set_proxy_credential(username, pw)
            else:
                plain_message(
                    self, QMessageBox.Icon.Information, "Proxy",
                    "The proxy settings were saved, but the password wasn't "
                    "stored because the vault stayed locked. You'll be asked "
                    "for it when the proxy requires sign-in.")
        elif not username and self.vault.unlocked:
            # Cleared out the username with no password: drop any stored login.
            self.vault.clear_proxy_credential()

        self._apply_proxy()
        self.statusBar().showMessage(
            f"Proxy set: {PROXY_TYPES.get(ptype, ptype)} "
            f"{host}:{port_spin.value()}.", 5000)

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
        self._refresh_vault_indicator()  # vault locked/unlocked state icon
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
        self._prompt_restart("The graphics mode has been changed.")

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
        # Hand it the live SafeBrowsing instance so the one-click update
        # refreshes the malicious-site definitions along with the app and
        # engine — those lists go stale fastest of the three.
        dialog = AboutDialog(self, safe_browsing=self.safe_browsing)
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

    # -- Local AI: search summaries and ask-anything (Ollama) ---------------

    def _ensure_ai_panel(self) -> None:
        """Build the docked AI panel once, lazily (mirrors DevTools). The same
        panel serves both modes: summaries and free-form chat."""
        if self._ai_panel is not None:
            return
        header = QWidget()
        header.setObjectName("aiHeader")
        header.setFixedHeight(32)
        hb = QHBoxLayout(header)
        hb.setContentsMargins(12, 0, 6, 0)
        hb.setSpacing(6)
        title = QLabel("LOCAL AI")
        title.setObjectName("aiTitle")
        self._ai_title = title
        # Model picker, populated from the local Ollama's installed models.
        self._ai_model_combo = QComboBox()
        self._ai_model_combo.setObjectName("aiModelCombo")
        self._ai_model_combo.setToolTip(
            "Model to use — the list is your local Ollama's installed models")
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

        # Ask box. Always available, in either mode — typing a question while a
        # summary is on screen continues from that summary as a conversation.
        ask_row = QHBoxLayout()
        ask_row.setContentsMargins(10, 6, 10, 0)
        ask_row.setSpacing(6)
        self._ai_input = QLineEdit()
        self._ai_input.setObjectName("aiInput")
        self._ai_input.setPlaceholderText("Ask anything…")
        self._ai_input.setClearButtonEnabled(True)
        self._ai_input.returnPressed.connect(self._send_ai_question)
        self._ai_send = QPushButton("Send")
        self._ai_send.setObjectName("aiSend")
        self._ai_send.clicked.connect(self._send_ai_question)
        ask_row.addWidget(self._ai_input, 1)
        ask_row.addWidget(self._ai_send)

        bar = QHBoxLayout()
        bar.setContentsMargins(10, 4, 10, 8)
        bar.setSpacing(6)
        self._ai_regen = QPushButton("Regenerate")
        self._ai_regen.setToolTip("Summarize this page's results again")
        self._ai_regen.clicked.connect(self.summarize_search)
        self._ai_stop = QPushButton("Stop")
        self._ai_stop.clicked.connect(self._stop_ai)
        self._ai_stop.setEnabled(False)
        self._ai_clear = QPushButton("New chat")
        self._ai_clear.setToolTip("Forget this conversation and start over")
        self._ai_clear.clicked.connect(self._clear_ai_chat)
        bar.addWidget(self._ai_regen)
        bar.addWidget(self._ai_stop)
        bar.addWidget(self._ai_clear)
        bar.addStretch()

        self._ai_panel = QWidget()
        self._ai_panel.setObjectName("aiPanel")
        pv = QVBoxLayout(self._ai_panel)
        pv.setContentsMargins(0, 0, 0, 0)
        pv.setSpacing(0)
        pv.addWidget(header)
        pv.addWidget(self._ai_status)
        pv.addWidget(self._ai_text, 1)
        pv.addLayout(ask_row)
        pv.addLayout(bar)
        self._split.addWidget(self._ai_panel)
        self._ai_panel.hide()

    def _show_ai_panel(self) -> None:
        self._ensure_ai_panel()
        # Refresh the model list from Ollama each time the panel opens (cheap,
        # and picks up models installed since last time).
        self.ai_client.list_models(self.ai_cfg, self._on_ai_models_listed)
        self._ai_panel.show()
        total = self._split.width() or self.width() or 1280
        self._split.setSizes([int(total * 0.62), int(total * 0.38)])

    def _set_ai_mode(self, mode: str) -> None:
        """Switch the panel between "summary" and "ask" presentation."""
        # A reply still streaming belongs to the old mode — its chunks would be
        # routed into the wrong view, so drop the request with the mode.
        if mode != self._ai_mode and self.ai_client.busy:
            self.ai_client.cancel()
        self._ai_mode = mode
        if self._ai_panel is None:
            return
        summary = mode == "summary"
        self._ai_title.setText("AI SUMMARY" if summary else "ASK AI")
        # Regenerate only means something for a summary of a results page.
        self._ai_regen.setVisible(summary)
        self._ai_clear.setVisible(not summary)

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
        if self.ai_client.busy:
            return
        # Nudge the user about what the new model applies to.
        if self._ai_mode == "summary" and self._ai_last is not None:
            self._set_ai_status(
                f"Model set to {name} — click Regenerate to re-summarize.")
        else:
            self._set_ai_status(f"Model set to {name}.")

    def _close_ai_panel(self) -> None:
        self.ai_client.cancel()
        if self._ai_panel is not None:
            self._ai_panel.hide()

    def _ai_enabled(self) -> bool:
        """True if local AI is switched on; otherwise nudge and return False."""
        if self.ai_cfg.get("enabled"):
            return True
        self.statusBar().showMessage(
            "Local AI is off — enable it in ☰ → Settings → Local AI.", 6000)
        return False

    def open_ai_panel(self) -> None:
        """The ✨ button: summarize if this is a results page, else ask."""
        view = self.current_view()
        if view is not None and is_search_results(view.url()):
            self.summarize_search()
        else:
            self.ask_ai()

    def ask_ai(self) -> None:
        """Open the panel in ask mode with the question box focused."""
        if not self._ai_enabled():
            return
        self._show_ai_panel()
        # Coming from a finished summary, keep it as the conversation's opening
        # so follow-ups still have that context.
        if self._ai_mode == "summary" and not self.ai_client.busy:
            self._carry_summary_into_chat()
        self._set_ai_mode("ask")
        self._render_ai_chat()
        if not self._ai_chat:
            self._set_ai_status(
                f"Ask {self.ai_cfg.get('model', '')} anything — runs on your "
                "device, and only what you type is sent to it.")
        self._ai_input.setFocus()
        self._ai_input.selectAll()

    def summarize_search(self) -> None:
        """Read the current search results and summarize them with Ollama."""
        if not self._ai_enabled():
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
        self._set_ai_mode("summary")
        self._ai_text.clear()
        self._set_ai_status("Reading the results on this page…")
        self._ai_stop.setEnabled(True)
        self._ai_regen.setEnabled(False)
        self._ai_send.setEnabled(False)
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
            self._ai_send.setEnabled(True)
            return
        self._ai_last = (query, results)
        model = self.ai_cfg.get("model", "")
        self._set_ai_status(
            f"Summarizing {len(results)} results with {model} — on your "
            f"device…")
        self.ai_client.summarize(query, results, self.ai_cfg)

    # -- ask mode ----------------------------------------------------------

    def _send_ai_question(self) -> None:
        """Send whatever is in the ask box as the next turn of the chat."""
        if self._ai_panel is None or not self._ai_enabled():
            return
        question = self._ai_input.text().strip()
        if not question or self.ai_client.busy:
            return
        # Asking from a finished summary carries it over, so follow-up
        # questions about those results have the context they need.
        if self._ai_mode == "summary":
            self._carry_summary_into_chat()
        self._set_ai_mode("ask")
        self._ai_input.clear()
        self._ai_chat.append({"role": "user", "content": question})
        self._ai_stream = ""
        self._render_ai_chat()
        self._set_ai_status(
            f"Asking {self.ai_cfg.get('model', '')} — on your device…")
        self._ai_stop.setEnabled(True)
        self._ai_send.setEnabled(False)
        self.ai_client.chat(self._ai_chat, self.ai_cfg)

    def _carry_summary_into_chat(self) -> None:
        """Seed the conversation with the summary that's on screen, so the
        model can answer follow-ups about it."""
        summary = self._ai_text.toPlainText().strip()
        if not summary or self._ai_chat:
            return
        query = self._ai_last[0] if self._ai_last else ""
        self._ai_chat = [
            {"role": "user",
             "content": (f'I searched for "{query}" and you summarized the '
                         "results. I have follow-up questions about that "
                         "summary.")},
            {"role": "assistant", "content": summary},
        ]

    def _clear_ai_chat(self) -> None:
        self.ai_client.cancel()
        self._ai_chat = []
        self._ai_stream = ""
        self._ai_text.clear()
        self._set_ai_status("New chat — previous conversation forgotten.")
        self._ai_stop.setEnabled(False)
        self._ai_send.setEnabled(True)
        self._ai_input.setFocus()

    def _render_ai_chat(self) -> None:
        """Redraw the whole ask-mode transcript, including any reply currently
        streaming in."""
        if self._ai_panel is None:
            return
        blocks = []
        for msg in self._ai_chat:
            if msg["role"] == "user":
                blocks.append(f"**You:** {msg['content']}")
            else:
                blocks.append(msg["content"])
        if self._ai_stream:
            blocks.append(self._ai_stream)
        self._ai_text.setMarkdown("\n\n---\n\n".join(blocks))
        sb = self._ai_text.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _stop_ai(self) -> None:
        self.ai_client.cancel()
        # Keep a partial answer in the transcript rather than dropping it.
        if self._ai_mode == "ask" and self._ai_stream:
            self._ai_chat.append(
                {"role": "assistant", "content": self._ai_stream})
            self._ai_stream = ""
            self._render_ai_chat()
        self._set_ai_status("Stopped.")
        self._ai_stop.setEnabled(False)
        self._ai_regen.setEnabled(True)
        self._ai_send.setEnabled(True)

    def _set_ai_status(self, text: str) -> None:
        if self._ai_panel is not None:
            self._ai_status.setText(text)

    def _on_ai_chunk(self, text: str) -> None:
        if self._ai_panel is None:
            return
        if self._ai_mode == "ask":
            self._ai_stream = text
            self._render_ai_chat()
            return
        self._ai_text.setMarkdown(text)
        sb = self._ai_text.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_ai_thinking(self, thinking: bool) -> None:
        if thinking:
            self._set_ai_status("Reasoning…")
        elif self._ai_mode == "ask":
            self._set_ai_status("Answering…")
        else:
            self._set_ai_status("Writing the summary…")

    def _on_ai_finished(self, text: str) -> None:
        if self._ai_panel is None:
            return
        if self._ai_mode == "ask":
            self._ai_chat.append({
                "role": "assistant",
                "content": text or "*(the model returned an empty answer)*"})
            self._ai_stream = ""
            self._render_ai_chat()
            self._ai_input.setFocus()
        else:
            self._ai_text.setMarkdown(
                text or "*(the model returned an empty summary)*")
        self._set_ai_status(
            f"Done · {self.ai_cfg.get('model', '')} · on-device")
        self._ai_stop.setEnabled(False)
        self._ai_regen.setEnabled(True)
        self._ai_send.setEnabled(True)

    def _on_ai_failed(self, message: str) -> None:
        if self._ai_panel is None:
            return
        if self._ai_mode == "ask":
            # Drop the unanswered question so a retry doesn't double it up.
            if self._ai_chat and self._ai_chat[-1]["role"] == "user":
                self._ai_chat.pop()
            self._ai_stream = ""
            self._render_ai_chat()
            self._set_ai_status(f"Couldn't answer. {message}")
        else:
            self._set_ai_status("Summary failed.")
            self._ai_text.setMarkdown(f"**Couldn't summarize.** {message}")
        self._ai_stop.setEnabled(False)
        self._ai_regen.setEnabled(True)
        self._ai_send.setEnabled(True)

    def _set_ai_search(self, on: bool) -> None:
        self.ai_cfg["enabled"] = bool(on)
        save_ai_config(self.ai_cfg)
        if not on:
            self._close_ai_panel()
        self.statusBar().showMessage(
            f"Local AI {'on' if on else 'off'}.", 4000)
        # Turning this on is the moment the user actually wants Ollama
        # working, so this is the natural point to notice it isn't even
        # installed yet rather than let them find out from a failed request.
        if on:
            from ollama_setup import ollama_on_path
            if not ollama_on_path():
                box = QMessageBox(self)
                box.setIcon(QMessageBox.Icon.Information)
                box.setWindowTitle("Ollama not found")
                box.setTextFormat(Qt.TextFormat.PlainText)
                box.setText(
                    "Local AI is on, but Ollama doesn't seem to be "
                    "installed on this machine yet. Set it up now?")
                box.setStandardButtons(QMessageBox.StandardButton.Yes
                                       | QMessageBox.StandardButton.No)
                if box.exec() == QMessageBox.StandardButton.Yes:
                    self.show_ollama_setup()

    def show_ai_options(self) -> None:
        cfg = self.ai_cfg
        from ai_search import CONFIG_FILE
        # A non-local endpoint in the config file was overridden at load time
        # rather than honoured; say so, or the setting would look ignored.
        rejected = ("\n              ⚠ the address in the config file was not "
                    "on this machine, so it was ignored"
                    if cfg.get("endpoint_rejected") else "")
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle("Local AI options")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(
            "Local AI runs entirely on your device, against your own Ollama "
            "instance. Vodou never changes Ollama's models or settings.\n\n"
            "  • Summarize — reads the results off the local SearXNG page and "
            "sends those to Ollama.\n"
            "  • Ask — sends only what you type. Never the page you're on, "
            "its address, or your history.\n\n"
            f"Enabled:      {'yes' if cfg.get('enabled') else 'no'}\n"
            f"Model:        {cfg.get('model')}\n"
            f"Ollama URL:   {cfg.get('endpoint')}{rejected}\n"
            f"Results used: {cfg.get('max_results')}\n"
            f"Chat memory:  {cfg.get('max_turns')} messages\n"
            f"Keep-alive:   {cfg.get('keep_alive')}  "
            "(how long Ollama keeps the model in memory afterwards)\n\n"
            "Change any of these by editing:\n"
            f"{CONFIG_FILE}\n\n"
            "Tip: set \"model\" to whichever model you already keep loaded to "
            "avoid a VRAM swap.")
        box.exec()

    def show_ollama_setup(self) -> None:
        from ollama_setup_ui import OllamaSetupDialog
        dialog = OllamaSetupDialog(
            self, model=self.ai_cfg.get("model", "llama3.2:latest"))
        dialog.exec()

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
        for view in self._views:
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
        self._refresh_vault_indicator()
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
            self._refresh_vault_indicator()
            self.statusBar().showMessage(
                f"Password vault auto-locked after {VAULT_AUTOLOCK_MINUTES} "
                f"minutes of inactivity.", 6000)

    def lock_vault_now(self) -> None:
        """Manually lock the vault ("log out"), like auto-lock but on demand."""
        if not self.vault.unlocked:
            self.statusBar().showMessage("The vault is already locked.", 4000)
            return
        # Close the open vault window first, or it would sit there showing
        # entries against a now-locked vault (and its next action would throw).
        # Closing it fires _on_vault_dialog_closed, which restarts the lock
        # timer while the vault is still unlocked — so stop the timer LAST.
        if self._vault_dialog is not None:
            self._vault_dialog.close()
        self.vault.lock()
        self._vault_lock_timer.stop()
        self._refresh_vault_indicator()
        self.statusBar().showMessage("Password vault locked.", 4000)

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
        # "Log out" inside the vault window routes through the browser so the
        # lock timer stops and the toolbar indicator updates (lock_vault_now
        # closes this dialog itself).
        dialog.logout_requested.connect(self.lock_vault_now)
        dialog.open_site_requested.connect(self.open_saved_site)
        self._vault_dialog = dialog
        dialog.show()

    def open_saved_site(self, site: str) -> None:
        """Open a saved login's site in a new tab and bring the browser
        forward (the vault window is a separate, modeless window)."""
        url = to_url(site)
        if not url.isValid() or url.scheme() not in ("http", "https"):
            return
        self.add_tab(url)
        self.raise_()
        self.activateWindow()

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

    def _setup_button_pulsers(self) -> None:
        """Wire the two attention cues: the key button (a saved login is here
        to fill) and the vault button (a login is here but the vault is locked,
        so unlock it first). Both pulse in the live theme accent."""
        accent = lambda: build_palette(self._theme_name, self._mode).accent
        self._key_pulser = ButtonPulser(self.key_button, accent)
        self._vault_pulser = ButtonPulser(self.vault_button, accent)

    def _set_key_active(self, on: bool) -> None:
        if getattr(self, "_key_pulser", None) is not None:
            self._key_pulser.set_active(on)

    def _set_vault_active(self, on: bool) -> None:
        if getattr(self, "_vault_pulser", None) is not None:
            self._vault_pulser.set_active(on)

    def _refresh_vault_indicator(self) -> None:
        """Repaint the vault button so its state reads at a glance: dimmed
        (locked) vs. accent-green (unlocked), with a matching tooltip. The icon
        is set on the QAction (which the toolbar button displays); call this
        after _apply_static_icons, which would otherwise reset it to neutral.
        Called on every lock/unlock transition and on theme switches."""
        action = getattr(self, "vault_action", None)
        if action is None:
            return
        p = build_palette(self._theme_name, self._mode)
        if not self.vault.exists():
            action.setIcon(make_icon("vault", p.text))
            action.setToolTip("Open password vault (Ctrl+Shift+V)")
            return
        if self.vault.unlocked:
            action.setIcon(make_icon("vault-unlocked", p.ok))
            action.setToolTip("Vault unlocked — open it (Ctrl+Shift+V)")
            self._set_vault_active(False)   # no need to nag to unlock
        else:
            action.setIcon(make_icon("vault-locked", p.danger))
            action.setToolTip("Vault locked — click to unlock (Ctrl+Shift+V)")

    def _clear_login_cues(self) -> None:
        """Stop both attention pulses (key and vault)."""
        self._set_key_active(False)
        self._set_vault_active(False)

    def _maybe_offer_fill(self, view: WebView, ok: bool) -> None:
        """After a page loads, offer to fill if the vault can help."""
        if view is not self.current_view():
            return
        if not ok:
            self._clear_login_cues()
            return
        url = view.url()
        host = url.host().removeprefix("www.")
        if url.scheme() != "https" or not host or not self.vault.exists():
            self._clear_login_cues()
            return
        if host in self._fill_offer_dismissed:
            self._clear_login_cues()
            return

        def probed(has_password_field: bool) -> None:
            try:
                if not has_password_field or view is not self.current_view():
                    self._clear_login_cues()
                    return
            except RuntimeError:  # tab closed before the probe returned
                return
            if self.vault.unlocked:
                if not self.vault.entries_for_host(host):
                    self._clear_login_cues()
                    return
                text = (f"🔑 Vodou has a saved login for {host}. "
                        f"Autofill username and password?")
                label = "Autofill"
                # Something to fill right now — flash the key button.
                self._set_vault_active(False)
                self._set_key_active(True)
            else:
                text = (f"🔑 This page has a login form. Unlock your vault "
                        f"to autofill a saved login for {host}?")
                label = "Unlock && autofill"
                # Can't fill until the vault is unlocked — flash the vault
                # button to point the user at the step they need first.
                self._set_key_active(False)
                self._set_vault_active(True)
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
        if not host:
            return

        # A submitted login with no username (multi-step or password-only
        # pages hide the username field) is matched to the host's sole saved
        # login if there is exactly one, so a password change is offered as an
        # Update rather than saved as an empty-username duplicate.
        if self.vault.unlocked:
            username, existing = self._resolve_capture(host, username)
        else:
            existing = None

        if (host, username) in self._capture_dismissed:
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

    def _resolve_capture(self, host: str, username: str):
        """Map a captured (host, username) to the entry it belongs to.

        Returns (username, existing). On an exact username match, that entry.
        When the captured username is empty but the host has exactly one saved
        login, adopt that login's username so a password change updates it
        instead of adding a duplicate. Requires the vault unlocked.
        """
        existing = self._find_entry(host, username)
        if existing is None and not username:
            matches = self.vault.entries_for_host(host)
            if len(matches) == 1:
                index, entry = matches[0]
                return entry.username, (index, entry)
        return username, existing

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
        # Re-resolve now that the vault is unlocked (the capture may have been
        # made while locked): an empty username adopts the host's sole login.
        username, existing = self._resolve_capture(host, username)
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
            "username-only": ("Username filled — continue to the password "
                              "step and Vodou will offer to fill it."),
            "no-login-field": "No login field found on this page.",
            "no-password-field": "No password field found on this page.",
        }
        self.statusBar().showMessage(
            messages.get(result, "Fill finished."), 5000)
        # The user acted on the cue; retire the flashes (a following multi-step
        # page will re-raise one on its next load if a password field appears).
        self._clear_login_cues()


class DetachedWindow(QMainWindow):
    """A single tab torn off into its own top-level window ("Move tab to new
    window"). It reuses the very WebView — no reload, full state kept — and
    shares the parent window's QWebEngineProfile, so there is no second engine
    profile to collide on Vodou's size-capped, shredded cache directory. It
    carries a slim nav bar; its lifetime is tied to the parent (see
    BrowserWindow.closeEvent)."""

    def __init__(self, browser: "BrowserWindow", view: "WebView"):
        super().__init__()
        self.browser = browser
        self.view = view
        self._shutting_down = False
        self._returned = False
        self.setWindowTitle("Vodou — detached tab (private)")
        self.resize(1024, 720)

        tb = QToolBar("Navigation")
        tb.setMovable(False)
        self.addToolBar(tb)

        def button(text: str, tip: str, slot) -> QToolButton:
            b = QToolButton()
            b.setText(text)
            b.setToolTip(tip)
            b.setAutoRaise(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(slot)
            tb.addWidget(b)
            return b

        button("‹", "Back", view.back)
        button("›", "Forward", view.forward)
        button("⟳", "Reload",
               lambda: view.page().triggerAction(
                   QWebEnginePage.WebAction.ReloadAndBypassCache))
        self._url = QLineEdit()
        self._url.setClearButtonEnabled(True)
        self._url.returnPressed.connect(self._navigate)
        tb.addWidget(self._url)
        button("⤢", "Return this tab to the main window",
               self._return_to_main)

        self.setCentralWidget(view)     # reparents the view (state preserved)
        view.show()
        view.urlChanged.connect(self._on_url)
        view.titleChanged.connect(self._on_title)
        self._on_url(view.url())
        self._on_title(view.title())

    def _navigate(self) -> None:
        self.view.setUrl(to_url(self._url.text()))

    def _on_url(self, url: QUrl) -> None:
        self._url.setText(url.toString())
        self._url.setCursorPosition(0)

    def _on_title(self, title: str) -> None:
        self.setWindowTitle(f"{title} — Vodou (private)" if title
                            else "Vodou — detached tab (private)")

    def _return_to_main(self) -> None:
        self._returned = True
        # Drop our own signal links first, or the view keeps this window alive.
        try:
            self.view.urlChanged.disconnect(self._on_url)
            self.view.titleChanged.disconnect(self._on_title)
        except TypeError:
            pass
        view = self.takeCentralWidget()   # release before reparenting
        self.browser.reattach_detached(self, view)
        self.close()

    def close_for_shutdown(self) -> None:
        """The main window is closing: drop this tab's view with it."""
        self._shutting_down = True
        view = self.takeCentralWidget()
        if view is not None:
            view.setParent(None)
            view.deleteLater()
        self.close()

    def closeEvent(self, event) -> None:
        # User-initiated close (not a return, not app shutdown): the tab goes
        # away for good, so destroy its view and tell the parent to forget us.
        if not self._returned and not self._shutting_down:
            view = self.takeCentralWidget()
            if view is not None:
                view.setParent(None)
                view.deleteLater()
            self.browser.forget_detached(self)
        super().closeEvent(event)


def main() -> None:
    migrate_config_dir()
    # Before the first write of the run — every module below assumes the
    # directory it writes into is already private.
    secure_config_dir()
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
