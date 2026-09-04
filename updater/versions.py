"""Stage 1 -- discover what is actually installed *in the running process*.

The requirements are explicit that the package version and the underlying
Qt/WebEngine runtime version must not be assumed identical, so every number
here comes from the most authoritative source available:

    PyQt6 binding      PyQt6.QtCore.PYQT_VERSION_STR
    Qt (headers)       PyQt6.QtCore.QT_VERSION_STR
    Qt WebEngine       PyQt6.QtWebEngineCore.qWebEngineVersion()
    Chromium           PyQt6.QtWebEngineCore.qWebEngineChromiumVersion()
    wheel versions     importlib.metadata.version(<dist name>)

``verify_installation()`` is the post-install / post-rollback gate: it starts a
*fresh* interpreter, imports the whole Qt WebEngine stack, and reports the
versions it sees. If that subprocess can't import the stack, the installation
is broken and the caller rolls back.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from importlib import metadata
from pathlib import Path

from .models import CurrentVersions

# Duplicated from about.py on purpose: about.py explains why these read .git
# files directly instead of shelling out to git (works under pythonw with no
# console flash, and when git isn't installed). Keeping a 12-line copy here
# lets this package stay import-light -- it must not drag in QtWidgets.
_REPO_DIR = Path(__file__).resolve().parent.parent


def _git_head() -> str:
    git = _REPO_DIR / ".git"
    try:
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref: "):
            ref = head[5:]
            ref_file = git.joinpath(*ref.split("/"))
            if ref_file.exists():
                head = ref_file.read_text(encoding="utf-8").strip()
            else:
                head = ""
                for line in (git / "packed-refs").read_text(
                        encoding="utf-8").splitlines():
                    if line.endswith(" " + ref):
                        head = line.split(" ", 1)[0]
                        break
    except OSError:
        return ""
    head = head[:7]
    return head if all(c in "0123456789abcdef" for c in head) else ""


def _git_branch() -> str:
    try:
        head = (_REPO_DIR / ".git" / "HEAD").read_text(
            encoding="utf-8").strip()
    except OSError:
        return ""
    prefix = "ref: refs/heads/"
    return head[len(prefix):] if head.startswith(prefix) else ""


def _read_app_version() -> str:
    """APP_VERSION straight from about.py's source, by regex -- importing
    about.py would pull in QtWidgets and the whole UI layer."""
    try:
        text = (_REPO_DIR / "about.py").read_text(encoding="utf-8")
    except OSError:
        return "unknown"
    import re
    m = re.search(r'APP_VERSION\s*=\s*"([^"]+)"', text)
    return m.group(1) if m else "unknown"


def _dist_version(name: str) -> str:
    try:
        return metadata.version(name)
    except Exception:
        return "unknown"


def _is_admin() -> bool:
    """Best-effort 'are we elevated'. Only ever used to *warn* -- the updater
    works fine as a normal user when site-packages is user-writable (the
    common case for a per-user Python), and refuses cleanly when it isn't."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def _site_packages_dir() -> str:
    try:
        import PyQt6
        # PyQt6/__init__.py lives directly in site-packages/PyQt6.
        return str(Path(PyQt6.__path__[0]).parent)
    except Exception:
        # Fall back to the first entry that looks like a site dir.
        for p in sys.path:
            if p.endswith(("site-packages", "dist-packages")):
                return p
    return ""


def get_current_versions() -> CurrentVersions:
    cv = CurrentVersions()

    cv.vodou_version = _read_app_version()
    cv.git_commit = _git_head()
    cv.git_branch = _git_branch()
    cv.vodou_display = cv.vodou_version + (
        f" ({cv.git_commit})" if cv.git_commit else "")

    vi = sys.version_info
    cv.python = f"{vi.major}.{vi.minor}.{vi.micro}"
    cv.python_tuple = (vi.major, vi.minor, vi.micro)
    cv.python_exe = sys.executable or ""
    # PyInstaller's bootloader sets both; a plain venv only moves sys.prefix.
    cv.in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)

    try:
        from PyQt6.QtCore import PYQT_VERSION_STR, QT_VERSION_STR
        cv.pyqt6_binding = PYQT_VERSION_STR
        cv.qt = QT_VERSION_STR
    except Exception:
        pass

    cv.pyqt6_wheel = _dist_version("PyQt6")
    cv.pyqt6_sip = _dist_version("PyQt6-sip")
    cv.pyqt6_webengine_wheel = _dist_version("PyQt6-WebEngine")
    cv.pyqt6_qt6 = _dist_version("PyQt6-Qt6")
    cv.pyqt6_webengine_qt6 = _dist_version("PyQt6-WebEngine-Qt6")

    try:
        from PyQt6.QtWebEngineCore import (
            qWebEngineChromiumVersion,
            qWebEngineVersion,
        )
        cv.qt_webengine = qWebEngineVersion()
        cv.chromium = qWebEngineChromiumVersion()
    except Exception:
        pass

    cv.frozen = bool(getattr(sys, "frozen", False))
    cv.site_packages = _site_packages_dir()
    cv.site_packages_writable = bool(
        cv.site_packages and os.access(cv.site_packages, os.W_OK))
    cv.is_admin = _is_admin()
    return cv


# A self-contained probe run in a *fresh* interpreter. It must import the exact
# modules Vodou needs at runtime -- if any of these fail after an install, the
# stack is broken and the caller rolls back.
_PROBE = r"""
import json, sys
try:
    from PyQt6.QtCore import QT_VERSION_STR, PYQT_VERSION_STR
    from PyQt6.QtWebEngineCore import (
        qWebEngineVersion, qWebEngineChromiumVersion)
    import PyQt6.QtWebEngineWidgets  # noqa: F401  -- must import cleanly
    from importlib import metadata
    out = {
        "ok": True,
        "qt": QT_VERSION_STR,
        "pyqt6": PYQT_VERSION_STR,
        "webengine": qWebEngineVersion(),
        "chromium": qWebEngineChromiumVersion(),
        "pyqt6_wheel": metadata.version("PyQt6"),
        "webengine_wheel": metadata.version("PyQt6-WebEngine"),
    }
except Exception as exc:  # noqa: BLE001 -- any failure means "broken"
    out = {"ok": False, "error": repr(exc)}
print("VODOU_PROBE " + json.dumps(out))
"""


class InstallationBroken(RuntimeError):
    """verify_installation() could not import the Qt WebEngine stack."""


def verify_installation(python_exe: str | None = None,
                        *, expect_minor: str | None = None,
                        timeout: int = 120) -> dict:
    """Import the whole stack in a fresh interpreter and return its versions.

    Raises :class:`InstallationBroken` if the import fails or (when
    *expect_minor* is given, e.g. "6.11") the running Qt WebEngine is not on
    that minor.
    """
    python_exe = python_exe or sys.executable
    env = dict(os.environ)
    # No display on a headless box / during an unattended apply.
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        proc = subprocess.run(
            [python_exe, "-c", _PROBE],
            capture_output=True, text=True, timeout=timeout, env=env,
            cwd=str(_REPO_DIR))
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallationBroken(f"could not run probe: {exc}") from exc

    line = ""
    for ln in proc.stdout.splitlines():
        if ln.startswith("VODOU_PROBE "):
            line = ln[len("VODOU_PROBE "):]
            break
    if not line:
        raise InstallationBroken(
            "probe produced no result "
            f"(exit {proc.returncode}): {proc.stderr.strip()[:400]}")
    try:
        data = json.loads(line)
    except ValueError as exc:
        raise InstallationBroken(f"probe output unreadable: {exc}") from exc
    if not data.get("ok"):
        raise InstallationBroken(
            f"Qt WebEngine stack failed to import: {data.get('error')}")

    if expect_minor:
        from .models import minor_of
        got = minor_of(data.get("webengine", ""))
        if got != expect_minor:
            raise InstallationBroken(
                f"expected Qt WebEngine {expect_minor}.x after install, "
                f"but the stack reports {data.get('webengine')!r}")
    return data


def platform_summary() -> dict:
    return {
        "os": platform.platform(),
        "machine": platform.machine(),
        "arch": platform.architecture()[0],
        "python_impl": platform.python_implementation(),
    }
