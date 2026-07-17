"""About dialog: version info, update check, and a one-click updater.

Vodou has two independently updatable parts:
  * the app itself — this git checkout; updated with `git pull`
  * the engine — the Chromium/Qt build bundled in the PyQt6-WebEngine
    package; updated with `pip install --upgrade`

UpdateChecker discovers newer versions of either (GitHub raw for the app's
APP_VERSION, PyPI's JSON API for the engine) without blocking the UI, and
AboutDialog's single button updates both in sequence. Both subprocesses run
through QProcess so the UI stays responsive.
"""

from __future__ import annotations

import json
import re
import sys
from importlib import metadata
from pathlib import Path

from PyQt6.QtCore import (
    PYQT_VERSION_STR,
    QT_VERSION_STR,
    QObject,
    QProcess,
    QSize,
    Qt,
    QUrl,
    pyqtSignal,
)
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from theme import make_app_icon

APP_VERSION = "1.7.0"
REPO_URL = "https://github.com/MSteier/Vodou-Web-Browser"

_REPO_DIR = Path(__file__).resolve().parent
_RAW_ABOUT_URL = ("https://raw.githubusercontent.com/MSteier/"
                  "Vodou-Web-Browser/master/about.py")
_PYPI_JSON_URL = "https://pypi.org/pypi/PyQt6-WebEngine/json"


def _git_head() -> str:
    """Short hash of the checked-out commit, read straight from .git files
    (no git subprocess — works under pythonw without a console flash, and
    even when git isn't installed). Empty string when unavailable."""
    git = _REPO_DIR / ".git"
    try:
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref: "):
            ref = head[5:]
            ref_file = git.joinpath(*ref.split("/"))
            if ref_file.exists():
                head = ref_file.read_text(encoding="utf-8").strip()
            else:  # ref may live in packed-refs instead
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


GIT_COMMIT = _git_head()
# Version as shown to the user, e.g. "1.4.0 (28fae28)" — the commit hash pins
# the exact code an issue report is about.
VERSION_DISPLAY = APP_VERSION + (f" ({GIT_COMMIT})" if GIT_COMMIT else "")


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for piece in version.split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def is_newer(remote: str, local: str) -> bool:
    return _version_tuple(remote) > _version_tuple(local)


class UpdateChecker(QObject):
    """Async check for newer versions of the app (GitHub) and engine (PyPI).

    Emits finished(vodou, engine) where each is the newer version string or
    None. Both requests are plain anonymous HTTPS GETs of public files — no
    identifiers are sent, and any network failure is silently treated as
    "no update".
    """

    finished = pyqtSignal(object, object)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._nam = QNetworkAccessManager(self)
        self._vodou: str | None = None
        self._engine: str | None = None
        self._pending = 0

    def start(self) -> None:
        for url, handler in ((_RAW_ABOUT_URL, self._parse_vodou),
                             (_PYPI_JSON_URL, self._parse_engine)):
            reply = self._nam.get(QNetworkRequest(QUrl(url)))
            self._pending += 1
            reply.finished.connect(
                lambda r=reply, h=handler: self._on_reply(r, h))

    def _on_reply(self, reply, handler) -> None:
        try:
            if reply.error() == QNetworkReply.NetworkError.NoError:
                handler(bytes(reply.readAll()).decode("utf-8", "replace"))
        except Exception:
            pass  # a failed check must never disturb the browser
        finally:
            reply.deleteLater()
            self._pending -= 1
            if self._pending == 0:
                self.finished.emit(self._vodou, self._engine)

    def _parse_vodou(self, text: str) -> None:
        match = re.search(r'APP_VERSION\s*=\s*"([^"]+)"', text)
        if match and is_newer(match.group(1), APP_VERSION):
            self._vodou = match.group(1)

    def _parse_engine(self, text: str) -> None:
        latest = json.loads(text)["info"]["version"]
        installed = metadata.version("PyQt6-WebEngine")
        if is_newer(latest, installed):
            self._engine = latest

# Packages that carry the engine + toolkit. Upgrading PyQt6-WebEngine pulls the
# matching Qt/Chromium binaries; PyQt6 keeps the widget layer in step.
_ENGINE_PACKAGES = ["PyQt6", "PyQt6-WebEngine"]


def engine_versions() -> dict[str, str]:
    """Best-effort version strings for the About screen."""
    py = f"{sys.version_info.major}.{sys.version_info.minor}." \
         f"{sys.version_info.micro}"
    info = {
        "Vodou": VERSION_DISPLAY,
        "Chromium engine": "unknown",
        "Qt WebEngine": "unknown",
        "Qt": QT_VERSION_STR,
        "PyQt6": PYQT_VERSION_STR,
        "Python": py,
    }
    try:
        from PyQt6.QtWebEngineCore import (
            qWebEngineChromiumVersion,
            qWebEngineVersion,
        )
        info["Chromium engine"] = qWebEngineChromiumVersion()
        info["Qt WebEngine"] = qWebEngineVersion()
    except Exception:
        pass
    return info


class AboutDialog(QDialog):
    # (app_or_engine_updated, had_problems) — lets the main window update
    # its footer version tag after a one-click update run.
    update_finished = pyqtSignal(bool, bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About Vodou")
        self.setMinimumWidth(420)
        self._proc: QProcess | None = None
        self._output = ""

        outer = QVBoxLayout(self)

        header = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(make_app_icon().pixmap(QSize(72, 72)))
        header.addWidget(icon)

        title_box = QVBoxLayout()
        name = QLabel("Vodou")
        name.setStyleSheet("font-size: 22pt; font-weight: 700;")
        company = QLabel("by Mist Technologies")
        company.setTextFormat(Qt.TextFormat.PlainText)
        company.setStyleSheet("font-size: 11pt; font-weight: 600;")
        tagline = QLabel("A privacy-first browser with a built-in vault.")
        tagline.setTextFormat(Qt.TextFormat.PlainText)
        tagline.setStyleSheet("color: gray;")
        credit = QLabel("Co-authored by Claude Fable 5")
        credit.setTextFormat(Qt.TextFormat.PlainText)
        credit.setStyleSheet("color: gray;")
        title_box.addWidget(name)
        title_box.addWidget(company)
        title_box.addWidget(tagline)
        title_box.addWidget(credit)
        header.addLayout(title_box)
        header.addStretch()
        outer.addLayout(header)

        versions = engine_versions()
        rows = QLabel("\n".join(f"{k}:  {v}" for k, v in versions.items()))
        rows.setTextFormat(Qt.TextFormat.PlainText)
        rows.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        rows.setStyleSheet("font-family: 'Consolas', monospace; "
                           "padding: 12px 4px;")
        outer.addWidget(rows)

        self.status = QLabel("")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setStyleSheet("color: gray;")
        self.status.setWordWrap(True)
        self.status.hide()
        outer.addWidget(self.status)

        buttons = QHBoxLayout()
        self.update_btn = QPushButton("Update Vodou && engine…")
        self.update_btn.setToolTip(
            "One click updates both parts: pulls the latest Vodou from "
            "GitHub, then upgrades the bundled Chromium engine and Qt "
            "toolkit via pip")
        self.update_btn.clicked.connect(self._update_all)
        buttons.addWidget(self.update_btn)
        buttons.addStretch()
        self.close_btn = QPushButton("Close")
        self.close_btn.setDefault(True)
        self.close_btn.clicked.connect(self.accept)
        buttons.addWidget(self.close_btn)
        outer.addLayout(buttons)

    # -- one-click update: Vodou (git pull), then engine (pip upgrade) ------

    def _update_all(self) -> None:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Update Vodou & engine")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(
            "This updates both parts of the browser in one go:\n\n"
            "1. Vodou itself — pulls the latest version from GitHub\n"
            "2. The engine — upgrades the bundled Chromium/Qt via pip\n\n"
            "An engine update can download a few hundred MB. Vodou stays "
            "usable while it runs; you'll get a summary when it finishes.\n\n"
            "Update now?")
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return

        self.update_btn.setEnabled(False)
        self.update_btn.setText("Updating…")
        self.status.show()
        self._results: list[str] = []
        self._start_git()

    def _start_proc(self, on_finished, on_error, program: str,
                    args: list[str], workdir: str | None = None) -> None:
        self._output = ""
        self._proc = QProcess(self)
        if workdir:
            self._proc.setWorkingDirectory(workdir)
        self._proc.setProcessChannelMode(
            QProcess.ProcessChannelMode.MergedChannels)
        self._proc.readyReadStandardOutput.connect(self._read_output)
        self._proc.finished.connect(on_finished)
        self._proc.errorOccurred.connect(on_error)
        self._proc.start(program, args)

    def _read_output(self) -> None:
        if self._proc is not None:
            chunk = bytes(self._proc.readAllStandardOutput()).decode(
                "utf-8", "replace")
            self._output += chunk

    # step 1: the app itself
    def _start_git(self) -> None:
        if not (_REPO_DIR / ".git").exists():
            self._results.append(
                "Vodou app: skipped — this copy is not a git checkout. "
                f"Get updates from {REPO_URL}")
            self._start_pip()
            return
        self.status.setText("Step 1/2: updating Vodou from GitHub…")
        # --ff-only so a locally modified checkout is never merged or
        # rebased behind the user's back — it fails loudly instead.
        self._start_proc(self._git_finished, self._git_error,
                         "git", ["pull", "--ff-only"], str(_REPO_DIR))

    def _git_error(self, _error) -> None:
        if self._proc is None:
            return
        self._proc = None
        self._results.append(
            "Vodou app: could not run git — update manually from "
            f"{REPO_URL}")
        self._start_pip()

    def _git_finished(self, exit_code: int, _status) -> None:
        self._read_output()
        out, self._proc = self._output, None
        if exit_code != 0:
            tail = (out.strip().splitlines() or ["unknown git error"])[-1]
            self._results.append(f"Vodou app: update failed — {tail}")
        elif "Already up to date" in out:
            self._results.append("Vodou app: already the current version.")
        else:
            self._results.append("Vodou app: updated — restart to apply.")
        self._start_pip()

    # step 2: the engine
    def _start_pip(self) -> None:
        self.status.setText("Step 2/2: checking the Chromium engine on PyPI — "
                            "this can take a few minutes…")
        self._start_proc(self._pip_finished, self._pip_error,
                         sys.executable,
                         ["-m", "pip", "install", "--upgrade",
                          *_ENGINE_PACKAGES])

    def _pip_error(self, _error) -> None:
        if self._proc is None:
            return
        self._proc = None
        self._results.append(
            "Engine: could not launch pip — update manually with:  "
            "python -m pip install --upgrade " + " ".join(_ENGINE_PACKAGES))
        self._finish()

    def _pip_finished(self, exit_code: int, _status) -> None:
        self._read_output()
        out, self._proc = self._output, None
        if exit_code != 0:
            tail = "\n".join(out.strip().splitlines()[-4:]) or "(no output)"
            hint = ""
            if "CERTIFICATE_VERIFY_FAILED" in out or "SSLError" in out:
                hint = (" This looks like your antivirus intercepting TLS; "
                        "installing 'pip-system-certs' fixes it.")
            self._results.append(
                f"Engine: update failed (exit code {exit_code}).{hint}\n"
                f"{tail}")
        elif "Successfully installed" in out:
            self._results.append("Engine: updated — restart to apply.")
        else:
            self._results.append("Engine: already the current version.")
        self._finish()

    def _finish(self) -> None:
        self.update_btn.setEnabled(True)
        self.update_btn.setText("Update Vodou && engine…")
        self.status.hide()
        summary = "\n\n".join(self._results)
        updated = any("restart to apply" in r for r in self._results)
        trouble = any("failed" in r or "could not" in r
                      for r in self._results)
        if trouble:
            icon, title, text = (QMessageBox.Icon.Warning,
                                 "Update finished with problems", summary)
        elif updated:
            icon, title, text = (
                QMessageBox.Icon.Information, "Update completed",
                f"Update completed.\n\n{summary}\n\n"
                f"Close and reopen Vodou to start using the new version.")
        else:
            icon, title, text = (
                QMessageBox.Icon.Information, "No update needed",
                "You are using the most current version of the "
                f"application.\n\n{summary}")
        box = QMessageBox(self)
        box.setIcon(icon)
        box.setWindowTitle(title)
        box.setText(text)
        # The summary quotes raw git/pip output (network-derived); never
        # let QMessageBox's rich-text auto-detection interpret it.
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.exec()
        self.update_finished.emit(updated, trouble)
