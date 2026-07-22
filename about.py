"""About dialog: version info, update check, and a one-click updater.

Vodou has three independently updatable parts:
  * the app itself — this git checkout; updated with `git pull`
  * the engine — the Chromium/Qt build bundled in the PyQt6-WebEngine
    package; updated with `pip install --upgrade`
  * the malicious-site definitions — the local Safe Browsing host lists,
    refreshed straight from their public feeds (see safebrowsing.py)

UpdateChecker discovers newer versions of the first two (GitHub raw for the
app's APP_VERSION, PyPI's JSON API for the engine) without blocking the UI, and
AboutDialog's single button updates all three in sequence. Both subprocesses run
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
    QTimer,
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

APP_VERSION = "1.14.2"
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


def _read_local_app_version() -> str:
    """APP_VERSION as it stands in about.py *on disk*. After a git pull this is
    the newly pulled value, while the APP_VERSION constant above is still the
    version the running process started with. Empty string when unreadable."""
    try:
        text = (_REPO_DIR / "about.py").read_text(encoding="utf-8")
    except OSError:
        return ""
    match = re.search(r'APP_VERSION\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else ""


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

# How long the definitions step waits for the feeds before giving up on them.
# SafeBrowsing.refresh() is fire-and-forget and stays silent when every feed
# fails, so the wait must be bounded or the summary would never appear.
_DEFINITIONS_TIMEOUT_MS = 60_000


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

    def __init__(self, parent=None, safe_browsing=None):
        super().__init__(parent)
        self.setWindowTitle("About Vodou")
        self.setMinimumWidth(420)
        self._proc: QProcess | None = None
        self._output = ""
        # The live SafeBrowsing instance, so the update run can refresh the
        # malicious-site definitions too. None when the caller has none, in
        # which case that step is simply skipped.
        self._safe_browsing = safe_browsing
        self._defs_timer: QTimer | None = None
        self._defs_done = True
        self._defs_before = 0

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
        rows.setStyleSheet("font-family: Consolas, 'JetBrains Mono', "
                           "'Ubuntu Mono', 'DejaVu Sans Mono', monospace; "
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
            "One click updates every part: pulls the latest Vodou from "
            "GitHub, upgrades the bundled Chromium engine and Qt toolkit via "
            "pip, then re-downloads the malicious-site definitions")
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
            "This updates every part of the browser in one go:\n\n"
            "1. Vodou itself — pulls the latest version from GitHub\n"
            "2. The engine — upgrades the bundled Chromium/Qt via pip\n"
            "3. Malicious-site definitions — re-downloads the phishing and "
            "malware lists\n\n"
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
        # (line, is_already_current) — the flag lets _finish drop "nothing to
        # do here" notes once some other part did update.
        self._results: list[tuple[str, bool]] = []
        # Real flags, so "was something applied?" never depends on matching the
        # wording of a status string.
        self._app_updated = False
        self._engine_updated = False
        # Definitions are data, not code: they count as "something updated"
        # for the wording, but they never call for a restart.
        self._defs_updated = False
        # Commit the running process started on — compared against HEAD after
        # the pull to tell an actual update apart from "already current".
        self._git_old_head = _git_head()
        self._start_git()

    def _note(self, text: str) -> None:
        """Record a summary line about something that happened."""
        self._results.append((text, False))

    def _note_already_current(self, text: str) -> None:
        """Record a 'this part needed nothing' line. Shown only when no part
        updated at all — after a real update, telling the user they already
        have the current version reads as a contradiction of the headline."""
        self._results.append((text, True))

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
            self._note(
                "Vodou app: skipped — this copy is not a git checkout. "
                f"Get updates from {REPO_URL}")
            self._start_pip()
            return
        self.status.setText("Step 1/3: updating Vodou from GitHub…")
        # --ff-only so a locally modified checkout is never merged or
        # rebased behind the user's back — it fails loudly instead.
        self._start_proc(self._git_finished, self._git_error,
                         "git", ["pull", "--ff-only"], str(_REPO_DIR))

    def _git_error(self, _error) -> None:
        if self._proc is None:
            return
        self._proc = None
        self._note(
            "Vodou app: could not run git — update manually from "
            f"{REPO_URL}")
        self._start_pip()

    def _git_finished(self, exit_code: int, _status) -> None:
        self._read_output()
        out, self._proc = self._output, None
        if exit_code != 0:
            tail = (out.strip().splitlines() or ["unknown git error"])[-1]
            self._note(f"Vodou app: update FAILED — {tail}")
            self._start_pip()
            return
        new_head = _git_head()
        already = "Already up to date" in out or (
            self._git_old_head and new_head == self._git_old_head)
        if already:
            self._note_already_current(
                "Vodou app: already the current version.")
            self._start_pip()
            return
        # A real update landed. Report the version change, then fetch the list
        # of commits that came in so the summary can say what actually changed.
        self._app_updated = True
        new_version = _read_local_app_version()
        if new_version and new_version != APP_VERSION:
            self._note(
                f"Vodou app: UPDATED {APP_VERSION} → {new_version} "
                "(restart to apply).")
        else:
            self._note("Vodou app: UPDATED (restart to apply).")
        if self._git_old_head and new_head:
            self._start_git_log(self._git_old_head, new_head)
        else:
            self._start_pip()

    # step 1b: list the commits the pull brought in ("what changed")
    def _start_git_log(self, old_head: str, new_head: str) -> None:
        self.status.setText("Reading what changed…")
        self._start_proc(
            self._git_log_finished, self._git_log_error, "git",
            ["log", "--no-merges", "--pretty=format:%s",
             f"{old_head}..{new_head}"], str(_REPO_DIR))

    def _git_log_error(self, _error) -> None:
        if self._proc is None:
            return
        self._proc = None  # a missing changelog must not stop the engine step
        self._start_pip()

    def _git_log_finished(self, _exit_code: int, _status) -> None:
        self._read_output()
        out, self._proc = self._output, None
        subjects = [s.strip() for s in out.splitlines() if s.strip()]
        if subjects:
            shown = subjects[:8]
            lines = "\n".join(f"   • {s}" for s in shown)
            extra = len(subjects) - len(shown)
            if extra > 0:
                lines += f"\n   • …and {extra} more change(s)"
            self._note("What changed:\n" + lines)
        self._start_pip()

    # step 2: the engine
    def _start_pip(self) -> None:
        self.status.setText("Step 2/3: checking the Chromium engine on PyPI — "
                            "this can take a few minutes…")
        self._start_proc(self._pip_finished, self._pip_error,
                         sys.executable,
                         ["-m", "pip", "install", "--upgrade",
                          *_ENGINE_PACKAGES])

    def _pip_error(self, _error) -> None:
        if self._proc is None:
            return
        self._proc = None
        self._note(
            "Engine: could not launch pip — update manually with:  "
            "python -m pip install --upgrade " + " ".join(_ENGINE_PACKAGES))
        self._start_definitions()

    @staticmethod
    def _parse_pip_installed(out: str) -> str:
        """The engine/toolkit packages pip reports it actually installed, e.g.
        'PyQt6-6.9.0, PyQt6-WebEngine-6.9.0'. Empty when nothing was upgraded."""
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Successfully installed"):
                tokens = line[len("Successfully installed"):].split()
                ours = [t for t in tokens if any(
                    t.lower().startswith(pkg.lower() + "-")
                    for pkg in _ENGINE_PACKAGES)]
                return ", ".join(ours or tokens)
        return ""

    def _pip_finished(self, exit_code: int, _status) -> None:
        self._read_output()
        out, self._proc = self._output, None
        if exit_code != 0:
            tail = "\n".join(out.strip().splitlines()[-4:]) or "(no output)"
            hint = ""
            if "CERTIFICATE_VERIFY_FAILED" in out or "SSLError" in out:
                hint = (" This looks like your antivirus intercepting TLS; "
                        "installing 'pip-system-certs' fixes it.")
            self._note(
                f"Engine: update FAILED (exit code {exit_code}).{hint}\n"
                f"{tail}")
            self._start_definitions()
            return
        installed = self._parse_pip_installed(out)
        if installed:
            self._engine_updated = True
            self._note(f"Engine: UPDATED to {installed} (restart to apply).")
        else:
            self._note_already_current("Engine: already the current version.")
        self._start_definitions()

    # step 3: the malicious-site definitions
    def _start_definitions(self) -> None:
        """Re-download the Safe Browsing host lists as part of the run.

        These go stale far faster than the app or the engine — phishing
        domains live hours — so a user who updates everything else and is
        still checking against week-old lists has the weakest part left
        untouched.
        """
        sb = self._safe_browsing
        if sb is None:
            self._finish()
            return
        if not sb.enabled:
            self._note("Malicious-site definitions: skipped — Safe Browsing "
                       "is turned off.")
            self._finish()
            return
        self.status.setText(
            "Step 3/3: refreshing the malicious-site definitions…")
        self._defs_before = sb.count()
        self._defs_done = False
        sb.updated.connect(self._on_definitions_updated)
        self._defs_timer = QTimer(self)
        self._defs_timer.setSingleShot(True)
        self._defs_timer.timeout.connect(
            lambda: self._definitions_done(False))
        self._defs_timer.start(_DEFINITIONS_TIMEOUT_MS)
        sb.refresh()

    def _on_definitions_updated(self, _count: int) -> None:
        self._definitions_done(True)

    def _definitions_done(self, refreshed: bool) -> None:
        # The signal and the timeout race; whichever lands first wins.
        if self._defs_done:
            return
        self._defs_done = True
        if self._defs_timer is not None:
            self._defs_timer.stop()
            self._defs_timer = None
        sb = self._safe_browsing
        try:
            sb.updated.disconnect(self._on_definitions_updated)
        except TypeError:
            pass
        if refreshed:
            now = sb.count()
            delta = now - self._defs_before
            if delta:
                self._defs_updated = True
                self._note(f"Malicious-site definitions: UPDATED — "
                           f"{now:,} sites known ({delta:+,}).")
            else:
                self._note_already_current(
                    f"Malicious-site definitions: already current — "
                    f"{now:,} sites known.")
        else:
            # Deliberately worded to avoid the FAILED / "could not" markers
            # _finish scans for. safebrowsing.py's whole design is that a bad
            # feed keeps the existing cache rather than dropping protection,
            # so a transient feed outage must not turn a clean app + engine
            # update into "Update failed".
            self._note(
                "Malicious-site definitions: not refreshed this time — the "
                f"lists were unreachable. The {self._defs_before:,} sites "
                "already downloaded stay in effect, and Vodou retries every "
                "12 hours.")
        self._finish()

    def _finish(self) -> None:
        self.update_btn.setEnabled(True)
        self.update_btn.setText("Update Vodou && engine…")
        self.status.hide()
        # Only new code needs a restart; refreshed definitions take effect at
        # once, so they must not raise the restart prompt.
        restart_needed = self._app_updated or self._engine_updated
        updated = restart_needed or self._defs_updated
        # Once anything did update, drop the "already the current version"
        # notes — they contradict the headline the user is reading.
        lines = [text for text, is_current in self._results
                 if not (updated and is_current)]
        summary = "\n\n".join(lines)
        trouble = any(("FAILED" in text) or ("could not" in text)
                      for text, _ in self._results)

        # Which parts were actually applied, for a plain-language verdict.
        # Each carries whether it takes a plural verb on its own, so a
        # definitions-only run doesn't read "the definitions was updated".
        parts: list[tuple[str, bool]] = []
        if self._app_updated:
            parts.append(("Vodou", False))
        if self._engine_updated:
            parts.append(("the engine", False))
        if self._defs_updated:
            parts.append(("the malicious-site definitions", True))
        labels = [label for label, _ in parts]
        what = (" and ".join(labels) if len(labels) < 3
                else ", ".join(labels[:-1]) + " and " + labels[-1])
        verb = "were" if len(parts) > 1 or (parts and parts[0][1]) else "was"
        restart = ("\n\nClose and reopen Vodou to start using the new version."
                   if restart_needed else "")

        if updated and trouble:
            icon, title = QMessageBox.Icon.Warning, "Update partly applied"
            text = (f"Some parts updated, but not everything succeeded — "
                    f"{what} {verb} updated.\n\n{summary}{restart}")
        elif trouble:
            icon, title = QMessageBox.Icon.Warning, "Update failed"
            text = (f"The update did not complete and nothing was changed.\n\n"
                    f"{summary}")
        elif updated:
            icon, title = (QMessageBox.Icon.Information,
                           "Update applied successfully")
            text = (f"Update applied successfully — {what} {verb} updated.\n\n"
                    f"{summary}{restart}")
        else:
            icon, title = QMessageBox.Icon.Information, "No update needed"
            text = ("You are already running the most current version of "
                    f"Vodou and its engine — nothing needed updating.\n\n"
                    f"{summary}")
        box = QMessageBox(self)
        box.setIcon(icon)
        box.setWindowTitle(title)
        box.setText(text)
        # The summary quotes raw git/pip output (network-derived); never
        # let QMessageBox's rich-text auto-detection interpret it.
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.exec()
        # Deliberately restart_needed, not updated: the footer tag is about
        # the running code, which a definitions refresh does not change.
        self.update_finished.emit(restart_needed, trouble)
