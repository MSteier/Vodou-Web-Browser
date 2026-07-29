"""Detect and set up a local Ollama instance for Vodou's Local AI features.

ai_search.py is a pure HTTP client of Ollama — it never installs or manages
Ollama itself. This module is the one-time (or as-needed) setup path that
gets Ollama installed and a model pulled, so someone who just downloaded the
standalone Vodou release isn't left guessing why the AI panel says "Couldn't
reach Ollama."

Windows only for the automated download+install step: Ollama's installer,
distribution mechanism, and typical install location differ per platform,
and Vodou's own standalone release build is Windows-only today (see
README). On macOS/Linux this instead points at the official download page —
automating an unverified install flow there would be worse than just
linking the vendor's own instructions.

Neither the download nor the installer launch happens without the caller
asking first (see ollama_setup_ui.py) — consistent with how Vodou's own
one-click updater (about.py) confirms before running git/pip.
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

from PyQt6.QtCore import QObject, QProcess, QUrl, pyqtSignal
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest

OLLAMA_WINDOWS_INSTALLER_URL = "https://ollama.com/download/OllamaSetup.exe"
OLLAMA_DOWNLOAD_PAGE = "https://ollama.com/download"


def is_windows() -> bool:
    return sys.platform == "win32"


def ollama_on_path() -> bool:
    """True if an `ollama` executable is reachable on PATH right now.

    This doesn't confirm the background service is *running* — callers that
    need that should try an actual API call (ai_search.OllamaClient) or
    `ollama list`, both of which fail fast and gracefully on their own."""
    return shutil.which("ollama") is not None


class OllamaInstaller(QObject):
    """Downloads the official Windows Ollama installer and launches it.

    Deliberately does not pass silent-install flags: Ollama's installer
    isn't documented as supporting them, and guessing wrong would either do
    nothing or install without the user seeing what they agreed to. The
    vendor's own installer window (with its own license screen) opens
    instead, and this class just waits for it to exit before reporting
    done — showing the real installer rather than pretending to fully
    automate a step Vodou can't verify.
    """

    progress = pyqtSignal(int, int)   # bytes received, bytes total (0 if unknown)
    download_failed = pyqtSignal(str)
    installer_launched = pyqtSignal()
    finished = pyqtSignal(bool)       # True if `ollama` is on PATH afterwards

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._nam = QNetworkAccessManager(self)
        self._reply: QNetworkReply | None = None
        self._proc: QProcess | None = None
        self._tmp_path = Path(tempfile.gettempdir()) / "OllamaSetup.exe"

    def start(self) -> None:
        req = QNetworkRequest(QUrl(OLLAMA_WINDOWS_INSTALLER_URL))
        self._reply = self._nam.get(req)
        self._reply.downloadProgress.connect(self.progress)
        self._reply.finished.connect(self._on_downloaded)

    def _on_downloaded(self) -> None:
        reply, self._reply = self._reply, None
        if reply is None:
            return
        try:
            if reply.error() != QNetworkReply.NetworkError.NoError:
                self.download_failed.emit(reply.errorString())
                return
            data = bytes(reply.readAll())
            try:
                self._tmp_path.write_bytes(data)
            except OSError as exc:
                self.download_failed.emit(f"Couldn't save the installer: {exc}")
                return
        finally:
            reply.deleteLater()
        self._launch_installer()

    def _launch_installer(self) -> None:
        self._proc = QProcess(self)
        self._proc.finished.connect(self._on_installer_finished)
        self._proc.errorOccurred.connect(
            lambda _e: self.download_failed.emit(
                "Couldn't launch the installer — run it yourself: "
                f"{self._tmp_path}"))
        self._proc.start(str(self._tmp_path), [])
        self.installer_launched.emit()

    def _on_installer_finished(self, _exit_code: int, _status) -> None:
        self._proc = None
        self.finished.emit(ollama_on_path())


class ModelPuller(QObject):
    """Runs `ollama pull <model>` and streams its console output as status
    lines — the CLI, not the HTTP /api/pull endpoint, because the CLI
    already renders human-readable progress and there's no need to
    reimplement that here; ai_search.py's HTTP client is for chat, not
    downloads."""

    line = pyqtSignal(str)
    finished = pyqtSignal(bool, str)   # success, last output line

    # `ollama pull`'s progress bar is a terminal UI: cursor moves (\x1b[<n>G),
    # line clears (\x1b[K), and a braille spinner glyph, all meant for a real
    # terminal. Strip the escape codes and spinner so the status label shows
    # plain text instead of that raw control-code noise.
    _ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
    _SPINNER = re.compile(r"[⠀-⣿]")

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._proc: QProcess | None = None
        self._output = ""

    def start(self, model: str) -> None:
        self._output = ""
        self._proc = QProcess(self)
        self._proc.setProcessChannelMode(
            QProcess.ProcessChannelMode.MergedChannels)
        self._proc.readyReadStandardOutput.connect(self._on_output)
        self._proc.finished.connect(self._on_finished)
        self._proc.errorOccurred.connect(
            lambda _e: self.finished.emit(
                False, "Couldn't launch `ollama` — is it installed?"))
        self._proc.start("ollama", ["pull", model])

    @classmethod
    def _clean(cls, text: str) -> str:
        return cls._SPINNER.sub("", cls._ANSI.sub("", text)).strip()

    def _on_output(self) -> None:
        if self._proc is None:
            return
        chunk = bytes(self._proc.readAllStandardOutput()).decode(
            "utf-8", "replace")
        self._output += chunk
        # `ollama pull` redraws its progress bar with carriage returns, not
        # newlines — split on either so the dialog shows the latest line
        # instead of one long \r-joined blob.
        for piece in chunk.replace("\r", "\n").split("\n"):
            piece = self._clean(piece)
            if piece:
                self.line.emit(piece)

    def _on_finished(self, exit_code: int, _status) -> None:
        self._proc = None
        last = ""
        for piece in self._output.replace("\r", "\n").splitlines():
            piece = self._clean(piece)
            if piece:
                last = piece
        self.finished.emit(exit_code == 0, last)
