"""Setup wizard: installs Ollama (if missing) and pulls a model, so Local AI
works without the user manually installing anything first.

Two independently-skippable steps:
  1. Ollama itself — checked with `shutil.which`, installed via the vendor's
     own Windows installer if missing (ollama_setup.OllamaInstaller).
  2. A model — pulled with `ollama pull` (ollama_setup.ModelPuller).

Both steps that touch the network or run an external program ask first —
the same confirm-before-acting pattern as the one-click updater in about.py.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from ollama_setup import (
    OLLAMA_DOWNLOAD_PAGE,
    ModelPuller,
    OllamaInstaller,
    is_windows,
    ollama_on_path,
)


class OllamaSetupDialog(QDialog):
    def __init__(self, parent=None, model: str = "llama3.2:latest"):
        super().__init__(parent)
        self.setWindowTitle("Set up Local AI")
        self.setMinimumWidth(460)
        self._model = model
        self._installer: OllamaInstaller | None = None
        self._puller: ModelPuller | None = None

        outer = QVBoxLayout(self)

        intro = QLabel(
            "Local AI needs Ollama running on this machine. This sets up "
            "two things:\n\n"
            "  1. Ollama itself (skipped if already installed)\n"
            f"  2. A model to run it — {model}\n\n"
            "Both run entirely on your device; the only thing fetched "
            "over the network is the official installer from ollama.com "
            "and the model itself, straight from Ollama.")
        intro.setTextFormat(Qt.TextFormat.PlainText)
        intro.setWordWrap(True)
        outer.addWidget(intro)

        self.status = QLabel("")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        self.status.setStyleSheet("color: gray;")
        outer.addWidget(self.status)

        buttons = QHBoxLayout()
        self.start_btn = QPushButton("Set up now")
        self.start_btn.clicked.connect(self._start)
        buttons.addWidget(self.start_btn)
        buttons.addStretch()
        self.close_btn = QPushButton("Close")
        self.close_btn.setDefault(True)
        self.close_btn.clicked.connect(self.accept)
        buttons.addWidget(self.close_btn)
        outer.addLayout(buttons)

    # -- step 1: Ollama itself -------------------------------------------

    def _start(self) -> None:
        self.start_btn.setEnabled(False)
        self.start_btn.setText("Setting up…")
        if ollama_on_path():
            self.status.setText("Step 1/2: Ollama is already installed. ✓")
            self._start_pull()
            return
        if not is_windows():
            self._finish(
                False,
                "Ollama isn't installed, and the automatic installer here "
                "is Windows-only. Install it yourself from "
                f"{OLLAMA_DOWNLOAD_PAGE}, then reopen this dialog to pull "
                "a model.")
            return

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Install Ollama?")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(
            "Ollama isn't installed. Vodou can download the official "
            "Windows installer from ollama.com and open it — you'll see "
            "Ollama's own installer window and agree to its terms there; "
            "nothing is installed silently.\n\n"
            "Download and open it now?")
        box.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            self.start_btn.setEnabled(True)
            self.start_btn.setText("Set up now")
            return

        self.status.setText("Step 1/2: downloading the Ollama installer…")
        self._installer = OllamaInstaller(self)
        self._installer.progress.connect(self._on_download_progress)
        self._installer.download_failed.connect(self._on_install_failed)
        self._installer.installer_launched.connect(
            self._on_installer_launched)
        self._installer.finished.connect(self._on_installer_finished)
        self._installer.start()

    def _on_download_progress(self, received: int, total: int) -> None:
        if total > 0:
            mb_r, mb_t = received / 1_048_576, total / 1_048_576
            self.status.setText(
                f"Step 1/2: downloading the Ollama installer… "
                f"{mb_r:.1f} / {mb_t:.1f} MB")
        else:
            self.status.setText(
                "Step 1/2: downloading the Ollama installer…")

    def _on_install_failed(self, message: str) -> None:
        self._finish(False, f"Ollama install: {message}")

    def _on_installer_launched(self) -> None:
        self.status.setText(
            "Step 1/2: the Ollama installer is open — finish it there, "
            "then this continues automatically…")

    def _on_installer_finished(self, ok: bool) -> None:
        if not ok:
            self._finish(
                False,
                "The Ollama installer closed, but `ollama` still isn't on "
                "PATH. It may need Vodou (or the machine) restarted to "
                "pick up the new PATH entry — reopen this dialog "
                "afterwards to pull a model.")
            return
        self._start_pull()

    # -- step 2: pull a model ---------------------------------------------

    def _start_pull(self) -> None:
        self.status.setText(
            f"Step 2/2: downloading the {self._model} model — this can "
            "take a while on the first run…")
        self._puller = ModelPuller(self)
        self._puller.line.connect(self.status.setText)
        self._puller.finished.connect(self._on_pull_finished)
        self._puller.start(self._model)

    def _on_pull_finished(self, ok: bool, last_line: str) -> None:
        if ok:
            self._finish(
                True,
                f"✅ Done — Ollama is installed and {self._model} is "
                "ready. Turn on ☰ → Settings → Local AI → Local AI "
                "(Ollama) to start using it.")
        else:
            self._finish(
                False,
                f"Model download failed: {last_line or 'unknown error'}\n\n"
                f"You can retry with:  ollama pull {self._model}")

    # -- done ---------------------------------------------------------------

    def _finish(self, ok: bool, message: str) -> None:
        self.status.setText(message)
        if ok:
            self.start_btn.hide()
        else:
            self.start_btn.setEnabled(True)
            self.start_btn.setText("Retry")
