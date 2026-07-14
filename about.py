"""About dialog: version info plus an in-place updater for the browser engine.

The rendering engine ("the chrome parts") is the Chromium build bundled inside
the PyQt6-WebEngine package, so updating it means upgrading that package with
pip. The upgrade runs through QProcess so the UI stays responsive and we can
read pip's output to tell whether anything actually changed:
  * pip printed "Successfully installed …"  -> an update was applied
  * pip only found requirements already satisfied -> already current
"""

from __future__ import annotations

import sys

from PyQt6.QtCore import PYQT_VERSION_STR, QT_VERSION_STR, QProcess, QSize, Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from theme import make_app_icon

APP_VERSION = "1.0.0"

# Packages that carry the engine + toolkit. Upgrading PyQt6-WebEngine pulls the
# matching Qt/Chromium binaries; PyQt6 keeps the widget layer in step.
_ENGINE_PACKAGES = ["PyQt6", "PyQt6-WebEngine"]


def engine_versions() -> dict[str, str]:
    """Best-effort version strings for the About screen."""
    py = f"{sys.version_info.major}.{sys.version_info.minor}." \
         f"{sys.version_info.micro}"
    info = {
        "Vodou": APP_VERSION,
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
        tagline = QLabel("A privacy-first browser with a built-in vault.")
        tagline.setTextFormat(Qt.TextFormat.PlainText)
        tagline.setStyleSheet("color: gray;")
        title_box.addWidget(name)
        title_box.addWidget(tagline)
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
        self.update_btn = QPushButton("Update browser engine…")
        self.update_btn.setToolTip(
            "Upgrade the bundled Chromium engine and Qt toolkit via pip")
        self.update_btn.clicked.connect(self._update_engine)
        buttons.addWidget(self.update_btn)
        buttons.addStretch()
        self.close_btn = QPushButton("Close")
        self.close_btn.setDefault(True)
        self.close_btn.clicked.connect(self.accept)
        buttons.addWidget(self.close_btn)
        outer.addLayout(buttons)

    def _update_engine(self) -> None:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Update browser engine")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(
            "This checks for a newer Chromium engine and Qt toolkit and "
            "installs it if one is available.\n\n"
            "If an update is found it may download a few hundred MB. Vodou "
            "stays usable while it runs; you'll be told the result when it "
            "finishes.\n\n"
            "Check for updates now?")
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return

        self._output = ""
        self.update_btn.setEnabled(False)
        self.update_btn.setText("Checking…")
        self.status.setText("Contacting PyPI and installing any update — "
                            "this can take a few minutes…")
        self.status.show()

        self._proc = QProcess(self)
        self._proc.setProcessChannelMode(
            QProcess.ProcessChannelMode.MergedChannels)
        self._proc.readyReadStandardOutput.connect(self._read_output)
        self._proc.finished.connect(self._on_finished)
        self._proc.errorOccurred.connect(self._on_error)
        self._proc.start(sys.executable,
                         ["-m", "pip", "install", "--upgrade",
                          *_ENGINE_PACKAGES])

    def _read_output(self) -> None:
        if self._proc is not None:
            chunk = bytes(self._proc.readAllStandardOutput()).decode(
                "utf-8", "replace")
            self._output += chunk

    def _reset_button(self) -> None:
        self.update_btn.setEnabled(True)
        self.update_btn.setText("Update browser engine…")
        self.status.hide()

    def _on_error(self, _error) -> None:
        # Failure to launch pip at all (e.g. python not found).
        if self._proc is None:
            return
        self._proc = None
        self._reset_button()
        QMessageBox.warning(
            self, "Update failed to start",
            "Could not launch the updater.\n\nYou can update manually with:\n"
            "  python -m pip install --upgrade " + " ".join(_ENGINE_PACKAGES))

    def _on_finished(self, exit_code: int, _status) -> None:
        self._read_output()
        self._proc = None
        self._reset_button()
        out = self._output

        if exit_code != 0:
            tail = "\n".join(out.strip().splitlines()[-8:]) or "(no output)"
            hint = ""
            if "CERTIFICATE_VERIFY_FAILED" in out or "SSLError" in out:
                hint = ("\n\nThis looks like your antivirus intercepting TLS. "
                        "Installing 'pip-system-certs' fixes it.")
            QMessageBox.warning(
                self, "Update failed",
                f"The update did not complete (exit code {exit_code}):\n\n"
                f"{tail}{hint}")
            return

        if "Successfully installed" in out:
            QMessageBox.information(
                self, "Update completed",
                "Update completed.\n\n"
                "Close and reopen Vodou to start using the new engine.")
        else:
            QMessageBox.information(
                self, "No update needed",
                "You are using the most current version of the application.")
