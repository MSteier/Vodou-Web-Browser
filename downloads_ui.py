"""Download manager: a non-modal dialog with a live progress row per file.

Downloads are session-only, like everything else in the off-the-record
profile — the list empties when the browser closes. Each row tracks its
QWebEngineDownloadRequest via signals (no polling): progress bar + byte
counts while running, then Open folder / a failure reason when done.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWebEngineCore import QWebEngineDownloadRequest
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

_STATE = QWebEngineDownloadRequest.DownloadState


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


class DownloadRow(QFrame):
    """One download: name, progress bar, byte counts, cancel/open button."""

    def __init__(self, item: QWebEngineDownloadRequest,
                 parent: QWidget | None = None):
        super().__init__(parent)
        self.item = item
        self.finished = False
        self.setObjectName("downloadRow")
        self.setFrameShape(QFrame.Shape.StyledPanel)

        col = QVBoxLayout(self)
        col.setContentsMargins(10, 8, 10, 8)
        col.setSpacing(4)

        top = QHBoxLayout()
        # Filename and host are attacker-controlled: plain text only.
        self.name_label = QLabel(item.downloadFileName())
        self.name_label.setTextFormat(Qt.TextFormat.PlainText)
        self.name_label.setStyleSheet("font-weight: 600;")
        top.addWidget(self.name_label, 1)
        self.action_btn = QPushButton("Cancel")
        self.action_btn.clicked.connect(self._on_action)
        top.addWidget(self.action_btn)
        col.addLayout(top)

        self.bar = QProgressBar()
        self.bar.setRange(0, 0)  # busy until the size is known
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(8)
        col.addWidget(self.bar)

        self.status_label = QLabel(f"Starting — from {item.url().host()}")
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setStyleSheet("color: gray;")
        col.addWidget(self.status_label)

        item.receivedBytesChanged.connect(self._on_progress)
        item.totalBytesChanged.connect(self._on_progress)
        item.stateChanged.connect(self._on_state)

    # A download request object can be torn down by the engine (page or
    # profile going away); every access is guarded so a dead item just
    # freezes the row instead of raising.
    def _on_progress(self) -> None:
        if self.finished:
            return
        try:
            got, total = self.item.receivedBytes(), self.item.totalBytes()
        except RuntimeError:
            return
        if total > 0:
            self.bar.setRange(0, 100)
            self.bar.setValue(int(got * 100 / total))
            self.status_label.setText(
                f"{human_size(got)} of {human_size(total)}")
        else:
            self.status_label.setText(f"{human_size(got)} downloaded")

    def _on_state(self, state) -> None:
        if state == _STATE.DownloadCompleted:
            self.finished = True
            self.bar.setRange(0, 100)
            self.bar.setValue(100)
            try:
                where = Path(self.item.downloadDirectory())
                total = self.item.totalBytes()
            except RuntimeError:
                where, total = Path.home() / "Downloads", -1
            size = f" ({human_size(total)})" if total > 0 else ""
            self.status_label.setText(f"Completed{size} — {where}")
            self.action_btn.setText("Open folder")
        elif state == _STATE.DownloadCancelled:
            self.finished = True
            self.bar.setRange(0, 100)
            self.bar.setValue(0)
            self.status_label.setText("Cancelled")
            self.action_btn.setText("Remove")
        elif state == _STATE.DownloadInterrupted:
            self.finished = True
            self.bar.setRange(0, 100)
            self.bar.setValue(0)
            try:
                reason = self.item.interruptReasonString()
            except RuntimeError:
                reason = "interrupted"
            self.status_label.setText(f"Failed — {reason}")
            self.action_btn.setText("Remove")

    def _on_action(self) -> None:
        if not self.finished:
            try:
                self.item.cancel()
            except RuntimeError:
                pass
            return
        if self.action_btn.text() == "Open folder":
            try:
                folder = self.item.downloadDirectory()
            except RuntimeError:
                folder = str(Path.home() / "Downloads")
            QDesktopServices.openUrl(QUrl.fromLocalFile(folder))
        else:  # Remove (cancelled / failed row)
            self.setParent(None)
            self.deleteLater()


class DownloadsDialog(QDialog):
    """Non-modal list of this session's downloads, newest first."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Downloads")
        self.resize(540, 420)
        self.setModal(False)

        outer = QVBoxLayout(self)

        self.empty_label = QLabel(
            "No downloads this session.\n"
            "(Like everything in Vodou, the list clears when you close "
            "the browser.)")
        self.empty_label.setStyleSheet("color: gray;")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(self.empty_label)

        inner = QWidget()
        self.rows_layout = QVBoxLayout(inner)
        self.rows_layout.setContentsMargins(0, 0, 0, 0)
        self.rows_layout.setSpacing(6)
        self.rows_layout.addStretch()

        scroll = QScrollArea()
        scroll.setWidget(inner)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(scroll, 1)

        buttons = QHBoxLayout()
        clear_btn = QPushButton("Clear finished")
        clear_btn.clicked.connect(self.clear_finished)
        buttons.addWidget(clear_btn)
        buttons.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setDefault(True)
        close_btn.clicked.connect(self.hide)
        buttons.addWidget(close_btn)
        outer.addLayout(buttons)

    def add(self, item: QWebEngineDownloadRequest) -> None:
        self.empty_label.hide()
        self.rows_layout.insertWidget(0, DownloadRow(item))
        self.show()
        self.raise_()
        self.activateWindow()

    def _rows(self) -> list[DownloadRow]:
        return [w for w in self.findChildren(DownloadRow)
                if w.parent() is not None]

    def clear_finished(self) -> None:
        remaining = 0
        for row in self._rows():
            if row.finished:
                row.setParent(None)
                row.deleteLater()
            else:
                remaining += 1
        if remaining == 0:
            self.empty_label.show()
