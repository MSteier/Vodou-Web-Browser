"""Extensions manager dialog: install real Chrome (Manifest V3) extensions
from a local .zip or unpacked folder.

Unlike plugins_ui.py's reviewed catalog, there is no vetting here -- the
user supplies the code. Every add is gated behind an explicit warning.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from extensions import ExtensionStore

WARNING_TEXT = (
    "Unlike Plugins, extensions are real third-party browser code with "
    "broad access to the pages you visit — Vodou does not review it. "
    "Only add extensions you trust."
)

ONE_ACTIVE_LIMIT_TEXT = (
    "Only one extension can be active at a time right now (loading a "
    "second one has been unreliable in current Qt WebEngine releases). "
    "Turning one on turns the previous one off."
)


class ExtensionsDialog(QDialog):
    def __init__(self, store: ExtensionStore, manager, parent: QWidget | None = None,
                 on_change: Callable[[], None] | None = None):
        super().__init__(parent)
        self.store = store
        self.manager = manager
        self.on_change = on_change
        self.setWindowTitle("Extensions")
        self.resize(760, 460)

        layout = QVBoxLayout(self)

        intro = QLabel(WARNING_TEXT)
        intro.setTextFormat(Qt.TextFormat.PlainText)
        intro.setWordWrap(True)
        intro.setStyleSheet("color: gray; padding-bottom: 6px;")
        layout.addWidget(intro)

        limit_note = QLabel(ONE_ACTIVE_LIMIT_TEXT)
        limit_note.setTextFormat(Qt.TextFormat.PlainText)
        limit_note.setWordWrap(True)
        limit_note.setStyleSheet("color: gray; padding-bottom: 6px;")
        layout.addWidget(limit_note)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["On", "Name", "Source", "Status"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self.table)

        self._populate()

        row = QHBoxLayout()
        add = QPushButton("Add extension…")
        add.clicked.connect(self._on_add)
        row.addWidget(add)
        remove = QPushButton("Remove")
        remove.clicked.connect(self._on_remove)
        row.addWidget(remove)
        reload_btn = QPushButton("Reload active")
        reload_btn.setToolTip(
            "Re-reads the active extension's files from disk -- use this "
            "after updating it in place at the same path.")
        reload_btn.clicked.connect(self._on_reload)
        row.addWidget(reload_btn)
        row.addStretch()
        close = QPushButton("Close")
        close.setDefault(True)
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)

    def _populate(self) -> None:
        records = self.store.records()
        self.table.blockSignals(True)
        self.table.setRowCount(len(records))
        for i, r in enumerate(records):
            check = QTableWidgetItem()
            check.setFlags(Qt.ItemFlag.ItemIsUserCheckable
                           | Qt.ItemFlag.ItemIsEnabled)
            check.setCheckState(
                Qt.CheckState.Checked if r.enabled
                else Qt.CheckState.Unchecked)
            check.setData(Qt.ItemDataRole.UserRole, r.id)

            name = QTableWidgetItem(r.name)
            source = QTableWidgetItem(r.source_path)
            status = QTableWidgetItem(r.last_error or ("Active" if r.enabled else "Off"))
            if r.last_error:
                status.setForeground(Qt.GlobalColor.red)
            for item in (name, source, status):
                item.setFlags(Qt.ItemFlag.ItemIsEnabled
                              | Qt.ItemFlag.ItemIsSelectable)

            self.table.setItem(i, 0, check)
            self.table.setItem(i, 1, name)
            self.table.setItem(i, 2, source)
            self.table.setItem(i, 3, status)
        self.table.blockSignals(False)

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        record_id = item.data(Qt.ItemDataRole.UserRole)
        enabled = item.checkState() == Qt.CheckState.Checked
        self.store.set_enabled(record_id, enabled)
        if enabled and self.on_change is not None:
            self.on_change()
        elif not enabled:
            self._unload(record_id)
        self._populate()

    def _on_add(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select an extension (.zip)", "", "Extension archives (*.zip)")
        if not path:
            path = QFileDialog.getExistingDirectory(
                self, "Or select an unpacked extension folder")
        if not path:
            return

        active = next((r for r in self.store.records() if r.enabled), None)
        deactivate_note = (
            f"\n\nThis will turn off the currently active extension ({active.name})."
            if active is not None else "")

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Add extension?")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(
            f"{WARNING_TEXT}\n\nAdd the extension at:\n{path}{deactivate_note}")
        box.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return

        resolved = str(Path(path).resolve())
        name = Path(path).stem
        self.store.add(resolved, name)
        self._populate()
        if self.on_change is not None:
            self.on_change()

    def _on_reload(self) -> None:
        active = next((r for r in self.store.records() if r.enabled), None)
        if active is None:
            QMessageBox.information(
                self, "Reload", "No extension is currently active.")
            return
        # Unload the live instance and let on_change() (main.py's
        # _apply_extensions) reload it fresh from disk, picking up
        # whatever changed at that path.
        self._unload(active.id)
        if self.on_change is not None:
            self.on_change()
        self._populate()

    def _on_remove(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        record_id = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        self._unload(record_id)
        self.store.remove(record_id)
        self._populate()

    def _unload(self, record_id: str) -> None:
        record = next((r for r in self.store.records() if r.id == record_id), None)
        if record is None:
            return
        for info in self.manager.extensions():
            if info.path() == record.source_path:
                self.manager.unloadExtension(info)
                break
