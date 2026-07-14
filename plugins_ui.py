"""Plugins manager dialog: a catalog of reviewed plugins to switch on/off.

There is deliberately no "add your own script" field — the whole point of the
trusted-source model is that all code comes from Vodou's reviewed catalog.
"""

from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from plugins import PluginManager, catalog


class PluginsDialog(QDialog):
    def __init__(self, manager: PluginManager, parent: QWidget | None = None,
                 on_change: Callable[[], None] | None = None):
        super().__init__(parent)
        self.manager = manager
        self.on_change = on_change
        self.setWindowTitle("Plugins")
        self.resize(720, 460)

        layout = QVBoxLayout(self)

        intro = QLabel(
            "Plugins come from Vodou's reviewed catalog — a trusted source. "
            "Each runs only on the sites listed and inside an isolated "
            "sandbox. Toggle the checkbox to enable a plugin; changes take "
            "effect on pages you load next (reload open tabs to apply now).")
        intro.setTextFormat(Qt.TextFormat.PlainText)
        intro.setWordWrap(True)
        intro.setStyleSheet("color: gray; padding-bottom: 6px;")
        layout.addWidget(intro)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["On", "Plugin", "Sites", "Code ID"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self.table)

        self._populate()

        row = QHBoxLayout()
        row.addStretch()
        close = QPushButton("Close")
        close.setDefault(True)
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)

    def _populate(self) -> None:
        plugins = catalog()
        self.table.blockSignals(True)
        self.table.setRowCount(len(plugins))
        for i, p in enumerate(plugins):
            check = QTableWidgetItem()
            check.setFlags(Qt.ItemFlag.ItemIsUserCheckable
                           | Qt.ItemFlag.ItemIsEnabled)
            check.setCheckState(
                Qt.CheckState.Checked if self.manager.is_enabled(p.id)
                else Qt.CheckState.Unchecked)
            check.setData(Qt.ItemDataRole.UserRole, p.id)

            name = QTableWidgetItem(f"{p.name}")
            name.setToolTip(f"{p.description}\n\nv{p.version} · {p.author}")
            sites = QTableWidgetItem(p.sites_label)
            code = QTableWidgetItem(p.fingerprint)
            code.setToolTip("SHA-256 fingerprint of this plugin's code "
                            "(tamper-evident identity).")
            for item in (name, sites, code):
                item.setFlags(Qt.ItemFlag.ItemIsEnabled
                              | Qt.ItemFlag.ItemIsSelectable)

            self.table.setItem(i, 0, check)
            self.table.setItem(i, 1, name)
            self.table.setItem(i, 2, sites)
            self.table.setItem(i, 3, code)
        self.table.blockSignals(False)

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        plugin_id = item.data(Qt.ItemDataRole.UserRole)
        enabled = item.checkState() == Qt.CheckState.Checked
        self.manager.set_enabled(plugin_id, enabled)
        if self.on_change is not None:
            self.on_change()
