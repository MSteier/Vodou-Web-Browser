"""Bookmark manager: view, add, edit, delete, and open stored bookmarks.

Bookmark titles and URLs are page-derived (untrusted), so everything shown in
message boxes is forced to plain text, and only http/https URLs are accepted —
matching the storage layer's own scheme allowlist.
"""

from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from bookmarks import Bookmarks, _is_safe_url


class BookmarkEditDialog(QDialog):
    """Add or edit a single bookmark (title + URL)."""

    def __init__(self, parent: QWidget | None = None,
                 title: str = "", url: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Edit Bookmark" if url else "Add Bookmark")
        self.setMinimumWidth(460)

        form = QFormLayout()
        self.title_edit = QLineEdit(title)
        self.title_edit.setPlaceholderText("Page title")
        self.url_edit = QLineEdit(url)
        self.url_edit.setPlaceholderText("https://example.com")
        form.addRow("Title:", self.title_edit)
        form.addRow("URL:", self.url_edit)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._submit)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _submit(self) -> None:
        url = self.url_edit.text().strip()
        # Be forgiving: a bare host becomes https://host.
        if url and "://" not in url:
            url = "https://" + url
        if not _is_safe_url(url):
            QMessageBox.warning(
                self, "Invalid URL",
                "Enter a web address starting with http:// or https://.")
            return
        self._url = url
        self.accept()

    def values(self) -> tuple[str, str]:
        return self.title_edit.text().strip(), self._url


class BookmarksManagerDialog(QDialog):
    """Table of stored bookmarks with add / edit / delete / open."""

    def __init__(self, store: Bookmarks, parent: QWidget | None = None,
                 open_url: Callable[[str], None] | None = None):
        super().__init__(parent)
        self.store = store
        self.open_url = open_url
        self.setWindowTitle("Bookmarks")
        self.resize(680, 440)

        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Title", "URL"])
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.doubleClicked.connect(lambda _: self._open())
        layout.addWidget(self.table)

        row = QHBoxLayout()
        for label, handler in (
                ("Add", self._add),
                ("Edit", self._edit),
                ("Delete", self._delete),
                ("Open", self._open)):
            btn = QPushButton(label)
            btn.clicked.connect(handler)
            row.addWidget(btn)
        row.addStretch()
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)

        self._refresh()

    def _refresh(self) -> None:
        items = self.store.all()
        self.table.setRowCount(len(items))
        for i, b in enumerate(items):
            for col, text in enumerate((b.title, b.url)):
                cell = QTableWidgetItem(text)
                cell.setData(Qt.ItemDataRole.UserRole, i)
                self.table.setItem(i, col, cell)

    def _selected_index(self) -> int | None:
        items = self.table.selectedItems()
        if not items:
            return None
        return items[0].data(Qt.ItemDataRole.UserRole)

    def _add(self) -> None:
        dialog = BookmarkEditDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        title, url = dialog.values()
        if not self.store.add(title, url):
            QMessageBox.information(self, "Already bookmarked",
                                    "That URL is already in your bookmarks.")
        self._refresh()

    def _edit(self) -> None:
        index = self._selected_index()
        if index is None:
            return
        current = self.store.all()[index]
        dialog = BookmarkEditDialog(self, title=current.title, url=current.url)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        title, url = dialog.values()
        if not self.store.update(index, title, url):
            QMessageBox.warning(
                self, "Couldn't save",
                "Another bookmark already uses that URL.")
        self._refresh()

    def _delete(self) -> None:
        index = self._selected_index()
        if index is None:
            return
        current = self.store.all()[index]
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Delete bookmark")
        box.setTextFormat(Qt.TextFormat.PlainText)  # title/url untrusted
        box.setText(f"Delete this bookmark?\n\n{current.title}\n{current.url}")
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() == QMessageBox.StandardButton.Yes:
            self.store.remove_at(index)
            self._refresh()

    def _open(self) -> None:
        index = self._selected_index()
        if index is None or self.open_url is None:
            return
        self.open_url(self.store.all()[index].url)
        self.accept()
