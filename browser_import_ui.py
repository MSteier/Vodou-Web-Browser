"""Import dialog: pick a detected Chrome/Edge profile and bring its
bookmarks and/or saved passwords into Vodou directly, no manual export.
"""

from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from browser_import import (
    BrowserProfile,
    detect_profiles,
    import_bookmarks_from,
    import_passwords_from,
)
from vault import normalize_site

NOTE_TEXT = (
    "Passwords are decrypted and stored in Vodou's own encrypted vault; "
    "the source browser's files are never modified. For best results, "
    "close Chrome/Edge first."
)


class BrowserImportDialog(QDialog):
    def __init__(self, vault, bookmarks, unlock_vault: Callable[[], bool],
                 parent: QWidget | None = None, on_imported: Callable[[], None] | None = None):
        super().__init__(parent)
        self.vault = vault
        self.bookmarks = bookmarks
        self.unlock_vault = unlock_vault
        self.on_imported = on_imported
        self.setWindowTitle("Import from Chrome/Edge")
        self.resize(480, 260)

        layout = QVBoxLayout(self)

        note = QLabel(NOTE_TEXT)
        note.setTextFormat(Qt.TextFormat.PlainText)
        note.setWordWrap(True)
        note.setStyleSheet("color: gray; padding-bottom: 6px;")
        layout.addWidget(note)

        self.profiles = detect_profiles()
        self.combo = QComboBox()
        if self.profiles:
            for p in self.profiles:
                self.combo.addItem(f"{p.browser} — {p.name}", p)
        else:
            self.combo.addItem("No Chrome/Edge profiles found", None)
            self.combo.setEnabled(False)
        layout.addWidget(self.combo)

        self.bookmarks_check = QCheckBox("Import bookmarks")
        self.bookmarks_check.setChecked(True)
        layout.addWidget(self.bookmarks_check)
        self.passwords_check = QCheckBox("Import saved passwords")
        self.passwords_check.setChecked(True)
        layout.addWidget(self.passwords_check)

        layout.addStretch()

        row = QHBoxLayout()
        row.addStretch()
        self.import_button = QPushButton("Import")
        self.import_button.setEnabled(bool(self.profiles))
        self.import_button.clicked.connect(self._on_import)
        row.addWidget(self.import_button)
        close = QPushButton("Close")
        close.setDefault(True)
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)

    def _selected_profile(self) -> BrowserProfile | None:
        return self.combo.currentData()

    def _warn(self, title: str, text: str) -> None:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(title)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(text)
        box.exec()

    def _on_import(self) -> None:
        profile = self._selected_profile()
        if profile is None:
            return
        if not self.bookmarks_check.isChecked() and not self.passwords_check.isChecked():
            self._warn("Nothing to do", "Check at least one of bookmarks or passwords.")
            return

        bookmarks_added = bookmarks_found = 0
        passwords_added = passwords_found = passwords_skipped = 0

        if self.bookmarks_check.isChecked():
            try:
                found = import_bookmarks_from(profile)
            except OSError as error:
                self._warn("Bookmark import failed", str(error))
                found = []
            bookmarks_found = len(found)
            bookmarks_added = self.bookmarks.add_many(found)

        if self.passwords_check.isChecked():
            if not self.unlock_vault():
                self._warn("Passwords skipped", "The vault was not unlocked, "
                           "so saved passwords were not imported.")
            else:
                try:
                    entries, passwords_skipped = import_passwords_from(profile)
                except OSError as error:
                    self._warn("Password import failed", str(error))
                    entries = []
                passwords_found = len(entries)
                existing = {(normalize_site(e.site), e.username)
                           for e in self.vault.entries()}
                to_add = []
                for entry in entries:
                    key = (normalize_site(entry.site), entry.username)
                    if key in existing:
                        continue
                    existing.add(key)
                    to_add.append(entry)
                passwords_added = self.vault.add_many(to_add)

        if self.on_imported is not None:
            self.on_imported()

        QMessageBox.information(
            self, "Import complete",
            f"Bookmarks: added {bookmarks_added} new of {bookmarks_found} found.\n"
            f"Passwords: added {passwords_added} new of {passwords_found} found "
            f"({passwords_skipped} unreadable row(s) skipped).")
