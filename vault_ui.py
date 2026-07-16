"""Dialogs for the password vault: unlock/create, manage entries, generator."""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QGuiApplication, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from importers import parse_password_csv, write_password_csv
from vault import (
    Entry,
    Vault,
    VaultCorrupted,
    WrongMasterPassword,
    generate_password,
    normalize_site,
)

CLIPBOARD_CLEAR_SECONDS = 30

# Secrets currently on the clipboard awaiting their timed wipe, so they can
# also be wiped if the app exits before the timer fires.
_pending_secrets: set[str] = set()


def clear_copied_secrets() -> None:
    """Wipe the clipboard now if it still holds a copied secret."""
    clipboard = QGuiApplication.clipboard()
    if clipboard.text() in _pending_secrets:
        clipboard.clear()
    _pending_secrets.clear()


def _copy_with_auto_clear(text: str, parent: QWidget) -> None:
    """Copy to clipboard and wipe it after CLIPBOARD_CLEAR_SECONDS.

    The timer deliberately has no context object: binding it to the dialog
    would cancel the wipe when the dialog closes — which is exactly when
    it's needed most.
    """
    clipboard = QGuiApplication.clipboard()
    clipboard.setText(text)
    _pending_secrets.add(text)

    def clear_if_unchanged():
        _pending_secrets.discard(text)
        if clipboard.text() == text:
            clipboard.clear()

    QTimer.singleShot(CLIPBOARD_CLEAR_SECONDS * 1000, clear_if_unchanged)


class UnlockDialog(QDialog):
    """Prompts for the master password; creates the vault on first run."""

    def __init__(self, vault: Vault, parent: QWidget | None = None):
        super().__init__(parent)
        self.vault = vault
        self.creating = not vault.exists()
        self.setWindowTitle("Create Vault" if self.creating else "Unlock Vault")
        self.setMinimumWidth(380)

        layout = QVBoxLayout(self)
        if self.creating:
            layout.addWidget(QLabel(
                "No vault exists yet. Choose a master password.\n"
                "It encrypts everything — if you forget it, the vault\n"
                "cannot be recovered."))

        form = QFormLayout()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Master password:", self.password_edit)

        self.confirm_edit = None
        if self.creating:
            self.confirm_edit = QLineEdit()
            self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow("Confirm:", self.confirm_edit)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._submit)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.password_edit.setFocus()

    def _submit(self) -> None:
        master = self.password_edit.text()
        if self.creating:
            if len(master) < 8:
                QMessageBox.warning(self, "Too short",
                                    "Use at least 8 characters (a long "
                                    "passphrase is best).")
                return
            if master != self.confirm_edit.text():
                QMessageBox.warning(self, "Mismatch", "Passwords don't match.")
                return
            try:
                self.vault.create(master)
            except (FileExistsError, OSError) as error:
                QMessageBox.critical(self, "Vault error",
                                     f"Could not create the vault:\n{error}")
                return
            self.accept()
            return
        try:
            self.vault.unlock(master)
        except WrongMasterPassword:
            QMessageBox.warning(self, "Wrong password",
                                "That master password is incorrect.")
            self.password_edit.clear()
            return
        except (VaultCorrupted, OSError) as error:
            QMessageBox.critical(
                self, "Vault error",
                f"The vault could not be opened:\n{error}\n\n"
                f"The file has not been modified.")
            return
        self.accept()


class ChangeMasterDialog(QDialog):
    """Change the vault's master password (current one re-verified first)."""

    def __init__(self, vault: Vault, parent: QWidget | None = None):
        super().__init__(parent)
        self.vault = vault
        self.setWindowTitle("Change master password")
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            "The new master password re-encrypts the whole vault.\n"
            "If you forget it, the vault cannot be recovered."))

        form = QFormLayout()
        self.current_edit = QLineEdit()
        self.new_edit = QLineEdit()
        self.confirm_edit = QLineEdit()
        for edit in (self.current_edit, self.new_edit, self.confirm_edit):
            edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Current master password:", self.current_edit)
        form.addRow("New master password:", self.new_edit)
        form.addRow("Confirm new:", self.confirm_edit)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._submit)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.current_edit.setFocus()

    def _submit(self) -> None:
        new = self.new_edit.text()
        if len(new) < 8:
            QMessageBox.warning(self, "Too short",
                                "Use at least 8 characters (a long "
                                "passphrase is best).")
            return
        if new != self.confirm_edit.text():
            QMessageBox.warning(self, "Mismatch",
                                "New passwords don't match.")
            return
        try:
            self.vault.change_master_password(self.current_edit.text(), new)
        except WrongMasterPassword:
            QMessageBox.warning(self, "Wrong password",
                                "The current master password is incorrect.")
            self.current_edit.clear()
            self.current_edit.setFocus()
            return
        except OSError as error:
            QMessageBox.critical(self, "Vault error",
                                 f"Could not save the vault:\n{error}")
            return
        QMessageBox.information(
            self, "Master password changed",
            "The vault was re-encrypted under your new master password.")
        self.accept()


def ensure_unlocked(vault: Vault, parent: QWidget | None = None) -> bool:
    """Unlock (or create) the vault interactively. True if usable."""
    if vault.unlocked:
        return True
    dialog = UnlockDialog(vault, parent)
    return dialog.exec() == QDialog.DialogCode.Accepted


class EntryDialog(QDialog):
    """Add or edit a single vault entry."""

    def __init__(self, parent: QWidget | None = None,
                 entry: Entry | None = None, site: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Edit Entry" if entry else "Add Entry")
        self.setMinimumWidth(420)

        form = QFormLayout()
        self.site_edit = QLineEdit(entry.site if entry else site)
        self.user_edit = QLineEdit(entry.username if entry else "")
        self.pass_edit = QLineEdit(entry.password if entry else "")
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.notes_edit = QLineEdit(entry.notes if entry else "")

        show = QCheckBox("Show")
        show.toggled.connect(lambda on: self.pass_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))

        gen_row = QHBoxLayout()
        gen_row.addWidget(self.pass_edit)
        gen_row.addWidget(show)
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 64)
        self.length_spin.setValue(20)
        gen_btn = QPushButton("Generate")
        gen_btn.clicked.connect(self._generate)
        gen_row.addWidget(self.length_spin)
        gen_row.addWidget(gen_btn)

        form.addRow("Site (domain):", self.site_edit)
        form.addRow("Username:", self.user_edit)
        form.addRow("Password:", gen_row)
        form.addRow("Notes:", self.notes_edit)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._submit)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _generate(self) -> None:
        self.pass_edit.setText(generate_password(self.length_spin.value()))
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Normal)

    def _submit(self) -> None:
        if not self.site_edit.text().strip() or not self.pass_edit.text():
            QMessageBox.warning(self, "Missing fields",
                                "Site and password are required.")
            return
        self.accept()

    def result_entry(self) -> Entry:
        return Entry(site=self.site_edit.text(),
                     username=self.user_edit.text(),
                     password=self.pass_edit.text(),
                     notes=self.notes_edit.text())


class VaultDialog(QDialog):
    """Table view of all saved logins with add/edit/delete/copy."""

    def __init__(self, vault: Vault, parent: QWidget | None = None,
                 current_site: str = ""):
        super().__init__(parent)
        self.vault = vault
        self.current_site = current_site
        self.setWindowTitle("Password Vault")
        self.resize(640, 420)

        layout = QVBoxLayout(self)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(
            "Search logins — site, username or notes  (Ctrl+F)")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(lambda _: self._refresh())
        QShortcut(QKeySequence.StandardKey.Find, self,
                  activated=lambda: (self.search_edit.setFocus(),
                                     self.search_edit.selectAll()))
        layout.addWidget(self.search_edit)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Site", "Username", "Notes"])
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.doubleClicked.connect(lambda _: self._edit())
        layout.addWidget(self.table)

        row = QHBoxLayout()
        for label, handler in (
                ("Add", self._add),
                ("Edit", self._edit),
                ("Delete", self._delete),
                ("Copy password", self._copy_password),
                ("Copy username", self._copy_username)):
            btn = QPushButton(label)
            btn.clicked.connect(handler)
            row.addWidget(btn)
        row.addStretch()
        layout.addLayout(row)

        io_row = QHBoxLayout()
        import_btn = QPushButton("Import CSV…")
        import_btn.clicked.connect(self._import_csv)
        export_btn = QPushButton("Export CSV…")
        export_btn.clicked.connect(self._export_csv)
        io_row.addWidget(import_btn)
        io_row.addWidget(export_btn)
        io_row.addStretch()
        master_btn = QPushButton("Change master password…")
        master_btn.clicked.connect(
            lambda: ChangeMasterDialog(self.vault, self).exec())
        io_row.addWidget(master_btn)
        layout.addLayout(io_row)

        hint = QLabel(f"Copied passwords are cleared from the clipboard "
                      f"after {CLIPBOARD_CLEAR_SECONDS}s.")
        hint.setStyleSheet("color: gray;")
        layout.addWidget(hint)

        self._refresh()

    def _refresh(self) -> None:
        # Rows carry the entry's true vault index in UserRole, so edit /
        # delete / copy keep working on a filtered view.
        query = self.search_edit.text().strip().lower()
        matches = [(i, e) for i, e in enumerate(self.vault.entries())
                   if not query
                   or query in e.site.lower()
                   or query in e.username.lower()
                   or query in e.notes.lower()]
        self.table.setRowCount(len(matches))
        for row, (i, e) in enumerate(matches):
            for col, text in enumerate((e.site, e.username, e.notes)):
                item = QTableWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, i)
                self.table.setItem(row, col, item)

    def _selected_index(self) -> int | None:
        items = self.table.selectedItems()
        if not items:
            return None
        return items[0].data(Qt.ItemDataRole.UserRole)

    def _add(self) -> None:
        dialog = EntryDialog(self, site=self.current_site)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.vault.add(dialog.result_entry())
            self._refresh()

    def _edit(self) -> None:
        index = self._selected_index()
        if index is None:
            return
        entry = self.vault.entries()[index]
        entry.password = self.vault.reveal(index)  # decrypt only for editing
        dialog = EntryDialog(self, entry=entry)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.vault.update(index, dialog.result_entry())
            self._refresh()

    def _delete(self) -> None:
        index = self._selected_index()
        if index is None:
            return
        entry = self.vault.entries()[index]
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Delete entry")
        box.setText(f"Delete the login for {entry.site} ({entry.username})?")
        box.setTextFormat(Qt.TextFormat.PlainText)  # site/username untrusted
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() == QMessageBox.StandardButton.Yes:
            self.vault.delete(index)
            self._refresh()

    def _copy_password(self) -> None:
        index = self._selected_index()
        if index is not None:
            _copy_with_auto_clear(self.vault.reveal(index), self)

    def _copy_username(self) -> None:
        index = self._selected_index()
        if index is not None:
            _copy_with_auto_clear(self.vault.entries()[index].username, self)

    def _import_csv(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Import passwords (CSV)", str(Path.home()),
            "CSV files (*.csv);;All files (*)")
        if not path:
            return
        try:
            entries, skipped = parse_password_csv(Path(path))
        except OSError as error:
            QMessageBox.warning(self, "Import failed",
                                f"Could not read the file:\n{error}")
            return
        if not entries:
            QMessageBox.warning(
                self, "Nothing imported",
                "No usable rows found. The CSV needs at least a password "
                "column plus a url or name column (Chrome, Edge, Firefox, "
                "Brave and Bitwarden exports all work).")
            return

        # Skip logins already present (same site + username).
        existing = {(normalize_site(e.site), e.username)
                    for e in self.vault.entries()}
        added = 0
        for entry in entries:
            key = (normalize_site(entry.site), entry.username)
            if key in existing:
                continue
            self.vault.add(entry)
            existing.add(key)
            added += 1
        self._refresh()
        QMessageBox.information(
            self, "Passwords imported",
            f"Imported {added} login(s) into the vault.\n"
            f"Skipped {len(entries) - added} duplicate(s) and {skipped} "
            f"row(s) without a usable password.\n\n"
            f"The CSV still holds these passwords in plain text — delete it "
            f"when you're done.")

    def _export_csv(self) -> None:
        count = len(self.vault.entries())
        if count == 0:
            QMessageBox.information(self, "Nothing to export",
                                   "The vault has no saved logins.")
            return
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Export passwords")
        box.setText(
            f"This writes all {count} login(s) to a CSV file with the "
            f"passwords in PLAIN TEXT — anyone who reads the file can see "
            f"them. Store it securely and delete it when done.\n\n"
            f"Continue?")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export passwords (CSV)",
            str(Path.home() / "vodou-passwords.csv"),
            "CSV files (*.csv);;All files (*)")
        if not path:
            return

        # Reveal each password only at the moment of writing.
        meta = self.vault.entries()
        full = [Entry(site=e.site, username=e.username,
                      password=self.vault.reveal(i), notes=e.notes)
                for i, e in enumerate(meta)]
        try:
            write_password_csv(Path(path), full)
        except OSError as error:
            QMessageBox.warning(self, "Export failed",
                                f"Could not write the file:\n{error}")
            return
        finally:
            for entry in full:  # drop plaintext references promptly
                entry.password = ""
        QMessageBox.information(
            self, "Passwords exported",
            f"Exported {count} login(s).\n\n"
            f"Remember: the file is unencrypted. Delete it once you've "
            f"imported it elsewhere.")


class PickEntryDialog(QDialog):
    """When several logins match the current site, pick one to fill.

    Takes (index, entry) pairs so the caller can reveal the chosen
    password by index — passwords are never held here. When a vault is
    passed, the highlighted login can also be deleted right from the
    picker (handy for clearing out stale duplicates).
    """

    def __init__(self, matches: list[tuple[int, Entry]],
                 parent: QWidget | None = None,
                 vault: Vault | None = None):
        super().__init__(parent)
        self.setWindowTitle("Choose login")
        self.choice: tuple[int, Entry] | None = None
        self.vault = vault

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Multiple saved logins match this site:"))

        self.list = QListWidget()
        for index, entry in matches:
            # QListWidgetItem renders plain text only, so the untrusted
            # username/site can't inject markup.
            item = QListWidgetItem(f"{entry.username}  ({entry.site})")
            item.setData(Qt.ItemDataRole.UserRole, (index, entry))
            self.list.addItem(item)
        self.list.setCurrentRow(0)
        self.list.itemDoubleClicked.connect(lambda _: self._select())
        layout.addWidget(self.list)

        buttons = QHBoxLayout()
        select_btn = QPushButton("Select")
        select_btn.setDefault(True)
        select_btn.clicked.connect(self._select)
        buttons.addWidget(select_btn)
        if vault is not None:
            delete_btn = QPushButton("Delete login")
            delete_btn.clicked.connect(self._delete)
            buttons.addWidget(delete_btn)
        buttons.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(cancel_btn)
        layout.addLayout(buttons)

    def _select(self) -> None:
        item = self.list.currentItem()
        if item is None:
            return
        self.choice = item.data(Qt.ItemDataRole.UserRole)
        self.accept()

    def _delete(self) -> None:
        item = self.list.currentItem()
        if item is None or self.vault is None:
            return
        index, entry = item.data(Qt.ItemDataRole.UserRole)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Delete login")
        box.setText(f"Delete the login for {entry.site} ({entry.username})?")
        box.setTextFormat(Qt.TextFormat.PlainText)  # site/username untrusted
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        self.vault.delete(index)
        self.list.takeItem(self.list.row(item))
        # Deleting shifts every later vault entry down one slot; fix the
        # stored indices so a follow-up Select still fills the right login.
        for i in range(self.list.count()):
            other = self.list.item(i)
            other_index, other_entry = other.data(Qt.ItemDataRole.UserRole)
            if other_index > index:
                other.setData(Qt.ItemDataRole.UserRole,
                              (other_index - 1, other_entry))
        if self.list.count() == 0:
            self.reject()
