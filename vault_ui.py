"""Dialogs for the password vault: unlock/create, manage entries, generator."""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QGuiApplication, QKeySequence, QPalette, QShortcut
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from authenticator import (
    AuthenticatorError,
    WindowsWebAuthnAuthenticator,
    webauthn_supported,
)
from icons import make_icon
from importers import parse_password_csv, write_password_csv
from vault import (
    Entry,
    SecondFactorFailed,
    SecondFactorRequired,
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


def _plain_warning(parent: QWidget, title: str, text: str) -> None:
    """Warning box that renders as PLAIN text — used wherever the message
    embeds a filename or OS error (a downloaded file's name was chosen by a
    website, and QMessageBox auto-detects rich text)."""
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle(title)
    box.setText(text)
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.exec()


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
        self.reset_requested = False
        self.needs_key = (not self.creating) and vault.file_has_factor()
        self.setWindowTitle("Create Vault" if self.creating else "Unlock Vault")
        self.setMinimumWidth(380)

        layout = QVBoxLayout(self)
        if self.creating:
            layout.addWidget(QLabel(
                "No vault exists yet. Choose a master password.\n"
                "It encrypts everything — if you forget it, the vault\n"
                "cannot be recovered."))
        elif self.needs_key:
            key_hint = QLabel(
                "🔑 This vault also needs a registered security key.\n"
                "Have it ready — you'll be prompted to tap it after you "
                "enter your password.")
            key_hint.setWordWrap(True)
            layout.addWidget(key_hint)

        form = QFormLayout()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._add_reveal_toggle(self.password_edit)
        form.addRow("Master password:", self.password_edit)

        self.confirm_edit = None
        if self.creating:
            self.confirm_edit = QLineEdit()
            self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self._add_reveal_toggle(self.confirm_edit)
            form.addRow("Confirm:", self.confirm_edit)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._submit)
        buttons.rejected.connect(self.reject)
        if not self.creating:
            # Only offer "start over" when a vault exists to erase. This is a
            # last resort for a forgotten master password — it cannot recover
            # the saved logins (they're encrypted under that password), it
            # only deletes the vault so a fresh one can be created.
            reset_btn = buttons.addButton(
                "Forgot? Start over…", QDialogButtonBox.ButtonRole.ResetRole)
            reset_btn.clicked.connect(self._start_over)
        layout.addWidget(buttons)
        self.password_edit.setFocus()

    def _start_over(self) -> None:
        text, ok = QInputDialog.getText(
            self, "Erase vault and start over",
            "This permanently erases EVERY saved login in the vault.\n\n"
            "Your passwords are encrypted with the master password you've\n"
            "forgotten, so they cannot be recovered — starting over only\n"
            "lets you create a new, empty vault. This cannot be undone.\n\n"
            "Type RESET to confirm:")
        if not ok or text.strip() != "RESET":
            return
        try:
            self.vault.destroy()
        except OSError as error:
            QMessageBox.critical(
                self, "Could not reset",
                f"The vault file could not be deleted:\n{error}")
            return
        self.reset_requested = True
        self.reject()

    def _add_reveal_toggle(self, edit: QLineEdit) -> None:
        """Put an eye icon inside the field's right edge that toggles the
        password between hidden (default) and visible. Replaces the old
        'Show password' checkbox; each field toggles independently, the icon
        reflects the current state, and clicking it keeps typing focus."""
        color = edit.palette().color(QPalette.ColorRole.Text).name()
        eye = make_icon("eye", color)          # open eye  -> currently visible
        eye_off = make_icon("eye-off", color)  # slashed   -> currently hidden
        action = edit.addAction(
            eye_off, QLineEdit.ActionPosition.TrailingPosition)
        action.setToolTip("Show password")
        action.setCheckable(True)

        def toggle(shown: bool) -> None:
            edit.setEchoMode(QLineEdit.EchoMode.Normal if shown
                             else QLineEdit.EchoMode.Password)
            action.setIcon(eye if shown else eye_off)
            action.setToolTip("Hide password" if shown else "Show password")
            edit.setFocus()  # a click on the icon must not steal typing focus

        action.toggled.connect(toggle)

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
        authenticator = None
        if self.needs_key:
            ok, why = webauthn_supported()
            if not ok:
                QMessageBox.critical(
                    self, "Security key required",
                    "This vault needs a registered security key to unlock, "
                    "but that isn't available right now:\n\n" + why)
                return
            authenticator = WindowsWebAuthnAuthenticator(int(self.winId()))
        try:
            self.vault.unlock(master, authenticator)
        except WrongMasterPassword:
            QMessageBox.warning(self, "Wrong password",
                                "That master password is incorrect.")
            self.password_edit.clear()
            return
        except SecondFactorRequired:
            QMessageBox.critical(
                self, "Security key required",
                "This vault needs a registered security key to unlock.")
            return
        except SecondFactorFailed as error:
            QMessageBox.warning(
                self, "Security key",
                f"Couldn't verify your security key:\n\n{error}\n\n"
                f"Make sure the right key is plugged in, then try again.")
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

        show = QCheckBox("Show passwords")
        show.toggled.connect(lambda on: [
            edit.setEchoMode(QLineEdit.EchoMode.Normal if on
                             else QLineEdit.EchoMode.Password)
            for edit in (self.current_edit, self.new_edit, self.confirm_edit)])
        layout.addWidget(show)

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


class SecurityKeysDialog(QDialog):
    """Enroll / remove FIDO2 security keys as the vault's second factor.

    Opened from the vault window while it's unlocked. Enrolling the first key
    turns on 2FA (password + key henceforth); each further key is an
    independent backup. Removing the last key reverts to password-only.
    """

    def __init__(self, vault: Vault, parent: QWidget | None = None):
        super().__init__(parent)
        self.vault = vault
        self.setWindowTitle("Security keys")
        self.setMinimumWidth(440)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            "A security key adds a second factor: the vault then needs BOTH "
            "your master password AND a registered key to open.\n\n"
            "Enroll at least two — a spare kept somewhere safe. If you lose "
            "the only key, the vault cannot be opened (there is no bypass)."))

        self.list = QListWidget()
        layout.addWidget(self.list)

        row = QHBoxLayout()
        self.add_btn = QPushButton("Add key…")
        self.add_btn.clicked.connect(self._add)
        self.remove_btn = QPushButton("Remove")
        self.remove_btn.clicked.connect(self._remove)
        row.addWidget(self.add_btn)
        row.addWidget(self.remove_btn)
        row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        row.addWidget(close_btn)
        layout.addLayout(row)

        available, why = webauthn_supported()
        if not available:
            self.add_btn.setEnabled(False)
            warn = QLabel(why)
            warn.setWordWrap(True)
            warn.setStyleSheet("color: #b00020;")
            layout.addWidget(warn)

        self._refresh()

    def _refresh(self) -> None:
        self.list.clear()
        keys = self.vault.list_authenticators()
        for rec in keys:
            label = rec["label"] or "Security key"
            item = QListWidgetItem(f"{label}   (added {rec['added']})")
            # QListWidgetItem is plain text, so a user-typed label can't inject
            # markup. Store the raw credential id for removal.
            item.setData(Qt.ItemDataRole.UserRole, rec["cred_id"])
            self.list.addItem(item)
        self.remove_btn.setEnabled(bool(keys))
        if not keys:
            placeholder = QListWidgetItem(
                "No security keys enrolled — this vault opens with the "
                "master password alone.")
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            self.list.addItem(placeholder)

    def _add(self) -> None:
        label, ok = QInputDialog.getText(
            self, "Add security key",
            "Name this key so you can tell it apart later\n"
            "(e.g. 'YubiKey 5C', 'Backup in drawer'):")
        if not ok:
            return
        if not self.vault.factor_enrolled:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle("Turn on security-key unlock")
            box.setText(
                "This makes a security key REQUIRED to open the vault, "
                "alongside your master password.\n\n"
                "If you later lose every enrolled key, the saved logins "
                "cannot be recovered. Enroll a backup key right after this "
                "one.\n\nContinue?")
            box.setStandardButtons(QMessageBox.StandardButton.Yes
                                   | QMessageBox.StandardButton.No)
            box.setDefaultButton(QMessageBox.StandardButton.No)
            if box.exec() != QMessageBox.StandardButton.Yes:
                return
        authenticator = WindowsWebAuthnAuthenticator(int(self.winId()))
        try:
            self.vault.enroll_authenticator(authenticator, label.strip())
        except AuthenticatorError as error:
            QMessageBox.warning(
                self, "Couldn't add the key",
                f"{error}\n\nMake sure your security key is plugged in.")
            return
        except ValueError as error:  # already enrolled
            QMessageBox.warning(self, "Already enrolled", str(error))
            return
        except OSError as error:
            QMessageBox.critical(self, "Vault error",
                                 f"Could not save the vault:\n{error}")
            return
        self._refresh()

    def _remove(self) -> None:
        item = self.list.currentItem()
        cred_id = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not cred_id:
            return
        last = len(self.vault.list_authenticators()) == 1
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Remove security key")
        box.setText(
            "Remove the LAST security key? The vault will go back to "
            "opening with just the master password (no second factor)."
            if last else "Remove this security key from the vault?")
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        try:
            self.vault.remove_authenticator(cred_id)
        except (ValueError, OSError) as error:
            QMessageBox.warning(self, "Couldn't remove the key", str(error))
            return
        self._refresh()


def ensure_unlocked(vault: Vault, parent: QWidget | None = None) -> bool:
    """Unlock (or create) the vault interactively. True if usable."""
    if vault.unlocked:
        return True
    while True:
        dialog = UnlockDialog(vault, parent)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            return True
        # A "start over" reset deleted the vault; loop so the dialog reopens
        # in create mode and the user sets a new master password right away.
        if not dialog.reset_requested:
            return False


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

    # Emitted when the user clicks "Log out": the browser locks the vault and
    # closes this window (it owns the lock timer and the toolbar indicator).
    logout_requested = pyqtSignal()
    # Emitted with a saved entry's site so the browser can open it in a tab.
    open_site_requested = pyqtSignal(str)

    def __init__(self, vault: Vault, parent: QWidget | None = None,
                 current_site: str = ""):
        super().__init__(parent)
        self.vault = vault
        self.current_site = current_site
        self.setWindowTitle("Password Vault")
        self.resize(660, 440)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 12)
        layout.setSpacing(10)

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

        # Entry actions: modify the selection on the left, copy it on the
        # right, so the two kinds of action read as distinct groups.
        actions = QHBoxLayout()
        actions.setSpacing(6)
        for label, handler in (("Add", self._add),
                               ("Edit", self._edit),
                               ("Delete", self._delete)):
            btn = QPushButton(label)
            btn.clicked.connect(handler)
            actions.addWidget(btn)
        actions.addStretch()
        for label, handler in (("Go to site", self._go_to_site),
                               ("Copy username", self._copy_username),
                               ("Copy password", self._copy_password)):
            btn = QPushButton(label)
            btn.clicked.connect(handler)
            actions.addWidget(btn)
        layout.addLayout(actions)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(divider)

        # Footer: a "Manage" menu gathers the occasional vault-wide actions so
        # they don't crowd the everyday buttons; Log out sits apart on the far
        # right where a "leave" control is expected.
        footer = QHBoxLayout()
        footer.setSpacing(8)

        manage_btn = QPushButton("Manage")
        manage_btn.setToolTip("Security keys, master password, and CSV "
                              "import/export.")
        manage_menu = QMenu(manage_btn)
        keys_action = manage_menu.addAction(
            "Security keys…",
            lambda: SecurityKeysDialog(self.vault, self).exec())
        keys_action.setToolTip(
            "Add or remove a FIDO2 security key as a second factor for "
            "unlocking the vault.")
        manage_menu.addAction(
            "Change master password…",
            lambda: ChangeMasterDialog(self.vault, self).exec())
        manage_menu.addSeparator()
        manage_menu.addAction("Import from CSV…", self._import_csv)
        manage_menu.addAction("Export to CSV…", self._export_csv)
        manage_btn.setMenu(manage_menu)
        footer.addWidget(manage_btn)

        hint = QLabel(f"Copied passwords clear after "
                      f"{CLIPBOARD_CLEAR_SECONDS}s")
        hint.setStyleSheet("color: gray;")
        footer.addWidget(hint)

        footer.addStretch()

        logout_btn = QPushButton("🔒  Log out")
        logout_btn.setToolTip(
            "Lock the vault now and close this window (Ctrl+Shift+L).")
        logout_btn.clicked.connect(lambda: self.logout_requested.emit())
        footer.addWidget(logout_btn)

        layout.addLayout(footer)

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

    def _go_to_site(self) -> None:
        index = self._selected_index()
        if index is None:
            QMessageBox.information(self, "No login selected",
                                    "Select a saved login first.")
            return
        site = self.vault.entries()[index].site.strip()
        if site:
            self.open_site_requested.emit(site)

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
            _plain_warning(self, "Import failed",
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
        to_add = []
        for entry in entries:
            key = (normalize_site(entry.site), entry.username)
            if key in existing:
                continue
            existing.add(key)
            to_add.append(entry)
        added = self.vault.add_many(to_add)
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
            _plain_warning(self, "Export failed",
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
