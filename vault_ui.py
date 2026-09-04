"""Dialogs for the password vault: unlock/create, manage entries, generator."""

from __future__ import annotations

import html
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (
    QActionGroup,
    QColor,
    QGuiApplication,
    QKeySequence,
    QPalette,
    QShortcut,
)
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

import password_strength
from authenticator import (
    AuthenticatorError,
    WindowsWebAuthnAuthenticator,
    webauthn_supported,
)
from icons import make_icon
from importers import parse_password_csv, write_password_csv
from safebrowsing import SafeBrowsing
from spoofcheck import inspect as spoof_inspect, registrable_domain
from vault_autolock import (
    DEFAULT_VAULT_AUTOLOCK_MINUTES,
    VAULT_AUTOLOCK_OPTIONS,
)
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

# Fixed, theme-independent colors for the strength verdict — deliberately
# not drawn from the live theme palette (like the WebAuthn warning below),
# since red/amber/green need to read as the same risk signal in every
# theme, the same way the address bar's security-pill lock icon does.
_STRENGTH_COLORS = {
    "Weak": "#e0384a",
    "Moderate": "#d9962b",
    "Strong": "#2fae72",
}

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


def add_reveal_toggle(edit: QLineEdit) -> None:
    """Put an eye icon inside the field's right edge that toggles the
    password between hidden (default) and visible. Each field toggles
    independently, the icon reflects the current state, and clicking it
    keeps typing focus. Shared by every dialog with a password field
    (UnlockDialog, EntryDialog, GeneratePasswordDialog) rather than each
    rolling its own show/hide control."""
    color = edit.palette().color(QPalette.ColorRole.Text).name()
    eye = make_icon("eye", color)          # open eye  -> currently visible
    eye_off = make_icon("eye-off", color)  # slashed   -> currently hidden
    action = edit.addAction(eye_off, QLineEdit.ActionPosition.TrailingPosition)
    action.setToolTip("Show password")
    action.setCheckable(True)

    def toggle(shown: bool) -> None:
        edit.setEchoMode(QLineEdit.EchoMode.Normal if shown
                         else QLineEdit.EchoMode.Password)
        action.setIcon(eye if shown else eye_off)
        action.setToolTip("Hide password" if shown else "Show password")
        edit.setFocus()  # a click on the icon must not steal typing focus

    action.toggled.connect(toggle)


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
        add_reveal_toggle(self.password_edit)
        form.addRow("Master password:", self.password_edit)

        self.confirm_edit = None
        if self.creating:
            self.confirm_edit = QLineEdit()
            self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
            add_reveal_toggle(self.confirm_edit)
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


class GeneratePasswordDialog(QDialog):
    """Standalone password generator, modeled on the reference generator at
    Password_Generator.html: a length control and three independently
    toggleable character types (at least one must stay on — matching the
    reference's own constraint), a live strength readout, and a copy
    button. Opened from EntryDialog's "Generate Strong Password" action;
    the caller reads the result back via password() once Accepted.

    Nothing here is saved anywhere — the candidate password exists only in
    this dialog and, if accepted, in the caller's password field, until the
    user explicitly saves the entry through the normal vault flow."""

    def __init__(self, parent: QWidget | None = None, length: int = 16):
        super().__init__(parent)
        self.setWindowTitle("Generate Password")
        self.setMinimumWidth(420)
        self._password = ""

        layout = QVBoxLayout(self)

        length_row = QHBoxLayout()
        length_label = QLabel("Length:")
        self.length_spin = QSpinBox()
        self.length_spin.setRange(4, 64)
        self.length_spin.setValue(length)
        self.length_spin.setAccessibleName("Password length")
        length_label.setBuddy(self.length_spin)
        length_row.addWidget(length_label)
        length_row.addWidget(self.length_spin)
        length_row.addStretch()
        layout.addLayout(length_row)

        # Matches the reference generator's three character-type toggles
        # exactly (mixed-case letters / numbers / punctuation).
        self.letters_check = QCheckBox("Letters (a–z, A–Z)")
        self.numbers_check = QCheckBox("Numbers (0–9)")
        self.symbols_check = QCheckBox("Punctuation (symbols)")
        for box in (self.letters_check, self.numbers_check,
                    self.symbols_check):
            box.setChecked(True)
            box.toggled.connect(self._on_type_toggled)
            layout.addWidget(box)

        out_row = QHBoxLayout()
        self.pass_edit = QLineEdit()
        self.pass_edit.setReadOnly(True)
        self.pass_edit.setAccessibleName("Generated password")
        add_reveal_toggle(self.pass_edit)
        out_row.addWidget(self.pass_edit)
        self.copy_btn = QPushButton("Copy")
        self.copy_btn.clicked.connect(self._copy)
        out_row.addWidget(self.copy_btn)
        layout.addLayout(out_row)

        self.strength_label = QLabel()
        self.strength_label.setWordWrap(True)
        self.strength_label.setAccessibleName("Generated password strength")
        layout.addWidget(self.strength_label)

        gen_btn = QPushButton("Generate password")
        gen_btn.clicked.connect(self._generate)
        layout.addWidget(gen_btn)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel)
        self.ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.setText("Use this password")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.length_spin.valueChanged.connect(self._generate)
        self._generate()  # a candidate is ready the moment the dialog opens

    def _on_type_toggled(self, _checked: bool = False) -> None:
        """At least one character type must stay on, exactly like the
        reference generator — refuse to leave every type off."""
        boxes = (self.letters_check, self.numbers_check, self.symbols_check)
        if not any(box.isChecked() for box in boxes):
            self.sender().setChecked(True)
            return
        self._generate()

    def _generate(self) -> None:
        pw = generate_password(
            self.length_spin.value(),
            letters=self.letters_check.isChecked(),
            numbers=self.numbers_check.isChecked(),
            symbols=self.symbols_check.isChecked())
        self._password = pw
        self.pass_edit.setText(pw)
        result = password_strength.analyze(pw)
        color = _STRENGTH_COLORS[result.label]
        self.strength_label.setText(
            f'<b style="color:{color}">{result.label}</b> '
            f'— about {result.bits:.0f} bits')

    def _copy(self) -> None:
        if self._password:
            _copy_with_auto_clear(self._password, self)

    def password(self) -> str:
        return self._password


class EntryDialog(QDialog):
    """Add or edit a single vault entry, with a live password-strength
    readout — including a same-password-as-another-saved-login check — and
    a one-click path to replacing a weak password: Generate Strong Password
    opens GeneratePasswordDialog and, if accepted, drops the result
    straight into the password field below — nothing is saved to the vault
    until Save is pressed."""

    def __init__(self, parent: QWidget | None = None,
                 entry: Entry | None = None, site: str = "",
                 other_entries: list[Entry] | None = None):
        super().__init__(parent)
        self.setWindowTitle("Edit Entry" if entry else "Add Entry")
        self.setMinimumWidth(440)
        # Every OTHER saved entry, password already revealed by the caller
        # (VaultDialog._reveal_all) — used only to check this field against
        # them live; never displayed itself, never written anywhere.
        self._other_entries = other_entries or []

        form = QFormLayout()
        self.site_edit = QLineEdit(entry.site if entry else site)
        self.user_edit = QLineEdit(entry.username if entry else "")
        self.pass_edit = QLineEdit(entry.password if entry else "")
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_edit.setAccessibleName("Password")
        add_reveal_toggle(self.pass_edit)
        self.pass_edit.textChanged.connect(self._update_strength)
        self.notes_edit = QLineEdit(entry.notes if entry else "")

        form.addRow("Site (domain):", self.site_edit)
        form.addRow("Username:", self.user_edit)
        form.addRow("Password:", self.pass_edit)

        self.strength_label = QLabel()
        self.strength_label.setWordWrap(True)
        self.strength_label.setAccessibleName("Password strength")
        form.addRow(self.strength_label)

        gen_btn = QPushButton("Generate Strong Password…")
        gen_btn.setToolTip(
            "Open the password generator and replace this password with a "
            "freshly generated one — it only fills the field below; Save "
            "still has to be pressed to keep it.")
        gen_btn.clicked.connect(self._open_generator)
        form.addRow(gen_btn)

        form.addRow("Notes:", self.notes_edit)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._submit)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._update_strength()

    def _reused_sites(self) -> list[str]:
        """Other saved entries' sites whose password matches this field's
        current text exactly. Empty text never counts as a match, and
        entries on the same registrable domain as this one are excluded —
        the same login on another hostname of the same site isn't reuse
        (matches the dashboard's Strength column; see _refresh)."""
        pw = self.pass_edit.text()
        if not pw:
            return []
        mine = registrable_domain(normalize_site(self.site_edit.text()))
        return [e.site for e in self._other_entries
                if e.password == pw
                and registrable_domain(normalize_site(e.site)) != mine]

    def _update_strength(self) -> None:
        result = password_strength.analyze(self.pass_edit.text())
        reused_sites = self._reused_sites()
        # A reused password is flagged in the same red as Weak regardless of
        # its own entropy — reuse is a real risk (one breach exposes every
        # site sharing it) that a high bit-count doesn't cancel out.
        color = _STRENGTH_COLORS["Weak"] if reused_sites \
            else _STRENGTH_COLORS[result.label]
        text = f'<b style="color:{color}">{result.label}</b>'
        if result.bits:
            text += f" — about {result.bits:.0f} bits"
        reasons = list(result.reasons)
        if reused_sites:
            shown = ", ".join(html.escape(s) for s in reused_sites[:5])
            if len(reused_sites) > 5:
                shown += f", and {len(reused_sites) - 5} more"
            reasons.append(f"Also the password for: {shown}.")
        if reasons:
            text += "<br>" + "<br>".join(reasons)
        self.strength_label.setText(text)

    def _open_generator(self) -> None:
        dialog = GeneratePasswordDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.pass_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.pass_edit.setText(dialog.password())

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


def _is_current_site(site: str, current: str) -> bool:
    """True when a stored login's `site` belongs to the same site as the
    page the user is currently on (`current`).

    Both are reduced to a bare domain with normalize_site (drops scheme, path
    and a leading "www."), then matched symmetrically so a login saved for the
    parent domain matches on a subdomain and vice-versa:

        current=replica.com      site=replica.com       -> equal
        current=www.replica.com  site=replica.com       -> equal (www stripped)
        current=app.replica.com  site=replica.com       -> current under site
        current=replica.com      site=app.replica.com   -> site under current

    Kept deliberately conservative (a label-boundary suffix, no public-suffix
    list) so unrelated hosts that merely share a suffix are not grouped.
    """
    site = normalize_site(site)
    current = normalize_site(current)
    if not site or not current:
        return False
    return (current == site
            or current.endswith("." + site)
            or site.endswith("." + current))


def prioritize_by_site(matches: list[tuple[int, Entry]],
                       current_site: str) -> list[tuple[int, Entry]]:
    """Reorder (index, Entry) pairs so logins for `current_site` come first.

    A stable sort: current-site matches keep their relative order and so do the
    rest, so this only lifts the matches to the top — it never filters, and with
    no detectable current site it leaves the order untouched. Returns a new
    list; the input is not mutated.
    """
    if not normalize_site(current_site):
        return list(matches)
    return sorted(matches,
                  key=lambda pair: not _is_current_site(pair[1].site,
                                                        current_site))


def two_factor_state(factor_enrolled: bool, webauthn_available: bool) -> dict:
    """UI state for the two-factor switch, computed with no Qt or hardware so it
    can be unit-tested.

    * checked  — the switch reads as ON exactly when a security key is enrolled.
    * enabled  — you can always turn it OFF; you can only turn it ON where
                 WebAuthn/security keys are actually usable. So an off switch on
                 a system that can't run WebAuthn is disabled rather than a dead
                 control that would go nowhere.
    * tooltip  — a short explanation of the current state.
    """
    checked = bool(factor_enrolled)
    enabled = bool(factor_enrolled or webauthn_available)
    if checked:
        tooltip = ("On — the vault needs your master password AND a registered "
                   "security key. Click to turn off (removes all keys).")
    elif webauthn_available:
        tooltip = ("Off — click to also require a security key alongside your "
                   "master password.")
    else:
        tooltip = ("Off — turning this on needs a FIDO2 security key, and none "
                   "can be used here.")
    return {"checked": checked, "enabled": enabled, "tooltip": tooltip}


class VaultDialog(QDialog):
    """Table view of all saved logins with add/edit/delete/copy."""

    # Emitted when the user clicks "Log out": the browser locks the vault and
    # closes this window (it owns the lock timer and the toolbar indicator).
    logout_requested = pyqtSignal()
    # Emitted with a saved entry's site so the browser can open it in a tab.
    open_site_requested = pyqtSignal(str)
    # Emitted when the user picks a different auto-lock duration; the browser
    # owns the lock timer, so it applies and persists the new value.
    autolock_minutes_changed = pyqtSignal(int)

    # Column indices, named so the row-building loop and the click handler
    # below don't scatter magic numbers.
    COL_WEBSITE, COL_SAFETY, COL_USERNAME, COL_PASSWORD, \
        COL_STRENGTH, COL_DUPLICATE, COL_LAST_CHANGED = range(7)

    # Fixed-width placeholder — deliberately NOT sized to the real password's
    # length, so glancing at a masked row leaks nothing about it.
    _MASKED_PASSWORD = "•" * 12

    def __init__(self, vault: Vault, parent: QWidget | None = None,
                 current_site: str = "",
                 autolock_minutes: int = DEFAULT_VAULT_AUTOLOCK_MINUTES,
                 safe_browsing: "SafeBrowsing | None" = None):
        super().__init__(parent)
        self.vault = vault
        self.current_site = current_site
        self._autolock_minutes = autolock_minutes
        # Optional: lets the Website Safety column also check Vodou's local
        # malicious-site list, not just the always-available spoof heuristic.
        # None (e.g. in a caller that hasn't wired it up) just means that
        # column falls back to the spoof-only verdict.
        self._safe_browsing = safe_browsing
        self.setWindowTitle("Password Vault")
        # Wider than the old 4-column layout's default — seven columns need
        # the room, and only Website stretches (see below). 980px (the old
        # width) left Duplicated and Last Changed past the edge even with no
        # search filter narrowing anything; ~1300px is the smallest width
        # that fits all seven at their natural ResizeToContents widths.
        self.resize(1300, 480)

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

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "Website", "Website Safety", "Username/Email", "Password",
            "Strength", "Duplicated", "Last Changed"])
        # Only Website stretches to fill leftover space; every other column
        # sizes to its own content. Two stretch columns (the old Site +
        # Username split) fought each other for space once there were seven
        # columns instead of four, pushing Password/Strength/Duplicated/Last
        # Changed past the right edge even in a wide window.
        # Every column sizes to its own content — no Stretch column at all.
        # Stretch (tried for Website alone, so the table wouldn't leave dead
        # space in a wide window) turned out to compute its share
        # incorrectly against a real window's actual layout despite sizing
        # correctly in an offscreen test, silently pushing Duplicated/Last
        # Changed off-screen even at the dialog's own default width. A little
        # unused space to the right of Last Changed in a wide window is a
        # far smaller cost than columns disappearing.
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.doubleClicked.connect(lambda _: self._edit())
        self.table.cellClicked.connect(self._on_cell_clicked)
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
        manage_btn.setToolTip("Vault security, auto-lock, and CSV "
                              "import/export.")
        manage_menu = QMenu(manage_btn)
        # Grouped into three labelled sections — Security, Auto-lock, Data — so
        # the occasional vault-wide actions read as an organised settings menu
        # rather than a flat list.

        # --- Security -----------------------------------------------------
        security_header = manage_menu.addAction("Security")
        security_header.setEnabled(False)  # non-clickable section caption

        self._two_factor_action = manage_menu.addAction(
            "Two-factor (security key)")
        self._two_factor_action.setCheckable(True)
        self._two_factor_action.triggered.connect(self._on_two_factor_triggered)

        keys_action = manage_menu.addAction(
            "Security keys…", self._manage_security_keys)
        keys_action.setToolTip(
            "Add a backup key or remove an individual key. The two-factor "
            "switch above is the quick way to turn it all on or off.")
        manage_menu.addAction(
            "Change master password…",
            lambda: ChangeMasterDialog(self.vault, self).exec())

        # --- Auto-lock ----------------------------------------------------
        manage_menu.addSeparator()
        autolock_menu = manage_menu.addMenu("Auto-lock vault")
        autolock_menu.setToolTip(
            "How long the unlocked vault waits, idle, before it re-locks.")
        self._autolock_group = QActionGroup(autolock_menu)
        self._autolock_group.setExclusive(True)
        for minutes, label in VAULT_AUTOLOCK_OPTIONS:
            option = autolock_menu.addAction(label)
            option.setCheckable(True)
            option.setChecked(minutes == self._autolock_minutes)
            self._autolock_group.addAction(option)
            option.triggered.connect(
                lambda _checked, m=minutes: self._choose_autolock(m))
        autolock_menu.addSeparator()
        caution = autolock_menu.addAction(
            "⚠  Longer windows keep the vault key in memory longer")
        caution.setEnabled(False)  # inline caution, not an action

        # --- Data ---------------------------------------------------------
        manage_menu.addSeparator()
        manage_menu.addAction("Import from CSV…", self._import_csv)
        manage_menu.addAction("Export to CSV…", self._export_csv)
        dedup_action = manage_menu.addAction(
            "Remove duplicate logins…", self._remove_duplicates)
        dedup_action.setToolTip(
            "Find logins saved more than once (same site, username, and "
            "password) and remove the extra copies, keeping the oldest.")

        manage_btn.setMenu(manage_menu)
        footer.addWidget(manage_btn)
        self._sync_two_factor_action()  # reflect the real 2FA state on open

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

    def _reveal_all(self) -> list[tuple[int, Entry]]:
        """(index, Entry-with-real-password) for every saved entry, each
        decrypted only for the instant needed to build it — the same
        on-demand reveal() the rest of the vault already uses for fill/copy/
        edit, just looped over everything once per refresh. Backs the
        Strength/reuse column below and the editor's own reuse check;
        skips (rather than raising for) any index reveal() can't handle, so
        a vault stand-in without it, or a genuinely locked vault, can't
        break the list."""
        revealed = []
        for i, meta in enumerate(self.vault.entries()):
            try:
                password = self.vault.reveal(i)
            except Exception:
                continue
            revealed.append((i, Entry(site=meta.site, username=meta.username,
                                      password=password, notes=meta.notes)))
        return revealed

    def _refresh(self) -> None:
        # Strength + cross-entry reuse both need every password decrypted
        # once; computed here, up front, so the loop below just looks them
        # up per row instead of re-decrypting on every keystroke of a search.
        revealed = self._reveal_all()
        strength_by_index = {i: password_strength.analyze(e.password)
                             for i, e in revealed}
        # Reuse is only flagged across DIFFERENT registrable domains: one
        # account reached through several hostnames of the same site
        # (idmsa.apple.com / account.apple.com, a bank's bare and "online."
        # domains) shares a password by design, not by carelessness. The
        # {index: registrable domain} map lets group_reused drop those.
        reg_domain_by_index = {i: registrable_domain(normalize_site(e.site))
                               for i, e in revealed}
        reused_counts = password_strength.group_reused(
            [(i, e.password) for i, e in revealed], reg_domain_by_index)
        # For each reused index, name the OTHER sites it's reused with (not
        # just a bare count) so the tooltip can be verified against what's
        # actually saved, rather than asking the user to take the count on
        # faith. Only sites on a different registrable domain are listed —
        # same-domain siblings aren't reuse and would just be noise. Cheap
        # here: at most the vault's own entry count squared, and only for
        # entries group_reused already flagged.
        reused_sites_by_index = {
            i: [e2.site for j, e2 in revealed
                if j != i and e2.password == e.password
                and reg_domain_by_index[j] != reg_domain_by_index[i]]
            for i, e in revealed if i in reused_counts}

        # Exact-duplicate groups (site + username + password all match) --
        # a separate, stricter concern from reuse: see vault.py's
        # find_duplicate_groups docstring.
        dup_indices = {i for group in self.vault.find_duplicate_groups()
                       for i in group}

        # Rows carry the entry's true vault index in UserRole, so edit /
        # delete / copy keep working on a filtered view.
        query = self.search_edit.text().strip().lower()
        matches = [(i, e) for i, e in enumerate(self.vault.entries())
                   if not query
                   or query in e.site.lower()
                   or query in e.username.lower()
                   or query in e.notes.lower()]
        # Float logins for the site the user is currently on to the top, keeping
        # everything else in its existing order (a no-op when there's no current
        # site). Applied after the search filter, so it reorders whatever the
        # current search shows rather than fighting it.
        matches = prioritize_by_site(matches, self.current_site)
        self.table.setRowCount(len(matches))
        for row, (i, e) in enumerate(matches):
            website_item = QTableWidgetItem(e.site)
            self.table.setItem(row, self.COL_WEBSITE, website_item)

            self.table.setItem(row, self.COL_SAFETY, self._safety_item(e.site))

            self.table.setItem(
                row, self.COL_USERNAME, QTableWidgetItem(e.username))

            password_item = QTableWidgetItem(self._MASKED_PASSWORD)
            password_item.setToolTip("Click to show or hide this password.")
            password_item.setData(Qt.ItemDataRole.UserRole + 1, False)
            self.table.setItem(row, self.COL_PASSWORD, password_item)

            self.table.setItem(row, self.COL_STRENGTH, self._strength_item(
                strength_by_index.get(i), reused_counts.get(i),
                reused_sites_by_index.get(i)))

            self.table.setItem(
                row, self.COL_DUPLICATE, self._duplicate_item(i in dup_indices))

            self.table.setItem(row, self.COL_LAST_CHANGED,
                               QTableWidgetItem(e.updated or "—"))

            # Every cell in the row carries the true vault index, regardless
            # of column, so selection/edit/delete/copy and the password-
            # reveal click handler all key off the same value.
            for col in range(self.table.columnCount()):
                self.table.item(row, col).setData(Qt.ItemDataRole.UserRole, i)

    def _strength_item(self, result: "password_strength.StrengthResult | None",
                       reused_count: int | None,
                       reused_sites: list[str] | None = None) -> QTableWidgetItem:
        """The Strength column's cell for one entry, from an already-computed
        result (see _refresh/_reveal_all) — never decrypts anything itself.
        `result` is None only when that entry's reveal() failed."""
        if result is None:
            return QTableWidgetItem("—")
        text = result.label
        tooltip_lines = list(result.reasons)
        color = _STRENGTH_COLORS[result.label]
        if reused_count:
            text += f" · Reused ({reused_count}×)"
            color = _STRENGTH_COLORS["Weak"]
            # Name the actual other logins sharing this password, not just a
            # count — lets the user verify the flag against what's really
            # saved instead of taking it on faith.
            shown = ", ".join(html.escape(s) for s in (reused_sites or [])[:5])
            if reused_sites and len(reused_sites) > 5:
                shown += f", and {len(reused_sites) - 5} more"
            tooltip_lines.append(
                (f"Same password also saved for: {shown}." if shown else
                 f"The same password is used for {reused_count} saved "
                 f"logins") + " — give each site its own password.")
        item = QTableWidgetItem(text)
        item.setForeground(QColor(color))
        if tooltip_lines:
            item.setToolTip("\n".join(tooltip_lines))
        return item

    def _safety_item(self, site: str) -> QTableWidgetItem:
        """The Website Safety column's cell: Vodou's own local, no-network
        checks (spoofcheck's homograph/typosquat heuristic, plus the
        malicious-site list when a SafeBrowsing instance was supplied) run
        against the saved site — the same signals the address bar and
        "Check this site" AI feature already use, not a live scan or
        antivirus check. Honest about that limit in the tooltip rather than
        implying more certainty than a local heuristic can offer."""
        host = normalize_site(site)
        if not host:
            return QTableWidgetItem("—")
        if self._safe_browsing is not None \
                and self._safe_browsing.is_dangerous(host) is not None:
            item = QTableWidgetItem("🛑 Malicious")
            item.setForeground(QColor(_STRENGTH_COLORS["Weak"]))
            item.setToolTip(
                "This address matches Vodou's local list of known "
                "malicious/phishing sites.")
            return item
        verdict = spoof_inspect(host)
        if verdict is not None:
            item = QTableWidgetItem("⚠ Possible spoof")
            item.setForeground(QColor(_STRENGTH_COLORS["Moderate"]))
            item.setToolTip(verdict.detail)
            return item
        item = QTableWidgetItem("OK")
        item.setForeground(QColor(_STRENGTH_COLORS["Strong"]))
        item.setToolTip(
            "No look-alike-address or malicious-list match found. This is a "
            "local heuristic check, not a live scan or antivirus lookup.")
        return item

    def _duplicate_item(self, is_duplicate: bool) -> QTableWidgetItem:
        """The Duplicated column's cell: whether this entry is part of an
        exact-match group (same site + username + password) from
        Vault.find_duplicate_groups() — distinct from the Strength column's
        cross-site reuse badge. See "Remove duplicate logins…" in Manage."""
        if not is_duplicate:
            return QTableWidgetItem("—")
        item = QTableWidgetItem("Duplicate")
        item.setForeground(QColor(_STRENGTH_COLORS["Weak"]))
        item.setToolTip(
            "Another saved login has the exact same site, username, and "
            "password. Manage → Remove duplicate logins… cleans these up.")
        return item

    def _on_cell_clicked(self, row: int, column: int) -> None:
        """Toggle one row's Password cell between masked and revealed.
        Independent per row; a fresh _refresh() (search, edit, add, delete)
        always re-masks everything rather than carrying reveal state
        forward, so a shown password doesn't linger past the moment that
        made it relevant."""
        if column != self.COL_PASSWORD:
            return
        item = self.table.item(row, column)
        if item is None:
            return
        index = item.data(Qt.ItemDataRole.UserRole)
        shown = bool(item.data(Qt.ItemDataRole.UserRole + 1))
        if shown:
            item.setText(self._MASKED_PASSWORD)
            item.setData(Qt.ItemDataRole.UserRole + 1, False)
            return
        try:
            item.setText(self.vault.reveal(index))
        except Exception:
            return
        item.setData(Qt.ItemDataRole.UserRole + 1, True)

    def set_current_site(self, site: str) -> None:
        """Update which site counts as "current" and re-prioritize the list.

        Called by the browser when the active tab or its URL changes while this
        (modeless) window is open, so the current-site logins stay at the top.
        """
        site = site or ""
        if site == self.current_site:
            return
        self.current_site = site
        self._refresh()

    # -- security & auto-lock menu ---------------------------------------

    def _choose_autolock(self, minutes: int) -> None:
        """User picked an auto-lock duration. The browser owns the timer, so
        just remember it here and ask the browser to apply and persist it."""
        if minutes == self._autolock_minutes:
            return
        self._autolock_minutes = minutes
        self.autolock_minutes_changed.emit(minutes)

    def _manage_security_keys(self) -> None:
        """Open the security-keys manager, then re-sync the two-factor switch:
        adding the first key or removing the last one flips 2FA on/off."""
        SecurityKeysDialog(self.vault, self).exec()
        self._sync_two_factor_action()

    def _on_two_factor_triggered(self, _checked: bool = False) -> None:
        """The two-factor switch was clicked. Act on the vault's REAL state,
        not the transient check state: with no key enrolled, turning it on runs
        the security-key enroll flow; with keys enrolled, turning it off removes
        every key (after a confirm). The check mark is then re-synced to what
        actually happened, so the switch never lies."""
        if not self.vault.factor_enrolled:
            SecurityKeysDialog(self.vault, self).exec()
        elif self._confirm_disable_two_factor():
            self._disable_two_factor()
        self._sync_two_factor_action()

    def _confirm_disable_two_factor(self) -> bool:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Turn off two-factor")
        box.setText(
            "Remove every enrolled security key and go back to opening the "
            "vault with just the master password?\n\n"
            "You can turn two-factor back on later, but you'll need to "
            "re-enroll your keys.")
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        return box.exec() == QMessageBox.StandardButton.Yes

    def _disable_two_factor(self) -> None:
        """Remove all enrolled keys. Reuses vault.remove_authenticator (removing
        the last key reverts the vault to password-only) — no new crypto here."""
        try:
            for record in self.vault.list_authenticators():
                self.vault.remove_authenticator(record["cred_id"])
        except (ValueError, OSError) as error:
            QMessageBox.warning(self, "Couldn't turn off two-factor",
                                str(error))

    def _sync_two_factor_action(self) -> None:
        """Make the switch reflect the vault's real second-factor state (and
        whether it can be turned on here)."""
        available, _why = webauthn_supported()
        state = two_factor_state(self.vault.factor_enrolled, available)
        action = self._two_factor_action
        action.blockSignals(True)  # setChecked must not re-fire triggered
        action.setChecked(state["checked"])
        action.blockSignals(False)
        action.setEnabled(state["enabled"])
        action.setToolTip(state["tooltip"])

    def _selected_index(self) -> int | None:
        items = self.table.selectedItems()
        if not items:
            return None
        return items[0].data(Qt.ItemDataRole.UserRole)

    def _add(self) -> None:
        others = [e for _, e in self._reveal_all()]
        dialog = EntryDialog(self, site=self.current_site,
                             other_entries=others)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.vault.add(dialog.result_entry())
            self._refresh()

    def _edit(self) -> None:
        index = self._selected_index()
        if index is None:
            return
        entry = self.vault.entries()[index]
        entry.password = self.vault.reveal(index)  # decrypt only for editing
        others = [e for i, e in self._reveal_all() if i != index]
        dialog = EntryDialog(self, entry=entry, other_entries=others)
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

    def _remove_duplicates(self) -> None:
        groups = self.vault.find_duplicate_groups()
        if not groups:
            QMessageBox.information(
                self, "No duplicates found",
                "Every saved login is unique — there's nothing to remove.")
            return
        extra = sum(len(group) - 1 for group in groups)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Remove duplicate logins")
        box.setText(
            f"Found {len(groups)} login{'s' if len(groups) != 1 else ''} "
            f"saved more than once (same site, username, and password) — "
            f"{extra} extra cop{'y' if extra == 1 else 'ies'} in total.\n\n"
            f"Keep one copy of each and remove the rest? Notes on a "
            f"removed copy are kept by merging them into the copy that "
            f"stays.")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        removed = self.vault.remove_duplicates()
        self._refresh()
        QMessageBox.information(
            self, "Duplicates removed",
            f"Removed {removed} duplicate login{'s' if removed != 1 else ''}.")

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
