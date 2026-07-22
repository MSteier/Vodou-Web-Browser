"""Dialog for managing cookie exceptions (sites whose cookies persist)."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QVBoxLayout,
)

from cookies import CookieKeeper
from vault import normalize_site


class CookieSitesDialog(QDialog):
    """Edit the list of sites whose cookies survive between sessions."""

    def __init__(self, sites: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Cookie exceptions")
        self.setMinimumWidth(420)

        outer = QVBoxLayout(self)
        intro = QLabel(
            "Cookies normally live in memory only and are erased when "
            "Vodou closes. Sites listed here are the exception: their "
            "cookies are saved (encrypted) and restored on the next start, "
            "so logins and site settings survive.\n\n"
            "Add a bare domain like  youtube.com  — subdomains are "
            "included. Sign-in cookies sometimes live on a parent or "
            "sibling domain (e.g. YouTube logins live on google.com).")
        intro.setTextFormat(Qt.TextFormat.PlainText)
        intro.setWordWrap(True)
        outer.addWidget(intro)

        # "saved (encrypted)" above is a promise Vodou keeps by not saving at
        # all when it can't encrypt. Say so here rather than let the list look
        # like it is working.
        problem = CookieKeeper.keystore_problem()
        if problem:
            warning = QLabel(
                "Cookie keeping is unavailable on this system, so nothing "
                f"below will be saved: {problem}.\n\n"
                "Vodou stores the jar's key in your desktop keyring and "
                "won't write cookies without it. Installing a keyring "
                "service (GNOME Keyring or KWallet) enables this.")
            warning.setTextFormat(Qt.TextFormat.PlainText)
            warning.setWordWrap(True)
            warning.setStyleSheet("font-weight: 600;")
            outer.addWidget(warning)

        self.listing = QListWidget()
        self.listing.addItems(sorted(set(sites)))
        outer.addWidget(self.listing)

        add_row = QHBoxLayout()
        self.site_edit = QLineEdit()
        self.site_edit.setPlaceholderText("example.com")
        self.site_edit.returnPressed.connect(self._add)
        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self._add)
        remove_btn = QPushButton("Remove selected")
        remove_btn.clicked.connect(self._remove)
        add_row.addWidget(self.site_edit, 1)
        add_row.addWidget(add_btn)
        add_row.addWidget(remove_btn)
        outer.addLayout(add_row)

        self._feedback = QLabel("")
        self._feedback.setTextFormat(Qt.TextFormat.PlainText)
        self._feedback.setStyleSheet("color: gray;")
        outer.addWidget(self._feedback)

        buttons = QHBoxLayout()
        buttons.addStretch()
        ok = QPushButton("Save")
        ok.setDefault(True)
        ok.clicked.connect(self.accept)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(ok)
        buttons.addWidget(cancel)
        outer.addLayout(buttons)

    def _add(self, *_args) -> None:
        # normalize_site strips scheme/path/www; also drop an accidental
        # :port ("localhost:8081" -> "localhost"), since cookie domains
        # never carry a port.
        site = normalize_site(self.site_edit.text()).split(":")[0]
        # Accept any real host: a dotted domain, a bare name like
        # "localhost", or an IP. Reject only empties and whitespace/garbage
        # (the earlier "must contain a dot" rule wrongly dropped localhost).
        if not site or any(c.isspace() for c in site) or "/" in site:
            self._feedback.setText(
                "Enter a hostname like  youtube.com  or  localhost")
            self.site_edit.setFocus()
            return
        existing = {self.listing.item(i).text()
                    for i in range(self.listing.count())}
        if site not in existing:
            self.listing.addItem(site)
            self.listing.sortItems()
            self._feedback.setText(f"Added {site}")
        else:
            self._feedback.setText(f"{site} is already listed")
        self.site_edit.clear()
        self.site_edit.setFocus()

    def _remove(self) -> None:
        for item in self.listing.selectedItems():
            self.listing.takeItem(self.listing.row(item))

    def sites(self) -> list[str]:
        return [self.listing.item(i).text()
                for i in range(self.listing.count())]
