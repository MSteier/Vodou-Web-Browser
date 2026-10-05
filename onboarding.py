"""First-run onboarding wizard: shown once, the very first time Vodou
launches on a machine. Introduces the search engine choice, theme, and
(on Windows) importing from an installed Chrome/Edge profile.

Persistence is a plain, unsigned marker file (`~/.vodou/onboarding.json`)
-- "has the wizard been shown" is not security-sensitive, the same
low-ceremony tier main.py's own prefs.json reserves for non-sensitive
settings. Written once the dialog closes, whether finished or skipped, so
this is strictly a once-ever prompt, never a nag on later launches.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

ONBOARDING_FILE = Path.home() / ".vodou" / "onboarding.json"


def is_first_run() -> bool:
    return not ONBOARDING_FILE.exists()


def mark_onboarding_done() -> None:
    try:
        ONBOARDING_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = ONBOARDING_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"completed": True}), encoding="utf-8")
        tmp.replace(ONBOARDING_FILE)
    except OSError:
        pass


class OnboardingDialog(QDialog):
    """Tightly coupled to BrowserWindow by nature -- unlike PluginsDialog/
    ExtensionsDialog, this isn't a reusable utility dialog, it's a one-off
    wizard over the window's own existing setting methods (_set_search_engine,
    _set_theme, _set_mode, import_from_browser), reused directly rather than
    re-implemented here."""

    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.setWindowTitle("Welcome to Vodou")
        self.resize(560, 420)
        self.setModal(True)

        layout = QVBoxLayout(self)
        self.stack = QStackedWidget()
        layout.addWidget(self.stack)
        self.stack.addWidget(self._welcome_page())
        self.stack.addWidget(self._search_engine_page())
        self.stack.addWidget(self._theme_page())
        self.stack.addWidget(self._import_page())
        self.stack.addWidget(self._finish_page())

        nav = QHBoxLayout()
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self._back)
        nav.addWidget(self.back_button)
        nav.addStretch()
        self.skip_button = QPushButton("Skip")
        self.skip_button.clicked.connect(self.accept)
        nav.addWidget(self.skip_button)
        self.next_button = QPushButton("Next")
        self.next_button.clicked.connect(self._on_next)
        nav.addWidget(self.next_button)
        layout.addLayout(nav)

        self._sync_nav()

    def _sync_nav(self) -> None:
        at_start = self.stack.currentIndex() == 0
        at_end = self.stack.currentIndex() == self.stack.count() - 1
        self.back_button.setEnabled(not at_start)
        self.skip_button.setVisible(not at_end)
        self.next_button.setText("Get started" if at_end else "Next")

    def _back(self) -> None:
        self.stack.setCurrentIndex(self.stack.currentIndex() - 1)
        self._sync_nav()

    def _on_next(self) -> None:
        if self.stack.currentIndex() == self.stack.count() - 1:
            self.accept()
        else:
            self.stack.setCurrentIndex(self.stack.currentIndex() + 1)
            self._sync_nav()

    @staticmethod
    def _page(title: str, body: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        heading = QLabel(title)
        heading.setStyleSheet("font-size:1.3rem; font-weight:600;")
        layout.addWidget(heading)
        text = QLabel(body)
        text.setTextFormat(Qt.TextFormat.PlainText)
        text.setWordWrap(True)
        layout.addWidget(text)
        layout.addStretch()
        return page

    def _welcome_page(self) -> QWidget:
        return self._page(
            "Welcome to Vodou",
            "Vodou is a privacy-first browser: an encrypted password vault, "
            "private search through your own local SearXNG instance, "
            "on-device AI summaries that never leave your machine, and no "
            "telemetry. The next few screens set up the basics — every one "
            "of them can be changed later from the ☰ menu.")

    def _search_engine_page(self) -> QWidget:
        from main import SEARCH_ENGINES
        page = self._page(
            "Choose a search engine",
            "This is what Vodou's address bar searches with. SearXNG "
            "(selected) runs locally and never shares your query with a "
            "third party.")
        listw = QListWidget()
        listw.addItems(SEARCH_ENGINES.keys())
        listw.setCurrentRow(0)
        listw.currentTextChanged.connect(
            lambda name: self.window._set_search_engine(SEARCH_ENGINES[name]))
        page.layout().insertWidget(page.layout().count() - 1, listw)
        return page

    def _theme_page(self) -> QWidget:
        from theme import THEMES
        page = self._page(
            "Pick a theme",
            "Changes apply immediately, so you can see it before deciding.")
        listw = QListWidget()
        listw.addItems(THEMES.keys())
        listw.setCurrentRow(0)
        listw.currentTextChanged.connect(self.window._set_theme)
        page.layout().insertWidget(page.layout().count() - 1, listw)

        mode_row = QHBoxLayout()
        dark = QPushButton("🌙  Dark mode")
        dark.clicked.connect(lambda: self.window._set_mode("dark"))
        light = QPushButton("☀  Light mode")
        light.clicked.connect(lambda: self.window._set_mode("light"))
        mode_row.addWidget(dark)
        mode_row.addWidget(light)
        page.layout().insertLayout(page.layout().count() - 1, mode_row)
        return page

    def _import_page(self) -> QWidget:
        if sys.platform == "win32":
            page = self._page(
                "Bring your bookmarks and passwords",
                "If you have Chrome or Edge installed, Vodou can import "
                "its bookmarks and saved passwords directly — no manual "
                "export needed. You can also do this later from the ☰ menu.")
            button = QPushButton("Import from Chrome/Edge…")
            button.clicked.connect(self.window.import_from_browser)
            page.layout().insertWidget(page.layout().count() - 1, button)
        else:
            page = self._page(
                "Bring your bookmarks and passwords",
                "Direct browser import is currently Windows-only. You can "
                "still bring bookmarks or passwords in from a .html/.csv "
                "export via the ☰ menu.")
        return page

    def _finish_page(self) -> QWidget:
        return self._page(
            "You're all set",
            "Everything here can be revisited any time from the ☰ menu — "
            "Settings for search/theme, Password vault… and Import from "
            "the Bookmarks/Passwords sections. Enjoy Vodou.")
