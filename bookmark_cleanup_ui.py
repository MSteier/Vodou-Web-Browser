"""Explicit scan, review, selection and confirmation for bookmark cleanup."""
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QDialog, QHBoxLayout, QHeaderView, QLabel,
                            QMessageBox, QPushButton, QTableWidget,
                            QTableWidgetItem, QTextEdit, QVBoxLayout)

from ai_search import load_config
from bookmark_cleanup import BookmarkScanner


class BookmarkCleanupDialog(QDialog):
    def __init__(self, store, parent=None, open_url=None):
        super().__init__(parent)
        self.store, self.open_url = store, open_url
        self.scanner = None
        self.results = []
        self.setWindowTitle("Review bookmarks with local AI")
        self.resize(940, 600)
        layout = QVBoxLayout(self)
        label = QLabel("Scan visits your bookmarked websites without browser login cookies. "
                       "Your local Ollama model compares page text with the saved title and URL. "
                       "Suspected failures are checked up to three times. Sites requesting a longer wait "
                       "are left for a later scan. Nothing is removed during scanning.")
        label.setWordWrap(True)
        self.explanation = label
        layout.addWidget(label)
        self.status = QLabel("Ready. Local AI uses the model selected in AI settings.")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Remove", "Saved title", "Result", "Saved URL"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for column, width in enumerate((65, 220, 240)):
            self.table.setColumnWidth(column, width)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._details)
        self.table.itemChanged.connect(self._selection)
        layout.addWidget(self.table)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(140)
        layout.addWidget(self.details)
        row = QHBoxLayout()
        self.scan = QPushButton("Scan bookmarks")
        self.scan.clicked.connect(self._start)
        self.stop = QPushButton("Stop scan")
        self.stop.setEnabled(False)
        self.stop.clicked.connect(self._stop)
        self.open = QPushButton("Open saved bookmark")
        self.open.clicked.connect(self._open)
        self.open.setEnabled(open_url is not None)
        self.remove = QPushButton("Remove checked…")
        self.remove.setEnabled(False)
        self.remove.clicked.connect(self._remove)
        close = QPushButton("Close")
        close.clicked.connect(self.reject)
        for button in (self.scan, self.stop, self.open, self.remove, close):
            row.addWidget(button)
        layout.addLayout(row)
        self.finished.connect(lambda _: self._cancel())
        self.confirmation_note = "AI suggestions can be wrong."

    def _start(self):
        self._cancel()
        self.results = []
        self.table.setRowCount(0)
        self.details.clear()
        self.remove.setEnabled(False)
        self.scan.setEnabled(False)
        self.stop.setEnabled(True)
        cfg = load_config()
        self.status.setText(f"Starting local review with {cfg['model']}…")
        self.scanner = BookmarkScanner(self, config=cfg)
        self.scanner.result.connect(self._result)
        self.scanner.progress.connect(self.status.setText)
        self.scanner.finished.connect(self._finished)
        self.scanner.start(self.store.all())

    def _cancel(self):
        if self.scanner:
            self.scanner.cancel()
            self.scanner.deleteLater()
            self.scanner = None

    def _stop(self):
        self._cancel()
        self._finished("Scan stopped. Completed results remain available for review.")

    def _finished(self, message="Scan complete. Review the evidence and check only bookmarks you want removed."):
        self.scan.setEnabled(True)
        self.stop.setEnabled(False)
        self.status.setText(message)
        self._selection()

    def _result(self, result):
        row = len(self.results)
        self.results.append(result)
        self.table.insertRow(row)
        check = QTableWidgetItem()
        check.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsSelectable)
        check.setCheckState(Qt.CheckState.Unchecked)
        self.table.setItem(row, 0, check)
        for col, text in enumerate((result.bookmark.title, result.status, result.bookmark.url), 1):
            self.table.setItem(row, col, QTableWidgetItem(text))

    def _checked(self):
        return [r.bookmark for i, r in enumerate(self.results)
                if self.table.item(i, 0) is not None
                and self.table.item(i, 0).checkState() == Qt.CheckState.Checked]

    def _selection(self):
        self.remove.setEnabled(not (self.scanner and self.scanner.busy) and bool(self._checked()))

    def _details(self):
        index = self.table.currentRow()
        if 0 <= index < len(self.results):
            r = self.results[index]
            self.details.setPlainText(f"{r.status}\n{r.detail}\n"
                                      f"Destination: {r.final_url or r.bookmark.url}\nChecks: {r.attempts}")

    def _open(self):
        index = self.table.currentRow()
        if self.open_url and 0 <= index < len(self.results):
            self.open_url(self.results[index].bookmark.url)

    def _remove(self):
        if self.scanner and self.scanner.busy:
            return
        selected = self._checked()
        if not selected:
            return
        box = QMessageBox(self)
        box.setWindowTitle("Confirm bookmark removal")
        box.setIcon(QMessageBox.Icon.Question)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(f"Permanently remove these {len(selected)} checked bookmarks? "
                    f"{self.confirmation_note} Use Show Details to review the full list.")
        box.setDetailedText("\n\n".join(f"{b.title}\n{b.url}" for b in selected))
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        try:
            removed = self.store.remove_reviewed(selected)
        except OSError:
            self.status.setText("Could not save bookmarks. Nothing was removed; check folder permissions.")
            return
        self.status.setText(f"Removed {removed} bookmarks. Entries edited since the scan were kept.")
        for row in range(self.table.rowCount()):
            self.table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)
        # Reflect actual store deletions in the results, not just the saved file.
        for row in range(len(self.results) - 1, -1, -1):
            if not self.store.contains(self.results[row].bookmark.url):
                self.table.removeRow(row)
                self.results.pop(row)
        self.details.clear()
        self._selection()
