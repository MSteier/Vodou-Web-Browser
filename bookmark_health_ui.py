"""Broken-only health review dialog. Independent of the local-AI review feature:
no import of ai_search.py or bookmark_cleanup(_ui).py, no Ollama dependency."""
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtWidgets import (QApplication, QDialog, QDoubleSpinBox, QHBoxLayout, QHeaderView,
                             QLabel, QMessageBox, QPushButton, QSpinBox, QTableWidget,
                             QTableWidgetItem, QTextEdit, QVBoxLayout)

from bookmark_health import DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT_SECONDS, HealthCheckWorker


class BookmarkHealthDialog(QDialog):
    def __init__(self, store, parent=None, open_url=None):
        super().__init__(parent)
        self.store, self.open_url = store, open_url
        self.scanner = None
        self.results = []
        self.checked = self.total = 0
        self.scan_error = ''
        self.setWindowTitle('Check Bookmarks')
        self.resize(940, 600)
        layout = QVBoxLayout(self)
        label = QLabel('Check bookmarked links with HEAD, then retry failures with GET. '
                       'Rate-limited or overloaded servers are backed off and retried rather '
                       'than reported broken immediately. Only failed links appear below. '
                       'A failure does not mean permanent removal: outages, expired certificates '
                       'and login restrictions are also listed. Nothing is deleted until you '
                       'select entries and confirm Delete Selected.')
        label.setWordWrap(True)
        layout.addWidget(label)
        self.status = QLabel('Ready. Checks run in the background; no AI model is required.')
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)
        options = QHBoxLayout()
        options.addWidget(QLabel('Timeout per request (seconds):'))
        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(.1, 120)
        self.timeout.setValue(DEFAULT_TIMEOUT_SECONDS)
        options.addWidget(self.timeout)
        options.addWidget(QLabel('Concurrent checks:'))
        self.concurrency = QSpinBox()
        self.concurrency.setRange(1, 64)
        self.concurrency.setValue(DEFAULT_CONCURRENCY)
        options.addWidget(self.concurrency)
        select_all = QPushButton('Select all')
        select_all.clicked.connect(self._select_all)
        options.addWidget(select_all)
        layout.addLayout(options)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(['Delete', 'Title', 'Reason', 'URL'])
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
        self.scan = QPushButton('Check Bookmarks')
        self.scan.clicked.connect(self._start)
        self.stop = QPushButton('Stop scan')
        self.stop.setEnabled(False)
        self.stop.clicked.connect(self._stop)
        self.open = QPushButton('Open saved bookmark')
        self.open.clicked.connect(self._open)
        self.open.setEnabled(open_url is not None)
        self.remove = QPushButton('Delete Selected…')
        self.remove.setEnabled(False)
        self.remove.clicked.connect(self._remove)
        close = QPushButton('Close')
        close.clicked.connect(self.reject)
        for button in (self.scan, self.stop, self.open, self.remove, close):
            row.addWidget(button)
        layout.addLayout(row)
        self.finished.connect(lambda _: self._cancel())

    def _select_all(self):
        for row in range(self.table.rowCount()):
            self.table.item(row, 0).setCheckState(Qt.CheckState.Checked)

    def _start(self):
        self._cancel()
        self.results = []
        self.table.setRowCount(0)
        self.details.clear()
        self.remove.setEnabled(False)
        self.scan.setEnabled(False)
        self.stop.setEnabled(True)
        self.timeout.setEnabled(False)
        self.concurrency.setEnabled(False)
        self.checked, self.total = 0, len(self.store.all())
        self.status.setText(f'Checked 0/{self.total} — 0 failed links')
        worker = HealthCheckWorker(self.store.all(), QApplication.instance(),
                                   timeout=self.timeout.value(), concurrency=self.concurrency.value())
        self.scanner = worker
        self.scan_error = ''
        worker.result.connect(self._result)
        worker.progress.connect(self._progress)
        worker.failed.connect(self._error)
        worker.finished.connect(self._worker_finished)
        worker.finished.connect(worker.deleteLater)
        QApplication.instance().aboutToQuit.connect(worker.shutdown)
        worker.start()

    def _cancel(self):
        if self.scanner is not None:
            self.scanner.cancel()
            # Keep the worker owned by QApplication until its thread finishes.
            self.scanner = None

    def _stop(self):
        self._cancel()
        self._finished(f'Stopped. Checked {self.checked}/{self.total}; {len(self.results)} failed links listed.')

    def _from_current_scanner(self):
        sender = self.sender()
        return sender is None or sender is self.scanner

    @pyqtSlot(int, int)
    def _progress(self, checked, total):
        if not self._from_current_scanner():
            return
        self.checked, self.total = checked, total
        self.status.setText(f'Checked {checked}/{total} — {len(self.results)} failed links')

    @pyqtSlot(str)
    def _error(self, message):
        if self._from_current_scanner():
            self.scan_error = message

    @pyqtSlot()
    def _worker_finished(self):
        if not self._from_current_scanner():
            return
        self.scanner = None
        self._finished(self.scan_error or
                       f'Checked {self.checked}/{self.total} — {len(self.results)} failed links. Review before deleting.')

    def _finished(self, message):
        self.scan.setEnabled(True)
        self.stop.setEnabled(False)
        self.timeout.setEnabled(True)
        self.concurrency.setEnabled(True)
        self.status.setText(message)
        self._selection()

    @pyqtSlot(object)
    def _result(self, result):
        if not self._from_current_scanner() or result.ok:
            return
        row = len(self.results)
        self.results.append(result)
        self.table.insertRow(row)
        check = QTableWidgetItem()
        check.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsSelectable)
        check.setCheckState(Qt.CheckState.Unchecked)
        self.table.setItem(row, 0, check)
        for col, text in enumerate((result.bookmark.title, result.reason, result.bookmark.url), 1):
            self.table.setItem(row, col, QTableWidgetItem(text))

    def _checked(self):
        return [r.bookmark for i, r in enumerate(self.results)
                if self.table.item(i, 0) is not None
                and self.table.item(i, 0).checkState() == Qt.CheckState.Checked]

    def _selection(self):
        self.remove.setEnabled(self.scanner is None and bool(self._checked()))

    def _details(self):
        index = self.table.currentRow()
        if 0 <= index < len(self.results):
            r = self.results[index]
            prefix = f'{r.method} check: ' if r.method else ''
            self.details.setPlainText(f'{prefix}{r.reason}\nDestination: {r.final_url or r.bookmark.url}')

    def _open(self):
        index = self.table.currentRow()
        if self.open_url and 0 <= index < len(self.results):
            self.open_url(self.results[index].bookmark.url)

    def _remove(self):
        if self.scanner is not None:
            return
        selected = self._checked()
        if not selected:
            return
        box = QMessageBox(self)
        box.setWindowTitle('Confirm bookmark removal')
        box.setIcon(QMessageBox.Icon.Question)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(f'Permanently remove these {len(selected)} checked bookmarks? '
                    'Some failures may be temporary or require a login. Use Show Details to review the full list.')
        box.setDetailedText('\n\n'.join(f'{b.title}\n{b.url}' for b in selected))
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        try:
            removed = self.store.remove_reviewed(selected)
        except OSError:
            self.status.setText('Could not save bookmarks. Nothing was removed; check folder permissions.')
            return
        self.status.setText(f'Removed {removed} bookmarks. Entries edited since the scan were kept.')
        for row in range(self.table.rowCount()):
            self.table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)
        # Reflect actual store deletions in the results, not just the saved file.
        for row in range(len(self.results) - 1, -1, -1):
            if not self.store.contains(self.results[row].bookmark.url):
                self.table.removeRow(row)
                self.results.pop(row)
        self.details.clear()
        self._selection()
