"""Broken-only health review dialog: plain HTTP checks, no AI or Ollama dependency."""
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtWidgets import (QApplication, QDialog, QDoubleSpinBox, QHBoxLayout, QHeaderView,
                             QLabel, QMessageBox, QProgressBar, QPushButton, QSpinBox,
                             QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout)

from bookmark_health import DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT_SECONDS, HealthCheckWorker
from i18n import tr


def _failed(count):
    return (tr("{count} failed link").format(count=count) if count == 1
            else tr("{count} failed links").format(count=count))


class BookmarkHealthDialog(QDialog):
    def __init__(self, store, parent=None, open_url=None):
        super().__init__(parent)
        self.store, self.open_url = store, open_url
        self.scanner = None
        self.results = []
        self.checked = self.total = 0
        self.scan_error = ''
        self.setWindowTitle(tr('Check Bookmarks'))
        self.resize(940, 600)
        layout = QVBoxLayout(self)
        label = QLabel(tr('Check bookmarked links with HEAD, then retry failures with GET. '
                          'Rate-limited or overloaded servers are backed off and retried rather '
                          'than reported broken immediately. Only failed links appear below. '
                          'A failure does not mean permanent removal: outages, expired certificates '
                          'and login restrictions are also listed. Nothing is deleted until you '
                          'select entries and confirm Delete Selected.'))
        label.setWordWrap(True)
        layout.addWidget(label)
        self.status = QLabel(tr('Ready. Checks run in the background; no AI model is required.'))
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setFormat(tr('Not started'))
        layout.addWidget(self.progress)
        options = QHBoxLayout()
        options.addWidget(QLabel(tr('Timeout per request (seconds):')))
        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(.1, 120)
        self.timeout.setValue(DEFAULT_TIMEOUT_SECONDS)
        options.addWidget(self.timeout)
        options.addWidget(QLabel(tr('Concurrent checks:')))
        self.concurrency = QSpinBox()
        self.concurrency.setRange(1, 64)
        self.concurrency.setValue(DEFAULT_CONCURRENCY)
        options.addWidget(self.concurrency)
        self.select_all = QPushButton(tr('Select all'))
        self.select_all.clicked.connect(self._select_all)
        options.addWidget(self.select_all)
        layout.addLayout(options)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            [tr('Delete'), tr('Title'), tr('Reason'), tr('URL')])
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
        self.scan = QPushButton(tr('Check Bookmarks'))
        self.scan.clicked.connect(self._start)
        self.stop = QPushButton(tr('Stop scan'))
        self.stop.setEnabled(False)
        self.stop.clicked.connect(self._stop)
        self.open = QPushButton(tr('Open saved bookmark'))
        self.open.clicked.connect(self._open)
        self.remove = QPushButton(tr('Delete Selected…'))
        self.remove.clicked.connect(self._remove)
        self.close_button = QPushButton(tr('Close'))
        self.close_button.clicked.connect(self.reject)
        for button in (self.scan, self.stop, self.open, self.remove, self.close_button):
            row.addWidget(button)
        layout.addLayout(row)
        self.finished.connect(lambda _: self._cancel())
        self._set_running(False)

    def _set_running(self, running):
        """While a scan runs, only Stop scan is usable; otherwise everything but Stop scan.
        (The window's own close button still works and cancels the scan.)"""
        self.stop.setEnabled(running)
        for widget in (self.scan, self.select_all, self.close_button,
                       self.timeout, self.concurrency):
            widget.setEnabled(not running)
        self.open.setEnabled(not running and self.open_url is not None)
        # Delete also needs at least one checked row; _selection() owns that rule.
        self._selection()

    def _select_all(self):
        for row in range(self.table.rowCount()):
            self.table.item(row, 0).setCheckState(Qt.CheckState.Checked)

    def _start(self):
        self._cancel()
        self.results = []
        self.table.setRowCount(0)
        self.details.clear()
        self.checked, self.total = 0, len(self.store.all())
        self.status.setText(tr('Scanning… Checked {checked}/{total} — {failed}').format(
            checked=0, total=self.total, failed=_failed(0)))
        self.progress.setRange(0, max(self.total, 1))
        self.progress.setValue(0)
        self.progress.setFormat(tr('%v / %m checked (%p%)'))
        worker = HealthCheckWorker(self.store.all(), QApplication.instance(),
                                   timeout=self.timeout.value(), concurrency=self.concurrency.value())
        self.scanner = worker
        self._set_running(True)
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
        self.progress.setFormat(
            tr('Stopped at {checked} / {total}').format(checked=self.checked, total=self.total))
        self._finished(tr('Scan stopped. Checked {checked}/{total}; {failed} listed.').format(
            checked=self.checked, total=self.total, failed=_failed(len(self.results))))

    def _from_current_scanner(self):
        sender = self.sender()
        return sender is None or sender is self.scanner

    @pyqtSlot(int, int)
    def _progress(self, checked, total):
        if not self._from_current_scanner():
            return
        self.checked, self.total = checked, total
        self.status.setText(tr('Scanning… Checked {checked}/{total} — {failed}').format(
            checked=checked, total=total, failed=_failed(len(self.results))))
        self.progress.setRange(0, max(total, 1))
        self.progress.setValue(checked)

    @pyqtSlot(str)
    def _error(self, message):
        if self._from_current_scanner():
            self.scan_error = message

    @pyqtSlot()
    def _worker_finished(self):
        if not self._from_current_scanner():
            return
        self.scanner = None
        if self.scan_error:
            self.progress.setFormat(
                tr('Scan failed at {checked} / {total}').format(
                    checked=self.checked, total=self.total))
            self._finished(self.scan_error)
            return
        # Complete even when the last progress tick was missed, or there was nothing to check.
        self.progress.setValue(self.progress.maximum())
        failed = len(self.results)
        self.progress.setFormat(tr('Scan complete — {total} checked, {failed} failed').format(
            total=self.total, failed=failed))
        summary = (
            tr('Scan complete. Checked {checked}/{total} — no broken links found.').format(
                checked=self.checked, total=self.total)
            if not failed else
            tr('Scan complete. Checked {checked}/{total} — {failed}. '
               'Review before deleting.').format(
                checked=self.checked, total=self.total, failed=_failed(failed)))
        self._finished(summary)
        # Flash the window in the taskbar if the user switched away during a long scan.
        QApplication.alert(self)

    def _finished(self, message):
        self._set_running(False)
        self.status.setText(message)

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
            prefix = tr('{method} check: ').format(method=r.method) if r.method else ''
            self.details.setPlainText(tr('{prefix}{reason}\nDestination: {destination}').format(
                prefix=prefix, reason=r.reason, destination=r.final_url or r.bookmark.url))

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
        box.setWindowTitle(tr('Confirm bookmark removal'))
        box.setIcon(QMessageBox.Icon.Question)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(tr('Permanently remove these {count} checked bookmarks? '
                       'Some failures may be temporary or require a login. '
                       'Use Show Details to review the full list.').format(count=len(selected)))
        box.setDetailedText('\n\n'.join(f'{b.title}\n{b.url}' for b in selected))
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        try:
            removed = self.store.remove_reviewed(selected)
        except OSError:
            self.status.setText(tr('Could not save bookmarks. Nothing was removed; '
                                   'check folder permissions.'))
            return
        self.status.setText(tr('Removed {removed} bookmarks. Entries edited since '
                               'the scan were kept.').format(removed=removed))
        for row in range(self.table.rowCount()):
            self.table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)
        # Reflect actual store deletions in the results, not just the saved file.
        for row in range(len(self.results) - 1, -1, -1):
            if not self.store.contains(self.results[row].bookmark.url):
                self.table.removeRow(row)
                self.results.pop(row)
        self.details.clear()
        self._selection()
