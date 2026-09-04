"""The "Vodou Updates" dialog -- the UI in front of the updater/ package.

Kept out of about.py so the coordinated Qt/PyQt6/WebEngine updater has a home
of its own, and so the heavy work (PyPI lookups, pip download, backup) always
runs on a worker thread with this dialog only ever reading finished
``UpdatePlan`` / ``StageResult`` objects.

Flow the dialog drives (see updater/__init__.py for the guarantees):

    open        -> show current versions, kick off a check
    check done  -> show available versions + compatibility verdict
    Update      -> confirm -> stage on a worker (backup, download, verify);
                   nothing in the live install is touched
    staged      -> "Restart & finish": spawn the detached helper, quit Vodou
                   (the helper installs, verifies, rolls back on failure, and
                   relaunches Vodou)
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from updater import UpdateManager
from updater.diagnostics import as_text as diagnostics_text
from updater.manager import default_relaunch

_MONO = ("font-family: Consolas, 'JetBrains Mono', 'Ubuntu Mono', "
         "'DejaVu Sans Mono', monospace;")


class _CheckWorker(QThread):
    done = pyqtSignal(object)          # UpdatePlan
    failed = pyqtSignal(str)

    def __init__(self, manager: UpdateManager, allow_prerelease: bool):
        super().__init__()
        self._mgr = manager
        self._pre = allow_prerelease

    def run(self) -> None:  # noqa: D401 -- QThread entry point
        try:
            self.done.emit(
                self._mgr.check_for_updates(allow_prerelease=self._pre))
        except Exception as exc:  # noqa: BLE001 -- report, never crash the UI
            self.failed.emit(f"{exc}")


class _StageWorker(QThread):
    progress = pyqtSignal(str)
    done = pyqtSignal(object)          # StageResult
    failed = pyqtSignal(str)

    def __init__(self, manager: UpdateManager, plan):
        super().__init__()
        self._mgr = manager
        self._plan = plan
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        try:
            res = self._mgr.stage(
                self._plan,
                progress=self.progress.emit,
                cancelled=lambda: self._cancelled)
            self.done.emit(res)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(f"{exc}")


class UpdatesDialog(QDialog):
    """Self-contained: create and ``exec()`` it. Emits nothing -- when an
    update is applied it spawns the helper and quits the application itself."""

    def __init__(self, parent=None, *, manager: UpdateManager | None = None):
        super().__init__(parent)
        self.setWindowTitle("Vodou Updates")
        self.setMinimumWidth(560)
        self._mgr = manager or UpdateManager()
        self._plan = None
        self._check_worker: _CheckWorker | None = None
        self._stage_worker: _StageWorker | None = None
        self._staged = False

        outer = QVBoxLayout(self)

        title = QLabel("Vodou Updates")
        title.setStyleSheet("font-size: 16pt; font-weight: 700;")
        outer.addWidget(title)

        outer.addWidget(_heading("Current installation"))
        self._current_grid = QGridLayout()
        self._current_grid.setColumnStretch(1, 1)
        outer.addLayout(self._current_grid)

        self._status = QLabel("Checking for updates…")
        self._status.setWordWrap(True)
        self._status.setStyleSheet("color: gray; padding: 8px 0;")
        outer.addWidget(self._status)

        self._avail_heading = _heading("Available update")
        self._avail_heading.hide()
        outer.addWidget(self._avail_heading)
        self._avail_grid = QGridLayout()
        self._avail_grid.setColumnStretch(1, 1)
        outer.addLayout(self._avail_grid)

        self._compat = QLabel("")
        self._compat.setWordWrap(True)
        self._compat.setTextFormat(Qt.TextFormat.PlainText)
        self._compat.hide()
        outer.addWidget(self._compat)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)          # indeterminate
        self._progress.hide()
        outer.addWidget(self._progress)

        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setStyleSheet(_MONO + " font-size: 9pt;")
        self._log.setFixedHeight(130)
        self._log.hide()
        outer.addWidget(self._log)

        self._prerelease = QCheckBox(
            "Include pre-release (developer) versions")
        self._prerelease.setToolTip(
            "Off by default. Vodou only ever installs stable releases unless "
            "you tick this.")
        self._prerelease.toggled.connect(lambda _=None: self._start_check())
        outer.addWidget(self._prerelease)

        buttons = QHBoxLayout()
        self._update_btn = QPushButton("Update Vodou")
        self._update_btn.setEnabled(False)
        self._update_btn.clicked.connect(self._on_update_clicked)
        buttons.addWidget(self._update_btn)

        self._recheck_btn = QPushButton("Check again")
        self._recheck_btn.clicked.connect(self._start_check)
        buttons.addWidget(self._recheck_btn)

        self._diag_btn = QPushButton("Copy diagnostics")
        self._diag_btn.setToolTip(
            "Copy a full environment report to the clipboard for a bug "
            "report.")
        self._diag_btn.clicked.connect(self._copy_diagnostics)
        buttons.addWidget(self._diag_btn)

        buttons.addStretch()
        self._close_btn = QPushButton("Close")
        self._close_btn.setDefault(True)
        self._close_btn.clicked.connect(self.reject)
        buttons.addWidget(self._close_btn)
        outer.addLayout(buttons)

        self._render_current(self._mgr.get_current_versions())
        self._start_check()

    # -- current versions ------------------------------------------------
    def _render_current(self, cv) -> None:
        rows = [
            ("Vodou", cv.vodou_display),
            ("Python", cv.python),
            ("PyQt6", f"{cv.pyqt6_binding}  (wheel {cv.pyqt6_wheel})"),
            ("Qt", cv.qt),
            ("Qt WebEngine", cv.qt_webengine),
            ("Chromium", cv.chromium),
        ]
        _fill_grid(self._current_grid, rows)

    # -- check ---------------------------------------------------------
    def _start_check(self) -> None:
        if self._check_worker and self._check_worker.isRunning():
            return
        if self._staged:
            return
        self._status.setText("Checking for updates…")
        self._status.setStyleSheet("color: gray; padding: 8px 0;")
        self._recheck_btn.setEnabled(False)
        self._update_btn.setEnabled(False)
        self._check_worker = _CheckWorker(self._mgr,
                                          self._prerelease.isChecked())
        self._check_worker.done.connect(self._on_check_done)
        self._check_worker.failed.connect(self._on_check_failed)
        self._check_worker.start()

    def _on_check_failed(self, message: str) -> None:
        self._recheck_btn.setEnabled(True)
        self._status.setText(
            "Could not check for updates: " + message
            + "\nNo changes have been made.")
        self._status.setStyleSheet("color: #b00; padding: 8px 0;")

    def _on_check_done(self, plan) -> None:
        self._plan = plan
        self._recheck_btn.setEnabled(True)
        self._render_current(plan.current)

        if not plan.possible:
            self._avail_heading.setText("Update unavailable")
            self._avail_heading.show()
            _fill_grid(self._avail_grid, [])
            self._compat.setText(plan.reason)
            self._compat.show()
            self._status.setText("No update will be made on this "
                                 "installation.")
            self._status.setStyleSheet("color: gray; padding: 8px 0;")
            return

        if not plan.update_available:
            self._avail_heading.hide()
            _fill_grid(self._avail_grid, [])
            self._compat.setText(plan.compatibility.reason)
            self._compat.show()
            self._status.setText(
                "Vodou's Qt stack is already the latest compatible version.")
            self._status.setStyleSheet("color: gray; padding: 8px 0;")
            return

        moving = [c for c in plan.components if c.will_update]
        rows = [(c.name, f"{c.current}  →  {c.available}")
                for c in moving]
        _fill_grid(self._avail_grid, rows)
        self._avail_heading.setText("Available update")
        self._avail_heading.show()

        verdict = ("Compatibility: Compatible"
                   if plan.compatibility.compatible
                   else "Compatibility: NOT compatible")
        self._compat.setText(
            verdict + "\n" + plan.compatibility.reason
            + "\n\nA restart is required to finish the update. Your Vodou "
            "source code and settings are not touched; the previous Qt "
            "packages are backed up and restored automatically if anything "
            "fails.")
        self._compat.show()
        self._status.setText(plan.summary_line())
        self._status.setStyleSheet("color: #185; padding: 8px 0;"
                                   " font-weight: 600;")
        self._update_btn.setEnabled(True)

    # -- update / stage ---------------------------------------------
    def _on_update_clicked(self) -> None:
        if self._staged:
            self._restart_and_finish()
            return
        if not (self._plan and self._plan.update_available):
            return
        moving = "\n".join(f"  • {c.name}: {c.current} → "
                           f"{c.available}"
                           for c in self._plan.components if c.will_update)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Update Vodou")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(
            "Vodou will download and verify this coordinated set:\n\n"
            f"{moving}\n\n"
            "Nothing is changed yet -- the download is staged and your "
            "current Qt packages are backed up first. When it is ready, "
            "Vodou restarts to finish; if the install fails it is rolled "
            "back automatically.\n\n"
            "Download the update now?")
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        self._begin_stage()

    def _begin_stage(self) -> None:
        self._update_btn.setEnabled(False)
        self._recheck_btn.setEnabled(False)
        self._prerelease.setEnabled(False)
        self._close_btn.setText("Cancel")
        self._progress.show()
        self._log.show()
        self._log.clear()
        self._stage_worker = _StageWorker(self._mgr, self._plan)
        self._stage_worker.progress.connect(self._append_log)
        self._stage_worker.done.connect(self._on_stage_done)
        self._stage_worker.failed.connect(self._on_stage_failed)
        self._stage_worker.start()

    def _append_log(self, line: str) -> None:
        self._log.appendPlainText(line)

    def _on_stage_failed(self, message: str) -> None:
        self._progress.hide()
        self._close_btn.setText("Close")
        self._recheck_btn.setEnabled(True)
        self._prerelease.setEnabled(True)
        self._append_log("\n" + message)
        self._status.setText("Update not applied. " + message.splitlines()[0])
        self._status.setStyleSheet("color: #b00; padding: 8px 0;")
        QMessageBox.warning(
            self, "Update not applied",
            message + "\n\nNothing on your system was changed.")

    def _on_stage_done(self, result) -> None:
        self._progress.hide()
        self._staged = True
        self._close_btn.setText("Later")
        self._append_log("\n" + result.message)
        self._status.setText(
            "Update downloaded and verified. Restart Vodou to finish.")
        self._status.setStyleSheet("color: #185; padding: 8px 0;"
                                   " font-weight: 600;")
        self._update_btn.setText("Restart && finish")
        self._update_btn.setEnabled(True)

    def _restart_and_finish(self) -> None:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Restart to finish updating")
        box.setText(
            "Vodou will close now. A helper then installs the verified "
            "update, checks it, and reopens Vodou. If the check fails it "
            "restores your previous version automatically.\n\nClose Vodou "
            "and finish the update?")
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.Yes)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        try:
            self._mgr.spawn_apply(relaunch=default_relaunch())
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self, "Could not start the updater",
                f"{exc}\n\nThe download is still staged; you can retry from "
                "About → Updates.")
            return
        app = QApplication.instance()
        if app is not None:
            app.quit()

    # -- misc --------------------------------------------------------
    def _copy_diagnostics(self) -> None:
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(diagnostics_text())
            self._status.setText("Diagnostics copied to the clipboard.")
            self._status.setStyleSheet("color: gray; padding: 8px 0;")

    def reject(self) -> None:  # noqa: D401
        if self._stage_worker and self._stage_worker.isRunning():
            self._stage_worker.cancel()
            self._append_log("\nCancelling…")
            self._stage_worker.wait(5000)
        for w in (self._check_worker, self._stage_worker):
            if w and w.isRunning():
                w.wait(3000)
        super().reject()


def _heading(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet("font-weight: 700; padding-top: 6px;")
    return lbl


def _fill_grid(grid: QGridLayout, rows: list[tuple[str, str]]) -> None:
    while grid.count():
        item = grid.takeAt(0)
        w = item.widget()
        if w is not None:
            w.deleteLater()
    for r, (name, value) in enumerate(rows):
        key = QLabel(name)
        key.setStyleSheet("color: gray;")
        val = QLabel(value)
        val.setTextFormat(Qt.TextFormat.PlainText)
        val.setStyleSheet(_MONO)
        val.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        grid.addWidget(key, r, 0, Qt.AlignmentFlag.AlignTop)
        grid.addWidget(val, r, 1)
