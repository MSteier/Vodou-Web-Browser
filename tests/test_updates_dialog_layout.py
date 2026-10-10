"""The Updates dialog must grow to fit text that appears after it opens.

It opens saying "Checking for updates…" and is sized for that. When the check
returns a long wrapped message (the Docker image's "Update unavailable"
reason), the window used to keep its original height, squeezing every row on
top of the next.

Run:  python tests/test_updates_dialog_layout.py
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PyQt6.QtWidgets import QApplication  # noqa: E402

app = QApplication.instance() or QApplication([])

import updater_ui  # noqa: E402
from updater.manager import _empty_compat  # noqa: E402
from updater.models import UpdatePlan  # noqa: E402
from updater.versions import get_current_versions  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


LONG_REASON = " ".join(["This installation cannot be updated in place."] * 8)
cur = get_current_versions()


class FakeManager:
    def get_current_versions(self):
        return cur

    def check_for_updates(self, *, allow_prerelease=False):
        return UpdatePlan(current=cur,
                          compatibility=_empty_compat(LONG_REASON),
                          possible=False, reason=LONG_REASON,
                          allow_prerelease=allow_prerelease)


def settle():
    for _ in range(3):
        app.processEvents()


# Deliver the plan by hand instead of starting the network check thread.
orig_start_check = updater_ui.UpdatesDialog._start_check
updater_ui.UpdatesDialog._start_check = lambda self: None
try:
    dlg = updater_ui.UpdatesDialog(manager=FakeManager())
    dlg.show()
    settle()
    opened_height = dlg.height()
    dlg._on_check_done(FakeManager().check_for_updates())
    settle()
    need = dlg.layout().totalHeightForWidth(dlg.width())
    check("window grows after a long result arrives",
          dlg.height() > opened_height)
    check("window is tall enough for the wrapped text (no overlap)",
          dlg.height() >= need)
    check("window can't be shrunk back into overlap",
          dlg.minimumHeight() >= need)
    dlg.close()
finally:
    updater_ui.UpdatesDialog._start_check = orig_start_check

print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL UPDATES-DIALOG LAYOUT TESTS PASSED")
