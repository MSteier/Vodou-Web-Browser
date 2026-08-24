"""Tests for cookie-jar persistence safety (cookies.py).

The regression guarded here: flush() must not delete a still-valid on-disk jar
when restore() failed to read it (a locked file, or on Linux a keyring that
wasn't up yet at startup). Otherwise a transient outage followed by a normal
exit permanently destroys every saved cookie-exception login.

Runs headless under offscreen Qt with a fake cookie store and a temp jar path.

Run:  python tests/test_cookie_persistence.py
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import cookies  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


class _FakeSignal:
    def connect(self, _fn):
        pass


class FakeStore:
    """Minimal stand-in for QWebEngineCookieStore (no real signals needed)."""

    def __init__(self):
        self.cookieAdded = _FakeSignal()
        self.cookieRemoved = _FakeSignal()
        self.set_calls = 0

    def setCookie(self, _cookie):
        self.set_calls += 1


def _raise_oserror(_data):
    raise OSError("keystore unavailable")


try:
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])

    with tempfile.TemporaryDirectory() as d:
        jar = Path(d) / "cookies.dat"
        cookies.COOKIE_JAR_FILE = jar  # module global, read at call time

        # --- Scenario 1: an unreadable existing jar must NOT be deleted -----
        jar.write_bytes(b"SEALED-VALID-JAR")
        cookies._unseal = _raise_oserror
        k = cookies.CookieKeeper(FakeStore())
        n = k.restore()
        check("restore() returns 0 when the jar can't be unsealed", n == 0)
        check("restore_ok stays False on a failed read", k._restore_ok is False)
        k.flush()  # _kept is empty
        check("flush() does NOT delete a jar it couldn't load", jar.exists())

        # --- Scenario 2: a clean restore -> safe to delete when nothing kept -
        cookies._unseal = lambda data: b""   # reads cleanly, yields no cookies
        k2 = cookies.CookieKeeper(FakeStore())
        k2.restore()
        check("restore_ok True after a clean read", k2._restore_ok is True)
        k2.flush()  # _kept empty AND restore_ok True
        check("flush() deletes the jar when restore succeeded and none kept",
              not jar.exists())

        # --- Scenario 3: no jar on disk -> restore_ok True (nothing to lose) -
        k3 = cookies.CookieKeeper(FakeStore())
        check("restore() on a missing jar returns 0 and sets restore_ok True",
              k3.restore() == 0 and k3._restore_ok is True)
        k3.flush()
        check("flush() with no jar and nothing kept is a harmless no-op",
              not jar.exists())

        # --- Scenario 4: clear() marks the jar known-absent -----------------
        jar.write_bytes(b"x")
        k4 = cookies.CookieKeeper(FakeStore())
        k4.clear()
        check("clear() removes the jar and sets restore_ok True",
              not jar.exists() and k4._restore_ok is True)
except Exception as exc:  # pragma: no cover - surfaces as a test failure
    check(f"cookie-persistence test ran without error ({exc!r})", False)

# ---------------------------------------------------------------------------
print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL COOKIE-PERSISTENCE TESTS PASSED")
