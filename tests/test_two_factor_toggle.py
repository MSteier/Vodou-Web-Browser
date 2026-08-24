"""Tests for the vault's two-factor on/off switch and the auto-lock menu wiring.

Two layers:
  * pure switch-state logic (two_factor_state) — no Qt, no hardware;
  * a VaultDialog integration pass under offscreen Qt with a fake vault: the
    switch reflects the real enrolled state, turning it off removes every key
    (reusing the vault's own remove path), and the auto-lock menu reflects the
    current duration and emits the change signal.

The enroll ("turn on") path opens the real SecurityKeysDialog and needs a
security key, so it is deliberately not driven here.

Run:  python tests/test_two_factor_toggle.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from vault import Entry  # noqa: E402
import vault_ui  # noqa: E402
from vault_ui import two_factor_state  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


# ---------------------------------------------------------------------------
print("two_factor_state — pure switch logic")

on_avail = two_factor_state(True, True)
on_unavail = two_factor_state(True, False)
off_avail = two_factor_state(False, True)
off_unavail = two_factor_state(False, False)

check("enrolled -> switch reads ON", on_avail["checked"] and on_unavail["checked"])
check("not enrolled -> switch reads OFF",
      not off_avail["checked"] and not off_unavail["checked"])
check("enrolled is always actionable (can turn off), even w/o WebAuthn",
      on_avail["enabled"] and on_unavail["enabled"])
check("off + WebAuthn available -> can turn on (enabled)", off_avail["enabled"])
check("off + no WebAuthn -> disabled (not a dead control)",
      not off_unavail["enabled"])
check("every state has a non-empty tooltip",
      all(s["tooltip"] for s in (on_avail, on_unavail, off_avail, off_unavail)))

# ---------------------------------------------------------------------------
print("\nVaultDialog integration (offscreen Qt)")


class FakeVault:
    """Just enough Vault surface for VaultDialog + the two-factor switch."""

    def __init__(self, keys=()):
        self._entries = [Entry(site="example.com", username="a", password="")]
        self._keys = [{"cred_id": k} for k in keys]

    def entries(self):
        return self._entries

    @property
    def factor_enrolled(self):
        return bool(self._keys)

    def list_authenticators(self):
        return [dict(k) for k in self._keys]

    def remove_authenticator(self, cred_id):
        before = len(self._keys)
        self._keys = [k for k in self._keys if k["cred_id"] != cred_id]
        if len(self._keys) == before:
            raise ValueError("not enrolled")


def autolock_checked_labels(dialog):
    return [a.text() for a in dialog._autolock_group.actions() if a.isChecked()]


try:
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])

    # Pretend WebAuthn is usable so the switch's enabled-state is exercised
    # independently of the host OS running the test.
    orig_supported = vault_ui.webauthn_supported
    vault_ui.webauthn_supported = lambda: (True, "")

    # --- switch reflects the enrolled state -------------------------------
    vault = FakeVault(keys=[b"key-1", b"key-2"])
    dlg = vault_ui.VaultDialog(vault, None, current_site="", autolock_minutes=1440)
    action = dlg._two_factor_action
    check("switch is ON when keys are enrolled", action.isChecked())
    check("switch is enabled when enrolled", action.isEnabled())

    # --- turning it off removes every key ---------------------------------
    dlg._disable_two_factor()
    check("disable removes all enrolled keys", not vault.factor_enrolled)
    dlg._sync_two_factor_action()
    check("switch re-syncs to OFF after disable", not action.isChecked())
    check("still enabled (WebAuthn available) so it can be turned back on",
          action.isEnabled())

    # --- no WebAuthn -> off switch is disabled ----------------------------
    vault_ui.webauthn_supported = lambda: (False, "no key here")
    dlg._sync_two_factor_action()
    check("off switch is disabled when WebAuthn is unavailable",
          not action.isEnabled())
    vault_ui.webauthn_supported = lambda: (True, "")

    # --- auto-lock menu reflects the current duration ---------------------
    check("the passed auto-lock duration is pre-checked (1 day)",
          autolock_checked_labels(dlg) == ["1 day"])

    # --- choosing a duration emits the change signal ----------------------
    seen = []
    dlg.autolock_minutes_changed.connect(seen.append)
    dlg._choose_autolock(10080)
    check("choosing a new duration emits it", seen == [10080])
    check("internal duration updated", dlg._autolock_minutes == 10080)
    dlg._choose_autolock(10080)  # same value again
    check("choosing the same duration does not re-emit", seen == [10080])

    dlg.deleteLater()
    vault_ui.webauthn_supported = orig_supported
except Exception as exc:  # pragma: no cover - surfaces as a test failure
    check(f"VaultDialog integration ran without error ({exc!r})", False)

# ---------------------------------------------------------------------------
print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL TWO-FACTOR-TOGGLE TESTS PASSED")
