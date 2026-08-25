"""Tests for the Password Vault dashboard's column redesign: Website,
Website Safety, Username/Email, Password, Strength, Duplicated, Last
Changed — against a real (temp-file) vault and an offscreen VaultDialog.

Run:  python tests/test_vault_dashboard_columns.py
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Must be set before any QApplication is created so the GUI part runs headless.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from vault import Entry, Vault  # noqa: E402
from vault_ui import VaultDialog  # noqa: E402

app = QApplication.instance() or QApplication([])

PW = "correct horse battery staple"

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


def fresh() -> Vault:
    d = Path(tempfile.mkdtemp())
    v = Vault(d / "vault.dat")
    v.create(PW)
    return v


def e(site, username="alice", password="Xk9#mQ2p!wRt4Lv7", notes=""):
    return Entry(site=site, username=username, password=password, notes=notes)


class FakeSafeBrowsing:
    """Just enough of safebrowsing.SafeBrowsing for the Website Safety
    column: a fixed set of hosts it reports as dangerous."""

    def __init__(self, dangerous_hosts):
        self._dangerous = set(dangerous_hosts)

    def is_dangerous(self, host):
        return object() if host in self._dangerous else None


def col(dialog, row, column):
    return dialog.table.item(row, column)


def find_row(dialog, site):
    for r in range(dialog.table.rowCount()):
        if col(dialog, r, VaultDialog.COL_WEBSITE).text() == site:
            return r
    raise AssertionError(f"no row for {site!r}")


# ---------------------------------------------------------------------------
print("Entry.updated — stamped by add/update/add_many, not user-supplied")

v = fresh()
v.add(e("github.com"))
stamp = v.entries()[0].updated
check("add() stamps today's date", len(stamp) == 10 and stamp.count("-") == 2)

v.update(0, e("github.com", password="NewPass!987"))
check("update() re-stamps", v.entries()[0].updated == stamp)  # same day

v2 = fresh()
v2.add_many([e("a.com"), e("b.com")])
check("add_many() stamps every imported entry",
      all(entry.updated for entry in v2.entries()))

# Persists through save/reload.
path = v.path
reopened = Vault(path)
reopened.unlock(PW)
check("updated survives a save/reload round trip",
      reopened.entries()[0].updated == stamp)

# ---------------------------------------------------------------------------
print("\nVaultDialog — column headers")

headers_vault = fresh()
headers_vault.add(e("example.com"))
dlg = VaultDialog(headers_vault, None)
check("seven columns", dlg.table.columnCount() == 7)
labels = [dlg.table.horizontalHeaderItem(c).text() for c in range(7)]
check("headers match the requested dashboard",
      labels == ["Website", "Website Safety", "Username/Email", "Password",
                 "Strength", "Duplicated", "Last Changed"])
dlg.deleteLater()

# ---------------------------------------------------------------------------
print("\nWebsite Safety column")

safety_vault = fresh()
safety_vault.add(e("github.com"))           # clean
safety_vault.add(e("paypa1.com"))           # typosquat (spoofcheck-only)
safety_vault.add(e("evil-tracker.test"))    # on the fake malicious list

sb = FakeSafeBrowsing(dangerous_hosts={"evil-tracker.test"})
dlg2 = VaultDialog(safety_vault, None, safe_browsing=sb)

check("clean site reads OK",
      col(dlg2, find_row(dlg2, "github.com"), VaultDialog.COL_SAFETY).text()
      == "OK")
check("typosquat site is flagged as a possible spoof",
      "spoof" in col(dlg2, find_row(dlg2, "paypa1.com"),
                     VaultDialog.COL_SAFETY).text().lower())
check("malicious-listed site is flagged, taking priority over spoofcheck",
      "Malicious" in col(dlg2, find_row(dlg2, "evil-tracker.test"),
                         VaultDialog.COL_SAFETY).text())

# Without a SafeBrowsing instance, the column still works (spoof-only).
dlg2b = VaultDialog(safety_vault, None, safe_browsing=None)
check("no SafeBrowsing instance -> still reports the spoof heuristic",
      "spoof" in col(dlg2b, find_row(dlg2b, "paypa1.com"),
                     VaultDialog.COL_SAFETY).text().lower())
dlg2.deleteLater()
dlg2b.deleteLater()

# ---------------------------------------------------------------------------
print("\nDuplicated column")

dup_vault = fresh()
dup_vault.add(e("github.com"))                       # 0: duplicate of 1
dup_vault.add(e("github.com"))                       # 1: duplicate of 0
dup_vault.add(e("gitlab.com"))                       # 2: unique
dlg3 = VaultDialog(dup_vault, None)
dup_rows = [r for r in range(dlg3.table.rowCount())
           if col(dlg3, r, VaultDialog.COL_WEBSITE).text() == "github.com"]
check("both exact-duplicate rows are flagged",
      len(dup_rows) == 2 and
      all(col(dlg3, r, VaultDialog.COL_DUPLICATE).text() == "Duplicate"
          for r in dup_rows))
check("the unique entry is not flagged",
      col(dlg3, find_row(dlg3, "gitlab.com"),
          VaultDialog.COL_DUPLICATE).text() == "—")
dlg3.deleteLater()

# ---------------------------------------------------------------------------
print("\nPassword column — masked by default, click-to-reveal per row")

pw_vault = fresh()
pw_vault.add(e("github.com", password="Tr0ub4dor&3"))
dlg4 = VaultDialog(pw_vault, None)
row = find_row(dlg4, "github.com")
cell = col(dlg4, row, VaultDialog.COL_PASSWORD)
check("masked by default", cell.text() == VaultDialog._MASKED_PASSWORD)
check("masked text does not leak the real password's length",
      len(VaultDialog._MASKED_PASSWORD) != len("Tr0ub4dor&3")
      or VaultDialog._MASKED_PASSWORD != "Tr0ub4dor&3")

dlg4._on_cell_clicked(row, VaultDialog.COL_PASSWORD)
check("click reveals the real password",
      col(dlg4, row, VaultDialog.COL_PASSWORD).text() == "Tr0ub4dor&3")

dlg4._on_cell_clicked(row, VaultDialog.COL_PASSWORD)
check("clicking again re-masks it",
      col(dlg4, row, VaultDialog.COL_PASSWORD).text()
      == VaultDialog._MASKED_PASSWORD)

# Clicking a different column is a no-op for the password cell.
dlg4._on_cell_clicked(row, VaultDialog.COL_PASSWORD)  # reveal
dlg4._on_cell_clicked(row, VaultDialog.COL_WEBSITE)   # click elsewhere
check("clicking a non-password cell doesn't change the reveal state",
      col(dlg4, row, VaultDialog.COL_PASSWORD).text() == "Tr0ub4dor&3")

# A refresh (e.g. typing in search) re-masks rather than carrying reveal
# state forward.
dlg4.search_edit.setText("git")
row_after = find_row(dlg4, "github.com")
check("a refresh re-masks previously revealed passwords",
      col(dlg4, row_after, VaultDialog.COL_PASSWORD).text()
      == VaultDialog._MASKED_PASSWORD)
dlg4.deleteLater()

# ---------------------------------------------------------------------------
print("\nLast Changed column")

lc_vault = fresh()
lc_vault.add(e("github.com"))
dlg5 = VaultDialog(lc_vault, None)
stamp_text = col(dlg5, find_row(dlg5, "github.com"),
                 VaultDialog.COL_LAST_CHANGED).text()
check("shows the entry's stamped date",
      stamp_text == lc_vault.entries()[0].updated and stamp_text != "—")
dlg5.deleteLater()

# A legacy entry with no stamp (pre-existing field default) shows "—".
legacy = Entry(site="legacy.com", username="bob", password="x", notes="")
assert legacy.updated == ""


class LegacyVault:
    def entries(self):
        return [legacy]

    def reveal(self, index):
        return "x"

    def find_duplicate_groups(self):
        return []

    @property
    def factor_enrolled(self):
        return False


dlg6 = VaultDialog(LegacyVault(), None)
check("a legacy entry with no recorded date shows an em dash",
      col(dlg6, 0, VaultDialog.COL_LAST_CHANGED).text() == "—")
dlg6.deleteLater()

# ---------------------------------------------------------------------------
print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL VAULT-DASHBOARD-COLUMNS TESTS PASSED")
