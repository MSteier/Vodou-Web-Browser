"""Tests for current-site prioritization of the vault's login list.

Two layers:
  * pure ordering logic (prioritize_by_site / _is_current_site) — no Qt needed;
  * a VaultDialog integration pass under the offscreen Qt platform, with a fake
    vault, checking that search + the existing (vault-index) order still hold and
    that the current-site logins are floated to the top of the rendered table.

Run:  python tests/test_vault_prioritize.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Must be set before any QApplication is created so the GUI part runs headless.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from vault import Entry  # noqa: E402
from vault_ui import (  # noqa: E402
    VaultDialog,
    _is_current_site,
    prioritize_by_site,
)

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


def e(site, username="user", notes=""):
    return Entry(site=site, username=username, password="", notes=notes)


def sites(pairs):
    """The site column, in order, from a list of (index, Entry) pairs."""
    return [entry.site for _, entry in pairs]


# ---------------------------------------------------------------------------
print("_is_current_site — same-site matching")

check("exact match", _is_current_site("replica.com", "replica.com"))
check("www on the login is ignored",
      _is_current_site("www.replica.com", "replica.com"))
check("www on the page is ignored",
      _is_current_site("replica.com", "www.replica.com"))
check("login parent matches on a subdomain page",
      _is_current_site("replica.com", "app.replica.com"))
check("login subdomain matches on the parent page",
      _is_current_site("app.replica.com", "replica.com"))
check("stored URL form is normalized",
      _is_current_site("https://replica.com/login", "replica.com"))
check("unrelated domain does not match",
      not _is_current_site("example.com", "replica.com"))
check("suffix-only lookalike does not match (notreplica.com)",
      not _is_current_site("notreplica.com", "replica.com"))
check("sibling subdomains are not grouped",
      not _is_current_site("a.replica.com", "b.replica.com"))
check("empty current site never matches",
      not _is_current_site("replica.com", ""))

# ---------------------------------------------------------------------------
print("\nprioritize_by_site — ordering")

pairs = [(0, e("example.com")),
         (1, e("replica.com")),
         (2, e("other.com"))]

check("current match floated to the top",
      sites(prioritize_by_site(pairs, "replica.com"))
      == ["replica.com", "example.com", "other.com"])

check("no current site preserves the original order",
      sites(prioritize_by_site(pairs, "")) == sites(pairs))

check("no match preserves the original order",
      sites(prioritize_by_site(pairs, "nowhere.com")) == sites(pairs))

many = [(0, e("example.com")),
        (1, e("replica.com", "alice")),
        (2, e("other.com")),
        (3, e("www.replica.com", "bob")),
        (4, e("app.replica.com", "carol")),
        (5, e("zebra.com"))]

ordered = prioritize_by_site(many, "replica.com")
check("all current-site matches come before the rest",
      sites(ordered)[:3] == ["replica.com", "www.replica.com", "app.replica.com"])
check("non-matches keep their original relative order",
      sites(ordered)[3:] == ["example.com", "other.com", "zebra.com"])
check("matches keep their original relative order among themselves",
      [u for _, ent in ordered[:3] for u in [ent.username]]
      == ["alice", "bob", "carol"])
check("prioritize does not drop or duplicate any entry",
      sorted(i for i, _ in ordered) == [0, 1, 2, 3, 4, 5])

# subdomain page: parent-domain login should still be prioritized.
onsub = prioritize_by_site(many, "app.replica.com")
check("on a subdomain page, same-site logins are floated up",
      set(sites(onsub)[:3])
      == {"replica.com", "www.replica.com", "app.replica.com"})

# ---------------------------------------------------------------------------
print("\nVaultDialog integration (offscreen Qt)")


class FakeVault:
    """Just enough of the Vault surface for VaultDialog._refresh()."""

    def __init__(self, entries):
        self._entries = entries

    def entries(self):
        return self._entries


def table_sites(dialog):
    return [dialog.table.item(r, 0).text()
            for r in range(dialog.table.rowCount())]


try:
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])

    vault = FakeVault([e("example.com"),
                       e("replica.com", "alice"),
                       e("other.com"),
                       e("app.replica.com", "carol"),
                       e("zebra.com")])

    # Opened while on replica.com -> current-site logins lead the table.
    dlg = VaultDialog(vault, None, current_site="replica.com")
    check("dialog: current-site logins are at the top",
          table_sites(dlg)[:2] == ["replica.com", "app.replica.com"])
    check("dialog: the rest keep vault-index order",
          table_sites(dlg)[2:] == ["example.com", "other.com", "zebra.com"])

    # Text search still filters, and prioritization still applies within it.
    dlg.search_edit.setText("com")  # matches everything (all .com)
    check("dialog: search keeps all matches and still prioritizes",
          table_sites(dlg)[:2] == ["replica.com", "app.replica.com"])

    dlg.search_edit.setText("zebra")
    check("dialog: a narrowing search filters the list",
          table_sites(dlg) == ["zebra.com"])

    dlg.search_edit.setText("")

    # No current site -> plain vault-index order (existing behavior).
    dlg2 = VaultDialog(vault, None, current_site="")
    check("dialog: no current site -> original order preserved",
          table_sites(dlg2)
          == ["example.com", "replica.com", "other.com",
              "app.replica.com", "zebra.com"])

    # A live tab/site change re-prioritizes an already-open window.
    dlg2.set_current_site("zebra.com")
    check("dialog: set_current_site re-prioritizes live",
          table_sites(dlg2)[0] == "zebra.com")
    dlg2.set_current_site("")
    check("dialog: clearing current site restores original order",
          table_sites(dlg2)
          == ["example.com", "replica.com", "other.com",
              "app.replica.com", "zebra.com"])

    dlg.deleteLater()
    dlg2.deleteLater()
except Exception as exc:  # pragma: no cover - surfaces as a test failure
    check(f"VaultDialog integration ran without error ({exc!r})", False)

# ---------------------------------------------------------------------------
print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL VAULT-PRIORITIZE TESTS PASSED")
