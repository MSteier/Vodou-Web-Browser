"""Tests for duplicate-login detection and removal (Vault.find_duplicate_groups
/ Vault.remove_duplicates), against a real (temp-file) vault.

Run:  python tests/test_vault_duplicates.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault import Entry, Vault  # noqa: E402

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


# ---------------------------------------------------------------------------
print("find_duplicate_groups — detection")

v = fresh()
v.add(e("github.com"))                      # 0: unique
v.add(e("github.com"))                      # 1: exact duplicate of 0
v.add(e("gitlab.com"))                      # 2: unique
v.add(e("github.com", password="other!Pw9"))  # 3: same site+user, different password -> NOT a duplicate
v.add(e("github.com", username="bob"))       # 4: same site+password, different user -> NOT a duplicate

groups = v.find_duplicate_groups()
check("exactly one duplicate group found", len(groups) == 1)
check("the group is {0, 1} (site+username+password all match)",
      groups == [[0, 1]])
check("a same-site-and-user but different-password entry is not grouped",
      not any(3 in g for g in groups))
check("a same-site-and-password but different-user entry is not grouped",
      not any(4 in g for g in groups))
check("find_duplicate_groups is read-only (nothing deleted)",
      len(v.entries()) == 5)

# ---------------------------------------------------------------------------
print("\nremove_duplicates — no duplicates present")

v2 = fresh()
v2.add(e("a.com"))
v2.add(e("b.com"))
check("nothing to remove -> returns 0", v2.remove_duplicates() == 0)
check("no entries lost", len(v2.entries()) == 2)

# ---------------------------------------------------------------------------
print("\nremove_duplicates — removes extras, keeps the first, merges notes")

v3 = fresh()
v3.add(e("github.com", notes="work account"))          # 0: kept
v3.add(e("github.com", notes="work account"))          # 1: exact dup, same notes
v3.add(e("github.com", notes="has 2FA"))                # 2: exact dup, different notes
v3.add(e("gitlab.com"))                                # 3: unrelated, untouched
removed = v3.remove_duplicates()
check("removed count matches the extra copies (2)", removed == 2)
check("only the unique site + one github.com entry remain",
      sorted(entry.site for entry in v3.entries())
      == ["github.com", "gitlab.com"])
kept = next(entry for entry in v3.entries() if entry.site == "github.com")
check("kept entry's password is unchanged",
      v3.reveal(next(i for i, x in enumerate(v3.entries())
                     if x.site == "github.com")) == "Xk9#mQ2p!wRt4Lv7")
check("duplicate notes aren't repeated", kept.notes.count("work account") == 1)
check("a differing duplicate's notes are merged in, not dropped",
      "has 2FA" in kept.notes)

# ---------------------------------------------------------------------------
print("\nremove_duplicates — persists to disk")

path = v3.path
reopened = Vault(path)
reopened.unlock(PW)
check("after reopening, the duplicates are still gone",
      sorted(entry.site for entry in reopened.entries())
      == ["github.com", "gitlab.com"])

# ---------------------------------------------------------------------------
print("\nremove_duplicates — a three-way duplicate collapses to one")

v4 = fresh()
v4.add(e("x.com"))
v4.add(e("x.com"))
v4.add(e("x.com"))
check("three-way duplicate removes two", v4.remove_duplicates() == 2)
check("exactly one x.com entry remains", len(v4.entries()) == 1)

# ---------------------------------------------------------------------------
print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL VAULT-DUPLICATES TESTS PASSED")
