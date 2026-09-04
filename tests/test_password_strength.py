"""Tests for local password hygiene checks (password_strength.py).

Pure, no Qt, no network: per-password heuristics (length, common passwords,
repeated/sequential runs, the entropy-based Moderate/Strong split) and
cross-entry reuse detection (group_reused).

Run:  python tests/test_password_strength.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import password_strength as ps  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


# ---------------------------------------------------------------------------
print("obvious weaknesses -> Weak, with a reason")

check("empty password is Weak", ps.analyze("").label == "Weak")
check("empty password carries a reason", bool(ps.analyze("").reasons))

short = ps.analyze("abc12")
check("short password is Weak", short.label == "Weak")
check("short password names the length", "5 character" in short.reasons[0])

common = ps.analyze("password123")
check("a well-known password is Weak", common.label == "Weak")
check("common-password reason given",
      any("common" in r.lower() for r in common.reasons))
check("common check is case-insensitive",
      ps.analyze("PASSWORD1").label == "Weak")

repeated = ps.analyze("aaaaaaaaZ9!")
check("a long repeated run is Weak", repeated.label == "Weak")
check("repeat reason given",
      any("repeat" in r.lower() for r in repeated.reasons))

sequence = ps.analyze("myqwertyPass9")
check("an embedded keyboard-row sequence is Weak", sequence.label == "Weak")
check("sequence reason given",
      any("sequence" in r.lower() for r in sequence.reasons))

digits_sequence = ps.analyze("user123456789")
check("an embedded digit sequence is Weak", digits_sequence.label == "Weak")

no_run = ps.analyze("aabbccddZ9!x")
check("doubled (not 4x) letters don't trigger the repeat check",
      not any("repeat" in r.lower() for r in no_run.reasons))

# ---------------------------------------------------------------------------
print("\nentropy banding for passwords with no named weakness")

moderate = ps.analyze("Xk9#mQ2p")  # 8 chars, all 4 classes, no bad pattern
check("a short-but-diverse password has no disqualifying reason",
      not moderate.reasons)
check("...and is Moderate or better",
      moderate.label in ("Moderate", "Strong"))

strong = ps.analyze("qX7#mZ2$vL9@wRk4!")  # 18 chars, all 4 classes
check("a long, diverse, pattern-free password is Strong",
      strong.label == "Strong")
check("Strong carries no reasons", not strong.reasons)
check("bits scale with length",
      ps.analyze("qX7#mZ2$vL9@wRk4!" * 2).bits > strong.bits)

# ---------------------------------------------------------------------------
print("\npool-size estimate reflects character classes actually used")

check("digits-only uses a 10-char pool",
      abs(ps._pool_size("13579246") - 10) < 1e-9)
check("lowercase-only uses a 26-char pool",
      abs(ps._pool_size("abcdefgh") - 26) < 1e-9)
check("mixed-case + digit + symbol uses the full pool",
      ps._pool_size("aB3!") == 26 + 26 + 10 + 32)

# ---------------------------------------------------------------------------
print("\ngroup_reused — cross-entry password matching")

unique = ps.group_reused([(0, "aaa"), (1, "bbb"), (2, "ccc")])
check("all-unique passwords -> empty result", unique == {})

pair = ps.group_reused([(0, "shared"), (1, "aaa"), (2, "shared")])
check("a shared password flags both indices", pair == {0: 2, 2: 2})
check("the non-shared index is omitted", 1 not in pair)

triple = ps.group_reused([(0, "x"), (1, "x"), (2, "x"), (3, "y")])
check("three-way reuse counts all three",
      triple == {0: 3, 1: 3, 2: 3})

blanks = ps.group_reused([(0, ""), (1, ""), (2, "aaa")])
check("blank passwords are never counted as reused", blanks == {})

check("order of the input pairs doesn't matter",
      ps.group_reused([(2, "shared"), (0, "shared"), (1, "aaa")])
      == {0: 2, 2: 2})

check("empty input -> empty result", ps.group_reused([]) == {})

# ---------------------------------------------------------------------------
print("\ngroup_reused — registrable-domain suppression")

# Same password, but every entry is the same site reached by different
# hostnames -> not reuse.
same_site = ps.group_reused(
    [(0, "shared"), (1, "shared"), (2, "shared")],
    {0: "apple.com", 1: "apple.com", 2: "apple.com"})
check("shared password within one registrable domain is not flagged",
      same_site == {})

# Shared across two registrable domains -> genuine reuse, every member flagged.
cross = ps.group_reused(
    [(0, "shared"), (1, "shared"), (2, "shared")],
    {0: "fisglobal.com", 1: "fisglobal.com", 2: "ebtedge.us"})
check("shared password spanning two registrable domains flags all members",
      cross == {0: 3, 1: 3, 2: 3})

# A second, unrelated pair on distinct domains is unaffected.
mixed = ps.group_reused(
    [(0, "p"), (1, "p"), (2, "q"), (3, "q")],
    {0: "a.com", 1: "a.com", 2: "b.com", 3: "c.com"})
check("only the cross-domain group survives",
      mixed == {2: 2, 3: 2})

# Unknown/blank domain for a member doesn't manufacture a second domain.
unknown = ps.group_reused(
    [(0, "shared"), (1, "shared")], {0: "apple.com", 1: ""})
check("a blank domain isn't counted as a distinct domain", unknown == {})

check("no domains map -> original behavior (exact-match reuse)",
      ps.group_reused([(0, "s"), (1, "s")]) == {0: 2, 1: 2})

# ---------------------------------------------------------------------------
print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL PASSWORD-STRENGTH TESTS PASSED")
