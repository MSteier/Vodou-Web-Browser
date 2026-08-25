"""Tests for the vault's password generator (vault.generate_password).

Pure, no Qt: the character-type toggles, the "at least one type required"
guard, and that every enabled type actually shows up in the result -- the
same contract GeneratePasswordDialog (vault_ui.py) relies on.

Run:  python tests/test_password_generator.py
"""

import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault import GENERATOR_PUNCTUATION, generate_password  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


# ---------------------------------------------------------------------------
print("length is respected")

for n in (4, 8, 16, 64):
    check(f"length={n}", len(generate_password(n)) == n)

# ---------------------------------------------------------------------------
print("\nat least one type must be enabled")

try:
    generate_password(16, letters=False, numbers=False, symbols=False)
    check("all types off raises ValueError", False)
except ValueError:
    check("all types off raises ValueError", True)

# ---------------------------------------------------------------------------
print("\neach enabled type is guaranteed present (100 trials each)")


def all_from(pw, alphabet):
    return all(c in alphabet for c in pw)


for _ in range(100):
    pw = generate_password(20, letters=True, numbers=False, symbols=False)
    if not (all_from(pw, string.ascii_letters)
            and any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)):
        check("letters-only draws from a-zA-Z with both cases present", False)
        break
else:
    check("letters-only draws from a-zA-Z with both cases present", True)

for _ in range(100):
    pw = generate_password(20, letters=False, numbers=True, symbols=False)
    if not all_from(pw, string.digits):
        check("numbers-only draws from 0-9 only", False)
        break
else:
    check("numbers-only draws from 0-9 only", True)

for _ in range(100):
    pw = generate_password(20, letters=False, numbers=False, symbols=True)
    if not all_from(pw, GENERATOR_PUNCTUATION):
        check("symbols-only draws from the punctuation set only", False)
        break
else:
    check("symbols-only draws from the punctuation set only", True)

for _ in range(100):
    pw = generate_password(12)  # default: all three types on
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(c in GENERATOR_PUNCTUATION for c in pw)
    if not (has_lower and has_upper and has_digit and has_symbol):
        check("all types on -> all four classes present", False)
        break
else:
    check("all types on -> all four classes present", True)

# ---------------------------------------------------------------------------
print("\ntwo calls don't collide (CSPRNG sanity)")

check("1000 generated passwords are all distinct",
      len({generate_password(20) for _ in range(1000)}) == 1000)

# ---------------------------------------------------------------------------
print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL PASSWORD-GENERATOR TESTS PASSED")
