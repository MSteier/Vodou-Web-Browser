"""Local, offline password hygiene checks for the vault: per-password
strength analysis, and cross-entry reuse detection.

Nothing here ever leaves the device, is logged, or is sent anywhere: every
check runs against password strings already held in memory by the caller
(vault_ui.py, which reveal()s them from the vault the same way it always
has for fill/copy/edit), using a small bundled list of well-known
leaked/reused passwords and a handful of pattern checks. No network access
-- this module imports nothing beyond the standard library, and never
raises on its input (a malformed/empty password just scores Weak).

The entropy estimate uses the same method as the reference generator this
vault's "Generate Strong Password" dialog is modeled on
(Password_Generator.html): bits = length * log2(character-pool size). For a
freshly generated password the pool is exactly what was offered; for an
existing, user-typed password there's no way to know the intended pool, so
it's inferred from which character classes actually appear in it -- a
standard, conservative heuristic.

Reuse detection (group_reused) is a separate, relational concern: whether
two or more saved entries share the exact same password. It says nothing
about that password's own quality -- a reused password can still score
Strong on entropy alone, which is exactly why the two checks are surfaced
independently rather than folded into one verdict.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

# A short, well-known set of the most commonly leaked/reused passwords
# (drawn from public breach-frequency lists such as the "rockyou" corpus).
# Checked case-insensitively. This is a cheap, obvious-case filter -- it
# catches passwords people actually reuse, which the entropy estimate alone
# would not (several of these are "long enough" to score well on bits alone).
COMMON_PASSWORDS = frozenset({
    "123456", "123456789", "12345678", "12345", "1234567", "1234567890",
    "111111", "000000", "121212", "123123", "123321", "555555", "666666",
    "password", "password1", "password123", "passw0rd", "p@ssw0rd",
    "letmein", "letmein1",
    "welcome", "welcome1", "qwerty", "qwertyuiop", "qazwsx", "1qaz2wsx",
    "abc123", "iloveyou", "admin", "administrator", "root", "toor",
    "login", "guest", "test", "user", "default", "changeme", "monkey",
    "dragon", "master", "superman", "michael", "ninja", "azerty",
    "trustno1", "hello", "freedom", "whatever", "starwars", "shadow",
    "sunshine", "princess", "football", "baseball", "asdfghjkl",
})

# Keyboard/alphabet runs, checked both ascending and descending, and
# case-insensitively (the caller lowercases first).
_SEQUENCE_ALPHABETS = (
    "0123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
)
_MIN_SEQUENCE_RUN = 4
_MIN_REPEAT_RUN = 4


@dataclass
class StrengthResult:
    label: str                                        # "Weak" | "Moderate" | "Strong"
    bits: float                                        # estimated entropy, for display
    reasons: list[str] = field(default_factory=list)   # why -- empty when there's none


def _pool_size(password: str) -> int:
    """Character classes actually present in `password` -> an estimated
    draw-pool size, the same four buckets the generator offers."""
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(not c.isalnum() for c in password):
        size += 32
    return size or 1


def _longest_repeat_run(password: str) -> int:
    """Length of the longest run of one character repeated back to back."""
    if not password:
        return 0
    longest = run = 1
    for i in range(1, len(password)):
        run = run + 1 if password[i] == password[i - 1] else 1
        longest = max(longest, run)
    return longest


def _has_sequence_run(lowered: str) -> bool:
    """Whether `lowered` contains a run of >= _MIN_SEQUENCE_RUN consecutive
    characters from a known alphabet or keyboard row, in either direction."""
    for alphabet in _SEQUENCE_ALPHABETS:
        for run in (alphabet, alphabet[::-1]):
            for i in range(len(run) - _MIN_SEQUENCE_RUN + 1):
                if run[i:i + _MIN_SEQUENCE_RUN] in lowered:
                    return True
    return False


def analyze(password: str) -> StrengthResult:
    """Score one password using only local heuristics: an entropy estimate,
    plus a few checks for obvious weaknesses a raw bit-count alone would
    miss. Any one of those concrete weaknesses marks the password Weak
    outright, regardless of its entropy; otherwise the verdict is purely
    the entropy band, split at the same 60-bit "strong" threshold the
    reference generator uses."""
    if not password:
        return StrengthResult("Weak", 0.0, ["No password set."])

    lowered = password.lower()
    bits = round(len(password) * math.log2(_pool_size(password)), 1)
    reasons: list[str] = []

    if len(password) < 8:
        reasons.append(
            f"Too short ({len(password)} character"
            f"{'s' if len(password) != 1 else ''}) — use at least 12.")
    if lowered in COMMON_PASSWORDS:
        reasons.append("One of the most common leaked passwords — avoid it.")
    if _longest_repeat_run(password) >= _MIN_REPEAT_RUN:
        reasons.append("Contains a long run of the same repeated character.")
    if _has_sequence_run(lowered):
        reasons.append(
            "Contains an easily guessed sequence, like \"1234\" or "
            "\"qwerty\".")

    if reasons:
        label = "Weak"
    elif bits < 60:
        label = "Moderate"
    else:
        label = "Strong"
    return StrengthResult(label, bits, reasons)


def group_reused(entries: list[tuple[int, str]],
                 domains: dict[int, str] | None = None) -> dict[int, int]:
    """Given (index, password) pairs -- one per saved vault entry, however
    many share the same password -- return {index: count} for every index
    whose password matches at least one other entry's. `count` is how many
    entries in total (including this one) share that exact password.
    Indices with a unique password are omitted from the result entirely,
    and a blank password is never treated as "reused" -- an absent
    password on two different entries isn't a meaningful match.

    If `domains` is given ({index: registrable domain}), a shared password
    only counts as reuse when it spans at least two *distinct* registrable
    domains: the same login reached through several hostnames of one site
    (`apple.com` / `idmsa.apple.com`, a bank's bare and `online.` domains)
    is one account, not password reuse. A group where every member maps to
    the same domain -- or to no known domain -- is dropped entirely."""
    by_password: dict[str, list[int]] = {}
    for index, pw in entries:
        if pw:
            by_password.setdefault(pw, []).append(index)

    result: dict[int, int] = {}
    for indices in by_password.values():
        if len(indices) < 2:
            continue
        if domains is not None:
            spanned = {domains.get(i) for i in indices}
            spanned.discard(None)
            spanned.discard("")
            if len(spanned) < 2:
                continue
        for i in indices:
            result[i] = len(indices)
    return result
