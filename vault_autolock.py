"""Vault auto-lock duration: the idle window before the unlocked vault re-locks.

Kept in its own tiny, dependency-free module (stdlib only, no Qt) so the two
places that need it share one source of truth: the browser (main.py), which
owns the lock timer, and the vault UI (vault_ui.py), which offers the menu. It
also means the mapping and the persistence can be unit-tested without importing
either of those much heavier modules.

The choice is stored in ~/.vodou/config.json under "vault_autolock_minutes",
alongside other non-secret configuration. 5 minutes is the safe default; the
longer windows trade convenience for keeping the vault's key in memory that much
longer, which the menu surfaces to the user. Only the offered values are ever
accepted — an unknown or out-of-range value falls back to the default rather
than being trusted.
"""

from __future__ import annotations

import json
from pathlib import Path

CONFIG_FILE = Path.home() / ".vodou" / "config.json"

DEFAULT_VAULT_AUTOLOCK_MINUTES = 5

# Ordered (minutes, label) choices offered in the vault's Auto-lock menu. The
# default (5 minutes) leads as the safest option; the rest are the longer
# "stay unlocked" windows the feature adds.
VAULT_AUTOLOCK_OPTIONS: tuple[tuple[int, str], ...] = (
    (5, "5 minutes"),
    (120, "2 hours"),
    (1440, "1 day"),
    (10080, "1 week"),
)

# The minute-values a stored or selected choice must be one of; anything else
# is invalid and coerced to the default.
VALID_AUTOLOCK_MINUTES = frozenset(minutes for minutes, _ in VAULT_AUTOLOCK_OPTIONS)


def is_valid_autolock_minutes(minutes: object) -> bool:
    """Whether ``minutes`` is exactly one of the offered choices."""
    return minutes in VALID_AUTOLOCK_MINUTES


def autolock_label(minutes: int) -> str:
    """Human label for a minutes value ('2 hours'); a plain fallback if unknown."""
    for value, label in VAULT_AUTOLOCK_OPTIONS:
        if value == minutes:
            return label
    return f"{minutes} minutes"


def autolock_interval_ms(minutes: int) -> int:
    """QTimer interval, in milliseconds, for a duration given in minutes."""
    return int(minutes) * 60 * 1000


def load_vault_autolock_minutes() -> int:
    """Idle minutes before the vault auto-locks, read from config.json.

    Defaults to DEFAULT_VAULT_AUTOLOCK_MINUTES; an unknown, out-of-range, or
    unreadable value falls back to that default rather than raising.
    """
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        minutes = int(data.get("vault_autolock_minutes",
                               DEFAULT_VAULT_AUTOLOCK_MINUTES))
    except (OSError, ValueError, AttributeError, TypeError):
        return DEFAULT_VAULT_AUTOLOCK_MINUTES
    return minutes if is_valid_autolock_minutes(minutes) \
        else DEFAULT_VAULT_AUTOLOCK_MINUTES


def save_vault_autolock_minutes(minutes: int) -> None:
    """Persist the chosen idle window to config.json (merging, atomic write).

    An invalid value is coerced to the default, so the file never records a
    choice the UI can't represent. Mirrors main.py's other save_ helpers: it
    merges into the existing config, writes via a temp file + replace, and
    swallows OSError so a read-only profile can't crash the browser.
    """
    if not is_valid_autolock_minutes(minutes):
        minutes = DEFAULT_VAULT_AUTOLOCK_MINUTES
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                data = {}
        except (OSError, ValueError):
            data = {}
        data["vault_autolock_minutes"] = int(minutes)
        tmp = CONFIG_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(CONFIG_FILE)
    except OSError:
        pass
