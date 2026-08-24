"""Tests for the vault auto-lock duration setting (vault_autolock.py).

Pure, no Qt: the option table, the label and interval mappings, validation, and
the config.json load/save round-trip (against a temp file, not the real
profile).

Run:  python tests/test_vault_autolock.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import vault_autolock as va  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


# ---------------------------------------------------------------------------
print("options & mappings")

minutes = [m for m, _ in va.VAULT_AUTOLOCK_OPTIONS]
check("the four requested windows are offered (default + 2h/1d/1w)",
      minutes == [5, 120, 1440, 10080])
check("5 minutes is the default and is a valid choice",
      va.DEFAULT_VAULT_AUTOLOCK_MINUTES == 5
      and va.is_valid_autolock_minutes(5))

check("label: 2 hours", va.autolock_label(120) == "2 hours")
check("label: 1 day", va.autolock_label(1440) == "1 day")
check("label: 1 week", va.autolock_label(10080) == "1 week")
check("label: unknown value falls back to a plain '<n> minutes'",
      va.autolock_label(7) == "7 minutes")

check("interval: 5 minutes -> 300000 ms", va.autolock_interval_ms(5) == 300000)
check("interval: 1 week -> 604800000 ms",
      va.autolock_interval_ms(10080) == 604800000)

check("valid: an offered value", va.is_valid_autolock_minutes(1440))
check("invalid: an unoffered value", not va.is_valid_autolock_minutes(30))
check("invalid: a non-int", not va.is_valid_autolock_minutes("120"))
check("invalid: None", not va.is_valid_autolock_minutes(None))

# ---------------------------------------------------------------------------
print("\nload/save round-trip (temp config.json)")

with tempfile.TemporaryDirectory() as d:
    cfg = Path(d) / "config.json"
    va.CONFIG_FILE = cfg  # load/save read the module global at call time

    check("load: missing file -> default",
          va.load_vault_autolock_minutes() == 5)

    va.save_vault_autolock_minutes(120)
    check("save then load: value persists", va.load_vault_autolock_minutes() == 120)
    check("save wrote the documented key",
          json.loads(cfg.read_text("utf-8"))["vault_autolock_minutes"] == 120)

    va.save_vault_autolock_minutes(10080)
    check("save again: value updates", va.load_vault_autolock_minutes() == 10080)

    # An out-of-range save is coerced to the default rather than stored.
    va.save_vault_autolock_minutes(999)
    check("save: invalid value coerced to the default",
          va.load_vault_autolock_minutes() == 5)
    check("save: invalid value written as the default, not 999",
          json.loads(cfg.read_text("utf-8"))["vault_autolock_minutes"] == 5)

    # Save merges rather than clobbering unrelated config (e.g. searxng_url).
    cfg.write_text(json.dumps({"searxng_url": "https://localhost/searxng"}),
                   encoding="utf-8")
    va.save_vault_autolock_minutes(1440)
    merged = json.loads(cfg.read_text("utf-8"))
    check("save: preserves other config keys",
          merged.get("searxng_url") == "https://localhost/searxng"
          and merged.get("vault_autolock_minutes") == 1440)

    # A garbage/out-of-range value on disk loads as the default.
    cfg.write_text(json.dumps({"vault_autolock_minutes": 42}), encoding="utf-8")
    check("load: out-of-range stored value -> default",
          va.load_vault_autolock_minutes() == 5)
    cfg.write_text("{ not json", encoding="utf-8")
    check("load: unreadable file -> default",
          va.load_vault_autolock_minutes() == 5)

# ---------------------------------------------------------------------------
print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL VAULT-AUTOLOCK TESTS PASSED")
