"""Tests for the engine-update staleness tracking and reminder throttle that
back the more-insistent engine-update nudge (about.py).

Offline and deterministic: it exercises the first_seen / days-outdated logic,
the once-a-day reminder throttle, version-change resets, and clearing when the
engine is current. The network check itself and the dialog are UI-driven.

Run:  python tests/test_update_state.py
"""

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import about  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


about.UPDATE_STATE_FILE = Path(tempfile.mkdtemp()) / "update_state.json"


def _age_first_seen(days):
    st = about._load_update_state()
    st["first_seen"] = time.time() - days * 86400
    about._save_update_state(st)


def _age_last_nagged(hours):
    st = about._load_update_state()
    st["last_nagged"] = time.time() - hours * 3600
    about._save_update_state(st)


print("staleness")
check("no state -> not clamped negative", about.note_engine_outdated("6.11.0") == 0)
check("fresh detection is 0 days outdated",
      about.note_engine_outdated("6.11.0") == 0)
_age_first_seen(15)
check("days-outdated grows with first_seen",
      about.note_engine_outdated("6.11.0") == 15)
check("same version keeps first_seen (still 15)",
      about.note_engine_outdated("6.11.0") == 15)

print("\nreminder throttle")
check("due before any reminder", about.engine_nag_due() is True)
about.mark_engine_nagged()
check("not due right after a reminder", about.engine_nag_due() is False)
_age_last_nagged(23)
check("still not due after 23h", about.engine_nag_due() is False)
_age_last_nagged(25)
check("due again after 25h", about.engine_nag_due() is True)

print("\nversion change resets")
_age_first_seen(30)
about.mark_engine_nagged()
check("new engine version resets days to 0",
      about.note_engine_outdated("6.12.0") == 0)
check("new engine version makes a reminder due again",
      about.engine_nag_due() is True)

print("\nclearing when current")
about.clear_engine_outdated()
check("clear removes the state file",
      not about.UPDATE_STATE_FILE.exists())
check("after clear, tracking starts fresh",
      about.note_engine_outdated("6.12.0") == 0)

print("\nversion comparison (the app update check)")
check("two-digit patch is newer than one-digit",
      about.is_newer("1.54.10", "1.54.9"))
check("one-digit patch is not newer than two-digit",
      not about.is_newer("1.54.9", "1.54.10"))
check("equal versions are not newer",
      not about.is_newer("1.54.10", "1.54.10"))
check("minor bump beats a large patch",
      about.is_newer("1.55.0", "1.54.99"))
# Docker image revisions (1.54.10-r1) are the same app version, so they must
# never trigger "update available" -- and must not parse as 1.54.101.
check("image revision tag is not newer than its app version",
      not about.is_newer("1.54.10-r1", "1.54.10"))
check("image revision tag is not newer than the next patch",
      not about.is_newer("1.54.10-r1", "1.54.11"))
check("a real next patch is newer than an image revision",
      about.is_newer("1.54.11", "1.54.10-r1"))
check("release-candidate suffix doesn't inflate the number",
      not about.is_newer("6.11.0rc1", "6.11.1"))
check("version tuple uses leading digits only",
      about._version_tuple("1.54.10-r1") == (1, 54, 10))

print("\nhelpers")
check("installed_engine_version returns a string",
      isinstance(about.installed_engine_version(), str)
      and about.installed_engine_version() != "")

print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL UPDATE-STATE TESTS PASSED")
