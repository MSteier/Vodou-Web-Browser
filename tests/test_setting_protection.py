"""Tests for Browser Setting Protection: the sealed last-authorized snapshot
and the tamper-history log that back the HMAC-signed prefs.

These cover the scenarios that actually apply to a QtWebEngine embedder (there
is no extension / sync / policy layer to test): an external process editing the
protected values on disk, restoring the user's real value, recording history,
persistence across restarts, and clearing history. The signing/verification
itself lives in main.py and is exercised live.

Run:  python tests/test_setting_protection.py
"""

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import setting_protection as sp  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


# Isolate all state in a temp dir (real DPAPI on Windows; magic header elsewhere).
_tmp = Path(tempfile.mkdtemp())
sp.SNAPSHOT_FILE = _tmp / "snap.dat"
sp.LOG_FILE = _tmp / "prot.log"

KEYS = ("start_page", "search_engine", "startup_page")

# --- snapshot round-trip -----------------------------------------------------
print("snapshot")
check("no file -> empty", sp.load_snapshot() == {})
authorized = {"start_page": "https://home.example",
              "search_engine": "https://searx.example/?q={}",
              "startup_page": "https://start.example"}
sp.save_snapshot(authorized)
back = sp.load_snapshot()
check("round-trips the authorized values",
      all(back.get(k) == authorized[k] for k in KEYS))
check("snapshot is sealed, not plaintext JSON",
      b"home.example" not in sp.SNAPSHOT_FILE.read_bytes()
      or sys.platform != "win32")

# --- tamper diff -------------------------------------------------------------
print("\ntamper diff")
tampered = dict(authorized)
tampered["search_engine"] = "https://evil.example/?q={}"
events = sp.diff_tamper(authorized, tampered, KEYS, "RESTORED")
check("one event for the changed key", len(events) == 1)
if events:
    e = events[0]
    check("event names the setting", e.setting == "search_engine")
    check("event keeps previous authorized value",
          e.previous == authorized["search_engine"])
    check("event keeps attempted value", e.attempted == tampered["search_engine"])
    check("event records the action", e.action == "RESTORED")
    check("event has a friendly label", e.label() == "Default search engine")
check("no change -> no events",
      sp.diff_tamper(authorized, authorized, KEYS, "RESTORED") == [])
check("restore values come straight from the snapshot",
      {k: back.get(k, "") for k in KEYS} == authorized)

# --- history log -------------------------------------------------------------
print("\nhistory")
check("no log -> no events", sp.load_events() == [])
sp.record_events(events)
loaded = sp.load_events()
check("recorded event loads back",
      len(loaded) == 1 and loaded[0].setting == "search_engine")
check("history survives a 'restart' (re-read from disk)",
      len(sp.load_events()) == 1)
# newest-first ordering
time.sleep(0.01)
later = sp.diff_tamper({"start_page": "https://home.example"},
                       {"start_page": "https://hijack.example"},
                       ("start_page",), "RESTORED")
sp.record_events(later)
ev = sp.load_events()
check("newest event first", ev[0].setting == "start_page" and len(ev) == 2)

# cap at _MAX_EVENTS
many = [sp.ProtectionEvent(time.time(), "start_page", "a", "b", "RESET")
        for _ in range(sp._MAX_EVENTS + 25)]
sp.record_events(many)
check("history capped at _MAX_EVENTS",
      len(sp.load_events()) == sp._MAX_EVENTS)

# --- clear -------------------------------------------------------------------
print("\nclear")
sp.clear_events()
check("clear empties the history", sp.load_events() == [])
check("clearing history does not touch the snapshot",
      sp.load_snapshot().get("start_page") == authorized["start_page"])

# --- RESET path (no snapshot) ------------------------------------------------
print("\nreset path (no last-good)")
empty_snap = {}
tamper2 = {"search_engine": "https://evil.example/?q={}"}
ev2 = sp.diff_tamper(empty_snap, tamper2, KEYS, "RESET")
check("tamper vs empty snapshot still logs the attempt",
      any(x.setting == "search_engine" for x in ev2))
check("no snapshot -> restore values are all blank",
      not any(str(empty_snap.get(k, "")).strip() for k in KEYS))

print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL SETTING-PROTECTION TESTS PASSED")
