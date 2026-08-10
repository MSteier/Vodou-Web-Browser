"""Browser Setting Protection — the tamper HISTORY and last-authorized SNAPSHOT
that sit alongside the HMAC signing in main.py.

main.py already BLOCKS unauthorized edits to the integrity-signed prefs (start
page, search engine, startup page): a value not written by Vodou's own Settings
UI carries no valid signature and is refused at load. This module adds the two
pieces that block alone couldn't:

  * a DPAPI-sealed SNAPSHOT of the last values Vodou itself authorized, so a
    detected tamper can be reverted to the user's REAL setting rather than a
    blank default (spec §8 step 4), and
  * a sealed HISTORY of tamper events, so the user can review what tried to
    change what, and when (spec §13 history, §16 event log).

Scope, honestly: Vodou is a QtWebEngine embedder, not a Chromium fork. There is
no extension system, enterprise-policy engine, or sync, and web content has no
path to these prefs (no QWebChannel/registerObject bridge exists). So the only
real attacker for these settings is another process editing ~/.vodou/prefs.json
on disk — adware, an installer, a "search hijacker". That is what this guards.

Both files are sealed with DPAPI, so another Windows account or an offline disk
can't read or forge them. Same honest limit as Vodou's cookie jar: software
running AS this user could still re-seal them — this raises the bar, it is not
a defence against code already running as you.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import dpapi

_DIR = Path.home() / ".vodou"
SNAPSHOT_FILE = _DIR / "setting_snapshot.dat"   # sealed: last authorized values
LOG_FILE = _DIR / "setting_protection.log"      # sealed: tamper history
_MAX_EVENTS = 100

# Friendly labels for the protected preference keys.
LABELS = {
    "start_page": "Home / start page",
    "search_engine": "Default search engine",
    "startup_page": "Startup page",
}


@dataclass
class ProtectionEvent:
    """One protected key that was found changed on disk without authorization."""
    time: float          # epoch seconds
    setting: str         # protected key
    previous: str        # last authorized value (may be "")
    attempted: str       # value found on disk (unsigned / tampered)
    action: str          # "RESTORED" (real value put back) or "RESET" (to default)

    def label(self) -> str:
        return LABELS.get(self.setting, self.setting)


def save_snapshot(values: dict) -> None:
    """Seal the current authorized values. Call on every trusted prefs write."""
    try:
        _DIR.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {k: str(values.get(k, "")) for k in LABELS}).encode("utf-8")
        tmp = SNAPSHOT_FILE.with_suffix(".tmp")
        tmp.write_bytes(dpapi.seal(payload))
        tmp.replace(SNAPSHOT_FILE)
    except OSError:
        pass


def load_snapshot() -> dict:
    """The last authorized values, or {} if none / unreadable / forged."""
    try:
        data = json.loads(
            dpapi.unseal(SNAPSHOT_FILE.read_bytes()).decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _load_events_raw() -> list:
    try:
        data = json.loads(dpapi.unseal(LOG_FILE.read_bytes()).decode("utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def record_events(events: "list[ProtectionEvent]") -> None:
    """Append tamper events to the sealed history (kept to the last _MAX_EVENTS)."""
    if not events:
        return
    try:
        _DIR.mkdir(parents=True, exist_ok=True)
        combined = (_load_events_raw() + [asdict(e) for e in events])[-_MAX_EVENTS:]
        tmp = LOG_FILE.with_suffix(".tmp")
        tmp.write_bytes(dpapi.seal(json.dumps(combined).encode("utf-8")))
        tmp.replace(LOG_FILE)
    except OSError:
        pass


def load_events() -> "list[ProtectionEvent]":
    """The tamper history, newest first."""
    out = []
    for d in _load_events_raw():
        try:
            out.append(ProtectionEvent(
                time=float(d.get("time", 0)),
                setting=str(d.get("setting", "")),
                previous=str(d.get("previous", "")),
                attempted=str(d.get("attempted", "")),
                action=str(d.get("action", ""))))
        except (TypeError, ValueError):
            continue
    out.reverse()
    return out


def clear_events() -> None:
    """Forget the recorded tamper history (does not weaken protection)."""
    try:
        LOG_FILE.unlink()
    except OSError:
        pass


def diff_tamper(snapshot: dict, on_disk: dict, keys, action: str
                ) -> "list[ProtectionEvent]":
    """One event per protected key whose on-disk value differs from the last
    authorized snapshot value. `action` records what Vodou did in response."""
    now = time.time()
    events = []
    for k in keys:
        prev = str(snapshot.get(k, ""))
        cur = str(on_disk.get(k, ""))
        if cur != prev:
            events.append(ProtectionEvent(now, k, prev, cur, action))
    return events
