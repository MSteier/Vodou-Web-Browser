"""Crash recovery: a small snapshot of open tabs, kept only while running.

The snapshot lives at ~/.vodou/session.json while the browser is running and
is deleted on every clean exit. So if the file is present at startup, the
last run ended unexpectedly (crash, kill, power loss) and the user is offered
their tabs back.

Privacy note: this is the only place Vodou writes page URLs to disk, and only
the URL of each open tab — no history, titles, or form data. On top of being
removed the moment the browser closes normally (and immediately if the user
declines the restore offer), the file is sealed at rest with the same per-user
OS encryption as the cookie jar (Windows DPAPI; see dpapi.py) — so a leftover
crash snapshot isn't a plaintext list of your open tabs another account or a
lifted disk could read. Like the jar, it is not protection from software
running as you.

Performance: callers debounce writes (one coalesced write per burst of
navigation), and save_snapshot() itself skips the disk entirely when nothing
changed since the last write.
"""

from __future__ import annotations

import json
from pathlib import Path

from dpapi import seal as _seal, unseal as _unseal

SESSION_FILE = Path.home() / ".vodou" / "session.json"
# Set just before an *intentional* self-restart (e.g. applying a graphics
# change) so the next launch restores the tabs silently instead of showing the
# "didn't shut down cleanly" prompt.
RESTART_FLAG = Path.home() / ".vodou" / "restart.flag"

# Sanity cap when reading the file back: a corrupt or hand-edited snapshot
# must not make the browser try to open hundreds of tabs.
MAX_TABS = 40

_last_written: str | None = None


def save_snapshot(urls: list[str], current: int) -> None:
    """Write the open-tab snapshot, atomically, only if it changed."""
    global _last_written
    payload = json.dumps({"urls": urls, "current": current})
    if payload == _last_written:
        return
    try:
        SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = SESSION_FILE.with_suffix(".tmp")
        # Sealed at rest. If sealing fails (DPAPI error), write nothing rather
        # than fall back to a plaintext tab list — fail closed.
        tmp.write_bytes(_seal(payload.encode("utf-8")))
        tmp.replace(SESSION_FILE)
        _last_written = payload
    except OSError:
        pass  # a failed snapshot must never disturb browsing


def clear_snapshot() -> None:
    """Remove the snapshot — called on clean exit and on declined restore."""
    global _last_written
    _last_written = None
    try:
        SESSION_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def mark_restart() -> None:
    """Flag that the coming exit is an intentional restart, not a crash."""
    try:
        RESTART_FLAG.parent.mkdir(parents=True, exist_ok=True)
        RESTART_FLAG.write_text("1", encoding="utf-8")
    except OSError:
        pass


def consume_restart() -> bool:
    """True (once) if the last exit was an intentional restart; clears the flag."""
    try:
        if RESTART_FLAG.exists():
            RESTART_FLAG.unlink(missing_ok=True)
            return True
    except OSError:
        pass
    return False


def load_snapshot() -> tuple[list[str], int] | None:
    """Read a leftover snapshot; None if absent or unusable.

    Present file = the previous run did not exit cleanly. It is unsealed first
    (a legacy plaintext snapshot from before sealing, or a tampered/foreign
    blob, fails to unseal and is treated as no snapshot), then validated
    strictly — anything malformed is also treated as no snapshot.
    """
    if not SESSION_FILE.exists():
        return None
    try:
        raw = _unseal(SESSION_FILE.read_bytes())
        blob = json.loads(raw.decode("utf-8"))
        urls = [u for u in blob["urls"][:MAX_TABS]
                if isinstance(u, str)
                and u.startswith(("http://", "https://", "file://"))]
        current = int(blob["current"])
    except (OSError, ValueError, TypeError, KeyError):
        return None
    if not urls:
        return None
    if not 0 <= current < len(urls):
        current = 0
    return urls, current
