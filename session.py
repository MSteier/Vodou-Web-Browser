"""Crash recovery: a small snapshot of open tabs, kept only while running.

The snapshot lives at ~/.vodou/session.json while the browser is running and
is deleted on every clean exit. So if the file is present at startup, the
last run ended unexpectedly (crash, kill, power loss) and the user is offered
their tabs back.

Privacy note: this is the only place Vodou writes page URLs to disk, and only
the URL of each open tab — no history, titles, or form data. The file is
removed the moment the browser closes normally, and the user can decline the
restore offer, which deletes it immediately.

Performance: callers debounce writes (one coalesced write per burst of
navigation), and save_snapshot() itself skips the disk entirely when nothing
changed since the last write.
"""

from __future__ import annotations

import json
from pathlib import Path

SESSION_FILE = Path.home() / ".vodou" / "session.json"

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
        tmp.write_text(payload, encoding="utf-8")
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


def load_snapshot() -> tuple[list[str], int] | None:
    """Read a leftover snapshot; None if absent or unusable.

    Present file = the previous run did not exit cleanly. The content is
    validated strictly (it sits unencrypted in the profile dir) and anything
    malformed is treated as no snapshot.
    """
    if not SESSION_FILE.exists():
        return None
    try:
        blob = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
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
