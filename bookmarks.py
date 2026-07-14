"""Persistent bookmarks store.

Bookmarks are the one thing a user explicitly wants to survive a session, so
unlike history/cookies they are saved to disk — as plain JSON at
~/.vodou/bookmarks.json (they contain no secrets). Writes are atomic.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

BOOKMARKS_FILE = Path.home() / ".vodou" / "bookmarks.json"

# Only these schemes may be stored/opened. Blocks javascript:, data:, file:,
# etc. — a tampered bookmarks.json or crafted import must not be able to plant
# a URL that runs script or reads local files when clicked.
_SAFE_SCHEMES = ("http://", "https://")

MAX_TITLE = 512
MAX_URL = 4096


def _is_safe_url(url: str) -> bool:
    return isinstance(url, str) and url.lower().startswith(_SAFE_SCHEMES) \
        and len(url) <= MAX_URL


@dataclass
class Bookmark:
    title: str
    url: str


class Bookmarks:
    def __init__(self, path: Path = BOOKMARKS_FILE):
        self.path = path
        self._items: list[Bookmark] = []
        self._urls: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            # Drop any entry whose URL isn't a safe web scheme, even if the
            # on-disk file was hand-edited or tampered with.
            self._items = [
                Bookmark(title=str(b.get("title", ""))[:MAX_TITLE],
                         url=str(b["url"]))
                for b in data if _is_safe_url(str(b.get("url", "")))]
        except (ValueError, KeyError, TypeError, OSError):
            self._items = []  # corrupt file: start clean, don't crash
        self._urls = {b.url for b in self._items}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps([asdict(b) for b in self._items], indent=2),
                       encoding="utf-8")
        tmp.replace(self.path)

    def all(self) -> list[Bookmark]:
        return list(self._items)

    def contains(self, url: str) -> bool:
        return url in self._urls

    def add(self, title: str, url: str) -> bool:
        """Add a bookmark. False if already present or an unsafe scheme."""
        if not _is_safe_url(url) or url in self._urls:
            return False
        self._items.append(Bookmark(title=(title or url)[:MAX_TITLE], url=url))
        self._urls.add(url)
        self._save()
        return True

    def remove(self, url: str) -> bool:
        if url not in self._urls:
            return False
        self._items = [b for b in self._items if b.url != url]
        self._urls.discard(url)
        self._save()
        return True

    def update(self, index: int, title: str, url: str) -> bool:
        """Edit the bookmark at index. False if the index is invalid, the URL
        is an unsafe scheme, or the new URL would duplicate a *different*
        existing bookmark."""
        if not (0 <= index < len(self._items)):
            return False
        if not _is_safe_url(url):
            return False
        old = self._items[index]
        if url != old.url and url in self._urls:
            return False
        self._items[index] = Bookmark(title=(title or url)[:MAX_TITLE], url=url)
        self._urls.discard(old.url)
        self._urls.add(url)
        self._save()
        return True

    def remove_at(self, index: int) -> bool:
        if not (0 <= index < len(self._items)):
            return False
        old = self._items.pop(index)
        self._urls.discard(old.url)
        self._save()
        return True

    def toggle(self, title: str, url: str) -> bool:
        """Add if absent, remove if present. Returns True if now bookmarked."""
        if url in self._urls:
            self.remove(url)
            return False
        self.add(title, url)
        return True

    def add_many(self, items: list[Bookmark]) -> int:
        """Bulk-add (for import); skips duplicates & unsafe URLs."""
        added = 0
        for b in items:
            if _is_safe_url(b.url) and b.url not in self._urls:
                self._items.append(Bookmark(title=b.title[:MAX_TITLE],
                                            url=b.url))
                self._urls.add(b.url)
                added += 1
        if added:
            self._save()
        return added
