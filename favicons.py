"""Favicon cache for the bookmarks bar.

Icons are captured from pages *as you browse* and at the moment you bookmark —
never fetched from a third-party favicon service, which would leak your
bookmark list. The cache is deliberately scoped to hosts you have bookmarked
(the same hosts already recorded in bookmarks.json), and pruned whenever a
bookmark is removed, so it never becomes a broader record of where you have
been. Stored as small PNGs under ~/.vodou/favicons/, keyed by host.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtGui import QIcon, QPixmap


class FaviconStore:
    def __init__(self, directory: Path):
        self.dir = directory
        self._cache: dict[str, QIcon] = {}

    @staticmethod
    def _ok(host: str) -> bool:
        # Hosts from QUrl are already filesystem-safe; guard anyway so a odd
        # value can't escape the favicons directory.
        return bool(host) and all(c.isalnum() or c in ".-" for c in host)

    def _path(self, host: str) -> Path:
        return self.dir / f"{host}.png"

    def get(self, host: str) -> QIcon | None:
        host = host.lower()
        cached = self._cache.get(host)
        if cached is not None:
            return cached if not cached.isNull() else None
        if not self._ok(host):
            return None
        path = self._path(host)
        if path.exists():
            icon = QIcon(str(path))
            if not icon.isNull():
                self._cache[host] = icon
                return icon
        return None

    def put(self, host: str, icon: QIcon | None) -> bool:
        """Cache an icon for host. Returns True if it was stored (new/usable)."""
        host = host.lower()
        if icon is None or icon.isNull() or not self._ok(host):
            return False
        pixmap = icon.pixmap(32, 32)
        if pixmap.isNull():
            return False
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            pixmap.save(str(self._path(host)), "PNG")
        except OSError:
            pass  # a cosmetic cache must never disturb browsing
        self._cache[host] = QIcon(pixmap)
        return True

    def prune(self, keep: set[str]) -> None:
        """Drop cached icons (memory and disk) for hosts not in `keep` — used
        to keep the cache aligned with the current bookmark set."""
        keep = {h.lower() for h in keep}
        for host in [h for h in self._cache if h not in keep]:
            del self._cache[host]
        try:
            for file in self.dir.glob("*.png"):
                if file.stem.lower() not in keep:
                    file.unlink()
        except OSError:
            pass
