"""Aggregated tracker-blocking history, for the ☰ → Blocking report window.

Privacy first. Which trackers you meet is browsing-adjacent data: seeing
"analytics.tiktok.com blocked 40x today" implies where you were. A browser
that keeps no history on disk must not quietly grow a proxy for one, so:

  * Only aggregates are kept — per day, per blocked host, a count. No
    timestamps beyond the date, no URLs, no first-party site, no order.
  * The file is sealed with Windows DPAPI (see dpapi.py), like the cookie
    jar. Same honest limit: software running as you can unseal it.
  * Retention is capped at RETENTION_DAYS; older days are pruned on load
    and on save.
  * Clearing browsing data (Ctrl+Shift+Del) erases it, and the report
    window offers its own reset.

Performance: record() is called from the UI thread for every blocked
request — dozens per second on ad-heavy pages — so it only touches two dict
lookups and marks the state dirty; disk writes are debounced.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

from PyQt6.QtCore import QObject, QTimer

from dpapi import seal, unseal

STATS_FILE = Path.home() / ".vodou" / "blockstats.dat"

RETENTION_DAYS = 90
# Per-day host cap. Trackers are a bounded set, but a hostile or unlucky page
# could mint endless subdomains; keeping the busiest bounds the file's size.
MAX_HOSTS_PER_DAY = 400


def _today() -> str:
    return date.today().isoformat()


class BlockStats(QObject):
    """Per-day, per-host counts of blocked requests."""

    def __init__(self, parent: QObject | None = None,
                 path: Path = STATS_FILE):
        super().__init__(parent)
        self.path = path
        # "YYYY-MM-DD" -> {host: count}
        self._days: dict[str, dict[str, int]] = {}
        self._load()
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(5000)
        self._timer.timeout.connect(self.flush)

    # -- recording -------------------------------------------------------

    def record(self, host: str) -> None:
        day = self._days.setdefault(_today(), {})
        if host not in day and len(day) >= MAX_HOSTS_PER_DAY:
            host = "(other)"  # fold the tail rather than grow without bound
        day[host] = day.get(host, 0) + 1
        if not self._timer.isActive():
            self._timer.start()

    # -- queries ---------------------------------------------------------

    def totals_by_day(self, days: int) -> list[tuple[date, int]]:
        """(day, blocked) for each of the last `days` days, oldest first.

        Days with no blocking are included as zeros — a gap-free axis is
        what makes the chart readable.
        """
        today = date.today()
        out = []
        for offset in range(days - 1, -1, -1):
            d = today - timedelta(days=offset)
            out.append((d, sum(self._days.get(d.isoformat(), {}).values())))
        return out

    def top_hosts(self, days: int, limit: int = 8) -> list[tuple[str, int]]:
        totals: dict[str, int] = {}
        for d, counts in self._window(days):
            for host, n in counts.items():
                totals[host] = totals.get(host, 0) + n
        ranked = sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))
        return ranked[:limit]

    def total(self, days: int) -> int:
        return sum(sum(c.values()) for _, c in self._window(days))

    def busiest_day(self, days: int) -> tuple[date, int] | None:
        points = [p for p in self.totals_by_day(days) if p[1] > 0]
        return max(points, key=lambda p: p[1]) if points else None

    def tracked_since(self) -> date | None:
        """Earliest day on record — so the window can say how much history
        it is actually reporting on."""
        if not self._days:
            return None
        return min(date.fromisoformat(d) for d in self._days)

    def _window(self, days: int) -> list[tuple[str, dict[str, int]]]:
        first = (date.today() - timedelta(days=days - 1)).isoformat()
        return [(d, c) for d, c in self._days.items() if d >= first]

    # -- disk ------------------------------------------------------------

    def _prune(self) -> None:
        cutoff = (date.today() - timedelta(days=RETENTION_DAYS - 1)).isoformat()
        for d in [d for d in self._days if d < cutoff]:
            del self._days[d]

    def _load(self) -> None:
        try:
            raw = json.loads(unseal(self.path.read_bytes()).decode("utf-8"))
        except (OSError, ValueError, TypeError):
            return  # absent, unreadable, or from another Windows account
        if not isinstance(raw, dict):
            return
        for day, counts in raw.items():
            if not isinstance(day, str) or not isinstance(counts, dict):
                continue
            try:
                date.fromisoformat(day)
            except ValueError:
                continue
            clean = {h: n for h, n in counts.items()
                     if isinstance(h, str) and isinstance(n, int) and n > 0}
            if clean:
                self._days[day] = clean
        self._prune()

    def flush(self) -> None:
        self._prune()
        try:
            if not self._days:
                self.path.unlink(missing_ok=True)
                return
            blob = seal(json.dumps(self._days).encode("utf-8"))
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_bytes(blob)
            tmp.replace(self.path)
        except OSError:
            pass  # statistics must never disturb browsing

    def clear(self) -> None:
        self._days.clear()
        self._timer.stop()
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass
