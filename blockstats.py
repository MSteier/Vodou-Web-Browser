"""In-memory tracker-blocking counts for the ☰ → Blocking report window.

Privacy first, and now session-only. Which trackers you meet is
browsing-adjacent data: seeing "analytics.tiktok.com blocked 40x" implies
where you were. A browser that keeps no history on disk must not quietly grow
a proxy for one — so the blocking counts are held in memory only and die with
the process, exactly like cookies and history. Nothing is written to disk.

The counts are bucketed per minute, kept for at most SESSION_HOURS, which is
therefore the longest window the report can show (per-minute and per-hour
views over the current run). Clearing browsing data (Ctrl+Shift+Del) drops
them immediately, and the report window offers its own reset.

Performance: record() runs on the UI thread for every blocked request — dozens
per second on ad-heavy pages — so it only bumps a couple of dict entries and
occasionally trims the tail of the buffer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from PyQt6.QtCore import QObject

# Earlier versions persisted per-day counts here. Nothing reads or writes it
# now; the leftover is deleted on startup so old browsing-adjacent data does
# not linger on disk.
_LEGACY_FILE = Path.home() / ".vodou" / "blockstats.dat"

# The whole buffer's horizon: how long a minute bucket is kept in memory, and
# so the longest period the report can offer.
SESSION_HOURS = 24
# Per-bucket host cap. Trackers are a bounded set, but a hostile or unlucky
# page could mint endless subdomains; keeping the busiest bounds memory use.
MAX_HOSTS = 400


@dataclass(frozen=True)
class Period:
    """A selectable reporting window and the bucket size it is drawn at."""
    key: str
    label: str          # dropdown text
    bucket: str         # "minute" | "hour"
    count: int          # number of buckets across the window
    unit: str           # noun for "about N per <unit>"


# Bounded by how the data is stored: the in-memory buffer holds at most
# SESSION_HOURS, so the longest period is the past 24 hours.
PERIODS: tuple[Period, ...] = (
    Period("1h", "Past hour", "minute", 60, "minute"),
    Period("24h", "Past 24 hours", "hour", SESSION_HOURS, "hour"),
)


class BlockStats(QObject):
    """Per-minute host counts of blocked requests, for this run only."""

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        # minute (datetime, second/µs zeroed) -> {host: count}
        self._minutes: dict[datetime, dict[str, int]] = {}
        try:  # remove any persisted stats left by an earlier version
            _LEGACY_FILE.unlink(missing_ok=True)
        except OSError:
            pass

    # -- recording -------------------------------------------------------

    @staticmethod
    def _bump(bucket: dict[str, int], host: str) -> None:
        if host not in bucket and len(bucket) >= MAX_HOSTS:
            host = "(other)"  # fold the tail rather than grow without bound
        bucket[host] = bucket.get(host, 0) + 1

    def record(self, host: str) -> None:
        now = datetime.now()
        minute = now.replace(second=0, microsecond=0)
        self._bump(self._minutes.setdefault(minute, {}), host)
        if len(self._minutes) > (SESSION_HOURS * 60 + 60):
            self._trim(minute)

    def _trim(self, now_minute: datetime) -> None:
        cutoff = now_minute - timedelta(hours=SESSION_HOURS)
        for t in [t for t in self._minutes if t < cutoff]:
            del self._minutes[t]

    # -- queries (all take a Period) -------------------------------------

    def _buckets(self, period: Period) -> list[dict[str, int]]:
        """The per-minute host-count dicts falling in the window."""
        now = datetime.now().replace(second=0, microsecond=0)
        minutes_back = period.count * (60 if period.bucket == "hour" else 1)
        cutoff = now - timedelta(minutes=minutes_back - 1)
        return [c for t, c in self._minutes.items() if t >= cutoff]

    def series(self, period: Period) -> list[tuple[datetime, int]]:
        """(bucket-start, blocked) for each bucket in the window, oldest
        first, zero-filled so the chart has a gap-free axis."""
        now = datetime.now()
        out: list[tuple[datetime, int]] = []
        if period.bucket == "minute":
            base = now.replace(second=0, microsecond=0)
            for off in range(period.count - 1, -1, -1):
                t = base - timedelta(minutes=off)
                out.append((t, sum(self._minutes.get(t, {}).values())))
        else:  # hour
            base = now.replace(minute=0, second=0, microsecond=0)
            per_hour = self._hour_totals()
            for off in range(period.count - 1, -1, -1):
                h = base - timedelta(hours=off)
                out.append((h, per_hour.get(h, 0)))
        return out

    def _hour_totals(self) -> dict[datetime, int]:
        totals: dict[datetime, int] = {}
        for t, counts in self._minutes.items():
            h = t.replace(minute=0)
            totals[h] = totals.get(h, 0) + sum(counts.values())
        return totals

    def total(self, period: Period) -> int:
        return sum(n for _, n in self.series(period))

    def top_hosts(self, period: Period,
                  limit: int = 8) -> list[tuple[str, int]]:
        totals: dict[str, int] = {}
        for counts in self._buckets(period):
            for host, n in counts.items():
                totals[host] = totals.get(host, 0) + n
        ranked = sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))
        return ranked[:limit]

    def busiest(self, period: Period) -> tuple[datetime, int] | None:
        points = [p for p in self.series(period) if p[1] > 0]
        return max(points, key=lambda p: p[1]) if points else None

    # -- lifecycle -------------------------------------------------------

    def clear(self) -> None:
        self._minutes.clear()
