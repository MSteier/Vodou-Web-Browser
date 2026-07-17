"""The blocking report window: what Vodou blocked, over a chosen period.

Drawn with QPainter rather than rendered as a document — it is a native
window, and it re-reads the active Vodou theme so it matches the chrome in
both dark and light mode.

Chart design notes (deliberate, not incidental):
  * One series ("requests blocked"), so one hue — the theme accent — and no
    legend: the heading already says what is plotted. Text never wears the
    data colour; it uses the theme's text/muted tokens.
  * Columns are capped at 24px, have a 4px rounded top and a square base,
    and are separated by a 2px gap of the surface colour rather than by
    borders drawn around them.
  * Grid is a solid hairline one step off the surface, and stays recessive.
  * Values are never printed on every column (that is unreadable noise):
    the y-axis ticks carry the scale, the busiest day is labelled directly,
    and hovering any column gives its exact figure. The top-tracker list
    prints its numbers, so no value is reachable only by hover.
"""

from __future__ import annotations

import math
from datetime import date

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPainterPath
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from blockstats import RETENTION_DAYS, BlockStats
from theme import build_palette, load_prefs

# The filter row's periods. Nothing longer than the retention window, or the
# report would quietly show a partial picture as if it were whole.
PERIODS: tuple[tuple[str, int], ...] = (
    ("Last 7 days", 7),
    ("Last 30 days", 30),
    (f"Last {RETENTION_DAYS} days", RETENTION_DAYS),
)

BAR_MAX_W = 24     # never fill the band; the leftover is air
BAR_GAP = 2        # surface gap between touching columns
RADIUS = 4         # rounded data-end


def _nice_ceiling(value: int) -> int:
    """Round an axis top up to a clean number (1/2/2.5/5 × 10ⁿ)."""
    if value <= 0:
        return 1
    magnitude = 10 ** math.floor(math.log10(value))
    for step in (1, 2, 2.5, 5, 10):
        top = step * magnitude
        if value <= top:
            return int(top)
    return int(10 * magnitude)


def _bar_path(rect: QRectF) -> QPainterPath:
    """A column: rounded data-end on top, square at the baseline.

    Built as one explicit outline. Unioning a rounded rect with a square one
    leaves a hairline seam along the join once antialiased.
    """
    path = QPainterPath()
    r = min(float(RADIUS), rect.width() / 2, rect.height())
    if r <= 0.5:
        path.addRect(rect)
        return path
    path.moveTo(rect.left(), rect.bottom())
    path.lineTo(rect.left(), rect.top() + r)
    path.quadTo(rect.left(), rect.top(), rect.left() + r, rect.top())
    path.lineTo(rect.right() - r, rect.top())
    path.quadTo(rect.right(), rect.top(), rect.right(), rect.top() + r)
    path.lineTo(rect.right(), rect.bottom())
    path.closeSubpath()
    return path


class DayColumns(QWidget):
    """Blocked-per-day columns for the selected period."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._points: list[tuple[date, int]] = []
        self._pal = build_palette(*load_prefs())
        self.setMinimumHeight(230)
        self.setMouseTracking(True)  # hover figures without clicking

    def set_data(self, points: list[tuple[date, int]]) -> None:
        self._points = points
        self._pal = build_palette(*load_prefs())
        self.update()

    # -- geometry shared by painting and hit-testing ---------------------

    def _plot_rect(self) -> QRectF:
        return QRectF(56, 12, max(1.0, self.width() - 68),
                      max(1.0, self.height() - 40))

    def _band_width(self) -> float:
        return self._plot_rect().width() / max(1, len(self._points))

    def _index_at(self, x: float) -> int | None:
        plot = self._plot_rect()
        if not self._points or not (plot.left() <= x <= plot.right()):
            return None
        i = int((x - plot.left()) // self._band_width())
        return min(max(i, 0), len(self._points) - 1)

    def mouseMoveEvent(self, event) -> None:
        i = self._index_at(event.position().x())
        if i is None:
            self.setToolTip("")
        else:
            day, n = self._points[i]
            self.setToolTip(f"{day:%a %d %b %Y}\n{n:,} blocked")
        super().mouseMoveEvent(event)

    # -- painting --------------------------------------------------------

    def paintEvent(self, _event) -> None:
        p = self._pal
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor(p.surface))
        if not self._points:
            painter.setPen(QColor(p.muted))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                             "Nothing blocked in this period yet.")
            return

        plot = self._plot_rect()
        peak = max(n for _, n in self._points)
        ceiling = _nice_ceiling(peak)

        small = QFont(self.font())
        small.setPixelSize(11)
        painter.setFont(small)
        metrics = QFontMetrics(small)

        # Grid + y ticks: hairline, one step off the surface, recessive.
        for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
            y = plot.bottom() - frac * plot.height()
            painter.setPen(QColor(p.border))
            painter.drawLine(int(plot.left()), int(y),
                             int(plot.right()), int(y))
            painter.setPen(QColor(p.muted))
            painter.drawText(0, int(y - 7), 48, 14,
                             int(Qt.AlignmentFlag.AlignRight
                                 | Qt.AlignmentFlag.AlignVCenter),
                             f"{round(ceiling * frac):,}")

        band = self._band_width()
        width = min(BAR_MAX_W, max(1.0, band - BAR_GAP))
        peak_i = max(range(len(self._points)),
                     key=lambda i: self._points[i][1])

        for i, (day, n) in enumerate(self._points):
            x = plot.left() + i * band + (band - width) / 2
            height = 0.0 if ceiling == 0 else (n / ceiling) * plot.height()
            if n > 0:
                height = max(height, 2.0)  # a blocked day never reads as zero
                bar = QRectF(x, plot.bottom() - height, width, height)
                painter.fillPath(_bar_path(bar), QColor(p.accent))

            # Label selectively: the extreme only. Everything else is the
            # axis and the hover figure.
            if i == peak_i and n > 0:
                painter.setPen(QColor(p.text))
                text = f"{n:,}"
                tw = metrics.horizontalAdvance(text)
                painter.drawText(
                    QRectF(x + width / 2 - tw / 2 - 6,
                           plot.bottom() - height - 16, tw + 12, 14),
                    int(Qt.AlignmentFlag.AlignCenter), text)

        self._paint_day_labels(painter, plot, band, metrics)

    def _paint_day_labels(self, painter, plot, band, metrics) -> None:
        """Sparse x labels — enough to orient, never enough to collide."""
        p = self._pal
        n = len(self._points)
        fmt = "%a" if n <= 7 else "%d %b"
        # Keep ~6 labels regardless of period, and always show the last day.
        step = max(1, round(n / 6))
        painter.setPen(QColor(p.muted))
        for i in range(n - 1, -1, -step):
            day = self._points[i][0]
            text = day.strftime(fmt)
            tw = metrics.horizontalAdvance(text)
            x = plot.left() + i * band + band / 2
            if x - tw / 2 < plot.left() - 4:
                continue
            painter.drawText(QRectF(x - tw / 2 - 4, plot.bottom() + 6,
                                    tw + 8, 14),
                             int(Qt.AlignmentFlag.AlignCenter), text)


class TopTrackers(QWidget):
    """Ranked horizontal bars: which hosts were blocked most."""

    ROW_H = 26

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._rows: list[tuple[str, int]] = []
        self._pal = build_palette(*load_prefs())

    def set_data(self, rows: list[tuple[str, int]]) -> None:
        self._rows = rows
        self._pal = build_palette(*load_prefs())
        self.setMinimumHeight(self.ROW_H * max(1, len(rows)))
        self.update()

    def paintEvent(self, _event) -> None:
        p = self._pal
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor(p.surface))
        if not self._rows:
            painter.setPen(QColor(p.muted))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                             "No trackers blocked in this period yet.")
            return

        font = QFont(self.font())
        font.setPixelSize(12)
        painter.setFont(font)
        metrics = QFontMetrics(font)

        name_w = 190
        count_w = 64
        biggest = max(n for _, n in self._rows)
        track = max(1.0, self.width() - name_w - count_w - 16)

        for i, (host, n) in enumerate(self._rows):
            y = i * self.ROW_H
            # Host names come from the network — always plain text, elided.
            painter.setPen(QColor(p.text))
            painter.drawText(
                QRectF(0, y, name_w, self.ROW_H),
                int(Qt.AlignmentFlag.AlignLeft
                    | Qt.AlignmentFlag.AlignVCenter),
                metrics.elidedText(host, Qt.TextElideMode.ElideRight,
                                   name_w - 8))
            width = (n / biggest) * track
            bar = QRectF(name_w, y + self.ROW_H / 2 - 5, max(2.0, width), 10)
            painter.fillPath(_bar_path_h(bar), QColor(p.accent))
            painter.setPen(QColor(p.muted))
            painter.drawText(
                QRectF(self.width() - count_w, y, count_w - 4, self.ROW_H),
                int(Qt.AlignmentFlag.AlignRight
                    | Qt.AlignmentFlag.AlignVCenter), f"{n:,}")


def _bar_path_h(rect: QRectF) -> QPainterPath:
    """Horizontal bar: rounded data-end (right), square at the base (left).

    One explicit outline, for the same reason as _bar_path.
    """
    path = QPainterPath()
    r = min(float(RADIUS), rect.height() / 2, rect.width())
    if r <= 0.5:
        path.addRect(rect)
        return path
    path.moveTo(rect.left(), rect.top())
    path.lineTo(rect.right() - r, rect.top())
    path.quadTo(rect.right(), rect.top(), rect.right(), rect.top() + r)
    path.lineTo(rect.right(), rect.bottom() - r)
    path.quadTo(rect.right(), rect.bottom(), rect.right() - r, rect.bottom())
    path.lineTo(rect.left(), rect.bottom())
    path.closeSubpath()
    return path


class BlockingReportWindow(QDialog):
    """Blocking report: hero total, per-day columns, top trackers."""

    def __init__(self, stats: BlockStats, parent: QWidget | None = None):
        super().__init__(parent)
        self.stats = stats
        self.setWindowTitle("Blocking report")
        self.resize(720, 620)

        outer = QVBoxLayout(self)
        outer.setSpacing(10)

        # One filter row above everything it scopes.
        filters = QHBoxLayout()
        self.period = QComboBox()
        for label, days in PERIODS:
            self.period.addItem(label, days)
        self.period.setCurrentIndex(1)  # 30 days
        self.period.currentIndexChanged.connect(self.refresh)
        filters.addWidget(QLabel("Period:"))
        filters.addWidget(self.period)
        filters.addStretch()
        reset = QPushButton("Reset statistics…")
        reset.clicked.connect(self._reset)
        filters.addWidget(reset)
        outer.addLayout(filters)

        # Hero figure — the one number the window leads with.
        self.hero = QLabel("0")
        hero_font = QFont(self.font())
        hero_font.setPixelSize(48)
        hero_font.setWeight(QFont.Weight.DemiBold)
        self.hero.setFont(hero_font)
        outer.addWidget(self.hero)
        self.hero_sub = QLabel("")
        self.hero_sub.setTextFormat(Qt.TextFormat.PlainText)
        self.hero_sub.setStyleSheet("color: gray;")
        outer.addWidget(self.hero_sub)

        self.chart_title = QLabel("Requests blocked per day")
        self.chart_title.setStyleSheet("font-weight: 600;")
        outer.addWidget(self.chart_title)
        self.columns = DayColumns()
        outer.addWidget(self.columns)

        top_title = QLabel("Most-blocked trackers")
        top_title.setStyleSheet("font-weight: 600;")
        outer.addWidget(top_title)
        self.top = TopTrackers()
        outer.addWidget(self.top)

        self.footnote = QLabel("")
        self.footnote.setTextFormat(Qt.TextFormat.PlainText)
        self.footnote.setWordWrap(True)
        self.footnote.setStyleSheet("color: gray; font-size: 11px;")
        outer.addWidget(self.footnote)

        buttons = QHBoxLayout()
        buttons.addStretch()
        close = QPushButton("Close")
        close.setDefault(True)
        close.clicked.connect(self.accept)
        buttons.addWidget(close)
        outer.addLayout(buttons)

        self.refresh()

    def refresh(self) -> None:
        days = self.period.currentData()
        total = self.stats.total(days)
        self.hero.setText(f"{total:,}")
        average = round(total / days) if days else 0
        parts = [f"trackers and ads blocked in the last {days} days",
                 f"about {average:,} per day"]
        busiest = self.stats.busiest_day(days)
        if busiest:
            # %-d is a POSIX-ism and raises on Windows — keep the zero.
            parts.append(f"busiest {busiest[0]:%d %b} ({busiest[1]:,})")
        self.hero_sub.setText(" · ".join(parts))

        self.columns.set_data(self.stats.totals_by_day(days))
        self.top.set_data(self.stats.top_hosts(days))

        since = self.stats.tracked_since()
        note = (f"Counts are kept per day for {RETENTION_DAYS} days, "
                "encrypted on disk, and never include the pages you "
                "visited. Clearing browsing data erases them.")
        if since:
            note = f"Recording since {since:%d %b %Y}. " + note
        self.footnote.setText(note)

    def _reset(self) -> None:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Reset statistics")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText("Delete all recorded blocking statistics?\n\n"
                    "This cannot be undone.")
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() == QMessageBox.StandardButton.Yes:
            self.stats.clear()
            self.refresh()
