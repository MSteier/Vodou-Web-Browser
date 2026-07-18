"""Crisp, theme-colored vector icons for the toolbar and address bar.

Every icon is drawn from stroke/path primitives on a 24x24 logical grid, so it
stays sharp at any size and can be recolored to match the active theme (the
chrome text color, or a security state color). Painted into an oversized pixmap
and handed to Qt as a QIcon; Qt scales it down smoothly for the ~18px toolbar.

There are no image files on disk — the whole icon set is generated at runtime,
which keeps the browser self-contained and lets it follow the live theme
switch (see icon_set / MainWindow._refresh_icons).
"""

from __future__ import annotations

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import (
    QColor,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)

# Logical grid every glyph is drawn on. The source pixmap is rendered at
# GRID * SCALE px so downscaling to the toolbar size stays crisp.
GRID = 24
SCALE = 4
_STROKE = 2.0  # default stroke width in grid units


def _pen(color: QColor, width: float = _STROKE) -> QPen:
    pen = QPen(color, width)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    return pen


# -- individual glyphs (draw on a painter already scaled to the 24-grid) -----

def _back(p: QPainter, c: QColor) -> None:
    p.setPen(_pen(c))
    p.drawLine(QPointF(19, 12), QPointF(6, 12))
    path = QPainterPath(QPointF(11, 7))
    path.lineTo(6, 12)
    path.lineTo(11, 17)
    p.drawPath(path)


def _forward(p: QPainter, c: QColor) -> None:
    p.setPen(_pen(c))
    p.drawLine(QPointF(5, 12), QPointF(18, 12))
    path = QPainterPath(QPointF(13, 7))
    path.lineTo(18, 12)
    path.lineTo(13, 17)
    p.drawPath(path)


def _reload(p: QPainter, c: QColor) -> None:
    p.setPen(_pen(c))
    # Most of a circle, opening at the top-right, with an arrowhead.
    rect = QRectF(5, 5, 14, 14)
    p.drawArc(rect, 60 * 16, 280 * 16)
    # Arrowhead at the open end (top-right of the ring).
    tip = QPointF(12 + 7 * 0.5, 12 - 7 * 0.866)  # 60 deg on the ring
    path = QPainterPath(QPointF(tip.x() - 4.4, tip.y() + 0.3))
    path.lineTo(tip.x(), tip.y())
    path.lineTo(tip.x() + 1.2, tip.y() - 4.2)
    p.drawPath(path)


def _home(p: QPainter, c: QColor) -> None:
    p.setPen(_pen(c))
    roof = QPainterPath(QPointF(4, 12))
    roof.lineTo(12, 5)
    roof.lineTo(20, 12)
    p.drawPath(roof)
    # Body walls.
    body = QPainterPath(QPointF(6.5, 11))
    body.lineTo(6.5, 19)
    body.lineTo(17.5, 19)
    body.lineTo(17.5, 11)
    p.drawPath(body)
    # Door.
    p.drawRect(QRectF(10.3, 14, 3.4, 5))


def _plus(p: QPainter, c: QColor) -> None:
    p.setPen(_pen(c, 2.2))
    p.drawLine(QPointF(12, 6), QPointF(12, 18))
    p.drawLine(QPointF(6, 12), QPointF(18, 12))


def _menu(p: QPainter, c: QColor) -> None:
    p.setPen(_pen(c, 2.2))
    for y in (8, 12, 16):
        p.drawLine(QPointF(5, y), QPointF(19, y))


def _star_outline(p: QPainter, c: QColor) -> None:
    p.setPen(_pen(c, 1.8))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPath(_star_path())


def _star_filled(p: QPainter, c: QColor) -> None:
    p.setPen(_pen(c, 1.8))
    p.setBrush(c)
    p.drawPath(_star_path())


def _star_path() -> QPainterPath:
    import math
    cx, cy, outer, inner = 12.0, 12.5, 8.0, 3.3
    path = QPainterPath()
    for i in range(10):
        r = outer if i % 2 == 0 else inner
        ang = -math.pi / 2 + i * math.pi / 5
        x = cx + r * math.cos(ang)
        y = cy + r * math.sin(ang)
        if i == 0:
            path.moveTo(x, y)
        else:
            path.lineTo(x, y)
    path.closeSubpath()
    return path


def _bookmarks(p: QPainter, c: QColor) -> None:
    # A bookmark ribbon (pennant) with a notched foot.
    p.setPen(_pen(c, 1.8))
    ribbon = QPainterPath(QPointF(7, 5))
    ribbon.lineTo(17, 5)
    ribbon.lineTo(17, 19)
    ribbon.lineTo(12, 15)
    ribbon.lineTo(7, 19)
    ribbon.closeSubpath()
    p.drawPath(ribbon)


def _key(p: QPainter, c: QColor) -> None:
    p.setPen(_pen(c, 1.8))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawEllipse(QRectF(5, 5, 8, 8))         # bow
    p.drawLine(QPointF(11.5, 11.5), QPointF(19, 19))  # stem
    p.drawLine(QPointF(16.5, 16.5), QPointF(19, 14))  # tooth
    p.drawLine(QPointF(14.5, 14.5), QPointF(16.5, 12.5))  # tooth


def _save(p: QPainter, c: QColor) -> None:
    # Floppy-disk save glyph: outer body with a clipped corner, a label slot,
    # and the shutter.
    p.setPen(_pen(c, 1.7))
    body = QPainterPath(QPointF(5, 5))
    body.lineTo(16, 5)
    body.lineTo(19, 8)
    body.lineTo(19, 19)
    body.lineTo(5, 19)
    body.closeSubpath()
    p.drawPath(body)
    p.drawRect(QRectF(8, 5, 6, 4))    # shutter
    p.drawRect(QRectF(8, 12, 8, 5))   # label


def _vault(p: QPainter, c: QColor) -> None:
    # A safe: rounded box with a combination dial and a stubby handle.
    p.setPen(_pen(c, 1.7))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawRoundedRect(QRectF(4.5, 5.5, 15, 13), 2, 2)
    p.drawEllipse(QRectF(9, 9, 5, 5))          # dial
    p.drawLine(QPointF(11.5, 14), QPointF(11.5, 16.5))  # dial spoke
    p.drawLine(QPointF(16, 10), QPointF(16, 14))         # handle


def _lock(p: QPainter, c: QColor) -> None:
    _lock_body(p, c, open_=False)


def _lock_open(p: QPainter, c: QColor) -> None:
    _lock_body(p, c, open_=True)


def _lock_body(p: QPainter, c: QColor, open_: bool) -> None:
    p.setPen(_pen(c, 1.8))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawRoundedRect(QRectF(6, 11, 12, 9), 1.8, 1.8)  # body
    # Shackle: a closed lock centers the arc over the body; an open lock
    # swings it up and to the left.
    if open_:
        shackle = QRectF(2.5, 4, 8, 8)
        p.drawArc(shackle, 20 * 16, 200 * 16)
        p.drawLine(QPointF(9.5, 8), QPointF(9.5, 11))
    else:
        shackle = QRectF(8, 4, 8, 8)
        p.drawArc(shackle, 0 * 16, 180 * 16)
        p.drawLine(QPointF(8, 8), QPointF(8, 11))
        p.drawLine(QPointF(16, 8), QPointF(16, 11))
    # Keyhole.
    p.setBrush(c)
    p.drawEllipse(QPointF(12, 15), 1.2, 1.2)


def _info(p: QPainter, c: QColor) -> None:
    p.setPen(_pen(c, 1.8))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawEllipse(QRectF(5, 5, 14, 14))
    p.setPen(_pen(c, 2.0))
    p.drawPoint(QPointF(12, 8.6))
    p.drawLine(QPointF(12, 11.5), QPointF(12, 16))


_GLYPHS = {
    "back": _back,
    "forward": _forward,
    "reload": _reload,
    "home": _home,
    "plus": _plus,
    "menu": _menu,
    "star": _star_outline,
    "star-filled": _star_filled,
    "bookmarks": _bookmarks,
    "key": _key,
    "save": _save,
    "vault": _vault,
    "lock": _lock,
    "lock-open": _lock_open,
    "info": _info,
}


def make_icon(name: str, color: str) -> QIcon:
    """Render the named glyph in the given color (#rrggbb) as a QIcon."""
    draw = _GLYPHS[name]
    c = QColor(color)
    px = GRID * SCALE
    pm = QPixmap(px, px)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(SCALE, SCALE)
    draw(p, c)
    p.end()
    return QIcon(pm)


def icon_set(color: str) -> dict[str, QIcon]:
    """All chrome-colored glyphs at once (single color), keyed by name."""
    return {name: make_icon(name, color) for name in _GLYPHS}
