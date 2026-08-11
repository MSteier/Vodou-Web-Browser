"""Vodou visual theme: switchable Fusion palettes, QSS, and a generated icon.

A theme is an accent trio (accent / dim / hover); the neutral surfaces come
from a shared dark or light base, so every theme works in both modes and the
dark/light toggle is a single flag. Semantic green/red are reserved for
security states and shift only for contrast between modes.

Applied at startup and re-applied live when the user switches theme or mode;
QSS only touches the chrome — page content is rendered by Chromium and never
styled from here. The choice is persisted to ~/.vodou/theme.json.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QIcon,
    QPainter,
    QPainterPath,
    QPalette,
    QPen,
    QPixmap,
)
from PyQt6.QtWidgets import QApplication

PREFS_FILE = Path.home() / ".vodou" / "theme.json"


@dataclass(frozen=True)
class Palette:
    bg: str        # window chrome
    surface: str   # inputs, menus, dialogs
    elevated: str  # hover / selected surfaces
    border: str
    text: str
    muted: str
    accent: str
    accent_dim: str
    accent_hover: str
    ok: str
    danger: str
    on_accent: str  # text drawn on top of an accent fill


# Shared neutral bases. A theme only supplies its accent trio; these fill in
# the rest for each mode.
_DARK_BASE = dict(bg="#141519", surface="#1e2027", elevated="#262933",
                  border="#31343e", text="#e8eaf0", muted="#9aa0ad",
                  ok="#3ddc97", danger="#ff5c7a", on_accent="#ffffff")
_LIGHT_BASE = dict(bg="#f4f4f7", surface="#ffffff", elevated="#e8e9f0",
                   border="#d3d5df", text="#1b1d26", muted="#6b7180",
                   ok="#1a7f37", danger="#d1233b", on_accent="#ffffff")

# Built-in themes: name -> (accent, accent_dim, accent_hover).
THEMES: dict[str, tuple[str, str, str]] = {
    "Vodou Violet": ("#7c5cff", "#5b43c4", "#8d70ff"),
    "Blood Ritual": ("#e23c4e", "#a11d2c", "#ff5c6c"),
    "Swamp Green":  ("#2fae72", "#1f7d51", "#3ddc97"),
    "Midnight Blue": ("#3d7dff", "#2857c4", "#5b93ff"),
    "Bone Amber":   ("#d99a3c", "#a9741f", "#f0b95a"),
    "Spider Web Grey": ("#7d8896", "#59616f", "#9aa6b6"),
    "Ghost White":  ("#eef1fc", "#767c92", "#ffffff"),
}
DEFAULT_THEME = "Vodou Violet"
DEFAULT_MODE = "dark"


def _mix(base_hex: str, accent_hex: str, t: float) -> str:
    """Blend accent into base by fraction t (0..1) and return #rrggbb."""
    b = base_hex.lstrip("#")
    a = accent_hex.lstrip("#")
    br, bg, bb = int(b[0:2], 16), int(b[2:4], 16), int(b[4:6], 16)
    ar, ag, ab = int(a[0:2], 16), int(a[2:4], 16), int(a[4:6], 16)
    r = round(br + (ar - br) * t)
    g = round(bg + (ag - bg) * t)
    bl = round(bb + (ab - bb) * t)
    return f"#{r:02x}{g:02x}{bl:02x}"


def _readable_on(hex_color: str) -> str:
    """Black or white — whichever reads better as text/fill over the colour.
    Lets pale accents (e.g. Ghost White) keep legible text on accent fills."""
    c = hex_color.lstrip("#")
    r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
    luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
    return "#17181f" if luminance > 0.6 else "#ffffff"


def build_palette(theme_name: str, mode: str) -> Palette:
    accent, dim, hover = THEMES.get(theme_name, THEMES[DEFAULT_THEME])
    base = dict(_LIGHT_BASE if mode == "light" else _DARK_BASE)
    # Tint the neutral chrome toward the accent so each theme has a distinct
    # atmosphere even where the accent itself isn't shown. Text stays neutral
    # for readability; borders/muted take the strongest tint.
    return Palette(
        accent=accent, accent_dim=dim, accent_hover=hover,
        bg=_mix(base["bg"], accent, 0.10),
        surface=_mix(base["surface"], accent, 0.10),
        elevated=_mix(base["elevated"], accent, 0.18),
        border=_mix(base["border"], accent, 0.30),
        text=base["text"],
        muted=_mix(base["muted"], accent, 0.20),
        ok=base["ok"], danger=base["danger"],
        # Derived from the accent so a pale accent gets dark text on its fills
        # (default buttons, table selection) instead of invisible white.
        on_accent=_readable_on(accent))


def load_prefs() -> tuple[str, str]:
    """Return (theme_name, mode), falling back to defaults on any problem."""
    try:
        data = json.loads(PREFS_FILE.read_text(encoding="utf-8"))
        name = data.get("theme")
        mode = data.get("mode")
        if name not in THEMES:
            name = DEFAULT_THEME
        if mode not in ("dark", "light"):
            mode = DEFAULT_MODE
        return name, mode
    except (OSError, ValueError, TypeError):
        return DEFAULT_THEME, DEFAULT_MODE


def save_prefs(theme_name: str, mode: str) -> None:
    try:
        PREFS_FILE.parent.mkdir(parents=True, exist_ok=True)
        PREFS_FILE.write_text(
            json.dumps({"theme": theme_name, "mode": mode}),
            encoding="utf-8")
    except OSError:
        pass  # a non-writable config dir must not break theming


def build_qss(p: Palette) -> str:
    return f"""
* {{
    font-family: "Segoe UI Variable Text", "Segoe UI", sans-serif;
    font-size: 10pt;
}}

QMainWindow, QDialog {{ background: {p.bg}; }}

QToolBar {{
    background: {p.bg};
    border: none;
    padding: 5px 8px;
    spacing: 3px;
}}
QToolBar QToolButton {{
    background: transparent;
    color: {p.text};
    border: none;
    border-radius: 7px;
    padding: 5px 9px;
    font-size: 12pt;
}}
QToolBar QToolButton:hover {{ background: {p.elevated}; }}
QToolBar QToolButton:pressed {{ background: {p.accent_dim}; }}
QToolBar QToolButton::menu-indicator {{ image: none; width: 0; }}

QLineEdit {{
    background: {p.surface};
    color: {p.text};
    border: 1px solid {p.border};
    border-radius: 8px;
    padding: 5px 10px;
    selection-background-color: {p.accent};
}}
QLineEdit:focus {{ border: 1px solid {p.accent}; }}
QLineEdit#urlBar {{
    border-radius: 16px;
    padding: 6px 14px;
    font-size: 10.5pt;
}}
QLineEdit#urlBar:focus {{ background: {p.elevated}; }}

QWidget#tabStrip {{ background: {p.bg}; }}
QTabBar {{ background: {p.bg}; }}
QTabBar::tab {{
    background: transparent;
    color: {p.muted};
    padding: 7px 14px;
    margin: 0 2px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    max-width: 220px;
}}
QTabBar::tab:hover {{ background: {p.surface}; color: {p.text}; }}
QTabBar::tab:selected {{
    background: {p.elevated};
    color: {p.text};
    border-bottom: 2px solid {p.accent};
}}

QToolButton#newTabButton {{
    background: transparent;
    border: none;
    border-radius: 7px;
    padding: 4px 8px;
    margin: 0 2px 0 4px;
}}
QToolButton#newTabButton:hover {{ background: {p.elevated}; }}
QToolButton#newTabButton:pressed {{ background: {p.accent_dim}; }}

/* Bookmarks bar under the address bar. */
QToolBar#bookmarkBar {{
    background: {p.bg};
    border: none;
    border-top: 1px solid {p.border};
    padding: 2px 6px;
    spacing: 1px;
}}
QToolBar#bookmarkBar QToolButton {{
    background: transparent;
    color: {p.muted};
    border: none;
    border-radius: 6px;
    padding: 3px 9px;
    font-size: 9pt;
}}
QToolBar#bookmarkBar QToolButton:hover {{
    background: {p.elevated};
    color: {p.text};
}}
QToolBar#bookmarkBar QToolButton:pressed {{ background: {p.accent_dim}; }}

QStatusBar {{
    background: {p.bg};
    color: {p.muted};
    border-top: 1px solid {p.border};
}}
QLabel#shieldLabel {{ color: {p.ok}; font-weight: 600; background: {p.bg}; }}
QLabel#shieldLabel[paused="true"] {{ color: {p.muted}; }}
QLabel#versionLabel {{
    color: {p.accent}; text-decoration: underline; background: {p.bg};
}}
QLabel#versionLabel:hover {{ color: {p.text}; }}

QMenu {{
    background: {p.surface};
    color: {p.text};
    border: 1px solid {p.border};
    border-radius: 8px;
    padding: 6px;
}}
QMenu::item {{ padding: 6px 24px; border-radius: 6px; }}
QMenu::item:selected {{ background: {p.accent_dim}; }}
QMenu::separator {{ height: 1px; background: {p.border}; margin: 5px 8px; }}

QPushButton {{
    background: {p.elevated};
    color: {p.text};
    border: 1px solid {p.border};
    border-radius: 8px;
    padding: 6px 16px;
}}
QPushButton:hover {{ background: {p.elevated}; border-color: {p.accent_dim}; }}
QPushButton:pressed {{ background: {p.accent_dim}; }}
QPushButton:default {{ background: {p.accent}; border-color: {p.accent}; color: {p.on_accent}; }}
QPushButton:default:hover {{ background: {p.accent_hover}; }}

QTableWidget, QTreeWidget {{
    background: {p.surface};
    color: {p.text};
    border: 1px solid {p.border};
    border-radius: 8px;
    gridline-color: transparent;
    alternate-background-color: {p.elevated};
    selection-background-color: {p.accent_dim};
    selection-color: {p.on_accent};
}}
QHeaderView::section {{
    background: {p.bg};
    color: {p.muted};
    border: none;
    border-bottom: 1px solid {p.border};
    padding: 6px 8px;
    font-weight: 600;
}}

QScrollBar:vertical {{
    background: transparent; width: 10px; margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: {p.border}; border-radius: 4px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {p.muted}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: transparent; height: 10px; margin: 2px;
}}
QScrollBar::handle:horizontal {{
    background: {p.border}; border-radius: 4px; min-width: 30px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

QSpinBox, QCheckBox {{ color: {p.text}; }}
QSpinBox {{
    background: {p.surface}; border: 1px solid {p.border};
    border-radius: 6px; padding: 4px 6px;
}}

QToolTip {{
    background: {p.surface};
    color: {p.text};
    border: 1px solid {p.border};
    padding: 5px 8px;
}}

QWidget#devtoolsHeader {{
    background: {p.bg};
    border-top: 1px solid {p.border};
    border-left: 1px solid {p.border};
    border-bottom: 1px solid {p.border};
}}
QLabel#devtoolsTitle {{
    color: {p.muted};
    font-size: 8.5pt;
    font-weight: 700;
    letter-spacing: 1px;
}}
QToolButton#devtoolsClose {{
    color: {p.muted};
    background: transparent;
    border: none;
    border-radius: 6px;
    font-size: 11pt;
}}
QToolButton#devtoolsClose:hover {{
    background: {p.danger};
    color: {p.on_accent};
}}

QWidget#splitViewRoot {{ background: {p.bg}; }}
QFrame#splitBar {{
    background: {p.bg};
    border-bottom: 1px solid {p.border};
}}
QLabel#splitBarTag {{
    color: {p.muted};
    font-size: 8.5pt;
    font-weight: 700;
    letter-spacing: 1px;
}}
QToolButton#splitBarBtn {{
    color: {p.text};
    background: transparent;
    border: none;
    border-radius: 6px;
    padding: 3px 10px;
}}
QToolButton#splitBarBtn:hover {{ background: {p.elevated}; }}
QToolButton#splitBarBtn:pressed {{ background: {p.accent_dim}; }}
QFrame#splitPaneHeader {{
    background: {p.surface};
    border-bottom: 1px solid {p.border};
}}
QLabel#splitPaneTitle {{ color: {p.muted}; font-size: 8.5pt; }}
QToolButton#splitPaneBtn {{
    color: {p.muted};
    background: transparent;
    border: none;
    border-radius: 5px;
    padding: 1px 6px;
    font-size: 10pt;
}}
QToolButton#splitPaneBtn:hover {{ background: {p.elevated}; color: {p.text}; }}
QSplitter#splitViewSplitter::handle {{ background: {p.border}; }}
QSplitter#splitViewSplitter::handle:hover {{ background: {p.accent}; }}

QFrame#notifyBar {{
    background: {p.elevated};
    border-bottom: 1px solid {p.accent_dim};
}}
QFrame#notifyBar QLabel {{ color: {p.text}; }}
QPushButton#notifyAccept {{
    background: {p.accent};
    border-color: {p.accent};
    color: {p.on_accent};
    font-weight: 600;
}}
QPushButton#notifyAccept:hover {{ background: {p.accent_hover}; }}

QWidget#aiPanel {{
    background: {p.surface};
    border-left: 1px solid {p.border};
}}
QWidget#aiHeader {{
    background: {p.bg};
    border-top: 1px solid {p.border};
    border-left: 1px solid {p.border};
    border-bottom: 1px solid {p.border};
}}
QLabel#aiTitle {{
    color: {p.accent};
    font-size: 8.5pt;
    font-weight: 700;
    letter-spacing: 1px;
}}
QComboBox#aiModelCombo {{
    color: {p.text};
    background: {p.elevated};
    border: 1px solid {p.border};
    border-radius: 6px;
    padding: 1px 6px;
    font-size: 8.5pt;
    font-family: 'Consolas', monospace;
    min-width: 120px;
}}
QComboBox#aiModelCombo:hover {{ border-color: {p.accent}; }}
QComboBox#aiModelCombo::drop-down {{ border: none; width: 16px; }}
QComboBox#aiModelCombo QAbstractItemView {{
    background: {p.surface};
    color: {p.text};
    border: 1px solid {p.border};
    selection-background-color: {p.accent};
    selection-color: {p.on_accent};
}}
QToolButton#aiClose {{
    color: {p.muted};
    background: transparent;
    border: none;
    border-radius: 6px;
    font-size: 11pt;
}}
QToolButton#aiClose:hover {{
    background: {p.danger};
    color: {p.on_accent};
}}
QLabel#aiStatus {{
    color: {p.muted};
    font-size: 9pt;
    padding: 8px 12px 4px 12px;
}}
QTextBrowser#aiSummary {{
    background: {p.surface};
    color: {p.text};
    border: none;
    padding: 4px 12px;
    font-size: 10.5pt;
}}
QLineEdit#aiInput {{
    background: {p.elevated};
    color: {p.text};
    border: 1px solid {p.border};
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 10.5pt;
}}
QLineEdit#aiInput:focus {{ border-color: {p.accent}; }}
QWidget#aiPanel QPushButton {{
    background: {p.elevated};
    color: {p.text};
    border: 1px solid {p.border};
    border-radius: 6px;
    padding: 4px 12px;
}}
QWidget#aiPanel QPushButton:hover {{ background: {p.accent}; color: {p.on_accent}; }}
QWidget#aiPanel QPushButton:disabled {{ color: {p.muted}; background: {p.surface}; }}
/* Send is the panel's primary action, so it carries the accent by default. */
QPushButton#aiSend {{ background: {p.accent}; color: {p.on_accent}; border-color: {p.accent}; }}
QPushButton#aiSend:disabled {{ color: {p.muted}; background: {p.surface}; border-color: {p.border}; }}
"""


def _draw_voodoo_doll(p: QPainter) -> None:
    """Paint the Vodou mark on a 128×128 painter: a white line-art voodoo doll
    — a stitched gingerbread-style figure with X-button eyes and a sewn mouth —
    on a black rounded backdrop. Vector primitives so it stays crisp when
    scaled down to a 16px favicon."""
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Black rounded backdrop, with a hair of dark edge so the icon still reads
    # as a distinct shape on a pure-black taskbar.
    p.setBrush(QBrush(QColor("#000000")))
    p.setPen(QPen(QColor("#2a2a2a"), 2))
    p.drawRoundedRect(QRectF(6, 6, 116, 116), 30, 30)

    white = QColor("#ffffff")

    # The doll silhouette, built as one united path (head + torso + arms +
    # legs) so it strokes as a single clean outline with no internal seams.
    def rounded(x, y, w, h, r):
        sub = QPainterPath()
        sub.addRoundedRect(QRectF(x, y, w, h), r, r)
        return sub

    body = QPainterPath()
    body.addEllipse(QPointF(64, 32), 16, 16)     # head
    body = body.united(rounded(48, 44, 32, 46, 14))   # torso
    body = body.united(rounded(18, 54, 92, 15, 7.5))  # outstretched arms
    body = body.united(rounded(49, 84, 12, 28, 6))    # left leg
    body = body.united(rounded(67, 84, 12, 28, 6))    # right leg

    outline = QPen(white, 5.5)
    outline.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    outline.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(outline)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPath(body)

    # Seam stitches running down the centre.
    seam = QPen(white, 2)
    seam.setStyle(Qt.PenStyle.DashLine)
    seam.setDashPattern([2, 3])
    p.setPen(seam)
    p.drawLine(64, 46, 64, 88)

    # X-button eyes.
    eye = QPen(white, 3)
    eye.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(eye)
    for cx in (57, 71):
        p.drawLine(cx - 4, 27, cx + 4, 36)
        p.drawLine(cx - 4, 36, cx + 4, 27)

    # Sewn cross-stitch mouth: a base line crossed by short stitches.
    mouth = QPen(white, 2)
    mouth.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(mouth)
    p.drawLine(57, 40, 71, 40)
    for mx in range(59, 72, 4):
        p.drawLine(mx, 38, mx - 2, 43)

    # A stitch cross on the chest, the classic "stick the pin here" mark.
    cross = QPen(white, 3)
    cross.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(cross)
    p.drawLine(58, 64, 70, 76)
    p.drawLine(58, 76, 70, 64)

    # Short cross-stitch ticks on the arms and legs.
    tick = QPen(white, 2)
    tick.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(tick)
    for x in (28, 96):        # arms
        p.drawLine(x - 3, 58, x + 3, 65)
        p.drawLine(x - 3, 65, x + 3, 58)
    for x in (55, 73):        # legs
        p.drawLine(x - 3, 98, x + 3, 103)
        p.drawLine(x - 3, 103, x + 3, 98)


def make_app_icon() -> QIcon:
    pixmap = QPixmap(128, 128)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    _draw_voodoo_doll(painter)
    painter.end()
    return QIcon(pixmap)


def apply_theme(app: QApplication, theme_name: str | None = None,
                mode: str | None = None) -> None:
    """Apply a theme + mode to the whole app. With no arguments, the saved
    preference (or the default) is used. Safe to call again at runtime to
    switch live."""
    if theme_name is None or mode is None:
        saved_name, saved_mode = load_prefs()
        theme_name = theme_name or saved_name
        mode = mode or saved_mode
    p = build_palette(theme_name, mode)

    app.setStyle("Fusion")

    palette = QPalette()
    roles = {
        QPalette.ColorRole.Window: p.bg,
        QPalette.ColorRole.WindowText: p.text,
        QPalette.ColorRole.Base: p.surface,
        QPalette.ColorRole.AlternateBase: p.elevated,
        QPalette.ColorRole.Text: p.text,
        QPalette.ColorRole.Button: p.elevated,
        QPalette.ColorRole.ButtonText: p.text,
        QPalette.ColorRole.Highlight: p.accent,
        QPalette.ColorRole.HighlightedText: p.on_accent,
        QPalette.ColorRole.ToolTipBase: p.surface,
        QPalette.ColorRole.ToolTipText: p.text,
        QPalette.ColorRole.PlaceholderText: p.muted,
        QPalette.ColorRole.Link: p.accent,
    }
    for role, color in roles.items():
        palette.setColor(role, QColor(color))
    palette.setColor(QPalette.ColorGroup.Disabled,
                     QPalette.ColorRole.Text, QColor(p.muted))
    palette.setColor(QPalette.ColorGroup.Disabled,
                     QPalette.ColorRole.ButtonText, QColor(p.muted))
    app.setPalette(palette)

    app.setStyleSheet(build_qss(p))
    app.setWindowIcon(make_app_icon())
