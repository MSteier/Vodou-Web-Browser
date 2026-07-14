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

from PyQt6.QtCore import QPointF, Qt
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QIcon,
    QLinearGradient,
    QPainter,
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
        ok=base["ok"], danger=base["danger"], on_accent=base["on_accent"])


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

QToolButton#lockButton[state="secure"]   {{ color: {p.ok}; }}
QToolButton#lockButton[state="insecure"] {{ color: {p.danger}; }}
QToolButton#lockButton[state="neutral"]  {{ color: {p.muted}; }}
QToolButton#starButton {{ color: {p.accent}; font-size: 14pt; }}

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
    padding: 6px 16px;
    font-size: 10.5pt;
}}

QTabWidget::pane {{ border: none; }}
QTabWidget::tab-bar {{ left: 6px; }}  /* nudge the tab row right a few px */
QTabBar {{ background: {p.bg}; }}
QTabBar::tab {{
    background: transparent;
    color: {p.muted};
    padding: 7px 14px;
    margin: 4px 2px 0 2px;
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

QStatusBar {{
    background: {p.bg};
    color: {p.muted};
    border-top: 1px solid {p.border};
}}
QLabel#shieldLabel {{ color: {p.ok}; font-weight: 600; }}

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
"""


def _draw_voodoo_doll(p: QPainter) -> None:
    """Paint the Vodou mark on a 128×128 painter: a stitched burlap doll head
    with X-button eyes, a sewn mouth, and a red-beaded pin driven through it,
    on the violet brand backdrop. Vector primitives so it stays crisp when
    scaled down to a 16px favicon."""
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Rounded violet backdrop (keeps the Vodou brand gradient).
    backdrop = QLinearGradient(0, 0, 128, 128)
    backdrop.setColorAt(0, QColor("#8d70ff"))
    backdrop.setColorAt(1, QColor("#3a2a86"))
    p.setBrush(QBrush(backdrop))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(6, 6, 116, 116, 30, 30)

    burlap = QColor("#e7d8b6")
    burlap_dark = QColor("#cbb98e")
    thread = QColor("#4a3720")

    # Head: a burlap sack, slightly egg-shaped, with a soft shaded underside.
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(burlap_dark))
    p.drawEllipse(QPointF(64, 65), 33, 39)      # shadow layer
    p.setBrush(QBrush(burlap))
    p.drawEllipse(QPointF(64, 62), 33, 39)      # head

    # Cinched top-knot where the sack is tied off.
    p.setBrush(QBrush(burlap_dark))
    p.drawEllipse(QPointF(64, 24), 8, 6)
    p.setPen(QPen(thread, 2))
    p.drawLine(60, 22, 68, 26)
    p.drawLine(60, 26, 68, 22)

    # Seam stitches running down the centre of the face.
    seam = QPen(thread, 2)
    seam.setStyle(Qt.PenStyle.DashLine)
    seam.setDashPattern([2, 3])
    p.setPen(seam)
    p.drawLine(64, 32, 64, 96)

    # X-button eyes.
    eye = QPen(thread, 4)
    eye.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(eye)
    for cx in (50, 78):
        p.drawLine(cx - 6, 52, cx + 6, 64)
        p.drawLine(cx - 6, 64, cx + 6, 52)

    # Sewn cross-stitch mouth: a base line crossed by short vertical stitches.
    mouth = QPen(thread, 3)
    mouth.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(mouth)
    p.drawLine(50, 84, 78, 84)
    for mx in range(52, 79, 6):
        p.drawLine(mx, 80, mx - 3, 88)

    # A pin driven through the doll: steel shaft with a bright red bead head,
    # angling out to the top-right corner.
    shaft = QPen(QColor("#e8e9f2"), 3)
    shaft.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(shaft)
    p.drawLine(70, 58, 108, 20)
    p.setPen(QPen(QColor("#7a1020"), 1))
    bead = QLinearGradient(102, 12, 116, 26)
    bead.setColorAt(0, QColor("#ff5c7a"))
    bead.setColorAt(1, QColor("#c81e3a"))
    p.setBrush(QBrush(bead))
    p.drawEllipse(QPointF(109, 19), 8, 8)
    # Glint on the bead.
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(QColor(255, 255, 255, 160)))
    p.drawEllipse(QPointF(106, 16), 2.2, 2.2)


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
