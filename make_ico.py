"""Regenerate vodou.ico from the app icon in theme._draw_voodoo_doll().

Renders the vector mark crisply at each icon size (exact pixels, no display-DPI
scaling), PNG-encodes each, and assembles a multi-resolution .ico (PNG-embedded
entries, the modern ICO form Windows reads). Run after changing the icon:

    python make_ico.py
"""

import struct
import sys
from pathlib import Path

from PyQt6.QtCore import QBuffer, QByteArray, QIODevice, Qt
from PyQt6.QtGui import QPainter, QPixmap
from PyQt6.QtWidgets import QApplication

import theme

SIZES = [16, 24, 32, 48, 64, 128, 256]
OUT = Path(__file__).resolve().parent / "vodou.ico"

# Keep the QApplication at module scope: a function-local one gets torn down
# while Qt objects are still live, which segfaults on exit.
_app = QApplication(sys.argv)


def render(size: int) -> QPixmap:
    """The doll mark drawn at exactly size×size px (the icon grid is 128)."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.scale(size / 128.0, size / 128.0)
    theme._draw_voodoo_doll(painter)
    painter.end()
    return pixmap


def png_bytes(pixmap: QPixmap) -> bytes:
    # The QByteArray must be a named local: QBuffer(QByteArray()) would let the
    # temporary be garbage-collected out from under the buffer (segfault).
    store = QByteArray()
    buffer = QBuffer(store)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    pixmap.save(buffer, "PNG")
    buffer.close()
    return bytes(store)


def build_ico(images: list[tuple[int, bytes]]) -> bytes:
    count = len(images)
    out = struct.pack("<HHH", 0, 1, count)   # reserved, type=icon, count
    offset = 6 + count * 16                   # dir header + all entries
    entries, payload = b"", b""
    for size, data in images:
        dim = 0 if size >= 256 else size      # 0 encodes 256 in ICO
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32,
                               len(data), offset)
        offset += len(data)
        payload += data
    return out + entries + payload


def main() -> int:
    images = [(s, png_bytes(render(s))) for s in SIZES]
    OUT.write_bytes(build_ico(images))
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes, sizes {SIZES})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
