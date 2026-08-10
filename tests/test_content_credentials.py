"""Tests for on-device Content Credentials (C2PA) verification.

Offline and deterministic: an unsigned image must report 'none' (no credential
= unknown, never 'authentic'), the AI-generated assertion parser is exercised,
and garbage input must degrade gracefully rather than crash. The signed /
trusted / tampered paths are validated against real signed assets during
development; they're not reproduced here so the test stays hermetic (no network,
no bundled signed fixtures).

Run:  python tests/test_content_credentials.py
"""

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

threading.Thread(target=lambda: (time.sleep(60), os._exit(3)), daemon=True).start()
os.environ["QT_QPA_PLATFORM"] = "offscreen"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import content_credentials as cc  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


# --- the AI-generated assertion parser (pure) --------------------------------
print("AI-generated assertion parser")
ai_man = {"assertions": [{"label": "c2pa.actions", "data": {"actions": [
    {"action": "c2pa.created",
     "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"}]}}]}
cap_man = {"assertions": [{"label": "c2pa.actions", "data": {"actions": [
    {"action": "c2pa.created",
     "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"}]}}]}
check("trainedAlgorithmicMedia -> AI", cc._is_ai(ai_man))
check("digitalCapture -> not AI", not cc._is_ai(cap_man))
check("no assertions -> not AI", not cc._is_ai({}))

check("available() is a bool", isinstance(cc.available(), bool))

# --- live verification (needs the c2pa library) ------------------------------
if not cc.available():
    print("\nc2pa library not installed — verifying graceful-unavailable only")
    r = cc.verify_image(b"whatever", "image/jpeg")
    check("unavailable -> status 'unavailable'", r.status == "unavailable")
else:
    print("\nlive verification (unsigned + garbage)")
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QImage, QColor
    app = QApplication.instance() or QApplication(sys.argv)
    img = QImage(120, 90, QImage.Format.Format_RGB32)
    img.fill(QColor("tomato"))
    path = Path(tempfile.mkdtemp()) / "unsigned.jpg"
    img.save(str(path), "JPG")

    r = cc.verify_image(path.read_bytes(), "image/jpeg")
    check("unsigned image -> status 'none'", r.status == "none")
    check("unsigned names no signer", r.signer == "")
    check("unsigned isn't flagged AI", r.ai_generated is False)

    g = cc.verify_image(b"this is not an image", "image/jpeg")
    check("garbage bytes -> none/error, never crash", g.status in ("none", "error"))

print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL CONTENT-CREDENTIALS TESTS PASSED")
