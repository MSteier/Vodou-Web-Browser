"""Manual verification that Qt WebEngine's loadExtension() behaves the way
extensions.py and main.py's wiring assume: Manifest V3 extensions load,
Manifest V2 extensions are rejected outright (per Qt's own docs).

NOT auto-discovered by unittest/pytest and NOT wired into CI (see ci.yml --
every test step there names its file explicitly, nothing globs tests/).
Deliberately excluded: running this exact check through unittest's
TestCase.run() machinery -- even split innocuously across two test methods,
or via a separate spin()-style helper, or with a second QWebEngineProfile
created shortly after the first -- was observed to reliably crash
(segfault) or silently misreport inside PyQt6-WebEngine 6.11.0's binding
for the brand-new (Qt 6.10) QWebEngineExtensionInfo. Running the identical
sequence as a plain top-level script, exactly once, in one profile, over
one signal connection (the shape below, and the shape main.py's own
_apply_extensions() uses) was reliably stable across many repeated runs.
This points at a fragility in that very new binding under certain call
patterns, not a bug in Vodou's own code -- but it means this check has to
stay a manual, plain-script run:

    python tests/manual_verify_extensions.py

Re-run this by hand after any PyQt6-WebEngine upgrade, or after touching
main.py's extension-loading code, to confirm the assumption still holds.
"""
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWebEngineCore import QWebEngineProfile


def write_manifest(directory: Path, manifest_version: int, name: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "manifest.json").write_text(
        f'{{"manifest_version": {manifest_version}, "name": "{name}", '
        f'"version": "1.0", "description": "test fixture"}}',
        encoding="utf-8")


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    profile = QWebEngineProfile(f"vodou-manual-verify-{uuid.uuid4().hex}", app)
    manager = profile.extensionManager()
    results = {}
    manager.loadFinished.connect(lambda info: results.__setitem__(info.path(), info))

    tmpdir = Path(tempfile.mkdtemp())
    mv3_dir = tmpdir / "mv3_ext"
    mv2_dir = tmpdir / "mv2_ext"
    write_manifest(mv3_dir, 3, "MV3 fixture")
    write_manifest(mv2_dir, 2, "MV2 fixture")

    manager.loadExtension(str(mv3_dir))
    manager.loadExtension(str(mv2_dir))

    deadline = time.time() + 10
    while time.time() < deadline and len(results) < 2:
        app.processEvents()
        time.sleep(.01)

    mv3_info = results.get(str(mv3_dir))
    mv2_info = results.get(str(mv2_dir))

    failures = []
    if mv3_info is None:
        failures.append("MV3 extension never got a loadFinished callback")
    elif not mv3_info.isLoaded() or mv3_info.error():
        failures.append(f"MV3 extension should have loaded cleanly: error={mv3_info.error()!r}")
    else:
        print("MV3 extension loaded successfully: OK")

    if mv2_info is None:
        failures.append("MV2 extension never got a loadFinished callback")
    elif mv2_info.isLoaded() or not mv2_info.error():
        failures.append(f"MV2 extension should have been rejected: isLoaded={mv2_info.isLoaded()}")
    else:
        print("MV2 extension correctly rejected with error:", mv2_info.error())

    if failures:
        for f in failures:
            print("FAIL:", f)
        return 1
    print("SUCCESS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
