"""Run every tests/test_*.py, each in its own Python process.

Use this instead of `python -m unittest discover`. Most of these files are
standalone scripts, not unittest modules: they redirect HOME to a temp dir
before importing main, create their own QApplication, and sys.exit() on
failure. Imported together into one process (which is what discover does)
they break each other -- main is already imported against the real home, Qt
WebEngine gets imported after a QApplication exists -- and the run ends in a
0xC0000409 crash on Windows. One process per file is also how CI runs them.

Run:  python tests/run_all.py [name-filter ...]
"""
import os
import subprocess
import sys
import time
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent


def main(filters: list[str]) -> int:
    files = sorted(TESTS_DIR.glob("test_*.py"))
    if filters:
        files = [f for f in files if any(s in f.stem for s in filters)]
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", PYTHONUTF8="1")

    failed = []
    for path in files:
        start = time.monotonic()
        result = subprocess.run([sys.executable, str(path)], env=env,
                                cwd=TESTS_DIR.parent, capture_output=True,
                                text=True, encoding="utf-8", errors="replace")
        status = "ok" if result.returncode == 0 else f"FAIL ({result.returncode})"
        print(f"{path.stem:<34} {status:<12} {time.monotonic() - start:5.1f}s")
        if result.returncode != 0:
            failed.append(path.stem)
            tail = (result.stdout + result.stderr).rstrip().splitlines()[-15:]
            print("\n".join("    " + line for line in tail))

    print()
    if failed:
        print(f"{len(failed)} of {len(files)} FAILED: {', '.join(failed)}")
        return 1
    print(f"ALL {len(files)} TEST FILES PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
