"""A copy-pasteable environment report, for support and bug reports.

Everything here is read-only. It answers the "critical first step" questions
the update system itself has to know -- how PyQt6 / WebEngine are supplied, how
Vodou is packaged, where it is installed, whether this user can write to
site-packages -- and a few more that make a support round-trip shorter.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

from .models import CurrentVersions
from .versions import get_current_versions

_REPO_DIR = Path(__file__).resolve().parent.parent


def packaging_method(cv: CurrentVersions) -> str:
    if cv.frozen:
        kind = "PyInstaller" if hasattr(sys, "_MEIPASS") else "frozen"
        return f"frozen executable ({kind})"
    if not (_REPO_DIR / ".git").exists():
        base = "source tree (no .git)"
    else:
        base = "source checkout"
    env = "virtual environment" if cv.in_venv else "system Python"
    return f"{base}, {env}"


def diagnostics_report(cv: CurrentVersions | None = None) -> dict:
    cv = cv or get_current_versions()
    updater_state = _updater_state()
    return {
        "Vodou": cv.vodou_display,
        "Vodou version": cv.vodou_version,
        "Git commit": cv.git_commit or "(not a git checkout)",
        "Git branch": cv.git_branch or "(detached / unknown)",
        "Python": cv.python,
        "Python executable": cv.python_exe,
        "Environment": "venv" if cv.in_venv else "system",
        "PyQt6 (binding)": cv.pyqt6_binding,
        "PyQt6 (wheel)": cv.pyqt6_wheel,
        "PyQt6-sip": cv.pyqt6_sip,
        "PyQt6-WebEngine (wheel)": cv.pyqt6_webengine_wheel,
        "PyQt6-Qt6 (runtime)": cv.pyqt6_qt6,
        "PyQt6-WebEngine-Qt6 (runtime)": cv.pyqt6_webengine_qt6,
        "Qt": cv.qt,
        "Qt WebEngine": cv.qt_webengine,
        "Chromium": cv.chromium,
        "OS": platform.platform(),
        "Architecture": f"{platform.machine()} / "
                        f"{platform.architecture()[0]}",
        "Packaging": packaging_method(cv),
        "Install directory": str(_REPO_DIR),
        "Site-packages": cv.site_packages or "(unknown)",
        "Site-packages writable": "yes" if cv.site_packages_writable
                                  else "no",
        "Running elevated": "yes" if cv.is_admin else "no",
        "Updater state": updater_state,
    }


def _updater_state() -> str:
    from .manager import DEFAULT_STATE_DIR
    status = DEFAULT_STATE_DIR / "status.json"
    if not status.exists():
        return "idle (no pending update)"
    try:
        import json
        data = json.loads(status.read_text(encoding="utf-8"))
        return f"phase={data.get('phase', '?')}"
    except (OSError, ValueError):
        return "unreadable"


def as_text(report: dict | None = None) -> str:
    report = report or diagnostics_report()
    width = max(len(k) for k in report) + 2
    return "\n".join(f"{k + ':':<{width}} {v}" for k, v in report.items())


def as_markdown(report: dict | None = None) -> str:
    report = report or diagnostics_report()
    lines = ["| Component | Value |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in report.items()]
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    print(as_text())
