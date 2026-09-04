"""Vodou's coordinated Qt / PyQt6 / Qt WebEngine update system.

Vodou runs from a source checkout against a normal Python install: PyQt6 and
PyQt6-WebEngine are ordinary pip wheels, and *they* pull the matching Qt +
Chromium binaries (PyQt6-Qt6 / PyQt6-WebEngine-Qt6). Nothing Qt-related is
vendored in the repo, so "update the engine" means "let pip move the whole
binding+runtime set to a newer, mutually compatible release" -- never swapping
an individual Qt6WebEngineCore.dll.

This package is deliberately UI-free (no PyQt widgets imported anywhere in it)
so each stage can be unit-tested headless. The stages, in order:

    versions       -- what is installed *in the running process*
    pypi           -- what PyPI offers (stable vs pre-release, requires_python)
    compatibility  -- resolve a PyQt6 / PyQt6-WebEngine pair that share an
                      X.Y minor AND whose requires_python fits this Python
    backup         -- snapshot the current versions + cache their wheels so a
                      rollback never needs the network
    manager        -- orchestrator: check_for_updates(), stage(), state files
    apply          -- the detached helper that runs *after Vodou exits* (the
                      loaded Qt DLLs are locked on Windows while it runs), does
                      the pip install, verifies it, rolls back on any failure,
                      and relaunches Vodou
    diagnostics    -- a support report (packaging, install dir, arch, admin…)

Safety rules enforced here (see the module docstrings for where):
  * the binding + runtime are always moved together, as one pip transaction
  * Python is never upgraded -- a release that needs a newer Python is
    reported, not installed
  * an incompatible PyQt6 / Qt / WebEngine mix is never assembled
  * nothing in the live installation is touched before a verified backup exists
  * pre-release builds are only ever considered with an explicit opt-in
  * anything uncertain -> stop, change nothing, tell the user why
"""

from __future__ import annotations

from .compatibility import resolve_compatible_versions
from .diagnostics import diagnostics_report
from .manager import UpdateManager
from .models import (
    STATE_SCHEMA,
    ApplyOutcome,
    CompatibilityResult,
    ComponentVersion,
    CurrentVersions,
    ResolvedTarget,
    StageResult,
    UpdatePlan,
)
from .versions import get_current_versions, verify_installation

__all__ = [
    "STATE_SCHEMA",
    "UpdateManager",
    "get_current_versions",
    "verify_installation",
    "resolve_compatible_versions",
    "diagnostics_report",
    "CurrentVersions",
    "ResolvedTarget",
    "CompatibilityResult",
    "ComponentVersion",
    "UpdatePlan",
    "StageResult",
    "ApplyOutcome",
]
