"""Plain data carriers passed between the updater's stages.

No behaviour, no I/O, no Qt -- just typed structs, so the stages and their
tests never have to reach across into each other. The UI (updater_ui.py) only
ever reads a finished :class:`UpdatePlan` / :class:`ApplyOutcome`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Bumped only when the on-disk state format (~/.vodou/update/*.json) changes in
# a way a running Vodou would misread. manager.py refuses to resume state from
# a newer schema than it understands. Lives here (the dependency-free module)
# so every stage can import it without an import cycle through the package
# __init__.
STATE_SCHEMA = 1


def _vtuple(version: str) -> tuple[int, ...]:
    """Loose dotted-int split ("6.11.1" -> (6, 11, 1)); non-digits in a
    segment are dropped so a stray "6.11.1.dev0" still orders sanely. Only
    used for display ordering here -- real PEP 440 comparison lives in
    pypi.py, which the resolver uses."""
    out: list[int] = []
    for piece in str(version).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def minor_of(version: str) -> str:
    """"6.11.1" -> "6.11". Empty string for anything without two segments."""
    parts = _vtuple(version)
    return f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else ""


@dataclass
class CurrentVersions:
    """Everything the *running* process can tell us about its own stack.

    Note the deliberate split the requirements call for: the PyQt6 *binding*
    version (``PYQT_VERSION_STR``), the Qt version the binding reports
    (``QT_VERSION_STR``), the Qt WebEngine *runtime* version
    (``qWebEngineVersion()``) and the Chromium version
    (``qWebEngineChromiumVersion()``) are four different numbers and are not
    assumed equal -- on this very machine the binding wheels are 6.11.0 while
    the ``*-Qt6`` runtime wheels are 6.11.1.
    """

    vodou_version: str = "unknown"          # "1.52.2"
    vodou_display: str = "unknown"          # "1.52.2 (20d963a)"
    git_commit: str = ""
    git_branch: str = ""

    python: str = "0.0.0"                   # "3.10.11"
    python_tuple: tuple[int, int, int] = (0, 0, 0)
    python_exe: str = ""
    in_venv: bool = False

    pyqt6_binding: str = "unknown"          # PyQt6.QtCore.PYQT_VERSION_STR
    pyqt6_wheel: str = "unknown"            # importlib.metadata "PyQt6"
    pyqt6_sip: str = "unknown"              # importlib.metadata "PyQt6-sip"
    pyqt6_webengine_wheel: str = "unknown"  # importlib.metadata "PyQt6-WebEngine"
    pyqt6_qt6: str = "unknown"              # importlib.metadata "PyQt6-Qt6"
    pyqt6_webengine_qt6: str = "unknown"    # "PyQt6-WebEngine-Qt6"

    qt: str = "unknown"                     # PyQt6.QtCore.QT_VERSION_STR
    qt_webengine: str = "unknown"           # qWebEngineVersion()
    chromium: str = "unknown"               # qWebEngineChromiumVersion()

    frozen: bool = False                    # sys.frozen (PyInstaller etc.)
    site_packages: str = ""
    site_packages_writable: bool = False
    is_admin: bool = False

    def display_rows(self) -> list[tuple[str, str]]:
        """The "Current installation" block, in the order the spec's mock-up
        shows it."""
        return [
            ("Vodou", self.vodou_display),
            ("Python", self.python),
            ("PyQt6", self.pyqt6_binding),
            ("Qt", self.qt),
            ("Qt WebEngine", self.qt_webengine),
            ("Chromium", self.chromium),
        ]


@dataclass
class ResolvedTarget:
    """The version set the resolver settled on. ``None`` everywhere when no
    safe set could be found (see :attr:`CompatibilityResult.reason`)."""

    minor: str | None = None               # "6.11"
    pyqt6: str | None = None               # binding wheel version to install
    pyqt6_webengine: str | None = None     # binding wheel version to install
    # The matching runtime wheels pip will pull in as dependencies -- recorded
    # for display and for the rollback set, not pinned on the install line.
    expected_qt6: str | None = None
    expected_webengine_qt6: str | None = None
    requires_python: str | None = None     # of the chosen release

    @property
    def resolved(self) -> bool:
        return bool(self.pyqt6 and self.pyqt6_webengine)


@dataclass
class CompatibilityResult:
    compatible: bool = False
    up_to_date: bool = False
    target: ResolvedTarget = field(default_factory=ResolvedTarget)
    # Always a full human sentence, safe to show verbatim.
    reason: str = ""
    # A newer stable release exists but its requires_python excludes this
    # Python: (version, requires_python_spec). Vodou never upgrades Python.
    blocked_by_python: tuple[str, str] | None = None
    newest_seen_pyqt6: str | None = None
    newest_seen_webengine: str | None = None


@dataclass
class ComponentVersion:
    """One row of the "Components that will be updated" list."""

    name: str
    current: str
    available: str
    will_update: bool
    note: str = ""


@dataclass
class UpdatePlan:
    current: CurrentVersions
    compatibility: CompatibilityResult
    # False when an update cannot even be attempted on this installation
    # (frozen build, un-writable site-packages, no Python-compatible release).
    possible: bool = False
    update_available: bool = False
    restart_required: bool = False
    components: list[ComponentVersion] = field(default_factory=list)
    reason: str = ""
    allow_prerelease: bool = False

    def summary_line(self) -> str:
        if not self.possible:
            return self.reason or "Update not possible on this installation."
        if self.update_available:
            moving = [c.name for c in self.components if c.will_update]
            what = ", ".join(moving) if moving else "the Qt stack"
            return (f"Update available: {what} "
                    f"(Qt WebEngine {self.compatibility.target.minor}.x, "
                    "restart required).")
        return "Vodou's Qt stack is already the latest compatible version."


@dataclass
class StageResult:
    staged: bool
    message: str = ""
    wheel_dir: str = ""
    wheels: list[str] = field(default_factory=list)
    rollback_path: str = ""
    plan_path: str = ""


@dataclass
class ApplyOutcome:
    """Written by apply.py to result.json and read back by Vodou on the next
    start to show the user how the update actually went."""

    # done | rolled_back | rollback_failed | failed | interrupted | discarded
    status: str
    message: str = ""
    old: dict = field(default_factory=dict)
    new: dict = field(default_factory=dict)
    log_path: str = ""

    @property
    def succeeded(self) -> bool:
        return self.status == "done"
