"""Stage 5 -- the orchestrator the UI talks to.

``UpdateManager`` owns the small state directory (``~/.vodou/update/``) and the
sequence:

    check_for_updates()  -> UpdatePlan   (pure inspection, safe to call often)
    stage(plan)          -> StageResult  (backup + download + verify; still
                                          nothing in the live install touched)
    apply_command(...)   -> argv         (what Vodou spawns, detached, on exit)

State files, all JSON, all schema-versioned:
    plan.json     the staged UpdatePlan (what the helper will install)
    rollback.json the verified backup snapshot (written by backup.snapshot)
    status.json   {"phase": staged|installing|verifying|done|rolled_back|
                   rollback_failed|failed, ...} -- lets a restarted Vodou tell
                   "downloaded, ready" from "died half-way, needs repair"
    result.json   the ApplyOutcome the helper leaves for Vodou to show once

Rule of thumb enforced here: ``stage`` either produces a fully verified,
ready-to-install set or raises and removes everything it made. There is no
in-between on disk.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import backup, pypi
from .compatibility import resolve_compatible_versions
from .models import (
    STATE_SCHEMA,
    ApplyOutcome,
    ComponentVersion,
    CurrentVersions,
    StageResult,
    UpdatePlan,
)
from .versions import get_current_versions

log = logging.getLogger("vodou.updater")

_REPO_DIR = Path(__file__).resolve().parent.parent
DEFAULT_STATE_DIR = Path.home() / ".vodou" / "update"


class StageError(RuntimeError):
    """stage() could not produce a verified, ready-to-install set. The live
    installation has not been touched."""


class UpdateManager:
    def __init__(self, *, state_dir: Path | None = None,
                 python_exe: str | None = None,
                 fetch=pypi.fetch_project):
        self.state_dir = Path(state_dir or DEFAULT_STATE_DIR)
        self.python_exe = python_exe or sys.executable
        self._fetch = fetch

    # -- paths -------------------------------------------------------------
    @property
    def plan_path(self) -> Path:
        return self.state_dir / "plan.json"

    @property
    def status_path(self) -> Path:
        return self.state_dir / "status.json"

    @property
    def result_path(self) -> Path:
        return self.state_dir / "result.json"

    @property
    def staged_wheels_dir(self) -> Path:
        return self.state_dir / "wheels"

    @property
    def log_path(self) -> Path:
        return self.state_dir / "apply.log"

    # -- inspection ------------------------------------------------------
    def get_current_versions(self) -> CurrentVersions:
        return get_current_versions()

    def check_for_updates(self, *, allow_prerelease: bool = False,
                          current: CurrentVersions | None = None
                          ) -> UpdatePlan:
        cur = current or get_current_versions()
        log.info("updater: current PyQt6 %s / Qt %s / Qt WebEngine %s / "
                 "Chromium %s / Python %s", cur.pyqt6_binding, cur.qt,
                 cur.qt_webengine, cur.chromium, cur.python)

        if cur.frozen:
            msg = ("Vodou is running from a frozen build. Its Qt runtime can "
                   "only be updated by rebuilding and re-packaging the "
                   "application -- the in-app updater cannot do that safely, "
                   "so no changes have been made. Rebuild from an up-to-date "
                   "source checkout instead.")
            return UpdatePlan(
                current=cur,
                compatibility=_empty_compat(msg),
                possible=False,
                reason=msg,
                allow_prerelease=allow_prerelease)

        compat = resolve_compatible_versions(
            cur, allow_prerelease=allow_prerelease, fetch=self._fetch)

        possible = compat.compatible
        reason = compat.reason
        if possible and not cur.site_packages_writable:
            possible = False
            reason = (
                "The Python packages directory is not writable by this user "
                f"({cur.site_packages or 'unknown location'}). Re-run Vodou "
                "from a user-writable environment (e.g. the recommended "
                "virtual environment) or with the right permissions. No "
                "changes have been made.")

        components = _components(cur, compat)
        update_available = bool(
            possible and compat.compatible and not compat.up_to_date)

        return UpdatePlan(
            current=cur,
            compatibility=compat,
            possible=possible,
            update_available=update_available,
            restart_required=update_available,
            components=components,
            reason=reason,
            allow_prerelease=allow_prerelease,
        )

    # -- staging --------------------------------------------------------
    def stage(self, plan: UpdatePlan, *, progress=None,
              cancelled=None, pip_download=None) -> StageResult:
        """Back up, download the target set, verify it. Never touches the live
        install. Raises :class:`StageError` (and cleans up) on any problem."""
        def emit(msg: str) -> None:
            log.info("stage: %s", msg)
            if progress:
                progress(msg)

        def check_cancel() -> None:
            if cancelled and cancelled():
                self.discard()
                raise StageError("Update cancelled. No changes were made.")

        if not plan.possible or not plan.update_available:
            raise StageError(plan.reason or "Nothing to update.")

        self.state_dir.mkdir(parents=True, exist_ok=True)
        # A fresh staging run supersedes any earlier one.
        self._clear_staging()

        emit("Preparing update...")
        check_cancel()

        emit("Backing up the current installation...")
        cur = plan.current
        known = {
            "PyQt6": cur.pyqt6_wheel,
            "PyQt6-WebEngine": cur.pyqt6_webengine_wheel,
            "PyQt6-Qt6": cur.pyqt6_qt6,
            "PyQt6-WebEngine-Qt6": cur.pyqt6_webengine_qt6,
            "PyQt6-sip": cur.pyqt6_sip,
        }
        try:
            snap = backup.snapshot(
                self.state_dir, python_exe=self.python_exe,
                fetch=self._fetch, pip_download=pip_download, packages=known)
        except backup.BackupError as exc:
            self.discard()
            raise StageError(str(exc)) from exc
        emit(f"Backed up {len(snap.get('packages', {}))} packages "
             f"({len(snap.get('verified_wheels', []))} wheels integrity-"
             "checked).")
        check_cancel()

        t = plan.compatibility.target
        specs = target_specs(t)
        emit(f"Downloading packages: {', '.join(specs)} ...")
        self.staged_wheels_dir.mkdir(parents=True, exist_ok=True)
        runner = pip_download or _pip_download
        rc, out = runner(self.python_exe, self.staged_wheels_dir, specs)
        if rc != 0:
            self.discard()
            raise StageError(
                "Could not download the update from PyPI "
                f"(pip exit {rc}). No changes have been made.\n"
                + "\n".join(out.splitlines()[-8:]))
        check_cancel()

        emit("Verifying packages...")
        want = {"PyQt6": t.pyqt6, "PyQt6-WebEngine": t.pyqt6_webengine}
        if t.expected_qt6:
            want["PyQt6-Qt6"] = t.expected_qt6
        if t.expected_webengine_qt6:
            want["PyQt6-WebEngine-Qt6"] = t.expected_webengine_qt6
        verified, unverified = _verify_against_pypi(
            self.staged_wheels_dir, want, self._fetch)
        if not verified:
            self.discard()
            raise StageError(
                "None of the downloaded packages could be integrity-checked "
                "against PyPI. No changes have been made.")
        emit(f"Verified {len(verified)} package file(s) against PyPI's "
             f"published SHA-256 digests.")

        # Persist the plan (as a plain dict) + mark the set staged.
        self.plan_path.write_text(json.dumps(_plan_dict(plan), indent=2),
                                  encoding="utf-8")
        self._write_status("staged", target=_target_dict(t))
        emit("Update downloaded and verified. Restart Vodou to finish.")
        return StageResult(
            staged=True,
            message="Ready to install on restart.",
            wheel_dir=str(self.staged_wheels_dir),
            wheels=sorted(p.name for p in self.staged_wheels_dir.glob("*")),
            rollback_path=str(self.state_dir / "rollback.json"),
            plan_path=str(self.plan_path),
        )

    # -- apply hand-off ------------------------------------------------
    def apply_command(self, *, relaunch: list[str] | None = None,
                      resume: bool = False) -> list[str]:
        """argv for the detached helper Vodou spawns just before it quits."""
        cmd = [self.python_exe, "-m", "updater.apply", str(self.state_dir),
               "--parent-pid", str(os.getpid())]
        if resume:
            cmd.append("--resume")
        if relaunch is None:
            relaunch = default_relaunch()
        if relaunch:
            cmd += ["--relaunch", *relaunch]
        return cmd

    def spawn_apply(self, *, relaunch: list[str] | None = None,
                    resume: bool = False) -> None:
        """Start the helper fully detached so it outlives this process."""
        cmd = self.apply_command(relaunch=relaunch, resume=resume)
        kwargs: dict = dict(cwd=str(_REPO_DIR), close_fds=True,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
        if os.name == "nt":
            # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
            kwargs["creationflags"] = 0x00000008 | 0x00000200
        else:
            kwargs["start_new_session"] = True
        log.info("updater: spawning apply helper: %s", " ".join(cmd))
        subprocess.Popen(cmd, **kwargs)

    # -- state for a restarted Vodou --------------------------------
    def pending(self) -> dict | None:
        """What, if anything, is waiting on disk. Returns a small dict:
        {"phase": ..., "target": {...}, "interrupted": bool} or None."""
        st = self._read_status()
        if not st:
            return None
        if st.get("schema", 1) > STATE_SCHEMA:
            return {"phase": "unknown", "interrupted": False,
                    "note": "update state written by a newer Vodou"}
        phase = st.get("phase", "")
        interrupted = phase in ("installing", "verifying", "rolling_back")
        return {"phase": phase, "target": st.get("target", {}),
                "interrupted": interrupted}

    def take_result(self) -> ApplyOutcome | None:
        """Read (and delete) the helper's result.json, for a one-time
        'here is how the update went' dialog on the next start."""
        try:
            data = json.loads(self.result_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        try:
            self.result_path.unlink()
        except OSError:
            pass
        return ApplyOutcome(
            status=data.get("status", "failed"),
            message=data.get("message", ""),
            old=data.get("old", {}), new=data.get("new", {}),
            log_path=data.get("log_path", str(self.log_path)))

    def discard(self) -> None:
        """Forget any staged/failed update. Safe to call any time -- it never
        touches the live installation, only the state directory."""
        self._clear_staging()
        for name in ("plan.json", "status.json", "result.json"):
            try:
                (self.state_dir / name).unlink()
            except OSError:
                pass

    # -- internals ---------------------------------------------------
    def _clear_staging(self) -> None:
        for d in (self.staged_wheels_dir,
                  self.state_dir / "rollback_wheels"):
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
        for name in ("rollback.json",):
            try:
                (self.state_dir / name).unlink()
            except OSError:
                pass

    def _write_status(self, phase: str, **extra) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        payload = {"schema": STATE_SCHEMA, "phase": phase,
                   "updated": time.time(), **extra}
        tmp = self.status_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.status_path)

    def _read_status(self) -> dict | None:
        try:
            data = json.loads(self.status_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None


# -- module helpers -------------------------------------------------------

def target_specs(t) -> list[str]:
    """The pip requirement list for an update. The two bindings are always
    pinned; the two ``*-Qt6`` runtime wheels are pinned too when PyPI told us
    a specific newer version -- otherwise pip's default 'only if needed'
    upgrade strategy would leave a same-minor Qt WebEngine security patch on
    the shelf."""
    specs = [f"PyQt6=={t.pyqt6}", f"PyQt6-WebEngine=={t.pyqt6_webengine}"]
    if t.expected_qt6:
        specs.append(f"PyQt6-Qt6=={t.expected_qt6}")
    if t.expected_webengine_qt6:
        specs.append(f"PyQt6-WebEngine-Qt6=={t.expected_webengine_qt6}")
    return specs


def default_relaunch() -> list[str]:
    """How to start Vodou again after the update. Mirrors how it was started:
    the current interpreter + main.py from the checkout."""
    main_py = _REPO_DIR / "main.py"
    return [sys.executable, str(main_py)]


def _components(cur: CurrentVersions, compat) -> list[ComponentVersion]:
    t = compat.target
    rows: list[ComponentVersion] = []

    def row(name, current, available, note=""):
        will = bool(available and available not in ("", "unknown", current)
                    and compat.compatible and not compat.up_to_date)
        rows.append(ComponentVersion(name, current or "unknown",
                                     available or "unknown", will, note))

    row("PyQt6", cur.pyqt6_binding, t.pyqt6 or cur.pyqt6_binding)
    row("PyQt6-WebEngine", cur.pyqt6_webengine_wheel,
        t.pyqt6_webengine or cur.pyqt6_webengine_wheel)
    row("Qt", cur.qt, (t.minor + ".x") if t.minor else cur.qt,
        "pulled in automatically with the bindings")
    row("Qt WebEngine", cur.qt_webengine,
        (t.expected_webengine_qt6 or (t.minor + ".x" if t.minor else ""))
        or cur.qt_webengine,
        "part of the PyQt6-WebEngine-Qt6 runtime wheel")
    row("Chromium", cur.chromium,
        "bundled with Qt WebEngine " + (t.minor + ".x" if t.minor else ""),
        "exact build is confirmed after the update")
    row("Python", cur.python, cur.python, "never changed by the updater")
    return rows


def _target_dict(t) -> dict:
    return {"minor": t.minor, "pyqt6": t.pyqt6,
            "pyqt6_webengine": t.pyqt6_webengine,
            "expected_qt6": t.expected_qt6,
            "expected_webengine_qt6": t.expected_webengine_qt6,
            "requires_python": t.requires_python}


def _plan_dict(plan: UpdatePlan) -> dict:
    t = plan.compatibility.target
    return {
        "schema": STATE_SCHEMA,
        "created": time.time(),
        "python_exe": plan.current.python_exe,
        "target": _target_dict(t),
        "from": {
            "pyqt6": plan.current.pyqt6_binding,
            "pyqt6_webengine": plan.current.pyqt6_webengine_wheel,
            "qt_webengine": plan.current.qt_webengine,
            "chromium": plan.current.chromium,
        },
        "install_specs": target_specs(t),
        "restart_required": True,
    }


def _empty_compat(reason: str):
    from .models import CompatibilityResult
    return CompatibilityResult(compatible=False, reason=reason)


def _pip_download(python_exe: str, dest: Path, specs: list[str]):
    cmd = [python_exe, "-m", "pip", "download", "--only-binary=:all:",
           "--dest", str(dest), *specs]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=3600)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"{exc}"
    return proc.returncode, (proc.stdout + proc.stderr)


def _verify_against_pypi(wheels_dir: Path, want: dict[str, str], fetch):
    """Independent SHA-256 check of the downloaded wheels against PyPI's
    published digests. *want* maps distribution name -> exact version. Any
    file pip pulled that we did not name (e.g. PyQt6-sip) is left in
    'unverified' -- pip fetched it from the same TLS'd index."""
    import hashlib

    digests: dict[str, str] = {}
    for name, ver in want.items():
        try:
            j = fetch(name)
        except pypi.PyPIError:
            continue
        for f in (j.get("releases") or {}).get(ver, []):
            sha = (f.get("digests") or {}).get("sha256")
            if f.get("filename") and sha:
                digests[f["filename"]] = sha

    verified: list[str] = []
    unverified: list[str] = []
    for wheel in sorted(wheels_dir.glob("*.whl")):
        want = digests.get(wheel.name)
        if not want:
            unverified.append(wheel.name)
            continue
        h = hashlib.sha256()
        with wheel.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != want:
            raise StageError(
                f"downloaded {wheel.name} failed its SHA-256 check against "
                "PyPI. No changes have been made.")
        verified.append(wheel.name)
    return verified, unverified
