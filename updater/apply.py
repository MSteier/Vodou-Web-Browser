"""Stage 6 -- the detached helper that finishes an update after Vodou exits.

Why a separate process: on Windows the Qt DLLs (Qt6WebEngineCore.dll,
QtWebEngineProcess.exe, the sip .pyd) are memory-mapped and locked while Vodou
runs, so ``pip install --upgrade PyQt6`` from inside the live app can half-fail
with "Access is denied". This helper is spawned fully detached just before
Vodou quits, waits for the process to actually be gone, and only then touches
the installation.

Sequence (every step logged to ``<state_dir>/apply.log``):

    wait for the parent PID to exit
    status -> installing
    pip install --no-index --find-links <staged wheels>  PyQt6==T  PyQt6-WebEngine==T
    status -> verifying
    import the whole Qt WebEngine stack in a fresh interpreter
        success -> status done, write result.json, relaunch Vodou
        failure -> restore the verified backup, verify *that*, write
                   result.json (rolled_back / rollback_failed), relaunch Vodou

``--resume`` skips straight to "restore the backup": it is how a Vodou that
finds ``status.json`` stuck at *installing* (the machine lost power mid-apply)
repairs itself.

Run:  python -m updater.apply <state_dir> [--parent-pid N]
                              [--relaunch <exe> <arg>...] [--resume]

Nothing here logs secrets -- the updater handles none (no tokens, no
passwords, anonymous PyPI over HTTPS).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

from . import backup
from .models import STATE_SCHEMA
from .versions import InstallationBroken, verify_installation

log = logging.getLogger("vodou.updater.apply")

_REPO_DIR = Path(__file__).resolve().parent.parent


def _setup_logging(state_dir: Path) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger("vodou.updater")
    root.setLevel(logging.INFO)
    target = str((state_dir / "apply.log").resolve())
    # Idempotent: don't stack a second handler on the same file if run twice
    # in one process (the test suite does exactly that).
    for h in root.handlers:
        if isinstance(h, logging.FileHandler) and \
                getattr(h, "baseFilename", None) == target:
            return
    handler = logging.FileHandler(target, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s"))
    root.addHandler(handler)
    root.addHandler(logging.StreamHandler(sys.stderr))


def _write_status(state_dir: Path, phase: str, **extra) -> None:
    payload = {"schema": STATE_SCHEMA, "phase": phase,
               "updated": time.time(), **extra}
    tmp = state_dir / "status.json.tmp"
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(state_dir / "status.json")


def _write_result(state_dir: Path, status: str, message: str,
                  old: dict, new: dict) -> None:
    payload = {"schema": STATE_SCHEMA, "status": status, "message": message,
               "old": old, "new": new, "finished": time.time(),
               "log_path": str(state_dir / "apply.log")}
    (state_dir / "result.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8")


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            import ctypes
            SYNCHRONIZE = 0x00100000
            h = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, pid)
            if not h:
                return False
            ctypes.windll.kernel32.CloseHandle(h)
            return True
        os.kill(pid, 0)
        return True
    except (OSError, PermissionError):
        return False


def _wait_for_parent(pid: int, timeout: int = 90) -> None:
    if pid <= 0:
        return
    log.info("waiting for Vodou (pid %s) to exit...", pid)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _pid_alive(pid):
            log.info("Vodou has exited; continuing.")
            time.sleep(1.0)  # let the OS release file locks
            return
        time.sleep(0.5)
    log.warning("Vodou pid %s still present after %ss -- continuing anyway.",
                pid, timeout)


def _run_pip(cmd: list[str], runner=None) -> tuple[int, str]:
    if runner is not None:
        return runner(cmd)
    log.info("running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=3600, cwd=str(_REPO_DIR))
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"{exc}"
    out = (proc.stdout or "") + (proc.stderr or "")
    for line in out.splitlines()[-12:]:
        log.info("pip| %s", line)
    return proc.returncode, out


def _relaunch(relaunch: list[str] | None) -> None:
    if not relaunch:
        log.info("no relaunch command given; not restarting Vodou.")
        return
    log.info("relaunching Vodou: %s", " ".join(relaunch))
    kwargs: dict = dict(cwd=str(_REPO_DIR), close_fds=True,
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
    if os.name == "nt":
        kwargs["creationflags"] = 0x00000008 | 0x00000200
    else:
        kwargs["start_new_session"] = True
    try:
        subprocess.Popen(list(relaunch), **kwargs)
    except OSError as exc:
        log.error("could not relaunch Vodou: %s", exc)


def _do_rollback(state_dir: Path, snap: dict, old: dict, why: str,
                 pip_runner=None) -> tuple[str, str]:
    log.warning("rolling back: %s", why)
    _write_status(state_dir, "rolling_back")
    try:
        backup.restore(snap, pip_install=(
            (lambda c: pip_runner(c)) if pip_runner else None))
    except (backup.BackupError, InstallationBroken) as exc:
        log.error("ROLLBACK FAILED: %s", exc)
        _write_status(state_dir, "rollback_failed", error=str(exc))
        return ("rollback_failed",
                f"The update failed ({why}) and the automatic rollback also "
                f"failed ({exc}). Your Qt packages may be inconsistent. "
                "Reinstall them with:\n    pip install --force-reinstall "
                + " ".join(f"{k}=={v}" for k, v in
                           (snap.get('packages') or {}).items()))
    log.info("rollback complete; previous versions restored and verified.")
    _write_status(state_dir, "rolled_back")
    return ("rolled_back",
            f"The update did not complete ({why}). Your previous Qt "
            "installation has been restored and verified -- Vodou is exactly "
            "as it was before.")


def run(argv: list[str] | None = None,
        *, pip_runner=None, wait=True) -> int:
    parser = argparse.ArgumentParser(prog="updater.apply")
    parser.add_argument("state_dir", type=Path)
    parser.add_argument("--parent-pid", type=int, default=0)
    parser.add_argument("--relaunch", nargs=argparse.REMAINDER, default=None)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)

    state_dir: Path = args.state_dir
    _setup_logging(state_dir)
    log.info("Vodou updater helper started (resume=%s).", args.resume)

    snap = backup.load_snapshot(state_dir)
    if not snap:
        log.error("no rollback snapshot in %s -- nothing to do.", state_dir)
        _write_result(state_dir, "failed",
                      "Internal error: the update state was incomplete "
                      "(no backup snapshot). No changes were made.", {}, {})
        _relaunch(args.relaunch)
        return 2

    old = {
        "PyQt6": (snap.get("packages") or {}).get("PyQt6"),
        "PyQt6-WebEngine": (snap.get("packages") or {}).get("PyQt6-WebEngine"),
    }
    python_exe = snap.get("python_exe") or sys.executable

    if wait:
        _wait_for_parent(args.parent_pid)

    # --resume: a previous apply died mid-flight. Do not try to install --
    # just get back to a known-good state.
    if args.resume:
        status, message = _do_rollback(
            state_dir, snap, old,
            "a previous update was interrupted", pip_runner)
        try:
            new = verify_installation(python_exe)
        except InstallationBroken as exc:
            new = {"error": str(exc)}
        _write_result(state_dir, status, message, old,
                      {"PyQt6": new.get("pyqt6_wheel"),
                       "PyQt6-WebEngine": new.get("webengine_wheel")})
        _relaunch(args.relaunch)
        return 0 if status == "rolled_back" else 1

    plan = _load_plan(state_dir)
    specs = plan.get("install_specs") or []
    wheels_dir = state_dir / "wheels"
    if not specs or not wheels_dir.is_dir():
        status, message = _do_rollback(
            state_dir, snap, old, "the staged update was incomplete",
            pip_runner)
        _write_result(state_dir, status, message, old, {})
        _relaunch(args.relaunch)
        return 1

    _write_status(state_dir, "installing", target=plan.get("target", {}))
    log.info("installing %s from the verified offline wheel set", specs)
    cmd = [python_exe, "-m", "pip", "install", "--upgrade", "--no-index",
           "--find-links", str(wheels_dir), *specs]
    rc, out = _run_pip(cmd, pip_runner)
    if rc != 0:
        status, message = _do_rollback(
            state_dir, snap, old, f"pip install failed (exit {rc})",
            pip_runner)
        _write_result(state_dir, status, message, old, {})
        _relaunch(args.relaunch)
        return 1

    _write_status(state_dir, "verifying", target=plan.get("target", {}))
    expect_minor = (plan.get("target") or {}).get("minor")
    try:
        new = verify_installation(python_exe, expect_minor=expect_minor)
    except InstallationBroken as exc:
        status, message = _do_rollback(
            state_dir, snap, old, f"the new stack would not import ({exc})",
            pip_runner)
        _write_result(state_dir, status, message, old, {})
        _relaunch(args.relaunch)
        return 1

    log.info("update complete: PyQt6 %s, PyQt6-WebEngine %s, "
             "Qt WebEngine %s, Chromium %s",
             new.get("pyqt6_wheel"), new.get("webengine_wheel"),
             new.get("webengine"), new.get("chromium"))
    _write_status(state_dir, "done", target=plan.get("target", {}))
    _write_result(
        state_dir, "done",
        "Update applied successfully and verified.",
        old,
        {"PyQt6": new.get("pyqt6_wheel"),
         "PyQt6-WebEngine": new.get("webengine_wheel"),
         "Qt WebEngine": new.get("webengine"),
         "Chromium": new.get("chromium")})
    # Clean the bulky wheel caches now that we no longer need them; keep the
    # small json files so Vodou can show the result once.
    import shutil
    for d in (wheels_dir, state_dir / "rollback_wheels"):
        shutil.rmtree(d, ignore_errors=True)
    _relaunch(args.relaunch)
    return 0


def _load_plan(state_dir: Path) -> dict:
    try:
        return json.loads((state_dir / "plan.json").read_text(
            encoding="utf-8"))
    except (OSError, ValueError):
        return {}


if __name__ == "__main__":  # pragma: no cover -- process entry point
    raise SystemExit(run())
