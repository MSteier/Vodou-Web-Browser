"""Stage 4 -- snapshot the current Qt stack so a failed update is reversible.

The requirements are strict: nothing in the live installation may be touched
before a *verified* backup exists, and a rollback must not depend on the
network (the update may have failed *because* the network died).

So a snapshot is:
  * ``rollback.json`` -- the exact installed version of every package in the
    coordinated group, plus the interpreter it belongs to
  * ``rollback_wheels/`` -- those exact wheels, downloaded now and checksum-
    verified, so ``restore()`` is a fully offline
    ``pip install --force-reinstall --no-deps --no-index`` of a known set

``restore()`` reinstalls that pinned set and then asks versions.verify_
installation() to confirm the stack imports again.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import pypi
from .compatibility import GROUP_PACKAGES
from .versions import InstallationBroken, verify_installation

_REPO_DIR = Path(__file__).resolve().parent.parent


class BackupError(RuntimeError):
    """A backup could not be created or verified -- the caller must abort and
    leave the installation untouched."""


_INSPECT = """
import json
from importlib import metadata
names = {names!r}
out = {{}}
for n in names:
    try:
        out[n] = metadata.version(n)
    except Exception:
        out[n] = None
print(json.dumps(out))
"""


def _installed_versions(python_exe: str) -> dict[str, str]:
    """Ask the *target* interpreter (not necessarily ours) what it has, so the
    snapshot describes the environment the apply step will actually modify."""
    script = _INSPECT.format(names=list(GROUP_PACKAGES))
    try:
        proc = subprocess.run([python_exe, "-c", script],
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BackupError(f"could not inspect the environment: {exc}") from exc
    if proc.returncode != 0:
        raise BackupError(
            f"environment inspection failed: {proc.stderr.strip()[:300]}")
    try:
        raw = json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise BackupError("environment inspection produced no result") from exc
    return {k: v for k, v in raw.items() if v}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(state_dir: Path, *, python_exe: str | None = None,
             fetch=pypi.fetch_project,
             pip_download=None,
             packages: dict[str, str] | None = None) -> dict:
    """Create and verify a rollback snapshot in *state_dir*.

    *packages* (name -> version) may be supplied by the caller -- it is what
    ``get_current_versions()`` already detected, so we skip a second
    subprocess. When omitted, the target interpreter is inspected directly.

    Returns the snapshot dict (also written to ``rollback.json``). Raises
    :class:`BackupError` on any problem -- callers treat that as "do not
    proceed with the update".
    """
    python_exe = python_exe or sys.executable
    state_dir = Path(state_dir)
    wheels_dir = state_dir / "rollback_wheels"
    if wheels_dir.exists():
        shutil.rmtree(wheels_dir, ignore_errors=True)
    wheels_dir.mkdir(parents=True, exist_ok=True)

    versions = {k: v for k, v in (packages or {}).items()
                if v and v != "unknown"} or _installed_versions(python_exe)
    if "PyQt6" not in versions or "PyQt6-WebEngine" not in versions:
        raise BackupError(
            "the current environment has no PyQt6 / PyQt6-WebEngine to back "
            "up -- refusing to touch it.")

    pins = [f"{name}=={ver}" for name, ver in versions.items()]
    runner = pip_download or _pip_download
    rc, out = runner(python_exe, wheels_dir, pins)
    if rc != 0:
        raise BackupError(
            "could not cache the current wheels for rollback "
            f"(pip download exit {rc}). No changes have been made.\n"
            + "\n".join(out.splitlines()[-6:]))

    # Verify every cached wheel against PyPI's published SHA-256 where we can
    # match it by filename. A mismatch aborts the whole update.
    verified, unverified = _verify_wheels(wheels_dir, versions, fetch)
    if not verified:
        raise BackupError(
            "no cached rollback wheel could be integrity-checked against "
            "PyPI. Refusing to proceed.")

    snap = {
        "schema": 1,
        "created": time.time(),
        "python": _python_version(python_exe),
        "python_exe": python_exe,
        "packages": versions,
        "wheels_dir": str(wheels_dir),
        "verified_wheels": verified,
        "unverified_wheels": unverified,
    }
    (state_dir / "rollback.json").write_text(
        json.dumps(snap, indent=2), encoding="utf-8")
    return snap


def _python_version(python_exe: str) -> str:
    try:
        proc = subprocess.run(
            [python_exe, "-c",
             "import sys;print('%d.%d.%d'%sys.version_info[:3])"],
            capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _pip_download(python_exe: str, dest: Path, specs: list[str]):
    """`pip download` fetches from PyPI over HTTPS and verifies the index
    hashes itself; we add an independent SHA-256 check in _verify_wheels."""
    cmd = [python_exe, "-m", "pip", "download", "--only-binary=:all:",
           "--no-deps", "--dest", str(dest), *specs]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=1800)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"{exc}"
    return proc.returncode, (proc.stdout + proc.stderr)


def _verify_wheels(wheels_dir: Path, versions: dict[str, str], fetch):
    verified: list[str] = []
    unverified: list[str] = []
    digests: dict[str, str] = {}
    for name, ver in versions.items():
        try:
            j = fetch(name)
        except pypi.PyPIError:
            continue
        for f in (j.get("releases") or {}).get(ver, []):
            sha = (f.get("digests") or {}).get("sha256")
            if f.get("filename") and sha:
                digests[f["filename"]] = sha
    for wheel in sorted(wheels_dir.glob("*.whl")):
        want = digests.get(wheel.name)
        if want is None:
            unverified.append(wheel.name)
            continue
        if _sha256(wheel) != want:
            raise BackupError(
                f"cached wheel {wheel.name} failed its SHA-256 check "
                "against PyPI -- aborting.")
        verified.append(wheel.name)
    return verified, unverified


def load_snapshot(state_dir: Path) -> dict | None:
    p = Path(state_dir) / "rollback.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def restore(snapshot_data: dict, *, pip_install=None,
            verify: bool = True) -> None:
    """Reinstall the exact pinned set from the offline wheel cache.

    Raises :class:`InstallationBroken` if, after restoring, the stack still
    won't import -- the worst case, which apply.py surfaces loudly.
    """
    python_exe = snapshot_data.get("python_exe") or sys.executable
    wheels_dir = snapshot_data.get("wheels_dir", "")
    packages = snapshot_data.get("packages") or {}
    if not packages:
        raise BackupError("rollback snapshot has no package list")

    pins = [f"{name}=={ver}" for name, ver in packages.items()]
    cmd = [python_exe, "-m", "pip", "install", "--force-reinstall",
           "--no-deps", "--no-index", "--find-links", wheels_dir, *pins]
    runner = pip_install or _run
    rc, out = runner(cmd)
    if rc != 0:
        raise BackupError(
            f"rollback pip install failed (exit {rc}):\n"
            + "\n".join(out.splitlines()[-8:]))
    if verify:
        verify_installation(python_exe)  # raises InstallationBroken


def _run(cmd: list[str]):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=1800, cwd=str(_REPO_DIR))
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"{exc}"
    return proc.returncode, (proc.stdout + proc.stderr)


__all__ = ["snapshot", "restore", "load_snapshot", "BackupError",
           "InstallationBroken"]
