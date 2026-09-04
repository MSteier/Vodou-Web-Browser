"""Tests for the coordinated Qt / PyQt6 / Qt WebEngine updater (updater/).

Offline and deterministic: PyPI is a canned dict, pip is a stub, and the only
real subprocess is the one "does the stack still import" probe (which stands in
for "Vodou still starts after an update"). Everything else -- resolution,
the Python-compatibility gate, the lockstep rule, staging, hash verification,
rollback, resume, cancellation -- runs against fakes.

Run:  python tests/test_updater.py      (or: pytest tests/test_updater.py)
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from updater import apply as apply_mod  # noqa: E402
from updater import backup as backup_mod  # noqa: E402
from updater import compatibility, diagnostics, pypi, versions  # noqa: E402
from updater.manager import StageError, UpdateManager, target_specs  # noqa: E402
from updater.models import CurrentVersions  # noqa: E402

_failures: list[str] = []


def check(label: str, cond: bool) -> None:
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


# -- fake PyPI ------------------------------------------------------------

def _wheel_name(name: str, version: str) -> str:
    return f"{name.replace('-', '_')}-{version}-cp310-cp310-win_amd64.whl"


def _file(name: str, version: str, requires_python: str,
          *, kind: str = "bdist_wheel", yanked: bool = False,
          sha: str | None = None) -> dict:
    fn = _wheel_name(name, version)
    return {
        "filename": fn,
        "packagetype": kind,
        "yanked": yanked,
        "requires_python": requires_python,
        "url": f"https://files.pythonhosted.org/{fn}",
        "digests": {"sha256": sha or ("00" * 32)},
    }


def _project(name: str, spec: dict[str, str]) -> dict:
    """spec: {version: requires_python}. Newest key is info.version."""
    releases = {v: [_file(name, v, rp)] for v, rp in spec.items()}
    newest = sorted(spec, key=pypi.parse_version)[-1]
    return {"info": {"version": newest, "requires_python": spec[newest]},
            "releases": releases}


def make_fetch(table: dict[str, dict]):
    def fetch(pkg: str) -> dict:
        if pkg not in table:
            raise pypi.PyPIError(f"no fake for {pkg}")
        return table[pkg]
    return fetch


def base_current(**over) -> CurrentVersions:
    cv = CurrentVersions(
        vodou_version="1.52.2", vodou_display="1.52.2 (abc1234)",
        python="3.10.11", python_tuple=(3, 10, 11),
        python_exe=sys.executable, in_venv=False,
        pyqt6_binding="6.10.1", pyqt6_wheel="6.10.1", pyqt6_sip="13.10.0",
        pyqt6_webengine_wheel="6.10.0", pyqt6_qt6="6.10.1",
        pyqt6_webengine_qt6="6.10.1", qt="6.10.1",
        qt_webengine="6.10.1", chromium="130.0.0.0", frozen=False,
        site_packages=str(Path(tempfile.gettempdir())),
        site_packages_writable=True, is_admin=False)
    for k, v in over.items():
        setattr(cv, k, v)
    return cv


# -- version detection --------------------------------------------------

def test_get_current_versions() -> None:
    cv = versions.get_current_versions()
    check("current: python tuple has 3 parts", len(cv.python_tuple) == 3)
    check("current: PyQt6 binding is a version string",
          cv.pyqt6_binding not in ("", "unknown"))
    check("current: Qt WebEngine distinct field is populated",
          cv.qt_webengine not in ("",))
    check("current: chromium field is populated", bool(cv.chromium))
    check("current: not frozen when run from source", cv.frozen is False)


def test_diagnostics_report() -> None:
    rep = diagnostics.diagnostics_report()
    for key in ("Packaging", "Install directory", "Site-packages writable",
                "Running elevated", "Qt WebEngine", "Chromium", "PyQt6-Qt6 "
                "(runtime)"):
        check(f"diagnostics has {key!r}", key in rep)
    check("diagnostics text renders",
          "Qt WebEngine" in diagnostics.as_text(rep))


# -- requires_python evaluator ---------------------------------------

def test_python_satisfies_table() -> None:
    py = (3, 10, 11)
    cases = {
        "": True, ">=3.10": True, ">=3.11": False,
        # exclusive > / <= of a bare "3.10" compare against 3.10.0, so a later
        # patch (3.10.11) is above it -- matches packaging's own behaviour.
        ">3.10": True, "<=3.10": False,
        "<3.11": True, ">=3.9,<3.13": True,
        ">=3.9,<3.10": False, "==3.10.*": True, "!=3.10.*": False,
        "~=3.10": True, "~=3.10.2": True, "~=3.11": False,
    }
    for spec, want in cases.items():
        got = pypi.python_satisfies(spec, py)
        check(f"python_satisfies({spec!r}) == {want}", got == want)
    try:
        pypi.python_satisfies(">=potato", py)
        check("unparseable requires_python raises", False)
    except ValueError:
        check("unparseable requires_python raises", True)


# -- resolution --------------------------------------------------------

def _mgr(table) -> UpdateManager:
    return UpdateManager(state_dir=Path(tempfile.mkdtemp()),
                         fetch=make_fetch(table))


def test_compatible_update_available() -> None:
    table = {
        "PyQt6": _project("PyQt6", {"6.10.1": ">=3.9", "6.11.0": ">=3.10"}),
        "PyQt6-WebEngine": _project(
            "PyQt6-WebEngine", {"6.10.0": ">=3.9", "6.11.0": ">=3.10"}),
        "PyQt6-Qt6": _project("PyQt6-Qt6", {"6.11.0": ">=3.10"}),
        "PyQt6-WebEngine-Qt6": _project(
            "PyQt6-WebEngine-Qt6", {"6.11.0": ">=3.10"}),
    }
    plan = _mgr(table).check_for_updates(current=base_current())
    check("update: possible", plan.possible)
    check("update: available", plan.update_available)
    check("update: restart required", plan.restart_required)
    check("update: target minor 6.11", plan.compatibility.target.minor
          == "6.11")
    check("update: target pyqt6 6.11.0",
          plan.compatibility.target.pyqt6 == "6.11.0")
    check("update: not up to date", plan.compatibility.up_to_date is False)


def test_no_update_when_current_is_latest() -> None:
    table = {
        "PyQt6": _project("PyQt6", {"6.11.0": ">=3.10"}),
        "PyQt6-WebEngine": _project("PyQt6-WebEngine", {"6.11.0": ">=3.10"}),
        "PyQt6-Qt6": _project("PyQt6-Qt6", {"6.11.0": ">=3.10"}),
        "PyQt6-WebEngine-Qt6": _project(
            "PyQt6-WebEngine-Qt6", {"6.11.0": ">=3.10"}),
    }
    cur = base_current(pyqt6_wheel="6.11.0", pyqt6_binding="6.11.0",
                       pyqt6_webengine_wheel="6.11.0", pyqt6_qt6="6.11.0",
                       pyqt6_webengine_qt6="6.11.0", qt_webengine="6.11.0")
    plan = _mgr(table).check_for_updates(current=cur)
    check("no-update: up to date", plan.compatibility.up_to_date)
    check("no-update: update_available False", plan.update_available is False)
    check("no-update: still possible/compatible", plan.possible)


def test_runtime_patch_only() -> None:
    # Bindings already current; only the *-Qt6 runtime moved 6.11.1 -> 6.11.2.
    table = {
        "PyQt6": _project("PyQt6", {"6.11.0": ">=3.10"}),
        "PyQt6-WebEngine": _project("PyQt6-WebEngine", {"6.11.0": ">=3.10"}),
        "PyQt6-Qt6": _project(
            "PyQt6-Qt6", {"6.11.1": ">=3.10", "6.11.2": ">=3.10"}),
        "PyQt6-WebEngine-Qt6": _project(
            "PyQt6-WebEngine-Qt6", {"6.11.1": ">=3.10", "6.11.2": ">=3.10"}),
    }
    cur = base_current(pyqt6_wheel="6.11.0", pyqt6_binding="6.11.0",
                       pyqt6_webengine_wheel="6.11.0", pyqt6_qt6="6.11.1",
                       pyqt6_webengine_qt6="6.11.1", qt_webengine="6.11.1")
    plan = _mgr(table).check_for_updates(current=cur)
    check("runtime-patch: update available", plan.update_available)
    specs = target_specs(plan.compatibility.target)
    check("runtime-patch: pins PyQt6-Qt6==6.11.2",
          "PyQt6-Qt6==6.11.2" in specs)
    check("runtime-patch: keeps bindings at 6.11.0",
          "PyQt6==6.11.0" in specs)
    check("runtime-patch: reason says 'patch'",
          "patch" in plan.compatibility.reason.lower())


def test_python_incompatibility_blocks_newer_only() -> None:
    table = {
        "PyQt6": _project("PyQt6", {"6.11.0": ">=3.10", "6.13.0": ">=3.12"}),
        "PyQt6-WebEngine": _project(
            "PyQt6-WebEngine", {"6.11.0": ">=3.10", "6.13.0": ">=3.12"}),
        "PyQt6-Qt6": _project("PyQt6-Qt6", {"6.11.0": ">=3.10"}),
        "PyQt6-WebEngine-Qt6": _project(
            "PyQt6-WebEngine-Qt6", {"6.11.0": ">=3.10"}),
    }
    plan = _mgr(table).check_for_updates(current=base_current())
    check("py-block: still resolves to 6.11", plan.compatibility.target.minor
          == "6.11")
    check("py-block: compatible True", plan.compatibility.compatible)
    check("py-block: blocked_by_python names 6.13",
          (plan.compatibility.blocked_by_python or ("", ""))[0] == "6.13")
    check("py-block: reason mentions Python",
          "Python" in plan.compatibility.reason)


def test_no_release_supports_this_python() -> None:
    table = {
        "PyQt6": _project("PyQt6", {"6.14.0": ">=3.13"}),
        "PyQt6-WebEngine": _project("PyQt6-WebEngine", {"6.14.0": ">=3.13"}),
    }
    plan = _mgr(table).check_for_updates(current=base_current())
    check("no-py: not possible", plan.possible is False)
    check("no-py: not compatible", plan.compatibility.compatible is False)
    check("no-py: reason mentions Python 3.10.11",
          "3.10.11" in plan.compatibility.reason)


def test_lockstep_no_version_mixing() -> None:
    # PyQt6 races ahead to 6.13; WebEngine binding tops out at 6.11 for py3.10.
    table = {
        "PyQt6": _project("PyQt6", {"6.11.0": ">=3.10", "6.12.0": ">=3.10",
                                    "6.13.0": ">=3.10"}),
        "PyQt6-WebEngine": _project(
            "PyQt6-WebEngine", {"6.10.0": ">=3.9", "6.11.0": ">=3.10"}),
        "PyQt6-Qt6": _project("PyQt6-Qt6", {"6.11.0": ">=3.10"}),
        "PyQt6-WebEngine-Qt6": _project(
            "PyQt6-WebEngine-Qt6", {"6.11.0": ">=3.10"}),
    }
    plan = _mgr(table).check_for_updates(current=base_current())
    t = plan.compatibility.target
    check("lockstep: both land on 6.11", t.pyqt6 == "6.11.0"
          and t.pyqt6_webengine == "6.11.0")
    check("lockstep: same minor",
          compatibility.is_compatible_pair(t.pyqt6, t.pyqt6_webengine,
                                           (3, 10, 11), t.requires_python))
    check("lockstep: never proposes 6.13 binding with 6.11 webengine",
          not (t.pyqt6 or "").startswith("6.13"))


def test_prerelease_gate() -> None:
    table = {
        "PyQt6": _project("PyQt6", {"6.11.0": ">=3.10", "6.12.0rc1": ">=3.10"}),
        "PyQt6-WebEngine": _project(
            "PyQt6-WebEngine", {"6.11.0": ">=3.10", "6.12.0rc1": ">=3.10"}),
        "PyQt6-Qt6": _project(
            "PyQt6-Qt6", {"6.11.0": ">=3.10", "6.12.0rc1": ">=3.10"}),
        "PyQt6-WebEngine-Qt6": _project(
            "PyQt6-WebEngine-Qt6",
            {"6.11.0": ">=3.10", "6.12.0rc1": ">=3.10"}),
    }
    m = _mgr(table)
    stable = m.check_for_updates(current=base_current())
    check("prerelease: default ignores rc",
          stable.compatibility.target.minor == "6.11")
    dev = m.check_for_updates(current=base_current(), allow_prerelease=True)
    check("prerelease: opt-in picks 6.12 rc",
          dev.compatibility.target.minor == "6.12")


def test_frozen_build_refused() -> None:
    table = {"PyQt6": _project("PyQt6", {"6.11.0": ">=3.10"}),
             "PyQt6-WebEngine": _project(
                 "PyQt6-WebEngine", {"6.11.0": ">=3.10"})}
    plan = _mgr(table).check_for_updates(current=base_current(frozen=True))
    check("frozen: not possible", plan.possible is False)
    check("frozen: reason says rebuild",
          "rebuild" in plan.reason.lower())


def test_readonly_site_packages_refused() -> None:
    table = {
        "PyQt6": _project("PyQt6", {"6.10.1": ">=3.9", "6.11.0": ">=3.10"}),
        "PyQt6-WebEngine": _project(
            "PyQt6-WebEngine", {"6.10.0": ">=3.9", "6.11.0": ">=3.10"}),
        "PyQt6-Qt6": _project("PyQt6-Qt6", {"6.11.0": ">=3.10"}),
        "PyQt6-WebEngine-Qt6": _project(
            "PyQt6-WebEngine-Qt6", {"6.11.0": ">=3.10"}),
    }
    plan = _mgr(table).check_for_updates(
        current=base_current(site_packages_writable=False))
    check("readonly: not possible", plan.possible is False)
    check("readonly: reason mentions writable",
          "writable" in plan.reason.lower())


# -- staging: backup, download, verify --------------------------------

def _good_plan(mgr) -> object:
    table = {
        "PyQt6": _project("PyQt6", {"6.10.1": ">=3.9", "6.11.0": ">=3.10"}),
        "PyQt6-WebEngine": _project(
            "PyQt6-WebEngine", {"6.10.0": ">=3.9", "6.11.0": ">=3.10"}),
        "PyQt6-Qt6": _project("PyQt6-Qt6", {"6.11.0": ">=3.10"}),
        "PyQt6-WebEngine-Qt6": _project(
            "PyQt6-WebEngine-Qt6", {"6.11.0": ">=3.10"}),
    }
    mgr._fetch = make_fetch(table)
    return mgr.check_for_updates(current=base_current())


def _sha256_of(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


# Every version that either the rollback snapshot (current 6.10.x + sip) or the
# staged target (6.11.0) will ask about.
_DIGEST_SPEC = {
    "PyQt6": {"6.10.1": ">=3.9", "6.11.0": ">=3.10"},
    "PyQt6-WebEngine": {"6.10.0": ">=3.9", "6.11.0": ">=3.10"},
    "PyQt6-Qt6": {"6.10.1": ">=3.9", "6.11.0": ">=3.10"},
    "PyQt6-WebEngine-Qt6": {"6.10.1": ">=3.9", "6.11.0": ">=3.10"},
    "PyQt6-sip": {"13.10.0": ">=3.9"},
}


def _fetch_with_digests(file_bytes: bytes):
    """A fake PyPI whose published SHA-256 for every wheel equals
    sha256(file_bytes)."""
    sha = _sha256_of(file_bytes)

    def proj(name, spec):
        rel = {v: [_file(name, v, rp, sha=sha)] for v, rp in spec.items()}
        newest = sorted(spec, key=pypi.parse_version)[-1]
        return {"info": {"version": newest}, "releases": rel}

    return make_fetch({n: proj(n, s) for n, s in _DIGEST_SPEC.items()})


def spec_aware_download(payload: bytes, *, rc: int = 0):
    """A fake `pip download`: writes one wheel per `Name==Version` spec, named
    exactly as the fake PyPI names it, with contents *payload*."""
    def download(python_exe, dest, specs):
        if rc != 0:
            return rc, "pip: simulated download failure"
        d = Path(dest)
        d.mkdir(parents=True, exist_ok=True)
        for spec in specs:
            name, _, version = spec.partition("==")
            version = version or "0.0.0"
            (d / _wheel_name(name, version)).write_bytes(payload)
        return 0, "Saved " + " ".join(specs)
    return download


def test_stage_download_failure_leaves_nothing() -> None:
    mgr = UpdateManager(state_dir=Path(tempfile.mkdtemp()))
    plan = _good_plan(mgr)
    mgr._fetch = _fetch_with_digests(b"payload")
    try:
        mgr.stage(plan, pip_download=spec_aware_download(b"payload", rc=1))
        check("stage-dlfail: raised StageError", False)
    except StageError as exc:
        check("stage-dlfail: raised StageError", True)
        check("stage-dlfail: message is actionable",
              "No changes have been made" in str(exc))
    check("stage-dlfail: no plan.json", not mgr.plan_path.exists())
    check("stage-dlfail: no status.json", not mgr.status_path.exists())
    check("stage-dlfail: no rollback snapshot",
          not (mgr.state_dir / "rollback.json").exists())


def test_stage_hash_mismatch_aborts() -> None:
    mgr = UpdateManager(state_dir=Path(tempfile.mkdtemp()))
    plan = _good_plan(mgr)
    # PyPI publishes the digest of "real", but the download writes "TAMPERED".
    mgr._fetch = _fetch_with_digests(b"real")
    try:
        mgr.stage(plan, pip_download=spec_aware_download(b"TAMPERED"))
        check("stage-hash: raised", False)
    except (StageError, backup_mod.BackupError) as exc:
        check("stage-hash: raised on digest mismatch", True)
        check("stage-hash: message names SHA-256",
              "SHA-256" in str(exc))
    check("stage-hash: no plan.json", not mgr.plan_path.exists())


def test_stage_success_writes_state() -> None:
    mgr = UpdateManager(state_dir=Path(tempfile.mkdtemp()))
    plan = _good_plan(mgr)
    payload = b"a-valid-wheel-payload"
    mgr._fetch = _fetch_with_digests(payload)

    res = mgr.stage(plan, pip_download=spec_aware_download(payload))
    check("stage-ok: staged flag", res.staged)
    check("stage-ok: plan.json written", mgr.plan_path.exists())
    st = json.loads(mgr.status_path.read_text())
    check("stage-ok: status phase 'staged'", st.get("phase") == "staged")
    plan_saved = json.loads(mgr.plan_path.read_text())
    check("stage-ok: plan pins the target",
          "PyQt6==6.11.0" in plan_saved.get("install_specs", []))
    check("stage-ok: rollback snapshot exists",
          (mgr.state_dir / "rollback.json").exists())
    snap = json.loads((mgr.state_dir / "rollback.json").read_text())
    check("stage-ok: snapshot records current PyQt6",
          snap["packages"].get("PyQt6") == "6.10.1")
    check("stage-ok: staged wheels present",
          any(w.endswith(".whl") for w in res.wheels))


def test_stage_user_cancellation() -> None:
    mgr = UpdateManager(state_dir=Path(tempfile.mkdtemp()))
    plan = _good_plan(mgr)
    mgr._fetch = _fetch_with_digests(b"p")
    try:
        mgr.stage(plan, pip_download=spec_aware_download(b"p"),
                  cancelled=lambda: True)
        check("cancel: raised StageError", False)
    except StageError as exc:
        check("cancel: raised StageError", True)
        check("cancel: says cancelled", "cancel" in str(exc).lower())
    check("cancel: no plan.json", not mgr.plan_path.exists())
    check("cancel: no rollback snapshot",
          not (mgr.state_dir / "rollback.json").exists())


# -- apply / rollback / resume -------------------------------------

def _staged_state(tmp: Path, *, minor="6.11") -> dict:
    """Hand-build a staged state dir: rollback.json + plan.json + wheels/."""
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "wheels").mkdir(exist_ok=True)
    (tmp / "wheels" / "PyQt6-6.11.0-py3-none-any.whl").write_bytes(b"x")
    (tmp / "rollback_wheels").mkdir(exist_ok=True)
    (tmp / "rollback_wheels" / "PyQt6-6.10.1-py3-none-any.whl").write_bytes(
        b"x")
    snap = {
        "schema": 1, "python_exe": sys.executable, "python": "3.10.11",
        "packages": {"PyQt6": "6.10.1", "PyQt6-WebEngine": "6.10.0",
                     "PyQt6-Qt6": "6.10.1", "PyQt6-WebEngine-Qt6": "6.10.1",
                     "PyQt6-sip": "13.10.0"},
        "wheels_dir": str(tmp / "rollback_wheels"),
        "verified_wheels": ["PyQt6-6.10.1-py3-none-any.whl"],
    }
    (tmp / "rollback.json").write_text(json.dumps(snap))
    plan = {"schema": 1, "target": {"minor": minor},
            "install_specs": ["PyQt6==6.11.0", "PyQt6-WebEngine==6.11.0"]}
    (tmp / "plan.json").write_text(json.dumps(plan))
    (tmp / "status.json").write_text(json.dumps({"schema": 1,
                                                 "phase": "staged"}))
    return snap


def test_apply_success() -> None:
    tmp = Path(tempfile.mkdtemp())
    _staged_state(tmp)
    calls: list[list[str]] = []

    def pip_runner(cmd):
        calls.append(cmd)
        return 0, "Successfully installed PyQt6-6.11.0"

    orig = apply_mod.verify_installation
    apply_mod.verify_installation = lambda *a, **k: {
        "ok": True, "webengine": "6.11.2", "chromium": "141.0.0.0",
        "pyqt6_wheel": "6.11.0", "webengine_wheel": "6.11.0"}
    try:
        rc = apply_mod.run([str(tmp), "--parent-pid", "0"],
                           pip_runner=pip_runner, wait=False)
    finally:
        apply_mod.verify_installation = orig
    check("apply-ok: exit 0", rc == 0)
    res = json.loads((tmp / "result.json").read_text())
    check("apply-ok: result status done", res["status"] == "done")
    check("apply-ok: pip install actually called",
          any("install" in c for c in calls))
    st = json.loads((tmp / "status.json").read_text())
    check("apply-ok: status phase done", st["phase"] == "done")


def test_apply_install_failure_rolls_back() -> None:
    tmp = Path(tempfile.mkdtemp())
    _staged_state(tmp)
    seen: list[list[str]] = []

    def pip_runner(cmd):
        seen.append(cmd)
        if "--force-reinstall" in cmd:      # the rollback install
            return 0, "Successfully installed PyQt6-6.10.1"
        return 1, "ERROR: could not install PyQt6"

    orig = apply_mod.verify_installation
    # First call (post-install verify) never happens because install fails;
    # the rollback's verify must pass.
    apply_mod.verify_installation = lambda *a, **k: {"ok": True}
    try:
        rc = apply_mod.run([str(tmp), "--parent-pid", "0"],
                           pip_runner=pip_runner, wait=False)
    finally:
        apply_mod.verify_installation = orig
    res = json.loads((tmp / "result.json").read_text())
    check("apply-fail: nonzero exit", rc != 0)
    check("apply-fail: rolled_back status", res["status"] == "rolled_back")
    check("apply-fail: rollback used --force-reinstall --no-index",
          any("--force-reinstall" in c and "--no-index" in c for c in seen))
    check("apply-fail: message reassures nothing lost",
          "restored" in res["message"].lower())


def test_apply_verify_failure_rolls_back() -> None:
    tmp = Path(tempfile.mkdtemp())
    _staged_state(tmp)

    def pip_runner(cmd):
        return 0, "ok"

    orig = apply_mod.verify_installation
    state = {"n": 0}

    def flaky_verify(*a, **k):
        state["n"] += 1
        if state["n"] == 1:
            raise versions.InstallationBroken("QtWebEngineCore import failed")
        return {"ok": True}          # rollback verify succeeds

    apply_mod.verify_installation = flaky_verify
    try:
        rc = apply_mod.run([str(tmp), "--parent-pid", "0"],
                           pip_runner=pip_runner, wait=False)
    finally:
        apply_mod.verify_installation = orig
    res = json.loads((tmp / "result.json").read_text())
    check("apply-verifyfail: rolled back", res["status"] == "rolled_back")
    check("apply-verifyfail: nonzero exit", rc != 0)


def test_apply_resume_repairs() -> None:
    tmp = Path(tempfile.mkdtemp())
    _staged_state(tmp)
    (tmp / "status.json").write_text(json.dumps({"schema": 1,
                                                 "phase": "installing"}))
    seen: list[list[str]] = []

    def pip_runner(cmd):
        seen.append(cmd)
        return 0, "Successfully installed PyQt6-6.10.1"

    orig = apply_mod.verify_installation
    apply_mod.verify_installation = lambda *a, **k: {
        "ok": True, "pyqt6_wheel": "6.10.1", "webengine_wheel": "6.10.0"}
    try:
        rc = apply_mod.run([str(tmp), "--resume", "--parent-pid", "0"],
                           pip_runner=pip_runner, wait=False)
    finally:
        apply_mod.verify_installation = orig
    res = json.loads((tmp / "result.json").read_text())
    check("resume: rolled_back", res["status"] == "rolled_back")
    check("resume: no forward install attempted",
          all("6.11.0" not in " ".join(c) for c in seen))
    check("resume: exit 0", rc == 0)


def test_manager_pending_and_take_result() -> None:
    tmp = Path(tempfile.mkdtemp())
    mgr = UpdateManager(state_dir=tmp)
    check("pending: none initially", mgr.pending() is None)
    _staged_state(tmp)
    p = mgr.pending()
    check("pending: sees staged", p and p["phase"] == "staged")
    check("pending: staged is not 'interrupted'", p["interrupted"] is False)
    (tmp / "status.json").write_text(json.dumps({"schema": 1,
                                                 "phase": "verifying"}))
    check("pending: verifying is 'interrupted'",
          mgr.pending()["interrupted"] is True)
    (tmp / "result.json").write_text(json.dumps(
        {"schema": 1, "status": "done", "message": "ok", "old": {}, "new": {}}))
    out = mgr.take_result()
    check("take_result: reads done", out and out.status == "done")
    check("take_result: consumes the file",
          not (tmp / "result.json").exists())
    mgr.discard()
    check("discard: clears plan.json", not mgr.plan_path.exists())
    check("discard: clears status.json", not mgr.status_path.exists())


def test_rollback_command_shape() -> None:
    snap = {
        "python_exe": "py", "wheels_dir": "/w",
        "packages": {"PyQt6": "6.10.1", "PyQt6-WebEngine": "6.10.0"},
    }
    seen: list[list[str]] = []
    backup_mod.restore(snap, pip_install=lambda c: (seen.append(c) or (0, "")),
                       verify=False)
    cmd = seen[0]
    for token in ("install", "--force-reinstall", "--no-deps", "--no-index",
                  "--find-links", "PyQt6==6.10.1",
                  "PyQt6-WebEngine==6.10.0"):
        check(f"rollback cmd has {token!r}", token in cmd)


def test_vodou_still_imports_after() -> None:
    """verify_installation() is the same gate apply.py uses to decide an
    update is good -- it must pass against the real, current environment
    (stands in for 'Vodou still starts')."""
    try:
        info = versions.verify_installation()
        check("verify: stack imports", info.get("ok") is not False)
        check("verify: reports a Qt WebEngine version",
              bool(info.get("webengine")))
        check("verify: reports a Chromium version",
              bool(info.get("chromium")))
    except versions.InstallationBroken as exc:
        check(f"verify: stack imports ({exc})", False)


ALL = [
    test_get_current_versions, test_diagnostics_report,
    test_python_satisfies_table, test_compatible_update_available,
    test_no_update_when_current_is_latest, test_runtime_patch_only,
    test_python_incompatibility_blocks_newer_only,
    test_no_release_supports_this_python, test_lockstep_no_version_mixing,
    test_prerelease_gate, test_frozen_build_refused,
    test_readonly_site_packages_refused,
    test_stage_download_failure_leaves_nothing,
    test_stage_hash_mismatch_aborts, test_stage_success_writes_state,
    test_stage_user_cancellation,
    test_apply_success, test_apply_install_failure_rolls_back,
    test_apply_verify_failure_rolls_back, test_apply_resume_repairs,
    test_manager_pending_and_take_result, test_rollback_command_shape,
    test_vodou_still_imports_after,
]


def main() -> int:
    for fn in ALL:
        print(f"\n{fn.__name__}")
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            _failures.append(f"{fn.__name__} raised {exc!r}")
    print()
    if _failures:
        print(f"{len(_failures)} FAILURE(S):")
        for f in _failures:
            print("  - " + f)
        return 1
    print(f"ALL {len(ALL)} UPDATER TEST GROUPS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
