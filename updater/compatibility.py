"""Stage 3 -- resolve a PyQt6 / PyQt6-WebEngine pair that is safe to install.

The rule, from observing how Riverbank ships these packages:

  * ``PyQt6`` (the widget binding) and ``PyQt6-WebEngine`` (the WebEngine
    binding) are released in lockstep and are only supported together when
    they share an ``X.Y`` **minor**. The ``.Z`` patch may differ (this machine
    runs the 6.11.0 bindings against the 6.11.1 ``*-Qt6`` runtime).
  * Each binding pulls its own matching ``*-Qt6`` runtime wheel (Qt +
    Chromium) automatically as a dependency -- so we never name a Qt DLL, we
    just let pip move the set.
  * A release's ``requires_python`` is the Python constraint. Vodou never
    upgrades Python, so a newer release that needs a newer Python is reported
    (``blocked_by_python``) and *not* selected.

The resolver therefore:
  1. asks PyPI for the stable, this-Python-compatible releases of both bindings
  2. finds the highest ``X.Y`` minor published by BOTH
  3. picks the highest patch each publishes within that minor
  4. if the current install is already on (or above) that minor -> up to date
  5. if no shared compatible minor exists -> compatible=False, with a reason

Nothing is downloaded or installed here -- this stage only decides.
"""

from __future__ import annotations

from collections import OrderedDict

from . import pypi
from .models import (
    CompatibilityResult,
    CurrentVersions,
    ResolvedTarget,
    minor_of,
)

# The distributions that make up the coordinated group. The two bindings are
# what we put on the pip line; the runtime + sip wheels come in as their deps
# and are listed here so the rollback snapshot pins the whole set.
BINDING_PACKAGES = ("PyQt6", "PyQt6-WebEngine")
RUNTIME_PACKAGES = ("PyQt6-Qt6", "PyQt6-WebEngine-Qt6", "PyQt6-sip")
GROUP_PACKAGES = BINDING_PACKAGES + RUNTIME_PACKAGES


def _by_minor(rels) -> "OrderedDict[str, list]":
    """Group releases by 'X.Y', each list newest-last."""
    out: "OrderedDict[str, list]" = OrderedDict()
    for r in rels:
        out.setdefault(minor_of(r.version), []).append(r)
    return out


def is_compatible_pair(pyqt6: str, webengine: str,
                       py: tuple[int, int, int],
                       requires_python: str = "") -> bool:
    """Pure predicate used by tests and callers: same minor, and this Python
    satisfies the (shared) requires_python."""
    if minor_of(pyqt6) != minor_of(webengine):
        return False
    try:
        return pypi.python_satisfies(requires_python, py)
    except ValueError:
        return False


def resolve_compatible_versions(
    current: CurrentVersions,
    *,
    allow_prerelease: bool = False,
    fetch=pypi.fetch_project,
) -> CompatibilityResult:
    py = current.python_tuple

    try:
        pyqt6_json = fetch("PyQt6")
        webengine_json = fetch("PyQt6-WebEngine")
    except pypi.PyPIError as exc:
        return CompatibilityResult(
            compatible=False,
            reason=f"Could not check PyPI for updates: {exc}. "
                   "No changes have been made.")

    # Newest stable of each *ignoring* the Python gate -- only for the
    # "a newer version exists but needs newer Python" message.
    newest_pyqt6_any = pypi.latest_release(
        pyqt6_json, allow_prerelease=allow_prerelease)
    newest_web_any = pypi.latest_release(
        webengine_json, allow_prerelease=allow_prerelease)

    pyqt6_ok = pypi.releases(
        pyqt6_json, allow_prerelease=allow_prerelease, py=py)
    web_ok = pypi.releases(
        webengine_json, allow_prerelease=allow_prerelease, py=py)
    if not pyqt6_ok or not web_ok:
        return _no_python_compatible_result(
            current, newest_pyqt6_any, newest_web_any)

    pyqt6_minors = _by_minor(pyqt6_ok)
    web_minors = _by_minor(web_ok)
    shared = [m for m in pyqt6_minors if m in web_minors and m]
    if not shared:
        return CompatibilityResult(
            compatible=False,
            reason="PyPI has no PyQt6 and PyQt6-WebEngine release that share "
                   "a version series and support Python "
                   f"{current.python}. No changes have been made.",
            newest_seen_pyqt6=getattr(newest_pyqt6_any, "version", None),
            newest_seen_webengine=getattr(newest_web_any, "version", None))

    # Highest shared minor wins; highest patch within it for each package.
    best_minor = max(shared, key=lambda m: pypi.parse_version(m + ".0"))
    target_pyqt6 = pyqt6_minors[best_minor][-1].version
    target_web = web_minors[best_minor][-1].version

    # The matching runtime wheels, for display + the rollback set. Best effort:
    # if PyPI can't be asked we just leave them None and pip still resolves
    # them at install time.
    exp_qt6 = _latest_in_minor(fetch, "PyQt6-Qt6", best_minor,
                               allow_prerelease, py)
    exp_web_qt6 = _latest_in_minor(fetch, "PyQt6-WebEngine-Qt6", best_minor,
                                   allow_prerelease, py)

    req_py = ""
    for r in web_minors[best_minor]:
        if r.version == target_web:
            req_py = r.requires_python
            break

    target = ResolvedTarget(
        minor=best_minor,
        pyqt6=target_pyqt6,
        pyqt6_webengine=target_web,
        expected_qt6=exp_qt6,
        expected_webengine_qt6=exp_web_qt6,
        requires_python=req_py,
    )

    # "Up to date" means every part of the coordinated group is already at or
    # above what we would install: the two bindings AND the two runtime wheels
    # (a newer same-minor PyQt6-WebEngine-Qt6 is a Qt WebEngine security patch
    # -- pip pulls it in with the bindings, so it counts).
    up_to_date = (
        _at_least(current.pyqt6_wheel, target.pyqt6)
        and _at_least(current.pyqt6_webengine_wheel, target.pyqt6_webengine)
        and _at_least(current.pyqt6_qt6, target.expected_qt6)
        and _at_least(current.pyqt6_webengine_qt6,
                      target.expected_webengine_qt6))

    blocked = _python_block(current, best_minor,
                            newest_pyqt6_any, newest_web_any)

    if up_to_date:
        reason = (f"Vodou is already on the latest compatible Qt series "
                  f"({best_minor}.x) for Python {current.python}.")
        if blocked:
            reason += (f" A newer series ({blocked[0]}) exists but needs "
                       f"Python {blocked[1]}; Vodou will not upgrade Python.")
        return CompatibilityResult(
            compatible=True, up_to_date=True, target=target, reason=reason,
            blocked_by_python=blocked,
            newest_seen_pyqt6=getattr(newest_pyqt6_any, "version", None),
            newest_seen_webengine=getattr(newest_web_any, "version", None))

    bindings_move = not (
        _at_least(current.pyqt6_wheel, target_pyqt6)
        and _at_least(current.pyqt6_webengine_wheel, target_web))
    if bindings_move:
        reason = (f"PyQt6 {target_pyqt6} and PyQt6-WebEngine {target_web} are "
                  f"a compatible set for Python {current.python} "
                  f"(Qt WebEngine {best_minor}.x, Chromium bundled with it). "
                  "The binding and runtime packages move together as one set.")
    else:
        reason = (
            f"A Qt WebEngine patch is available within the {best_minor} "
            f"series: the PyQt6-Qt6 / PyQt6-WebEngine-Qt6 runtime goes to "
            f"{exp_web_qt6 or best_minor + '.x'} while the PyQt6 "
            f"{target_pyqt6} bindings stay put -- a same-series patch, not a "
            "version mix. Chromium updates with it.")
    if blocked:
        reason += (f" Note: a newer series ({blocked[0]}) is out but requires "
                   f"Python {blocked[1]} -- Vodou will not upgrade Python, so "
                   f"{best_minor}.x is the newest it will install.")
    return CompatibilityResult(
        compatible=True, up_to_date=False, target=target, reason=reason,
        blocked_by_python=blocked,
        newest_seen_pyqt6=getattr(newest_pyqt6_any, "version", None),
        newest_seen_webengine=getattr(newest_web_any, "version", None))


def _latest_in_minor(fetch, name, minor, allow_prerelease, py):
    try:
        j = fetch(name)
    except pypi.PyPIError:
        return None
    best = None
    for r in pypi.releases(j, allow_prerelease=allow_prerelease, py=py):
        if minor_of(r.version) == minor:
            best = r.version
    return best


def _minor_ge(a: str, b: str) -> bool:
    if not a:
        return False
    return pypi.parse_version(a + ".0") >= pypi.parse_version(b + ".0")


def _at_least(installed: str | None, target: str | None) -> bool:
    """Is *installed* a real version at or above *target*? An unknown target
    (PyPI could not be asked for that runtime wheel) is treated as satisfied
    so it never fabricates an update; an unknown/unparseable installed value
    is treated as behind."""
    if not target or target in ("", "unknown"):
        return True
    if not installed or installed in ("", "unknown"):
        return False
    return pypi.parse_version(installed) >= pypi.parse_version(target)


def _python_block(current, best_minor, newest_pyqt6_any, newest_web_any):
    """If the newest stable series (ignoring the Python gate) is above the one
    we resolved, and it is above because of Python, report (version, spec)."""
    for rel in (newest_web_any, newest_pyqt6_any):
        if rel is None:
            continue
        if minor_of(rel.version) == best_minor:
            continue
        if not _minor_ge(minor_of(rel.version), best_minor):
            continue
        try:
            fits = pypi.python_satisfies(rel.requires_python,
                                         current.python_tuple)
        except ValueError:
            fits = False
        if not fits and rel.requires_python:
            return (minor_of(rel.version), rel.requires_python)
    return None


def _no_python_compatible_result(current, newest_pyqt6_any, newest_web_any):
    spec = ""
    for rel in (newest_web_any, newest_pyqt6_any):
        if rel is not None and rel.requires_python:
            spec = rel.requires_python
            break
    reason = ("No PyQt6-WebEngine release on PyPI supports Python "
              f"{current.python}.")
    if spec:
        reason += f" The current releases require Python {spec}."
    reason += (" Vodou will not upgrade Python, so no changes have been "
               "made.")
    blocked = None
    if newest_web_any is not None and spec:
        blocked = (minor_of(newest_web_any.version), spec)
    return CompatibilityResult(
        compatible=False, reason=reason, blocked_by_python=blocked,
        newest_seen_pyqt6=getattr(newest_pyqt6_any, "version", None),
        newest_seen_webengine=getattr(newest_web_any, "version", None))
