"""Stage 2 -- the only "what's out there?" source: PyPI's JSON API.

Official, stable, versioned, and it carries everything the resolver needs:
every release, each file's ``requires_python``, ``yanked`` status and SHA-256
digest. No web scraping, no hard-coded version numbers -- when Riverbank
publishes PyQt6 6.13 this module sees it the same day.

Pre-release handling (PEP 440): ``a`` / ``b`` / ``rc`` / ``.dev`` / ``.post`` of
a dev build are all recognised and excluded unless the caller passes
``allow_prerelease=True`` (the "developer / experimental" opt-in).

This module has no third-party dependencies -- it re-implements the small slice
of PEP 440 the resolver actually needs, because ``packaging`` is not guaranteed
importable in the target environment.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field

_PYPI_JSON = "https://pypi.org/pypi/{name}/json"
_UA = "Vodou-Updater (+https://github.com/MSteier/Vodou-Web-Browser)"

# PEP 440 release segment + optional pre/post/dev suffixes. Enough to order and
# to classify "is this a stable release".
_VERSION_RE = re.compile(
    r"^\s*v?"
    r"(?P<release>[0-9]+(?:\.[0-9]+)*)"
    r"(?P<pre>[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?"
    r"(?P<post>[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?"
    r"(?P<dev>[-_.]?dev[-_.]?[0-9]*)?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?\s*$",
    re.IGNORECASE,
)


class PyPIError(RuntimeError):
    """A PyPI lookup failed (network, HTTP, or unparseable JSON)."""


@dataclass
class Release:
    version: str
    key: tuple                       # sort key from parse_version()
    is_prerelease: bool
    requires_python: str             # "" when the release declares none
    files: list[dict] = field(default_factory=list)  # raw PyPI file dicts

    def wheel_files(self) -> list[dict]:
        return [f for f in self.files
                if f.get("packagetype") == "bdist_wheel"
                and not f.get("yanked")]

    def sha256_for(self, filename: str) -> str | None:
        for f in self.files:
            if f.get("filename") == filename:
                return (f.get("digests") or {}).get("sha256")
        return None


_PRE_INF = (999, 0)     # "no pre-release" -> sorts after every a/b/rc
_PRE_NEG_INF = (-1, 0)  # a bare .devN of a final release -> sorts before them
_DEV_INF = 10 ** 9      # "no dev segment" -> sorts after any .devN


def parse_version(version: str) -> tuple:
    """A total order over the versions PyPI actually ships for these packages.

    Follows PEP 440's own ordering for the slice that matters here
    (``X.Y.Z`` plus ``aN`` / ``bN`` / ``rcN`` / ``.devN`` / ``.postN``):

        1.0.dev1 < 1.0a1 < 1.0b1 < 1.0rc1 < 1.0 < 1.0.post1

    Mirrors ``packaging.version._cmpkey``: a bare ``.devN`` with no
    pre-release sorts *below* the pre-releases, a version with no pre-release
    sorts *above* them.
    """
    m = _VERSION_RE.match(version or "")
    if not m:
        # Unknown shape: sort it below everything so it is never "latest".
        return ((-1,), _PRE_NEG_INF, -1, -1)
    release = tuple(int(p) for p in m.group("release").split("."))

    def _num(seg: str | None) -> int | None:
        if not seg:
            return None
        digits = "".join(ch for ch in seg if ch.isdigit())
        return int(digits) if digits else 0

    pre_seg, post_seg, dev_seg = (m.group("pre"), m.group("post"),
                                  m.group("dev"))
    pre_n, post_n, dev_n = _num(pre_seg), _num(post_seg), _num(dev_seg)

    if pre_seg:
        rank = {"a": 0, "alpha": 0, "b": 1, "beta": 1,
                "c": 2, "rc": 2, "pre": 2, "preview": 2}
        word = re.sub(r"[^a-z]", "", pre_seg.lower())
        pre_key = (rank.get(word, 2), pre_n or 0)
    elif post_seg is None and dev_seg is not None:
        pre_key = _PRE_NEG_INF
    else:
        pre_key = _PRE_INF

    post_key = -1 if post_seg is None else (post_n or 0)
    dev_key = _DEV_INF if dev_seg is None else (dev_n or 0)
    return (release, pre_key, post_key, dev_key)


def is_prerelease(version: str) -> bool:
    m = _VERSION_RE.match(version or "")
    if not m:
        return False
    return bool(m.group("pre") or m.group("dev"))


# -- requires_python evaluation ------------------------------------------------

_SPEC_RE = re.compile(r"^\s*(===|~=|==|!=|>=|<=|>|<)\s*(.+?)\s*$")


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple, tuple]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def _clause_ok(op: str, spec: str, py: tuple[int, int, int]) -> bool:
    star = spec.endswith(".*")
    base = spec[:-2] if star else spec
    try:
        want = tuple(int(p) for p in base.split(".") if p != "")
    except ValueError:
        raise ValueError(f"unparseable version in requires_python: {spec!r}")

    if op in ("==", "===") and star:
        pref = py[:len(want)]
        return _pad(pref, want)[0] == _pad(pref, want)[1]
    if op == "!=" and star:
        pref = py[:len(want)]
        return _pad(pref, want)[0] != _pad(pref, want)[1]

    pa, pb = _pad(py, want)
    if op in ("==", "==="):
        return pa == pb
    if op == "!=":
        return pa != pb
    if op == ">=":
        return pa >= pb
    if op == "<=":
        return pa <= pb
    if op == ">":
        return pa > pb
    if op == "<":
        return pa < pb
    if op == "~=":
        # ~=X.Y  -> >=X.Y,  <X+1 ;  ~=X.Y.Z -> >=X.Y.Z, <X.(Y+1)
        if len(want) < 2:
            raise ValueError(f"~= needs at least two segments: {spec!r}")
        lower_ok = _pad(py, want)[0] >= _pad(py, want)[1]
        upper = want[:-1]
        upper = upper[:-1] + (upper[-1] + 1,)
        pu, wu = _pad(py, upper)
        return lower_ok and pu < wu
    raise ValueError(f"unsupported requires_python operator: {op!r}")


def python_satisfies(requires_python: str,
                     py: tuple[int, int, int]) -> bool:
    """Does interpreter *py* satisfy a ``requires_python`` specifier set?

    An empty / missing specifier means "any Python" -> True. A specifier this
    minimal parser cannot understand raises :class:`ValueError`; the resolver
    treats that as "cannot vouch for it" and refuses the update rather than
    guessing (safety rule 7).
    """
    spec = (requires_python or "").strip()
    if not spec:
        return True
    for raw in spec.split(","):
        raw = raw.strip()
        if not raw:
            continue
        m = _SPEC_RE.match(raw)
        if not m:
            raise ValueError(f"unparseable requires_python clause: {raw!r}")
        if not _clause_ok(m.group(1), m.group(2), py):
            return False
    return True


# -- the fetch ---------------------------------------------------------------

def fetch_project(name: str, *, timeout: int = 20) -> dict:
    """Raw PyPI JSON for *name*. HTTPS only, no cookies, no identifiers."""
    url = _PYPI_JSON.format(name=name)
    req = urllib.request.Request(url, headers={"User-Agent": _UA,
                                               "Accept": "application/json"})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status != 200:
                raise PyPIError(f"{url} -> HTTP {resp.status}")
            payload = resp.read()
    except urllib.error.URLError as exc:
        raise PyPIError(f"could not reach PyPI for {name}: {exc}") from exc
    try:
        return json.loads(payload)
    except ValueError as exc:
        raise PyPIError(f"PyPI returned invalid JSON for {name}") from exc


def releases(project_json: dict, *, allow_prerelease: bool = False,
             py: tuple[int, int, int] | None = None) -> list[Release]:
    """All releases of a project as sorted :class:`Release` objects, newest
    last. Filters out: fully-yanked releases, releases with no usable wheel,
    pre-releases (unless *allow_prerelease*), and -- when *py* is given --
    releases whose ``requires_python`` this interpreter fails.
    """
    out: list[Release] = []
    for version, files in (project_json.get("releases") or {}).items():
        if not files:
            continue
        if all(f.get("yanked") for f in files):
            continue
        pre = is_prerelease(version)
        if pre and not allow_prerelease:
            continue
        rp = ""
        for f in files:
            if f.get("requires_python"):
                rp = f["requires_python"]
                break
        rel = Release(version=version, key=parse_version(version),
                      is_prerelease=pre, requires_python=rp, files=files)
        if not rel.wheel_files():
            continue
        if py is not None:
            try:
                if not python_satisfies(rp, py):
                    continue
            except ValueError:
                # Unparseable spec: exclude it -- never silently ship an
                # update we cannot vouch for.
                continue
        out.append(rel)
    out.sort(key=lambda r: r.key)
    return out


def latest_release(project_json: dict, *, allow_prerelease: bool = False,
                   py: tuple[int, int, int] | None = None) -> Release | None:
    rels = releases(project_json, allow_prerelease=allow_prerelease, py=py)
    return rels[-1] if rels else None
