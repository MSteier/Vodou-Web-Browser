"""Per-site cookie persistence ("cookie exceptions").

Vodou's profile never persists cookies — they live in RAM and die with the
process. That's the right default, but it also forgets logins and site
preferences the user *wants* kept (the reason this exists). QtWebEngine's
persistence policy is profile-wide, so selective persistence is built here
instead: a keeper watches the live cookie store, mirrors the cookies whose
domain the user has allowlisted, and writes just those to disk — everything
else stays memory-only.

At rest the jar is sealed with the OS keystore (see dpapi.py) — DPAPI on
Windows, the desktop keyring elsewhere: no password prompt, and another local
account (or a lifted disk) can't read it. Honest limit: like Chrome's jar,
anything running *as this user* could decrypt it.

Where no keystore is available, cookie keeping switches itself off rather
than writing the jar in the clear. Persisted cookies are live session
credentials for the sites the user chose to stay signed in to; a plaintext
jar would be a worse outcome than forgetting them, so the allowlist stays
(it is a setting, not data) and nothing is written.

Only non-session cookies are kept (session cookies are meant to die with
the browser), and expired ones are dropped on restore.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from PyQt6.QtCore import QObject, QTimer
from PyQt6.QtNetwork import QNetworkCookie

from dpapi import Unavailable, seal as _seal, unseal as _unseal
from dpapi import unavailable_reason as _keystore_problem

COOKIE_SITES_FILE = Path.home() / ".vodou" / "cookie_sites.json"
COOKIE_JAR_FILE = Path.home() / ".vodou" / "cookies.dat"


def load_sites() -> list[str]:
    try:
        raw = json.loads(COOKIE_SITES_FILE.read_text(encoding="utf-8"))
        return sorted({s for s in raw if isinstance(s, str) and s})[:200]
    except (OSError, ValueError, TypeError):
        return []


def save_sites(sites: list[str]) -> None:
    COOKIE_SITES_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = COOKIE_SITES_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(sorted(set(sites))), encoding="utf-8")
    tmp.replace(COOKIE_SITES_FILE)


class CookieKeeper(QObject):
    """Mirrors allowlisted-domain cookies from the live store to disk.

    The live QWebEngineCookieStore stays the single source of truth; this
    only listens (cookieAdded/cookieRemoved), keeps the allowed subset, and
    persists it debounced — so heavy cookie churn on ordinary sites costs
    nothing, and a crash loses at most a few seconds of cookie updates.
    """

    def __init__(self, store, parent: QObject | None = None):
        super().__init__(parent)
        self._store = store
        self.sites: list[str] = load_sites()
        # (domain, path, name) -> raw Set-Cookie form of the cookie
        self._kept: dict[tuple[str, str, bytes], bytes] = {}
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(3000)
        self._timer.timeout.connect(self.flush)
        store.cookieAdded.connect(self._on_added)
        store.cookieRemoved.connect(self._on_removed)

    # -- allowlist ------------------------------------------------------

    def allows(self, domain: str) -> bool:
        d = domain.lstrip(".").lower()
        for site in self.sites:
            if d == site or d.endswith("." + site):
                return True
        return False

    def set_sites(self, sites: list[str]) -> None:
        self.sites = sorted(set(sites))
        save_sites(self.sites)
        # Drop kept cookies that are no longer covered; newly covered
        # cookies are picked up as the live store next touches them.
        self._kept = {key: raw for key, raw in self._kept.items()
                      if self.allows(key[0])}
        self._schedule()

    # -- live-store mirroring ---------------------------------------------

    @staticmethod
    def _key(cookie: QNetworkCookie) -> tuple[str, str, bytes]:
        return (cookie.domain(), cookie.path(), bytes(cookie.name()))

    def _on_added(self, cookie: QNetworkCookie) -> None:
        # Session cookies are meant to die with the browser; keeping them
        # would silently extend logins the site asked to be temporary.
        if cookie.isSessionCookie() or not self.allows(cookie.domain()):
            return
        self._kept[self._key(cookie)] = bytes(cookie.toRawForm())
        self._schedule()

    def _on_removed(self, cookie: QNetworkCookie) -> None:
        if self._kept.pop(self._key(cookie), None) is not None:
            self._schedule()

    def _schedule(self) -> None:
        if not self._timer.isActive():
            self._timer.start()

    # -- disk ----------------------------------------------------------

    def flush(self) -> None:
        """Write the kept cookies now (debounce target; also exit path)."""
        try:
            if not self._kept:
                COOKIE_JAR_FILE.unlink(missing_ok=True)
                return
            try:
                blob = _seal(b"\n".join(self._kept.values()))
            except Unavailable:
                # No keystore: keep nothing rather than keep it in the clear.
                # The jar is removed too — a stale one holds cookies the user
                # believes are being maintained, and they only get staler.
                COOKIE_JAR_FILE.unlink(missing_ok=True)
                return
            COOKIE_JAR_FILE.parent.mkdir(parents=True, exist_ok=True)
            tmp = COOKIE_JAR_FILE.with_suffix(".tmp")
            tmp.write_bytes(blob)
            tmp.replace(COOKIE_JAR_FILE)
        except OSError:
            pass  # cookie persistence must never disturb browsing

    @staticmethod
    def keystore_problem() -> str:
        """Why cookie keeping can't work here, or "" when it can.

        The UI asks so the allowlist dialog can say so plainly — silently
        accepting sites into a list that will never persist anything is the
        one behaviour worse than not offering the feature.
        """
        return _keystore_problem()

    def restore(self) -> int:
        """Load the jar into the live store. Returns cookies restored."""
        try:
            raw = _unseal(COOKIE_JAR_FILE.read_bytes())
        except OSError:
            return 0
        now = datetime.now(timezone.utc)
        count = 0
        for line in raw.split(b"\n"):
            for cookie in QNetworkCookie.parseCookies(line):
                expiry = cookie.expirationDate()
                if (cookie.isSessionCookie()
                        or not self.allows(cookie.domain())
                        or (expiry.isValid()
                            and expiry.toPyDateTime().astimezone(timezone.utc)
                            < now)):
                    continue
                self._store.setCookie(cookie)
                count += 1
        return count

    def clear(self) -> None:
        """Forget every kept cookie and delete the jar (the allowlist
        itself is kept — clearing data shouldn't erase settings)."""
        self._kept.clear()
        self._timer.stop()
        try:
            COOKIE_JAR_FILE.unlink(missing_ok=True)
        except OSError:
            pass
