"""Local, privacy-preserving Safe Browsing: block reported phishing/malware.

The naive way to do "safe browsing" is to send every URL you visit to a
server for a verdict — which is a browsing log by another name, exactly what
Vodou refuses to keep. This does the opposite: it downloads public lists of
known-bad *domains* on a schedule and checks each navigation **entirely on the
machine**. Nothing about where you go ever leaves your device — not the URL,
not a hash, not a prefix. The only network activity is an anonymous, periodic
GET of the public lists, the same kind of request as the version check.

Honest limits (stated plainly so the protection isn't oversold):
  * Domain-level, not URL-level: a bad path on an otherwise-fine host is not
    caught, only wholly-bad hosts.
  * Periodically refreshed, so a brand-new phishing domain (they live hours)
    can slip the window until the next update. It layers with the built-in
    homograph/typosquat detection, which needs no list.

Configurable, offline-friendly, and fail-safe:
  * Sources default to well-known no-API-key feeds; override them by listing
    URLs (one per line) in ~/.vodou/safebrowsing_sources.txt.
  * Add your own hosts in ~/.vodou/safebrowsing_extra.txt.
  * The merged list is cached at ~/.vodou/safebrowsing.dat so protection is
    live at startup before the first refresh; a failed refresh keeps the
    cache rather than dropping protection.
  * Toggle the whole feature in ~/.vodou/safebrowsing.json (or the menu).
"""

from __future__ import annotations

import json
from datetime import datetime
from itertools import islice
from pathlib import Path

from PyQt6.QtCore import QObject, QTimer, QUrl, pyqtSignal
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest

from spoofcheck import SpoofVerdict

VODOU_DIR = Path.home() / ".vodou"
CACHE_FILE = VODOU_DIR / "safebrowsing.dat"
SOURCES_FILE = VODOU_DIR / "safebrowsing_sources.txt"
EXTRA_FILE = VODOU_DIR / "safebrowsing_extra.txt"
CONFIG_FILE = VODOU_DIR / "safebrowsing.json"

# No-API-key, public feeds of reported malware/phishing hosts. URLhaus is
# abuse.ch's malware host list; the Phishing.Database "ACTIVE" list is a
# widely-used aggregate of live phishing domains. Override in SOURCES_FILE.
DEFAULT_SOURCES = (
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://raw.githubusercontent.com/mitchellkrogza/"
    "Phishing.Database/master/phishing-domains-ACTIVE.txt",
)

REFRESH_INTERVAL_MS = 12 * 60 * 60 * 1000   # re-fetch every 12 hours
# Bounds memory / file size. Truncation in _commit is arbitrary — it keeps
# whatever the set happens to iterate first, not the newest or worst hosts —
# so a cap the feeds actually reach silently drops real coverage. 300k was
# below the combined size of the default feeds and was being hit exactly;
# 500k clears them with room to grow. Roughly 29 bytes/host on disk, several
# times that resident, so this is ~14 MB cached and ~55 MB in memory.
MAX_HOSTS = 500_000
_VERDICT_CACHE_MAX = 8192

# Never treat these as blockable even if a list is malformed.
_NEVER = frozenset({"localhost", "localhost.localdomain"})


def _valid_host(host: str) -> bool:
    if not host or "." not in host or host in _NEVER:
        return False
    if any(c.isspace() for c in host):
        return False
    # Plain IPv4 entries in a host list are almost always noise (0.0.0.0 etc.).
    if all(part.isdigit() for part in host.split(".")):
        return False
    return all(c.isalnum() or c in ".-_" for c in host)


def parse_hosts(text: str) -> set[str]:
    """Extract domains from a hosts-format or plain-domain-per-line list."""
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        # "0.0.0.0 domain" / "127.0.0.1 domain" hosts format, or a bare domain.
        token = line.split()[-1].lower().rstrip(".")
        if _valid_host(token):
            out.add(token)
    return out


class SafeBrowsing(QObject):
    """Checks navigations against a locally-cached bad-host list."""

    updated = pyqtSignal(int)   # emitted with the host count after a refresh

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._hosts: frozenset[str] = frozenset()
        self._extra: frozenset[str] = frozenset()
        self._verdicts: dict[str, object] = {}
        self._enabled = self._load_config()
        self._nam = QNetworkAccessManager(self)
        self._pending = 0
        self._collected: set[str] = set()
        self._timer = QTimer(self)
        self._timer.setInterval(REFRESH_INTERVAL_MS)
        self._timer.timeout.connect(self.refresh)
        self._load_extra()
        self._load_cache()

    # -- state -----------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self._enabled

    def count(self) -> int:
        return len(self._hosts) + len(self._extra)

    def last_updated(self) -> datetime | None:
        try:
            return datetime.fromtimestamp(CACHE_FILE.stat().st_mtime)
        except OSError:
            return None

    def start(self) -> None:
        """Begin periodic refreshing and fetch once now (if enabled)."""
        if self._enabled:
            self._timer.start()
            self.refresh()

    def set_enabled(self, on: bool) -> None:
        self._enabled = on
        self._verdicts.clear()
        self._save_config()
        if on:
            self._timer.start()
            self.refresh()
        else:
            self._timer.stop()

    # -- checking (hot path) ---------------------------------------------

    def is_dangerous(self, host: str) -> SpoofVerdict | None:
        if not self._enabled:
            return None
        host = host.lower().rstrip(".")
        if not host or host in _NEVER:
            return None
        cached = self._verdicts.get(host, 0)
        if cached != 0:
            return cached or None            # False (safe) -> None
        verdict = self._make_verdict(host) if self._match(host) else False
        if len(self._verdicts) >= _VERDICT_CACHE_MAX:
            self._verdicts.clear()
        self._verdicts[host] = verdict
        return verdict or None

    def _match(self, host: str) -> bool:
        """True if host or any parent domain is on the bad list."""
        d = host
        while True:
            if d in self._hosts or d in self._extra:
                return True
            dot = d.find(".")
            if dot == -1:
                return False
            d = d[dot + 1:]

    @staticmethod
    def _make_verdict(host: str) -> SpoofVerdict:
        return SpoofVerdict(
            kind="unsafe",
            display_host=host,
            impersonated="",
            headline="Dangerous site",
            detail="This site appears on an up-to-date list of reported "
                   "phishing and malware sites.")

    # -- refresh ---------------------------------------------------------

    def refresh(self) -> None:
        if not self._enabled or self._pending:
            return
        sources = self._load_sources()
        if not sources:
            return
        self._collected = set()
        self._pending = len(sources)
        for url in sources:
            req = QNetworkRequest(QUrl(url))
            req.setAttribute(
                QNetworkRequest.Attribute.RedirectPolicyAttribute,
                QNetworkRequest.RedirectPolicy.NoLessSafeRedirectPolicy)
            reply = self._nam.get(req)
            reply.finished.connect(lambda r=reply: self._on_reply(r))

    def _on_reply(self, reply: QNetworkReply) -> None:
        try:
            if reply.error() == QNetworkReply.NetworkError.NoError:
                text = bytes(reply.readAll()).decode("utf-8", "replace")
                self._collected |= parse_hosts(text)
        except Exception:
            pass  # a failed feed must never disturb browsing
        finally:
            reply.deleteLater()
            self._pending -= 1
            if self._pending == 0:
                self._commit()

    def _commit(self) -> None:
        # All feeds failed → keep the existing cache rather than lose cover.
        if not self._collected:
            return
        hosts = self._collected
        if len(hosts) > MAX_HOSTS:
            hosts = set(islice(hosts, MAX_HOSTS))
        self._hosts = frozenset(hosts)
        self._collected = set()
        self._verdicts.clear()
        self._write_cache()
        self.updated.emit(self.count())

    # -- files -----------------------------------------------------------

    def _load_sources(self) -> list[str]:
        try:
            lines = SOURCES_FILE.read_text(encoding="utf-8").splitlines()
            urls = [ln.strip() for ln in lines
                    if ln.strip().startswith("https://")]
            if urls:
                return urls
        except OSError:
            pass
        return list(DEFAULT_SOURCES)

    def _load_extra(self) -> None:
        try:
            self._extra = frozenset(
                parse_hosts(EXTRA_FILE.read_text(encoding="utf-8")))
        except OSError:
            self._extra = frozenset()

    def _load_cache(self) -> None:
        try:
            self._hosts = frozenset(
                parse_hosts(CACHE_FILE.read_text(encoding="utf-8")))
        except OSError:
            self._hosts = frozenset()

    def _write_cache(self) -> None:
        try:
            VODOU_DIR.mkdir(parents=True, exist_ok=True)
            tmp = CACHE_FILE.with_suffix(".tmp")
            tmp.write_text("\n".join(sorted(self._hosts)), encoding="utf-8")
            tmp.replace(CACHE_FILE)
        except OSError:
            pass

    def _load_config(self) -> bool:
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            return bool(data.get("enabled", True))
        except (OSError, ValueError, TypeError):
            return True   # on by default

    def _save_config(self) -> None:
        try:
            VODOU_DIR.mkdir(parents=True, exist_ok=True)
            CONFIG_FILE.write_text(json.dumps({"enabled": self._enabled}),
                                   encoding="utf-8")
        except OSError:
            pass
