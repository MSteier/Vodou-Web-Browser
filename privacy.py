"""Privacy hardening: request interception (tracker/ad blocking) and headers.

Every outgoing request gets DNT and Sec-GPC headers, and requests to known
tracking/advertising domains are blocked outright. The blocklist below covers
the most common trackers; drop extra domains (one per line, comments with #)
into ~/.vodou/blocklist.txt to extend it.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWebEngineCore import (
    QWebEngineUrlRequestInfo,
    QWebEngineUrlRequestInterceptor,
)

USER_BLOCKLIST = Path.home() / ".vodou" / "blocklist.txt"

# Common tracking / advertising / fingerprinting domains. Matched against the
# request host as an exact match or parent-domain suffix.
TRACKER_DOMAINS = {
    # Google advertising & analytics
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "google-analytics.com", "googletagmanager.com", "googletagservices.com",
    "adservice.google.com", "admob.com", "app-measurement.com",
    # Meta / Facebook
    "facebook.net", "connect.facebook.net", "graph.facebook.com",
    "pixel.facebook.com", "an.facebook.com",
    # Other major ad networks
    "adnxs.com", "adsrvr.org", "advertising.com", "adform.net",
    "criteo.com", "criteo.net", "taboola.com", "outbrain.com",
    "pubmatic.com", "rubiconproject.com", "openx.net", "casalemedia.com",
    "smartadserver.com", "yieldmo.com", "sharethrough.com", "media.net",
    "amazon-adsystem.com", "moatads.com", "adcolony.com", "unityads.com",
    "applovin.com", "vungle.com", "inmobi.com", "mopub.com",
    # Analytics & session recording
    "scorecardresearch.com", "quantserve.com", "quantcount.com",
    "hotjar.com", "mouseflow.com", "fullstory.com", "clarity.ms",
    "mixpanel.com", "amplitude.com", "segment.io", "segment.com",
    "chartbeat.com", "parsely.com", "newrelic.com", "nr-data.net",
    "bugsnag.com", "sentry-cdn.com", "crazyegg.com", "luckyorange.com",
    "kissmetrics.com", "statcounter.com", "matomo.cloud",
    # Data brokers & tag managers
    "bluekai.com", "krxd.net", "exelator.com", "demdex.net", "omtrdc.net",
    "everesttech.net", "agkn.com", "mathtag.com", "rlcdn.com", "tapad.com",
    "liveramp.com", "id5-sync.com", "adsafeprotected.com",
    "doubleverify.com", "branch.io", "appsflyer.com", "adjust.com",
    "kochava.com", "singular.net",
    # Social widgets that double as trackers
    "platform.twitter.com", "ads-twitter.com", "static.ads-twitter.com",
    "ads.linkedin.com", "px.ads.linkedin.com", "snap.licdn.com",
    "analytics.tiktok.com", "ads.tiktok.com", "ads.pinterest.com",
    "ct.pinterest.com", "ads.yahoo.com", "analytics.yahoo.com",
    "yandex.ru", "mc.yandex.ru",
}


def _load_user_blocklist() -> set[str]:
    if not USER_BLOCKLIST.exists():
        return set()
    domains = set()
    for line in USER_BLOCKLIST.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            domains.add(line)
    return domains


def _suffix_match(host: str, domains: frozenset[str]) -> bool:
    """True if host or any parent domain of it is in domains.

    Walks suffixes in place ("a.b.tracker.com" -> "b.tracker.com" -> ...)
    instead of split/join, avoiding per-label list and string allocations.
    """
    d = host
    while True:
        if d in domains:
            return True
        dot = d.find(".")
        if dot == -1:
            return False
        d = d[dot + 1:]


class PrivacyInterceptor(QWebEngineUrlRequestInterceptor):
    """Blocks tracker requests and adds opt-out headers to the rest.

    This is the hottest path in the browser — it runs for every network
    request of every page — so verdicts are cached per host. Note:
    interceptRequest may run on Chromium's IO thread; it only touches the
    immutable domain set and the verdict dict (single dict get/set,
    GIL-atomic) and emits a queued signal for the UI counter.
    """

    blocked = pyqtSignal(str)  # host that was blocked

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._domains = frozenset(TRACKER_DOMAINS | _load_user_blocklist())
        self._verdicts: dict[str, bool] = {}

    def is_tracker(self, host: str) -> bool:
        """Verdict for a host, with caching. Normalizes first: lowercase and
        strip a trailing dot, so a fully-qualified "ads.doubleclick.net."
        can't evade the blocklist."""
        host = host.lower().rstrip(".")
        verdict = self._verdicts.get(host)
        if verdict is None:
            verdict = _suffix_match(host, self._domains)
            if len(self._verdicts) >= 4096:
                self._verdicts.clear()
            self._verdicts[host] = verdict
        return verdict

    def interceptRequest(self, info: QWebEngineUrlRequestInfo) -> None:
        host = info.requestUrl().host()
        verdict = self.is_tracker(host)

        if verdict:
            info.block(True)
            self.blocked.emit(host)
            return
        info.setHttpHeader(b"DNT", b"1")
        info.setHttpHeader(b"Sec-GPC", b"1")


# A common, generic user agent so the browser doesn't advertise QtWebEngine
# (shrinks the fingerprinting surface a little).
#
# The Chrome version is pinned to the *actual* Chromium version that this
# QtWebEngine build ships, so the UA string agrees with the Sec-CH-UA client
# hints QtWebEngine sends automatically. A mismatch between the two (or an
# outdated version) reads as a spoofed/insecure browser and is one of the
# signals Google uses to refuse sign-in with "this browser may not be secure".
def _chrome_major() -> str:
    try:
        from PyQt6.QtWebEngineCore import qWebEngineChromiumVersion
        return qWebEngineChromiumVersion().split(".")[0]
    except Exception:
        return "140"


GENERIC_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    f"(KHTML, like Gecko) Chrome/{_chrome_major()}.0.0.0 Safari/537.36"
)
