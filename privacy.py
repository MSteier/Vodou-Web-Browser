"""Privacy hardening: request interception (tracker/ad blocking) and headers.

Every outgoing request gets DNT and Sec-GPC headers, and requests to known
tracking/advertising domains are blocked outright. The blocklist below covers
the most common trackers; drop extra domains (one per line, comments with #)
into ~/.vodou/blocklist.txt to extend it.
"""

from __future__ import annotations

import sys
import time
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
        # UI-toggled kill switch. Written from the UI thread, read from the
        # IO thread — a single bool attribute read/write is GIL-atomic.
        self.paused = False

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
        global _last_auth_nav
        host = info.requestUrl().host()
        verdict = self.is_tracker(host)

        if verdict and not self.paused:
            info.block(True)
            self.blocked.emit(host)
            return
        info.setHttpHeader(b"DNT", b"1")
        info.setHttpHeader(b"Sec-GPC", b"1")
        # Keep the Firefox sign-in identity alive for as long as the user is
        # actually on a Google auth page. Google's sign-in is a single-page
        # app: advancing from the email screen to the password screen produces
        # no main-frame navigation, so the identity's wall-clock hold
        # (_identity_for) is only ever refreshed at initial page load. A slow
        # password entry — the ceremony a passkey finishes in a second — can
        # outlast the 90s hold; the next redirect to a non-auth host then
        # flips the profile back to Chrome mid-handshake and Google rejects it
        # ("browser may not be secure"). That's the retry-until-it-works
        # symptom, and it hits password sign-in specifically. The sign-in page
        # keeps making requests the whole time it's open, so refreshing the
        # hold here — scoped to requests whose FIRST party is an auth host
        # (you're on the sign-in page, not merely seeing a third-party Google
        # widget on some other site) — pins Firefox until sign-in finishes.
        on_auth_page = google_auth_host(info.firstPartyUrl().host())
        if on_auth_page:
            _last_auth_nav = time.monotonic()
        if _firefox_mode or on_auth_page or google_auth_host(host):
            # Google-sign-in quirk: present as Firefox (see FIREFOX_USER_AGENT
            # below) on EVERY request while the Firefox identity is active,
            # not just on auth hosts. A sign-in flow crosses non-auth hosts
            # (YouTube's bounces through www.youtube.com mid-handshake), and
            # a Firefox User-Agent carrying Chrome Sec-CH-UA brands is
            # exactly the mismatch Google flags as a spoofed browser. Real
            # Firefox sends no client hints anywhere, so none are injected.
            info.setHttpHeader(b"User-Agent", FIREFOX_UA_BYTES)
            return
        # Keep the client-hint brands consistent with the Chrome UA string
        # (QtWebEngine otherwise omits the "Google Chrome" brand, which reads as
        # a spoofed/embedded browser to sites that inspect these headers).
        info.setHttpHeader(b"Sec-CH-UA", SEC_CH_UA)
        info.setHttpHeader(b"Sec-CH-UA-Full-Version-List", SEC_CH_UA_FULL)


# A common, generic user agent so the browser doesn't advertise QtWebEngine
# (shrinks the fingerprinting surface a little).
#
# The Chrome version is pinned to the *actual* Chromium version that this
# QtWebEngine build ships, so the UA string agrees with the Sec-CH-UA client
# hints QtWebEngine sends automatically. A mismatch between the two (or an
# outdated version) reads as a spoofed/insecure browser and is one of the
# signals Google uses to refuse sign-in with "this browser may not be secure".
def _chrome_version() -> str:
    try:
        from PyQt6.QtWebEngineCore import qWebEngineChromiumVersion
        return qWebEngineChromiumVersion()
    except Exception:
        return "140.0.0.0"


_CHROME_FULL = _chrome_version()             # e.g. "140.0.7339.225"
_CHROME_MAJOR = _CHROME_FULL.split(".")[0]   # e.g. "140"

GENERIC_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    f"(KHTML, like Gecko) Chrome/{_CHROME_MAJOR}.0.0.0 Safari/537.36"
)

# User-Agent Client Hints. QtWebEngine's own Sec-CH-UA advertises only
# "Chromium" (no "Google Chrome" brand), which contradicts the Chrome UA string
# above and makes the browser look spoofed/embedded to sites like Google that
# read these headers. We rewrite them so the brands agree with the UA — the
# same "present as generic Chrome" identity the browser already adopts, made
# consistent. GREASE token ("Not=A?Brand";v="24") matches what this Chromium
# build emits. Sent as bytes for the interceptor's setHttpHeader.
SEC_CH_UA = (
    f'"Chromium";v="{_CHROME_MAJOR}", "Not=A?Brand";v="24", '
    f'"Google Chrome";v="{_CHROME_MAJOR}"'
).encode()
SEC_CH_UA_FULL = (
    f'"Chromium";v="{_CHROME_FULL}", "Not=A?Brand";v="24.0.0.0", '
    f'"Google Chrome";v="{_CHROME_FULL}"'
).encode()

# Google refuses sign-in from embedded Chromium engines ("This browser or app
# may not be secure") no matter how consistent the Chrome identity above is —
# it fingerprints the engine, not the headers. qutebrowser (also QtWebEngine)
# solved this years ago with a site-specific quirk: present as *Firefox* on
# Google's account hosts only (qutebrowser/qutebrowser#5182, shipped as
# content.site_specific_quirks). Firefox UAs have kept working where Chrome-
# and Edge-flavored ones get re-blocked, and real Firefox sends no Sec-CH-UA
# client hints at all, so the "spoofed browser" inconsistency disappears.
# Bump the version below if Google ever complains the browser is outdated.
FIREFOX_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) "
    "Gecko/20100101 Firefox/140.0"
)
FIREFOX_UA_BYTES = FIREFOX_USER_AGENT.encode()

_GOOGLE_AUTH_HOSTS = frozenset({"accounts.google.com", "accounts.youtube.com"})

# Second-level labels Google's ccTLD domains actually use ahead of a country
# code (google.co.uk, google.com.au, google.com.br…).
_GOOGLE_SECOND_LEVEL = frozenset({"co", "com", "net", "org"})


def _google_tld(rest: str) -> bool:
    """True if `rest` looks like the TLD part of a google.<tld> domain.

    Accepts a single short alphabetic TLD ("com", "de", "fr") or a
    second-level public suffix ("co.uk", "com.au") — nothing else.
    """
    labels = rest.split(".")
    if len(labels) == 1:
        return 2 <= len(labels[0]) <= 3 and labels[0].isalpha()
    if len(labels) == 2:
        return (labels[0] in _GOOGLE_SECOND_LEVEL
                and len(labels[1]) == 2 and labels[1].isalpha())
    return False


def google_auth_host(host: str) -> bool:
    """True for Google's sign-in hosts (including ccTLD variants like
    accounts.google.co.uk that the sign-in flow can bounce through).

    The tail is validated as an actual TLD rather than accepted as any
    "accounts.google.*" prefix. A bare prefix test also matched
    accounts.google.evil.com — a name anyone can create under a domain they
    own — and matching here is not cosmetic: interceptRequest refreshes
    _last_auth_nav from it, which pins the Firefox identity **profile-wide**
    for _AUTH_HOLD_SECONDS. That let any website flip the identity Vodou
    presents to every other site, and get FIREFOX_QUIRK_JS injected into its
    own main world. Residual risk is now limited to someone owning an actual
    google.<tld>, which is a far narrower set than "any domain at all".
    """
    if host in _GOOGLE_AUTH_HOSTS:
        return True
    prefix = "accounts.google."
    return host.startswith(prefix) and _google_tld(host[len(prefix):])


# QtWebEngine's WebAuthn performs the actual ceremonies fine (Windows Hello
# prompts and signs), but PublicKeyCredential.getClientCapabilities() never
# settles — a known engine bug (qutebrowser#8930) that stalls or fails any
# sign-in flow that awaits it before/after the ceremony. Google's rejection
# code for our passkey loop (rrk=46, adjacent to rrk=47 "JavaScript
# disabled") points at exactly such a client-capability failure, matching
# the retry-until-it-works symptom. The shim resolves immediately with what
# the engine truly offers: a user-verifying platform authenticator (Windows
# Hello) and NO conditional/autofill passkey UI — steering sites onto the
# modal flow that actually works. Injected on all sites; the bug isn't
# Google-specific (it also breaks e.g. ChatGPT's login modal).
#
# What the shim may claim is platform-dependent, and getting this wrong is
# worse than not shimming at all. Windows Hello is a real user-verifying
# platform authenticator that QtWebEngine drives correctly. On Linux there is
# none behind QtWebEngine, so claiming one would steer sites onto the modal
# platform flow that cannot complete — hiding the security-key path that does
# work. The engine bug being worked around is platform-independent; only the
# answer is not.
_PLATFORM_AUTHENTICATOR = "true" if sys.platform == "win32" else "false"

WEBAUTHN_SHIM_JS = """\
(function () {
    "use strict";
    if (!window.PublicKeyCredential) {
        return;
    }
    var caps = {
        conditionalCreate: false,
        conditionalGet: false,
        conditionalMediation: false,
        hybridTransport: false,
        passkeyPlatformAuthenticator: %PLATFORM_AUTH%,
        userVerifyingPlatformAuthenticator: %PLATFORM_AUTH%,
        relatedOrigins: false,
        signalAllAcceptedCredentials: false,
        signalCurrentUserDetails: false,
        signalUnknownCredential: false
    };
    try {
        Object.defineProperty(PublicKeyCredential, "getClientCapabilities", {
            value: function () { return Promise.resolve(caps); },
            configurable: true,
            writable: true
        });
    } catch (e) {}
    try {
        Object.defineProperty(PublicKeyCredential,
                              "isConditionalMediationAvailable", {
            value: function () { return Promise.resolve(false); },
            configurable: true,
            writable: true
        });
    } catch (e) {}
})();
""".replace("%PLATFORM_AUTH%", _PLATFORM_AUTHENTICATOR)


# JS-visible Chromium giveaways that contradict the Firefox identity on
# Google's sign-in pages. The risk checks there don't stop at headers: page
# script can see window.chrome, navigator.userAgentData (with Chromium
# brands), and navigator.vendor "Google Inc." — none of which exist in real
# Firefox — no matter what the User-Agent claims. Injected at
# DocumentCreation in the page's MAIN world (it must affect what the page
# itself sees), self-limited to the auth hosts, incl. their subframes.
FIREFOX_QUIRK_JS = """\
(function () {
    "use strict";
    var h = location.host;
    // Mirrors privacy.google_auth_host: the tail after "accounts.google."
    // must be a real TLD ("de", "co.uk"), not just any suffix — otherwise
    // accounts.google.evil.com, which anyone can create, gets this shim.
    function googleAuthHost(host) {
        if (host === "accounts.google.com" || host === "accounts.youtube.com") {
            return true;
        }
        var prefix = "accounts.google.";
        if (host.indexOf(prefix) !== 0) {
            return false;
        }
        var labels = host.slice(prefix.length).split(".");
        if (labels.length === 1) {
            return /^[a-z]{2,3}$/.test(labels[0]);
        }
        if (labels.length === 2) {
            return /^(co|com|net|org)$/.test(labels[0])
                && /^[a-z]{2}$/.test(labels[1]);
        }
        return false;
    }
    if (!googleAuthHost(h)) {
        return;
    }
    try { delete window.chrome; } catch (e) {}
    var firefoxNavigator = {
        userAgentData: undefined,             // Chromium-only API
        vendor: "",                           // "Google Inc." in Chromium
        productSub: "20100101",               // Firefox's frozen value
        buildID: "20181001000000",            // Firefox-only, frozen value
        oscpu: "Windows NT 10.0; Win64; x64"  // Firefox-only
    };
    Object.keys(firefoxNavigator).forEach(function (name) {
        try {
            Object.defineProperty(Navigator.prototype, name, {
                get: function () { return firefoxNavigator[name]; },
                configurable: true
            });
        } catch (e) {}
    });
})();
"""


# How long the Firefox identity stays sticky after the last navigation to a
# Google auth host. A sign-in flow bounces through redirects, popups, and the
# site's OAuth callback; reverting the (profile-wide) identity on the first
# non-Google hop reloads pages mid-handshake and breaks the flow — the
# "retry until it works" symptom. Sites seeing a Firefox UA for a bit after
# sign-in is harmless; the next navigation after the hold reverts it.
_AUTH_HOLD_SECONDS = 90.0
_last_auth_nav = 0.0
# Mirrors which identity the profile currently presents. Written on the UI
# thread by apply_ua_quirk, read on the IO thread by interceptRequest — a
# single bool attribute is GIL-atomic. The interceptor keys its headers off
# this so per-request identity can never contradict the profile identity.
_firefox_mode = False


def _identity_for(profile, host: str) -> str:
    """The User-Agent the profile should present for a main-frame navigation
    to host: Firefox on Google's auth hosts, Firefox held through the
    sign-in grace period, generic Chrome otherwise."""
    global _last_auth_nav
    now = time.monotonic()
    if google_auth_host(host):
        _last_auth_nav = now
        return FIREFOX_USER_AGENT
    if (profile.httpUserAgent() == FIREFOX_USER_AGENT
            and now - _last_auth_nav < _AUTH_HOLD_SECONDS):
        return FIREFOX_USER_AGENT
    return GENERIC_USER_AGENT


def ua_quirk_needed(profile, host: str) -> bool:
    """True if a main-frame navigation to host must switch identity first.

    Read-only (no engine mutation), so it IS safe inside navigation
    callbacks — callers use it to decide whether to hold a navigation while
    the deferred apply_ua_quirk runs."""
    return profile.httpUserAgent() != _identity_for(profile, host)


def apply_ua_quirk(profile, host: str) -> bool:
    """Switch the profile identity for a main-frame navigation: Firefox on
    Google's account hosts (sticky for _AUTH_HOLD_SECONDS — see above), the
    generic Chrome identity everywhere else. Returns True if the identity
    actually changed.

    Profile-level (not just the header override in interceptRequest) so that
    navigator.userAgent in page JS agrees with the HTTP headers — Google's
    sign-in check reads both.

    Must NOT be called from inside a QtWebEngine navigation callback
    (acceptNavigationRequest etc.) — setHttpUserAgent re-enters the engine
    and aborts the process. Callers defer it by one event-loop tick.
    """
    global _firefox_mode
    target = _identity_for(profile, host)
    _firefox_mode = target == FIREFOX_USER_AGENT
    if profile.httpUserAgent() == target:
        return False
    profile.setHttpUserAgent(target)
    try:
        # Qt 6.8+: real Firefox sends no client hints, so disable them
        # entirely while presenting as Firefox.
        profile.clientHints().setAllClientHintsEnabled(
            target != FIREFOX_USER_AGENT)
    except AttributeError:
        pass
    return True
