"""Location & region emulation — profile model, presets, and persistence.

A LocationProfile bundles a *coherent* set of regional signals for one place, so
the browser can never expose contradictory ones (Tokyo locale with a New York
timezone, etc.). This module owns the data and main.py applies the parts Vodou
can emulate.

Honest scope:

  APPLIED NATIVELY (no script, no debug port)
    * navigator.language / navigator.languages / Accept-Language
        — live, via QWebEngineProfile.setHttpAcceptLanguage()
    * Intl date / number / currency formatting locale
        — via the Chromium --lang flag, which takes effect on the next restart

  APPLIED VIA SCRIPT INJECTION (opt-in, "Also emulate geolocation && timezone")
    * timezone      (Intl timezone / Date)
    * geolocation   (navigator.geolocation coordinates)
        QtWebEngine exposes no native geolocation-provider override reachable
        from a PyQt6 embedder (no equivalent of Chrome's --geo-override or a
        platform location-provider hook) — confirmed, not assumed. A script
        injected at DocumentCreation in the page's MAIN world (main.py,
        _sync_geolocation_scripts) is the closest available mechanism: it
        replaces navigator.geolocation before any page script runs. Honest
        limits, stated in the Settings UI and Diagnostics view: it does not
        reach dedicated/service workers, and a determined page can detect it.
        It never changes the browser's real IP or IP stack (v4/v6) — see
        "Match VPN location" below for the IP-geolocation half of that.

  MATCH VPN LOCATION (opt-in, never automatic — see _match_vpn_location in
  main.py): a one-shot lookup of the current public IP's approximate region,
  used to fill in a "custom" LocationProfile. Vodou has no VPN client of its
  own and does not detect VPN connect/disconnect — this only reads whatever
  public IP the OS is already routing through (a VPN, a proxy, or the real
  connection) at the moment the user clicks the button. There is deliberately
  no background polling for a changed exit IP: that would mean silently
  re-contacting a third party on a timer, which this feature's own consent
  dialog explicitly promises not to do. `note_lookup`/`cached_lookup` below
  only cover the *same click session* (in-memory, cleared on restart) — they
  detect "did this lookup return a different IP than last time" and avoid
  re-hitting the network for rapid repeat clicks, not silent background sync.

The UI marks exactly which dimensions are active, so a "Tokyo" *locale* is never
presented as being *located* in Tokyo. This keeps the feature honest.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

CONFIG_FILE = Path.home() / ".vodou" / "location.json"
SITES_FILE = Path.home() / ".vodou" / "location_sites.json"


@dataclass
class LocationProfile:
    key: str
    city: str
    country: str            # display name, e.g. "United Kingdom"
    country_code: str = ""  # ISO, e.g. "GB"
    region: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    accuracy: int = 100     # metres (geolocation — not emulated in v1)
    timezone: str = ""      # e.g. "Europe/London" (not emulated in v1)
    locale: str = ""        # e.g. "en-GB"
    language_name: str = ""  # e.g. "English (United Kingdom)"
    languages: list = field(default_factory=list)  # e.g. ["en-GB", "en"]
    currency: str = ""      # e.g. "GBP"
    measurement: str = ""   # "metric" | "imperial"

    @property
    def label(self) -> str:
        return f"{self.city}, {self.country}"

    def accept_language(self) -> str:
        """The Accept-Language / navigator.languages value, e.g.
        'ja-JP,ja;q=0.9,en;q=0.8'."""
        langs = self.languages or ([self.locale] if self.locale else ["en-US"])
        parts, q = [], 1.0
        for i, lang in enumerate(langs):
            parts.append(lang if i == 0 else f"{lang};q={q:.1f}")
            q = max(0.1, round(q - 0.1, 1))
        return ",".join(parts)

    def chromium_lang(self) -> str:
        """The --lang flag value that drives Intl's default locale."""
        return self.locale or (self.languages[0] if self.languages else "en-US")


# Popular presets — each internally consistent (locale ↔ language ↔ currency ↔
# measurement ↔ timezone ↔ coordinates all agree).
PRESETS: dict[str, LocationProfile] = {
    p.key: p for p in [
        LocationProfile("new_york", "New York", "United States", "US",
                        "New York", 40.7128, -74.0060, 100, "America/New_York",
                        "en-US", "English (United States)", ["en-US", "en"],
                        "USD", "imperial"),
        LocationProfile("london", "London", "United Kingdom", "GB", "England",
                        51.5074, -0.1278, 100, "Europe/London",
                        "en-GB", "English (United Kingdom)", ["en-GB", "en"],
                        "GBP", "metric"),
        LocationProfile("tokyo", "Tokyo", "Japan", "JP", "Tokyo",
                        35.6762, 139.6503, 100, "Asia/Tokyo",
                        "ja-JP", "Japanese", ["ja-JP", "ja", "en"],
                        "JPY", "metric"),
        LocationProfile("sydney", "Sydney", "Australia", "AU", "New South Wales",
                        -33.8688, 151.2093, 100, "Australia/Sydney",
                        "en-AU", "English (Australia)", ["en-AU", "en"],
                        "AUD", "metric"),
        LocationProfile("paris", "Paris", "France", "FR", "Île-de-France",
                        48.8566, 2.3522, 100, "Europe/Paris",
                        "fr-FR", "French (France)", ["fr-FR", "fr", "en"],
                        "EUR", "metric"),
        LocationProfile("berlin", "Berlin", "Germany", "DE", "Berlin",
                        52.5200, 13.4050, 100, "Europe/Berlin",
                        "de-DE", "German (Germany)", ["de-DE", "de", "en"],
                        "EUR", "metric"),
        LocationProfile("toronto", "Toronto", "Canada", "CA", "Ontario",
                        43.6532, -79.3832, 100, "America/Toronto",
                        "en-CA", "English (Canada)", ["en-CA", "en", "fr-CA"],
                        "CAD", "metric"),
        LocationProfile("sao_paulo", "São Paulo", "Brazil", "BR", "São Paulo",
                        -23.5505, -46.6333, 100, "America/Sao_Paulo",
                        "pt-BR", "Portuguese (Brazil)", ["pt-BR", "pt", "en"],
                        "BRL", "metric"),
    ]
}


def load() -> tuple[bool, bool, LocationProfile | None]:
    """(enabled, geo, profile) as saved.

    enabled — master switch; when on, language/locale is emulated natively.
    geo     — additionally emulate geolocation + timezone via an injected
              script (only meaningful when enabled and a profile is set).
    profile — a known preset, or None.
    """
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return False, False, None
    except (OSError, ValueError):
        return False, False, None
    key = str(data.get("key", ""))
    prof = (_profile_from_dict(data.get("custom")) if key == "custom"
            else PRESETS.get(key))
    on = bool(data.get("enabled")) and prof is not None
    return on, on and bool(data.get("geo")), prof


def save(enabled: bool, geo: bool, profile: LocationProfile | None) -> None:
    """Persist the on/off state, geolocation/timezone toggle, and profile (a
    preset, or a 'custom' profile e.g. from Match VPN location)."""
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        on = bool(enabled) and profile is not None
        out = {"enabled": on, "geo": on and bool(geo),
               "key": profile.key if profile else ""}
        if on and profile and profile.key == "custom":
            out["custom"] = asdict(profile)
        tmp = CONFIG_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(out), encoding="utf-8")
        tmp.replace(CONFIG_FILE)
    except OSError:
        pass


def _profile_from_dict(d) -> LocationProfile | None:
    """Rebuild a (custom) profile from stored/derived fields; None if unusable."""
    if not isinstance(d, dict):
        return None
    try:
        names = {f.name for f in fields(LocationProfile)}
        kw = {k: v for k, v in d.items() if k in names}
        kw["key"] = "custom"
        kw.setdefault("city", "Custom")
        kw.setdefault("country", "")
        p = LocationProfile(**kw)
        return p if p.locale and p.timezone else None
    except (TypeError, ValueError):
        return None


def chromium_lang_flag() -> str:
    """' --lang=<locale>' for the saved profile when emulation is on, else ''.
    Read at launch (before Qt initializes) so Intl formatting is localized too.
    Returns nothing when disabled, so the browser keeps its real Intl locale."""
    on, _geo, prof = load()
    return f" --lang={prof.chromium_lang()}" if on and prof else ""


# Injected at DocumentCreation in each frame's MAIN world (it must replace what
# the page itself sees) when geolocation/timezone emulation is on. This is
# script-based, so its honest limits apply: it does not reach dedicated/service
# workers, and a determined page can detect the override. It covers the primary
# signals — navigator.geolocation and the Intl/Date timezone.
#
# It resolves the location PER FRAME by hostname: a per-site override wins,
# otherwise the global profile applies. This is genuinely per-site (each frame
# picks its own), unlike the language/Accept-Language dimension which is a
# single browser-profile setting.
_SPOOF_JS = r"""(function(){
  "use strict";
  var SITES = __SITES__, GLOBAL = __GLOBAL__;
  var P = SITES[location.hostname] || GLOBAL;
  if (!P) return;
  var LAT=P.lat, LON=P.lon, ACC=P.acc, TZ=P.tz;
  // --- geolocation -> fixed coordinates ---
  if ("geolocation" in navigator) {
    var proto = Object.getPrototypeOf(navigator.geolocation) || navigator.geolocation;
    function fix(){ return {coords:{latitude:LAT,longitude:LON,accuracy:ACC,
      altitude:null,altitudeAccuracy:null,heading:null,speed:null},
      timestamp:Date.now()}; }
    function def(n,v){ try{ Object.defineProperty(proto,n,
      {value:v,configurable:true,writable:true}); }catch(e){} }
    def("getCurrentPosition", function(ok){
      if (typeof ok==="function") setTimeout(function(){ try{ok(fix());}catch(e){} },0); });
    var wid=1;
    def("watchPosition", function(ok){
      if (typeof ok==="function") setTimeout(function(){ try{ok(fix());}catch(e){} },0);
      return wid++; });
    def("clearWatch", function(){});
  }
  // --- timezone -> Intl default + getTimezoneOffset ---
  try {
    var Real = Intl.DateTimeFormat;
    function Patched(){
      var a = Array.prototype.slice.call(arguments);
      var o = a[1] || {};
      if (!o.timeZone) o = Object.assign({}, o, {timeZone: TZ});
      if (this instanceof Patched) return new Real(a[0], o);
      return Real(a[0], o);
    }
    Patched.prototype = Real.prototype;
    Patched.supportedLocalesOf = Real.supportedLocalesOf;
    Intl.DateTimeFormat = Patched;
    function offMin(d){
      try {
        var f = new Real("en-US",{timeZone:TZ,hour12:false,year:"numeric",
          month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"});
        var p={}; f.formatToParts(d).forEach(function(x){p[x.type]=x.value;});
        var u = Date.UTC(+p.year,+p.month-1,+p.day,+p.hour,+p.minute,+p.second);
        return -Math.round((u - d.getTime())/60000);
      } catch(e){ return 0; }
    }
    Object.defineProperty(Date.prototype,"getTimezoneOffset",
      {value:function(){ return offMin(this); },configurable:true,writable:true});
  } catch(e){}
})();"""


def _params(p: LocationProfile) -> dict:
    return {"lat": float(p.latitude), "lon": float(p.longitude),
            "acc": int(p.accuracy), "tz": p.timezone}


def spoof_script(global_profile: LocationProfile | None,
                 sites: dict[str, LocationProfile] | None = None) -> str:
    """The geolocation + timezone override script. `sites` maps hostname ->
    profile (per-site overrides); `global_profile` is the fallback."""
    site_map = {host: _params(p) for host, p in (sites or {}).items()}
    g = _params(global_profile) if global_profile else None
    return (_SPOOF_JS
            .replace("__SITES__", json.dumps(site_map))
            .replace("__GLOBAL__", json.dumps(g)))


# --- per-site overrides (host -> preset) -------------------------------------
def load_sites() -> dict[str, LocationProfile]:
    """{hostname: profile} of per-site overrides (presets only)."""
    try:
        data = json.loads(SITES_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
    except (OSError, ValueError):
        return {}
    out = {}
    for host, key in data.items():
        prof = PRESETS.get(str(key))
        if prof and isinstance(host, str) and host:
            out[host] = prof
    return out


def save_sites(mapping: dict[str, str]) -> None:
    """Persist {hostname: preset_key}, keeping only known presets/hosts."""
    try:
        SITES_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = {h: k for h, k in mapping.items() if k in PRESETS and h}
        tmp = SITES_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(clean), encoding="utf-8")
        tmp.replace(SITES_FILE)
    except OSError:
        pass


def effective_profile(host: str, global_profile: LocationProfile | None,
                      sites: dict[str, LocationProfile] | None
                      ) -> LocationProfile | None:
    """Precedence: an exact per-site override wins, else the global profile."""
    return (sites or {}).get(host) or global_profile


# --- Match VPN location: derive a profile from IP geolocation ----------------
# countryCode -> (locale, language_name, languages, currency, measurement). A
# best-effort guess for the region's language when only the country is known;
# the user can always override the result.
COUNTRY_LOCALE = {
    "US": ("en-US", "English (United States)", ["en-US", "en"], "USD", "imperial"),
    "GB": ("en-GB", "English (United Kingdom)", ["en-GB", "en"], "GBP", "metric"),
    "JP": ("ja-JP", "Japanese", ["ja-JP", "ja", "en"], "JPY", "metric"),
    "AU": ("en-AU", "English (Australia)", ["en-AU", "en"], "AUD", "metric"),
    "FR": ("fr-FR", "French (France)", ["fr-FR", "fr", "en"], "EUR", "metric"),
    "DE": ("de-DE", "German (Germany)", ["de-DE", "de", "en"], "EUR", "metric"),
    "CA": ("en-CA", "English (Canada)", ["en-CA", "en", "fr-CA"], "CAD", "metric"),
    "BR": ("pt-BR", "Portuguese (Brazil)", ["pt-BR", "pt", "en"], "BRL", "metric"),
    "ES": ("es-ES", "Spanish (Spain)", ["es-ES", "es", "en"], "EUR", "metric"),
    "IT": ("it-IT", "Italian (Italy)", ["it-IT", "it", "en"], "EUR", "metric"),
    "NL": ("nl-NL", "Dutch (Netherlands)", ["nl-NL", "nl", "en"], "EUR", "metric"),
    "MX": ("es-MX", "Spanish (Mexico)", ["es-MX", "es", "en"], "MXN", "metric"),
    "IN": ("en-IN", "English (India)", ["en-IN", "hi", "en"], "INR", "metric"),
    "CN": ("zh-CN", "Chinese (Simplified)", ["zh-CN", "zh", "en"], "CNY", "metric"),
    "KR": ("ko-KR", "Korean", ["ko-KR", "ko", "en"], "KRW", "metric"),
    "RU": ("ru-RU", "Russian", ["ru-RU", "ru", "en"], "RUB", "metric"),
    "SE": ("sv-SE", "Swedish", ["sv-SE", "sv", "en"], "SEK", "metric"),
    "SG": ("en-SG", "English (Singapore)", ["en-SG", "en"], "SGD", "metric"),
    "CH": ("de-CH", "German (Switzerland)", ["de-CH", "de", "fr-CH"], "CHF", "metric"),
}


IPGEO_URL = "https://ipapi.co/json/"


def from_ipgeo(data: dict) -> LocationProfile | None:
    """Build a custom profile from an ipapi.co response, guessing the locale
    from the country. Returns None on an error / malformed response."""
    try:
        if data.get("error"):
            return None
        cc = str(data.get("country_code", "")).upper()
        if not cc:
            return None
        locale, lang_name, langs, currency, meas = COUNTRY_LOCALE.get(
            cc, ("en-US", "English (United States)", ["en-US", "en"], "USD", "metric"))
        tz = str(data.get("timezone", "") or "")
        if not tz:
            return None
        return LocationProfile(
            key="custom",
            city=str(data.get("city", "") or "Unknown"),
            country=str(data.get("country_name", "") or cc),
            country_code=cc,
            region=str(data.get("region", "") or ""),
            latitude=float(data.get("latitude", 0.0)),
            longitude=float(data.get("longitude", 0.0)),
            accuracy=1000,
            timezone=tz,
            locale=locale, language_name=lang_name, languages=list(langs),
            currency=str(data.get("currency", "") or currency),
            measurement=meas)
    except (TypeError, ValueError):
        return None


def ipgeo_ip_info(data: dict) -> tuple[str, str] | None:
    """(ip, version) — "IPv4" or "IPv6" — from an ipapi.co response, or None.

    Deliberately NOT a LocationProfile field: LocationProfile is what
    save()/asdict() persist to disk, and the whole point of this function is
    a value that must never end up there — the raw public IP is used
    transiently (cache de-duplication, the confirmation dialog, diagnostics)
    and is never written to CONFIG_FILE. ipapi.co reports whichever protocol
    the request actually used, so IPv4 and IPv6 need no separate handling
    here beyond reading the field it already sends.
    """
    ip = str(data.get("ip", "") or "").strip()
    if not ip:
        return None
    version = str(data.get("version", "") or "").strip()
    if version not in ("IPv4", "IPv6"):
        version = "IPv6" if ":" in ip else "IPv4"
    return ip, version


# --- IP-geolocation failure classification -----------------------------------
# Pure and Qt-free so it's unit-testable without a live network. main.py maps
# a QNetworkReply's outcome onto these inputs.
IPGEO_TIMEOUT = "timeout"
IPGEO_RATE_LIMITED = "rate_limited"
IPGEO_NETWORK_ERROR = "network_error"
IPGEO_MALFORMED = "malformed_response"
IPGEO_UNRECOGNIZED = "unrecognized_response"

_IPGEO_MESSAGES = {
    IPGEO_TIMEOUT:
        "The location lookup timed out.",
    IPGEO_RATE_LIMITED:
        "The location service is rate-limiting requests — try again shortly.",
    IPGEO_NETWORK_ERROR:
        "Couldn't reach the location service (no network, or it's down).",
    IPGEO_MALFORMED:
        "The location service returned an unreadable response.",
    IPGEO_UNRECOGNIZED:
        "The location service didn't return a recognizable region for this IP.",
}


def classify_ipgeo_failure(*, timed_out: bool = False,
                           network_error: bool = False,
                           http_status: int | None = None,
                           raw: bytes | None = None) -> str:
    """Best-effort reason code for why a lookup failed, in priority order:
    transfer timeout, HTTP 429 (rate limit), any other transport error, an
    empty/unparsable body, else "unrecognized_response" — a well-formed
    response `from_ipgeo` still couldn't use (e.g. no timezone for the IP)."""
    if timed_out:
        return IPGEO_TIMEOUT
    if http_status == 429:
        return IPGEO_RATE_LIMITED
    if network_error:
        return IPGEO_NETWORK_ERROR
    if not raw:
        return IPGEO_MALFORMED
    try:
        json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return IPGEO_MALFORMED
    return IPGEO_UNRECOGNIZED


def ipgeo_failure_message(reason: str) -> str:
    """User-facing sentence for a classify_ipgeo_failure() reason code."""
    return _IPGEO_MESSAGES.get(reason, "Couldn't determine your IP location.")


# --- lookup de-duplication (in-memory only — never persisted, never a
# background poller) -----------------------------------------------------
_last_lookup: dict | None = None  # {"ip": str, "profile": LocationProfile, "at": float}


def note_lookup(ip: str, profile: LocationProfile) -> bool:
    """Record a successful lookup. Returns True if `ip` differs from the
    previously recorded lookup (the VPN/exit IP changed since last time);
    False on the first lookup of a session or when it's unchanged."""
    global _last_lookup
    changed = _last_lookup is not None and _last_lookup["ip"] != ip
    _last_lookup = {"ip": ip, "profile": profile, "at": time.monotonic()}
    return changed


def cached_lookup(max_age: float = 30.0) -> tuple[str, LocationProfile] | None:
    """(ip, profile) from the last recorded lookup if younger than max_age
    seconds, else None. Only for de-duplicating rapid repeat clicks of
    "Match VPN location" — never used to skip the user's explicit action or
    to answer navigator.geolocation on its own."""
    if _last_lookup is None:
        return None
    if time.monotonic() - _last_lookup["at"] > max_age:
        return None
    return _last_lookup["ip"], _last_lookup["profile"]


def clear_lookup_cache() -> None:
    """Drop the recorded lookup — test isolation, or an explicit reset."""
    global _last_lookup
    _last_lookup = None
