"""Location & region emulation — profile model, presets, and persistence.

A LocationProfile bundles a *coherent* set of regional signals for one place, so
the browser can never expose contradictory ones (Tokyo locale with a New York
timezone, etc.). This module owns the data and main.py applies the parts Vodou
can emulate *natively* today.

Honest scope (v1 — the clean, native, no-debug-port parts):

  APPLIED
    * navigator.language / navigator.languages / Accept-Language
        — live, via QWebEngineProfile.setHttpAcceptLanguage()
    * Intl date / number / currency formatting locale
        — via the Chromium --lang flag, which takes effect on the next restart

  NOT emulated yet (in the model for the UI/diagnostics and future stages;
  QtWebEngine exposes no native override, and the alternatives — a remote-
  debugging port or script injection — were deliberately deferred):
    * timezone      (Intl timezone / Date)
    * geolocation   (navigator.geolocation coordinates)

The UI marks exactly which dimensions are active, so a "Tokyo" *locale* is never
presented as being *located* in Tokyo. This keeps the feature honest.
"""

from __future__ import annotations

import json
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
    "NL": ("nl-NL", "Dutch (Netherlands)", ["nl-NL", "nl", "en"], "EUR", "metric"),
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
