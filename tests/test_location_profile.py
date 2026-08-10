"""Tests for the Location & region emulation profile model and persistence.

Offline and deterministic: preset coherence, the Accept-Language / --lang
derivations, and the on/off persistence round-trip. The live effect
(navigator.language(s), Accept-Language, Intl locale) is verified against a
real QtWebEngine page during development.

Run:  python tests/test_location_profile.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import location_profile as lp  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


# --- preset coherence --------------------------------------------------------
print("preset coherence")
check("several presets exist", len(lp.PRESETS) >= 6)
for key, p in lp.PRESETS.items():
    ok = (p.key == key and p.locale and p.languages and p.currency
          and p.timezone and p.country_code and p.language_name
          and p.locale == p.languages[0])
    check(f"{key}: complete & self-consistent", ok)

# --- derivations -------------------------------------------------------------
print("\nderivations")
tok = lp.PRESETS["tokyo"]
check("tokyo Accept-Language", tok.accept_language() == "ja-JP,ja;q=0.9,en;q=0.8")
check("tokyo --lang value", tok.chromium_lang() == "ja-JP")
check("london Accept-Language", lp.PRESETS["london"].accept_language()
      == "en-GB,en;q=0.9")
check("label format", tok.label == "Tokyo, Japan")

# --- persistence round-trip (isolated file) ----------------------------------
print("\npersistence")
lp.CONFIG_FILE = Path(tempfile.mkdtemp()) / "location.json"
check("no file -> off", lp.load() == (False, False, None))
lp.save(True, False, lp.PRESETS["tokyo"])
en, gg, prof = lp.load()
check("save/load enabled tokyo, geo off", en and not gg and prof.key == "tokyo")
check("flag on -> --lang=ja-JP", lp.chromium_lang_flag() == " --lang=ja-JP")
lp.save(True, True, lp.PRESETS["tokyo"])
check("geo persists when set", lp.load()[1] is True)
check("geo requires enabled", lp.save(False, True, None) or lp.load()[1] is False)
lp.save(False, False, None)
check("save disabled -> off", lp.load() == (False, False, None))
check("flag off -> empty", lp.chromium_lang_flag() == "")
lp.CONFIG_FILE.write_text('{"enabled": true, "geo": true, "key": "atlantis"}',
                          encoding="utf-8")
check("unknown preset -> off", lp.load() == (False, False, None))

# --- spoof script generation -------------------------------------------------
print("\nspoof script")
js = lp.spoof_script(lp.PRESETS["tokyo"])
check("script embeds latitude", "35.6762" in js)
check("script embeds timezone", "Asia/Tokyo" in js)
check("script overrides geolocation", "getCurrentPosition" in js)
check("script overrides Intl timezone", "DateTimeFormat" in js and "timeZone" in js)
check("no unfilled placeholders",
      not any(p in js for p in ("__LAT__", "__TZ__", "__SITES__", "__GLOBAL__")))
check("script resolves per hostname", "location.hostname" in js)
js2 = lp.spoof_script(lp.PRESETS["london"], {"example.com": lp.PRESETS["tokyo"]})
check("per-site override embedded", "example.com" in js2 and "139.6503" in js2)
check("global fallback embedded", "51.5074" in js2)

# --- per-site overrides ------------------------------------------------------
print("\nper-site overrides")
lp.SITES_FILE = Path(tempfile.mkdtemp()) / "sites.json"
check("no file -> empty", lp.load_sites() == {})
lp.save_sites({"a.com": "tokyo", "b.com": "paris", "bad.com": "atlantis"})
sites = lp.load_sites()
check("known presets kept, unknown dropped",
      {h: p.key for h, p in sites.items()} == {"a.com": "tokyo", "b.com": "paris"})
check("effective: site override wins",
      lp.effective_profile("a.com", lp.PRESETS["london"], sites).key == "tokyo")
check("effective: falls back to global",
      lp.effective_profile("z.com", lp.PRESETS["london"], sites).key == "london")
check("effective: no global, no site -> None",
      lp.effective_profile("z.com", None, sites) is None)

# --- Match VPN location (ipapi.co response -> custom profile) -----------------
print("\nip-geo / custom profile")
prof = lp.from_ipgeo({
    "city": "Tokyo", "region": "Tokyo", "country_code": "JP",
    "country_name": "Japan", "latitude": 35.68, "longitude": 139.76,
    "timezone": "Asia/Tokyo", "currency": "JPY"})
check("from_ipgeo builds custom profile",
      prof is not None and prof.key == "custom" and prof.label == "Tokyo, Japan")
check("from_ipgeo guesses locale from country", prof.locale == "ja-JP")
check("from_ipgeo keeps timezone/coords",
      prof.timezone == "Asia/Tokyo" and abs(prof.latitude - 35.68) < 1e-6)
check("from_ipgeo error response -> None", lp.from_ipgeo({"error": True}) is None)
check("from_ipgeo missing country -> None", lp.from_ipgeo({"timezone": "UTC"}) is None)
# custom profile persists through save/load
lp.CONFIG_FILE = Path(tempfile.mkdtemp()) / "location.json"
lp.save(True, True, prof)
en, gg, back = lp.load()
check("custom profile round-trips",
      en and gg and back is not None and back.key == "custom"
      and back.city == "Tokyo" and back.locale == "ja-JP")

print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL LOCATION-PROFILE TESTS PASSED")
