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
check("no unfilled placeholders", "__LAT__" not in js and "__TZ__" not in js)

print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL LOCATION-PROFILE TESTS PASSED")
