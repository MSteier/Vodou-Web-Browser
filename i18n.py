"""Vodou UI localization: a plain JSON string catalog per language, not
Qt's QTranslator/.ts/.qm pipeline.

Why not QTranslator: `pylupdate6` (which extracts tr() calls into .ts) is
available, but there is no `lrelease`/`pyside6-lrelease` anywhere in this
project's toolchain to compile a .ts into the .qm file QTranslator actually
loads, and getting one means installing PySide6 solely as a build-time
tool. Since these catalogs are machine-translated data rather than
something a human translator edits in Qt Linguist's GUI, a flat JSON map
per language is just as serviceable and needs no new dependency.

**Translations are machine-translated and have not been reviewed by a
native speaker of each language.**

Persistence is a plain, unsigned ~/.vodou/language.json -- not
security-sensitive, the same low-ceremony tier theme.py's own prefs use.
Changing the language always goes through main.py's existing
_prompt_restart()/_restart_app() flow (the same one used for the
region/locale --lang flag): nothing here does live retranslation, so
there is no QEvent.LanguageChange handling to get right.
"""

from __future__ import annotations

import json
from pathlib import Path

PREFS_FILE = Path.home() / ".vodou" / "language.json"
_CATALOG_DIR = Path(__file__).resolve().parent / "translations"

# Display name -> language code. English has no catalog file (it IS the
# source text), so it's never looked up, only ever the identity case.
LANGUAGES: dict[str, str] = {
    "English": "en",
    "Spanish": "es",
    "French": "fr",
    "German": "de",
    "Portuguese": "pt",
    "Chinese": "zh",
    "Japanese": "ja",
    "Russian": "ru",
    "Arabic": "ar",
}
DEFAULT_LANGUAGE = "en"

_current = DEFAULT_LANGUAGE
_catalogs: dict[str, dict[str, str]] = {}


def load_prefs() -> str:
    """Return the saved language code, falling back to English on any
    problem or an unrecognized code."""
    try:
        data = json.loads(PREFS_FILE.read_text(encoding="utf-8"))
        code = data.get("language", DEFAULT_LANGUAGE)
        return code if code in LANGUAGES.values() else DEFAULT_LANGUAGE
    except (OSError, ValueError, TypeError):
        return DEFAULT_LANGUAGE


def save_prefs(code: str) -> None:
    try:
        PREFS_FILE.parent.mkdir(parents=True, exist_ok=True)
        PREFS_FILE.write_text(json.dumps({"language": code}), encoding="utf-8")
    except OSError:
        pass  # a non-writable config dir must not break the language setting


def set_language(code: str) -> None:
    """Set the active language for tr(). Read once at startup from the
    saved pref -- see the module docstring for why this never needs to
    change the running UI live."""
    global _current
    _current = code if code in LANGUAGES.values() else DEFAULT_LANGUAGE


def current_language() -> str:
    return _current


def _catalog(code: str) -> dict[str, str]:
    if code not in _catalogs:
        try:
            path = _CATALOG_DIR / f"{code}.json"
            _catalogs[code] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            _catalogs[code] = {}
    return _catalogs[code]


def tr(text: str) -> str:
    """Translate `text` into the active language. Falls back to `text`
    itself on a missing catalog, a missing key, or English -- a stale or
    incomplete catalog degrades to English for just the missing strings,
    never raises and never breaks the caller."""
    if _current == DEFAULT_LANGUAGE:
        return text
    return _catalog(_current).get(text, text)
