"""Multi-language spell check for page content, via QWebEngineProfile's
built-in Chromium/Hunspell spellchecker.

Not security-sensitive (same low-ceremony tier as theme.py's own prefs),
so the choice is a plain, unsigned ~/.vodou/spellcheck.json -- the same
load/save-with-fallback-to-defaults shape theme.py uses.

Only languages with a dictionary bundled in dictionaries/ (see that
directory's README.md) are offered: Chromium's Hunspell-based spellchecker
has no dictionary at all for Chinese, Japanese, or Arabic, so listing them
here would silently do nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

PREFS_FILE = Path.home() / ".vodou" / "spellcheck.json"

# Label -> Chromium dictionary code, matching the bundled .bdic filename's
# <lang>-<REGION> prefix exactly (see dictionaries/README.md).
AVAILABLE_LANGUAGES: dict[str, str] = {
    "English (US)": "en-US",
    "Spanish": "es-ES",
    "French": "fr-FR",
    "German": "de-DE",
    "Portuguese (Brazil)": "pt-BR",
    "Portuguese (Portugal)": "pt-PT",
    "Russian": "ru-RU",
}
DEFAULT_ENABLED = False
DEFAULT_LANGUAGES: list[str] = ["en-US"]


def load_prefs() -> tuple[bool, list[str]]:
    """Return (enabled, languages), falling back to defaults on any problem."""
    try:
        data = json.loads(PREFS_FILE.read_text(encoding="utf-8"))
        enabled = bool(data.get("enabled", DEFAULT_ENABLED))
        languages = [
            code for code in data.get("languages", DEFAULT_LANGUAGES)
            if code in AVAILABLE_LANGUAGES.values()
        ]
        return enabled, (languages or list(DEFAULT_LANGUAGES))
    except (OSError, ValueError, TypeError):
        return DEFAULT_ENABLED, list(DEFAULT_LANGUAGES)


def save_prefs(enabled: bool, languages: list[str]) -> None:
    try:
        PREFS_FILE.parent.mkdir(parents=True, exist_ok=True)
        PREFS_FILE.write_text(
            json.dumps({"enabled": enabled, "languages": languages}),
            encoding="utf-8")
    except OSError:
        pass  # a non-writable config dir must not break spell check


def apply(profile, enabled: bool, languages: list[str]) -> None:
    """Push (enabled, languages) onto a live QWebEngineProfile."""
    profile.setSpellCheckEnabled(enabled)
    if enabled:
        profile.setSpellCheckLanguages(languages)
