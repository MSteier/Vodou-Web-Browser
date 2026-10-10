"""spellcheck.py's load_prefs()/save_prefs() persistence and apply() --
pure Python, no Qt (apply() is exercised against a stub profile object, not
a real QWebEngineProfile). Monkeypatches the module's own PREFS_FILE
constant to a temp path, the same convention test_onboarding.py uses for
this style of plain, unsigned prefs file."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import spellcheck


class _StubProfile:
    def __init__(self):
        self.enabled = None
        self.languages = None

    def setSpellCheckEnabled(self, enabled):
        self.enabled = enabled

    def setSpellCheckLanguages(self, languages):
        self.languages = list(languages)


class SpellcheckPrefsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = spellcheck.PREFS_FILE
        spellcheck.PREFS_FILE = self.tmp / "spellcheck.json"

    def tearDown(self):
        spellcheck.PREFS_FILE = self._orig

    def test_defaults_when_no_file_exists(self):
        enabled, languages = spellcheck.load_prefs()
        self.assertEqual(enabled, spellcheck.DEFAULT_ENABLED)
        self.assertEqual(languages, spellcheck.DEFAULT_LANGUAGES)

    def test_round_trip(self):
        spellcheck.save_prefs(True, ["es-ES", "fr-FR"])
        enabled, languages = spellcheck.load_prefs()
        self.assertTrue(enabled)
        self.assertEqual(sorted(languages), ["es-ES", "fr-FR"])

    def test_unknown_language_codes_are_dropped(self):
        spellcheck.PREFS_FILE.parent.mkdir(parents=True, exist_ok=True)
        spellcheck.PREFS_FILE.write_text(
            '{"enabled": true, "languages": ["es-ES", "zh-CN"]}',
            encoding="utf-8")
        enabled, languages = spellcheck.load_prefs()
        self.assertTrue(enabled)
        self.assertEqual(languages, ["es-ES"])

    def test_empty_language_list_falls_back_to_default(self):
        spellcheck.save_prefs(True, [])
        _, languages = spellcheck.load_prefs()
        self.assertEqual(languages, spellcheck.DEFAULT_LANGUAGES)

    def test_malformed_file_falls_back_to_defaults(self):
        spellcheck.PREFS_FILE.parent.mkdir(parents=True, exist_ok=True)
        spellcheck.PREFS_FILE.write_text("not json", encoding="utf-8")
        enabled, languages = spellcheck.load_prefs()
        self.assertEqual(enabled, spellcheck.DEFAULT_ENABLED)
        self.assertEqual(languages, spellcheck.DEFAULT_LANGUAGES)


class SpellcheckApplyTests(unittest.TestCase):
    def test_apply_enabled_sets_languages(self):
        profile = _StubProfile()
        spellcheck.apply(profile, True, ["de-DE", "ru-RU"])
        self.assertTrue(profile.enabled)
        self.assertEqual(sorted(profile.languages), ["de-DE", "ru-RU"])

    def test_apply_disabled_does_not_touch_languages(self):
        profile = _StubProfile()
        spellcheck.apply(profile, False, ["de-DE"])
        self.assertFalse(profile.enabled)
        self.assertIsNone(profile.languages)


if __name__ == "__main__":
    unittest.main()
