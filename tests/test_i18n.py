"""i18n.py's tr()/load_prefs()/save_prefs() -- pure Python, no Qt -- plus a
catalog-consistency check against every wrapped file's actual tr() call
sites (main.py's ☰ menu tree, Phase 1; vault_ui.py, Phase 2).

The consistency check is AST-based rather than constructing the real
widgets: BrowserWindow.__init__ does a lot of real-world setup
(single-instance locking, a live QWebEngineProfile, vault/safe-browsing
state) and reliably crashes the interpreter when built outside main()'s
normal startup sequence -- confirmed while developing this feature. A
static scan of each file's source for tr(...) calls needs no Qt event
loop and can't suffer that crash. (VaultDialog itself CAN be built
offscreen with a fake vault -- see test_two_factor_toggle.py -- but the
AST approach stays consistent across every wrapped file, including
BrowserWindow, which can't.)

As later phases wrap more files, add that file to WRAPPED_FILES and any
new dict/tuple-iteration dynamic values to EXPECTED_DYNAMIC_VALUES below,
rather than re-deriving this from scratch.
"""
import ast
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import i18n

# Every file whose tr() call sites feed the shipped catalogs so far.
WRAPPED_FILES = ("main.py", "vault_ui.py")

# Dict/tuple collections whose displayed members are passed to tr() via a
# loop variable (name/label), not a literal, so the AST scan below can't
# see their value directly:
#   main.py: SEARCH_ENGINES keys, TRANSLATE_LANGUAGES tuple,
#   spellcheck.AVAILABLE_LANGUAGES keys, i18n.LANGUAGES keys, theme.THEMES
#   keys, _build_appearance_menu's inline dark/light mode labels.
#   vault_ui.py: password_strength.analyze()'s result.label values,
#   vault_autolock.VAULT_AUTOLOCK_OPTIONS labels.
EXPECTED_DYNAMIC_VALUES = (
    {"SearXNG (local, private)", "DuckDuckGo", "Startpage", "Brave Search",
     "Google"}
    | {"English", "Spanish", "French", "German", "Portuguese", "Chinese",
       "Japanese", "Russian", "Arabic"}
    | {"English (US)", "Spanish", "French", "German",
       "Portuguese (Brazil)", "Portuguese (Portugal)", "Russian"}
    | {"Vodou Violet", "Blood Ritual", "Swamp Green", "Midnight Blue",
       "Bone Amber", "Spider Web Grey", "Ghost White"}
    | {"\U0001F319  Dark mode", "☀  Light mode"}
    | {"Weak", "Moderate", "Strong"}
    | {"5 minutes", "2 hours", "1 day", "1 week"}
)
# Real trademarked product names -- deliberately never translated, so
# they're excluded from every catalog and left to tr()'s English fallback.
BRAND_NAMES = {"DuckDuckGo", "Startpage", "Brave Search", "Google"}

_PLACEHOLDER_RE = re.compile(r"\{[a-zA-Z_][a-zA-Z0-9_]*(?::[^}]*)?\}")


def _tr_call_strings(path: Path) -> set[str]:
    """Every literal string passed to a bare tr(...) call in `path`."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
    found = set()

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node):
            if (isinstance(node.func, ast.Name) and node.func.id == "tr"
                    and len(node.args) == 1):
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    found.add(arg.value)
            self.generic_visit(node)

    Visitor().visit(tree)
    return found


def _all_tr_call_strings() -> set[str]:
    found = set()
    for name in WRAPPED_FILES:
        found |= _tr_call_strings(ROOT / name)
    return found


class TrFallbackTests(unittest.TestCase):
    def setUp(self):
        self._orig_current = i18n.current_language()
        self._orig_catalogs = dict(i18n._catalogs)

    def tearDown(self):
        i18n.set_language(self._orig_current)
        i18n._catalogs.clear()
        i18n._catalogs.update(self._orig_catalogs)

    def test_english_is_always_identity(self):
        i18n.set_language("en")
        self.assertEqual(i18n.tr("Settings"), "Settings")
        self.assertEqual(i18n.tr("Nonexistent string"), "Nonexistent string")

    def test_missing_catalog_file_falls_back_to_english(self):
        i18n.set_language("es")
        i18n._catalogs.pop("es", None)
        orig_dir = i18n._CATALOG_DIR
        i18n._CATALOG_DIR = Path(tempfile.mkdtemp())  # empty, no es.json
        try:
            self.assertEqual(i18n.tr("Settings"), "Settings")
        finally:
            i18n._CATALOG_DIR = orig_dir

    def test_missing_key_falls_back_to_english(self):
        i18n.set_language("es")
        i18n._catalogs["es"] = {"Settings": "Configuración"}
        self.assertEqual(i18n.tr("Settings"), "Configuración")
        self.assertEqual(i18n.tr("Some new untranslated string"),
                          "Some new untranslated string")

    def test_unrecognized_language_code_falls_back_to_english(self):
        i18n.set_language("xx")
        self.assertEqual(i18n.current_language(), i18n.DEFAULT_LANGUAGE)


class PrefsPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = i18n.PREFS_FILE
        i18n.PREFS_FILE = self.tmp / "language.json"

    def tearDown(self):
        i18n.PREFS_FILE = self._orig

    def test_defaults_when_no_file_exists(self):
        self.assertEqual(i18n.load_prefs(), i18n.DEFAULT_LANGUAGE)

    def test_round_trip(self):
        i18n.save_prefs("fr")
        self.assertEqual(i18n.load_prefs(), "fr")

    def test_unknown_code_on_disk_falls_back_to_default(self):
        i18n.PREFS_FILE.parent.mkdir(parents=True, exist_ok=True)
        i18n.PREFS_FILE.write_text('{"language": "xx"}', encoding="utf-8")
        self.assertEqual(i18n.load_prefs(), i18n.DEFAULT_LANGUAGE)

    def test_malformed_file_falls_back_to_default(self):
        i18n.PREFS_FILE.parent.mkdir(parents=True, exist_ok=True)
        i18n.PREFS_FILE.write_text("not json", encoding="utf-8")
        self.assertEqual(i18n.load_prefs(), i18n.DEFAULT_LANGUAGE)


class CatalogConsistencyTests(unittest.TestCase):
    """Every shipped catalog must exactly match what every wrapped file's
    tr() call sites actually need -- catches a catalog drifting out of
    sync (stale key after a source string changes, or a typo'd key that
    silently never matches anything) in either direction."""

    @classmethod
    def setUpClass(cls):
        cls.expected = (_all_tr_call_strings() | EXPECTED_DYNAMIC_VALUES) - BRAND_NAMES

    def test_all_catalogs_match_expected_keys_exactly(self):
        for code in ("es", "fr", "de", "pt", "zh", "ja", "ru", "ar"):
            with self.subTest(language=code):
                path = ROOT / "translations" / f"{code}.json"
                catalog = json.loads(path.read_text(encoding="utf-8"))
                keys = set(catalog.keys())
                self.assertEqual(
                    keys, self.expected,
                    f"{code}.json keys don't match tr() call sites: "
                    f"missing={self.expected - keys} "
                    f"extra={keys - self.expected}")

    def test_no_catalog_entry_is_empty(self):
        for code in ("es", "fr", "de", "pt", "zh", "ja", "ru", "ar"):
            path = ROOT / "translations" / f"{code}.json"
            catalog = json.loads(path.read_text(encoding="utf-8"))
            for key, value in catalog.items():
                with self.subTest(language=code, key=key):
                    self.assertTrue(value.strip())

    def test_placeholder_tokens_preserved_in_every_translation(self):
        """A translation of a string with {placeholder} tokens must keep
        every one of those exact tokens, or str.format() at the call site
        breaks (KeyError for a dropped one; a silently wrong substitution
        for anything else)."""
        for key in self.expected:
            placeholders = set(_PLACEHOLDER_RE.findall(key))
            if not placeholders:
                continue
            for code in ("es", "fr", "de", "pt", "zh", "ja", "ru", "ar"):
                path = ROOT / "translations" / f"{code}.json"
                catalog = json.loads(path.read_text(encoding="utf-8"))
                with self.subTest(language=code, key=key):
                    translated = catalog[key]
                    for placeholder in placeholders:
                        self.assertIn(placeholder, translated)


if __name__ == "__main__":
    unittest.main()
