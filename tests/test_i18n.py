"""i18n.py's tr()/load_prefs()/save_prefs() -- pure Python, no Qt -- plus a
catalog-consistency check against main.py's actual tr() call sites.

The consistency check is AST-based rather than constructing a real
BrowserWindow: BrowserWindow.__init__ does a lot of real-world setup
(single-instance locking, a live QWebEngineProfile, vault/safe-browsing
state) and reliably crashes the interpreter when built outside main()'s
normal startup sequence -- confirmed while developing this feature. A
static scan of main.py's source for tr(...) calls needs no Qt event loop
and can't suffer that crash.

Phase 1 (this feature) only wraps main.py's menu tree; the dynamic-arg
call sites below are each menus/toolbars.py's name/label loop variable
iterating a real module-level dict/tuple -- see each comment. As later
phases wrap more files, extend EXPECTED_DYNAMIC_VALUES and this docstring
rather than re-deriving it from scratch.
"""
import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import i18n

# Mirrors main.py's SEARCH_ENGINES keys, TRANSLATE_LANGUAGES tuple,
# spellcheck.AVAILABLE_LANGUAGES keys, i18n.LANGUAGES keys, theme.THEMES
# keys, and _build_appearance_menu's inline dark/light mode labels -- the
# six dict/tuple collections whose displayed members are passed to tr()
# via a loop variable (name/label), not a literal, so the AST scan below
# can't see their value directly.
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
)
# Real trademarked product names -- deliberately never translated, so
# they're excluded from every catalog and left to tr()'s English fallback.
BRAND_NAMES = {"DuckDuckGo", "Startpage", "Brave Search", "Google"}


def _tr_call_strings_in_main() -> set[str]:
    """Every literal string passed to a bare tr(...) call in main.py."""
    tree = ast.parse((ROOT / "main.py").read_text(encoding="utf-8"),
                      filename="main.py")
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
    """Every shipped catalog must exactly match what main.py's Phase 1
    tr() call sites actually need -- catches a catalog drifting out of
    sync (stale key after a source string changes, or a typo'd key that
    silently never matches anything) in either direction."""

    @classmethod
    def setUpClass(cls):
        cls.expected = ((_tr_call_strings_in_main() | EXPECTED_DYNAMIC_VALUES)
                        - BRAND_NAMES)

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
        """A translation of a string with a {placeholder} must keep that
        exact token, or str.format() at the call site breaks."""
        for key in self.expected:
            if "{" not in key:
                continue
            for code in ("es", "fr", "de", "pt", "zh", "ja", "ru", "ar"):
                path = ROOT / "translations" / f"{code}.json"
                catalog = json.loads(path.read_text(encoding="utf-8"))
                with self.subTest(language=code, key=key):
                    self.assertIn("{name}", catalog[key])


if __name__ == "__main__":
    unittest.main()
