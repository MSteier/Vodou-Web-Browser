"""ai_search.translate_prompt(): pure string checks, no network, no Qt
event loop needed (OllamaClient.translate() itself just forwards this
string into the existing _start() streaming path, already covered by
manual/integration testing of Ask/Summarize)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ai_search


class TranslatePromptTests(unittest.TestCase):
    def test_includes_target_language_and_text(self):
        prompt = ai_search.translate_prompt("Bonjour le monde", "English")
        self.assertIn("English", prompt)
        self.assertIn("Bonjour le monde", prompt)

    def test_instructs_translation_only_no_preamble(self):
        prompt = ai_search.translate_prompt("hello", "Spanish")
        self.assertIn("ONLY", prompt)
        self.assertIn("no preamble", prompt)

    def test_truncates_very_long_text(self):
        long_text = "x" * (ai_search.TRANSLATE_MAX_CHARS + 500)
        prompt = ai_search.translate_prompt(long_text, "German")
        self.assertNotIn("x" * (ai_search.TRANSLATE_MAX_CHARS + 1), prompt)
        self.assertIn("x" * ai_search.TRANSLATE_MAX_CHARS, prompt)

    def test_short_text_is_not_truncated(self):
        prompt = ai_search.translate_prompt("short text", "French")
        self.assertIn("short text", prompt)


if __name__ == "__main__":
    unittest.main()
