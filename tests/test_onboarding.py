"""onboarding.py's is_first_run()/mark_onboarding_done() persistence --
pure Python, no Qt. Monkeypatches the module's own ONBOARDING_FILE
constant to a temp path, the same convention test_setting_protection.py
uses for this style of plain module-level marker file."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import onboarding


class OnboardingPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = onboarding.ONBOARDING_FILE
        onboarding.ONBOARDING_FILE = self.tmp / "onboarding.json"

    def tearDown(self):
        onboarding.ONBOARDING_FILE = self._orig

    def test_fresh_install_is_first_run(self):
        self.assertTrue(onboarding.is_first_run())

    def test_marking_done_persists_across_reload(self):
        self.assertTrue(onboarding.is_first_run())
        onboarding.mark_onboarding_done()
        self.assertFalse(onboarding.is_first_run())

    def test_marker_file_survives_a_fresh_check(self):
        onboarding.mark_onboarding_done()
        # A later launch re-reads from disk rather than any in-memory
        # state, so re-checking is_first_run() must still see it.
        self.assertFalse(onboarding.is_first_run())
        self.assertTrue(onboarding.ONBOARDING_FILE.exists())


if __name__ == "__main__":
    unittest.main()
