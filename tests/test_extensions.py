"""ExtensionStore persistence -- pure Python, no Qt. See
tests/manual_verify_extensions.py for the real QWebEngineExtensionManager
behavior this backs (why that one isn't run here or in CI)."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from extensions import ExtensionStore


class ExtensionStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.store_path = self.tmpdir / "extensions.json"

    def test_round_trips_across_reload(self):
        store = ExtensionStore(path=self.store_path)
        self.assertEqual(store.records(), [])

        record = store.add("/fake/ext.zip", "Fake Ext")
        self.assertTrue(record.enabled)

        reloaded = ExtensionStore(path=self.store_path)
        self.assertEqual(len(reloaded.records()), 1)
        self.assertEqual(reloaded.records()[0].source_path, "/fake/ext.zip")
        self.assertEqual(len(reloaded.enabled_records()), 1)

    def test_disable_and_error_persist(self):
        store = ExtensionStore(path=self.store_path)
        record = store.add("/fake/ext.zip", "Fake Ext")

        store.set_enabled(record.id, False)
        reloaded = ExtensionStore(path=self.store_path)
        self.assertEqual(reloaded.enabled_records(), [])
        self.assertEqual(len(reloaded.records()), 1)

        store.set_error(record.id, "Unsupported manifest version")
        reloaded2 = ExtensionStore(path=self.store_path)
        self.assertEqual(
            reloaded2.records()[0].last_error, "Unsupported manifest version")

    def test_remove_persists(self):
        store = ExtensionStore(path=self.store_path)
        record = store.add("/fake/ext.zip", "Fake Ext")
        store.remove(record.id)
        reloaded = ExtensionStore(path=self.store_path)
        self.assertEqual(reloaded.records(), [])


if __name__ == "__main__":
    unittest.main()
