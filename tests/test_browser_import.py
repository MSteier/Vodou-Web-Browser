"""browser_import.py: profile detection, bookmark parsing (portable), and a
full synthetic Chrome-format password round-trip (Windows-only, since it
exercises the real DPAPI mechanism -- see tests/test_platform.py's own
DPAPI round-trip for the same gating precedent)."""
import base64
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import browser_import as bi

WINDOWS = sys.platform == "win32"


class DetectProfilesTests(unittest.TestCase):
    """Windows-only: detect_profiles() itself short-circuits to [] on any
    other platform (browser_import.py), so there is nothing to detect."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    @unittest.skipUnless(WINDOWS, "detect_profiles() is a no-op off Windows")
    def test_finds_profiles_with_bookmarks_or_logins(self):
        chrome = self.tmp / "Chrome"
        (chrome / "Default").mkdir(parents=True)
        (chrome / "Default" / "Bookmarks").write_text("{}", encoding="utf-8")
        (chrome / "Profile 1").mkdir(parents=True)
        (chrome / "Profile 1" / "Login Data").write_bytes(b"")
        (chrome / "Profile 2").mkdir(parents=True)  # neither file -- skipped
        (chrome / "not_a_profile_dir").mkdir(parents=True)
        (chrome / "not_a_profile_dir" / "Bookmarks").write_text("{}", encoding="utf-8")

        found = bi.detect_profiles({"Chrome": chrome})
        names = sorted(p.name for p in found)
        self.assertEqual(names, ["Default", "Profile 1"])
        self.assertTrue(all(p.browser == "Chrome" for p in found))

    @unittest.skipUnless(WINDOWS, "detect_profiles() is a no-op off Windows")
    def test_missing_base_dir_is_empty_not_an_error(self):
        found = bi.detect_profiles({"Chrome": self.tmp / "does_not_exist"})
        self.assertEqual(found, [])

    def test_non_windows_returns_empty_regardless_of_input(self):
        if WINDOWS:
            self.skipTest("only meaningful off Windows")
        found = bi.detect_profiles({"Chrome": self.tmp})
        self.assertEqual(found, [])


class BookmarkParsingTests(unittest.TestCase):
    """Portable: pure JSON parsing, no crypto, runs on every OS."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.profile_dir = self.tmp / "Default"
        self.profile_dir.mkdir()
        self.profile = bi.BrowserProfile(browser="Chrome", name="Default",
                                         path=self.profile_dir)

    def _write_bookmarks(self, data: dict) -> None:
        (self.profile_dir / "Bookmarks").write_text(
            json.dumps(data), encoding="utf-8")

    def test_walks_folders_and_keeps_only_http_urls(self):
        self._write_bookmarks({
            "roots": {
                "bookmark_bar": {
                    "type": "folder",
                    "children": [
                        {"type": "url", "name": "Example", "url": "https://example.com/"},
                        {"type": "url", "name": "JS", "url": "javascript:alert(1)"},
                        {"type": "folder", "children": [
                            {"type": "url", "name": "Nested", "url": "http://nested.example/"},
                        ]},
                    ],
                },
                "other": {"type": "folder", "children": []},
            }
        })
        found = bi.import_bookmarks_from(self.profile)
        urls = sorted(b.url for b in found)
        self.assertEqual(urls, ["http://nested.example/", "https://example.com/"])

    def test_dedupes_by_url(self):
        self._write_bookmarks({
            "roots": {
                "bookmark_bar": {"type": "folder", "children": [
                    {"type": "url", "name": "A", "url": "https://dup.example/"},
                    {"type": "url", "name": "A again", "url": "https://dup.example/"},
                ]},
            }
        })
        found = bi.import_bookmarks_from(self.profile)
        self.assertEqual(len(found), 1)

    def test_no_bookmarks_file_returns_empty_not_an_error(self):
        found = bi.import_bookmarks_from(self.profile)
        self.assertEqual(found, [])

    def test_malformed_json_raises_oserror(self):
        (self.profile_dir / "Bookmarks").write_text("not json", encoding="utf-8")
        with self.assertRaises(OSError):
            bi.import_bookmarks_from(self.profile)


@unittest.skipUnless(WINDOWS, "exercises real Windows DPAPI")
class PasswordRoundTripTests(unittest.TestCase):
    """Builds a fully synthetic Chrome-format profile -- a Local State with
    a DPAPI-protected AES key (constructed the same way Chrome itself
    would, via CryptProtectData) and a Login Data SQLite db with one row
    AES-256-GCM-encrypted under that key in the real v10 wire format --
    and confirms import_passwords_from recovers the original password.
    No real Chrome/Edge install needed."""

    @staticmethod
    def _dpapi_protect(data: bytes) -> bytes:
        from ctypes import (POINTER, Structure, byref, c_char, cast,
                            create_string_buffer, string_at, windll)
        from ctypes.wintypes import DWORD

        class _Blob(Structure):
            _fields_ = [("cbData", DWORD), ("pbData", POINTER(c_char))]

        buf = create_string_buffer(data, len(data))
        blob_in = _Blob(len(data), cast(buf, POINTER(c_char)))
        blob_out = _Blob()
        if not windll.crypt32.CryptProtectData(
                byref(blob_in), None, None, None, None, 0, byref(blob_out)):
            raise OSError("DPAPI protect failed")
        try:
            return string_at(blob_out.pbData, blob_out.cbData)
        finally:
            windll.kernel32.LocalFree(blob_out.pbData)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.user_data = self.tmp / "User Data"
        self.profile_dir = self.user_data / "Default"
        self.profile_dir.mkdir(parents=True)
        self.profile = bi.BrowserProfile(browser="Chrome", name="Default",
                                         path=self.profile_dir)

        self.aes_key = os.urandom(32)
        protected_key = self._dpapi_protect(self.aes_key)
        encoded = base64.b64encode(b"DPAPI" + protected_key).decode("ascii")
        (self.user_data / "Local State").write_text(
            json.dumps({"os_crypt": {"encrypted_key": encoded}}), encoding="utf-8")

    def _write_login_data(self, rows: list[tuple[str, str, bytes]]) -> None:
        db_path = self.profile_dir / "Login Data"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE logins (origin_url TEXT, username_value TEXT, "
                     "password_value BLOB)")
        conn.executemany("INSERT INTO logins VALUES (?, ?, ?)", rows)
        conn.commit()
        conn.close()

    def _encrypt_v10(self, plaintext: str) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        ct = AESGCM(self.aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
        return b"v10" + nonce + ct

    def test_recovers_original_password(self):
        self._write_login_data([
            ("https://example.com/login", "alice", self._encrypt_v10("hunter2")),
        ])
        entries, skipped = bi.import_passwords_from(self.profile)
        self.assertEqual(skipped, 0)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].site, "example.com")
        self.assertEqual(entries[0].username, "alice")
        self.assertEqual(entries[0].password, "hunter2")

    def test_wrong_key_row_is_skipped_not_crashed(self):
        other_key = os.urandom(32)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        bad_blob = b"v10" + nonce + AESGCM(other_key).encrypt(nonce, b"nope", None)
        self._write_login_data([("https://example.com/", "bob", bad_blob)])
        entries, skipped = bi.import_passwords_from(self.profile)
        self.assertEqual(entries, [])
        self.assertEqual(skipped, 1)

    def test_no_login_data_file_returns_empty_not_an_error(self):
        entries, skipped = bi.import_passwords_from(self.profile)
        self.assertEqual((entries, skipped), ([], 0))

    def test_aes_key_recovered_matches_what_was_protected(self):
        self.assertEqual(bi._get_aes_key(self.profile), self.aes_key)


if __name__ == "__main__":
    unittest.main()
