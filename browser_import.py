"""Import bookmarks and saved passwords directly from an installed Chrome or
Edge profile -- no manual CSV/HTML export step first.

Windows only (both browsers' saved-password encryption is DPAPI-rooted on
this platform; a different approach would be needed elsewhere). Firefox is
deliberately out of scope: its NSS/key4.db format is a different, harder
problem and not worth coupling to this module.

Security note: this reads another application's own on-disk secrets using
the same Windows DPAPI mechanism that application used to protect them --
exactly what "logged in as this user" already grants, the same boundary
dpapi.py documents for Vodou's own state. The raw DPAPI call is written
fresh here rather than reusing dpapi.py's private helper: that module's own
docstring draws an explicit line ("not for passwords ... must never fall
back to this") about *protecting Vodou's own data*, which is a different
operation from *reading a blob Chrome itself already protected*. Keeping
that boundary unambiguous matters more than saving ~15 lines.

Both the bookmarks file and the passwords database are copied to a temp
file before being read, never opened live -- a running browser can hold an
exclusive lock on "Login Data", and copying first means this never fights
over it (nor risks corrupting it; this module never writes to the source
browser's own files).
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import tempfile
from base64 import b64decode
from dataclasses import dataclass
from pathlib import Path

from bookmarks import Bookmark
from vault import Entry, normalize_site

MAX_BOOKMARKS = 20_000
MAX_FIELD = 8192

_DPAPI_KEY_PREFIX = b"DPAPI"


@dataclass(frozen=True)
class BrowserProfile:
    browser: str   # "Chrome" or "Edge"
    name: str      # "Default", "Profile 1", ...
    path: Path     # .../User Data/<name>


def _default_base_dirs() -> dict[str, Path]:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return {}
    local = Path(local)
    return {
        "Chrome": local / "Google" / "Chrome" / "User Data",
        "Edge": local / "Microsoft" / "Edge" / "User Data",
    }


def detect_profiles(base_dirs: dict[str, str | Path] | None = None) -> list[BrowserProfile]:
    """Every profile folder (under each browser's "User Data") that has a
    Bookmarks file and/or a Login Data file. base_dirs is injectable so
    tests can point this at a synthetic tree instead of the real one."""
    if sys.platform != "win32":
        return []
    dirs = base_dirs if base_dirs is not None else _default_base_dirs()
    found: list[BrowserProfile] = []
    for browser, base in dirs.items():
        base = Path(base)
        if not base.is_dir():
            continue
        for entry in sorted(base.iterdir()):
            if not entry.is_dir():
                continue
            if entry.name != "Default" and not entry.name.startswith("Profile "):
                continue
            if (entry / "Bookmarks").is_file() or (entry / "Login Data").is_file():
                found.append(BrowserProfile(browser=browser, name=entry.name, path=entry))
    return found


def _dpapi_unprotect(blob: bytes) -> bytes:
    """Decrypt a DPAPI blob (CryptUnprotectData) for the current Windows
    user -- the same key Chrome/Edge itself used to protect it."""
    from ctypes import (POINTER, Structure, byref, c_char, cast,
                        create_string_buffer, string_at, windll)
    from ctypes.wintypes import DWORD

    class _Blob(Structure):
        _fields_ = [("cbData", DWORD), ("pbData", POINTER(c_char))]

    buf = create_string_buffer(blob, len(blob))
    blob_in = _Blob(len(blob), cast(buf, POINTER(c_char)))
    blob_out = _Blob()
    if not windll.crypt32.CryptUnprotectData(
            byref(blob_in), None, None, None, None, 0, byref(blob_out)):
        raise OSError("DPAPI unprotect failed")
    try:
        return string_at(blob_out.pbData, blob_out.cbData)
    finally:
        windll.kernel32.LocalFree(blob_out.pbData)


def _get_aes_key(profile: BrowserProfile) -> bytes | None:
    """The AES-256 key Chrome/Edge uses for v10/v11 password encryption,
    recovered from "Local State" (a sibling of the profile folder, shared
    across all profiles of one browser install). None if unavailable --
    callers then fall back to treating every row as legacy-format."""
    local_state_path = profile.path.parent / "Local State"
    try:
        data = json.loads(local_state_path.read_text(encoding="utf-8"))
        encoded_key = data["os_crypt"]["encrypted_key"]
    except (OSError, ValueError, KeyError):
        return None
    try:
        raw = b64decode(encoded_key)
    except (ValueError, TypeError):
        return None
    if not raw.startswith(_DPAPI_KEY_PREFIX):
        return None
    try:
        return _dpapi_unprotect(raw[len(_DPAPI_KEY_PREFIX):])
    except OSError:
        return None


def _copy_to_temp(path: Path) -> Path:
    tmp_dir = Path(tempfile.mkdtemp(prefix="vodou-import-"))
    dest = tmp_dir / path.name
    shutil.copy2(path, dest)
    return dest


def _walk_bookmark_nodes(node: dict) -> list[Bookmark]:
    found: list[Bookmark] = []
    node_type = node.get("type")
    if node_type == "url":
        url = node.get("url", "")
        if url.lower().startswith(("http://", "https://")) and len(url) <= MAX_FIELD:
            title = (node.get("name") or url)[:MAX_FIELD]
            found.append(Bookmark(title=title, url=url))
    elif node_type == "folder":
        for child in node.get("children", []):
            if len(found) >= MAX_BOOKMARKS:
                break
            found.extend(_walk_bookmark_nodes(child))
    return found[:MAX_BOOKMARKS]


def import_bookmarks_from(profile: BrowserProfile) -> list[Bookmark]:
    """Bookmarks from this profile's Bookmarks file. Empty list if the
    profile simply has none; raises OSError only on a genuine read/parse
    failure of a file that does exist."""
    source = profile.path / "Bookmarks"
    if not source.is_file():
        return []
    tmp_dir = None
    try:
        copied = _copy_to_temp(source)
        tmp_dir = copied.parent
        data = json.loads(copied.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise OSError(f"Could not read bookmarks: {error}") from error
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    found: list[Bookmark] = []
    for root in data.get("roots", {}).values():
        if isinstance(root, dict):
            found.extend(_walk_bookmark_nodes(root))
    seen: set[str] = set()
    unique: list[Bookmark] = []
    for b in found:
        if b.url not in seen:
            seen.add(b.url)
            unique.append(b)
    return unique[:MAX_BOOKMARKS]


def _decrypt_password(blob: bytes, key: bytes | None) -> str | None:
    if blob[:3] in (b"v10", b"v11") and key is not None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce, ciphertext = blob[3:15], blob[15:]
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8", "replace")
        except Exception:
            return None
    if blob[:3] in (b"v10", b"v11"):
        return None  # new-format row but no key available
    try:
        return _dpapi_unprotect(blob).decode("utf-8", "replace")
    except OSError:
        return None


def import_passwords_from(profile: BrowserProfile) -> tuple[list[Entry], int]:
    """(entries, skipped_count) from this profile's Login Data. Empty list
    if the profile simply has none saved; raises OSError only on a genuine
    read failure of a file that does exist."""
    source = profile.path / "Login Data"
    if not source.is_file():
        return [], 0

    key = _get_aes_key(profile)
    tmp_dir = None
    entries: list[Entry] = []
    skipped = 0
    try:
        copied = _copy_to_temp(source)
        tmp_dir = copied.parent
        conn = sqlite3.connect(str(copied))
        try:
            rows = conn.execute(
                "SELECT origin_url, username_value, password_value "
                "FROM logins").fetchall()
        finally:
            conn.close()
    except (OSError, sqlite3.Error) as error:
        raise OSError(f"Could not read saved passwords: {error}") from error
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    for origin_url, username, password_blob in rows:
        password = _decrypt_password(bytes(password_blob), key) if password_blob else ""
        site = normalize_site(origin_url or "")
        if (not password or not site or not username
                or any(len(v) > MAX_FIELD for v in (password, username, site))):
            skipped += 1
            continue
        entries.append(Entry(site=site, username=username, password=password))
    return entries, skipped
