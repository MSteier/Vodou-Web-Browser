"""At-rest encryption for the small state Vodou keeps between sessions.

Windows DPAPI (CryptProtectData) seals data with a key derived from the
logged-in Windows account — the same per-user OS encryption Chrome uses for
its cookie database. No password prompt, and another Windows account (or a
lifted disk) can't read it.

Honest limit: like Chrome's jar, anything running *as this user* can ask
DPAPI to unseal it. This raises the bar against other accounts and offline
disk access; it is not protection from software running as you. On
non-Windows platforms the payload is written unencrypted behind a magic
header — callers document that.

Not for passwords: the vault has its own master-password-derived key
(vault.py) and must never fall back to this.
"""

from __future__ import annotations

import sys

_MAGIC = b"VODOUJAR1\n"  # marks the plaintext (non-Windows) fallback


def _dpapi(data: bytes, protect: bool) -> bytes:
    """Encrypt/decrypt with the Windows user's DPAPI key."""
    from ctypes import (POINTER, Structure, byref, c_char, cast,
                        create_string_buffer, string_at, windll)
    from ctypes.wintypes import DWORD

    class _Blob(Structure):
        _fields_ = [("cbData", DWORD), ("pbData", POINTER(c_char))]

    buf = create_string_buffer(data, len(data))
    blob_in = _Blob(len(data), cast(buf, POINTER(c_char)))
    blob_out = _Blob()
    func = (windll.crypt32.CryptProtectData if protect
            else windll.crypt32.CryptUnprotectData)
    if not func(byref(blob_in), None, None, None, None, 0, byref(blob_out)):
        raise OSError("DPAPI call failed")
    try:
        return string_at(blob_out.pbData, blob_out.cbData)
    finally:
        windll.kernel32.LocalFree(blob_out.pbData)


def seal(data: bytes) -> bytes:
    if sys.platform == "win32":
        return _dpapi(data, protect=True)
    return _MAGIC + data


def unseal(blob: bytes) -> bytes:
    if blob.startswith(_MAGIC):
        return blob[len(_MAGIC):]
    if sys.platform == "win32":
        return _dpapi(blob, protect=False)
    raise OSError("unreadable sealed blob")
