"""At-rest encryption for the small state Vodou keeps between sessions.

Each platform seals with the OS facility that binds the key to the logged-in
account, so there is no password prompt and another local account (or a
lifted disk) can't read the payload:

  Windows   DPAPI (CryptProtectData) — the same per-user OS encryption
            Chrome uses for its cookie database.
  POSIX     A random key held in the desktop keyring (Secret Service
            /libsecret or KWallet), used to Fernet-seal the payload. The
            keyring unlocks with the login session, which is the same
            "no prompt, bound to this account" property DPAPI provides.

Honest limit, identical on both: like Chrome's jar, anything running *as this
user* can ask the OS to unseal it. This raises the bar against other accounts
and against offline disk access; it is not protection from software running
as you.

Where no acceptable keyring exists — a headless box, no running daemon, or
only an insecure plaintext backend installed — `available()` reports False and
`seal()` raises Unavailable. Callers must then persist NOTHING. Writing the
payload in the clear instead is not a degraded mode, it is a silent breach of
the guarantee this module's callers advertise. Versions before Linux support
did exactly that behind a magic header; that fallback is gone, and `unseal`
no longer honours it.

Not for passwords: the vault has its own master-password-derived key
(vault.py) and must never fall back to this.
"""

from __future__ import annotations

import sys

_HEADER = b"VODOUKR1\n"   # marks the keyring-sealed (POSIX) format

# Keyring backends whose storage the OS actually encrypts. `keyring` will
# otherwise happily select keyrings.alt's PlaintextKeyring, which stores
# secrets base64-encoded in a file — reintroducing one layer down exactly the
# plaintext fallback this module exists to refuse.
_SECURE_BACKENDS = (
    "keyring.backends.SecretService",
    "keyring.backends.libsecret",
    "keyring.backends.kwallet",
    "keyring.backends.macOS",
)

_SERVICE = "Vodou"
_ACCOUNT = "at-rest-key"


class Unavailable(Exception):
    """No OS keystore is usable, so nothing may be persisted."""


# -- Windows: DPAPI ------------------------------------------------------

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


# -- POSIX: desktop keyring ----------------------------------------------

def _leaf_backends(backend, depth: int = 0) -> list:
    """Flatten a backend, unwrapping keyring's chainer.

    On a desktop with more than one viable backend, get_keyring() commonly
    returns a ChainerBackend rather than the backend itself; judging it by its
    own module name would reject a perfectly good GNOME or KDE keyring.
    """
    inner = getattr(backend, "backends", None)
    if inner is None or depth > 3:      # depth guard: chainers can nest
        return [backend]
    flattened = []
    for item in inner:
        flattened.extend(_leaf_backends(item, depth + 1))
    return flattened or [backend]


def _keyring():
    """The keyring module, if installed AND backed by real encryption.

    Raises Unavailable rather than handing back a backend that would store
    the key in the clear.
    """
    try:
        import keyring
    except ImportError:
        raise Unavailable("the 'keyring' package is not installed")
    try:
        leaves = _leaf_backends(keyring.get_keyring())
    except Exception as error:          # backend probing is fragile by nature
        raise Unavailable(f"no usable keyring backend ({error})")
    if not leaves:
        raise Unavailable("no keyring backend is available")
    # EVERY leaf must be secure, not merely the highest-priority one. A
    # chainer reads from whichever member has the value, so one insecure
    # member in the chain is enough for the key to come back out of a
    # plaintext file — the chain is only as private as its weakest link.
    for backend in leaves:
        module = type(backend).__module__ or ""
        if not module.startswith(_SECURE_BACKENDS):
            raise Unavailable(
                f"the {module or 'unknown'} keyring backend does not encrypt "
                "its storage")
    return keyring


def _fernet():
    """Fernet built on this account's stored key, minted on first use."""
    from cryptography.fernet import Fernet

    keyring = _keyring()
    try:
        stored = keyring.get_password(_SERVICE, _ACCOUNT)
        if not stored:
            stored = Fernet.generate_key().decode("ascii")
            keyring.set_password(_SERVICE, _ACCOUNT, stored)
    except Unavailable:
        raise
    except Exception as error:      # locked keyring, no daemon, D-Bus refusal
        raise Unavailable(f"the keyring could not be read ({error})")
    try:
        return Fernet(stored.encode("ascii"))
    except (ValueError, TypeError) as error:
        raise Unavailable(f"the stored key is unusable ({error})")


# -- public API ----------------------------------------------------------

def available() -> bool:
    """True if seal() can be expected to work. Never raises.

    Callers persisting optional state should check this and skip writing
    altogether when it is False.
    """
    return not unavailable_reason()


def unavailable_reason() -> str:
    """Why available() is False, phrased for a user; "" when it is True."""
    if sys.platform == "win32":
        return ""
    try:
        _fernet()
        return ""
    except Unavailable as error:
        return str(error)


def seal(data: bytes) -> bytes:
    if sys.platform == "win32":
        return _dpapi(data, protect=True)
    return _HEADER + _fernet().encrypt(data)


def unseal(blob: bytes) -> bytes:
    if sys.platform == "win32":
        # On Windows the payload is always DPAPI-sealed. Do NOT honour any
        # other format here: accepting one would let anyone who can write the
        # file plant an unauthenticated payload (e.g. a forged cookie for an
        # allowlisted site — session fixation), sidestepping the tamper
        # resistance DPAPI is here to provide.
        return _dpapi(blob, protect=False)
    if not blob.startswith(_HEADER):
        raise OSError("unreadable sealed blob")
    from cryptography.fernet import InvalidToken
    try:
        return _fernet().decrypt(blob[len(_HEADER):])
    except InvalidToken:
        # Same reasoning as the Windows branch: a payload that fails to
        # authenticate is a tampered payload, not a recoverable one.
        raise OSError("sealed blob failed authentication")
    except Unavailable as error:
        raise OSError(str(error))
