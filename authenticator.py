"""FIDO2 security-key abstraction for the vault's optional second factor.

The vault's real protection is the master password (see vault.py). This adds
an *optional* hardware second factor: a FIDO2 security key that, via the
CTAP2 `hmac-secret` extension, produces a stable 32-byte secret it computes
inside the key and never reveals. Mixing that secret into the vault's key
means a stolen vault file plus a guessed master password still opens nothing
without the physical key present.

Two different keys produce two different hmac-secrets, so backups can't share
one secret. vault.py handles that with envelope encryption: one random factor
secret `V`, wrapped once per enrolled key under that key's hmac-secret. This
module only has to do two things per key — register one, and re-derive its
hmac-secret on demand — so it is a thin, swappable interface:

    make_credential(salt)      -> (credential_id, hmac_secret)   # enroll
    get_assertion(ids, salt)   -> (credential_id, hmac_secret)   # unlock

`FakeAuthenticator` implements the same contract in memory so the vault's key
model and migrations can be tested with no hardware. The real implementation
(WindowsWebAuthnAuthenticator, backed by the `fido2` package's native
WebAuthn client) is added in stage two and must be validated on a real key.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
from typing import Protocol

# WebAuthn relying-party identity for the vault. This is a *local* app, not a
# website, so the id is a private pseudo-domain that never resolves; the
# Windows WebAuthn API accepts it and it only ever has to match itself. Keep
# both stable — changing them orphans every already-enrolled key.
_RP_ID = "vodou.local"
_ORIGIN = "https://vodou.local"
_RP_NAME = "Vodou"


class AuthenticatorError(Exception):
    """The ceremony failed or no enrolled key was present/usable."""


class Authenticator(Protocol):
    """A FIDO2 key capable of the hmac-secret extension."""

    def make_credential(self, salt: bytes) -> tuple[bytes, bytes]:
        """Register a new credential and return (credential_id, hmac_secret).

        The user is prompted to tap/verify their key. `salt` is the (public,
        per-vault) hmac-secret salt; the returned secret is HMAC of it under a
        key generated and held inside the authenticator.
        """
        ...

    def get_assertion(self, credential_ids: list[bytes],
                      salt: bytes) -> tuple[bytes, bytes]:
        """Re-derive the hmac-secret for whichever enrolled key is present.

        `credential_ids` lists every enrolled credential; the key that is
        actually plugged in signs and returns (its credential_id, hmac_secret).
        Raises AuthenticatorError if none of them can be satisfied.
        """
        ...


class FakeAuthenticator:
    """In-memory stand-in for tests — never used in the shipping app.

    Models a bag of security keys. Each credential owns a random internal HMAC
    key, so its hmac-secret is a deterministic function of the salt (stable
    across calls) yet independent of every other credential's — exactly the
    property real hmac-secret has, and the one that forces envelope wrapping.
    """

    def __init__(self) -> None:
        # credential_id -> internal per-credential HMAC key
        self._keys: dict[bytes, bytes] = {}

    def make_credential(self, salt: bytes) -> tuple[bytes, bytes]:
        credential_id = os.urandom(16)
        internal = os.urandom(32)
        self._keys[credential_id] = internal
        return credential_id, self._hmac(internal, salt)

    def get_assertion(self, credential_ids: list[bytes],
                      salt: bytes) -> tuple[bytes, bytes]:
        for credential_id in credential_ids:
            internal = self._keys.get(credential_id)
            if internal is not None:
                return credential_id, self._hmac(internal, salt)
        raise AuthenticatorError("no enrolled security key is present")

    def unplug(self, credential_id: bytes) -> None:
        """Test helper: simulate a key not being available."""
        self._keys.pop(credential_id, None)

    @staticmethod
    def _hmac(internal: bytes, salt: bytes) -> bytes:
        return hmac.new(internal, salt, hashlib.sha256).digest()


def webauthn_supported() -> tuple[bool, str]:
    """Whether real security-key unlock can run here, and why not if it can't.

    The reason string is meant to be shown to the user, so it names the fix.
    """
    if sys.platform != "win32":
        return False, ("Security-key unlock is currently Windows-only "
                       "(it uses the Windows WebAuthn API).")
    try:
        from fido2.client.windows import WindowsClient
    except ImportError:
        return False, ("The 'fido2' package isn't installed. Run "
                       "'pip install fido2' to enable security-key unlock.")
    try:
        available = WindowsClient.is_available()
    except Exception:  # noqa: BLE001 — defensive against odd fido2 builds
        available = False
    if not available:
        return False, ("Windows WebAuthn isn't available on this system "
                       "(needs Windows 10 1903 or newer).")
    return True, ""


def _run_on_mta_thread(fn):
    """Run a blocking WebAuthn ceremony on a dedicated COM-MTA thread.

    The Windows WebAuthn API hosts a modal dialog. Called inline on the Qt GUI
    thread — which Qt initialises as a COM single-threaded apartment (STA) —
    WebAuthNAuthenticatorMakeCredential returns RPC_S_CALL_IN_PROGRESS. Run on
    a fresh thread initialised as MTA (verified working) it drives its dialog
    correctly. The caller's thread blocks on join(), which is fine: the
    system security dialog is modal anyway.
    """
    import ctypes
    import threading

    box: dict = {}

    def runner():
        ctypes.windll.ole32.CoInitializeEx(None, 0x0)  # COINIT_MULTITHREADED
        try:
            box["result"] = fn()
        except BaseException as error:  # noqa: BLE001 — re-raised below
            box["error"] = error
        finally:
            ctypes.windll.ole32.CoUninitialize()

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box["result"]


class WindowsWebAuthnAuthenticator:
    """Real FIDO2 second factor via the native Windows WebAuthn API.

    Implements the Authenticator contract on top of the `fido2` package's
    WindowsClient (fido2 2.x), using the CTAP2 hmac-secret extension to
    produce the stable per-key secret vault.py wraps V under.

    Written against fido2 2.2's verified API — the class names, extension keys
    ('hmacCreateSecret' / 'hmacGetSecret' with salt1, outputs under 'output1'),
    the credential id at response.raw_id, and outputs at
    response.client_extension_results were all confirmed against the installed
    package. What is NOT yet confirmed is the *live ceremony*: whether a given
    key returns the hmac-secret at registration, and whether the native prompt
    parents cleanly over the Qt window. Those need a physical key to verify;
    the two-step fallback in make_credential() is here precisely because the
    first is uncertain.
    """

    def __init__(self, window_handle: int | None = None):
        # The native prompt is parented to this HWND (from a Qt widget's
        # winId()) so it appears modal over Vodou instead of behind it.
        self._handle = window_handle

    # -- Authenticator protocol -----------------------------------------

    def make_credential(self, salt: bytes) -> tuple[bytes, bytes]:
        # On Windows the hmac-secret can come back at registration, saving a
        # tap; but not every key/API level populates it, so fall back to a
        # separate assertion when it doesn't. Each ceremony runs on its own
        # MTA thread (see _run_on_mta_thread).
        credential_id, hmac_secret = _run_on_mta_thread(
            lambda: self._register(salt))
        if hmac_secret is None:
            _, hmac_secret = self.get_assertion([credential_id], salt)
        return credential_id, hmac_secret

    def get_assertion(self, credential_ids: list[bytes],
                      salt: bytes) -> tuple[bytes, bytes]:
        return _run_on_mta_thread(
            lambda: self._get_assertion(credential_ids, salt))

    def _get_assertion(self, credential_ids: list[bytes],
                       salt: bytes) -> tuple[bytes, bytes]:
        from fido2.webauthn import (
            PublicKeyCredentialDescriptor,
            PublicKeyCredentialRequestOptions,
            PublicKeyCredentialType,
            UserVerificationRequirement,
        )
        client = self._client()
        allow = [PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY, id=cid)
                 for cid in credential_ids]
        options = PublicKeyCredentialRequestOptions(
            challenge=os.urandom(32),
            rp_id=_RP_ID,
            allow_credentials=allow,
            user_verification=UserVerificationRequirement.DISCOURAGED,
            extensions={"hmacGetSecret": {"salt1": salt}},
        )
        try:
            selection = client.get_assertion(options)
            response = selection.get_response(0)
        except Exception as error:  # noqa: BLE001 — surface any CTAP failure
            raise AuthenticatorError(
                f"the security key couldn't be read ({error})")
        secret = self._hmac_output(response)
        if secret is None:
            raise AuthenticatorError(
                "the security key didn't return an hmac-secret — it may not "
                "support the extension")
        return bytes(response.raw_id), secret

    # -- fido2 plumbing -------------------------------------------------

    def _client(self):
        from fido2.client import DefaultClientDataCollector
        from fido2.client.windows import WindowsClient
        # allow_hmac_secret=True is required or the client strips the
        # extension before it reaches the key.
        return WindowsClient(
            DefaultClientDataCollector(_ORIGIN),
            handle=self._handle,
            allow_hmac_secret=True)

    def _register(self, salt: bytes) -> tuple[bytes, bytes | None]:
        from fido2.webauthn import (
            AuthenticatorSelectionCriteria,
            PublicKeyCredentialCreationOptions,
            PublicKeyCredentialParameters,
            PublicKeyCredentialRpEntity,
            PublicKeyCredentialType,
            PublicKeyCredentialUserEntity,
            UserVerificationRequirement,
        )
        client = self._client()
        options = PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(id=_RP_ID, name=_RP_NAME),
            user=PublicKeyCredentialUserEntity(
                id=os.urandom(16), name="vodou-vault",
                display_name="Vodou Vault"),
            challenge=os.urandom(32),
            pub_key_cred_params=[
                PublicKeyCredentialParameters(
                    type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7),
                PublicKeyCredentialParameters(
                    type=PublicKeyCredentialType.PUBLIC_KEY, alg=-257),
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.DISCOURAGED),
            # Enable the secret, and ask for it now in case the key returns it.
            extensions={"hmacCreateSecret": True,
                        "hmacGetSecret": {"salt1": salt}},
        )
        try:
            result = client.make_credential(options)
        except Exception as error:  # noqa: BLE001
            raise AuthenticatorError(
                f"the security key couldn't be registered ({error})")
        return bytes(result.raw_id), self._hmac_output(result)

    @staticmethod
    def _hmac_output(response) -> bytes | None:
        """Pull hmacGetSecret.output1 out of a response's extension outputs.

        fido2 websafe-base64-encodes byte fields into strings when the client
        extension results are read, so output1 arrives as a str; decode it
        back to the raw secret bytes. (Older/other paths may hand back bytes
        directly, so accept both.)
        """
        ext = getattr(response, "client_extension_results", None) or {}
        try:
            output = ext["hmacGetSecret"]["output1"]
        except (KeyError, TypeError):
            return None
        if not output:
            return None
        if isinstance(output, str):
            from fido2.utils import websafe_decode
            return websafe_decode(output)
        return bytes(output)
