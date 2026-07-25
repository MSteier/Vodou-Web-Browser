"""Encrypted password vault.

Storage format (JSON on disk):
    {
      "kdf": "scrypt", "n": 32768, "r": 8, "p": 1,
      "salt": "<base64>",
      "data": "<base64 Fernet token of JSON entry list>"
    }

The Fernet key is derived from the master password with scrypt (memory-hard),
so the file is useless without the master password. Nothing is ever written
to disk unencrypted.

Defence in depth in memory: while the vault is unlocked, passwords are NOT
kept as plaintext. Each password is re-encrypted under a random, ephemeral
per-session key and only decrypted at the instant it is needed (fill, copy,
edit, capture comparison). `entries()` therefore returns metadata with blank
password fields; callers must ask for a specific secret via `reveal(index)`.
This shrinks the window in which any plaintext password exists in RAM.

Caveat: Python strings are immutable and cannot be wiped, so a decrypted
password lingers until garbage-collected, and the session key itself lives in
RAM while unlocked. This reduces exposure; it does not make memory forensics
impossible.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import string
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from authenticator import Authenticator, AuthenticatorError

VAULT_DIR = Path.home() / ".vodou"
VAULT_FILE = VAULT_DIR / "vault.dat"
# Config dir used by earlier versions; migrated on startup (see main.py).
LEGACY_VAULT_DIR = Path.home() / ".privacy_browser"

# OWASP-recommended interactive scrypt parameters (~128 MB, ~1 s to derive).
# Older vaults created with weaker parameters still unlock: the parameters
# actually used are read from the vault file and preserved on save.
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1

# HKDF context string binding the mixed key to this purpose/version.
_FACTOR_INFO = b"vodou-vault-factor-v2"
# AES-GCM additional-authenticated-data for wrapping the factor secret.
_WRAP_AAD = b"vodou-factor-wrap"


class WrongMasterPassword(Exception):
    pass


class VaultLocked(Exception):
    pass


class VaultCorrupted(Exception):
    """The vault file is malformed, truncated, or tampered with."""


class SecondFactorRequired(Exception):
    """The vault has a security key enrolled but none was supplied."""


class SecondFactorFailed(Exception):
    """A security key was supplied but couldn't satisfy the vault.

    Either no enrolled key was present, or the present key's wrapped copy of
    the factor secret didn't decrypt. Distinct from WrongMasterPassword so the
    UI can tell "tap your key" apart from "that password is wrong".
    """


@dataclass
class Entry:
    site: str          # bare domain, e.g. "github.com"
    username: str
    password: str
    notes: str = ""


def _scrypt_raw(master: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    """The 32 raw bytes scrypt derives from the master password."""
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(master.encode("utf-8"))


def _fernet_key(scrypt_raw: bytes, factor_secret: bytes | None) -> bytes:
    """The Fernet key that actually encrypts the vault.

    With no security key enrolled this is exactly the historical key —
    base64(scrypt) — so every existing password-only vault keeps opening
    unchanged. With a factor enrolled, the scrypt output is combined with the
    key-held factor secret through HKDF, so the file needs BOTH the password
    and a present, enrolled security key.
    """
    if factor_secret is None:
        return base64.urlsafe_b64encode(scrypt_raw)
    okm = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=_FACTOR_INFO).derive(scrypt_raw + factor_secret)
    return base64.urlsafe_b64encode(okm)


def _wrap(secret_key: bytes, plaintext: bytes) -> bytes:
    """Seal `plaintext` under a security key's hmac-secret (AES-GCM)."""
    aes = AESGCM(secret_key)
    nonce = secrets.token_bytes(12)
    return nonce + aes.encrypt(nonce, plaintext, _WRAP_AAD)


def _unwrap(secret_key: bytes, blob: bytes) -> bytes:
    """Reverse _wrap; raises on the wrong key or a tampered blob."""
    aes = AESGCM(secret_key)
    return aes.decrypt(blob[:12], blob[12:], _WRAP_AAD)


def normalize_site(site: str) -> str:
    site = site.strip().lower()
    for prefix in ("https://", "http://"):
        if site.startswith(prefix):
            site = site[len(prefix):]
    site = site.split("/")[0]
    if site.startswith("www."):
        site = site[4:]
    return site


class Vault:
    def __init__(self, path: Path = VAULT_FILE):
        self.path = path
        self._fernet: Fernet | None = None       # at-rest key (master-derived)
        self._key: bytes | None = None           # same key, raw, for rekeying
        self._session: Fernet | None = None      # ephemeral in-memory key
        # Metadata only: the `password` field of every entry here is "".
        self._entries: list[Entry] = []
        # Parallel to _entries: each password sealed under the session key.
        self._secrets: list[bytes] = []
        # KDF parameters the current key was derived with. Saves MUST write
        # these (not the module constants), or a parameter bump would write
        # metadata that no longer matches the key and brick the vault.
        self._kdf: tuple[int, int, int] = (SCRYPT_N, SCRYPT_R, SCRYPT_P)
        # Optional hardware second factor (see authenticator.py). When any
        # security key is enrolled, _factor_secret holds the random secret V
        # that all enrolled keys wrap and the file key mixes in; _hmac_salt is
        # the public per-vault salt each key's hmac-secret is computed over;
        # _authenticators is the persistent list of wrapped copies.
        self._pw_raw: bytes | None = None        # scrypt(current password)
        self._factor_secret: bytes | None = None  # V, set iff a key enrolled
        self._hmac_salt: bytes | None = None
        self._authenticators: list[dict] = []

    # -- state ---------------------------------------------------------

    def exists(self) -> bool:
        return self.path.exists()

    @property
    def unlocked(self) -> bool:
        return self._fernet is not None

    @property
    def factor_enrolled(self) -> bool:
        """True while unlocked if at least one security key is enrolled."""
        return bool(self._authenticators)

    def lock(self) -> None:
        self._fernet = None
        self._key = None
        self._session = None
        self._entries = []
        self._secrets = []
        self._pw_raw = None
        self._factor_secret = None
        self._hmac_salt = None
        self._authenticators = []

    def file_has_factor(self) -> bool:
        """Peek the on-disk file: does unlocking it need a security key?

        Read before prompting so the UI knows to involve a key. Never
        decrypts; a malformed file simply reports False and the real error
        surfaces from unlock().
        """
        try:
            blob = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        factor = blob.get("factor")
        return bool(factor and factor.get("authenticators"))

    # -- in-memory secret sealing ----------------------------------------

    def _seal(self, plaintext: str) -> bytes:
        return self._session.encrypt(plaintext.encode("utf-8"))

    def _open(self, token: bytes) -> str:
        return self._session.decrypt(token).decode("utf-8")

    def _ingest(self, full_entries: list[Entry]) -> None:
        """Take plaintext entries, seal each password, keep metadata blank."""
        self._entries = []
        self._secrets = []
        for e in full_entries:
            self._secrets.append(self._seal(e.password))
            self._entries.append(
                Entry(site=e.site, username=e.username, password="",
                      notes=e.notes))

    @staticmethod
    def _meta_copy(entry: Entry) -> Entry:
        return Entry(site=entry.site, username=entry.username,
                     password="", notes=entry.notes)

    # -- create / unlock -------------------------------------------------

    def create(self, master: str) -> None:
        if self.path.exists():
            raise FileExistsError(
                f"Refusing to overwrite existing vault at {self.path}")
        salt = secrets.token_bytes(16)
        self._kdf = (SCRYPT_N, SCRYPT_R, SCRYPT_P)
        pw_raw = _scrypt_raw(master, salt, *self._kdf)
        # A brand-new vault is always password-only; a security key is added
        # afterwards via enroll_authenticator().
        self._factor_secret = None
        self._hmac_salt = None
        self._authenticators = []
        self._pw_raw = pw_raw
        self._key = _fernet_key(pw_raw, None)
        self._fernet = Fernet(self._key)
        self._session = Fernet(Fernet.generate_key())
        self._salt = salt
        self._entries = []
        self._secrets = []
        self._save()

    def destroy(self) -> None:
        """Irrecoverably delete the on-disk vault and lock this instance.

        Used only by the explicit "start over" flow, for when the master
        password is forgotten. There is deliberately no recovery path: the
        stored logins are encrypted under the forgotten password and cannot
        be read without it, so the file is simply removed. The caller is
        then free to create() a fresh, empty vault.
        """
        self.lock()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def unlock(self, master: str,
               authenticator: Authenticator | None = None) -> None:
        try:
            blob = json.loads(self.path.read_text(encoding="utf-8"))
            salt = base64.b64decode(blob["salt"])
            data = base64.b64decode(blob["data"])
            kdf = (int(blob["n"]), int(blob["r"]), int(blob["p"]))
        except (KeyError, ValueError, TypeError) as error:
            raise VaultCorrupted(
                f"vault file is malformed or unreadable ({error})")

        # Bound the KDF parameters BEFORE deriving: a tampered file with a
        # huge n would otherwise make scrypt allocate unbounded memory
        # (128 * n * r bytes) the moment the master password is entered.
        n, r, p = kdf
        if not (1024 <= n <= 2 ** 22 and n & (n - 1) == 0
                and 1 <= r <= 32 and 1 <= p <= 16
                and 128 * n * r <= 512 * 2 ** 20
                and 8 <= len(salt) <= 64):
            raise VaultCorrupted(
                "vault KDF parameters are out of bounds — the file may "
                "have been tampered with")

        hmac_salt, authenticators = self._parse_factor(blob)
        # A file with an enrolled key cannot be opened by password alone: fail
        # closed before deriving anything if no key was supplied.
        if authenticators and authenticator is None:
            raise SecondFactorRequired()

        factor_secret = None
        if authenticators:
            factor_secret = self._recover_factor_secret(
                authenticator, hmac_salt, authenticators)

        pw_raw = _scrypt_raw(master, salt, *kdf)
        key = _fernet_key(pw_raw, factor_secret)
        fernet = Fernet(key)
        try:
            raw = fernet.decrypt(data)
        except InvalidToken:
            raise WrongMasterPassword()
        self._fernet = fernet
        self._key = key
        self._pw_raw = pw_raw
        self._factor_secret = factor_secret
        self._hmac_salt = hmac_salt
        self._authenticators = authenticators
        self._session = Fernet(Fernet.generate_key())
        self._salt = salt
        self._kdf = kdf
        self._ingest([Entry(**e) for e in json.loads(raw)])

    @staticmethod
    def _parse_factor(blob: dict) -> tuple[bytes | None, list[dict]]:
        """Read the optional factor section into (hmac_salt, records)."""
        factor = blob.get("factor")
        if not factor:
            return None, []
        try:
            hmac_salt = base64.b64decode(factor["hmac_salt"])
            records = []
            for a in factor["authenticators"]:
                records.append({
                    "cred_id": base64.b64decode(a["cred_id"]),
                    "wrap": base64.b64decode(a["wrap"]),
                    "label": str(a.get("label", "")),
                    "added": str(a.get("added", "")),
                })
        except (KeyError, ValueError, TypeError) as error:
            raise VaultCorrupted(
                f"vault security-key metadata is malformed ({error})")
        return hmac_salt, records

    @staticmethod
    def _recover_factor_secret(authenticator: Authenticator, hmac_salt: bytes,
                               records: list[dict]) -> bytes:
        """Use the present security key to unwrap the shared factor secret."""
        cred_ids = [r["cred_id"] for r in records]
        try:
            used_id, hmac_secret = authenticator.get_assertion(
                cred_ids, hmac_salt)
        except AuthenticatorError as error:
            raise SecondFactorFailed(str(error))
        for record in records:
            if record["cred_id"] == used_id:
                try:
                    return _unwrap(hmac_secret, record["wrap"])
                except Exception:  # InvalidTag etc. — wrong/tampered wrap
                    raise SecondFactorFailed(
                        "the security key did not match this vault")
        raise SecondFactorFailed(
            "the security key is not enrolled in this vault")

    def change_master_password(self, current: str, new: str) -> None:
        """Re-encrypt the vault under a key derived from a new master.

        The current master password must be re-entered and is verified
        (constant-time) against the key the vault was unlocked with, so a
        walk-up attacker at an unlocked vault can't silently take it over.
        Rekeying uses a fresh random salt and today's recommended scrypt
        parameters, so an old vault is also upgraded in passing.
        """
        self._require_unlocked()
        if not secrets.compare_digest(
                _scrypt_raw(current, self._salt, *self._kdf), self._pw_raw):
            raise WrongMasterPassword()
        self._salt = secrets.token_bytes(16)
        self._kdf = (SCRYPT_N, SCRYPT_R, SCRYPT_P)
        # Changing the password only re-derives the scrypt half; the security
        # keys and the factor secret they wrap are untouched, so an enrolled
        # vault stays enrolled across a password change.
        self._pw_raw = _scrypt_raw(new, self._salt, *self._kdf)
        self._key = _fernet_key(self._pw_raw, self._factor_secret)
        self._fernet = Fernet(self._key)
        self._save()

    # -- second factor (security keys) -----------------------------------

    def enroll_authenticator(self, authenticator: Authenticator,
                             label: str = "") -> None:
        """Register a security key as a second factor for this vault.

        The first key enrolled generates the shared factor secret and re-keys
        the vault so the file now needs password + key; each further key adds
        another wrapped copy of that secret (a backup). The user is prompted
        to tap their key during make_credential().
        """
        self._require_unlocked()
        first = self._factor_secret is None
        if first:
            self._factor_secret = secrets.token_bytes(32)
            self._hmac_salt = secrets.token_bytes(32)
        cred_id, hmac_secret = authenticator.make_credential(self._hmac_salt)
        if any(r["cred_id"] == cred_id for r in self._authenticators):
            raise ValueError("that security key is already enrolled")
        self._authenticators.append({
            "cred_id": cred_id,
            "wrap": _wrap(hmac_secret, self._factor_secret),
            "label": label,
            "added": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        })
        # Re-key: enabling the factor (or just re-affirming it) means the file
        # key now mixes in the factor secret.
        self._key = _fernet_key(self._pw_raw, self._factor_secret)
        self._fernet = Fernet(self._key)
        self._save()

    def remove_authenticator(self, cred_id: bytes) -> None:
        """Un-enroll one security key. Removing the last one disables 2FA.

        When the last key goes, the vault re-keys back to password-only so the
        user isn't locked out with no key left to present.
        """
        self._require_unlocked()
        before = len(self._authenticators)
        self._authenticators = [r for r in self._authenticators
                                if r["cred_id"] != cred_id]
        if len(self._authenticators) == before:
            raise ValueError("that security key is not enrolled")
        if not self._authenticators:
            self._factor_secret = None
            self._hmac_salt = None
            self._key = _fernet_key(self._pw_raw, None)
            self._fernet = Fernet(self._key)
        self._save()

    def list_authenticators(self) -> list[dict]:
        """Enrolled keys as display metadata (label, added, short id)."""
        self._require_unlocked()
        return [{"cred_id": r["cred_id"],
                 "label": r["label"],
                 "added": r["added"]}
                for r in self._authenticators]

    # -- entries ---------------------------------------------------------

    def entries(self) -> list[Entry]:
        """All entries as metadata copies — password fields are blank.

        Use reveal(index) to obtain a specific password when actually needed.
        """
        self._require_unlocked()
        return [self._meta_copy(e) for e in self._entries]

    def entries_for_host(self, host: str) -> list[tuple[int, Entry]]:
        """(index, metadata-entry) pairs whose site matches host or a parent.

        The index lets the caller reveal(index) the password on demand.
        """
        self._require_unlocked()
        host = host.lower()
        matches = []
        for i, e in enumerate(self._entries):
            site = normalize_site(e.site)
            if host == site or host.endswith("." + site):
                matches.append((i, self._meta_copy(e)))
        return matches

    def reveal(self, index: int) -> str:
        """Decrypt and return one password, on demand, at point of use."""
        self._require_unlocked()
        return self._open(self._secrets[index])

    def add(self, entry: Entry) -> None:
        self._require_unlocked()
        entry.site = normalize_site(entry.site)
        self._secrets.append(self._seal(entry.password))
        self._entries.append(self._meta_copy(entry))
        self._save()

    def add_many(self, new_entries: list[Entry]) -> int:
        """Bulk add (imports): seal everything, then ONE re-encrypt + disk
        write — per-entry add() would rewrite the whole vault n times."""
        self._require_unlocked()
        for entry in new_entries:
            entry.site = normalize_site(entry.site)
            self._secrets.append(self._seal(entry.password))
            self._entries.append(self._meta_copy(entry))
        if new_entries:
            self._save()
        return len(new_entries)

    def update(self, index: int, entry: Entry) -> None:
        self._require_unlocked()
        entry.site = normalize_site(entry.site)
        self._secrets[index] = self._seal(entry.password)
        self._entries[index] = self._meta_copy(entry)
        self._save()

    def delete(self, index: int) -> None:
        self._require_unlocked()
        del self._entries[index]
        del self._secrets[index]
        self._save()

    # -- internals -------------------------------------------------------

    def _require_unlocked(self) -> None:
        if self._fernet is None:
            raise VaultLocked()

    def _save(self) -> None:
        self._require_unlocked()
        # Re-materialize full entries (passwords decrypted) only transiently
        # here, to build the single on-disk blob, then let them be collected.
        full = [
            asdict(Entry(site=e.site, username=e.username,
                         password=self._open(self._secrets[i]),
                         notes=e.notes))
            for i, e in enumerate(self._entries)]
        raw = json.dumps(full).encode("utf-8")
        n, r, p = self._kdf
        blob = {
            "kdf": "scrypt",
            "n": n,
            "r": r,
            "p": p,
            "salt": base64.b64encode(self._salt).decode("ascii"),
            "data": base64.b64encode(self._fernet.encrypt(raw)).decode("ascii"),
        }
        # Only stamp the format version and factor section when a security key
        # is actually enrolled, so a password-only vault stays byte-for-byte
        # the historical shape and older builds keep reading it.
        if self._authenticators:
            blob["version"] = 2
            blob["factor"] = {
                "hmac_salt": base64.b64encode(self._hmac_salt).decode("ascii"),
                "authenticators": [
                    {"cred_id": base64.b64encode(r["cred_id"]).decode("ascii"),
                     "wrap": base64.b64encode(r["wrap"]).decode("ascii"),
                     "label": r["label"],
                     "added": r["added"]}
                    for r in self._authenticators],
            }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(blob), encoding="utf-8")
        # Narrow the mode BEFORE the rename, so the live vault file is never
        # momentarily world-readable. The contents are encrypted either way;
        # this denies other local accounts the salt and ciphertext they would
        # need to mount an offline attack on the master password.
        if os.name == "posix":
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
        tmp.replace(self.path)


def generate_password(length: int = 20, symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits
    if symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        # require at least one of each character class present in the alphabet
        if (any(c.islower() for c in pw)
                and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)
                and (not symbols or any(not c.isalnum() for c in pw))):
            return pw
