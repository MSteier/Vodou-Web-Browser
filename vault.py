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
import secrets
import string
from dataclasses import dataclass, asdict
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

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


class WrongMasterPassword(Exception):
    pass


class VaultLocked(Exception):
    pass


class VaultCorrupted(Exception):
    """The vault file is malformed, truncated, or tampered with."""


@dataclass
class Entry:
    site: str          # bare domain, e.g. "github.com"
    username: str
    password: str
    notes: str = ""


def _derive_key(master: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return base64.urlsafe_b64encode(kdf.derive(master.encode("utf-8")))


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
        self._session: Fernet | None = None      # ephemeral in-memory key
        # Metadata only: the `password` field of every entry here is "".
        self._entries: list[Entry] = []
        # Parallel to _entries: each password sealed under the session key.
        self._secrets: list[bytes] = []
        # KDF parameters the current key was derived with. Saves MUST write
        # these (not the module constants), or a parameter bump would write
        # metadata that no longer matches the key and brick the vault.
        self._kdf: tuple[int, int, int] = (SCRYPT_N, SCRYPT_R, SCRYPT_P)

    # -- state ---------------------------------------------------------

    def exists(self) -> bool:
        return self.path.exists()

    @property
    def unlocked(self) -> bool:
        return self._fernet is not None

    def lock(self) -> None:
        self._fernet = None
        self._session = None
        self._entries = []
        self._secrets = []

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
        key = _derive_key(master, salt, *self._kdf)
        self._fernet = Fernet(key)
        self._session = Fernet(Fernet.generate_key())
        self._salt = salt
        self._entries = []
        self._secrets = []
        self._save()

    def unlock(self, master: str) -> None:
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

        key = _derive_key(master, salt, *kdf)
        fernet = Fernet(key)
        try:
            raw = fernet.decrypt(data)
        except InvalidToken:
            raise WrongMasterPassword()
        self._fernet = fernet
        self._session = Fernet(Fernet.generate_key())
        self._salt = salt
        self._kdf = kdf
        self._ingest([Entry(**e) for e in json.loads(raw)])

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
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(blob), encoding="utf-8")
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
