"""Credential helper for the Vodou noVNC viewer's LAN gate.

Vodou's browser-viewable container (docker/Dockerfile.vnc) runs x11vnc with
``-nopw``; the actual LAN authentication is done by the reverse proxy in front
of the viewer as HTTP Basic Auth (nginx ``auth_basic`` / ``auth_basic_user_file``
-> a ``vodou.htpasswd`` file). This module manages that htpasswd file:

  * seed a bootstrap login ONLY when none exists yet, with a password randomly
    generated for this install (returned once so it can be shown to the
    administrator -- it is never stored in plaintext),
  * detect that the old, publicly documented default password is still in use
    (installs seeded before per-install passwords existed), and
  * change the password with the usual current/new/confirm validation.

Passwords are stored only as salted Apache-MD5 (``$apr1$``) hashes -- the format
nginx accepts on every platform (including Windows, where bcrypt/system-crypt
hashes are not supported). A random 144-bit bootstrap password keeps that weak
hash out of reach of offline cracking. Nothing here logs or persists a
plaintext password, and validation errors never contain the password value.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

# Bootstrap username for a fresh install's LAN gate. The password is generated
# per install by seed_default(), which never overwrites an existing credential.
DEFAULT_USERNAME = "vodou"

# The fixed default earlier versions seeded. It was published in the docs, so
# an install still using it is effectively unprotected: status flags it and
# change_password refuses it (see uses_published_default).
PUBLISHED_DEFAULT_PASSWORD = "vodou-lan-2026"

# The custom base64 alphabet md5crypt/apr1 use for their output encoding.
_ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


class PasswordChangeError(Exception):
    """A password change was rejected. The message is safe to show a user and
    never contains a password value."""


def _to64(value: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(_ITOA64[value & 0x3F])
        value >>= 6
    return "".join(out)


def apr1(password: str, salt: str | None = None) -> str:
    """Return an Apache-MD5 (``$apr1$``) hash of ``password``.

    ``salt`` (up to 8 chars from the itoa64 alphabet) is generated randomly when
    omitted. This is the same algorithm as ``openssl passwd -apr1`` and
    ``htpasswd -m``.
    """
    if salt is None:
        salt = "".join(secrets.choice(_ITOA64) for _ in range(8))
    salt = salt[:8]
    pw = password.encode("utf-8")
    sb = salt.encode("ascii")
    magic = b"$apr1$"

    # Primary digest.
    ctx = hashlib.md5(pw + magic + sb)

    # A digest of password+salt+password, folded in one password-length's worth.
    alt = hashlib.md5(pw + sb + pw).digest()
    i = len(pw)
    while i > 0:
        ctx.update(alt[: min(i, 16)])
        i -= 16

    # Then, for each bit of the password length, add either a NUL or the first
    # password byte (the historical md5crypt quirk).
    i = len(pw)
    while i:
        ctx.update(b"\x00" if i & 1 else pw[:1])
        i >>= 1

    final = ctx.digest()

    # 1000 iterations of deterministic re-hashing to slow brute force.
    for i in range(1000):
        ctx = hashlib.md5()
        ctx.update(pw if i & 1 else final)
        if i % 3:
            ctx.update(sb)
        if i % 7:
            ctx.update(pw)
        ctx.update(final if i & 1 else pw)
        final = ctx.digest()

    encoded = (
        _to64((final[0] << 16) | (final[6] << 8) | final[12], 4)
        + _to64((final[1] << 16) | (final[7] << 8) | final[13], 4)
        + _to64((final[2] << 16) | (final[8] << 8) | final[14], 4)
        + _to64((final[3] << 16) | (final[9] << 8) | final[15], 4)
        + _to64((final[4] << 16) | (final[10] << 8) | final[5], 4)
        + _to64(final[11], 2)
    )
    return f"$apr1${salt}${encoded}"


def verify(password: str, hashed: str) -> bool:
    """True if ``password`` matches the ``$apr1$`` ``hashed`` value."""
    if not hashed.startswith("$apr1$"):
        return False
    try:
        salt = hashed.split("$", 3)[2]
    except IndexError:
        return False
    # Constant-time compare so a wrong password can't be timed apart.
    return secrets.compare_digest(apr1(password, salt), hashed)


# -- htpasswd file I/O -------------------------------------------------------

def read_htpasswd(path: str | os.PathLike) -> dict[str, str]:
    """Parse an htpasswd file into ``{username: hash}``. Missing file -> {}."""
    entries: dict[str, str] = {}
    p = Path(path)
    if not p.exists():
        return entries
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        user, _, h = line.partition(":")
        entries[user] = h
    return entries


def write_htpasswd(path: str | os.PathLike, entries: dict[str, str]) -> None:
    """Write ``{username: hash}`` to ``path`` atomically, owner-only perms.

    A temp file in the same directory is written then renamed, so a crash never
    leaves a half-written credentials file (which would lock everyone out).
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{user}:{h}\n" for user, h in entries.items())
    tmp = p.with_name(p.name + f".tmp-{secrets.token_hex(4)}")
    tmp.write_text(body, encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)  # best-effort; a no-op on some Windows filesystems
    except OSError:
        pass
    os.replace(tmp, p)


# -- bootstrap / status / change --------------------------------------------

def generate_password() -> str:
    """A random bootstrap password: 24 URL-safe characters (144 bits)."""
    return secrets.token_urlsafe(18)


def seed_default(path: str | os.PathLike,
                 username: str = DEFAULT_USERNAME) -> str | None:
    """Create the htpasswd entry with a freshly generated password, but only if
    it doesn't exist yet.

    Returns the generated password -- the ONLY time it is available in
    plaintext, so the caller must show it to the administrator -- or None if an
    entry for ``username`` already existed (in which case the existing
    credential is left untouched -- an upgrade or re-run never clobbers a
    password the user already set).
    """
    entries = read_htpasswd(path)
    if username in entries:
        return None
    password = generate_password()
    entries[username] = apr1(password)
    write_htpasswd(path, entries)
    return password


def uses_published_default(path: str | os.PathLike,
                           username: str = DEFAULT_USERNAME) -> bool:
    """True if ``username`` still authenticates with the old published default.

    Derived from the stored hash itself, so no separate flag (which could drift
    out of sync with the file) is needed.
    """
    entries = read_htpasswd(path)
    h = entries.get(username)
    return bool(h) and verify(PUBLISHED_DEFAULT_PASSWORD, h)


def change_password(path: str | os.PathLike,
                    username: str,
                    current: str,
                    new: str,
                    confirm: str) -> None:
    """Validate and apply a password change for ``username``.

    Raises PasswordChangeError (with a password-free message) if the current
    password is wrong, the new password and confirmation differ, the new
    password is empty, or the new password is the published default or
    unchanged.
    """
    entries = read_htpasswd(path)
    h = entries.get(username)
    if not h:
        raise PasswordChangeError(f"No credential exists for user "
                                  f"“{username}”.")
    if not verify(current, h):
        raise PasswordChangeError("The current password is incorrect.")
    if new != confirm:
        raise PasswordChangeError("The new password and its confirmation do "
                                  "not match.")
    if not new:
        raise PasswordChangeError("The new password must not be empty.")
    if new == PUBLISHED_DEFAULT_PASSWORD:
        raise PasswordChangeError("The new password must not be the old "
                                  "published default password.")
    if verify(new, h):
        raise PasswordChangeError("The new password must be different from the "
                                  "current password.")
    entries[username] = apr1(new)
    write_htpasswd(path, entries)
