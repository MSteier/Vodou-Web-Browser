"""Hardware-free tests for the vault's optional security-key second factor.

Uses authenticator.FakeAuthenticator (an in-memory stand-in with the same
contract as a real FIDO2 key) so the whole key model, migration, backup-key
recovery, and lockout behaviour can be exercised with no hardware.

Run:  python tests/test_vault_factor.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from authenticator import FakeAuthenticator  # noqa: E402
from vault import (  # noqa: E402
    Entry,
    SecondFactorFailed,
    SecondFactorRequired,
    Vault,
    WrongMasterPassword,
    _fernet_key,
    _scrypt_raw,
)

PW = "correct horse battery staple"
NEWPW = "a whole different passphrase"

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


def fresh():
    d = Path(tempfile.mkdtemp())
    return Vault(d / "vault.dat")


def raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    except Exception as other:  # noqa: BLE001
        print(f"      (raised {type(other).__name__}, wanted {exc.__name__})")
        return False
    return False


# ---------------------------------------------------------------------------
print("password-only vault is unchanged / v1-compatible")

v = fresh()
v.create(PW)
v.add(Entry(site="github.com", username="mike", password="hunter2"))
check("no factor enrolled after create", not v.factor_enrolled)
check("file_has_factor() is False", not v.file_has_factor())
# The historical key derivation must be byte-identical: base64(scrypt).
raw = _scrypt_raw(PW, v._salt, *v._kdf)
check("password-only key == historical base64(scrypt)",
      _fernet_key(raw, None) == v._key)
v.lock()
v.unlock(PW)  # no authenticator needed
check("re-unlocks with password alone", v.unlocked)
check("entry survived", v.reveal(0) == "hunter2")

# ---------------------------------------------------------------------------
print("\nenrolling a key migrates the vault to 2FA")

auth = FakeAuthenticator()
v.enroll_authenticator(auth, label="YubiKey 5C")
check("factor now enrolled", v.factor_enrolled)
check("file_has_factor() is True", v.file_has_factor())
check("one authenticator listed", len(v.list_authenticators()) == 1)
check("label persisted", v.list_authenticators()[0]["label"] == "YubiKey 5C")

# ---------------------------------------------------------------------------
print("\npassword ALONE no longer opens the vault")

v.lock()
check("unlock without key raises SecondFactorRequired",
      raises(SecondFactorRequired, lambda: v.unlock(PW)))
check("still locked", not v.unlocked)

# ---------------------------------------------------------------------------
print("\npassword + enrolled key opens it")

v.unlock(PW, auth)
check("unlocked with password + key", v.unlocked)
check("entry still readable", v.reveal(0) == "hunter2")

# ---------------------------------------------------------------------------
print("\nwrong password with right key -> WrongMasterPassword")

v.lock()
check("wrong pw + right key",
      raises(WrongMasterPassword, lambda: v.unlock("nope", auth)))

# ---------------------------------------------------------------------------
print("\nright password with a STRANGER key -> SecondFactorFailed")

v.lock()
stranger = FakeAuthenticator()
stranger.make_credential(b"x" * 32)  # a key that exists but isn't enrolled
check("right pw + unenrolled key",
      raises(SecondFactorFailed, lambda: v.unlock(PW, stranger)))
check("empty authenticator (no key present)",
      raises(SecondFactorFailed, lambda: v.unlock(PW, FakeAuthenticator())))

# ---------------------------------------------------------------------------
print("\nbackup key: a SECOND key opens the same vault independently")

v.unlock(PW, auth)
backup = FakeAuthenticator()
v.enroll_authenticator(backup, label="Backup key")
check("two authenticators listed", len(v.list_authenticators()) == 2)
v.lock()
v.unlock(PW, backup)  # only the backup present
check("backup key alone unlocks", v.unlocked and v.reveal(0) == "hunter2")
v.lock()
v.unlock(PW, auth)  # original still works too
check("original key still unlocks", v.unlocked)

# ---------------------------------------------------------------------------
print("\nchanging the master password keeps the keys")

v.change_master_password(PW, NEWPW)
v.lock()
check("old pw rejected after change",
      raises(WrongMasterPassword, lambda: v.unlock(PW, auth)))
v.unlock(NEWPW, auth)
check("new pw + key unlocks", v.unlocked)
check("still 2FA after pw change", v.factor_enrolled)

# ---------------------------------------------------------------------------
print("\nremoving one of two keys leaves 2FA on")

v.remove_authenticator(auth_records_first := v.list_authenticators()[0]["cred_id"])
check("one key left", len(v.list_authenticators()) == 1)
check("still requires a factor", v.factor_enrolled)
v.lock()
check("removed key no longer works",
      raises(SecondFactorFailed, lambda: v.unlock(NEWPW, auth)))
v.unlock(NEWPW, backup)
check("remaining key still works", v.unlocked)

# ---------------------------------------------------------------------------
print("\nremoving the LAST key disables 2FA (back to password-only)")

v.remove_authenticator(v.list_authenticators()[0]["cred_id"])
check("no keys left", len(v.list_authenticators()) == 0)
check("factor disabled", not v.factor_enrolled)
check("file_has_factor() False again", not v.file_has_factor())
v.lock()
v.unlock(NEWPW)  # password alone again
check("password alone opens it again", v.unlocked and v.reveal(0) == "hunter2")

# ---------------------------------------------------------------------------
print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL VAULT-FACTOR TESTS PASSED")
