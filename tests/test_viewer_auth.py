"""Tests for the Vodou viewer's LAN credential management (docker/viewer_auth).

This is the nginx Basic-Auth htpasswd gate that fronts the passwordless VNC
server — there is no VNC-protocol login hook, so enforcement is at the
management/provisioning layer, which is what these tests exercise.

Run:  python tests/test_viewer_auth.py
"""

import subprocess
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "docker"))

import viewer_auth as va  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


def raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    except Exception:
        return False
    return False


def fresh():
    return Path(tempfile.mkdtemp()) / "vodou.htpasswd"


# ---------------------------------------------------------------------------
print("apr1 hashing")

# Byte-for-byte match with `openssl passwd -apr1` (the format nginx consumes).
check("apr1 matches openssl reference vector",
      va.apr1("vodou", "abcd1234")
      == "$apr1$abcd1234$dRT61VkljDby0iStGz/4i/")
h = va.apr1("vodou-lan-2026")
check("hash carries the $apr1$ prefix", h.startswith("$apr1$"))
check("verify accepts the right password", va.verify("vodou-lan-2026", h))
check("verify rejects the wrong password", not va.verify("nope", h))
check("random salt -> different hashes for same password",
      va.apr1("x") != va.apr1("x"))

# Cross-check our hash against openssl's verifier when openssl is available.
try:
    salt = h.split("$", 3)[2]
    ref = subprocess.run(
        ["openssl", "passwd", "-apr1", "-salt", salt, "vodou-lan-2026"],
        capture_output=True, text=True, timeout=10).stdout.strip()
    check("our hash equals openssl's for the same salt", ref == h)
except (OSError, subprocess.SubprocessError):
    print("  --  (openssl not available; skipped cross-check)")

# ---------------------------------------------------------------------------
print("\nfresh install seeds the bootstrap credential")

p = fresh()
check("seed writes on a fresh install", va.seed_default(p) is True)
entries = va.read_htpasswd(p)
check("default username present", va.DEFAULT_USERNAME in entries)
check("default password authenticates",
      va.verify(va.DEFAULT_PASSWORD, entries[va.DEFAULT_USERNAME]))
check("bootstrap default is vodou / vodou-lan-2026",
      va.DEFAULT_USERNAME == "vodou"
      and va.DEFAULT_PASSWORD == "vodou-lan-2026")
check("is_default_unchanged True right after seeding",
      va.is_default_unchanged(p))

# ---------------------------------------------------------------------------
print("\nexisting credentials are never overwritten")

p2 = fresh()
va.write_htpasswd(p2, {"vodou": va.apr1("already-strong-secret")})
check("seed is a no-op when an entry exists", va.seed_default(p2) is False)
check("the pre-existing password is preserved",
      va.verify("already-strong-secret", va.read_htpasswd(p2)["vodou"]))
check("a preserved non-default is NOT flagged as default",
      not va.is_default_unchanged(p2))

# ---------------------------------------------------------------------------
print("\nchanging the password")

p3 = fresh()
va.seed_default(p3)
check("wrong current password is rejected",
      raises(va.PasswordChangeError,
             lambda: va.change_password(p3, "vodou", "WRONG",
                                        "brand-new-pass", "brand-new-pass")))
check("mismatched confirmation is rejected",
      raises(va.PasswordChangeError,
             lambda: va.change_password(p3, "vodou", va.DEFAULT_PASSWORD,
                                        "new-a", "new-b")))
check("empty new password is rejected",
      raises(va.PasswordChangeError,
             lambda: va.change_password(p3, "vodou", va.DEFAULT_PASSWORD,
                                        "", "")))
check("reusing the default password is rejected",
      raises(va.PasswordChangeError,
             lambda: va.change_password(p3, "vodou", va.DEFAULT_PASSWORD,
                                        va.DEFAULT_PASSWORD,
                                        va.DEFAULT_PASSWORD)))
# All rejections above left the credential untouched.
check("still on the default after every rejected change",
      va.is_default_unchanged(p3))

# A valid change goes through and persists.
va.change_password(p3, "vodou", va.DEFAULT_PASSWORD,
                   "a-strong-new-password", "a-strong-new-password")
check("new password authenticates after change",
      va.verify("a-strong-new-password", va.read_htpasswd(p3)["vodou"]))
check("old default no longer authenticates",
      not va.verify(va.DEFAULT_PASSWORD, va.read_htpasswd(p3)["vodou"]))
check("is_default_unchanged False after a successful change",
      not va.is_default_unchanged(p3))

# The change state persists across a re-read (the stored hash IS the state).
check("changed state persists on re-read",
      not va.is_default_unchanged(p3))
# And the (now non-default) login still works — existing auth keeps working.
check("changed credential still authenticates normally",
      va.verify("a-strong-new-password", va.read_htpasswd(p3)["vodou"]))

# ---------------------------------------------------------------------------
print("\nno plaintext password is ever written to disk")

p4 = fresh()
va.seed_default(p4)
va.change_password(p4, "vodou", va.DEFAULT_PASSWORD,
                   "another-secret-value", "another-secret-value")
blob = p4.read_text(encoding="utf-8")
check("default password plaintext absent from the file",
      va.DEFAULT_PASSWORD not in blob)
check("new password plaintext absent from the file",
      "another-secret-value" not in blob)
check("file only stores $apr1$ hashes",
      all(part.split(":", 1)[1].startswith("$apr1$")
          for part in blob.splitlines() if ":" in part))

# Error messages must not leak the password value either.
try:
    va.change_password(p4, "vodou", "the-wrong-current-secret",
                       "x-new", "x-new")
except va.PasswordChangeError as exc:
    check("error message does not contain the attempted password",
          "the-wrong-current-secret" not in str(exc))

# ---------------------------------------------------------------------------
print("\nCLI status reports and can fail a setup script")

p5 = fresh()
va.seed_default(p5)


def _cli(*args):
    return subprocess.run(
        [sys.executable, str(_ROOT / "docker" / "manage_viewer_password.py"),
         "--file", str(p5), *args],
        capture_output=True, text=True, timeout=30)

r = _cli("status", "--fail-if-default")
check("status --fail-if-default exits nonzero while default in use",
      r.returncode != 0)
check("CLI status output does not print the password",
      va.DEFAULT_PASSWORD not in (r.stdout + r.stderr))

va.change_password(p5, "vodou", va.DEFAULT_PASSWORD, "cli-new-pw", "cli-new-pw")
r = _cli("status", "--fail-if-default")
check("status --fail-if-default exits zero once changed", r.returncode == 0)

# ---------------------------------------------------------------------------
print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL VIEWER-AUTH TESTS PASSED")
