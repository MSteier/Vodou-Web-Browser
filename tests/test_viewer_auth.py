"""Tests for the Vodou viewer's LAN credential management (docker/viewer_auth).

This is the nginx Basic-Auth htpasswd gate that fronts the passwordless VNC
server — there is no VNC-protocol login hook, so enforcement is at the
management/provisioning layer, which is what these tests exercise.

Run:  python tests/test_viewer_auth.py
"""

import os
import shutil
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
h = va.apr1(va.PUBLISHED_DEFAULT_PASSWORD)
check("hash carries the $apr1$ prefix", h.startswith("$apr1$"))
check("verify accepts the right password", va.verify(va.PUBLISHED_DEFAULT_PASSWORD, h))
check("verify rejects the wrong password", not va.verify("nope", h))
check("random salt -> different hashes for same password",
      va.apr1("x") != va.apr1("x"))

# Cross-check our hash against openssl's verifier when openssl is available.
try:
    salt = h.split("$", 3)[2]
    ref = subprocess.run(
        ["openssl", "passwd", "-apr1", "-salt", salt, va.PUBLISHED_DEFAULT_PASSWORD],
        capture_output=True, text=True, timeout=10).stdout.strip()
    check("our hash equals openssl's for the same salt", ref == h)
except (OSError, subprocess.SubprocessError):
    print("  --  (openssl not available; skipped cross-check)")

# ---------------------------------------------------------------------------
print("\nfresh install seeds a random per-install password")

p = fresh()
pw = va.seed_default(p)
check("seed returns the generated password on a fresh install",
      isinstance(pw, str) and len(pw) >= 24)
entries = va.read_htpasswd(p)
check("default username present", va.DEFAULT_USERNAME in entries)
check("generated password authenticates",
      va.verify(pw, entries[va.DEFAULT_USERNAME]))
check("seeded password is not the published default",
      pw != va.PUBLISHED_DEFAULT_PASSWORD
      and not va.uses_published_default(p))
check("each install gets a different password",
      va.seed_default(fresh()) != pw)

# ---------------------------------------------------------------------------
print("\nexisting credentials are never overwritten")

p2 = fresh()
va.write_htpasswd(p2, {"vodou": va.apr1("already-strong-secret")})
check("seed is a no-op when an entry exists", va.seed_default(p2) is None)
check("the pre-existing password is preserved",
      va.verify("already-strong-secret", va.read_htpasswd(p2)["vodou"]))
check("a preserved non-default is NOT flagged as published default",
      not va.uses_published_default(p2))

# An install seeded by an older version still holds the published default.
p_old = fresh()
va.write_htpasswd(p_old, {"vodou": va.apr1(va.PUBLISHED_DEFAULT_PASSWORD)})
check("legacy install on the published default is flagged",
      va.uses_published_default(p_old))
check("seed leaves the legacy entry alone", va.seed_default(p_old) is None)

# ---------------------------------------------------------------------------
print("\nchanging the password")

p3 = fresh()
pw3 = va.seed_default(p3)
check("wrong current password is rejected",
      raises(va.PasswordChangeError,
             lambda: va.change_password(p3, "vodou", "WRONG",
                                        "brand-new-pass", "brand-new-pass")))
check("mismatched confirmation is rejected",
      raises(va.PasswordChangeError,
             lambda: va.change_password(p3, "vodou", pw3, "new-a", "new-b")))
check("empty new password is rejected",
      raises(va.PasswordChangeError,
             lambda: va.change_password(p3, "vodou", pw3, "", "")))
check("switching to the published default is rejected",
      raises(va.PasswordChangeError,
             lambda: va.change_password(p3, "vodou", pw3,
                                        va.PUBLISHED_DEFAULT_PASSWORD,
                                        va.PUBLISHED_DEFAULT_PASSWORD)))
check("reusing the current password is rejected",
      raises(va.PasswordChangeError,
             lambda: va.change_password(p3, "vodou", pw3, pw3, pw3)))
# All rejections above left the credential untouched.
check("seeded password still works after every rejected change",
      va.verify(pw3, va.read_htpasswd(p3)["vodou"]))

# A valid change goes through and persists.
va.change_password(p3, "vodou", pw3,
                   "a-strong-new-password", "a-strong-new-password")
check("new password authenticates after change",
      va.verify("a-strong-new-password", va.read_htpasswd(p3)["vodou"]))
check("seeded password no longer authenticates",
      not va.verify(pw3, va.read_htpasswd(p3)["vodou"]))

# Moving a legacy install off the published default clears the flag.
va.change_password(p_old, "vodou", va.PUBLISHED_DEFAULT_PASSWORD,
                   "legacy-now-changed", "legacy-now-changed")
check("published-default flag clears after change",
      not va.uses_published_default(p_old))

# ---------------------------------------------------------------------------
print("\nno plaintext password is ever written to disk")

p4 = fresh()
pw4 = va.seed_default(p4)
check("seeded password plaintext absent from the file",
      pw4 not in p4.read_text(encoding="utf-8"))
va.change_password(p4, "vodou", pw4,
                   "another-secret-value", "another-secret-value")
blob = p4.read_text(encoding="utf-8")
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
print("\nCLI seed shows the password once; status can fail a setup script")

p5 = fresh()


def _cli(*args):
    return subprocess.run(
        [sys.executable, str(_ROOT / "docker" / "manage_viewer_password.py"),
         "--file", str(p5), *args],
        capture_output=True, text=True, timeout=30)

r = _cli("seed")
shown = [line.split("password:", 1)[1].strip()
         for line in r.stdout.splitlines() if "password:" in line]
check("CLI seed prints the generated password",
      len(shown) == 1 and va.verify(shown[0], va.read_htpasswd(p5)["vodou"]))
r = _cli("seed")
check("CLI re-seed does not print a password",
      r.returncode == 0 and "password:" not in r.stdout)
r = _cli("status", "--fail-if-default")
check("status --fail-if-default exits zero for a generated password",
      r.returncode == 0)

va.write_htpasswd(p5, {"vodou": va.apr1(va.PUBLISHED_DEFAULT_PASSWORD)})
r = _cli("status", "--fail-if-default")
check("status --fail-if-default exits nonzero on the published default",
      r.returncode != 0)
check("CLI status output does not print the password",
      va.PUBLISHED_DEFAULT_PASSWORD not in (r.stdout + r.stderr))
check("CLI status warns about the published default",
      "WARNING" in r.stdout)

# ---------------------------------------------------------------------------
print("\nmigration: an install still on the published default is rotated")

p6 = fresh()
va.write_htpasswd(p6, {"vodou": va.apr1(va.PUBLISHED_DEFAULT_PASSWORD),
                       "someone-else": va.apr1("their-own-secret")})
outcome, pw6 = va.ensure_credential(p6)
entries = va.read_htpasswd(p6)
check("published default is rotated", outcome == "rotated")
check("rotated password is random and authenticates",
      pw6 and pw6 != va.PUBLISHED_DEFAULT_PASSWORD
      and va.verify(pw6, entries["vodou"]))
check("published default no longer authenticates after rotation",
      not va.uses_published_default(p6))
check("other users in the file are untouched",
      va.verify("their-own-secret", entries["someone-else"]))
check("re-running after rotation keeps the new password",
      va.ensure_credential(p6) == ("kept", None)
      and va.verify(pw6, va.read_htpasswd(p6)["vodou"]))

p7 = fresh()
va.write_htpasswd(p7, {"vodou": va.apr1("chosen-by-the-user")})
check("a user-chosen password is kept",
      va.ensure_credential(p7) == ("kept", None)
      and va.verify("chosen-by-the-user", va.read_htpasswd(p7)["vodou"]))

outcome, pw8 = va.ensure_credential(fresh())
check("fresh file -> created with a random password",
      outcome == "created" and pw8 and pw8 != va.PUBLISHED_DEFAULT_PASSWORD)

# The CLI's seed performs the migration and says so.
va.write_htpasswd(p5, {"vodou": va.apr1(va.PUBLISHED_DEFAULT_PASSWORD)})
r = _cli("seed")
shown = [line.split("password:", 1)[1].strip()
         for line in r.stdout.splitlines() if "password:" in line]
check("CLI seed warns when it rotates the published default",
      "WARNING" in r.stdout)
check("CLI seed prints the rotated password once",
      len(shown) == 1 and va.verify(shown[0], va.read_htpasswd(p5)["vodou"]))
check("status is clean after the CLI migration",
      _cli("status", "--fail-if-default").returncode == 0)

# The htpasswd path can come from the environment instead of --file.
p9 = fresh()
env = dict(os.environ, VODOU_VIEWER_HTPASSWD=str(p9))
r = subprocess.run(
    [sys.executable, str(_ROOT / "docker" / "manage_viewer_password.py"),
     "seed"], capture_output=True, text=True, timeout=30, env=env)
check("VODOU_VIEWER_HTPASSWD selects the file", p9.exists()
      and "vodou" in va.read_htpasswd(p9))

# ---------------------------------------------------------------------------
print("\nsetup.sh generates the password on the host, once")

sh = shutil.which("sh")
if sh is None:
    print("  --  (no POSIX sh available; skipped setup.sh run)")
else:
    work = Path(tempfile.mkdtemp()) / "docker"
    (work / "searxng").mkdir(parents=True)
    for name in ("setup.sh", "manage_viewer_password.py", "viewer_auth.py",
                 ".env.example"):
        shutil.copy(_ROOT / "docker" / name, work / name)
    shutil.copy(_ROOT / "docker" / "searxng" / "settings.yml",
                work / "searxng" / "settings.yml")
    # Only this interpreter and the shell's own tools on PATH, so the script
    # can't pick up an unrelated (or Store-stub) python.
    env = {k: v for k, v in os.environ.items()
           if k != "VODOU_VIEWER_HTPASSWD"}
    env["PATH"] = os.pathsep.join([str(Path(sys.executable).parent),
                                   str(Path(sh).parent)])

    def _setup():
        return subprocess.run([sh, "setup.sh"], cwd=work, capture_output=True,
                              text=True, timeout=120, env=env)

    r1 = _setup()
    store = work / "viewer-auth" / "vodou.htpasswd"
    shown = [line.split("password:", 1)[1].strip()
             for line in r1.stdout.splitlines() if "password:" in line]
    check("setup.sh succeeds", r1.returncode == 0)
    check("setup.sh stores the credential in a host file",
          store.exists() and "vodou" in va.read_htpasswd(store))
    check("setup.sh prints a labeled, working password once",
          "shown once" in r1.stdout and len(shown) == 1
          and va.verify(shown[0], va.read_htpasswd(store)["vodou"]))
    check("the plaintext password is not written to disk",
          shown and shown[0] not in store.read_text(encoding="utf-8"))
    r2 = _setup()
    check("re-running setup.sh keeps the password (no regeneration)",
          r2.returncode == 0 and "password:" not in r2.stdout
          and shown and va.verify(shown[0], va.read_htpasswd(store)["vodou"]))

# ---------------------------------------------------------------------------
print()
if _failures:
    print(f"{len(_failures)} FAILURE(S): " + "; ".join(_failures))
    sys.exit(1)
print("ALL VIEWER-AUTH TESTS PASSED")
