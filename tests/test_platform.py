"""Platform-conditional behaviour, checked on every OS that CI runs.

Vodou is developed on Windows, so the POSIX branches added for Linux support
would otherwise never execute until a user hit them. These assertions are
what stands in for a Linux machine: run under GitHub Actions on
ubuntu-latest, they exercise the code paths a Windows developer cannot.

Run:  QT_QPA_PLATFORM=offscreen python tests/test_platform.py
"""

import os
import stat
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

WINDOWS = sys.platform == "win32"
failures = []


def check(label, got, want):
    if got != want:
        failures.append(label)
    print(f"  [{'PASS' if got == want else 'FAIL'}] {label}: "
          f"got {got!r}, want {want!r}")


print(f"\n=== platform: {sys.platform} ===")

print("\n--- graphics flags match the platform's actual GPU stack ---")
import main as vodou_main

flags = vodou_main.GFX_MODES
# d3d11/WARP are Direct3D. Passing them to Chromium anywhere else names a
# backend ANGLE cannot build, which is how you get a browser that starts with
# no GPU at all — or does not start.
d3d = [mode for mode, value in flags.items()
       if "d3d11" in value or "warp" in value]
check("no Direct3D backends off Windows", d3d if not WINDOWS else [], [])
if WINDOWS:
    check("Windows default is unchanged", flags["default"],
          "--disable-direct-composition --use-angle=d3d11 "
          "--enable-gpu-rasterization --enable-zero-copy")
else:
    check("POSIX default defers to Chromium", flags["default"], "")
# The ☰ menu offers exactly these three; every platform must define them.
for mode in ("default", "compat", "software"):
    check(f"menu mode {mode!r} exists", mode in flags, True)

print("\n--- WebAuthn shim claims only what the platform can do ---")
from privacy import WEBAUTHN_SHIM_JS

check("no unsubstituted placeholder", "%PLATFORM_AUTH%" in WEBAUTHN_SHIM_JS,
      False)
# Claiming a platform authenticator that isn't there steers sites onto a
# modal flow that cannot complete, hiding the security-key path that works.
claims_platform_auth = "userVerifyingPlatformAuthenticator: true" in \
    WEBAUTHN_SHIM_JS
check("platform authenticator claimed only on Windows",
      claims_platform_auth, WINDOWS)
check("conditional mediation still denied everywhere",
      "conditionalMediation: false" in WEBAUTHN_SHIM_JS, True)

print("\n--- at-rest sealing never degrades to plaintext ---")
import dpapi

# The pre-Linux plaintext fallback. If this were still honoured, anyone able
# to write the jar could plant unauthenticated cookies for an allowlisted
# site — session fixation.
old_plaintext = b"VODOUJAR1\nname=value; Domain=example.com"
try:
    dpapi.unseal(old_plaintext)
    check("legacy plaintext blob is refused", "accepted", "refused")
except (OSError, dpapi.Unavailable):
    check("legacy plaintext blob is refused", "refused", "refused")

if WINDOWS:
    sealed = dpapi.seal(b"round trip")
    check("DPAPI round-trips", dpapi.unseal(sealed), b"round trip")
    check("sealed bytes are not the plaintext", b"round trip" in sealed, False)
    check("available() on Windows", dpapi.available(), True)
else:
    # CI has no keyring daemon, so this is the fallback path a headless or
    # minimal Linux box takes. It must be a clean refusal, not a crash and
    # not a plaintext write.
    usable = dpapi.available()
    print(f"  [INFO] keyring usable here: {usable}")
    if not usable:
        check("unavailable_reason explains itself",
              bool(dpapi.unavailable_reason()), True)
        try:
            dpapi.seal(b"secret")
            check("seal refuses without a keystore", "wrote", "raised")
        except dpapi.Unavailable:
            check("seal refuses without a keystore", "raised", "raised")
    else:
        sealed = dpapi.seal(b"round trip")
        check("keyring round-trips", dpapi.unseal(sealed), b"round trip")
        check("sealed bytes are not the plaintext",
              b"round trip" in sealed, False)

print("\n--- only encrypted keyring backends are accepted ---")
import types


def _fake_backend(module_name, inner=None):
    cls = type("Backend", (), {})
    cls.__module__ = module_name
    obj = cls()
    if inner is not None:
        obj.backends = inner      # what makes keyring's chainer a chainer
    return obj


_secret = _fake_backend("keyring.backends.SecretService")
_kwallet = _fake_backend("keyring.backends.kwallet")
_plaintext = _fake_backend("keyrings.alt.file")

_saved_keyring = sys.modules.get("keyring")
_stub = types.ModuleType("keyring")
sys.modules["keyring"] = _stub
for label, backend, acceptable in [
        ("bare SecretService", _secret, True),
        ("chainer of two secure backends",
         _fake_backend("keyring.backends.chainer", [_secret, _kwallet]), True),
        # A chainer reads from whichever member holds the value, so one
        # plaintext member is enough to leak the key back out of a file.
        ("chainer containing a plaintext backend",
         _fake_backend("keyring.backends.chainer", [_secret, _plaintext]),
         False),
        ("bare plaintext backend", _plaintext, False),
        ("keyring.backends.fail", _fake_backend("keyring.backends.fail"),
         False)]:
    _stub.get_keyring = lambda b=backend: b
    try:
        dpapi._keyring()
        accepted = True
    except dpapi.Unavailable:
        accepted = False
    check(f"{label} accepted", accepted, acceptable)
if _saved_keyring is not None:
    sys.modules["keyring"] = _saved_keyring
else:
    del sys.modules["keyring"]

print("\n--- cookie keeping switches off rather than writing plaintext ---")
import cookies

problem = cookies.CookieKeeper.keystore_problem()
check("keystore_problem agrees with available()",
      bool(problem), not dpapi.available())

print("\n--- config directory is private where the OS can express it ---")
with tempfile.TemporaryDirectory() as td:
    d = Path(td) / ".vodou"
    vodou_main.secure_config_dir(d)
    check("directory created", d.is_dir(), True)
    if not WINDOWS:
        # Never actually executed before Linux support existed.
        mode = stat.S_IMODE(d.stat().st_mode)
        check("mode is 0700", oct(mode), "0o700")

    from vault import Vault
    v = Vault(d / "vault.dat")
    v.create("correct horse battery staple")
    if not WINDOWS:
        check("vault file is 0600",
              oct(stat.S_IMODE((d / "vault.dat").stat().st_mode)), "0o600")
    v.lock()
    v.unlock("correct horse battery staple")
    check("vault unlocks after create", v.unlocked, True)

print("\n--- the on-device guarantee is platform-independent ---")
from ai_search import is_local_endpoint

for endpoint, want in [("http://127.0.0.1:11434", True),
                       ("http://localhost:11434", True),
                       ("http://127.0.0.1.example.net", False),
                       ("https://elsewhere.example:11434", False)]:
    check(f"is_local_endpoint({endpoint})", is_local_endpoint(endpoint), want)

print("\n" + "=" * 60)
print(f"FAILURES: {len(failures)}")
for name in failures:
    print("  -", name)
sys.exit(1 if failures else 0)
