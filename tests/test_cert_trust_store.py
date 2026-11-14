"""Tests for the cert viewer's trust store (cert_viewer._verified_context).

Regression: on Windows, Python loads the "CA" (intermediate) store as trust
anchors. It held the 2020 "ISRG Root X2" cross-sign (expired 2025-09-15), and
OpenSSL picked that stale copy over the valid cross-sign the server sent, so
the padlock said "certificate has expired" for every Let's Encrypt ECDSA
site (search.misttechnologies.net) while the page itself loaded fine.

This rebuilds that situation offline with a throwaway PKI shaped like Let's
Encrypt's (X1 -> X2 cross-sign -> YE -> leaf), fakes ssl.enum_certificates()
so it runs on any OS, and does a real TLS handshake against a local server.
No network, no Qt event loop.

Run:  python tests/test_cert_trust_store.py
"""

import os
import socket
import ssl
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

import cert_viewer  # noqa: E402

_failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        _failures.append(label)


NOW = datetime.now(timezone.utc)
DAY = timedelta(days=1)
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_cn, subject_key, issuer_cn, issuer_key, *, ca,
          not_before, not_after, san=None):
    """A certificate that satisfies VERIFY_X509_STRICT (Python 3.13+)."""
    b = (x509.CertificateBuilder()
         .subject_name(_name(subject_cn))
         .issuer_name(_name(issuer_cn))
         .public_key(subject_key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(not_before)
         .not_valid_after(not_after)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                        critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(
             subject_key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
             issuer_key.public_key()), critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False), critical=True)
    else:
        b = (b.add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
             .add_extension(x509.ExtendedKeyUsage(
                 [ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
             .add_extension(x509.SubjectAlternativeName(
                 [x509.DNSName(n) for n in san]), critical=False))
    return b.sign(issuer_key, hashes.SHA256())


def _der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


# -- a Let's Encrypt-shaped PKI ------------------------------------------------
key = {n: ec.generate_private_key(ec.SECP256R1())
       for n in ("X1", "X2", "YE", "leaf")}
x1_root = _cert("Test Root X1", key["X1"], "Test Root X1", key["X1"], ca=True,
                not_before=NOW - 3000 * DAY, not_after=NOW + 3000 * DAY)
x2_cross_old = _cert("Test Root X2", key["X2"], "Test Root X1", key["X1"],
                     ca=True, not_before=NOW - 2000 * DAY,
                     not_after=NOW - 60 * DAY)            # the stale one
x2_cross_new = _cert("Test Root X2", key["X2"], "Test Root X1", key["X1"],
                     ca=True, not_before=NOW - 30 * DAY,
                     not_after=NOW + 2000 * DAY)          # what Caddy sends
ye = _cert("Test YE", key["YE"], "Test Root X2", key["X2"], ca=True,
           not_before=NOW - 30 * DAY, not_after=NOW + 1000 * DAY)
leaf = _cert("localhost", key["leaf"], "Test YE", key["YE"], ca=False,
             not_before=NOW - DAY, not_after=NOW + 90 * DAY,
             san=["localhost"])

# What enum_certificates() returns for each store on the broken machine.
STORES = {
    "ROOT": [(_der(x1_root), "x509_asn", True)],
    "CA": [(_der(x2_cross_old), "x509_asn", True)],
}


# -- local TLS server presenting leaf + YE + the valid cross-sign --------------
tmp = Path(tempfile.mkdtemp())
(tmp / "chain.pem").write_bytes(_pem(leaf) + _pem(ye) + _pem(x2_cross_new))
(tmp / "key.pem").write_bytes(key["leaf"].private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()))
server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_ctx.load_cert_chain(tmp / "chain.pem", tmp / "key.pem")
listener = socket.create_server(("127.0.0.1", 0))
PORT = listener.getsockname()[1]


def _serve():
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        try:
            with server_ctx.wrap_socket(conn, server_side=True):
                pass
        except (ssl.SSLError, OSError):
            pass  # client rejected us; that's the point of some checks


threading.Thread(target=_serve, daemon=True).start()


def handshake(context):
    """None on success, else the verify message."""
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=5) as s:
            with context.wrap_socket(s, server_hostname="localhost"):
                return None
    except ssl.SSLCertVerificationError as e:
        return e.verify_message or str(e)


# -----------------------------------------------------------------------------
print("the bug reproduces with the stdlib behaviour")

all_store = b"".join(d for s in ("CA", "ROOT") for d, _, _ in STORES[s])
check("stdlib-style context (expired cross-sign trusted) fails as 'expired'",
      "expired" in (handshake(ssl.create_default_context(cadata=all_store))
                    or ""))

print("_verified_context() with faked Windows stores")

had_enum = hasattr(ssl, "enum_certificates")
real_enum = getattr(ssl, "enum_certificates", None)
ssl.enum_certificates = lambda store: list(STORES.get(store, []))
try:
    result = handshake(cert_viewer._verified_context())
    check(f"handshake verifies (got: {result or 'ok'})", result is None)
finally:
    if had_enum:
        ssl.enum_certificates = real_enum
    else:
        del ssl.enum_certificates

print("_unexpired_store_ders() filtering")

entries = [
    (_der(x1_root), "x509_asn", True),
    (_der(x2_cross_old), "x509_asn", True),
    (_der(ye), "x509_asn", {SERVER_AUTH}),
    (_der(x2_cross_new), "x509_asn", {"1.3.6.1.5.5.7.3.4"}),  # email only
    (b"\x01\x02", "pkcs_7_asn", True),
    (b"not a certificate", "x509_asn", True),
]
kept = cert_viewer._unexpired_store_ders(entries, now=NOW)
check("valid root kept", _der(x1_root) in kept)
check("expired cross-sign dropped", _der(x2_cross_old) not in kept)
check("cert trusted for serverAuth kept", _der(ye) in kept)
check("cert not trusted for serverAuth skipped (like stdlib)",
      _der(x2_cross_new) not in kept)
check("non-X.509 entry skipped", b"\x01\x02" not in kept)
check("unparseable cert kept, matching stdlib", b"not a certificate" in kept)

listener.close()

if _failures:
    print(f"\n{len(_failures)} failure(s)")
    sys.exit(1)
print("\nall ok")
