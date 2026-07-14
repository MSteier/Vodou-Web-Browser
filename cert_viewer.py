"""TLS certificate probe and viewer dialog (the padlock button).

Qt WebEngine doesn't expose the certificate of a loaded page, so the viewer
performs its own TLS handshake to the same host:port and inspects what the
server presents. Only the handshake happens — no request is sent. A verified
handshake (system root store) is attempted first; if verification fails, the
certificate is fetched anyway so it can still be examined, and the dialog
says exactly why verification failed.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)


@dataclass
class CertProbe:
    der: bytes
    trusted: bool
    trust_error: str | None
    tls_version: str | None
    cipher: str | None


def fetch_certificate(host: str, port: int = 443,
                      timeout: float = 5.0) -> CertProbe:
    try:
        return _handshake(host, port, timeout, verify=True)
    except ssl.SSLCertVerificationError as error:
        probe = _handshake(host, port, timeout, verify=False)
        probe.trusted = False
        probe.trust_error = error.verify_message or str(error)
        return probe


def _handshake(host: str, port: int, timeout: float,
               verify: bool) -> CertProbe:
    if verify:
        context = ssl.create_default_context()
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cipher = tls.cipher()
            return CertProbe(
                der=tls.getpeercert(binary_form=True),
                trusted=verify,
                trust_error=None,
                tls_version=tls.version(),
                cipher=cipher[0] if cipher else None)


# -- formatting helpers ------------------------------------------------------

_OID_LABELS = {
    "commonName": "Common name (CN)",
    "organizationName": "Organization (O)",
    "organizationalUnitName": "Organizational unit (OU)",
    "countryName": "Country (C)",
    "stateOrProvinceName": "State/Province (ST)",
    "localityName": "Locality (L)",
    "emailAddress": "Email",
}


def _name_rows(name: x509.Name) -> list[tuple[str, str]]:
    rows = []
    for attr in name:
        raw = attr.oid._name or attr.oid.dotted_string
        rows.append((_OID_LABELS.get(raw, raw), str(attr.value)))
    return rows


def _fingerprint(cert: x509.Certificate, algorithm) -> str:
    return ":".join(f"{b:02X}" for b in cert.fingerprint(algorithm))


def _serial_hex(cert: x509.Certificate) -> str:
    digits = format(cert.serial_number, "X")
    if len(digits) % 2:
        digits = "0" + digits
    return ":".join(digits[i:i + 2] for i in range(0, len(digits), 2))


def _public_key_desc(cert: x509.Certificate) -> str:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA, {key.key_size} bits"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA ({key.curve.name})"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(key, dsa.DSAPublicKey):
        return f"DSA, {key.key_size} bits"
    return type(key).__name__


def _validity(cert: x509.Certificate) -> tuple[datetime, datetime]:
    try:  # cryptography >= 42
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:
        return (cert.not_valid_before.replace(tzinfo=timezone.utc),
                cert.not_valid_after.replace(tzinfo=timezone.utc))


def _san_rows(cert: x509.Certificate) -> list[tuple[str, str]]:
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return [("(none)", "")]
    rows = [("DNS", n) for n in san.get_values_for_type(x509.DNSName)]
    rows += [("IP", str(n)) for n in san.get_values_for_type(x509.IPAddress)]
    return rows or [("(none)", "")]


# -- dialog ------------------------------------------------------------------

class CertificateDialog(QDialog):
    def __init__(self, host: str, probe: CertProbe, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Certificate — {host}")
        self.resize(560, 620)
        self._probe = probe
        cert = x509.load_der_x509_certificate(probe.der)

        layout = QVBoxLayout(self)
        layout.addWidget(self._status_label(cert, probe))

        tree = QTreeWidget()
        tree.setColumnCount(2)
        tree.setHeaderLabels(["Field", "Value"])
        tree.setRootIsDecorated(True)

        def section(title: str, rows: list[tuple[str, str]]) -> None:
            top = QTreeWidgetItem(tree, [title, ""])
            for field, value in rows:
                QTreeWidgetItem(top, [field, value])
            top.setExpanded(True)

        not_before, not_after = _validity(cert)
        now = datetime.now(timezone.utc)
        if now > not_after:
            expiry = f"EXPIRED {(now - not_after).days} days ago"
        elif now < not_before:
            expiry = "Not yet valid"
        else:
            expiry = f"Valid ({(not_after - now).days} days remaining)"

        section("Subject", _name_rows(cert.subject))
        section("Subject alternative names", _san_rows(cert))
        section("Issuer", _name_rows(cert.issuer)
                + ([("Note", "Self-signed (issuer = subject)")]
                   if cert.issuer == cert.subject else []))
        section("Validity", [
            ("Not before", not_before.strftime("%Y-%m-%d %H:%M UTC")),
            ("Not after", not_after.strftime("%Y-%m-%d %H:%M UTC")),
            ("Status", expiry),
        ])
        section("Details", [
            ("Public key", _public_key_desc(cert)),
            ("Signature algorithm",
             cert.signature_algorithm_oid._name
             or cert.signature_algorithm_oid.dotted_string),
            ("Version", cert.version.name),
            ("Serial number", _serial_hex(cert)),
        ])
        section("Fingerprints", [
            ("SHA-256", _fingerprint(cert, hashes.SHA256())),
            ("SHA-1", _fingerprint(cert, hashes.SHA1())),
        ])
        section("Connection", [
            ("Protocol", probe.tls_version or "unknown"),
            ("Cipher suite", probe.cipher or "unknown"),
        ])

        tree.resizeColumnToContents(0)
        layout.addWidget(tree)

        buttons = QHBoxLayout()
        copy_pem = QPushButton("Copy PEM")
        copy_pem.clicked.connect(self._copy_pem)
        buttons.addWidget(copy_pem)
        buttons.addStretch()
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.reject)
        buttons.addWidget(close)
        layout.addLayout(buttons)

    @staticmethod
    def _status_label(cert: x509.Certificate, probe: CertProbe) -> QLabel:
        not_before, not_after = _validity(cert)
        now = datetime.now(timezone.utc)
        if probe.trusted and not_before <= now <= not_after:
            label = QLabel("✅ Certificate verified — chains to a root "
                           "trusted by this system.")
            label.setStyleSheet("color: #1a7f37; font-weight: bold;")
        else:
            reason = probe.trust_error or "outside its validity period"
            label = QLabel(f"⚠️ Certificate could NOT be verified: {reason}")
            label.setStyleSheet("color: #b35900; font-weight: bold;")
        # The verification reason can carry certificate-derived text; never
        # render it as rich text.
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setWordWrap(True)
        return label

    def _copy_pem(self) -> None:
        QGuiApplication.clipboard().setText(
            ssl.DER_cert_to_PEM_cert(self._probe.der))
