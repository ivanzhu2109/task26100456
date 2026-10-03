"""Helpers to issue real certificates for tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(
    subject,
    issuer,
    subject_key,
    issuer_key,
    *,
    ca=False,
    path_length=None,
    key_cert_sign=None,
    dns_sans=None,
    permitted=None,
    excluded=None,
    not_before=None,
    not_after=None,
    serial=None,
):
    """Issue a sha256WithRSAEncryption certificate and return DER bytes."""
    now = datetime.now(timezone.utc)
    not_before = not_before or (now - timedelta(days=1))
    not_after = not_after or (now + timedelta(days=30))
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length), critical=True
        )
    )
    if key_cert_sign is not None:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if dns_sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_sans]),
            critical=False,
        )
    if permitted is not None or excluded is not None:
        builder = builder.add_extension(
            x509.NameConstraints(
                permitted_subtrees=(
                    [x509.DNSName(p) for p in permitted] if permitted else None
                ),
                excluded_subtrees=(
                    [x509.DNSName(e) for e in excluded] if excluded else None
                ),
            ),
            critical=True,
        )
    cert = builder.sign(issuer_key, hashes.SHA256())
    return cert.public_bytes(Encoding.DER)
