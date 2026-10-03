"""Real certificate issuance helpers for tests (RSA + SHA-256)."""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

_serial = itertools.count(1000)


def gen_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(
    *,
    subject: x509.Name,
    subject_key: rsa.RSAPrivateKey,
    issuer: x509.Name,
    issuer_key: rsa.RSAPrivateKey,
    ca: bool,
    path_len: int | None = None,
    key_cert_sign: bool | None = None,
    sans: list[str] | None = None,
    permitted: list[str] | None = None,
    excluded: list[str] | None = None,
    not_before: datetime,
    not_after: datetime,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(next(_serial))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_len), critical=True)
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
    if sans is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    if permitted is not None or excluded is not None:
        builder = builder.add_extension(
            x509.NameConstraints(
                permitted_subtrees=(
                    [x509.DNSName(p) for p in permitted] if permitted is not None else None
                ),
                excluded_subtrees=(
                    [x509.DNSName(e) for e in excluded] if excluded is not None else None
                ),
            ),
            critical=True,
        )
    return builder.sign(issuer_key, SHA256())


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(Encoding.DER)


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
VALID_FROM = NOW - timedelta(days=30)
VALID_TO = NOW + timedelta(days=30)
EXPIRED_FROM = NOW - timedelta(days=60)
EXPIRED_TO = NOW - timedelta(days=30)
