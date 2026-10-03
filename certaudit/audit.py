"""Offline TLS certificate path auditing.

Scope:
  - Signature algorithm: sha256WithRSAEncryption only.
  - Extensions: BasicConstraints, KeyUsage, DNS SAN, DNS NameConstraints.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509.oid import ExtensionOID, SignatureAlgorithmOID


@dataclass
class AuditResult:
    """Result of a path audit.

    On success path holds the ordered chain from leaf to the trust
    anchor (inclusive). On failure path is None and reason
    describes why no qualifying path exists.
    """

    ok: bool
    path: Optional[list[x509.Certificate]] = None
    reason: str = ""


def _parse_der(der: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(der)


def _is_self_issued(cert: x509.Certificate) -> bool:
    """Self-issued means subject == issuer (not necessarily self-signed)."""
    return cert.subject == cert.issuer


def _verify_signature(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Verify cert's signature under issuer's key; sha256WithRSAEncryption only."""
    if cert.signature_algorithm_oid != SignatureAlgorithmOID.RSA_WITH_SHA256:
        return False
    key = issuer.public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        return False
    try:
        key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), SHA256())
    except InvalidSignature:
        return False
    return True


def _in_validity(cert: x509.Certificate, now: datetime) -> bool:
    """Closed-interval validity check at now."""
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def _basic_constraints(cert: x509.Certificate) -> tuple[bool, Optional[int]]:
    """Return (ca, path_length); absent extension means (False, None)."""
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        return False, None
    return bc.ca, bc.path_length


def _key_usage_allows_cert_sign(cert: x509.Certificate) -> bool:
    """Absent KeyUsage is permissive; present KeyUsage needs keyCertSign."""
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return True
    return ku.key_cert_sign


def _dns_sans(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound:
        return []
    return san.get_values_for_type(x509.DNSName)


def _name_constraints(
    cert: x509.Certificate,
) -> tuple[Optional[list[str]], list[str]]:
    """Return (permitted, excluded) DNS subtrees; permitted None means absent."""
    try:
        nc = cert.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        return None, []
    permitted = None
    if nc.permitted_subtrees is not None:
        permitted = [
            g.value for g in nc.permitted_subtrees if isinstance(g, x509.DNSName)
        ]
    excluded = [
        g.value for g in (nc.excluded_subtrees or []) if isinstance(g, x509.DNSName)
    ]
    return permitted, excluded


def _dns_matches(subtree: str, name: str) -> bool:
    """Case-insensitive DNS subtree match.

    "example.com" matches itself and label-boundary subdomains;
    ".example.com" matches only proper subdomains.
    "badexample.com" matches neither.
    """
    subtree = subtree.lower()
    name = name.lower()
    if subtree.startswith("."):
        return name.endswith(subtree) and len(name) > len(subtree)
    return name == subtree or name.endswith("." + subtree)


def _dns_permitted(
    name: str, permitted: Optional[list[str]], excluded: list[str]
) -> bool:
    if any(_dns_matches(sub, name) for sub in excluded):
        return False
    if permitted is None:
        return True
    return any(_dns_matches(sub, name) for sub in permitted)


def _valid_dns_name(name: str) -> bool:
    """ASCII-only, no wildcards."""
    if not name.isascii() or "*" in name:
        return False
    return bool(name)


def audit(
    leaf: bytes,
    peers: Sequence[bytes],
    anchors: Sequence[bytes],
    now: datetime,
) -> AuditResult:
    """Audit whether a qualifying certification path exists.

    Args:
        leaf: DER-encoded leaf certificate.
        peers: DER-encoded candidate intermediate certificates.
        anchors: DER-encoded explicit trust anchors.
        now: UTC moment of the audit.

    Returns:
        AuditResult with the qualifying path, or a failure reason.
    """
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    try:
        leaf_cert = _parse_der(leaf)
    except ValueError:
        return AuditResult(ok=False, reason="leaf is not a valid DER certificate")

    ca, _ = _basic_constraints(leaf_cert)
    if ca:
        return AuditResult(ok=False, reason="leaf must not be a CA")
    leaf_names = _dns_sans(leaf_cert)
    if not leaf_names:
        return AuditResult(ok=False, reason="leaf has no DNS SAN")
    if not all(_valid_dns_name(n) for n in leaf_names):
        return AuditResult(ok=False, reason="leaf DNS SAN must be ASCII without wildcards")
    if not _in_validity(leaf_cert, now):
        return AuditResult(ok=False, reason="leaf is not valid at the audit time")

    anchor_by_der: dict[bytes, x509.Certificate] = {}
    for der in anchors:
        try:
            anchor_by_der.setdefault(bytes(der), _parse_der(der))
        except ValueError:
            continue

    peer_by_der: dict[bytes, x509.Certificate] = {}
    for der in peers:
        try:
            peer_by_der.setdefault(bytes(der), _parse_der(der))
        except ValueError:
            continue

    def path_len_ok(candidate: x509.Certificate, below: list[x509.Certificate]) -> bool:
        _, path_length = _basic_constraints(candidate)
        if path_length is None:
            return True
        # Only non-self-issued intermediate CAs below the candidate count;
        # the leaf (below[0]) never counts.
        count = sum(1 for c in below[1:] if not _is_self_issued(c))
        return count <= path_length

    def name_constraints_ok(
        candidate: x509.Certificate, below: list[x509.Certificate]
    ) -> bool:
        permitted, excluded = _name_constraints(candidate)
        if permitted is None and not excluded:
            return True
        for index, cert in enumerate(below):
            if index > 0 and _is_self_issued(cert):
                # Self-issued intermediates are exempt from ancestors' DNS
                # constraints; the leaf (index 0) is never exempt.
                continue
            for name in _dns_sans(cert):
                if not _dns_permitted(name, permitted, excluded):
                    return False
        return True

    def intermediate_ok(
        candidate: x509.Certificate, below: list[x509.Certificate]
    ) -> bool:
        if not _in_validity(candidate, now):
            return False
        ca, _ = _basic_constraints(candidate)
        if not ca:
            return False
        if not _key_usage_allows_cert_sign(candidate):
            return False
        if not path_len_ok(candidate, below):
            return False
        if not name_constraints_ok(candidate, below):
            return False
        return True

    def search(chain: list[x509.Certificate], used: set[bytes]) -> Optional[list[x509.Certificate]]:
        current = chain[-1]
        # An anchor with matching subject and a valid signature ends the path.
        # Anchors need not be self-signed; their validity and extensions are
        # not checked.
        for der, anchor in anchor_by_der.items():
            if der in used:
                continue
            if anchor.subject == current.issuer and _verify_signature(current, anchor):
                return chain + [anchor]
        for der, candidate in peer_by_der.items():
            if der in used:
                continue
            if candidate.subject != current.issuer:
                continue
            if not _verify_signature(current, candidate):
                continue
            if not intermediate_ok(candidate, chain):
                continue
            result = search(chain + [candidate], used | {der})
            if result is not None:
                return result
        return None

    path = search([leaf_cert], {bytes(leaf)})
    if path is None:
        return AuditResult(ok=False, reason="no qualifying certification path exists")
    return AuditResult(ok=True, path=path)
