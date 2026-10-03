"""Offline TLS certificate path audit library.

Scope:
- Signature algorithm: sha256WithRSAEncryption only.
- Extensions: BasicConstraints, KeyUsage, DNS SAN, DNS NameConstraints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID, SignatureAlgorithmOID

from datetime import timezone


@dataclass
class AuditResult:
    """Result of a path audit.

    On success ``path`` holds the chain from leaf (index 0) up to and
    including the trust anchor (last element), as DER bytes.
    On failure ``path`` is None and ``reason`` describes the failure.
    """

    ok: bool
    path: Optional[list[bytes]] = None
    reason: str = ""


def audit(
    leaf: bytes,
    peers: Sequence[bytes],
    anchors: Sequence[bytes],
    now: datetime,
) -> AuditResult:
    """Audit whether a valid certification path exists.

    Args:
        leaf: DER-encoded leaf certificate.
        peers: DER-encoded candidate intermediate/peer certificates.
        anchors: DER-encoded explicit trust anchors. Only byte-identical
            DER may terminate a path.
        now: UTC moment for validity checks.

    Returns:
        AuditResult with the discovered path, or a failure reason.
    """
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    try:
        leaf_cert = x509.load_der_x509_certificate(leaf)
    except Exception:
        return AuditResult(False, None, "leaf: cannot parse DER")

    failure = _check_leaf(leaf_cert, now)
    if failure:
        return AuditResult(False, None, failure)

    anchor_certs: dict[bytes, x509.Certificate] = {}
    for der in anchors:
        if der not in anchor_certs:
            try:
                anchor_certs[der] = x509.load_der_x509_certificate(der)
            except Exception:
                continue

    peer_certs: dict[bytes, x509.Certificate] = {}
    for der in peers:
        if der not in peer_certs and der not in anchor_certs:
            try:
                peer_certs[der] = x509.load_der_x509_certificate(der)
            except Exception:
                continue

    if leaf in anchor_certs:
        return AuditResult(True, [leaf])

    found = _search([leaf_cert], {leaf}, peer_certs, anchor_certs, now)
    if found is None:
        return AuditResult(False, None, "no valid path to a trust anchor")
    return AuditResult(True, [c.public_bytes(Encoding.DER) for c in found])


def _search(chain, chain_ders, peer_certs, anchor_certs, now):
    current = chain[-1]
    for der, candidate in list(anchor_certs.items()) + list(peer_certs.items()):
        if der in chain_ders:
            continue
        if candidate.subject != current.issuer:
            continue
        if not _signature_valid(current, candidate):
            continue
        if der in anchor_certs:
            return chain + [candidate]
        if _check_intermediate(candidate, now):
            continue
        new_chain = chain + [candidate]
        if not _path_len_ok(new_chain):
            continue
        if not _name_constraints_ok(new_chain):
            continue
        result = _search(new_chain, chain_ders | {der}, peer_certs, anchor_certs, now)
        if result is not None:
            return result
    return None


def _is_self_issued(cert):
    return cert.subject == cert.issuer


def _signature_valid(child, issuer):
    if child.signature_algorithm_oid != SignatureAlgorithmOID.RSA_WITH_SHA256:
        return False
    key = issuer.public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        return False
    try:
        key.verify(
            child.signature,
            child.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True


def _in_validity(cert, now):
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def _check_leaf(cert, now):
    if cert.signature_algorithm_oid != SignatureAlgorithmOID.RSA_WITH_SHA256:
        return "leaf: unsupported signature algorithm"
    if not _in_validity(cert, now):
        return "leaf: not valid at the given time"
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        if bc.ca:
            return "leaf: must not be a CA"
    except x509.ExtensionNotFound:
        pass
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound:
        return "leaf: missing DNS SAN"
    dns_names = san.get_values_for_type(x509.DNSName)
    if not dns_names:
        return "leaf: missing DNS SAN"
    for name in dns_names:
        if not name.isascii():
            return "leaf: non-ASCII DNS SAN"
        if "*" in name:
            return "leaf: wildcard DNS SAN"
    return None


def _check_intermediate(cert, now):
    """Return a failure string, or None if the cert is acceptable."""
    if cert.signature_algorithm_oid != SignatureAlgorithmOID.RSA_WITH_SHA256:
        return "intermediate: unsupported signature algorithm"
    if not _in_validity(cert, now):
        return "intermediate: not valid at the given time"
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        return "intermediate: missing BasicConstraints"
    if not bc.ca:
        return "intermediate: not a CA"
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if not ku.key_cert_sign:
            return "intermediate: keyCertSign not allowed"
    except x509.ExtensionNotFound:
        pass
    return None


def _path_len_ok(chain):
    """chain = [leaf, i1, ..., ik]; check each intermediate's pathLenConstraint.

    pathLen counts only non-self-issued intermediate CAs below the CA;
    the leaf is never counted.
    """
    for pos in range(1, len(chain)):
        ca = chain[pos]
        try:
            bc = ca.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
        except x509.ExtensionNotFound:
            continue
        limit = bc.path_length
        if limit is None:
            continue
        below = sum(
            1 for lower in chain[1:pos] if not _is_self_issued(lower)
        )
        if below > limit:
            return False
    return True


def _name_constraints_ok(chain):
    """chain = [leaf, i1, ..., ik]; each intermediate's DNS NameConstraints
    must cover every DNS SAN of every lower cert.

    Self-issued intermediates are exempt from ancestors' constraints (but
    their own constraints still apply downward); the leaf is never exempt.
    """
    for pos in range(1, len(chain)):
        ca = chain[pos]
        try:
            nc = ca.extensions.get_extension_for_oid(
                ExtensionOID.NAME_CONSTRAINTS
            ).value
        except x509.ExtensionNotFound:
            continue
        for lower in chain[:pos]:
            if lower is not chain[0] and _is_self_issued(lower):
                continue
            for name in _dns_sans(lower):
                if not _dns_name_allowed(name, nc):
                    return False
    return True


def _dns_sans(cert):
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound:
        return []
    return san.get_values_for_type(x509.DNSName)


def _dns_name_allowed(name, nc):
    excluded = [
        d.value
        for d in (nc.excluded_subtrees or [])
        if isinstance(d, x509.DNSName)
    ]
    if any(_dns_match(name, sub) for sub in excluded):
        return False
    permitted = [
        d.value
        for d in (nc.permitted_subtrees or [])
        if isinstance(d, x509.DNSName)
    ]
    if permitted:
        return any(_dns_match(name, sub) for sub in permitted)
    return True


def _dns_match(host, subtree):
    host = host.lower()
    subtree = subtree.lower()
    if subtree.startswith("."):
        return host.endswith(subtree) and len(host) > len(subtree)
    return host == subtree or host.endswith("." + subtree)
