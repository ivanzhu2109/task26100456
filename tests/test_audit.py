import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from certbuild import issue, make_key, name
from tls_audit import audit

NOW = datetime.now(timezone.utc)
PAST = NOW - timedelta(days=10)
FUTURE = NOW + timedelta(days=10)


@pytest.fixture(scope="module")
def keys():
    return {k: make_key() for k in ("a", "x", "b", "q", "l0", "l0b", "m", "leaf")}


def leaf_cert(keys, issuer_name, signing_key, sans, **kw):
    return issue(
        name("leaf"),
        issuer_name,
        keys["leaf"],
        signing_key,
        ca=False,
        dns_sans=sans,
        **kw,
    )


# ---------------------------------------------------------------------------
# Cross-signed candidates: shuffled / duplicated peers, expired and
# domain-restricted rejected branches coexisting with a viable branch.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cross(keys):
    ka, kx, kb, kq = keys["a"], keys["x"], keys["b"], keys["q"]
    # Trust anchor: not self-signed (issuer "root" is nowhere) and expired;
    # anchors are exempt from validity/extension checks.
    anchor = issue(
        name("anchor"), name("root"), ka, ka, ca=True,
        not_before=PAST - timedelta(days=100), not_after=PAST,
    )
    # Viable intermediate.
    x_ok = issue(name("x"), name("anchor"), kx, ka, ca=True)
    # Cross-signed by an unavailable root "b": dead-end branch.
    x_cross = issue(name("x"), name("b"), kx, kb, ca=True)
    # Expired branch.
    x_expired = issue(
        name("x"), name("anchor"), kx, ka, ca=True,
        not_before=PAST - timedelta(days=100), not_after=PAST,
    )
    # Domain-restricted branch: leaf SAN is outside the permitted subtree.
    x_restricted = issue(
        name("x"), name("anchor"), kx, ka, ca=True, permitted=["other.org"]
    )
    # Irrelevant certificate.
    z = issue(name("z"), name("anchor"), keys["m"], ka, ca=True)
    leaf = leaf_cert(keys, name("x"), kx, ["www.example.com"])
    # Cycle reachable from the leaf: p (subject "x", key kx) <-> q.
    p = issue(name("x"), name("q"), kx, kq, ca=True)
    q = issue(name("q"), name("x"), kq, kx, ca=True)
    return {
        "anchor": anchor, "x_ok": x_ok, "x_cross": x_cross,
        "x_expired": x_expired, "x_restricted": x_restricted, "z": z,
        "leaf": leaf, "p": p, "q": q,
    }


def test_viable_path_found_among_rejected_branches(cross):
    peers = [cross["z"], cross["x_cross"], cross["x_expired"],
             cross["x_restricted"], cross["x_ok"]]
    result = audit(cross["leaf"], peers, [cross["anchor"]], NOW)
    assert result.ok
    assert result.path == [cross["leaf"], cross["x_ok"], cross["anchor"]]


def test_result_independent_of_order_duplicates_and_irrelevant(cross):
    base = [cross["z"], cross["x_cross"], cross["x_expired"],
            cross["x_restricted"], cross["x_ok"]]
    for seed in range(5):
        peers = base + [cross["x_ok"], cross["z"], cross["x_cross"]]
        random.Random(seed).shuffle(peers)
        result = audit(cross["leaf"], peers, [cross["anchor"]], NOW)
        assert result.ok
        assert result.path == [cross["leaf"], cross["x_ok"], cross["anchor"]]


def test_cycle_terminates_and_rejects_after_viable_removed(cross):
    peers = [cross["z"], cross["x_cross"], cross["x_expired"],
             cross["x_restricted"], cross["p"], cross["q"]]
    result = audit(cross["leaf"], peers, [cross["anchor"]], NOW)
    assert not result.ok


def test_anchor_must_be_der_identical(cross, keys):
    # Same subject and key as the anchor, but re-issued: different DER.
    # As a peer it is a perfectly valid intermediate, yet it cannot
    # terminate the path because it is not byte-identical to any anchor.
    lookalike = issue(
        name("anchor"), name("root"), keys["a"], keys["a"], ca=True
    )
    unrelated_anchor = issue(
        name("unrelated"), name("unrelated"), keys["b"], keys["b"], ca=True
    )
    result = audit(cross["leaf"], [cross["x_ok"], lookalike],
                   [unrelated_anchor], NOW)
    assert not result.ok
    # The identical DER does terminate the path.
    assert audit(cross["leaf"], [cross["x_ok"]], [lookalike], NOW).ok


# ---------------------------------------------------------------------------
# pathLen = 0 on a non-anchor CA.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def pathlen(keys):
    ka, kl0, kl0b, km = keys["a"], keys["l0"], keys["l0b"], keys["m"]
    anchor = issue(name("anchor"), name("anchor"), ka, ka, ca=True)
    # pathLen=0 CA, constrains descendants to example.com.
    l0 = issue(
        name("l0"), name("anchor"), kl0, ka, ca=True,
        path_length=0, permitted=["example.com"],
    )
    # Self-issued re-key of l0 (new key kl0b), signed by the old key.
    # Its SAN violates l0's permitted subtree, but self-issued certs are
    # exempt from ancestors' constraints. Its own constraint still applies
    # to the leaf.
    l0_rekey = issue(
        name("l0"), name("l0"), kl0b, kl0, ca=True,
        dns_sans=["unrelated.org"], permitted=["sub.example.com"],
    )
    # Ordinary (non-self-issued) intermediate below l0.
    m = issue(name("m"), name("l0"), km, kl0, ca=True)
    leaf_ok = leaf_cert(keys, name("l0"), kl0b, ["app.sub.example.com"])
    leaf_bad = leaf_cert(keys, name("l0"), kl0b, ["app.other.org"])
    leaf_m = leaf_cert(keys, name("m"), km, ["www.example.com"])
    return {
        "anchor": anchor, "l0": l0, "l0_rekey": l0_rekey, "m": m,
        "leaf_ok": leaf_ok, "leaf_bad": leaf_bad, "leaf_m": leaf_m,
    }


def test_pathlen_zero_rejects_normal_intermediate(pathlen):
    peers = [pathlen["m"], pathlen["l0"]]
    result = audit(pathlen["leaf_m"], peers, [pathlen["anchor"]], NOW)
    assert not result.ok


def test_pathlen_zero_allows_self_issued_rekey(pathlen):
    peers = [pathlen["l0_rekey"], pathlen["l0"]]
    result = audit(pathlen["leaf_ok"], peers, [pathlen["anchor"]], NOW)
    assert result.ok
    assert result.path == [
        pathlen["leaf_ok"], pathlen["l0_rekey"], pathlen["l0"],
        pathlen["anchor"],
    ]


def test_self_issued_own_constraints_still_apply_to_leaf(pathlen):
    # Leaf SAN is outside the re-key cert's own permitted subtree;
    # the leaf is never exempt.
    peers = [pathlen["l0_rekey"], pathlen["l0"]]
    result = audit(pathlen["leaf_bad"], peers, [pathlen["anchor"]], NOW)
    assert not result.ok


# ---------------------------------------------------------------------------
# DNS NameConstraints matching semantics.
# ---------------------------------------------------------------------------

def _run_with_constraint(keys, permitted=None, excluded=None, sans=None):
    ka, kx = keys["a"], keys["x"]
    anchor = issue(name("anchor"), name("anchor"), ka, ka, ca=True)
    inter = issue(
        name("x"), name("anchor"), kx, ka, ca=True,
        permitted=permitted, excluded=excluded,
    )
    leaf = leaf_cert(keys, name("x"), kx, sans or ["www.example.com"])
    return audit(leaf, [inter], [anchor], NOW)


def test_dns_bare_domain_matches_self_and_subdomains(keys):
    assert _run_with_constraint(keys, permitted=["example.com"],
                                sans=["example.com"]).ok
    assert _run_with_constraint(keys, permitted=["example.com"],
                                sans=["a.b.example.com"]).ok
    assert not _run_with_constraint(keys, permitted=["example.com"],
                                    sans=["badexample.com"]).ok


def test_dns_leading_dot_matches_only_proper_subdomains(keys):
    assert _run_with_constraint(keys, permitted=[".example.com"],
                                sans=["a.example.com"]).ok
    assert not _run_with_constraint(keys, permitted=[".example.com"],
                                    sans=["example.com"]).ok
    assert not _run_with_constraint(keys, permitted=[".example.com"],
                                    sans=["badexample.com"]).ok


def test_dns_case_insensitive(keys):
    assert _run_with_constraint(keys, permitted=["EXAMPLE.com"],
                                sans=["WWW.Example.COM"]).ok


def test_dns_excluded_rejects(keys):
    result = _run_with_constraint(
        keys, permitted=["example.com"], excluded=["bad.example.com"],
        sans=["bad.example.com"],
    )
    assert not result.ok
    assert _run_with_constraint(
        keys, permitted=["example.com"], excluded=["bad.example.com"],
        sans=["good.example.com"],
    ).ok


def test_constraints_of_all_ancestors_apply(keys):
    ka, kx, km = keys["a"], keys["x"], keys["m"]
    anchor = issue(name("anchor"), name("anchor"), ka, ka, ca=True)
    upper = issue(name("upper"), name("anchor"), kx, ka, ca=True,
                  permitted=["example.com"])
    lower = issue(name("lower"), name("upper"), km, kx, ca=True,
                  permitted=[".corp.example.com"])
    ok_leaf = leaf_cert(keys, name("lower"), km, ["a.corp.example.com"])
    bad_leaf = leaf_cert(keys, name("lower"), km, ["a.example.com"])
    assert audit(ok_leaf, [lower, upper], [anchor], NOW).ok
    assert not audit(bad_leaf, [lower, upper], [anchor], NOW).ok


# ---------------------------------------------------------------------------
# Leaf and intermediate eligibility.
# ---------------------------------------------------------------------------

def test_expired_leaf_rejected(keys):
    ka, kx = keys["a"], keys["x"]
    anchor = issue(name("anchor"), name("anchor"), ka, ka, ca=True)
    inter = issue(name("x"), name("anchor"), kx, ka, ca=True)
    leaf = leaf_cert(keys, name("x"), kx, ["www.example.com"],
                     not_before=PAST - timedelta(days=100), not_after=PAST)
    assert not audit(leaf, [inter], [anchor], NOW).ok


def test_intermediate_without_keycertsign_rejected(keys):
    ka, kx = keys["a"], keys["x"]
    anchor = issue(name("anchor"), name("anchor"), ka, ka, ca=True)
    inter = issue(name("x"), name("anchor"), kx, ka, ca=True,
                  key_cert_sign=False)
    leaf = leaf_cert(keys, name("x"), kx, ["www.example.com"])
    assert not audit(leaf, [inter], [anchor], NOW).ok


def test_intermediate_with_keycertsign_accepted(keys):
    ka, kx = keys["a"], keys["x"]
    anchor = issue(name("anchor"), name("anchor"), ka, ka, ca=True)
    inter = issue(name("x"), name("anchor"), kx, ka, ca=True,
                  key_cert_sign=True)
    leaf = leaf_cert(keys, name("x"), kx, ["www.example.com"])
    assert audit(leaf, [inter], [anchor], NOW).ok


def test_wildcard_leaf_rejected(keys):
    ka, kx = keys["a"], keys["x"]
    anchor = issue(name("anchor"), name("anchor"), ka, ka, ca=True)
    inter = issue(name("x"), name("anchor"), kx, ka, ca=True)
    leaf = leaf_cert(keys, name("x"), kx, ["*.example.com"])
    assert not audit(leaf, [inter], [anchor], NOW).ok
