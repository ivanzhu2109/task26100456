"""pathLen=0 CA: normal intermediates rejected, self-issued key change
allowed; DNS constraint exemption of the self-issued certificate and
enforcement of its own constraints on the leaf."""

from __future__ import annotations

import pytest

from certaudit import audit
from factory import NOW, VALID_FROM, VALID_TO, der, gen_key, issue, name


@pytest.fixture(scope="module")
def pki():
    root_key = gen_key()
    root = issue(
        subject=name("ROOT2"), subject_key=root_key,
        issuer=name("ROOT2"), issuer_key=root_key,
        ca=True, key_cert_sign=True,
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    ca0_old_key = gen_key()
    ca0 = issue(
        subject=name("CA0"), subject_key=ca0_old_key,
        issuer=name("ROOT2"), issuer_key=root_key,
        ca=True, path_len=0, key_cert_sign=True,
        permitted=["example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    # Self-issued key-change certificate: same name as CA0, new key,
    # signed by CA0's old key. Its own SAN falls outside CA0's permitted
    # subtree, which must be excused by the self-issued exemption.
    ca0_new_key = gen_key()
    self_issued = issue(
        subject=name("CA0"), subject_key=ca0_new_key,
        issuer=name("CA0"), issuer_key=ca0_old_key,
        ca=True, key_cert_sign=True,
        sans=["unrelated.org"],
        permitted=["example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    leaf_key = gen_key()
    leaf = issue(
        subject=name("leaf"), subject_key=leaf_key,
        issuer=name("CA0"), issuer_key=ca0_new_key,
        ca=False, sans=["www.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    return {
        "root": root, "ca0": ca0, "self_issued": self_issued,
        "leaf": leaf, "ca0_old_key": ca0_old_key,
    }


def test_self_issued_key_change_passes_under_pathlen_zero(pki):
    result = audit(
        der(pki["leaf"]),
        [der(pki["self_issued"]), der(pki["ca0"])],
        [der(pki["root"])],
        NOW,
    )
    assert result.ok
    assert [c.subject for c in result.path] == [
        pki["leaf"].subject,
        pki["self_issued"].subject,
        pki["ca0"].subject,
        pki["root"].subject,
    ]


def test_self_issued_exempt_from_ancestor_dns_constraints(pki):
    # The self-issued certificate carries SAN "unrelated.org", outside
    # CA0's permitted "example.com". The path still succeeds, proving
    # the exemption; without it this fixture could not pass.
    result = audit(
        der(pki["leaf"]),
        [der(pki["ca0"]), der(pki["self_issued"])],
        [der(pki["root"])],
        NOW,
    )
    assert result.ok


def test_normal_intermediate_rejected_under_pathlen_zero(pki):
    n_key = gen_key()
    normal = issue(
        subject=name("N"), subject_key=n_key,
        issuer=name("CA0"), issuer_key=pki["ca0_old_key"],
        ca=True, key_cert_sign=True,
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    leaf_key = gen_key()
    leaf = issue(
        subject=name("leaf"), subject_key=leaf_key,
        issuer=name("N"), issuer_key=n_key,
        ca=False, sans=["www.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    result = audit(
        der(leaf), [der(normal), der(pki["ca0"])], [der(pki["root"])], NOW
    )
    assert not result.ok


def test_self_issued_own_constraints_still_apply_to_leaf(pki):
    ca0_new_key = gen_key()
    strict = issue(
        subject=name("CA0"), subject_key=ca0_new_key,
        issuer=name("CA0"), issuer_key=pki["ca0_old_key"],
        ca=True, key_cert_sign=True,
        permitted=["app.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    leaf_key = gen_key()
    leaf = issue(
        subject=name("leaf"), subject_key=leaf_key,
        issuer=name("CA0"), issuer_key=ca0_new_key,
        ca=False, sans=["www.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    result = audit(
        der(leaf), [der(strict), der(pki["ca0"])], [der(pki["root"])], NOW
    )
    assert not result.ok
