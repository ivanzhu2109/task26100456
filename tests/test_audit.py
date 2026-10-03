"""Tests for certaudit.audit. Certificates are really issued in-fixture."""

from __future__ import annotations

from datetime import timedelta

import pytest

from certaudit import audit
from certaudit.audit import _dns_matches
from factory import (
    EXPIRED_FROM,
    EXPIRED_TO,
    NOW,
    VALID_FROM,
    VALID_TO,
    der,
    gen_key,
    issue,
    name,
)


@pytest.fixture(scope="module")
def pki():
    """A simple root -> intermediate -> leaf PKI, all really signed."""
    root_key = gen_key()
    root = issue(
        subject=name("ROOT"), subject_key=root_key,
        issuer=name("ROOT"), issuer_key=root_key,
        ca=True, key_cert_sign=True,
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    int_key = gen_key()
    intermediate = issue(
        subject=name("INT"), subject_key=int_key,
        issuer=name("ROOT"), issuer_key=root_key,
        ca=True, key_cert_sign=True, permitted=["example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    leaf_key = gen_key()
    leaf = issue(
        subject=name("leaf"), subject_key=leaf_key,
        issuer=name("INT"), issuer_key=int_key,
        ca=False, sans=["www.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    return {
        "root_key": root_key, "root": root,
        "int_key": int_key, "intermediate": intermediate,
        "leaf_key": leaf_key, "leaf": leaf,
    }


def test_happy_path(pki):
    result = audit(
        der(pki["leaf"]), [der(pki["intermediate"])], [der(pki["root"])], NOW
    )
    assert result.ok
    assert [c.subject for c in result.path] == [
        pki["leaf"].subject,
        pki["intermediate"].subject,
        pki["root"].subject,
    ]


def test_anchor_must_be_der_exact_member(pki):
    # The root passed as a peer (not an anchor) cannot end the path.
    result = audit(
        der(pki["leaf"]),
        [der(pki["intermediate"]), der(pki["root"])],
        [],
        NOW,
    )
    assert not result.ok


def test_missing_intermediate_fails(pki):
    result = audit(der(pki["leaf"]), [], [der(pki["root"])], NOW)
    assert not result.ok


def test_leaf_validity_closed_interval(pki):
    assert not audit(
        der(pki["leaf"]), [der(pki["intermediate"])], [der(pki["root"])],
        VALID_FROM - timedelta(seconds=1),
    ).ok
    # Boundary instants are inside the closed interval.
    assert audit(
        der(pki["leaf"]), [der(pki["intermediate"])], [der(pki["root"])],
        VALID_FROM,
    ).ok


def test_leaf_must_not_be_ca(pki):
    key = gen_key()
    ca_leaf = issue(
        subject=name("leafca"), subject_key=key,
        issuer=name("INT"), issuer_key=pki["int_key"],
        ca=True, key_cert_sign=True, sans=["www.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    assert not audit(
        der(ca_leaf), [der(pki["intermediate"])], [der(pki["root"])], NOW
    ).ok


def test_leaf_needs_dns_san(pki):
    key = gen_key()
    no_san = issue(
        subject=name("leaf"), subject_key=key,
        issuer=name("INT"), issuer_key=pki["int_key"],
        ca=False, not_before=VALID_FROM, not_after=VALID_TO,
    )
    assert not audit(
        der(no_san), [der(pki["intermediate"])], [der(pki["root"])], NOW
    ).ok


def test_leaf_wildcard_rejected(pki):
    key = gen_key()
    wild = issue(
        subject=name("leaf"), subject_key=key,
        issuer=name("INT"), issuer_key=pki["int_key"],
        ca=False, sans=["*.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    assert not audit(
        der(wild), [der(pki["intermediate"])], [der(pki["root"])], NOW
    ).ok


def test_intermediate_key_usage(pki):
    key = gen_key()
    no_sign = issue(
        subject=name("INT2"), subject_key=key,
        issuer=name("ROOT"), issuer_key=pki["root_key"],
        ca=True, key_cert_sign=False,
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    leaf_key = gen_key()
    leaf = issue(
        subject=name("leaf"), subject_key=leaf_key,
        issuer=name("INT2"), issuer_key=key,
        ca=False, sans=["www.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    assert not audit(der(leaf), [der(no_sign)], [der(pki["root"])], NOW).ok


def test_intermediate_without_key_usage_extension_ok(pki):
    key = gen_key()
    no_ku = issue(
        subject=name("INT3"), subject_key=key,
        issuer=name("ROOT"), issuer_key=pki["root_key"],
        ca=True, key_cert_sign=None,
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    leaf_key = gen_key()
    leaf = issue(
        subject=name("leaf"), subject_key=leaf_key,
        issuer=name("INT3"), issuer_key=key,
        ca=False, sans=["www.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    assert audit(der(leaf), [der(no_ku)], [der(pki["root"])], NOW).ok


def test_non_ca_intermediate_rejected(pki):
    key = gen_key()
    not_ca = issue(
        subject=name("INT4"), subject_key=key,
        issuer=name("ROOT"), issuer_key=pki["root_key"],
        ca=False, not_before=VALID_FROM, not_after=VALID_TO,
    )
    leaf_key = gen_key()
    leaf = issue(
        subject=name("leaf"), subject_key=leaf_key,
        issuer=name("INT4"), issuer_key=key,
        ca=False, sans=["www.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    assert not audit(der(leaf), [der(not_ca)], [der(pki["root"])], NOW).ok


def test_excluded_subtree_rejects(pki):
    key = gen_key()
    excl = issue(
        subject=name("INTX"), subject_key=key,
        issuer=name("ROOT"), issuer_key=pki["root_key"],
        ca=True, key_cert_sign=True, excluded=["bad.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    leaf_key = gen_key()
    bad_leaf = issue(
        subject=name("leaf"), subject_key=leaf_key,
        issuer=name("INTX"), issuer_key=key,
        ca=False, sans=["bad.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    assert not audit(der(bad_leaf), [der(excl)], [der(pki["root"])], NOW).ok
    good_leaf = issue(
        subject=name("leaf"), subject_key=leaf_key,
        issuer=name("INTX"), issuer_key=key,
        ca=False, sans=["good.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    assert audit(der(good_leaf), [der(excl)], [der(pki["root"])], NOW).ok
