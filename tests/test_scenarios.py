"""Scenario tests: cross-signing, cycles, pathLen, self-issued key change."""

from __future__ import annotations

import random

import pytest

from certaudit import audit
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
def cross_pki():
    """Cross-signed intermediates sharing one subject name and key.

    I_GOOD is the viable branch; I_EXPIRED and I_NARROW are rejecting
    branches. LOOP1/LOOP2 form a reachable cycle once I_GOOD is removed.
    """
    root_key = gen_key()
    root = issue(
        subject=name("ROOT"), subject_key=root_key,
        issuer=name("ROOT"), issuer_key=root_key,
        ca=True, key_cert_sign=True,
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    x_key = gen_key()

    def cross(**kwargs):
        return issue(
            subject=name("XCA"), subject_key=x_key,
            issuer=name("ROOT"), issuer_key=root_key,
            ca=True, key_cert_sign=True, **kwargs,
        )

    i_good = cross(
        permitted=["example.com"], not_before=VALID_FROM, not_after=VALID_TO
    )
    i_expired = cross(not_before=EXPIRED_FROM, not_after=EXPIRED_TO)
    i_narrow = cross(
        permitted=["other.org"], not_before=VALID_FROM, not_after=VALID_TO
    )

    loop_key = gen_key()
    loop1 = issue(
        subject=name("XCA"), subject_key=x_key,
        issuer=name("LOOP"), issuer_key=loop_key,
        ca=True, key_cert_sign=True,
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    loop2 = issue(
        subject=name("LOOP"), subject_key=loop_key,
        issuer=name("XCA"), issuer_key=x_key,
        ca=True, key_cert_sign=True,
        not_before=VALID_FROM, not_after=VALID_TO,
    )

    noise_key = gen_key()
    noise = issue(
        subject=name("NOISE"), subject_key=noise_key,
        issuer=name("NOISE"), issuer_key=noise_key,
        ca=True, key_cert_sign=True,
        not_before=VALID_FROM, not_after=VALID_TO,
    )

    leaf_key = gen_key()
    leaf = issue(
        subject=name("leaf"), subject_key=leaf_key,
        issuer=name("XCA"), issuer_key=x_key,
        ca=False, sans=["www.example.com"],
        not_before=VALID_FROM, not_after=VALID_TO,
    )
    return {
        "root": root, "leaf": leaf,
        "i_good": i_good, "i_expired": i_expired, "i_narrow": i_narrow,
        "loop1": loop1, "loop2": loop2, "noise": noise,
    }


def test_shuffled_duplicated_cross_signed_candidates(cross_pki):
    peers = [
        der(cross_pki["i_narrow"]),
        der(cross_pki["noise"]),
        der(cross_pki["i_expired"]),
        der(cross_pki["i_good"]),
        der(cross_pki["i_narrow"]),  # duplicate
        der(cross_pki["i_expired"]),  # duplicate
        der(cross_pki["noise"]),  # duplicate
    ]
    result = audit(der(cross_pki["leaf"]), peers, [der(cross_pki["root"])], NOW)
    assert result.ok
    # The qualifying path goes through the viable branch only.
    assert der(result.path[1]) == der(cross_pki["i_good"])
    assert der(result.path[2]) == der(cross_pki["root"])


def test_peer_order_and_duplicates_do_not_change_conclusion(cross_pki):
    base = [
        der(cross_pki["i_good"]),
        der(cross_pki["i_expired"]),
        der(cross_pki["i_narrow"]),
        der(cross_pki["noise"]),
    ]
    conclusions = set()
    for seed in range(8):
        shuffled = base * 3  # duplicates
        random.Random(seed).shuffle(shuffled)
        result = audit(der(cross_pki["leaf"]), shuffled, [der(cross_pki["root"])], NOW)
        conclusions.add(result.ok)
    assert conclusions == {True}


def test_cycle_terminates_and_rejects_without_viable_branch(cross_pki):
    peers = [
        der(cross_pki["i_expired"]),
        der(cross_pki["i_narrow"]),
        der(cross_pki["loop1"]),
        der(cross_pki["loop2"]),
        der(cross_pki["loop1"]),  # duplicate
    ]
    result = audit(der(cross_pki["leaf"]), peers, [der(cross_pki["root"])], NOW)
    assert not result.ok
