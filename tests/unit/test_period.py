"""Tests for period.py: deterministic disjoint shares from a signed policy and a membership list,
policy adoption, and the narrow-at-once, widen-with-consent rule.
"""

from __future__ import annotations

import random
from dataclasses import replace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from lets.canonical import b64url_decode, b64url_encode
from lets.crypto import Ed25519Signer
from lets.errors import ConflictError, PolicyError, SignatureError, ValidationError
from lets.period import (
    BudgetPolicy,
    Member,
    PolicyChange,
    WideningConsent,
    adopt_policy,
    classify_change,
    derive_budget,
    membership_digest,
    period_bounds,
    period_index,
)

DAY = 86_400 * 10**9
SIGNER = Ed25519Signer.from_seed("owner", bytes(range(32)))


def verifier(issuer: str, message: bytes, signature: str) -> bool:
    return issuer == "owner" and SIGNER.verify(message, b64url_decode(signature))


def policy(**overrides: Any) -> BudgetPolicy:
    base: dict[str, Any] = {
        "policy_id": "mesh-budget",
        "version": 1,
        "issuer": "owner",
        "epoch_ns": 1_000,
        "period_ns": DAY,
        "dimensions": ("model_tokens", "notes_write", "outside_effect"),
        "totals": (1_000_000, 1_000, 100),
        "shares": {
            "pocket": (200_000, 200, 20),
            "desktop": (400_000, 300, 20),
            "node": (800_000, 400, 20),
        },
        "solo": {
            "pocket": (50_000, 50, 0),
            "desktop": (100_000, 100, 0),
            "node": (100_000, 100, 0),
        },
        "attested_reduction_permille": 0,
        "unattested_reduction_permille": 500,
    }
    base.update(overrides)
    unsigned = BudgetPolicy(**base)
    return replace(unsigned, sig=b64url_encode(SIGNER.sign(unsigned.message())))


MEMBERS = [
    Member("phone", "pocket", True),
    Member("laptop", "desktop", True),
    Member("old-phone", "pocket", False),
]


def test_derivation_is_deterministic_and_order_independent() -> None:
    base = derive_budget(policy(), MEMBERS, 3)
    for seed in range(6):
        shuffled = list(MEMBERS)
        random.Random(seed).shuffle(shuffled)
        again = derive_budget(policy(), shuffled, 3)
        assert again == base
        assert again.digest == base.digest
    assert [item.member_id for item in base.shares] == ["laptop", "old-phone", "phone"]


def test_shares_are_disjoint_and_bounded_by_the_total() -> None:
    budget = derive_budget(policy(), MEMBERS, 0)
    for i, total in enumerate(budget.total):
        assert sum(item.fresh[i] for item in budget.shares) + budget.reserve[i] == total
    phone = budget.share_of("phone")
    assert phone is not None
    assert phone.fresh == (200_000, 200, 20)
    assert phone.solo == (50_000, 50, 0)
    assert budget.share_of("nobody") is None


def test_unattested_members_get_the_reduced_share() -> None:
    budget = derive_budget(policy(), MEMBERS, 0)
    old = budget.share_of("old-phone")
    assert old is not None
    assert old.fresh == (100_000, 100, 10)
    assert old.solo == (25_000, 25, 0)


def test_oversubscription_scales_every_member_down_proportionally() -> None:
    crowded = policy(totals=(300_000, 1_000, 100))
    budget = derive_budget(crowded, MEMBERS, 0)
    assert sum(item.fresh[0] for item in budget.shares) <= 300_000
    phone = budget.share_of("phone")
    laptop = budget.share_of("laptop")
    assert phone is not None and laptop is not None
    assert phone.fresh[0] == 200_000 * 300_000 // 700_000
    assert laptop.fresh[0] == 400_000 * 300_000 // 700_000
    assert all(item.solo[0] <= item.fresh[0] for item in budget.shares)


@given(
    kinds=st.lists(st.sampled_from(["pocket", "desktop", "node"]), min_size=1, max_size=12),
    attested=st.lists(st.booleans(), min_size=12, max_size=12),
    total=st.integers(min_value=0, max_value=2_000_000),
    seed=st.integers(min_value=0, max_value=1000),
)
def test_sum_never_exceeds_total_for_any_membership(
    kinds: list[str], attested: list[bool], total: int, seed: int
) -> None:
    members = [Member(f"m{i}", kind, attested[i]) for i, kind in enumerate(kinds)]
    candidate = policy(totals=(total, total, total))
    budget = derive_budget(candidate, members, 1)
    for i in range(3):
        assert sum(item.fresh[i] for item in budget.shares) <= total
        assert budget.reserve[i] >= 0
    shuffled = list(members)
    random.Random(seed).shuffle(shuffled)
    assert derive_budget(candidate, shuffled, 1) == budget


def test_membership_errors_are_refused() -> None:
    with pytest.raises(ValidationError, match="at least one"):
        derive_budget(policy(), [], 0)
    with pytest.raises(ValidationError, match="twice"):
        derive_budget(policy(), [MEMBERS[0], MEMBERS[0]], 0)
    with pytest.raises(PolicyError, match="no share"):
        derive_budget(policy(), [Member("x", "watch", True)], 0)
    with pytest.raises(ValidationError, match="at most"):
        derive_budget(policy(), [Member(f"m{i}", "pocket", True) for i in range(1025)], 0)
    with pytest.raises(ValidationError, match="boolean"):
        Member("x", "pocket", 1)  # type: ignore[arg-type]


def test_membership_digest_ignores_order() -> None:
    assert membership_digest(MEMBERS) == membership_digest(reversed(MEMBERS))
    assert membership_digest(MEMBERS) != membership_digest(MEMBERS[:2])


def test_period_index_and_bounds() -> None:
    p = policy()
    assert period_index(p, 1_000) == 0
    assert period_index(p, 1_000 + DAY - 1) == 0
    assert period_index(p, 1_000 + DAY) == 1
    assert period_bounds(p, 2) == (1_000 + 2 * DAY, 1_000 + 3 * DAY)
    with pytest.raises(PolicyError, match="before the policy epoch"):
        period_index(p, 999)
    with pytest.raises(ValidationError, match="64-bit"):
        period_bounds(p, (1 << 63) // DAY)


def test_wire_round_trip_and_strictness() -> None:
    p = policy()
    assert BudgetPolicy.from_dict(p.to_dict()) == p
    wire = p.to_dict()
    for broken in (
        wire | {"extra": 1},
        {k: v for k, v in wire.items() if k != "sig"},
        wire | {"type": "lets.period-policy/v2"},
        wire | {"reduction_permille": {"attested": 0}},
        wire | {"totals": {"model_tokens": 1}},
        wire | {"totals": [1, 2]},
        wire | {"totals": {**wire["totals"], "notes_write": 1.5}},
        wire | {"shares": {**wire["shares"], "pocket": {"model_tokens": 1}}},
    ):
        with pytest.raises(ValidationError):
            BudgetPolicy.from_dict(broken)


@pytest.mark.parametrize(
    "overrides",
    [
        {"version": 0},
        {"period_ns": 0},
        {"dimensions": ("b", "a"), "totals": (1, 1)},
        {"dimensions": (), "totals": ()},
        {"totals": (1, 2)},
        {"solo": {"pocket": (1, 1, 1)}},
        {"solo": {"pocket": (999_999_999, 50, 0), "desktop": (1, 1, 0), "node": (1, 1, 0)}},
        {"attested_reduction_permille": 1001},
        {"shares": {"pocket": (1, 1)}, "solo": {"pocket": (1, 1)}},
        {"sig": 5},
    ],
)
def test_invalid_policies_are_refused(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        policy(**overrides)


def test_signature_verification_is_pluggable_and_fails_closed() -> None:
    p = policy()
    p.verify(verifier)
    with pytest.raises(SignatureError, match="invalid"):
        replace(p, version=2).verify(verifier)
    with pytest.raises(SignatureError, match="invalid"):
        p.verify(lambda *_: "yes")  # type: ignore[arg-type, return-value]

    def explode(*_: Any) -> bool:
        raise RuntimeError("boom")

    with pytest.raises(SignatureError, match="could not be verified"):
        p.verify(explode)


def test_classification() -> None:
    base = policy()
    assert classify_change(base, policy(version=2)) is PolicyChange.UNCHANGED
    narrower = policy(version=2, totals=(900_000, 1_000, 100))
    assert classify_change(base, narrower) is PolicyChange.NARROWED
    assert (
        classify_change(base, policy(version=2, unattested_reduction_permille=600))
        is PolicyChange.NARROWED
    )
    assert (
        classify_change(base, policy(version=2, unattested_reduction_permille=400))
        is PolicyChange.WIDENED
    )
    assert (
        classify_change(base, policy(version=2, totals=(1_000_001, 1_000, 100)))
        is PolicyChange.WIDENED
    )
    mixed = policy(version=2, totals=(900_000, 1_001, 100))
    assert classify_change(base, mixed) is PolicyChange.WIDENED
    wider_solo = policy(
        version=2,
        solo={"pocket": (60_000, 50, 0), "desktop": (100_000, 100, 0), "node": (100_000, 100, 0)},
    )
    assert classify_change(base, wider_solo) is PolicyChange.WIDENED
    assert classify_change(base, policy(version=2, period_ns=DAY // 2)) is PolicyChange.WIDENED
    assert classify_change(base, policy(version=2, epoch_ns=0)) is PolicyChange.WIDENED
    assert (
        classify_change(base, policy(version=2, dimensions=("a", "b", "c"))) is PolicyChange.WIDENED
    )
    fewer_kinds = policy(
        version=2,
        shares={"pocket": (200_000, 200, 20)},
        solo={"pocket": (50_000, 50, 0)},
    )
    assert classify_change(base, fewer_kinds) is PolicyChange.WIDENED


def test_adoption_applies_narrowing_at_once_and_requires_consent_to_widen() -> None:
    first = adopt_policy(None, policy(), verifier=verifier)
    narrower = policy(version=2, totals=(500_000, 1_000, 100))
    assert adopt_policy(first, narrower, verifier=verifier) is narrower
    wider = policy(version=3, totals=(2_000_000, 1_000, 100))
    with pytest.raises(PolicyError, match="needs consent"):
        adopt_policy(narrower, wider, verifier=verifier)
    wrong = WideningConsent("sha256:" + "0" * 64, "owner", "biometric-1")
    with pytest.raises(PolicyError, match="needs consent"):
        adopt_policy(narrower, wider, verifier=verifier, consent=wrong)
    marker = WideningConsent(wider.digest, "owner", "biometric-1")
    assert adopt_policy(narrower, wider, verifier=verifier, consent=marker) is wider
    budget = derive_budget(wider, MEMBERS, 0)
    assert budget.policy_digest == wider.digest


def test_adoption_refuses_stale_foreign_and_unsigned_policies() -> None:
    current = policy(version=5)
    assert adopt_policy(current, policy(version=5), verifier=verifier) is current
    with pytest.raises(PolicyError, match="not newer"):
        adopt_policy(current, policy(version=4, totals=(1, 1, 1)), verifier=verifier)
    with pytest.raises(PolicyError, match="not newer"):
        adopt_policy(current, policy(version=5, totals=(1, 1, 1)), verifier=verifier)
    with pytest.raises(ConflictError):
        adopt_policy(current, policy(version=6, policy_id="other"), verifier=verifier)
    forged = replace(policy(version=6), sig=b64url_encode(bytes(64)))
    with pytest.raises(SignatureError):
        adopt_policy(current, forged, verifier=verifier)


def test_consent_marker_requires_every_field() -> None:
    with pytest.raises(ValidationError):
        WideningConsent("", "owner", "x")
