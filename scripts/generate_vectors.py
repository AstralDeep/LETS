"""Generates the signed, deterministic conformance vectors under protocol/vectors from fixed test
keys and fixed clocks. Run it to rewrite them, or with --check in CI to prove the committed
files still match what the reference implementation emits.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Any

from lets.canonical import b64url_encode, canonical_digest, canonical_json
from lets.crypto import Ed25519Signer
from lets.models import LeaseGrant, Receipt, TransferAck, TransferVoucher
from lets.period import BudgetPolicy, Member, PolicyChange, WideningConsent, derive_budget

VECTOR_DIR = Path(__file__).resolve().parents[1] / "protocol" / "vectors"
NOW = 1_800_000_000_000_000_000
SECOND = 1_000_000_000
POLICY_DIGEST = "sha256:" + sha256(b"lets-vectors/policy").hexdigest()
OTHER_POLICY_DIGEST = "sha256:" + sha256(b"lets-vectors/other-policy").hexdigest()
MACHINE_DIGEST = "sha256:" + sha256(b"lets-vectors/machine").hexdigest()
EVIDENCE_DIGEST = "sha256:" + sha256(b"lets-vectors/evidence").hexdigest()

KEY_NAMES = ("warden-a", "warden-b", "mallory", "owner")


def signer_for(name: str) -> Ed25519Signer:
    seed = sha256(f"lets-vectors/key/{name}".encode()).digest()
    warden_id = "mallory" if name == "mallory" else name
    return Ed25519Signer.from_seed(warden_id, seed)


SIGNERS = {name: signer_for(name) for name in KEY_NAMES}


def key_entry(name: str) -> dict[str, str]:
    signer = SIGNERS[name]
    return {
        "name": name,
        "warden_id": signer.warden_id,
        "key_id": signer.key_id,
        "public_key": b64url_encode(signer.public_key_bytes),
    }


def trusted(*names: str) -> list[dict[str, str]]:
    return [key_entry(name) for name in names]


def sign(record: Any, signer: Ed25519Signer) -> Any:
    return replace(
        record, signature=b64url_encode(signer.sign(canonical_json(record.unsigned_payload())))
    )


def forged(record: Any, signer: Ed25519Signer, as_key_id: str) -> Any:
    unsigned = replace(record, key_id=as_key_id)
    return sign(unsigned, signer)


def step(
    record: Any, expect: str, *, now_ns: int | None = None, wire: dict[str, Any] | None = None
) -> dict[str, Any]:
    payload = record.to_dict() if wire is None else wire
    result: dict[str, Any] = {"wire": payload, "expect": expect}
    if now_ns is not None:
        result["now_ns"] = now_ns
    if wire is None:
        unsigned = canonical_json(record.unsigned_payload())
        result["signing_input"] = unsigned.decode("utf-8")
        result["signing_input_sha256"] = sha256(unsigned).hexdigest()
    return result


def case(
    name: str, description: str, verifier: dict[str, Any], *steps: dict[str, Any]
) -> dict[str, Any]:
    return {"name": name, "description": description, "verifier": verifier, "steps": list(steps)}


def document(
    wire_type: str, summary: str, cases: list[dict[str, Any]], keys: list[str]
) -> dict[str, Any]:
    return {
        "format": "lets.vectors/v1",
        "wire_type": wire_type,
        "summary": summary,
        "clock_ns": NOW,
        "trusted_keys": trusted(*keys),
        "cases": cases,
    }


def receipt_document() -> dict[str, Any]:
    warden = SIGNERS["warden-a"]
    mallory = SIGNERS["mallory"]

    def make(**overrides: Any) -> Receipt:
        base: dict[str, Any] = {
            "tenant_id": "tenant-1",
            "envelope_id": "envelope-1",
            "config_epoch": 1,
            "receipt_id": "receipt-0001",
            "request_id": "request-0001",
            "warden_id": warden.warden_id,
            "key_id": warden.key_id,
            "policy_id": "vector-policy",
            "policy_version": "v1",
            "policy_digest": POLICY_DIGEST,
            "machine_digest": MACHINE_DIGEST,
            "lease_id": "lease-root",
            "lineage_id": "lineage-1",
            "subject_id": "agent-1",
            "executor_audience": "executor-a",
            "transition": "act",
            "source_state": "ready",
            "target_state": "ready",
            "cost": (1, 0),
            "resulting_sequence": 1,
            "evidence_digest": None,
            "nonce": "nonce-0000000000000001",
            "issued_at_ns": NOW - 10 * SECOND,
            "expires_at_ns": NOW + 290 * SECOND,
        }
        base.update(overrides)
        return sign(Receipt(**base), warden)

    context = {
        "audience": "executor-a",
        "allowed_policy_digests": [POLICY_DIGEST],
        "trusted_wardens": [warden.warden_id],
    }
    valid = make()
    unknown_field = valid.to_dict() | {"extra": 1}
    wrong_type = valid.to_dict() | {"type": "lets.receipt/v2"}
    cases = [
        case(
            "valid-minimal",
            "A fresh receipt with a one-unit cost.",
            context,
            step(valid, "valid", now_ns=NOW),
        ),
        case(
            "valid-with-evidence",
            "A receipt that carries an evidence digest and a multi-dimension cost.",
            context,
            step(make(evidence_digest=EVIDENCE_DIGEST, cost=(3, 7)), "valid", now_ns=NOW),
        ),
        case(
            "valid-last-nanosecond",
            "The receipt is still fresh one nanosecond before its expiry.",
            context,
            step(valid, "valid", now_ns=valid.expires_at_ns - 1),
        ),
        case(
            "valid-first-nanosecond",
            "The receipt is accepted at the exact instant of issuance.",
            context,
            step(valid, "valid", now_ns=valid.issued_at_ns),
        ),
        case(
            "bad-signature",
            "Signed by another key but naming the trusted key id.",
            context,
            step(forged(make(), mallory, warden.key_id), "signature", now_ns=NOW),
        ),
        case(
            "wrong-audience",
            "The receipt names a different executor.",
            context,
            step(make(executor_audience="executor-b"), "audience", now_ns=NOW),
        ),
        case(
            "expired",
            "The executor clock is at the exact expiry instant.",
            context,
            step(valid, "expired", now_ns=valid.expires_at_ns),
        ),
        case(
            "not-yet-valid",
            "The executor clock is before issuance.",
            context,
            step(valid, "not_yet_valid", now_ns=valid.issued_at_ns - 1),
        ),
        case(
            "policy-digest-mismatch",
            "The receipt policy digest is not in the executor allow list.",
            context,
            step(make(policy_digest=OTHER_POLICY_DIGEST), "policy_digest", now_ns=NOW),
        ),
        case(
            "untrusted-issuer",
            "The issuing warden is not in the executor trusted set.",
            {**context, "trusted_wardens": ["warden-b"]},
            step(valid, "issuer", now_ns=NOW),
        ),
        case(
            "replayed-claim",
            "The same receipt is claimed twice. The second claim is refused.",
            context,
            step(valid, "valid", now_ns=NOW),
            step(valid, "replay", now_ns=NOW + SECOND),
        ),
        case(
            "malformed-unknown-field",
            "A field outside the frozen set is refused before any signature check.",
            context,
            step(valid, "malformed", now_ns=NOW, wire=unknown_field),
        ),
        case(
            "malformed-wire-type",
            "A different wire type is refused.",
            context,
            step(valid, "malformed", now_ns=NOW, wire=wrong_type),
        ),
    ]
    return document(Receipt.WIRE_TYPE, "Signed receipt and executor claim.", cases, ["warden-a"])


def lease_document() -> dict[str, Any]:
    warden = SIGNERS["warden-a"]
    mallory = SIGNERS["mallory"]

    def make(**overrides: Any) -> LeaseGrant:
        base: dict[str, Any] = {
            "tenant_id": "tenant-1",
            "envelope_id": "envelope-1",
            "config_epoch": 1,
            "lease_id": "lease-root",
            "lineage_id": "lineage-1",
            "parent_id": None,
            "subject_id": "agent-1",
            "warden_id": warden.warden_id,
            "allocation": (100, 20),
            "capabilities": frozenset({"tool.notes.write", "tool.web.send"}),
            "policy_id": "vector-policy",
            "policy_version": "v1",
            "policy_digest": POLICY_DIGEST,
            "machine_digest": MACHINE_DIGEST,
            "ancestor_path": (),
            "branch_epoch": 0,
            "issued_at_ns": NOW - 10 * SECOND,
            "expires_at_ns": NOW + 3600 * SECOND,
            "key_id": warden.key_id,
        }
        base.update(overrides)
        return sign(LeaseGrant(**base), warden)

    context = {
        "holder_warden": warden.warden_id,
        "policy_digest": POLICY_DIGEST,
    }
    root = make()
    child = make(
        lease_id="lease-child",
        parent_id="lease-root",
        ancestor_path=("lease-root",),
        allocation=(10, 0),
        capabilities=frozenset({"tool.notes.write"}),
        branch_epoch=2,
    )
    cases = [
        case(
            "valid-root",
            "A root lease inside its window.",
            context,
            step(root, "valid", now_ns=NOW),
        ),
        case(
            "valid-child",
            "A child lease with a one-entry ancestor path.",
            context,
            step(child, "valid", now_ns=NOW),
        ),
        case(
            "bad-signature",
            "Signed by another key but naming the trusted key id.",
            context,
            step(forged(make(), mallory, warden.key_id), "signature", now_ns=NOW),
        ),
        case(
            "wrong-audience",
            "The holder verifying the grant is not the warden it names.",
            {**context, "holder_warden": "warden-b"},
            step(root, "audience", now_ns=NOW),
        ),
        case(
            "expired",
            "The clock is at the exact expiry instant.",
            context,
            step(root, "expired", now_ns=root.expires_at_ns),
        ),
        case(
            "not-yet-valid",
            "The clock is before issuance.",
            context,
            step(root, "not_yet_valid", now_ns=root.issued_at_ns - 1),
        ),
        case(
            "policy-digest-mismatch",
            "The grant policy digest is not the one the holder expects.",
            {**context, "policy_digest": OTHER_POLICY_DIGEST},
            step(root, "policy_digest", now_ns=NOW),
        ),
        case(
            "malformed-unknown-field",
            "A field outside the frozen set is refused.",
            context,
            step(root, "malformed", now_ns=NOW, wire=root.to_dict() | {"extra": 1}),
        ),
    ]
    return document(LeaseGrant.WIRE_TYPE, "Signed lease grant.", cases, ["warden-a"])


def voucher_and_ack_documents() -> tuple[dict[str, Any], dict[str, Any]]:
    source = SIGNERS["warden-a"]
    target = SIGNERS["warden-b"]
    mallory = SIGNERS["mallory"]

    def make_voucher(**overrides: Any) -> TransferVoucher:
        base: dict[str, Any] = {
            "tenant_id": "tenant-1",
            "envelope_id": "envelope-1",
            "config_epoch": 1,
            "transfer_id": "transfer-0001",
            "source_warden": source.warden_id,
            "target_warden": target.warden_id,
            "policy_id": "vector-policy",
            "policy_version": "v1",
            "policy_digest": POLICY_DIGEST,
            "sequence": 1,
            "amount": (5, 1),
            "issued_at_ns": NOW - SECOND,
            "key_id": source.key_id,
        }
        base.update(overrides)
        return sign(TransferVoucher(**base), source)

    def make_ack(voucher: TransferVoucher, **overrides: Any) -> TransferAck:
        base: dict[str, Any] = {
            "tenant_id": voucher.tenant_id,
            "envelope_id": voucher.envelope_id,
            "config_epoch": voucher.config_epoch,
            "transfer_id": voucher.transfer_id,
            "source_warden": voucher.source_warden,
            "target_warden": voucher.target_warden,
            "sequence": voucher.sequence,
            "voucher_digest": canonical_digest(voucher.to_dict()),
            "accepted_at_ns": NOW,
            "contiguous_watermark": voucher.sequence,
            "key_id": target.key_id,
        }
        base.update(overrides)
        return sign(TransferAck(**base), target)

    voucher_context = {"receiver_warden": target.warden_id, "policy_digest": POLICY_DIGEST}
    pool = make_voucher()
    lease_request = {
        "child_lease_id": "lease-remote-child",
        "lineage_id": "lineage-1",
        "parent_id": "lease-root",
        "subject_id": "agent-1",
        "capabilities": ["tool.notes.write"],
        "ancestor_path": ["lease-root"],
        "branch_epoch": 1,
        "expires_at_ns": NOW + 3600 * SECOND,
    }
    lease_voucher = make_voucher(
        transfer_id="transfer-0002", sequence=2, kind="lease", lease_request=lease_request
    )
    conflicting = make_voucher(transfer_id="transfer-0003", amount=(6, 1))
    vouchers = [
        case(
            "valid-pool",
            "A pool transfer from warden-a to warden-b.",
            voucher_context,
            step(pool, "valid", now_ns=NOW),
        ),
        case(
            "valid-lease",
            "A transfer that carries a child lease request.",
            voucher_context,
            step(lease_voucher, "valid", now_ns=NOW),
        ),
        case(
            "valid-redelivery",
            "The identical voucher delivered twice is accepted both times.",
            voucher_context,
            step(pool, "valid", now_ns=NOW),
            step(pool, "valid", now_ns=NOW + SECOND),
        ),
        case(
            "bad-signature",
            "Signed by another key but naming the trusted key id.",
            voucher_context,
            step(forged(make_voucher(), mallory, source.key_id), "signature", now_ns=NOW),
        ),
        case(
            "wrong-audience",
            "The receiver is not the target the voucher names.",
            {**voucher_context, "receiver_warden": "warden-c"},
            step(pool, "audience", now_ns=NOW),
        ),
        case(
            "policy-digest-mismatch",
            "The voucher policy digest is not the one the receiver expects.",
            {**voucher_context, "policy_digest": OTHER_POLICY_DIGEST},
            step(pool, "policy_digest", now_ns=NOW),
        ),
        case(
            "replayed-sequence",
            "A second voucher reuses an accepted sequence with different content.",
            voucher_context,
            step(pool, "valid", now_ns=NOW),
            step(conflicting, "sequence_conflict", now_ns=NOW + SECOND),
        ),
        case(
            "malformed-unknown-field",
            "A field outside the frozen set is refused.",
            voucher_context,
            step(pool, "malformed", now_ns=NOW, wire=pool.to_dict() | {"extra": 1}),
        ),
    ]
    ack = make_ack(pool)
    lease_ack = make_ack(lease_voucher, child_lease_id="lease-remote-child", child_outcome="ISSUED")
    ack_context = {"source_warden": source.warden_id, "voucher": pool.to_dict()}
    lease_ack_context = {"source_warden": source.warden_id, "voucher": lease_voucher.to_dict()}
    acks = [
        case(
            "valid-pool",
            "An acknowledgement of a pool transfer.",
            ack_context,
            step(ack, "valid", now_ns=NOW),
        ),
        case(
            "valid-lease",
            "An acknowledgement that reports the child lease outcome.",
            lease_ack_context,
            step(lease_ack, "valid", now_ns=NOW),
        ),
        case(
            "bad-signature",
            "Signed by another key but naming the trusted key id.",
            ack_context,
            step(forged(make_ack(pool), mallory, target.key_id), "signature", now_ns=NOW),
        ),
        case(
            "wrong-audience",
            "The warden verifying the acknowledgement is not its source.",
            {**ack_context, "source_warden": "warden-c"},
            step(ack, "audience", now_ns=NOW),
        ),
        case(
            "voucher-digest-mismatch",
            "The acknowledgement answers a different voucher.",
            {**ack_context, "voucher": conflicting.to_dict()},
            step(ack, "voucher_digest", now_ns=NOW),
        ),
        case(
            "malformed-unknown-field",
            "A field outside the frozen set is refused.",
            ack_context,
            step(ack, "malformed", now_ns=NOW, wire=ack.to_dict() | {"extra": 1}),
        ),
    ]
    return (
        document(TransferVoucher.WIRE_TYPE, "Signed transfer voucher.", vouchers, ["warden-a"]),
        document(TransferAck.WIRE_TYPE, "Signed transfer acknowledgement.", acks, ["warden-b"]),
    )


DAY_NS = 86_400 * SECOND
PERIOD_EPOCH_NS = 10 * DAY_NS
CLOCK_START_NS = PERIOD_EPOCH_NS + 1_000
DIMENSIONS = ("model_tokens", "notes_write", "outside_effect")


def period_policy(**overrides: Any) -> BudgetPolicy:
    base: dict[str, Any] = {
        "policy_id": "mesh-budget",
        "version": 1,
        "issuer": "owner",
        "epoch_ns": PERIOD_EPOCH_NS,
        "period_ns": DAY_NS,
        "dimensions": DIMENSIONS,
        "totals": (1_000, 100, 10),
        "shares": {"pocket": (400, 20, 4), "desktop": (600, 80, 6)},
        "solo": {"pocket": (100, 5, 0), "desktop": (200, 10, 0)},
        "attested_reduction_permille": 0,
        "unattested_reduction_permille": 500,
    }
    base.update(overrides)
    unsigned = BudgetPolicy(**base)
    return replace(unsigned, sig=b64url_encode(SIGNERS["owner"].sign(unsigned.message())))


def member_wire(member_id: str, kind: str, attested: bool = True) -> dict[str, Any]:
    return Member(member_id, kind, attested).to_dict()


def derive_case(
    name: str, description: str, policy: BudgetPolicy, members: list[dict[str, Any]], index: int
) -> dict[str, Any]:
    budget = derive_budget(policy, [Member(**item) for item in members], index)
    return {
        "name": name,
        "description": description,
        "policy": policy.to_dict(),
        "members": members,
        "period_index": index,
        "expect": {"budget": budget.to_dict(), "digest": budget.digest},
    }


def refused_derive(
    name: str,
    description: str,
    policy: BudgetPolicy,
    members: list[dict[str, Any]],
    index: int,
    reason: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "policy": policy.to_dict(),
        "members": members,
        "period_index": index,
        "expect": {"refuse": reason},
    }


def period_document() -> dict[str, Any]:
    base = period_policy()
    trio = [
        member_wire("phone", "pocket"),
        member_wire("laptop", "desktop"),
        member_wire("old-phone", "pocket", False),
    ]
    crowded = period_policy(totals=(300, 100, 10))
    derive = [
        derive_case("two-members", "Two attested members under the totals.", base, trio[:2], 0),
        derive_case(
            "unattested-reduction",
            "An unattested member gets half of its kind's share, rounded down.",
            base,
            trio,
            0,
        ),
        derive_case(
            "input-order-does-not-matter",
            "The same members in another order give the identical budget.",
            base,
            [trio[2], trio[0], trio[1]],
            0,
        ),
        derive_case(
            "oversubscribed-scales-down",
            "Demand above the total scales every share by total over demand, rounding down.",
            crowded,
            trio,
            0,
        ),
        derive_case(
            "later-period", "Period 400 starts 400 periods after the epoch.", base, trio, 400
        ),
        derive_case(
            "odd-division-rounds-down",
            "A share that does not divide evenly rounds down and leaves a reserve.",
            period_policy(totals=(1_000, 100, 7)),
            trio[:2],
            1,
        ),
        derive_case(
            "single-member",
            "One member alone keeps its full share.",
            base,
            trio[:1],
            3,
        ),
        refused_derive(
            "no-members", "A period needs at least one member.", base, [], 0, "membership"
        ),
        refused_derive(
            "duplicate-member",
            "A member id listed twice is refused.",
            base,
            [trio[0], trio[0]],
            0,
            "membership",
        ),
        refused_derive(
            "unknown-kind",
            "A member kind the policy does not price is refused.",
            base,
            [member_wire("watch", "wrist")],
            0,
            "no_share",
        ),
        refused_derive(
            "period-bounds-overflow",
            "A period whose end passes signed 64-bit time is refused.",
            base,
            trio[:1],
            (1 << 63) // DAY_NS,
            "bounds",
        ),
    ]
    indexes = [
        {
            "name": "at-the-epoch",
            "policy": base.to_dict(),
            "now_ns": PERIOD_EPOCH_NS,
            "expect": {"index": 0},
        },
        {
            "name": "last-nanosecond-of-period-0",
            "policy": base.to_dict(),
            "now_ns": PERIOD_EPOCH_NS + DAY_NS - 1,
            "expect": {"index": 0},
        },
        {
            "name": "first-nanosecond-of-period-1",
            "policy": base.to_dict(),
            "now_ns": PERIOD_EPOCH_NS + DAY_NS,
            "expect": {"index": 1},
        },
        {
            "name": "before-the-epoch",
            "policy": base.to_dict(),
            "now_ns": PERIOD_EPOCH_NS - 1,
            "expect": {"refuse": "before_epoch"},
        },
    ]
    kind_swap = {"pocket": (400, 20, 4)}
    classify_cases = [
        ("same-terms-new-version", period_policy(version=2), PolicyChange.UNCHANGED),
        ("smaller-total", period_policy(version=2, totals=(900, 100, 10)), PolicyChange.NARROWED),
        (
            "bigger-unattested-reduction",
            period_policy(version=2, unattested_reduction_permille=600),
            PolicyChange.NARROWED,
        ),
        ("bigger-total", period_policy(version=2, totals=(1_001, 100, 10)), PolicyChange.WIDENED),
        (
            "smaller-reduction",
            period_policy(version=2, unattested_reduction_permille=400),
            PolicyChange.WIDENED,
        ),
        (
            "one-up-one-down",
            period_policy(version=2, totals=(900, 101, 10)),
            PolicyChange.WIDENED,
        ),
        (
            "bigger-solo-cap",
            period_policy(
                version=2,
                solo={"pocket": (110, 5, 0), "desktop": (200, 10, 0)},
            ),
            PolicyChange.WIDENED,
        ),
        ("shorter-period", period_policy(version=2, period_ns=DAY_NS // 2), PolicyChange.WIDENED),
        ("moved-epoch", period_policy(version=2, epoch_ns=0), PolicyChange.WIDENED),
        (
            "fewer-kinds",
            period_policy(version=2, shares=kind_swap, solo={"pocket": (100, 5, 0)}),
            PolicyChange.WIDENED,
        ),
    ]
    classify = [
        {
            "name": name,
            "current": base.to_dict(),
            "candidate": candidate.to_dict(),
            "expect": change.value,
        }
        for name, candidate, change in classify_cases
    ]
    narrower = period_policy(version=2, totals=(500, 100, 10))
    wider = period_policy(version=3, totals=(2_000, 100, 10))
    forged = replace(period_policy(version=2), sig=b64url_encode(bytes(64)))
    adopt = [
        {
            "name": "first-policy",
            "current": None,
            "candidate": base.to_dict(),
            "consent": None,
            "expect": "adopted",
        },
        {
            "name": "narrowing-needs-no-consent",
            "current": base.to_dict(),
            "candidate": narrower.to_dict(),
            "consent": None,
            "expect": "adopted",
        },
        {
            "name": "same-version-same-digest",
            "current": base.to_dict(),
            "candidate": base.to_dict(),
            "consent": None,
            "expect": "unchanged",
        },
        {
            "name": "widening-without-consent",
            "current": narrower.to_dict(),
            "candidate": wider.to_dict(),
            "consent": None,
            "expect": "consent_required",
        },
        {
            "name": "widening-with-consent-for-another-digest",
            "current": narrower.to_dict(),
            "candidate": wider.to_dict(),
            "consent": {
                "policy_digest": base.digest,
                "given_by": "owner",
                "evidence": "presence-signature-1",
            },
            "expect": "consent_required",
        },
        {
            "name": "widening-with-consent",
            "current": narrower.to_dict(),
            "candidate": wider.to_dict(),
            "consent": {
                "policy_digest": wider.digest,
                "given_by": "owner",
                "evidence": "presence-signature-1",
            },
            "expect": "adopted",
        },
        {
            "name": "stale-version",
            "current": narrower.to_dict(),
            "candidate": period_policy(version=1, totals=(1, 1, 1)).to_dict(),
            "consent": None,
            "expect": "stale_version",
        },
        {
            "name": "same-version-other-content",
            "current": base.to_dict(),
            "candidate": period_policy(version=1, totals=(1, 1, 1)).to_dict(),
            "consent": None,
            "expect": "stale_version",
        },
        {
            "name": "another-policy-id",
            "current": base.to_dict(),
            "candidate": period_policy(version=2, policy_id="other").to_dict(),
            "consent": None,
            "expect": "policy_id",
        },
        {
            "name": "bad-signature",
            "current": base.to_dict(),
            "candidate": forged.to_dict(),
            "consent": None,
            "expect": "signature",
        },
    ]
    return {
        "format": "lets.vectors/v1",
        "wire_type": BudgetPolicy.WIRE_TYPE,
        "summary": "Period budget derivation, period arithmetic and policy adoption.",
        "verifier": {
            "issuer": "owner",
            "algorithm": "Ed25519 over the canonical unsigned policy, signature base64url in sig",
            "key": key_entry("owner"),
        },
        "arithmetic": (
            "scaled = share * (1000 - reduction) // 1000. If the sum of scaled shares for a "
            "dimension is at most the total, fresh = scaled."
            "Otherwise fresh = scaled * total // sum. "
            "solo = min(scaled solo cap, fresh). reserve = total - sum(fresh). Use 128-bit "
            "intermediates."
        ),
        "derive": derive,
        "period_index": indexes,
        "classify": classify,
        "adopt": adopt,
    }


def consent_for(policy: BudgetPolicy) -> dict[str, str]:
    marker = WideningConsent(policy.digest, "owner", "presence-signature-1")
    return {
        "policy_digest": marker.policy_digest,
        "given_by": marker.given_by,
        "evidence": marker.evidence,
    }


def device_scenarios() -> list[dict[str, Any]]:
    pocket = [member_wire("phone", "pocket"), member_wire("laptop", "desktop")]
    narrower = period_policy(version=2, shares={"pocket": (400, 10, 4), "desktop": (600, 80, 6)})
    wider = period_policy(version=3, shares={"pocket": (400, 40, 4), "desktop": (600, 60, 6)})

    def allowance(device: str, **expect: Any) -> dict[str, Any]:
        return {"op": "allowance", "device": device, "expect": expect}

    def spend(device: str, dimension: str, units: int, expect: str) -> dict[str, Any]:
        return {
            "op": "spend",
            "device": device,
            "dimension": dimension,
            "units": units,
            "expect": expect,
        }

    def amounts(model: int = 0, notes: int = 0, outside: int = 0) -> dict[str, int]:
        return {"model_tokens": model, "notes_write": notes, "outside_effect": outside}

    base = period_policy().to_dict()
    scenarios = [
        {
            "name": "solo-share-and-edge",
            "description": "A device with no contact spends its solo cap, then is refused.",
            "policy": base,
            "members": pocket,
            "config": {},
            "clock_start_ns": CLOCK_START_NS,
            "steps": [
                {"op": "start", "device": "phone"},
                allowance(
                    "phone",
                    period_index=0,
                    mode="solo",
                    cap=amounts(100, 5, 0),
                    consumed=amounts(),
                    remaining=amounts(100, 5, 0),
                ),
                spend("phone", "notes_write", 5, "ok"),
                spend("phone", "notes_write", 1, "solo_cap_reached"),
                spend("phone", "outside_effect", 1, "solo_cap_reached"),
                spend("phone", "teleport", 1, "unknown_dimension"),
                spend("phone", "notes_write", 0, "invalid_amount"),
                allowance("phone", remaining=amounts(100, 0, 0), consumed=amounts(0, 5, 0)),
            ],
        },
        {
            "name": "freshness-window",
            "description": "Contact unlocks the full share for exactly the freshness window.",
            "policy": base,
            "members": pocket,
            "config": {"freshness_window_ns": 3_600 * SECOND},
            "clock_start_ns": CLOCK_START_NS,
            "steps": [
                {"op": "start", "device": "phone"},
                {"op": "contact", "device": "phone"},
                allowance("phone", mode="fresh", cap=amounts(400, 20, 4)),
                spend("phone", "notes_write", 20, "ok"),
                spend("phone", "notes_write", 1, "share_spent"),
                {"op": "clock", "device": "phone", "advance_ns": 3_600 * SECOND},
                allowance("phone", mode="fresh"),
                {"op": "clock", "device": "phone", "advance_ns": 1},
                allowance(
                    "phone",
                    mode="solo",
                    cap=amounts(100, 5, 0),
                    consumed=amounts(0, 20, 0),
                    remaining=amounts(100, 0, 0),
                ),
            ],
        },
        {
            "name": "alone-in-the-mesh",
            "description": "A device that is the only member is never fresh.",
            "policy": base,
            "members": pocket[:1],
            "config": {},
            "clock_start_ns": CLOCK_START_NS,
            "steps": [
                {"op": "start", "device": "phone"},
                {"op": "contact", "device": "phone"},
                allowance("phone", mode="solo", cap=amounts(100, 5, 0)),
            ],
        },
        {
            "name": "new-period-and-clock-floor",
            "description": (
                "A later period gives a new share. A clock set back earns no period and "
                "spending stays bounded."
            ),
            "policy": base,
            "members": pocket,
            "config": {},
            "clock_start_ns": CLOCK_START_NS,
            "steps": [
                {"op": "start", "device": "phone"},
                {"op": "contact", "device": "phone"},
                spend("phone", "notes_write", 5, "ok"),
                {"op": "clock", "device": "phone", "advance_ns": 2 * DAY_NS},
                allowance(
                    "phone",
                    period_index=2,
                    mode="solo",
                    consumed=amounts(),
                    remaining=amounts(100, 5, 0),
                ),
                spend("phone", "notes_write", 3, "ok"),
                {"op": "clock", "device": "phone", "set_ns": CLOCK_START_NS},
                allowance(
                    "phone",
                    period_index=2,
                    clock_regressed=True,
                    consumed=amounts(0, 3, 0),
                    remaining=amounts(100, 2, 0),
                ),
                spend("phone", "notes_write", 3, "solo_cap_reached"),
                spend("phone", "notes_write", 2, "ok"),
            ],
        },
        {
            "name": "transfer-restores-headroom",
            "description": "A transfer moves unspent rights between devices and the total holds.",
            "policy": base,
            "members": pocket,
            "config": {},
            "clock_start_ns": CLOCK_START_NS,
            "steps": [
                {"op": "start", "device": "phone"},
                {"op": "start", "device": "laptop"},
                {"op": "contact", "device": "phone"},
                {"op": "contact", "device": "laptop"},
                spend("phone", "notes_write", 20, "ok"),
                spend("phone", "notes_write", 1, "share_spent"),
                {
                    "op": "transfer",
                    "from": "laptop",
                    "to": "phone",
                    "amounts": amounts(0, 81, 0),
                    "expect": "share_spent",
                },
                {
                    "op": "transfer",
                    "from": "laptop",
                    "to": "phone",
                    "amounts": amounts(0, 30, 0),
                    "expect": "ok",
                },
                allowance("laptop", cap=amounts(600, 50, 6), remaining=amounts(600, 50, 6)),
                allowance(
                    "phone",
                    cap=amounts(400, 50, 4),
                    consumed=amounts(0, 20, 0),
                    remaining=amounts(400, 30, 4),
                ),
                spend("phone", "notes_write", 30, "ok"),
                spend("phone", "notes_write", 1, "share_spent"),
                spend("laptop", "notes_write", 50, "ok"),
                spend("laptop", "notes_write", 1, "share_spent"),
            ],
        },
        {
            "name": "restore-as-a-new-holder",
            "description": (
                "A restored device is a new holder with a fresh share, and the old holder's "
                "share lapses with its period."
            ),
            "policy": base,
            "members": [*pocket, member_wire("phone2", "pocket")],
            "config": {},
            "clock_start_ns": CLOCK_START_NS,
            "steps": [
                {"op": "start", "device": "phone"},
                {"op": "contact", "device": "phone"},
                spend("phone", "notes_write", 5, "ok"),
                {
                    "op": "start",
                    "device": "phone",
                    "seed_floor_from": "phone",
                    "expect": "new_member_id_required",
                },
                {"op": "start", "device": "phone2", "seed_floor_from": "phone"},
                allowance("phone2", mode="solo", consumed=amounts(), remaining=amounts(100, 5, 0)),
                spend("phone2", "notes_write", 1, "ok"),
                {"op": "retire", "device": "phone"},
                spend("phone", "notes_write", 1, "ok"),
                allowance("phone", retired=True),
                {"op": "clock", "device": "phone", "advance_ns": DAY_NS},
                {"op": "clock", "device": "phone2", "advance_ns": DAY_NS},
                spend("phone", "notes_write", 1, "lapsed"),
                allowance("phone2", period_index=1, remaining=amounts(100, 5, 0)),
            ],
        },
        {
            "name": "not-in-the-period-membership",
            "description": "A device the roster did not list at period start holds no share.",
            "policy": base,
            "members": pocket[1:],
            "config": {},
            "clock_start_ns": CLOCK_START_NS,
            "steps": [
                {"op": "start", "device": "phone"},
                {"op": "start", "device": "laptop"},
                allowance("phone", remaining=amounts()),
                spend("phone", "notes_write", 1, "not_a_member"),
                {
                    "op": "transfer",
                    "from": "phone",
                    "to": "laptop",
                    "amounts": amounts(0, 1, 0),
                    "expect": "not_a_member",
                },
            ],
        },
        {
            "name": "policy-narrowing-and-widening",
            "description": (
                "Narrowing applies at once. Widening needs consent bound to its digest and "
                "starts with the next period."
            ),
            "policy": base,
            "members": pocket,
            "config": {},
            "clock_start_ns": CLOCK_START_NS,
            "steps": [
                {"op": "start", "device": "phone"},
                {"op": "contact", "device": "phone"},
                spend("phone", "notes_write", 4, "ok"),
                {
                    "op": "set_policy",
                    "device": "phone",
                    "policy": narrower.to_dict(),
                    "consent": None,
                    "expect": "ok",
                },
                allowance("phone", cap=amounts(400, 10, 4), remaining=amounts(400, 6, 4)),
                {
                    "op": "set_policy",
                    "device": "phone",
                    "policy": wider.to_dict(),
                    "consent": None,
                    "expect": "consent_required",
                },
                {
                    "op": "set_policy",
                    "device": "phone",
                    "policy": wider.to_dict(),
                    "consent": consent_for(narrower),
                    "expect": "consent_required",
                },
                {
                    "op": "set_policy",
                    "device": "phone",
                    "policy": wider.to_dict(),
                    "consent": consent_for(wider),
                    "expect": "ok",
                },
                allowance("phone", remaining=amounts(400, 6, 4)),
                {"op": "clock", "device": "phone", "advance_ns": DAY_NS + 1},
                allowance("phone", period_index=1, mode="solo", cap=amounts(100, 5, 0)),
                {"op": "contact", "device": "phone"},
                allowance("phone", mode="fresh", cap=amounts(400, 40, 4)),
            ],
        },
    ]
    return scenarios


def device_document() -> dict[str, Any]:
    return {
        "format": "lets.vectors/v1",
        "wire_type": "lets.device-profile/v1",
        "summary": "Device holder scenarios: shares, freshness, clock floor, transfers, restore.",
        "verifier": period_document()["verifier"],
        "devices": ["laptop", "phone", "phone2"],
        "config_defaults": {
            "freshness_window_ns": DAY_NS,
            "receipt_ttl_ns": 300 * SECOND,
            "max_clock_uncertainty_ns": 0,
        },
        "ops": {
            "start": "Create the holder. seed_floor_from names a device whose backup seeds it.",
            "contact": "Record contact with another member now.",
            "clock": "Set the device clock with set_ns or move it with advance_ns.",
            "spend": "Spend units of one dimension. expect is ok or a refusal reason.",
            "transfer": "from offers amounts to to, to accepts, from settles.",
            "set_policy": "Adopt a candidate policy. consent is null or a marker.",
            "retire": "Mark the holder retired for its current period.",
            "allowance": "Compare the named fields of the holder's allowance.",
        },
        "scenarios": device_scenarios(),
    }


def keys_document() -> dict[str, Any]:
    return {
        "format": "lets.vector-keys/v1",
        "warning": "Test keys derived from public labels. Never use them for anything real.",
        "derivation": 'seed = SHA-256("lets-vectors/key/" + name), Ed25519',
        "keys": [
            {
                **key_entry(name),
                "seed": b64url_encode(sha256(f"lets-vectors/key/{name}".encode()).digest()),
            }
            for name in KEY_NAMES
        ],
    }


def builders() -> dict[str, Callable[[], dict[str, Any]]]:
    voucher_ack = voucher_and_ack_documents
    return {
        "keys.json": keys_document,
        "receipt.json": receipt_document,
        "lease-grant.json": lease_document,
        "transfer-voucher.json": lambda: voucher_ack()[0],
        "transfer-ack.json": lambda: voucher_ack()[1],
        "period.json": period_document,
        "device.json": device_document,
    }


def render(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if committed vectors differ")
    parser.add_argument("--output", type=Path, default=VECTOR_DIR)
    arguments = parser.parse_args()
    stale: list[str] = []
    for name, build in builders().items():
        text = render(build())
        path = arguments.output / name
        if arguments.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    if stale:
        print("stale vectors: " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
