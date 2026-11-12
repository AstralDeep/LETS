"""Generates the signed, deterministic conformance vectors under protocol/vectors from fixed test keys and fixed clocks. Run it to rewrite them, or with --check in CI to prove the committed files still match what the reference implementation emits.
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

VECTOR_DIR = Path(__file__).resolve().parents[1] / "protocol" / "vectors"
NOW = 1_800_000_000_000_000_000
SECOND = 1_000_000_000
POLICY_DIGEST = "sha256:" + sha256(b"lets-vectors/policy").hexdigest()
OTHER_POLICY_DIGEST = "sha256:" + sha256(b"lets-vectors/other-policy").hexdigest()
MACHINE_DIGEST = "sha256:" + sha256(b"lets-vectors/machine").hexdigest()
EVIDENCE_DIGEST = "sha256:" + sha256(b"lets-vectors/evidence").hexdigest()

KEY_NAMES = ("warden-a", "warden-b", "mallory")


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
    return replace(record, signature=b64url_encode(signer.sign(canonical_json(record.unsigned_payload()))))


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


def case(name: str, description: str, verifier: dict[str, Any], *steps: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "description": description, "verifier": verifier, "steps": list(steps)}


def document(wire_type: str, summary: str, cases: list[dict[str, Any]], keys: list[str]) -> dict[str, Any]:
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
        case("valid-minimal", "A fresh receipt with a one-unit cost.", context, step(valid, "valid", now_ns=NOW)),
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
        case("valid-root", "A root lease inside its window.", context, step(root, "valid", now_ns=NOW)),
        case("valid-child", "A child lease with a one-entry ancestor path.", context, step(child, "valid", now_ns=NOW)),
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
        case("expired", "The clock is at the exact expiry instant.", context, step(root, "expired", now_ns=root.expires_at_ns)),
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
        case("valid-pool", "A pool transfer from warden-a to warden-b.", voucher_context, step(pool, "valid", now_ns=NOW)),
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
        case("valid-pool", "An acknowledgement of a pool transfer.", ack_context, step(ack, "valid", now_ns=NOW)),
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


def keys_document() -> dict[str, Any]:
    return {
        "format": "lets.vector-keys/v1",
        "warning": "Test keys derived from public labels. Never use them for anything real.",
        "derivation": "seed = SHA-256(\"lets-vectors/key/\" + name), Ed25519",
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
