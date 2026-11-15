"""Offline reference checks for the frozen signed wire records: lease grants, transfer vouchers
and acknowledgements, and receipts. Each check raises a stable reason code so a second
implementation can be run against protocol/vectors. Receipt checks delegate to
executor.py's ReceiptVerifier and replay store.
"""

from __future__ import annotations

import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lets.canonical import b64url_decode, canonical_digest, canonical_json
from lets.clock import ManualClock
from lets.crypto import PublicKeyRegistry
from lets.errors import (
    ClockUncertainError,
    LETSError,
    PolicyError,
    ReplayError,
    SignatureError,
    ValidationError,
)
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.models import LeaseGrant, Receipt, TransferAck, TransferVoucher

VALID = "valid"
REASONS = frozenset(
    {
        "malformed",
        "signature",
        "audience",
        "expired",
        "not_yet_valid",
        "policy_digest",
        "voucher_digest",
        "sequence_conflict",
        "replay",
        "issuer",
        "clock",
        "denied",
    }
)


class WireRejectedError(PolicyError):
    def __init__(self, reason: str, message: str) -> None:
        if reason not in REASONS:
            raise ValueError(f"unknown rejection reason {reason!r}")
        super().__init__(message)
        self.reason = reason


def _check_signature(record: Any, registry: PublicKeyRegistry, warden_id: str) -> None:
    try:
        signature = b64url_decode(record.signature)
    except Exception as exc:
        raise WireRejectedError("signature", "signature is malformed") from exc
    if not registry.verify(
        warden_id, record.key_id, canonical_json(record.unsigned_payload()), signature
    ):
        raise WireRejectedError("signature", "signature is invalid or untrusted")


def _check_window(issued_at_ns: int, expires_at_ns: int, now_ns: int, uncertainty_ns: int) -> None:
    if issued_at_ns > now_ns + uncertainty_ns:
        raise WireRejectedError("not_yet_valid", "issuance is in the future")
    if now_ns + uncertainty_ns >= expires_at_ns:
        raise WireRejectedError("expired", "record is expired or cannot be proven fresh")


def verify_lease_grant(
    grant: LeaseGrant,
    *,
    registry: PublicKeyRegistry,
    holder_warden: str,
    expected_policy_digest: str,
    now_ns: int,
    uncertainty_ns: int = 0,
) -> None:
    if grant.warden_id != holder_warden:
        raise WireRejectedError("audience", "lease grant names another holder")
    if grant.policy_digest != expected_policy_digest:
        raise WireRejectedError("policy_digest", "lease grant policy digest is not accepted")
    _check_window(grant.issued_at_ns, grant.expires_at_ns, now_ns, uncertainty_ns)
    _check_signature(grant, registry, grant.warden_id)


@dataclass(slots=True)
class TransferStreamLedger:
    digests: dict[tuple[str, int], str] = field(default_factory=dict)


def verify_transfer_voucher(
    voucher: TransferVoucher,
    *,
    registry: PublicKeyRegistry,
    receiver_warden: str,
    expected_policy_digest: str,
    ledger: TransferStreamLedger | None = None,
) -> str:
    if voucher.target_warden != receiver_warden:
        raise WireRejectedError("audience", "voucher target is another warden")
    if voucher.policy_digest != expected_policy_digest:
        raise WireRejectedError("policy_digest", "voucher policy digest is not accepted")
    _check_signature(voucher, registry, voucher.source_warden)
    digest = canonical_digest(voucher.to_dict())
    if ledger is not None:
        key = (voucher.source_warden, voucher.sequence)
        bound = ledger.digests.setdefault(key, digest)
        if bound != digest:
            raise WireRejectedError(
                "sequence_conflict", "transfer sequence is bound to another voucher"
            )
    return digest


def verify_transfer_ack(
    ack: TransferAck,
    voucher: TransferVoucher,
    *,
    registry: PublicKeyRegistry,
    source_warden: str,
) -> None:
    if ack.source_warden != source_warden:
        raise WireRejectedError("audience", "acknowledgement source is another warden")
    if ack.voucher_digest != canonical_digest(voucher.to_dict()):
        raise WireRejectedError("voucher_digest", "acknowledgement does not match the voucher")
    _check_signature(ack, registry, ack.target_warden)


def _classify(error: Exception) -> str:
    if isinstance(error, WireRejectedError):
        return error.reason
    if isinstance(error, ValidationError):
        return "malformed"
    if isinstance(error, SignatureError):
        return "signature"
    if isinstance(error, ReplayError):
        return "replay"
    if isinstance(error, ClockUncertainError):
        return "clock"
    if isinstance(error, PolicyError):
        message = str(error)
        for marker, reason in (
            ("audience", "audience"),
            ("future", "not_yet_valid"),
            ("expired", "expired"),
            ("policy digest", "policy_digest"),
            ("issuer", "issuer"),
        ):
            if marker in message:
                return reason
        return "denied"
    raise error


def _registry(keys: list[Mapping[str, Any]]) -> PublicKeyRegistry:
    registry = PublicKeyRegistry()
    for key in keys:
        registry.register(key["warden_id"], key["key_id"], b64url_decode(key["public_key"]))
    return registry


class VectorRunner:
    def __init__(self, workdir: Path) -> None:
        self._workdir = workdir

    def run(
        self, wire_type: str, case: Mapping[str, Any], keys: list[Mapping[str, Any]]
    ) -> list[str]:
        context = case["verifier"]
        registry = _registry(list(case.get("trusted_keys", keys)))
        if wire_type == Receipt.WIRE_TYPE:
            return self._receipts(case, context, registry)
        ledger = TransferStreamLedger()
        outcomes: list[str] = []
        for step in case["steps"]:
            try:
                self._step(wire_type, step, context, registry, ledger)
                outcomes.append(VALID)
            except LETSError as error:
                outcomes.append(_classify(error))
        return outcomes

    @staticmethod
    def _step(
        wire_type: str,
        step: Mapping[str, Any],
        context: Mapping[str, Any],
        registry: PublicKeyRegistry,
        ledger: TransferStreamLedger,
    ) -> None:
        if wire_type == LeaseGrant.WIRE_TYPE:
            verify_lease_grant(
                LeaseGrant.from_dict(dict(step["wire"])),
                registry=registry,
                holder_warden=context["holder_warden"],
                expected_policy_digest=context["policy_digest"],
                now_ns=step["now_ns"],
                uncertainty_ns=step.get("uncertainty_ns", 0),
            )
        elif wire_type == TransferVoucher.WIRE_TYPE:
            verify_transfer_voucher(
                TransferVoucher.from_dict(dict(step["wire"])),
                registry=registry,
                receiver_warden=context["receiver_warden"],
                expected_policy_digest=context["policy_digest"],
                ledger=ledger,
            )
        elif wire_type == TransferAck.WIRE_TYPE:
            verify_transfer_ack(
                TransferAck.from_dict(dict(step["wire"])),
                TransferVoucher.from_dict(dict(context["voucher"])),
                registry=registry,
                source_warden=context["source_warden"],
            )
        else:
            raise ValueError(f"unknown wire type {wire_type!r}")

    def _receipts(
        self,
        case: Mapping[str, Any],
        context: Mapping[str, Any],
        registry: PublicKeyRegistry,
    ) -> list[str]:
        policy = ExecutorPolicy(
            audience=context["audience"],
            allowed_policy_digests=frozenset(context["allowed_policy_digests"]),
            trusted_wardens=frozenset(context["trusted_wardens"]),
        )
        with tempfile.TemporaryDirectory(dir=self._workdir) as directory:
            store = SQLiteReceiptReplayStore.initialize(
                Path(directory) / "replay.sqlite3", allow_unanchored=True
            )
            clock = ManualClock(0)
            verifier = ReceiptVerifier(registry, store, policy, clock=clock)
            outcomes: list[str] = []
            for step in case["steps"]:
                clock.current_ns = step["now_ns"]
                try:
                    verifier.verify_and_claim(Receipt.from_dict(dict(step["wire"])))
                    outcomes.append(VALID)
                except LETSError as error:
                    outcomes.append(_classify(error))
            return outcomes
