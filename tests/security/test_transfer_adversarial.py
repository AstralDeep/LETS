from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from lets.canonical import b64url_encode, canonical_json
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ConflictError, ReplayError, SignatureError
from lets.models import IdentityContext, TransferVoucher
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage


def _policy() -> PolicySpec:
    return PolicySpec(
        "transfer-policy",
        "v1",
        (ResourceDimension("work", "count"),),
        MachineSpec(
            "worker",
            "ready",
            (TransitionSpec("act", "ready", "ready", (1,), "worker.act"),),
        ),
        10_000,
        100,
        0,
        4,
    )


def _identity(subject: str, *scopes: str) -> IdentityContext:
    return IdentityContext(subject, "tenant", frozenset(scopes))


def _open(
    path: Path,
    warden_id: str,
    share: tuple[int, ...],
    clock: ManualClock,
    registry: PublicKeyRegistry,
    *,
    initialize: bool = True,
) -> tuple[SQLiteStorage, WardenService, Ed25519Signer]:
    signer = Ed25519Signer.from_seed(warden_id, sha256(warden_id.encode("utf-8")).digest())
    factory = SQLiteStorage.initialize if initialize else SQLiteStorage
    store = factory(
        path,
        warden_id,
        (100,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        initial_local_share=share,
        receipt_ttl_ns=100,
        transfer_gap_window=4,
    )
    registry.register_signer(signer)
    service = WardenService(store, signer=signer, clock=clock, trust_registry=registry)
    service.register_policy(_policy())
    return store, service, signer


def _resign(voucher: TransferVoucher, signer: Ed25519Signer) -> TransferVoucher:
    unsigned = replace(voucher, signature="")
    return replace(
        unsigned,
        signature=b64url_encode(signer.sign(canonical_json(unsigned.unsigned_payload()))),
    )


def test_duplicate_and_reordered_vouchers_remain_exactly_once_across_restart(
    tmp_path: Path,
) -> None:
    clock = ManualClock(1_000_000)
    registry = PublicKeyRegistry(clock=clock)
    source_store, source, source_signer = _open(
        tmp_path / "source.sqlite3", "source", (100,), clock, registry
    )
    target_path = tmp_path / "target.sqlite3"
    target_store, target, _ = _open(target_path, "target", (0,), clock, registry)
    transfer_identity = _identity("operator", "lets.transfer")
    peer_identity = _identity("source", "lets.peer")
    try:
        vouchers = tuple(
            source.prepare_transfer(
                request_id=f"prepare-{index}",
                identity=transfer_identity,
                tenant_id="tenant",
                envelope_id="envelope",
                target_warden="target",
                amount=(5,),
            )
            for index in range(1, 4)
        )
        ack_two = target.accept_transfer(identity=peer_identity, voucher=vouchers[1])
        assert ack_two.contiguous_watermark == 0
        target_store.close()

        target_store, target, _ = _open(
            target_path, "target", (0,), clock, registry, initialize=False
        )
        assert target.accept_transfer(identity=peer_identity, voucher=vouchers[1]) == ack_two
        ack_one = target.accept_transfer(identity=peer_identity, voucher=vouchers[0])
        assert ack_one.contiguous_watermark == 2
        assert target.invariant_snapshot(identity=_identity("auditor")).free_pool == (10,)
        with pytest.raises(ReplayError, match="admission window"):
            # Sequence 3 is valid; moving it beyond the configured sparse window is not.
            far = _resign(replace(vouchers[2], sequence=7), source_signer)
            target.accept_transfer(identity=peer_identity, voucher=far)
    finally:
        source_store.close()
        target_store.close()


def test_sequence_and_transfer_id_are_each_bound_to_one_signed_voucher(tmp_path: Path) -> None:
    clock = ManualClock(1_000_000)
    registry = PublicKeyRegistry(clock=clock)
    source_store, source, signer = _open(
        tmp_path / "source.sqlite3", "source", (100,), clock, registry
    )
    target_store, target, _ = _open(tmp_path / "target.sqlite3", "target", (0,), clock, registry)
    transfer_identity = _identity("operator", "lets.transfer")
    peer_identity = _identity("source", "lets.peer")
    try:
        first = source.prepare_transfer(
            request_id="first",
            identity=transfer_identity,
            tenant_id="tenant",
            envelope_id="envelope",
            target_warden="target",
            amount=(5,),
        )
        second = source.prepare_transfer(
            request_id="second",
            identity=transfer_identity,
            tenant_id="tenant",
            envelope_id="envelope",
            target_warden="target",
            amount=(5,),
        )
        target.accept_transfer(identity=peer_identity, voucher=first)

        same_sequence = _resign(
            replace(first, transfer_id="transfer-conflict", amount=(6,)), signer
        )
        with pytest.raises(ConflictError, match="sequence"):
            target.accept_transfer(identity=peer_identity, voucher=same_sequence)

        duplicate_id = _resign(replace(second, transfer_id=first.transfer_id), signer)
        with pytest.raises(ConflictError, match="transfer_id"):
            target.accept_transfer(identity=peer_identity, voucher=duplicate_id)
        assert target.invariant_snapshot(identity=_identity("auditor")).free_pool == (5,)
    finally:
        source_store.close()
        target_store.close()


def test_signed_voucher_binds_tenant_target_amount_and_signature_spelling(
    tmp_path: Path,
) -> None:
    clock = ManualClock(1_000_000)
    registry = PublicKeyRegistry(clock=clock)
    source_store, source, _ = _open(tmp_path / "source.sqlite3", "source", (100,), clock, registry)
    target_store, target, _ = _open(tmp_path / "target.sqlite3", "target", (0,), clock, registry)
    try:
        voucher = source.prepare_transfer(
            request_id="signed-binding",
            identity=_identity("operator", "lets.transfer"),
            tenant_id="tenant",
            envelope_id="envelope",
            target_warden="target",
            amount=(5,),
        )
        for changed in (
            replace(voucher, tenant_id="other"),
            replace(voucher, target_warden="other"),
            replace(voucher, amount=(6,)),
            replace(voucher, signature=voucher.signature + "!"),
        ):
            with pytest.raises(SignatureError):
                target.accept_transfer(
                    identity=_identity("source", "lets.peer"),
                    voucher=changed,
                )
        assert target.invariant_snapshot(identity=_identity("auditor")).free_pool == (0,)
    finally:
        source_store.close()
        target_store.close()
