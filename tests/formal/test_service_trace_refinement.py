from __future__ import annotations

from pathlib import Path

import pytest

from formal.model_checker import (
    Bounds,
    State,
    accept_transfer,
    authorize,
    claim_receipt,
    finalize_transfer,
    initial_state,
    issue_root,
    prepare_transfer,
    validate,
)
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ReplayError
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.models import IdentityContext, InvariantSnapshot
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage


def _identity(subject: str, *scopes: str) -> IdentityContext:
    return IdentityContext(subject, "tenant", frozenset(scopes))


def _policy() -> PolicySpec:
    return PolicySpec(
        policy_id="refinement-policy",
        policy_version="v1",
        dimensions=(ResourceDimension("steps", "count"),),
        machine=MachineSpec(
            machine_id="refinement-machine",
            initial_state="ready",
            transitions=(TransitionSpec("step", "ready", "ready", (1,), "step"),),
        ),
        max_lease_ttl_ns=1_000_000,
        receipt_ttl_ns=100_000,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=4,
    )


def _service(
    path: Path,
    warden_id: str,
    share: int,
    clock: ManualClock,
    registry: PublicKeyRegistry,
) -> tuple[SQLiteStorage, WardenService]:
    signer = Ed25519Signer.generate(warden_id)
    store = SQLiteStorage.initialize(
        path,
        warden_id,
        (8,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        initial_local_share=(share,),
        receipt_ttl_ns=100_000,
        transfer_gap_window=4,
    )
    registry.register_signer(signer)
    return store, WardenService(store, signer=signer, clock=clock, trust_registry=registry)


def _observe(service: WardenService, subject: str) -> InvariantSnapshot:
    return service.invariant_snapshot(identity=_identity(subject))


def _assert_refines(
    abstract: State,
    bounds: Bounds,
    source: WardenService,
    target: WardenService,
) -> None:
    validate(abstract, bounds)
    observed = (_observe(source, "warden-a"), _observe(target, "warden-b"))
    assert tuple(snapshot.free_pool[0] for snapshot in observed) == abstract.pools
    assert sum(snapshot.lease_residual[0] for snapshot in observed) == sum(
        lease.residual for lease in abstract.leases
    )
    assert sum(snapshot.consumed[0] for snapshot in observed) == abstract.consumed
    assert all(snapshot.healthy for snapshot in observed)
    pending = sum(
        transfer.amount for transfer in abstract.transfers if transfer.status == "PREPARED"
    )
    actual_accounted = sum(
        snapshot.free_pool[0] + snapshot.lease_residual[0] + snapshot.consumed[0]
        for snapshot in observed
    )
    assert actual_accounted + pending == bounds.budget


def test_service_transfer_and_executor_trace_refines_bounded_model(tmp_path: Path) -> None:
    bounds = Bounds(
        initial_shares=(6, 2),
        max_leases=2,
        max_transfers=2,
        max_receipts=2,
        max_depth=8,
        max_action_amount=3,
    )
    abstract = initial_state(bounds)
    clock = ManualClock(1_000_000)
    registry = PublicKeyRegistry(clock=clock)
    source_store, source = _service(tmp_path / "source.sqlite3", "warden-a", 6, clock, registry)
    target_store, target = _service(tmp_path / "target.sqlite3", "warden-b", 2, clock, registry)
    try:
        policy = _policy()
        digest = source.register_policy(policy)
        target.register_policy(policy)
        issuer = _identity("agent", "lets.lease.issue")
        source_peer = _identity("warden-a")
        target_peer = _identity("warden-b")
        _assert_refines(abstract, bounds, source, target)

        grant = source.issue_root(
            request_id="refinement-root",
            identity=issuer,
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent",
            allocation=(3,),
            capabilities={"step"},
            policy_digest=digest,
            ttl_ns=500_000,
        )
        abstract = issue_root(abstract, 0, 3)
        _assert_refines(abstract, bounds, source, target)

        receipt = source.authorize(
            request_id="refinement-authorize",
            identity=issuer,
            lease_id=grant.lease_id,
            transition="step",
            audience="executor",
            nonce="refinement-nonce-0001",
            expected_sequence=0,
        )
        abstract = authorize(abstract, 1, 1)
        _assert_refines(abstract, bounds, source, target)

        voucher = source.prepare_transfer(
            request_id="refinement-transfer",
            identity=source_peer,
            tenant_id="tenant",
            envelope_id="envelope",
            target_warden="warden-b",
            amount=(2,),
            policy_digest=digest,
        )
        abstract = prepare_transfer(abstract, 0, 1, 2)
        _assert_refines(abstract, bounds, source, target)

        acknowledgement = target.accept_transfer(identity=target_peer, voucher=voucher)
        abstract = accept_transfer(abstract, 1)
        _assert_refines(abstract, bounds, source, target)

        duplicate_acknowledgement = target.accept_transfer(identity=target_peer, voucher=voucher)
        duplicate_abstract = accept_transfer(abstract, 1)
        assert duplicate_acknowledgement == acknowledgement
        assert duplicate_abstract == abstract
        _assert_refines(duplicate_abstract, bounds, source, target)

        source.finalize_transfer(identity=source_peer, acknowledgement=acknowledgement)
        abstract = finalize_transfer(abstract, 1)
        _assert_refines(abstract, bounds, source, target)

        verifier = ReceiptVerifier(
            registry,
            SQLiteReceiptReplayStore.initialize(tmp_path / "executor.sqlite3"),
            ExecutorPolicy(
                audience="executor",
                tenant_id="tenant",
                envelope_id="envelope",
                config_epoch=1,
                allowed_policy_digests=frozenset({policy.digest}),
                allowed_machine_digests=frozenset({policy.machine.digest}),
                trusted_wardens=frozenset({"warden-a"}),
            ),
            clock=clock,
        )
        verifier.verify_and_claim(receipt)
        abstract = claim_receipt(abstract, 1)
        with pytest.raises(ReplayError):
            verifier.verify_and_claim(receipt)
        assert claim_receipt(abstract, 1) == abstract
        _assert_refines(abstract, bounds, source, target)

        # Finalization and executor claims do not create or destroy rights.
        assert abstract.consumed == 1
    finally:
        source_store.close()
        target_store.close()
