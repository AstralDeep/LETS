from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from lets.canonical import b64url_encode, canonical_digest, canonical_json
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ConflictError, PolicyError, ReplayError, SignatureError
from lets.models import IdentityContext, LeaseStatus, TransferAck, TransferVoucher
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage


def _policy(*, gap_window: int = 4) -> PolicySpec:
    return PolicySpec(
        policy_id="generic-policy",
        policy_version="v1",
        dimensions=(ResourceDimension("operations", "count"),),
        machine=MachineSpec(
            machine_id="worker",
            initial_state="ready",
            transitions=(TransitionSpec("act", "ready", "ready", (2,), "worker.act"),),
        ),
        max_lease_ttl_ns=10_000,
        receipt_ttl_ns=100,
        max_clock_uncertainty_ns=5,
        transfer_gap_window=gap_window,
    )


def _identity(subject: str, *scopes: str) -> IdentityContext:
    return IdentityContext(subject, "tenant", frozenset(scopes))


def _service(
    path: Path,
    warden_id: str,
    share: tuple[int, ...],
    clock: ManualClock,
    registry: PublicKeyRegistry,
) -> tuple[SQLiteStorage, WardenService]:
    signer = Ed25519Signer.generate(warden_id)
    store = SQLiteStorage.initialize(
        path,
        warden_id,
        (100,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        initial_local_share=share,
        receipt_ttl_ns=100,
        max_clock_uncertainty_ns=5,
        transfer_gap_window=4,
    )
    registry.register_signer(signer)
    return store, WardenService(store, signer=signer, clock=clock, trust_registry=registry)


@pytest.fixture
def warden(tmp_path: Path) -> Iterator[tuple[SQLiteStorage, WardenService, ManualClock]]:
    clock = ManualClock(1_000_000, 5)
    registry = PublicKeyRegistry()
    store, service = _service(tmp_path / "warden.db", "warden-a", (100,), clock, registry)
    service.register_policy(_policy())
    yield store, service, clock
    store.close()


def test_authorization_is_atomic_signed_and_idempotent(
    warden: tuple[SQLiteStorage, WardenService, ManualClock],
) -> None:
    store, service, _ = warden
    agent = _identity("agent-a", "lets.lease.issue")
    policy_digest = _policy().digest
    grant = service.issue_root(
        request_id="issue-1",
        identity=agent,
        tenant_id="tenant",
        envelope_id="envelope",
        subject_id="agent-a",
        allocation=(20,),
        capabilities={"worker.act"},
        policy_digest=policy_digest,
        ttl_ns=1_000,
    )
    duplicate_grant = service.issue_root(
        request_id="issue-1",
        identity=agent,
        tenant_id="tenant",
        envelope_id="envelope",
        subject_id="agent-a",
        allocation=(20,),
        capabilities={"worker.act"},
        policy_digest=policy_digest,
        ttl_ns=1_000,
    )
    assert duplicate_grant == grant

    receipt = service.authorize(
        request_id="authorize-1",
        identity=agent,
        lease_id=grant.lease_id,
        transition="act",
        audience="executor-a",
        nonce="nonce-0000000001",
        expected_state="ready",
        expected_sequence=0,
    )
    duplicate = service.authorize(
        request_id="authorize-1",
        identity=agent,
        lease_id=grant.lease_id,
        transition="act",
        audience="executor-a",
        nonce="nonce-0000000001",
        expected_state="ready",
        expected_sequence=0,
    )
    assert duplicate == receipt
    snapshot = service.snapshot(identity=agent, lease_id=grant.lease_id)
    assert snapshot.residual == (18,)
    assert snapshot.sequence == 1
    invariant = service.invariant_snapshot(identity=_identity("admin", "lets.admin"))
    assert invariant.healthy
    assert invariant.consumed == (2,)
    with store.read() as transaction:
        assert transaction.connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 1
        assert transaction.connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0] == 1

    with pytest.raises(ConflictError):
        service.issue_root(
            request_id="issue-1",
            identity=agent,
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent-a",
            allocation=(19,),
            capabilities={"worker.act"},
            policy_digest=policy_digest,
            ttl_ns=1_000,
        )
    with pytest.raises(ReplayError):
        service.authorize(
            request_id="authorize-2",
            identity=agent,
            lease_id=grant.lease_id,
            transition="act",
            audience="executor-a",
            nonce="nonce-0000000001",
        )


def test_spawn_attenuation_renewal_cascade_and_identity_binding(
    warden: tuple[SQLiteStorage, WardenService, ManualClock],
) -> None:
    _, service, _ = warden
    parent_identity = _identity("parent", "lets.lease.issue", "lets.lease.manage")
    root = service.issue_root(
        request_id="root",
        identity=parent_identity,
        tenant_id="tenant",
        envelope_id="envelope",
        subject_id="parent",
        allocation=(50,),
        capabilities={"worker.act"},
        policy_digest=_policy().digest,
        ttl_ns=2_000,
    )
    with pytest.raises(PolicyError):
        service.spawn(
            request_id="bad-spawn",
            identity=_identity("intruder"),
            parent_id=root.lease_id,
            subject_id="child",
            allocation=(10,),
            capabilities={"worker.act"},
            ttl_ns=1_000,
        )
    child = service.spawn(
        request_id="spawn",
        identity=parent_identity,
        parent_id=root.lease_id,
        subject_id="child",
        allocation=(10,),
        capabilities={"worker.act"},
        ttl_ns=1_000,
        expected_sequence=0,
    )
    with pytest.raises(ConflictError, match="beneath a live child"):
        service.renew(
            request_id="renew-short",
            identity=parent_identity,
            lease_id=root.lease_id,
            ttl_ns=500,
        )
    renewed = service.renew(
        request_id="renew-cascade",
        identity=parent_identity,
        lease_id=root.lease_id,
        ttl_ns=500,
        cascade=True,
    )
    child_snapshot = service.snapshot(identity=_identity("child"), lease_id=child.lease_id)
    assert child_snapshot.grant.expires_at_ns == renewed.grant.expires_at_ns
    assert child_snapshot.sequence == 1


def test_service_never_issues_a_higher_sequence_with_an_earlier_receipt_horizon(
    warden: tuple[SQLiteStorage, WardenService, ManualClock],
) -> None:
    store, service, _ = warden
    agent = _identity("agent", "lets.lease.issue", "lets.lease.manage")
    grant = service.issue_root(
        request_id="expiry-order-root",
        identity=agent,
        tenant_id="tenant",
        envelope_id="envelope",
        subject_id="agent",
        allocation=(10,),
        capabilities={"worker.act"},
        policy_digest=_policy().digest,
        ttl_ns=500,
    )
    first = service.authorize(
        request_id="expiry-order-first",
        identity=agent,
        lease_id=grant.lease_id,
        transition="act",
        audience="executor-a",
        nonce="expiry-order-nonce-1",
        expected_sequence=0,
    )
    shortened = service.renew(
        request_id="expiry-order-shorten",
        identity=agent,
        lease_id=grant.lease_id,
        ttl_ns=30,
        expected_sequence=1,
    )
    assert shortened.sequence == 2
    assert shortened.grant.expires_at_ns < first.expires_at_ns

    with pytest.raises(ConflictError, match="receipt expiry would regress"):
        service.authorize(
            request_id="expiry-order-blocked",
            identity=agent,
            lease_id=grant.lease_id,
            transition="act",
            audience="executor-a",
            nonce="expiry-order-nonce-2",
            expected_sequence=2,
        )

    snapshot = service.snapshot(identity=agent, lease_id=grant.lease_id)
    assert snapshot.sequence == 2
    assert snapshot.residual == (8,)
    with store.read() as transaction:
        assert (
            transaction.scalar(
                "SELECT COUNT(*) FROM receipts WHERE lease_id = ?",
                (grant.lease_id,),
            )
            == 1
        )


def test_reclamation_waits_for_uncertainty_and_receipt_ttl(
    warden: tuple[SQLiteStorage, WardenService, ManualClock],
) -> None:
    _, service, clock = warden
    agent = _identity("agent", "lets.lease.issue")
    admin = _identity("admin", "lets.admin")
    grant = service.issue_root(
        request_id="short-root",
        identity=agent,
        tenant_id="tenant",
        envelope_id="envelope",
        subject_id="agent",
        allocation=(10,),
        capabilities={"worker.act"},
        policy_digest=_policy().digest,
        ttl_ns=200,
    )
    clock.current_ns = grant.expires_at_ns + 100 + 4
    assert service.reclaim_expired(identity=admin) == (0,)
    clock.advance(1)
    assert service.reclaim_expired(identity=admin) == (10,)
    assert service.reclaim_expired(identity=admin) == (0,)
    assert service.snapshot(identity=agent, lease_id=grant.lease_id).status is LeaseStatus.EXPIRED


def test_signed_revocation_ingest_is_monotonic_and_idempotent(tmp_path: Path) -> None:
    clock = ManualClock(1_000_000, 5)
    registry = PublicKeyRegistry()
    source_store, source = _service(tmp_path / "source.db", "source", (100,), clock, registry)
    target_store, target = _service(tmp_path / "target.db", "target", (0,), clock, registry)
    try:
        source.register_policy(_policy())
        target.register_policy(_policy())
        root = source.issue_root(
            request_id="root",
            identity=_identity("agent", "lets.lease.issue"),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent",
            allocation=(10,),
            capabilities={"worker.act"},
            policy_digest=_policy().digest,
            ttl_ns=1_000,
        )
        revocation = source.revoke_branch(
            request_id="revoke-1",
            identity=_identity("operator", "lets.admin"),
            lease_id=root.lease_id,
            reason="operator request",
        )
        assert (
            source.revoke_branch(
                request_id="revoke-1",
                identity=_identity("operator", "lets.admin"),
                lease_id=root.lease_id,
                reason="operator request",
            )
            == revocation
        )
        peer = _identity("source", "lets.revocation.propagate")
        assert target.ingest_revocation(identity=peer, revocation=revocation) == revocation
        assert target.ingest_revocation(identity=peer, revocation=revocation) == revocation
        next_revocation = source.revoke_branch(
            request_id="revoke-2",
            identity=_identity("operator", "lets.admin"),
            lease_id=root.lease_id,
            reason="operator confirmation",
            expected_epoch=1,
        )
        assert next_revocation.epoch == 2
        target.ingest_revocation(identity=peer, revocation=next_revocation)
        with target_store.read() as transaction:
            epoch = transaction.connection.execute("SELECT epoch FROM revocations").fetchone()[0]
            assert epoch == 2
        with pytest.raises(SignatureError):
            target.ingest_revocation(
                identity=peer,
                revocation=replace(revocation, reason="tampered"),
            )
    finally:
        source_store.close()
        target_store.close()


def test_transfer_gap_exactly_once_and_bilateral_checkpoint(tmp_path: Path) -> None:
    clock = ManualClock(1_000_000, 5)
    registry = PublicKeyRegistry()
    source_store, source = _service(tmp_path / "source.db", "source", (100,), clock, registry)
    target_store, target = _service(tmp_path / "target.db", "target", (0,), clock, registry)
    try:
        digest = source.register_policy(_policy())
        target.register_policy(_policy())
        source_identity = _identity("source")
        target_identity = _identity("target")
        vouchers = [
            source.prepare_transfer(
                request_id=f"transfer-{index}",
                identity=source_identity,
                tenant_id="tenant",
                envelope_id="envelope",
                target_warden="target",
                amount=(5,),
                policy_digest=digest,
            )
            for index in range(1, 6)
        ]
        with pytest.raises(ReplayError, match="admission window"):
            target.accept_transfer(identity=target_identity, voucher=vouchers[4])
        ack_two = target.accept_transfer(identity=target_identity, voucher=vouchers[1])
        assert ack_two.contiguous_watermark == 0
        ack_one = target.accept_transfer(identity=target_identity, voucher=vouchers[0])
        assert ack_one.contiguous_watermark == 2
        assert target.accept_transfer(identity=target_identity, voucher=vouchers[0]) == ack_one
        assert target.invariant_snapshot(identity=target_identity).free_pool == (10,)
        source.finalize_transfer(identity=source_identity, acknowledgement=ack_two)
        source.finalize_transfer(identity=source_identity, acknowledgement=ack_one)
        checkpoint = source.create_transfer_checkpoint(
            identity=source_identity,
            target_warden="target",
        )
        target.ingest_transfer_checkpoint(identity=source_identity, checkpoint=checkpoint)
        target.ingest_transfer_checkpoint(identity=source_identity, checkpoint=checkpoint)
        with source_store.read() as transaction:
            outgoing_count = transaction.connection.execute(
                "SELECT COUNT(*) FROM outgoing_transfers"
            ).fetchone()[0]
            assert outgoing_count == 3
            minimum_sequence = transaction.connection.execute(
                "SELECT MIN(sequence) FROM outgoing_transfers"
            ).fetchone()[0]
            assert minimum_sequence == 3
        with target_store.read() as transaction:
            inbound_count = transaction.connection.execute(
                "SELECT COUNT(*) FROM inbound_transfer_acks"
            ).fetchone()[0]
            assert inbound_count == 0
    finally:
        source_store.close()
        target_store.close()


def test_storage_and_service_share_the_same_out_of_order_sequence_representation(
    tmp_path: Path,
) -> None:
    clock = ManualClock(1_000_000, 5)
    registry = PublicKeyRegistry()
    source_store, source = _service(tmp_path / "mixed-source.db", "source", (100,), clock, registry)
    target_store, target = _service(tmp_path / "mixed-target.db", "target", (0,), clock, registry)
    try:
        digest = source.register_policy(_policy())
        target.register_policy(_policy())
        vouchers = [
            source.prepare_transfer(
                request_id=f"mixed-transfer-{index}",
                identity=_identity("source"),
                tenant_id="tenant",
                envelope_id="envelope",
                target_warden="target",
                amount=(5,),
                policy_digest=digest,
            )
            for index in (1, 2)
        ]
        second = vouchers[1]
        voucher_digest = canonical_digest(second.to_dict())
        stored_second = TransferAck(
            tenant_id="tenant",
            envelope_id="envelope",
            config_epoch=1,
            transfer_id=second.transfer_id,
            source_warden="source",
            target_warden="target",
            sequence=2,
            voucher_digest=voucher_digest,
            accepted_at_ns=clock.now_ns(),
            contiguous_watermark=0,
            key_id=target_store.metadata.signing_key_id,
            signature=b64url_encode(b"storage-adapter-signature"),
        )
        with target_store.write() as transaction:
            state = transaction.get_warden_state()
            assert transaction.record_inbound_ack(
                transfer_id=second.transfer_id,
                source_warden="source",
                sequence=2,
                transfer_digest=voucher_digest,
                contiguous_watermark=0,
                key_id=stored_second.key_id,
                ack_payload=canonical_json(stored_second.to_dict()),
                signature=b"storage-adapter-signature",
                accepted_at_ns=clock.now_ns(),
            )
            transaction.update_warden_state(
                free_pool=(state["free_pool"][0] + 5,),
                transferred_in=(state["transferred_in"][0] + 5,),
                updated_at_ns=clock.now_ns(),
            )

        first_ack = target.accept_transfer(identity=_identity("target"), voucher=vouchers[0])
        assert first_ack.contiguous_watermark == 2
        assert target.accept_transfer(identity=_identity("target"), voucher=second) == stored_second
        assert target.invariant_snapshot(identity=_identity("target")).free_pool == (10,)
        with target_store.read() as transaction:
            assert transaction.scalar("SELECT COUNT(*) FROM inbound_transfer_gaps") == 0
            assert (
                transaction.scalar("SELECT contiguous_through FROM inbound_transfer_streams") == 2
            )
    finally:
        source_store.close()
        target_store.close()


def test_manifest_peer_allowlist_rejects_transfer_before_debit(tmp_path: Path) -> None:
    clock = ManualClock(1_000_000, 5)
    registry = PublicKeyRegistry()
    signer = Ed25519Signer.generate("source")
    registry.register_signer(signer)
    store = SQLiteStorage.initialize(
        tmp_path / "allowlisted.db",
        "source",
        (100,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        receipt_ttl_ns=100,
        max_clock_uncertainty_ns=5,
        transfer_gap_window=4,
    )
    service = WardenService(
        store,
        signer=signer,
        clock=clock,
        trust_registry=registry,
        allowed_peer_wardens={"target"},
    )
    try:
        digest = service.register_policy(_policy())
        before = service.invariant_snapshot(identity=_identity("source"))
        with pytest.raises(PolicyError, match="not authorized"):
            service.prepare_transfer(
                request_id="typo-target",
                identity=_identity("source"),
                tenant_id="tenant",
                envelope_id="envelope",
                target_warden="targte",
                amount=(5,),
                policy_digest=digest,
            )
        after = service.invariant_snapshot(identity=_identity("source"))
        assert after == before
        with store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM outgoing_transfers"
                ).fetchone()[0]
                == 0
            )
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM peer_delivery_state"
                ).fetchone()[0]
                == 0
            )
    finally:
        store.close()


def test_transfer_rejects_target_whose_last_trusted_key_expired_after_startup(
    tmp_path: Path,
) -> None:
    clock = ManualClock(1_000_000, 5)
    source_signer = Ed25519Signer.generate("source")
    target_signer = Ed25519Signer.generate("target")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(source_signer)
    registry.register(
        target_signer.warden_id,
        target_signer.key_id,
        target_signer.public_key_bytes,
        not_after_ns=1_000_010,
    )
    store = SQLiteStorage.initialize(
        tmp_path / "expiring-target.db",
        "source",
        (100,),
        signing_key_id=source_signer.key_id,
        signing_public_key=source_signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        receipt_ttl_ns=100,
        max_clock_uncertainty_ns=5,
        transfer_gap_window=4,
    )
    service = WardenService(
        store,
        signer=source_signer,
        clock=clock,
        trust_registry=registry,
        allowed_peer_wardens={"target"},
    )
    try:
        digest = service.register_policy(_policy())
        before = service.invariant_snapshot(identity=_identity("source"))
        clock.current_ns = 1_000_006

        with pytest.raises(SignatureError, match="no currently valid trusted key"):
            service.prepare_transfer(
                request_id="expired-target",
                identity=_identity("source"),
                tenant_id="tenant",
                envelope_id="envelope",
                target_warden="target",
                amount=(5,),
                policy_digest=digest,
            )

        after = service.invariant_snapshot(identity=_identity("source"))
        assert replace(after, checked_at_ns=before.checked_at_ns) == before
        with store.read() as transaction:
            assert transaction.scalar("SELECT COUNT(*) FROM outgoing_transfers") == 0
            assert transaction.scalar("SELECT COUNT(*) FROM peer_delivery_state") == 0
    finally:
        store.close()


def test_audit_pagination_and_chain_verification(
    warden: tuple[SQLiteStorage, WardenService, ManualClock],
) -> None:
    _, service, _ = warden
    admin = _identity("admin", "lets.admin")
    agent = _identity("agent", "lets.lease.issue")
    service.issue_root(
        request_id="audit-root",
        identity=agent,
        tenant_id="tenant",
        envelope_id="envelope",
        subject_id="agent",
        allocation=(5,),
        capabilities={"worker.act"},
        policy_digest=_policy().digest,
        ttl_ns=1_000,
    )
    first_page = service.list_audit(identity=admin, limit=1)
    second_page = service.list_audit(identity=admin, after_sequence=first_page[-1].sequence)
    assert len(first_page) == 1
    assert second_page
    assert first_page[-1].sequence < second_page[0].sequence
    assert service.verify_audit(identity=admin)


def test_historical_local_key_uses_registry_after_rotation(tmp_path: Path) -> None:
    clock = ManualClock(1_000_000, 0)
    old_signer = Ed25519Signer.generate("warden-a")
    current_signer = Ed25519Signer.generate("warden-a")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(old_signer)
    registry.register_signer(current_signer)
    store = SQLiteStorage.initialize(
        tmp_path / "rotated.db",
        "warden-a",
        (10,),
        signing_key_id=current_signer.key_id,
        signing_public_key=current_signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
    )
    service = WardenService(
        store,
        signer=current_signer,
        clock=clock,
        trust_registry=registry,
    )
    unsigned = TransferVoucher(
        tenant_id="tenant",
        envelope_id="envelope",
        config_epoch=1,
        transfer_id="historical-transfer",
        source_warden="warden-a",
        target_warden="warden-b",
        policy_id="policy",
        policy_version="v1",
        policy_digest="sha256:" + "0" * 64,
        sequence=1,
        amount=(1,),
        issued_at_ns=1,
        key_id=old_signer.key_id,
    )
    historical = replace(
        unsigned,
        signature=b64url_encode(old_signer.sign(canonical_json(unsigned.unsigned_payload()))),
    )

    service._verify_record(historical, warden_id="warden-a")
    store.close()


def test_service_rejects_signer_substitution_at_startup(tmp_path: Path) -> None:
    anchored = Ed25519Signer.generate("warden-a")
    replacement = Ed25519Signer.generate("warden-a")
    store = SQLiteStorage.initialize(
        tmp_path / "anchored.db",
        "warden-a",
        (10,),
        signing_key_id=anchored.key_id,
        signing_public_key=anchored.public_key_bytes,
    )

    with pytest.raises(ConflictError, match="key_id"):
        WardenService(store, signer=replacement)
    store.close()
