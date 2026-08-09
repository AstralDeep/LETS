from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from lets.canonical import b64url_encode, canonical_digest, canonical_json, strict_json_loads
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import (
    CapacityError,
    ConflictError,
    DrainingError,
    PolicyError,
    ReplayError,
    SignatureError,
    ValidationError,
)
from lets.models import (
    IdentityContext,
    LeaseStatus,
    RuntimeMode,
    TransferAck,
    TransferVoucher,
)
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage
from lets.vector import pack


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
    *,
    gap_window: int = 4,
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
        transfer_gap_window=gap_window,
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


def test_policy_registration_binds_authenticated_admin_tenant(
    tmp_path: Path,
) -> None:
    clock = ManualClock(1_000_000, 5)
    registry = PublicKeyRegistry()
    store, service = _service(tmp_path / "policy-tenant.db", "warden-a", (100,), clock, registry)
    try:
        wrong_tenant = IdentityContext(
            "operator-a",
            "tenant-b",
            frozenset({"lets.admin"}),
        )
        with pytest.raises(PolicyError, match="identity tenant"):
            service.register_policy(_policy(), identity=wrong_tenant)
        with store.read() as transaction:
            assert transaction.scalar("SELECT COUNT(*) FROM policies") == 0

        digest = service.register_policy(
            _policy(),
            identity=_identity("operator-a", "lets.admin"),
        )
        assert digest == _policy().digest
    finally:
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


def test_peer_replay_claim_and_legacy_import_are_core_authority_events(
    warden: tuple[SQLiteStorage, WardenService, ManualClock],
) -> None:
    store, service, _ = warden
    before = store.authority_checkpoint()
    assert service.claim_peer_request(
        warden_id="warden-b",
        key_id="warden-b-key",
        nonce="peer-nonce-000000000001",
        timestamp_s=0,
        expires_at_s=30,
        now_s=0,
        clock_tolerance_s=30,
    )
    assert not service.claim_peer_request(
        warden_id="warden-b",
        key_id="warden-b-key",
        nonce="peer-nonce-000000000001",
        timestamp_s=0,
        expires_at_s=30,
        now_s=0,
        clock_tolerance_s=30,
    )
    after = store.authority_checkpoint()
    status = service.peer_replay_status()
    assert after.audit_sequence == before.audit_sequence + 1
    assert after.state_digest != before.state_digest
    assert status["authority"] == "core"
    assert status["revision"] == 1
    assert status["active_claims"] == 1

    other_store, other_service = _service(
        Path(store.path).parent / "legacy-import.db",
        "warden-c",
        (100,),
        ManualClock(2_000_000_000, 5),
        PublicKeyRegistry(),
    )
    try:
        digest = bytes(range(32))
        with pytest.raises(ValidationError, match="still has live claims"):
            other_service.import_legacy_peer_replay(
                clock_floor_s=1,
                snapshot_digest=digest,
                active_claim_count=1,
                now_s=2,
            )
        assert other_service.import_legacy_peer_replay(
            clock_floor_s=1,
            snapshot_digest=digest,
            active_claim_count=0,
            now_s=2,
        )
        assert not other_service.import_legacy_peer_replay(
            clock_floor_s=1,
            snapshot_digest=digest,
            active_claim_count=0,
            now_s=2,
        )
        imported = other_service.peer_replay_status()
        assert imported["clock_floor_s"] == 2
        assert imported["revision"] == 1
        assert imported["legacy_snapshot_digest"] == f"sha256:{digest.hex()}"
        with pytest.raises(ConflictError, match="different snapshot"):
            other_service.import_legacy_peer_replay(
                clock_floor_s=1,
                snapshot_digest=bytes(reversed(range(32))),
                active_claim_count=0,
                now_s=2,
            )
    finally:
        other_store.close()


def test_peer_replay_expired_claim_gc_is_bounded_per_authority_event(
    warden: tuple[SQLiteStorage, WardenService, ManualClock],
) -> None:
    store, service, _ = warden
    with store.write() as transaction:
        transaction.connection.executemany(
            """
            INSERT INTO peer_http_replay(
                tenant_id, envelope_id, warden_id, key_id, nonce,
                timestamp_s, expires_at_s, accepted_at_ns
            ) VALUES ('tenant', 'envelope', 'warden-old', 'key-old', ?, 0, 0, 0)
            """,
            ((f"expired-{index:04d}",) for index in range(200)),
        )
    assert service.claim_peer_request(
        warden_id="warden-b",
        key_id="warden-b-key",
        nonce="peer-nonce-000000000002",
        timestamp_s=0,
        expires_at_s=30,
        now_s=1,
        clock_tolerance_s=30,
    )
    with store.read() as transaction:
        expired = transaction.connection.execute(
            "SELECT COUNT(*) FROM peer_http_replay WHERE expires_at_s < 1"
        ).fetchone()
        assert expired is not None
        assert int(expired[0]) == 72
        plan = tuple(
            str(row[3])
            for row in transaction.connection.execute(
                """
                EXPLAIN QUERY PLAN
                SELECT tenant_id, envelope_id, warden_id, key_id, nonce
                FROM peer_http_replay
                WHERE tenant_id=? AND envelope_id=? AND expires_at_s < ?
                ORDER BY expires_at_s, warden_id, key_id, nonce LIMIT ?
                """,
                ("tenant", "envelope", 1, 128),
            )
        )
        assert any("COVERING INDEX ix_peer_http_replay_expiry" in step for step in plan)
        assert all("USE TEMP" not in step for step in plan)


def test_drain_fences_new_authority_but_preserves_retries_and_safety(
    warden: tuple[SQLiteStorage, WardenService, ManualClock],
) -> None:
    store, service, _ = warden
    agent = _identity("agent-a", "lets.lease.issue", "lets.lease.manage")
    admin = _identity("operator", "lets.admin")
    grant = service.issue_root(
        request_id="drain-root",
        identity=agent,
        tenant_id="tenant",
        envelope_id="envelope",
        subject_id="agent-a",
        allocation=(10,),
        capabilities={"worker.act"},
        policy_digest=_policy().digest,
        ttl_ns=1_000,
    )
    receipt = service.authorize(
        request_id="drain-authorize",
        identity=agent,
        lease_id=grant.lease_id,
        transition="act",
        audience="executor-a",
        nonce="drain-nonce-0000001",
    )

    draining = service.set_runtime_mode(
        request_id="mode-draining",
        identity=admin,
        mode=RuntimeMode.DRAINING,
        reason="planned schema migration",
    )
    assert draining.mode is RuntimeMode.DRAINING
    assert draining.generation == 1
    assert service.runtime_status(identity=admin) == draining
    assert not service.ready()

    # Retries committed before the fence remain exactly idempotent.
    assert (
        service.issue_root(
            request_id="drain-root",
            identity=agent,
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent-a",
            allocation=(10,),
            capabilities={"worker.act"},
            policy_digest=_policy().digest,
            ttl_ns=1_000,
        )
        == grant
    )
    assert (
        service.authorize(
            request_id="drain-authorize",
            identity=agent,
            lease_id=grant.lease_id,
            transition="act",
            audience="executor-a",
            nonce="drain-nonce-0000001",
        )
        == receipt
    )

    with pytest.raises(DrainingError):
        service.issue_root(
            request_id="new-root-while-draining",
            identity=agent,
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent-a",
            allocation=(1,),
            capabilities={"worker.act"},
            policy_digest=_policy().digest,
            ttl_ns=1_000,
        )
    with pytest.raises(DrainingError):
        service.authorize(
            request_id="new-effect-while-draining",
            identity=agent,
            lease_id=grant.lease_id,
            transition="act",
            audience="executor-a",
            nonce="drain-nonce-0000002",
        )

    quiescent = service.quiesce(
        request_id="quiesce-while-draining",
        identity=agent,
        lease_id=grant.lease_id,
    )
    assert quiescent.status is LeaseStatus.QUIESCENT
    with pytest.raises(DrainingError):
        service.resume(
            request_id="resume-while-draining",
            identity=agent,
            lease_id=grant.lease_id,
        )
    closed = service.close(
        request_id="close-while-draining",
        identity=agent,
        lease_id=grant.lease_id,
    )
    assert closed.status is LeaseStatus.CLOSED

    active = service.set_runtime_mode(
        request_id="mode-active",
        identity=admin,
        mode="ACTIVE",
        reason="migration completed and diagnostics passed",
    )
    assert active.mode is RuntimeMode.ACTIVE
    assert active.generation == 2
    assert service.ready()
    with store.read() as transaction:
        events = {
            str(row[0])
            for row in transaction.connection.execute(
                "SELECT event_type FROM audit_log WHERE event_type LIKE 'warden.runtime-%'"
            )
        }
    assert events == {"warden.runtime-mode-changed"}


def test_readiness_fails_before_the_configured_database_capacity_limit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "capacity-warden.db"
    signer = Ed25519Signer.generate("warden-a")
    registry = PublicKeyRegistry()
    registry.register_signer(signer)
    options = {
        "signing_key_id": signer.key_id,
        "signing_public_key": signer.public_key_bytes,
        "tenant_id": "tenant",
        "envelope_id": "envelope",
        "initial_local_share": (100,),
        "receipt_ttl_ns": 100,
        "max_clock_uncertainty_ns": 5,
        "transfer_gap_window": 4,
    }
    initial = SQLiteStorage.initialize(path, "warden-a", (100,), **options)
    service = WardenService(
        initial,
        signer=signer,
        clock=ManualClock(1_000_000, 5),
        trust_registry=registry,
    )
    service.register_policy(_policy())
    capacity = initial.capacity_snapshot()
    initial.close()

    limited = SQLiteStorage(
        path,
        "warden-a",
        (100,),
        max_database_bytes=capacity.page_count * capacity.page_size,
        reserve_pages=capacity.free_pages + 1,
        **options,
    )
    limited_service = WardenService(
        limited,
        signer=signer,
        clock=ManualClock(1_000_000, 5),
        trust_registry=registry,
    )
    try:
        assert not limited_service.ready()
        with pytest.raises(CapacityError):
            limited_service.issue_root(
                request_id="capacity-root",
                identity=_identity("agent", "lets.lease.issue"),
                tenant_id="tenant",
                envelope_id="envelope",
                subject_id="agent",
                allocation=(1,),
                capabilities={"worker.act"},
                policy_digest=_policy().digest,
                ttl_ns=1_000,
            )
        assert limited_service.invariant_snapshot(
            identity=_identity("operator", "lets.admin")
        ).healthy
    finally:
        limited.close()


def test_capacity_degraded_node_serves_exact_retries_but_fences_new_mutations(
    tmp_path: Path,
) -> None:
    path = tmp_path / "degraded-idempotency.db"
    clock = ManualClock(1_000_000, 5)
    signer = Ed25519Signer.generate("warden-a")
    peer_signer = Ed25519Signer.generate("warden-b")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    registry.register_signer(peer_signer)
    options = {
        "signing_key_id": signer.key_id,
        "signing_public_key": signer.public_key_bytes,
        "tenant_id": "tenant",
        "envelope_id": "envelope",
        "initial_local_share": (100,),
        "receipt_ttl_ns": 100,
        "max_clock_uncertainty_ns": 5,
        "transfer_gap_window": 4,
    }
    initial = SQLiteStorage.initialize(path, "warden-a", (100,), **options)
    service = WardenService(
        initial,
        signer=signer,
        clock=clock,
        trust_registry=registry,
        allowed_peer_wardens={"warden-b"},
    )
    service.register_policy(_policy())
    identity = _identity("agent-a", "lets.lease.issue", "lets.lease.manage", "lets.transfer")
    root = service.issue_root(
        request_id="degraded-root",
        identity=identity,
        tenant_id="tenant",
        envelope_id="envelope",
        subject_id="agent-a",
        allocation=(40,),
        capabilities={"worker.act"},
        policy_digest=_policy().digest,
        ttl_ns=5_000,
    )
    child = service.spawn(
        request_id="degraded-spawn",
        identity=identity,
        parent_id=root.lease_id,
        subject_id="agent-a",
        allocation=(10,),
        capabilities={"worker.act"},
        ttl_ns=2_000,
    )
    receipt = service.authorize(
        request_id="degraded-authorize",
        identity=identity,
        lease_id=child.lease_id,
        transition="act",
        audience="executor-a",
        nonce="degraded-nonce-0001",
    )
    renewed = service.renew(
        request_id="degraded-renew",
        identity=identity,
        lease_id=root.lease_id,
        ttl_ns=5_000,
    )
    quiesced = service.quiesce(
        request_id="degraded-quiesce",
        identity=identity,
        lease_id=child.lease_id,
    )
    resumed = service.resume(
        request_id="degraded-resume",
        identity=identity,
        lease_id=child.lease_id,
    )
    voucher = service.prepare_transfer(
        request_id="degraded-transfer",
        identity=identity,
        tenant_id="tenant",
        envelope_id="envelope",
        target_warden="warden-b",
        amount=(5,),
    )
    capacity = initial.capacity_snapshot()
    initial.close()

    limited = SQLiteStorage(
        path,
        "warden-a",
        (100,),
        max_database_bytes=capacity.page_count * capacity.page_size,
        reserve_pages=capacity.free_pages + 1,
        **options,
    )
    degraded = WardenService(
        limited,
        signer=signer,
        clock=clock,
        trust_registry=registry,
        allowed_peer_wardens={"warden-b"},
    )
    try:
        assert not degraded.ready()
        assert (
            degraded.issue_root(
                request_id="degraded-root",
                identity=identity,
                tenant_id="tenant",
                envelope_id="envelope",
                subject_id="agent-a",
                allocation=(40,),
                capabilities={"worker.act"},
                policy_digest=_policy().digest,
                ttl_ns=5_000,
            )
            == root
        )
        assert (
            degraded.spawn(
                request_id="degraded-spawn",
                identity=identity,
                parent_id=root.lease_id,
                subject_id="agent-a",
                allocation=(10,),
                capabilities={"worker.act"},
                ttl_ns=2_000,
            )
            == child
        )
        assert (
            degraded.authorize(
                request_id="degraded-authorize",
                identity=identity,
                lease_id=child.lease_id,
                transition="act",
                audience="executor-a",
                nonce="degraded-nonce-0001",
            )
            == receipt
        )
        assert (
            degraded.renew(
                request_id="degraded-renew",
                identity=identity,
                lease_id=root.lease_id,
                ttl_ns=5_000,
            )
            == renewed
        )
        assert (
            degraded.quiesce(
                request_id="degraded-quiesce",
                identity=identity,
                lease_id=child.lease_id,
            )
            == quiesced
        )
        assert (
            degraded.resume(
                request_id="degraded-resume",
                identity=identity,
                lease_id=child.lease_id,
            )
            == resumed
        )
        assert (
            degraded.prepare_transfer(
                request_id="degraded-transfer",
                identity=identity,
                tenant_id="tenant",
                envelope_id="envelope",
                target_warden="warden-b",
                amount=(5,),
            )
            == voucher
        )

        with pytest.raises(CapacityError):
            degraded.issue_root(
                request_id="new-while-degraded",
                identity=identity,
                tenant_id="tenant",
                envelope_id="envelope",
                subject_id="agent-a",
                allocation=(1,),
                capabilities={"worker.act"},
                policy_digest=_policy().digest,
                ttl_ns=1_000,
            )
        with pytest.raises(ConflictError):
            degraded.issue_root(
                request_id="degraded-root",
                identity=identity,
                tenant_id="tenant",
                envelope_id="envelope",
                subject_id="agent-a",
                allocation=(39,),
                capabilities={"worker.act"},
                policy_digest=_policy().digest,
                ttl_ns=5_000,
            )
    finally:
        limited.close()


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


def test_large_branch_cascade_rejects_atomically_and_revocation_materializes_in_batches(
    warden: tuple[SQLiteStorage, WardenService, ManualClock],
) -> None:
    store, service, _ = warden
    manager = _identity("manager", "lets.lease.issue", "lets.lease.manage")
    root = service.issue_root(
        request_id="bounded-root",
        identity=manager,
        tenant_id="tenant",
        envelope_id="envelope",
        subject_id="manager",
        allocation=(80,),
        capabilities={"worker.act"},
        policy_digest=_policy().digest,
        ttl_ns=2_000,
    )
    for index in range(65):
        service.spawn(
            request_id=f"bounded-child-{index:03d}",
            identity=manager,
            parent_id=root.lease_id,
            subject_id="child",
            allocation=(1,),
            capabilities={"worker.act"},
            ttl_ns=1_000,
        )

    checkpoint = store.authority_checkpoint()
    root_before = service.snapshot(identity=manager, lease_id=root.lease_id)
    with pytest.raises(PolicyError, match="more than 64 live descendants"):
        service.renew(
            request_id="oversized-cascade",
            identity=manager,
            lease_id=root.lease_id,
            ttl_ns=500,
            cascade=True,
        )
    assert store.authority_checkpoint() == checkpoint
    assert service.snapshot(identity=manager, lease_id=root.lease_id) == root_before

    revocation = service.revoke_branch(
        request_id="bounded-revoke",
        identity=_identity("operator", "lets.admin"),
        lease_id=root.lease_id,
        reason="bounded materialization regression",
    )
    with store.read() as transaction:
        revoked = int(
            transaction.connection.execute(
                "SELECT COUNT(*) FROM leases WHERE status = 'REVOKED'"
            ).fetchone()[0]
        )
        assert revoked == 64
        active_child = transaction.connection.execute(
            """
            SELECT lease_id FROM leases
            WHERE status = 'ACTIVE' AND parent_id IS NOT NULL
            LIMIT 1
            """
        ).fetchone()
        assert active_child is not None
        event = transaction.connection.execute(
            """
            SELECT payload FROM audit_log
            WHERE event_type = 'branch.revoked'
            ORDER BY sequence DESC LIMIT 1
            """
        ).fetchone()
        assert event is not None
        signed_event = strict_json_loads(bytes(event[0]))
        assert len(signed_event["details"]["affected"]) == 64
        assert signed_event["details"]["materialization_complete"] is False

    with pytest.raises(PolicyError, match="revoked branch"):
        service.renew(
            request_id="revoked-unmaterialized-child",
            identity=_identity("child"),
            lease_id=str(active_child[0]),
            ttl_ns=400,
        )

    assert (
        service.revoke_branch(
            request_id="bounded-revoke",
            identity=_identity("operator", "lets.admin"),
            lease_id=root.lease_id,
            reason="bounded materialization regression",
        )
        == revocation
    )
    with store.read() as transaction:
        assert (
            transaction.connection.execute(
                "SELECT COUNT(*) FROM leases WHERE status = 'REVOKED'"
            ).fetchone()[0]
            == 66
        )
        progress = transaction.connection.execute(
            """
            SELECT payload FROM audit_log
            WHERE event_type = 'branch.revocation-materialized'
            ORDER BY sequence DESC LIMIT 1
            """
        ).fetchone()
        assert progress is not None
        signed_progress = strict_json_loads(bytes(progress[0]))
        assert len(signed_progress["details"]["affected"]) == 2
        assert signed_progress["details"]["materialization_complete"] is True


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


def test_reclamation_updates_at_most_one_batch_and_converges(
    warden: tuple[SQLiteStorage, WardenService, ManualClock],
) -> None:
    store, service, clock = warden
    issuer = _identity("issuer", "lets.lease.issue")
    admin = _identity("admin", "lets.admin")
    grants = [
        service.issue_root(
            request_id=f"reclaim-root-{index:03d}",
            identity=issuer,
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id=f"agent-{index:03d}",
            allocation=(1,),
            capabilities={"worker.act"},
            policy_digest=_policy().digest,
            ttl_ns=200,
        )
        for index in range(65)
    ]
    clock.current_ns = max(grant.expires_at_ns for grant in grants) + 105

    assert service.reclaim_expired(identity=admin) == (64,)
    with store.read() as transaction:
        assert (
            transaction.connection.execute(
                "SELECT COUNT(*) FROM leases WHERE status = 'EXPIRED'"
            ).fetchone()[0]
            == 64
        )
        first = transaction.connection.execute(
            """
            SELECT payload FROM audit_log
            WHERE event_type = 'leases.reclaimed'
            ORDER BY sequence DESC LIMIT 1
            """
        ).fetchone()
        assert first is not None
        first_event = strict_json_loads(bytes(first[0]))
        assert len(first_event["details"]["lease_ids"]) == 64

    assert service.reclaim_expired(identity=admin) == (1,)
    assert service.reclaim_expired(identity=admin) == (0,)
    assert service.invariant_snapshot(identity=admin).free_pool == (100,)


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


def test_transfer_watermarks_advance_in_bounded_retry_driven_batches(
    tmp_path: Path,
) -> None:
    clock = ManualClock(1_000_000, 5)
    registry = PublicKeyRegistry()
    source_store, source = _service(
        tmp_path / "watermark-source.db",
        "source",
        (100,),
        clock,
        registry,
        gap_window=128,
    )
    target_store, target = _service(
        tmp_path / "watermark-target.db",
        "target",
        (0,),
        clock,
        registry,
        gap_window=128,
    )
    try:
        policy = _policy(gap_window=128)
        policy_digest = source.register_policy(policy)
        target.register_policy(policy)
        source_identity = _identity("source")
        target_identity = _identity("target")
        vouchers = [
            source.prepare_transfer(
                request_id=f"watermark-transfer-{sequence:03d}",
                identity=source_identity,
                tenant_id="tenant",
                envelope_id="envelope",
                target_warden="target",
                amount=(1,),
                policy_digest=policy_digest,
            )
            for sequence in range(1, 67)
        ]

        acknowledgements = {
            voucher.sequence: target.accept_transfer(
                identity=target_identity,
                voucher=voucher,
            )
            for voucher in vouchers[1:]
        }
        assert all(ack.contiguous_watermark == 0 for ack in acknowledgements.values())
        first_ack = target.accept_transfer(
            identity=target_identity,
            voucher=vouchers[0],
        )
        acknowledgements[1] = first_ack
        assert first_ack.contiguous_watermark == 65
        with target_store.read() as transaction:
            stream = transaction.connection.execute(
                "SELECT contiguous_through FROM inbound_transfer_streams"
            ).fetchone()
            assert stream is not None and int(stream[0]) == 65
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM inbound_transfer_gaps"
                ).fetchone()[0]
                == 1
            )
            before_retry_pool = transaction.connection.execute(
                "SELECT free_pool FROM warden_state"
            ).fetchone()
            assert before_retry_pool is not None and bytes(before_retry_pool[0]) == pack((66,))

        assert target.accept_transfer(identity=target_identity, voucher=vouchers[0]) == first_ack
        with target_store.read() as transaction:
            stream = transaction.connection.execute(
                "SELECT contiguous_through FROM inbound_transfer_streams"
            ).fetchone()
            assert stream is not None and int(stream[0]) == 66
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM inbound_transfer_gaps"
                ).fetchone()[0]
                == 0
            )
            after_retry_pool = transaction.connection.execute(
                "SELECT free_pool FROM warden_state"
            ).fetchone()
            assert after_retry_pool is not None and bytes(after_retry_pool[0]) == pack((66,))

        for sequence in range(2, 67):
            acknowledgement = acknowledgements[sequence]
            assert (
                source.finalize_transfer(
                    identity=source_identity,
                    acknowledgement=acknowledgement,
                )
                == acknowledgement
            )
        with source_store.read() as transaction:
            stream = transaction.connection.execute(
                "SELECT acked_through FROM outgoing_transfer_streams"
            ).fetchone()
            assert stream is not None and int(stream[0]) == 0

        assert (
            source.finalize_transfer(
                identity=source_identity,
                acknowledgement=first_ack,
            )
            == first_ack
        )
        with source_store.read() as transaction:
            stream = transaction.connection.execute(
                "SELECT acked_through FROM outgoing_transfer_streams"
            ).fetchone()
            assert stream is not None and int(stream[0]) == 64

        with pytest.raises(ConflictError, match="exceeds the finalized acknowledgement"):
            source.create_transfer_checkpoint(
                identity=source_identity,
                target_warden="target",
                through_sequence=65,
            )
        ack_65 = acknowledgements[65]
        assert (
            source.finalize_transfer(
                identity=source_identity,
                acknowledgement=ack_65,
            )
            == ack_65
        )
        with source_store.read() as transaction:
            stream = transaction.connection.execute(
                "SELECT acked_through FROM outgoing_transfer_streams"
            ).fetchone()
            assert stream is not None and int(stream[0]) == 66

        checkpoint_66 = source.create_transfer_checkpoint(
            identity=source_identity,
            target_warden="target",
        )
        assert checkpoint_66["through_sequence"] == 66
        target.ingest_transfer_checkpoint(
            identity=source_identity,
            checkpoint=checkpoint_66,
        )
        with source_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM outgoing_transfers"
                ).fetchone()[0]
                == 2
            )
        with target_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM inbound_transfer_acks"
                ).fetchone()[0]
                == 2
            )
        with pytest.raises(ReplayError, match="compacted transfer prefix"):
            target.accept_transfer(identity=target_identity, voucher=vouchers[64])

        assert (
            source.create_transfer_checkpoint(
                identity=source_identity,
                target_warden="target",
                through_sequence=66,
            )
            == checkpoint_66
        )
        assert (
            target.ingest_transfer_checkpoint(
                identity=source_identity,
                checkpoint=checkpoint_66,
            )
            == checkpoint_66
        )
        with source_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM outgoing_transfers"
                ).fetchone()[0]
                == 0
            )
        with target_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM inbound_transfer_acks"
                ).fetchone()[0]
                == 0
            )
    finally:
        source_store.close()
        target_store.close()


def test_bilateral_checkpoint_prefix_pruning_is_bounded_and_retry_convergent(
    tmp_path: Path,
) -> None:
    clock = ManualClock(1_000_000, 5)
    registry = PublicKeyRegistry()
    source_store, source = _service(
        tmp_path / "bounded-checkpoint-source.db", "source", (100,), clock, registry
    )
    target_store, target = _service(
        tmp_path / "bounded-checkpoint-target.db", "target", (0,), clock, registry
    )
    try:
        policy = _policy()
        policy_digest = source.register_policy(policy)
        target.register_policy(policy)
        amount = pack((1,))
        with source_store.write() as transaction:
            connection = transaction.connection
            connection.execute(
                """
                INSERT INTO outgoing_transfer_streams(
                    tenant_id, envelope_id, target_warden, config_epoch,
                    next_sequence, acked_through, compacted_through,
                    checkpoint_payload, updated_at_ns
                ) VALUES ('tenant', 'envelope', 'target', 1, 66, 65, 0, NULL, 2)
                """
            )
            connection.executemany(
                """
                INSERT INTO outgoing_transfers(
                    tenant_id, envelope_id, transfer_id, source_warden, target_warden,
                    sequence, config_epoch, amount, policy_version, policy_digest,
                    digest, key_id, signature, voucher_payload, status,
                    prepared_at_ns, acknowledged_at_ns, ack_payload
                ) VALUES (
                    'tenant', 'envelope', ?, 'source', 'target', ?, 1, ?, 'v1', ?,
                    ?, 'seed-key', X'01', X'7B7D', 'FINALIZED', 1, 2, X'7B7D'
                )
                """,
                (
                    (
                        f"transfer-{sequence:03d}",
                        sequence,
                        amount,
                        policy_digest,
                        f"digest-{sequence:03d}",
                    )
                    for sequence in range(1, 66)
                ),
            )
            connection.execute(
                """
                UPDATE warden_state
                SET free_pool = ?, transferred_out = ?, revision = revision + 1,
                    updated_at_ns = 2
                WHERE tenant_id = 'tenant' AND envelope_id = 'envelope'
                """,
                (pack((35,)), pack((65,))),
            )

        with target_store.write() as transaction:
            connection = transaction.connection
            connection.execute(
                """
                INSERT INTO inbound_transfer_streams(
                    tenant_id, envelope_id, source_warden, config_epoch,
                    contiguous_through, highest_seen, compacted_through,
                    checkpoint_payload, updated_at_ns
                ) VALUES ('tenant', 'envelope', 'source', 1, 65, 65, 0, NULL, 2)
                """
            )
            connection.executemany(
                """
                INSERT INTO inbound_transfer_acks(
                    tenant_id, envelope_id, transfer_id, source_warden, target_warden,
                    sequence, config_epoch, transfer_digest, contiguous_watermark,
                    key_id, ack_payload, signature, accepted_at_ns, expires_at_ns
                ) VALUES (
                    'tenant', 'envelope', ?, 'source', 'target', ?, 1, ?, 65,
                    'seed-key', X'7B7D', X'01', 2, NULL
                )
                """,
                (
                    (
                        f"transfer-{sequence:03d}",
                        sequence,
                        f"digest-{sequence:03d}",
                    )
                    for sequence in range(1, 66)
                ),
            )
            connection.execute(
                """
                UPDATE warden_state
                SET free_pool = ?, transferred_in = ?, revision = revision + 1,
                    updated_at_ns = 2
                WHERE tenant_id = 'tenant' AND envelope_id = 'envelope'
                """,
                (pack((65,)), pack((65,))),
            )

        source_identity = _identity("source")
        checkpoint = source.create_transfer_checkpoint(
            identity=source_identity,
            target_warden="target",
        )
        assert (
            target.ingest_transfer_checkpoint(identity=source_identity, checkpoint=checkpoint)
            == checkpoint
        )
        with source_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM outgoing_transfers"
                ).fetchone()[0]
                == 1
            )
        with target_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM inbound_transfer_acks"
                ).fetchone()[0]
                == 1
            )

        assert (
            source.create_transfer_checkpoint(
                identity=source_identity,
                target_warden="target",
                through_sequence=65,
            )
            == checkpoint
        )
        assert (
            target.ingest_transfer_checkpoint(identity=source_identity, checkpoint=checkpoint)
            == checkpoint
        )
        with source_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM outgoing_transfers"
                ).fetchone()[0]
                == 0
            )
        with target_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM inbound_transfer_acks"
                ).fetchone()[0]
                == 0
            )
    finally:
        source_store.close()
        target_store.close()


def test_draining_target_accepts_and_compacts_already_debited_transfer(tmp_path: Path) -> None:
    clock = ManualClock(1_000_000, 5)
    registry = PublicKeyRegistry()
    source_store, source = _service(tmp_path / "source.db", "source", (100,), clock, registry)
    target_store, target = _service(tmp_path / "target.db", "target", (0,), clock, registry)
    try:
        digest = source.register_policy(_policy())
        target.register_policy(_policy())
        source_identity = _identity("source")
        target_identity = _identity("target")
        voucher = source.prepare_transfer(
            request_id="prepared-before-drain",
            identity=source_identity,
            tenant_id="tenant",
            envelope_id="envelope",
            target_warden="target",
            amount=(5,),
            policy_digest=digest,
        )
        target.set_runtime_mode(
            request_id="target-drain",
            identity=_identity("operator", "lets.admin"),
            mode=RuntimeMode.DRAINING,
            reason="cluster upgrade",
        )

        acknowledgement = target.accept_transfer(identity=target_identity, voucher=voucher)
        source.finalize_transfer(identity=source_identity, acknowledgement=acknowledgement)
        checkpoint = source.create_transfer_checkpoint(
            identity=source_identity,
            target_warden="target",
        )
        target.ingest_transfer_checkpoint(identity=source_identity, checkpoint=checkpoint)

        assert target.invariant_snapshot(identity=target_identity).free_pool == (5,)
        with source_store.read() as transaction:
            assert transaction.scalar("SELECT COUNT(*) FROM outgoing_transfers") == 0
        with target_store.read() as transaction:
            assert transaction.scalar("SELECT COUNT(*) FROM inbound_transfer_acks") == 0
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


def test_audit_verification_streams_large_payload_history_without_fetchall(
    warden: tuple[SQLiteStorage, WardenService, ManualClock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, service, clock = warden
    with store.write() as transaction:
        for sequence in range(256):
            service._append_audit(
                transaction.connection,
                tenant_id="tenant",
                envelope_id="envelope",
                event_type="test.large-audit-payload",
                entity_type="test",
                entity_id=f"row-{sequence}",
                actor_id="test-suite",
                details={"payload": "x" * 8192},
                now_ns=clock.now_ns() + sequence,
            )

    class StreamingOnlyCursor:
        def __init__(self, delegate: sqlite3.Cursor) -> None:
            self._delegate = delegate

        def __iter__(self) -> Iterator[sqlite3.Row]:
            return iter(self._delegate)

        def fetchall(self) -> None:
            raise AssertionError("audit verification must not materialize the full history")

        def __getattr__(self, name: str) -> object:
            return getattr(self._delegate, name)

    class StreamingConnection:
        def __init__(self, delegate: sqlite3.Connection) -> None:
            self._delegate = delegate

        def execute(self, sql: str, parameters: object = ()) -> object:
            cursor = self._delegate.execute(sql, parameters)
            if "SELECT * FROM audit_log" in sql and "ORDER BY sequence" in sql:
                return StreamingOnlyCursor(cursor)
            return cursor

        def __getattr__(self, name: str) -> object:
            return getattr(self._delegate, name)

    monkeypatch.setattr(
        service,
        "_connection",
        lambda transaction: StreamingConnection(transaction.connection),
    )
    assert service.verify_audit(identity=_identity("admin", "lets.audit.verify"))


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
