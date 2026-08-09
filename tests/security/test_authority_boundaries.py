from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from lets.canonical import b64url_encode, canonical_json
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import (
    ClockUncertainError,
    ConflictError,
    PolicyError,
    SignatureError,
    ValidationError,
)
from lets.models import BranchRevocation, IdentityContext
from lets.policy import (
    EvidenceRule,
    MachineSpec,
    PolicySpec,
    ResourceDimension,
    TransitionSpec,
    evaluate_evidence,
)
from lets.service import WardenService
from lets.storage import SQLiteStorage


def _policy(
    *,
    version: str = "v1",
    cost: int = 1,
    evidence: EvidenceRule | None = None,
) -> PolicySpec:
    return PolicySpec(
        policy_id="security-policy",
        policy_version=version,
        dimensions=(ResourceDimension("operations", "count"),),
        machine=MachineSpec(
            machine_id=f"worker-{version}",
            initial_state="ready",
            transitions=(
                TransitionSpec(
                    "act",
                    "ready",
                    "ready",
                    (cost,),
                    "worker.act",
                    evidence,
                ),
            ),
        ),
        max_lease_ttl_ns=10_000,
        receipt_ttl_ns=100,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=8,
    )


def _identity(subject: str, *scopes: str, tenant: str = "tenant") -> IdentityContext:
    return IdentityContext(subject, tenant, frozenset(scopes))


def _service(path: Path) -> tuple[SQLiteStorage, WardenService, ManualClock]:
    clock = ManualClock(1_000_000)
    signer = Ed25519Signer.generate("warden-a")
    store = SQLiteStorage.initialize(
        path,
        "warden-a",
        (100,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        receipt_ttl_ns=100,
        transfer_gap_window=8,
    )
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    return store, WardenService(store, signer=signer, clock=clock, trust_registry=registry), clock


def test_unscoped_subject_cannot_self_issue_root_or_debit_pool(tmp_path: Path) -> None:
    store, service, _ = _service(tmp_path / "warden.sqlite3")
    try:
        policy = _policy()
        service.register_policy(policy)
        with pytest.raises(PolicyError, match="issuance scope"):
            service.issue_root(
                request_id="unauthorized-root",
                identity=_identity("agent"),
                tenant_id="tenant",
                envelope_id="envelope",
                subject_id="agent",
                allocation=(100,),
                capabilities={"worker.act"},
                policy_digest=policy.digest,
                ttl_ns=1_000,
            )
        with store.read() as transaction:
            assert transaction.get_warden_state()["free_pool"] == (100,)
            assert transaction.scalar("SELECT COUNT(*) FROM leases") == 0
    finally:
        store.close()


def test_authorized_issuer_can_name_a_distinct_subject_but_not_cross_tenant(
    tmp_path: Path,
) -> None:
    store, service, _ = _service(tmp_path / "warden.sqlite3")
    try:
        policy = _policy()
        service.register_policy(policy)
        grant = service.issue_root(
            request_id="scheduler-root",
            identity=_identity("scheduler", "lets.lease.issue"),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent",
            allocation=(10,),
            capabilities={"worker.act"},
            policy_digest=policy.digest,
            ttl_ns=1_000,
        )
        assert grant.subject_id == "agent"
        with pytest.raises(PolicyError, match="tenant"):
            service.issue_root(
                request_id="cross-tenant-root",
                identity=_identity("scheduler", "lets.lease.issue", tenant="other"),
                tenant_id="tenant",
                envelope_id="envelope",
                subject_id="agent",
                allocation=(1,),
                capabilities={"worker.act"},
                policy_digest=policy.digest,
                ttl_ns=1_000,
            )
    finally:
        store.close()


def test_spawn_cannot_substitute_even_a_same_machine_policy_alias(tmp_path: Path) -> None:
    store, service, _ = _service(tmp_path / "warden.sqlite3")
    try:
        expensive = _policy(version="expensive", cost=10)
        cheap = replace(
            expensive,
            policy_version="same-machine-more-permissive",
            max_lease_ttl_ns=100_000,
        )
        service.register_policy(expensive)
        service.register_policy(cheap)
        parent = service.issue_root(
            request_id="parent-root",
            identity=_identity("scheduler", "lets.lease.issue"),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="parent",
            allocation=(20,),
            capabilities={"worker.act"},
            policy_digest=expensive.digest,
            ttl_ns=1_000,
        )
        assert cheap.machine.digest == expensive.machine.digest
        with pytest.raises(PolicyError, match="not inherited exactly"):
            service.spawn(
                request_id="machine-substitution",
                identity=_identity("parent"),
                parent_id=parent.lease_id,
                subject_id="child",
                allocation=(10,),
                capabilities={"worker.act"},
                ttl_ns=500,
                policy_digest=cheap.digest,
            )
        snapshot = service.snapshot(identity=_identity("parent"), lease_id=parent.lease_id)
        assert snapshot.residual == (20,)
        assert snapshot.sequence == 0
    finally:
        store.close()


def test_root_capabilities_must_be_declared_by_the_bound_machine(tmp_path: Path) -> None:
    store, service, _ = _service(tmp_path / "warden.sqlite3")
    try:
        policy = _policy()
        service.register_policy(policy)
        with pytest.raises(PolicyError, match="undeclared"):
            service.issue_root(
                request_id="undeclared-capability",
                identity=_identity("issuer", "lets.lease.issue"),
                tenant_id="tenant",
                envelope_id="envelope",
                subject_id="agent",
                allocation=(10,),
                capabilities={"worker.act", "adapter.superuser"},
                policy_digest=policy.digest,
                ttl_ns=1_000,
            )
        with store.read() as transaction:
            assert transaction.get_warden_state()["free_pool"] == (100,)
            assert transaction.scalar("SELECT COUNT(*) FROM leases") == 0
    finally:
        store.close()


def test_evidence_equality_does_not_alias_json_boolean_and_integer(tmp_path: Path) -> None:
    store, service, _ = _service(tmp_path / "warden.sqlite3")
    try:
        policy = _policy(evidence=EvidenceRule("eq", path="evidence.level", value=1))
        service.register_policy(policy)
        grant = service.issue_root(
            request_id="evidence-root",
            identity=_identity("issuer", "lets.lease.issue"),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent",
            allocation=(2,),
            capabilities={"worker.act"},
            policy_digest=policy.digest,
            ttl_ns=1_000,
        )
        with pytest.raises(PolicyError, match="evidence predicate"):
            service.authorize(
                request_id="bool-is-not-one",
                identity=_identity("agent"),
                lease_id=grant.lease_id,
                transition="act",
                audience="executor",
                nonce="nonce-bool-alias-0001",
                evidence={"level": True},
            )
        receipt = service.authorize(
            request_id="integer-one",
            identity=_identity("agent"),
            lease_id=grant.lease_id,
            transition="act",
            audience="executor",
            nonce="nonce-integer-one-001",
            evidence={"level": 1},
        )
        assert receipt.resulting_sequence == 1
    finally:
        store.close()


def test_evidence_negation_cannot_mint_receipts_from_invalid_facts(tmp_path: Path) -> None:
    store, service, _ = _service(tmp_path / "warden.sqlite3")
    try:
        policy = _policy(
            evidence=EvidenceRule(
                "not",
                rule=EvidenceRule("lt", path="evidence.score", value=2),
            )
        )
        service.register_policy(policy)
        grant = service.issue_root(
            request_id="negation-root",
            identity=_identity("issuer", "lets.lease.issue"),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent",
            allocation=(2,),
            capabilities={"worker.act"},
            policy_digest=policy.digest,
            ttl_ns=1_000,
        )

        invalid_facts = (
            ("missing-score", "nonce-missing-score-001", {}),
            ("boolean-score", "nonce-boolean-score-001", {"score": True}),
            ("malformed-score", "nonce-malformed-score-1", {"score": "malformed"}),
        )
        for request_id, nonce, evidence in invalid_facts:
            with pytest.raises(PolicyError, match="evidence predicate"):
                service.authorize(
                    request_id=request_id,
                    identity=_identity("agent"),
                    lease_id=grant.lease_id,
                    transition="act",
                    audience="executor",
                    nonce=nonce,
                    evidence=evidence,
                )

        with pytest.raises(PolicyError, match="evidence predicate"):
            service.authorize(
                request_id="valid-not-deny",
                identity=_identity("agent"),
                lease_id=grant.lease_id,
                transition="act",
                audience="executor",
                nonce="nonce-valid-not-deny-01",
                evidence={"score": 1},
            )

        unchanged = service.snapshot(identity=_identity("agent"), lease_id=grant.lease_id)
        invariant = service.invariant_snapshot(identity=_identity("agent"))
        assert unchanged.residual == (2,)
        assert unchanged.sequence == 0
        assert invariant.consumed == (0,)
        with store.read() as transaction:
            assert (
                transaction.connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 0
            )

        receipt = service.authorize(
            request_id="valid-not-allow",
            identity=_identity("agent"),
            lease_id=grant.lease_id,
            transition="act",
            audience="executor",
            nonce="nonce-valid-not-allow-1",
            evidence={"score": 5},
        )
        assert receipt.resulting_sequence == 1
        assert service.snapshot(identity=_identity("agent"), lease_id=grant.lease_id).residual == (
            1,
        )
        assert service.invariant_snapshot(identity=_identity("agent")).consumed == (1,)
    finally:
        store.close()


def test_concurrent_spawns_cannot_overdraw_parent(tmp_path: Path) -> None:
    store, service, _ = _service(tmp_path / "warden.sqlite3")
    try:
        policy = _policy()
        service.register_policy(policy)
        parent = service.issue_root(
            request_id="concurrent-parent",
            identity=_identity("issuer", "lets.lease.issue"),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="parent",
            allocation=(10,),
            capabilities={"worker.act"},
            policy_digest=policy.digest,
            ttl_ns=1_000,
        )

        def spawn(index: int) -> bool:
            try:
                service.spawn(
                    request_id=f"spawn-{index}",
                    identity=_identity("parent"),
                    parent_id=parent.lease_id,
                    subject_id=f"child-{index}",
                    allocation=(3,),
                    capabilities={"worker.act"},
                    ttl_ns=500,
                )
            except PolicyError:
                return False
            return True

        with ThreadPoolExecutor(max_workers=8) as executor:
            accepted = list(executor.map(spawn, range(16)))
        assert sum(accepted) == 3
        snapshot = service.snapshot(identity=_identity("parent"), lease_id=parent.lease_id)
        assert snapshot.residual == (1,)
        assert snapshot.sequence == 3
        assert service.invariant_snapshot(identity=_identity("admin", "lets.admin")).healthy
    finally:
        store.close()


def test_request_id_collision_never_reuses_authority_for_different_arguments(
    tmp_path: Path,
) -> None:
    store, service, _ = _service(tmp_path / "warden.sqlite3")
    try:
        policy = _policy()
        service.register_policy(policy)
        issuer = _identity("issuer", "lets.lease.issue")
        service.issue_root(
            request_id="collision",
            identity=issuer,
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent-a",
            allocation=(5,),
            capabilities={"worker.act"},
            policy_digest=policy.digest,
            ttl_ns=1_000,
        )
        with pytest.raises(ConflictError, match="incompatible arguments"):
            service.issue_root(
                request_id="collision",
                identity=issuer,
                tenant_id="tenant",
                envelope_id="envelope",
                subject_id="agent-b",
                allocation=(5,),
                capabilities={"worker.act"},
                policy_digest=policy.digest,
                ttl_ns=1_000,
            )
        with store.read() as transaction:
            assert transaction.scalar("SELECT COUNT(*) FROM leases") == 1
    finally:
        store.close()


def test_zero_allocations_and_zero_cost_transitions_cannot_create_metadata(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValidationError, match="non-zero"):
        TransitionSpec("free", "ready", "ready", (0,), "worker.act")

    store, service, _ = _service(tmp_path / "warden.sqlite3")
    try:
        policy = _policy()
        service.register_policy(policy)
        issuer = _identity("issuer", "lets.lease.issue")
        with pytest.raises(ValidationError, match="non-zero"):
            service.issue_root(
                request_id="zero-root",
                identity=issuer,
                tenant_id="tenant",
                envelope_id="envelope",
                subject_id="parent",
                allocation=(0,),
                capabilities={"worker.act"},
                policy_digest=policy.digest,
                ttl_ns=1_000,
            )
        parent = service.issue_root(
            request_id="nonzero-root",
            identity=issuer,
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="parent",
            allocation=(10,),
            capabilities={"worker.act"},
            policy_digest=policy.digest,
            ttl_ns=1_000,
        )
        with pytest.raises(ValidationError, match="non-zero"):
            service.spawn(
                request_id="zero-child",
                identity=_identity("parent"),
                parent_id=parent.lease_id,
                subject_id="child",
                allocation=(0,),
                capabilities={"worker.act"},
                ttl_ns=500,
            )
        with store.read() as transaction:
            assert transaction.scalar("SELECT COUNT(*) FROM leases") == 1
            assert transaction.scalar("SELECT COUNT(*) FROM idempotency") == 1
    finally:
        store.close()


def test_root_subject_cannot_roll_its_issuer_ttl_forever(tmp_path: Path) -> None:
    store, service, _ = _service(tmp_path / "warden.sqlite3")
    try:
        policy = _policy()
        service.register_policy(policy)
        root = service.issue_root(
            request_id="managed-root",
            identity=_identity("issuer", "lets.lease.issue"),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent",
            allocation=(10,),
            capabilities={"worker.act"},
            policy_digest=policy.digest,
            ttl_ns=1_000,
        )
        with pytest.raises(PolicyError, match="management"):
            service.renew(
                request_id="self-renew",
                identity=_identity("agent"),
                lease_id=root.lease_id,
                ttl_ns=1_000,
            )
        renewed = service.renew(
            request_id="managed-renew",
            identity=_identity("manager", "lets.lease.manage"),
            lease_id=root.lease_id,
            ttl_ns=1_000,
        )
        assert renewed.sequence == 1
    finally:
        store.close()


def test_request_id_is_unique_across_operations_and_lease_scopes(tmp_path: Path) -> None:
    store, service, _ = _service(tmp_path / "warden.sqlite3")
    try:
        policy = _policy()
        service.register_policy(policy)
        root = service.issue_root(
            request_id="global-operation-id",
            identity=_identity("issuer", "lets.lease.issue"),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="parent",
            allocation=(10,),
            capabilities={"worker.act"},
            policy_digest=policy.digest,
            ttl_ns=1_000,
        )
        with pytest.raises(ConflictError, match="incompatible arguments"):
            service.spawn(
                request_id="global-operation-id",
                identity=_identity("parent"),
                parent_id=root.lease_id,
                subject_id="child",
                allocation=(1,),
                capabilities={"worker.act"},
                ttl_ns=500,
            )
        assert service.snapshot(identity=_identity("parent"), lease_id=root.lease_id).residual == (
            10,
        )
    finally:
        store.close()


def test_durable_clock_floor_rejects_restart_after_wall_clock_rollback(
    tmp_path: Path,
) -> None:
    path = tmp_path / "warden.sqlite3"
    clock = ManualClock(1_000_000)
    signer = Ed25519Signer.generate("warden-a")
    store = SQLiteStorage.initialize(
        path,
        "warden-a",
        (100,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        receipt_ttl_ns=100,
        transfer_gap_window=8,
    )
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    service = WardenService(store, signer=signer, clock=clock, trust_registry=registry)
    policy = _policy()
    service.register_policy(policy)
    root = service.issue_root(
        request_id="clock-root",
        identity=_identity("issuer", "lets.lease.issue"),
        tenant_id="tenant",
        envelope_id="envelope",
        subject_id="agent",
        allocation=(10,),
        capabilities={"worker.act"},
        policy_digest=policy.digest,
        ttl_ns=1_000,
    )
    clock.advance(100)
    service.authorize(
        request_id="clock-forward",
        identity=_identity("agent"),
        lease_id=root.lease_id,
        transition="act",
        audience="executor",
        nonce="clock-forward-nonce-001",
    )
    store.close()

    rolled_back = ManualClock(1_000_000)
    reopened = SQLiteStorage(
        path,
        "warden-a",
        (100,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        receipt_ttl_ns=100,
        transfer_gap_window=8,
    )
    recovered = WardenService(reopened, signer=signer, clock=rolled_back)
    try:
        assert not recovered.ready()
        with pytest.raises(ClockUncertainError, match="durable"):
            recovered.spawn(
                request_id="rollback-spawn",
                identity=_identity("agent"),
                parent_id=root.lease_id,
                subject_id="child",
                allocation=(1,),
                capabilities={"worker.act"},
                ttl_ns=500,
            )
    finally:
        reopened.close()


def test_evidence_relational_types_and_expression_size_fail_closed() -> None:
    assert not evaluate_evidence(
        EvidenceRule("lt", path="score", value=2),
        {"score": True},
        now_ns=1,
        subject_id="agent",
        audience="executor",
    )

    nested: dict[str, object] = {"op": "exists", "path": "ok"}
    for _ in range(32):
        nested = {"op": "not", "rule": nested}
    with pytest.raises(ValidationError, match="depth"):
        EvidenceRule.from_dict(nested)

    too_many = {
        "op": "all",
        "rules": [{"op": "exists", "path": f"item{i}"} for i in range(256)],
    }
    with pytest.raises(ValidationError, match="node count"):
        EvidenceRule.from_dict(too_many)


def test_manifest_bounded_service_stops_signing_at_key_expiry(tmp_path: Path) -> None:
    clock = ManualClock(100)
    signer = Ed25519Signer.generate("warden-a")
    store = SQLiteStorage.initialize(
        tmp_path / "key-validity.sqlite3",
        signer.warden_id,
        (100,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        receipt_ttl_ns=100,
        transfer_gap_window=8,
    )
    try:
        service = WardenService(
            store,
            signer=signer,
            clock=clock,
            signing_key_validity=(90, 110),
        )
        service.register_policy(_policy())
        assert service.ready()

        clock.current_ns = 110
        assert not service.ready()
        with pytest.raises(SignatureError, match="expired"):
            service.register_policy(_policy(version="v2"))
        with store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM policies WHERE policy_version = 'v2'"
                ).fetchone()[0]
                == 0
            )
    finally:
        store.close()


def test_peer_cannot_revoke_a_branch_owned_by_another_warden(tmp_path: Path) -> None:
    clock = ManualClock(1_000_000)
    owner = Ed25519Signer.generate("warden-owner")
    attacker = Ed25519Signer.generate("warden-attacker")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(owner)
    registry.register_signer(attacker)
    store = SQLiteStorage.initialize(
        tmp_path / "revocation-owner.sqlite3",
        owner.warden_id,
        (100,),
        signing_key_id=owner.key_id,
        signing_public_key=owner.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        receipt_ttl_ns=100,
        transfer_gap_window=8,
    )
    try:
        service = WardenService(store, signer=owner, clock=clock, trust_registry=registry)
        policy = _policy()
        service.register_policy(policy)
        root = service.issue_root(
            request_id="owner-root",
            identity=_identity("issuer", "lets.lease.issue"),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent",
            allocation=(10,),
            capabilities={"worker.act"},
            policy_digest=policy.digest,
            ttl_ns=1_000,
        )
        unsigned = BranchRevocation(
            tenant_id="tenant",
            envelope_id="envelope",
            config_epoch=1,
            branch_lease_id=root.lease_id,
            lineage_id=root.lineage_id,
            epoch=1,
            issuer_warden=attacker.warden_id,
            issued_at_ns=clock.now_ns(),
            reason="cross-warden availability attack",
            key_id=attacker.key_id,
        )
        forged = replace(
            unsigned,
            signature=b64url_encode(attacker.sign(canonical_json(unsigned.unsigned_payload()))),
        )
        relay = _identity(attacker.warden_id, "lets.peer")
        with pytest.raises(PolicyError, match="does not own"):
            service.ingest_revocation(identity=relay, revocation=forged)

        owner_record = service.revoke_branch(
            request_id="owner-revocation",
            identity=_identity("operator", "lets.admin"),
            lease_id=root.lease_id,
            reason="owner decision",
        )
        assert service.ingest_revocation(identity=relay, revocation=owner_record) == owner_record
    finally:
        store.close()
