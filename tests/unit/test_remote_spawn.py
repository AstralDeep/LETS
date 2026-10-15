"""Tests for cross-warden spawn in service.py: a parent lease on one warden funds a
child lease on another through the lease-kind transfer voucher, conservation holds on
both ledgers, and close waits for every descendant, local or remote, to terminate.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ConflictError, PolicyError, SignatureError, ValidationError
from lets.models import (
    CHILD_OUTCOME_FENCED,
    CHILD_OUTCOME_ISSUED,
    IdentityContext,
    LeaseStatus,
    TransferAck,
    TransferVoucher,
)
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage
from lets.vector import add


def _policy() -> PolicySpec:
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
        transfer_gap_window=4,
    )


def _identity(subject: str, *scopes: str) -> IdentityContext:
    return IdentityContext(subject, "tenant", frozenset(scopes))


SUBJECT = _identity("agent", "lets.lease.issue", "lets.lease.manage", "lets.transfer")
SOURCE_PEER = _identity("source", "lets.peer", "lets.transfer")
TARGET_PEER = _identity("target", "lets.peer", "lets.transfer")
ADMIN = _identity("operator", "lets.admin")


def _service(
    path: Path,
    warden_id: str,
    share: tuple[int, ...],
    clock: ManualClock,
    registry: PublicKeyRegistry,
    *,
    peers: set[str],
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
    service = WardenService(
        store,
        signer=signer,
        clock=clock,
        trust_registry=registry,
        allowed_peer_wardens=peers,
    )
    service.register_policy(_policy())
    return store, service


class Pair:
    def __init__(self, tmp_path: Path) -> None:
        self.clock = ManualClock(1_000_000, 5)
        self.registry = PublicKeyRegistry()
        self.source_store, self.source = _service(
            tmp_path / "source.db", "source", (60,), self.clock, self.registry, peers={"target"}
        )
        self.target_store, self.target = _service(
            tmp_path / "target.db", "target", (40,), self.clock, self.registry, peers={"source"}
        )
        self.source.bind_remote_lease_resolver(self.resolve)

    def resolve(self, warden_id: str, lease_id: str) -> Mapping[str, Any] | None:
        if warden_id != "target":
            return None
        return self.target.peer_lease_status(identity=SOURCE_PEER, lease_id=lease_id).to_dict()

    def close(self) -> None:
        self.source_store.close()
        self.target_store.close()

    def root(self, allocation: int = 10, ttl_ns: int = 5_000) -> str:
        return self.source.issue_root(
            request_id=f"root-{allocation}-{ttl_ns}",
            identity=SUBJECT,
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent",
            allocation=(allocation,),
            capabilities={"worker.act"},
            policy_digest=_policy().digest,
            ttl_ns=ttl_ns,
        ).lease_id

    def spawn_remote(
        self, parent_id: str, allocation: int = 4, **overrides: Any
    ) -> TransferVoucher:
        arguments: dict[str, Any] = {
            "request_id": f"remote-{parent_id}-{allocation}",
            "identity": SUBJECT,
            "parent_id": parent_id,
            "target_warden": "target",
            "subject_id": "agent",
            "allocation": (allocation,),
            "capabilities": {"worker.act"},
            "ttl_ns": 2_000,
        }
        arguments.update(overrides)
        return self.source.spawn_remote(**arguments)

    def deliver(self, voucher: TransferVoucher) -> TransferAck:
        ack = self.target.accept_transfer(identity=SOURCE_PEER, voucher=voucher)
        self.source.finalize_transfer(identity=TARGET_PEER, acknowledgement=ack)
        return ack

    def conserved(self) -> tuple[int, ...]:
        source = self.source.invariant_snapshot(identity=ADMIN)
        target = self.target.invariant_snapshot(identity=ADMIN)
        assert source.healthy and target.healthy
        spendable = add(add(source.free_pool, source.lease_residual), target.free_pool)
        spendable = add(spendable, target.lease_residual)
        consumed = add(source.consumed, target.consumed)
        in_flight = add(
            source.transferred_out,
            tuple(-value for value in target.transferred_in),
        )
        return add(add(spendable, consumed), in_flight)

    def remote_child_status(self, child_lease_id: str) -> str:
        with self.source_store.read() as transaction:
            row = transaction.connection.execute(
                "SELECT status FROM remote_children WHERE child_lease_id = ?",
                (child_lease_id,),
            ).fetchone()
        assert row is not None
        return str(row[0])


@pytest.fixture
def pair(tmp_path: Path) -> Iterator[Pair]:
    wardens = Pair(tmp_path)
    try:
        yield wardens
    finally:
        wardens.close()


def _audit_events(service: WardenService) -> list[str]:
    records = service.list_audit(identity=ADMIN, after_sequence=-1, limit=200)
    return [record.event_type for record in records]


def test_remote_spawn_funds_a_child_on_the_target_warden(pair: Pair) -> None:
    parent = pair.root()
    voucher = pair.spawn_remote(parent)
    assert voucher.is_lease
    assert voucher.amount == (4,)
    assert voucher.lease_request is not None
    child_id = voucher.lease_request["child_lease_id"]
    assert voucher.lease_request["ancestor_path"] == [parent]
    source_before = pair.source.invariant_snapshot(identity=ADMIN)
    assert source_before.lease_residual == (6,)
    assert source_before.transferred_out == (4,)
    assert pair.remote_child_status(child_id) == "PENDING"
    assert pair.conserved() == (100,)

    ack = pair.deliver(voucher)
    assert ack.child_outcome == CHILD_OUTCOME_ISSUED
    assert ack.child_lease_id == child_id
    assert pair.remote_child_status(child_id) == "ACTIVE"
    child = pair.target.snapshot(identity=SUBJECT, lease_id=child_id)
    assert child.grant.parent_id == parent
    assert child.grant.warden_id == "target"
    assert child.grant.ancestor_path == (parent,)
    assert child.residual == (4,)
    target_after = pair.target.invariant_snapshot(identity=ADMIN)
    assert target_after.free_pool == (40,)
    assert target_after.transferred_in == (4,)
    assert target_after.lease_residual == (4,)
    assert pair.conserved() == (100,)

    receipt = pair.target.authorize(
        request_id="child-act",
        identity=SUBJECT,
        lease_id=child_id,
        transition="act",
        audience="executor-t",
        nonce="remote-child-nonce-01",
    )
    assert receipt.cost == (2,)
    assert pair.target.snapshot(identity=SUBJECT, lease_id=child_id).residual == (2,)
    assert pair.conserved() == (100,)
    assert "lease.spawned-remote" in _audit_events(pair.source)
    assert "lease.remote-child-acknowledged" in _audit_events(pair.source)
    assert "lease.remote-child-issued" in _audit_events(pair.target)


def test_parent_close_waits_for_the_remote_child_then_succeeds(pair: Pair) -> None:
    parent = pair.root()
    voucher = pair.spawn_remote(parent)
    child_id = voucher.lease_request["child_lease_id"]  # type: ignore[index]
    with pytest.raises(PolicyError, match="remote descendant"):
        pair.source.close(request_id="close-pending", identity=SUBJECT, lease_id=parent)
    pair.deliver(voucher)
    with pytest.raises(PolicyError, match="remote descendant"):
        pair.source.close(request_id="close-live", identity=SUBJECT, lease_id=parent)
    closed_child = pair.target.close(request_id="close-child", identity=SUBJECT, lease_id=child_id)
    assert closed_child.status is LeaseStatus.CLOSED
    assert pair.target.invariant_snapshot(identity=ADMIN).free_pool == (44,)
    closed = pair.source.close(request_id="close-parent", identity=SUBJECT, lease_id=parent)
    assert closed.status is LeaseStatus.CLOSED
    assert pair.remote_child_status(child_id) == "TERMINATED"
    assert pair.source.invariant_snapshot(identity=ADMIN).free_pool == (56,)
    assert "lease.remote-child-terminated" in _audit_events(pair.source)
    assert pair.conserved() == (100,)


def test_parent_close_fails_closed_when_the_remote_child_cannot_be_observed(pair: Pair) -> None:
    parent = pair.root()
    voucher = pair.spawn_remote(parent)
    child_id = voucher.lease_request["child_lease_id"]  # type: ignore[index]
    pair.deliver(voucher)
    pair.target.close(request_id="close-child", identity=SUBJECT, lease_id=child_id)

    def unreachable(warden_id: str, lease_id: str) -> Mapping[str, Any] | None:
        raise ConnectionError("partition")

    pair.source.bind_remote_lease_resolver(unreachable)
    with pytest.raises(PolicyError, match="not proven terminated"):
        pair.source.close(request_id="close-cut", identity=SUBJECT, lease_id=parent)
    pair.source.bind_remote_lease_resolver(None)
    with pytest.raises(PolicyError, match="not proven terminated"):
        pair.source.close(request_id="close-cut", identity=SUBJECT, lease_id=parent)
    assert pair.remote_child_status(child_id) == "ACTIVE"


def test_parent_close_uses_the_expiry_fallback_without_a_resolver(pair: Pair) -> None:
    parent = pair.root(ttl_ns=9_000)
    voucher = pair.spawn_remote(parent, ttl_ns=1_000)
    child_id = voucher.lease_request["child_lease_id"]  # type: ignore[index]
    pair.deliver(voucher)
    pair.source.bind_remote_lease_resolver(None)
    with pytest.raises(PolicyError, match="not proven terminated"):
        pair.source.close(request_id="close-early", identity=SUBJECT, lease_id=parent)
    pair.clock.advance(1_000 + 5 + 100 + 1)
    closed = pair.source.close(request_id="close-late", identity=SUBJECT, lease_id=parent)
    assert closed.status is LeaseStatus.CLOSED
    assert pair.remote_child_status(child_id) == "ACTIVE"
    assert pair.conserved() == (100,)


def test_duplicate_lease_voucher_returns_the_stored_ack_without_a_second_child(pair: Pair) -> None:
    parent = pair.root()
    voucher = pair.spawn_remote(parent)
    first = pair.target.accept_transfer(identity=SOURCE_PEER, voucher=voucher)
    second = pair.target.accept_transfer(identity=SOURCE_PEER, voucher=voucher)
    assert first == second
    target = pair.target.invariant_snapshot(identity=ADMIN)
    assert target.transferred_in == (4,)
    assert target.lease_residual == (4,)
    assert target.free_pool == (40,)
    pair.source.finalize_transfer(identity=TARGET_PEER, acknowledgement=first)
    pair.source.finalize_transfer(identity=TARGET_PEER, acknowledgement=second)
    assert pair.conserved() == (100,)


def test_revoked_branch_fences_the_child_and_credits_the_target_pool(pair: Pair) -> None:
    parent = pair.root()
    voucher = pair.spawn_remote(parent)
    child_id = voucher.lease_request["child_lease_id"]  # type: ignore[index]
    revocation = pair.source.revoke_branch(
        request_id="revoke-parent",
        identity=_identity("operator", "lets.branch.revoke"),
        lease_id=parent,
        reason="compromised",
    )
    pair.target.ingest_revocation(identity=SOURCE_PEER, revocation=revocation)
    ack = pair.deliver(voucher)
    assert ack.child_outcome == CHILD_OUTCOME_FENCED
    assert ack.child_lease_id == child_id
    assert pair.remote_child_status(child_id) == "FENCED"
    target = pair.target.invariant_snapshot(identity=ADMIN)
    assert target.free_pool == (44,)
    assert target.transferred_in == (4,)
    assert target.lease_residual == (0,)
    with pytest.raises(Exception, match="does not exist"):
        pair.target.snapshot(identity=SUBJECT, lease_id=child_id)
    assert "lease.remote-child-fenced" in _audit_events(pair.target)
    assert pair.conserved() == (100,)


def test_revocation_arriving_after_issue_fences_the_remote_child_and_grandchild(pair: Pair) -> None:
    parent = pair.root()
    voucher = pair.spawn_remote(parent)
    child_id = voucher.lease_request["child_lease_id"]  # type: ignore[index]
    pair.deliver(voucher)
    grandchild = pair.target.spawn(
        request_id="grandchild",
        identity=SUBJECT,
        parent_id=child_id,
        subject_id="agent",
        allocation=(2,),
        capabilities={"worker.act"},
        ttl_ns=1_000,
    )
    assert grandchild.ancestor_path == (parent, child_id)
    revocation = pair.source.revoke_branch(
        request_id="revoke-parent",
        identity=_identity("operator", "lets.branch.revoke"),
        lease_id=parent,
        reason="compromised",
    )
    pair.target.ingest_revocation(identity=SOURCE_PEER, revocation=revocation)
    assert pair.target.snapshot(identity=SUBJECT, lease_id=child_id).status is LeaseStatus.REVOKED
    assert (
        pair.target.snapshot(identity=SUBJECT, lease_id=grandchild.lease_id).status
        is LeaseStatus.REVOKED
    )
    with pytest.raises(PolicyError, match=r"REVOKED|revoked"):
        pair.target.authorize(
            request_id="revoked-act",
            identity=SUBJECT,
            lease_id=grandchild.lease_id,
            transition="act",
            audience="executor-t",
            nonce="revoked-child-nonce-01",
        )
    assert pair.conserved() == (100,)


def test_child_expired_in_flight_is_fenced_not_issued(pair: Pair) -> None:
    parent = pair.root()
    voucher = pair.spawn_remote(parent, ttl_ns=500)
    pair.clock.advance(600)
    ack = pair.deliver(voucher)
    assert ack.child_outcome == CHILD_OUTCOME_FENCED
    assert pair.target.invariant_snapshot(identity=ADMIN).free_pool == (44,)
    assert pair.conserved() == (100,)


def test_remote_spawn_is_idempotent_and_debits_once(pair: Pair) -> None:
    parent = pair.root()
    first = pair.spawn_remote(parent, request_id="same-request")
    second = pair.spawn_remote(parent, request_id="same-request")
    assert first == second
    source = pair.source.invariant_snapshot(identity=ADMIN)
    assert source.lease_residual == (6,)
    assert source.transferred_out == (4,)
    with pytest.raises(ConflictError):
        pair.spawn_remote(parent, request_id="same-request", allocation=3)


@pytest.mark.parametrize(
    ("overrides", "error", "match"),
    [
        ({"allocation": 11}, PolicyError, "does not cover"),
        ({"capabilities": {"worker.other"}}, PolicyError, "not attenuated"),
        ({"target_warden": "source"}, ValidationError, "must differ"),
        ({"target_warden": "stranger"}, PolicyError, "not authorized"),
        ({"expected_sequence": 7}, ConflictError, "expected 7"),
        ({"allocation": 0}, ValidationError, "non-zero"),
        ({"ttl_ns": 20_000}, PolicyError, "exceeds the registered policy maximum"),
    ],
)
def test_remote_spawn_denials(
    pair: Pair, overrides: dict[str, Any], error: type[Exception], match: str
) -> None:
    parent = pair.root()
    with pytest.raises(error, match=match):
        pair.spawn_remote(parent, **overrides)
    source = pair.source.invariant_snapshot(identity=ADMIN)
    assert source.lease_residual == (10,)
    assert source.transferred_out == (0,)


def test_tampered_lease_request_is_rejected_by_the_target(pair: Pair) -> None:
    parent = pair.root()
    voucher = pair.spawn_remote(parent)
    tampered = dict(voucher.to_dict())
    request = dict(tampered["lease_request"])
    request["capabilities"] = ["worker.act", "worker.other"]
    tampered["lease_request"] = request
    with pytest.raises(SignatureError):
        pair.target.accept_transfer(identity=SOURCE_PEER, voucher=tampered)
    inflated = dict(voucher.to_dict())
    inflated["amount"] = [40]
    with pytest.raises(SignatureError):
        pair.target.accept_transfer(identity=SOURCE_PEER, voucher=inflated)
    assert pair.target.invariant_snapshot(identity=ADMIN).transferred_in == (0,)


def test_acknowledgement_must_report_the_expected_child(pair: Pair) -> None:
    parent = pair.root()
    voucher = pair.spawn_remote(parent)
    ack = pair.target.accept_transfer(identity=SOURCE_PEER, voucher=voucher)
    forged = replace(ack, child_lease_id="lease-other", child_outcome=CHILD_OUTCOME_ISSUED)
    with pytest.raises(SignatureError):
        pair.source.finalize_transfer(identity=TARGET_PEER, acknowledgement=forged)
    silent = ack.to_dict()
    silent.pop("child_lease_id")
    silent.pop("child_outcome")
    with pytest.raises(SignatureError):
        pair.source.finalize_transfer(identity=TARGET_PEER, acknowledgement=silent)
    pair.source.finalize_transfer(identity=TARGET_PEER, acknowledgement=ack)
    assert pair.remote_child_status(voucher.lease_request["child_lease_id"]) == "ACTIVE"  # type: ignore[index]


def test_lease_vouchers_share_the_transfer_stream_with_pool_vouchers(pair: Pair) -> None:
    parent = pair.root()
    pool_one = pair.source.prepare_transfer(
        request_id="pool-1",
        identity=SUBJECT,
        tenant_id="tenant",
        envelope_id="envelope",
        target_warden="target",
        amount=(5,),
    )
    lease = pair.spawn_remote(parent)
    pool_two = pair.source.prepare_transfer(
        request_id="pool-2",
        identity=SUBJECT,
        tenant_id="tenant",
        envelope_id="envelope",
        target_warden="target",
        amount=(5,),
    )
    assert (pool_one.sequence, lease.sequence, pool_two.sequence) == (1, 2, 3)
    assert not pool_one.is_lease and lease.is_lease
    for voucher in (pool_two, lease, pool_one):
        pair.deliver(voucher)
    target = pair.target.invariant_snapshot(identity=ADMIN)
    assert target.free_pool == (50,)
    assert target.lease_residual == (4,)
    assert target.transferred_in == (14,)
    assert pair.conserved() == (100,)


def test_close_waits_for_live_local_children(pair: Pair) -> None:
    parent = pair.root()
    child = pair.source.spawn(
        request_id="local-child",
        identity=SUBJECT,
        parent_id=parent,
        subject_id="agent",
        allocation=(3,),
        capabilities={"worker.act"},
        ttl_ns=1_000,
    )
    with pytest.raises(PolicyError, match="live local descendant"):
        pair.source.close(request_id="close-parent", identity=SUBJECT, lease_id=parent)
    pair.source.close(request_id="close-child", identity=SUBJECT, lease_id=child.lease_id)
    closed = pair.source.close(request_id="close-parent", identity=SUBJECT, lease_id=parent)
    assert closed.status is LeaseStatus.CLOSED
    assert pair.source.invariant_snapshot(identity=ADMIN).free_pool == (60,)


def test_peer_lease_status_requires_a_peer_identity(pair: Pair) -> None:
    parent = pair.root()
    voucher = pair.spawn_remote(parent)
    pair.deliver(voucher)
    child_id = voucher.lease_request["child_lease_id"]  # type: ignore[index]
    snapshot = pair.target.peer_lease_status(identity=SOURCE_PEER, lease_id=child_id)
    assert snapshot.grant.lease_id == child_id
    with pytest.raises(PolicyError, match="peer identity"):
        pair.target.peer_lease_status(identity=_identity("stranger"), lease_id=child_id)


def test_resolver_binding_rejects_non_callables(pair: Pair) -> None:
    with pytest.raises(ValidationError):
        pair.source.bind_remote_lease_resolver("not-callable")  # type: ignore[arg-type]


def test_pool_vouchers_keep_their_wire_shape(pair: Pair) -> None:
    voucher = pair.source.prepare_transfer(
        request_id="pool",
        identity=SUBJECT,
        tenant_id="tenant",
        envelope_id="envelope",
        target_warden="target",
        amount=(5,),
    )
    payload = voucher.to_dict()
    assert "kind" not in payload and "lease_request" not in payload
    assert TransferVoucher.from_dict(payload) == voucher
    ack = pair.target.accept_transfer(identity=SOURCE_PEER, voucher=voucher)
    assert "child_lease_id" not in ack.to_dict()
    assert TransferAck.from_dict(ack.to_dict()) == ack


RemoteResolver = Callable[[str, str], Mapping[str, Any] | None]
