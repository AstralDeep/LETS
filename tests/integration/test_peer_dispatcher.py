from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import lets.peer as peer_module
from lets.client import ProblemDetails, RemoteValidationError
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.models import IdentityContext
from lets.peer import PeerDispatcher
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage


def _identity(subject: str, *scopes: str) -> IdentityContext:
    return IdentityContext(subject, "tenant", frozenset(scopes))


def _policy(*, gap_window: int = 64) -> PolicySpec:
    return PolicySpec(
        policy_id="dispatcher-policy",
        policy_version="v1",
        dimensions=(ResourceDimension("operations", "count"),),
        machine=MachineSpec(
            machine_id="worker",
            initial_state="ready",
            transitions=(TransitionSpec("act", "ready", "ready", (1,), "worker.act"),),
        ),
        max_lease_ttl_ns=10_000,
        receipt_ttl_ns=100,
        max_clock_uncertainty_ns=5,
        transfer_gap_window=gap_window,
    )


class _ServiceTransport:
    def __init__(
        self, target: WardenService, source_warden: str, *, fail_once: bool = False
    ) -> None:
        self._target = target
        self._source_identity = _identity(source_warden, "lets.peer", "lets.transfer")
        self._fail_once = fail_once
        self.closed = False

    def accept_transfer(self, voucher: Mapping[str, Any]) -> Mapping[str, Any]:
        if self._fail_once:
            self._fail_once = False
            raise OSError("injected peer partition")
        return self._target.accept_transfer(
            identity=self._source_identity,
            voucher=voucher,
        ).to_dict()

    def ingest_revocation(self, revocation: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._target.ingest_revocation(
            identity=self._source_identity,
            revocation=revocation,
        ).to_dict()

    def ingest_transfer_checkpoint(self, checkpoint: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._target.ingest_transfer_checkpoint(
            identity=self._source_identity,
            checkpoint=checkpoint,
        )

    def close(self) -> None:
        self.closed = True


def _node(
    path: Path,
    *,
    warden_id: str,
    share: int,
    signer: Ed25519Signer,
    clock: ManualClock,
    registry: PublicKeyRegistry,
    peers: set[str],
    gap_window: int = 64,
) -> tuple[SQLiteStorage, WardenService]:
    store = SQLiteStorage.initialize(
        path,
        warden_id,
        (100,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        initial_local_share=(share,),
        receipt_ttl_ns=100,
        max_clock_uncertainty_ns=5,
        transfer_gap_window=gap_window,
    )
    service = WardenService(
        store,
        signer=signer,
        clock=clock,
        trust_registry=registry,
        allowed_peer_wardens=peers,
    )
    service.register_policy(_policy(gap_window=gap_window))
    return store, service


def test_durable_dispatch_retries_across_restart_and_delivers_all_record_kinds(
    tmp_path: Path,
) -> None:
    clock = ManualClock(1_000_000, 5)
    source_signer = Ed25519Signer.generate("source")
    target_signer = Ed25519Signer.generate("target")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(source_signer)
    registry.register_signer(target_signer)
    source_path = tmp_path / "source.db"
    source_store, source = _node(
        source_path,
        warden_id="source",
        share=100,
        signer=source_signer,
        clock=clock,
        registry=registry,
        peers={"target"},
    )
    target_store, target = _node(
        tmp_path / "target.db",
        warden_id="target",
        share=0,
        signer=target_signer,
        clock=clock,
        registry=registry,
        peers={"source"},
    )
    first_transport = _ServiceTransport(target, "source", fail_once=True)
    dispatcher = PeerDispatcher(
        source,
        source_store,
        source_signer,
        {"target": "memory://target"},
        client_factory=lambda _endpoint: first_transport,
        poll_interval_s=0.01,
        request_timeout_s=0.01,
    )
    try:
        digest = _policy().digest
        source.prepare_transfer(
            request_id="transfer-1",
            identity=_identity("source"),
            tenant_id="tenant",
            envelope_id="envelope",
            target_warden="target",
            amount=(5,),
            policy_digest=digest,
        )
        dispatcher.run_once()
        assert dispatcher.status()["failed_records"] == 1
        dispatcher.stop()
        source_store.close()

        source_store = SQLiteStorage(
            source_path,
            "source",
            (100,),
            signing_key_id=source_signer.key_id,
            signing_public_key=source_signer.public_key_bytes,
            tenant_id="tenant",
            envelope_id="envelope",
            initial_local_share=(100,),
            receipt_ttl_ns=100,
            max_clock_uncertainty_ns=5,
            transfer_gap_window=64,
        )
        source = WardenService(
            source_store,
            signer=source_signer,
            clock=clock,
            trust_registry=registry,
            allowed_peer_wardens={"target"},
        )
        with source_store.write() as transaction:
            transaction.connection.execute("UPDATE peer_delivery_state SET next_attempt_ns = 0")
        recovered_transport = _ServiceTransport(target, "source")
        dispatcher = PeerDispatcher(
            source,
            source_store,
            source_signer,
            {"target": "memory://target"},
            client_factory=lambda _endpoint: recovered_transport,
            poll_interval_s=0.01,
            request_timeout_s=0.01,
        )
        dispatcher.run_once()
        assert target.invariant_snapshot(identity=_identity("target")).free_pool == (5,)
        dispatcher.run_once()

        root = source.issue_root(
            request_id="root",
            identity=_identity("operator", "lets.lease.issue"),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="operator",
            allocation=(10,),
            capabilities={"worker.act"},
            policy_digest=digest,
            ttl_ns=1_000,
        )
        source.revoke_branch(
            request_id="revoke",
            identity=_identity("admin", "lets.admin"),
            lease_id=root.lease_id,
            reason="dispatcher test",
        )
        dispatcher.run_once()
        status = dispatcher.status()
        assert status["pending_records"] == 0
        assert status["delivered_records"] == 3
        with target_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT compacted_through FROM inbound_transfer_streams"
                ).fetchone()[0]
                == 1
            )
            assert (
                transaction.connection.execute("SELECT COUNT(*) FROM revocations").fetchone()[0]
                == 1
            )
    finally:
        dispatcher.stop()
        source_store.close()
        target_store.close()


def test_crash_after_finalize_cannot_compact_away_pending_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = ManualClock(1_000_000, 5)
    source_signer = Ed25519Signer.generate("source")
    target_signer = Ed25519Signer.generate("target")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(source_signer)
    registry.register_signer(target_signer)
    source_store, source = _node(
        tmp_path / "crash-source.db",
        warden_id="source",
        share=100,
        signer=source_signer,
        clock=clock,
        registry=registry,
        peers={"target"},
    )
    target_store, target = _node(
        tmp_path / "crash-target.db",
        warden_id="target",
        share=0,
        signer=target_signer,
        clock=clock,
        registry=registry,
        peers={"source"},
    )
    transport = _ServiceTransport(target, "source")
    dispatcher = PeerDispatcher(
        source,
        source_store,
        source_signer,
        {"target": "memory://target"},
        client_factory=lambda _endpoint: transport,
    )
    original_record_attempt = dispatcher._record_attempt
    injected = False

    def crash_before_delivery_mark(
        kind: str,
        record_id: str,
        target_warden: str,
        *,
        now_ns: int,
        error: Exception | None,
    ) -> None:
        nonlocal injected
        if kind == "transfer" and error is None and not injected:
            injected = True
            raise OSError("injected crash after local finalize")
        original_record_attempt(
            kind,
            record_id,
            target_warden,
            now_ns=now_ns,
            error=error,
        )

    try:
        source.prepare_transfer(
            request_id="crash-transfer",
            identity=_identity("source"),
            tenant_id="tenant",
            envelope_id="envelope",
            target_warden="target",
            amount=(5,),
            policy_digest=_policy().digest,
        )
        monkeypatch.setattr(dispatcher, "_record_attempt", crash_before_delivery_mark)
        dispatcher.run_once()
        with source_store.read() as transaction:
            assert (
                transaction.connection.execute("SELECT status FROM outgoing_transfers").fetchone()[
                    0
                ]
                == "FINALIZED"
            )
            assert (
                transaction.connection.execute(
                    "SELECT delivered_at_ns FROM peer_delivery_state WHERE record_kind = 'transfer'"
                ).fetchone()[0]
                is None
            )

        monkeypatch.setattr(dispatcher, "_record_attempt", original_record_attempt)
        dispatcher.run_once()
        with source_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM outgoing_transfers"
                ).fetchone()[0]
                == 1
            )
        dispatcher.run_once()
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
                    "SELECT compacted_through FROM inbound_transfer_streams"
                ).fetchone()[0]
                == 1
            )
    finally:
        dispatcher.stop()
        source_store.close()
        target_store.close()


def test_remote_accept_before_local_finalize_retries_without_duplicate_credit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = ManualClock(1_000_000, 5)
    source_signer = Ed25519Signer.generate("source")
    target_signer = Ed25519Signer.generate("target")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(source_signer)
    registry.register_signer(target_signer)
    source_store, source = _node(
        tmp_path / "accept-source.db",
        warden_id="source",
        share=100,
        signer=source_signer,
        clock=clock,
        registry=registry,
        peers={"target"},
    )
    target_store, target = _node(
        tmp_path / "accept-target.db",
        warden_id="target",
        share=0,
        signer=target_signer,
        clock=clock,
        registry=registry,
        peers={"source"},
    )
    transport = _ServiceTransport(target, "source")
    dispatcher = PeerDispatcher(
        source,
        source_store,
        source_signer,
        {"target": "memory://target"},
        client_factory=lambda _endpoint: transport,
    )
    original_finalize = source.finalize_transfer

    def fail_finalize(*, identity: IdentityContext, acknowledgement: Mapping[str, Any]) -> None:
        del identity, acknowledgement
        raise OSError("injected crash before local finalize")

    try:
        source.prepare_transfer(
            request_id="accepted-remotely",
            identity=_identity("source"),
            tenant_id="tenant",
            envelope_id="envelope",
            target_warden="target",
            amount=(5,),
            policy_digest=_policy().digest,
        )
        monkeypatch.setattr(source, "finalize_transfer", fail_finalize)
        dispatcher.run_once()
        assert target.invariant_snapshot(identity=_identity("target")).free_pool == (5,)
        monkeypatch.setattr(source, "finalize_transfer", original_finalize)
        with source_store.write() as transaction:
            transaction.connection.execute("UPDATE peer_delivery_state SET next_attempt_ns = 0")
        dispatcher.run_once()
        assert target.invariant_snapshot(identity=_identity("target")).free_pool == (5,)
        with source_store.read() as transaction:
            assert (
                transaction.connection.execute("SELECT status FROM outgoing_transfers").fetchone()[
                    0
                ]
                == "FINALIZED"
            )
    finally:
        dispatcher.stop()
        source_store.close()
        target_store.close()


def test_checkpoint_outbox_survives_restart_before_remote_acceptance(tmp_path: Path) -> None:
    clock = ManualClock(1_000_000, 5)
    source_signer = Ed25519Signer.generate("source")
    target_signer = Ed25519Signer.generate("target")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(source_signer)
    registry.register_signer(target_signer)
    source_path = tmp_path / "checkpoint-source.db"
    source_store, source = _node(
        source_path,
        warden_id="source",
        share=100,
        signer=source_signer,
        clock=clock,
        registry=registry,
        peers={"target"},
    )
    target_store, target = _node(
        tmp_path / "checkpoint-target.db",
        warden_id="target",
        share=0,
        signer=target_signer,
        clock=clock,
        registry=registry,
        peers={"source"},
    )

    class _CheckpointPartition(_ServiceTransport):
        def ingest_transfer_checkpoint(self, checkpoint: Mapping[str, Any]) -> Mapping[str, Any]:
            raise OSError("injected checkpoint partition")

    dispatcher = PeerDispatcher(
        source,
        source_store,
        source_signer,
        {"target": "memory://target"},
        client_factory=lambda _endpoint: _CheckpointPartition(target, "source"),
    )
    try:
        source.prepare_transfer(
            request_id="checkpoint-transfer",
            identity=_identity("source"),
            tenant_id="tenant",
            envelope_id="envelope",
            target_warden="target",
            amount=(5,),
            policy_digest=_policy().digest,
        )
        dispatcher.run_once()
        dispatcher.run_once()
        with source_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM outgoing_transfers"
                ).fetchone()[0]
                == 0
            )
            assert (
                transaction.connection.execute(
                    """
                SELECT COUNT(*) FROM peer_delivery_state
                WHERE record_kind = 'checkpoint' AND delivered_at_ns IS NULL
                """
                ).fetchone()[0]
                == 1
            )
        dispatcher.stop()
        source_store.close()

        source_store = SQLiteStorage(
            source_path,
            "source",
            (100,),
            signing_key_id=source_signer.key_id,
            signing_public_key=source_signer.public_key_bytes,
            tenant_id="tenant",
            envelope_id="envelope",
            initial_local_share=(100,),
            receipt_ttl_ns=100,
            max_clock_uncertainty_ns=5,
            transfer_gap_window=64,
        )
        source = WardenService(
            source_store,
            signer=source_signer,
            clock=clock,
            trust_registry=registry,
            allowed_peer_wardens={"target"},
        )
        with source_store.write() as transaction:
            transaction.connection.execute("UPDATE peer_delivery_state SET next_attempt_ns = 0")
        dispatcher = PeerDispatcher(
            source,
            source_store,
            source_signer,
            {"target": "memory://target"},
            client_factory=lambda _endpoint: _ServiceTransport(target, "source"),
        )
        dispatcher.run_once()
        with target_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT compacted_through FROM inbound_transfer_streams"
                ).fetchone()[0]
                == 1
            )
        with source_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM peer_delivery_state"
                ).fetchone()[0]
                == 0
            )
    finally:
        dispatcher.stop()
        source_store.close()
        target_store.close()


def test_newer_revocation_supersedes_older_pending_delivery(tmp_path: Path) -> None:
    clock = ManualClock(1_000_000, 5)
    signer = Ed25519Signer.generate("source")
    target_signer = Ed25519Signer.generate("target")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    registry.register_signer(target_signer)
    store, service = _node(
        tmp_path / "revocation-outbox.db",
        warden_id="source",
        share=100,
        signer=signer,
        clock=clock,
        registry=registry,
        peers={"target"},
    )
    try:
        root = service.issue_root(
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
        service.revoke_branch(
            request_id="revoke-1",
            identity=_identity("admin", "lets.admin"),
            lease_id=root.lease_id,
            reason="first",
        )
        service.revoke_branch(
            request_id="revoke-2",
            identity=_identity("admin", "lets.admin"),
            lease_id=root.lease_id,
            reason="newer",
            expected_epoch=1,
        )
        with store.read() as transaction:
            terminal = transaction.connection.execute(
                """
                SELECT
                    SUM(superseded_at_ns IS NOT NULL),
                    SUM(delivered_at_ns IS NULL AND superseded_at_ns IS NULL)
                FROM peer_delivery_state WHERE record_kind = 'revocation'
                """
            ).fetchone()
        assert tuple(terminal) == (1, 1)
    finally:
        store.close()


def test_equal_timestamps_preserve_transfer_sequence_and_compact_outbox(tmp_path: Path) -> None:
    clock = ManualClock(1_000_000, 5)
    source_signer = Ed25519Signer.generate("source")
    target_signer = Ed25519Signer.generate("target")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(source_signer)
    registry.register_signer(target_signer)
    source_store, source = _node(
        tmp_path / "ordered-source.db",
        warden_id="source",
        share=100,
        signer=source_signer,
        clock=clock,
        registry=registry,
        peers={"target"},
        gap_window=4,
    )
    target_store, target = _node(
        tmp_path / "ordered-target.db",
        warden_id="target",
        share=0,
        signer=target_signer,
        clock=clock,
        registry=registry,
        peers={"source"},
        gap_window=4,
    )
    accepted_sequences: list[int] = []

    class _OrderedTransport(_ServiceTransport):
        def accept_transfer(self, voucher: Mapping[str, Any]) -> Mapping[str, Any]:
            accepted_sequences.append(int(voucher["sequence"]))
            return super().accept_transfer(voucher)

    transport = _OrderedTransport(target, "source")
    dispatcher = PeerDispatcher(
        source,
        source_store,
        source_signer,
        {"target": "memory://target"},
        client_factory=lambda _endpoint: transport,
        poll_interval_s=0.01,
    )
    try:
        for sequence in range(1, 13):
            source.prepare_transfer(
                request_id=f"ordered-{sequence}",
                identity=_identity("source"),
                tenant_id="tenant",
                envelope_id="envelope",
                target_warden="target",
                amount=(1,),
                policy_digest=_policy(gap_window=4).digest,
            )
        for _ in range(14):
            dispatcher.run_once()

        assert accepted_sequences == list(range(1, 13))
        with target_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT contiguous_through FROM inbound_transfer_streams"
                ).fetchone()[0]
                == 12
            )
        with source_store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM peer_delivery_state"
                ).fetchone()[0]
                == 0
            )
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM peer_delivery_counters"
                ).fetchone()[0]
                <= 2
            )
    finally:
        dispatcher.stop()
        source_store.close()
        target_store.close()


def test_rejected_revocation_stream_does_not_block_transfer_to_same_peer(
    tmp_path: Path,
) -> None:
    clock = ManualClock(1_000_000, 5)
    source_signer = Ed25519Signer.generate("source")
    target_signer = Ed25519Signer.generate("target")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(source_signer)
    registry.register_signer(target_signer)
    source_store, source = _node(
        tmp_path / "isolated-source.db",
        warden_id="source",
        share=100,
        signer=source_signer,
        clock=clock,
        registry=registry,
        peers={"target"},
    )
    target_store, target = _node(
        tmp_path / "isolated-target.db",
        warden_id="target",
        share=0,
        signer=target_signer,
        clock=clock,
        registry=registry,
        peers={"source"},
    )

    class _StreamRejectingTransport(_ServiceTransport):
        def ingest_revocation(self, revocation: Mapping[str, Any]) -> Mapping[str, Any]:
            del revocation
            raise RemoteValidationError(
                ProblemDetails(
                    type="urn:lets:problem:invalid-revocation",
                    title="Invalid revocation",
                    status=422,
                    detail="injected stream-local rejection",
                    instance=None,
                    code="invalid_revocation",
                    request_id=None,
                )
            )

    dispatcher = PeerDispatcher(
        source,
        source_store,
        source_signer,
        {"target": "memory://target"},
        client_factory=lambda _endpoint: _StreamRejectingTransport(target, "source"),
    )
    try:
        root = source.issue_root(
            request_id="isolated-root",
            identity=_identity("agent", "lets.lease.issue"),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent",
            allocation=(5,),
            capabilities={"worker.act"},
            policy_digest=_policy().digest,
            ttl_ns=1_000,
        )
        source.revoke_branch(
            request_id="isolated-revocation",
            identity=_identity("admin", "lets.admin"),
            lease_id=root.lease_id,
            reason="injected rejection",
        )
        source.prepare_transfer(
            request_id="isolated-transfer",
            identity=_identity("source"),
            tenant_id="tenant",
            envelope_id="envelope",
            target_warden="target",
            amount=(3,),
            policy_digest=_policy().digest,
        )
        dispatcher.run_once()
        assert target.invariant_snapshot(identity=_identity("target")).free_pool == (3,)
        assert dispatcher.status()["failed_records"] == 1
    finally:
        dispatcher.stop()
        source_store.close()
        target_store.close()


def test_dispatcher_round_robin_does_not_starve_a_healthy_peer(tmp_path: Path) -> None:
    clock = ManualClock(1_000_000, 5)
    signer = Ed25519Signer.generate("source")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    store, service = _node(
        tmp_path / "fair.db",
        warden_id="source",
        share=100,
        signer=signer,
        clock=clock,
        registry=registry,
        peers={"down", "healthy"},
    )

    class _Down(_ServiceTransport):
        def accept_transfer(self, voucher: Mapping[str, Any]) -> Mapping[str, Any]:
            raise OSError("down")

    healthy_calls: list[str] = []

    class _Healthy:
        def accept_transfer(self, voucher: Mapping[str, Any]) -> Mapping[str, Any]:
            healthy_calls.append(str(voucher["transfer_id"]))
            raise OSError("stop after proving fair selection")

        ingest_revocation = _Down.ingest_revocation
        ingest_transfer_checkpoint = _Down.ingest_transfer_checkpoint

        def close(self) -> None:
            return None

    down = _Down(service, "source")
    healthy = _Healthy()
    dispatcher = PeerDispatcher(
        service,
        store,
        signer,
        {"down": "memory://down", "healthy": "memory://healthy"},
        client_factory=lambda endpoint: down if endpoint.endswith("down") else healthy,
        batch_size=2,
        max_concurrency=2,
        request_timeout_s=0.01,
    )
    try:
        payload = b'{"transfer_id":"synthetic"}'
        with store.write() as transaction:
            for index in range(5):
                transaction.connection.execute(
                    """
                    INSERT INTO peer_delivery_state(
                        record_kind, record_id, target_warden, ordering_key,
                        stream_position, payload, created_at_ns,
                        attempts, next_attempt_ns
                    ) VALUES ('transfer', ?, 'down', 'down', ?, ?, ?, 0, 0)
                    """,
                    (f"down-{index}", index + 1, payload, index + 1),
                )
            transaction.connection.execute(
                """
                INSERT INTO peer_delivery_state(
                    record_kind, record_id, target_warden, ordering_key,
                    stream_position, payload, created_at_ns,
                    attempts, next_attempt_ns
                ) VALUES ('transfer', 'healthy-1', 'healthy', 'healthy', 1, ?, 10, 0, 0)
                """,
                (payload,),
            )
        dispatcher.run_once()
        assert healthy_calls == ["synthetic"]
    finally:
        dispatcher.stop()
        store.close()


def test_dispatcher_rotates_across_more_due_streams_than_one_batch(tmp_path: Path) -> None:
    clock = ManualClock(1_000_000, 5)
    signer = Ed25519Signer.generate("source")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    peer_ids = {f"peer-{index:03d}" for index in range(65)}
    store, service = _node(
        tmp_path / "rotating-fairness.db",
        warden_id="source",
        share=100,
        signer=signer,
        clock=clock,
        registry=registry,
        peers=peer_ids,
    )

    class _UnusedTransport:
        def accept_transfer(self, voucher: Mapping[str, Any]) -> Mapping[str, Any]:
            raise AssertionError(f"unexpected delivery: {voucher!r}")

        def ingest_revocation(self, revocation: Mapping[str, Any]) -> Mapping[str, Any]:
            raise AssertionError(f"unexpected delivery: {revocation!r}")

        def ingest_transfer_checkpoint(self, checkpoint: Mapping[str, Any]) -> Mapping[str, Any]:
            raise AssertionError(f"unexpected delivery: {checkpoint!r}")

        def close(self) -> None:
            return None

    dispatcher = PeerDispatcher(
        service,
        store,
        signer,
        {peer_id: f"memory://{peer_id}" for peer_id in peer_ids},
        client_factory=lambda _endpoint: _UnusedTransport(),
        batch_size=64,
    )
    try:
        payload = b"{}"
        with store.write() as transaction:
            for index, peer_id in enumerate(sorted(peer_ids)):
                transaction.connection.execute(
                    """
                    INSERT INTO peer_delivery_state(
                        record_kind, record_id, target_warden, ordering_key,
                        stream_position, payload, created_at_ns,
                        attempts, next_attempt_ns
                    ) VALUES ('revocation', ?, ?, ?, 1, ?, ?, 1, 0)
                    """,
                    (f"record-{index:03d}", peer_id, f"branch-{index:03d}", payload, index + 1),
                )

        first = dispatcher._pending_records()
        second = dispatcher._pending_records()
        assert len(first) == 64
        assert set(first) | set(second) == peer_ids
        assert set(second) - set(first)
    finally:
        dispatcher.stop()
        store.close()


def test_dispatcher_passes_outbound_tls_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = ManualClock(1_000_000, 5)
    signer = Ed25519Signer.generate("source")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    store, service = _node(
        tmp_path / "tls.db",
        warden_id="source",
        share=100,
        signer=signer,
        clock=clock,
        registry=registry,
        peers={"target"},
    )
    captured: dict[str, Any] = {}

    class _CapturingClient:
        def __init__(self, base_url: str, **options: Any) -> None:
            captured.update({"base_url": base_url, **options})

        def accept_transfer(self, voucher: Mapping[str, Any]) -> Mapping[str, Any]:
            return {}

        def ingest_revocation(self, revocation: Mapping[str, Any]) -> Mapping[str, Any]:
            return {}

        def ingest_transfer_checkpoint(self, checkpoint: Mapping[str, Any]) -> Mapping[str, Any]:
            return {}

        def close(self) -> None:
            captured["closed"] = True

    monkeypatch.setattr(peer_module, "PeerClient", _CapturingClient)
    dispatcher = PeerDispatcher(
        service,
        store,
        signer,
        {"target": "https://target.example"},
        verify="private-ca.pem",
        cert=("client.pem", "client.key"),
    )
    try:
        assert captured["verify"] == "private-ca.pem"
        assert captured["cert"] == ("client.pem", "client.key")
        assert captured["timeout"] == 2.0
    finally:
        dispatcher.stop()
        store.close()
    assert captured["closed"] is True


def test_started_dispatcher_close_interrupts_blocked_transport(tmp_path: Path) -> None:
    clock = ManualClock(1_000_000, 5)
    signer = Ed25519Signer.generate("source")
    target_signer = Ed25519Signer.generate("target")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    registry.register_signer(target_signer)
    store, service = _node(
        tmp_path / "shutdown.db",
        warden_id="source",
        share=100,
        signer=signer,
        clock=clock,
        registry=registry,
        peers={"target"},
    )
    entered = threading.Event()
    released = threading.Event()

    class _BlockingTransport:
        def accept_transfer(self, voucher: Mapping[str, Any]) -> Mapping[str, Any]:
            del voucher
            entered.set()
            released.wait()
            raise OSError("transport closed")

        def ingest_revocation(self, revocation: Mapping[str, Any]) -> Mapping[str, Any]:
            raise AssertionError(revocation)

        def ingest_transfer_checkpoint(self, checkpoint: Mapping[str, Any]) -> Mapping[str, Any]:
            raise AssertionError(checkpoint)

        def close(self) -> None:
            released.set()

    dispatcher = PeerDispatcher(
        service,
        store,
        signer,
        {"target": "memory://target"},
        client_factory=lambda _endpoint: _BlockingTransport(),
        poll_interval_s=0.01,
        request_timeout_s=0.1,
    )
    try:
        service.prepare_transfer(
            request_id="blocked-transfer",
            identity=_identity("source"),
            tenant_id="tenant",
            envelope_id="envelope",
            target_warden="target",
            amount=(1,),
            policy_digest=_policy().digest,
        )
        dispatcher.start()
        assert entered.wait(2)
        started = time.perf_counter()
        dispatcher.stop(timeout_s=2)
        assert time.perf_counter() - started < 2
    finally:
        released.set()
        dispatcher.stop(timeout_s=2)
        store.close()
