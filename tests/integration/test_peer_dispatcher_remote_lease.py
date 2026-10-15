"""Tests for PeerDispatcher.resolve_remote_lease in src/lets/peer.py: a remote child's
status is fetched through the configured peer transport, a missing lease resolves to
None, and an unconfigured peer fails closed.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from lets.client import ProblemDetails, ResourceNotFoundError
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import NotFoundError, StorageError
from lets.models import IdentityContext
from lets.peer import PeerDispatcher
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage


def _policy() -> PolicySpec:
    return PolicySpec(
        policy_id="generic-policy",
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
        transfer_gap_window=64,
    )


def _identity(subject: str, *scopes: str) -> IdentityContext:
    return IdentityContext(subject, "tenant", frozenset(scopes))


class _StatusTransport:
    def __init__(self, target: WardenService) -> None:
        self._target = target
        self._identity = _identity("source", "lets.peer", "lets.transfer")

    def accept_transfer(self, voucher: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._target.accept_transfer(identity=self._identity, voucher=voucher).to_dict()

    def ingest_revocation(self, revocation: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._target.ingest_revocation(
            identity=self._identity, revocation=revocation
        ).to_dict()

    def ingest_transfer_checkpoint(self, checkpoint: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._target.ingest_transfer_checkpoint(
            identity=self._identity, checkpoint=checkpoint
        )

    def lease_status(self, lease_id: str) -> Mapping[str, Any]:
        try:
            snapshot = self._target.peer_lease_status(identity=self._identity, lease_id=lease_id)
        except NotFoundError as error:
            raise ResourceNotFoundError(
                ProblemDetails(
                    type="urn:lets:problem:not_found",
                    title="Not Found",
                    status=404,
                    detail=str(error),
                    instance=None,
                    code="not_found",
                    request_id=None,
                )
            ) from error
        return snapshot.to_dict()

    def close(self) -> None:
        return None


def _node(
    path: Path,
    warden_id: str,
    signer: Ed25519Signer,
    clock: ManualClock,
    registry: PublicKeyRegistry,
    peers: set[str],
) -> tuple[SQLiteStorage, WardenService]:
    store = SQLiteStorage.initialize(
        path,
        warden_id,
        (100,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        initial_local_share=(50,),
        receipt_ttl_ns=100,
        max_clock_uncertainty_ns=5,
        transfer_gap_window=64,
    )
    service = WardenService(
        store, signer=signer, clock=clock, trust_registry=registry, allowed_peer_wardens=peers
    )
    service.register_policy(_policy())
    return store, service


def test_dispatcher_resolves_remote_lease_status_through_the_peer_transport(
    tmp_path: Path,
) -> None:
    clock = ManualClock(1_000_000, 5)
    source_signer = Ed25519Signer.generate("source")
    target_signer = Ed25519Signer.generate("target")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(source_signer)
    registry.register_signer(target_signer)
    source_store, source = _node(
        tmp_path / "source.db", "source", source_signer, clock, registry, {"target"}
    )
    target_store, target = _node(
        tmp_path / "target.db", "target", target_signer, clock, registry, {"source"}
    )
    dispatcher = PeerDispatcher(
        source,
        source_store,
        source_signer,
        {"target": "memory://target"},
        client_factory=lambda _endpoint: _StatusTransport(target),
        poll_interval_s=0.01,
        request_timeout_s=0.01,
    )
    try:
        root = target.issue_root(
            request_id="target-root",
            identity=_identity("agent", "lets.lease.issue"),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent",
            allocation=(5,),
            capabilities={"worker.act"},
            policy_digest=_policy().digest,
            ttl_ns=5_000,
        )
        resolved = dispatcher.resolve_remote_lease("target", root.lease_id)
        assert resolved is not None
        assert resolved["grant"]["lease_id"] == root.lease_id
        assert resolved["status"] == "ACTIVE"
        assert dispatcher.resolve_remote_lease("target", "lease-missing") is None
        with pytest.raises(StorageError, match="no configured client"):
            dispatcher.resolve_remote_lease("stranger", root.lease_id)
    finally:
        dispatcher.stop(timeout_s=1.0)
        source_store.close()
        target_store.close()
