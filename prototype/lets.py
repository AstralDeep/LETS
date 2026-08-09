"""Reference implementation of LETS: Lineage Escrow Transition Systems.

This module is intentionally small and auditable.  It is a research prototype,
not a production authorization service.  The trusted-computing-base assumptions
and unsupported threat classes are documented in the companion manuscript.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from hashlib import sha256
import json
import time
from typing import Callable, Iterable, Mapping, Sequence
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

Vector = tuple[int, ...]
EvidenceGuard = Callable[[Mapping[str, object] | None], bool]


def _same_dim(a: Vector, b: Vector) -> None:
    if len(a) != len(b):
        raise ValueError(f"resource-vector dimension mismatch: {len(a)} != {len(b)}")


def vadd(a: Vector, b: Vector) -> Vector:
    _same_dim(a, b)
    return tuple(x + y for x, y in zip(a, b, strict=True))


def vsub(a: Vector, b: Vector) -> Vector:
    _same_dim(a, b)
    out = tuple(x - y for x, y in zip(a, b, strict=True))
    if any(x < 0 for x in out):
        raise ValueError(f"insufficient escrow rights: {a} - {b}")
    return out


def vleq(a: Vector, b: Vector) -> bool:
    _same_dim(a, b)
    return all(x <= y for x, y in zip(a, b, strict=True))


def vsum(vectors: Iterable[Vector], dim: int) -> Vector:
    total = (0,) * dim
    for vector in vectors:
        total = vadd(total, vector)
    return total


def vzero(dim: int) -> Vector:
    return (0,) * dim


class LeaseStatus(str, Enum):
    ACTIVE = "active"
    QUIESCENT = "quiescent"
    REVOKED = "revoked"
    EXPIRED = "expired"
    CLOSED = "closed"
    MIGRATING = "migrating"


class TransferStatus(str, Enum):
    PREPARED = "prepared"
    ACCEPTED = "accepted"


@dataclass(frozen=True, slots=True)
class TransitionSpec:
    name: str
    source: str
    target: str
    cost: Vector
    capability: str
    evidence_guard: EvidenceGuard | None = field(default=None, compare=False, repr=False)


@dataclass(frozen=True, slots=True)
class MachineSpec:
    name: str
    initial_state: str
    transitions: tuple[TransitionSpec, ...]

    def transition(self, state: str, name: str) -> TransitionSpec:
        matches = [t for t in self.transitions if t.source == state and t.name == name]
        if len(matches) != 1:
            raise ValueError(f"transition {name!r} is not enabled from state {state!r}")
        return matches[0]

    @property
    def digest(self) -> str:
        serializable = {
            "name": self.name,
            "initial_state": self.initial_state,
            "transitions": [
                {
                    "name": t.name,
                    "source": t.source,
                    "target": t.target,
                    "cost": list(t.cost),
                    "capability": t.capability,
                    "has_evidence_guard": t.evidence_guard is not None,
                }
                for t in self.transitions
            ],
        }
        payload = json.dumps(serializable, sort_keys=True, separators=(",", ":")).encode()
        return sha256(payload).hexdigest()


@dataclass(slots=True)
class Lease:
    lease_id: str
    lineage_id: str
    parent_id: str | None
    subject_id: str
    warden_id: str
    allocation: Vector
    residual: Vector
    capabilities: frozenset[str]
    machine_digest: str
    current_state: str
    ancestor_path: tuple[str, ...]
    issued_at: float
    expires_at: float
    branch_epoch: int
    status: LeaseStatus
    signature: bytes
    sequence: int = 0

    def immutable_payload(self) -> bytes:
        data = {
            "lease_id": self.lease_id,
            "lineage_id": self.lineage_id,
            "parent_id": self.parent_id,
            "subject_id": self.subject_id,
            "warden_id": self.warden_id,
            "allocation": list(self.allocation),
            "capabilities": sorted(self.capabilities),
            "machine_digest": self.machine_digest,
            "ancestor_path": list(self.ancestor_path),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "branch_epoch": self.branch_epoch,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    def is_descendant_of(self, branch_lease_id: str) -> bool:
        return branch_lease_id == self.lease_id or branch_lease_id in self.ancestor_path


@dataclass(slots=True)
class Transfer:
    transfer_id: str
    source_warden: str
    target_warden: str
    amount: Vector
    status: TransferStatus


@dataclass(slots=True)
class AuditEvent:
    event: str
    warden_id: str
    lease_id: str | None
    logical_time: float
    details: dict[str, object]


class Warden:
    """Stable escrow replica and complete-mediation boundary.

    The reasoner, planner, agent memory, and generated code are outside this
    object.  The reference implementation assumes the warden's process,
    persistent state, signing key, and clock are trusted.
    """

    def __init__(self, warden_id: str, initial_pool: Vector):
        if any(x < 0 for x in initial_pool):
            raise ValueError("initial rights must be non-negative")
        self.warden_id = warden_id
        self.free_pool: Vector = initial_pool
        self.consumed: Vector = vzero(len(initial_pool))
        self.leases: dict[str, Lease] = {}
        self.machine_specs: dict[str, MachineSpec] = {}
        self.known_revocations: dict[str, int] = {}
        self.accepted_transfers: set[str] = set()
        self.audit: list[AuditEvent] = []
        self._signing_key = Ed25519PrivateKey.generate()
        self.public_key: Ed25519PublicKey = self._signing_key.public_key()

    @property
    def dim(self) -> int:
        return len(self.free_pool)

    def register_machine(self, spec: MachineSpec) -> None:
        for transition in spec.transitions:
            if len(transition.cost) != self.dim:
                raise ValueError("transition cost dimension does not match warden resource dimension")
            if any(x < 0 for x in transition.cost):
                raise ValueError("LETS v0 supports non-negative transition costs only")
        self.machine_specs[spec.digest] = spec

    def _sign_lease(self, lease: Lease) -> bytes:
        return self._signing_key.sign(lease.immutable_payload())

    def verify_lease_signature(self, lease: Lease) -> bool:
        try:
            self.public_key.verify(lease.signature, lease.immutable_payload())
            return True
        except InvalidSignature:
            return False

    def _log(self, event: str, lease_id: str | None, now: float, **details: object) -> None:
        self.audit.append(AuditEvent(event, self.warden_id, lease_id, now, dict(details)))

    def issue_root(
        self,
        *,
        subject_id: str,
        allocation: Vector,
        capabilities: Iterable[str],
        machine: MachineSpec,
        ttl: float,
        now: float | None = None,
        lineage_id: str | None = None,
    ) -> Lease:
        now = time.time() if now is None else now
        self.register_machine(machine)
        self.free_pool = vsub(self.free_pool, allocation)
        lease_id = f"lease-{uuid4().hex}"
        lineage_id = lineage_id or f"lineage-{uuid4().hex}"
        unsigned = Lease(
            lease_id=lease_id,
            lineage_id=lineage_id,
            parent_id=None,
            subject_id=subject_id,
            warden_id=self.warden_id,
            allocation=allocation,
            residual=allocation,
            capabilities=frozenset(capabilities),
            machine_digest=machine.digest,
            current_state=machine.initial_state,
            ancestor_path=(),
            issued_at=now,
            expires_at=now + ttl,
            branch_epoch=0,
            status=LeaseStatus.ACTIVE,
            signature=b"",
        )
        unsigned.signature = self._sign_lease(unsigned)
        self.leases[lease_id] = unsigned
        self._log("issue_root", lease_id, now, allocation=list(allocation), lineage_id=lineage_id)
        return unsigned

    def spawn_local(
        self,
        *,
        parent_id: str,
        subject_id: str,
        allocation: Vector,
        capabilities: Iterable[str],
        machine: MachineSpec | None = None,
        ttl: float,
        now: float | None = None,
    ) -> Lease:
        now = time.time() if now is None else now
        parent = self._require_actionable(parent_id, now)
        child_caps = frozenset(capabilities)
        if not child_caps.issubset(parent.capabilities):
            raise PermissionError("child capability set is not attenuated")
        if not vleq(allocation, parent.residual):
            raise ValueError("parent lacks requested child allocation")
        spec = machine or self.machine_specs[parent.machine_digest]
        self.register_machine(spec)
        parent.residual = vsub(parent.residual, allocation)
        parent.sequence += 1
        lease_id = f"lease-{uuid4().hex}"
        unsigned = Lease(
            lease_id=lease_id,
            lineage_id=parent.lineage_id,
            parent_id=parent.lease_id,
            subject_id=subject_id,
            warden_id=self.warden_id,
            allocation=allocation,
            residual=allocation,
            capabilities=child_caps,
            machine_digest=spec.digest,
            current_state=spec.initial_state,
            ancestor_path=parent.ancestor_path + (parent.lease_id,),
            issued_at=now,
            expires_at=min(parent.expires_at, now + ttl),
            branch_epoch=parent.branch_epoch,
            status=LeaseStatus.ACTIVE,
            signature=b"",
        )
        unsigned.signature = self._sign_lease(unsigned)
        self.leases[lease_id] = unsigned
        self._log(
            "spawn",
            lease_id,
            now,
            parent_id=parent_id,
            allocation=list(allocation),
            capabilities=sorted(child_caps),
        )
        return unsigned

    def execute(
        self,
        *,
        lease_id: str,
        transition_name: str,
        evidence: Mapping[str, object] | None = None,
        now: float | None = None,
    ) -> Lease:
        now = time.time() if now is None else now
        lease = self._require_actionable(lease_id, now)
        spec = self.machine_specs.get(lease.machine_digest)
        if spec is None:
            raise RuntimeError("machine specification is not registered at this warden")
        transition = spec.transition(lease.current_state, transition_name)
        if transition.capability not in lease.capabilities:
            raise PermissionError(f"missing capability {transition.capability!r}")
        if transition.evidence_guard is not None and not transition.evidence_guard(evidence):
            raise PermissionError("transition evidence guard failed")
        if not vleq(transition.cost, lease.residual):
            raise ValueError("lease lacks transition rights")
        lease.residual = vsub(lease.residual, transition.cost)
        self.consumed = vadd(self.consumed, transition.cost)
        lease.current_state = transition.target
        lease.sequence += 1
        self._log(
            "execute",
            lease_id,
            now,
            transition=transition_name,
            source=transition.source,
            target=transition.target,
            cost=list(transition.cost),
        )
        return lease

    def set_quiescent(self, lease_id: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        lease = self._require_actionable(lease_id, now)
        lease.status = LeaseStatus.QUIESCENT
        lease.sequence += 1
        self._log("quiesce", lease_id, now)

    def resume(self, lease_id: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        lease = self.leases[lease_id]
        if lease.status != LeaseStatus.QUIESCENT:
            raise ValueError("only a quiescent lease may resume")
        if now >= lease.expires_at:
            raise PermissionError("lease expired")
        if self._revoked_by_known_prefix(lease):
            raise PermissionError("lease branch is revoked")
        lease.status = LeaseStatus.ACTIVE
        lease.sequence += 1
        self._log("resume", lease_id, now)

    def renew(self, lease_id: str, *, ttl: float, now: float | None = None) -> None:
        now = time.time() if now is None else now
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        lease = self._require_actionable(lease_id, now)
        if self._revoked_by_known_prefix(lease):
            raise PermissionError("cannot renew a revoked branch")

        requested_expiry = now + ttl
        if lease.parent_id is not None:
            parent = self.leases.get(lease.parent_id)
            if parent is None:
                raise RuntimeError("local prototype cannot renew a child whose parent is absent")
            if parent.status in {LeaseStatus.REVOKED, LeaseStatus.EXPIRED, LeaseStatus.CLOSED}:
                raise PermissionError("cannot renew beneath an inactive parent")
            if now >= parent.expires_at or self._revoked_by_known_prefix(parent):
                raise PermissionError("cannot renew beneath an expired or revoked parent")
            requested_expiry = min(requested_expiry, parent.expires_at)

        # Renewal changes immutable token fields; issue a fresh signature. Descendant
        # expiry remains nested beneath the parent so no sublease outlives its grant.
        lease.expires_at = requested_expiry
        lease.issued_at = now
        lease.signature = self._sign_lease(lease)
        lease.sequence += 1
        self._log("renew", lease_id, now, ttl=ttl, expires_at=requested_expiry)

    def revoke_branch(self, branch_lease_id: str, *, epoch: int, now: float | None = None) -> int:
        now = time.time() if now is None else now
        previous = self.known_revocations.get(branch_lease_id, -1)
        if epoch <= previous:
            return 0
        self.known_revocations[branch_lease_id] = epoch
        affected = 0
        for lease in self.leases.values():
            if lease.is_descendant_of(branch_lease_id) and lease.status in {
                LeaseStatus.ACTIVE,
                LeaseStatus.QUIESCENT,
            }:
                lease.status = LeaseStatus.REVOKED
                lease.sequence += 1
                affected += 1
        self._log("revoke_branch", branch_lease_id, now, epoch=epoch, affected=affected)
        return affected

    def close(self, lease_id: str, now: float | None = None) -> Vector:
        now = time.time() if now is None else now
        lease = self.leases[lease_id]
        if lease.status in {LeaseStatus.CLOSED, LeaseStatus.EXPIRED}:
            return vzero(self.dim)
        returned = lease.residual
        lease.residual = vzero(self.dim)
        lease.status = LeaseStatus.CLOSED
        lease.sequence += 1
        self.free_pool = vadd(self.free_pool, returned)
        self._log("close", lease_id, now, returned=list(returned))
        return returned

    def reclaim_expired(self, now: float | None = None) -> Vector:
        now = time.time() if now is None else now
        reclaimed = vzero(self.dim)
        for lease in self.leases.values():
            if lease.status in {LeaseStatus.CLOSED, LeaseStatus.EXPIRED}:
                continue
            if now >= lease.expires_at:
                reclaimed = vadd(reclaimed, lease.residual)
                lease.residual = vzero(self.dim)
                lease.status = LeaseStatus.EXPIRED
                lease.sequence += 1
                self._log("expire", lease.lease_id, now)
        self.free_pool = vadd(self.free_pool, reclaimed)
        return reclaimed

    def active_leases(self) -> list[Lease]:
        return [
            lease
            for lease in self.leases.values()
            if lease.status in {LeaseStatus.ACTIVE, LeaseStatus.QUIESCENT, LeaseStatus.REVOKED}
            and any(lease.residual)
        ]

    def online_metadata_cells(self) -> int:
        # Research accounting model: one record per live lease, plus revocation prefixes.
        return len(self.active_leases()) + len(self.known_revocations)

    def _revoked_by_known_prefix(self, lease: Lease) -> bool:
        return any(lease.is_descendant_of(branch_id) for branch_id in self.known_revocations)

    def _require_actionable(self, lease_id: str, now: float) -> Lease:
        lease = self.leases[lease_id]
        if lease.status != LeaseStatus.ACTIVE:
            raise PermissionError(f"lease status is {lease.status.value}, not active")
        if now >= lease.expires_at:
            raise PermissionError("lease expired")
        if self._revoked_by_known_prefix(lease):
            raise PermissionError("lease branch is revoked")
        if not self.verify_lease_signature(lease):
            raise PermissionError("invalid lease signature")
        return lease


class LETSystem:
    """A small multi-warden container with an idempotent escrow handoff."""

    def __init__(self, initial_budget: Vector, warden_ids: Sequence[str]):
        if not warden_ids:
            raise ValueError("at least one warden is required")
        self.initial_budget = initial_budget
        self.dim = len(initial_budget)
        base = tuple(x // len(warden_ids) for x in initial_budget)
        remainder = tuple(x % len(warden_ids) for x in initial_budget)
        self.wardens: dict[str, Warden] = {}
        for i, warden_id in enumerate(warden_ids):
            share = tuple(base[j] + (1 if i < remainder[j] else 0) for j in range(self.dim))
            self.wardens[warden_id] = Warden(warden_id, share)
        self.transfers: dict[str, Transfer] = {}

    def prepare_transfer(self, source: str, target: str, amount: Vector) -> Transfer:
        if source == target:
            raise ValueError("source and target must differ")
        src = self.wardens[source]
        src.free_pool = vsub(src.free_pool, amount)
        transfer = Transfer(
            transfer_id=f"transfer-{uuid4().hex}",
            source_warden=source,
            target_warden=target,
            amount=amount,
            status=TransferStatus.PREPARED,
        )
        self.transfers[transfer.transfer_id] = transfer
        src._log("prepare_transfer", None, time.time(), transfer_id=transfer.transfer_id, amount=list(amount))
        return transfer

    def accept_transfer(self, transfer_id: str) -> bool:
        transfer = self.transfers[transfer_id]
        target = self.wardens[transfer.target_warden]
        if transfer_id in target.accepted_transfers:
            return False
        if transfer.status != TransferStatus.PREPARED:
            return False
        target.free_pool = vadd(target.free_pool, transfer.amount)
        target.accepted_transfers.add(transfer_id)
        transfer.status = TransferStatus.ACCEPTED
        target._log("accept_transfer", None, time.time(), transfer_id=transfer_id, amount=list(transfer.amount))
        return True

    def conservation_components(self) -> dict[str, Vector]:
        free = vsum((w.free_pool for w in self.wardens.values()), self.dim)
        leases = vsum(
            (lease.residual for w in self.wardens.values() for lease in w.leases.values()),
            self.dim,
        )
        consumed = vsum((w.consumed for w in self.wardens.values()), self.dim)
        in_flight = vsum(
            (t.amount for t in self.transfers.values() if t.status == TransferStatus.PREPARED),
            self.dim,
        )
        return {"free": free, "leases": leases, "consumed": consumed, "in_flight": in_flight}

    def assert_invariants(self) -> None:
        parts = self.conservation_components()
        total = vzero(self.dim)
        for vector in parts.values():
            total = vadd(total, vector)
        if total != self.initial_budget:
            raise AssertionError(f"conservation violated: {total=} != {self.initial_budget=}; {parts=}")
        for warden in self.wardens.values():
            if any(x < 0 for x in warden.free_pool + warden.consumed):
                raise AssertionError("negative warden vector")
            for lease in warden.leases.values():
                if any(x < 0 for x in lease.residual):
                    raise AssertionError("negative lease residual")
                if not vleq(lease.residual, lease.allocation):
                    raise AssertionError("lease residual exceeds allocation")
                if lease.parent_id is not None:
                    parent = warden.leases.get(lease.parent_id)
                    if parent is not None and not lease.capabilities.issubset(parent.capabilities):
                        raise AssertionError("capability amplification detected")

    def online_metadata_cells(self) -> int:
        # W^2 rights-transfer matrix equivalent plus live lease/revocation records.
        w = len(self.wardens)
        return w * w + sum(warden.online_metadata_cells() for warden in self.wardens.values())


def default_machine(dim: int = 2) -> MachineSpec:
    """A domain-neutral lifecycle used by tests and benchmarks.

    Resource dimension 0 is an abstract protected-action budget.  Dimension 1
    is an abstract communication/actuation budget.
    """
    if dim != 2:
        raise ValueError("default_machine currently uses exactly two resource dimensions")

    def evidence_ok(evidence: Mapping[str, object] | None) -> bool:
        return bool(evidence and evidence.get("verified") is True)

    return MachineSpec(
        name="generic-autonomous-worker",
        initial_state="provisioned",
        transitions=(
            TransitionSpec("activate", "provisioned", "active", (1, 0), "lifecycle.activate"),
            TransitionSpec("observe", "active", "active", (0, 1), "sensor.read", evidence_ok),
            TransitionSpec("act", "active", "active", (1, 1), "actuator.write"),
            TransitionSpec("quiesce", "active", "quiescent", (0, 0), "lifecycle.quiesce"),
            TransitionSpec("resume", "quiescent", "active", (0, 0), "lifecycle.activate"),
            TransitionSpec("terminate", "active", "terminated", (0, 0), "lifecycle.terminate"),
        ),
    )
