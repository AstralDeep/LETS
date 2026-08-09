"""Protocol-neutral lifecycle mapping for systems that create agent replicas."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from lets.errors import PolicyError, ValidationError
from lets.ids import require_digest, require_identifier
from lets.vector import ResourceVector, vector

WireObject = Mapping[str, Any]


class AuthorizerClient(Protocol):
    """Small public-client surface required by a host-system adapter."""

    def issue_root(self, payload: Mapping[str, Any]) -> WireObject: ...

    def spawn(self, parent_id: str, payload: Mapping[str, Any]) -> WireObject: ...

    def authorize(self, lease_id: str, payload: Mapping[str, Any]) -> WireObject: ...

    def renew(self, lease_id: str, payload: Mapping[str, Any]) -> WireObject: ...

    def quiesce(self, lease_id: str, payload: Mapping[str, Any]) -> WireObject: ...

    def resume(self, lease_id: str, payload: Mapping[str, Any]) -> WireObject: ...

    def close_lease(self, lease_id: str, payload: Mapping[str, Any]) -> WireObject: ...

    def revoke_branch(self, lease_id: str, payload: Mapping[str, Any]) -> WireObject: ...


@dataclass(frozen=True, slots=True)
class ReplicaProfile:
    """Immutable binding between a host deployment and one LETS policy."""

    tenant_id: str
    envelope_id: str
    policy_digest: str
    default_allocation: ResourceVector
    default_capabilities: frozenset[str]
    default_ttl_ns: int

    def __post_init__(self) -> None:
        require_identifier(self.tenant_id, field="profile tenant_id")
        require_identifier(self.envelope_id, field="profile envelope_id")
        require_digest(self.policy_digest, field="profile policy_digest")
        object.__setattr__(self, "default_allocation", vector(self.default_allocation))
        if not self.default_capabilities:
            raise ValidationError("replica profile requires at least one capability")
        for capability in self.default_capabilities:
            require_identifier(capability, field="profile capability")
        if (
            isinstance(self.default_ttl_ns, bool)
            or not isinstance(self.default_ttl_ns, int)
            or self.default_ttl_ns <= 0
        ):
            raise ValidationError("replica profile default_ttl_ns must be positive")


class ReplicaAuthorizer:
    """Map host lifecycle events to LETS without importing the host system.

    The caller supplies its own durable operation identifier as ``request_id``.
    LETS then makes retries safe across process and network failures. Replica
    artifacts, secrets, process memory, and owner credentials are intentionally
    absent from this interface.
    """

    def __init__(self, client: AuthorizerClient, profile: ReplicaProfile) -> None:
        self.client = client
        self.profile = profile

    @staticmethod
    def _capabilities(
        requested: frozenset[str] | set[str] | tuple[str, ...] | None,
        default: frozenset[str],
    ) -> list[str]:
        selected = default if requested is None else frozenset(requested)
        if not selected:
            raise ValidationError("a replica must receive at least one capability")
        if not selected.issubset(default):
            raise PolicyError(
                f"replica capabilities exceed the configured profile: {sorted(selected - default)}"
            )
        for capability in selected:
            require_identifier(capability, field="replica capability")
        return sorted(selected)

    @staticmethod
    def _ttl(ttl_ns: int) -> int:
        if isinstance(ttl_ns, bool) or not isinstance(ttl_ns, int) or ttl_ns <= 0:
            raise ValidationError("replica ttl_ns must be a positive integer")
        return ttl_ns

    @staticmethod
    def _sequence(sequence: int | None) -> int | None:
        if sequence is not None and (
            isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0
        ):
            raise ValidationError("expected_sequence must be a non-negative integer")
        return sequence

    def provision(
        self,
        *,
        request_id: str,
        replica_id: str,
        allocation: ResourceVector | None = None,
        capabilities: frozenset[str] | set[str] | tuple[str, ...] | None = None,
        ttl_ns: int | None = None,
        lineage_id: str | None = None,
    ) -> WireObject:
        require_identifier(request_id, field="request_id")
        require_identifier(replica_id, field="replica_id")
        payload: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": self.profile.tenant_id,
            "envelope_id": self.profile.envelope_id,
            "subject_id": replica_id,
            "allocation": list(
                self.profile.default_allocation
                if allocation is None
                else vector(allocation, dimensions=len(self.profile.default_allocation))
            ),
            "capabilities": self._capabilities(
                capabilities,
                self.profile.default_capabilities,
            ),
            "policy_digest": self.profile.policy_digest,
            "ttl_ns": self._ttl(self.profile.default_ttl_ns if ttl_ns is None else ttl_ns),
        }
        if lineage_id is not None:
            payload["lineage_id"] = require_identifier(lineage_id, field="lineage_id")
        return self.client.issue_root(payload)

    def replicate(
        self,
        *,
        request_id: str,
        parent_lease_id: str,
        replica_id: str,
        allocation: ResourceVector,
        capabilities: frozenset[str] | set[str] | tuple[str, ...],
        ttl_ns: int,
        expected_sequence: int | None = None,
    ) -> WireObject:
        require_identifier(request_id, field="request_id")
        require_identifier(parent_lease_id, field="parent_lease_id")
        require_identifier(replica_id, field="replica_id")
        payload: dict[str, Any] = {
            "request_id": request_id,
            "subject_id": replica_id,
            "allocation": list(vector(allocation, dimensions=len(self.profile.default_allocation))),
            "capabilities": self._capabilities(capabilities, self.profile.default_capabilities),
            "ttl_ns": self._ttl(ttl_ns),
            "policy_digest": self.profile.policy_digest,
        }
        checked_sequence = self._sequence(expected_sequence)
        if checked_sequence is not None:
            payload["expected_sequence"] = checked_sequence
        return self.client.spawn(parent_lease_id, payload)

    def authorize_effect(
        self,
        *,
        request_id: str,
        lease_id: str,
        transition: str,
        executor_audience: str,
        nonce: str,
        evidence: Mapping[str, Any] | None = None,
        expected_state: str | None = None,
        expected_sequence: int | None = None,
    ) -> WireObject:
        for field, value in (
            ("request_id", request_id),
            ("lease_id", lease_id),
            ("transition", transition),
            ("executor_audience", executor_audience),
            ("nonce", nonce),
        ):
            require_identifier(value, field=field)
        payload: dict[str, Any] = {
            "request_id": request_id,
            "transition": transition,
            "executor_audience": executor_audience,
            "nonce": nonce,
        }
        if evidence is not None:
            payload["evidence"] = dict(evidence)
        if expected_state is not None:
            payload["expected_state"] = expected_state
        checked_sequence = self._sequence(expected_sequence)
        if checked_sequence is not None:
            payload["expected_sequence"] = checked_sequence
        return self.client.authorize(lease_id, payload)

    def renew(
        self,
        lease_id: str,
        *,
        request_id: str,
        ttl_ns: int,
        expected_sequence: int | None = None,
        cascade: bool = False,
    ) -> WireObject:
        require_identifier(request_id, field="request_id")
        require_identifier(lease_id, field="lease_id")
        payload: dict[str, Any] = {
            "request_id": request_id,
            "ttl_ns": self._ttl(ttl_ns),
            "cascade": cascade,
        }
        checked_sequence = self._sequence(expected_sequence)
        if checked_sequence is not None:
            payload["expected_sequence"] = checked_sequence
        return self.client.renew(lease_id, payload)

    def quiesce(self, lease_id: str, *, request_id: str) -> WireObject:
        require_identifier(lease_id, field="lease_id")
        require_identifier(request_id, field="request_id")
        return self.client.quiesce(lease_id, {"request_id": request_id})

    def resume(self, lease_id: str, *, request_id: str) -> WireObject:
        require_identifier(lease_id, field="lease_id")
        require_identifier(request_id, field="request_id")
        return self.client.resume(lease_id, {"request_id": request_id})

    def close(self, lease_id: str, *, request_id: str) -> WireObject:
        require_identifier(lease_id, field="lease_id")
        require_identifier(request_id, field="request_id")
        return self.client.close_lease(lease_id, {"request_id": request_id})

    def revoke(self, lease_id: str, *, request_id: str, reason: str) -> WireObject:
        require_identifier(lease_id, field="lease_id")
        require_identifier(request_id, field="request_id")
        if not reason or len(reason) > 1000:
            raise ValidationError("revocation reason must contain 1..1000 characters")
        return self.client.revoke_branch(
            lease_id,
            {"request_id": request_id, "reason": reason},
        )
