"""Immutable domain and wire records for the LETS v1 protocol."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, ClassVar, Self

from lets.errors import ValidationError
from lets.ids import require_digest, require_identifier, require_key_id, require_warden_id
from lets.vector import MAX_RESOURCE, ResourceVector, vector

WireDict = dict[str, Any]
MAX_LINEAGE_DEPTH = 64


def _positive(value: int, field: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    if value < 0 or (not allow_zero and value == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValidationError(f"{field} must be {qualifier}")
    if value > MAX_RESOURCE:
        raise ValidationError(f"{field} must fit in a signed 64-bit integer")
    return value


def _strings(values: Any, field: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValidationError(f"{field} must be an array of strings")
    try:
        result = tuple(values)
    except TypeError as exc:
        raise ValidationError(f"{field} must be an array of strings") from exc
    if any(not isinstance(item, str) or not item for item in result):
        raise ValidationError(f"{field} must contain non-empty strings")
    return result


def _strict(
    data: dict[str, Any],
    allowed: set[str],
    name: str,
    *,
    required: set[str] | None = None,
) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise ValidationError(f"unknown {name} fields: {sorted(unknown)}")
    missing = (allowed if required is None else required) - set(data)
    if missing:
        raise ValidationError(f"missing {name} fields: {sorted(missing)}")


class LeaseStatus(StrEnum):
    PROVISIONED = "PROVISIONED"
    ACTIVE = "ACTIVE"
    QUIESCENT = "QUIESCENT"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    CLOSED = "CLOSED"


class TransferStatus(StrEnum):
    PREPARED = "PREPARED"
    ACCEPTED = "ACCEPTED"
    FINALIZED = "FINALIZED"


@dataclass(frozen=True, slots=True)
class IdentityContext:
    """Identity resolved by a transport authenticator, never from request JSON."""

    subject_id: str
    tenant_id: str
    scopes: frozenset[str]
    authentication_method: str = "embedded"

    def __post_init__(self) -> None:
        require_identifier(self.subject_id, field="identity subject")
        require_identifier(self.tenant_id, field="identity tenant")
        require_identifier(self.authentication_method, field="authentication method")
        for scope in self.scopes:
            require_identifier(scope, field="identity scope")

    def require_scope(self, scope: str) -> None:
        if scope not in self.scopes:
            raise PermissionError(f"authenticated identity lacks required scope {scope!r}")


@dataclass(frozen=True, slots=True)
class LeaseGrant:
    WIRE_TYPE: ClassVar[str] = "lets.lease-grant/v1"

    tenant_id: str
    envelope_id: str
    config_epoch: int
    lease_id: str
    lineage_id: str
    parent_id: str | None
    subject_id: str
    warden_id: str
    allocation: ResourceVector
    capabilities: frozenset[str]
    policy_id: str
    policy_version: str
    policy_digest: str
    machine_digest: str
    ancestor_path: tuple[str, ...]
    branch_epoch: int
    issued_at_ns: int
    expires_at_ns: int
    key_id: str
    signature: str = ""

    def __post_init__(self) -> None:
        for field in (
            "tenant_id",
            "envelope_id",
            "lease_id",
            "lineage_id",
            "subject_id",
            "policy_id",
            "policy_version",
        ):
            require_identifier(getattr(self, field), field=field)
        require_warden_id(self.warden_id)
        require_key_id(self.key_id)
        if self.parent_id is not None:
            require_identifier(self.parent_id, field="parent_id")
        require_digest(self.policy_digest, field="policy_digest")
        require_digest(self.machine_digest, field="machine_digest")
        _positive(self.config_epoch, "config_epoch")
        _positive(self.branch_epoch, "branch_epoch", allow_zero=True)
        _positive(self.issued_at_ns, "issued_at_ns", allow_zero=True)
        _positive(self.expires_at_ns, "expires_at_ns")
        if self.expires_at_ns <= self.issued_at_ns:
            raise ValidationError("lease expiry must be later than issuance")
        object.__setattr__(self, "allocation", vector(self.allocation))
        if not any(self.allocation):
            raise ValidationError("lease allocation must contain a non-zero dimension")
        for capability in self.capabilities:
            require_identifier(capability, field="capability")
        for ancestor in self.ancestor_path:
            require_identifier(ancestor, field="ancestor_path item")
        if len(self.ancestor_path) > MAX_LINEAGE_DEPTH:
            raise ValidationError(
                f"lease ancestor_path exceeds the v1 limit of {MAX_LINEAGE_DEPTH}"
            )
        if len(set(self.ancestor_path)) != len(self.ancestor_path):
            raise ValidationError("lease ancestor_path must not contain a cycle")
        if self.lease_id in self.ancestor_path:
            raise ValidationError("lease ancestor_path must not contain the lease itself")
        if self.parent_id is None and self.ancestor_path:
            raise ValidationError("root lease ancestor_path must be empty")
        if self.parent_id is not None and (
            not self.ancestor_path or self.ancestor_path[-1] != self.parent_id
        ):
            raise ValidationError("child lease ancestor_path must end with parent_id")

    def unsigned_payload(self) -> WireDict:
        return {
            "type": self.WIRE_TYPE,
            "tenant_id": self.tenant_id,
            "envelope_id": self.envelope_id,
            "config_epoch": self.config_epoch,
            "lease_id": self.lease_id,
            "lineage_id": self.lineage_id,
            "parent_id": self.parent_id,
            "subject_id": self.subject_id,
            "warden_id": self.warden_id,
            "allocation": list(self.allocation),
            "capabilities": sorted(self.capabilities),
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "machine_digest": self.machine_digest,
            "ancestor_path": list(self.ancestor_path),
            "branch_epoch": self.branch_epoch,
            "issued_at_ns": self.issued_at_ns,
            "expires_at_ns": self.expires_at_ns,
            "key_id": self.key_id,
        }

    def to_dict(self) -> WireDict:
        return {**self.unsigned_payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: WireDict) -> Self:
        allowed = set(cls.__dataclass_fields__) - {"WIRE_TYPE"} | {"type"}
        _strict(data, allowed, "lease grant", required=allowed - {"parent_id"})
        if data.get("type") != cls.WIRE_TYPE:
            raise ValidationError("unsupported lease grant type")
        return cls(
            tenant_id=data["tenant_id"],
            envelope_id=data["envelope_id"],
            config_epoch=data["config_epoch"],
            lease_id=data["lease_id"],
            lineage_id=data["lineage_id"],
            parent_id=data.get("parent_id"),
            subject_id=data["subject_id"],
            warden_id=data["warden_id"],
            allocation=vector(data["allocation"]),
            capabilities=frozenset(_strings(data["capabilities"], "capabilities")),
            policy_id=data["policy_id"],
            policy_version=data["policy_version"],
            policy_digest=data["policy_digest"],
            machine_digest=data["machine_digest"],
            ancestor_path=_strings(data["ancestor_path"], "ancestor_path"),
            branch_epoch=data["branch_epoch"],
            issued_at_ns=data["issued_at_ns"],
            expires_at_ns=data["expires_at_ns"],
            key_id=data["key_id"],
            signature=data["signature"],
        )


@dataclass(frozen=True, slots=True)
class LeaseSnapshot:
    WIRE_TYPE: ClassVar[str] = "lets.lease-snapshot/v1"

    grant: LeaseGrant
    residual: ResourceVector
    current_state: str
    status: LeaseStatus
    sequence: int
    updated_at_ns: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "residual",
            vector(self.residual, dimensions=len(self.grant.allocation)),
        )
        require_identifier(self.current_state, field="current_state")
        _positive(self.sequence, "sequence", allow_zero=True)
        _positive(self.updated_at_ns, "updated_at_ns", allow_zero=True)
        if any(
            left > right for left, right in zip(self.residual, self.grant.allocation, strict=True)
        ):
            raise ValidationError("lease residual exceeds its signed allocation")

    def to_dict(self) -> WireDict:
        return {
            "type": self.WIRE_TYPE,
            "grant": self.grant.to_dict(),
            "residual": list(self.residual),
            "current_state": self.current_state,
            "status": self.status.value,
            "sequence": self.sequence,
            "updated_at_ns": self.updated_at_ns,
        }

    @classmethod
    def from_dict(cls, data: WireDict) -> Self:
        allowed = {
            "type",
            "grant",
            "residual",
            "current_state",
            "status",
            "sequence",
            "updated_at_ns",
        }
        _strict(data, allowed, "lease snapshot")
        if data.get("type") != cls.WIRE_TYPE:
            raise ValidationError("unsupported lease snapshot type")
        try:
            status = LeaseStatus(data["status"])
        except (TypeError, ValueError) as exc:
            raise ValidationError("lease snapshot status is invalid") from exc
        return cls(
            grant=LeaseGrant.from_dict(data["grant"]),
            residual=vector(data["residual"]),
            current_state=data["current_state"],
            status=status,
            sequence=data["sequence"],
            updated_at_ns=data["updated_at_ns"],
        )


@dataclass(frozen=True, slots=True)
class Receipt:
    WIRE_TYPE: ClassVar[str] = "lets.receipt/v1"

    tenant_id: str
    envelope_id: str
    config_epoch: int
    receipt_id: str
    request_id: str
    warden_id: str
    key_id: str
    policy_id: str
    policy_version: str
    policy_digest: str
    machine_digest: str
    lease_id: str
    lineage_id: str
    subject_id: str
    executor_audience: str
    transition: str
    source_state: str
    target_state: str
    cost: ResourceVector
    resulting_sequence: int
    evidence_digest: str | None
    nonce: str
    issued_at_ns: int
    expires_at_ns: int
    signature: str = ""

    def __post_init__(self) -> None:
        for field in (
            "tenant_id",
            "envelope_id",
            "receipt_id",
            "request_id",
            "policy_id",
            "policy_version",
            "lease_id",
            "lineage_id",
            "subject_id",
            "executor_audience",
            "transition",
            "source_state",
            "target_state",
            "nonce",
        ):
            require_identifier(getattr(self, field), field=field)
        require_warden_id(self.warden_id)
        require_key_id(self.key_id)
        require_digest(self.policy_digest, field="policy_digest")
        require_digest(self.machine_digest, field="machine_digest")
        if self.evidence_digest is not None:
            require_digest(self.evidence_digest, field="evidence_digest")
        _positive(self.config_epoch, "config_epoch")
        _positive(self.resulting_sequence, "resulting_sequence")
        _positive(self.issued_at_ns, "issued_at_ns", allow_zero=True)
        _positive(self.expires_at_ns, "expires_at_ns")
        if self.expires_at_ns <= self.issued_at_ns:
            raise ValidationError("receipt expiry must be later than issuance")
        object.__setattr__(self, "cost", vector(self.cost))

    def unsigned_payload(self) -> WireDict:
        return {
            "type": self.WIRE_TYPE,
            "tenant_id": self.tenant_id,
            "envelope_id": self.envelope_id,
            "config_epoch": self.config_epoch,
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "warden_id": self.warden_id,
            "key_id": self.key_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "machine_digest": self.machine_digest,
            "lease_id": self.lease_id,
            "lineage_id": self.lineage_id,
            "subject_id": self.subject_id,
            "executor_audience": self.executor_audience,
            "transition": self.transition,
            "source_state": self.source_state,
            "target_state": self.target_state,
            "cost": list(self.cost),
            "resulting_sequence": self.resulting_sequence,
            "evidence_digest": self.evidence_digest,
            "nonce": self.nonce,
            "issued_at_ns": self.issued_at_ns,
            "expires_at_ns": self.expires_at_ns,
        }

    def to_dict(self) -> WireDict:
        return {**self.unsigned_payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: WireDict) -> Self:
        allowed = set(cls.__dataclass_fields__) - {"WIRE_TYPE"} | {"type"}
        _strict(data, allowed, "receipt")
        if data.get("type") != cls.WIRE_TYPE:
            raise ValidationError("unsupported receipt type")
        values = dict(data)
        values.pop("type")
        values["cost"] = vector(values["cost"])
        return cls(**values)


@dataclass(frozen=True, slots=True)
class TransferVoucher:
    WIRE_TYPE: ClassVar[str] = "lets.transfer-voucher/v1"

    tenant_id: str
    envelope_id: str
    config_epoch: int
    transfer_id: str
    source_warden: str
    target_warden: str
    policy_id: str
    policy_version: str
    policy_digest: str
    sequence: int
    amount: ResourceVector
    issued_at_ns: int
    key_id: str
    signature: str = ""

    def __post_init__(self) -> None:
        for field in (
            "tenant_id",
            "envelope_id",
            "transfer_id",
            "policy_id",
            "policy_version",
        ):
            require_identifier(getattr(self, field), field=field)
        require_warden_id(self.source_warden, field="source_warden")
        require_warden_id(self.target_warden, field="target_warden")
        require_key_id(self.key_id)
        require_digest(self.policy_digest, field="policy_digest")
        if self.source_warden == self.target_warden:
            raise ValidationError("transfer source and target must differ")
        _positive(self.config_epoch, "config_epoch")
        _positive(self.sequence, "sequence")
        _positive(self.issued_at_ns, "issued_at_ns", allow_zero=True)
        object.__setattr__(self, "amount", vector(self.amount))
        if not any(self.amount):
            raise ValidationError("transfer amount must contain a non-zero dimension")

    def unsigned_payload(self) -> WireDict:
        return {
            "type": self.WIRE_TYPE,
            "tenant_id": self.tenant_id,
            "envelope_id": self.envelope_id,
            "config_epoch": self.config_epoch,
            "transfer_id": self.transfer_id,
            "source_warden": self.source_warden,
            "target_warden": self.target_warden,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "sequence": self.sequence,
            "amount": list(self.amount),
            "issued_at_ns": self.issued_at_ns,
            "key_id": self.key_id,
        }

    def to_dict(self) -> WireDict:
        return {**self.unsigned_payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: WireDict) -> Self:
        allowed = set(cls.__dataclass_fields__) - {"WIRE_TYPE"} | {"type"}
        _strict(data, allowed, "transfer voucher")
        if data.get("type") != cls.WIRE_TYPE:
            raise ValidationError("unsupported transfer voucher type")
        values = dict(data)
        values.pop("type")
        values["amount"] = vector(values["amount"])
        return cls(**values)


@dataclass(frozen=True, slots=True)
class TransferAck:
    WIRE_TYPE: ClassVar[str] = "lets.transfer-ack/v1"

    tenant_id: str
    envelope_id: str
    config_epoch: int
    transfer_id: str
    source_warden: str
    target_warden: str
    sequence: int
    voucher_digest: str
    accepted_at_ns: int
    contiguous_watermark: int
    key_id: str
    signature: str = ""

    def __post_init__(self) -> None:
        for field in (
            "tenant_id",
            "envelope_id",
            "transfer_id",
        ):
            require_identifier(getattr(self, field), field=field)
        require_warden_id(self.source_warden, field="source_warden")
        require_warden_id(self.target_warden, field="target_warden")
        require_key_id(self.key_id)
        require_digest(self.voucher_digest, field="voucher_digest")
        _positive(self.config_epoch, "config_epoch")
        _positive(self.sequence, "sequence")
        _positive(self.contiguous_watermark, "contiguous_watermark", allow_zero=True)
        _positive(self.accepted_at_ns, "accepted_at_ns", allow_zero=True)

    def unsigned_payload(self) -> WireDict:
        return {
            "type": self.WIRE_TYPE,
            "tenant_id": self.tenant_id,
            "envelope_id": self.envelope_id,
            "config_epoch": self.config_epoch,
            "transfer_id": self.transfer_id,
            "source_warden": self.source_warden,
            "target_warden": self.target_warden,
            "sequence": self.sequence,
            "voucher_digest": self.voucher_digest,
            "accepted_at_ns": self.accepted_at_ns,
            "contiguous_watermark": self.contiguous_watermark,
            "key_id": self.key_id,
        }

    def to_dict(self) -> WireDict:
        return {**self.unsigned_payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: WireDict) -> Self:
        allowed = set(cls.__dataclass_fields__) - {"WIRE_TYPE"} | {"type"}
        _strict(data, allowed, "transfer acknowledgement")
        if data.get("type") != cls.WIRE_TYPE:
            raise ValidationError("unsupported transfer acknowledgement type")
        values = dict(data)
        values.pop("type")
        return cls(**values)


@dataclass(frozen=True, slots=True)
class BranchRevocation:
    WIRE_TYPE: ClassVar[str] = "lets.branch-revocation/v1"

    tenant_id: str
    envelope_id: str
    config_epoch: int
    branch_lease_id: str
    lineage_id: str
    epoch: int
    issuer_warden: str
    issued_at_ns: int
    reason: str
    key_id: str
    signature: str = ""

    def __post_init__(self) -> None:
        for field in (
            "tenant_id",
            "envelope_id",
            "branch_lease_id",
            "lineage_id",
        ):
            require_identifier(getattr(self, field), field=field)
        require_warden_id(self.issuer_warden, field="issuer_warden")
        require_key_id(self.key_id)
        _positive(self.config_epoch, "config_epoch")
        _positive(self.epoch, "epoch")
        _positive(self.issued_at_ns, "issued_at_ns", allow_zero=True)
        if not self.reason or len(self.reason) > 1000:
            raise ValidationError("revocation reason must contain 1..1000 characters")

    def unsigned_payload(self) -> WireDict:
        return {
            "type": self.WIRE_TYPE,
            "tenant_id": self.tenant_id,
            "envelope_id": self.envelope_id,
            "config_epoch": self.config_epoch,
            "branch_lease_id": self.branch_lease_id,
            "lineage_id": self.lineage_id,
            "epoch": self.epoch,
            "issuer_warden": self.issuer_warden,
            "issued_at_ns": self.issued_at_ns,
            "reason": self.reason,
            "key_id": self.key_id,
        }

    def to_dict(self) -> WireDict:
        return {**self.unsigned_payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: WireDict) -> Self:
        allowed = set(cls.__dataclass_fields__) - {"WIRE_TYPE"} | {"type"}
        _strict(data, allowed, "branch revocation")
        if data.get("type") != cls.WIRE_TYPE:
            raise ValidationError("unsupported branch revocation type")
        values = dict(data)
        values.pop("type")
        return cls(**values)


@dataclass(frozen=True, slots=True)
class AuditRecord:
    sequence: int
    event_type: str
    tenant_id: str
    envelope_id: str
    entity_id: str | None
    actor_id: str
    occurred_at_ns: int
    details: WireDict
    previous_hash: str | None
    event_hash: str
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        _positive(self.sequence, "audit sequence", allow_zero=True)
        for field in ("event_type", "tenant_id", "envelope_id", "actor_id"):
            require_identifier(getattr(self, field), field=field)
        require_key_id(self.key_id)
        if self.entity_id is not None:
            require_identifier(self.entity_id, field="entity_id")
        if self.previous_hash is not None:
            require_digest(self.previous_hash, field="previous_hash")
        require_digest(self.event_hash, field="event_hash")
        _positive(self.occurred_at_ns, "occurred_at_ns", allow_zero=True)


@dataclass(frozen=True, slots=True)
class InvariantSnapshot:
    tenant_id: str
    envelope_id: str
    config_epoch: int
    initial_share: ResourceVector
    transferred_in: ResourceVector
    transferred_out: ResourceVector
    free_pool: ResourceVector
    lease_residual: ResourceVector
    consumed: ResourceVector
    checked_at_ns: int
    healthy: bool

    def __post_init__(self) -> None:
        require_identifier(self.tenant_id, field="tenant_id")
        require_identifier(self.envelope_id, field="envelope_id")
        _positive(self.config_epoch, "config_epoch")
        dimensions = len(vector(self.initial_share))
        for field in (
            "initial_share",
            "transferred_in",
            "transferred_out",
            "free_pool",
            "lease_residual",
            "consumed",
        ):
            object.__setattr__(
                self,
                field,
                vector(getattr(self, field), dimensions=dimensions),
            )
        _positive(self.checked_at_ns, "checked_at_ns", allow_zero=True)
