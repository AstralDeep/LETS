"""External monotonic anchors for protected-executor receipt claims.

An executor replay database is crash safe, but a byte-for-byte older copy is
also internally valid.  This module binds one replay database instance and its
append-only claim-chain head to a linearizable record outside the database's
rollback domain.  A claim is not authorized to reach the protected effect until
that record has acknowledged the committed database head.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol, Self, cast

from lets.authority import FileAuthorityAnchor, ProcessFileAuthorityAnchor
from lets.canonical import b64url_decode, b64url_encode, strict_json_loads
from lets.errors import StorageError, ValidationError
from lets.ids import require_identifier
from lets.vector import MAX_RESOURCE

EXECUTOR_ANCHOR_FORMAT = "LETS-EXECUTOR-AUTHORITY-ANCHOR/1"
_ZERO_HASH = bytes(32)


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    if value < minimum or value > MAX_RESOURCE:
        raise ValidationError(f"{field} is outside the supported signed 64-bit range")
    return value


def _digest(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be canonical base64url")
    try:
        decoded = b64url_decode(value)
    except ValueError as exc:
        raise ValidationError(f"{field} must be canonical base64url") from exc
    if len(decoded) != 32:
        raise ValidationError(f"{field} must contain exactly 32 bytes")
    return decoded


@dataclass(frozen=True, slots=True)
class ExecutorReplayIdentity:
    """The exact policy domain owned by one protected-executor replay store."""

    audience: str
    tenant_id: str
    envelope_id: str
    config_epoch: int
    executor_policy_sha256: bytes
    trust_registry_sha256: bytes

    def __post_init__(self) -> None:
        require_identifier(self.audience, field="executor replay audience")
        require_identifier(self.tenant_id, field="executor replay tenant_id")
        require_identifier(self.envelope_id, field="executor replay envelope_id")
        _integer(self.config_epoch, "executor replay config_epoch", minimum=1)
        if (
            not isinstance(self.executor_policy_sha256, bytes)
            or len(self.executor_policy_sha256) != 32
        ):
            raise ValidationError(
                "executor replay policy fingerprint must contain exactly 32 bytes"
            )
        if (
            not isinstance(self.trust_registry_sha256, bytes)
            or len(self.trust_registry_sha256) != 32
        ):
            raise ValidationError(
                "executor replay trust-registry fingerprint must contain exactly 32 bytes"
            )


@dataclass(frozen=True, slots=True)
class ExecutorAuthorityCheckpoint:
    """Identity-bound monotonic summary of committed executor claims."""

    identity: ExecutorReplayIdentity
    schema_version: int
    database_instance_id: bytes
    claim_sequence: int
    claim_digest: bytes
    clock_floor_ns: int | None

    def __post_init__(self) -> None:
        _integer(self.schema_version, "executor checkpoint schema_version", minimum=1)
        _integer(self.claim_sequence, "executor checkpoint claim_sequence")
        if self.clock_floor_ns is not None:
            _integer(self.clock_floor_ns, "executor checkpoint clock_floor_ns")
        if not isinstance(self.database_instance_id, bytes) or len(self.database_instance_id) != 32:
            raise ValidationError(
                "executor checkpoint database_instance_id must contain exactly 32 bytes"
            )
        if not isinstance(self.claim_digest, bytes) or len(self.claim_digest) != 32:
            raise ValidationError("executor checkpoint claim_digest must contain exactly 32 bytes")
        if self.claim_sequence == 0 and self.claim_digest != _ZERO_HASH:
            raise ValidationError("an empty executor claim chain must use the zero digest")

    @property
    def stable_identity(self) -> tuple[ExecutorReplayIdentity, int, bytes]:
        return (self.identity, self.schema_version, self.database_instance_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "format": EXECUTOR_ANCHOR_FORMAT,
            "audience": self.identity.audience,
            "tenant_id": self.identity.tenant_id,
            "envelope_id": self.identity.envelope_id,
            "config_epoch": self.identity.config_epoch,
            "executor_policy_sha256": b64url_encode(self.identity.executor_policy_sha256),
            "trust_registry_sha256": b64url_encode(self.identity.trust_registry_sha256),
            "schema_version": self.schema_version,
            "database_instance_id": b64url_encode(self.database_instance_id),
            "claim_sequence": self.claim_sequence,
            "claim_digest": b64url_encode(self.claim_digest),
            "clock_floor_ns": self.clock_floor_ns,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Self:
        expected = {
            "format",
            "audience",
            "tenant_id",
            "envelope_id",
            "config_epoch",
            "executor_policy_sha256",
            "trust_registry_sha256",
            "schema_version",
            "database_instance_id",
            "claim_sequence",
            "claim_digest",
            "clock_floor_ns",
        }
        if set(value) != expected:
            raise ValidationError(
                "executor authority fields do not match LETS-EXECUTOR-AUTHORITY-ANCHOR/1"
            )
        if value.get("format") != EXECUTOR_ANCHOR_FORMAT:
            raise ValidationError("unsupported executor authority anchor format")
        audience = value.get("audience")
        tenant_id = value.get("tenant_id")
        envelope_id = value.get("envelope_id")
        if not all(isinstance(item, str) for item in (audience, tenant_id, envelope_id)):
            raise ValidationError("executor authority identity fields must be strings")
        return cls(
            identity=ExecutorReplayIdentity(
                audience=cast(str, audience),
                tenant_id=cast(str, tenant_id),
                envelope_id=cast(str, envelope_id),
                config_epoch=_integer(
                    value.get("config_epoch"), "executor anchor config_epoch", minimum=1
                ),
                executor_policy_sha256=_digest(
                    value.get("executor_policy_sha256"),
                    "executor anchor executor_policy_sha256",
                ),
                trust_registry_sha256=_digest(
                    value.get("trust_registry_sha256"),
                    "executor anchor trust_registry_sha256",
                ),
            ),
            schema_version=_integer(
                value.get("schema_version"), "executor anchor schema_version", minimum=1
            ),
            database_instance_id=_digest(
                value.get("database_instance_id"), "executor anchor database_instance_id"
            ),
            claim_sequence=_integer(value.get("claim_sequence"), "executor anchor claim_sequence"),
            claim_digest=_digest(value.get("claim_digest"), "executor anchor claim_digest"),
            clock_floor_ns=(
                None
                if value.get("clock_floor_ns") is None
                else _integer(value.get("clock_floor_ns"), "executor anchor clock_floor_ns")
            ),
        )


class ExecutorAuthorityAnchor(Protocol):
    """Linearizable CAS record outside the executor database rollback domain."""

    def reconcile(
        self,
        checkpoint: ExecutorAuthorityCheckpoint,
        *,
        claim_digest_at: Callable[[int], bytes | None],
        initialize: bool = False,
    ) -> None: ...

    def read_current(self) -> ExecutorAuthorityCheckpoint: ...


def _requires_advance(
    anchored: ExecutorAuthorityCheckpoint,
    current: ExecutorAuthorityCheckpoint,
    *,
    claim_digest_at: Callable[[int], bytes | None],
) -> bool:
    """Validate one local branch and report whether the CAS head must advance."""

    if anchored.stable_identity != current.stable_identity:
        raise StorageError("executor authority anchor identity does not match this replay database")
    if current.claim_sequence < anchored.claim_sequence:
        raise StorageError("executor replay database is older than its monotonic authority anchor")
    if current.claim_sequence == anchored.claim_sequence:
        if current.claim_digest != anchored.claim_digest:
            raise StorageError("executor replay claim head diverges from its authority anchor")
        if anchored.clock_floor_ns is not None and (
            current.clock_floor_ns is None or current.clock_floor_ns < anchored.clock_floor_ns
        ):
            raise StorageError("executor replay clock floor moved behind its authority anchor")
        return current.clock_floor_ns != anchored.clock_floor_ns

    historical = (
        _ZERO_HASH if anchored.claim_sequence == 0 else claim_digest_at(anchored.claim_sequence)
    )
    if historical != anchored.claim_digest:
        raise StorageError("executor replay database does not extend the anchored claim history")
    if anchored.clock_floor_ns is not None and (
        current.clock_floor_ns is None or current.clock_floor_ns < anchored.clock_floor_ns
    ):
        raise StorageError("executor replay clock floor moved behind its authority anchor")
    return True


class FileExecutorAuthorityAnchor:
    """Serialized durable file anchor for executor claim heads.

    The file MUST reside in a failure/rollback domain independent from the
    replay database.  Production callers should normally use
    :class:`ProcessFileExecutorAuthorityAnchor`, which adds a hard deadline to
    otherwise uninterruptible filesystem calls.
    """

    def __init__(self, path: str | os.PathLike[str], *, timeout_s: float = 5.0) -> None:
        self._backend = FileAuthorityAnchor(path, timeout_s=timeout_s)

    @property
    def path(self) -> Path:
        return self._backend.path

    def _locked(self) -> AbstractContextManager[None]:
        return self._backend._locked()

    def _read_executor(self) -> ExecutorAuthorityCheckpoint:
        try:
            raw = self.path.read_bytes()
            decoded = strict_json_loads(raw)
        except FileNotFoundError as exc:
            raise StorageError(f"executor authority anchor does not exist: {self.path}") from exc
        except (OSError, UnicodeError, ValueError) as exc:
            raise StorageError(f"executor authority anchor is unreadable: {self.path}") from exc
        if not isinstance(decoded, Mapping):
            raise StorageError("executor authority anchor root must be an object")
        try:
            return ExecutorAuthorityCheckpoint.from_dict(decoded)
        except ValidationError as exc:
            raise StorageError("executor authority anchor is malformed") from exc

    def _write_executor(self, checkpoint: ExecutorAuthorityCheckpoint, *, exclusive: bool) -> None:
        # The base writer is deliberately format-agnostic at runtime: it
        # canonicalizes ``to_dict()``, fsyncs, and performs an atomic durable
        # move.  Reuse those reviewed durability mechanics without pretending an
        # executor checkpoint is a warden AuthorityCheckpoint.
        self._backend._write(checkpoint, exclusive=exclusive)  # type: ignore[arg-type]

    def reconcile(
        self,
        checkpoint: ExecutorAuthorityCheckpoint,
        *,
        claim_digest_at: Callable[[int], bytes | None],
        initialize: bool = False,
    ) -> None:
        with self._locked():
            if not self.path.exists():
                if not initialize:
                    raise StorageError(
                        "executor authority anchor is missing; refusing rollback-sensitive state"
                    )
                self._write_executor(checkpoint, exclusive=True)
                return
            anchored = self._read_executor()
            if _requires_advance(anchored, checkpoint, claim_digest_at=claim_digest_at):
                self._write_executor(checkpoint, exclusive=False)

    def read_current(self) -> ExecutorAuthorityCheckpoint:
        with self._locked():
            return self._read_executor()


class ProcessFileExecutorAuthorityAnchor:
    """Executor file anchor whose I/O runs behind a killable helper process."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        timeout_s: float = 5.0,
        helper_command: Sequence[str] | None = None,
    ) -> None:
        if helper_command is None:
            import sys

            command: Sequence[str] | None = (
                sys.executable,
                "-m",
                "lets.authority_helper",
                "--format",
                "executor",
            )
        else:
            command = helper_command
        self._timeout_s = float(timeout_s)
        self._backend = ProcessFileAuthorityAnchor(
            path, timeout_s=timeout_s, helper_command=command
        )

    @property
    def path(self) -> Path:
        return self._backend.path

    def close(self) -> None:
        """Stop the isolated I/O helper; safe to call repeatedly."""

        self._backend.close()

    def _invoke(self, request: Mapping[str, object], *, deadline: float) -> Mapping[str, Any]:
        return self._backend._invoke(request, deadline=deadline)

    @staticmethod
    def _executor_checkpoint(
        response: Mapping[str, Any],
    ) -> ExecutorAuthorityCheckpoint:
        value = response.get("checkpoint")
        if not isinstance(value, Mapping):
            raise StorageError("executor authority helper omitted its checkpoint")
        try:
            return ExecutorAuthorityCheckpoint.from_dict(value)
        except ValidationError as exc:
            raise StorageError("executor authority helper returned an invalid checkpoint") from exc

    def _reconcile_before_deadline(
        self,
        checkpoint: ExecutorAuthorityCheckpoint,
        *,
        claim_digest_at: Callable[[int], bytes | None],
        initialize: bool,
        deadline: float,
    ) -> None:
        while True:
            response = self._invoke({"operation": "read"}, deadline=deadline)
            if response["status"] == "missing":
                if not initialize:
                    raise StorageError(
                        "executor authority anchor is missing; refusing rollback-sensitive state"
                    )
                result = self._invoke(
                    {"operation": "initialize", "checkpoint": checkpoint.to_dict()},
                    deadline=deadline,
                )
                self._backend._check_deadline(
                    deadline,
                    operation="initialize",
                    request_flushed=True,
                    mutation_uncertain=True,
                )
                if result["status"] == "ok":
                    return
                if result["status"] == "conflict":
                    continue
                raise StorageError("executor authority anchor initialization failed")

            anchored = self._executor_checkpoint(response)
            self._backend._check_deadline(
                deadline,
                operation="read",
                request_flushed=True,
                mutation_uncertain=False,
            )
            if not _requires_advance(anchored, checkpoint, claim_digest_at=claim_digest_at):
                self._backend._check_deadline(
                    deadline,
                    operation="read",
                    request_flushed=True,
                    mutation_uncertain=False,
                )
                return
            self._backend._check_deadline(
                deadline,
                operation="read",
                request_flushed=True,
                mutation_uncertain=False,
            )
            result = self._invoke(
                {
                    "operation": "compare-and-set",
                    "expected": anchored.to_dict(),
                    "checkpoint": checkpoint.to_dict(),
                },
                deadline=deadline,
            )
            self._backend._check_deadline(
                deadline,
                operation="compare-and-set",
                request_flushed=True,
                mutation_uncertain=True,
            )
            if result["status"] == "ok":
                return
            if result["status"] != "conflict":
                raise StorageError("executor authority anchor compare-and-set failed")

    def reconcile(
        self,
        checkpoint: ExecutorAuthorityCheckpoint,
        *,
        claim_digest_at: Callable[[int], bytes | None],
        initialize: bool = False,
    ) -> None:
        self._reconcile_before_deadline(
            checkpoint,
            claim_digest_at=claim_digest_at,
            initialize=initialize,
            deadline=time.monotonic() + self._timeout_s,
        )

    def _confirm_before_deadline(
        self,
        checkpoint: ExecutorAuthorityCheckpoint,
        *,
        deadline: float,
    ) -> None:
        response = self._invoke(
            {"operation": "confirm", "checkpoint": checkpoint.to_dict()},
            deadline=deadline,
        )
        if response["status"] != "ok":
            raise StorageError("executor authority anchor durable confirmation failed")
        self._backend._check_deadline(
            deadline,
            operation="confirm",
            request_flushed=True,
            mutation_uncertain=True,
        )

    def confirm(self, checkpoint: ExecutorAuthorityCheckpoint) -> None:
        self._confirm_before_deadline(
            checkpoint,
            deadline=time.monotonic() + self._timeout_s,
        )

    def reconcile_and_confirm(
        self,
        checkpoint: ExecutorAuthorityCheckpoint,
        *,
        claim_digest_at: Callable[[int], bytes | None],
        initialize: bool = False,
    ) -> None:
        """Reconcile and durably confirm within one configured deadline."""

        deadline = time.monotonic() + self._timeout_s
        self._reconcile_before_deadline(
            checkpoint,
            claim_digest_at=claim_digest_at,
            initialize=initialize,
            deadline=deadline,
        )
        self._confirm_before_deadline(checkpoint, deadline=deadline)

    def read_current(self) -> ExecutorAuthorityCheckpoint:
        deadline = time.monotonic() + self._timeout_s
        response = self._invoke(
            {"operation": "read"},
            deadline=deadline,
        )
        if response["status"] == "missing":
            raise StorageError(
                "executor authority anchor is missing; refusing rollback-sensitive state"
            )
        checkpoint = self._executor_checkpoint(response)
        self._backend._check_deadline(
            deadline,
            operation="read",
            request_flushed=True,
            mutation_uncertain=False,
        )
        return checkpoint


def executor_identity_digest(identity: ExecutorReplayIdentity) -> bytes:
    """Stable diagnostic digest for logs/configuration comparisons."""

    return sha256(
        (
            f"{identity.audience}\0{identity.tenant_id}\0"
            f"{identity.envelope_id}\0{identity.config_epoch}\0"
            f"{identity.executor_policy_sha256.hex()}\0"
            f"{identity.trust_registry_sha256.hex()}"
        ).encode()
    ).digest()


__all__ = [
    "EXECUTOR_ANCHOR_FORMAT",
    "ExecutorAuthorityAnchor",
    "ExecutorAuthorityCheckpoint",
    "ExecutorReplayIdentity",
    "FileExecutorAuthorityAnchor",
    "ProcessFileExecutorAuthorityAnchor",
    "executor_identity_digest",
]
