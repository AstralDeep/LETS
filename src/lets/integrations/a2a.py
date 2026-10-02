"""Optional host-neutral mapping from A2A v1.0.1 task operations to LETS leases, receipts and
revocation, built on ReplicaAuthorizer with task storage behind a host-supplied TaskLedger.
See docs/adapters/a2a.md for the identity, delegation and cancellation contract.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from threading import RLock
from typing import Any, Protocol

from lets.canonical import canonical_json
from lets.errors import ConflictError, ExpiredError, PolicyError, ValidationError
from lets.ids import require_identifier
from lets.integrations.ports import ReplicaAuthorizer, WireObject
from lets.models import IdentityContext
from lets.vector import ResourceVector

MAPPING_VERSION = "lets.a2a-profile/v1"


@dataclass(frozen=True, slots=True)
class A2ARevision:
    version: str
    commit: str


PINNED_REVISION = A2ARevision("1.0.1", "3303592588e388e62e0f69f701af531d2f4e3991")


class TaskState(Enum):
    SUBMITTED = "TASK_STATE_SUBMITTED"
    WORKING = "TASK_STATE_WORKING"
    COMPLETED = "TASK_STATE_COMPLETED"
    FAILED = "TASK_STATE_FAILED"
    CANCELED = "TASK_STATE_CANCELED"
    REJECTED = "TASK_STATE_REJECTED"


TERMINAL_STATES = frozenset(
    {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELED, TaskState.REJECTED}
)


class A2AProfileError(Exception):
    def __init__(self, name: str, code: int, message: str) -> None:
        super().__init__(message)
        self.name = name
        self.code = code


def _not_found() -> A2AProfileError:
    return A2AProfileError("TaskNotFoundError", -32001, "task not found")


def _not_cancelable(state: TaskState) -> A2AProfileError:
    return A2AProfileError(
        "TaskNotCancelableError", -32002, f"task is already terminal ({state.value})"
    )


def _unsupported(message: str) -> A2AProfileError:
    return A2AProfileError("UnsupportedOperationError", -32004, message)


@dataclass(frozen=True, slots=True)
class TaskKey:
    tenant_id: str
    principal: str
    task_id: str


@dataclass(frozen=True, slots=True)
class TaskRecord:
    key: TaskKey
    context_id: str
    subject_id: str
    lease_id: str
    admission_digest: str
    state: TaskState = TaskState.SUBMITTED
    parent: TaskKey | None = None
    cancel_requested: bool = False
    reason: str | None = None
    revoked_at_ns: int | None = None
    receipt_horizon_ns: int = 0
    completion_requested: bool = False
    parent_lease_id: str = ""
    allocation: ResourceVector = ()
    capabilities: frozenset[str] = frozenset()
    ttl_ns: int = 0


class TaskLedger(Protocol):
    def get(self, key: TaskKey) -> TaskRecord | None: ...

    def put_if_absent(self, record: TaskRecord) -> TaskRecord: ...

    def update(self, key: TaskKey, mutate: Callable[[TaskRecord], TaskRecord]) -> TaskRecord: ...

    def children_of(self, key: TaskKey) -> tuple[TaskRecord, ...]: ...


@dataclass(slots=True)
class InMemoryTaskLedger:
    _records: dict[TaskKey, TaskRecord] = field(default_factory=dict)
    _lock: RLock = field(default_factory=RLock)

    def get(self, key: TaskKey) -> TaskRecord | None:
        with self._lock:
            return self._records.get(key)

    def put_if_absent(self, record: TaskRecord) -> TaskRecord:
        with self._lock:
            return self._records.setdefault(record.key, record)

    def update(self, key: TaskKey, mutate: Callable[[TaskRecord], TaskRecord]) -> TaskRecord:
        with self._lock:
            current = self._records.get(key)
            if current is None:
                raise _not_found()
            updated = mutate(current)
            self._records[key] = updated
            return updated

    def children_of(self, key: TaskKey) -> tuple[TaskRecord, ...]:
        with self._lock:
            return tuple(r for r in self._records.values() if r.parent == key)


@dataclass(frozen=True, slots=True)
class AudienceBinding:
    audiences: Mapping[str, str]

    def __post_init__(self) -> None:
        for executor, audience in self.audiences.items():
            require_identifier(executor, field="verified executor id")
            require_identifier(audience, field="executor audience")

    def resolve(self, verified_executor_id: str) -> str:
        audience = self.audiences.get(verified_executor_id)
        if audience is None:
            raise PolicyError("executor identity has no audience binding")
        return audience


def _identity(identity: IdentityContext) -> IdentityContext:
    if not isinstance(identity, IdentityContext):
        raise ValidationError("identity must be a verified IdentityContext, not request data")
    return identity


def derive_id(
    kind: str,
    key: TaskKey,
    context_id: str,
    discriminator: str = "",
    *,
    prefix: str = "a2a1",
) -> str:
    digest = hashlib.sha256(
        canonical_json(
            {
                "type": MAPPING_VERSION,
                "kind": kind,
                "tenant": key.tenant_id,
                "principal": key.principal,
                "task": key.task_id,
                "context": context_id,
                "discriminator": discriminator,
            }
        )
    ).hexdigest()
    return f"{prefix}.{kind}.{digest[:48]}"


def content_digest(content: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(dict(content))).hexdigest()


def _admission_digest(
    content: Mapping[str, Any],
    *,
    subject_id: str,
    parent_lease_id: str,
    allocation: ResourceVector,
    capabilities: Iterable[str],
    ttl_ns: int,
) -> str:
    return content_digest(
        {
            "content": content_digest(content),
            "subject": subject_id,
            "parent_lease": parent_lease_id,
            "allocation": list(allocation),
            "capabilities": sorted(capabilities),
            "ttl_ns": ttl_ns,
        }
    )


def task_to_a2a(record: TaskRecord) -> dict[str, Any]:
    return {
        "id": record.key.task_id,
        "contextId": record.context_id,
        "status": {"state": record.state.value},
        "metadata": {
            "lets": {
                "mapping": MAPPING_VERSION,
                "a2a_revision": PINNED_REVISION.version,
                "cancel_requested": record.cancel_requested,
                "reason": record.reason,
                "revoked_at_ns": record.revoked_at_ns,
                "known_receipt_horizon_ns": record.receipt_horizon_ns,
            }
        },
    }


class A2ATaskProfile:
    def __init__(
        self,
        authorizer: ReplicaAuthorizer,
        ledger: TaskLedger,
        audiences: AudienceBinding,
    ) -> None:
        self.authorizer = authorizer
        self.ledger = ledger
        self.audiences = audiences

    def admit(
        self,
        identity: IdentityContext,
        *,
        task_id: str,
        context_id: str,
        content: Mapping[str, Any],
        subject_id: str,
        parent_lease_id: str,
        allocation: ResourceVector,
        capabilities: Iterable[str],
        ttl_ns: int,
    ) -> TaskRecord:
        return self._admit(
            identity,
            task_id=task_id,
            context_id=context_id,
            content=content,
            subject_id=subject_id,
            parent_lease_id=parent_lease_id,
            parent=None,
            allocation=allocation,
            capabilities=capabilities,
            ttl_ns=ttl_ns,
        )

    def delegate(
        self,
        identity: IdentityContext,
        *,
        parent_key: TaskKey,
        task_id: str,
        context_id: str,
        content: Mapping[str, Any],
        subject_id: str,
        allocation: ResourceVector,
        capabilities: Iterable[str],
        ttl_ns: int,
    ) -> TaskRecord:
        identity = self._verified(identity)
        if parent_key.tenant_id != identity.tenant_id:
            raise _not_found()
        parent = self.ledger.get(parent_key)
        if parent is None:
            raise _not_found()
        parent = self._ensure_lease(parent)
        if parent.subject_id != identity.subject_id:
            raise PolicyError("only the parent task's executing subject may delegate")
        if parent.state in TERMINAL_STATES or parent.cancel_requested:
            raise PolicyError("parent task is not accepting delegation")
        return self._admit(
            identity,
            task_id=task_id,
            context_id=context_id,
            content=content,
            subject_id=subject_id,
            parent_lease_id=parent.lease_id,
            parent=parent_key,
            allocation=allocation,
            capabilities=capabilities,
            ttl_ns=ttl_ns,
        )

    def _admit(
        self,
        identity: IdentityContext,
        *,
        task_id: str,
        context_id: str,
        content: Mapping[str, Any],
        subject_id: str,
        parent_lease_id: str,
        parent: TaskKey | None,
        allocation: ResourceVector,
        capabilities: Iterable[str],
        ttl_ns: int,
    ) -> TaskRecord:
        identity = self._verified(identity)
        require_identifier(task_id, field="task id")
        require_identifier(context_id, field="context id")
        capabilities = frozenset(capabilities)
        key = TaskKey(identity.tenant_id, identity.subject_id, task_id)
        digest = _admission_digest(
            content,
            subject_id=subject_id,
            parent_lease_id=parent_lease_id,
            allocation=allocation,
            capabilities=capabilities,
            ttl_ns=ttl_ns,
        )
        pending = TaskRecord(
            key=key,
            context_id=context_id,
            subject_id=subject_id,
            lease_id="",
            admission_digest=digest,
            parent=parent,
            parent_lease_id=parent_lease_id,
            allocation=tuple(allocation),
            capabilities=capabilities,
            ttl_ns=ttl_ns,
        )
        bound = self._same_admission(self.ledger.put_if_absent(pending), context_id, digest)
        return self._ensure_lease(bound)

    def _verified(self, identity: IdentityContext) -> IdentityContext:
        identity = _identity(identity)
        if identity.tenant_id != self.authorizer.profile.tenant_id:
            raise PolicyError("identity tenant does not match the configured LETS tenant")
        return identity

    def _ensure_lease(self, record: TaskRecord) -> TaskRecord:
        if record.lease_id or record.state in TERMINAL_STATES:
            return record
        try:
            grant = self.authorizer.replicate(
                request_id=derive_id("spawn", record.key, record.context_id),
                parent_lease_id=record.parent_lease_id,
                replica_id=record.subject_id,
                allocation=record.allocation,
                capabilities=record.capabilities,
                ttl_ns=record.ttl_ns,
            )
        except (PolicyError, ValidationError, ExpiredError):
            self._reject(record.key)
            raise
        lease_id = str(grant["lease_id"])

        def bind(current: TaskRecord) -> TaskRecord:
            if current.lease_id:
                return current
            return replace(current, lease_id=lease_id)

        return self.ledger.update(record.key, bind)

    def _reject(self, key: TaskKey) -> None:
        def reject(current: TaskRecord) -> TaskRecord:
            if current.lease_id or current.state in TERMINAL_STATES:
                return current
            return replace(current, state=TaskState.REJECTED, reason="admission_denied")

        self.ledger.update(key, reject)

    @staticmethod
    def _same_admission(record: TaskRecord, context_id: str, digest: str) -> TaskRecord:
        if record.context_id != context_id:
            raise ConflictError("task id is already bound to a different context")
        if record.admission_digest != digest:
            raise ConflictError("task id was already admitted with different content or authority")
        return record

    def get_task(self, identity: IdentityContext, task_id: str) -> TaskRecord:
        return self._owned(identity, task_id)

    def subscribe(self, identity: IdentityContext, task_id: str) -> TaskRecord:
        record = self._owned(identity, task_id)
        if record.state in TERMINAL_STATES:
            raise _unsupported(f"task is terminal ({record.state.value})")
        return record

    def _owned(self, identity: IdentityContext, task_id: str) -> TaskRecord:
        identity = self._verified(identity)
        record = self.ledger.get(TaskKey(identity.tenant_id, identity.subject_id, task_id))
        if record is None:
            raise _not_found()
        return record

    def authorize_effect(
        self,
        identity: IdentityContext,
        *,
        task_id: str,
        effect_id: str,
        transition: str,
        verified_executor_id: str,
        expected_state: str | None = None,
        expected_sequence: int | None = None,
    ) -> WireObject:
        record = self._owned(identity, task_id)
        require_identifier(effect_id, field="effect id")
        if (
            record.state in TERMINAL_STATES
            or record.cancel_requested
            or record.completion_requested
        ):
            raise PolicyError("task is not accepting new effects")
        record = self._ensure_lease(record)
        audience = self.audiences.resolve(verified_executor_id)
        try:
            receipt = self.authorizer.authorize_effect(
                request_id=derive_id("effect", record.key, record.context_id, effect_id),
                lease_id=record.lease_id,
                transition=transition,
                executor_audience=audience,
                nonce=derive_id("nonce", record.key, record.context_id, effect_id),
                expected_state=expected_state,
                expected_sequence=expected_sequence,
            )
        except ExpiredError:
            self._mark_failed(record.key, "authority_expired")
            raise
        horizon = int(receipt["expires_at_ns"])

        def note(current: TaskRecord) -> TaskRecord:
            moved = max(current.receipt_horizon_ns, horizon)
            if current.state in (TaskState.SUBMITTED,):
                return replace(current, state=TaskState.WORKING, receipt_horizon_ns=moved)
            return replace(current, receipt_horizon_ns=moved)

        self.ledger.update(record.key, note)
        return receipt

    def _mark_failed(self, key: TaskKey, reason: str) -> None:
        def fail(current: TaskRecord) -> TaskRecord:
            if current.state in TERMINAL_STATES:
                return current
            return replace(current, state=TaskState.FAILED, reason=reason)

        self.ledger.update(key, fail)

    def complete_task(self, identity: IdentityContext, task_id: str) -> TaskRecord:
        record = self._owned(identity, task_id)

        def begin(current: TaskRecord) -> TaskRecord:
            if current.state is TaskState.COMPLETED:
                return current
            if current.state in TERMINAL_STATES or current.cancel_requested:
                raise ConflictError("task is canceled, canceling, or already failed")
            return replace(current, completion_requested=True)

        started = self.ledger.update(record.key, begin)
        if started.state is TaskState.COMPLETED:
            return started
        started = self._ensure_lease(started)
        self.authorizer.close(
            started.lease_id,
            request_id=derive_id("close", started.key, started.context_id),
        )

        def finish(current: TaskRecord) -> TaskRecord:
            if current.state is TaskState.COMPLETED:
                return current
            if current.state in TERMINAL_STATES or current.cancel_requested:
                raise ConflictError("task is canceled, canceling, or already failed")
            return replace(current, state=TaskState.COMPLETED, completion_requested=False)

        return self.ledger.update(started.key, finish)

    def cancel_task(
        self,
        identity: IdentityContext,
        task_id: str,
        *,
        reason: str = "a2a.cancel",
    ) -> TaskRecord:
        record = self._owned(identity, task_id)

        def intent(current: TaskRecord) -> TaskRecord:
            if current.state is TaskState.CANCELED:
                return current
            if current.state in TERMINAL_STATES:
                raise _not_cancelable(current.state)
            return replace(current, cancel_requested=True)

        marked = self.ledger.update(record.key, intent)
        if marked.state is TaskState.CANCELED:
            self._cascade(marked.key)
            return marked
        marked = self._ensure_lease(marked)
        revocation = self.authorizer.revoke(
            marked.lease_id,
            request_id=derive_id("cancel", marked.key, marked.context_id),
            reason=reason,
        )
        revoked_at = int(revocation["issued_at_ns"])

        def canceled(current: TaskRecord) -> TaskRecord:
            return replace(
                current,
                state=TaskState.CANCELED,
                cancel_requested=False,
                reason=reason,
                revoked_at_ns=revoked_at,
            )

        result = self.ledger.update(marked.key, canceled)
        self._cascade(result.key)
        return result

    def _cascade(self, key: TaskKey) -> None:
        for child in self.ledger.children_of(key):

            def mirror(current: TaskRecord) -> TaskRecord:
                if current.state in TERMINAL_STATES:
                    return current
                return replace(current, state=TaskState.CANCELED, reason="parent_canceled")

            self.ledger.update(child.key, mirror)
            self._cascade(child.key)
