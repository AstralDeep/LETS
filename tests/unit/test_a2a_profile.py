"""Deterministic conformance fixtures for lets.integrations.a2a, run against a real WardenService,
ManualClock and ReceiptVerifier. They also cover examples/a2a_host.py.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ConflictError, ExpiredError, PolicyError, ReplayError, ValidationError
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.integrations import ReplicaAuthorizer, ReplicaProfile
from lets.integrations.a2a import (
    PINNED_REVISION,
    A2AProfileError,
    A2ATaskProfile,
    AudienceBinding,
    InMemoryTaskLedger,
    TaskKey,
    TaskRecord,
    TaskState,
    derive_id,
    task_to_a2a,
)
from lets.models import IdentityContext, Receipt
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage

TENANT = "tenant"
POLICY = PolicySpec(
    policy_id="a2a-policy",
    policy_version="v1",
    dimensions=(ResourceDimension("operations", "count"),),
    machine=MachineSpec(
        machine_id="worker",
        initial_state="ready",
        transitions=(
            TransitionSpec("act", "ready", "ready", (2,), "worker.act"),
            TransitionSpec("audit", "ready", "ready", (1,), "worker.audit"),
        ),
    ),
    max_lease_ttl_ns=10_000,
    receipt_ttl_ns=100,
    max_clock_uncertainty_ns=5,
    transfer_gap_window=4,
)
CONTENT = {"message": {"messageId": "m-1", "parts": [{"text": "do the thing"}]}}


DELEGATOR = IdentityContext("agent-1", TENANT, frozenset())


def _client_identity(subject: str = "client-a") -> IdentityContext:
    return IdentityContext(subject, TENANT, frozenset())


@dataclass
class ServiceClient:
    service: WardenService
    subjects: dict[str, str] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)
    fail_revoke: int = 0
    lose_spawn_reply: int = 0
    lose_close_reply: int = 0
    fail_spawn: int = 0
    fail_close: int = 0
    during_spawn: Callable[[], None] | None = None

    def _acting(self, lease_id: str | None) -> IdentityContext:
        subject = "host" if lease_id is None else self.subjects[lease_id]
        scopes = frozenset({"lets.lease.issue", "lets.lease.manage", "lets.branch.revoke"})
        return IdentityContext(subject, TENANT, scopes)

    def issue_root(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append("issue_root")
        grant = self.service.issue_root(
            request_id=payload["request_id"],
            identity=self._acting(None),
            tenant_id=payload["tenant_id"],
            envelope_id=payload["envelope_id"],
            subject_id=payload["subject_id"],
            allocation=tuple(payload["allocation"]),
            capabilities=set(payload["capabilities"]),
            policy_digest=payload["policy_digest"],
            ttl_ns=payload["ttl_ns"],
        )
        self.subjects[grant.lease_id] = grant.subject_id
        return grant.to_dict()

    def spawn(self, parent_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if self.fail_spawn:
            self.fail_spawn -= 1
            raise TimeoutError("spawn never reached the warden")
        self.calls.append("spawn")
        grant = self.service.spawn(
            request_id=payload["request_id"],
            identity=self._acting(parent_id),
            parent_id=parent_id,
            subject_id=payload["subject_id"],
            allocation=tuple(payload["allocation"]),
            capabilities=set(payload["capabilities"]),
            ttl_ns=payload["ttl_ns"],
            policy_digest=payload.get("policy_digest"),
        )
        self.subjects[grant.lease_id] = grant.subject_id
        if self.during_spawn is not None:
            hook, self.during_spawn = self.during_spawn, None
            hook()
        if self.lose_spawn_reply:
            self.lose_spawn_reply -= 1
            raise TimeoutError("spawn committed but the reply was lost")
        return grant.to_dict()

    def authorize(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append("authorize")
        receipt = self.service.authorize(
            request_id=payload["request_id"],
            identity=self._acting(lease_id),
            lease_id=lease_id,
            transition=payload["transition"],
            audience=payload["executor_audience"],
            nonce=payload["nonce"],
            expected_state=payload.get("expected_state"),
            expected_sequence=payload.get("expected_sequence"),
        )
        return receipt.to_dict()

    def renew(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        raise NotImplementedError

    def quiesce(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        raise NotImplementedError

    def resume(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        raise NotImplementedError

    def close_lease(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if self.fail_close:
            self.fail_close -= 1
            raise ConflictError("close did not reach the warden")
        self.calls.append("close")
        snapshot = self.service.close(
            request_id=payload["request_id"],
            identity=self._acting(lease_id),
            lease_id=lease_id,
        )
        if self.lose_close_reply:
            self.lose_close_reply -= 1
            raise TimeoutError("close committed but the reply was lost")
        return snapshot.to_dict()

    def revoke_branch(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append("revoke")
        if self.fail_revoke:
            self.fail_revoke -= 1
            raise ConflictError("transient revoke failure")
        revocation = self.service.revoke_branch(
            request_id=payload["request_id"],
            identity=self._acting(lease_id),
            lease_id=lease_id,
            reason=payload["reason"],
        )
        return revocation.to_dict()


@dataclass
class FlakyLedger(InMemoryTaskLedger):
    fail_key: TaskKey | None = None

    def update(self, key: TaskKey, mutate: Callable[[TaskRecord], TaskRecord]) -> TaskRecord:
        if key == self.fail_key:
            self.fail_key = None
            raise RuntimeError("ledger unavailable")
        return super().update(key, mutate)


@dataclass
class Rig:
    profile: A2ATaskProfile
    client: ServiceClient
    service: WardenService
    clock: ManualClock
    registry: PublicKeyRegistry
    ledger: FlakyLedger
    root_lease_id: str
    tmp: Path

    def admit(self, task_id: str = "task-1", **overrides: Any) -> Any:
        arguments: dict[str, Any] = {
            "task_id": task_id,
            "context_id": "ctx-1",
            "content": CONTENT,
            "subject_id": "agent-1",
            "parent_lease_id": self.root_lease_id,
            "allocation": (30,),
            "capabilities": {"worker.act"},
            "ttl_ns": 1_500,
        }
        arguments.update(overrides)
        return self.profile.admit(_client_identity(), **arguments)

    def verifier(self, audience: str) -> ReceiptVerifier:
        store = SQLiteReceiptReplayStore.initialize(
            self.tmp / f"{audience}.db", allow_unanchored=True
        )
        policy = ExecutorPolicy(
            audience=audience,
            tenant_id=TENANT,
            envelope_id="envelope",
            trusted_wardens=frozenset({"warden-a"}),
            max_clock_uncertainty_ns=5,
        )
        return ReceiptVerifier(self.registry, store, policy, clock=self.clock)

    def effect(self, task_id: str = "task-1", effect_id: str = "effect-1") -> Any:
        return self.profile.authorize_effect(
            _client_identity(),
            task_id=task_id,
            effect_id=effect_id,
            transition="act",
            verified_executor_id="spiffe://exec/a",
            expected_state="ready",
        )


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    clock = ManualClock(1_000_000, 5)
    registry = PublicKeyRegistry()
    signer = Ed25519Signer.generate("warden-a")
    store = SQLiteStorage.initialize(
        tmp_path / "warden.db",
        "warden-a",
        (200,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id=TENANT,
        envelope_id="envelope",
        initial_local_share=(200,),
        receipt_ttl_ns=100,
        max_clock_uncertainty_ns=5,
        transfer_gap_window=4,
    )
    registry.register_signer(signer)
    service = WardenService(store, signer=signer, clock=clock, trust_registry=registry)
    service.register_policy(POLICY)
    client = ServiceClient(service)
    replicas = ReplicaAuthorizer(
        client,
        ReplicaProfile(
            tenant_id=TENANT,
            envelope_id="envelope",
            policy_digest=POLICY.digest,
            default_allocation=(100,),
            default_capabilities=frozenset({"worker.act", "worker.audit"}),
            default_ttl_ns=2_000,
        ),
    )
    root = replicas.provision(request_id="root", replica_id="host", allocation=(100,), ttl_ns=2_000)
    ledger = FlakyLedger()
    profile = A2ATaskProfile(
        replicas,
        ledger,
        AudienceBinding({"spiffe://exec/a": "executor-a", "spiffe://exec/b": "executor-b"}),
    )
    yield Rig(profile, client, service, clock, registry, ledger, root["lease_id"], tmp_path)
    store.close()


def test_pins_official_a2a_revision() -> None:
    assert PINNED_REVISION.version == "1.0.1"
    assert PINNED_REVISION.commit == "3303592588e388e62e0f69f701af531d2f4e3991"
    record = TaskRecord(
        key=TaskKey(TENANT, "client-a", "t"),
        context_id="c",
        subject_id="s",
        lease_id="l",
        admission_digest="sha256:" + "0" * 64,
    )
    task = task_to_a2a(record)
    assert task["status"]["state"] == "TASK_STATE_SUBMITTED"
    assert task["metadata"]["lets"]["a2a_revision"] == "1.0.1"
    assert task["metadata"]["lets"]["mapping"] == "lets.a2a-profile/v1"


def test_ids_bind_verified_identity_and_ignore_asserted_json(rig: Rig) -> None:
    mine = TaskKey(TENANT, "client-a", "task-1")
    other = TaskKey(TENANT, "client-b", "task-1")
    assert derive_id("spawn", mine, "ctx-1") != derive_id("spawn", other, "ctx-1")
    assert derive_id("spawn", mine, "ctx-1") != derive_id("spawn", mine, "ctx-2")
    assert derive_id("spawn", mine, "ctx-1") == derive_id("spawn", mine, "ctx-1")

    forged = {"message": CONTENT["message"], "principal": "admin", "tenant": "other"}
    record = rig.admit(content=forged)
    assert record.key.principal == "client-a"

    with pytest.raises(ValidationError, match="verified IdentityContext"):
        rig.profile.admit(
            {"subject_id": "admin"},  # type: ignore[arg-type]
            task_id="t",
            context_id="c",
            content=CONTENT,
            subject_id="agent-9",
            parent_lease_id=rig.root_lease_id,
            allocation=(1,),
            capabilities={"worker.act"},
            ttl_ns=100,
        )


def test_duplicate_delivery_admits_once_and_returns_the_same_receipt(rig: Rig) -> None:
    first = rig.admit()
    second = rig.admit()
    assert second == first
    assert rig.client.calls.count("spawn") == 1

    receipt = rig.effect()
    again = rig.effect()
    assert again == receipt

    verifier = rig.verifier("executor-a")
    verifier.verify_and_claim(Receipt.from_dict(dict(receipt)))
    with pytest.raises(ReplayError):
        verifier.verify_and_claim(Receipt.from_dict(dict(again)))


def test_reconnect_status_lookup_hides_foreign_tasks_and_rejects_terminal_subscribe(
    rig: Rig,
) -> None:
    admitted = rig.admit()
    assert rig.profile.get_task(_client_identity(), "task-1") == admitted
    assert rig.profile.subscribe(_client_identity(), "task-1") == admitted

    with pytest.raises(A2AProfileError) as foreign:
        rig.profile.get_task(_client_identity("client-b"), "task-1")
    assert (foreign.value.name, foreign.value.code) == ("TaskNotFoundError", -32001)

    rig.effect()
    rig.profile.complete_task(_client_identity(), "task-1")
    state = rig.profile.get_task(_client_identity(), "task-1")
    assert state.state is TaskState.COMPLETED
    with pytest.raises(A2AProfileError) as terminal:
        rig.profile.subscribe(_client_identity(), "task-1")
    assert terminal.value.code == -32004


def test_changed_content_context_or_authority_conflicts_without_a_new_lease(rig: Rig) -> None:
    rig.admit()
    changed = {"message": {"messageId": "m-1", "parts": [{"text": "something else"}]}}
    with pytest.raises(ConflictError, match="different content"):
        rig.admit(content=changed)
    with pytest.raises(ConflictError, match="different content or authority"):
        rig.admit(allocation=(31,))
    with pytest.raises(ConflictError, match="different context"):
        rig.admit(context_id="ctx-2")
    assert rig.client.calls.count("spawn") == 1


def test_wrong_audience_is_refused_by_host_policy_and_by_the_executor(rig: Rig) -> None:
    rig.admit()
    before = rig.client.calls.count("authorize")
    with pytest.raises(PolicyError, match="no audience binding"):
        rig.profile.authorize_effect(
            _client_identity(),
            task_id="task-1",
            effect_id="e-unknown",
            transition="act",
            verified_executor_id="https://agent.example/.well-known/agent-card.json",
        )
    assert rig.client.calls.count("authorize") == before

    receipt = Receipt.from_dict(dict(rig.effect()))
    assert receipt.executor_audience == "executor-a"
    with pytest.raises(PolicyError, match="audience"):
        rig.verifier("executor-b").verify_and_claim(receipt)


def test_delegation_is_attenuated_by_lets_not_by_the_agent_card(rig: Rig) -> None:
    parent = rig.admit()
    delegator = IdentityContext("agent-1", TENANT, frozenset())

    def delegate(task_id: str, **overrides: Any) -> Any:
        arguments: dict[str, Any] = {
            "parent_key": parent.key,
            "task_id": task_id,
            "context_id": "ctx-1",
            "content": CONTENT,
            "subject_id": "agent-2",
            "allocation": (10,),
            "capabilities": {"worker.act"},
            "ttl_ns": 1_000,
        }
        arguments.update(overrides)
        return rig.profile.delegate(delegator, **arguments)

    child = delegate("child-ok")
    assert child.parent == parent.key

    with pytest.raises(PolicyError, match="not attenuated"):
        delegate("child-wide", capabilities={"worker.act", "worker.audit"}, subject_id="agent-3")
    with pytest.raises(PolicyError, match="residual does not cover"):
        delegate("child-big", allocation=(31,), subject_id="agent-4")
    with pytest.raises(PolicyError, match="executing subject"):
        rig.profile.delegate(
            IdentityContext("impostor", TENANT, frozenset()),
            parent_key=parent.key,
            task_id="child-x",
            context_id="ctx-1",
            content=CONTENT,
            subject_id="agent-5",
            allocation=(1,),
            capabilities={"worker.act"},
            ttl_ns=100,
        )


def test_parent_expiry_bounds_the_child_and_fails_the_task_closed(rig: Rig) -> None:
    parent = rig.admit()
    child = rig.profile.delegate(
        DELEGATOR,
        parent_key=parent.key,
        task_id="child-1",
        context_id="ctx-1",
        content=CONTENT,
        subject_id="agent-2",
        allocation=(10,),
        capabilities={"worker.act"},
        ttl_ns=9_000,
    )
    parent_expiry = rig.service.snapshot(
        identity=IdentityContext("agent-1", TENANT, frozenset()), lease_id=parent.lease_id
    ).grant.expires_at_ns
    child_expiry = rig.service.snapshot(
        identity=IdentityContext("agent-2", TENANT, frozenset()), lease_id=child.lease_id
    ).grant.expires_at_ns
    assert child_expiry == parent_expiry

    rig.clock.advance(2_000)
    with pytest.raises(ExpiredError):
        rig.profile.authorize_effect(
            DELEGATOR,
            task_id="child-1",
            effect_id="late",
            transition="act",
            verified_executor_id="spiffe://exec/a",
        )
    failed = rig.profile.get_task(DELEGATOR, "child-1")
    assert (failed.state, failed.reason) == (TaskState.FAILED, "authority_expired")


def test_cancel_refuses_new_effects_but_issued_receipts_stay_claimable(rig: Rig) -> None:
    rig.admit()
    issued = Receipt.from_dict(dict(rig.effect(effect_id="before-cancel")))

    canceled = rig.profile.cancel_task(_client_identity(), "task-1")
    assert canceled.state is TaskState.CANCELED
    assert canceled.revoked_at_ns == rig.clock.now_ns()
    assert canceled.receipt_horizon_ns == issued.expires_at_ns > canceled.revoked_at_ns

    executor = rig.verifier("executor-a")
    executor.verify_and_claim(issued)

    with pytest.raises(PolicyError, match="not accepting"):
        rig.effect(effect_id="after-cancel")
    with pytest.raises(PolicyError, match=r"(?i)revoked"):
        rig.profile.authorizer.authorize_effect(
            request_id="bypass",
            lease_id=canceled.lease_id,
            transition="act",
            executor_audience="executor-a",
            nonce="bypass-nonce-0001",
        )
    rig.clock.advance(200)
    with pytest.raises(PolicyError, match="expired"):
        executor.verify(issued)


def test_cancel_is_idempotent_and_terminal_states_are_not_cancelable(rig: Rig) -> None:
    rig.admit("task-a")
    first = rig.profile.cancel_task(_client_identity(), "task-a")
    assert rig.profile.cancel_task(_client_identity(), "task-a") == first
    assert rig.client.calls.count("revoke") == 1

    rig.admit("task-b", context_id="ctx-1")
    rig.profile.complete_task(_client_identity(), "task-b")
    with pytest.raises(A2AProfileError) as error:
        rig.profile.cancel_task(_client_identity(), "task-b")
    assert (error.value.name, error.value.code) == ("TaskNotCancelableError", -32002)


def test_cancel_wins_over_a_later_complete_and_survives_a_failed_revoke(rig: Rig) -> None:
    rig.admit()
    rig.client.fail_revoke = 1
    with pytest.raises(ConflictError, match="transient"):
        rig.profile.cancel_task(_client_identity(), "task-1")
    pending = rig.profile.get_task(_client_identity(), "task-1")
    assert pending.cancel_requested and pending.state is not TaskState.CANCELED
    with pytest.raises(PolicyError, match="not accepting"):
        rig.effect()
    with pytest.raises(ConflictError, match="canceling"):
        rig.profile.complete_task(_client_identity(), "task-1")

    retried = rig.profile.cancel_task(_client_identity(), "task-1")
    assert retried.state is TaskState.CANCELED and not retried.cancel_requested


def test_parent_cancel_revokes_the_delegated_branch(rig: Rig) -> None:
    parent = rig.admit()
    child = rig.profile.delegate(
        DELEGATOR,
        parent_key=parent.key,
        task_id="child-1",
        context_id="ctx-1",
        content=CONTENT,
        subject_id="agent-2",
        allocation=(10,),
        capabilities={"worker.act"},
        ttl_ns=1_000,
    )
    rig.profile.cancel_task(_client_identity(), "task-1")
    mirrored = rig.profile.get_task(DELEGATOR, "child-1")
    assert (mirrored.state, mirrored.reason) == (TaskState.CANCELED, "parent_canceled")
    with pytest.raises(PolicyError, match=r"(?i)revoked"):
        rig.profile.authorizer.authorize_effect(
            request_id="child-bypass",
            lease_id=child.lease_id,
            transition="act",
            executor_audience="executor-a",
            nonce="child-bypass-0001",
        )


def test_ledger_protocol_is_replaceable() -> None:
    update: Callable[..., Any] = InMemoryTaskLedger().update
    with pytest.raises(A2AProfileError):
        update(TaskKey(TENANT, "x", "missing"), lambda record: record)


def test_example_host_dispatches_a2a_methods_from_verified_identity(rig: Rig) -> None:
    from examples.a2a_host import A2AHost

    host = A2AHost(
        rig.profile,
        parent_lease_id=rig.root_lease_id,
        executor_subject="agent-1",
        allocation=(30,),
        capabilities=frozenset({"worker.act"}),
        ttl_ns=1_500,
    )
    caller = _client_identity()
    params = {"taskId": "task-1", "message": {"contextId": "ctx-1", "messageId": "m-1"}}
    created = host.handle(caller, "SendMessage", params)
    assert created["status"]["state"] == "TASK_STATE_SUBMITTED"
    assert host.handle(caller, "SendMessage", params) == created
    assert host.handle(caller, "GetTask", {"id": "task-1"})["id"] == "task-1"
    canceled = host.handle(caller, "CancelTask", {"id": "task-1"})
    assert canceled["status"]["state"] == "TASK_STATE_CANCELED"
    with pytest.raises(A2AProfileError):
        host.handle(caller, "SubscribeToTask", {"id": "task-1"})
    with pytest.raises(A2AProfileError):
        host.handle(_client_identity("client-b"), "GetTask", {"id": "task-1"})


def test_delegation_requires_a_live_known_parent(rig: Rig) -> None:
    parent = rig.admit()

    def delegate(parent_key: TaskKey) -> Any:
        return rig.profile.delegate(
            DELEGATOR,
            parent_key=parent_key,
            task_id="child-1",
            context_id="ctx-1",
            content=CONTENT,
            subject_id="agent-2",
            allocation=(1,),
            capabilities={"worker.act"},
            ttl_ns=100,
        )

    with pytest.raises(A2AProfileError):
        delegate(TaskKey(TENANT, "client-a", "missing"))
    rig.profile.cancel_task(_client_identity(), "task-1")
    with pytest.raises(PolicyError, match="not accepting delegation"):
        delegate(parent.key)


def test_identity_is_bound_to_the_configured_tenant(rig: Rig) -> None:
    parent = rig.admit()
    foreign = IdentityContext("agent-1", "other-tenant", frozenset())
    spawns = rig.client.calls.count("spawn")
    with pytest.raises(PolicyError, match="configured LETS tenant"):
        rig.profile.delegate(
            foreign,
            parent_key=parent.key,
            task_id="stolen",
            context_id="ctx-1",
            content=CONTENT,
            subject_id="agent-2",
            allocation=(1,),
            capabilities={"worker.act"},
            ttl_ns=100,
        )
    with pytest.raises(PolicyError, match="configured LETS tenant"):
        rig.profile.admit(
            foreign,
            task_id="foreign-task",
            context_id="ctx-1",
            content=CONTENT,
            subject_id="agent-2",
            parent_lease_id=rig.root_lease_id,
            allocation=(1,),
            capabilities={"worker.act"},
            ttl_ns=100,
        )
    with pytest.raises(PolicyError, match="configured LETS tenant"):
        rig.profile.get_task(foreign, "task-1")
    assert rig.client.calls.count("spawn") == spawns
    assert rig.ledger.get(TaskKey("other-tenant", "agent-1", "stolen")) is None


def test_delegation_cannot_name_a_parent_in_another_tenant(rig: Rig) -> None:
    parent = rig.admit()
    with pytest.raises(A2AProfileError) as error:
        rig.profile.delegate(
            DELEGATOR,
            parent_key=TaskKey("other-tenant", parent.key.principal, parent.key.task_id),
            task_id="child-x",
            context_id="ctx-1",
            content=CONTENT,
            subject_id="agent-2",
            allocation=(1,),
            capabilities={"worker.act"},
            ttl_ns=100,
        )
    assert error.value.code == -32001


def test_lost_spawn_reply_keeps_the_original_content_binding(rig: Rig) -> None:
    rig.client.lose_spawn_reply = 1
    with pytest.raises(TimeoutError):
        rig.admit()
    pending = rig.ledger.get(TaskKey(TENANT, "client-a", "task-1"))
    assert pending is not None and pending.lease_id == ""

    changed = {"message": {"messageId": "m-1", "parts": [{"text": "something else"}]}}
    with pytest.raises(ConflictError, match="different content"):
        rig.admit(content=changed)
    assert rig.ledger.get(pending.key) == pending

    recovered = rig.admit()
    assert recovered.lease_id and recovered.admission_digest == pending.admission_digest
    assert len(rig.client.subjects) == 2
    assert rig.admit() == recovered


def test_operations_resume_a_pending_admission(rig: Rig) -> None:
    rig.client.lose_spawn_reply = 1
    with pytest.raises(TimeoutError):
        rig.admit()
    canceled = rig.profile.cancel_task(_client_identity(), "task-1")
    assert canceled.state is TaskState.CANCELED and canceled.lease_id
    assert len(rig.client.subjects) == 2


def test_denied_admission_is_rejected_and_keeps_its_binding(rig: Rig) -> None:
    with pytest.raises(PolicyError):
        rig.admit(capabilities={"worker.act", "worker.audit", "worker.extra"})
    rejected = rig.profile.get_task(_client_identity(), "task-1")
    assert (rejected.state, rejected.reason) == (TaskState.REJECTED, "admission_denied")
    with pytest.raises(ConflictError):
        rig.admit()


def test_completed_is_published_only_after_close_succeeds(rig: Rig) -> None:
    rig.admit()
    rig.effect()
    rig.client.lose_close_reply = 1
    with pytest.raises(TimeoutError):
        rig.profile.complete_task(_client_identity(), "task-1")
    pending = rig.profile.get_task(_client_identity(), "task-1")
    assert pending.state is TaskState.WORKING and pending.completion_requested
    with pytest.raises(PolicyError, match="not accepting"):
        rig.effect(effect_id="after-complete")

    done = rig.profile.complete_task(_client_identity(), "task-1")
    assert done.state is TaskState.COMPLETED and not done.completion_requested
    assert rig.profile.complete_task(_client_identity(), "task-1") == done


def test_cancel_wins_over_an_unfinished_completion(rig: Rig) -> None:
    rig.admit()
    rig.client.lose_close_reply = 1
    with pytest.raises(TimeoutError):
        rig.profile.complete_task(_client_identity(), "task-1")
    canceled = rig.profile.cancel_task(_client_identity(), "task-1")
    assert canceled.state is TaskState.CANCELED
    with pytest.raises(ConflictError, match="canceled"):
        rig.profile.complete_task(_client_identity(), "task-1")


def test_cancel_resumes_a_failed_descendant_cascade(rig: Rig) -> None:
    parent = rig.admit()
    child = rig.profile.delegate(
        DELEGATOR,
        parent_key=parent.key,
        task_id="child-1",
        context_id="ctx-1",
        content=CONTENT,
        subject_id="agent-2",
        allocation=(10,),
        capabilities={"worker.act"},
        ttl_ns=1_000,
    )
    rig.ledger.fail_key = child.key
    with pytest.raises(RuntimeError, match="ledger unavailable"):
        rig.profile.cancel_task(_client_identity(), "task-1")
    assert rig.profile.get_task(_client_identity(), "task-1").state is TaskState.CANCELED
    assert rig.profile.get_task(DELEGATOR, "child-1").state is not TaskState.CANCELED

    again = rig.profile.cancel_task(_client_identity(), "task-1")
    assert again.state is TaskState.CANCELED
    mirrored = rig.profile.get_task(DELEGATOR, "child-1")
    assert (mirrored.state, mirrored.reason) == (TaskState.CANCELED, "parent_canceled")
    assert rig.client.calls.count("revoke") == 1


def _delegate_as(identity: IdentityContext, rig: Rig, parent: TaskKey, task_id: str) -> Any:
    return rig.profile.delegate(
        identity,
        parent_key=parent,
        task_id=task_id,
        context_id="ctx-1",
        content=CONTENT,
        subject_id="agent-2",
        allocation=(1,),
        capabilities={"worker.act"},
        ttl_ns=100,
    )


def test_denied_delegate_does_not_recover_a_pending_parent(rig: Rig) -> None:
    rig.client.fail_spawn = 1
    with pytest.raises(TimeoutError):
        rig.admit()
    key = TaskKey(TENANT, "client-a", "task-1")
    leases = len(rig.client.subjects)

    intruder = IdentityContext("intruder", TENANT, frozenset())
    with pytest.raises(PolicyError, match="executing subject"):
        _delegate_as(intruder, rig, key, "stolen")
    assert len(rig.client.subjects) == leases
    pending = rig.ledger.get(key)
    assert pending is not None and pending.lease_id == ""

    child = _delegate_as(DELEGATOR, rig, key, "child-1")
    assert child.lease_id and len(rig.client.subjects) == leases + 2


def test_unknown_executor_does_not_recover_a_pending_task(rig: Rig) -> None:
    rig.client.fail_spawn = 1
    with pytest.raises(TimeoutError):
        rig.admit()
    key = TaskKey(TENANT, "client-a", "task-1")
    leases = len(rig.client.subjects)

    with pytest.raises(PolicyError, match="no audience binding"):
        rig.profile.authorize_effect(
            _client_identity(),
            task_id="task-1",
            effect_id="e-1",
            transition="act",
            verified_executor_id="spiffe://exec/unknown",
        )
    assert len(rig.client.subjects) == leases
    pending = rig.ledger.get(key)
    assert pending is not None and pending.lease_id == ""

    receipt = rig.effect()
    assert receipt["executor_audience"] == "executor-a"
    assert len(rig.client.subjects) == leases + 1


def test_delegation_is_refused_once_completion_starts(rig: Rig) -> None:
    parent = rig.admit()
    rig.client.fail_close = 1
    with pytest.raises(ConflictError, match="close did not reach"):
        rig.profile.complete_task(_client_identity(), "task-1")
    leases = len(rig.client.subjects)
    with pytest.raises(PolicyError, match="not accepting delegation"):
        _delegate_as(DELEGATOR, rig, parent.key, "late-child")
    assert len(rig.client.subjects) == leases
    assert rig.ledger.get(TaskKey(TENANT, "agent-1", "late-child")) is None

    done = rig.profile.complete_task(_client_identity(), "task-1")
    assert done.state is TaskState.COMPLETED


def test_delegation_is_refused_when_completion_started_during_recovery(rig: Rig) -> None:
    rig.client.fail_spawn = 2
    with pytest.raises(TimeoutError):
        rig.admit()
    with pytest.raises(TimeoutError):
        rig.profile.complete_task(_client_identity(), "task-1")
    key = TaskKey(TENANT, "client-a", "task-1")
    pending = rig.ledger.get(key)
    assert pending is not None and pending.completion_requested and pending.lease_id == ""
    leases = len(rig.client.subjects)

    with pytest.raises(PolicyError, match="not accepting delegation"):
        _delegate_as(DELEGATOR, rig, key, "late-child")
    assert len(rig.client.subjects) == leases


def test_effect_recovery_rechecks_cancellation_before_issuing_authority(rig: Rig) -> None:
    rig.client.fail_spawn = 1
    with pytest.raises(TimeoutError):
        rig.admit()
    rig.client.fail_revoke = 1

    def cancel_during_recovery() -> None:
        with pytest.raises(ConflictError, match="transient revoke"):
            rig.profile.cancel_task(_client_identity(), "task-1")

    rig.client.during_spawn = cancel_during_recovery
    with pytest.raises(PolicyError, match="not accepting new effects"):
        rig.effect()
    assert "authorize" not in rig.client.calls
    interrupted = rig.profile.get_task(_client_identity(), "task-1")
    assert interrupted.cancel_requested and interrupted.state is not TaskState.CANCELED

    canceled = rig.profile.cancel_task(_client_identity(), "task-1")
    assert canceled.state is TaskState.CANCELED


def test_effect_recovery_rechecks_completion_before_issuing_authority(rig: Rig) -> None:
    rig.client.fail_spawn = 1
    with pytest.raises(TimeoutError):
        rig.admit()
    rig.client.fail_close = 1

    def complete_during_recovery() -> None:
        with pytest.raises(ConflictError, match="close did not reach"):
            rig.profile.complete_task(_client_identity(), "task-1")

    rig.client.during_spawn = complete_during_recovery
    with pytest.raises(PolicyError, match="not accepting new effects"):
        rig.effect()
    assert "authorize" not in rig.client.calls
