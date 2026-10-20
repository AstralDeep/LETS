"""Deterministic conformance fixtures for lets.integrations.mcp, run against a real WardenService,
ManualClock and ReceiptVerifier. They also cover examples/mcp_host.py and the pinned MCP revision.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from lets.canonical import canonical_digest
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ConflictError, PolicyError, ReplayError, ValidationError
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.integrations import (
    HostToolApproval,
    MCPAudienceBinding,
    MCPOperationKey,
    MCPToolAuthorization,
    MCPToolProfile,
    ReplicaAuthorizer,
    ReplicaProfile,
)
from lets.integrations.mcp import (
    MAPPING_VERSION,
    PINNED_REVISION,
    derive_id,
    effect_digest,
)
from lets.models import IdentityContext, Receipt
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage

TENANT = "tenant"
CALLER = IdentityContext("agent-1", TENANT, frozenset())
POLICY = PolicySpec(
    policy_id="mcp-policy",
    policy_version="v1",
    dimensions=(ResourceDimension("operations", "count"),),
    machine=MachineSpec(
        machine_id="worker",
        initial_state="ready",
        transitions=(
            TransitionSpec("execute", "ready", "ready", (2,), "worker.execute"),
            TransitionSpec("read", "ready", "ready", (1,), "worker.read"),
        ),
    ),
    max_lease_ttl_ns=10_000,
    receipt_ttl_ns=100,
    max_clock_uncertainty_ns=5,
    transfer_gap_window=4,
)


@dataclass
class ServiceClient:
    service: WardenService
    subjects: dict[str, str] = field(default_factory=dict)
    calls: list[tuple[str, str | None, dict[str, Any]]] = field(default_factory=list)
    authorizations: list[dict[str, Any]] = field(default_factory=list)
    lose_authorize_reply: int = 0

    def _acting(self, lease_id: str | None) -> IdentityContext:
        subject = "host" if lease_id is None else self.subjects[lease_id]
        scopes = frozenset({"lets.lease.issue", "lets.lease.manage", "lets.branch.revoke"})
        return IdentityContext(subject, TENANT, scopes)

    def _record(
        self,
        operation: str,
        lease_id: str | None,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        copied = dict(payload)
        self.calls.append((operation, lease_id, copied))
        return copied

    def issue_root(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._record("issue_root", None, payload)
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
        raise NotImplementedError

    def authorize(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._record("authorize", lease_id, payload)
        receipt = self.service.authorize(
            request_id=payload["request_id"],
            identity=self._acting(lease_id),
            lease_id=lease_id,
            transition=payload["transition"],
            audience=payload["executor_audience"],
            nonce=payload["nonce"],
            evidence=payload.get("evidence"),
            expected_state=payload.get("expected_state"),
            expected_sequence=payload.get("expected_sequence"),
        )
        wire = receipt.to_dict()
        self.authorizations.append(wire)
        if self.lose_authorize_reply:
            self.lose_authorize_reply -= 1
            raise TimeoutError("authorize committed but the reply was lost")
        return wire

    def renew(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        raise NotImplementedError

    def quiesce(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        raise NotImplementedError

    def resume(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        raise NotImplementedError

    def close_lease(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        raise NotImplementedError

    def revoke_branch(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._record("revoke", lease_id, payload)
        revocation = self.service.revoke_branch(
            request_id=payload["request_id"],
            identity=self._acting(lease_id),
            lease_id=lease_id,
            reason=payload["reason"],
        )
        return revocation.to_dict()


@dataclass
class RecordingGate:
    allow: bool = True
    malformed: bool = False
    approval_digest: str | None = None
    confirmation_id: str | None = "confirmation-1"
    policy_reference: str | None = "policy://tools"
    calls: list[dict[str, Any]] = field(default_factory=list)

    def approve(
        self,
        identity: IdentityContext,
        *,
        tool_name: str,
        scope: str,
        arguments: Mapping[str, Any],
        effect_digest: str,
    ) -> HostToolApproval | None:
        self.calls.append(
            {
                "identity": identity,
                "tool_name": tool_name,
                "scope": scope,
                "arguments": dict(arguments),
                "effect_digest": effect_digest,
            }
        )
        if not self.allow:
            return None
        if self.malformed:
            return object()
        return HostToolApproval(
            self.approval_digest or effect_digest,
            confirmation_id=self.confirmation_id,
            policy_reference=self.policy_reference,
        )


@dataclass
class Rig:
    profile: MCPToolProfile
    client: ServiceClient
    service: WardenService
    clock: ManualClock
    registry: PublicKeyRegistry
    root_lease_id: str
    tmp: Path
    gate: RecordingGate
    store_count: int = 0

    def authorize(
        self,
        *,
        operation_id: str = "op-1",
        tool_name: str = "echo",
        arguments: Mapping[str, Any] | None = None,
        identity: IdentityContext = CALLER,
        executor_id: str = "spiffe://exec/a",
        expected_state: str | None = "ready",
        expected_sequence: int | None = None,
    ) -> MCPToolAuthorization:
        return self.profile.authorize_tool(
            identity,
            operation_id=operation_id,
            lease_id=self.root_lease_id,
            tool_name=tool_name,
            arguments={"text": "hello"} if arguments is None else arguments,
            verified_executor_id=executor_id,
            expected_state=expected_state,
            expected_sequence=expected_sequence,
        )

    def verifier(self, audience: str = "executor-a", *, tenant: str = TENANT) -> ReceiptVerifier:
        self.store_count += 1
        store = SQLiteReceiptReplayStore.initialize(
            self.tmp / f"{audience}-{self.store_count}.sqlite3", allow_unanchored=True
        )
        policy = ExecutorPolicy(
            audience=audience,
            tenant_id=tenant,
            envelope_id="envelope",
            trusted_wardens=frozenset({"warden-a"}),
            max_clock_uncertainty_ns=5,
        )
        return ReceiptVerifier(self.registry, store, policy, clock=self.clock)

    def residual(self) -> tuple[int, ...]:
        return self.service.snapshot(identity=CALLER, lease_id=self.root_lease_id).residual


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    clock = ManualClock(1_000_000, 5)
    signer = Ed25519Signer.generate("warden-a")
    registry = PublicKeyRegistry()
    storage = SQLiteStorage.initialize(
        tmp_path / "warden.sqlite3",
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
    service = WardenService(storage, signer=signer, clock=clock, trust_registry=registry)
    service.register_policy(POLICY)
    client = ServiceClient(service)
    replicas = ReplicaAuthorizer(
        client,
        ReplicaProfile(
            tenant_id=TENANT,
            envelope_id="envelope",
            policy_digest=POLICY.digest,
            default_allocation=(100,),
            default_capabilities=frozenset({"worker.execute", "worker.read"}),
            default_ttl_ns=2_000,
        ),
    )
    root = replicas.provision(
        request_id="root", replica_id="agent-1", allocation=(100,), ttl_ns=2_000
    )
    gate = RecordingGate()
    profile = MCPToolProfile(
        replicas,
        tool_scopes={"echo": "tools.execute", "read": "tools.read"},
        scope_capabilities={"tools.execute": "worker.execute", "tools.read": "worker.read"},
        scope_transitions={"tools.execute": "execute", "tools.read": "read"},
        audiences=MCPAudienceBinding(
            {"spiffe://exec/a": "executor-a", "spiffe://exec/b": "executor-b"}
        ),
        gate=gate,
    )
    try:
        yield Rig(profile, client, service, clock, registry, root["lease_id"], tmp_path, gate)
    finally:
        storage.close()


def test_pins_official_mcp_revision_and_discovery_grants_no_authority(rig: Rig) -> None:
    from lets.integrations import __all__ as integration_exports

    assert {
        "HostToolApproval",
        "MCPAudienceBinding",
        "MCPOperationKey",
        "MCPToolAuthorization",
        "MCPToolDescriptor",
        "MCPToolProfile",
        "ToolGate",
    } <= set(integration_exports)
    assert PINNED_REVISION.specification == "2026-07-28"
    assert PINNED_REVISION.sdk == "mcp==2.3.0"
    assert MAPPING_VERSION == "lets.mcp-profile/v1"
    before = len(rig.client.calls)
    descriptors = rig.profile.descriptors()
    assert [descriptor.name for descriptor in descriptors] == ["echo", "read"]
    assert descriptors[0].to_mcp() == {
        "name": "echo",
        "_meta": {
            "lets/mapping": MAPPING_VERSION,
            "lets/mcp_revision": "2026-07-28",
            "lets/scope": "tools.execute",
        },
    }
    assert rig.profile.capabilities_for_tools({"echo", "read"}) == frozenset(
        {"worker.execute", "worker.read"}
    )
    assert len(rig.client.calls) == before
    assert rig.gate.calls == []


def test_unknown_tool_and_scope_fail_closed_before_authority(rig: Rig) -> None:
    before = len(rig.client.calls)
    with pytest.raises(PolicyError, match="not mapped"):
        rig.authorize(tool_name="missing")
    with pytest.raises(PolicyError, match="at least one"):
        rig.profile.capabilities_for_tools([])
    with pytest.raises(ValidationError, match="unknown scope"):
        MCPToolProfile(
            rig.profile.authorizer,
            tool_scopes={"echo": "tools.missing"},
            scope_capabilities={"tools.execute": "worker.execute"},
            scope_transitions={"tools.execute": "execute"},
            audiences=rig.profile.audiences,
            gate=rig.gate,
        )
    assert len(rig.client.calls) == before
    assert rig.gate.calls == []


def test_invalid_profile_configuration_is_rejected(rig: Rig) -> None:
    authorizer = rig.profile.authorizer
    audiences = rig.profile.audiences
    with pytest.raises(ValidationError, match="at least one tool"):
        MCPToolProfile(
            authorizer,
            tool_scopes={},
            scope_capabilities={"tools.execute": "worker.execute"},
            scope_transitions={"tools.execute": "execute"},
            audiences=audiences,
            gate=rig.gate,
        )
    with pytest.raises(ValidationError, match="at least one scope"):
        MCPToolProfile(
            authorizer,
            tool_scopes={"echo": "tools.execute"},
            scope_capabilities={},
            scope_transitions={},
            audiences=audiences,
            gate=rig.gate,
        )
    with pytest.raises(ValidationError, match="one LETS transition"):
        MCPToolProfile(
            authorizer,
            tool_scopes={"echo": "tools.execute"},
            scope_capabilities={"tools.execute": "worker.execute"},
            scope_transitions={},
            audiences=audiences,
            gate=rig.gate,
        )
    with pytest.raises(ValidationError, match="MCPAudienceBinding"):
        MCPToolProfile(
            authorizer,
            tool_scopes={"echo": "tools.execute"},
            scope_capabilities={"tools.execute": "worker.execute"},
            scope_transitions={"tools.execute": "execute"},
            audiences={},
            gate=rig.gate,
        )
    with pytest.raises(ValidationError, match="host tool gate"):
        MCPToolProfile(
            authorizer,
            tool_scopes={"echo": "tools.execute"},
            scope_capabilities={"tools.execute": "worker.execute"},
            scope_transitions={"tools.execute": "execute"},
            audiences=audiences,
            gate=object(),
        )


def test_host_gate_denial_and_unbound_approval_stop_before_the_warden(rig: Rig) -> None:
    before = len(rig.client.calls)
    rig.gate.allow = False
    with pytest.raises(PolicyError, match="gate denied"):
        rig.authorize(operation_id="op-denied")
    assert len(rig.client.calls) == before
    assert rig.gate.calls[-1]["effect_digest"].startswith("sha256:")

    rig.gate.allow = True
    rig.gate.approval_digest = "sha256:" + "0" * 64
    with pytest.raises(PolicyError, match="does not bind"):
        rig.authorize(operation_id="op-unbound-approval")
    assert len(rig.client.calls) == before

    rig.gate.approval_digest = None
    rig.gate.malformed = True
    with pytest.raises(ValidationError, match="HostToolApproval"):
        rig.authorize(operation_id="op-malformed-approval")
    assert len(rig.client.calls) == before


def test_effect_and_retry_identity_are_stable_while_arguments_change_the_digest(rig: Rig) -> None:
    first = rig.authorize(operation_id="op-stable", arguments={"text": "hello"})
    again = rig.authorize(operation_id="op-stable", arguments={"text": "hello"})
    assert again == first
    assert again.receipt == first.receipt
    assert first.request_id == derive_id(
        "authorize", MCPOperationKey(TENANT, "agent-1", "op-stable")
    )
    assert first.nonce == derive_id("nonce", MCPOperationKey(TENANT, "agent-1", "op-stable"))
    assert first.effect_digest == effect_digest("echo", "tools.execute", {"text": "hello"})
    assert first.arguments_digest == canonical_digest({"text": "hello"})
    assert effect_digest("echo", "tools.execute", {"text": "goodbye"}) != first.effect_digest
    assert rig.residual() == (98,)


def test_changed_arguments_or_tool_on_the_same_operation_conflict(rig: Rig) -> None:
    first = rig.authorize(operation_id="op-changed", arguments={"text": "hello"})
    with pytest.raises(ConflictError):
        rig.authorize(operation_id="op-changed", arguments={"text": "changed"})
    with pytest.raises(ConflictError):
        rig.authorize(operation_id="op-changed", tool_name="read", arguments={"text": "hello"})
    assert rig.residual() == (98,)
    assert (
        first.receipt
        == rig.authorize(operation_id="op-changed", arguments={"text": "hello"}).receipt
    )


def test_lost_authorize_reply_recovers_the_same_receipt_once(rig: Rig) -> None:
    rig.client.lose_authorize_reply = 1
    with pytest.raises(TimeoutError):
        rig.authorize(operation_id="op-lost")
    assert rig.residual() == (98,)
    assert len(rig.client.authorizations) == 1

    recovered = rig.authorize(operation_id="op-lost")
    assert len(rig.client.authorizations) == 2
    assert rig.client.authorizations[0] == rig.client.authorizations[1] == recovered.receipt
    assert rig.residual() == (98,)

    verifier = rig.verifier()
    verifier.verify_and_claim(Receipt.from_dict(dict(recovered.receipt)))
    with pytest.raises(ReplayError):
        verifier.verify_and_claim(
            Receipt.from_dict(dict(rig.authorize(operation_id="op-lost").receipt))
        )


def test_wrong_audience_and_tenant_are_refused(rig: Rig) -> None:
    before = len(rig.client.calls)
    with pytest.raises(PolicyError, match="audience binding"):
        rig.authorize(operation_id="op-unbound", executor_id="spiffe://exec/unknown")
    with pytest.raises(PolicyError, match="configured LETS tenant"):
        rig.authorize(
            operation_id="op-foreign",
            identity=IdentityContext("agent-1", "other-tenant", frozenset()),
        )
    assert len(rig.client.calls) == before

    authorization = rig.authorize(operation_id="op-audience")
    receipt = Receipt.from_dict(dict(authorization.receipt))
    with pytest.raises(PolicyError, match="audience"):
        rig.verifier("executor-b").verify_and_claim(receipt)
    with pytest.raises(PolicyError, match="tenant"):
        rig.verifier("executor-a", tenant="other-tenant").verify_and_claim(receipt)


def test_missing_or_mismatched_receipts_cannot_be_bound(rig: Rig) -> None:
    first = rig.authorize(operation_id="op-first", arguments={"text": "first"})
    second = rig.authorize(operation_id="op-second", arguments={"text": "second"})
    with pytest.raises(ValidationError, match="requires a receipt"):
        rig.profile.bind_receipt(first, None)
    with pytest.raises(ValidationError, match="MCPToolAuthorization"):
        rig.profile.bind_receipt("not-authorization", first.receipt)
    with pytest.raises(PolicyError, match="does not bind"):
        rig.profile.bind_receipt(first, second.receipt)
    assert rig.profile.bind_receipt(first, first.receipt).receipt_id == first.receipt["receipt_id"]


def test_warden_receipt_must_bind_the_requested_effect(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = rig.profile.authorizer.authorize_effect

    def tampered(**arguments: Any) -> Mapping[str, Any]:
        wire = dict(original(**arguments))
        wire["request_id"] = "mcp1.authorize.tampered"
        return wire

    monkeypatch.setattr(rig.profile.authorizer, "authorize_effect", tampered)
    with pytest.raises(PolicyError, match="receipt does not bind"):
        rig.authorize(operation_id="op-tampered")


def test_raw_arguments_and_credentials_never_reach_the_warden(rig: Rig) -> None:
    arguments = {"text": "hello", "api_token": "super-secret-value", "nested": {"key": "secret"}}
    authorization = rig.authorize(operation_id="op-secrets", arguments=arguments)
    authorize_calls = [call for call in rig.client.calls if call[0] == "authorize"]
    payload = authorize_calls[-1][2]
    assert "super-secret-value" not in repr(payload)
    assert "arguments" not in payload
    assert "api_token" not in payload
    assert set(payload) == {
        "request_id",
        "transition",
        "executor_audience",
        "nonce",
        "evidence",
        "expected_state",
    }
    assert "super-secret-value" not in repr(authorization.evidence)
    assert authorization.arguments_digest == canonical_digest(arguments)
    assert rig.gate.calls[-1]["arguments"] == arguments


def test_cancellation_revokes_new_authority_but_keeps_issued_receipts_claimable(rig: Rig) -> None:
    issued = rig.authorize(operation_id="op-before-cancel")
    revocation = rig.profile.revoke_lease(
        CALLER, operation_id="op-cancel", lease_id=rig.root_lease_id, reason="mcp.cancel"
    )
    assert revocation["branch_lease_id"] == rig.root_lease_id
    with pytest.raises(PolicyError, match=r"(?i)revoked"):
        rig.authorize(operation_id="op-after-cancel")
    assert rig.authorize(operation_id="op-before-cancel").receipt == issued.receipt
    rig.verifier().verify_and_claim(Receipt.from_dict(dict(issued.receipt)))


def test_at_most_once_authorization_burns_the_claim_before_the_effect(rig: Rig) -> None:
    authorization = rig.authorize(operation_id="op-claimed")
    verifier = rig.verifier()
    receipt = rig.profile.bind_receipt(authorization, authorization.receipt)
    verifier.verify_and_claim(receipt)
    with pytest.raises(ReplayError):
        verifier.verify_and_claim(receipt)
    duplicate = rig.authorize(operation_id="op-claimed")
    assert duplicate.receipt == authorization.receipt
    assert rig.residual() == (98,)


def test_example_host_claims_immediately_before_the_effect(rig: Rig) -> None:
    from examples.mcp_host import MCPToolHost

    effects: list[tuple[str, str, dict[str, Any]]] = []

    def effect(operation_id: str, tool_name: str, arguments: Mapping[str, Any]) -> str:
        effects.append((operation_id, tool_name, dict(arguments)))
        return "executed"

    host = MCPToolHost(rig.profile, rig.verifier(), effect)
    assert [descriptor["name"] for descriptor in host.discover()] == ["echo", "read"]
    result = host.call(
        CALLER,
        operation_id="op-host",
        lease_id=rig.root_lease_id,
        tool_name="echo",
        arguments={"text": "run"},
        verified_executor_id="spiffe://exec/a",
        expected_state="ready",
    )
    assert result == "executed"
    assert effects == [("op-host", "echo", {"text": "run"})]

    authorization = host.authorize(
        CALLER,
        operation_id="op-host-duplicate",
        lease_id=rig.root_lease_id,
        tool_name="echo",
        arguments={"text": "run"},
        verified_executor_id="spiffe://exec/a",
        expected_state="ready",
    )
    assert host.execute(CALLER, {"text": "run"}, authorization=authorization) == "executed"
    with pytest.raises(ReplayError):
        host.execute(CALLER, {"text": "run"}, authorization=authorization)
    with pytest.raises(ValidationError, match="requires a receipt"):
        host.execute(CALLER, {"text": "run"}, authorization=None)
    assert len(effects) == 2


def test_approval_without_confirmation_or_policy_omits_evidence_fields(rig: Rig) -> None:
    rig.gate.confirmation_id = None
    rig.gate.policy_reference = None
    authorization = rig.authorize(operation_id="op-minimal-approval")
    assert "confirmation_id" not in authorization.evidence
    assert "policy_reference" not in authorization.evidence


def test_argument_digest_rejects_noncanonical_json_and_invalid_identifiers(rig: Rig) -> None:
    with pytest.raises(ValidationError, match="canonical JSON"):
        effect_digest("echo", "tools.execute", {"value": 1.5})
    with pytest.raises(ValidationError, match="canonical JSON"):
        rig.authorize(operation_id="op-float", arguments={"value": 1.5})
    with pytest.raises(ValidationError, match="tool name"):
        effect_digest("", "tools.execute", {})
    with pytest.raises(ValidationError, match="tool scope"):
        effect_digest("echo", "", {})
    with pytest.raises(ValidationError, match="arguments must be an object"):
        rig.profile.authorize_tool(
            CALLER,
            operation_id="op-bad-arguments",
            lease_id=rig.root_lease_id,
            tool_name="echo",
            arguments=[],  # type: ignore[arg-type]
            verified_executor_id="spiffe://exec/a",
        )
    with pytest.raises(ValidationError, match="verified IdentityContext"):
        rig.profile.authorize_tool(
            {"subject_id": "agent-1"},  # type: ignore[arg-type]
            operation_id="op-identity",
            lease_id=rig.root_lease_id,
            tool_name="echo",
            arguments={},
            verified_executor_id="spiffe://exec/a",
        )


def test_audience_and_approval_records_validate_their_inputs() -> None:
    assert HostToolApproval("sha256:" + "1" * 64).confirmation_id is None
    with pytest.raises(ValidationError, match="at least one executor"):
        MCPAudienceBinding({})
    with pytest.raises(ValidationError, match="executor audience"):
        MCPAudienceBinding({"spiffe://exec/a": ""})
    with pytest.raises(ValidationError, match="approved effect digest"):
        HostToolApproval("not-a-digest")
    with pytest.raises(ValidationError, match="confirmation id"):
        HostToolApproval("sha256:" + "1" * 64, confirmation_id="")
    with pytest.raises(ValidationError, match="policy reference"):
        HostToolApproval("sha256:" + "1" * 64, policy_reference="")
    with pytest.raises(ValidationError, match="operation id"):
        MCPOperationKey(TENANT, "agent-1", "")
    with pytest.raises(ValidationError, match="kind"):
        derive_id("", MCPOperationKey(TENANT, "agent-1", "op"))
