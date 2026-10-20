"""Optional host-neutral mapping from MCP 2026-07-28 discovery and tool calls to LETS
leases, receipts and revocation, built on ReplicaAuthorizer with host gate, audience and
effect bindings. See docs/adapters/mcp.md for the transport, auth and retry contracts.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from lets.canonical import canonical_digest, canonical_json
from lets.errors import PolicyError, ValidationError
from lets.ids import require_digest, require_identifier
from lets.integrations.ports import ReplicaAuthorizer, WireObject
from lets.models import IdentityContext, Receipt

MAPPING_VERSION = "lets.mcp-profile/v1"


@dataclass(frozen=True, slots=True)
class MCPRevision:
    specification: str
    sdk: str
    retrieved: str


PINNED_REVISION = MCPRevision("2026-07-28", "mcp==2.3.0", "2026-07-29")


@dataclass(frozen=True, slots=True)
class MCPToolDescriptor:
    name: str
    scope: str

    def to_mcp(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "_meta": {
                "lets/mapping": MAPPING_VERSION,
                "lets/mcp_revision": PINNED_REVISION.specification,
                "lets/scope": self.scope,
            },
        }


@dataclass(frozen=True, slots=True)
class MCPAudienceBinding:
    audiences: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.audiences:
            raise ValidationError("MCP audience binding requires at least one executor")
        for executor, audience in self.audiences.items():
            require_identifier(executor, field="verified executor id")
            require_identifier(audience, field="executor audience")

    def resolve(self, verified_executor_id: str) -> str:
        require_identifier(verified_executor_id, field="verified executor id")
        audience = self.audiences.get(verified_executor_id)
        if audience is None:
            raise PolicyError("executor identity has no MCP audience binding")
        return audience


@dataclass(frozen=True, slots=True)
class HostToolApproval:
    effect_digest: str
    confirmation_id: str | None = None
    policy_reference: str | None = None

    def __post_init__(self) -> None:
        require_digest(self.effect_digest, field="approved effect digest")
        if self.confirmation_id is not None:
            require_identifier(self.confirmation_id, field="host confirmation id")
        if self.policy_reference is not None:
            require_identifier(self.policy_reference, field="host policy reference")


class ToolGate(Protocol):
    def approve(
        self,
        identity: IdentityContext,
        *,
        tool_name: str,
        scope: str,
        arguments: Mapping[str, Any],
        effect_digest: str,
    ) -> HostToolApproval | None: ...


@dataclass(frozen=True, slots=True)
class MCPOperationKey:
    tenant_id: str
    principal: str
    operation_id: str

    def __post_init__(self) -> None:
        require_identifier(self.tenant_id, field="operation tenant")
        require_identifier(self.principal, field="operation principal")
        require_identifier(self.operation_id, field="MCP operation id")


@dataclass(frozen=True, slots=True)
class MCPToolAuthorization:
    operation_id: str
    request_id: str
    nonce: str
    lease_id: str
    tool_name: str
    scope: str
    capability: str
    transition: str
    executor_audience: str
    effect_digest: str
    arguments_digest: str
    evidence: Mapping[str, Any]
    receipt: WireObject


def derive_id(kind: str, key: MCPOperationKey, *, prefix: str = "mcp1") -> str:
    require_identifier(kind, field="MCP derived id kind")
    digest = hashlib.sha256(
        canonical_json(
            {
                "type": MAPPING_VERSION,
                "kind": kind,
                "tenant": key.tenant_id,
                "principal": key.principal,
                "operation": key.operation_id,
            }
        )
    ).hexdigest()
    return f"{prefix}.{kind}.{digest[:48]}"


def effect_digest(tool_name: str, scope: str, arguments: Mapping[str, Any]) -> str:
    require_identifier(tool_name, field="MCP tool name")
    require_identifier(scope, field="MCP tool scope")
    try:
        arguments_object = dict(arguments)
        return canonical_digest(
            {
                "type": MAPPING_VERSION,
                "mcp_revision": PINNED_REVISION.specification,
                "tool": tool_name,
                "scope": scope,
                "arguments": arguments_object,
            }
        )
    except (TypeError, ValueError) as error:
        raise ValidationError("MCP tool arguments must be canonical JSON") from error


class MCPToolProfile:
    def __init__(
        self,
        authorizer: ReplicaAuthorizer,
        *,
        tool_scopes: Mapping[str, str],
        scope_capabilities: Mapping[str, str],
        scope_transitions: Mapping[str, str],
        audiences: MCPAudienceBinding,
        gate: ToolGate,
    ) -> None:
        if not tool_scopes:
            raise ValidationError("MCP profile requires at least one tool")
        if not scope_capabilities:
            raise ValidationError("MCP profile requires at least one scope mapping")
        if set(scope_transitions) != set(scope_capabilities):
            raise ValidationError("every MCP scope must map to one LETS transition")
        for tool_name, scope in tool_scopes.items():
            require_identifier(tool_name, field="MCP tool name")
            require_identifier(scope, field="MCP tool scope")
            if scope not in scope_capabilities:
                raise ValidationError(f"MCP tool {tool_name!r} names an unknown scope")
        for value in (*scope_capabilities.values(), *scope_transitions.values()):
            require_identifier(value, field="MCP LETS mapping")
        if not isinstance(audiences, MCPAudienceBinding):
            raise ValidationError("MCP audiences must be an MCPAudienceBinding")
        if not callable(getattr(gate, "approve", None)):
            raise ValidationError("MCP profile requires a host tool gate")
        self.authorizer = authorizer
        self.tool_scopes = dict(tool_scopes)
        self.scope_capabilities = dict(scope_capabilities)
        self.scope_transitions = dict(scope_transitions)
        self.audiences = audiences
        self.gate = gate

    def descriptors(self) -> tuple[MCPToolDescriptor, ...]:
        return tuple(
            MCPToolDescriptor(name, self.tool_scopes[name]) for name in sorted(self.tool_scopes)
        )

    def capabilities_for_tools(self, tool_names: Iterable[str]) -> frozenset[str]:
        selected = frozenset(tool_names)
        if not selected:
            raise PolicyError("an MCP lease must enable at least one mapped tool")
        return frozenset(self._binding(tool_name)[1] for tool_name in selected)

    def authorize_tool(
        self,
        identity: IdentityContext,
        *,
        operation_id: str,
        lease_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        verified_executor_id: str,
        expected_state: str | None = None,
        expected_sequence: int | None = None,
    ) -> MCPToolAuthorization:
        identity = self._verified(identity)
        require_identifier(operation_id, field="MCP operation id")
        require_identifier(lease_id, field="lease_id")
        scope, capability, transition = self._binding(tool_name)
        if not isinstance(arguments, Mapping):
            raise ValidationError("MCP tool arguments must be an object")
        arguments_object = dict(arguments)
        approved_digest = effect_digest(tool_name, scope, arguments_object)
        arguments_digest = canonical_digest(arguments_object)
        audience = self.audiences.resolve(verified_executor_id)
        approval = self.gate.approve(
            identity,
            tool_name=tool_name,
            scope=scope,
            arguments=arguments_object,
            effect_digest=approved_digest,
        )
        if approval is None:
            raise PolicyError("host permission or confirmation gate denied the MCP tool call")
        if not isinstance(approval, HostToolApproval):
            raise ValidationError("host tool gate must return a HostToolApproval")
        if approval.effect_digest != approved_digest:
            raise PolicyError("host approval does not bind this MCP effect")
        evidence: dict[str, Any] = {
            "type": MAPPING_VERSION,
            "mcp_revision": PINNED_REVISION.specification,
            "tool": tool_name,
            "scope": scope,
            "capability": capability,
            "arguments_digest": arguments_digest,
            "effect_digest": approved_digest,
        }
        if approval.confirmation_id is not None:
            evidence["confirmation_id"] = approval.confirmation_id
        if approval.policy_reference is not None:
            evidence["policy_reference"] = approval.policy_reference
        key = MCPOperationKey(identity.tenant_id, identity.subject_id, operation_id)
        request_id = derive_id("authorize", key)
        nonce = derive_id("nonce", key)
        wire = self.authorizer.authorize_effect(
            request_id=request_id,
            lease_id=lease_id,
            transition=transition,
            executor_audience=audience,
            nonce=nonce,
            evidence=evidence,
            expected_state=expected_state,
            expected_sequence=expected_sequence,
        )
        receipt = Receipt.from_dict(dict(wire))
        if (
            receipt.request_id != request_id
            or receipt.lease_id != lease_id
            or receipt.executor_audience != audience
            or receipt.transition != transition
            or receipt.nonce != nonce
            or receipt.evidence_digest != canonical_digest(evidence)
        ):
            raise PolicyError("warden receipt does not bind the requested MCP tool effect")
        return MCPToolAuthorization(
            operation_id=operation_id,
            request_id=request_id,
            nonce=nonce,
            lease_id=lease_id,
            tool_name=tool_name,
            scope=scope,
            capability=capability,
            transition=transition,
            executor_audience=audience,
            effect_digest=approved_digest,
            arguments_digest=arguments_digest,
            evidence=evidence,
            receipt=dict(wire),
        )

    def bind_receipt(
        self,
        authorization: MCPToolAuthorization,
        receipt: Mapping[str, Any] | Receipt | None,
    ) -> Receipt:
        if not isinstance(authorization, MCPToolAuthorization):
            raise ValidationError("MCP receipt binding requires an MCPToolAuthorization")
        if receipt is None:
            raise ValidationError("MCP tool effect requires a receipt")
        parsed = receipt if isinstance(receipt, Receipt) else Receipt.from_dict(dict(receipt))
        if (
            parsed.request_id != authorization.request_id
            or parsed.nonce != authorization.nonce
            or parsed.lease_id != authorization.lease_id
            or parsed.executor_audience != authorization.executor_audience
            or parsed.transition != authorization.transition
            or parsed.evidence_digest != canonical_digest(dict(authorization.evidence))
        ):
            raise PolicyError("receipt does not bind the authorized MCP tool effect")
        return parsed

    def revoke_lease(
        self,
        identity: IdentityContext,
        *,
        operation_id: str,
        lease_id: str,
        reason: str = "mcp.cancel",
    ) -> WireObject:
        identity = self._verified(identity)
        require_identifier(operation_id, field="MCP operation id")
        require_identifier(lease_id, field="lease_id")
        key = MCPOperationKey(identity.tenant_id, identity.subject_id, operation_id)
        return self.authorizer.revoke(
            lease_id,
            request_id=derive_id("revoke", key),
            reason=reason,
        )

    def _verified(self, identity: IdentityContext) -> IdentityContext:
        if not isinstance(identity, IdentityContext):
            raise ValidationError("identity must be a verified IdentityContext, not request data")
        if identity.tenant_id != self.authorizer.profile.tenant_id:
            raise PolicyError("identity tenant does not match the configured LETS tenant")
        return identity

    def _binding(self, tool_name: str) -> tuple[str, str, str]:
        require_identifier(tool_name, field="MCP tool name")
        scope = self.tool_scopes.get(tool_name)
        if scope is None:
            raise PolicyError(f"MCP tool {tool_name!r} is not mapped by this profile")
        return scope, self.scope_capabilities[scope], self.scope_transitions[scope]
