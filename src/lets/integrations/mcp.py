"""MCP (Model Context Protocol) integration profile and authorizer for LETS.

Provides protocol-neutral mapping of host-verified tool execution to stable
request IDs, transition/evidence bindings, executor audiences, and claims.

Pinned MCP Specification Revision: 2024-11-05 (JSON-RPC 2.0 Transport)
Reference: https://spec.modelcontextprotocol.io/
Optional SDK Dependency: mcp >= 1.0.0
"""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from lets.canonical import canonical_digest
from lets.errors import PolicyError, ValidationError
from lets.ids import require_digest, require_identifier
from lets.integrations.ports import AuthorizerClient, WireObject

# Pinned MCP Specification Revision
MCP_SPEC_REVISION = "2024-11-05"
MCP_PROFILE_ID = "lets.mcp-profile/v1"

__all__ = [
    "MCPAuthorizer",
    "MCPProfile",
    "MCPToolInvocationReceipt",
    "MCP_PROFILE_ID",
    "MCP_SPEC_REVISION",
]


@dataclass(frozen=True, slots=True)
class MCPProfile:
    """Configuration profile for MCP authorizer boundaries."""

    expected_audience: str
    expected_tenant: str
    allowed_tools: frozenset[str]
    spec_version: str = MCP_SPEC_REVISION
    enforce_confirmation_gate: bool = True
    default_identity: str = "mcp-executor"

    def __post_init__(self) -> None:
        if isinstance(self.allowed_tools, (set, list, tuple)):
            object.__setattr__(
                self, "allowed_tools", frozenset(self.allowed_tools)
            )
        require_identifier(self.expected_audience, field="expected_audience")
        require_identifier(self.expected_tenant, field="expected_tenant")
        require_identifier(self.default_identity, field="default_identity")
        if not self.allowed_tools:
            raise ValidationError(
                "MCP profile requires at least one allowed tool"
            )
        for tool in self.allowed_tools:
            require_identifier(tool, field="allowed_tool")


@dataclass(frozen=True, slots=True)
class MCPToolInvocationReceipt:
    """Immutable cryptographic claim and receipt for verified tool execution."""

    request_id: str
    tool_name: str
    args_digest: str
    effect_digest: str
    lease_id: str
    audience: str
    tenant: str
    identity: str
    nonce: str
    auth_record: WireObject


class MCPAuthorizer:
    """Protocol-neutral authorizer adapter for Model Context Protocol execution.

    Implements:
    - Discovery without authority: inspects manifests without issuing tokens.
    - Host permission/confirmation gate enforcement.
    - Empty tool scope fails closed.
    - LETS-CJ/1 canonical request and effect digest binding.
    - Actual LETS AuthorizerClient invocation for leased authorizations.
    - At-most-once authorization semantics with durable replay protection.
    - verify_and_claim immediately preceding the tool effect.
    """

    def __init__(
        self,
        authorizer_client: AuthorizerClient,
        profile: MCPProfile,
        *,
        default_lease_id: str = "mcp-root-lease",
        replay_registry: set[str] | None = None,
    ) -> None:
        self._client = authorizer_client
        self._profile = profile
        self._default_lease_id = default_lease_id
        self._lock = threading.Lock()
        self._receipts: dict[str, MCPToolInvocationReceipt] = {}
        self._claimed_ids: set[str] = (
            replay_registry if replay_registry is not None else set()
        )
        self._cancelled_ids: set[str] = set()

    def discover_tools(
        self, tools_manifest: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        """Discovery without authority: returns metadata with authorized=False."""
        discovered: list[dict[str, Any]] = []
        for t in tools_manifest:
            tool_name = str(t.get("name", ""))
            if tool_name in self._profile.allowed_tools:
                discovered.append(
                    {
                        "name": tool_name,
                        "description": t.get("description", ""),
                        "input_schema": t.get("input_schema", {}),
                        "authorized": False,
                    }
                )
        return discovered

    def authorize_invocation(
        self,
        request_id: str,
        tool_name: str,
        tool_args: Mapping[str, Any],
        audience: str,
        tenant: str,
        *,
        identity: str | None = None,
        nonce: str = "mcp-nonce-0",
        host_confirmed: bool = True,
        lease_id: str | None = None,
    ) -> MCPToolInvocationReceipt:
        """Evaluates permission gates, calls client, and binds receipt."""
        require_identifier(request_id, field="request_id")
        require_identifier(tool_name, field="tool_name")
        require_identifier(audience, field="audience")
        require_identifier(tenant, field="tenant")
        effective_identity = identity or self._profile.default_identity
        require_identifier(effective_identity, field="identity")
        target_lease = lease_id or self._default_lease_id

        # 1. Empty scope fail closed & tool permit check
        if not self._profile.allowed_tools:
            raise PolicyError("Empty tool scope: no tools permitted.")
        if tool_name not in self._profile.allowed_tools:
            raise PolicyError(
                f"Tool {tool_name} not permitted in profile scope."
            )

        # 2. Host confirmation gate
        if self._profile.enforce_confirmation_gate and not host_confirmed:
            raise PolicyError("Host confirmation gate rejected tool invocation.")

        # 3. Audience and tenant enforcement
        if audience != self._profile.expected_audience:
            raise PolicyError(
                f"Mismatched audience: expected {self._profile.expected_audience}, "
                f"got {audience}"
            )
        if tenant != self._profile.expected_tenant:
            raise PolicyError(
                f"Mismatched tenant: expected {self._profile.expected_tenant}, "
                f"got {tenant}"
            )

        # 4. LETS-CJ/1 canonical digest binding
        args_digest = canonical_digest(tool_args)
        effect_payload = {
            "args_digest": args_digest,
            "audience": audience,
            "identity": effective_identity,
            "nonce": nonce,
            "request_id": request_id,
            "tenant": tenant,
            "tool": tool_name,
        }
        effect_digest = canonical_digest(effect_payload)

        with self._lock:
            # 5. Idempotent request / conflicting identity & replay detection
            if request_id in self._receipts:
                existing = self._receipts[request_id]
                if existing.tool_name != tool_name:
                    raise ValidationError(
                        f"Mismatched tool on identical request ID: {request_id}"
                    )
                if existing.args_digest != args_digest:
                    raise ValidationError(
                        "Changed arguments detected on identical request ID: "
                        f"{request_id}"
                    )
                if existing.audience != audience or existing.tenant != tenant:
                    raise PolicyError(
                        "Mismatched audience/tenant on identical request ID: "
                        f"{request_id}"
                    )
                if existing.identity != effective_identity:
                    raise PolicyError(
                        f"Mismatched identity on identical request ID: {request_id}"
                    )
                if request_id in self._claimed_ids:
                    raise PolicyError(
                        f"Duplicate invocation: request {request_id} already claimed."
                    )
                return existing

            if request_id in self._claimed_ids:
                raise PolicyError(
                    f"Duplicate invocation: request {request_id} already claimed."
                )

            # 6. Actual LETS AuthorizerClient invocation
            auth_payload: dict[str, Any] = {
                "args_digest": args_digest,
                "audience": audience,
                "effect_digest": effect_digest,
                "identity": effective_identity,
                "nonce": nonce,
                "request_id": request_id,
                "scope": sorted(self._profile.allowed_tools),
                "tenant_id": tenant,
                "tool": tool_name,
            }
            auth_record = self._client.authorize(target_lease, auth_payload)

            # 7. Construct immutable signed invocation receipt
            receipt = MCPToolInvocationReceipt(
                request_id=request_id,
                tool_name=tool_name,
                args_digest=args_digest,
                effect_digest=effect_digest,
                lease_id=target_lease,
                audience=audience,
                tenant=tenant,
                identity=effective_identity,
                nonce=nonce,
                auth_record=auth_record,
            )
            self._receipts[request_id] = receipt
            return receipt

    def verify_and_claim(
        self,
        request_id: str,
        effect_digest: str,
        *,
        durable_store: set[str] | None = None,
    ) -> None:
        """Verifies receipt binding and claims execution before effect."""
        require_identifier(request_id, field="request_id")
        require_digest(effect_digest, field="effect_digest")
        with self._lock:
            if request_id in self._claimed_ids:
                raise PolicyError(
                    f"Duplicate invocation: request {request_id} already claimed."
                )
            if request_id not in self._receipts:
                raise ValidationError(
                    f"Missing receipt for request ID: {request_id}"
                )
            receipt = self._receipts[request_id]

            if request_id in self._cancelled_ids:
                raise PolicyError(
                    f"Cannot claim cancelled request: {request_id}"
                )
            if receipt.effect_digest != effect_digest:
                raise ValidationError(
                    "Effect digest mismatch during verify_and_claim."
                )

            # Record durable claim
            self._claimed_ids.add(request_id)
            if durable_store is not None:
                durable_store.add(request_id)

    def cancel_invocation(self, request_id: str) -> None:
        """Cancels an existing authorization lease before execution."""
        require_identifier(request_id, field="request_id")
        with self._lock:
            if request_id in self._claimed_ids:
                raise PolicyError(
                    "Cannot cancel already-executed tool invocation."
                )
            if request_id in self._receipts:
                self._cancelled_ids.add(request_id)
