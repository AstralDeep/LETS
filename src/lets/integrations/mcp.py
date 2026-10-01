"""MCP (Model Context Protocol) integration profile and authorizer for LETS.

Provides protocol-neutral mapping of host-verified tool execution to stable
request IDs, transition/evidence bindings, executor audiences, and receipt claims.

Pinned MCP Specification Revision: 2024-11-05 (JSON-RPC 2.0 Transport)
Reference: https://spec.modelcontextprotocol.io/
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from lets.errors import PolicyError, ValidationError
from lets.integrations.ports import AuthorizerClient

# Pinned MCP Specification Revision
MCP_SPEC_REVISION = "2024-11-05"


@dataclass(frozen=True)
class MCPProfile:
    """Configuration profile for MCP authorizer boundaries."""

    expected_audience: str
    expected_tenant: str
    spec_version: str = MCP_SPEC_REVISION
    enforce_confirmation_gate: bool = True
    allowed_tools: list[str] | None = None


@dataclass
class MCPToolInvocationReceipt:
    """Cryptographic claim and receipt for verified tool execution."""

    request_id: str
    tool_name: str
    args_digest: str
    lease_id: str
    audience: str
    tenant: str
    verified: bool = False
    executed: bool = False
    cancelled: bool = False


class MCPAuthorizer:
    """Protocol-neutral authorizer adapter for Model Context Protocol execution.

    Implements:
    - Discovery without authority.
    - Host permission/confirmation gates.
    - Request and effect digest binding.
    - verify_and_claim immediately before tool effect.
    - At-most-once authorization semantics.
    """

    def __init__(self, authorizer_client: AuthorizerClient, profile: MCPProfile):
        self._client = authorizer_client
        self._profile = profile
        self._lock = threading.Lock()
        self._receipts: dict[str, MCPToolInvocationReceipt] = {}

    def _compute_digest(self, payload: Mapping[str, Any]) -> str:
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def discover_tools(self, tools_manifest: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Discovery without authority: returns metadata without issuing authorization tokens."""
        discovered = []
        for t in tools_manifest:
            tool_name = t.get("name", "")
            if not self._profile.allowed_tools or tool_name in self._profile.allowed_tools:
                discovered.append({
                    "name": tool_name,
                    "description": t.get("description", ""),
                    "input_schema": t.get("input_schema", {}),
                    "authorized": False,
                })
        return discovered

    def authorize_invocation(
        self,
        request_id: str,
        tool_name: str,
        tool_args: Mapping[str, Any],
        audience: str,
        tenant: str,
        host_confirmed: bool = True,
    ) -> MCPToolInvocationReceipt:
        """Evaluates host permission gate and creates an at-most-once invocation receipt."""
        with self._lock:
            # 1. Tenant and Audience boundary check
            if audience != self._profile.expected_audience:
                msg = f"Mismatched audience: expected {self._profile.expected_audience}, got {audience}"
                raise PolicyError(msg)
            if tenant != self._profile.expected_tenant:
                msg = f"Mismatched tenant: expected {self._profile.expected_tenant}, got {tenant}"
                raise PolicyError(msg)

            # 2. Scope / Tool allowlist check
            if self._profile.allowed_tools and tool_name not in self._profile.allowed_tools:
                raise PolicyError(f"Tool {tool_name} not permitted in profile scope.")

            # 3. Host confirmation gate
            if self._profile.enforce_confirmation_gate and not host_confirmed:
                raise PolicyError("Host confirmation gate rejected tool invocation.")

            args_digest = self._compute_digest(tool_args)

            # 4. At-most-once invocation protection & Duplicate detection
            if request_id in self._receipts:
                existing = self._receipts[request_id]
                if existing.args_digest != args_digest:
                    raise ValidationError(
                        f"Changed arguments detected on identical request ID: {request_id}"
                    )
                if existing.executed:
                    raise PolicyError(
                        f"Duplicate invocation: request {request_id} has already executed."
                    )
                return existing

            receipt = MCPToolInvocationReceipt(
                request_id=request_id,
                tool_name=tool_name,
                args_digest=args_digest,
                lease_id=f"mcp-lease-{request_id[:16]}",
                audience=audience,
                tenant=tenant,
                verified=False,
                executed=False,
            )
            self._receipts[request_id] = receipt
            return receipt

    def verify_and_claim(self, request_id: str, args_digest: str) -> None:
        """verify_and_claim immediately precedes tool execution effect."""
        with self._lock:
            if request_id not in self._receipts:
                raise ValidationError(f"Missing receipt for request ID: {request_id}")
            receipt = self._receipts[request_id]

            if receipt.cancelled:
                raise PolicyError(f"Cannot claim cancelled request: {request_id}")
            if receipt.executed:
                raise PolicyError(
                    f"Duplicate invocation: request {request_id} already claimed and executed."
                )
            if receipt.args_digest != args_digest:
                raise ValidationError("Effect digest mismatch during verify_and_claim.")

            receipt.verified = True
            receipt.executed = True

    def cancel_invocation(self, request_id: str) -> None:
        """Cancels an existing authorization lease before execution."""
        with self._lock:
            if request_id in self._receipts:
                receipt = self._receipts[request_id]
                if receipt.executed:
                    raise PolicyError("Cannot cancel already-executed tool invocation.")
                receipt.cancelled = True
