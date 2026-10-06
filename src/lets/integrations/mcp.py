"""Model Context Protocol (MCP) integration profile for LETS protected tool execution.

Provides an independently reusable profile and authorizer mapping MCP tool calls
to LETS stable request IDs, transition/evidence bindings, executor audiences, and receipt claims.
LETS remains protocol-neutral while hosting the integration logic.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from lets.integrations.ports import AuthorizerClient


@dataclass(frozen=True)
class MCPProfile:
    """Configuration profile for Model Context Protocol integration."""

    tenant_id: str
    envelope_id: str
    policy_digest: str
    tool_capabilities: Mapping[str, str] = field(default_factory=dict)
    tool_transitions: Mapping[str, str] = field(default_factory=dict)
    default_allocation: tuple[int, int] = (1_000_000, 100_000_000)
    default_ttl_ns: int = 300_000_000_000


class MCPAuthorizer:
    """Authorizer for MCP tool calls using LETS leases and policies."""

    def __init__(self, client: AuthorizerClient, profile: MCPProfile) -> None:
        self.client = client
        self.profile = profile

    def authorize_tool(
        self,
        *,
        agent_id: str,
        tool_name: str,
        request_id: str,
        audience: str,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Authorize a protected tool invocation via MCP.

        Maps host-verified tool operations to stable request IDs, transition/evidence
        bindings, executor audiences, and receipt claims.
        """
        capability = self.profile.tool_capabilities.get(tool_name)
        if not capability:
            raise ValueError(f"Unknown or unmapped MCP tool capability for tool: {tool_name}")

        transition = self.profile.tool_transitions.get(tool_name, "execute")

        payload: dict[str, Any] = {
            "request_id": request_id,
            "agent_id": agent_id,
            "capability": capability,
            "transition": transition,
            "executor_audience": audience,
            "evidence": evidence or {},
        }

        # Delegate authorization to LETS client
        result = self.client.authorize(self.profile.envelope_id, payload)
        return dict(result)
