"""Model Context Protocol (MCP) integration profile for LETS protected tool execution.

Provides an independently reusable profile and authorizer mapping MCP tool calls
to LETS stable request IDs, transition/evidence bindings, executor audiences, and receipt claims.
LETS remains protocol-neutral while hosting the integration logic.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Optional, Mapping

from lets.client import LETSClient
from lets.integrations.ports import Authorizer


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


class MCPAuthorizer(Authorizer):
    """Authorizer for MCP tool calls using LETS leases and policies."""

    def __init__(self, client: LETSClient, profile: MCPProfile) -> None:
        self.client = client
        self.profile = profile

    def authorize_tool(
        self,
        *,
        agent_id: str,
        tool_name: str,
        request_id: str,
        audience: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Authorize a protected tool invocation via MCP.

        Maps host-verified tool operations to stable request IDs, transition/evidence
        bindings, executor audiences, and receipt claims.
        """
        capability = self.profile.tool_capabilities.get(tool_name)
        if not capability:
            raise ValueError(f"Unknown or unmapped MCP tool capability for tool: {tool_name}")

        transition = self.profile.tool_transitions.get(tool_name, "execute")

        # Delegate authorization to LETS client
        result = self.client.authorize(
            tenant_id=self.profile.tenant_id,
            envelope_id=self.profile.envelope_id,
            agent_id=agent_id,
            capability=capability,
            transition=transition,
            request_id=request_id,
            audience=audience,
            evidence=evidence or {},
        )
        return result
