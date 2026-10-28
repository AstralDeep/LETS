"""Package of host-system adapters built only on LETS's public client contracts; exposes
the AstralDeep profile (astraldeep.py), the generic replica-lifecycle mapping
(ports.py), the optional A2A task/delegation profile (a2a.py), and the optional MCP
tool-execution profile (mcp.py).
"""

from lets.integrations.a2a import A2ATaskProfile, AudienceBinding, TaskLedger
from lets.integrations.astraldeep import AstralDeepAuthorizer, AstralDeepProfile
from lets.integrations.mcp import (
    HostToolApproval,
    MCPAudienceBinding,
    MCPOperationKey,
    MCPToolAuthorization,
    MCPToolDescriptor,
    MCPToolProfile,
    ToolGate,
)
from lets.integrations.ports import AuthorizerClient, ReplicaAuthorizer, ReplicaProfile

__all__ = [
    "A2ATaskProfile",
    "AstralDeepAuthorizer",
    "AstralDeepProfile",
    "AudienceBinding",
    "AuthorizerClient",
    "HostToolApproval",
    "MCPAudienceBinding",
    "MCPOperationKey",
    "MCPToolAuthorization",
    "MCPToolDescriptor",
    "MCPToolProfile",
    "ReplicaAuthorizer",
    "ReplicaProfile",
    "TaskLedger",
    "ToolGate",
]
