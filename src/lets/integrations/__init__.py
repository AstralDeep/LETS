"""Package of host-system adapters built only on LETS's public client contracts; exposes
the AstralDeep profile (astraldeep.py), the generic replica-lifecycle mapping
(ports.py), and the optional A2A task/delegation profile (a2a.py).
"""

from lets.integrations.a2a import A2ATaskProfile, AudienceBinding, TaskLedger
from lets.integrations.astraldeep import AstralDeepAuthorizer, AstralDeepProfile
from lets.integrations.mcp import MCPAuthorizer, MCPProfile
from lets.integrations.ports import AuthorizerClient, ReplicaAuthorizer, ReplicaProfile

__all__ = [
    "A2ATaskProfile",
    "AstralDeepAuthorizer",
    "AstralDeepProfile",
    "AudienceBinding",
    "AuthorizerClient",
    "MCPAuthorizer",
    "MCPProfile",
    "ReplicaAuthorizer",
    "ReplicaProfile",
    "TaskLedger",
]
