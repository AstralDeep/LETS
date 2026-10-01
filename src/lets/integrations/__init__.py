"""Package of host-system adapters built only on LETS's public client contracts; exposes
the AstralDeep profile (astraldeep.py) and the generic replica-lifecycle mapping
(ports.py).
"""

from lets.integrations.astraldeep import AstralDeepAuthorizer, AstralDeepProfile
from lets.integrations.ports import AuthorizerClient, ReplicaAuthorizer, ReplicaProfile
from lets.integrations.mcp import MCPAuthorizer, MCPProfile

__all__ = [
    "AstralDeepAuthorizer",
    "AstralDeepProfile",
    "AuthorizerClient",
    "ReplicaAuthorizer",
    "ReplicaProfile",
    "MCPAuthorizer",
    "MCPProfile",
]
