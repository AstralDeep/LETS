# Model Context Protocol (MCP) Integration Profile

LETS provides a thin, tested Model Context Protocol (MCP) integration profile for protected tool execution.
The MCP server and user IAM remain in the host; LETS remains strictly protocol-neutral.

## Overview

The MCP integration profile maps host-verified tool operations to:
1. Stable request IDs for idempotency and tracing.
2. Transition and evidence bindings.
3. Executor audiences for cryptographically bound receipt validation.
4. Receipt claims before effect execution.

## Concrete Mapping

`lets.integrations.MCPAuthorizer` maps declared MCP tool names to LETS capabilities and policy transitions.

from lets.client import LETSClient
from lets.integrations import MCPAuthorizer, MCPProfile

lets_client = LETSClient(lets_url, token=service_token)
authorizer = MCPAuthorizer(
    lets_client,
    MCPProfile(
        tenant_id="tenant-1",
        envelope_id="mcp-envelope",
        policy_digest=policy_digest,
        tool_capabilities={
            "fs_read": "mcp.fs.read",
            "fs_write": "mcp.fs.write",
        },
        tool_transitions={
            "fs_read": "read",
            "fs_write": "write",
        },
    ),
)

## Protected Execution Flow

1. The host MCP server receives a tool call request from an LLM client.
2. The host verifies user authentication and IAM permissions.
3. The host generates a stable `request_id` and invokes `MCPAuthorizer.authorize_tool(...)`.
4. LETS validates the lease, capabilities, and policy state, returning an authoritative receipt bound to the executor audience.
5. The host verifies the receipt and executes the tool effect.
