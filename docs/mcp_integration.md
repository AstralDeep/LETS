# Model Context Protocol (MCP) Integration Profile

## Overview
This document specifies the Model Context Protocol (MCP) integration profile for LETS, fulfilling the requirements of [LETS #71](https://github.com/AstralDeep/LETS/issues/71).

- **Pinned MCP Specification Revision:** `2024-11-05` (JSON-RPC 2.0 Transport)
- **Transport / Auth Boundary:** Protocol-neutral. The MCP server and IAM identity reside in the host; LETS maintains at-most-once authorization and effect digest binding.
- **Core Runtime Impact:** Unchanged. Only `lets.integrations.mcp` is introduced.

## Guarantees
1. **Discovery without Authority:** `discover_tools` provides metadata without issuing invocation tokens.
2. **Host Confirmation Gates:** Permission must be explicitly confirmed before token issuance.
3. **Digest Binding:** Invocation parameters are cryptographically hashed using SHA-256 and bound to the lease receipt.
4. **Immediate Claim:** `verify_and_claim` is invoked immediately preceding tool execution to enforce at-most-once execution.
