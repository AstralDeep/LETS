# Model Context Protocol (MCP) Integration Profile

## Overview
This document specifies the Model Context Protocol (MCP) integration profile for LETS, fulfilling the requirements of [LETS #71](https://github.com/AstralDeep/LETS/issues/71).

- **Profile Identifier:** `lets.mcp-profile/v1`
- **Pinned MCP Specification Revision:** `2024-11-05` (JSON-RPC 2.0 Transport)
- **Optional SDK Dependency:** `mcp >= 1.0.0`
- **Transport / Auth Boundary:** Protocol-neutral. The MCP client/server transport, JSON-RPC 2.0 message handling, and IAM identity verification reside entirely in the host application; LETS provides lineage escrow, lease attenuation, and durable at-most-once authorization. No credentials, tokens, or opaque agent internal states are passed through the adapter.
- **Core Runtime Impact:** Unchanged. Only `lets.integrations.mcp` is introduced; core runtime storage schemas and protocol engines remain untouched.

## Guarantees
1. **Discovery without Authority:** `discover_tools` inspects manifests without issuing invocation tokens or contacting the warden. Discovered tool metadata sets `authorized: False`.
2. **Host Confirmation Gates:** Permission must be explicitly confirmed by the host before token issuance. Disabling confirmation requires explicit profile override.
3. **Canonical Digest Binding:** Invocation parameters and effect contexts are cryptographically hashed using LETS-CJ/1 canonical JSON digests (`canonical_digest`) and bound to the lease receipt.
4. **Immediate Claim:** `verify_and_claim` is invoked immediately preceding the tool effect to verify effect digest bindings and record durable replay claims.
5. **At-Most-Once Authorization:** Authorization leases are evaluated once per distinct request ID. Replayed or duplicated requests are rejected at the edge. Effect idempotency is handled separately by the target tool provider.
