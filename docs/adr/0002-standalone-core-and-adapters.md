# ADR 0002: standalone core with protocol adapters

- Status: accepted
- Date: 2026-08-09

## Context

AstralDeep is the initial integration target, while LETS must work for robotics, infrastructure,
healthcare, logistics, software agents, and non-agent workflows without inheriting one host's
database, identity provider, UI schema, or lifecycle implementation.

## Decision

Keep the domain, storage, wire protocol, warden service, and executor verifier free of AstralDeep
imports. Publish library and HTTP client ports. Implement AstralDeep, A2A, MCP, and future system
mappings as optional adapters that preserve the host's existing identity and policy gates.

## Consequences

- LETS can be deployed and tested independently.
- Integration occurs through versioned manifests and APIs rather than shared tables.
- Adapters carry explicit mapping and downgrade tests.
- The AstralDeep adapter can evolve on its own release cadence.
