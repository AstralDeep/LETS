# ADR 0001: distributed escrow instead of per-action consensus

- Status: accepted
- Date: 2026-08-09

## Context

LETS must preserve a hard population-wide resource envelope while useful local work continues
during peer partitions. Per-action consensus preserves a total order but makes every protected
effect unavailable when a quorum cannot be reached.

## Decision

Assign disjoint, durable resource shares to stable wardens. Each warden authorizes only from its
local ownership. Coordinate only when ownership moves between wardens, using signed sequenced
vouchers, exactly-once acceptance, acknowledgement, and checkpointed compaction.

## Consequences

- Local transitions and local recursive spawn do not require a peer round trip.
- Aggregate conservation follows from disjoint ownership plus atomic local transactions.
- A partition can strand rights and reduce useful work at another site.
- Peer transfer and restore/fencing protocols become security-critical.
- This is a distributed multi-node runtime but not a replicated-state-machine cluster.
