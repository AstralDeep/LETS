# LETS production architecture

Status: implementation contract for LETS v1.

LETS is a distributed authorization runtime for changing populations of agents and other
autonomous workers. It is not an agent framework, scheduler, model host, or transport. A LETS
cluster mediates protected effects and preserves a finite multi-dimensional envelope while
subjects spawn descendants, disconnect, recover, and move work between sites.

## Hard acceptance boundary

The v1 release is complete only when three or more independently persisted warden processes can
run on separate network nodes, continue locally during peer partitions, transfer rights without
duplication after retry/reorder/restart, and issue receipts that an independent executor verifies
and consumes exactly once. In-process simulations and a single database with several logical
warden objects do not satisfy this boundary.

## Topology

```text
                    cluster manifest / trust roots
                               |
             +-----------------+-----------------+
             |                 |                 |
        +----v-----+       +----v-----+       +----v-----+
        | warden A |<----->| warden B |<----->| warden C |
        | SQLite A | peer  | SQLite B | peer  | SQLite C |
        +----+-----+       +----+-----+       +----+-----+
             |                  |                  |
       local leases       local leases       local leases
             |                  |                  |
        +----v-----+       +----v-----+       +----v-----+
        | executor |       | executor |       | executor |
        +----------+       +----------+       +----------+
```

Each warden is a stable accounting replica with its own durable database and signing identity.
Ephemeral agents are leased subjects, not database replicas. A protected executor performs an
effect only after it verifies and durably consumes a fresh, audience-bound warden receipt.

## Why LETS does not run consensus for every transition

At envelope creation, a signed cluster manifest assigns disjoint rights shares to wardens. A
warden may spend, lease, or subdivide only its locally owned share. Therefore ordinary local
transitions need no peer round trip and remain safe during a peer/control-plane partition. A
cross-warden transfer is an explicit quantity-preserving handoff with a source sequence, signed
voucher, exactly-once target acceptance, signed acknowledgement, and source finalization.

This design preserves a global safety invariant while accepting the corresponding availability
trade-off: rights stranded at an unreachable warden are unavailable elsewhere. LETS does not
claim that all work remains available under every partition.

## State ownership

Every envelope is identified by `(tenant_id, envelope_id, config_epoch)` and declares an ordered
resource schema. Values are non-negative signed-64-bit-range integers; dimensions and units never
change within an epoch. V1 permits 1--256 dimensions. Root and child allocations and every
protected-transition cost must contain at least one nonzero component, preventing cost-free
authority trees or unbounded zero-cost receipt production.

The authoritative conservation equation is:

```text
initial budget + accepted replenishment
  = free pools
  + lease residuals
  + consumed rights
  + source-owned in-flight transfers
```

A quantity appears in exactly one ownership class on a consistent distributed cut. Audit logs,
discovery metadata, and eventually delivered events are not authority and are excluded from the
safety equation.

## Warden transaction boundary

Each state-changing command is one durable local transaction. Transition authorization performs
the following steps atomically:

1. authenticate the caller outside the request body;
2. resolve the immutable tenant, envelope, epoch, policy, and machine digests;
3. check the envelope-global idempotency key plus operation name and full request fingerprint;
4. lock and validate lease status, subject, expiry, branch revocations, state, sequence,
   capabilities, audience, clock uncertainty, and evidence;
5. debit the non-negative transition cost and update machine state/sequence;
6. persist the signed receipt, idempotent response, hash-chained audit record, and outbox event;
7. commit before returning the receipt.

SQLite uses WAL, foreign keys, `BEGIN IMMEDIATE`, `synchronous=FULL`, a bounded busy timeout, and
an integrity check on startup. The storage port permits a later PostgreSQL implementation without
changing domain or wire contracts.

## Agent lifecycle

- `issue_root` partitions rights from a warden free pool into a root lease.
- `spawn` atomically subtracts a child allocation from a parent residual. Capabilities, allowed
  machines, TTL, tenant, envelope, epoch, and exact policy digest are inherited or attenuated.
  Lineage depth is capped at 64.
- `authorize` emits a short-lived signed receipt after a legal, funded state transition.
- `quiesce` and `resume` control lease actionability without inventing a second machine state.
- `renew` never lets a descendant outlive its parent. Parent shortening beneath a live descendant
  is rejected in v1.
- `revoke_branch` creates a signed, monotonic branch revocation record. Disconnected descendants
  remain bounded by their residual rights and nested expiries.
- `close` and expiry reclamation return only the lease's own residual. Reclamation waits through
  clock uncertainty and the maximum outstanding receipt lifetime.

Active-subtree migration is not a v1 operation. Cross-node placement uses free-right transfer
followed by issuance at the target. Copy-and-delete migration is forbidden because it can duplicate
authority.

## Transfer protocol

For each `(envelope, source, target)` stream, the source assigns a strictly increasing sequence.

1. **Prepare:** atomically debit the source free pool and persist/sign a voucher. Timeout never
   restores the amount.
2. **Accept:** the target authenticates the source, applies a bounded sequence-window rule, credits
   the amount once, advances a contiguous high-water mark or gap set, and signs an acknowledgement.
3. **Finalize:** the source verifies the target acknowledgement and marks the transfer complete.
4. **Checkpoint:** peers exchange signed contiguous watermarks before compacting per-transfer
   records below the common checkpoint.

Before checkpoint compaction, duplicate vouchers return the original logical acknowledgement.
After compaction, the signed covered prefix is rejected without credit. A conflicting sequence, a
gap beyond the configured window, an unknown epoch, or an untrusted peer fails closed.

## Network planes

- **Client API:** authenticated commands and read-only snapshots. Identity is derived from a
  verified token or mutually authenticated connection, never trusted from JSON fields.
- **Peer mutation API:** transfer, revocation, and checkpoint requests are Ed25519 message-signed
  over TLS and require durable timestamp/nonce replay protection. Each accepted transport nonce is
  a signed, hash-chained core authority event covered by the same external monotonic checkpoint as
  resource state; there is no independently rollbackable replay store in schema 2. Deployments may
  additionally require mTLS. Key discovery and liveness/readiness are separate public, unsigned
  read endpoints; discovering a key or a healthy node never grants authority.
- **Executor API/library:** offline receipt signature and exact policy/trust-registry verification
  plus a durable replay store. Production stores bind a database-instance identity, monotonic
  clock floor, and append-only claim-chain head to a linearizable external CAS in an independent
  rollback domain. A stale restore or concurrent clone loses admission; a committed claim is not
  returned until its head is anchored. An executor must still bind receipt consumption to its
  application effect as atomically as its domain permits.
- **Operator API:** loopback or separately protected health, invariant, audit verification,
  reconciliation, and maintenance endpoints.

The Python service is an application-core port, not an authentication boundary. Direct calls such
as `register_policy` are trusted in-process administration and belong to the host TCB; network
adapters must authenticate and authorize them. Evidence rules are bounded to depth 32 and 256
nodes/values, machines to 1,024 transitions, and manifests to bounded v1 collection counts and a
16 MiB encoded file. Extension values accepted by direct library calls are likewise trusted host
inputs, not agent-controlled authority.

## Portable interoperability boundary

LETS consumes stable IDs, versioned JSON, and authenticated identity context. It does not require
MCP, A2A, Kubernetes, AstralDeep, a particular agent model, or a particular workload. Adapters map
their native lifecycle and tool calls to the LETS client API; they may not bypass executor receipt
verification or mint LETS authority.

Discovery is not authorization. An advertised skill becomes executable only after intersecting
transport support, site policy, lease capabilities/residual, executor audience policy, and any
required attestation. Recommended profiles compose with, rather than replace, [A2A Agent
Cards](https://a2a-protocol.org/latest/specification), [MCP capability
negotiation](https://modelcontextprotocol.io/specification/2026-07-28),
[SPIFFE workload identity](https://spiffe.io/docs/latest/spiffe-specs/), [OCI
artifacts](https://github.com/opencontainers/image-spec/blob/main/manifest.md), and
[CloudEvents](https://github.com/cloudevents/spec).

## AstralDeep extension

The optional AstralDeep adapter is a separate consumer of the public LETS client/executor
interfaces. It maps mediated agent creation and `AgentHopRequest` delegation into LETS commands
while preserving AstralDeep's Keycloak identity, RFC 8693 token attenuation, owner isolation,
tool-policy, PHI/egress, confirmation, and hash-chained audit gates. LETS core never imports
AstralDeep modules or writes AstralDeep tables.

## Operability and evidence

The repository ships a three-warden Docker Compose topology, health/readiness checks,
persistent volumes, key/bootstrap tooling, metrics, structured audit events, a fault proxy, and
documented backup/restore rules. Release evidence covers clean start, explicit no-create recovery,
crash/restart, duplicate/reorder/drop/partition behavior, durable clock-floor rollback rejection,
executor and peer replay, bounded model exploration, and reproducible single-host performance
measurements. Cross-version rolling-upgrade evidence is future work and is not claimed for v1.
