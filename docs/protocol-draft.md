# LETS Protocol Contract v1 (Implementation Draft)

This document specifies the interoperable contract implemented by the LETS v0.1 runtime. It is
not yet a frozen standards-track specification. Normative terms **MUST**, **SHOULD**, and **MAY**
apply to v1 implementations unless a passage is explicitly marked as future work.

`protocol/openapi.yaml` is the normative HTTP request/response schema. The JSON examples below use
real v1 field names and types; the policy, grant, and receipt examples were generated from the
runtime models with a fixed documentation key so their digests and signatures are reproducible.

## 1. Roles and trust boundary

- **Agent / subject:** proposes transitions and may request attenuated child leases. It is untrusted with respect to conservation and transition legality.
- **Warden:** authoritative mediator for local lease state, residual rights, HSM state, epochs, transfer records, and signed receipts. Wardens are assumed crash-stop in the base model.
- **Protected executor:** performs an external effect only after verifying a fresh warden receipt for its own audience.
- **Evidence provider:** signs or otherwise authenticates sensor observations. Evidence can satisfy a guard but cannot create rights.
- **Rebalancer:** recommends movement of free rights between wardens. It is advisory; source and target wardens enforce transfer conservation.

Every policy-scoped effect MUST pass through a protected executor that rejects direct agent calls. This complete-mediation assumption is part of the trusted computing base.

## 2. Identifiers and clocks

Most identifiers are opaque Unicode strings or UUIDs:

- `lineage_id`: immutable root-population identifier.
- `lease_id`: immutable grant identifier.
- `parent_id`: immediate authorization parent, absent only for roots.
- `subject_id`: authenticated process/workload/device principal.
- `warden_id`: stable accounting replica.
- `request_id`: caller-generated idempotency key, unique across all mutation kinds and targets in
  one `(tenant_id, envelope_id)` until its durable record expires.
- `receipt_id`: warden-generated authorization record.
- `transfer_sequence`: monotonically increasing per `(source_warden, target_warden)` stream.

Identifiers carried in HTTP paths or headers use a narrower transport grammar. `warden_id` MUST
match `^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`; node `key_id` MUST match
`^[A-Za-z0-9][A-Za-z0-9._~:/+-]{0,511}$`. Implementations MUST reject, rather than normalize,
nonconforming transport identifiers.

Manifest timestamps use UTC RFC 3339. Runtime fields ending in `_ns` are signed 64-bit Unix
nanoseconds; the peer HTTP `X-LETS-Timestamp` is signed 64-bit Unix seconds. A warden MUST maintain
an estimate of clock uncertainty.
When uncertainty exceeds policy, it MUST reject renewal and SHOULD fail closed for protected
execution whose safe expiry cannot be established. Warden, executor, and peer-replay stores MUST
persist a monotonic clock floor and reject rollback beyond that declared uncertainty across
restart.

### 2.1 LETS-CJ/1 canonical JSON

All content digests and Ed25519 signatures over protocol objects use **LETS-CJ/1**. Its canonical
octets are UTF-8 JSON with no byte-order mark, no insignificant whitespace, `,` and `:` separators,
and object keys sorted by Unicode scalar/code-point order. Values are limited to objects with
string keys, arrays, strings, booleans, null, and integers in
`[-9223372036854775808, 9223372036854775807]`. Floating-point values, non-finite numbers, unordered
sets, duplicate object keys at any depth, lone surrogates, and non-string object keys are invalid.
Strings are not Unicode-normalized; composed and decomposed spellings therefore sign differently.
Control characters use JSON escapes, while other Unicode scalar values are emitted directly.

Binary fields use the unique unpadded RFC 4648 base64url spelling. Decoders MUST reject padding,
non-alphabet characters, non-ASCII input, and encodings that do not round-trip to the same text.
SHA-256 digests use lowercase `sha256:<64 hex>` text. Normative cross-language vectors are in
`protocol/canonicalization-vectors.json`.

### 2.2 Authenticated peer HTTP

Every peer mutation carries these six singleton headers:

| Header | Meaning |
|---|---|
| `X-LETS-Warden-ID` | manifest-trusted source warden |
| `X-LETS-Key-ID` | manifest-trusted Ed25519 key |
| `X-LETS-Timestamp` | Unix seconds inside the receiver skew window |
| `X-LETS-Nonce` | fresh 16..256-character message nonce |
| `X-LETS-Content-SHA256` | SHA-256 of the exact HTTP body bytes |
| `X-LETS-Signature` | unpadded base64url Ed25519 signature |

The signed LETS-CJ/1 object has exactly `type=lets.peer-http-signature/v1`, uppercase `method`, the
exact ASGI request target (`path` plus query string when present), `content_digest`, `timestamp_s`,
`nonce`, `warden_id`, and `key_id`. Receivers verify the body digest and manifest key, then durably
claim `(warden_id, key_id, nonce)` before dispatch. Duplicate headers, stale timestamps, repeated
nonces, unknown keys, and target/body changes MUST fail closed. TLS is required for non-loopback
production endpoints; deployments MAY additionally require mTLS. Message signatures do not
replace transport confidentiality or endpoint authentication.

Manifest endpoint origins use lowercase `http` or `https`, an ASCII DNS name (including explicit
IDNA A-labels) or IP literal, and an optional TCP port in `1..65535`. IPv6 literals use hexadecimal
address syntax without a scope ID or embedded dotted-quad spelling. Admission lowercases DNS,
compresses IP literals, removes the scheme's default port and a trailing `/`, and requires one
effective peer origin per warden. Whitespace, controls, credentials, noncanonical ports, paths
other than `/`, queries, and fragments are invalid. Runtime admission permits cleartext HTTP only
under an explicit development override.

## 3. Resource and capability semantics

A resource vector is a fixed-length array of nonnegative integers. Dimensions and units are
defined by a versioned policy. This complete `PolicySpec` wire object illustrates three dimensions:

```json
{
  "policy_id": "aviation-demo",
  "policy_version": "v1",
  "resources": [
    {"id": "actuator_commands", "unit": "command"},
    {"id": "energy_millijoules", "unit": "mJ"},
    {"id": "network_egress_bytes", "unit": "byte"}
  ],
  "machine": {
    "machine_id": "autopilot",
    "initial_state": "planned",
    "transitions": [{
      "name": "commit_route",
      "source": "planned",
      "target": "committed",
      "cost": [1, 10000, 512],
      "capability": "vehicle.route.commit"
    }],
    "machine_digest": "sha256:8a83e4a6d3393b07925edcc56996acb2ad26eee718797202ca4fca6370f0f456"
  },
  "machine_digest": "sha256:8a83e4a6d3393b07925edcc56996acb2ad26eee718797202ca4fca6370f0f456",
  "max_lease_ttl_ns": 300000000000,
  "receipt_ttl_ns": 1000000000,
  "max_clock_uncertainty_ns": 50000000,
  "transfer_gap_window": 64,
  "policy_digest": "sha256:33511add6d276bbeb299efb8522b0c9a80ad48b1d26f00c7efc1a7cefc6ef70f"
}
```

Vectors MUST have the policy-defined dimensionality. Arithmetic is componentwise and MUST use checked integer operations. A child allocation MUST be no greater than its parent's residual vector. A child capability set MUST be a subset of its parent's capability set. A child expiry MUST be no later than every ancestor expiry.

## 4. Lease grant

Immutable grant fields are signed by the issuing warden:

```json
{
  "type": "lets.lease-grant/v1",
  "tenant_id": "example",
  "envelope_id": "aviation",
  "config_epoch": 1,
  "lease_id": "lease-child-42",
  "lineage_id": "lineage-root-1",
  "parent_id": "lease-parent-7",
  "subject_id": "spiffe://example/agent/42",
  "warden_id": "warden-a",
  "allocation": [100, 1000000, 10485760],
  "capabilities": ["vehicle.route.commit"],
  "policy_id": "aviation-demo",
  "policy_version": "v1",
  "policy_digest": "sha256:33511add6d276bbeb299efb8522b0c9a80ad48b1d26f00c7efc1a7cefc6ef70f",
  "machine_digest": "sha256:8a83e4a6d3393b07925edcc56996acb2ad26eee718797202ca4fca6370f0f456",
  "ancestor_path": ["lease-root-1", "lease-parent-7"],
  "branch_epoch": 7,
  "issued_at_ns": 1786161600000000000,
  "expires_at_ns": 1786161900000000000,
  "key_id": "warden-a/ed25519-56475aa75463474c0285df5dbf2bcab7",
  "signature": "vkD0q3-kBRyqN0nok00ciGiViwMviCFZRuBZw07vSVBSsmei5PMgREhuZ1Yrm7BbGm3a9Jt80FDxDxHfKoCXBg"
}
```

`residual`, current HSM `state`, and operation `sequence` are mutable authoritative fields held by the warden. Clients MAY receive snapshots, but they MUST NOT be treated as authority.

## 5. Protected transition request

An agent submits the following body to
`POST /v1/leases/{lease_id}/transitions`. The authenticated subject comes from the bearer/mTLS
identity adapter and is deliberately absent from the body:

```json
{
  "request_id": "operation-51",
  "transition": "commit_route",
  "executor_audience": "spiffe://example/executor/autopilot",
  "evidence": {
    "gps": {
      "issuer": "spiffe://example/sensor/gps-1",
      "observed_at_ns": 1786161721000000000,
      "fix_valid": true
    }
  },
  "nonce": "effect-route-51",
  "expected_state": "planned",
  "expected_sequence": 50
}
```

The warden MUST atomically verify:

1. caller identity equals the lease subject or is explicitly delegated;
2. lease status is active and unexpired under the clock-uncertainty policy;
3. lineage and branch epochs are current;
4. requested capability is present;
5. machine digest and transition are known;
6. source HSM state matches authoritative state and optional `expected_state`;
7. evidence predicates, issuer policy, freshness, and audience are satisfied;
8. residual vector covers the transition cost;
9. the envelope-global `request_id` and nonce have not produced an incompatible prior result.

On success, the same local durable transaction MUST debit residual, update HSM state, increment sequence, and persist the receipt. The external physical effect is not part of this transaction.

## 6. Receipt

```json
{
  "type": "lets.receipt/v1",
  "tenant_id": "example",
  "envelope_id": "aviation",
  "config_epoch": 1,
  "receipt_id": "receipt-51",
  "request_id": "operation-51",
  "warden_id": "warden-a",
  "key_id": "warden-a/ed25519-56475aa75463474c0285df5dbf2bcab7",
  "policy_id": "aviation-demo",
  "policy_version": "v1",
  "policy_digest": "sha256:33511add6d276bbeb299efb8522b0c9a80ad48b1d26f00c7efc1a7cefc6ef70f",
  "machine_digest": "sha256:8a83e4a6d3393b07925edcc56996acb2ad26eee718797202ca4fca6370f0f456",
  "lease_id": "lease-child-42",
  "lineage_id": "lineage-root-1",
  "subject_id": "spiffe://example/agent/42",
  "executor_audience": "spiffe://example/executor/autopilot",
  "transition": "commit_route",
  "source_state": "planned",
  "target_state": "committed",
  "cost": [1, 10000, 512],
  "resulting_sequence": 51,
  "evidence_digest": null,
  "nonce": "effect-route-51",
  "issued_at_ns": 1786161721410000000,
  "expires_at_ns": 1786161722410000000,
  "signature": "_b8AjLfRVax5YlcWmb9qSO3AZZZUkIWIc2yiYspP7a7A8RRnv9CbOigS_o3cLLSJJCDQrlH2_AzIfdvoB7fcAw"
}
```

A protected executor MUST verify the signature, key epoch, audience, freshness, machine/policy version, and nonce/sequence replay rules before performing the effect. Receipt acceptance SHOULD be durably recorded before or atomically with the application-specific effect when possible.

For each `(warden_id, lease_id, executor_audience)`, receipt expiry MUST be nondecreasing with
`resulting_sequence`. A warden that shortens a lease beneath an earlier outstanding receipt horizon
MUST refuse to issue a later receipt for that audience. This lets an executor retain a sequence
watermark through the latest accepted expiry and safely compact it only after every lower-sequence
receipt is necessarily stale.

## 7. Recursive spawn

A child request includes `parent_id`, child subject, allocation vector, requested capabilities, machine digest, and TTL. The authoritative parent warden performs an atomic partition:

```text
parent.residual := parent.residual - child.allocation
create child with child.residual := child.allocation
```

The child grant inherits the lineage, receives an ancestor-membership proof, and has `expires_at <= parent.expires_at`. Spawn is local in v0. Cross-warden spawn is represented as free-rights transfer followed by local issuance, or as the future active-subtree migration protocol; clients MUST NOT improvise a copy-and-delete migration.

## 8. Branch revocation and expiry

`POST /v1/branches/{lease_id}/revoke` increments a branch epoch and records a revocation prefix/proof. Connected wardens reject matching leases immediately and reject renewal. Disconnected descendants can continue only until their nested leases expire or their residual rights are exhausted. Revocation does not reclaim rights merely because a message was sent; reclamation requires authoritative closure, expiry under policy, or migration completion.

Expiry reclamation MUST be idempotent. A lease with nonzero residual may enter `EXPIRED_PENDING_RECLAIM`; one atomic operation returns residual to the authoritative warden and marks it reclaimed. Duplicate reclaim requests are no-ops.

## 9. Free-rights transfer

Each source-target pair has a monotonic sequence. The protocol is a quantity-preserving handoff:

### 9.1 Prepare at source

In one durable transaction:

1. verify `amount <= source.free_pool`;
2. subtract `amount` from the free pool;
3. create `IN_FLIGHT(source, target, sequence, amount, digest)`;
4. return a signed transfer voucher.

### 9.2 Accept at target

In one durable transaction:

1. authenticate the source and voucher;
2. verify `(source, target, sequence)` has not been accepted;
3. add `amount` to the target free pool;
4. advance the contiguous high-water mark or add the sequence to a bounded gap set;
5. persist an acknowledgement.

Before checkpoint compaction covers a sequence, duplicate acceptance MUST return the stored original
acknowledgement without adding rights. After the target has accepted a signed checkpoint and
removed acknowledgements in that proven prefix, the same or an older sequence MUST be rejected as
already compacted, again without adding rights. The source retains the in-flight record until a
valid acknowledgement is recorded. Administrative cancellation cannot restore source rights unless
non-acceptance is proved by a protocol stronger than timeout alone.

### 9.3 Compaction

For each peer stream, the target stores:

- a contiguous accepted high-water mark;
- a bounded sparse set of accepted sequences above that mark;
- an alert/fail-closed condition when the configured gap window is exceeded.

After the target returns a signed acknowledgement, the source durably finalizes the transfer. The
source signs a contiguous-prefix checkpoint only after every transfer delivery through that
watermark is itself durably confirmed, persists the checkpoint in the peer outbox, and then removes
the covered voucher rows. The target verifies and stores that checkpoint before removing covered
acknowledgement rows. Duplicate checkpoints are idempotent; backward or content-conflicting
checkpoints fail closed. This bilateral compaction protocol is implemented in the v0.1 runtime.

### 9.4 Durable delivery

A warden MUST reject transfers to nodes absent from its startup-admitted endpoint and current-key
trust set before debiting free rights. A manifest-backed deployment derives that set exactly from
the verified signed manifest. Every local voucher, owner revocation, and checkpoint commit also
inserts its exact signed payload into the same SQLite transaction's peer outbox. The running peer
dispatcher performs bounded-concurrency, per-stream ordered, at-least-once delivery with durable
exponential backoff while the signing and verification keys remain current. Finite key expiry is a
hard drain deadline: operators MUST stop new durable mutations and prove the peer outboxes and
checkpoints drained before expiry. A newer checkpoint or branch epoch supersedes an older pending record for the
same stream/branch; transfer vouchers are never superseded. Crash recovery opens the existing
authority and replay databases in no-create mode and resumes pending work. Missing authority or
replay state is a startup failure, never an implicit re-genesis.

## 10. Failure matrix

| Failure | Required behavior | Safety effect | Availability effect |
|---|---|---|---|
| Agent crash | Do not reclaim solely from process death | None | Residual may remain stranded until close/expiry |
| Warden crash/restart | Recover lease, receipt, free-pool, and transfer state from an atomic log | No duplication if recovery is correct | Local outage during recovery |
| Network partition | Continue only from locally owned rights and valid leases | Global bound preserved | Rights may be stranded; renewal/rebalancing unavailable |
| Duplicate transition request | Return prior compatible result or reject conflict | No second debit/effect authorization | Minimal |
| Duplicate transfer voucher | Return the original ack before compaction; reject a compacted-prefix replay afterward | No minting | Minimal |
| Lost transfer acknowledgement | Source retains in-flight record; target repeats the ack until checkpoint compaction while the required keys remain current; finite-expiry deployments must drain before expiry | Rights remain conserved | Rights temporarily unavailable at source |
| Parent crash | Children continue with disjoint allocations | None | Parent residual may be stranded |
| Clock uncertainty violation | Stop renewal; fail closed where expiry cannot be established | Preserves configured exposure bound | Reduced offline availability |
| Evidence replay | Reject stale digest/nonce/issuer/audience | Prevents guard bypass | Possible false rejection |
| Warden compromise | Out of base threat model | Can violate conservation | Undefined; threshold/verified wardens are future work |

## 11. Scheduling and rebalancing

Rights ownership and CPU scheduling are separate. A warden SHOULD use a fair scheduler such as deficit round robin across lineages. A rebalancer MAY transfer free rights based on recent demand, but MUST preserve a configured local reserve and MUST use the handoff protocol. Prediction affects utilization, not conservation.

## 12. Audit events

Every state-changing operation SHOULD emit an append-only event containing operation type, request/receipt/transfer identifiers, lineage and lease identifiers, prior and resulting state digests, vector delta, policy/machine versions, branch epoch, authenticated actor, timestamp, and signature. Audit storage can grow with historical descendants; it is intentionally excluded from the online safety-state bound.

## 13. Versioning and compatibility

Policy and machine digests are immutable within a receipt. A warden MUST reject a request that ambiguously maps between versions. Migration to a new machine is an explicit protected transition or administrative protocol. Adding resource dimensions requires a new policy version and an explicit mapping; silent padding is forbidden.

## 14. Implementation status and deployment boundary

The v0.1 runtime implements durable serializable warden transactions, authenticated client and peer
identity adapters, independent receipt-enforcing executors, durable replay stores, crash recovery,
bilateral transfer compaction, bounded clock monitoring, owner-signed branch revocation, a durable
peer dispatcher, fault-injected multi-node acceptance, and invariant telemetry. Operators still
MUST satisfy the deployment assumptions in `docs/threat-model.md` and `docs/operations.md`, protect
signing keys and databases, configure TLS/private PKI as needed, and preserve complete executor
mediation. Byzantine wardens, active-subtree migration, multi-envelope databases, cross-version
rolling upgrades, automated key rotation, and threshold execution authorization remain outside v1.
