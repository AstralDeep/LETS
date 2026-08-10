# Integrating a host system with LETS

LETS is an authorization and accounting runtime, not an agent transport, model host, artifact
store, or scheduler. A host keeps those responsibilities and calls LETS at four lifecycle seams:

1. issue a root lease when a governed population is admitted;
2. spawn a child lease before creating a replica or delegate;
3. request a transition receipt immediately before a protected effect;
4. close, quiesce, renew, or revoke leases as the host lifecycle changes.

The protected executor independently verifies and durably claims the receipt. Checking a receipt
only in the orchestrator is insufficient if an agent can reach the effect through another path.

## Portable adapter contract

`lets.integrations.ReplicaAuthorizer` maps ordinary host lifecycle events onto the versioned HTTP
client. The profile binds one deployment to an immutable tenant, envelope, policy digest,
allocation shape, capability allowlist, and TTL. Requested capabilities must be a subset of that
allowlist.

```python
from lets.client import LETSClient
from lets.integrations import ReplicaAuthorizer, ReplicaProfile

client = LETSClient("https://warden-a.example", token=service_token)
authorizer = ReplicaAuthorizer(
    client,
    ReplicaProfile(
        tenant_id="production",
        envelope_id="agent-actions-2026-08",
        policy_digest="sha256:...",
        default_allocation=(10_000, 50_000_000),
        default_capabilities=frozenset({"tools.read", "tools.execute"}),
        default_ttl_ns=300_000_000_000,
    ),
)

root = authorizer.provision(
    request_id=host_operation_id,
    replica_id=agent_id,
    capabilities={"tools.read"},
)

receipt = authorizer.authorize_effect(
    request_id=tool_operation_id,
    lease_id=root["lease_id"],
    transition="read",
    executor_audience="document-gateway",
    nonce=effect_nonce,
    expected_sequence=0,
)
```

Use the host's durable operation ID as `request_id`; do not generate a new value on retry. LETS
stores the complete request fingerprint, so the same ID and same request returns the committed
result while the same ID with different content fails closed.

## Replication semantics

In LETS, replication means creating a new runtime identity under a declared capability, state,
resource, policy, and lineage envelope. It never means copying:

- bearer tokens, private keys, or ambient authority;
- a human or owner identity;
- process memory, open sockets, or uncommitted work;
- protected health information or other host-governed data;
- audit signing secrets.

Artifact and state transfer remain host operations. Store immutable artifact digests and
provenance in the host system, and place only identifiers or evidence digests in LETS requests.

## Executor integration

Use `lets.executor.ReceiptVerifier` with a filesystem-backed
`SQLiteReceiptReplayStore`. Production mode also requires an external executor authority anchor
in a rollback and failure domain independent from the replay database:

```python
from lets.crypto import PublicKeyRegistry
from lets.executor import (
    ExecutorPolicy,
    ReceiptVerifier,
    SQLiteReceiptReplayStore,
    executor_replay_identity,
)
from lets.executor_authority import ProcessFileExecutorAuthorityAnchor

registry = PublicKeyRegistry()
# Load this exact material and its validity bounds from an authenticated,
# signed bootstrap manifest. An unauthenticated /v1/keys response is not a
# production trust root.
registry.register(
    "warden-a",
    manifest_key_id,
    manifest_public_key,
    not_before_ns=manifest_not_before_ns,
    not_after_ns=manifest_not_after_ns,
)
policy = ExecutorPolicy(
    audience="document-gateway",
    tenant_id="production",
    envelope_id="agent-actions-2026-08",
    config_epoch=1,
    allowed_policy_digests=frozenset({"sha256:..."}),
    allowed_machine_digests=frozenset({"sha256:..."}),
    trusted_wardens=frozenset({"warden-a"}),
    max_clock_uncertainty_ns=10_000_000,
)
anchor = ProcessFileExecutorAuthorityAnchor(
    "/var/lib/lets-executor-authority/document-gateway.anchor"
)
identity = executor_replay_identity(policy, registry)
store = SQLiteReceiptReplayStore.initialize(
    "/var/lib/lets-executor/document-gateway.sqlite3",
    authority_anchor=anchor,
    identity=identity,
)
verifier = ReceiptVerifier(registry, store, policy)
```

On reopen, omit `identity`; the database supplies it and the verifier proves that the complete
policy plus exact registry key bytes and validity intervals still match. A policy widening,
same-warden key substitution, database clone, stale restore, missing anchor, or clock-floor
rollback fails before authorization. The process-isolated file anchor gives filesystem calls a
hard deadline. Helper creation, request correlation, locking, file I/O, response validation, and
channel reset share that one absolute deadline; a timed-out or broken channel is reset before it
can be used again. Its directory must not be snapshotted, restored, replicated, or writable with
the replay database directory; a remote linearizable CAS/HSM implementation may instead implement
`ExecutorAuthorityAnchor`.

Construction and reopen are admission, not a deferred recovery phase. A transport error while
opening preserves the database and anchor bytes but leaves that store object unadmitted; close its
anchor and create a fresh anchor/store pair after repair. Once an open has succeeded, only a
well-formed `AuthorityAnchorTransportError` can arm bounded recovery. After the reported monotonic
cooldown, the next explicit store transaction reconciles the exact SQLite head and anchor under the
store lock. It does not replay the original verifier or storage call. Anchor rejections, protocol
violations, malformed transport metadata, and other provider failures are permanent for that store
instance and require operator repair plus a fresh open. A later exact caller retry after a
pre-`BEGIN` failure may claim once; after a post-`COMMIT` failure it observes the already-burned
claim as `ReplayError`. The core warden store follows the same recovery contract.

`verify_and_claim()` verifies the receipt, commits its replay claim and append-only hash-chain
head, and synchronously advances the external CAS before returning. Every fresh process-file store
lifetime durably confirms the admitted checkpoint. If a mutating helper request may have completed
but its reply is lost, recovery reconciles and durably confirms that exact committed head before
reporting healthy. The original call still returns an error: when the SQLite claim committed, that
receipt is burned, and an explicit retry raises `ReplayError` without executing the protected
effect.
Expired claim/window cleanup is limited to 128 claim rows and 128 watermarks per accepted receipt.
`allow_unanchored=True` is an explicit development-only mode: it survives ordinary restart but
provides no stale-restore or cloned-branch protection and is never a production default.

This supplies durable at-most-once *authorization*, not exactly-once physical execution. A crash
after claim and before effect can omit the effect; a generic library cannot atomically commit an
arbitrary actuator. Make the domain operation idempotent, consume the receipt in the effect's own
transaction through a conforming `ReceiptReplayStore`, or implement explicit recovery and
compensation.

The immutable `claim_history` is intentionally append-only, so an executor database is a finite
authority epoch. Put it on a dedicated quota-owned local filesystem, alert on the database/WAL/SHM
and free-byte fields from `store.status()`, and treat `SQLITE_FULL` as a protected-effect outage.
Before a database-only backup, quiesce callers, require `store.checkpoint_wal()` to return a zero
busy field, and copy the database without its external anchor. Never restore WAL/SHM from another
point in time. A stale database restored beneath a live anchor is rejected on exact reopen.

Schema 4 has no external claim chain and therefore cannot be safely promoted in place. Reopen
fails closed without modifying it. Drain the old executor for the maximum outstanding receipt
lifetime plus declared clock uncertainty, prove there are no in-flight effects, archive its bytes,
and start a fresh schema-5 database and new independent anchor. The same drain rule applies when a
capacity epoch is retired; retain the old database/anchor as audit evidence and never reuse an old
anchor path for a new database instance.

## Identity and transport

The bundled bearer authenticator is a bootstrap mechanism. A production host should inject an
`IdentityAuthenticator` backed by its gateway, OIDC verifier, mTLS identity, or SPIFFE workload
identity. Identity is created at the transport boundary and is never accepted from a JSON body.

Peer warden traffic is Ed25519 message-signed, timestamped, content-digested, and protected by a
durable nonce store. Run it over TLS as well: signatures authenticate the message but do not hide
its contents or protect traffic metadata.

## Standards profiles

Treat standards as composable profiles rather than reimplementing them inside LETS:

- A2A Agent Cards, OASF, Agent Spec, or ARD for agent discovery and descriptions;
- MCP or A2A for invocation and capability negotiation;
- OCI artifacts plus SLSA/in-toto and SPDX/CycloneDX for immutable build provenance;
- SPIFFE and remote-attestation evidence for workload identity;
- CloudEvents and OpenTelemetry for exporting non-authoritative operational events.

Discovery is not authorization. A capability is usable only after intersecting the advertised
surface, host policy, LETS lease capability/residual, receipt audience policy, and executor trust.
