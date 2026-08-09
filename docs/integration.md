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
`SQLiteReceiptReplayStore`. Configure the exact audience, tenant, envelope, configuration epoch,
accepted policy/machine digests, and trusted warden keys. `verify_and_claim()` supplies durable
at-most-once authorization. The host must additionally make its effect idempotent or bind the
claim and effect in one domain transaction; no generic library can make an arbitrary external
effect exactly once.

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
