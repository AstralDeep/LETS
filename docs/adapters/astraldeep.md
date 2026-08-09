# AstralDeep adapter profile

The LETS repository remains independent of AstralDeep. The supported integration is a thin
consumer of the public LETS client and executor contracts; LETS core contains no AstralDeep
imports and never reads or writes AstralDeep database tables.

The profile was checked against AstralDeep commit `d3cb9a51c900`. Revalidate it when the host
contracts change.

## Recommended placement

Use one of these deployment shapes:

1. an AstralDeep-owned adapter calls a separately deployed LETS warden over HTTPS;
2. an external A2A/MCP sidecar exposes lifecycle tools and calls LETS;
3. a small first-party shim depends on `lets-agent[client]`, while LETS remains a separately
   versioned service.

The first option has the lowest coupling. Do not move LETS core into `backend/agents`, import
AstralDeep repositories from LETS, or write the internal `user_agent` lifecycle tables.

## Concrete mapping

`lets.integrations.AstralDeepAuthorizer` recognizes only AstralDeep's declared public tool scopes:

- `tools:read`
- `tools:write`
- `tools:search`
- `tools:system`
- `tools:files`
- `tools:execute`

Each enabled scope must map explicitly to one LETS capability and one policy transition. Unknown
or incompletely mapped scopes fail closed.

```python
from lets.client import LETSClient
from lets.integrations import (
    AstralDeepAuthorizer,
    AstralDeepProfile,
    ReplicaAuthorizer,
    ReplicaProfile,
)

lets_client = LETSClient(lets_url, token=astral_service_token)
replicas = ReplicaAuthorizer(
    lets_client,
    ReplicaProfile(
        tenant_id=astral_tenant,
        envelope_id="astral-agents",
        policy_digest=policy_digest,
        default_allocation=(1_000_000, 100_000_000),
        default_capabilities=frozenset({"astral.tools.read", "astral.tools.execute"}),
        default_ttl_ns=300_000_000_000,
    ),
)
authorizer = AstralDeepAuthorizer(
    replicas,
    AstralDeepProfile(
        scope_capabilities={
            "tools:read": "astral.tools.read",
            "tools:execute": "astral.tools.execute",
        },
        scope_transitions={
            "tools:read": "read",
            "tools:execute": "execute",
        },
    ),
)
```

Map Astral lifecycle operations as follows:

| AstralDeep event | LETS call |
|---|---|
| governed root agent/task admitted | `provision_agent` / `issue_root` |
| child agent or replica created | `replicate_agent` / `spawn` |
| protected tool about to execute | `authorize_tool` / `authorize` |
| lifecycle pause or disconnect | `quiesce` |
| healthy reconnect | `resume` |
| terminal deletion | `close` or branch `revoke` |

The Astral operation ID becomes the LETS idempotency key. The Astral agent ID becomes the lease
subject. Keep a durable `(agent_id, lease_id, policy_digest, config_epoch)` association in the
Astral-owned integration layer.

## Preserve AstralDeep's authority path

LETS adds quantitative and state-machine mediation. It does not replace AstralDeep's Keycloak
identity, RFC 8693 delegation, owner isolation, permission, taint, PHI, egress, confirmation, or
hash-chained audit gates. Call LETS only after those gates accept the operation, and pass the
orchestrator's durable operation ID. Recursive agent calls continue through the orchestrator's
`AgentHopRequest`; a replica must never forward Astral credentials or mint peer authority.

For external agents, prefer the existing custom Agent Card plus WebSocket seam when schema and
scope fidelity matter, with official A2A as the standards fallback. The adapter's registration
key and service token are runtime configuration secrets, never lease data or replication
artifacts. Ownerless external agents remain private until an operator enables them.

## Protected execution

Install an independent receipt verifier at each tool gateway or actuator. Bind its audience to
the gateway, trust only configured LETS warden keys, and claim the receipt before the effect. A
check inside the orchestrator alone is bypassable if any alternate path can reach the same tool.

Existing Astral UI can display LETS state with current Card, Table, Timeline, Badge, Progress,
Alert, and KeyValue primitives. No LETS-specific primitive is required. Adding a new primitive
would require coordinated Astral-Primitives, wire protocol, and every client renderer change.
