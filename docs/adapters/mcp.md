# MCP tool-execution profile

`lets.integrations.mcp` is an optional, host-neutral mapping from MCP discovery and tool calls
to LETS authorization. Profile identifier: `lets.mcp-profile/v1`.

It is a thin layer over `ReplicaAuthorizer`. It owns no transport, no MCP server, no user IAM,
no tool implementation, and no storage schema. LETS core never imports it, never stores MCP
sessions or arguments, and gains no MCP tables. The profile itself does not import an MCP SDK.

## Pinned revision and optional SDK

| Field | Value |
| :-- | :-- |
| Specification | MCP `2026-07-28` |
| Specification source | [MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28) |
| Authoritative schema | [2026-07-28 schema at commit 271ecc9](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/271ecc9accafdd9b83a3c869fa67c22953b2af80/schema/2026-07-28/schema.ts) |
| Status | Published specification and released SDK; no SDK interoperability claim |
| Retrieved | 2026-10-25 |
| Optional host SDK | [`mcp==2.3.0`](https://pypi.org/project/mcp/2.3.0/) |
| Constants | `lets.integrations.mcp.PINNED_REVISION`, `MAPPING_VERSION` |

The SDK pin is an optional dependency of a host-side MCP server or client, not of
`lets-agent`. The core runtime dependency set is unchanged and the adapter remains usable with
plain mappings. Re-validate this profile and bump `MAPPING_VERSION` before moving either pin.

## Transport and authentication boundary

| Concern | Owner |
| :-- | :-- |
| stdio or Streamable HTTP transport, sessions, JSON-RPC envelopes | Host |
| MCP server, discovery, `tools/list`, `tools/call`, cancellation notification | Host |
| User IAM, OAuth/token validation, scopes, consent and confirmation recording | Host |
| Tool schemas, argument parsing, execution and effect recovery | Host executor |
| Verified caller identity passed as `IdentityContext` | Host authenticator |
| Tool-to-scope mapping, effect digest, lease/evidence binding | This profile |
| Lease, receipt, branch revocation and accounting | LETS warden |
| Audience policy, receipt verification and durable claim | Independent LETS executor |

An MCP client's `_meta`, `clientInfo`, tool annotations, JSON-RPC request ID, or discovery result
never establishes identity or authority. The host derives `IdentityContext` at its authenticated
transport boundary and passes it separately. Credentials, access tokens, owner identity, session
state, prompts, and opaque agent state are not adapter inputs or outputs.

The host selects a caller-owned lease and a caller-bound `ReplicaAuthorizer` client before invoking
authorization or revocation. A lease ID from MCP arguments does not establish that relationship.
`IdentityContext` namespaces operation IDs but does not replace the warden client's authenticated
identity. A host using management credentials across callers must enforce its own caller-to-lease
ownership check before either profile call; a matching tenant alone is insufficient.

## Authority model

All of the following must agree before a tool effect:

1. **Host IAM and tool gate.** The host authenticates the caller, applies its permission gate,
   and obtains any required human confirmation. `ToolGate.approve` returns `HostToolApproval`
   bound to the exact `effect_digest`, or `None` to deny. The profile calls this gate before any
   warden request.
2. **Mapped tool and scope.** The tool name must map to a declared scope, capability and LETS
   transition. Unknown tools and unknown scopes fail closed.
3. **LETS lease.** The lease must contain the transition capability, sufficient residual, an
   actionable state, a live expiry, and no revoked branch.
4. **Audience binding.** `MCPAudienceBinding` maps a *host-verified* executor workload identity
   to the LETS executor audience. Unbound executors are refused before any warden call.
5. **Independent executor.** The executor runs `ReceiptVerifier` with its own audience, trusted
   wardens, policy/trust-registry identity and durable replay store.

Discovery is not authorization. `MCPToolProfile.descriptors()` only projects the tool names and
scope labels for the host's discovery response; it performs no LETS call and grants nothing.
The host may combine that projection with its own MCP tool schemas and annotations.

## Operation mapping

| MCP operation | Profile call | LETS calls | Notes |
| :-- | :-- | :-- | :-- |
| `tools/list` / discovery | `descriptors` | none | Labels only; no lease or receipt |
| `tools/call` | `authorize_tool` | `authorize` | One receipt for one stable host operation ID |
| Protected effect | `bind_receipt`, then the executor's `verify_and_claim` | none | Claim immediately before the effect |
| Cancellation before authorization | Host stops | none | No LETS authority was created |
| Revoke future effects under a lease | `revoke_lease` | `revoke_branch` | For explicit host cancellation or incident response |
| Lease creation | Host `ReplicaAuthorizer.provision`/`replicate` | `issue_root`/`spawn` | Use `capabilities_for_tools` for the attenuated set |

## Stable identity and effect binding

The host supplies a durable `operation_id`; an ephemeral JSON-RPC request ID is not sufficient
when a session can reuse it. `MCPOperationKey(tenant, principal, operation_id)` includes the
tenant and principal from the verified `IdentityContext`. The same key always derives the same
LETS `request_id` and executor nonce.

`effect_digest(tool_name, scope, arguments)` binds the mapping version, pinned MCP revision, tool,
scope and canonical LETS-CJ/1 arguments. The warden receives an evidence object containing only
identifiers and digests:

```text
type, mcp_revision, tool, scope, capability,
arguments_digest, effect_digest,
confirmation_id?, policy_reference?
```

Raw arguments never cross the adapter boundary into LETS. The host tool gate sees the arguments
locally, but the warden receives only `arguments_digest` and `effect_digest`.

Consequences:

- **Retry with the same operation ID and same content** derives the same request ID and nonce and
  returns the original signed receipt without a second debit.
- **Same operation ID with changed arguments or tool** keeps the same request ID but changes the
  evidence digest, so the warden rejects the reuse with `ConflictError`.
- **Same operation ID with a changed lease or audience** also keeps the same request ID; the
  warden's complete request fingerprint differs and rejects the reuse with `ConflictError`.
- **Different principal or tenant** derives a different request ID and cannot inherit another
  caller's receipt.
- **Lost warden reply** leaves the committed receipt or debit in place. Retry the same operation;
  never generate a fresh request ID.
- **Receipt relabeling** is refused. `bind_receipt` derives the operation key from the verified
  caller, recomputes the actual arguments and effect digests, checks the configured tool mapping
  against the signed evidence, and binds request ID, nonce, lease, transition and audience before
  the executor verifies the signature and burns the claim.

## Protected execution

```python
from lets.canonical import canonical_json, strict_json_loads

arguments = {"path": "docs/report.md", "content": content}
arguments = strict_json_loads(canonical_json(dict(arguments)))
authorization = profile.authorize_tool(
    identity,
    operation_id=durable_operation_id,
    lease_id=lease_id,
    tool_name="repository.write",
    arguments=arguments,
    verified_executor_id=verified_workload_identity,
    expected_state="ready",
)
receipt = profile.bind_receipt(
    authorization, authorization.receipt, identity=identity, arguments=arguments
)
verifier.verify_and_claim(receipt)
effect(durable_operation_id, authorization.tool_name, arguments)
```

`examples/mcp_host.py` shows this seam as `MCPToolHost.call`. A missing receipt is refused before
the effect, and a duplicate authorization still produces the same receipt, which the executor's
durable claim rejects on the second invocation.

`bind_receipt` requires the verified caller and the exact arguments that the effect will consume.
Retain a private canonical snapshot through binding, claim and execution: the example makes this
snapshot so mutation of the caller's nested objects cannot change the effect after validation.
Arguments use LETS-CJ/1, so non-integer JSON numbers must be represented by a host-defined fixed-point
encoding before authorization.

`verify_and_claim` gives durable at-most-once **authorization**. It is not a promise that an
arbitrary external tool effect happens exactly once. A crash after the claim and before the effect
can omit the effect; a retry cannot claim the burned receipt again. Make the domain operation
idempotent with the stable operation ID, consume the receipt in the effect's own transaction
through a conforming replay store, or implement host recovery and compensation.

## Cancellation and revocation

MCP cancellation is a host operation. If cancellation arrives before `authorize_tool`, the host
simply stops and no LETS authority exists.

If the host must stop future effects for an entire lease branch, `revoke_lease` calls LETS
`revoke_branch` with a derived, idempotent request ID. LETS then refuses new authorizations on
that branch.

A receipt that was already issued remains valid and claimable until its own expiry. Executors
verify offline and do not consult the warden, so cancellation is not instantaneous revocation.
Hosts should record the known receipt horizon and the revocation time when reporting when
cancellation has fully taken effect. A receipt issued before cancellation may still authorize an
effect that finishes after the host reports cancellation.

## Conformance fixtures

`tests/unit/test_mcp_profile.py` runs against a real `WardenService`, `ManualClock`,
`ReceiptVerifier` and `SQLiteReceiptReplayStore`. No network or MCP transport is involved.

- pinned MCP revision and SDK pin; discovery projects labels without a warden call or gate call
- unknown tool and unknown scope, plus invalid profile, audience and approval configuration
- host gate denial, mismatched approval digest and malformed gate result, all before the warden
- stable request ID, nonce and effect digest across retries; changed arguments change the digest
- changed arguments or tool on the same operation ID conflicts with one debit
- lost authorization reply recovers the same receipt once; duplicate claim is replayed
- wrong audience and wrong tenant are refused by the host binding and by the executor
- missing, mismatched and relabeled receipts are refused; a tampered warden reply is detected
- raw arguments and credential-like values never appear in the warden request or evidence
- cancellation refuses new authority while a pre-cancel receipt remains claimable
- at-most-once authorization burns the claim before the effect and cannot promise effect exactly
  once
- the example host verifies and claims immediately before the effect and refuses a missing receipt
- final execution refuses changed arguments, caller/tenant substitution and relabelled operation or
  tool metadata before burning the claim, and executes an independent snapshot of nested arguments

## Limits of this profile

- No MCP wire-level interoperability test was run and no MCP SDK is imported. The profile is
  validated against the pinned specification contract and the LETS client/executor contracts.
- The host owns the MCP server, transport, OAuth/IAM, tool schemas, confirmation UX and audit.
- Resources, prompts, sampling, subscriptions, tasks, extensions and streaming are out of scope.
- The profile maps one protected tool call to one LETS transition. Multi-step tools, long-running
  work and effect compensation remain host designs.
- At-most-once authorization is not exactly-once physical execution.
- An issued receipt is not retracted by cancellation; exposure is bounded by receipt TTL and the
  executor clock-uncertainty policy.
- Multi-warden transfer and cross-warden revocation propagation remain LETS concerns and are not
  re-specified here.
