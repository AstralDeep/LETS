# A2A task and delegation profile

`lets.integrations.a2a` is an optional, host-neutral mapping from A2A task operations to LETS
authorization. Profile identifier: `lets.a2a-profile/v1`.

It is a thin layer over `ReplicaAuthorizer`. It owns no transport, no HTTP server, and no
storage schema. LETS core never imports it, never stores A2A task state, and gains no A2A
tables.

## Pinned A2A revision

| Field | Value |
| :-- | :-- |
| Specification | A2A v1.0.1 (`a2aproject/A2A`, tag `v1.0.1`) |
| Commit | `3303592588e388e62e0f69f701af531d2f4e3991` |
| Status | Released tag of a living specification |
| Retrieved | 2026-10-01 |
| Status / retrieved | Released tag, retrieved 2026-10-01 |
| Constants | `lets.integrations.a2a.PINNED_REVISION`, `MAPPING_VERSION` |

Method names, task states and error codes below come from that tag (`specification/a2a.proto`
and `docs/specification.md` sections 3.1.5, 3.3.1, 3.4 and 5.4). Re-validate the mapping and
bump `MAPPING_VERSION` before moving the pin.

## Authority model

A2A describes and invokes. LETS authorizes. A capability is usable only when all three hold:

1. **Lease attenuation (LETS).** The child lease is a subset of its parent in capabilities,
   allocation and lifetime. The warden enforces this on every spawn.
2. **Host policy (this profile).** `AudienceBinding` maps a *host-verified* executor identity
   to a LETS `executor_audience`. Unbound executors are refused before any LETS call.
3. **Independent executor verification.** The executor runs `ReceiptVerifier` with its own
   audience, trusted wardens and replay store. It does not trust the host or the A2A task.

An Agent Card is a description. It is never an input to any of the three.

## Identity and ID mapping

Identity is created at the transport boundary (OIDC, mTLS, SPIFFE) as an `IdentityContext`
and is passed to the profile as a separate argument. It is never read from the A2A JSON body.
Passing anything other than an `IdentityContext` raises `ValidationError`.

The identity's tenant must equal the tenant configured on the `ReplicaAuthorizer` profile, or
every operation raises `PolicyError`. Delegation also requires the parent task key to be in the
caller's tenant, so a subject with the same name in another tenant cannot borrow a parent's
authority.

| A2A input | Trusted? | Used for |
| :-- | :-- | :-- |
| Caller identity | Only as an `IdentityContext` from the host authenticator | `TaskKey(tenant, principal, task_id)` and every derived ID |
| `taskId` | Untrusted label, scoped by verified tenant and principal | Ledger key; ID derivation |
| `contextId` | Untrusted label | ID derivation; a task is bound to exactly one context |
| `messageId` / message parts | Untrusted | Content digest (changed-content detection) |
| Agent Card URL | Never | Nothing |
| Executor workload identity | Only when host-verified | `AudienceBinding` lookup |

`derive_id(kind, key, context_id, discriminator)` returns
`a2a1.<kind>.<48 hex of SHA-256 over canonical JSON>`. The digest covers the mapping version,
kind, tenant, principal, task, context and discriminator. The same inputs always produce the
same LETS `request_id` and nonce, so retries are exact. A different principal using the same
`taskId` produces different IDs and cannot collide with, or replay, another caller's request.

## Operation mapping

| A2A | Profile call | LETS calls | Notes |
| :-- | :-- | :-- | :-- |
| `SendMessage` (new task) | `admit` | `spawn` | Child lease beneath a host-selected parent lease |
| Delegating to another agent | `delegate` | `spawn` under the parent task's lease | Delegator must be the parent lease's subject |
| Each effect | `authorize_effect` | `authorize` | One receipt per `effect_id` |
| `GetTask` | `get_task` | none | Reconnect and status lookup read the ledger |
| `SubscribeToTask` | `subscribe` | none | Terminal task: `UnsupportedOperationError` (spec 3.1.6) |
| `CancelTask` | `cancel_task` | `revoke_branch` | See "Cancellation versus revocation" |
| Successful finish | `complete_task` | `close` | `COMPLETED` is published only after `close` succeeds; cancellation requested first wins |

## State mapping

| Task state | Cause |
| :-- | :-- |
| `TASK_STATE_SUBMITTED` | Admitted, no effect authorized yet |
| `TASK_STATE_WORKING` | At least one receipt issued |
| `TASK_STATE_COMPLETED` | `complete_task` closed the lease and then won the ledger race |
| `TASK_STATE_REJECTED` (`admission_denied`) | LETS refused the spawn: attenuation, residual, expiry or validation |
| `TASK_STATE_CANCELED` | `cancel_task` revoked the lease branch |
| `TASK_STATE_FAILED` (`authority_expired`) | The lease or a parent expired while authorizing an effect |

`INPUT_REQUIRED` and `AUTH_REQUIRED` are not produced. `AUTH_REQUIRED` means the
agent needs more credentials from the client, which is not what lease expiry means.
Lease renewal is a host choice through `ReplicaAuthorizer.renew`; the profile does not renew.

A denial by LETS policy (a capability the lease lacks, a revoked branch) raises `PolicyError`
and does not change task state.

## Duplicate delivery, retries and reconnects

- **Duplicate `SendMessage`.** The ledger returns the existing record. LETS sees one `spawn`.
- **Admission is recorded before the spawn.** The ledger first stores the immutable admission
  digest and spawn parameters in a pending record (`put_if_absent`, which must be atomic), then
  spawns, then binds the lease ID. If the reply is lost after LETS committed the spawn, the
  retry re-sends the same derived `request_id` and receives the original grant. A retry with
  changed content conflicts instead of inheriting that grant. Every later operation on a
  pending record resumes the same idempotent spawn first.
- **Duplicate effect request.** The same `effect_id` returns the same signed receipt.
- **Reconnect.** `get_task` and `subscribe` read the host ledger. A task owned by another
  principal returns `TaskNotFoundError`, indistinguishable from a missing task.
- **Changed request content.** Reusing a `taskId` with different message content, a different
  context, or different lease parameters raises `ConflictError` before any LETS call. This is
  checked against the admission digest held in the ledger, including after a lost spawn reply
  and after a denied admission.

## Delegation and expiry

`delegate` spawns beneath the parent task's lease. LETS rejects capabilities outside the
parent, allocation above the parent's residual, and a lifetime beyond the parent's. A requested
TTL longer than the parent's remaining life is clipped to the parent's expiry. When the parent
expires, the child cannot be authorized: the next `authorize_effect` raises `ExpiredError` and
the task becomes `FAILED` with reason `authority_expired`.

Child tasks are owned by the delegating agent's verified identity, not by the original caller.

## Cancellation versus revocation

These are different operations that the profile sequences.

- **Task cancellation** is an A2A concept. `CancelTask` asks the host to stop a task and
  reports a task state.
- **Lease revocation** is a LETS concept. `revoke_branch` stops the warden from issuing new
  receipts for a lease and every descendant lease.

`cancel_task` does this in order:

1. In one atomic ledger update, set `cancel_requested`. From here the host refuses new effects.
   A concurrent `complete_task` now fails with `ConflictError`; if `COMPLETED` was published
   first, `cancel_task` raises `TaskNotCancelableError` (`-32002`). A completion that has
   started but not published `COMPLETED` loses to cancellation.
2. Call `revoke_branch`. LETS then refuses any further `authorize` on that lease branch.
3. Atomically record `TASK_STATE_CANCELED` and `revoked_at_ns`, and mirror the state to
   delegated child records.

If step 2 fails, the task remains `cancel_requested`. Retrying `cancel_task` is safe because the
revocation request ID is derived. A repeated cancel of an already canceled task returns it
unchanged (spec 3.3.1: cancel is idempotent). It also re-runs the descendant mirroring, so a
cascade that failed part-way is completed by retrying `cancel_task` on the parent.

## Completion

`complete_task` records `completion_requested`, which makes the host refuse new effects, then
calls `close`, then publishes `TASK_STATE_COMPLETED`. If the close fails or its reply is lost,
the task is not terminal and retrying `complete_task` repeats the idempotent `close`.

### What cancellation does not guarantee

- **No instant offline revocation.** Executors verify receipts offline and do not consult the
  warden. A receipt issued before the revocation remains valid until its own `expires_at_ns`,
  which is bounded by the policy's receipt TTL plus declared clock uncertainty. The record
  exposes `revoked_at_ns` and `known_receipt_horizon_ns` so a host can report when cancellation
  has fully taken effect. The fixtures show a pre-cancel receipt still verifies and claims after
  cancel.
- **No exactly-once effects.** LETS provides at-most-once *authorization* through the executor
  replay store. A crash after the claim and before the effect can omit the effect. Make the
  domain operation idempotent or consume the receipt in the effect's own transaction, as
  described in the integration guide.
- **`CANCELED` is a host statement, not proof that nothing ran.** Effects begun under an issued
  receipt may finish after the task reports `CANCELED`.

## Storage boundary

Task state lives behind the `TaskLedger` protocol, supplied by the host. A production ledger
must make `update` atomic and durable; the cancel and complete race depends on it.
`InMemoryTaskLedger` is a reference for tests and examples and is not durable. Nothing is added
to the LETS database schema. `examples/a2a_host.py` shows the method-dispatch seam.

## Error mapping

| Condition | Raised | A2A representation |
| :-- | :-- | :-- |
| Unknown or foreign task | `A2AProfileError` | `TaskNotFoundError` (-32001) |
| Cancel of a completed or failed task | `A2AProfileError` | `TaskNotCancelableError` (-32002) |
| Subscribe to a terminal task | `A2AProfileError` | `UnsupportedOperationError` (-32004) |
| Capability, audience, branch or attenuation denial | `PolicyError` | Host authorization failure, not an A2A code |
| Expired lease | `ExpiredError` | Host authorization failure; task becomes `FAILED` |
| Changed content for a reused `taskId` | `ConflictError` | Host binding decides (for example HTTP 409) |

## Conformance fixtures

`tests/unit/test_a2a_profile.py` runs against a real `WardenService`, `ManualClock`,
`ReceiptVerifier` and `SQLiteReceiptReplayStore`. No network and no A2A transport is involved.

- pinned revision and projected task metadata
- ID derivation bound to verified identity; asserted JSON identity ignored and rejected
- tenant binding for admit, delegate, status lookup, and cross-tenant parent keys
- lost spawn reply: changed content conflicts, original content recovers the original grant
- operations resume a pending admission; denied admission becomes `REJECTED`
- `COMPLETED` published only after `close` succeeds; cancel wins over an unfinished completion
- cancel on an already canceled parent resumes a failed descendant cascade
- duplicate delivery: one spawn, same receipt, executor replay refused
- reconnect and status lookup; foreign task hidden; terminal subscribe refused
- changed content, context and authority conflicts with no second lease
- wrong audience: host refusal and executor refusal
- attenuated delegation: widened capabilities, oversized allocation, non-parent delegator
- parent expiry clips the child and fails the task closed
- cancel refuses new effects while an issued receipt stays claimable
- cancel idempotence and `TaskNotCancelableError`
- cancel winning over complete; revoke failure and retry
- parent cancel revokes the delegated branch
- example host dispatch from a verified identity

## Limits of this profile

- No A2A wire-level interoperability test was run, and no JSON-RPC, REST or gRPC binding is
  provided. The profile is validated against the pinned specification text and the LETS
  contracts only.
- Push notification configuration, extended Agent Cards and `ListTasks` are out of scope.
- Streaming delivery and `SubscribeToTask` event fan-out belong to the host.
- Multi-warden transfer and cross-warden revocation propagation are LETS concerns and are not
  re-specified here.
