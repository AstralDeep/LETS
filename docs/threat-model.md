# LETS v1 threat model

## Security goals

LETS v1 is designed to preserve these properties for every envelope:

- resource conservation across free pools, descendants, consumption, and transfer;
- capability, machine, tenant, envelope, epoch, and expiry attenuation on delegation;
- legal state-machine ordering for every receipt;
- exactly-once accounting for retried commands and cross-warden transfer acceptance;
- audience-bound, short-lived, replay-detected executor authorization;
- detectable audit tampering and fail-closed policy/version negotiation.

## Trusted computing base

- each warden process, its loaded policy code, local durable database, and signing key;
- the configured wall-clock source and truthful operator-declared uncertainty bound;
- bootstrap manifest and peer/public-key trust roots;
- protected executors and their durable replay/effect boundary;
- explicitly configured evidence verifiers and their trust anchors;
- host/container isolation that prevents agents from directly modifying warden state.

## Untrusted inputs and components

- agents, reasoners, generated code, tools, models, prompts, and agent memory;
- every identity, subject, scope, timestamp, audience, state, sequence, and cost claimed in a
  request body until independently resolved;
- network delivery, including loss, delay, duplication, reordering, replay, and partition;
- discovery documents, advertised skills, unverified manifests, evidence payloads, and audit
  consumers;
- operators of other tenants and unrelated envelopes.

## Failures covered by tests

- agent/process crash and retry;
- abrupt process exit with both uncommitted rollback and committed-state recovery, plus a
  committed authorization recovered after process exit;
- delayed/lost transfer acknowledgements and duplicate vouchers;
- out-of-order transfers within and beyond the bounded gap window;
- peer partitions while each site continues local work;
- stale, missing, malformed, conflicting, or wrongly addressed evidence;
- expired leases/receipts and clocks whose uncertainty exceeds policy;
- replayed receipts, nonces, request IDs, and peer requests;
- policy/machine/manifest substitution or downgrade;
- operator-threshold and cross-warden public-key aliasing;
- database reopen/no-create admission, SQLite WAL recovery, exact critical replay-schema and core
  required-object checks, full integrity diagnostics, and immutable metadata mismatch;
- wall-clock rollback across warden, executor, or peer-replay process restarts.

## Explicit non-goals in v1

- Byzantine or compromised wardens. One compromised warden can sign invalid authority for rights
  assigned to it. Threshold wardens are future work.
- Safe simultaneous use of cloned/restored copies of the same warden database and key. Operators
  must fence the old instance before restore. Backup rollback detection is diagnostic, not a
  distributed consensus protocol.
- Instant revocation of an unreachable descendant. Exposure is bounded by residual rights and
  nested expiry; availability and instantaneous offline revocation cannot both be guaranteed.
- Exactly-once physical effects from a receipt alone. The executor must atomically consume the
  receipt with the effect, use an idempotent domain operation, or implement compensation.
- Policy correctness. LETS faithfully enforces declared dimensions, costs, machines, and evidence
  rules; it cannot prove that a domain designer chose semantically adequate ones.
- Arbitrary active-subtree migration. V1 moves free rights and then issues at the target.
- Secret, identity, memory, open-socket, or credential cloning during agent replication.

Each authority boundary persists a monotonic clock floor. A request whose current time plus its
declared uncertainty falls behind that floor fails closed, including after process restart. This
prevents ordinary wall-clock rollback from reviving expired authority; it does not defend against
an operator who lies about uncertainty, rewrites the durable floor, or activates an old cloned
database. Large forward jumps can reduce availability by expiring authority early.

## Security invariants for adapters

An adapter translates identities and lifecycle operations but never becomes an authority root. It
must preserve tenant/subject/audience binding, pass the host system's already verified identity
context, keep secrets out of manifests, reject unknown capability mappings, and leave destructive
confirmation and domain policy gates in place. Adapter failure cannot turn a denial into an allow.
