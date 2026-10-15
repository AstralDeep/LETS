# ADR 0003: live-lease top-up and non-refundable spawn cost

- Status: proposed
- Date: 2026-10-14

## Context

A child lease receives its whole allocation at `spawn`, and `renew` extends only expiry. No v1
operation adds rights to a live lease, so a parent must size each child before the child's work is
known. Over-allocation strands rights inside a live child, unavailable to siblings, and closing the
child returns them to the warden free pool rather than to the parent. Under-allocation exhausts the
child, which must close and be respawned, losing its machine state and operation sequence.
Active-network resource bounds (ANTS, PLAN, SNAP) met the same problem with a scalar limit fixed at
injection, divided among copies, and never refunded, and, by the account of an active-networking
researcher, choosing the initial value was the hard part.

A child allocation is a transfer rather than a cost: `close` and expiry reclamation return the
unused residual to the warden free pool, not to the parent, so the envelope recovers it but the
lineage does not. Because every child allocation must contain a nonzero component, each spawn
permanently removes at least one unit from the parent's residual, and a lease can create at most
as many descendants as its residual holds units. That population bound is denominated in whatever
dimensions the parent uses to fund children, so it cannot be set independently of action budgets,
and creation itself consumes nothing from the envelope. `MAX_LINEAGE_DEPTH` bounds depth at 64,
and the parent chooses how much of its residual one child receives with no policy floor.

## Decision

Propose three additive mechanisms. This record changes no runtime, OpenAPI, schema, model, or
test; each mechanism needs its own formal-model extension and implementation review before
acceptance.

### Grant: top-up of a live child lease

`POST /v1/leases/{child_id}/grant` moves an `amount` vector from the authoritative parent's
residual into the live child's residual in one durable local transaction. The checks mirror
`spawn`:

- the child is a direct child of `parent_id`; both share tenant, envelope, config epoch, and policy
  digest, and both are held by the local warden;
- the parent is actionable and the child is unexpired and not fenced by a branch revocation;
- `amount` has the policy dimensionality, at least one nonzero component, and is componentwise no
  greater than the parent residual, using checked integer arithmetic;
- the caller holds the same identity scope that `spawn` requires, and `expected_sequence` is
  checked against the parent's operation sequence, which the grant advances;
- the child's capabilities, machine, expiry, and sequence are unchanged; a grant never extends
  lifetime or adds capability, which remain `renew` and `spawn` concerns.

Idempotency uses the envelope-global `request_id` with a fingerprint over the operation name,
actor, parent, child, and amount, exactly as the other commands do; an identical replay returns
the prior response and a changed body is rejected. The audit record carries one signed event with
the negative delta on the parent, the positive delta on the child, both lease identifiers, and the
prior and resulting state digests, followed by the usual outbox event.

Conservation holds term by term in the equation in `docs/architecture.md`: a grant moves quantity
between two entries of the lease-residual class on the same warden projection and touches neither
the free pool, the consumed class, nor in-flight transfers. Once held, granted rights are
indistinguishable from the initial allocation, so close and expiry reclamation need no change:
unspent granted rights return to the free pool like any other residual.
Grant is local-only, like spawn; a parent and child on different wardens continue to use
free-rights transfer followed by issuance at the target.

### Spawn cost: a non-refundable lineage charge

A policy may declare an optional `spawn_cost` vector with the policy dimensionality. On `spawn` the
warden debits `allocation + spawn_cost` from the parent residual in the same transaction:
`allocation` becomes the child residual and returns to the free pool on closure, while `spawn_cost`
enters the consumed class and is never returned. A zero vector is equivalent to today's behaviour.
The same invariant distinguishes the two quantities: reclamation returns a child's residual, never
the cost paid to create it. The audit record's vector delta shows both components.

With a nonzero cost, every spawn consumes envelope, so creation becomes a conserved effect
under the same accounting as every other protected transition. Operators who want to bound
population independently of action or token budgets add a dedicated dimension and charge spawns
only in that dimension, which the parent cannot route around by funding children from another
dimension. Because leases pin the policy digest, an existing lineage keeps
its policy until re-issued under the new one.

### Child-share bound: an attenuation rule on partitions

A policy may declare `max_child_share`, an integer numerator and denominator per dimension, and a
`parent_floor` vector. `spawn` and `grant` reject when the child's resulting residual would exceed
the parent's pre-operation residual scaled by `max_child_share`, or when the parent's
post-operation residual would fall below `parent_floor`. Both comparisons use checked integer
cross-multiplication. The rule narrows what a parent may propose; it changes no conservation
class and is enforced at the same warden boundary as capability attenuation.

### What stays out of scope

Neither grant nor spawn cost is possible toward a parent on an unreachable warden. During a
partition the child's initial allocation plus any grants already applied remain its entire offline
budget, consistent with ADR 0001's choice of bounded authority over availability. Grant from an
arbitrary ancestor, grant across wardens, grant of capability or lifetime, and automatic refill
policies are deferred.

## Consequences

- Allocation becomes incremental: a small initial allocation plus grants on demand. The sizing
  decision shrinks from total need to increment, and over-allocation no longer strands rights.
- The initial allocation still governs disconnected operation, so the pre-positioning question
  ANTS faced remains, confined to the offline case.
- Population becomes boundable in a dedicated dimension rather than only through the action units
  that fund children, and one bad proposal cannot take a parent's whole residual when a share bound
  is configured.
- Each mechanism widens the transaction, idempotency, audit, invariant, OpenAPI, client, CLI, and
  `formal/` surfaces; the bounded TLA+ model and exhaustive checker must cover grant and spawn cost
  before implementation is accepted.
- `spawn_cost`, `max_child_share`, and `parent_floor` change the policy digest, so adopting them
  is a policy version change and is rejected by wardens that predate the field.
- The lineage depth cap remains.
