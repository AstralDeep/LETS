# ADR 0004: period budgets and the device holder

- Status: accepted
- Date: 2026-11-12

## Context

LETS divides a fixed budget among wardens when an envelope is created. It never refills the budget and it fixes membership at that moment. A device fleet needs the opposite. Devices join, leave and are restored from backups. The owner wants a daily allowance that each device can spend while it is offline and that stops at its edge.

A device also differs from a server warden. Its clock can be set by whoever holds it. A restored backup replays old state. Its agent, warden and executor share one process.

## Decision

### Period budgets

A signed **budget policy** (`lets.period-policy/v1`, `src/lets/period.py`) states the period length, the epoch that periods count from, a total per dimension, a fresh share and a solo cap per member kind and dimension, and two reductions in permille for attested and unattested members. A dimension is any string. The mesh uses one per effect class and one for model spend. A member kind is any string that the policy gives a share.

Signature checking is a verifier the caller passes in. It receives the issuer, the canonical bytes of the unsigned policy and the signature string. LETS makes no assumption about key types. The mesh passes a P-256 check over the context `astral.policy/v1`.

A **period budget** is derived, never requested. Given a policy, a membership list and a period index, every holder computes the same result with integer arithmetic:

1. Period `p` runs from `epoch + p * period` to `epoch + (p + 1) * period`.
2. For each member, scale the kind's fresh share and solo cap by `(1000 - reduction) / 1000`, rounding down. The reduction is the attested or unattested one.
3. Sum the scaled fresh shares for each dimension. If the sum is at most the total, each member keeps its share. Otherwise each share becomes `share * total / sum`, rounding down.
4. A member's solo cap is the smaller of its scaled solo cap and its final fresh share.
5. The reserve is the total minus the sum of the final shares.

Shares are disjoint and their sum never exceeds the total. Members are sorted by id before anything is written or hashed, so input order does not matter. The result and the membership have canonical digests. Products reach about 2^126, so a second implementation needs 128-bit intermediates.

The membership list for period `p` is the roster as it stood at the start of that period. A member added later has no share until the next period. This keeps two devices that derive apart in agreement. The cost is that a restored phone gets nothing until the next period boundary unless it was enrolled before the boundary.

### Changing the policy

A policy has a version. A candidate must name the same policy id, carry a valid signature and have a higher version. The same version with the same digest is a no-op.

A change is **narrowing** when no total, share or solo cap grew and neither reduction shrank. It is **widening** in every other case. That includes a different period length, epoch, dimension set or kind set, because LETS cannot prove those are not larger. Narrowing is adopted at once. Widening needs a consent marker that the caller supplies. The marker names the digest of the new policy. LETS checks the binding and treats the evidence as opaque. The mesh puts the owner's presence-key signature there.

On a device, narrowing lowers the caps of the current period at once. Widening takes effect from the next period, because the period's storage was opened under the old policy.

### The device holder

`src/lets/device.py` wraps one `WardenService` per period. Each period has its own database, an envelope named `period-<index>` and a configuration epoch of `index + 1`. The envelope budget is the period total and the local share is the device's fresh share. A new budget per period, built from the current roster, replaces the live top-up that ADR 0003 proposed, so that ADR stays unneeded.

- **Spending.** Each budgeted dimension has a transition `spend.<dimension>` that costs one unit. A spend of `n` units issues `n` receipts under live leases, each with its own request id, so a retry after a crash returns the same receipts. A host picks a unit that suits the dimension, for example a thousand tokens.
- **Edge.** Before any receipt is issued the holder compares the request with what is left. A refusal names its reason: `share_spent`, `solo_cap_reached`, `not_a_member`, `lapsed`, `unknown_dimension` or `invalid_amount`. It carries the dimension, the amount asked and the amount left. Nothing is spent on a refusal.
- **Freshness.** The full share applies only while the device has recorded contact with another member within a window. The default is one day. Contact is recorded by the host when it hears from a peer, a node or the mailbox, and by a completed transfer. With no contact in the window, or with no other member in the period, the cap falls to the solo cap. Spending already done counts against the solo cap.
- **Clock floor.** The holder stores the highest time it has seen. A clock that reads lower is ignored and the floor is used, so setting a clock back earns no new period. A clock moved forward is believed. It starts a later period and ends freshness, so the device is on the solo cap in it.
- **Restore.** Backups hold the clock floor and nothing about spending. A restored device must enroll under a new member id, and `seed_from_backup` refuses the old one. The new holder starts with nothing spent and no contact. The old holder can finish its current period and then lapses when `retire` has been called. Until the owner removes the old member from the roster, its share stays in the derivation. This is safe because shares are disjoint.
- **Transfer.** To give headroom, a device closes its leases, which returns their residual to its free pool, then calls `prepare_transfer` and puts what is left back under a new lease. The target calls `accept_transfer` and leases what it received. The source calls `finalize_transfer`. A crash at any step is repaired on the next open, because the holder leases any free pool it finds, using request ids that make the lease issue repeatable. Total rights in the period never grow.

## Consequences

- No peer has to be reachable to know its share. The total is bounded by construction.
- A holder that has not yet seen a narrowing derives the wider share. The damage is bounded by that one period's old share.
- Moving the clock forward one period at a time earns a solo cap for each period. This is the stated exposure in the design: one fresh share plus solo caps.
- A device with no contact for a day is held to the solo cap. That is a bound, not a revocation. A removed device that is never online again cannot be told.
- A member added after a period starts waits for the next boundary.
- The holder's own process can bypass the bound. The bound protects against runaway models, injected instructions and loops. Real separation exists when a different peer verifies the receipt.
- Frozen wire formats (see `docs/wire-formats.md`) are unchanged. Period policies and budgets are new wire types with their own vectors.
