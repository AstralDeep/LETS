# Formal safety statement and bounded sensitivity

Let (D) be the resource dimensions and (W) the wardens for one fixed
envelope. For warden (w) and dimension (d), let (S_{w,d}) be its initial
share, (F_{w,d}) its free pool, (R_{w,d}) the sum of its lease residuals,
(C_{w,d}) its cumulative warden debits, and (I_{w,d}) and (O_{w,d}) its
cumulative accepted-in and prepared-out transfers. Define

\[
B_d = \sum_{w\in W} S_{w,d}, \qquad
X_d = \sum_{w\in W} O_{w,d} - \sum_{w\in W} I_{w,d}.
\]

Here (X_d) is authority durably debited at a source but not yet durably
credited at a target. Transfer finalization and checkpoint compaction do not
remove amounts from the cumulative (I) and (O) counters.

## Assumptions

The statements below are conditional on the following system assumptions.

1. The envelope configuration and genesis shares are fixed during the
   execution being considered, and the initial shares sum to (B).
2. Each logical warden serializes each mutation in one durable transaction.
   A committed mutation is recovered atomically; an uncommitted mutation has
   no effect.
3. The warden and executor stores enforce their schema constraints and use
   exact, nonnegative, component-wise vector arithmetic.
4. Trusted wardens follow the transition code. Source signing keys are not
   compromised, canonical signed records cannot be forged, and targets use
   the configured source-key registry.
5. There is at most one unfenced instance of each logical warden and executor
   state. The rollback authority rejects stale snapshots and clones. This is
   an operational precondition, not a state explored by the bounded model.
6. Transfer acceptance verifies the envelope, configuration epoch, source,
   target, policy, signature, sequence, transfer identifier, and voucher
   digest. The durable uniqueness and digest bindings remain effective across
   retries, restarts, out-of-order delivery, and compaction.
7. A close reclaims only an eligible lease; in particular, it cannot reclaim
   a parent while a live descendant remains. A checkpoint covers only a
   contiguous finalized prefix.
8. Executor settlement is durable before the protected effect is invoked.
   Conservation concerns authority expenditure, not proof of physical
   completion; a warden debit whose receipt is never settled remains debited.

## Accounting lemmas and theorem

**Lemma 1 (local preservation).** For every committed state of a warden and
every dimension (d),

\[
S_{w,d}+I_{w,d}=F_{w,d}+R_{w,d}+C_{w,d}+O_{w,d}.
\]

Every enabled local transition preserves this identity: root issue moves an
amount from (F) to (R); spawn moves it between parent and child residuals;
authorization moves its cost from (R) to (C); eligible close moves residual
from (R) to (F); transfer prepare moves an amount from (F) to (O); and
transfer acceptance increases (I) and (F) by the same amount. Finalization,
idempotent retries, executor settlement, and checkpoint compaction do not
change this identity.

**Lemma 2 (non-duplication and origin of transfer credit).** For each logical
voucher (v), let (\mathsf{credit}(v)) count committed target transactions
that add (v)'s amount to (F) and (I). Under Assumptions 2--6,

\[
\mathsf{credit}(v)\in\{0,1\},
\]

and (\mathsf{credit}(v)=1) implies that a source transaction previously
decreased its free pool and included the same amount in (O). The target's
durable key ((\text{tenant},\text{envelope},\text{source},\text{sequence})),
the independent transfer-identifier uniqueness constraint, and voucher-digest
binding make a duplicate delivery return the stored acknowledgement rather
than credit again. Consequently,

\[
X_d=\sum_{v:\,\mathsf{credit}(v)=0} \mathsf{amount}(v)_d\ge 0.
\]

**Theorem 1 (global conservation across transfer).** If the initial state
satisfies Lemma 1, then every reachable committed state satisfying the stated
assumptions obeys, independently for every resource dimension (d),

\[
B_d =
\sum_{w\in W}F_{w,d}
+\sum_{w\in W}R_{w,d}
+\sum_{w\in W}C_{w,d}
+X_d.
\]

*Proof sketch.* Sum Lemma 1 over the wardens and rearrange. Lemma 2 makes
(X_d=\sum_w O_{w,d}-\sum_w I_{w,d}) a nonnegative sum of prepared but
unaccepted transfer amounts. Preparation decreases spendable authority and
increases (X) equally; acceptance increases target free authority and
decreases (X) equally; finalization changes neither term. All other actions
preserve the local identity. Induction over committed transitions gives the
result. Because (C_d,X_d\ge0), the immediately spendable authority satisfies

\[
\sum_w F_{w,d}+\sum_w R_{w,d}\le B_d.
\]

**Lemma 3 (executor claim uniqueness).** For a fixed executor authority
boundary, each receipt identifier and nonce can cause at most one durable
settlement, and an accepted sequence must advance the corresponding lease
watermark. This follows from the atomic claim transaction, the receipt primary
key, the nonce uniqueness constraint, and the monotonic lease watermark. It is
separate from warden debit: settlement does not debit authority a second time.

## Executable-model correspondence

The checker is an intentionally smaller scalar abstraction. The correspondence
below is a refinement map, not a claim of line-by-line equivalence; the runtime
also models resource vectors, policies, epochs, clocks, signatures, and recovery.

| Abstract term or action | Executable model | Implementation component |
|---|---|---|
| (B,S_w) | `Bounds.initial_shares`, `Bounds.budget` | `envelopes.initial_local_share` and `envelopes.budget` |
| (F_w) | `State.pools[w]` | `warden_state.free_pool` |
| (R_w) | sum of `Lease.residual` | `leases.residual`, aggregated by triggers in `warden_state.lease_residual` |
| (C) | `State.consumed` | `warden_state.consumed` at each warden |
| (X) | amounts of `Transfer(status="PREPARED")` | cumulative `transferred_out - transferred_in` |
| root issue | `issue_root` | `WardenService.issue_root` |
| delegated issue | `spawn` | `WardenService.spawn` and the parent-linked `leases` table |
| warden debit | `authorize` and `Receipt` | `WardenService.authorize`, the `receipts` table, and the signed `Receipt` |
| eligible reclaim | `close_lease` | `WardenService.close` |
| transfer prepare | `prepare_transfer` | `WardenService.prepare_transfer`, `outgoing_transfer_streams`, and `outgoing_transfers` |
| transfer accept | `accept_transfer` | `WardenService.accept_transfer`, `inbound_transfer_streams`, and `inbound_transfer_acks` |
| transfer finalize | `finalize_transfer` | `WardenService.finalize_transfer` and the source outgoing status |
| executor settlement | `claim_receipt`, claimed identifiers/nonces, and watermarks | `ReceiptVerifier.verify_and_claim`, `receipt_claims`, `lease_watermarks`, and `claim_history` |
| invariant check | `conserved_rights` and `validate` | `ConservationSnapshot` and SQLite's local-conservation check |

## Bounded exploration: depth 9 is a cutoff, not exhaustion

The breadth-first checker instantiated one scalar dimension with initial shares
((1,1,1)), budget 3, at most three leases, two transfers, two receipts, unit
action amounts, and a shortest-trace cutoff of nine actions. It found no
invariant violation among **101,245 states** and **318,558 expanded
transitions** through that cutoff. This is bounded evidence, not an exhaustive
exploration of the configured transition system: the 48,720 states first
reached at depth 9 had 302,688 outgoing transitions, including **69,492 unique
successor states not previously seen**. Accordingly, the result is reported as
`termination=depth_limit` and `frontier_exhausted=false`.

| Shortest depth | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| States first reached | 1 | 9 | 57 | 210 | 732 | 2,199 | 6,030 | 14,307 | 28,980 | 48,720 |
| Outgoing transitions checked | 9 | 69 | 336 | 1,356 | 4,533 | 13,692 | 36,693 | 86,754 | 175,116 | 302,688 |

Depth-9 outgoing transitions were probed to characterize the frontier but their
successors were not enqueued. At lower depths, the table reports expanded
outgoing transitions.

## Mutation sensitivity

A separate breadth-first sensitivity run used initial shares ((2,1)), budget
3, at most three leases, two transfers, two receipts, maximum action amount 2,
and cutoff depth 6. Its unmodified baseline found no property violation in
4,569 states and 9,341 transitions; it also terminated at its depth cutoff.
Each mutant below was enabled alone. All seven were killed, and counterexample
depth is the number of actions in the shortest trace.

| Isolated mutant | Violated property | Depth | States | Transitions |
|---|---|---:|---:|---:|
| Spawn without parent debit | `global_conservation` | 2 | 14 | 14 |
| Restore source after target acceptance | `global_conservation` | 3 | 138 | 185 |
| Accept duplicate executor claim | `claim_at_most_once` | 4 | 252 | 366 |
| Close parent with a live descendant | `active_descendant_has_active_ancestors` | 3 | 58 | 64 |
| Accept stale authorization sequence | `authorization_sequence_freshness` | 3 | 84 | 103 |
| Credit ghost inbound without voucher | `transfer_origin` | 1 | 7 | 7 |
| Admit noncontiguous checkpoint | `checkpoint_contiguity` | 5 | 1,538 | 2,716 |

These mutations show that the checked predicates detect the intended failure
classes within these bounds; they do not establish completeness outside them.
The evidence is bound to model digest
`sha256:77d48812fa293cf5934496c90a435f8f7792a6f88aef6e4f460bcf0e7ee3b5b8`
and analyzer digest
`sha256:c6db9dfd332c2895562fa8cfb3f9729637c6c033823dde6cfd131f685d403f68`.

Evidence source: `results/generated/formal/sensitivity-frontier.json`. Model and
implementation sources: `formal/model_checker.py`,
`formal/sensitivity_frontier.py`, `src/lets/invariants.py`,
`src/lets/service.py`, `src/lets/storage/schema.py`, and
`src/lets/executor.py`.
