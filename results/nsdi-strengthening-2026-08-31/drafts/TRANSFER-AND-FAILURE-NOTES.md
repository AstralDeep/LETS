# Transfer and failure semantics

This draft states the operational semantics that are easy to blur in prose:
authority expenditure, receipt settlement, and physical completion are three
different events. All quantities below are nonnegative resource vectors and all
equalities hold component-wise for one fixed tenant, envelope, and configuration
epoch.

## Conservation and the three effect-path events

For warden \(w\), let \(S_w\) be its genesis share, \(F_w\) its free pool,
\(R_w=\sum_{\ell\text{ at }w}R_\ell\) its live lease residual, \(C_w\) its
cumulative warden debit, and \(I_w,O_w\) its cumulative accepted-in and
prepared-out transfer amounts. LETS maintains the local identity

\[
S_w+I_w=F_w+R_w+C_w+O_w .
\]

Let \(B=\sum_w S_w\) and \(X=\sum_w O_w-\sum_w I_w\). Authenticated,
exactly-once transfer acceptance makes \(X\) the nonnegative amount prepared
at a source but not yet accepted at a destination. Summing the local identities
gives

\[
B=\sum_w F_w+\sum_w R_w+\sum_w C_w+X ,
\qquad
\sum_w F_w+\sum_w R_w\le B .
\]

The last inequality is the safety claim: currently spendable authority cannot
exceed the genesis budget.

For an authorized transition with cost \(c\), the **warden debit** is one
serialized transaction:

\[
(R_\ell,C_w,q_\ell)
\longrightarrow
(R_\ell-c,\ C_w+c,\ q_\ell+1),
\]

subject to the policy, capability, evidence, state, audience, expiry, epoch,
expected-sequence, and component-wise \(c\le R_\ell\) checks. The same
transaction persists the signed receipt, idempotent response, audit record, and
outbox event before returning. A receipt that is lost, abandoned, or expires
without being claimed does not restore \(R_\ell\): its cost remains in \(C_w\).
This conservative loss of capacity is deliberate; generic refund after receipt
issuance would permit a still-live receipt to spend restored authority.

The **executor settlement** is a different durable transaction. For executor
claim set \(Q_e\), nonce set \(N_e\), and lease watermark \(W_e\), accepting
receipt \(r\) performs

\[
\begin{aligned}
Q'_e &= Q_e\cup\{r.\mathit{receipt\_id}\},\\
N'_e &= N_e\cup\{(r.\mathit{tenant},r.\mathit{envelope},
                 r.\mathit{audience},r.\mathit{nonce})\},\\
W'_e[r.\mathit{warden},r.\mathit{lease},r.\mathit{audience}]
  &=r.\mathit{resulting\_sequence}>W_e[\cdot].
\end{aligned}
\]

It also appends a hash-chained claim event and advances the external monotonic
claim anchor before authorizing the actuator call. Settlement changes none of
\(F,R,C,I,O,X\); the budget was already debited.

For indicator variables \(D_r\) (durable warden debit), \(Q_r\) (durable
executor claim), and \(V_r\) (actuator invocation through the protected path),
complete mediation gives

\[
V_r\le Q_r\le D_r\le 1.
\]

This ordering does not prove physical completion. A crash can occur after
claim but before invocation, or after the actuator completes but before its
response is observed. Exactly-once external effects therefore still require a
domain transaction, an idempotent actuator operation, compensation, or explicit
uncertain-outcome handling.

| Failure point | Budget state | Claim state | External outcome |
|---|---|---|---|
| Before warden commit | unchanged | absent | not invoked |
| After debit, before receipt delivery | debited permanently | absent | not invoked |
| After receipt delivery, before claim | debited permanently | absent | not invoked |
| After claim, before actuator | debited | claimed | not invoked or uncertain |
| After actuator, before response | debited | claimed | completed, response uncertain |

## Replay and idempotency scope

The word “replay” covers distinct keys at distinct trust boundaries:

| Boundary | Durable key and binding | Exact repeat |
|---|---|---|
| Warden client mutation | \((tenant,envelope,request\_id)\), envelope-global and bound to operation scope plus the full request fingerprint | returns the stored response; reuse for another operation, target, or payload conflicts |
| Peer HTTP authentication | \((tenant,envelope,peer\_warden,key\_id,http\_nonce)\), after signature, body digest, path, and timestamp verification | the identical HTTP envelope is rejected; a logical protocol retry uses a newly signed HTTP nonce |
| Transfer voucher acceptance | \((tenant,envelope,source,sequence)\) bound to the voucher digest, with an independent transfer-identifier uniqueness constraint | before compaction, returns the stored acknowledgement without credit; a conflict is rejected; a covered compacted-prefix replay is rejected |
| Executor receipt claim | receipt identifier, store-wide, and \((tenant,envelope,audience,nonce)\) | rejected without another claim |
| Executor lease order | \((warden,lease,audience)\mapsto resulting\_sequence\) | a non-increasing sequence is rejected |

Thus transport replay rejection does not replace logical idempotency. If a
response is lost after the transport nonce was durably burned, the sender
retries the same request or voucher identity in a fresh authenticated envelope.

## Roles

| Role | Authority and responsibility | Cannot do |
|---|---|---|
| Authorized administrator or host | invokes prepare at the source with one durable operation identity and the lets.transfer or administrative scope | cannot mint a source voucher, destination credit, or acknowledgement |
| Source warden | owns the debited free pool; selects the per-destination sequence; signs and durably queues the voucher; verifies the destination acknowledgement | never restores the amount merely because delivery or a response timed out |
| Destination warden | authenticates the peer request and source voucher; enforces epoch, policy, target, sequence-window, transfer-ID, and digest bindings; credits once and signs the acknowledgement | cannot credit an unauthenticated, conflicting, or out-of-window voucher |

The executor is not a participant in this handoff. Transfer moves free
authority, not an active lease, running agent, credential, memory image, or
physical effect. The destination may issue new leases and receipts only after
the accepted amount is in its local free pool.

## Transfer sequence and durability points

For amount \(a\) sent from source \(s\) to destination \(t\):

~~~text
administrator        source warden                         destination warden
     |                     |                                      |
     | prepare(request_id) |                                      |
     |-------------------->| D1: debit, sign, persist, enqueue    |
     |                     |---- signed voucher ----------------->|
     |                     |                         D2: verify, credit once,
     |                     |                             persist and sign ack
     |                     |<--- signed acknowledgement ----------|
     |                     | D3: verify and finalize               |
     |                     |---- signed prefix checkpoint ------->| D4: compact
~~~

1. **D1—prepare at the source.** One source transaction allocates the next
   sequence in the \((envelope,source,target)\) stream, persists the signed
   voucher and durable delivery record, records the idempotent prepare response,
   and applies
   \[
   F'_s=F_s-a,\qquad O'_s=O_s+a.
   \]
   Commit precedes the prepare response. Timeout does not cancel this debit.

2. **D2—accept at the destination.** Peer authentication first verifies the
   signed HTTP envelope and durably burns its transport nonce. A destination
   transaction then verifies the signed voucher and applies, at most once,
   \[
   F'_t=F_t+a,\qquad I'_t=I_t+a.
   \]
   It stores the voucher binding and signed acknowledgement before replying.
   A sequence within the configured gap window may be credited out of order
   while the contiguous watermark waits for missing predecessors; a sequence
   beyond the window is rejected without credit.

3. **D3—finalize at the source.** The source verifies the destination signature,
   epoch, source/target identities, transfer identifier, sequence, and voucher
   digest, then durably records finalization and advances only the contiguous
   acknowledged watermark. This changes no resource vector.

4. **D4—checkpoint and compaction.** After a contiguous prefix is finalized and
   confirmed delivered, the source signs a prefix checkpoint. The destination
   admits only a verified, monotonic, contiguous checkpoint. Individual rows
   may then be pruned, while cumulative \(I\) and \(O\) remain unchanged.

In production, each authoritative transaction is admitted against the
independent monotonic authority anchor. A post-commit anchor failure is not
reported as success; the process fails closed and a restart may reconcile only
a provable contiguous extension.

## Transfer failure matrix

| Fault | Source durable state | Destination durable state | Recovery and safety result |
|---|---|---|---|
| Source crash before D1 commit | unchanged | unchanged | same prepare request may be retried |
| Source crash after D1, before send | debited; voucher and outbox durable | unchanged | restart dispatches the same voucher; authority is stranded until delivery |
| Prepare response lost | debited once; idempotent response durable | unchanged or later credited | retry with the same request ID returns the same voucher, never a second debit |
| Voucher lost or source-to-destination partition | debited and pending | unchanged | durable backoff/retry; no timeout refund |
| Destination crash before D2 commit | debited and pending | unchanged | a fresh authenticated delivery can retry |
| Destination crash after D2, before acknowledgement is observed | debited and pending | credited once; acknowledgement durable | duplicate voucher returns the stored acknowledgement after restart |
| Acknowledgement path partitioned or response lost | still PREPARED until D3 | credited once | source resends the same voucher with a fresh HTTP nonce, recovers the acknowledgement, then finalizes |
| Source crash after D2, before or during D3 | PREPARED or durably FINALIZED | credited once | restart retry is idempotent at both target acceptance and source finalization |
| Duplicate logical voucher | debited once | credited once | matching duplicate returns the original acknowledgement before compaction; conflict or covered-prefix replay fails closed |
| Exact duplicate HTTP envelope | unchanged from its prior logical outcome | unchanged from its prior logical outcome | transport nonce replay is rejected; logical retry requires a fresh envelope |
| Out-of-order delivery | debited | credited once if within the gap window; otherwise unchanged | accepted gaps delay only the contiguous watermark; beyond-window delivery is rejected |
| Bidirectional peer partition | existing local ledgers remain usable | existing local ledgers remain usable | transfer progress stops; already accepted credit remains spendable, while unaccepted debit remains stranded |

## Conditional partition guarantee

The partition property is a safety-preserving **conditional local-progress**
statement, not global availability. During loss of peer/control-plane
connectivity, a site can authorize a transition without contacting another
warden if and only if:

1. the host or subject can still reach the lease-owning local warden and the
   intended protected executor;
2. both local durable stores, clocks, keys, and rollback anchors are healthy;
3. the lease remains active, unexpired, correctly sequenced, and locally funded
   component-wise for the requested cost; and
4. all policy, capability, evidence, epoch, audience, and host-mediation checks
   pass without requiring a new cross-warden transfer.

Peer reachability is absent from the local authorization transaction, so those
conditions suffice for safe local progress. They do not guarantee that an
arbitrary disconnected agent can act, that a site can borrow remote rights, or
that a locally exhausted site remains available. Authority at an unreachable
warden and authority in an unaccepted transfer are stranded. Conservation is
maintained despite this loss of availability; the implementation chooses
bounded authority over unconditional progress.

An agent's execution location is also distinct from its accounting site. An
agent may cross a provider boundary while continuing to use the same
lease-owning warden and executor path. Conversely, cross-warden transfer moves
only free authority and does not migrate that agent or its active lease.

## Rollback and clone evidence taxonomy

The standalone runner at
benchmarks/nsdi_strengthening/rollback_matrix.py selects the following ten
focused tests under the runner's current Python executable and retains JUnit,
complete standard output/error, source revision, dirty state, platform, and a
machine-readable requirement mapping.

| Failure class | Selected test | Established behavior |
|---|---|---|
| Warden database rollback | test_external_anchor_rejects_a_stale_but_internally_valid_backup | a valid stale SQLite copy is older than the independent anchor and is rejected |
| Sequential warden clone | test_anchor_fences_a_second_database_copy_before_its_next_write | after one copy advances, the other copy is fenced before its next write |
| Warden commit/anchor crash window | test_commit_anchor_crash_window_fails_closed_then_recovers_extension | no success escapes the failed anchor update; restart proves and anchors the committed extension |
| Concurrent warden forks | test_simultaneous_database_forks_use_one_linearizable_anchor_successor | one fork wins the anchor successor CAS and the divergent fork is rejected |
| Executor claim-store rollback | test_process_anchor_rejects_stale_preclaim_database_restore | restoring the pre-claim replay database behind its claim anchor is rejected |
| Concurrent executor clones | test_concurrent_cloned_databases_have_one_external_cas_winner | exactly one cloned claim store advances the external anchor |
| Executor anchor response loss | test_process_executor_startup_confirm_lost_reply_preserves_and_reconfirms | restart reads and reconfirms an initialization whose confirmation response was lost |
| Claim commit/anchor crash window | test_commit_before_anchor_failure_recovers_claim_without_reauthorizing | restart anchors the committed claim, and the original receipt remains a replay |
| Recovery-bundle replacement | test_stale_recovery_bundle_is_fenced_before_live_files_are_replaced | an anchor mismatch is rejected before replacing live state; interrupted exact restore resumes from its journal |
| Same-state concurrent operation | test_server_holds_same_process_lock_as_recovery_for_its_full_lifetime | serving and recovery cannot concurrently own one local node directory |

Run it from the repository root with:

~~~powershell
uv run --frozen python -m benchmarks.nsdi_strengthening.rollback_matrix --output-dir results/nsdi-strengthening-2026-08-31/rollback-clone
~~~

These tests distinguish four anchor relations. A database behind the anchor is
stale and rejected; an equal database is admitted; a database ahead of the
anchor is admitted only when it proves a contiguous extension, allowing safe
recovery from a database commit followed by a lost anchor response; and a
same-position or concurrent divergent successor is rejected. Process locking
adds same-directory exclusion but is not a substitute for clone fencing.

The evidence boundary must remain explicit. The selected tests use local
file/process anchors and local concurrency, not independently administered
hosts. Replacing a valid anchor with a stale copy, rolling back the database and
anchor together, compromising the anchor or its keys, or violating the
linearizable-CAS assumption is not directly tested and is outside the claimed
fault model. Production protection therefore requires the database and
monotonic anchor to reside in independently administered rollback domains.

## Source cross-reference

The transfer state machine is implemented in src/lets/service.py and the
durable dispatcher in src/lets/peer.py. Replay boundaries are implemented in
src/lets/auth.py and src/lets/executor.py. The runner's exact selectors and
coverage labels are authoritative in
benchmarks/nsdi_strengthening/rollback_matrix.py.
