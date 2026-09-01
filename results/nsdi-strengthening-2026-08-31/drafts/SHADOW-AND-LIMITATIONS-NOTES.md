# Shadow semantics and limitations notes

Status: paper-ready drafting material based on the current repository. This file
does not change LETS, the host integration, or the submission.

## Current shadow behavior: factual description

The current LETS core does not implement a read-only `shadow` authorization.
Its transition endpoint calls the ordinary `authorize` method
(`src/lets/api.py:592-609`), and the public client sends the ordinary idempotent
transition request (`src/lets/client.py:461-472`). The service states the
operation directly: authorize, debit, advance state and sequence, and persist a
signed receipt (`src/lets/service.py:2570-2583`). On success, the same durable
transaction subtracts the cost from the lease residual and advances the lease
state and sequence (`src/lets/service.py:2804-2819`), increases the warden's
consumed counter and revision (`src/lets/service.py:2820-2827`), and inserts the
signed receipt (`src/lets/service.py:2828-2840`). A caller cannot turn this path
into a non-mutating check by discarding its response: the mutation has already
committed at the warden.

`shadow` is therefore a host-side use of a real LETS authorization, not a LETS
protocol mode. In the retained case-study contract, the runner maps shadow to
`evaluate` (`benchmarks/astraldeep/run_case_study.py:143-148`). Every enabled
scenario must make at least one LETS request, while a shadow scenario is invalid
if it claims a receipt (`benchmarks/astraldeep/run_case_study.py:547-554`). For
fault scenarios, only enforce mode is expected to deny; shadow is expected to
execute the physical effect (`benchmarks/astraldeep/run_case_study.py:203-212`,
`benchmarks/astraldeep/run_case_study.py:616-630`). Thus the studied shadow
posture is **state-changing and fail-open at the actuator**: a successful check
consumes authority but its receipt is not passed to or claimed by the executor,
and a failed check does not prevent the effect.

The retained figure derivation reports 19 shadow scenarios, 33 warden calls, 15
issued receipts, zero claimed receipts, and 18 physical effects
(`paper/submission/figures/evidence_behavior.json:32-37`). The benchmark tests
encode the same evidence contract: synthetic shadow results issue but do not
claim receipts (`tests/benchmarks/test_astraldeep_case_study.py:91-115`), the
mode is labeled `evaluate` (`tests/benchmarks/test_astraldeep_case_study.py:438-439`),
a shadow claim is rejected (`tests/benchmarks/test_astraldeep_case_study.py:658-672`),
and the aggregate role is `shadow-observation`
(`tests/benchmarks/test_astraldeep_case_study.py:2002-2008`). These tests validate
the harness and retained-evidence contract; they are not an independent replay
of the external host implementation.

### Paper-ready paragraph

> Shadow is an observational posture at the host boundary, not a read-only LETS
> transaction. The host submits the normal authorization request. A successful
> request durably debits the lease, advances its state and sequence, increments
> warden consumption, and persists a signed receipt. The host then discards that
> receipt before executor handoff, so the executor neither verifies nor durably
> claims it. If shadow authorization fails, the host records the outcome but
> still permits the protected effect. Shadow therefore measures authorization
> decisions under a fail-open host policy while consuming the authority used by
> successful checks. It must not be described as a dry run, a non-mutating
> policy preview, or evidence of executor mediation.

This agrees with the current submission's existing description
(`paper/submission/manuscript.tex:160`, `paper/submission/manuscript.tex:274`,
`paper/submission/manuscript.tex:285-289`).

## DESIGN RECOMMENDATION (not implemented)

**Recommended current-release posture:** confine same-envelope shadow to
isolated, disposable tests. If production-like shadow observation is required,
run it against a separately bootstrapped shadow envelope and leases whose
authority can never be handed to a production executor. Do not run shadow
authorizations against the production envelope merely to discard their
receipts.

| Option | What it would mean | Safety and evidentiary consequence | Recommendation |
|---|---|---|---|
| Test-only, same semantics | Keep the current call/discard/fail-open behavior, but use disposable stores and authority. | Exactly exercises the implemented state-changing path. It cannot observe live production decisions without consuming the tested authority. | Safe immediate default for experiments and CI. Label results as path tests, not production shadow telemetry. |
| Separate shadow envelope | Mirror policy and lifecycle inputs into a distinct `(tenant, envelope)` with distinct leases, request identifiers, and nonces; never expose its receipts to a production executor. | Prevents shadow checks from consuming production authority or creating production-spendable receipts. Its residuals and sequences can diverge, so a decision is an advisory comparison, not proof that the contemporaneous production request would be admitted. | Preferred near-term production-like design because it needs no change to core transaction semantics. Provision, rotate, revoke, and audit it as explicitly non-production authority. |
| Non-mutating authorization mode | Add a new preview operation that evaluates against an observed revision without debit, sequence advance, consumption update, or signed spendable receipt. | Gives the cleanest policy preview but introduces concurrency and time-of-check/time-of-use questions. A preview can be stale immediately and must never be accepted as authority. | A future protocol feature only. Specify a distinct advisory wire type bound to the observed revision and policy digest; do not implement it as transaction rollback or as an ordinary signed receipt. |

The separate envelope recommendation protects production conservation by domain
separation, not by pretending shadow is non-mutating. It should carry explicit
metadata such as `purpose=shadow`, use independent lease identifiers, exclude
executor trust distribution for its signing key, and report both the advisory
decision and the production decision when comparison is required. Differences
caused by lifecycle lag, residual divergence, or concurrent production traffic
must be counted rather than silently reconciled.

## Compact three-part limitations rewrite outline

### 1. Safety boundary and operational availability

Retain the non-Byzantine warden, protected keys and clocks, durable independent
rollback anchors, protected executor and claim store, and complete-mediation
assumptions. State explicitly that conservation and availability are different
claims: a partitioned warden can spend only authority already local to its free
pool and leases, while remote authority remains unavailable until authenticated
transfer resumes. The work does not establish Byzantine tolerance, online
membership reconfiguration, share-placement policy quality, external-operation
exactly-once semantics, or physical completion from a receipt claim. The current
submission already supplies the underlying points at
`paper/submission/manuscript.tex:298-300`.

### 2. Formal and experimental evidence boundary

Describe the formal artifacts as finite scalar state-space explorations, not
proofs or source refinements. Describe the distributed acceptance and soak rows
as bounded fault-path executions on one physical host and one Docker VM, with no
independent-host or WAN experiment and no availability distribution. Describe
the latency studies as single-host synthetic microbenchmarks, not an
application slowdown estimate or population inference. This consolidates the
current qualifications in `paper/submission/manuscript.tex:295` and
`paper/submission/manuscript.tex:302` without weakening the observed safety
results.

### 3. Host integration, shadow, and outcome boundary

State that the host study covers the configured cohorts, six invocation-count
dimensions, and fixed scenarios only; it neither covers every execution path nor
exercises cross-warden transfer. A durable claim shows consumption at the
executor boundary, not success of the external operation. Shadow is the
state-changing, no-claim, fail-open observation posture described above, so it
does not demonstrate executor mediation and should not share production
authority. The mechanism bounds configured authorization units; it does not
measure tokens, money, compute, time, reasoning quality, or application outcome.
The existing source for these qualifications is
`paper/submission/manuscript.tex:278-280`,
`paper/submission/manuscript.tex:289-293`, and
`paper/submission/manuscript.tex:304`.

## Stale TLC wording to correct when the paper is edited

The sentence at `paper/submission/manuscript.tex:302` is stale:

> The pinned TLC runner exposed upstream pin drift, while the separate
> current-tool execution does not repair that reproducibility gap.

The current repository now pins the official TLC v1.8.0 JAR by release, exact
byte count, SHA-256, URL, and reported version (`formal/tlc-tool.json:2-7`). The
retained evidence records a passing run with an empty queue and the same tool
identity plus exact specification and configuration hashes
(`formal/evidence/tlc-check.json:3-17`). A repository test verifies all those
bindings against the current files (`tests/formal/test_bounded_model.py:56-73`).
The comment at `paper/submission/evidence.tex:92-93`, which still says the
"pinned hash drifted," is stale for the same reason.

Suggested replacement:

> The formal models are finite scalar abstractions, not proofs or source
> refinements. The retained TLC evidence records a completed finite exploration
> and binds the official v1.8.0 tool, specification, and configuration by exact
> hashes and byte count. Those bindings make this bounded run reproducible; they
> do not establish unbounded correctness, source refinement, or validity after a
> model or implementation change without a fresh run.

One small provenance caveat should remain visible: the retained runner command
contains a legacy `1.0.0` output-directory label
(`formal/evidence/tlc-check.json:8`). The label should not be used as release
identity; the evidentiary identity is the bound tool/spec/config content. A
future regeneration can remove that naming residue.
