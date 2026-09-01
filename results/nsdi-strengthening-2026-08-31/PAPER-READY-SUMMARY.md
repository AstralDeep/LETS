# Paper-ready results summary

This file distills the reproducible evidence into compact language and tables.
Each subsection includes the qualification that should travel with the number.
The manuscript itself was not edited.

## Three-host Linux partition and centralized baseline

The remote experiment ran one real LETS SQLite warden and one separate local
SQLite executor claim store on each of three separately booted Linux SSH
endpoints. It crossed equal and 70%-to-s1 authority placement with equal and
70%-to-s1 demand, producing the full four-scenario factorial below. Every
scenario included normal operation, a symmetric s1↔s2 application-path gate,
and recovery; s3→s2 remained reachable. The same operation schedule was also
sent to a durable centralized SQLite counter on s2.

| Initial placement | Workload | LETS authorized / denied | Central authorized / denied | LETS consumed | Post-heal transfer |
|---|---|---:|---:|---:|---|
| Equal | Equal | 18 / 0 | 15 / 3 | 18 | s2→s1, 1 unit |
| Equal | 70% at s1 | 19 / 1 | 13 / 7 | 19 | s2→s1, 3 units |
| 70% at s1 | Equal | 16 / 2 | 15 / 3 | 16 | s1→s2, 2 units |
| 70% at s1 | 70% at s1 | 20 / 0 | 13 / 7 | 20 | s2→s1, 1 unit |

All four scenarios passed their assertions, retained healthy per-site SQLite
artifacts, conserved the 30-unit envelope, and completed and finalized one
post-heal transfer. During the gate, LETS sites continued against local
authority while requests originating at s1 could not reach the centralized
counter on s2; placement therefore changed how much LETS work completed under
skew. The JSON and CSV retain per-site cumulative authorization and denial,
local remaining authority,
stranded authority on the blocked counterpart, phase snapshots, transfer state,
and central outcomes.

This is independent-endpoint development evidence with important limits. Peer
bytes traversed a controller-mediated relay over two SSH sessions, not a direct
host-to-host route, and the fault was an application gate rather than a firewall
or physical partition. The three address fingerprints, SSH host keys, and Linux
boot-identity hashes are distinct, but those facts do not prove separate
physical machines, power supplies, racks, or failure domains. The executors used
LETS's explicit unanchored development mode, so this is not production rollback
evidence and no WAN latency conclusion is supported.

The readable report, raw scenario JSON, event timeline, aggregate comparison,
12-panel per-site timeline, and per-site phase-end table are under
`remote/three-host-linux-*`. The per-site figure explicitly shows cumulative
authorization and denial, remaining local authority, stranded authority, and
the partition interval for every scenario/site pair.

### Same-host high-volume companion

The separate same-host experiment issued 300 requests over three logical sites.
The partition was active for request indices 60–209 and isolated site A from a
centralized counter hosted at site B. LETS used a separate durable warden
database and executor claim database for each logical site. The centralized
baseline used one durable counter transaction. All components ran in one Python
process on one physical host; this is higher-volume accounting and
fault-injection evidence, not an independent-endpoint result.

| Workload and initial placement | LETS authorized / denied | Central authorized / denied | Site-A partition result, LETS | Site-A partition result, central | Stranded remote authority at first local exhaustion |
|---|---:|---:|---:|---:|---:|
| Balanced demand, equal 100/100/100 shares | 300 / 0 | 250 / 50 | 50 / 0 | 0 / 50 | — |
| 70/15/15 demand, equal 100/100/100 shares | 253 / 47 | 195 / 105 | 58 / 47 | 0 / 105 | 157 units |
| 70/15/15 demand, demand-placed 210/45/45 shares | 300 / 0 | 195 / 105 | 105 / 0 | 0 / 105 | — |

After the skew/equal-share partition healed, 55 units moved from site B to A
and 8 from C to A; both transfers were accepted once and finalized. The safe
same-host conclusion is: local LETS authorization continued until local
authority was
exhausted, unreachable authority remained unavailable rather than being
duplicated, placement affected completed work, and aggregate accounting never
exceeded the 300-unit envelope. The result must not be called a three-host
experiment.

Raw events and summaries are under `distributed/`; the ready-to-import figure
is `distributed/partition-skew-equal-shares.svg`, with a PNG preview beside it.

## Pinned native-Linux current-composition final dispatch

The matched replacement used clean, exact revisions of AstralDeep
`04f04ee93718d2ff681726e2a47a2550a837612d`, AstralPlane
`4a1d990387428436041dd70d9c417e9e86000b6c`, and LETS v1.0.11
`6245189920c686353c4ced7a208d56ec266f745c`. It ran on native x86-64 Linux
with CPython 3.12.3 and SQLite 3.45.1. Ten trials alternated mode order; each
mode received 100 warmups and 1,000 measured operations per trial, yielding
10,000 retained samples per mode.

| Mode | Pooled p50 | Pooled p95 | Pooled p99 | Mean | Sequential measured-path rate |
|---|---:|---:|---:|---:|---:|
| Off | 0.008558 ms | 0.015688 ms | 0.026794 ms | 0.010601 ms | 94,328.342 ops/s |
| Enforce | 34.096067 ms | 40.160652 ms | 45.904426 ms | 34.563711 ms | 28.932 ops/s |

The enforce path executed the real `GovernedFinalDispatch.execute`, the real
SQLite `WardenService` authorization and Ed25519 receipt path, public receipt
verification, and the real SQLite replay claim with process-file executor
anchor. Non-overlapping exclusive spans partition the pooled enforce mean:

| Exclusive span group | Mean | Share of enforce mean |
|---|---:|---:|
| Non-signing Warden transaction boundary | 14.899959 ms | 43.11% |
| Executor rollback-anchor claim and status | 9.752135 ms | 28.21% |
| Executor replay transaction and status | 5.756857 ms | 16.66% |
| Host gateway remainder | 1.211425 ms | 3.50% |
| Warden request adapter | 0.581456 ms | 1.68% |
| Receipt handoff and host validation | 0.512450 ms | 1.48% |
| Host dispatch framework | 0.477947 ms | 1.38% |
| Warden signing and serialization | 0.395659 ms | 1.14% |
| All other exclusive spans | 0.975823 ms | 2.82% |

Pooling the first 250 and last 250 measured operations from every enforce run
shows a within-run mean increase from 32.278389 to 36.968199 ms: +4.689810 ms,
or +14.53%. The non-signing Warden transaction span increased by 4.368956 ms,
93.16% of that net drift; signing/serialization contributed 0.010749 ms, or
0.23%. This localizes the observed drift numerically but does not by itself
identify whether database growth, journal/checkpoint behavior, storage, or
another effect inside that boundary is causal.

The timed host-binding, Plane transaction, audit, and coordinator adapters were
deterministic and in memory. The run excluded HTTP, PostgreSQL, provider/model
calls, and external tool work. Its Warden was unanchored; the executor anchor
and replay database shared one storage device, so production rollback-domain
independence was not established.

This result resolves the performance review item only as a pinned
current-composition replacement and decomposition. The original
`20260826T231656Z` artifact and exact driver are unavailable, and the historical
environment reported SQLite 3.53.4 rather than 3.45.1. It is therefore not a
reproduction or complete causal explanation of the historical 74.778 ms
AstralDeep/WSL2 result. The raw JSON retains every sample and inclusive/exclusive
span; `remote/matched-host/remote-matched-host-manifest.json` binds the clean
component revisions, environment, hashes, sanitization, and read-only recovery.

## Windows native LETS durable-core latency

The paired matrix retained 10,000 raw operations: 2 trials × 50 operations × 2
storage devices × 5 application delays × 5 worker counts × 2 modes. Enforce
mode executed the real durable `WardenService.authorize` path and the real
durable `ReceiptVerifier.verify_and_claim` path before the same synthetic
application delay used by off mode. Percentiles use nearest rank.

The storage devices were a WD_BLACK SN850X 2 TB NVMe on C: and a CT1000P1SSD8
1 TB NVMe on Y:, both NTFS on the same Windows host. File anchors were distinct
from the SQLite files but remained below the same selected storage root, so
they do not establish an independent rollback domain.

### Single-worker operational context

| Device | Application delay | Off p50 | Enforce p50 | p50 increment | Enforce p95 / p99 | Warden p50 | Claim p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| C: SN850X | 0 ms | 0.000 ms | 24.863 ms | 24.863 ms | 26.564 / 27.107 ms | 14.125 ms | 10.684 ms |
| C: SN850X | 1 ms | 1.983 ms | 26.012 ms | 24.029 ms | 27.989 / 28.290 ms | 14.107 ms | 10.619 ms |
| C: SN850X | 10 ms | 10.590 ms | 35.587 ms | 24.997 ms | 37.102 / 38.534 ms | 14.481 ms | 10.781 ms |
| C: SN850X | 100 ms | 100.456 ms | 126.118 ms | 25.663 ms | 130.553 / 132.631 ms | 14.971 ms | 10.752 ms |
| C: SN850X | 1000 ms | 1000.495 ms | 1026.919 ms | 26.424 ms | 1028.857 / 1029.794 ms | 15.385 ms | 10.932 ms |
| Y: CT1000P1 | 0 ms | 0.000 ms | 25.447 ms | 25.447 ms | 27.783 / 28.399 ms | 14.196 ms | 11.214 ms |
| Y: CT1000P1 | 1 ms | 1.297 ms | 28.378 ms | 27.081 ms | 30.906 / 49.598 ms | 14.991 ms | 11.656 ms |
| Y: CT1000P1 | 10 ms | 10.675 ms | 36.571 ms | 25.897 ms | 39.997 / 43.296 ms | 14.560 ms | 11.468 ms |
| Y: CT1000P1 | 100 ms | 100.415 ms | 127.443 ms | 27.029 ms | 130.307 / 137.541 ms | 15.480 ms | 11.458 ms |
| Y: CT1000P1 | 1000 ms | 1000.366 ms | 1028.809 ms | 28.443 ms | 1033.742 / 1045.524 ms | 16.453 ms | 11.615 ms |

At one worker, the current native durable core added roughly 24–28 ms at the
median. Relative to the observed off baseline, the median increment at the
1-second application cell was 2.64% on C: and 2.84% on Y:. This percentage is
descriptive for this run, not a population estimate.

### Concurrency endpoints

| Device | Delay | Workers | Enforce throughput p50 | Enforce p50 / p95 / p99 |
|---|---:|---:|---:|---:|
| C: SN850X | 0 ms | 1 | 39.72 ops/s | 24.863 / 26.564 / 27.107 ms |
| C: SN850X | 0 ms | 16 | 61.39 ops/s | 256.937 / 260.709 / 267.850 ms |
| C: SN850X | 1000 ms | 16 | 12.05 ops/s | 1031.678 / 1233.730 / 1263.581 ms |
| Y: CT1000P1 | 0 ms | 1 | 38.38 ops/s | 25.447 / 27.783 / 28.399 ms |
| Y: CT1000P1 | 0 ms | 16 | 60.03 ops/s | 253.874 / 265.353 / 270.801 ms |
| Y: CT1000P1 | 1000 ms | 16 | 12.02 ops/s | 1035.856 / 1242.214 / 1271.620 ms |

The zero-delay result shows shared-SQLite serialization: throughput plateaued
near 60 operations/s while end-to-end latency grew with queued workers. With a
1-second application delay, application work overlapped across workers and the
median stayed near 1.03 seconds, although p95/p99 retained contention tails.

These Windows numbers do not reproduce the paper's historical 74.778 ms
integrated AstralDeep/WSL2 final-dispatch result. This matrix runner omits Astral
host binding, routing, audit/coordinator work, and inter-component handoff, and
uses a different platform. It is therefore unsafe to subtract 25 ms from
74.778 ms and attribute the remainder to Astral. Treat it as a controlled
durable-core and concurrency companion to the pinned Linux replacement above,
not as another replicate of that integrated path.

## Resource-vector semantics

The runtime policy used `(read, system)` resources with costs `(1,0)` for
configuration inspection, `(0,3)` for service restart, and `(1,5)` for
credential rotation. It exercised independent attenuation, a `(4,10)`
cross-warden transfer, target authority derived solely from that inbound
transfer, a denied multi-dimensional action when the child had zero read
authority, and durable executor claims.

Twelve receipts were issued and eleven were claimed. One unclaimed `(0,3)`
receipt was allowed to expire; its warden debit remained consumed and was not
refunded. Duplicate transfer credit and duplicate executor settlement were
both rejected. Final accounting was:

```text
genesis budget      (40, 60)
free pool            (6, 10)
lease residual      (26, 23)
cumulative debit     (8, 27)
in-flight transfer    (0,  0)
spendable            (32, 33)
```

Thus conservation held independently in both dimensions and spendable
authority remained component-wise bounded by genesis.

A separate finite two-dimensional model used initial warden pools `(2,5)` and
`(1,3)`, total budget `(3,8)`, at most two leases, one transfer, and the same
three heterogeneous costs. Its state frontier was exhausted: 8,348 states and
18,468 transitions were checked through maximum shortest depth 10. Explored
coverage included 2,464 `(1,0)` authorizations, 1,801 `(0,3)` authorizations,
537 `(1,5)` authorizations, 141 attenuated spawns, and 2,891 transfer prepares
plus 2,891 accepts. A cross-dimension-debit mutant violated per-dimension
conservation after the shortest two-action trace. This is an exhaustive result
for that finite configuration, not an unbounded proof or source refinement.

## Recursive lineage scaling

The grid covered depths 1, 2, 4, and 8 and branching factors 1, 2, 4, and 8.
Every combination ran a disclosed spine-and-fanout tree; complete trees also
ran when their calculated size was at most 5,000 nodes. Thirty cells ran,
authorized every leaf, passed conservation, checkpointed, and reopened with
SQLite integrity `ok`. The complete depth-4/branch-8 tree was the largest at
4,681 nodes and 4,096 sibling actions; its authorization p50/p95 was
305.600/459.392 ms, throughput 52.5 ops/s, checkpointed state 85,744 KiB, and
reopen time 61.623 ms. Complete depth-8 trees at branching 4 and 8 were
explicitly skipped because they would contain 87,381 and 19,173,961 nodes.

A separate boundary probe accepted a chain at depth 64 and rejected depth 65
with `policy_denied`.

## Formal evidence

The scalar breadth-first run found no invariant violation in 101,245 states
and 318,558 expanded transitions through depth 9. It did not exhaust the
frontier: 48,720 states were first reached at the cutoff, and probing their
302,688 outgoing transitions found 69,492 unique unseen successors. Report the
result as bounded exploration with `termination=depth_limit`, not as exhaustive
verification.

Seven isolated mutants were all killed:

| Mutant | Violated property | Shortest actions |
|---|---|---:|
| Spawn without parent debit | global conservation | 2 |
| Restore source after target acceptance | global conservation | 3 |
| Accept duplicate executor claim | claim at most once | 4 |
| Close parent with live descendant | live-ancestor property | 3 |
| Accept stale authorization sequence | sequence freshness | 3 |
| Credit inbound without voucher | transfer origin | 1 |
| Admit noncontiguous checkpoint | checkpoint contiguity | 5 |

The theorem, assumptions, transition argument, and checker-to-implementation
mapping are in `drafts/FORMAL-NOTES.md`.

## Rollback, clones, and acceptance faults

The focused rollback matrix passed ten tests covering stale but internally
valid warden restoration, sequential and concurrent warden clones, warden
commit/anchor crash windows, stale executor restoration, concurrent executor
clones, executor confirmation loss, claim commit/anchor recovery, stale
recovery bundles, and same-directory process exclusion. The retained JUnit has
10 tests, 0 failures, 0 errors, and 0 skips.

The evidence does not directly test replacing a valid independent anchor with
a stale copy or jointly rolling back database and anchor. Those are deployment
assumptions, and production claims require independently administered rollback
domains.

The current Docker acceptance run also passed the three-node scenario. During
a bidirectional A↔B link fault, local progress receipts were issued while peer
delivery retained a durable retry. Recovery converged automatic transfer,
finalization, and checkpointing; a reordered transfer replay returned HTTP 409;
a SIGKILL restart preserved the signing key and replay rejection; an independent
executor rejected replay after reopening. Aggregate accounting remained 300,
with 20 units transferred out and in and all local invariants and audit chains
healthy. This remains three processes inside one Docker VM, not three hosts.

## Implementation and interface material

The source inventory found 34 Python runtime files with 28,573 physical lines
and 26,738 nonblank lines. The explicitly listed 18-file narrow core contains
16,169 physical and 15,188 nonblank lines. The inventory verifies eight facts
and binds every counted file by SHA-256. `drafts/IMPLEMENTATION-TABLE.md`
contains the component, storage, transaction, trust, crypto, serialization,
identifier, clock, and replica details.

`drafts/CURRENT-INTERFACE-COMPARISON.md` is a 2026-08-31 documentation audit of
OpenAI, Anthropic, Google, and Intended using 18 first-party links. Its negatives
are intentionally phrased as “not documented in the audited public interface.”

`drafts/SHADOW-AND-LIMITATIONS-NOTES.md` verifies that current shadow behavior
uses a real state-changing authorization, discards successful receipts before
claim, and fails open at the actuator. It recommends same-envelope shadow only
for disposable tests and a separate non-production envelope for production-like
observation. That is a design recommendation; no behavior was changed.

## Claims that still need external work

Before an NSDI submission asserts physical or failure-domain independence, run
the distributed workload on infrastructure whose machine, power, rack, and
storage-failure boundaries are independently verified, with direct peer routes,
a network-level fault, and production rollback anchors. The retained three-host
development run does not establish those properties.

The current pinned native-Linux final-dispatch path has now been run and deeply
instrumented, but reproducing the historical 74.778 ms value would require the
missing `20260826T231656Z` artifact, exact driver, and original environment. If
those cannot be recovered, report the new result as replacement evidence and
leave the historical value explicitly unreproduced.
