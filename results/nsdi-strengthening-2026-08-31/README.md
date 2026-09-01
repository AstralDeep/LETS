# LETS paper-strengthening evidence

This directory is the entry point for the reproducible work requested on
2026-08-31. The submission under `paper/submission/` was read for context but
was not edited. Results were generated from `main` at
`a9f4ba810e1741f93ba204eb782b6c4e3d409a03`, which matched `origin/main` after
the local repository was fast-forwarded.

The evidence-generating working tree is intentionally recorded as dirty because
the new harnesses and their tests were uncommitted when the measurements ran.
The exact pre-PR source bytes are frozen in a deterministic source snapshot;
the review-facing Python files were subsequently Ruff-formatted without changing
the retained raw observations. Before treating the numbers as archival
submission evidence, rerun from a clean merged checkout. The evidence retains
the commit, environment, configuration, and observations needed to audit the
present run.

## Start here

- [Paper-ready results and caveats](PAPER-READY-SUMMARY.md)
- [Exact reproduction commands](RUNBOOK.md)
- [Three-host Linux report](remote/three-host-linux-report.md)
- [Three-host Linux raw scenario JSON](remote/three-host-linux-result.json)
- [Three-host Linux timeline data](remote/three-host-linux-timeline.csv)
- [Three-host Linux aggregate timeline figure](remote/three-host-linux-timeline.svg)
- [Three-host Linux per-site timeline figure](remote/three-host-linux-per-site-timeline.svg)
- [Three-host Linux per-site PNG preview](remote/three-host-linux-per-site-timeline.png)
- [Three-host Linux per-site phase-end table](remote/three-host-linux-phase-end.md)
- [Pinned native-Linux final-dispatch replacement](remote/matched-host/matched-host-path.md)
- [Pinned replacement raw samples (CSV)](remote/matched-host/matched-host-path-samples.csv)
- [Pinned replacement raw result (deterministic JSON gzip)](remote/matched-host/matched-host-path.json.gz)
- [Pinned replacement provenance and recovery manifest](remote/matched-host/remote-matched-host-manifest.json)
- [Partition/skew summary](distributed/PARTITION-RESULTS.md)
- [Partition figure](distributed/partition-skew-equal-shares.svg)
- [Partition figure PNG preview](distributed/partition-skew-equal-shares.png)
- [Performance matrix](performance/performance-matrix.md)
- [Vector workload](vector/VECTOR-RESULTS.md)
- [Lineage scaling](lineage/LINEAGE-RESULTS.md)
- [Formal frontier and mutation results](formal/sensitivity-frontier.md)
- [Two-dimensional finite-model results](formal/VECTOR-MODEL-RESULTS.md)
- [Rollback/clone machine-readable summary](rollback/rollback-matrix.summary.json)
- [Implementation inventory](implementation/implementation-inventory.md)
- [Current Docker acceptance summary and artifact hashes](docker/DOCKER-ACCEPTANCE.md)
- [SHA-256 manifest for this evidence directory](MANIFEST.json)
- [SHA-256 snapshot of the paper inputs that were read](PAPER-INPUT-MANIFEST.json)
- [SHA-256 manifest for the final harnesses, tests, project dependency locks, and declared controller dependency](SOURCE-MANIFEST.json)
- [Source-state and post-run formatting provenance](source/SOURCE-PROVENANCE.md)
- [Exact pre-PR source snapshot](source/pre-pr-source-snapshot.zip)

The `drafts/` directory contains paste-ready technical material:

- [Conservation theorem, lemmas, refinement map, and sensitivity table](drafts/FORMAL-NOTES.md)
- [Debit/claim semantics, connectivity guarantee, transfer sequence, and failure matrix](drafts/TRANSFER-AND-FAILURE-NOTES.md)
- [Implementation and TCB table](drafts/IMPLEMENTATION-TABLE.md)
- [Performance scope and historical 74.778 ms caveat](drafts/PERFORMANCE-SCOPE-NOTES.md)
- [Current-interface comparison, audited 2026-08-31](drafts/CURRENT-INTERFACE-COMPARISON.md)
- [Shadow-mode and limitations notes](drafts/SHADOW-AND-LIMITATIONS-NOTES.md)

## What was measured

| Evidence | Outcome | Honest scope |
|---|---|---|
| Full regression before new harnesses | 794 passed, 3 skipped in 78.30 s | Updated upstream `main` |
| Final CI-equivalent regression with all new harness tests | 868 passed, 1 skipped, 2 E2E tests deselected in 104.22 s | Windows, CPython 3.14.0; `-m "not e2e"` |
| Three-host Linux partition and central baseline | Four placement/workload scenarios passed; 89/89 independent checks passed; each exercised normal, symmetric s1↔s2 application-gate, and recovery phases; every scenario conserved its 30-unit envelope and completed a post-heal transfer | Three separately booted Linux SSH endpoints with distinct address, SSH-key, and boot-identity hashes; peer bytes used a controller relay over two SSH sessions; development/unanchored executors; small deterministic single runs, not performance statistics or proof of physical/failure-domain independence |
| Pinned native-Linux current-composition final dispatch | 20,000 measured operations after 2,000 warmups; pooled off p50/p95/p99 0.008558/0.015688/0.026794 ms; enforce 34.096067/40.160652/45.904426 ms; enforce mean 34.563711 ms and sequential measured-path rate 28.932 ops/s | Clean pinned AstralDeep/AstralPlane/LETS composition on CPython 3.12.3/Linux; deterministic in-memory Plane/host adapters, real durable LETS warden and executor path; replacement evidence, not a reproduction of the missing historical artifact |
| Logical-site partition and skew | Six LETS/central runs passed; 1,800 retained request events | Three independent warden DBs and three independent executor DBs, but one process and one physical host |
| Native durable-core performance | 10,000 raw operations; 200 trials; 100 aggregate cells; no failed or unhealthy enforce trials | Two local NVMe/NTFS devices on one Windows host; not the AstralDeep final-dispatch path |
| Resource vector | All 11 declared checks passed; final per-dimension conservation `(40,60)` | Two wardens in one process with separate durable stores |
| Lineage scaling | 30 runnable tree cells passed and reopened cleanly; two explosive complete trees explicitly skipped by node cap | Depths 1/2/4/8, branching 1/2/4/8; sibling work contends on one SQLite warden |
| Formal frontier | 101,245 states and 318,558 expanded transitions; no violation within the bound | Depth-9 cutoff, not exhaustive; 69,492 unseen successors exist beyond it |
| Mutation sensitivity | All seven scalar mutants killed at shortest depths 1–5 | Bounded scalar abstraction |
| Two-dimensional model | 8,348 states and 18,468 transitions; frontier exhausted; vector mutant killed at depth 2 | Finite two-warden model with costs `(1,0)`, `(0,3)`, and `(1,5)` |
| Rollback/clone matrix | 10 passed, 0 failed | Local process/file anchors; stale-anchor replacement remains an infrastructure assumption |
| Docker acceptance | Real three-node fault/recovery/conservation scenario passed; production mTLS profile skipped | Three containers/processes inside one Docker VM on one physical host |
| Implementation inventory | 34 runtime files / 28,573 physical lines; narrow 18-file core / 16,169 physical lines; 8/8 facts verified | Source-derived counts, not a manual estimate |

The current Docker evidence is in `results/generated/docker-acceptance.json` and
`results/generated/scenario-evidence.json`. That older generated-results tree
also contains historical artifacts; only those two named files and
`docker-compose.log` were regenerated by this run.

## Review-item disposition

“Ready” means the result or drafting material exists. It does not mean the
submission was edited.

| Review item | Disposition | Evidence or remaining boundary |
|---:|---|---|
| 1. Independent-host partition plus central baseline | **Resolved within the tested development scope** | Four full-factorial scenarios ran wardens and executor stores on three separately booted Linux SSH endpoints and compared LETS with a durable centralized counter on s2 through normal, symmetric application-gate, and recovery phases. Distinct hashes establish distinct endpoints and boot identities, not physical-machine, power, rack, or failure-domain independence. Transport was a controller relay over two SSH sessions, not a direct host-to-host route, and executors used unanchored development mode. The larger same-host workload remains a separate companion result. |
| 2. Replace or diagnose 74.778 ms | **Resolved as a pinned replacement and decomposition** | A clean, pinned current AstralDeep/AstralPlane/LETS composition ran the integrated final-dispatch path on native Linux for 10,000 operations per mode. The retained exclusive spans localize the current 34.563711 ms enforce mean, including a 14.53% first-to-last-quartile within-run drift whose net increase was 93.16% in the non-signing Warden transaction boundary. The original `20260826T231656Z` artifact and exact driver remain unavailable, and SQLite differs, so 74.778 ms was not reproduced or completely explained. The Windows durable-core matrix remains separate evidence. |
| 3. Explicit properties and lemmas | **Ready as drafting material** | Formal assumptions, three lemmas, a per-dimension conservation theorem, spendable bound, transition semantics, and implementation mapping are in `drafts/`. |
| 4. Vectors and recursive scaling | **Ready** | Runtime and a separate bounded model cover two dimensions, heterogeneous and multi-dimension costs, attenuation, transfer, claims, and a vector-accounting mutant. The lineage grid measures spawn/auth latency, size, reopen, throughput, and conservation. |
| 5. Debit versus claim semantics | **Ready as drafting material and runtime evidence** | Terminology, equations, crash table, and an expired unclaimed receipt that remains debited are retained. |
| 6. Conditional connectivity guarantee | **Ready as drafting material** | The guarantee is conditioned on reachability of the owning warden and protected executor plus sufficient local authority. |
| 7. Transfer diagram and failure matrix | **Mostly ready** | A sequence, durability points, retry/failure matrix, runtime transfer, and Docker transfer/fault scenario exist. AstralDeep itself still does not invoke cross-warden transfer. |
| 8. Rollback and clone protection | **Mostly ready** | Direct stale-DB, clone-race, executor-restore, lost-response, recovery-bundle, and process-lock tests passed. Joint/stale anchor rollback remains outside the tested fault model. |
| 9. Concrete implementation section | **Ready as drafting material** | Source-backed component/atomicity/trust table, algorithms, storage semantics, clock handling, replica caveat, and LOC inventory are retained. |
| 10. Shadow mode | **Analysis and recommendation only** | Current behavior is verified as state-changing, no-claim, and fail-open at the host. No runtime semantics were changed. The note recommends disposable test use and a separate non-production envelope for production-like observation. |
| 11. Model sensitivity and frontier | **Ready** | Seven mutants, shortest traces, depth histogram, cutoff probe, and source digests are retained. |
| 12. Compress interface comparison | **Ready as drafting material** | A compact table was refreshed from 18 first-party links on 2026-08-31 using cautious “not documented” wording. |
| 13. Limitations cleanup | **Ready as drafting material** | A three-part outline and corrected TLC wording are supplied; the paper remains untouched. |

## Important non-results

The following claims are not supported by this bundle:

- physical-machine, power, rack, or failure-domain independence for the three
  Linux SSH endpoints;
- a firewall/physical partition, direct host-to-host route, or WAN latency
  experiment (peer bytes traversed a controller relay over two SSH sessions);
- production rollback protection for the three-host development run;
- a reproduction or complete causal decomposition of the historical 74.778 ms
  AstralDeep/WSL2 result; the original artifact and exact driver remain absent;
- a production rollback anchor in a failure domain independent of this host;
- Byzantine wardens, keys, clocks, or anchors;
- physical exactly-once completion of protected external effects;
- an implementation change to shadow mode;
- an edit to the ArXiv or NSDI manuscript.

Those boundaries should remain visible anywhere these results are cited.
