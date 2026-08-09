# LETS Engineering Roadmap

This file is the execution-oriented companion to `research_dossier.md`. Durations assume one primary researcher with occasional review support and an existing Python reference kernel.

## Critical path

| Milestone | Duration | Required output | Failure condition |
|---|---:|---|---|
| M0: Claim and threat-model freeze | 2 days | ADT, operation ownership table, non-claims | equivalent prior work found |
| M1: Machine-checked bounded model | 4 days | TLC/Apalache run, counterexample suite | ownership ambiguity remains |
| M2: Persistent warden service | 6 days | atomic storage, signed receipts, restart tests | conservation fails after crash |
| M3: Partition and transfer protocol | 6 days | fault proxy, sequence compaction, baseline harness | duplicate/reorder unsafe |
| M4: Branch revocation and reclamation | 4 days | epoch propagation, nested expiry, exposure measurements | descendants can outlive grant |
| M5: Sensor/edge workload | 6 days | MQTT evidence, protected executor, fault injection | workload bypasses mediation |
| M6: Baselines and ablations | 5 days | central, consensus, eventual, replica-per-agent, static tree | comparison not apples-to-apples |
| M7: Benchmark campaign | 5 days | frozen raw data, 30+ seeds, hardware provenance | primary hypotheses untested |
| M8: Paper and artifact hardening | 6 days | submission draft, one-command reproduction | independent reproduction fails |

## MVP definition

A three-warden deployment that supports recursive local spawn, protected HSM transitions, nested leases, branch revocation, expiry reclamation, idempotent free-right transfer, crash/restart, and a receipt-enforcing executor. It must preserve the exported conservation invariant under duplicate, reordered, delayed, and dropped messages.

## Publishable intermediate outputs

- **M1:** formal specification and counterexample artifact.
- **M3:** open-source distributed escrow/lineage prototype.
- **M5:** sensor-driven autonomous-systems demonstration.
- **M7:** benchmark dataset and lineage-governance workload suite.
- **M8:** AAMAS paper and extended arXiv preprint.

## Suggested repository layout

```text
lets/
  spec/                 # TLA+/Apalache and property definitions
  warden/               # persistent enforcement service
  executor/             # receipt-verifying protected effect endpoint
  clients/              # fixed, symbolic, RL, and optional LLM proposers
  protocol/             # protobuf/OpenAPI and test vectors
  workloads/
    lineage_stress/
    sensor_response/
    logistics/
  baselines/
    central/
    raft/
    eventual/
    replica_per_agent/
    tree_quota/
  experiments/
    manifests/
    fault_profiles/
    analysis/
  artifact/
    containers/
    reproduce.sh
  paper/
```

## Implementation decisions that must be explicit

1. **Atomicity boundary:** authorization debit, HSM update, receipt sequence, and audit append must commit atomically.
2. **Executor replay defense:** receipt nonce or monotonic sequence must be checked by the executor.
3. **Clock model:** specify monotonic-clock source, maximum skew assumption, and behavior when uncertainty exceeds the bound.
4. **Parent expiry:** every descendant issuance and renewal must be capped by its parent expiry.
5. **Revoked residual:** residual remains conserved but unusable until safe close/reclaim.
6. **Transfer ownership:** rights are in exactly one of source-free, in-flight, or target-free states.
7. **Transfer garbage collection:** use per-peer sequence watermarks plus a bounded gap set; do not store all historical IDs online.
8. **Subtree migration:** either implement a single-authority ownership epoch or remove migration from the evaluated claim.
9. **Audit versus safety state:** archive growth is measured separately from online enforcement state.
10. **Evidence:** evidence can satisfy a guard but never alter a lease allocation.

## Primary experiment matrix

| Dimension | Values |
|---|---|
| Wardens | 1, 3, 5, 9 |
| Active leases | 10², 10³, 10⁴, 10⁵ where feasible |
| Historical descendants | 10³ to 10⁷ generated/compacted |
| Branching factor | 1, 2, 4, 8 |
| Depth | 1, 4, 8, 16, 32 |
| Partition duration | 0, 1, 5, 20, 60, 300 s |
| Lease TTL | 1, 2, 5, 10, 20, 60, 300 s |
| Message fault | drop, duplicate, reorder, delay, burst partition |
| Reasoner | fixed policy, symbolic planner, optional RL, optional LLM |
| Evidence | valid, stale, forged, missing, conflicting |

## Required figures for the submission

1. architecture and TCB boundary;
2. lease/HSM lifecycle;
3. spawn/execute/transfer sequence;
4. safe work versus partition duration;
5. overrun versus baseline;
6. revocation exposure–availability frontier;
7. p50/p95/p99 transition latency;
8. online metadata versus active and historical population;
9. crash/recovery timeline; and
10. ablation summary.

## Artifact acceptance checklist

- clean-room deployment succeeds from documented commands;
- all random seeds and workload manifests are versioned;
- raw data are immutable and analysis is scripted;
- tests include deliberately broken implementations that trigger invariants;
- no credentials or private data are present;
- software licenses are compatible and listed;
- exact commit, container digest, hardware, OS, Python/Rust version, and dependency lockfiles are recorded;
- the paper’s numerical claims are generated from the archived result files; and
- limitations and unsupported threat classes are included in the README.
