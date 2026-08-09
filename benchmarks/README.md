# LETS performance evidence

Run the workload from the repository-local environment:

```powershell
.venv\Scripts\python.exe -m benchmarks.run --iterations 100 --warmup 10 `
  --profile benchmarks/results/profile.pstats
```

JSON and CSV are written below the ignored `benchmarks/results/` directory.  A
reviewed machine-specific observation may be copied to `benchmarks/baselines/`;
it is evidence from that host, not a portable performance guarantee.

Production measurements retain the runtime defaults: SQLite WAL mode,
`synchronous=FULL`, and one atomic transaction per operation.  The raw SQLite
diagnostics show the possible benefit of batching and `synchronous=NORMAL`, but
they bypass LETS validation, signatures, conservation triggers, audit records,
and protocol state.  They are deliberately marked `production_semantics=false`
and are not recommendations to weaken durability.

Latency uses `perf_counter_ns`.  Percentiles use nearest-rank samples, and the
concurrent workload reports wall-clock throughput plus per-call latency (which
includes writer-lock wait).  Network and HTTP latency are excluded from these
in-process microbenchmarks; the Docker acceptance suite covers real node
boundaries and injected partitions separately.

`profile_scaling.py` measures authorization and explicit foreign-key diagnostic
cost as durable tables grow. `profile_invariants.py` checks that frequent ledger
snapshots stay independent of lease-table cardinality. `profile_anchor.py` runs
an order-alternated A/B experiment for a lifetime SQLite keeper connection; the
keeper is implemented only inside that benchmark, so a negative result cannot
alter runtime behavior.
