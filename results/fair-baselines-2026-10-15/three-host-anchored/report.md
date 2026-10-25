# E1 grid report

## three-host-anchored: completion at 0.7x load, theta=1

| System | bridge-s3 | flapping-s1-s2 | t_auth p50 (ms) |
|---|---|---|---|
| LETS | 1.00 | 1.00 | 24 |
| LETS, rollback anchors | 1.00 | 1.00 | 42 |

Completion is authorized requests divided by all requests, pooled over the seeds of each cell; the latency column is the median over authorized requests that arrived in the first 5 s of every run in the grid; stranded unit-seconds are the mean over seeds. Safety: 160 run-system pairs, maximum authorized 30 of 30 units, every safety check passed, effects equal authorized counts.

### Lease-tree costs

| System | Leases per site tree | Lease ops / run | Refreshes / run | Ops / refresh | Refresh p50 / p95 (ms) |
|---|---:|---:|---:|---:|---|
| lets | 1.0 | 10.6 | 3.90 | 1.9 | 22.5 / 57.2 |
| lets-anchored | 1.0 | 10.8 | 4.00 | 1.9 | 44.5 / 100.2 |

A refresh closes every live lease of a site's tree and rebuilds it from the refreshed root; lease operations are issue, spawn, and close calls, and the times are measured at the site over the runs at this load and skew.

### 95% seed-bootstrap intervals

| Topology | System | Completion | CI low | CI high | Width (points) | Seeds |
|---|---|---|---|---|---|---|
| bridge-s3 | lets | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| bridge-s3 | lets-anchored | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | lets | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | lets-anchored | 1.000 | 1.000 | 1.000 | 0.0 | 20 |

## Widest completion intervals

- lets: 0.0 percentage points (three-host-anchored, flapping-s1-s2, lets)
- lets-anchored: 0.0 percentage points (three-host-anchored, flapping-s1-s2, lets-anchored)
