# E1 grid report

## three-host-anchored: completion at 2x load, theta=1

| System | bridge-s3 | flapping-s1-s2 | t_auth p50 (ms) |
|---|---|---|---|
| LETS | 0.48 | 0.52 | 24 |
| LETS, rollback anchors | 0.48 | 0.52 | 42 |

Completion is authorized requests divided by all requests, pooled over the seeds of each cell; the latency column is the median over authorized requests that arrived in the first 5 s of every run in the grid; stranded unit-seconds are the mean over seeds. Safety: 160 run-system pairs, maximum authorized 30 of 30 units, every safety check passed, effects equal authorized counts.

### Lease-tree costs

| System | Leases per site tree | Lease ops / run | Refreshes / run | Ops / refresh | Refresh p50 / p95 (ms) |
|---|---:|---:|---:|---:|---|
| lets | 1.0 | 23.1 | 10.80 | 1.9 | 23.4 / 71.1 |
| lets-anchored | 1.0 | 23.2 | 10.90 | 1.9 | 46.8 / 118.4 |

A refresh closes every live lease of a site's tree and rebuilds it from the refreshed root; lease operations are issue, spawn, and close calls, and the times are measured at the site over the runs at this load and skew.

### 95% seed-bootstrap intervals

| Topology | System | Completion | CI low | CI high | Width (points) | Seeds |
|---|---|---|---|---|---|---|
| bridge-s3 | lets | 0.476 | 0.449 | 0.506 | 5.7 | 20 |
| bridge-s3 | lets-anchored | 0.476 | 0.449 | 0.506 | 5.7 | 20 |
| flapping-s1-s2 | lets | 0.519 | 0.493 | 0.546 | 5.3 | 20 |
| flapping-s1-s2 | lets-anchored | 0.519 | 0.493 | 0.546 | 5.3 | 20 |

## Widest completion intervals

- lets: 5.7 percentage points (three-host-anchored, bridge-s3, lets)
- lets-anchored: 5.7 percentage points (three-host-anchored, bridge-s3, lets-anchored)
