# E1 grid report

## three-host-anchored-restore: completion at 0.7x load, theta=1

| System | split-s1 | full-isolation | t_auth p50 (ms) | Stranded unit-s (split-s1) |
|---|---|---|---|---|
| LETS | 0.99 | 1.00 | 44 | 18 |
| LETS, rollback anchors | 0.99 | 1.00 | 70 | 22 |
| LETS, rollback anchors, stale restore | 0.65 | 0.67 | 70 | 10 |
| LETS, no anchors, stale restore | 1.00 | 1.00 | 44 | 8 |

Completion is authorized requests divided by all requests, pooled over the seeds of each cell; the latency column is the median over authorized requests that arrived in the first 5 s of every run in the grid; stranded unit-seconds are the mean over seeds. Safety: 320 run-system pairs, maximum authorized 40 of 30 units, 40 unanchored stale-restore control pairs over the envelope by design and every other safety check passed, effects equal authorized counts.

### Lease-tree costs

| System | Leases per site tree | Lease ops / run | Refreshes / run | Ops / refresh | Refresh p50 / p95 (ms) |
|---|---:|---:|---:|---:|---|
| lets | 1.0 | 9.4 | 3.30 | 2.0 | 22.9 / 56.9 |
| lets-anchored | 1.0 | 9.4 | 3.30 | 2.0 | 45.2 / 115.1 |
| lets-anchored-restore@s1 | 1.0 | 3.3 | 0.15 | 2.0 | 45.0 / 119.0 |
| lets-restore@s1 | 1.0 | 4.6 | 0.80 | 2.0 | 23.3 / 64.7 |

A refresh closes every live lease of a site's tree and rebuilds it from the refreshed root; lease operations are issue, spawn, and close calls, and the times are measured at the site over the runs at this load and skew.

### 95% seed-bootstrap intervals

| Topology | System | Completion | CI low | CI high | Width (points) | Seeds |
|---|---|---|---|---|---|---|
| split-s1 | lets | 0.990 | 0.972 | 1.000 | 2.8 | 20 |
| split-s1 | lets-anchored | 0.990 | 0.972 | 1.000 | 2.8 | 20 |
| split-s1 | lets-anchored-restore@s1 | 0.650 | 0.610 | 0.689 | 7.9 | 20 |
| split-s1 | lets-restore@s1 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| full-isolation | lets | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| full-isolation | lets-anchored | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| full-isolation | lets-anchored-restore@s1 | 0.665 | 0.623 | 0.711 | 8.9 | 20 |
| full-isolation | lets-restore@s1 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |

## Widest completion intervals

- lets: 2.8 percentage points (three-host-anchored-restore, split-s1, lets)
- lets-anchored: 2.8 percentage points (three-host-anchored-restore, split-s1, lets-anchored)
- lets-anchored-restore: 8.9 percentage points (three-host-anchored-restore, full-isolation, lets-anchored-restore@s1)
- lets-restore: 0.0 percentage points (three-host-anchored-restore, split-s1, lets-restore@s1)
