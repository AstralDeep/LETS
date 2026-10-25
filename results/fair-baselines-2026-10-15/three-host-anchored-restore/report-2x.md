# E1 grid report

## three-host-anchored-restore: completion at 2x load, theta=1

| System | split-s1 | full-isolation | t_auth p50 (ms) | Stranded unit-s (split-s1) |
|---|---|---|---|---|
| LETS | 0.50 | 0.49 | 44 | 107 |
| LETS, rollback anchors | 0.50 | 0.49 | 70 | 107 |
| LETS, rollback anchors, stale restore | 0.49 | 0.49 | 70 | 51 |
| LETS, no anchors, stale restore | 0.60 | 0.59 | 44 | 78 |

Completion is authorized requests divided by all requests, pooled over the seeds of each cell; the latency column is the median over authorized requests that arrived in the first 5 s of every run in the grid; stranded unit-seconds are the mean over seeds. Safety: 320 run-system pairs, maximum authorized 40 of 30 units, 40 unanchored stale-restore control pairs over the envelope by design and every other safety check passed, effects equal authorized counts.

### Lease-tree costs

| System | Leases per site tree | Lease ops / run | Refreshes / run | Ops / refresh | Refresh p50 / p95 (ms) |
|---|---:|---:|---:|---:|---|
| lets | 1.0 | 12.7 | 5.45 | 1.8 | 27.0 / 91.8 |
| lets-anchored | 1.0 | 13.0 | 5.65 | 1.8 | 47.6 / 178.6 |
| lets-anchored-restore@s1 | 1.0 | 9.8 | 3.70 | 1.8 | 52.9 / 195.3 |
| lets-restore@s1 | 1.0 | 12.9 | 5.50 | 1.8 | 29.1 / 89.0 |

A refresh closes every live lease of a site's tree and rebuilds it from the refreshed root; lease operations are issue, spawn, and close calls, and the times are measured at the site over the runs at this load and skew.

### 95% seed-bootstrap intervals

| Topology | System | Completion | CI low | CI high | Width (points) | Seeds |
|---|---|---|---|---|---|---|
| split-s1 | lets | 0.497 | 0.475 | 0.522 | 4.7 | 20 |
| split-s1 | lets-anchored | 0.497 | 0.475 | 0.522 | 4.7 | 20 |
| split-s1 | lets-anchored-restore@s1 | 0.486 | 0.468 | 0.505 | 3.6 | 20 |
| split-s1 | lets-restore@s1 | 0.599 | 0.572 | 0.630 | 5.8 | 20 |
| full-isolation | lets | 0.493 | 0.468 | 0.519 | 5.1 | 20 |
| full-isolation | lets-anchored | 0.493 | 0.468 | 0.519 | 5.1 | 20 |
| full-isolation | lets-anchored-restore@s1 | 0.485 | 0.464 | 0.506 | 4.2 | 20 |
| full-isolation | lets-restore@s1 | 0.587 | 0.551 | 0.623 | 7.2 | 20 |

## Widest completion intervals

- lets: 5.1 percentage points (three-host-anchored-restore, full-isolation, lets)
- lets-anchored: 5.1 percentage points (three-host-anchored-restore, full-isolation, lets-anchored)
- lets-anchored-restore: 4.2 percentage points (three-host-anchored-restore, full-isolation, lets-anchored-restore@s1)
- lets-restore: 7.2 percentage points (three-host-anchored-restore, full-isolation, lets-restore@s1)
