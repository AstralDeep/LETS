# E1 grid report

## local-delegation: completion at 0.7x load, theta=1

| System | split-s1 | full-isolation | t_auth p50 (ms) | Stranded unit-s (split-s1) |
|---|---|---|---|---|
| LETS | 0.93 | 1.00 | 15 | 55 |
| LETS, delegation tree (depth 2, fanout 2) | 0.93 | 1.00 | 16 | 55 |

Completion is authorized requests divided by all requests, pooled over the seeds of each cell; the latency column is the median over authorized requests that arrived in the first 5 s of every run in the grid; stranded unit-seconds are the mean over seeds. Safety: 16 run-system pairs, maximum authorized 30 of 30 units, every safety check passed, effects equal authorized counts.

### Lease-tree costs

| System | Leases per site tree | Lease ops / run | Refreshes / run | Ops / refresh | Refresh p50 / p95 (ms) |
|---|---:|---:|---:|---:|---|
| lets | 1.0 | 8.5 | 3.00 | 1.8 | 8.6 / 27.0 |
| lets-tree-d2-f2 | 7.0 | 51.5 | 3.00 | 10.2 | 49.8 / 79.3 |

A refresh closes every live lease of a site's tree and rebuilds it from the refreshed root; lease operations are issue, spawn, and close calls, and the times are measured at the site over the runs at this load and skew.

### 95% seed-bootstrap intervals

| Topology | System | Completion | CI low | CI high | Width (points) | Seeds |
|---|---|---|---|---|---|---|
| split-s1 | lets | 0.931 | 0.882 | 1.000 | 11.8 | 2 |
| split-s1 | lets-tree-d2-f2 | 0.931 | 0.882 | 1.000 | 11.8 | 2 |
| full-isolation | lets | 1.000 | 1.000 | 1.000 | 0.0 | 2 |
| full-isolation | lets-tree-d2-f2 | 1.000 | 1.000 | 1.000 | 0.0 | 2 |

## Widest completion intervals

- lets: 11.8 percentage points (local-delegation, split-s1, lets)
- lets-tree: 11.8 percentage points (local-delegation, split-s1, lets-tree-d2-f2)
