# E1 grid report

## three-host-delegation: completion at 2x load, theta=1

| System | split-s1 | bridge-s3 | full-isolation | flapping-s1-s2 | t_auth p50 (ms) | Stranded unit-s (split-s1) |
|---|---|---|---|---|---|---|
| LETS | 0.50 | 0.48 | 0.49 | 0.52 | 28 | 106 |
| LETS, delegation tree (depth 2, fanout 2) | 0.50 | 0.48 | 0.49 | 0.52 | 29 | 105 |
| Static per-site quotas | 0.48 | 0.47 | 0.48 | 0.50 | 5.1 | 3 |
| Central counter, no retry | 0.50 | 0.48 | 0.49 | 0.52 | 6.0 | 341 |
| Central counter, retry | 0.50 | 0.48 | 0.49 | 0.52 | 6 to 47 | 382 to 419 |
| Raft quorum counter | 0.42 | 0.48 | 0.27 | 0.52 | 230 | 390 |

Completion is authorized requests divided by all requests, pooled over the seeds of each cell; the latency column is the median over authorized requests that arrived in the first 5 s of every run in the grid; stranded unit-seconds are the mean over seeds. Safety: 3840 run-system pairs, maximum authorized 30 of 30 units, every safety check passed, effects equal authorized counts.

### Lease-tree costs

| System | Leases per site tree | Lease ops / run | Refreshes / run | Ops / refresh | Refresh p50 / p95 (ms) |
|---|---:|---:|---:|---:|---|
| lets | 1.0 | 17.8 | 8.10 | 1.8 | 22.7 / 76.8 |
| lets-tree-d2-f2 | 7.0 | 88.2 | 7.90 | 8.5 | 106.1 / 346.3 |

A refresh closes every live lease of a site's tree and rebuilds it from the refreshed root; lease operations are issue, spawn, and close calls, and the times are measured at the site over the runs at this load and skew.

### 95% seed-bootstrap intervals

| Topology | System | Completion | CI low | CI high | Width (points) | Seeds |
|---|---|---|---|---|---|---|
| split-s1 | lets | 0.497 | 0.475 | 0.522 | 4.7 | 20 |
| split-s1 | lets-tree-d2-f2 | 0.497 | 0.475 | 0.522 | 4.7 | 20 |
| split-s1 | static-quota | 0.479 | 0.458 | 0.503 | 4.5 | 20 |
| split-s1 | central-noretry@s2 | 0.497 | 0.475 | 0.522 | 4.7 | 20 |
| split-s1 | central-retry@s1 | 0.497 | 0.475 | 0.522 | 4.7 | 20 |
| split-s1 | central-retry@s2 | 0.497 | 0.475 | 0.522 | 4.7 | 20 |
| split-s1 | central-retry@s3 | 0.497 | 0.475 | 0.522 | 4.7 | 20 |
| split-s1 | raft-quorum | 0.416 | 0.391 | 0.442 | 5.0 | 20 |
| bridge-s3 | lets | 0.476 | 0.449 | 0.506 | 5.7 | 20 |
| bridge-s3 | lets-tree-d2-f2 | 0.476 | 0.449 | 0.506 | 5.7 | 20 |
| bridge-s3 | static-quota | 0.472 | 0.447 | 0.499 | 5.2 | 20 |
| bridge-s3 | central-noretry@s2 | 0.476 | 0.449 | 0.506 | 5.7 | 20 |
| bridge-s3 | central-retry@s1 | 0.476 | 0.449 | 0.506 | 5.7 | 20 |
| bridge-s3 | central-retry@s2 | 0.476 | 0.449 | 0.506 | 5.7 | 20 |
| bridge-s3 | central-retry@s3 | 0.476 | 0.449 | 0.506 | 5.7 | 20 |
| bridge-s3 | raft-quorum | 0.476 | 0.449 | 0.506 | 5.7 | 20 |
| full-isolation | lets | 0.493 | 0.468 | 0.519 | 5.1 | 20 |
| full-isolation | lets-tree-d2-f2 | 0.493 | 0.468 | 0.519 | 5.1 | 20 |
| full-isolation | static-quota | 0.482 | 0.455 | 0.508 | 5.2 | 20 |
| full-isolation | central-noretry@s2 | 0.489 | 0.467 | 0.513 | 4.6 | 20 |
| full-isolation | central-retry@s1 | 0.493 | 0.468 | 0.519 | 5.1 | 20 |
| full-isolation | central-retry@s2 | 0.493 | 0.468 | 0.519 | 5.1 | 20 |
| full-isolation | central-retry@s3 | 0.493 | 0.467 | 0.519 | 5.1 | 20 |
| full-isolation | raft-quorum | 0.269 | 0.242 | 0.298 | 5.6 | 20 |
| flapping-s1-s2 | lets | 0.519 | 0.493 | 0.546 | 5.3 | 20 |
| flapping-s1-s2 | lets-tree-d2-f2 | 0.519 | 0.493 | 0.546 | 5.3 | 20 |
| flapping-s1-s2 | static-quota | 0.499 | 0.474 | 0.527 | 5.3 | 20 |
| flapping-s1-s2 | central-noretry@s2 | 0.519 | 0.493 | 0.546 | 5.3 | 20 |
| flapping-s1-s2 | central-retry@s1 | 0.519 | 0.493 | 0.546 | 5.3 | 20 |
| flapping-s1-s2 | central-retry@s2 | 0.519 | 0.493 | 0.546 | 5.3 | 20 |
| flapping-s1-s2 | central-retry@s3 | 0.519 | 0.493 | 0.546 | 5.3 | 20 |
| flapping-s1-s2 | raft-quorum | 0.519 | 0.493 | 0.546 | 5.3 | 20 |

## Widest completion intervals

- baselines: 5.7 percentage points (three-host-delegation, bridge-s3, raft-quorum)
- lets: 5.7 percentage points (three-host-delegation, bridge-s3, lets)
- lets-tree: 5.7 percentage points (three-host-delegation, bridge-s3, lets-tree-d2-f2)
