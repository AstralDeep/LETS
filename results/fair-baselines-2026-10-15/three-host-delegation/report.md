# E1 grid report

## three-host-delegation: completion at 0.7x load, theta=1

| System | split-s1 | bridge-s3 | full-isolation | flapping-s1-s2 | t_auth p50 (ms) | Stranded unit-s (split-s1) |
|---|---|---|---|---|---|---|
| LETS | 0.99 | 1.00 | 1.00 | 1.00 | 28 | 16 |
| LETS, delegation tree (depth 2, fanout 2) | 0.99 | 1.00 | 1.00 | 1.00 | 29 | 15 |
| Static per-site quotas | 0.90 | 0.93 | 0.90 | 0.87 | 5.1 | 3 |
| Central counter, no retry | 0.70 | 0.70 | 0.56 | 0.88 | 6.0 | 264 |
| Central counter, retry | 0.89 to 0.90 | 0.88 to 1.00 | 0.86 to 0.93 | 1.00 | 6 to 47 | 612 to 652 |
| Raft quorum counter | 0.81 | 1.00 | 0.67 | 1.00 | 230 | 632 |

Completion is authorized requests divided by all requests, pooled over the seeds of each cell; the latency column is the median over authorized requests that arrived in the first 5 s of every run in the grid; stranded unit-seconds are the mean over seeds. Safety: 3840 run-system pairs, maximum authorized 30 of 30 units, every safety check passed, effects equal authorized counts.

### Lease-tree costs

| System | Leases per site tree | Lease ops / run | Refreshes / run | Ops / refresh | Refresh p50 / p95 (ms) |
|---|---:|---:|---:|---:|---|
| lets | 1.0 | 10.2 | 3.67 | 2.0 | 22.3 / 67.7 |
| lets-tree-d2-f2 | 7.0 | 58.0 | 3.73 | 9.9 | 113.8 / 340.1 |

A refresh closes every live lease of a site's tree and rebuilds it from the refreshed root; lease operations are issue, spawn, and close calls, and the times are measured at the site over the runs at this load and skew.

### 95% seed-bootstrap intervals

| Topology | System | Completion | CI low | CI high | Width (points) | Seeds |
|---|---|---|---|---|---|---|
| split-s1 | lets | 0.990 | 0.972 | 1.000 | 2.8 | 20 |
| split-s1 | lets-tree-d2-f2 | 0.990 | 0.972 | 1.000 | 2.8 | 20 |
| split-s1 | static-quota | 0.904 | 0.851 | 0.955 | 10.4 | 20 |
| split-s1 | central-noretry@s2 | 0.703 | 0.654 | 0.746 | 9.3 | 20 |
| split-s1 | central-retry@s1 | 0.897 | 0.867 | 0.927 | 6.0 | 20 |
| split-s1 | central-retry@s2 | 0.894 | 0.866 | 0.920 | 5.4 | 20 |
| split-s1 | central-retry@s3 | 0.892 | 0.863 | 0.916 | 5.3 | 20 |
| split-s1 | raft-quorum | 0.813 | 0.771 | 0.853 | 8.2 | 20 |
| bridge-s3 | lets | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| bridge-s3 | lets-tree-d2-f2 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| bridge-s3 | static-quota | 0.932 | 0.886 | 0.973 | 8.6 | 20 |
| bridge-s3 | central-noretry@s2 | 0.695 | 0.652 | 0.743 | 9.1 | 20 |
| bridge-s3 | central-retry@s1 | 0.945 | 0.927 | 0.964 | 3.7 | 20 |
| bridge-s3 | central-retry@s2 | 0.880 | 0.850 | 0.910 | 6.0 | 20 |
| bridge-s3 | central-retry@s3 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| bridge-s3 | raft-quorum | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| full-isolation | lets | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| full-isolation | lets-tree-d2-f2 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| full-isolation | static-quota | 0.904 | 0.856 | 0.946 | 9.0 | 20 |
| full-isolation | central-noretry@s2 | 0.564 | 0.503 | 0.621 | 11.8 | 20 |
| full-isolation | central-retry@s1 | 0.926 | 0.901 | 0.950 | 5.0 | 20 |
| full-isolation | central-retry@s2 | 0.862 | 0.830 | 0.893 | 6.3 | 20 |
| full-isolation | central-retry@s3 | 0.862 | 0.825 | 0.893 | 6.9 | 20 |
| full-isolation | raft-quorum | 0.675 | 0.628 | 0.720 | 9.2 | 20 |
| flapping-s1-s2 | lets | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | lets-tree-d2-f2 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | static-quota | 0.869 | 0.815 | 0.927 | 11.1 | 20 |
| flapping-s1-s2 | central-noretry@s2 | 0.877 | 0.843 | 0.910 | 6.7 | 20 |
| flapping-s1-s2 | central-retry@s1 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | central-retry@s2 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | central-retry@s3 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | raft-quorum | 1.000 | 1.000 | 1.000 | 0.0 | 20 |

## Widest completion intervals

- baselines: 11.8 percentage points (three-host-delegation, full-isolation, central-noretry@s2)
- lets: 2.8 percentage points (three-host-delegation, split-s1, lets)
- lets-tree: 2.8 percentage points (three-host-delegation, split-s1, lets-tree-d2-f2)
