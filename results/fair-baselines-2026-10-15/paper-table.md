# Partition-study numbers

## three-host: completion at 0.7x load, theta=1

| System | split-s1 | bridge-s3 | full-isolation | flapping-s1-s2 | t_auth p50 (ms) | Stranded unit-s (split-s1) |
|---|---|---|---|---|---|---|
| LETS | 0.99 | 1.00 | 1.00 | 1.00 | 18 | 14 |
| Static per-site quotas | 0.90 | 0.93 | 0.90 | 0.87 | 4.6 | 2 |
| Central counter, no retry | 0.70 | 0.69 | 0.56 | 0.86 | 5.6 | 264 |
| Central counter, retry | 0.89 to 0.90 | 0.88 to 1.00 | 0.85 to 0.93 | 1.00 | 5 to 46 | 638 to 653 |
| Raft quorum counter | 0.82 | 1.00 | 0.68 | 1.00 | 230 | 633 |

Completion is authorized requests divided by all requests, pooled over the seeds of each cell; the latency column is the median over authorized requests that arrived in the first 5 s of every run in the grid; stranded unit-seconds are the mean over seeds. Safety: 3360 run-system pairs, maximum authorized 30 of 30 units, every safety check passed, effects equal authorized counts.

### 95% seed-bootstrap intervals

| Topology | System | Completion | CI low | CI high | Width (points) | Seeds |
|---|---|---|---|---|---|---|
| split-s1 | lets | 0.990 | 0.972 | 1.000 | 2.8 | 20 |
| split-s1 | static-quota | 0.904 | 0.851 | 0.955 | 10.4 | 20 |
| split-s1 | central-noretry@s2 | 0.703 | 0.654 | 0.746 | 9.3 | 20 |
| split-s1 | central-retry@s1 | 0.897 | 0.867 | 0.926 | 5.9 | 20 |
| split-s1 | central-retry@s2 | 0.894 | 0.866 | 0.920 | 5.4 | 20 |
| split-s1 | central-retry@s3 | 0.892 | 0.863 | 0.916 | 5.3 | 20 |
| split-s1 | raft-quorum | 0.818 | 0.775 | 0.859 | 8.4 | 20 |
| bridge-s3 | lets | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| bridge-s3 | static-quota | 0.932 | 0.886 | 0.973 | 8.6 | 20 |
| bridge-s3 | central-noretry@s2 | 0.688 | 0.646 | 0.736 | 9.0 | 20 |
| bridge-s3 | central-retry@s1 | 0.945 | 0.927 | 0.964 | 3.7 | 20 |
| bridge-s3 | central-retry@s2 | 0.875 | 0.845 | 0.904 | 6.0 | 20 |
| bridge-s3 | central-retry@s3 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| bridge-s3 | raft-quorum | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| full-isolation | lets | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| full-isolation | static-quota | 0.904 | 0.856 | 0.946 | 9.0 | 20 |
| full-isolation | central-noretry@s2 | 0.559 | 0.501 | 0.615 | 11.4 | 20 |
| full-isolation | central-retry@s1 | 0.926 | 0.902 | 0.951 | 4.9 | 20 |
| full-isolation | central-retry@s2 | 0.855 | 0.823 | 0.885 | 6.2 | 20 |
| full-isolation | central-retry@s3 | 0.860 | 0.829 | 0.888 | 5.9 | 20 |
| full-isolation | raft-quorum | 0.677 | 0.636 | 0.718 | 8.2 | 20 |
| flapping-s1-s2 | lets | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | static-quota | 0.869 | 0.815 | 0.927 | 11.1 | 20 |
| flapping-s1-s2 | central-noretry@s2 | 0.857 | 0.836 | 0.881 | 4.6 | 20 |
| flapping-s1-s2 | central-retry@s1 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | central-retry@s2 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | central-retry@s3 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | raft-quorum | 1.000 | 1.000 | 1.000 | 0.0 | 20 |

## seven-site: completion at 0.7x load, theta=1

| System | isolate-s1 | isolate-s7 | halves | full-isolation | flapping-s1-s2 | t_auth p50 (ms) | Stranded unit-s (isolate-s1) |
|---|---|---|---|---|---|---|---|
| LETS | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 28 | 70 |
| Static per-site quotas | 0.83 | 0.79 | 0.83 | 0.81 | 0.80 | 5.2 | 4 |
| Central counter, no retry | 0.79 | 0.97 | 0.90 | 0.52 | 0.91 | 43 | 161 |
| Central counter, retry | 0.84 to 0.93 | 0.82 to 0.99 | 0.79 to 0.96 | 0.82 to 0.89 | 1.00 | 43 to 447 | 473 to 693 |
| Raft quorum counter | 0.89 | 0.97 | 0.93 | 0.66 | 1.00 | 295 | 483 |

Completion is authorized requests divided by all requests, pooled over the seeds of each cell; the latency column is the median over authorized requests that arrived in the first 5 s of every run in the grid; stranded unit-seconds are the mean over seeds. Safety: 4200 run-system pairs, maximum authorized 30 of 30 units, every safety check passed, effects equal authorized counts.

### 95% seed-bootstrap intervals

| Topology | System | Completion | CI low | CI high | Width (points) | Seeds |
|---|---|---|---|---|---|---|
| isolate-s1 | lets | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| isolate-s1 | static-quota | 0.826 | 0.793 | 0.861 | 6.8 | 20 |
| isolate-s1 | central-noretry@s2 | 0.791 | 0.756 | 0.824 | 6.8 | 20 |
| isolate-s1 | central-retry@s1 | 0.836 | 0.806 | 0.865 | 5.9 | 20 |
| isolate-s1 | central-retry@s4 | 0.929 | 0.902 | 0.957 | 5.5 | 20 |
| isolate-s1 | central-retry@s7 | 0.922 | 0.888 | 0.953 | 6.5 | 20 |
| isolate-s1 | raft-quorum | 0.887 | 0.851 | 0.919 | 6.8 | 20 |
| isolate-s7 | lets | 0.998 | 0.993 | 1.000 | 0.7 | 20 |
| isolate-s7 | static-quota | 0.788 | 0.743 | 0.835 | 9.2 | 20 |
| isolate-s7 | central-noretry@s2 | 0.965 | 0.949 | 0.980 | 3.2 | 20 |
| isolate-s7 | central-retry@s1 | 0.988 | 0.979 | 0.996 | 1.7 | 20 |
| isolate-s7 | central-retry@s4 | 0.988 | 0.979 | 0.996 | 1.7 | 20 |
| isolate-s7 | central-retry@s7 | 0.815 | 0.774 | 0.854 | 8.0 | 20 |
| isolate-s7 | raft-quorum | 0.972 | 0.957 | 0.986 | 2.9 | 20 |
| halves | lets | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| halves | static-quota | 0.828 | 0.776 | 0.886 | 11.0 | 20 |
| halves | central-noretry@s2 | 0.898 | 0.872 | 0.923 | 5.0 | 20 |
| halves | central-retry@s1 | 0.961 | 0.939 | 0.980 | 4.1 | 20 |
| halves | central-retry@s4 | 0.961 | 0.939 | 0.980 | 4.1 | 20 |
| halves | central-retry@s7 | 0.789 | 0.753 | 0.822 | 6.9 | 20 |
| halves | raft-quorum | 0.932 | 0.911 | 0.953 | 4.2 | 20 |
| full-isolation | lets | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| full-isolation | static-quota | 0.813 | 0.772 | 0.853 | 8.1 | 20 |
| full-isolation | central-noretry@s2 | 0.525 | 0.482 | 0.567 | 8.5 | 20 |
| full-isolation | central-retry@s1 | 0.894 | 0.862 | 0.923 | 6.1 | 20 |
| full-isolation | central-retry@s4 | 0.828 | 0.789 | 0.862 | 7.3 | 20 |
| full-isolation | central-retry@s7 | 0.820 | 0.781 | 0.855 | 7.5 | 20 |
| full-isolation | raft-quorum | 0.660 | 0.619 | 0.699 | 8.0 | 20 |
| flapping-s1-s2 | lets | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | static-quota | 0.797 | 0.742 | 0.858 | 11.7 | 20 |
| flapping-s1-s2 | central-noretry@s2 | 0.906 | 0.879 | 0.931 | 5.2 | 20 |
| flapping-s1-s2 | central-retry@s1 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | central-retry@s4 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | central-retry@s7 | 1.000 | 1.000 | 1.000 | 0.0 | 20 |
| flapping-s1-s2 | raft-quorum | 1.000 | 1.000 | 1.000 | 0.0 | 20 |

## Widest completion intervals

- baselines: 11.7 percentage points (seven-site, flapping-s1-s2, static-quota)
- lets: 2.8 percentage points (three-host, split-s1, lets)
