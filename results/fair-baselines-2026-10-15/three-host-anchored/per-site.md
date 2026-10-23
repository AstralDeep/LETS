# E1 fair-baseline family: per-site results

Per-site results aggregated over seeds. `A/D/T` are mean authorized, denied, and timed-out requests per run at that site; completion is the per-run fraction of the site's requests authorized by their deadline with a 95% seed-bootstrap CI; time-to-authorization quantiles are over authorized requests only (timeouts are censored, see the censored column); stranded capacity is reconstructed from free-unit and waiting events against the fault timeline; messages are application messages sent from that site per run.

| Topology | Load | θ | System | Site | Share | N/run | A/D/T per run | Completion [95% CI] | t_auth p50 / p95 (s) | Censored | Stranded peak / unit·s | Msgs/run |
|---|---:|---:|---|---|---:|---:|---:|---|---:|---:|---:|---:|
| bridge-s3 | 0.7 | 1 | lets | s1 | 10 | 10.3 | 10.3/0.0/0.0 | 1.00 [1.00, 1.00] | 0.024 / 0.536 | 0.00 | 10 / 4.6 | 2.7 |
| bridge-s3 | 0.7 | 1 | lets | s2 | 10 | 5.5 | 5.5/0.0/0.0 | 1.00 [1.00, 1.00] | 0.021 / 0.023 | 0.00 | 10 / 4.6 | 2.2 |
| bridge-s3 | 0.7 | 1 | lets | s3 | 10 | 3.4 | 3.4/0.0/0.0 | 1.00 [1.00, 1.00] | 0.065 / 0.078 | 0.00 | 10 / 4.6 | 0.6 |
| bridge-s3 | 0.7 | 1 | lets-anchored | s1 | 10 | 10.3 | 10.3/0.0/0.0 | 1.00 [1.00, 1.00] | 0.041 / 0.519 | 0.00 | 10 / 5.9 | 2.7 |
| bridge-s3 | 0.7 | 1 | lets-anchored | s2 | 10 | 5.5 | 5.5/0.0/0.0 | 1.00 [1.00, 1.00] | 0.040 / 0.043 | 0.00 | 10 / 5.9 | 2.2 |
| bridge-s3 | 0.7 | 1 | lets-anchored | s3 | 10 | 3.4 | 3.4/0.0/0.0 | 1.00 [1.00, 1.00] | 0.117 / 0.132 | 0.00 | 10 / 6.0 | 0.6 |
| bridge-s3 | 2 | 1 | lets | s1 | 10 | 32.5 | 13.9/0.0/18.6 | 0.44 [0.40, 0.47] | 0.024 / 3.594 | 0.57 | 10 / 26.0 | 147.4 |
| bridge-s3 | 2 | 1 | lets | s2 | 10 | 17.6 | 9.4/0.0/8.2 | 0.55 [0.51, 0.59] | 0.020 / 0.023 | 0.46 | 10 / 26.0 | 135.9 |
| bridge-s3 | 2 | 1 | lets | s3 | 10 | 12.8 | 6.6/0.0/6.2 | 0.53 [0.47, 0.58] | 0.065 / 0.579 | 0.49 | 10 / 26.0 | 149.2 |
| bridge-s3 | 2 | 1 | lets-anchored | s1 | 10 | 32.5 | 14.0/0.0/18.6 | 0.44 [0.41, 0.47] | 0.042 / 3.105 | 0.57 | 10 / 27.9 | 148.0 |
| bridge-s3 | 2 | 1 | lets-anchored | s2 | 10 | 17.6 | 9.4/0.0/8.2 | 0.55 [0.51, 0.60] | 0.038 / 0.043 | 0.46 | 10 / 27.9 | 136.6 |
| bridge-s3 | 2 | 1 | lets-anchored | s3 | 10 | 12.8 | 6.5/0.0/6.3 | 0.53 [0.47, 0.58] | 0.116 / 0.649 | 0.49 | 10 / 27.9 | 150.7 |
| flapping-s1-s2 | 0.7 | 1 | lets | s1 | 10 | 11.6 | 11.6/0.0/0.0 | 1.00 [1.00, 1.00] | 0.026 / 0.891 | 0.00 | 9 / 5.5 | 5.6 |
| flapping-s1-s2 | 0.7 | 1 | lets | s2 | 10 | 5.3 | 5.3/0.0/0.0 | 1.00 [1.00, 1.00] | 0.021 / 0.025 | 0.00 | 9 / 5.5 | 4.3 |
| flapping-s1-s2 | 0.7 | 1 | lets | s3 | 10 | 3.8 | 3.8/0.0/0.0 | 1.00 [1.00, 1.00] | 0.066 / 0.078 | 0.00 | 9 / 5.5 | 1.7 |
| flapping-s1-s2 | 0.7 | 1 | lets-anchored | s1 | 10 | 11.6 | 11.6/0.0/0.0 | 1.00 [1.00, 1.00] | 0.046 / 0.987 | 0.00 | 10 / 6.2 | 5.8 |
| flapping-s1-s2 | 0.7 | 1 | lets-anchored | s2 | 10 | 5.3 | 5.3/0.0/0.0 | 1.00 [1.00, 1.00] | 0.039 / 0.058 | 0.00 | 10 / 6.2 | 4.5 |
| flapping-s1-s2 | 0.7 | 1 | lets-anchored | s3 | 10 | 3.8 | 3.8/0.0/0.0 | 1.00 [1.00, 1.00] | 0.119 / 0.131 | 0.00 | 10 / 6.2 | 1.7 |
| flapping-s1-s2 | 2 | 1 | lets | s1 | 10 | 31.6 | 16.1/0.0/15.6 | 0.52 [0.47, 0.57] | 0.027 / 2.759 | 0.49 | 10 / 12.1 | 155.2 |
| flapping-s1-s2 | 2 | 1 | lets | s2 | 10 | 16.6 | 8.3/0.0/8.3 | 0.51 [0.46, 0.56] | 0.021 / 0.899 | 0.50 | 10 / 12.1 | 145.7 |
| flapping-s1-s2 | 2 | 1 | lets | s3 | 10 | 9.5 | 5.7/0.0/3.9 | 0.58 [0.51, 0.64] | 0.068 / 0.301 | 0.41 | 10 / 12.1 | 147.4 |
| flapping-s1-s2 | 2 | 1 | lets-anchored | s1 | 10 | 31.6 | 16.1/0.0/15.6 | 0.52 [0.47, 0.57] | 0.046 / 3.533 | 0.49 | 10 / 13.2 | 155.6 |
| flapping-s1-s2 | 2 | 1 | lets-anchored | s2 | 10 | 16.6 | 8.3/0.0/8.3 | 0.51 [0.46, 0.56] | 0.039 / 0.973 | 0.50 | 10 / 13.2 | 145.9 |
| flapping-s1-s2 | 2 | 1 | lets-anchored | s3 | 10 | 9.5 | 5.6/0.0/3.9 | 0.58 [0.51, 0.64] | 0.116 / 0.220 | 0.41 | 10 / 13.2 | 147.2 |
