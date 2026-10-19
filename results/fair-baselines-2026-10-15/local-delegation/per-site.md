# E1 delegation under partition: local grid

Per-site results aggregated over seeds. `A/D/T` are mean authorized, denied, and timed-out requests per run at that site; completion is the per-run fraction of the site's requests authorized by their deadline with a 95% seed-bootstrap CI; time-to-authorization quantiles are over authorized requests only (timeouts are censored, see the censored column); stranded capacity is reconstructed from free-unit and waiting events against the fault timeline; messages are application messages sent from that site per run.

| Topology | Load | θ | System | Site | Share | N/run | A/D/T per run | Completion [95% CI] | t_auth p50 / p95 (s) | Censored | Stranded peak / unit·s | Msgs/run |
|---|---:|---:|---|---|---:|---:|---:|---|---:|---:|---:|---:|
| full-isolation | 0.7 | 0 | lets | s1 | 10 | 4.0 | 4.0/0.0/0.0 | 1.00 [1.00, 1.00] | 0.015 / 0.017 | 0.00 | 18 / 1.8 | 0.0 |
| full-isolation | 0.7 | 0 | lets | s2 | 10 | 6.0 | 6.0/0.0/0.0 | 1.00 [1.00, 1.00] | 0.015 / 0.017 | 0.00 | 18 / 1.8 | 0.0 |
| full-isolation | 0.7 | 0 | lets | s3 | 10 | 3.5 | 3.5/0.0/0.0 | 1.00 [1.00, 1.00] | 0.016 / 0.017 | 0.00 | 18 / 1.8 | 0.0 |
| full-isolation | 0.7 | 0 | lets-tree-d2-f2 | s1 | 10 | 4.0 | 4.0/0.0/0.0 | 1.00 [1.00, 1.00] | 0.015 / 0.017 | 0.00 | 18 / 1.8 | 0.0 |
| full-isolation | 0.7 | 0 | lets-tree-d2-f2 | s2 | 10 | 6.0 | 6.0/0.0/0.0 | 1.00 [1.00, 1.00] | 0.015 / 0.017 | 0.00 | 18 / 1.8 | 0.0 |
| full-isolation | 0.7 | 0 | lets-tree-d2-f2 | s3 | 10 | 3.5 | 3.5/0.0/0.0 | 1.00 [1.00, 1.00] | 0.016 / 0.017 | 0.00 | 18 / 1.8 | 0.0 |
| full-isolation | 0.7 | 1 | lets | s1 | 10 | 9.5 | 9.5/0.0/0.0 | 1.00 [1.00, 1.00] | 0.015 / 0.522 | 0.00 | 20 / 6.2 | 1.0 |
| full-isolation | 0.7 | 1 | lets | s2 | 10 | 6.5 | 6.5/0.0/0.0 | 1.00 [1.00, 1.00] | 0.015 / 0.017 | 0.00 | 20 / 6.2 | 1.0 |
| full-isolation | 0.7 | 1 | lets | s3 | 10 | 4.5 | 4.5/0.0/0.0 | 1.00 [1.00, 1.00] | 0.016 / 0.017 | 0.00 | 20 / 6.2 | 0.0 |
| full-isolation | 0.7 | 1 | lets-tree-d2-f2 | s1 | 10 | 9.5 | 9.5/0.0/0.0 | 1.00 [1.00, 1.00] | 0.016 / 0.485 | 0.00 | 20 / 6.2 | 1.0 |
| full-isolation | 0.7 | 1 | lets-tree-d2-f2 | s2 | 10 | 6.5 | 6.5/0.0/0.0 | 1.00 [1.00, 1.00] | 0.015 / 0.017 | 0.00 | 20 / 6.2 | 1.0 |
| full-isolation | 0.7 | 1 | lets-tree-d2-f2 | s3 | 10 | 4.5 | 4.5/0.0/0.0 | 1.00 [1.00, 1.00] | 0.015 / 0.017 | 0.00 | 20 / 6.2 | 0.0 |
| split-s1 | 0.7 | 0 | lets | s1 | 10 | 9.0 | 9.0/0.0/0.0 | 1.00 [1.00, 1.00] | 0.018 / 0.497 | 0.00 | 15 / 1.2 | 1.5 |
| split-s1 | 0.7 | 0 | lets | s2 | 10 | 9.0 | 9.0/0.0/0.0 | 1.00 [1.00, 1.00] | 0.017 / 0.020 | 0.00 | 15 / 1.2 | 0.5 |
| split-s1 | 0.7 | 0 | lets | s3 | 10 | 5.5 | 5.5/0.0/0.0 | 1.00 [1.00, 1.00] | 0.019 / 0.021 | 0.00 | 15 / 1.2 | 1.0 |
| split-s1 | 0.7 | 0 | lets-tree-d2-f2 | s1 | 10 | 9.0 | 9.0/0.0/0.0 | 1.00 [1.00, 1.00] | 0.018 / 0.934 | 0.00 | 15 / 1.4 | 1.5 |
| split-s1 | 0.7 | 0 | lets-tree-d2-f2 | s2 | 10 | 9.0 | 9.0/0.0/0.0 | 1.00 [1.00, 1.00] | 0.017 / 0.020 | 0.00 | 15 / 1.4 | 0.5 |
| split-s1 | 0.7 | 0 | lets-tree-d2-f2 | s3 | 10 | 5.5 | 5.5/0.0/0.0 | 1.00 [1.00, 1.00] | 0.018 / 0.021 | 0.00 | 15 / 1.4 | 1.0 |
| split-s1 | 0.7 | 1 | lets | s1 | 10 | 14.0 | 13.0/0.0/1.0 | 0.95 [0.89, 1.00] | 0.015 / 9.485 | 0.07 | 17 / 54.6 | 38.5 |
| split-s1 | 0.7 | 1 | lets | s2 | 10 | 11.0 | 10.0/0.0/1.0 | 0.92 [0.83, 1.00] | 0.015 / 0.049 | 0.09 | 17 / 54.6 | 35.0 |
| split-s1 | 0.7 | 1 | lets | s3 | 10 | 4.0 | 4.0/0.0/0.0 | 1.00 [1.00, 1.00] | 0.016 / 0.018 | 0.00 | 17 / 54.6 | 24.5 |
| split-s1 | 0.7 | 1 | lets-tree-d2-f2 | s1 | 10 | 14.0 | 13.0/0.0/1.0 | 0.95 [0.89, 1.00] | 0.015 / 9.590 | 0.07 | 17 / 54.6 | 39.5 |
| split-s1 | 0.7 | 1 | lets-tree-d2-f2 | s2 | 10 | 11.0 | 10.0/0.0/1.0 | 0.92 [0.83, 1.00] | 0.015 / 0.048 | 0.09 | 17 / 54.6 | 35.5 |
| split-s1 | 0.7 | 1 | lets-tree-d2-f2 | s3 | 10 | 4.0 | 4.0/0.0/0.0 | 1.00 [1.00, 1.00] | 0.016 / 0.018 | 0.00 | 17 / 54.6 | 25.0 |
