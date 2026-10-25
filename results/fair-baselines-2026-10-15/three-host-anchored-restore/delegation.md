# E1 fair-baseline family: per-site results: lease-tree build costs

Lease-tree build costs per cell and LETS system, from the `tree_build` events. A build is the issue of a site's root lease plus the spawn of every child down to the leaves; a refresh is the close of every live lease in the tree followed by a new build, which is how an exhausted tree takes up transferred budget (`in-*`) or releases units for an outgoing transfer (`out-*`). Lease operations count issue, spawn, and close calls to the warden; times are wall-clock at the site. A depth of 0 is the one-lease system.

| Topology | Load | θ | System | Depth | Fanout | Runs | Leases / tree | Leaves / tree | Initial ops / site | Initial p50 (ms) | Refreshes / run | Ops / refresh | Refresh p50 / p95 / max (ms) | Lease ops / run | Build ms / run |
|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|
| full-isolation | 0.7 | 1 | lets | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 8.9 | 3.60 | 2.0 | 22.3 / 42.2 / 57.9 | 10.1 | 126.5 |
| full-isolation | 0.7 | 1 | lets-anchored | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 21.0 | 3.60 | 2.0 | 44.8 / 94.2 / 145.2 | 10.1 | 257.7 |
| full-isolation | 0.7 | 1 | lets-anchored-restore@s1 | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 20.9 | 0.00 | — | — / — / — | 3.0 | 83.5 |
| full-isolation | 0.7 | 1 | lets-restore@s1 | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 8.9 | 0.50 | 2.0 | 22.1 / 27.8 / 27.8 | 4.0 | 48.2 |
| full-isolation | 2 | 1 | lets | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 9.0 | 5.20 | 1.7 | 26.1 / 91.8 / 121.4 | 12.0 | 232.4 |
| full-isolation | 2 | 1 | lets-anchored | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 21.5 | 5.00 | 1.8 | 47.2 / 204.2 / 228.9 | 11.9 | 444.6 |
| full-isolation | 2 | 1 | lets-anchored-restore@s1 | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 20.5 | 4.00 | 1.8 | 49.6 / 208.0 / 247.9 | 10.3 | 409.6 |
| full-isolation | 2 | 1 | lets-restore@s1 | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 8.9 | 5.10 | 1.8 | 25.5 / 94.1 / 112.5 | 12.1 | 234.6 |
| split-s1 | 0.7 | 1 | lets | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 9.3 | 3.00 | 1.9 | 23.2 / 67.7 / 79.0 | 8.8 | 123.4 |
| split-s1 | 0.7 | 1 | lets-anchored | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 21.2 | 3.00 | 1.9 | 45.4 / 121.9 / 144.4 | 8.8 | 241.7 |
| split-s1 | 0.7 | 1 | lets-anchored-restore@s1 | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 20.9 | 0.30 | 2.0 | 45.0 / 119.0 / 119.0 | 3.6 | 105.8 |
| split-s1 | 0.7 | 1 | lets-restore@s1 | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 9.0 | 1.10 | 2.0 | 24.9 / 64.7 / 75.5 | 5.2 | 73.6 |
| split-s1 | 2 | 1 | lets | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 9.0 | 5.70 | 1.8 | 27.8 / 91.2 / 113.1 | 13.3 | 266.7 |
| split-s1 | 2 | 1 | lets-anchored | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 20.9 | 6.30 | 1.8 | 48.1 / 165.2 / 202.8 | 14.1 | 518.8 |
| split-s1 | 2 | 1 | lets-anchored-restore@s1 | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 21.0 | 3.40 | 1.8 | 53.3 / 188.3 / 213.0 | 9.2 | 376.6 |
| split-s1 | 2 | 1 | lets-restore@s1 | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 8.8 | 5.90 | 1.8 | 30.4 / 88.0 / 113.4 | 13.8 | 270.7 |
