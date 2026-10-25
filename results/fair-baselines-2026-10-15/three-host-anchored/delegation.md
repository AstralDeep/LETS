# E1 fair-baseline family: per-site results: lease-tree build costs

Lease-tree build costs per cell and LETS system, from the `tree_build` events. A build is the issue of a site's root lease plus the spawn of every child down to the leaves; a refresh is the close of every live lease in the tree followed by a new build, which is how an exhausted tree takes up transferred budget (`in-*`) or releases units for an outgoing transfer (`out-*`). Lease operations count issue, spawn, and close calls to the warden; times are wall-clock at the site. A depth of 0 is the one-lease system.

| Topology | Load | θ | System | Depth | Fanout | Runs | Leases / tree | Leaves / tree | Initial ops / site | Initial p50 (ms) | Refreshes / run | Ops / refresh | Refresh p50 / p95 / max (ms) | Lease ops / run | Build ms / run |
|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|
| bridge-s3 | 0.7 | 1 | lets | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 9.0 | 2.60 | 1.9 | 23.1 / 57.2 / 73.2 | 8.1 | 108.3 |
| bridge-s3 | 0.7 | 1 | lets-anchored | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 21.8 | 2.60 | 1.9 | 43.4 / 109.6 / 129.2 | 8.1 | 215.1 |
| bridge-s3 | 2 | 1 | lets | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 8.9 | 8.60 | 1.9 | 23.2 / 74.8 / 101.1 | 18.9 | 325.0 |
| bridge-s3 | 2 | 1 | lets-anchored | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 20.6 | 8.80 | 1.8 | 48.6 / 122.0 / 145.3 | 19.2 | 674.6 |
| flapping-s1-s2 | 0.7 | 1 | lets | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 9.1 | 5.20 | 1.9 | 22.5 / 46.3 / 87.3 | 13.1 | 175.8 |
| flapping-s1-s2 | 0.7 | 1 | lets-anchored | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 21.3 | 5.40 | 1.9 | 44.9 / 100.2 / 125.5 | 13.4 | 366.8 |
| flapping-s1-s2 | 2 | 1 | lets | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 9.0 | 13.00 | 1.9 | 23.5 / 61.5 / 87.1 | 27.4 | 436.1 |
| flapping-s1-s2 | 2 | 1 | lets-anchored | 0 | 0 | 20 | 1.0 | 1.0 | 1.0 | 21.2 | 13.00 | 1.9 | 46.0 / 115.4 / 135.6 | 27.1 | 851.0 |
