# E1 delegation under partition: local grid: lease-tree build costs

Lease-tree build costs per cell and LETS system, from the `tree_build` events. A build is the issue of a site's root lease plus the spawn of every child down to the leaves; a refresh is the close of every live lease in the tree followed by a new build, which is how an exhausted tree takes up transferred budget (`in-*`) or releases units for an outgoing transfer (`out-*`). Lease operations count issue, spawn, and close calls to the warden; times are wall-clock at the site. A depth of 0 is the one-lease system.

| Topology | Load | θ | System | Depth | Fanout | Runs | Leases / tree | Leaves / tree | Initial ops / site | Initial p50 (ms) | Refreshes / run | Ops / refresh | Refresh p50 / p95 / max (ms) | Lease ops / run | Build ms / run |
|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|
| full-isolation | 0.7 | 0 | lets | 0 | 0 | 2 | 1.0 | 1.0 | 1.0 | 3.2 | 0.00 | — | — / — / — | 3.0 | 9.8 |
| full-isolation | 0.7 | 0 | lets-tree-d2-f2 | 2 | 2 | 2 | 7.0 | 4.0 | 7.0 | 24.3 | 0.00 | — | — / — / — | 21.0 | 73.0 |
| full-isolation | 0.7 | 1 | lets | 0 | 0 | 2 | 1.0 | 1.0 | 1.0 | 3.2 | 1.00 | 2.0 | 7.6 / 27.0 / 27.0 | 5.0 | 27.2 |
| full-isolation | 0.7 | 1 | lets-tree-d2-f2 | 2 | 2 | 2 | 7.0 | 4.0 | 7.0 | 24.2 | 1.00 | 12.0 | 41.5 / 79.3 / 79.3 | 33.0 | 133.6 |
| split-s1 | 0.7 | 0 | lets | 0 | 0 | 2 | 1.0 | 1.0 | 1.0 | 4.0 | 1.00 | 2.0 | 8.0 / 27.3 / 27.3 | 5.0 | 29.7 |
| split-s1 | 0.7 | 0 | lets-tree-d2-f2 | 2 | 2 | 2 | 7.0 | 4.0 | 7.0 | 28.4 | 1.00 | 12.0 | 43.1 / 87.1 / 87.1 | 33.0 | 150.0 |
| split-s1 | 0.7 | 1 | lets | 0 | 0 | 2 | 1.0 | 1.0 | 1.0 | 3.2 | 5.00 | 1.8 | 8.6 / 20.9 / 20.9 | 12.0 | 64.1 |
| split-s1 | 0.7 | 1 | lets-tree-d2-f2 | 2 | 2 | 2 | 7.0 | 4.0 | 7.0 | 23.9 | 5.00 | 9.8 | 49.8 / 72.7 / 72.7 | 70.0 | 305.6 |
