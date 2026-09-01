# Lineage depth and branching results

All 16 depth/fanout combinations use the disclosed spine-and-fanout shape. Complete trees are also run when their calculated node count is at most the configured cap; larger cells are explicitly skipped.

| Shape | Depth | Branch | Nodes | Leaves/actions | Spawn p50 (ms) | Auth p50 (ms) | Auth p95 (ms) | Throughput (ops/s) | DB after checkpoint (KiB) | Reopen (ms) | Status |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| spine_fanout | 1 | 1 | 2 | 1 | 6.754 | 7.035 | 7.035 | 131.2 | 288.0 | 29.969 | passed |
| complete_tree | 1 | 1 | 2 | 1 | 6.495 | 6.671 | 6.671 | 143.9 | 288.0 | 5.028 | passed |
| spine_fanout | 1 | 2 | 3 | 2 | 6.455 | 9.790 | 12.992 | 149.0 | 316.0 | 5.177 | passed |
| complete_tree | 1 | 2 | 3 | 2 | 6.203 | 9.626 | 12.917 | 149.7 | 316.0 | 4.940 | passed |
| spine_fanout | 1 | 4 | 5 | 4 | 6.790 | 15.995 | 25.582 | 151.6 | 352.0 | 5.542 | passed |
| complete_tree | 1 | 4 | 5 | 4 | 6.320 | 16.959 | 27.009 | 143.8 | 352.0 | 5.010 | passed |
| spine_fanout | 1 | 8 | 9 | 8 | 6.362 | 30.629 | 53.115 | 145.8 | 420.0 | 5.975 | passed |
| complete_tree | 1 | 8 | 9 | 8 | 6.506 | 29.105 | 51.463 | 150.7 | 420.0 | 5.872 | passed |
| spine_fanout | 2 | 1 | 3 | 1 | 6.360 | 6.484 | 6.484 | 149.3 | 300.0 | 5.008 | passed |
| complete_tree | 2 | 1 | 3 | 1 | 6.328 | 6.361 | 6.361 | 151.1 | 300.0 | 5.019 | passed |
| spine_fanout | 2 | 2 | 5 | 3 | 6.648 | 13.834 | 20.382 | 142.8 | 332.0 | 5.143 | passed |
| complete_tree | 2 | 2 | 7 | 4 | 6.504 | 16.782 | 26.364 | 146.7 | 372.0 | 5.127 | passed |
| spine_fanout | 2 | 4 | 9 | 7 | 6.425 | 25.753 | 44.713 | 151.7 | 408.0 | 5.075 | passed |
| complete_tree | 2 | 4 | 21 | 16 | 6.428 | 56.262 | 105.883 | 146.2 | 608.0 | 5.135 | passed |
| spine_fanout | 2 | 8 | 17 | 15 | 6.364 | 53.280 | 97.701 | 148.3 | 560.0 | 5.417 | passed |
| complete_tree | 2 | 8 | 73 | 64 | 6.526 | 116.503 | 120.523 | 137.4 | 1612.0 | 5.595 | passed |
| spine_fanout | 4 | 1 | 5 | 1 | 6.475 | 6.587 | 6.587 | 146.7 | 316.0 | 5.059 | passed |
| complete_tree | 4 | 1 | 5 | 1 | 6.827 | 6.755 | 6.755 | 143.5 | 316.0 | 5.872 | passed |
| spine_fanout | 4 | 2 | 9 | 5 | 6.611 | 19.959 | 33.274 | 144.9 | 392.0 | 5.406 | passed |
| complete_tree | 4 | 2 | 31 | 16 | 6.567 | 56.628 | 105.631 | 146.6 | 696.0 | 5.500 | passed |
| spine_fanout | 4 | 4 | 17 | 13 | 6.349 | 45.157 | 83.485 | 150.7 | 540.0 | 5.161 | passed |
| complete_tree | 4 | 4 | 341 | 256 | 6.849 | 131.422 | 140.443 | 122.6 | 6000.0 | 8.450 | passed |
| spine_fanout | 4 | 8 | 33 | 29 | 6.443 | 102.613 | 112.563 | 142.5 | 852.0 | 5.223 | passed |
| complete_tree | 4 | 8 | 4681 | 4096 | 7.092 | 305.600 | 459.392 | 52.5 | 85744.0 | 61.623 | passed |
| spine_fanout | 8 | 1 | 9 | 1 | 6.552 | 6.434 | 6.434 | 148.8 | 352.0 | 5.548 | passed |
| complete_tree | 8 | 1 | 9 | 1 | 6.557 | 7.018 | 7.018 | 137.6 | 352.0 | 5.065 | passed |
| spine_fanout | 8 | 2 | 17 | 9 | 6.568 | 34.896 | 61.491 | 141.6 | 496.0 | 5.137 | passed |
| complete_tree | 8 | 2 | 511 | 256 | 7.043 | 127.522 | 137.145 | 121.8 | 7508.0 | 8.502 | passed |
| spine_fanout | 8 | 4 | 33 | 25 | 6.689 | 89.347 | 111.409 | 143.5 | 824.0 | 5.394 | passed |
| complete_tree | 8 | 4 | 87381 | 65536 | — | — | — | — | — | — | skipped_node_cap |
| spine_fanout | 8 | 8 | 65 | 57 | 6.811 | 116.011 | 119.412 | 136.0 | 1468.0 | 5.356 | passed |
| complete_tree | 8 | 8 | 19173961 | 16777216 | — | — | — | — | — | — | skipped_node_cap |

## Runtime lineage-depth boundary

A chain at depth 64 was accepted; depth 65 was rejected with `policy_denied`.
