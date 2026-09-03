# Lineage depth and branching results

All 16 depth/fanout combinations use the disclosed spine-and-fanout shape. Complete trees are also run when their calculated node count is at most the configured cap; larger cells are explicitly skipped.

| Shape | Depth | Branch | Nodes | Leaves/actions | Spawn p50 (ms) | Auth p50 (ms) | Auth p95 (ms) | Throughput (ops/s) | DB after checkpoint (KiB) | Reopen (ms) | Status |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| spine_fanout | 1 | 1 | 2 | 1 | 6.580 | 6.936 | 6.936 | 131.3 | 288.0 | 34.446 | passed |
| complete_tree | 1 | 1 | 2 | 1 | 6.822 | 7.052 | 7.052 | 135.2 | 288.0 | 7.594 | passed |
| spine_fanout | 1 | 2 | 3 | 2 | 6.709 | 10.481 | 13.921 | 139.2 | 316.0 | 7.658 | passed |
| complete_tree | 1 | 2 | 3 | 2 | 6.719 | 10.423 | 13.703 | 141.2 | 316.0 | 8.954 | passed |
| spine_fanout | 1 | 4 | 5 | 4 | 7.047 | 17.520 | 27.677 | 140.1 | 352.0 | 7.555 | passed |
| complete_tree | 1 | 4 | 5 | 4 | 7.006 | 18.439 | 28.963 | 132.9 | 352.0 | 7.943 | passed |
| spine_fanout | 1 | 8 | 9 | 8 | 7.032 | 32.600 | 58.871 | 131.6 | 420.0 | 9.291 | passed |
| complete_tree | 1 | 8 | 9 | 8 | 7.662 | 34.466 | 63.169 | 122.8 | 420.0 | 9.564 | passed |
| spine_fanout | 2 | 1 | 3 | 1 | 7.368 | 7.492 | 7.492 | 129.0 | 300.0 | 9.278 | passed |
| complete_tree | 2 | 1 | 3 | 1 | 7.599 | 7.208 | 7.208 | 134.2 | 300.0 | 8.876 | passed |
| spine_fanout | 2 | 2 | 5 | 3 | 7.563 | 14.952 | 22.136 | 131.2 | 332.0 | 8.551 | passed |
| complete_tree | 2 | 2 | 7 | 4 | 7.191 | 18.590 | 30.176 | 127.8 | 372.0 | 9.547 | passed |
| spine_fanout | 2 | 4 | 9 | 7 | 7.191 | 29.646 | 51.322 | 132.2 | 408.0 | 9.349 | passed |
| complete_tree | 2 | 4 | 21 | 16 | 7.514 | 66.385 | 120.151 | 129.0 | 608.0 | 8.326 | passed |
| spine_fanout | 2 | 8 | 17 | 15 | 6.973 | 58.942 | 115.104 | 126.4 | 560.0 | 8.164 | passed |
| complete_tree | 2 | 8 | 73 | 64 | 7.335 | 128.745 | 134.444 | 121.7 | 1608.0 | 8.273 | passed |
| spine_fanout | 4 | 1 | 5 | 1 | 6.937 | 7.062 | 7.062 | 135.5 | 316.0 | 8.166 | passed |
| complete_tree | 4 | 1 | 5 | 1 | 6.952 | 7.541 | 7.541 | 128.0 | 316.0 | 7.803 | passed |
| spine_fanout | 4 | 2 | 9 | 5 | 6.897 | 20.578 | 34.296 | 140.5 | 392.0 | 7.601 | passed |
| complete_tree | 4 | 2 | 31 | 16 | 7.102 | 61.954 | 117.178 | 132.6 | 684.0 | 7.950 | passed |
| spine_fanout | 4 | 4 | 17 | 13 | 6.899 | 50.431 | 92.930 | 135.3 | 540.0 | 8.028 | passed |
| complete_tree | 4 | 4 | 341 | 256 | 7.355 | 139.245 | 151.248 | 115.6 | 6028.0 | 10.681 | passed |
| spine_fanout | 4 | 8 | 33 | 29 | 6.804 | 105.035 | 115.525 | 138.8 | 852.0 | 7.889 | passed |
| complete_tree | 4 | 8 | 4681 | 4096 | 7.407 | 339.731 | 503.895 | 48.0 | 85800.0 | 67.583 | passed |
| spine_fanout | 8 | 1 | 9 | 1 | 6.790 | 6.819 | 6.819 | 141.6 | 352.0 | 7.763 | passed |
| complete_tree | 8 | 1 | 9 | 1 | 6.648 | 6.637 | 6.637 | 144.5 | 352.0 | 7.858 | passed |
| spine_fanout | 8 | 2 | 17 | 9 | 6.600 | 34.393 | 61.848 | 140.9 | 500.0 | 7.870 | passed |
| complete_tree | 8 | 2 | 511 | 256 | 7.124 | 138.325 | 146.646 | 117.9 | 7500.0 | 11.402 | passed |
| spine_fanout | 8 | 4 | 33 | 25 | 6.814 | 91.050 | 114.944 | 138.7 | 820.0 | 7.879 | passed |
| complete_tree | 8 | 4 | 87381 | 65536 | — | — | — | — | — | — | skipped_node_cap |
| spine_fanout | 8 | 8 | 65 | 57 | 6.924 | 118.286 | 121.393 | 135.3 | 1472.0 | 8.185 | passed |
| complete_tree | 8 | 8 | 19173961 | 16777216 | — | — | — | — | — | — | skipped_node_cap |

## Runtime lineage-depth boundary

A chain at depth 64 was accepted; depth 65 was rejected with `policy_denied`.
