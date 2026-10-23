# Lineage depth and branching results

All 16 depth/fanout combinations use the disclosed spine-and-fanout shape. Complete trees are also run when their calculated node count is at most the configured cap; larger cells are explicitly skipped.

| Shape | Depth | Branch | Nodes | Leaves/actions | Spawn p50 (ms) | Auth p50 (ms) | Auth p95 (ms) | Throughput (ops/s) | DB after checkpoint (KiB) | Reopen (ms) | Status |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| spine_fanout | 1 | 1 | 2 | 1 | 6.500 | 6.775 | 6.775 | 135.6 | 308.0 | 58.004 | passed |
| complete_tree | 1 | 1 | 2 | 1 | 6.433 | 6.572 | 6.572 | 146.5 | 308.0 | 7.297 | passed |
| spine_fanout | 1 | 2 | 3 | 2 | 6.426 | 9.704 | 12.844 | 151.3 | 336.0 | 7.238 | passed |
| complete_tree | 1 | 2 | 3 | 2 | 6.335 | 9.959 | 13.110 | 148.2 | 336.0 | 7.133 | passed |
| spine_fanout | 1 | 4 | 5 | 4 | 6.329 | 15.997 | 25.672 | 151.0 | 372.0 | 7.116 | passed |
| complete_tree | 1 | 4 | 5 | 4 | 6.290 | 16.033 | 25.738 | 150.8 | 372.0 | 7.170 | passed |
| spine_fanout | 1 | 8 | 9 | 8 | 6.408 | 29.823 | 52.856 | 146.8 | 440.0 | 7.195 | passed |
| complete_tree | 1 | 8 | 9 | 8 | 6.380 | 29.558 | 53.040 | 146.3 | 440.0 | 7.219 | passed |
| spine_fanout | 2 | 1 | 3 | 1 | 6.296 | 6.465 | 6.465 | 150.3 | 320.0 | 7.205 | passed |
| complete_tree | 2 | 1 | 3 | 1 | 6.433 | 6.417 | 6.417 | 151.7 | 320.0 | 7.173 | passed |
| spine_fanout | 2 | 2 | 5 | 3 | 6.286 | 12.736 | 19.050 | 152.8 | 352.0 | 7.496 | passed |
| complete_tree | 2 | 2 | 7 | 4 | 6.375 | 16.513 | 26.123 | 148.6 | 392.0 | 7.247 | passed |
| spine_fanout | 2 | 4 | 9 | 7 | 6.357 | 26.018 | 45.129 | 150.3 | 428.0 | 7.794 | passed |
| complete_tree | 2 | 4 | 21 | 16 | 6.551 | 56.789 | 106.712 | 145.5 | 628.0 | 7.337 | passed |
| spine_fanout | 2 | 8 | 17 | 15 | 6.575 | 53.478 | 100.477 | 144.8 | 580.0 | 7.968 | passed |
| complete_tree | 2 | 8 | 73 | 64 | 6.670 | 114.293 | 116.305 | 139.6 | 1628.0 | 8.533 | passed |
| spine_fanout | 4 | 1 | 5 | 1 | 6.441 | 6.626 | 6.626 | 146.4 | 336.0 | 7.836 | passed |
| complete_tree | 4 | 1 | 5 | 1 | 6.444 | 6.597 | 6.597 | 147.4 | 336.0 | 7.764 | passed |
| spine_fanout | 4 | 2 | 9 | 5 | 6.399 | 19.547 | 32.363 | 149.6 | 412.0 | 7.833 | passed |
| complete_tree | 4 | 2 | 31 | 16 | 6.529 | 56.540 | 105.690 | 146.9 | 704.0 | 7.415 | passed |
| spine_fanout | 4 | 4 | 17 | 13 | 6.505 | 46.058 | 85.164 | 148.1 | 560.0 | 8.106 | passed |
| complete_tree | 4 | 4 | 341 | 256 | 6.907 | 128.336 | 151.184 | 123.1 | 6036.0 | 10.832 | passed |
| spine_fanout | 4 | 8 | 33 | 29 | 6.606 | 103.183 | 112.716 | 141.8 | 884.0 | 7.922 | passed |
| complete_tree | 4 | 8 | 4681 | 4096 | 7.091 | 302.636 | 469.741 | 52.7 | 85840.0 | 65.101 | passed |
| spine_fanout | 8 | 1 | 9 | 1 | 6.456 | 6.855 | 6.855 | 141.2 | 372.0 | 7.080 | passed |
| complete_tree | 8 | 1 | 9 | 1 | 6.436 | 6.538 | 6.538 | 148.2 | 372.0 | 7.247 | passed |
| spine_fanout | 8 | 2 | 17 | 9 | 6.499 | 32.484 | 58.379 | 149.2 | 516.0 | 7.288 | passed |
| complete_tree | 8 | 2 | 511 | 256 | 6.989 | 124.069 | 134.369 | 127.7 | 7552.0 | 10.895 | passed |
| spine_fanout | 8 | 4 | 33 | 25 | 6.570 | 88.007 | 111.225 | 143.6 | 840.0 | 8.152 | passed |
| complete_tree | 8 | 4 | 87381 | 65536 | — | — | — | — | — | — | skipped_node_cap |
| spine_fanout | 8 | 8 | 65 | 57 | 6.741 | 113.425 | 115.301 | 140.1 | 1480.0 | 8.075 | passed |
| complete_tree | 8 | 8 | 19173961 | 16777216 | — | — | — | — | — | — | skipped_node_cap |

## Runtime lineage-depth boundary

A chain at depth 64 was accepted; depth 65 was rejected with `policy_denied`.
