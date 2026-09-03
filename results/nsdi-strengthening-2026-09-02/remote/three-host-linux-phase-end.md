# LETS three-endpoint per-site phase endpoints

Counts are cumulative for each site at each phase boundary. `A/D/R/S` means authorized, denied, local actions remaining, and authority stranded on the blocked peer.

| Initial placement | Demand | Site | Initial authority | Pre-gate A/D/R/S | Application-path gate A/D/R/S | Recovery A/D/R/S | Central counter A/D | Post-heal transfer |
|---|---|---|---:|---:|---:|---:|---:|---|
| Equal | Equal | s1 | 10 | 2/0/8/0 | 5/0/5/5 | 6/0/5/0 | 3/3 | s2→s1, 1 |
| Equal | Equal | s2 | 10 | 2/0/8/0 | 5/0/5/5 | 6/0/3/0 | 6/0 | s2→s1, 1 |
| Equal | Equal | s3 | 10 | 2/0/8/0 | 5/0/5/0 | 6/0/4/0 | 6/0 | s2→s1, 1 |
| Equal | 70% at s1 | s1 | 10 | 4/0/6/0 | 10/1/0/8 | 13/1/0/0 | 7/7 | s2→s1, 3 |
| Equal | 70% at s1 | s2 | 10 | 1/0/9/0 | 2/0/8/0 | 3/0/4/0 | 3/0 | s2→s1, 3 |
| Equal | 70% at s1 | s3 | 10 | 1/0/9/0 | 2/0/8/0 | 3/0/7/0 | 3/0 | s2→s1, 3 |
| 70% at s1 | Equal | s1 | 21 | 2/0/19/0 | 5/0/16/0 | 6/0/13/0 | 3/3 | s1→s2, 2 |
| 70% at s1 | Equal | s2 | 4 | 2/0/2/0 | 4/1/0/16 | 5/1/1/0 | 6/0 | s1→s2, 2 |
| 70% at s1 | Equal | s3 | 5 | 2/0/3/0 | 5/0/0/0 | 5/1/0/0 | 6/0 | s1→s2, 2 |
| 70% at s1 | 70% at s1 | s1 | 21 | 4/0/17/0 | 11/0/10/2 | 14/0/8/0 | 7/7 | s2→s1, 1 |
| 70% at s1 | 70% at s1 | s2 | 4 | 1/0/3/0 | 2/0/2/10 | 3/0/0/0 | 3/0 | s2→s1, 1 |
| 70% at s1 | 70% at s1 | s3 | 5 | 1/0/4/0 | 2/0/3/0 | 3/0/2/0 | 3/0 | s2→s1, 1 |

The application-path gate is symmetric between s1 and s2. Stranded authority is therefore zero for s3 and outside that phase. The central-counter counts use the same per-operation site/phase schedule as the partitioned wardens.
