# LETS three-host per-site phase endpoints

Counts are cumulative at each phase endpoint. `A/D/R/S` means LETS authorized, LETS denied, local actions remaining, and authority stranded on the blocked peer.

| Placement | Workload | Site | Share | Normal A/D/R/S | Partition A/D/R/S | Recovery A/D/R/S | Central A/D | Post-heal transfer |
|---|---|---:|---:|---:|---:|---:|---:|---|
| equal | equal | s1 | 10 | 2/0/8/0 | 5/0/5/5 | 6/0/5/0 | 3/3 | s2→s1 (1) |
| equal | equal | s2 | 10 | 2/0/8/0 | 5/0/5/5 | 6/0/3/0 | 6/0 | s2→s1 (1) |
| equal | equal | s3 | 10 | 2/0/8/0 | 5/0/5/0 | 6/0/4/0 | 6/0 | s2→s1 (1) |
| equal | 70-percent-s1 | s1 | 10 | 4/0/6/0 | 10/1/0/8 | 13/1/0/0 | 7/7 | s2→s1 (3) |
| equal | 70-percent-s1 | s2 | 10 | 1/0/9/0 | 2/0/8/0 | 3/0/4/0 | 3/0 | s2→s1 (3) |
| equal | 70-percent-s1 | s3 | 10 | 1/0/9/0 | 2/0/8/0 | 3/0/7/0 | 3/0 | s2→s1 (3) |
| 70-percent-s1 | equal | s1 | 21 | 2/0/19/0 | 5/0/16/0 | 6/0/13/0 | 3/3 | s1→s2 (2) |
| 70-percent-s1 | equal | s2 | 4 | 2/0/2/0 | 4/1/0/16 | 5/1/1/0 | 6/0 | s1→s2 (2) |
| 70-percent-s1 | equal | s3 | 5 | 2/0/3/0 | 5/0/0/0 | 5/1/0/0 | 6/0 | s1→s2 (2) |
| 70-percent-s1 | 70-percent-s1 | s1 | 21 | 4/0/17/0 | 11/0/10/2 | 14/0/8/0 | 7/7 | s2→s1 (1) |
| 70-percent-s1 | 70-percent-s1 | s2 | 4 | 1/0/3/0 | 2/0/2/10 | 3/0/0/0 | 3/0 | s2→s1 (1) |
| 70-percent-s1 | 70-percent-s1 | s3 | 5 | 1/0/4/0 | 2/0/3/0 | 3/0/2/0 | 3/0 | s2→s1 (1) |

The partition is the symmetric s1↔s2 application-path gate. Stranded authority is therefore zero for s3 and outside the partition phase. The central counts use the identical per-operation site/phase schedule as LETS.
