# LETS three-endpoint development experiment

- **Result:** `passed`
- **Run:** `run-20260903-013357-d114b8f9`
- **Tracked source commit:** `ca6baef43541197d3b812c9f05ebe2e3494d49d0`

> Scope: three distinct SSH endpoints with distinct Linux boot identities, one real LETS SQLite warden, and one separate local SQLite executor claim store per endpoint. This does not prove physical-machine, power, rack, or failure-domain independence. Peer bytes traversed a controller relay over two SSH sessions, so this is not a direct endpoint-to-endpoint route or WAN latency measurement.

## Reproducibility and safety

- Remote write boundary: authenticated normalized home only.
- Pinned Python: `3.12.3`; pinned uv: `0.11.21`.
- Source archive SHA-256: `8d4e4c5bf8f873e8a5d941b7a3d98bc2cfac5f6764a3323f46d95c5d933d8614`.
- Harness SHA-256: `d87fcb402e34f3f0322290768028807774a920b0561529042e798ee2e8887a1e`.
- Rerun: `python -m benchmarks.nsdi_strengthening.remote_three_host --credentials <credential-file> --inventory <inventory.json> --overwrite`.
- No sudo, Docker, system package mutation, credential retention, raw address retention, or raw username retention.

## Endpoint and transport evidence

- Distinct address fingerprints: **3**.
- Distinct SSH host keys: **3**.
- Distinct Linux boot IDs: **3**.
- Peer transport: controller-mediated byte relay over two Paramiko SSH sessions; not a direct endpoint-to-endpoint route or WAN measurement.
- Inter-warden authentication: HMAC-SHA256 over method, path, timestamp, nonce, body digest, and source alias; the shared key was never sent on the peer path.

## Partitioned local progress

| Initial placement | Demand | Partitioned wardens | Central counter | Post-heal transfer |
|---|---|---:|---:|---|
| Equal | Equal | 18/0 | 15/3 | s2→s1, 1 |
| Equal | 70% at s1 | 19/1 | 13/7 | s2→s1, 3 |
| 70% at s1 | Equal | 16/2 | 15/3 | s1→s2, 2 |
| 70% at s1 | 70% at s1 | 20/0 | 13/7 | s2→s1, 1 |

Every row conserved its 30-unit envelope.
Each operation cost one unit, so warden debit equaled the authorized count in every row.

Each fixed schedule includes pre-gate, symmetric s1↔s2 application-path gate, and recovery phases. Raw events contain cumulative authorized/denied counts, remaining local actions, phase snapshots, authority stranded on the blocked counterpart, and the same operation schedule against a durable centralized SQLite counter on s2.

The executor claim stores deliberately used LETS's explicit unanchored development mode. The result demonstrates separately hosted durable state and executors, but does not claim production rollback protection, firewall-level partitioning, direct WAN transport, or physical failure-domain independence.
