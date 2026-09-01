# LETS three-host Linux development experiment

- **Result:** `passed`
- **Run:** `run-20260901-025132-bf2ef17a`
- **Tracked source commit:** `a9f4ba810e1741f93ba204eb782b6c4e3d409a03`

> Scope: three distinct SSH endpoints with distinct Linux boot identities, one real LETS SQLite warden, and one separate local SQLite executor claim store per host. This does not prove physical-machine, power, rack, or failure-domain independence. Peer bytes traversed a controller relay over two SSH sessions, so this is not a direct host-to-host route or WAN latency measurement.

## Reproducibility and safety

- Remote write boundary: authenticated normalized home only.
- Pinned Python: `3.12.3`; pinned uv: `0.11.21`.
- Source archive SHA-256: `fb9d33e83eadc1f71cd9aaf060714fe50968e7dee34ed937c4bb36fbabcd05d1`.
- Harness SHA-256: `e0d09441da6682d69d1e9fe898bc19770baf7be19a3ec5462f0eb7da70e51721`.
- Rerun: `python -m benchmarks.nsdi_strengthening.remote_three_host --credentials <credential-file> --inventory <inventory.json> --overwrite`.
- No sudo, Docker, system package mutation, credential retention, raw address retention, or raw username retention.

## Host and transport evidence

- Distinct address fingerprints: **3**.
- Distinct SSH host keys: **3**.
- Distinct Linux boot IDs: **3**.
- Peer transport: controller-mediated byte relay over two Paramiko SSH sessions; not a direct host-to-host route or WAN measurement.
- Inter-host authentication: HMAC-SHA256 over method, path, timestamp, nonce, body digest, and source alias; the shared key was never sent on the peer path.

## Full-factorial placement/workload matrix

| Placement | Workload | LETS auth/deny | Central auth/deny | Consumed | Conservation | Transfer |
|---|---|---:|---:|---:|---|---|
| equal | equal | 18/0 | 15/3 | 18 | True | s2→s1 (1) |
| equal | 70-percent-s1 | 19/1 | 13/7 | 19 | True | s2→s1 (3) |
| 70-percent-s1 | equal | 16/2 | 15/3 | 16 | True | s1→s2 (2) |
| 70-percent-s1 | 70-percent-s1 | 20/0 | 13/7 | 20 | True | s2→s1 (1) |

Each scenario includes normal, symmetric s1↔s2 application-gate, and recovery phases. Raw events contain cumulative authorized/denied counts, remaining local actions, phase snapshots, authority stranded on the blocked counterpart, and the same operation schedule against a durable centralized SQLite counter on s2.

The executor stores deliberately used LETS's explicit unanchored development mode. The result demonstrates separately hosted durable state and executors, but does not claim production rollback protection, firewall-level partitioning, direct WAN transport, or physical failure-domain independence.
