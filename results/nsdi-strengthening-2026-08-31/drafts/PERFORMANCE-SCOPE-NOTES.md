# Performance evidence scope notes

## Pinned native-Linux current-composition replacement

`benchmarks/nsdi_strengthening/matched_host_path.py` was run through the guarded
SSH controller on a native x86-64 Linux endpoint. The clean composition was
AstralDeep `04f04ee93718d2ff681726e2a47a2550a837612d`, AstralPlane
`4a1d990387428436041dd70d9c417e9e86000b6c`, and LETS v1.0.11
`6245189920c686353c4ced7a208d56ec266f745c`. The runtime was CPython 3.12.3
with SQLite 3.45.1. Ten trials alternated off/enforce order; each mode used 100
warmups and 1,000 measured operations per trial, for 10,000 samples per mode.

The pooled final-dispatch results were:

| Mode | p50 | p95 | p99 | Mean | Sequential measured-path rate |
|---|---:|---:|---:|---:|---:|
| Off | 0.008558 ms | 0.015688 ms | 0.026794 ms | 0.010601 ms | 94,328.342 ops/s |
| Enforce | 34.096067 ms | 40.160652 ms | 45.904426 ms | 34.563711 ms | 28.932 ops/s |

The enforce run executed the real `GovernedFinalDispatch.execute`, real SQLite
`WardenService` authorization, Ed25519 signing and canonical receipt
serialization, public receipt verification, and real SQLite executor replay
claim with a process-file anchor. Its non-overlapping exclusive spans sum to the
end-to-end interval. The largest pooled mean components were the non-signing
Warden transaction boundary (14.899959 ms), executor rollback-anchor claim and
status (9.752135 ms), executor replay transaction and status (5.756857 ms), and
host-gateway remainder (1.211425 ms). Warden signing and serialization averaged
0.395659 ms.

For an explicit temporal check, pool operations 0–249 and 750–999 from each of
the ten enforce runs. Mean end-to-end time rose from 32.278389 to 36.968199 ms,
a 4.689810 ms or 14.53% within-run increase. The non-signing Warden transaction
boundary rose by 4.368956 ms, accounting numerically for 93.16% of the net
increase; signing/serialization rose by only 0.010749 ms (0.23%). This does not
prove which behavior inside the Warden transaction boundary caused the drift.
Database growth, journal/checkpoint behavior, and storage remain candidate
mechanisms requiring a targeted follow-up.

The timed host-binding, Plane transaction, audit, and coordinator adapters were
deterministic and in memory. The runner did not include HTTP, PostgreSQL,
provider/model calls, external tool work, or process startup. The Warden was
unanchored. The executor's process-file anchor and replay database were on the
same storage device, so the run does not establish an independent production
rollback domain.

The retained output is a current-composition replacement, not the historical
artifact. Every raw sample, inclusive and derived exclusive span, span call
count, environment identity, component commit, and storage posture is in the
deterministic `remote/matched-host/matched-host-path.json.gz` archive; its
decompressed SHA-256 is recorded by the adjacent manifest together with source
hashes and the guarded read-only recovery used to retain the completed run.

## What the Windows durable-core matrix measures

`benchmarks/nsdi_strengthening/performance_matrix.py` is a native LETS durable-path
microbenchmark. It measures two paired modes against the same synthetic actuator:

- **off** invokes only the configured actuator delay;
- **enforce** first calls the real `WardenService.authorize` backed by
  `SQLiteStorage`, then calls the real `ReceiptVerifier.verify_and_claim` backed by
  `SQLiteReceiptReplayStore`, and finally invokes the same actuator delay.

The trial rig is created outside the measured interval. Each concurrent worker receives
its own root lease, while all workers in a trial share the same warden service/database
and executor replay database. This arrangement measures contention at the shared durable
authorization and claim boundaries without introducing same-lease sequence contention.
Workers are threads in one Python process, not networked clients or independent hosts.

For every measured operation, the runner retains these non-overlapping spans:

- `warden_ns`: the in-process `WardenService.authorize` call, including the durable
  SQLite authorization transaction and receipt creation;
- `claim_ns`: receipt verification and the durable executor replay-store claim;
- `application_ns`: the observed duration of the requested synthetic actuator delay;
- `unattributed_ns`: timer and call-boundary time not included in the three spans above;
- `end_to_end_ns`: the complete measured operation from immediately before authorization
  (or the off-mode actuator) through actuator return.

The experiment retains raw per-operation observations in JSON and CSV. It reports
nearest-rank p50, p95, and p99 latency, achieved operations per second, and paired
off/enforce cells across configured actuator delays, worker counts, trials, and storage
roots. The 0, 1, 10, 100, and 1,000 ms delay cells provide operational context: they show
the absolute durable authorization cost and how that cost changes the end-to-end latency
of progressively less trivial application work. Requested sleep duration is not assumed
to be exact; `application_ns` records the duration actually observed from the host OS.

Setup, policy registration, key generation, root-lease issuance, and database creation
are intentionally outside the measured interval. Warm-up activity is also excluded from
latency and throughput. Throughput covers only the concurrent measured interval, from
barrier release until the last worker finishes.

## What the Windows matrix excludes

This is not an AstralDeep integration benchmark. It does not import or execute
AstralDeep or AstralPlane, and therefore does not measure:

- Astral host binding, host-side policy selection, or final-dispatch plumbing;
- coordinator, audit, tool-routing, or application-specific bookkeeping;
- inter-process receipt handoff, RPC, serialization across a host boundary, or network
  latency;
- cross-warden transfer, a partition, multiple machines, or a wide-area deployment;
- native-Linux behavior; this evidence run is native Windows;
- multiple executor replicas sharing a remotely deployed claim service;
- a rollback authority in a failure domain independent of the SQLite stores.

The file anchors are distinct from the SQLite database files but are created below the
same ephemeral storage root. They exercise the anchor implementation and permit the
runner to report its status, but they do not establish independent rollback protection.
The experiment also does not separately time signing, canonical serialization, SQLite
commit, or anchor mutation inside `warden_ns` and `claim_ns`; those require deeper
instrumentation if an internal decomposition is needed.

The off-mode cell is a controlled baseline for the synthetic actuator and measurement
harness. It is not the historical AstralDeep “LETS off” path or the off path in the
pinned Linux replacement, because Astral host and dispatch work is absent from both
Windows matrix modes.

## Why this is not a reproduction of the 74.778 ms host result

The paper's historical final-dispatch result compared approximately 0.068 ms with LETS
off against 74.778 ms with LETS enforced, for an incremental 74.700 ms. That number came
from an integrated AstralDeep final-dispatch path under WSL2 and is associated with a
temporal shift and a compatibility-only pairing of LETS and Astral revisions.

The historical `20260826T231656Z` result directory and exact benchmark driver are not
present in the available repositories or retained artifacts. The historical environment
reported SQLite 3.53.4; the pinned native-Linux replacement used SQLite 3.45.1. It also
uses the clean current composition and deterministic in-memory host-binding, Plane,
audit, and coordinator adapters. Those differences prevent an exact replay even though
the replacement now exercises and instruments the integrated final-dispatch boundary.

The current 34.096067 ms enforce median is therefore not evidence that 74.778 ms was
“fixed,” and its difference from 74.778 ms cannot be assigned to one software component.
The defensible conclusion is narrower: the review item now has a pinned native-Linux
current-composition replacement with raw samples and a complete non-overlapping span
decomposition; the historical artifact remains unavailable and its value unreproduced.

The Windows native LETS matrix answers a separate question: how much latency and
throughput cost appears in the durable authorization-and-claim core across controlled
concurrency, actuator delay, and two local storage devices? It neither executes the
integrated host path nor recreates the historical environment. Do not pool its cells with
the native-Linux replacement or use subtraction between them for causal attribution.

## Windows two-storage-root interpretation

The runner accepts repeated `--storage-root` arguments and creates an independent
ephemeral trial directory under each root. Within one trial, the warden database,
executor database, and their separate anchor files reside on that trial's selected root.
The intended two-root run compares these two local devices:

| Root volume | Filesystem | Device | Bus | Capacity |
|---|---|---|---|---:|
| `C:` | NTFS | WD_BLACK SN850X HS 2000GB | NVMe | 2,000,398,934,016 bytes |
| `Y:` | NTFS | CT1000P1SSD8 | NVMe | 1,000,204,886,016 bytes |

The JSON evidence captures the resolved root path, filesystem, disk number, device model,
bus type, capacity, free space at start, and Git/environment identity. Results must be
grouped by `storage_id`; samples from the two roots must not be pooled as if they were
replicate trials from one device.

This comparison varies local storage hardware while holding the computer, CPU, operating
system, Python process, and code revision constant. It is useful for checking whether the
durable-path result is peculiar to one local storage environment. It is not a two-machine
replication, an independent-host experiment, a Linux-versus-Windows comparison, or a
test of an anchor on an independent device. Claims should therefore be limited to two
local NVMe/NTFS storage roots on one host.

## Safe reporting language

The evidence supports statements about the pinned current-composition native-Linux
final-dispatch latency, its retained exclusive-span decomposition, and its observed
within-run temporal drift. It separately supports statements about Windows native LETS
durable authorization and executor-claim latency, tail behavior, throughput,
concurrency, application-delay context, and sensitivity to two local storage devices.

It does not support a claim that the historical AstralDeep 74.778 ms result was
reproduced, fixed, or completely explained, or that either run establishes an
independent production rollback domain. Any paper table should identify the result
family, platform, exact code revisions, SQLite version, storage posture, configuration,
percentile method, sample count, included adapters, and the distinction between the
integrated current-composition path and the Windows durable-core matrix.
