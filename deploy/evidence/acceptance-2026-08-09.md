# LETS distributed acceptance — 2026-08-09

This is the sanitized, runner-generated summary of the latest successful local
three-node Docker Compose acceptance. The authoritative machine-readable record
and container log are written to ignored paths under `results/generated/`.
This summary deliberately omits bearer credentials, full logs, process IDs,
public-key identifiers, receipt identifiers, and host filesystem paths.

## Provenance

- Evidence schema: `lets.acceptance-evidence/v2`.
- Started `2026-08-11T13:04:11.321165Z`; completed `2026-08-11T13:04:38.272102Z`.
- Total evidence-bound duration: `26.954` seconds;
  pytest scenario duration: `11.421` seconds.
- Git commit `82dbe4f5ddf410cc86778784bb612440725ec66d` on `main`; worktree was
  `dirty` with 0 staged,
  0 unstaged, and
  1 non-ignored untracked files.
- The 176-file source snapshot was stable before and
  after the acceptance scenario. Its deterministic digest was
  `sha256:94ba80c3241cb16d0c3656736f2bdbccff6053b168994f0b04f2e7beab713db3`; the path-redacted status digest was
  `sha256:ad2287f3cbbaaf89a8d7d52bee50399e82de419754e9707b9dc5516e77f8d648`.
- The non-circular runtime/acceptance-input set contained
  57 files and had deterministic digest
  `sha256:ac3c88ff1b01bfc9483f566bb09d262deba3bace3505337c7fe63660b137ec4e`. That explicit set covers container build
  inputs, top-level deployment programs, protocol artifacts, and `tests/e2e`,
  while excluding this derived evidence summary and paper prose.
- Compose digest: `sha256:5eb124cdfcc755391aded75ededa0f6a7c14f4b43d8d0eb8f5cc745f02840615`.
- Runtime image content ID: `sha256:bfc609fd759494a1afb6430364eee6e461aff964800c5724f52b2a8de7760cf8`.
- Toxiproxy image content ID: `sha256:3edf5d14625b9aa8ad71d5dd084da1f8a0eb46ee749457549ae91d29d96546aa`; pulled repository
  digest: `ghcr.io/shopify/toxiproxy@sha256:9378ed52a28bc50edc1350f936f518f31fa95f0d15917d6eb40b8e376d1a214e`.
- Signed manifest digest: `sha256:a8d17de274b3cc54c69942c2c3674befffc251e2e23f49d398132a53e70ea650`; policy digest:
  `sha256:04fedc989f5cf5d9956fe71bd4465fd4da00c278dff485b6f3ac7cf75684dba0`.
- Tools: uv 0.11.21 (5aa65dd7a 2026-06-11 x86_64-pc-windows-msvc); git version 2.45.1.windows.1; pytest 9.1.1;
  Docker version 29.7.2, build a7dcaa6; server 29.7.2;
  Docker Compose version v5.3.1.

The runner records both complete source snapshots in the JSON evidence and
compares them before it writes evidence outputs. A source change during the
cluster run makes the command fail even when pytest succeeds.

## Result

- Pytest exit code `0`; overall evidence status:
  `passed=true`.
- 3 distinct container processes used 3 distinct
  Ed25519 signing keys and one signed manifest.
- Transfer sequence 2 arrived before missing
  sequence 1; the contiguous watermark stayed at
  0. Exact signed HTTP replay was rejected
  with `409 replay_detected`.
- Both directed peer links were disabled. The durable source outbox retained
  2 pending records and
  2 prepared transfers,
  while the partitioned wardens issued 2 valid local receipts.
- The target was stopped with `SIGKILL` and restarted with a new
  process while its signing key stayed stable. Exact transport replay remained
  rejected with `409 replay_detected` and application-level duplicate
  acceptance returned the original acknowledgement.
- After link restoration, the production dispatcher automatically accepted and
  finalized both transfers, delivered the checkpoint, reached compacted high
  water 2 on the source and
  2 on the target, and converged to
  0 pending records and
  0 prepared transfers.
- An independent executor verified a signed receipt, durably claimed it in its
  own SQLite replay store, rejected it after reopening that store, and reported
  integrity `["ok"]`.
- Aggregate transfer counters were `[20]` in and `[20]`
  out. Across all wardens, `free_pool + lease_residual + consumed` was
  `[300]` against initial budget `[300]`; every local invariant
  and signed audit chain was healthy.

The runner stopped all acceptance containers and removed the Compose network
in its `finally` block. It preserves the five named volumes for inspection; a
future run validates those exact names before removing them for a clean start.
