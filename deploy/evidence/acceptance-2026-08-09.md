# LETS distributed acceptance — 2026-08-09

This is the sanitized, runner-generated summary of the latest successful local
three-node Docker Compose acceptance. The authoritative machine-readable record
and container log are written to ignored paths under `results/generated/`.
This summary deliberately omits bearer credentials, full logs, process IDs,
public-key identifiers, receipt identifiers, and host filesystem paths.

## Provenance

- Evidence schema: `lets.acceptance-evidence/v2`.
- Started `2026-08-09T10:02:15.143119Z`; completed `2026-08-09T10:02:38.924901Z`.
- Total evidence-bound duration: `23.782` seconds;
  pytest scenario duration: `6.88` seconds.
- Git commit `149c1fe3c748d1f13ae2b9d4845a1fb1a17d2f8d` on `main`; worktree was
  `dirty` with 0 staged,
  1 unstaged, and
  122 non-ignored untracked files.
- The 123-file source snapshot was stable before and
  after the acceptance scenario. Its deterministic digest was
  `sha256:b3402e15d92a1b0d0ccec2aac1ff488a6cdd44e944c4a1ef14df8164b434ac5e`; the path-redacted status digest was
  `sha256:580b1cb9fcd81f65807479451a378b7f222dfa5a8daeee1d52892e032aca970f`.
- The non-circular runtime/acceptance-input set contained
  46 files and had deterministic digest
  `sha256:8216a535323863ca1d9ff523adfb29597ac7d02fe2e871985c4851433df13e56`. That explicit set covers container build
  inputs, top-level deployment programs, protocol artifacts, and `tests/e2e`,
  while excluding this derived evidence summary and paper prose.
- Compose digest: `sha256:5eb124cdfcc755391aded75ededa0f6a7c14f4b43d8d0eb8f5cc745f02840615`.
- Runtime image content ID: `sha256:fe174161832f624c01a005fa1253607356a194a78d669eb72aec4eec3af52ef6`.
- Toxiproxy image content ID: `sha256:3edf5d14625b9aa8ad71d5dd084da1f8a0eb46ee749457549ae91d29d96546aa`; pulled repository
  digest: `ghcr.io/shopify/toxiproxy@sha256:9378ed52a28bc50edc1350f936f518f31fa95f0d15917d6eb40b8e376d1a214e`.
- Signed manifest digest: `sha256:1c3f47302300af39e50b065327d307a46e883c5d1e4f44d3de37c7bda4f3250f`; policy digest:
  `sha256:04fedc989f5cf5d9956fe71bd4465fd4da00c278dff485b6f3ac7cf75684dba0`.
- Tools: uv 0.11.21 (5aa65dd7a 2026-06-11 x86_64-pc-windows-msvc); git version 2.45.1.windows.1; pytest 9.1.1;
  Docker version 29.6.2, build dfc4efb; server 29.6.2;
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
