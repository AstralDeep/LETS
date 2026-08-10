# Changelog

All notable changes are documented here. LETS uses semantic versioning for the package and OCI
image together; the Git tag is the package version prefixed with `v`.

## [Unreleased]

## [1.0.5] - 2026-08-10

### Fixed

- Decoupled sustained-soak health observation from the serial mixed-workload cycle. A dedicated
  client now samples on an absolute monotonic schedule, retains explicit scheduling and
  observation timing, shares one fail-closed audit-error budget for the whole run, and makes a
  missed exporter-stall deadline a release failure instead of allowing a later healthy response
  to hide the evidence gap.
- Replaced the infeasible fixed 300-cycle and coupled 301-health-sample release floors with
  independently verifiable evidence contracts. Workload adequacy is derived from host-bound
  authorized active time at a bounded 15-second-per-cycle rate and requires three complete
  rotations through all six directed transfer paths plus three executor reopen intervals (54 cycles
  with the supplied frequencies); health adequacy is derived from the independent sampler's
  interval and strict per-node observation coverage. Recorded pause episodes must bind the exact
  orchestrator partition schedule before excluded time can reduce the workload-rate denominator.
- Made release publication recompute the active-time, pause, sample-retention, per-node cadence,
  and throughput relationships from raw soak evidence. A forged or truncated workload record, a
  sampler failure, or a mismatch between the evaluator and release verifier remains
  non-promotable.
- Made warden and protected-executor authority recovery symmetric and fail closed. Only a
  well-formed, typed helper-transport failure after successful admission can recover on a later
  explicit transaction after its bounded cooldown; the failed call is never retried internally.
  Admission-time transport failure requires a fresh store/anchor open, while anchor semantic,
  protocol, malformed-transport, and other provider failures remain permanently sticky for that
  instance.
- Bound process-isolated anchor helper start, request correlation, lock/I/O, response, and reset to
  one absolute deadline. A fresh process-file store lifetime durably confirms its exact checkpoint,
  and any uncertain mutating reply is reconciled and confirmed before recovery is reported.
- Added authenticated bounded authority status to metrics and
  `GET /v1/maintenance/authority-status`, plus the idempotent
  `POST /v1/maintenance/authority-fence` snapshot-and-fence operation. The fence binds the exact
  warden, namespace PID, process-lifetime ID, restart ID, monotonic timestamp, and terminal anchor
  status before a planned host `SIGKILL`.
- Strengthened the sustained soak with one deterministic injected executor fault after SQLite
  `COMMIT` and a successful external CAS, surfaced as a classified lost reply. The durable claim is
  burned, the original call fails closed, and retry raises `ReplayError` with zero protected
  effects. Every core and executor lifetime is captured terminally; the raw global authority
  fault, episode, attempt, and recovery counters must each be exactly one with zero permanent
  faults, and final verification snapshot-and-fences all surviving wardens.

### Changed

- The signed `v1.0.4` tag is retained as an unpromoted candidate. Its package, provenance,
  hardened acceptance, full 3,601-second mixed workload, conservation, all six transfer paths, 26
  durable partition recoveries, and resource/cleanup checks passed; its records also captured all
  three planned `SIGKILL` operations. Promotion was nevertheless blocked because inline health
  requests left an unobserved 26.45-second interval against a 15-second audit-stall bound, while the
  same serial design made its fixed 300-cycle and 301-sample thresholds mathematically infeasible
  under the injected pauses. No `1.0.4` package or final OCI tag was published and no GitHub release
  was created.
  Version 1.0.5 fixes the evidence design forward without moving or reusing that public tag.
- Diagnostic provenance for the next local, unpublished candidate is retained separately. Commit
  `e304cb742562da4fcea0b58afbcb44f30e382812` passed its exact production acceptance in 61.076
  seconds; the retained local `results/generated/production-profile-acceptance-v105-e304cb7.json`
  record's raw SHA-256 is
  `a399e0cbe71cb80a1a667b3655c1eaa68951b6fd9b0dcbbba6e9b49d707c693a`. Its exact one-hour soak
  then failed after 122.268 seconds and 13 workload cycles, before the first partition or restart,
  when warden A remained on HTTP 503 `storage_error` with an undifferentiated sticky authority
  outage. The workload had run for 87.676576 seconds. The retained local
  `results/generated/production-profile-soak-v105-e304cb7-anchor-failure.json` raw `passed: false`
  record is SHA-256
  `d4a789e351a09df0b98c4bb139ecb4618f734f634bd0fe6b5f6bf9aceeeb210c`; its canonical payload is
  `sha256:d1e667fa459482a1b40c8e32269bf6f7b1c037799b9e39c4a31ecde45cfe9aee`. Contemporaneous broad
  Docker/VM delays made a host/VM stall near the five-second helper boundary a useful hypothesis,
  not a proven root cause. Cleanup proved zero remaining containers, networks, and volumes. This
  local diagnostic was not a release asset; no Git release tag was created, the candidate was not
  promoted or released, and no package or final OCI release tag was published. This is not passing
  soak evidence and does not authorize promotion. It motivated the typed transport recovery and
  terminal-lifetime proof above, which still require a fresh mandatory exact-candidate soak.
- Carries forward every 1.0.1 through 1.0.4 candidate change, including the pre-authentication body
  deadline, exact-candidate sustained soak, cgroup-v2 resource proof, bounded audit-BUSY recovery,
  serialized SQLite recovery, the bounded production peer deadline, full convergence budget, and
  exact failed-run cleanup.

### Compatibility, migration, and rollback

- Warden schema 2, executor schema 5, manifest semantics, and durable authority/replay formats are
  unchanged; no database or executor migration is required. Existing public LETS v1 operations
  remain compatible with 1.0.0 through 1.0.4. Authority status fields in authenticated metrics,
  the two authenticated maintenance endpoints, and the typed 503
  `authority_anchor_transport_error` problem code/type are additive public API changes. The private
  bundled parent/helper protocol is intentionally changed in 1.0.5 by exact request correlation
  and `confirm`; deploy it only as a matched 1.0.5 pair and never mix a pre-1.0.5 helper with a
  1.0.5 parent. The top-level soak evidence and its nested workload record remain the non-runtime
  schemas
  `lets.production-profile-soak/v2` and
  `lets.production-profile-soak-workload/v2`; their stronger authority-lifetime evidence is not a
  runtime protocol or storage change.
- Drain peer and audit queues, verify an authority-safe recovery bundle, stop every old process,
  and deploy only the exact 1.0.5 artifacts. Mixed-version operation remains unsupported; retain
  the 60-second peer request deadline and 120-second stop grace of the supplied profile.
- Binary/schema compatibility does not make an unpublished candidate an approved rollback target.
  Versions 1.0.1 through 1.0.4 were never promoted, while 1.0.0 lacks the later production defenses;
  v1.0.5 therefore has no approved earlier binary rollback digest. Never restore older database,
  audit, replay, or anchor bytes; preserve live monotonic state, fence the cluster, and recover
  forward with a patch release.

## [1.0.4] - 2026-08-09 (unreleased candidate)

### Fixed

- Replaced the peer dispatcher's obsolete two-second request watchdog with an explicit bounded
  deadline. The supplied production profile defaults to 60 seconds, admits 30 through 60 seconds,
  and rejects a value that cannot cover every signer, authority-anchor, SQLite, and scheduling/TLS
  bound in the authenticated transfer-acceptance path. A durable delivery still performs one HTTP
  attempt per dispatcher cycle and remains `PREPARED` after any timeout; no timeout is treated as
  acceptance.
- Removed the soak's hidden 60-second settle cap. Recovery now uses the configured convergence
  budget through one shared monotonic deadline across every node/status request, while continuing
  to require all failed/pending/prepared/in-flight peer state to drain before fault injection or
  final success.
- Hardened failed-soak teardown for the named Compose one-off workload. Cleanup may remove only the
  exact container whose project, service, and one-off labels match the current unique run, records
  the bounded result, and then proves the project has no remaining containers, networks, or
  volumes.
- Made durable peer failure diagnostics safe and actionable: newly persisted errors retain only a
  bounded exception-class token, while authenticated metrics expose the oldest failed delivery's
  sanitized attempt count, remaining retry delay, record kind, and target warden. Raw exception
  text, URLs, paths, and credentials are never copied into the status document.

### Changed

- The signed `v1.0.3` tag is retained as an unpromoted candidate. Its package, provenance, and
  hardened acceptance gates passed, but the mandatory soak failed before its first injected fault:
  a transfer was accepted by the target while the sender's two-second watchdog closed before the
  acknowledgement completed, leaving durable `PREPARED`/failed work for an exponentially backed-off
  retry. No `1.0.3` package or final OCI tag was published and no GitHub release was created.
  Version 1.0.4 fixes forward without moving or reusing any failed public candidate tag.
- The supplied container stop window is 120 seconds so the maximum admitted peer deadline, server
  graceful shutdown, audit-exporter stop, SQLite busy allowance, and dispatcher join all remain
  bounded before the runtime may be killed.
- Carries forward every 1.0.1 through 1.0.3 candidate change, including the pre-authentication body
  deadline, exact-candidate sustained soak, cgroup-v2 resource proof, sampled audit-BUSY recovery,
  and serialized core storage recovery.

### Compatibility, migration, and rollback

- LETS v1 wire/API compatibility, warden schema 2, executor schema 5, manifest semantics, and
  authority/replay formats remain unchanged from 1.0.0 through 1.0.3. No database or executor
  migration is required. The new peer deadline is a deployment/runtime setting, not a wire change.
- Drain peer and audit queues, verify an authority-safe recovery bundle, stop every old process,
  and deploy only the exact 1.0.4 artifacts. Mixed-version operation remains unsupported; set the
  required `LETS_PEER_REQUEST_TIMEOUT_SECONDS` consistently across the stopped cluster before
  restart (the supplied generic profile uses `60`).
- A binary/configuration rollback remains schema-compatible, but never restore older database,
  audit, replay, or anchor bytes. Preserve the live monotonic state or recover forward. Rolling
  back below 1.0.4 also restores the unsafe two-second production peer watchdog and is not a
  supported remedy for delayed delivery.

## [1.0.3] - 2026-08-09 (unreleased candidate)

### Fixed

- Kept audit readiness fail-closed while allowing the sustained release soak to observe at most one
  sampled, bounded archive-connect `SQLITE_BUSY`-family error and require a fully healthy recovery
  within the remainder of the existing stall window. Any other, repeated, cross-node, over-bound,
  blocked, or unresolved error still fails the run and prevents promotion.
- Closed the audit archive connection when SQLite session setup fails, and retained only sanitized
  SQLite error identity in exporter diagnostics so transient lock/I/O failures are actionable
  without exposing storage paths.
- Serialized core capacity snapshots, fault clearing, WAL checkpoints, and failed-transaction
  rollback/teardown with authority transactions; latched `SQLITE_FULL` before releasing the lock;
  restored a sticky fault after failed clearing; and exposed only a fixed setup stage plus sanitized
  SQLite error identity when a core connection cannot open.

### Changed

- The signed `v1.0.2` tag is retained as an unpromoted candidate. Its package, candidate-provenance,
  and hardened acceptance jobs passed, but its mandatory soak stopped on a single exporter status
  sampled 5.11 seconds into the configured 15-second recovery window. No `1.0.2` package or final
  OCI tag was published and no GitHub release was created. Version 1.0.3 fixes forward without
  moving or reusing either failed public candidate tag.
- Carries forward every 1.0.1 and 1.0.2 candidate change, including the pre-authentication body
  deadline, quiet disconnect handling, exact-candidate one-hour soak, cgroup-v2 resource proof,
  bounded failure diagnostics, and release-governance checks.

### Compatibility, migration, and rollback

- LETS v1 wire/API compatibility, warden schema 2, executor schema 5, manifest semantics, and
  authority/replay formats remain unchanged from 1.0.0 through 1.0.2. No database or executor
  migration is required.
- Drain peer and audit queues, verify an authority-safe recovery bundle, stop every old process, and
  deploy only the exact 1.0.3 artifacts. Mixed-version operation remains unsupported.
- A binary/configuration rollback remains schema-compatible, but never restore older database,
  audit, replay, or anchor bytes. Preserve the live monotonic state or recover forward.

## [1.0.2] - 2026-08-09 (unreleased candidate)

### Fixed

- Strengthened the mandatory production soak's resource proof after the public 1.0.1 candidate
  failed closed under transient allocation pressure. The hardened profile now matches the shipped
  1 GiB cgroup while retaining 25 percent operational headroom, independently bounds the LETS
  process, records cgroup memory/PID peaks and limit events across every process lifetime, prohibits
  swap and OOM/limit hits, captures failure-time resource evidence before cleanup, and atomically
  preserves the complete structured diagnostic afterward.
- Made workload coordination surface an exited workload immediately, with bounded diagnostics,
  instead of replacing its root cause with a later pause-acknowledgement timeout.

### Changed

- Carries forward every 1.0.1 candidate change: the bounded pre-authentication request-body
  deadline and quiet disconnect handling, separate service/exporter readiness evidence, the
  mandatory exact-candidate one-hour soak, and the strengthened release-governance checks.
- The signed `v1.0.1` tag is retained as an unpromoted candidate whose release workflow failed the
  new soak gate; no `1.0.1` package, final OCI tag, or GitHub release was published. Version 1.0.2
  supersedes it without weakening any gate or rewriting the public tag.

### Compatibility, migration, and rollback

- LETS v1 wire/API compatibility, warden schema 2, executor schema 5, manifest semantics, and
  authority/replay formats remain unchanged from 1.0.0 and 1.0.1. No database or executor migration
  is required.
- Apply the same stop-the-world procedure documented for 1.0.1: drain peer and audit queues, verify
  an authority-safe recovery bundle, stop all old processes, and deploy the exact 1.0.2 artifacts.
- A binary/configuration rollback remains schema-compatible, but never restore older database,
  audit, replay, or anchor bytes. Preserve the live monotonic state or recover forward.

## [1.0.1] - 2026-08-09 (unreleased candidate)

### Fixed

- Bound the complete pre-authentication request-body read to an operator-configurable deadline
  (30 seconds by default). A stalled upload now fails with HTTP 408
  `request_body_timeout`, closes the connection, and never reaches authentication or authority
  handling; a client that disconnects mid-body is rejected quietly without an unexpected-error
  traceback or log amplification.

### Changed

- Added a mandatory one-hour, exact-candidate production soak before image promotion. The soak
  drives mixed lease lifecycle, authorization, anchored executor replay, and all-pairs transfer
  traffic through repeated peer partitions and rotating `SIGKILL` process replacement; it fails on
  insufficient work, unhealthy invariants/audit/capacity, unconverged backlogs, or bounded-resource
  regressions and publishes its source- and digest-bound machine record as a signed release asset.
- Tightened release governance so publication requires the exact commit's successful CI and
  security push runs, exact compatibility/migration/rollback notes, repository release
  immutability, and GitHub's post-publication release attestation.

### Compatibility, migration, and rollback

- LETS v1 wire/API compatibility, warden schema 2, executor schema 5, manifest semantics, and
  authority/replay formats are unchanged from 1.0.0. No database or executor migration is required.
- Mixed-version operation remains unsupported. Drain peer and audit queues, take and verify an
  authority-safe recovery bundle, stop every old process, and deploy the exact 1.0.1 image/package
  together. Configure the new body deadline explicitly if the 30-second default is unsuitable.
- A stop-the-world rollback to the exact 1.0.0 artifact is schema-compatible, but it removes the
  pre-authentication body deadline. Never restore older database or anchor bytes; preserve the live
  schema-2/schema-5 state and monotonic authority checkpoints or recover forward.

## [1.0.0] - 2026-08-09

### Added

- Distributed, partition-safe warden runtime with signed manifests, leases, receipts, replication,
  lifecycle control, cross-warden transfers, peer replay defense, audit chains, and conservation
  invariants.
- HTTP API, typed client, CLI, strict canonical wire format, SQLite persistence, protocol schemas,
  host-neutral adapters, formal bounded checks, and fault-injected three-node acceptance.
- External runtime-provider boundary for managed signing and production identity integrations.
- Fail-closed production Compose boundary with TLS/mTLS, immutable image digests, independent
  state/authority/audit/backup rollback domains, non-root/read-only execution, immutable staged
  configuration, capacity admission, and networkless maintenance/provisioning surfaces.
- Journaled backup, restore, and stop-the-world migration flows with signed-audit, anchor, exact-byte,
  capacity, crash-resume, and replay-authority admission.
- Schema-5 protected-executor replay storage with an independent monotonic anchor, exact policy and
  trust binding, stale-restore/clone rejection, bounded replay cleanup, and explicit finite-epoch
  operation.
- Pinned security and release workflows covering SAST, dependency audit, reproducible Python and
  deployment artifacts, package smoke tests, CycloneDX/SPDX SBOMs, per-architecture container
  scanning, hashes, keyless provenance/SBOM attestations, exact-candidate acceptance, keyless image
  and release-manifest signing, and immutable retry-safe publication.

### Changed

- Hardened the production profile with conservative cold-start admission timing, a 64-request
  concurrency limit and bounded accept backlog, exact state/WAL/SHM capacity admission, explicit
  append-only audit-volume forecasting, immutable security-path checks, and a resource-fenced
  provider/SQLite image probe.
- Bound production executor replay state to an independent monotonic anchor plus the complete
  executor policy and operator-authenticated manifest key registry; production acceptance now
  rejects duplicate receipts and a pre-claim stale database restore.
- Reworked release publication so the hardened three-node profile runs against the exact published
  candidate digest before per-architecture scanning/SBOMs, keyless provenance and SBOM attestations,
  signing, retry-safe immutable tag promotion, and a signed release-asset manifest.

### Security

- Invalid/missing evidence remains invalid through Boolean negation instead of becoming an allow.
- Operator/warden key roles and public-key material are globally disjoint; transport identifiers,
  peer targets, manifest endpoints, and signed canonical inputs are admitted consistently.
- Runtime, replay, audit, recovery, capacity, and distributed-delivery failures are fail closed;
  bounded maintenance keeps authority-convergence transactions within fixed write budgets.

### Compatibility, migration, and rollback

- The 1.0.0 wire/API contract is LETS v1, warden storage is schema 2, and protected-executor replay
  storage is schema 5. Mixed-version rolling operation is not supported; upgrades are
  stop-the-world after a signed drain and exact recovery backup.
- Schema-1 wardens migrate through the journaled `lets migrate` flow after peer/audit drain and
  legacy replay expiry. Executor schema 4 has no authority-safe in-place promotion; wait through
  the receipt-validity window, drain effects, and initialize a fresh schema-5 executor epoch and
  independent anchor.
- Rollback never means reopening older authority bytes. Restore accepts only an exact verified
  bundle consistent with the live monotonic anchors; a database behind an anchor remains fenced.
  Roll back deployment configuration or binaries only while their schema/protocol compatibility is
  proven, otherwise recover forward with a patch release.

[Unreleased]: https://github.com/AstralDeep/LETS/compare/v1.0.5...HEAD
[1.0.5]: https://github.com/AstralDeep/LETS/releases/tag/v1.0.5
[1.0.4]: https://github.com/AstralDeep/LETS/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/AstralDeep/LETS/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/AstralDeep/LETS/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/AstralDeep/LETS/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/AstralDeep/LETS/releases/tag/v1.0.0
