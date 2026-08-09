# Changelog

All notable changes are documented here. LETS uses semantic versioning for the package and OCI
image together; the Git tag is the package version prefixed with `v`.

## [Unreleased]

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
  scanning, hashes, attestations, exact-candidate acceptance, keyless image signing, and immutable
  retry-safe publication.

### Changed

- Hardened the production profile with conservative cold-start admission timing, a 64-request
  concurrency limit and bounded accept backlog, exact state/WAL/SHM capacity admission, explicit
  append-only audit-volume forecasting, immutable security-path checks, and a resource-fenced
  provider/SQLite image probe.
- Bound production executor replay state to an independent monotonic anchor plus the complete
  executor policy and operator-authenticated manifest key registry; production acceptance now
  rejects duplicate receipts and a pre-claim stale database restore.
- Reworked release publication so the hardened three-node profile runs against the exact published
  candidate digest before per-architecture scanning/SBOMs, signing, retry-safe immutable tag
  promotion, and explicit release-asset attestation.

### Security

- Invalid/missing evidence remains invalid through Boolean negation instead of becoming an allow.
- Operator/warden key roles and public-key material are globally disjoint; transport identifiers,
  peer targets, manifest endpoints, and signed canonical inputs are admitted consistently.
- Runtime, replay, audit, recovery, capacity, and distributed-delivery failures are fail closed;
  bounded maintenance keeps authority-convergence transactions within fixed write budgets.

[Unreleased]: https://github.com/AstralDeep/LETS/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/AstralDeep/LETS/releases/tag/v1.0.0
