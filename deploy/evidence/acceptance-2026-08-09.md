# LETS production-profile acceptance — 2026-08-09

This is the sanitized summary of the final successful local three-node production-profile
acceptance. The authoritative machine-readable record is written to the ignored
`results/generated/production-profile-acceptance.json` path. This summary omits bearer material,
private keys, full logs, process IDs, public-key identifiers, receipt identifiers, and host paths.

## Provenance

- Evidence schema: `lets.production-profile-acceptance/v1`.
- Started `2026-08-09T14:51:49.574851Z`; completed `2026-08-09T14:52:52.497479Z`.
- Evidence-bound duration: `62.923` seconds.
- LETS version: `1.0.0`; Git commit:
  `6ef7a02bdeacbc05b5c75741a3b6082fa3839441`.
- The pre-run source snapshot contained 168 files and had deterministic digest
  `sha256:d08cc199bd954563b13c3e6d32439b2492a5e1eeba6599e65abf11b13a4b0758`.
  The worktree was dirty because the production implementation had not yet been committed. This
  tracked summary is a derived post-run artifact and is not copied into the runtime image.
- Exact runtime candidate:
  `127.0.0.1:25000/astraldeep/lets@sha256:2f002bc691685930e07bf5d4e297f2b9ba13617aad222d512afc7b3d59a8e8ad`.
- Local runtime image content ID:
  `sha256:e252f08159156d3f13f05a8722a8caa82d09ea491e4623482bee959bbdcf2d3e`.
- The image labels bind version `1.0.0`, the Git revision above, and the commit-derived creation
  time. The process ran as UID/GID `10001:10001` and loaded SQLite `3.53.2`, which passes the
  production WAL-reset safety admission.
- Signed manifest digest:
  `sha256:8b56c82dc49f3a030fad762bdd7fb76c8bcd5d89534bd847e729644bb7e5d9a3`.
- Raw JSON evidence SHA-256:
  `c1ffc7911f72f0a9608169e5c1033e011559532c1b64d5f447f6a37eaf929f80`.
- Dockerfile SHA-256:
  `af26180a2afe70d0cf758c33677aeac7838817676cbadad4610c2cb8f260c594`;
  production acceptance Compose SHA-256:
  `5b8177e27b059a5da8f9e1810e311159ef385c978fe60db15ca560e2afb3e6db`;
  acceptance runner SHA-256:
  `be943040a364285820295c4d071965f6f1ac7da4c63f1bb5966c5166d336c26e`.

The candidate was pushed to a loopback-only ephemeral registry, pulled by its exact manifest
digest, and used as the configured image for all three wardens. Harness, material-generation, and
scenario services used the separate reviewed acceptance target; they did not replace the warden
runtime image.

## Security and runtime boundary

- TLS with required client certificates protected all three warden APIs and peer links.
- Missing and untrusted client certificates were rejected.
- Missing and expired short-lived EdDSA JWTs were rejected.
- Each warden used the bundled `generic-production` provider through a separately mounted external
  signer-helper process boundary.
- Every warden ran non-root with a read-only root filesystem, all capabilities dropped,
  `no-new-privileges`, bounded memory/CPU/PIDs/file descriptors, bounded JSON logs, a hardened
  16 MiB temporary filesystem, and no backup mount.
- State, monotonic authority, and append-only audit archives used distinct volumes. Config, trust,
  PKI, and signer mounts were read-only; UID 10001 was unable to rewrite or unlink the staged
  configuration.

| Warden | Audit bytes | Records | Archive head | External signer calls |
| --- | ---: | ---: | ---: | ---: |
| a | 53,248 | 6 | 5 | 21 |
| b | 53,248 | 6 | 5 | 10 |
| c | 45,056 | 1 | 0 | 4 |

All three immutable audit chains verified successfully.

## Distributed fault result

- Both directed links between wardens A and B were partitioned while a transfer was prepared. The
  durable outbox retained the work and recorded the expected transient delivery failure.
- Warden A was terminated with `SIGKILL` and restarted with a different process.
- After link restoration, the dispatcher drained to zero pending, failed, prepared, and superseded
  records. The transfer converged with vectors `[10]` out and `[10]` in, and conservation held.
- Mutual TLS remained enabled throughout the partition, restart, and convergence sequence.

## Protected executor result

- The protected executor used a replay database and monotonic executor anchor in independent
  domains, with identity derived from the authenticated policy and exact manifest key registry.
- The first claim advanced the authority sequence to 1.
- The same receipt was rejected after reopen, and replacing the main database with its pre-claim
  snapshot was rejected as older than the monotonic authority anchor.

## Cleanup and release boundary

The runner removed every acceptance container, named volume, and Compose network. A separate
read-only, capability-free registry helper was then stopped and removed after its exact image and
configuration were verified. Post-run counts were zero containers, zero volumes, and zero networks
for the acceptance project.

This is local Linux/amd64 topology evidence, not a published release artifact. The signed-tag
release workflow independently builds the multi-architecture candidate, binds GitHub provenance
and per-platform SPDX attestations to its digest, and reruns this production profile against that
exact published digest before promotion or GitHub release publication.
