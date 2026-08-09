# LETS production-profile acceptance — 2026-08-09

This is the sanitized summary of the final successful local three-node production-profile
acceptance. The authoritative machine-readable record is written to the ignored
`results/generated/production-profile-acceptance.json` path. This summary omits bearer material,
private keys, full logs, process IDs, public-key identifiers, receipt identifiers, and host paths.

## Provenance

- Evidence schema: `lets.production-profile-acceptance/v1`.
- Started `2026-08-09T15:32:06.966382Z`; completed `2026-08-09T15:32:48.860173Z`.
- Evidence-bound duration: `41.894` seconds.
- LETS version: `1.0.0`; Git commit:
  `8cd4b5e2f50c5d356de249aa93af2aef516e1fa6`.
- The clean pre-run source snapshot contained 167 files and had deterministic digest
  `sha256:ba0ede68f6def3244bebe9a051239fc34a28f76f0cfb324d0816cc50714cf06f`.
  This tracked summary is a derived post-run artifact and is not copied into the runtime image.
- Exact runtime candidate:
  `127.0.0.1:25001/astraldeep/lets@sha256:336feda3da169ecffea8ab3f0b68858c5de304cafe2208ee696d714c6dab64c4`.
- Local runtime image content ID:
  `sha256:5d397bb16c6da91199595f2344fcabc109f08af69ca02b5d5bc4c3bf8245eb38`.
- The image labels bind version `1.0.0`, the Git revision above, and the commit-derived creation
  time. The process ran as UID/GID `10001:10001` and loaded SQLite `3.53.2`, which passes the
  production WAL-reset safety admission.
- Signed manifest digest:
  `sha256:80ebcdba5ae7d27f94248564b59c68dd75aaecceda70572eb301ec632acb40de`.
- Raw JSON evidence SHA-256:
  `e9d8c47ab92b26c78c20552038be38641ba509047183ea7f36b1c34d0dbd353b`.
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
| b | 53,248 | 5 | 4 | 9 |
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
