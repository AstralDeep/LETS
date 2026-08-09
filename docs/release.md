# Release and upgrade runbook

LETS releases one Python package and one multi-architecture OCI image from the same signed tag. The
automated workflow publishes a GitHub release and `ghcr.io/astraldeep/lets`; it does not publish to
PyPI. Never create a release from a workstation build or move an existing tag.

## Repository prerequisites

Before the first release, an owner must enable GitHub Actions read/write access to Packages,
artifact attestations, and OIDC, and allow the immutable action commits in `release.yml`. The
repository or organization plan must support GitHub artifact attestations for private repositories.
Those capabilities are mandatory: attestation, GHCR push, or signing failure stops the workflow
before the GitHub release is created. There is no `continue-on-error` or private-repository bypass.

Protect `main` and the `v*` tag namespace. Require CI and security workflows, reviewed changes,
linear history, no force pushes, and signed annotated tags. Restrict package deletion and tag/release
administration to release operators. Retain Actions logs and attestation records for the system's
audit lifetime.

## Prepare a release

1. Resolve every P0/P1 issue and confirm `ci` plus `security` are green on the exact commit.
2. Update the version in `pyproject.toml`; do not edit `uv.lock` by hand. Run `uv lock` in the
   repository-local environment and commit both files.
3. Move the relevant `Unreleased` entries in `CHANGELOG.md` under
   `## [X.Y.Z] - YYYY-MM-DD`. State protocol/schema compatibility, migration steps, and rollback
   boundaries explicitly.
4. Run the complete local gate:

   ```sh
   uv sync --all-extras --frozen
   uv run --frozen ruff check .
   uv run --frozen ruff format --check .
   uv run --frozen mypy src
   uv run --frozen pytest -m "not e2e"
   uv run --frozen python deploy/run_acceptance.py
   python deploy/production/check_build_context.py
   ```

5. Merge the reviewed release commit to `main`. From a trusted, hardware-backed maintainer key,
   create and push a signed annotated tag whose text exactly matches the package version:

   ```sh
   git tag -s vX.Y.Z -m "LETS vX.Y.Z"
   git push origin vX.Y.Z
   ```

The release workflow verifies that the tag is annotated, GitHub reports its signature as verified,
the tag resolves to the current `main` commit, the tag/version/changelog agree, and two clean
package builds have the same hashes. It first publishes a uniquely run-addressed image candidate and
records its GitHub build-provenance attestation in that same build job. The image creation time and
`SOURCE_DATE_EPOCH` come from the release commit timestamp instead of workflow wall-clock time. This
stabilizes build timestamps, and the registry exporter rewrites new layer timestamps to that epoch.
Volatile inline BuildKit provenance and SBOM manifests are disabled so their invocation identifiers
and timestamps cannot perturb the candidate index. GitHub provenance is attached to the exact
published digest immediately afterward, and the independently generated per-platform SPDX
attestations are attached after acceptance. These controls improve reproducibility but are not a
claim that arbitrary independent BuildKit invocations must produce the same index digest. The
workflow then runs the three-node mTLS production profile against that exact digest with the generic
external provider through a partition and process restart. After acceptance, it scans both candidate
architectures by digest, requires the upstream WAL-reset fix in the SQLite library loaded by both,
signs and inspects the image digest, and promotes only that verified digest to the full-version and
commit tags.

The Python wheel smoke test runs in an isolated environment synchronized from the server/client
closure exported from the frozen `uv.lock`; the wheel is then installed with `--no-deps`. Dependency
checking, vulnerability audit, and the CycloneDX environment SBOM all inspect that same installed
environment, so they cannot silently resolve three different dependency sets. For the container,
the workflow runs pinned Syft once for `linux/amd64` and once for `linux/arm64`. It verifies each
result's index digest, child-manifest digest, platform metadata, exact repository digest, generator
version, and nonempty package set. Each SPDX document is attested to its platform child manifest.
`lets-container-sbom-index.json` binds both SPDX filenames and hashes to the multi-architecture
candidate digest and its two child-manifest digests.

Promotion is retry-safe for a partial release only when every already-present release tag resolves
to one digest. Before building on a retry, the workflow checks both intended immutable tags. If
either exists, it requires all existing tags to agree, verifies the two platform configurations'
revision, version, and commit-derived creation labels, verifies GitHub provenance from this release
workflow and source ref, and reuses that digest for every acceptance and scan gate. It never assumes
that rebuilding will reproduce the digest. A mismatched existing tag stops the workflow; a
successful create is read back and compared with the candidate before the next tag is attempted.
Registry tag creation is not a transactional compare-and-set, so release operators must prevent
concurrent writers to the protected release namespace for the duration of this job. A failed job can
leave the uniquely addressed candidate or a same-digest release tag. GitHub publication is also
retry-safe: after every gate and the explicit final-asset allowlist succeed, the workflow creates or
resumes a draft release, overwrites the expected assets, downloads them again, and compares every
name and SHA-256 digest before publishing the draft. A retry accepts an already published release
only when its complete downloaded asset set is byte-identical; an unexpected title, prerelease
state, extra asset, or digest mismatch stops the job. Enable GitHub's immutable-releases control for
this repository and prevent concurrent release writers. Never retag or rewrite a mismatched
version; investigate it as a release-integrity incident and fix forward with a new patch version.

## Verify before deployment

Download the release assets and verify their recorded hashes and GitHub attestations:

```sh
sha256sum --check RELEASE_SHA256SUMS
gh attestation verify lets_agent-X.Y.Z-py3-none-any.whl --repo AstralDeep/LETS
gh attestation verify lets_agent-X.Y.Z.tar.gz --repo AstralDeep/LETS
gh attestation verify lets-deployment-X.Y.Z.tar.gz --repo AstralDeep/LETS
gh attestation verify production-profile-acceptance.json --repo AstralDeep/LETS
```

`SHA256SUMS` is the attested package-build manifest. `RELEASE_SHA256SUMS` is generated only after
the independently gated package, production-acceptance, and image jobs have completed. Before
constructing it, the workflow requires the exact versioned asset allowlist, rejects missing, extra,
empty, nested, or colliding inputs, and rechecks the package hashes. The resulting manifest covers
every release asset and is itself the input to a final GitHub provenance attestation.

The image asset group contains `lets-container-amd64.spdx.json`,
`lets-container-arm64.spdx.json`, and `lets-container-sbom-index.json`. Verify the hashes in the
binding index before using either architecture-specific SBOM for admission or incident response;
the final `RELEASE_SHA256SUMS` also covers all three files.

The `lets-deployment-X.Y.Z.tar.gz` asset is the reproducible, attested operator bundle. It contains
the production/provisioning Compose files, environment template, config validator/stager, and the
matching operations, provider, recovery, and release runbooks. Deploy from that bundle and the
verified OCI digest; do not copy deployment files from a mutable branch checkout.

Read `image-digest.txt`, then verify the immutable image and its keyless signature. The certificate
identity is restricted to this repository's release workflow and the GitHub Actions OIDC issuer:

```sh
cosign verify \
  --certificate-identity "https://github.com/AstralDeep/LETS/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/astraldeep/lets@sha256:RELEASE_DIGEST
gh attestation verify \
  oci://ghcr.io/astraldeep/lets@sha256:RELEASE_DIGEST \
  --repo AstralDeep/LETS
```

Archive the release assets, digest, signer identity, verification output, signed manifest/config
epoch, and deployment approval together. A tag is convenient metadata; the digest is the deployment
identity.

## Recovery backup and restore

Create a production recovery point only after draining the warden and allowing both peer delivery
and audit export queues to reach zero. Draining deliberately makes readiness fail, while liveness
remains available. Stop the server before taking the bundle so the node process lock proves there
is only one authority writer:

```sh
docker compose --env-file /etc/lets/warden-a/compose.env \
  -f deploy/production/compose.yaml exec -T warden \
  lets --config /var/lib/lets/config.json drain --reason "scheduled recovery backup"

# Confirm peer-delivery and audit-outbox counts are zero through authenticated metrics.
docker compose --env-file /etc/lets/warden-a/compose.env \
  -f deploy/production/compose.yaml stop --timeout 75 warden

docker compose --env-file /etc/lets/warden-a/compose.env \
  -f deploy/production/maintenance-compose.yaml run --rm --no-deps maintenance \
  lets --config /var/lib/lets/config.json recovery backup --production \
  --output /var/lib/lets-backup/warden-a-YYYYMMDDTHHMMSSZ

docker compose --env-file /etc/lets/warden-a/compose.env \
  -f deploy/production/maintenance-compose.yaml run --rm --no-deps maintenance \
  lets --config /var/lib/lets/config.json recovery verify --production \
  --bundle /var/lib/lets-backup/warden-a-YYYYMMDDTHHMMSSZ
```

Copy the verified bundle to immutable off-host storage and record its digest beside the live,
independent authority checkpoint. The bundle contains a checkpoint summary, never the authority
anchor itself. Exercise restore on a fenced clone regularly. A real restore must run with the
warden stopped and the live authority provider available; it refuses an obsolete database that
would move behind that anchor:

```sh
docker compose --env-file /etc/lets/warden-a/compose.env \
  -f deploy/production/maintenance-compose.yaml run --rm --no-deps maintenance \
  lets --config /var/lib/lets/config.json recovery restore \
  --bundle /var/lib/lets-backup/warden-a-YYYYMMDDTHHMMSSZ \
  --confirm-warden-id warden-a
```

Restore leaves the node durably `DRAINING`. The bundle parent is its explicit scratch/quarantine
workspace and must have the preflighted peak free space; it must never be under node state. An
interrupted restore retains only its journal-bound quarantine for exact resume. After anchored
completion LETS removes that exact quarantine and reports that it was not retained. Inspect
`lets info --production`, reconcile the incident and peers, then explicitly activate; never treat
a successful file copy as authority-safe recovery or a transient quarantine as a rollback point.

## Rolling upgrade

Test the exact digest against a restored, fenced copy of production data before touching a live
warden. Verify free space, database integrity, peer reachability, certificate/key validity, outbox
lag, and the authority checkpoint. Preserve at least the database, config, signed manifest, release
digest, and a separately captured monotonic authority checkpoint.

Upgrade one failure domain at a time:

1. Run `lets drain`, remove external mutation traffic from the node, and wait for prepared
   transfers, peer delivery, and audit export to settle. Readiness becoming false is expected.
2. Stop the node gracefully and confirm the process exited before changing its image.
3. Create and verify a production recovery bundle on `/var/lib/lets-backup`. Record the authority
   checkpoint separately; never copy the anchor into the database backup set or rewind it.
4. If the release notes require a schema transition, run `lets migrate --production --dry-run`
   first and then the explicit stop-the-world migration with a new backup destination. LETS does
   not claim rolling schema migration support.
5. Set `LETS_IMAGE` to the verified digest, pull, render Compose, and start the node without `--wait`;
   the durable drain state intentionally keeps readiness false.
6. Run `lets info --production`, inspect invariant/capacity/peer/audit status, then run
   `lets activate --reason "verified upgrade to vX.Y.Z"`. Require authenticated readiness and
   successful canary operations through at least one receipt TTL before continuing.

Do not roll back across an irreversible schema migration. A binary rollback is permitted only when
the release notes explicitly guarantee backward compatibility with the current schema; drain and
stop the new binary before starting the old digest, inspect it while still drained, then explicitly
activate it. A database rollback requires fencing the old and new node instances and proving that no
authority transition committed after the backup. `recovery restore` reconciles against the live
monotonic anchor and fails closed when that proof is absent. In that case, keep the node fenced and
recover forward.

Treat the staged `LETS_CONFIG_FILE` as a release input. Do not edit it in place. If an approved
upgrade changes provider options or another configuration field, stage an exclusive new file with
`deploy/production/stage_config.py`, review and archive its digest, stop the warden, point the
environment file at the new host path, render Compose, and recreate the container. The runtime must
never start against the writable generated config inside its state directory.

## Emergency response

If a published image or artifact is compromised, do not delete or overwrite its tag. Revoke
deployment approval for the digest, fence affected wardens, publish a patch release, and record the
incident and superseding digest in the changelog/release notes. Package or release deletion destroys
audit evidence and is reserved for repository-owner incident procedure.
