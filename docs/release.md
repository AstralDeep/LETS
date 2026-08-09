# Release and upgrade runbook

LETS releases one Python package and one multi-architecture OCI image from the same signed tag. The
automated workflow publishes a GitHub release and `ghcr.io/astraldeep/lets`; it does not publish to
PyPI. Never create a release from a workstation build or move an existing tag.

## Repository prerequisites

Before the first release, an owner must enable GitHub Actions read/write access to Packages and
Releases, permit OIDC token issuance, and allow the immutable action commits in `release.yml`. GHCR
must retain OCI signatures, attestations, and referrers. The workflow uses Sigstore/Cosign keyless
signing through GitHub Actions OIDC, so a private repository does not depend on GitHub's separate
artifact-attestation service or its plan availability. OIDC, Cosign attestation/verification, GHCR
push, or signing failure stops the workflow before the GitHub release is created. There is no
`continue-on-error` or private-repository bypass.

Immediately before pushing a release tag, a trusted release operator with repository
Administration-read permission must confirm the repository setting (the Actions `GITHUB_TOKEN`
cannot read this admin-only endpoint):

```sh
test "$(gh api -H 'X-GitHub-Api-Version: 2026-03-10' \
  repos/AstralDeep/LETS/immutable-releases --jq .enabled)" = true
```

Protect `main` and the `v*` tag namespace when the repository plan provides server-side branch and
tag rules. Require CI and security workflows, reviewed changes, linear history, no force pushes,
and signed annotated tags. A private repository plan that does not expose those rules must treat
repository administrators as trusted release operators and record that governance boundary. The
release workflow still fails closed unless the commit is GitHub-verified, its exact `push` CI and
security runs succeeded, a GitHub-verified annotated tag resolves to the current `main`, and the
same tag still resolves to that commit immediately before publication. These checks protect the
published artifact but do not pretend to provide independent review or no-force-push governance.
Restrict package deletion and tag/release administration to release operators. GitHub Actions log
retention is a short-lived diagnostic window, not the release archive. Before that window expires,
export any incident-relevant logs and their hashes to the independently controlled audit archive.
Retain the immutable GitHub release attestation, release signature bundles, registry signatures and
attestations, acceptance evidence, and transparency-log records for the system's audit lifetime.

## Prepare a release

1. Resolve every P0/P1 issue and confirm `ci` plus `security` are green on the exact commit.
2. Update the version in `pyproject.toml`, `src/lets/__init__.py`, and the FastAPI application;
   regenerate `protocol/openapi.yaml`, then run `uv lock` in the repository-local environment.
   Do not edit `uv.lock` by hand. If the paper describes the current release, regenerate every
   version-bound evidence field and rebuild/render it rather than merely relabeling old evidence.
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
package builds have the same hashes. It first publishes a uniquely run-addressed image candidate. In
that same build job it generates a SLSA/in-toto provenance predicate binding the repository, release
workflow, source tag and commit, and build metadata to the exact candidate digest. Cosign attaches a
keyless attestation to that digest and immediately verifies the expected workflow identity and
GitHub Actions OIDC issuer. The image creation time and `SOURCE_DATE_EPOCH` come from the release
commit timestamp instead of workflow wall-clock time. This stabilizes build timestamps, and the
registry exporter rewrites new layer timestamps to that epoch. Volatile inline BuildKit provenance
and SBOM manifests are disabled so their invocation identifiers and timestamps cannot perturb the
candidate index. The independently generated per-platform SPDX documents are attached with keyless
Cosign attestations to their exact child-manifest digests after acceptance, then verified before
promotion. These controls improve reproducibility but are not a claim that arbitrary independent
BuildKit invocations must produce the same index digest. The workflow runs the three-node mTLS
production profile against that exact candidate digest with the generic external provider through a
partition and process restart. A separate mandatory one-hour soak drives mixed lease lifecycle,
authorization, anchored executor replay, and transfer traffic while repeatedly partitioning peer
links and replacing warden processes with `SIGKILL`. It continuously checks invariants, audit and
dispatcher health, final conservation and backlog convergence, and explicit RSS, file-descriptor,
database, WAL, audit, and signer growth bounds. The soak uses the shipped 1 GiB container limit but
admits at most a 768 MiB retained cgroup peak, independently caps the LETS process, disables swap,
and requires zero memory/OOM/PID limit events. It samples retained cgroup counters before every
planned process replacement so a new container lifetime cannot erase an earlier pressure event.
Its machine record binds the exact OCI digest and config ID to the clean release commit,
source-tree digest, and soak-harness hashes. A failed soak captures a final resource sample before
cleanup, then atomically writes and uploads a bounded structured failure record that includes the
cleanup result; that diagnostic artifact never authorizes promotion. After
acceptance and soak, the workflow scans both candidate architectures by digest, requires the
upstream WAL-reset fix in the SQLite library loaded by both, signs and inspects the image digest,
and promotes only that verified digest to the full-version and commit tags.
The package build, isolated smoke, locked dependency audit, and package SBOM must all pass before
the production-profile acceptance, production-soak, or image-promotion jobs can start.

The Python wheel smoke test runs in an isolated environment synchronized from the server/client
closure exported from the frozen `uv.lock`; the wheel is then installed with `--no-deps`. Dependency
checking and the CycloneDX environment SBOM inspect that installed environment, while strict
`pip-audit` checks the exact exported third-party requirement closure used to create it. This keeps
the intentionally unpublished first-party wheel out of registry resolution without allowing the
three dependency views to drift. For the container, the workflow runs pinned Syft once for
`linux/amd64` and once for `linux/arm64`. It verifies each result's index digest, child-manifest
digest, platform metadata, exact repository digest, generator version, and nonempty package set.
Each SPDX document is attested to its platform child manifest. `lets-container-sbom-index.json`
binds both SPDX filenames and hashes to the multi-architecture candidate digest and its two
child-manifest digests.

Promotion is retry-safe for a partial release only when every already-present release tag resolves
to one digest. Before building on a retry, the workflow checks both intended immutable tags. If
either exists, it requires all existing tags to agree, verifies the two platform configurations'
revision, version, and commit-derived creation labels, verifies the keyless SLSA attestation and its
exact repository/workflow/source bindings, and reuses that digest for every acceptance and scan
gate. It never assumes that rebuilding will reproduce the digest. A mismatched existing tag stops
the workflow; a successful create is read back and compared with the candidate before the next tag
is attempted.
Registry tag creation is not a transactional compare-and-set, so release operators must prevent
concurrent writers to the protected release namespace for the duration of this job. A failed job can
leave the uniquely addressed candidate or a same-digest release tag. GitHub publication is also
retry-safe: after every gate and the explicit final-asset allowlist succeed, the workflow creates or
resumes a draft release, overwrites the expected assets, downloads them again, and compares every
name and SHA-256 digest before publishing the draft. A retry accepts an already published release
only when its complete downloaded asset set is byte-identical; an unexpected title, prerelease
state, extra asset, or digest mismatch stops the job. GitHub's immutable-releases control is a hard
operator prerequisite. The workflow immediately verifies the published release's `immutable` state
and GitHub release attestation; if GitHub does not make it immutable, the workflow returns the
release to draft and fails. Prevent concurrent release writers. Never retag or rewrite a mismatched
version; investigate it as a release-integrity incident and fix forward with a new patch version.

## Verify before deployment

Download every release asset and use a verified Cosign v3.1.3 binary, matching the workflow pin.
Authenticate the checksum manifest with the release workflow's keyless Sigstore bundle before
trusting any recorded payload hash, then check all payloads:

```sh
RELEASE_IDENTITY="https://github.com/AstralDeep/LETS/.github/workflows/release.yml@refs/tags/vX.Y.Z"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
cosign verify-blob \
  --bundle RELEASE_SHA256SUMS.sigstore.json \
  --certificate-identity "$RELEASE_IDENTITY" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  RELEASE_SHA256SUMS
sha256sum --check RELEASE_SHA256SUMS
```

`SHA256SUMS` is the package-build manifest and is itself one of the payloads authenticated through
the final manifest. `RELEASE_SHA256SUMS` is generated only after the independently gated package,
production-acceptance, one-hour production-soak, and image jobs have completed. Before constructing
it, the workflow requires the exact versioned payload allowlist, rejects missing, extra, empty,
nested, or colliding inputs, and rechecks the package hashes. It covers all fifteen payload assets,
including `production-profile-soak.json`. The published release then adds `RELEASE_SHA256SUMS` and
its `RELEASE_SHA256SUMS.sigstore.json` verification bundle for an exact seventeen-asset set. The
bundle cannot be listed in the manifest it authenticates;
`cosign verify-blob` instead verifies the manifest's certificate identity, OIDC issuer, signature,
and transparency-log evidence directly from that bundle. Publication still downloads and
byte-compares the complete seventeen-asset set before making the draft public.

The SBOM portion of the image asset group contains `lets-container-amd64.spdx.json`,
`lets-container-arm64.spdx.json`, and `lets-container-sbom-index.json`. Verify the hashes in the
binding index before using either architecture-specific SBOM for admission or incident response;
the final `RELEASE_SHA256SUMS` also covers all three files.

The `lets-deployment-X.Y.Z.tar.gz` asset is the reproducible, signed-manifest-bound operator bundle.
It contains the production/provisioning Compose files, environment template, config
validator/stager, and the matching operations, provider, recovery, and release runbooks. Deploy
from that bundle and the verified OCI digest; do not copy deployment files from a mutable branch
checkout.

Read `image-digest.txt`, then verify the immutable image, its keyless signature, and the
SLSA/in-toto candidate provenance attached to that same digest. The certificate identity is
restricted to this repository's release workflow at the signed tag and the GitHub Actions OIDC
issuer:

```sh
IMAGE_REF="$(cat image-digest.txt)"
RELEASE_IDENTITY="https://github.com/AstralDeep/LETS/.github/workflows/release.yml@refs/tags/vX.Y.Z"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
cosign verify \
  --certificate-identity "$RELEASE_IDENTITY" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  "$IMAGE_REF"
cosign verify-attestation \
  --type slsaprovenance1 \
  --certificate-identity "$RELEASE_IDENTITY" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  "$IMAGE_REF"
```

Inspect the verified provenance predicate for the expected repository, workflow, tag, commit, and
candidate digest. Then read the `linux/amd64` and `linux/arm64` child digests from
`lets-container-sbom-index.json` and verify each child-manifest SBOM attestation with the same
identity and issuer, substituting the corresponding digest:

```sh
cosign verify-attestation \
  --type spdxjson \
  --certificate-identity "$RELEASE_IDENTITY" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  ghcr.io/astraldeep/lets@sha256:CHILD_MANIFEST_DIGEST
```

Compare the verified predicates with the downloaded architecture-specific SPDX documents and the
hashes recorded by `lets-container-sbom-index.json`. Archive the complete release assets, immutable
digest, signer identity, verification output, Sigstore bundle, signed manifest/config epoch, and
deployment approval together. A tag is convenient metadata; the digest is the deployment identity.

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
