# Distributed acceptance evidence

Run the hard acceptance suite from a repository-local environment:

```powershell
uv sync --all-extras --frozen
uv run --frozen python deploy/run_acceptance.py
```

The runner validates that it will remove only the five named volumes owned by
the `lets-acceptance` Compose project, starts from fresh volumes, builds the
runtime image, waits for the three wardens and directed fault proxies, executes
`tests/e2e`, records machine-readable evidence under `results/generated`, and
then stops the containers while preserving the post-test volumes.

The version 2 evidence records two complementary source hashes. The full
Git-visible snapshot records the commit and ref, clean/dirty counts, a
path-redacted Git status digest, and a deterministic SHA-256 over the names and
bytes of every tracked or non-ignored untracked file. A second, non-circular
runtime/acceptance-input SHA-256 covers the files that can change the artifact
or the scenario: `.dockerignore`, `.gitattributes`, `.gitignore`,
`.python-version`, `Dockerfile`, `compose.yaml`, `pyproject.toml`, `uv.lock`,
the package metadata files copied by the image build, `src/`, top-level
`deploy/*.py`, `protocol/`, and `tests/e2e/`. Tracked evidence summaries and
paper prose are excluded from that second digest.

The runner captures both complete provenance objects before the build and
again after the scenario, before it writes evidence outputs; a source change
invalidates an otherwise passing run. It then generates the sanitized tracked
summary from the structured record. The evidence also records the Compose-file
digest, declared image references, content-addressed image IDs and available
repository digests for the LETS runtime and Toxiproxy, the signed manifest
digest observed by every node, start/completion times, elapsed durations,
host/container Python, and Git, uv, pytest, Docker Engine, and Docker Compose
versions. A supplied `LETS_BOOTSTRAP_TOKEN` is redacted from retained pytest
and Compose output.

The same one-command runner is a required GitHub Actions job on pushes to
`main`, pull requests, and manual dispatches. Its JSON, scenario record, and
Compose log are uploaded even when the acceptance step fails.

The acceptance is intentionally not an in-process simulation. It requires
three distinct container PIDs, three durable SQLite stores, three independent
Ed25519 keys, real signed HTTP exchange, a bidirectional proxy partition, an
abrupt target restart, durable replay rejection, independent executor receipt
claiming, audit-chain verification, and an aggregate conservation check.

This Compose file is a fault-test topology, not a production security profile:
it deliberately enables cleartext HTTP inside its isolated bridge network and
ships a public, test-only default bearer token. Peer messages are still bound
to method, target, body digest, timestamp, nonce, warden, and key by Ed25519.
Set `LETS_BOOTSTRAP_TOKEN` when running outside an isolated developer machine;
production deployments should use the CLI's TLS/mTLS options, secret-mounted
signing seeds, an external identity provider, and operator-controlled backups.
