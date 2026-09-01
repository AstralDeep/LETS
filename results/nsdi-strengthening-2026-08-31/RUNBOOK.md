# Reproduction runbook

Run all commands from the LETS repository root. The controller and same-host
experiments used Windows 10 and CPython 3.14.0. The remote evidence additionally
used three Linux SSH endpoints; the pinned final-dispatch replacement ran on
CPython 3.12.3 with SQLite 3.45.1. The Windows durable-core matrix used SQLite
3.50.4, uv 0.11.21, Docker 29.7.2, and Docker Compose v5.4.0, and its two
performance roots resolved to different local NVMe devices. Do not pool the
Windows and Linux results.

## Prepare the exact checkout

```powershell
git fetch --prune origin
git switch main
git pull --ff-only origin main
uv sync --locked --all-extras
```

The recorded commit is
`a9f4ba810e1741f93ba204eb782b6c4e3d409a03`. Reproduction also requires the
uncommitted harness files listed in the final section of this runbook; freeze
them before an archival rerun.

## Remote inventory and safety boundary

The SSH controller requires Paramiko 4.0.0. Install it into the existing local
virtual environment without changing project metadata:

```powershell
uv pip install --python .\.venv\Scripts\python.exe paramiko==4.0.0
```

Set the credential-file location without copying its contents into a command,
log, or result. The parser requires exactly the nine `s1`/`s2`/`s3` address,
username, and password keys described by the harness.

```powershell
$credentialFile = 'C:\path\to\servers.env'

.\.venv\Scripts\python.exe -m benchmarks.nsdi_strengthening.remote_cluster `
  --credentials $credentialFile `
  --output results\nsdi-strengthening-2026-08-31\remote\cluster-inventory.json `
  --overwrite
```

The sanitized inventory pins address and SSH-host-key hashes and verifies each
authenticated user's absolute, normalized, owned home directory. The remote
runners refuse an endpoint or home mismatch. All remote runtime, cache, source,
database, and temporary files are created under a unique directory below that
home. They do not use sudo, Docker, or system package mutation, and they leave
the remote run directory in place for audit.

## Three-host Linux partition and central baseline

```powershell
.\.venv\Scripts\python.exe -m benchmarks.nsdi_strengthening.remote_three_host `
  --credentials $credentialFile `
  --inventory results\nsdi-strengthening-2026-08-31\remote\cluster-inventory.json `
  --repository . `
  --output-dir results\nsdi-strengthening-2026-08-31\remote `
  --overwrite
```

The runner creates one real LETS SQLite warden and a separate local SQLite
executor claim store on each of three separately booted Linux SSH endpoints. It
runs all four equal/70%-skew placement and workload combinations through normal,
symmetric s1↔s2 application-gate, and recovery phases, alongside a durable
centralized SQLite counter on s2. Peer bytes are relayed by the controller over
two SSH sessions because direct high-port paths were unavailable. Consequently,
this command does not measure a direct host-to-host route, WAN latency, or a
firewall/physical partition. The executors intentionally use unanchored
development mode, and distinct endpoint/host-key/boot hashes are not proof of
physical, power, rack, or failure-domain independence.

The per-site figure and phase-end tables are pure local views of the retained
JSON. Regenerate them without credentials or SSH:

```powershell
.\.venv\Scripts\python.exe -m benchmarks.nsdi_strengthening.remote_three_host `
  --render-existing results\nsdi-strengthening-2026-08-31\remote\three-host-linux-result.json `
  --output-dir results\nsdi-strengthening-2026-08-31\remote `
  --overwrite
```

This writes `three-host-linux-per-site-timeline.svg` and the adjacent
`three-host-linux-phase-end.csv`/`.md`; it does not change the raw JSON. The
SVG is the reproducible figure source. The retained PNG beside it is only a
convenience preview rendered from that SVG.

## Pinned native-Linux final-dispatch replacement

To create a fresh run on s1:

```powershell
.\.venv\Scripts\python.exe -m benchmarks.nsdi_strengthening.remote_matched_host `
  --credentials $credentialFile `
  --inventory results\nsdi-strengthening-2026-08-31\remote\cluster-inventory.json `
  --output-dir results\nsdi-strengthening-2026-08-31\remote\matched-host `
  --overwrite
```

The controller checks out exact clean commits of AstralDeep, AstralPlane, and
LETS under the authenticated home, creates AstralDeep's canonical `.venv` with
CPython 3.12.3, and runs 10 trials × 1,000 measured operations per mode after
100 warmups per mode. The retained evidence used the following read-only
recovery command after the original benchmark completed but local retention was
stopped by an over-conservative redaction collision:

```powershell
.\.venv\Scripts\python.exe -m benchmarks.nsdi_strengthening.remote_matched_host `
  --credentials $credentialFile `
  --inventory results\nsdi-strengthening-2026-08-31\remote\cluster-inventory.json `
  --output-dir results\nsdi-strengthening-2026-08-31\remote\matched-host `
  --recover-existing `
  --overwrite
```

Recovery performs no remote writes: it selects the unique latest guarded
candidate, verifies the exact Git composition, runner and uv hashes, and exact
three-artifact set, then downloads, sanitizes, semantically revalidates, and
retains the evidence locally. It is not a way to accept arbitrary or incomplete
remote output.

For repository retention, the 54,117,510-byte sanitized JSON is stored as the
deterministic `matched-host-path.json.gz` archive. Verify its exact decompressed
content without writing another copy:

```powershell
.\.venv\Scripts\python.exe -c "import gzip,hashlib,pathlib; p=pathlib.Path(r'results\nsdi-strengthening-2026-08-31\remote\matched-host\matched-host-path.json.gz'); print(hashlib.sha256(gzip.decompress(p.read_bytes())).hexdigest())"
```

The expected decompressed SHA-256 is
`6d55ca2b60cd7d60ee7ba1c090864386494389c55b443c69b9a64a6d0eade289`.

## Same-host partition, skew, and centralized baseline

```powershell
.\.venv\Scripts\python.exe -m benchmarks.nsdi_strengthening.distributed_partition `
  --output-dir results\nsdi-strengthening-2026-08-31\distributed `
  --workspace benchmarks\results `
  --overwrite
```

This command is intentionally labeled as three logical sites on one host. It
does not accept a switch that relabels the result as independent-host evidence.

## Windows native durable-core performance matrix

```powershell
.\.venv\Scripts\python.exe -m benchmarks.nsdi_strengthening.performance_matrix `
  --trials 2 `
  --operations 50 `
  --warmup 2 `
  --delays-ms 0,1,10,100,1000 `
  --workers 1,2,4,8,16 `
  --storage-root $LOCAL_HOME\AppData\Local\lets-nsdi-storage `
  --storage-root $REPOSITORY\benchmarks\results\nsdi-storage `
  --output results\nsdi-strengthening-2026-08-31\performance `
  --overwrite
```

The run takes roughly 15 minutes because the 1-second application cells sleep
for real. Do not run other CPU- or storage-heavy workloads concurrently. Each
aggregate cell contains 100 raw operations across two trials.

## Vector workload

```powershell
.\.venv\Scripts\python.exe -m benchmarks.nsdi_strengthening.vector_workload `
  --output-dir results\nsdi-strengthening-2026-08-31\vector `
  --workspace benchmarks\results `
  --overwrite
```

## Lineage depth and branching

```powershell
.\.venv\Scripts\python.exe -m benchmarks.nsdi_strengthening.lineage_scaling `
  --output-dir results\nsdi-strengthening-2026-08-31\lineage `
  --workspace benchmarks\results `
  --overwrite
```

The default grid uses depths `1,2,4,8`, branching `1,2,4,8`, a 5,000-node cap
for complete trees, 16 authorization workers, and the depth-64/65 boundary
probe.

## Formal frontier and sensitivity

```powershell
.\.venv\Scripts\python.exe -m formal.sensitivity_frontier `
  --mode all `
  --output results\nsdi-strengthening-2026-08-31\formal\sensitivity-frontier.json `
  --markdown-output results\nsdi-strengthening-2026-08-31\formal\sensitivity-frontier.md `
  --overwrite
```

Run the separate vector checker with:

```powershell
.\.venv\Scripts\python.exe -m formal.vector_model_checker `
  --json-out results\nsdi-strengthening-2026-08-31\formal\vector-model.json `
  --markdown-out results\nsdi-strengthening-2026-08-31\formal\VECTOR-MODEL-RESULTS.md `
  --overwrite
```

## Rollback and clone matrix

```powershell
.\.venv\Scripts\python.exe -m benchmarks.nsdi_strengthening.rollback_matrix `
  --output-dir results\nsdi-strengthening-2026-08-31\rollback `
  --overwrite
```

The summary JSON records exact pytest node IDs, command, JUnit digest,
environment, limitations, and Git state.

## Implementation inventory

```powershell
.\.venv\Scripts\python.exe -m benchmarks.nsdi_strengthening.implementation_inventory `
  --root . `
  --output results\nsdi-strengthening-2026-08-31\implementation `
  --overwrite
```

## Docker acceptance

Start Docker Desktop, then run:

```powershell
.\.venv\Scripts\python.exe deploy\run_acceptance.py
```

The runner validates that every preexisting project volume is in its exact
allowlist before it performs a fresh `lets-acceptance` start. It writes current
evidence to `results/generated/docker-acceptance.json`,
`results/generated/scenario-evidence.json`, and
`results/generated/docker-compose.log`, updates the curated non-paper summary,
and stops the containers in a `finally` block. It preserves the five named
volumes for inspection until the next validated clean start.

## Tests and lint

```powershell
.\.venv\Scripts\python.exe -m pytest -q `
  --junitxml results\nsdi-strengthening-2026-08-31\raw\final-full-suite.xml

.\.venv\Scripts\ruff.exe check `
  benchmarks\nsdi_strengthening `
  formal\sensitivity_frontier.py `
  tests\benchmarks `
  tests\formal

git diff --check
```

Expected environment-gated skips on this host are the Astral layout/native
Windows alternate lane, the Docker E2E test when compose is not already running,
and the production mTLS acceptance profile. The exact Docker runner separately
enables and passes the Docker E2E scenario.

## Evidence source files to freeze

The new or extended evidence implementation is under:

```text
benchmarks/nsdi_strengthening/
formal/sensitivity_frontier.py
formal/vector_model_checker.py
tests/benchmarks/test_nsdi_*.py
tests/benchmarks/test_remote_*.py
tests/benchmarks/test_rollback_matrix.py
tests/formal/test_sensitivity_frontier.py
tests/formal/test_vector_model_checker.py
```

Do not cite an archival Git revision for these results until those files have
been reviewed, committed, and rerun from a clean worktree. The present JSON
records `dirty=true` so that boundary cannot be overlooked.
