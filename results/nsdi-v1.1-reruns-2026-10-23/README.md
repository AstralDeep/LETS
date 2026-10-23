# LETS 1.1 evidence reruns, 2026-10-23

The same-host, formal, Docker, and native-Linux host-path experiments recorded on 2026-09-02
(`results/nsdi-strengthening-2026-09-02/`, a pre-1.1 build) rerun on the LETS 1.1 runtime, so that
every retained result describes one runtime. Each run started from a clean checkout of commit
`b248f29` (the `v1.1.2` release plus SSH-key support and current pins for the remote runners). The
LETS `src/` tree there is byte-identical to `v1.1.0` (`ed5c1e4`) apart from the version string.

## What ran, and where

| Folder | Experiment | Host |
|---|---|---|
| `rollback/` | 10-scenario rollback and clone matrix (stale SQLite restores at warden and executor, clone races, crash between commit and anchor update, dropped acknowledgements, stale recovery bundles, lock contention) | Windows 10, CPython 3.14.0, SQLite 3.50.4 |
| `vector/` | Two-dimensional runtime workload: attenuation, a cross-warden `(4,10)` transfer, a child with no read units, one deliberately unclaimed receipt | same |
| `formal/` | Scalar frontier and eleven-mutant sensitivity (`sensitivity-frontier.*`); two-dimensional finite model with the cross-dimension mutant (`vector-model.json`, `VECTOR-MODEL-RESULTS.md`) | same |
| `performance/` | Durable-core latency/throughput matrix: delays 0/1/10/100/1000 ms x 1/2/4/8/16 workers x two storage roots on separate NVMe devices | same |
| `lineage/` | Lineage scaling: spine and complete trees, depth and branching 1/2/4/8, 5,000-node cap, 16 authorization workers, depth-64/65 probe | same |
| `docker/` | Three-warden Docker Compose acceptance with Toxiproxy partitions, a `SIGKILL` restart, reordered and replayed transfers, executor replay after reopen | same, Docker 29.9.2 |
| `implementation/` | Runtime file and line inventory | same |
| `remote/` | Host inventory and the matched final-dispatch benchmark through the AstralDeep host adapter (AstralDeep `3627625e`, LETS runtime `ed5c1e4`) | bare-metal x86-64 Linux, CPython 3.12.3, SQLite 3.45.1 |

The two-dimensional model, the scalar frontier, the Python bounded check
(`formal/evidence/bounded-check.json`), and the TLC fixpoint (`formal/evidence/tlc-check.json`)
check models unchanged since cross-warden spawn entered 1.1.0, so the bounded check and TLC evidence
already describe 1.1 and are not repeated here. The partition grids, the anchored runs, and the
host-mediation case study were recorded on the 1.1 runtime when they ran
(`results/fair-baselines-2026-10-15/`, `results/astraldeep-case-study-2026-10-23/`).

## Results

- Rollback and clone matrix: 10 of 10 scenarios passed.
- Two-dimensional workload: genesis `(40, 60)` conserved; free pool `(6, 10)`, lease residuals
  `(26, 23)`, consumed `(8, 27)`, spendable `(32, 33)`; 12 receipts issued, 11 claimed, and the
  unclaimed `(0, 3)` receipt stayed debited after expiry.
- Two-dimensional finite model: 8,348 states and 18,468 transitions through depth 10 with no
  violation; the cross-dimension debit mutant fails at depth 2.
- Scalar frontier: 147,673 states and 481,728 transitions through depth 9; 68,802 cutoff states with
  430,140 probed transitions and 93,066 unseen successors. All eleven mutants are killed; shortest
  counterexample depths are in `formal/sensitivity-frontier.md`.
- Performance matrix: single-worker enforce median 22.6 to 23.6 ms with 0 or 1 ms application delay
  on either storage root; enforce throughput peaks at 65.8 operations/s per shared SQLite writer.
- Lineage scaling: all 30 measured configurations passed (two complete trees above the node cap are
  skipped). The complete tree with depth 4 and branching 8 (4,681 leases, 4,096 leaf calls)
  sustained 52.7 authorizations/s with 16 workers at a 302.6 ms median and 469.7 ms 95th percentile;
  trees of up to 511 leases sustained 123.1 to 152.8/s; its median lease creation took 7.1 ms; its
  85,840 KiB database reopened in 65.1 ms. A depth-64 chain is accepted and depth 65 is refused.
- Docker acceptance: three wardens conserve the 300-unit budget (free + residual + consumed = 300,
  with 20 units transferred out and 20 in), every audit chain verifies, an out-of-order transfer
  stays behind the missing sequence and an exact replay is refused (`409 replay_detected`, also
  after a `SIGKILL` restart that keeps the signing key and acknowledgements), and the executor
  refuses a replay after reopening its store.
- Matched final dispatch (10 paired trials, 1,000 timed calls per mode after 100 warmups): `off`
  0.008 / 0.014 / 0.020 ms and `enforce` 34.0 / 37.2 / 41.3 ms at the 50th / 95th / 99th
  percentiles over 10,000 calls; enforce mean 34.2 ms (per-trial medians 33.7 to 34.5 ms), 29.3
  calls/s. Exclusive time per call: warden SQLite transaction 14.7 ms (43.0%), executor rollback
  anchor 9.7 ms (28.5%), executor claim store 5.7 ms (16.7%), everything else 4.0 ms (11.9%). The
  last 250 calls of each trial averaged 11.7% more than the first 250 (32.2 to 36.0 ms), all of it
  in the warden transaction. The warden runs unanchored; the executor uses a process-file anchor.
- Implementation inventory: 36 runtime files with 30,887 physical lines; the 18-file enforcement
  core has 16,670.

## Reproduce

From a clean checkout of this commit, with `uv sync --python 3.14 --all-extras --frozen`:

```sh
python -m benchmarks.nsdi_strengthening.rollback_matrix --output-dir OUT/rollback --overwrite
python -m benchmarks.nsdi_strengthening.vector_workload --output-dir OUT/vector --workspace benchmarks/results --overwrite
python -m formal.vector_model_checker --json-out OUT/formal/vector-model.json --markdown-out OUT/formal/VECTOR-MODEL-RESULTS.md --overwrite
python -m formal.sensitivity_frontier --mode all --output OUT/formal/sensitivity-frontier.json --markdown-output OUT/formal/sensitivity-frontier.md --overwrite
python -m benchmarks.nsdi_strengthening.performance_matrix --trials 2 --operations 50 --warmup 2 \
  --delays-ms 0,1,10,100,1000 --workers 1,2,4,8,16 \
  --storage-root STORAGE_ON_DEVICE_A --storage-root STORAGE_ON_DEVICE_B --output OUT/performance --overwrite
python -m benchmarks.nsdi_strengthening.lineage_scaling --output-dir OUT/lineage --workspace benchmarks/results --overwrite
python -m benchmarks.nsdi_strengthening.implementation_inventory --root . --output OUT/implementation --overwrite
python deploy/run_acceptance.py   # needs Docker; writes results/generated/
```

Run them one at a time on an otherwise idle machine; the performance matrix takes about 17 minutes
because its 1 s cells sleep for real. Keep `OUT` and any virtual environment outside the checkout
(or in an ignored path) so each record's Git state stays clean.

The matched final-dispatch benchmark runs on a Linux host reached over SSH. The credentials file
names each of `s1`, `s2`, `s3` with its address (`sN=`), user (`sN_USERNAME=`), and exactly one of a
password (`sN_PASS=`) or a private-key file (`sN_KEY=`):

```sh
python -m benchmarks.nsdi_strengthening.remote_cluster --credentials SERVERS.env --output OUT/remote/cluster-inventory.json --overwrite
python -m benchmarks.nsdi_strengthening.remote_matched_host --credentials SERVERS.env \
  --inventory OUT/remote/cluster-inventory.json --output-dir OUT/remote/matched-host --overwrite
```

The runner clones AstralDeep at the pinned commit on `s1`, builds its environment with the host's
CPython 3.12.3, and confines every write beneath the remote user's home.

## Retained form

Local paths in the records are replaced by `$REPOSITORY`, `$VENV`, `$OUTPUT`, `$HOME`,
`$STORAGE_ROOT_0`, and `$STORAGE_ROOT_1`; the rollback summary's artifact sizes and digests are
recomputed for the scrubbed log. `remote/matched-host/matched-host-path.json.gz` is the
deterministically gzipped sanitized benchmark JSON; its decompressed SHA-256 is
`c0ebadfb4b9728eb6d4c7f10bec4f5460878dd265db9712dffdeb45ee1cbdcd4`, the value
`remote-matched-host-manifest.json` records. The host inventory keeps only hashed addresses and host
keys.
