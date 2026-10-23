# E1: fair-baseline family under kernel-level partitions

This directory holds the E1 experiment that replaces the earlier three-endpoint comparison. That
study compared LETS against one SQLite counter on s2 behind an
application-path gate, with a fixed schedule whose demand never reached the envelope and whose
denied requests were never retried. E1 instead compares five authority designs under the same
randomized demand and the same real network partitions, measures time-to-authorization per
request, and checks safety from an actuator-side effect log rather than the warden ledger.

Everything in `local/` was produced by the commands in this file at the commit named below.
`local/MANIFEST.json` carries the SHA-256 of every file, the controller command line, and the
source identity the controller observed.

## The terms used in this document, in plain words

| Term | What it means here |
|---|---|
| site, host | One computer taking part: `s1` and `s2` are two servers on one university LAN, `s3` a cloud VM in the US East region, `s4` to `s7` cloud instances in Ohio, Oregon, London, and Singapore. |
| envelope, units | The one shared budget of 30 actions that all the sites together may approve, and the individual actions in it. |
| request, authorized / denied / timed out | A demand for one action at one site; it is approved, refused, or still unanswered when its 20 s deadline passes. |
| partition, cut, link cut | The network between some sites is blocked for 30 s by a firewall rule on the machines themselves, so those sites cannot reach each other. |
| heal | The firewall rule is removed and the sites can reach each other again. |
| topology | Which links were blocked. The names say which: `split-s1` / `isolate-s1`, one LAN server cut off from everyone; `isolate-s7`, the Singapore machine cut off; `bridge-s3`, the two LAN servers cannot reach each other but both still reach the cloud VM; `halves`, the four nearer sites cut off from the three farther ones; `full-isolation`, every site cut off from every other; `flapping-s1-s2`, the LAN link blocked and unblocked every 3 s, like a flaky connection. |
| load 0.7x, 2x | How much work was requested: 70% of the budget, or twice the budget (so it must run out). |
| theta (θ), Zipf skew | How unevenly requests were spread over the sites: 0 is even, 1 means a few sites get most of them. |
| seed, cell, run | A cell is one combination of topology, load, and skew; each cell is run 20 times with different random request timings (seeds); each of those is a run. |
| pre-partition, in-cut, post-heal | The three phases of a run: the first 5 s with the network intact, the 30 s with it blocked, and the 15 s after it is restored. |
| completion (by deadline) | The fraction of requests approved within their 20 s deadline; the main score. |
| time to authorization (t_auth), p50 / p95 | How long a request waits for its answer; the median and the 95th percentile. |
| stranded capacity, unit-seconds | Budget sitting unused at one site while requests wait at another site that cannot reach it; the peak number of such units and how many unit-seconds they sat idle. |
| the five systems | The ways of sharing the budget that were compared: LETS (each site holds a share and can hand unused units to a site it can reach); static quotas (the budget split once and never moved); a central counter (the whole budget at one site that everyone must call, either giving up after one failed try or retrying until the deadline); a Raft quorum counter (a majority of sites must agree to each approval). |
| delegation tree, leaf, refresh | The LETS variant `lets-tree-d2-f2`, in which each site's root lease hands its units down through two levels of child leases and the four leaves at the bottom are the leases that approve requests; a refresh is the site closing the whole tree and building it again from a new root, which is how it takes up budget transferred from another site. |
| rollback anchor, stale restore | A rollback anchor is a small file, kept outside a database's own storage, that records how far the database has advanced; a database found behind its anchor is refused when it is opened. A stale restore puts a site's databases back to an earlier backup, as an operator restoring from backup would. The variants `lets-anchored`, `lets-anchored-restore@s1`, and `lets-restore@s1` run LETS with anchors, with anchors and a stale restore at `s1`, and with the same restore but no anchors. |
| in-cut probes | While the network was blocked, each site tried to contact every other site; the record shows which pairs could and could not reach each other, which proves the block was real. |
| drop counters | The number of packets the firewall rule discarded during the block. |
| safety, margin | After each run the actions that actually happened are counted and checked against the 30-unit budget; the margin is how far below 30 a run stayed. |
| schedule fidelity, cut formation, heal lateness | How closely the block and its removal happened at their scheduled moments. |
| messages per run | How many network messages a system's clients and servers exchanged in one run. |

## Commit and platforms

| Item | Value |
|---|---|
| Harness commit (LETS) | `5faf0f1` (`Add the E1 fair-baseline family experiment harness`); `local/MANIFEST.json` → `run_source` records it, with the only tracked difference being the `benchmarks/README.md` paragraph added while the grid ran |
| Results commit | the commit that adds this directory; it also moves the figure legends below the panels and makes `controller assemble` carry the run's grid metadata into `MANIFEST.json`, after which the figures and manifest were regenerated from the unchanged `runs/` and CSVs |
| Controller host | AMD Ryzen 9 7950X (16 cores), 31 GiB RAM, Windows 10 Home 10.0.19045 |
| Controller Python | CPython 3.11.15 from the repository `.venv` (`uv sync --all-extras --frozen`) |
| Site containers | Docker Desktop 29.8.2, WSL2 kernel 6.6.87.2, `python:3.12-alpine` image pinned by digest in `benchmarks/fair_baselines/docker/Dockerfile`; CPython 3.12.15, SQLite 3.53.4 |
| Site dependencies | PyNaCl 1.6.2, pysyncobj 0.3.17 |
| Fault injection | `iptables` (chain `LETS_E1`, `-s`/`-d` DROP on peer addresses) and `tc qdisc ... netem delay 25ms` on `eth0` inside each site container, executed with `docker exec` |
| Clusters | three independent Docker bridge networks (`10.231.{0,1,2}.0/24`), each with sites `s1`/`s2`/`s3` at `.11`/`.12`/`.13`; one cell per cluster at a time |

The local mode is a smoke-grade platform: nine site processes share one machine, so absolute
latencies are not WAN numbers. It exists so the whole grid can be regenerated on one machine in
under 30 minutes and so the three-endpoint run below can be reproduced by anyone with three
Linux hosts. The RTT is emulated (25 ms one-way netem on every site, 50 ms RTT between sites).

## Systems compared

| System | What it is | Client policy |
|---|---|---|
| `central-noretry@s2` | one durable SQLite counter (WAL, `synchronous=FULL`, one transaction per request, idempotent by request id) hosted on s2; other sites call it over HTTP | one attempt; an unreachable or exhausted counter is a denial (the three-endpoint study's original baseline) |
| `central-retry@s1`, `@s2`, `@s3` | the same counter placed on each site in turn | retry with jittered exponential backoff (0.2 s base, ×1.5, 1 s cap) until the request's deadline; exhausted is final |
| `static-quota` | each site holds a fixed share of the envelope in its own durable counter; no transfer ever (LETS minus escrow) | exhausted is final |
| `raft-quorum` | a three-node majority counter built on pysyncobj (Raft, 0.1 s heartbeats, 0.4–1.4 s election timeout, journal file) with the same idempotent state machine; each site's requests go to its local node and are forwarded to the leader | retry until deadline on timeout or missing leader (2 s per attempt); exhausted is final |
| `lets` | the real LETS warden (`WardenService` on SQLite, signed receipts verified and durably claimed by a local executor store) with one lease per site; when a site is exhausted with waiting requests it asks reachable peers every 0.5 s for a transfer sized to its queue, the peer grants at most half its free units through the signed voucher/acknowledgement/finalize sequence | retry until deadline while exhausted (a transfer may arrive) |

| `lets-tree-d2-f2` | the same warden, claim store, and transfer protocol as `lets`, with the root lease delegated through a spawn tree (two children per parent, two levels) whose leaf leases authorize the requests round-robin; a transfer in or out closes the whole tree bottom-up and respawns it from the refreshed root (see "Delegation under partition" below) | as `lets` |

All systems run concurrently in every run against the identical arrival sequence, so comparisons
within a run are paired. Each system keeps its own state files; nothing is shared between
systems except the network links the faults act on.

Durability parity: the central counters, static quotas, and LETS all commit with SQLite
`synchronous=FULL`. pysyncobj's journal flushes an mmap rather than fsyncing each commit, which
favours the Raft baseline slightly on latency.

## Topologies, demand, and phases

| Topology | Links cut during the window |
|---|---|
| `split-s1` | s1–s2 and s1–s3: a true two-way split {s1} \| {s2, s3} |
| `bridge-s3` | s1–s2 only: the three-endpoint study's cut, with s3 reachable from both |
| `full-isolation` | all three links: every site alone |
| `flapping-s1-s2` | s1–s2 toggles every 3 s (down, up, down, …) for the whole window |

Each run lasts 50 s of arrivals: 5 s before the partition, a 30 s partition window, and 15 s
after the heal; requests keep retrying for up to their 20 s deadline afterwards. Demand is a
Poisson process over the 50 s whose expected count is `load × envelope` (envelope 30 units, one
unit per request), with each arrival assigned to a site by Zipf weights `1/rank^θ` over (s1, s2,
s3). Loads are 0.7× and 2× the envelope; θ ∈ {0, 0.5, 1}. Shares for `static-quota` and `lets`
are equal (10/10/10). Seeds are 1–2 in the local grid (`--seeds 2`); the three-host and seven-site grids use 20.

## Metrics

- **Completions by deadline**: fraction of a run's requests authorized before their deadline;
  the per-site table reports the mean over seeds with a 95% percentile bootstrap over seeds.
- **Time-to-authorization**: arrival to actuation, measured at the requesting site with a
  monotonic clock; timeouts and denials are censored, so every CDF plateaus at the completion
  fraction.
- **Stranded capacity**: at every 0.1 s step, the units held by a pool that no site with a
  waiting request can use through the system's own path (its own site, a direct link for a
  LETS transfer, the counter's host, or a majority for Raft); reported as the peak and the
  integral in unit-seconds, reconstructed offline from `events.csv` and `faults.csv`.
- **Safety**: every actuation is appended to a per-site SQLite effect log that is separate from
  the warden ledger and from every counter; the controller unions the three logs per system and
  requires no duplicate request ids, `effects ≤ envelope`, and `effects == authorized records`.
  `runs.csv` carries the margin per run and system.
- **Messages**: application messages sent from each site per system (requests and responses,
  Raft messages at the transport, LETS voucher traffic); `messages.csv` and the per-site table.
- **Fault evidence**: `faults.csv` has every fault command with its send and return offsets (a
  cut is one batched `iptables` script per site, applied to all sites concurrently; the in-cut
  probes run on their own thread so the heal fires at its scheduled offset);
  each run's JSON keeps the peer probes taken inside the cut (the cut links are unreachable, the
  others are not) and the `LETS_E1` chain's dropped-packet counters read just before each heal.

## Outputs in `local/`

| File | Content |
|---|---|
| `runs/<run_id>.json.gz` | the full record of one run: configuration, per-site records, events, snapshots, effect-log summaries, faults, probes, drop counters, safety verdicts |
| `requests.csv` | one row per request and system (outcome, reason, time-to-authorization, attempts, client messages) |
| `events.csv` | free-unit, waiting-count, transfer, lease, and Raft state events with run offsets |
| `faults.csv` | the fault timeline |
| `messages.csv`, `runs.csv` | per-site message counts and per-run safety/outcome summaries |
| `per-site.md`, `per-site.csv` | the per-site results table (the analogue of `three-host-linux-phase-end.md`) |
| `summary.csv` | the same aggregated per topology × load × θ × system |
| `MANIFEST.json` | file digests, command line, source and environment identity |

## Highlights of the local grid (48 runs, 13,923 requests, 2 seeds per cell)

All numbers below come from `local/summary.csv`, `local/per-site.csv`, and `local/runs.csv`;
two seeds per cell is a smoke grid, so treat its confidence intervals as wide.

- **Safety.** Every one of the 48 × 7 run-system pairs satisfied `effects ≤ 30` with no duplicate
  actuation and `effects == authorized records`; the minimum margin is 0, so the ceiling bound in
  every 2× cell. The `LETS_E1` chains dropped 20,454 packets across the grid, and every in-cut
  probe over a cut link failed while probes over intact links succeeded.
- **Completions at 0.7× load, requests arriving inside the 30 s window (all topologies and
  skews pooled, 320 requests per system):** LETS 1.00, static quotas 0.97, central with retry
  0.87–0.92 depending on placement, Raft 0.79, and the three-endpoint study's no-retry central counter 0.55.
  Retry alone lifts the central baseline from 0.55 to about 0.9; the remaining loss is the
  requests whose 20 s deadline ends before the 30 s cut heals.
- **Topology matters more than placement for the baselines.** At 0.7× and θ=1, per-topology
  completion for the whole run is: `split-s1` LETS 0.93, static 0.81, central-retry 0.84–0.88,
  Raft 0.76; `bridge-s3` LETS 1.00, static 0.93, central-retry 0.88–1.00 (1.00 only when the
  counter sits on the bridging site s3), Raft 1.00; `full-isolation` LETS 1.00, static 0.98,
  central-retry 0.85–0.93, Raft 0.63; `flapping-s1-s2` LETS 1.00, static 0.85, central-retry
  1.00, Raft 1.00. LETS loses completions only on `split-s1`, where s1 carries 54% of demand with
  a third of the authority and cannot reach either peer for a transfer until the heal.
- **At 2× load every system completes 0.45–0.55** because 30 units cannot cover roughly 60
  requests; the comparison then is time-to-authorization and waste, not completions. Raft under
  `full-isolation` falls to 0.36 because pysyncobj queues commands while no leader exists and
  applies them after the heal: all 30 units were consumed in each of those runs while only 17–23
  authorizations reached a client before its deadline, so 7–13 units were spent on requests that
  had already timed out. The effect log shows the same 17–23, which is why the safety check still
  passes.
- **Time-to-authorization before the partition (p50 / p95 over 194 authorized requests per
  system):** static quotas 2.1 / 4.2 ms, LETS 8.2 / 14.3 ms (warden commit, receipt verification,
  executor claim), central counters 102 / 105 ms (one netem round trip plus TCP setup), Raft 219
  / 295 ms (forward to leader plus a majority round). Inside the window the CDFs separate: LETS and
  static quotas stay flat near their final value within milliseconds, the central and Raft curves
  climb in steps at the heal and at each retry.
- **Stranded capacity.** Under `split-s1` at 0.7× and θ=1, LETS strands a peak of 14 units for
  55 unit-seconds per run (s2/s3 authority that s1's queue cannot reach), static quotas strand up
  to 19 units, and the central and Raft pools strand 25–29 units for 550–660 unit-seconds because
  the whole envelope is unreachable from the cut-off site.
- **Messages per run.** Static quotas send none; LETS sends 2–13 messages per run when transfers
  are rare and 300–380 under 2× load, where exhausted sites poll peers every 0.5 s to no avail;
  central counters send roughly two messages per remote attempt (24–212 per run); Raft sends
  2,000–3,000 per run, dominated by heartbeats.

## Regenerating the local grid

From the LETS repository root with Docker running:

```bash
uv sync --all-extras --frozen
uv run python -m benchmarks.fair_baselines.local_cluster up --work-dir benchmarks/results/fair-baselines/local --clusters 3
uv run python -m benchmarks.fair_baselines.controller run --endpoints benchmarks/results/fair-baselines/local/endpoints.json --output results/fair-baselines-2026-10-15/local --seeds 2
uv run python -m benchmarks.fair_baselines.analysis --output results/fair-baselines-2026-10-15/local
uv run python -m benchmarks.fair_baselines.local_cluster down --work-dir benchmarks/results/fair-baselines/local
```

The controller defaults are the grid above (`--topologies split-s1 bridge-s3 full-isolation
flapping-s1-s2 --loads 0.7 2.0 --thetas 0 0.5 1 --pre-s 5 --partition-s 30 --post-s 15
--deadline-s 20 --rtt-ms 50`). It skips cells whose run file already exists, so an interrupted
grid resumes; `--overwrite` reruns everything. `benchmarks/results/` is ignored by Git and holds
the generated compose file and the per-invocation shared token.

## Headline metrics from the committed runs

The headline metrics for both grids (completion at 0.7x load with theta = 1, the pre-break median
time to authorization, stranded unit-seconds under `split-s1`/`isolate-s1`, the safety totals,
and the 95% seed-bootstrap intervals with their widest widths) come from the committed run files
alone. From a clone of this repository:

```bash
uv sync --all-extras --frozen
uv run python -m benchmarks.fair_baselines.report --grid three-host=results/fair-baselines-2026-10-15/three-host --grid seven-site=results/fair-baselines-2026-10-15/seven-site --write results/fair-baselines-2026-10-15
```

The command regenerates `requests.csv` and `events.csv` from `runs/` when they are absent (about
30 s for both grids), then writes `report.md` and `report.json` next to the grid
directories; the committed copies of those two files are its output on the retained runs.
Completion is pooled over seeds (authorized requests divided by all requests), the bootstrap
resamples the 20 seeds with a fixed generator seed, and the latency column pools the authorized
requests that arrived in the first 5 s of every run in the grid.

## Running on remote endpoints (three or more sites)

The controller is topology-agnostic: it only needs, per site, a control URL, the address the
other sites use to reach it, and a privileged command prefix. The number of sites and their
aliases come from the endpoints file, so the same harness runs the original three-host grid and a
multi-region grid (for example two UK hosts, one Azure VM, and four AWS regions). On each endpoint
(Ubuntu 22.04 or 24.04 as inventoried in
`results/nsdi-strengthening-2026-09-02/remote/cluster-inventory.json`):

1. Check out this commit, install CPython 3.12 with uv as the three-host harness does, and run
   `uv sync --extra benchmarks --frozen`.
2. Start the site agent with a shared random token and the site's alias, binding the host's
   private address so the peers reach it directly (no controller relay):

   ```bash
   LETS_E1_TOKEN="$(cat ~/.lets-e1/token)" uv run python -m benchmarks.fair_baselines.site_agent --site uk1 --bind 0.0.0.0 --port 9701 --state-root ~/.lets-e1/state
   ```

   An alias is 1-32 letters, digits, or underscores (`uk1`, `use2`, `aws_euw2`); hyphens are not
   allowed because link labels and topology names join aliases with `-`. The peer API on 9701 and
   the Raft port 9801 must be open between every pair of hosts (security groups and NSGs included);
   the control API (also 9701, bearer token) should be reachable from the controller only, for
   example through an SSH port forward to `127.0.0.1:97xx` on the controller.
3. Give the controller a way to run `iptables` and `tc` as root on each host. The supported
   remote form is a persistent sudo-over-SSH session per site,
   `"fault_ssh": {"host": "<host>", "user": "<user>", "key_file": "<key>"}` (optional `port` and
   `prefix`, default `["sudo", "-n"]`), which needs passwordless sudo for the user and keeps one
   authenticated connection open for the whole grid, reconnecting once if it drops. Do not drive
   remote hosts through a per-command `ssh` prefix: the first three-host grid did, and the 3 s
   `flapping` toggles opened connections faster than sshd's default `MaxStartups` admits, so 76 of
   120 flapping cells failed with `kex_exchange_identification: Connection reset` while every other
   topology passed; the block was rerun with `fault_ssh`. A command-prefix list `fault_exec` remains
   for local Docker sites (`["docker", "exec", "lets-e1-uk1", "sh", "-c"]`, which keeps argument
   boundaries) and for any other prefix that preserves them; a prefix that goes through a login
   shell needs `"fault_exec_quote": true`. Set `"interface"` to the host's data interface if it is
   not `eth0` (`ens5` on the AWS instances). A site whose advertised `peer_ip` is not an address on
   its own interfaces (an Azure VM behind a NAT public address, for example) still works: the Raft
   node listens on every interface for its advertised port.
4. Write the endpoints file. The top-level `sites` list is the ordered roster: it fixes the Zipf
   rank order of demand (the first site is the heaviest), the order in which equal shares absorb
   the envelope remainder, the Raft membership, and the site order in every table and figure.
   Every cluster must describe exactly those aliases. When `sites` is absent the roster is
   `["s1", "s2", "s3"]`, which is what the three-host run used.
   `benchmarks/fair_baselines/examples/seven-site-endpoints.json` is a complete seven-site
   example with placeholder addresses; the three-site shape is:

   ```json
   {
     "token_env": "LETS_E1_TOKEN",
     "sites": ["s1", "s2", "s3"],
     "clusters": [{"name": "three-host", "sites": {
       "s1": {"control_url": "http://127.0.0.1:9711", "peer_ip": "<s1 private ip>", "peer_port": 9701, "raft_port": 9801, "interface": "eth0", "fault_ssh": {"host": "<s1>", "user": "<user>", "key_file": "<key>"}},
       "s2": {"control_url": "http://127.0.0.1:9712", "peer_ip": "<s2 private ip>", "peer_port": 9701, "raft_port": 9801, "interface": "eth0", "fault_ssh": {"host": "<s2>", "user": "<user>", "key_file": "<key>"}},
       "s3": {"control_url": "http://127.0.0.1:9713", "peer_ip": "<s3 private ip>", "peer_port": 9701, "raft_port": 9801, "interface": "eth0", "fault_ssh": {"host": "<s3>", "user": "<user>", "key_file": "<key>"}}
     }}]
   }
   ```

5. Choose topologies and systems for the roster. Topology names are parametric and resolved
   against the roster, so a seven-site run reads as what it does:

   | Name | Links cut during the window |
   |---|---|
   | `isolate-<site>` | every link of that site (a true split {site} \| rest) |
   | `halves` | every link between the first ⌈N/2⌉ sites of the roster and the rest |
   | `full-isolation` | all N(N-1)/2 links: every site alone |
   | `cut-<a>-<b>` | the one link a–b |
   | `flapping-<a>-<b>` | the link a–b toggles every 3 s for the whole window |

   The three-site names `split-s1`, `bridge-s3`, and `flapping-s1-s2` still resolve on the
   `s1`/`s2`/`s3` roster (`split-<site>` is a synonym of `isolate-<site>`; `bridge-<site>` exists
   only for three sites), so the three-host grid above regenerates unchanged. With no
   `--topologies` the controller runs `split-s1 bridge-s3 full-isolation flapping-s1-s2` on the
   default roster and `isolate-<first> halves full-isolation flapping-<first>-<second>` on any
   other. With no `--systems` it runs `central-noretry@<second site>`, `central-retry@<site>` for
   every site, `static-quota`, `raft-quorum`, and `lets`; pass `--systems` to keep the per-run
   process count down on a large roster. Shares for `static-quota` and `lets` are the envelope
   divided equally with the remainder going to the first sites of the roster (30 units over seven
   sites: 5, 5, 4, 4, 4, 4, 4); `--placements proportional` follows the Zipf weights, and
   `--placements explicit --shares uk1=9 uk2=6 az1=3 use2=3 usw2=3 euw2=3 apse1=3` fixes them
   (every site at least one unit, summing to the envelope).
6. Run the grid from the controller machine and render:

   ```bash
   LETS_E1_TOKEN=... uv run python -m benchmarks.fair_baselines.controller run --endpoints seven-site-endpoints.json --output results/fair-baselines-2026-10-15/seven-site --seeds 20 --rtt-ms 0
   uv run python -m benchmarks.fair_baselines.analysis --output results/fair-baselines-2026-10-15/seven-site
   ```

   480 cells at about 75 s each is roughly 10 hours on one cluster (the 600-cell seven-site grid
   below took 13.3 hours at about 80 s per cell); clocks must agree to within a
   second (NTP) because the synchronized start uses wall-clock time, while every latency is
   measured with each site's monotonic clock. Use `--rtt-ms 0` to measure the real WAN RTT instead
   of adding netem delay. The per-site table has one row per site.

The N-site path can be smoke-tested on one Docker machine with
`local_cluster up --sites uk1 uk2 az1 use2 usw2 euw2 apse1 --clusters 1`, which renders one
container per site and writes an endpoints file with that roster.

The three-host run (2026-10-17) and the seven-site run (2026-10-17/18) were executed from this
branch; their results are in `three-host/` and `seven-site/` and described below.

## Three-host results (480 runs, 135,093 requests, 20 seeds per cell)

The full grid on three real hosts: `s1` and `s2` are two Linux servers on one university LAN
(80 and 40 cores, Ubuntu 24.04 and 22.04, 0.18 ms RTT between them) and `s3` is an Azure VM in
East US (4 cores, Ubuntu 24.04) 23 ms away from both; the controller ran on a Windows 10 desktop
over a VPN, reaching each agent through an SSH port forward and injecting faults as root through
one persistent SSH session per site. No netem delay was added (`--rtt-ms 0`): the latencies below
are the real network. Every site ran CPython 3.12.13, SQLite 3.53.1, LETS 1.1.0, PyNaCl 1.6.2, and
pysyncobj 0.3.17 from a uv-managed environment (uv 0.11.21). The agents bound `0.0.0.0:9701` with
the peer and Raft ports opened only to each other.

The directory holds the grid's final execution: all 480 cells from harness commit `cd1dcc7` on
2026-10-17 02:30 to 09:48 UTC in one invocation (`three-host/MANIFEST.json`, `run_history`). Two
earlier executions were discarded and are not part of this directory: the first drove faults
through one `ssh` process per iptables command and lost 76 `flapping-s1-s2` cells to sshd's
connection rate limit, and both it and its flapping rerun let the in-cut probe pass delay the
final heal (median 5.6 s, maximum 22.7 s past the 35 s offset), so their partition windows ran
long. In the final execution every cut formed within 0.23 s of its offset and every final heal
landed within 0.17 s. The run files, figures, aggregates, and manifest are committed; `events.csv`
(28 MB) and `requests.csv` (20 MB) are regenerated by `controller assemble` and listed with their
digests in the manifest rather than committed.

- **Safety.** All 3,360 run-system pairs satisfied `effects <= 30`, `effects == authorized
  records`, and no duplicate actuation; the minimum margin is 0 (the ceiling bound in 2x cells)
  and the maximum 25. Every run dropped packets on its `LETS_E1` chains (184,345 in total); the
  2,160 in-cut probes of the three static topologies match their cut sets exactly (1,440 cut links
  unreachable, 720 intact links reachable, zero mismatches).
- **Completions at 0.7x load (mean cell completion over topologies and skews):** LETS 1.00, static
  quotas 0.94, central with retry 0.92 to 0.94 by placement, Raft 0.88, the three-endpoint study's no-retry central
  counter 0.74. At theta=1 per topology: `split-s1` LETS 0.99, static 0.90, central-retry 0.89 to
  0.90, Raft 0.82; `bridge-s3` LETS 1.00, static 0.93, central-retry 0.88 to 1.00 (1.00 only with the
  counter on the bridging site), Raft 1.00; `full-isolation` LETS 1.00, static 0.90, central-retry
  0.85 to 0.93, Raft 0.68; `flapping-s1-s2` LETS 1.00, static 0.87, central-retry 1.00, Raft 1.00.
- **At 2x load every system completes about 0.50**, the envelope being the binding constraint;
  Raft under `full-isolation` falls to 0.27 at theta=1 for the reason the local grid showed
  (commands queued without a leader are applied after the heal, consuming units for requests that
  had already timed out). The effect logs agree with the delivered authorizations, so the safety
  check still passes.
- **Time-to-authorization before the partition (p50 / p95, about 1,850 to 1,920 authorized requests
  per system arriving in the first 5 s):** static quotas 4.6 / 12.7 ms, local central counters 5.2
  to 5.7 / 45 ms (the p95 is the Azure site's round trip), the Azure-hosted counter 46 / 51 ms, LETS
  18.1 / 55.4 ms (warden commit, receipt verification, executor claim, plus the Azure site's
  transfer path), Raft 230 / 302 ms (forward to the leader plus a majority round across the WAN).
- **Stranded capacity under `split-s1` at 0.7x, theta=1 (peak units / unit-seconds per run):** LETS
  20 / 14, static quotas 20 / 2, the central counters 30 / 264 to 653, Raft 30 / 633.
- **Messages per run:** static quotas 0; LETS 2 to 452 (the upper range is 2x load, where exhausted
  sites poll peers); central counters 18 to 243; Raft 693 to 2,595, dominated by heartbeats.

Compared with the local Docker grid, the ordering of systems is unchanged while the absolute
latencies are real: the LAN pair makes the local central counters and static quotas faster than the
emulated 25 ms netem path, the Azure site adds a 46 ms round trip to everything that crosses it,
and Raft's leader placement shows up directly in its latency.

## Seven-site results (600 runs, 167,797 requests, 20 seeds per cell)

The grid on seven real sites across five networks. `s1` and `s2` are the two university LAN
servers of the three-host run (80 and 40 cores, Ubuntu 24.04 and 22.04), `s3` is the Azure VM in
East US (4 cores, Ubuntu 24.04), and `s4` to `s7` are AWS `t3.medium` instances (2 vCPUs, 4 GiB,
Ubuntu 24.04.5, kernel 7.0.0-1014-aws) in us-east-2 (Ohio), us-west-2 (Oregon), eu-west-2
(London), and ap-southeast-1 (Singapore), each behind an Elastic IP with the peer and Raft ports
opened only to the other six sites. The controller ran on the same Windows 10 desktop over a VPN,
reaching each agent through an SSH port forward and injecting faults as root through one
persistent SSH session per site; no netem delay was added (`--rtt-ms 0`). Every site ran CPython
3.12.13, SQLite 3.53.1, LETS 1.1.0, PyNaCl 1.6.2, and pysyncobj 0.3.17 from a uv-managed
environment (uv 0.11.21). The round-trip times between sites, measured after the grid as the
median TCP connect time of seven connections from each site to each peer's agent port, in
milliseconds:

| from \ to | s1 | s2 | s3 | s4 | s5 | s6 | s7 |
|---|---:|---:|---:|---:|---:|---:|---:|
| s1 (LAN) | | 0.4 | 20 | 23 | 68 | 122 | 242 |
| s2 (LAN) | 0.3 | | 20 | 23 | 68 | 123 | 242 |
| s3 (Azure East US) | 20 | 20 | | 19 | 76 | 78 | 222 |
| s4 (AWS Ohio) | 22 | 23 | 19 | | 50 | 86 | 209 |
| s5 (AWS Oregon) | 68 | 68 | 76 | 46 | | 127 | 159 |
| s6 (AWS London) | 122 | 122 | 79 | 87 | 127 | | 157 |
| s7 (AWS Singapore) | 242 | 242 | 221 | 210 | 159 | 156 | |

The grid is `isolate-s1 isolate-s7 halves full-isolation flapping-s1-s2` × loads 0.7 and 2 ×
θ 0, 0.5, 1 × 20 seeds, with seven systems in every run: `lets`, `static-quota`, `raft-quorum`
(seven Raft nodes), `central-noretry@s2`, and `central-retry` with the counter on `s1` (LAN), `s4`
(Ohio), and `s7` (Singapore); the other four `central-retry` placements were left out to keep the
process count per site at seven. `halves` cuts the twelve links between {`s1`, `s2`, `s3`, `s4`}
and {`s5`, `s6`, `s7`}; `full-isolation` cuts all 21 links. Equal shares give `s1` and `s2` five
units and the other five sites four. The 600 cells ran in one invocation of harness commit
`902a8e6` from 2026-10-17 11:29 to 2026-10-18 00:49 UTC (`seven-site/MANIFEST.json`,
`run_history`), about 80 s per cell. One earlier execution was discarded and is not part of this
directory: it applied cuts one `iptables` command at a time, so the 21-link `full-isolation` cut
took 25 s to form through 84 sequential commands and 24 of its cells overran the fault thread's
deadline, and its in-cut probe pass delayed every final heal by about 15 s. The run files,
figures, aggregates, and manifest are committed; `events.csv` (37 MB) and `requests.csv` (26 MB)
are regenerated by `controller assemble` and listed with their digests in the manifest rather
than committed.

- **Schedule fidelity.** A cut or heal is one batched script per site, dispatched to every
  affected site concurrently. Every fault command left the controller within 0.25 s of its offset
  in 559 cells, within 0.5 s in 574, within 1.0 s in 598, and within 1.5 s in all 600; the
  partition had formed on the last site a median 0.13 s after the offset on the two-site flapping
  link and about 0.6 s on the seven-site cuts (maximum 2.0 s), and every final heal had completed
  on all seven sites within 1.82 s, the bound being the sudo-over-SSH round trip to Singapore.
  The analysis reconstructs stranded capacity against the recorded return time of each fault
  command, not its scheduled offset.
- **Safety.** All 4,200 run-system pairs satisfied `effects <= 30`, `effects == authorized
  records`, and no duplicate actuation; the minimum margin is 0 (the ceiling bound in 2x cells)
  and the maximum 28. Every run dropped packets on its `LETS_E1` chains (415,963 in total). The
  20,160 in-cut probes of the four static topologies match their cut sets exactly (10,800 cut
  links unreachable, 9,360 intact links reachable, zero mismatches); the 5,040 probes on the
  flapping link are recorded but, the link toggling every 3 s, are not checked against a fixed
  set.
- **Completions at 0.7x load (mean cell completion over topologies and skews):** LETS 1.00
  (0.999), central with retry 0.94, 0.92, and 0.88 with the counter in Ohio, on the LAN, and in
  Singapore, Raft 0.88, static quotas 0.87, the no-retry counter 0.82. At theta=1 per topology:
  `isolate-s1` LETS 1.00, central-retry 0.84 to 0.93, Raft 0.89, static 0.83, no-retry 0.79;
  `isolate-s7` LETS 1.00, central-retry 0.99 with the counter on the LAN or in Ohio but 0.82 with
  it on the isolated Singapore site, Raft 0.97, no-retry 0.97, static 0.79; `halves` LETS 1.00,
  central-retry 0.96 with the counter in the four-site half and 0.79 with it in the three-site
  half, Raft 0.93, no-retry 0.90, static 0.83; `full-isolation` LETS 1.00, central-retry 0.82 to
  0.89, static 0.81, Raft 0.66, no-retry 0.52; `flapping-s1-s2` LETS, central-retry, and Raft
  1.00, no-retry 0.91, static 0.80.
- **At 2x load every system completes about 0.50**, the envelope being the binding constraint,
  except static quotas at 0.44 to 0.47 (fixed shares cannot follow the skewed demand) and Raft
  under `full-isolation` at 0.27 for theta=1, for the reason the local and three-host grids showed.
- **Time-to-authorization before the partition (p50 / p95, about 2,160 to 2,380 authorized
  requests per system arriving in the first 5 s):** static quotas 5.2 / 8.0 ms; LETS 28.4 / 46.2
  ms, set by the local warden commit rather than by distance (p50 by site: 17 ms on the LAN
  servers, 28 to 32 ms on the 2-vCPU AWS instances, 44 ms on the 4-core Azure VM); the LAN-hosted
  counters 43 / 483 ms (the p50 is the Azure and Ohio sites' round trip, the p95 Singapore's); the
  Ohio-hosted counter 50 / 424 ms; the Singapore-hosted counter 447 / 516 ms; Raft 295 / 666 ms
  (forward to the leader plus a majority round across five networks; p50 by site rises from 257 ms
  on `s1` to 454 ms on `s7`).
- **Stranded capacity at 0.7x, theta=1 (peak units / unit-seconds per run):** under `isolate-s1`
  LETS 22 / 70, static quotas 26 / 3.5, the central counters 28 to 30 / 161 to 693, Raft 29 / 483;
  under `isolate-s7` LETS 25 / 5.0, the central counters 29 / 40 to 228 with the counter elsewhere
  and 30 / 770 with it on the isolated site, Raft 29 / 209; under `full-isolation` LETS 25 / 130,
  static 26 / 3.2, the central counters 30 / 391 to 786, Raft 30 / 799.
- **Messages per run:** static quotas 0; LETS 8 to 1,495 (the upper range is 2x load, where
  exhausted sites poll six peers); central counters 22 to 283; Raft 2,609 to 8,437, dominated by
  heartbeats among seven nodes.

The ordering of systems is the one the three-host grid gave, and the spread of the sites widens
the gaps that come from placement. Every central counter is far from most of its requesters, so
its time-to-authorization is the requester's distance to the counter (43 to 447 ms at the median
against 5 ms for a local quota and 28 ms for LETS), and its completion under a partition depends
on which side of the cut the counter sits (0.99 against 0.82 under `isolate-s7`, 0.96 against
0.79 under `halves`). Raft with seven nodes across a 240 ms diameter pays a 295 ms median round
and 2,600 to 8,400 messages per run. LETS's completion does not depend on where anything is
placed, because every site authorizes from its own lease and only the transfers cross the
network.

## Delegation under partition (local grid, 8 runs, 346 requests, 2 seeds per cell)

Every LETS site in the grids above holds its budget in one root lease, so those grids never
exercised the design's central mechanism, a parent agent handing part of its budget to child
agents. The system `lets-tree-d2-f2` closes that gap: it is
the same warden, executor claim store, and transfer protocol as `lets`, run in the same cells and
against the same arrivals, with one difference in how each site holds its share.

**What the tree is.** At the start of a run each site issues its root lease from its share as
before, then the root spawns two children, each child spawns two children of its own, and the
four grandchildren (the leaves) are the leases that authorize the protected calls; a site's
requests are dealt to the leaves in turn. The share is split evenly at each level with the
remainder going to the first children (10 units become 5/5, then 3/2 and 3/2), and a child that
would receive no unit is not spawned, so a one-unit site gets a three-lease chain with one leaf.
With the 30-unit envelope over three sites each site runs a seven-lease tree with four
leaves, and every parent has delegated its whole residual (`depth` counts the levels below the
root; `fanout` is the children per parent; both are part of the system name).

**How an exhausted tree takes up a transfer.** Two rules of the design shape this. A parent cannot
close while any of its children is live, and no operation adds budget to a live lease. A transfer therefore lands in the receiving warden's free pool, from which only a new
root lease can be issued. The harness handles it as a *refresh*: it closes every live lease of the
tree bottom-up (leaves, then their parents, then the root; each close returns that lease's unspent
units to the free pool), issues a new root from the whole pool, and spawns the tree again. The
same teardown funds an outgoing transfer: the site closes its tree, prepares the voucher from the
pool, and rebuilds the tree from the remainder. The one-lease system does the same with one close
and one issue, so the difference between the two systems is exactly the delegation cost.

**What is recorded.** Every build or refresh is a `tree_build` event in `events.csv` whose value is
the number of lease operations (issue, spawn, and close calls to the warden) and whose detail
holds the reason (`initial`, `in-<n>` for a transfer taken up, `out-<site>-<n>` for a transfer
granted), the resulting tree size, and the wall time in microseconds. Each site's snapshot carries
the tree shape, the live leases and leaves, the leaf residuals, and the lifetime counts of builds,
lease operations, and build time. `analysis.py` reduces the events to `delegation.csv` and
`delegation.md`, and `report.py` adds a delegation-tree row and a lease-tree cost table to the
grid report. Spawns and closes are local warden transactions; they send no network messages.

**Local-grid check.** `split-s1` and `full-isolation` at 0.7x load, skew 0 and 1, two seeds, with
`lets` and `lets-tree-d2-f2` in every run (`local-delegation/`). The partitions were real: all 48
in-cut probes match the cut sets, every cut had formed within 0.19 s of its offset and every heal
within 0.25 s. Safety held for all 16 run-system pairs (`effects <= 30`, no duplicate actuation,
`effects == authorized records`; the minimum margin is 0 because the skewed `split-s1` cells spent
the whole envelope).

| Cell (0.7x) | Requests / run | Completion `lets` | Completion `lets-tree-d2-f2` | Stranded peak / unit-s | Messages / run (`lets` / tree) |
|---|---:|---:|---:|---|---|
| `full-isolation`, skew 0 | 13.5 | 1.00 (27/27) | 1.00 (27/27) | 18 / 1.8 | 0 / 0 |
| `full-isolation`, skew 1 | 20.5 | 1.00 (41/41) | 1.00 (41/41) | 20 / 6.2 | 2 / 2 |
| `split-s1`, skew 0 | 23.5 | 1.00 (47/47) | 1.00 (47/47) | 15 / 1.2 (`lets`), 15 / 1.4 (tree) | 3 / 3 |
| `split-s1`, skew 1 | 29.0 | 0.93 (54/58) | 0.93 (54/58) | 17 / 54.6 | 98 / 100 |

The tree completes exactly the same requests as the one-lease system in every cell, strands the
same capacity to within the timing of one transfer (the stranding reconstruction depends only on
where the units sit, which the tree does not change), and sends the same transfer traffic within
one request. Time to authorization before the break is 15.7 / 20.7 ms (p50 / p95 over 17
authorized requests) for the tree against 15.4 / 20.6 ms for one lease; the leaf authorization
carries a two-level ancestor path, which the warden checks for revocation, and costs well under a
millisecond more.

| 0.7x cells | Leases per site tree | Initial build per site | Refresh (close all, reissue, respawn) | Refreshes / run | Lease ops / run | Build time / run |
|---|---:|---|---|---:|---:|---:|
| `lets` | 1 | 1 op, 3.2 to 4.0 ms (p50) | 2 ops, 7.6 to 8.6 ms (p50), 27 ms max | 0 to 5 | 3 to 12 | 10 to 64 ms |
| `lets-tree-d2-f2` | 7 | 7 ops, 24 to 28 ms (p50) | 10 to 12 ops, 42 to 50 ms (p50), 87 ms max | 0 to 5 | 21 to 70 | 73 to 306 ms |

A refresh of the seven-lease tree is about six times the work of the one-lease refresh (12 lease
operations against 2) and takes 42 to 50 ms at the median on this machine, about 4 ms per lease
operation; the busiest cell (`split-s1` at skew 1, five transfers per run into the cut-off site
after the heal) spends 306 ms per run rebuilding trees. During a refresh the site's requests wait
for the warden lock, so the cost shows up as up to about 90 ms of extra latency for the few
requests that arrive while a transfer is being taken up, not as lost completions. The grid report is in
`local-delegation/report.md`.

Regenerate the grid with the local Docker clusters (about six minutes on two clusters):

```bash
uv run python -m benchmarks.fair_baselines.local_cluster up --work-dir benchmarks/results/fair-baselines/local-deleg --clusters 2
uv run python -m benchmarks.fair_baselines.controller run --endpoints benchmarks/results/fair-baselines/local-deleg/endpoints.json --output results/fair-baselines-2026-10-15/local-delegation --topologies split-s1 full-isolation --loads 0.7 --thetas 0 1 --seeds 2 --systems lets lets-tree-d2-f2
uv run python -m benchmarks.fair_baselines.analysis --output results/fair-baselines-2026-10-15/local-delegation --title "E1 delegation under partition: local grid"
uv run python -m benchmarks.fair_baselines.report --grid local-delegation=results/fair-baselines-2026-10-15/local-delegation --write results/fair-baselines-2026-10-15/local-delegation
uv run python -m benchmarks.fair_baselines.local_cluster down --work-dir benchmarks/results/fair-baselines/local-deleg
```

**Three-host grid.** The same cells as the three-host grid above were then run on the real hosts
(next section), with the seven original systems and the tree in every run so that every comparison is paired:

```bash
LETS_E1_TOKEN=... uv run python -m benchmarks.fair_baselines.controller run --endpoints three-host-endpoints.json --output results/fair-baselines-2026-10-15/three-host-delegation --seeds 20 --rtt-ms 0 --systems central-noretry@s2 central-retry@s1 central-retry@s2 central-retry@s3 static-quota raft-quorum lets lets-tree-d2-f2
uv run python -m benchmarks.fair_baselines.analysis --output results/fair-baselines-2026-10-15/three-host-delegation
uv run python -m benchmarks.fair_baselines.report --grid three-host-delegation=results/fair-baselines-2026-10-15/three-host-delegation --write results/fair-baselines-2026-10-15/three-host-delegation
```

The endpoints file is the one of the three-host run above (`s1` <s1-ip> on `eno50`, `s2`
<s2-ip> on `enp5s0np0`, `s3` <s3-ip> on `eth0`, control through SSH port forwards
9731 to 9733, faults through persistent sudo-over-SSH). The 480 cells took about nine hours. Before
the run the hosts needed the openings that the 2026-10-18 teardown had removed: passwordless sudo
for the fault user on `s1` and `s2`, the `lets-e1` ufw rules admitting TCP 9701 and 9801 between
the three hosts, and the Azure network-security-group rule admitting the same ports from the two
LAN hosts, plus the harness deployed to `~/lets-e1/src` and the site agents started; all of it was
removed again after the run.

## Three-host delegation results (480 runs, 154,392 requests, 20 seeds per cell)

The three-host grid above, rerun on the same hosts (`s1` and `s2` on
the university LAN, `s3` the Azure VM in East US, controller on the Windows desktop over the VPN,
faults through persistent sudo-over-SSH, no netem), with the seven original systems and
`lets-tree-d2-f2` in every run, so every number below is paired with one-lease LETS on the same
arrivals (`three-host-delegation/`). The sites ran harness commit `a85e177` (deployed as a Git
archive, CPython 3.12.13, SQLite 3.53.1, LETS 1.1.0, PyNaCl 1.6.2, pysyncobj 0.3.17 under uv
0.11.21) and the controller ran from commit `f168c3d` of this branch. The grid took two
invocations of the same command: the first ran 342 cells from 2026-10-20 00:10 to 06:28 UTC and
was stopped when the controller's VPN link reset (32 cells that then errored on the dead link in
two minutes were deleted); the second ran the remaining 138 cells from 06:31 to 09:09 UTC,
rerunning the one cell the link loss had cut short. `MANIFEST.json` carries both invocations in
`run_history` and every run file records its own start and finish.

- **Fault fidelity.** The 2,160 in-cut probes of the three static topologies match their cut
  sets exactly (1,440 cut links unreachable, 720 intact links reachable); every cut had formed
  within 0.38 s of its offset (median 0.13 s) and every final heal within 0.19 s (median 0.14 s);
  the `LETS_E1` chains dropped 183,014 packets.
- **Safety.** All 3,840 run-system pairs satisfied `effects <= 30`, `effects == authorized
  records`, and no duplicate actuation; the margin ranges from 0 (every 2x cell) to 25, and every
  LETS invariant snapshot on every site (one-lease and tree) was healthy at the end of its run.
- **Completion.** At 0.7x load and skew 1, the delegation tree completes exactly what one-lease
  LETS completes: `split-s1` 0.99 (95% seed-bootstrap interval 0.972 to 1.000, 2.8 points wide),
  `bridge-s3` 1.00, `full-isolation` 1.00, `flapping-s1-s2` 1.00 (all three with zero-width
  intervals), against static quotas 0.87 to 0.93, central with retry 0.86 to 1.00, Raft 0.67 to
  1.00, and the no-retry counter 0.56 to 0.88. The two LETS systems have the same pooled
  completion to three decimals in all 24 cells of the grid, including 2x load, where every system
  except Raft completes 0.48 to 0.53 because the envelope binds.
- **Time to authorization before the break (p50 / p95 over about 1,920 authorized requests per
  system).** One-lease LETS 28.4 / 78.4 ms, the tree 28.6 / 80.5 ms; by site, one lease against
  tree: `s1` 28.7 against 28.8 ms, `s2` 22.5 against 22.9 ms, `s3` 72.6 against 75.3 ms. The leaf
  authorization carries a two-level ancestor path that the warden checks for revocation; its cost
  is 0.2 ms at the median over the grid and at most 2.7 ms at the median on the Azure VM. The
  absolute LETS latencies are higher than in the three-host run above (18.1 / 55.4 ms) because
  each site now hosts eight systems, two of them LETS wardens committing with `synchronous=FULL`,
  and the 4-core Azure VM's disk serialises those commits (`s3` is the slowest site for every
  system that commits locally); the paired one-lease row is the comparator, not the earlier grid.
- **Stranded capacity at 0.7x, skew 1 (peak units / unit-seconds per run).** `split-s1`: one
  lease 20 / 15.7, tree 20 / 15.5; `full-isolation`: one lease 20 / 15.7, tree 20 / 15.9. At 2x
  load `split-s1` 18 / 106 against 18 / 105 and `full-isolation` 20 / 121 against 20 / 121.
- **Messages per run.** Both LETS systems send 1 to 446 (the upper range is 2x load, where
  exhausted sites poll peers every 0.5 s); the tree adds no network messages because spawn and
  close are local warden transactions.
- **Lease-tree costs.** Every 10-unit site builds a seven-lease tree with four leaves (3/2/3/2
  units). The initial build is 7 lease operations and 66.5 ms at the median (95th percentile 149
  ms) against 1 operation and 9.1 ms for one lease. Over the grid the tree refreshed 3.88 times
  per run and one-lease LETS reissued 3.96 times per run (a refresh happens once per transfer in
  or out, and the counts differ slightly because voucher timing differs between runs). A tree
  refresh costs 8.8 lease operations on average (9.9 at 0.7x load and skew 1; fewer when the
  remaining share funds fewer than four leaves) and 113.7 ms at the median, 340 ms at the 95th
  percentile, 433 ms at most; the one-lease reissue costs 1.8 operations and 22.8 ms at the
  median, 74 ms at the 95th percentile, 104 ms at most. By site the median refresh is 92.6 ms on
  `s1`, 91.8 ms on `s2`, and 218 ms on the Azure VM, against 22.0, 18.7, and 44.0 ms for one
  lease, so a refresh is about 4.5 to 5 times the one-lease reissue everywhere, roughly 10 to 25
  ms per lease operation. The busiest cells (2x load, skew 1, `split-s1` and `full-isolation`,
  about eight transfers per run) spend up to 2.0 s per run rebuilding trees against 0.47 s
  reissuing single leases, spread over three sites and 50 s. `delegation.md` has the per-cell
table and `report.md` / `report-2x.md` the grid reports at 0.7x and 2x.

The delegation question is therefore settled by measurement rather than argument: with each site's
budget delegated through a two-level tree whose leaves issue every call, real network breaks of
30 s on three hosts leave the conservation check, the completions, the stranded budget, and the
transfer traffic indistinguishable from the one-lease study, at a cost of a few tenths of a
millisecond per approval and about 0.1 s of warden work each time a site takes up or gives away
budget. What this grid does not cover is unchanged: deeper or wider trees (the lineage benchmark
measures those on one warden) and children spawned on a remote warden during a break.

## Anchored partition results (160 runs, 19,414 requests, 20 seeds per cell)

Every LETS warden and executor in the grids above ran without rollback anchors, so none of them
showed what a site does when its databases are put back to an older state while it is cut off.
Three LETS variants answer that on the same three hosts. `lets-anchored` is `lets` with a
process-file rollback anchor beside the warden and another beside the executor: the warden anchor
records the audit position and state of the warden database as the warden commits, the executor
anchor does the same for the executor's claim store, and a database found behind its anchor is
refused when it is opened. `lets-anchored-restore@s1` adds a stale restore at `s1`: one second into
the break the site takes an online SQLite backup of both databases of that system, and halfway
through the break (20 s into the run), still cut off, it closes them, replaces the database files
with the backup, and reopens them, leaving the anchors as they are. `lets-restore@s1` does the same
restore with no anchors. It is the control: the controller expects it may exceed the envelope,
records its safety verdict, and does not count the run as failed for it. The restore event of each
run (`restore_snapshot`, then `restore_refused` or `restore_accepted` in `events.csv`) carries the
warden revision at the backup and just before the restore.

**Keeping the anchors out of the databases' rollback domain.** On each host the anchors lived on
their own 512 MB ext4 filesystem (a loop-mounted image) at `/srv/lets-anchor`, owned by a dedicated
system account `lets-anchor` with mode 700. The site agents, and with them the databases, the
backups, and the restores, ran under the experiment account on the host's main filesystem; before
the grid that account was checked on all three hosts to be unable to list or write the anchor
filesystem. It reached the anchors only through the LETS anchor helper, started as `lets-anchor`
through a sudo rule that permits that one command
(`sudo -n -u lets-anchor /opt/lets-anchor/venv/bin/python -m lets.authority_helper`), so a backup
or restore could not copy or replace an anchor even by mistake. The account, filesystem, helper,
and sudo rule were removed after the run.

**Grid.** The three-host setup of the delegation grid (`s1` and `s2` on the university LAN, `s3`
the Azure VM in East US, controller on the Windows desktop through SSH port forwards, faults
through persistent sudo-over-SSH, no netem), skew 1, 0.7x and 2x load, 20 seeds. The sites ran
harness commit `b9f48d3` (deployed as a Git archive, CPython 3.12.13, LETS 1.1.0 in the anchor
helper) and the controller ran the same commit. Two directories:

- `three-host-anchored-restore/`: `split-s1` and `full-isolation` with `lets`, `lets-anchored`,
  `lets-anchored-restore@s1`, and `lets-restore@s1` in every run (80 runs, 2026-10-22 20:10 to
  21:44 UTC). Its `MANIFEST.json` also records a second invocation of the same command, which found
  all 80 cells present and ran none.
- `three-host-anchored/`: `bridge-s3` and `flapping-s1-s2` with `lets` and `lets-anchored` (80 runs,
  21:44 to 23:24 UTC). The first invocation ran 44 cells and stopped at 22:33 UTC when the
  controller process and its SSH port forwards ended; after the site agents and forwards were
  restarted, the same command skipped those 44 cells and ran the other 36 from 22:42 UTC.

**Fault fidelity.** All 160 runs passed. The 720 in-cut probes of the static topologies match their
cut sets exactly (480 cut links unreachable, 240 intact links reachable); every cut had formed
within 0.21 s of its offset (median 0.11 s) and every heal within 0.28 s (median 0.13 s); the
`LETS_E1` chains dropped 6,405 packets.

**Stale restores.** The anchored warden refused every restore of a database that had advanced since
the backup, with `StorageError: warden database is older than its monotonic authority anchor`, and
`s1` then refused every later request of that system (`stale_state_refused`) and approved none.
The unanchored control accepted every restore, which handed `s1` back the units it had spent since
the backup. A site's allocation below is its share plus the units transferred to it minus the
units it transferred away (the `transfer_in` and `transfer_out` events of that system at `s1`);
overspend is the actuations in `s1`'s effect log beyond that allocation.

| Cell (skew 1) | Anchored: refused / stale restores | Anchored: runs over 30 | Unanchored: restores accepted | Unanchored: runs where `s1` overspent (max units) | Unanchored: runs over 30 (max actuations) |
|---|---|---:|---:|---|---|
| `split-s1`, 0.7x | 20 / 20 | 0 | 20 | 11 (6) | 1 (34) |
| `full-isolation`, 0.7x | 20 / 20 | 0 | 20 | 12 (5) | 0 (25) |
| `split-s1`, 2x | 20 / 20 | 0 | 20 | 20 (10) | 20 (40) |
| `full-isolation`, 2x | 19 / 19, plus 1 unchanged and accepted | 0 | 20 | 19 (8) | 19 (38) |
| All | 79 / 79 | 0 of 80 | 80 of 80 | 62 of 79 stale restores (1 to 10 units) | 40 of 80 (at most 40) |

In the one accepted anchored restore (`full-isolation-L2-T1-equal-S006`), `s1` had used up its
units before the backup, so the warden revision was 11 at both the backup and the restore and the
restored database was not stale; accepting it is the correct outcome. With anchors, `s1` never
actuated beyond its allocation and every one of the 80 runs stayed within the envelope. Refusing
has a price in completion: the anchored-restore copy completes 0.65 (`split-s1`) and 0.665
(`full-isolation`) at 0.7x, against 0.99 and 1.00 for `lets`, and 0.486 and 0.485 at 2x, against
0.497 and 0.493, where the envelope binds anyway. The unanchored control completes 1.00 at 0.7x and
0.599 and 0.587 at 2x only because it spends units it does not hold.

**Availability with anchors.** `lets-anchored` approved exactly as many requests as `lets` in every
one of the 160 runs, so the pooled completions are identical: at 0.7x, 0.99 for `split-s1` and
1.00 for `bridge-s3`, `full-isolation`, and `flapping-s1-s2`; at 2x, 0.497, 0.476, 0.493, and
0.519. That includes what a cut-off site serves from its own share: of the requests that arrived at
`s1` between cut formation and heal at 0.7x, both systems approved all 126 in `split-s1` and all
129 in `full-isolation`. Both systems satisfied `effects <= 30`, `effects == authorized records`,
and no duplicate actuation in all 160 runs.

**What the anchors cost.** Every LETS approval records an `auth_cost` event with its warden debit
and executor claim times. In `three-host-anchored/`, where each site hosts the two LETS systems,
the median time to authorization before the break (306 authorized requests per system) is 23.6 ms
without anchors and 41.9 ms with them (95th percentile 67.8 and 119.5 ms). By site, the median
warden step goes from 18.8 to 28.4 ms on `s1`, 17.2 to 25.1 ms on `s2`, and 36.0 to 72.7 ms on
`s3`, and the executor step from 4.5 to 13.0, 3.3 to 13.7, and 28.4 to 40.9 ms. In the restore
grid, where four LETS systems share each site's disk, the median time to authorization before the
break is 43.6 ms without anchors and 70.4 ms with them. To isolate the anchor's own cost,
`anchor_cost.py` was run on each host before the grids started: ten trials per configuration,
alternating which configuration goes first, each of 20 warm-up calls and 200 timed calls (2,000
samples per configuration per host), written to `anchor-cost/anchor-cost-<site>.json` with every
sample.

| Host | Median approval, no anchors / anchors (ms) | Anchors, 95th percentile (ms) | Warden step, no anchors / anchors (ms) | Executor step, no anchors / anchors (ms) |
|---|---|---:|---|---|
| `s1` | 15.1 / 32.1 | 34.3 | 11.1 / 20.1 (+8.9) | 4.0 / 12.0 (+8.0) |
| `s2` | 11.2 / 34.7 | 38.7 | 8.3 / 21.3 (+13.1) | 2.9 / 13.4 (+10.5) |
| `s3` | 42.9 / 92.4 | 125.4 | 23.8 / 48.9 (+25.1) | 18.7 / 43.2 (+24.6) |

The added cost in parentheses is the difference of the medians.

**What this grid does not cover.** The anchor filesystem was a separate volume and account on the
same disk and host, not separate hardware or a remote service, so the grid tests independence from
a database rollback, not from the loss of a disk or host. The experiment account also held the
general passwordless sudo the fault injector needs; the backups and restores did not use it, but an
administrator with root on a host can still roll back a database and its anchor together, which
remains outside what anchors protect against. Each stale restore replaced both databases of the
system together and the warden refused first, so the executor anchor's own refusal was not reached
under partition.

Reproduce on the three hosts. Each site agent needs the anchor root and the helper command (the
host prerequisites are those of the delegation grid plus the anchor account, filesystem, and sudo
rule described above):

```bash
LETS_E1_TOKEN="$(cat ~/.lets-e1/token)" uv run python -m benchmarks.fair_baselines.site_agent --site s1 --bind 0.0.0.0 --port 9701 --state-root ~/.lets-e1/state --anchor-root /srv/lets-anchor --anchor-helper "sudo -n -u lets-anchor /opt/lets-anchor/venv/bin/python -m lets.authority_helper"
```

An agent started without `--anchor-root` rejects the anchored systems. Then, from the controller:

```bash
LETS_E1_TOKEN=... uv run python -m benchmarks.fair_baselines.controller run --endpoints three-host-endpoints.json --output results/fair-baselines-2026-10-15/three-host-anchored-restore --thetas 1 --rtt-ms 0 --topologies split-s1 full-isolation --loads 0.7 2.0 --seeds 20 --systems lets lets-anchored lets-anchored-restore@s1 lets-restore@s1
LETS_E1_TOKEN=... uv run python -m benchmarks.fair_baselines.controller run --endpoints three-host-endpoints.json --output results/fair-baselines-2026-10-15/three-host-anchored --thetas 1 --rtt-ms 0 --topologies bridge-s3 flapping-s1-s2 --loads 0.7 2.0 --seeds 20 --systems lets lets-anchored
uv run python -m benchmarks.fair_baselines.analysis --output results/fair-baselines-2026-10-15/three-host-anchored-restore
uv run python -m benchmarks.fair_baselines.report --grid three-host-anchored-restore=results/fair-baselines-2026-10-15/three-host-anchored-restore --write results/fair-baselines-2026-10-15/three-host-anchored-restore
uv run python -m benchmarks.fair_baselines.report --grid three-host-anchored-restore=results/fair-baselines-2026-10-15/three-host-anchored-restore --load 2 --basename report-2x --write results/fair-baselines-2026-10-15/three-host-anchored-restore
```

(`analysis` and both `report` calls run the same way for `three-host-anchored/`.) The quiet-host
cost, on each host while no grid runs:

```bash
uv run python -m benchmarks.fair_baselines.anchor_cost --site s1 --state-root ~/.lets-e1/anchor-cost --anchor-root /srv/lets-anchor --anchor-helper "sudo -n -u lets-anchor /opt/lets-anchor/venv/bin/python -m lets.authority_helper" --output anchor-cost-s1.json
```

The grid reports count the unanchored control apart in their safety sentence. The stale-restore
table and the per-site anchor costs above are reductions of `events.csv` (the restore, transfer,
and `auth_cost` events), `runs.csv` (actuations and safety verdicts), and each run file's effect
log; `report.md` and `report-2x.md` in each directory have the completion tables and intervals.

## Known limitations

- The local platform shares one CPU and kernel across nine site processes; it demonstrates the
  mechanics and the qualitative ordering, not WAN latency.
- The LETS transfer policy is reactive only; proactive or gossip policies belong to E7.
- The delegation tree takes up a transfer by closing and respawning the whole tree, because no
  warden operation adds budget to a live lease. A grant operation, which the warden does not yet offer, would let
  the refreshed root fund a new leaf without closing the others; its cost would be one spawn per
  leaf instead of a full rebuild. Deeper or wider trees than depth 2, fanout 2 are run by naming
  them (`lets-tree-d4-f2`, up to depth 8 and fanout 8); their refresh cost grows with the number
  of leases a share can fund.
- The Raft baseline is one library's implementation without pre-vote; leader churn on the
  `bridge-s3` topology is a property of that implementation and is visible in the `raft_state`
  events and in the term counter of each run's snapshots.
- Time-to-authorization for `lets` includes the local warden commit, receipt verification, and the
  executor claim; the counters commit once and verify nothing.
