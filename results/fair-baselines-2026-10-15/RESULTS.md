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

All five run concurrently in every run against the identical arrival sequence, so comparisons
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

## Known limitations

- The local platform shares one CPU and kernel across nine site processes; it demonstrates the
  mechanics and the qualitative ordering, not WAN latency.
- The LETS transfer policy is reactive only; proactive or gossip policies belong to E7.
- The Raft baseline is one library's implementation without pre-vote; leader churn on the
  `bridge-s3` topology is a property of that implementation and is visible in the `raft_state`
  events and in the term counter of each run's snapshots.
- Time-to-authorization for `lets` includes the local warden commit, receipt verification, and the
  executor claim; the counters commit once and verify nothing.
