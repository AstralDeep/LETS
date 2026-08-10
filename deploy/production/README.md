# Production deployment boundary

This directory is a fail-closed, one-warden-per-host Docker Compose deployment. It is not the
fault-injection topology in the repository root. Run one independently provisioned instance on
each failure domain and connect nodes only through the HTTPS endpoints in the signed manifest.

The manifest deliberately refuses to start with the built-in raw-seed/static-token runtime. A
production image must contain an installed `lets.runtime_providers` entry point that supplies a
managed Ed25519 signer, a production identity authenticator, an independent monotonic authority
anchor, and a durable external audit sink, and that provider must return `production_capable=True`.
The vendor-neutral `generic-production` adapter can call an operator-controlled signer helper and
use short-lived EdDSA identity tokens; cloud KMS, PKCS#11, OIDC, SPIFFE, PKI, and managed audit
integrations remain deployment packages. Derive and lock an operator image containing the selected
provider and signer helper, publish it by digest, and set `LETS_RUNTIME_PROVIDER` to its entry-point
name. Provider-specific non-secret options belong in the node configuration or an audited Compose
override; provider credentials belong in the platform secret/identity system, never this
environment file. See [the provider contract](../../docs/runtime-providers.md).

## Provisioning contract

Before starting a node, create and protect:

1. `LETS_STATE_DIR`, containing the SQLite database, node lock, and any schema-specific replay
   state. Put it on a dedicated filesystem or an actually enforced quota with no unrelated
   writers. The directory must be writable only by container UID/GID 10001 and its operator backup
   principal. Production admission requires explicit positive `min_free_disk_bytes`,
   `max_database_bytes`, and `reserve_pages` values in `config.json`. Declare the independently
   enforced limit as `LETS_STATE_CAPACITY_BYTES` and its mechanism as
   `LETS_STATE_STORAGE_BOUNDARY`; the validator refuses a limit too small for the logical main
   database cap, one full worst-case transaction WAL, its WAL-index, and the emergency floor.
   A quota can enforce that capacity limit, but it does not replace the separately mounted state
   filesystem required for rollback/failure isolation.
2. `LETS_CONFIG_FILE`, an operator-reviewed copy of the generated configuration outside every
   writable runtime domain. Stage it with the repository helper below. The runtime bind-mounts
   this file read-only over `/var/lib/lets/config.json`; it must identify the state database by the
   absolute container path `/var/lib/lets/warden.sqlite3`. Never run from the writable generated
   copy left in `LETS_STATE_DIR`.
3. `LETS_AUTHORITY_DIR`, on an independent monotonic/fenced storage domain. It is mounted at
   `/var/lib/lets-authority` and must not be restored from the same snapshot as the state database.
   The production runtime/provider integration must bind its authority anchor here.
4. `LETS_AUDIT_DIR`, containing the provider's independently durable audit archive. It is mounted at
   `/var/lib/lets-audit`; initialize it with the selected provider's provisioning command before
   node initialization, back it up independently, and retain it for the system audit lifetime.
   Declare a dedicated filesystem or enforced quota, its byte capacity, an evidence-based expected
   daily growth rate, the commissioned forecast duration, and an emergency free-space floor through
   the `LETS_AUDIT_*` values. The validator rejects a boundary that cannot hold the current archive
   plus that complete append-only lifecycle forecast.
5. `LETS_BACKUP_DIR`, on a protected backup domain separate from state, authority, audit, and trust.
   Only the networkless one-shot maintenance service mounts it at `/var/lib/lets-backup`; the live
   warden has no backup-domain access. Recovery bundles are written here and then copied to
   immutable off-host storage. A backup on the state filesystem is not a disaster-recovery copy.
6. `LETS_TRUST_DIR`, containing the operator-signed manifest and immutable trust material. It is
   mounted read-only at `/etc/lets/trust`; paths stored in `config.json` must use that mount.
7. A server certificate/key, inbound client CA, outbound peer CA, and outbound peer certificate/key.
   The server certificate must include `LETS_SERVER_NAME`, peer certificates must chain to the
   configured client CA, and private-key host ACLs must exclude other users. All certificate, CA,
   config, and trust parents must be controlled by a host identity other than runtime UID 10001 and
   must not be group/world writable; otherwise that UID could stage a replacement for recreation.
8. An immutable multi-architecture image reference of the form `image@sha256:<digest>`.

Keeping the authority anchor outside the database backup domain is a correctness requirement, not
merely hardening. Restoring an older database together with its anchor can resurrect already-spent
authority.

The environment therefore requires `LETS_AUTHORITY_STORAGE_BOUNDARY=fenced-filesystem`,
`LETS_BACKUP_STORAGE_BOUNDARY=dedicated-filesystem`, and four pairwise-distinct
`LETS_*_ROLLBACK_DOMAIN` identifiers. Each identifier must name the actual controller plus
volume/dataset, for example `zfs://authority-pool/warden-a`; it is not a free-form role label.
Validation rejects a missing, malformed, or reused identity. Device numbers and bind-mount paths
cannot prove full control-plane independence because coordinated snapshots can span otherwise
distinct host devices. The validator nevertheless requires all four directories to report distinct
mounted-filesystem device identities; an enforced quota never waives that minimum. Before
commissioning, attach evidence that the declared identifiers are governed by separately scoped
snapshot/restore operations and credentials, and demonstrate that restoring each domain cannot
roll back any other. A false identifier defeats the stale-restore guarantee and is an unsupported
deployment, even if the validator passes.

Use dedicated Linux filesystems whose documented guarantees include local POSIX advisory locks,
SQLite WAL shared-memory locking, atomic same-directory rename/link, and durable file plus directory
`fsync`. Do not place the state database, generic file anchor, or generic SQLite audit archive on
NFS, SMB/CIFS, a desktop file share, or an eventually consistent object mount. Never attach one
state directory to two containers or hosts. Each declared local storage directory must be the exact
Linux mountpoint, must contain no nested mount, and must not use a network, overlay, RAM, or desktop
share filesystem. All Compose binds use private propagation. Run the validator on the Linux Docker
host; Docker Desktop storage is deliberately not admitted as a production durability boundary.
The validator proves path and mounted-device
separation, not storage-controller grouping, snapshot policy, quota enforcement, or filesystem
semantics; record those properties in deployment evidence. Sites that cannot provide them must
supply remote linearizable anchor/audit provider
bindings and a supported database storage boundary rather than declaring the generic file profile
safe.

### Generic provider example

For the bundled `generic-production` adapter, put the executable signer bridge in the immutable
operator image and identity verification keys in `/etc/lets/trust/identity-keys.json`. Initialize
the independent audit archive, then run provider-backed node initialization inside the same mounted
container boundary (replace public IDs/keys and capacity values):

```sh
docker compose --env-file /etc/lets/warden-a/compose.env \
  -f deploy/production/provision-compose.yaml run --rm --no-deps provision \
  lets-provider audit-init --path /var/lib/lets-audit/audit.sqlite3

docker compose --env-file /etc/lets/warden-a/compose.env \
  -f deploy/production/provision-compose.yaml run --rm --no-deps provision \
  lets --config /var/lib/lets/config.json init --production \
  --warden-id warden-a \
  --manifest /etc/lets/trust/manifest.json \
  --operator-key operator-2026=REPLACE_WITH_BASE64URL_PUBLIC_KEY \
  --min-free-disk-bytes 1073741824 \
  --max-database-bytes 10737418240 \
  --reserve-pages 256 \
  --runtime-provider generic-production \
  --runtime-option 'signer_command_json=["/usr/local/bin/lets-hsm-sign"]' \
  --runtime-option signer_key_id=REPLACE_WITH_MANIFEST_KEY_ID \
  --runtime-option signer_public_key=REPLACE_WITH_BASE64URL_PUBLIC_KEY \
  --runtime-option identity_keys_file=/etc/lets/trust/identity-keys.json \
  --runtime-option identity_issuer=https://identity.example \
  --runtime-option identity_audience=lets-warden \
  --runtime-option authority_anchor_path=/var/lib/lets-authority/warden.anchor.json \
  --runtime-option audit_archive_path=/var/lib/lets-audit/audit.sqlite3

sudo .venv/bin/python deploy/production/stage_config.py \
  --source /srv/lets-state/warden-a/config.json \
  --destination /etc/lets/warden-a/config.json
```

The signer helper receives bytes on standard input and must emit only the unpadded base64url
Ed25519 signature. Production initialization proves the signer, verifies it is a current local key
in the signed manifest, creates no raw key file or bootstrap bearer, and persists these non-secret
provider references in `config.json`. Protect the audit archive and anchor before this step; a
partially initialized directory is deliberately not overwritten on retry. The provisioning
Compose service has no network and does not mount the staged runtime config. Providers that need a
remote KMS during provisioning require an operator-reviewed network override. `stage_config.py`
creates its destination exclusively, canonicalizes the JSON, rewrites the state database (and the
legacy replay database when present) to absolute container paths, rejects development trust,
fsyncs the result, and removes all write bits. Run it through the repository-local virtual
environment as a trusted host operator; never stage into `LETS_STATE_DIR`.

The production validator treats the exact OCI digest as the signer-helper code identity. It rejects
shells, interpreters, environment launchers, dynamic loaders, parent traversal, and command
arguments that load from writable or ephemeral mounts, then proves inside a CPU/memory/PID-bounded,
networkless container that the selected provider entry point loads and the dedicated helper is a
regular executable in that image. Put fixed code and public configuration in immutable image/trust
paths; pass secrets through the platform identity/secret boundary, never command-line arguments.

When deploying from release assets rather than a source checkout, extract the verified
`lets-deployment-X.Y.Z.tar.gz`, create a dedicated virtual environment, and install the matching
verified wheel into that environment before running the staging helper. Do not install the wheel
into the system interpreter:

```sh
python3 -m venv /opt/lets-release/X.Y.Z/venv
/opt/lets-release/X.Y.Z/venv/bin/python -m pip install --no-deps \
  ./lets_agent-X.Y.Z-py3-none-any.whl
sudo /opt/lets-release/X.Y.Z/venv/bin/python \
  lets-deployment-X.Y.Z/deploy/production/stage_config.py \
  --source /srv/lets-state/warden-a/config.json \
  --destination /etc/lets/warden-a/config.json
```

## Validate and start

Copy `.env.example` to a protected file outside the repository and replace every placeholder.
After provisioning and config staging, pull the exact image, then run the repository-local
validator and render Compose before changing live state. The validator executes the image itself
with no network, a read-only root, no capabilities, and the production SQLite admission check:

```sh
docker compose --env-file /etc/lets/warden-a/compose.env \
  -f deploy/production/compose.yaml pull
python deploy/production/validate.py --env-file /etc/lets/warden-a/compose.env
docker compose --env-file /etc/lets/warden-a/compose.env \
  -f deploy/production/compose.yaml config --quiet
docker compose --env-file /etc/lets/warden-a/compose.env \
  -f deploy/production/maintenance-compose.yaml config --quiet
docker compose --env-file /etc/lets/warden-a/compose.env \
  -f deploy/production/compose.yaml up -d --wait
```

The service runs as UID/GID 10001 with a read-only root filesystem, no Linux capabilities,
`no-new-privileges`, bounded processes/memory/CPU/file descriptors, a no-exec tmpfs, bounded JSON
logs, bounded request concurrency/body receipt/keep-alive/shutdown, and a 120-second container stop
window. That window covers the maximum admitted 40-second server graceful shutdown, the
audit-exporter stop, and the peer dispatcher's maximum 60-second request plus SQLite/poll/join
allowance before Docker can kill the process. Do not shorten it without proving the complete
configured shutdown inequality. The separately staged config is a nested read-only bind over the
writable state directory, so the runtime UID cannot replace it across a restart. It publishes TLS
only. The readiness probe performs hostname-verifying TLS with a client certificate and accepts
only the exact LETS ready document.

The request concurrency limit defaults to 64 and the TCP accept backlog to 128 in both the core
server and this profile. Override `LETS_LIMIT_CONCURRENCY` or `LETS_BACKLOG` only after measuring
the complete TLS/provider/SQLite path under the configured CPU, memory, file-descriptor, and PID
limits; increasing either value can raise memory and shutdown pressure.

The total pre-authentication request-body deadline defaults to 30 seconds. Set
`LETS_REQUEST_BODY_TIMEOUT_SECONDS` from 1 through 300 only after measuring legitimate uploads over
the complete TLS path. A client that does not finish its body within that deadline receives a
`408 request_body_timeout` problem and its connection is closed; the keep-alive timeout does not
replace this body-read deadline.

The supplied profile uses a 60-second outbound peer request deadline. Production validation
requires `LETS_PEER_REQUEST_TIMEOUT_SECONDS`, admits only 30 through 60 seconds, and still performs
one HTTP attempt per durable dispatcher attempt. A timeout therefore leaves the authoritative
transfer `PREPARED` and records a failed delivery for bounded retry; it never implies that a
response was not committed remotely. For the bundled `generic-production` provider, admission also
requires the peer deadline to cover four authority-anchor calls, four signer calls, two SQLite busy
allowances, and a fixed scheduling/TLS margin. The exact floor is
`4 * authority_timeout_s + 4 * signer_timeout_s + 15` seconds. Increasing signer or authority
timeouts without increasing this deadline is rejected, as is a combination whose derived bound
exceeds the 60-second production ceiling. The peer timestamp is authenticated on arrival before
target-side storage work; do not route peers through an intermediary that can hold a signed
request beyond the accepted clock-skew window.

Startup deliberately performs full SQLite integrity, foreign-key, authority-anchor, and audit
admission before serving. The healthcheck start period defaults to ten minutes; it does not weaken
or skip those scans. Benchmark a worst-case cold start against a restored database at the planned
logical cap on the actual storage class, then set `LETS_HEALTH_START_PERIOD_SECONDS` above that
measured bound (up to the validator's 24-hour ceiling). An orchestrator that kills or replaces the
process before this period expires can turn safe admission into a restart loop.

Process-file authority admission also performs an exact durable checkpoint confirmation. If helper
transport fails during construction or reopen, the database and anchor remain preserved but that
store instance is not admitted; close it and perform a fresh open after repair. After successful
admission, only a typed, well-formed helper-transport fault may recover on a later explicit
transaction after its monotonic cooldown. The original operation is not retried inside the store.
The helper's start, correlation, lock/I/O, response, and reset share one absolute deadline, and an
uncertain mutating reply must be reconciled and durably confirmed before the store becomes healthy.
Anchor semantic or protocol rejection, malformed transport metadata, and other provider failures
remain sticky until operator repair and a fresh process/store lifetime. These rules are identical
for core and protected-executor anchors. The 1.0.5 bundled helper wire adds exact request
correlation and `confirm`; never pair a pre-1.0.5 helper executable with a 1.0.5 parent.

Authenticated metrics include the bounded `authority_anchor` state and counters. Operators with
`lets.admin`, `lets.warden.admin`, or `lets.metrics.read` may read the same snapshot from
`GET /v1/maintenance/authority-status`. That endpoint performs no SQLite or authority-admission
work: it deep-copies the most recently completed status published through a separate snapshot
lock. While a reconcile is in progress it may show the prior complete state. The admin-only
`POST /v1/maintenance/authority-fence` remains the exact terminal barrier: it atomically publishes
the fenced warden/PID/lifetime status and permanently stops new authority transactions for that
process lifetime. It is idempotent only for the same `restart_id` and `expected_lifetime_id`; a
different identity conflicts. This endpoint is for host-orchestrated replacement after traffic is
already removed, not a general un-fence mechanism.

The supplied 1 GiB profile defaults to 64 concurrent requests. Raise that only after a
representative TLS, signer, SQLite, audit-export, and partition-recovery load test demonstrates
bounded memory and shutdown latency within the configured cgroup. A larger number is not a
throughput guarantee.

The maintenance Compose service mounts the backup domain, but has no network, port, restart
policy, or long-running command. Use it only after stopping the warden; the shared node lock rejects
concurrent authority access. Providers that require a remote KMS need an operator-reviewed network
override for that one command. Remove the one-shot container after every invocation and copy
completed bundles to immutable off-host retention promptly.

The 16 MiB `/tmp` mounts are only for bounded library temporaries. Recovery verification,
migration copies, and restore quarantine use the existing bundle or backup parent under
`/var/lib/lets-backup`; preflight that separate filesystem for the documented peak. No full
database scratch copy is written to the runtime tmpfs.

Compose file-backed secrets are an interoperability floor. On platforms where Compose cannot
honor secret UID/GID/mode metadata, secure the host files with ACLs and confirm UID 10001 can read
only the intended files before start. Prefer the orchestrator's native secret mechanism for a
managed deployment.

The published runtime targets Linux `amd64` and `arm64`. This manifest's UID/GID, capability,
tmpfs, signal, and bind-mount controls require a Linux container runtime. Docker Desktop on Windows
or macOS is useful for render/smoke testing, but its VM and desktop lifecycle are not an independent
production failure domain; use Linux hosts or translate the same controls into a supported
orchestrator. The Python package remains cross-platform for client/tooling use.

## Opt-in production-profile acceptance

The repository keeps the cleartext Toxiproxy topology at the root as a fast development fault
harness. The separate production-profile acceptance builds three hardened wardens with required
TLS/mTLS, the bundled `generic-production` provider, executable subprocess signers, short-lived
EdDSA JWT identities, independent state/anchor/audit volumes, and a TLS-preserving network
partition. It also runs a protected executor with its replay database and monotonic anchor on
independent volumes, verifies and claims a live signed receipt, rejects that receipt after reopen,
and proves that restoring the pre-claim executor database is rejected against the advanced anchor.
The cluster checks reject missing and untrusted client certificates plus expired JWTs, kill and
restart a warden during the partition, and require durable transfer/checkpoint convergence.

Run it directly from the repository-local environment:

```sh
python deploy/production/run_acceptance.py
```

Or include it through pytest by setting `LETS_RUN_PRODUCTION_ACCEPTANCE=1` and selecting the `e2e`
marker. The runner generates test-only PKI and seed-backed signer material inside ephemeral Docker
volumes, validates the exact project volume set before cleanup, and writes sanitized evidence to
`results/generated/production-profile-acceptance.json`. Set
`LETS_KEEP_PRODUCTION_ACCEPTANCE=1` only while diagnosing a failed run; the material is not suitable
for any deployment and must be removed afterward.

Release automation publishes a unique multi-architecture candidate first and sets
`LETS_PRODUCTION_ACCEPTANCE_IMAGE` to that exact `name@sha256:index-digest`. The harness then proves
that all three wardens ran that candidate while keeping only material generation and the scenario
driver in the local test image. Evidence records both the configured registry digest and the one
platform image ID; a mismatch fails the release before scan, signing, or tag promotion.

### Sustained production soak

The soak runner extends the same hardened three-warden profile for a time-bounded mixed workload.
It requires an immutable OCI index digest; mutable tags and locally built runtime images are
rejected. A normal run lasts at least five minutes and must contain at least two bidirectional
Toxiproxy partitions. Every warden must receive a planned `SIGKILL` and reopen at least once; the
one-hour default spaces those kills 900 seconds apart:

```sh
python deploy/production/run_soak.py \
  --image ghcr.io/astraldeep/lets@sha256:INDEX_DIGEST \
  --duration-seconds 3600 \
  --output results/generated/production-profile-soak.json
```

Every workload cycle issues a root lease, authorizes signed transitions, quiesces, resumes, renews,
and closes the lease. Directed transfers rotate across every warden pair while partitions and
process kills occur. A separately anchored executor claims each receipt, rejects its replay, and
periodically closes and reopens both `SQLiteReceiptReplayStore` and
`ProcessFileExecutorAuthorityAnchor`. Warden restarts similarly reopen `SQLiteStorage`,
`ProcessFileAuthorityAnchor`, `SQLiteAuditSink`, and `AuditExporter` through the production provider.

The workload injects exactly one deterministic executor transport failure after SQLite `COMMIT` and
after the external CAS durably succeeds, then reports the outcome as a classified lost reply.
Recovery must durably confirm the committed claim in the same store lifetime. The original
authorization remains failed closed, an exact retry raises `ReplayError`, and the protected-effect
count for that receipt remains zero. Across all terminal core and executor lifetimes, raw transport
faults, episodes, attempts, and recoveries must each total exactly one, while permanent faults total
zero; any natural second episode fails the run. Mutating HTTP retries in the harness preserve the
exact request/restart ID and are later, separate transactions against idempotent API operations; a
response retry is never evidence that the failed storage call was internally replayed.

An independent monitor owns a separate cluster client and follows an absolute schedule anchored to
workload start rather than sleeping after each sample. It records the schedule, sample timing, and
raw per-node observation timing while checking local conservation, full signed-audit verification,
audit-export health, storage capacity, and peer backlogs. The release verifier evaluates cadence
per node and requires every health-observation gap to be at most 15 seconds; sample-batch timing and
a runtime-reported exporter stall bound cannot relax that limit. A planned `SIGKILL` permits an
exclusion only for the exact killed node and only after that node's sampler has acknowledged the
unique host marker. Arming alone grants no exclusion: the prior live observation through the first
exact acknowledgment must stay within 15 seconds. The host-bound acknowledgment-to-completion
exclusion window is capped at 30 seconds, while arming-to-ack remains inside that prior 15-second
cadence; the replacement must produce a validated live observation within the following 15
seconds, and the marker identity must bind the acknowledgment, restart, and recovery records. The
two unaffected nodes remain continuously observed. Any missed deadline, monitor error, or
retained-sample truncation fails the run.

When the workload end lands on or immediately after a regular health-cadence boundary, the
terminal sample retains the exact workload-end schedule and original 15-second deadline but waits
for one bounded observation-publisher heartbeat before issuing its single metrics request per
node. This prevents a millisecond-separated duplicate request from falsely claiming a reused
snapshot while still making a stalled or stale publisher fail closed inside the same deadline.

The machine record exposes this proof under `health_monitor`. It must report `status: passed`,
`schedule: absolute_monotonic`, `joined: true`, `deadline_miss_count: 0`, equal
`expected_sample_count`, `actual_sample_count`, and `retained_sample_count`,
`samples_truncated: 0`, and `audit_error_budget_instances: 1`. Each retained sample binds its
schedule index and scheduled, started, completed, and deadline times. Every per-node entry is either
a raw `observation` with request and metrics timing or the exact killed node's host-bound
`planned_unavailable` record; no generic missing-node result is admissible. Monitor request retries
remain explicit evidence rather than disappearing into cadence.

Before each partition the workload acknowledges a pause and the cluster settles. The host requires
a unique one-to-one binding between that interval and its own partition-coordination window. A
successful record uses top-level schema `lets.production-profile-soak/v2` and nested workload
schema `lets.production-profile-soak-workload/v2`. A host-generated run ID first binds an atomic
workload-clock start record containing the measurement
origin, duration, seed, and workload frequencies; the host retains it before chaos, and the final
workload, evaluator, and publication verifier must match it exactly. After the exact acknowledgment
and before link disable, an in-container check records a token-bound
workload-clock authorization start; after link restoration and immediately before resume, a second
check records the matching authorization end. Only this workload-clock interval, clipped to
`measurement_window_seconds`, may locate excluded time, and the independently recomputed host
acknowledgment-to-resume duration caps the amount removed. Each boundary echoes the
host-issued pause token and workload-clock request timestamp. The verifier treats the workload's
raw observed-to-resumed `paused_workload_seconds` and `active_workload_seconds` as cross-checks only;
the authoritative denominator is the evaluator-derived authorized active time under
`workload_evaluation.metrics.pause_evidence`. An unmatched, duplicate, overlapping, malformed,
self-reported, or otherwise unexplained interval fails instead. The completed-cycle requirement is
`max(3 * 6 * transfer_every_cycles, 3 * executor_reopen_every_cycles, ceil(active_workload_seconds / 15))`.
At the default transfer-every-three-cycles and reopen-every-ten-cycles frequencies, the first term
sets a 54-cycle path-coverage floor. The evidence exposes the independently derived
`semantic_cycle_floor`, `active_time_cycle_floor`, and `required_cycles`. The evaluator still
requires exact counter relationships, exact directed-pair counts for the actual cycle total, exact
executor claim/replay/reopen relationships, and bounded per-cycle latency with no overflow.

While both A/B proxy links are disabled, the runner binds the exact probe transfer ID, sequence, and
direction to a failed `PREPARED` transfer and its undelivered durable delivery row. After restoring
the links it requires that exact source stream's acknowledged/compacted watermarks and target
stream's contiguous/compacted watermarks to cover the probe sequence, then requires every peer,
transfer, and audit queue to converge to zero. Settle, partition recovery, and final convergence
poll until success and return immediately; the default 180-second convergence timeout is a maximum
deadline, not a fixed wait or extra workload time.

The sustained workload permits at most one sampled, bounded, subsequently recovered transient
exporter error across the entire three-node run. The only admissible class is the sanitized
archive-connect `SQLITE_BUSY` family; I/O, corruption, archive-write, schema, and undiagnosed errors
fail immediately. The exporter must still be running, have a prior successful export, be unblocked,
and remain within its backlog, oldest-record, and stall bounds. A second observation on the same or
another node fails live. On the first observation the independent monitor immediately polls only
that node for the unused portion of its configured stall window
(`max_stall_s - stalled_for_s`); it does not restart or extend the 15-second window. The recovery
probe must show the node fully ready, reconciled, error-free, and empty, and both the original
observation and bounded recovery are retained. An unrecovered final sample fails, final convergence
independently requires `last_error` to be null on every node, and the authoritative live count must
equal the retained evidence while expected, actual, and retained sample counts agree with zero
truncation. This is explicitly a sampled-observation claim, not a count of errors that arise and
recover wholly between health samples.

Host-side probes record the actual LETS child process's RSS and file-descriptor count (not the PID 1
init shim), core DB/WAL/SHM, audit DB/WAL/SHM, signer log, anchor, Docker restart count, OOM state,
and process identity. The acceptance wardens use the shipped 1 GiB memory ceiling with
`memswap_limit` set to the same value, which makes cgroup v2 `memory.max` exactly 1 GiB and
`memory.swap.max` zero. The probe fails closed unless it can read current, peak, limit, and event
counters for memory, swap, and PIDs from the unified cgroup v2 hierarchy. LETS-child RSS must stay
at or below 256 MiB and grow by no more than 128 MiB; total cgroup memory peak must stay at or below
768 MiB; swap current/peak and every memory/swap exhaustion, OOM, and PID-limit event must remain
zero; and PID peak must stay at or below 192 under the exact limit of 256.

Any automatic restart or OOM fails the run. Immediately before every planned `SIGKILL`, the runner
captures and evaluates a resource checkpoint for all wardens, binds its sample index to the kill,
and refuses to continue if it fails. The host then obtains an authenticated authority snapshot and
an exact, idempotent terminal snapshot-and-fence response bound to the old container ID, host PID,
namespace PID, warden, process-lifetime ID, and restart ID before it may send `SIGKILL`. Bounded
attempt evidence is retained and an unproven fence prevents the kill. This retains the killed
process lifetime's peak counters and terminal authority counters even though a replacement
container receives a fresh cgroup. Every planned kill must replace the PID, and every warden must
retain a long uninterrupted process lifetime. Fixed ceilings and per-cycle growth budgets fail the
run on unbounded resource growth. The sorted JSON record binds
start/end timestamps, the unique initially empty Compose project and zero-resource cleanup, exact
requested OCI index digest, inspected image ID and repository digests, matching OCI/host/three-node
runtime/workload/verifier package versions, Git commit/dirty state, deterministic source-tree
digest, individual soak harness file hashes, chaos events, replay/anchor heads, health/load/latency
metrics, and a canonical payload SHA-256.

The independent sampler and active-time cycle calculation change only how evidence coverage is
measured. They do not relax the required partition or `SIGKILL` episodes, resource ceilings,
single-observation audit-error budget, exact workload relationships, or final conservation and
zero-backlog gates.

Final verification runs in the trusted workload step while it still has the executor SQLite and
anchor volumes. It performs a fresh no-create open, SQLite integrity check, and exact anchor
reconciliation, captures the final executor lifetime, and snapshot-and-fences every surviving core
lifetime within one bounded terminal window. The host and publication verifiers then validate the
exact terminal schemas, lifetime relationships, identities, sequences, counters, and global budget
from raw JSON. They do not receive the complete append-only executor `claim_history`, so this is
not an offline replay of an omitted claim-event ledger; the live integrity/reconciliation step is
part of the trusted release harness.

Use `--smoke` only for harness diagnostics. It permits a run shorter than five minutes but still
requires at least two proven partition episodes and planned restarts covering all three wardens;
never present smoke output as sustained-soak evidence. Every run uses a unique Compose project,
requires its container/volume/network namespace to be empty before startup, and proves that all
three resource classes are absent after cleanup. Use `--keep` only for failure investigation because
all generated PKI, signer seeds, and authority state are test material. A successful terminal
capture has already fenced every surviving warden, so `--keep` leaves those containers unready and
unable to admit authority transactions; a failed capture may have fenced only a subset. In either
case the retained project is diagnostic evidence, not a usable cluster: route no traffic and
recreate/restart every fenced warden before any transaction rather than attempting to resume it. On
any failure the runner
atomically replaces the requested output with a bounded `passed: false` evidence record containing
the source/image/preflight state, retained resource and chaos samples, workload exit status and
bounded output, original error, and one-shot cleanup result, then rethrows the original exception.
Before stopping the workload or touching the fault state, it also attempts one final `failure`
resource sample and records either its sample index or a bounded capture error without masking the
original failure. Failure-only Docker probes use five-second per-command timeouts and resolve each
warden container once, bounding the complete three-node resource attempt to about 60 seconds.
Failure log capture is limited to ten seconds; cleanup uses five-second inventory probes and a
30-second Compose-down limit. Normal success-path probe and cleanup deadlines are unchanged, while
the failure path reaches atomic evidence publication within an approximately three-minute budget.
After the host Compose CLI is confirmed stopped, failure cleanup may force-remove only the exact
named workload container whose Compose project, service, and one-off labels match the unique run;
it then applies the checked project teardown and retains the zero-container/network/volume proof.
Release automation archives that failure evidence under a run-attempt-scoped `diagnostic-*`
artifact using an `always()` failure condition, while only verified success evidence receives the
`release-*` artifact name consumed by publication. The failed soak job continues to block image
promotion and release publication.

## Protected executor boundary

The warden authorizes effects but deliberately does not run them. Every production executor must
own a filesystem-backed `SQLiteReceiptReplayStore` and an `ExecutorAuthorityAnchor` in separate
failure and rollback domains. Initialize the store once with the exact audience, tenant, envelope,
and configuration epoch accepted by its `ExecutorPolicy`. Derive the identity with
`executor_replay_identity(policy, registry)` from the complete executor policy and the exact
operator-authenticated manifest key registry, including key validity bounds; never substitute the
unauthenticated discovery response from `/v1/keys`. Subsequent opens read the identity and its
policy/trust fingerprints from the database and fail if any accepted authority differs. Do not use
`allow_unanchored=True` outside a
development test: it protects ordinary restart only and cannot detect restoration of older bytes.

The generic file executor anchor has the same local-filesystem requirements as the warden file
anchor and must not be included in a replay-database snapshot. A managed deployment should replace
it with a remote linearizable CAS binding when the executor state and anchor cannot be placed in
independent storage domains. Back up the replay database while the executor is fenced, retain the
anchor independently, and require a successful anchored reopen before routing effects after a
restore. Missing, divergent, forked, or stale replay state is a fail-closed recovery incident, not
permission to initialize a new store.

`ReceiptVerifier.verify_and_claim` advances the durable receipt/nonces/lease-watermark history and
the external claim anchor before the protected effect may begin. A post-`COMMIT` lost reply can burn
the claim even though the caller received an error; recovery confirms the head, and retry raises
`ReplayError` with no effect. The application must still bind that claim to its own effect
transaction or make the effect idempotent; LETS cannot atomically commit an arbitrary external side
effect. Monitor
executor anchor latency/errors, replay-store integrity and capacity, clock uncertainty, rejected
duplicates, and the age of the oldest retained receipt. Fence effects immediately if the anchor
becomes unavailable or the store reports an authority fault.

## Capacity, retention, and disk-full response

The core signed audit chain is intentionally immutable and is not deleted after external export.
`max_database_bytes` is a logical main-database ceiling, not a physical combined-file hard cap or
an automatic retention target. LETS applies `PRAGMA max_page_count` on every connection. The main
database, live WAL, and transient WAL-index remain separate physical files, and a pinned reader can
keep committed WAL frames live. Every write therefore requires free filesystem space for all
remaining main-file growth, one transaction that could touch every configured database page, any
additional WAL-index growth, and the emergency floor. This also leaves enough room for a checkpoint
to grow the main file while the WAL remains live. A subsequent write fails closed until checkpoint
progress restores that complete reserve.

For SQLite page size `P` and `N = floor(max_database_bytes / P)`, LETS reports the conservative WAL
reserve `32 + N * (P + 24)`. The standard SQLite WAL-index uses one 32,768-byte block for the first
4,062 frames and another block per 4,096 frames. The deployment validator consequently requires:

```text
LETS_STATE_CAPACITY_BYTES >=
  floor(max_database_bytes / P) * P
  + WAL-index bytes
  + min_free_disk_bytes
  + worst_case_transaction_wal_bytes
```

At runtime the corresponding free-space admission is
`min_free_disk_bytes + remaining_main_growth_bytes + worst_case_transaction_wal_bytes +
additional_shared_memory_bytes`. Logical `reserve_pages` is enforced separately inside the main
database page ceiling; it is not a substitute for physical checkpoint headroom.

This declaration must correspond to a real dedicated filesystem or enforced quota; the validator
can compare sizes but cannot prove storage-controller policy or the absence of unrelated writers.
Record `findmnt`/quota evidence at commissioning. See SQLite's official
[WAL-index format](https://sqlite.org/walformat.html) for the physical index layout. Before
commissioning, measure worst-case logical database growth with the real policy and mutation mix,
calculate the time remaining to the configured cap, and make that horizon longer than the approved
node lifecycle. Alert on `storage_capacity.logical_live_bytes`, `main_database_bytes`, `wal_bytes`,
`shared_memory_bytes`, `worst_case_transaction_wal_bytes`,
`worst_case_shared_memory_bytes`, `additional_shared_memory_bytes`,
`remaining_main_growth_bytes`, `required_filesystem_free_bytes`, actual filesystem free bytes,
`audit_exporter.pending`/`stalled_for_s`, peer pending/prepared counts,
`peer_dispatcher.durable_retry` attempt/delay/kind/target metadata, and readiness. The status uses a
bounded exception-class token and never returns raw transport error text; each new attempt also
replaces a legacy pending row's raw error with that class-only form. Recalculate the horizon after
every policy or traffic change.

The provider audit archive has a separate append-only growth curve and does not share the core
state cap. Alert on archive main/WAL/SHM bytes, filesystem/quota free bytes, exported head sequence,
core-to-archive lag, `audit_exporter.pending`, `archive_reconciled`, `publish_blocked`, and
`last_error`. Recalculate `LETS_AUDIT_EXPECTED_DAILY_BYTES` after every workload/payload change and
extend or retire the archive before its commissioned `LETS_AUDIT_FORECAST_DAYS` horizon. A full
sink makes readiness false; deleting archive rows or resetting its head is not recovery.

Production WAL mode is admitted only on SQLite 3.53 or newer, the 3.51.3 patch line, or the
maintained 3.50.7/3.44.6 backports. Earlier affected builds and the withdrawn 3.52.x line are
refused. The validator checks the loaded library inside the exact image digest, the server rechecks
it before opening production state, and `/v1/info` records `sqlite_version` for evidence.

LETS v1 has no in-place core-audit deletion or live configuration-epoch rollover. Do not delete
SQLite rows, WAL/SHM files, audit records, receipts, or idempotency state by hand. A deployment whose
measured growth cannot fit its planned lifecycle is not ready for that workload; drain and retire
it under an explicitly reconciled new envelope/epoch before the capacity reserve is reached.

On a capacity or `SQLITE_FULL` incident, remove the node from routing and fence mutation traffic.
Extend the state filesystem or remove only unrelated host data; never manipulate LETS database,
anchor, audit, or outbox files. An actual SQLite-full error is sticky in the running process, so
after restoring headroom stop the container, prove the node lock is free, run
`lets info --production` from `maintenance-compose.yaml`, drain the node, and create a verified
recovery bundle before deciding whether to reactivate it. Repeated crash-loop restarts are not a
recovery procedure.

## Credential and trust rotation

TLS material and the generic provider's JWT verification-key set are loaded when the process
starts; they are not live-reloaded. Rotate them with an overlap window: provision CA bundles and
identity-key JSON containing both old and new trust, recreate one drained warden at a time, verify
mTLS/JWT canaries, rotate every peer/client, and remove old trust only after the maximum token
lifetime, clock skew, connection lifetime, and certificate rollout window have elapsed. Compose
file-backed secrets require container recreation to pick up new material.

The Python TLS boundary does not perform online OCSP fetching. Use short-lived server and client
certificates, restrict CA scope to LETS, and make emergency CA/certificate distrust a recreate-all
incident with network fencing until every affected process has restarted. If the platform requires
real-time workload-certificate revocation, terminate mTLS in an approved proxy or service-mesh
identity layer and preserve equivalent authenticated peer identity end to end.

The warden signing identity is bound to the signed manifest, database, and authority checkpoint;
replacing it without an admitted manifest/epoch transition is rejected. Never edit the staged
`config.json` in place. Use the release runbook's exclusive staging and recreate procedure for an
approved non-authority configuration change. Follow the new-manifest/new-epoch drain procedure for
identity changes, and retain old verification keys for every still-valid receipt and queued peer
record.

## Upgrade and rollback

Follow [the release runbook](../../docs/release.md). Never move a mutable tag into production.
LETS v1 does not support a live mixed-version cluster. Drain every warden and remove external
mutation traffic while keeping the internal peer/audit paths available; settle those queues, then
fence the cluster, stop every old process, and create a separately verified recovery bundle and
authority checkpoint for every node before starting any replacement. Stage the same verified digest
on all nodes, start the entire cluster in its durable drained state, prove uniform version/config,
invariants, capacity, audit state, and peer reachability, then activate and canary the uniform
cluster before restoring traffic. Do not restore a database behind its monotonic anchor. The signed
v1.0.1 through v1.0.4 tags were never promoted and are not rollback artifacts; v1.0.0 lacks the
later production defenses, so v1.0.5 has no approved earlier binary rollback target. Recover
forward with a patch release unless future release notes explicitly name a compatible published
digest. A restore is admitted only while fenced and only when the live anchor proves the bundle
cannot resurrect spent authority.

## Provider integration boundary

The bundled `generic-production` provider makes the deployment runnable without coupling LETS to
one cloud or HSM vendor. Operators must still supply the signer bridge, identity trust keys, signed
cluster manifest, and PKI material described above; those are security-domain inputs, not missing
runtime components. LETS fails closed if the provider cannot sign, the external audit archive is
unavailable, the monotonic anchor cannot advance, identity keys are invalid, or TLS/mTLS material is
absent. A cloud KMS, PKCS#11, SPIFFE, or OIDC integration can replace this provider through the same
entry-point contract without changing the core runtime or Compose hardening.
