# Operating a LETS cluster

This guide describes the standalone SQLite warden deployment. Each warden owns one independent
core database, stable signing identity, externally monotonic authority anchor, and a disjoint
genesis share. The core database is also the sole peer HTTP replay authority in schema 2.

## Bootstrap requirements

Before starting any node:

1. create one cluster manifest with an ordered resource schema and exact global budget;
2. assign each budget unit to exactly one warden (`sum(initial_share) == initial_budget`);
3. include every warden endpoint and Ed25519 public key;
4. include immutable policy and machine digests;
5. obtain the configured operator-signature threshold;
6. provision each private key through a secret store or a protected local file;
7. initialize every node from the same manifest digest and epoch.

`ClusterManifest` rejects duplicate warden/key IDs or peer origins, public-key material reused
across identities, operator-key aliases that would inflate a signature threshold, operator keys
reused by online wardens, policy drift, vector-shape drift, and under- or over-allocation. Plain
HTTP endpoints require an explicit development override. Production manifests use HTTPS.

Never independently initialize two wardens with the full budget. Local invariants cannot detect a
bad genesis split after the fact.

## Local environment

Use the repository-local environment only:

```powershell
uv sync --all-extras --frozen
uv run lets --help
```

Do not run `pip install` against the system interpreter. The CLI writes development state below
the selected project-local configuration directory; `.lets/` is ignored by Git.

## Development initialization

For a one-node local setup:

```powershell
uv run lets --config .lets/a/config.json init `
  --warden-id warden-a `
  --tenant-id example `
  --envelope-id agents `
  --budget 1000000,100000000 `
  --local-share 1000000,100000000
```

The generated bootstrap token is printed once; only its SHA-256 digest is stored. Treat the raw
Ed25519 seed and token as secrets. The warden database stores the signing key ID, never the private
seed; the seed file or external signer must therefore be backed up separately. For multiple nodes,
use the checked manifest/bootstrap workflow and Docker example rather than giving every node the
full budget.

## Provider-backed production provisioning

Production initialization never writes a raw signing seed or static bootstrap identity. Initialize
the provider's independent audit archive, then admit the signed manifest and select the provider in
the one authorized genesis operation:

```powershell
uv run lets --config C:\lets\node\config.json init `
  --production --warden-id warden-a `
  --manifest C:\lets\trust\cluster.json `
  --operator-key operator-a=BASE64URL_PUBLIC_KEY `
  --runtime-provider generic-production `
  --runtime-option signer_command_json='["C:\lets\bin\hsm-sign.exe"]' `
  --runtime-option signer_key_id=warden-a/ed25519-managed `
  --runtime-option signer_public_key=BASE64URL_PUBLIC_KEY `
  --runtime-option identity_keys_file=C:\lets\trust\identity-keys.json `
  --runtime-option identity_issuer=https://identity.example `
  --runtime-option identity_audience=lets `
  --runtime-option authority_anchor_path=C:\lets-authority\warden-a.json `
  --runtime-option audit_archive_path=C:\lets-audit\warden-a.sqlite3 `
  --min-free-disk-bytes 1073741824 `
  --max-database-bytes 10737418240 --reserve-pages 1024
```

Runtime options are persisted and may contain only non-secret handles, paths, public material,
issuers, and timeouts; never put a token, PIN, credential, or private key in an option. Provider
admission and a live signing proof happen before any local node artifact is created. The managed
key must match the local warden key in the operator-signed manifest. The independent monotonic
anchor and audit archive must not share the node snapshot or each other's failure domain.

## Serving

Loopback development:

```powershell
uv run lets --config .lets/a/config.json serve --host 127.0.0.1 --port 8741
```

Non-loopback serving fails unless TLS certificate/key paths are configured or the explicit
`--allow-insecure-http` development flag is present. Peer payloads are additionally Ed25519
message-signed and protected by durable timestamp/nonce replay detection. Use TLS even with those
signatures because message signing does not provide confidentiality.

Outbound peer clients verify the system trust store by default. Use `--peer-ca` for a private CA
and the `--peer-cert`/`--peer-key` pair when peers require mTLS. Cleartext peer origins are rejected
unless they came from a manifest accepted with `--allow-insecure-manifest` or serve is started with
the separate `--allow-insecure-peer-http` development override. Peer endpoints are origin URLs;
credentials, paths, queries, fragments, and invalid ports are rejected at startup.
Hosts must be ASCII DNS names or IP literals; internationalized names must be supplied in explicit
IDNA A-label form so manifest admission and the HTTP transport cannot normalize them differently.
Every outbound target must also have at least one currently valid trusted verification key;
startup rejects an endpoint/key mismatch, and transfer preparation rechecks the target immediately
before any local rights are debited.

Startup admission performs full core-database integrity, foreign-key, conservation, signed-audit,
and peer-replay-authority checks. A peer nonce claim, replay clock-floor advance, replay history
digest, signed audit row, and audit-outbox row commit in one core transaction; the existing
post-COMMIT external-anchor comparison is its linearization point. A crash before that comparison
faults the process, and restart admits only a provable contiguous extension. New schema-2 nodes do
not create or open a separate replay database.
`/health/live` reports process liveness. The unauthenticated `/health/ready` path is deliberately
bounded: it performs a cheap database read and checks the durable clock floor and current signing
key, rather than repeating database-size scans on every probe. Use `lets info` for explicit deep
diagnostics. Route traffic only to ready nodes. A locally ready warden can continue spending only
its local escrow share during a peer partition.

`serve --production` requires inbound mTLS (`--tls-cert`, `--tls-key`, and `--client-ca`). When
peers are configured it also requires outbound `--peer-ca`, `--peer-cert`, and `--peer-key`.
`--limit-concurrency`, `--request-body-timeout`, `--timeout-keep-alive`, and
`--timeout-graceful-shutdown` bound overload, body receipt, idle connections, and termination. The
request-body timeout is a total application deadline around pre-authentication body buffering; an
incomplete body receives a `408 request_body_timeout` problem and the connection is closed. It is
independent of the HTTP keep-alive timeout. Give the process at least its graceful-shutdown interval
before a hard kill. The server owns the node process lock for its entire lifetime, so recovery and
schema migration cannot run concurrently with it. Production readiness also requires a healthy,
bounded audit exporter; a blocked sink, excessive backlog, or stalled export makes readiness false.

`max_clock_uncertainty_ns` is an operator-attested upper bound, not a measured guarantee. Monitor
the actual source and configure a conservative bound. Core warden authority and executor replay
stores persist monotonic clock floors and fail closed after a restart if wall time rolls back beyond
the declared tolerance. A forward jump can expire authority early and reduce availability, but
cannot revive it.

## Policy rollout

Policies are immutable and content addressed. A policy version can never be rebound to different
content. Resource dimensions, receipt TTL, clock uncertainty, and transfer gap window are
configuration-epoch properties and cannot drift between policies within an envelope.

Roll out a policy to every warden and compare digests before activation. Live configuration-epoch
rollover is not a v1 operation; create a new envelope/epoch and drain the old one.

## Transfers and partitions

A source prepare permanently moves rights from its free pool into cumulative transferred-out
accounting and signs a sequenced voucher. The same transaction writes the exact signed payload to
the durable peer outbox. Timeout never refunds the source. The running dispatcher preserves
per-stream order, retries at least once with bounded exponential backoff, receives the target's
signed acknowledgement, and finalizes the source record without operator key access.

Targets accept each sequence exactly once, tolerate a bounded out-of-order window, and reject
conflicts or gaps beyond that window. After both sides have a finalized contiguous prefix, the
dispatcher creates and delivers a signed checkpoint. Transfer outbox payloads are retained until
that checkpoint is confirmed, then terminal transfer/checkpoint/revocation payloads are pruned;
bounded aggregate counters preserve delivery observability.

During a partition:

- continue local transitions while leases, receipts, and clock bounds remain valid;
- monitor `peer_dispatcher.pending_records`, `failed_records`, and `prepared_transfers`; the
  runtime retains and retries the exact signed business record;
- do not manually edit pools or restore timed-out transfers;
- accept that rights stranded at the other warden are unavailable.

## Backup and restore

The database-only `lets backup` command remains for development compatibility. Production uses an
exclusive, exact recovery bundle:

```powershell
uv run lets --config C:\lets\node\config.json drain --reason "scheduled recovery point"
# Wait for peer-delivery and audit-export queues to reach zero, then stop the server.
uv run lets --config C:\lets\node\config.json recovery backup --production `
  --output D:\lets-backups\warden-a-20260809T120000Z
uv run lets --config C:\lets\node\config.json recovery verify --production `
  --bundle D:\lets-backups\warden-a-20260809T120000Z
```

Backup proves DRAINING state, empty peer/audit queues, core integrity/schema/replay authority,
conservation, signed audit continuity, healthy capacity, manifest/current-key trust, and agreement
with the independent authority anchor. SQLite's backup API snapshots the sole authoritative core
database. LETS fsyncs every file and publishes the directory with a durable rename. `bundle.json`
binds exact paths, lengths, SHA-256 digests, identity, schema, and a checkpoint summary. A schema-2
bundle containing the retired schema-1 replay artifact is rejected as mixed authority.

Every production recovery or migration command also requires the live operator-signed manifest,
its persisted trust inputs, no static bootstrap identity, and explicit positive storage reserves.
The bundle contains byte-exact copies of the live config and signed manifest, never provider
secrets.

The independent authority anchor is deliberately never copied into the bundle. Managed-key
recovery material and identity credentials also remain provider-owned. Encrypt and protect the
bundle, but keep the anchor on its independent non-rollback service or volume. Snapshotting the
anchor beside the database defeats stale-restore fencing.

For the production Compose profile, record the actual state, authority, audit, and backup
controller/volume identities in the four `LETS_*_ROLLBACK_DOMAIN` values. They must be distinct;
the authority and backup boundary kinds must also declare `fenced-filesystem` and
`dedicated-filesystem`, respectively. These declarations are operator attestations because host
paths and device numbers cannot reveal storage-controller snapshot grouping. The validator does
require four distinct mounted-filesystem device identities, and a quota does not waive that
minimum. It also requires each directory to be the exact Linux mountpoint with no nested mount and
rejects network, overlay, RAM, and desktop-share filesystems; the shipped Compose binds use private
mount propagation. Docker Desktop paths are not a production storage boundary. Commissioning
evidence must additionally exercise independent restore permissions and prove that no snapshot job
can include both the database and either monotonic anchor.

The bundle parent is also the explicit recovery scratch/quarantine domain. In production it must
already exist outside the node state directory on the independent backup volume. Candidate and
migration verification copy there, never to the runtime's small default temporary filesystem.
LETS checks exact artifact bytes plus 1 MiB metadata headroom before copying. Restore separately
admits the peak atomic-replacement bytes on state storage and the live core/sidecar preservation
bytes on backup storage before it writes its journal.

Restore is explicitly destructive and requires the trusted live config, production provider, node
lock, exact warden confirmation, and current external anchor:

```powershell
uv run lets --config C:\lets\node\config.json recovery restore `
  --bundle D:\lets-backups\warden-a-20260809T120000Z `
  --confirm-warden-id warden-a
```

LETS validates a temporary copy unanchored before replacing any live file. An old, ahead, or forked
database is rejected by a non-mutating exact read of the current anchor before audit-archive repair
or publication; standalone verification does not mutate the archive. A durable restore journal
fences serving through `PREPARED` and `CORE_INSTALLED` and lets the exact command resume after a
crash. Exact pre-restore core/sidecar copies remain in the backup-domain quarantine only while the
journal is incomplete; after the second anchored admission, LETS records `COMPLETE` and removes
only that exact allow-listed quarantine. These copies are never authority rollback points. A
restored node remains DRAINING.
Run `lets info --production`, reconcile peers and the incident, then use
`lets activate --reason ...` only after every check is green.

Operational opens use SQLite `mode=rw` and never initialize missing authority implicitly. Losing a
database is not permission to rerun genesis. See [upgrade and recovery](upgrade-recovery.md) for
the resumable schema-transition and fault procedure.

## Protected-executor authority

Every production protected executor uses its own schema-5 replay database and monotonic executor
anchor. Keep their directories on independent failure/rollback domains with separate credentials;
never include the anchor in a database snapshot or restore. Build the replay identity with
`executor_replay_identity(policy, registry)` after loading the exact key bytes and validity bounds
from the authenticated signed manifest. Runtime key discovery is diagnostic and must not replace
that trust root. Reopen requires the same complete policy and registry digest, so policy widening
or same-warden key substitution is a deliberate new authority epoch rather than a live config
edit.

`verify_and_claim()` returns only after the local claim commit and external CAS acknowledgement.
If the anchor times out after commit, the caller receives an error, the store remains faulted, and
the protected effect must not run. Restart with the same database and anchor; reopen advances a
committed-ahead local head only when its append-only history extends the anchored digest. An older
or divergent database remains fenced. Do not delete or rewrite the anchor to restore availability.

Before copying an executor database, quiesce claim callers and require
`SQLiteReceiptReplayStore.checkpoint_wal()` to report `busy == 0`. Copy only the main database; do
not combine WAL/SHM from a different instant, and do not copy the anchor. After a restore, exact
open against the live anchor is the admission test. Monitor `store.status()` for rollback
protection, authority health, claim sequence, clock floor, database/WAL/SHM bytes, live replay rows,
and filesystem free bytes.

Expired replay rows and watermarks are deleted in batches of at most 128 per accepted receipt, but
the authority claim chain never shrinks. Allocate a dedicated quota for a finite executor epoch and
alert before exhaustion; `SQLITE_FULL` disables effects. Schema 4 cannot be promoted because it has
no externally provable claim history. Drain for the maximum receipt lifetime plus clock
uncertainty, prove no effects are in flight, archive the old database, then initialize a fresh
schema-5 database and unused anchor path. Use the same drain-and-new-anchor procedure for capacity
rotation. `allow_unanchored=True` is restricted to disposable development/test executors.

## Key rotation

Wire records bind `warden_id` and `key_id`. Add and distribute a new trusted public key before
using it, and remove the old public key only after all signed records that may still arrive are
expired or checkpointed and every durable peer-delivery row for that key is drained.
Hardware/external key providers are preferred for production. The included raw-seed provider is a
portable bootstrap implementation. Its seed never enters the SQLite database.

A finite manifest `not_after` is a hard drain deadline, not a rotation grace period: v1 retries
durable peer records without a fixed maximum age, while verification rejects signatures after the
key interval. Stop new durable mutations, prove transfer/revocation/checkpoint outboxes empty, and
complete bilateral compaction before that time. Active v1 warden keys should normally omit a
finite `not_after` unless this drain is operationally enforced.

The v1 database is immutably bound to its configured key ID and public-key fingerprint, so simply
replacing its seed is intentionally rejected. Automated in-place rotation is not a v1 CLI
operation: drain into a new manifest/configuration epoch and database, retain historical public
keys for receipt/audit verification, and rehearse the cutover and rollback procedure first.

## Audit and incident response

Audit rows are append-only, hash chained, and signed. Query them through `/v1/audit` with bounded
pagination and verify the complete chain through `/v1/audit/verify`. Full verification streams the
ordered cursor row by row, so audit history and payload size do not require an equivalent in-memory
copy. Export outbox events to a separate retention system; the local log is authoritative for
detection but is not an external anti-rollback anchor.

On suspected compromise:

1. remove the warden from service and fence its workload identity;
2. preserve database/key/config evidence without starting a clone;
3. revoke affected branches from a trusted warden where possible;
4. verify audit and transfer checkpoints against peer copies;
5. treat every unexpired receipt from the compromised key as suspect;
6. rotate trust through a new manifest/epoch after containment.

## Capacity and maintenance

Monitor disk space, WAL size, write latency, SQLite busy errors, clock uncertainty, receipt expiry,
transfer gaps, finalized/compacted watermarks, peer-dispatch retry/backlog counters, invariant
health, and audit-outbox lag. Checkpoint and terminal peer-outbox compaction are automatic; schedule
audit-outbox export. Do not delete signed audit or idempotency history by hand.

The database contains sensitive subjects, lineage, receipts, and audit state and is not encrypted
at rest. Creation applies mode `0600` best-effort on POSIX; operators remain responsible for parent
directory permissions, Windows ACLs, container-volume permissions, backup encryption, and access
control. WAL and shared-memory files inherit the database directory's ownership and must be
protected with the same policy.

One SQLite database owns one envelope and one live warden identity in v1. Keep it on a local disk
or local container volume; do not place the database on NFS, SMB, a replicated filesystem, or a
shared volume, and never run concurrent clones against it. Scale by assigning independent
envelopes and disjoint manifest shares to independent warden processes. A different storage
adapter is safe only after it has equivalent transaction, recovery, fault, and conformance
evidence.
