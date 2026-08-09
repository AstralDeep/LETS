# Operating a LETS cluster

This guide describes the standalone SQLite warden deployment. Each warden owns one independent
database, stable signing identity, durable peer-replay database, and a disjoint genesis share.

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

Startup admission performs full warden-database integrity, foreign-key, and conservation scans and
verifies the peer replay database's application identity, exact critical schema, WAL mode, and
integrity once.
`/health/live` reports process liveness. The unauthenticated `/health/ready` path is deliberately
bounded: it performs a cheap database read and checks the durable clock floor and current signing
key, rather than repeating database-size scans on every probe. Use `lets info` for explicit deep
diagnostics. Route traffic only to ready nodes. A locally ready warden can continue spending only
its local escrow share during a peer partition.

`max_clock_uncertainty_ns` is an operator-attested upper bound, not a measured guarantee. Monitor
the actual source and configure a conservative bound. Warden, executor, and peer-replay databases
persist monotonic clock floors and fail closed after a restart if wall time rolls back beyond the
declared tolerance. A forward jump can expire authority early and reduce availability, but cannot
revive it.

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

The database, separately provisioned signing seed, peer replay database, configuration, signed
manifest, and operator trust roots form one authority unit. Fence command and peer traffic first,
then create the database portion with SQLite's consistent backup API:

```powershell
uv run lets --config .lets/a/config.json backup --output .lets/backups/warden-a.sqlite3
```

The command refuses to overwrite a destination and verifies the produced database. It backs up
only the warden database. To form a complete recovery bundle, snapshot the resulting database,
signing seed or external-signer recovery material, peer replay database, configuration, manifest,
and operator trust roots while the node remains fenced. Preserve ACLs, encrypt the bundle, and
record its checksum, manifest digest, configuration epoch, last audit hash/sequence, and transfer
watermarks. Do not treat a copied main database file without its WAL as a backup, and do not
manually copy live `-wal` or `-shm` files as a substitute for the backup API.

Operational opens use SQLite `mode=rw`: `serve`, `info`, and `backup` refuse missing or empty
warden/replay databases and never initialize authority implicitly. Only `lets init` may create the
genesis share and replay store. Losing either database is a fail-closed recovery event, not a reason
to rerun initialization; restore the complete fenced authority unit.

After restore, run `lets info`, database integrity/foreign-key checks, audit verification, and peer
watermark reconciliation before restoring readiness. Restoring an old clone while the original
continues running duplicates authority and is outside the v1 safety model. Fence the old instance
with infrastructure controls first.

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
pagination and verify the complete chain through `/v1/audit/verify`. Export outbox events to a
separate retention system; the local log is authoritative for detection but is not an external
anti-rollback anchor.

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
