# Upgrade and recovery runbook

LETS schema migration is an explicit stop-the-world operation. The current release supports the
single expand-only schema 1 to schema 2 transition. It does **not** claim rolling schema upgrades,
mixed-version serving, or database rollback after an irreversible migration.

## Preconditions

1. Drain the warden and let existing transfer acceptance/finalization converge.
2. Confirm peer delivery and external audit-export queues are empty.
3. Stop the server. The migration command must acquire the same node lock that `serve` holds for
   its full lifetime.
4. Keep the schema-1 node stopped until every legacy peer-signature claim has expired. With the
   current 30-second skew window, the worst-case validity interval is 60 seconds. Migration checks
   the legacy store and refuses to write while even one live claim remains.
5. Preserve the independent authority service, managed signer, audit archive, identity keys, and
   signed manifest. Do not copy or rewind the authority anchor with node state.
6. Choose a new, nonexistent backup directory on independent protected storage. Its existing
   parent directory is the explicit scratch and quarantine domain; do not put it under node state.

Schema 1 predates durable runtime-control and external database-instance fencing, so it cannot
record DRAINING. For that one transition, the node process lock and stopped server are the
stop-the-world fence. Schema 2 introduces durable DRAINING state and the database-instance ID.

## Rehearse without mutation

```powershell
uv run lets --config C:\lets\node\config.json migrate --production --dry-run `
  --backup D:\lets-backups\warden-a-before-v2
```

Dry-run verifies application/schema identity, core/legacy-replay integrity, foreign keys, empty
queues, zero live legacy peer claims, the provider signer and manifest trust, and migration
compatibility on a disposable copy beside the requested backup path. It does not use the runtime
`/tmp`, create the backup, or change the source database.

## Execute

```powershell
uv run lets --config C:\lets\node\config.json migrate --production `
  --backup D:\lets-backups\warden-a-before-v2
```

Before its first source write, LETS creates and re-verifies an exact schema-1 recovery bundle and
durably writes `migration-v1-v2.json`. The journal binds the warden, source/target versions, exact
backup path, and SHA-256 of `bundle.json`. Migration then commits the expand-only schema, records
the migration-owned DRAINING state, bootstraps/reconciles the provider's independent anchor, opens
the result through that anchor, and advances the journal through these phases:

- `BACKUP_VERIFIED`
- `DATABASE_MIGRATED`
- `ANCHOR_ADMITTED`
- `COMPLETE`

The node remains DRAINING after `COMPLETE`; activation is a separate operator decision.

Schema 2 folds peer HTTP replay authority into the core database. Migration binds the exact
SHA-256 of the frozen schema-1 replay artifact, imports its monotonic clock floor, advances that
floor to migration time, and appends a signed audit/outbox event before anchor admission. It does
not copy an unbounded nonce set: the precondition above proves all old claims have expired. The
separate schema-1 replay file remains immutable migration evidence and is never opened by a v2
server or included in a v2 recovery bundle.

## Resume after power loss or provider failure

Never delete or edit the journal or backup. Re-run against the same exact paths:

```powershell
uv run lets --config C:\lets\node\config.json migrate --production --resume `
  --backup D:\lets-backups\warden-a-before-v2
```

Resume rehashes and fully verifies the schema-1 bundle and journal. If the schema transaction
committed but the process died before the drain, LETS accepts only the exact pristine expansion
state (`ACTIVE`, generation 0, schema-initialization provenance) and requires its authority-state
fingerprint to match the verified schema-1 bundle before atomically recording DRAINING. Any other
ACTIVE state is rejected. If the drain committed but anchor admission failed, resume reconstructs
the checkpoint and reconciles it through the same provider anchor. Repeating resume after
`COMPLETE` is idempotent: it neither reinitializes authority nor activates the node.

The external anchor is authoritative. A missing anchor may be initialized only by this journaled
schema-1 transition. An existing anchor is reconciled with compare-and-swap semantics; it is never
unconditionally replaced. A stale, divergent, or differently identified database remains fenced.

## Recovery bundles

`recovery verify` checks exact membership and hashes without writing into the protected bundle or
external anchor/archive; repeated verification works on read-only media. The bundle parent is the
explicit recovery workspace, so production rejects a bundle stored in or above node state and
fails before copying unless it has the exact candidate bytes plus 1 MiB metadata headroom. For a
current-schema disaster restore, stop the server and run:

```powershell
uv run lets --config C:\lets\node\config.json recovery verify --production `
  --bundle D:\lets-backups\warden-a-v2
uv run lets --config C:\lets\node\config.json recovery restore `
  --bundle D:\lets-backups\warden-a-v2 --confirm-warden-id warden-a
```

Restore opens a temporary copy without exposing it to the live independent anchor. Candidate
integrity, conservation, and signed audit verification run unanchored; only then does LETS perform
a non-mutating exact comparison with `read_current()`. Audit-archive repair is allowed only after
that exact comparison, while `recovery verify` remains entirely non-mutating. An older backup
cannot resurrect consumed or transferred rights, and an invalid, stale, ahead, or forked candidate
cannot poison either the anchor or archive. LETS preserves exact pre-restore database/sidecar
copies in a direct-child quarantine beside the bundle, then advances a durable
`recovery-restore.json` journal through `PREPARED`, `CORE_INSTALLED`, and `COMPLETE`. Before writing
the journal it admits both peak same-filesystem replacement bytes and backup-domain quarantine
bytes. `serve`, lifecycle commands, backup, and migration refuse every incomplete phase; the same
exact restore command safely resumes publication. After the core file is durable LETS performs a
second anchored admission, marks the journal complete, and deletes only the exact allow-listed
temporary quarantine files. It never restores the anchor itself or silently rewrites trusted
config.

## Post-upgrade admission

Run `lets info --production` and inspect every named check. It returns nonzero for any serve
blocker: schema/identity drift, core replay-authority corruption, foreign-key failure,
manifest/operator signature drift, missing/current-key failure, invalid peer endpoints/trust,
unsafe clock floor,
conservation failure, audit-chain failure, anchor disagreement, capacity exhaustion, non-ACTIVE
runtime state, or unhealthy audit export. Reconcile the release and peers while still DRAINING,
then activate explicitly:

```powershell
uv run lets --config C:\lets\node\config.json activate `
  --reason "v2 migration and admission checks complete"
uv run lets --config C:\lets\node\config.json info --production
```

Do not start an older binary against the migrated database. Roll forward with `--resume` or restore
a separately fenced authority unit only when the current independent anchor admits it.
