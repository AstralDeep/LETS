# LETS implementation table

## Scope and provenance

This note separates current implementation facts from recommendations for paper or
deployment language. Source citations are repository-relative and line-specific. The
generated inventory is bound to Git revision
`a9f4ba810e1741f93ba204eb782b6c4e3d409a03`, records that the working tree was dirty,
and includes a SHA-256 digest for every counted source file
(`results/nsdi-strengthening-2026-08-31/implementation/implementation-inventory.md:3-7`).
The table below describes the current Python/SQLite implementation, not a generic backend
that has not been inventoried. “Trust role” is an architectural interpretation of the
code's enforcement responsibility, not a runtime annotation.

## Current implementation facts

| Component | Responsibility | Storage | Atomicity boundary | Trust role | Source evidence |
|---|---|---|---|---|---|
| Warden service | Makes fail-closed lease, policy, debit, state-transition, transfer, and signed-receipt decisions for one stable warden. | Consumes a `Storage` protocol; the concrete backend inventoried here is one-envelope `SQLiteStorage`. | The service defines the local serialization point: safety decisions and durable consequences execute in one explicit SQLite write transaction. Authorization signs the receipt, debits the lease, increments cumulative consumption, stores the receipt and audit event, and records the idempotent response before the transaction exits. | Trusted authorization and accounting boundary. Clients do not decide whether an operation is allowed. | `src/lets/service.py:1-6`; `src/lets/service.py:99-115`; `src/lets/service.py:165-183`; `src/lets/service.py:2570-2583`; `src/lets/service.py:2802-2827`; `src/lets/service.py:2828-2899`; `src/lets/storage/sqlite.py:1781-1803` |
| Public client | Sends blocking HTTP requests with configured bearer/TLS credentials and applies bounded retries only to idempotent operations; `authorize` submits a transition request to the lease endpoint. | No authority ledger or claim database is owned by `LETSClient`; its state is an HTTP client, retry policy, locks, and request limits. | One client request is not a safety transaction. Request idempotency is presented to, and durably enforced by, the warden boundary. | Outside the narrow enforcement core; treat request fields and transport responses as untrusted inputs at the warden. | `src/lets/client.py:182-200`; `src/lets/client.py:208-238`; `src/lets/client.py:461-473`; narrow-core enumeration at `benchmarks/nsdi_strengthening/implementation_inventory.py:20-38` |
| Receipt signer and trust registry | Creates Ed25519 signatures over canonical unsigned records; verifiers resolve a `(warden_id, key_id)` to a trusted verification key. | `Ed25519Signer` holds a PyNaCl signing key in process memory. It can generate a key or load an exactly 32-byte raw seed from a file; this module is not an encrypted keystore or HSM adapter. | Receipt signing occurs while the warden write transaction is open; the signed bytes, debit, receipt row, and idempotent response are committed by the surrounding warden transaction. | Trusted cryptographic authority. Loss of seed confidentiality or incorrect registry configuration compromises receipt authenticity. | `src/lets/crypto.py:23-61`; `src/lets/crypto.py:70-75`; `src/lets/service.py:892-911`; `src/lets/service.py:2776-2804`; `src/lets/service.py:2828-2868` |
| Executor verifier | Fail-closed protected-executor boundary. Checks executor/tenant/envelope/config binding, policy and machine digests, trusted warden, freshness, and signature before requesting a durable claim. | Holds policy and registry in memory and delegates durable state to a `ReceiptReplayStore` protocol. | `verify_and_claim` verifies first, then calls the replay store's claim operation. The physical actuator is not inside this method or the claim transaction. | Trusted pre-effect enforcement boundary. The integration must invoke the physical effect only after successful return. | `src/lets/executor.py:51-70`; `src/lets/executor.py:1372-1393`; `src/lets/executor.py:1415-1453`; `src/lets/executor.py:1459-1466` |
| SQLite replay/claim store | Provides durable single-use receipt settlement, nonce uniqueness, per-lease sequence watermarks, a durable clock floor, and chained claim history. | Filesystem-backed SQLite database; production construction requires an executor authority anchor unless explicit development-only unanchored mode is selected. | Each claim uses explicit `BEGIN IMMEDIATE`, commits the claim transaction, then reconciles/publishes the anchored head. Primary/unique constraints reject duplicate receipt IDs and `(tenant, envelope, audience, nonce)` tuples. | Trusted durable settlement state. Losing or rolling back this state can permit replay unless the independently protected anchor detects it. | `src/lets/executor.py:151-182`; `src/lets/executor.py:281-302`; `src/lets/executor.py:357-389`; `src/lets/executor.py:1045-1066`; `src/lets/executor.py:1085-1126`; `src/lets/executor.py:1160-1199` |
| Warden SQLite store | Persists envelope metadata, free and consumed authority, leases, receipts, transfers, policies, audit records, idempotency records, and the durable clock floor. | One filesystem-backed SQLite database per store/envelope identity. It is durable storage, not encryption at rest. | Connections use Python explicit-autocommit mode (`isolation_level=None`); writes explicitly begin with `BEGIN IMMEDIATE`, run conservation checks before commit, commit once, and reconcile the external authority anchor after commit before allowing observations through the storage instance. | Trusted authoritative state and local writer-serialization point. | `src/lets/storage/sqlite.py:1781-1803`; `src/lets/storage/sqlite.py:1983-2014`; `src/lets/storage/sqlite.py:2029-2041`; `src/lets/storage/sqlite.py:3102-3137`; `src/lets/storage/sqlite.py:3147-3181` |
| Rollback anchors | Detect stale database restoration or cloned histories by comparing monotonic authority/claim checkpoints outside the primary database. File and helper-process-backed file implementations exist for both warden and executor state. | Separate durable anchor file; production documentation requires a failure/rollback domain independent from the protected database. | Storage reconciles the anchor before beginning a mutation and publishes/reconciles the committed head after the database commit. The file implementation serializes access across processes. | Trusted rollback-fencing authority. Co-snapshotting the anchor with its database defeats the stated protection. | `src/lets/authority.py:308-339`; `src/lets/authority.py:465`; `src/lets/executor_authority.py:235-245`; `src/lets/executor_authority.py:300`; `src/lets/storage/sqlite.py:3122-3137`; `src/lets/storage/sqlite.py:3178-3181`; `src/lets/executor.py:1045-1062` |

## Cryptography, wire format, IDs, clocks, and transactions

These are source-verified facts:

- **Signature and key format.** Receipts use PyNaCl Ed25519. A signer is backed by a
  32-byte raw private seed; its encoded public verification key is exposed as bytes. The
  key ID is `<warden-id>/ed25519-<fingerprint>`, where `fingerprint` is the first 32 hex
  characters of SHA-256 over the public key. Signatures are base64url-encoded on wire
  (`src/lets/crypto.py:14`; `src/lets/crypto.py:23-40`;
  `src/lets/crypto.py:50-61`; `src/lets/crypto.py:70-75`).

- **Canonical serialization.** Signed protocol objects use UTF-8 JSON with sorted object
  keys and compact `,`/`:` separators. The accepted canonical domain has string keys,
  signed 64-bit integers, strings, booleans, null, and ordered arrays; floats and unordered
  sets are rejected. The strict decoder rejects duplicate object keys, non-finite numbers,
  and floating-point numbers and then re-runs canonical validation
  (`src/lets/canonical.py:16-43`; `src/lets/canonical.py:46-66`;
  `src/lets/canonical.py:69-95`).

- **Operation identifiers.** `new_id(kind)` validates the kind prefix and appends
  `uuid4().hex`; the implementation does not derive identifiers from time, process ID, or
  database sequence (`src/lets/ids.py:15-19`).

- **Clock and uncertainty.** `SystemClock` uses `time.time_ns()` and requires callers to
  declare a non-negative signed-64-bit uncertainty. The warden rejects uncertainty above
  the envelope maximum and rejects time that moves behind its durable clock floor beyond
  that uncertainty. The executor separately rejects uncertainty above its executor-policy
  maximum and evaluates issuance/expiry against the uncertainty interval
  (`src/lets/clock.py:19-38`; `src/lets/service.py:461-517`;
  `src/lets/executor.py:1395-1413`; `src/lets/executor.py:1438-1441`).

- **SQLite isolation and durability.** Both authoritative stores use
  `isolation_level=None`, so transaction scope is explicit rather than Python's implicit
  transaction management. Both select WAL and `synchronous=FULL`; mutations use
  `BEGIN IMMEDIATE`, which obtains SQLite's writer reservation before safety decisions and
  serializes competing writers. The source does not select or claim a named SQL-standard
  isolation level such as `SERIALIZABLE`; the precise statement is “explicit
  `BEGIN IMMEDIATE` writer transactions under SQLite WAL with `synchronous=FULL`”
  (`src/lets/storage/sqlite.py:1983-2009`; `src/lets/storage/sqlite.py:3135-3148`;
  `src/lets/executor.py:281-302`; `src/lets/executor.py:1045-1053`).

## Executor-replica and claim-store caveat

The verifier is parameterized by a `ReceiptReplayStore` protocol, but the concrete durable
backend inventoried here is the local filesystem-backed `SQLiteReceiptReplayStore`
(`src/lets/executor.py:51-58`; `src/lets/executor.py:151-176`;
`src/lets/executor.py:1375-1392`). The source and generated inventory establish durable
uniqueness within that claim database; they do not establish a networked, replicated, or
high-availability claim service. The inventory itself describes the concrete backend as
“a local SQLite replay store”
(`results/nsdi-strengthening-2026-08-31/implementation/implementation-inventory.md:22`).

Therefore, a deployment with multiple executor replicas must route all replicas through
one shared, authoritative claim namespace with equivalent atomic uniqueness and rollback
protection. Saying that independently hosted replicas already share such a backend would
be a recommendation or future deployment requirement, not a fact demonstrated by the
current implementation. A SQLite file on one host may be a single shared local claim
boundary, but this evidence does not qualify cross-host filesystem sharing or failover.

## Trusted-core source footprint

The generated inventory reports:

| Counted group | Files | Physical lines | Nonblank lines |
|---|---:|---:|---:|
| Whole `src/lets/**/*.py` runtime | 34 | 28,573 | 26,738 |
| Enumerated narrow enforcement core | 18 | 16,169 | 15,188 |

These values are exact for the inventoried working-tree bytes and counting rule, but they
are physical/nonblank line counts rather than semantic SLOC. The full 18-file list is
explicit in `benchmarks/nsdi_strengthening/implementation_inventory.py:20-38`; totals and
the counting caveat appear at
`results/nsdi-strengthening-2026-08-31/implementation/implementation-inventory.md:7-12`.
Each JSON file record also carries its SHA-256 digest.

The 15,188 nonblank lines are a useful approximate source footprint for the enumerated
Python enforcement core, not a complete transitive TCB measurement. CPython, SQLite,
PyNaCl/libsodium, the operating system and filesystem, key custody, rollback-anchor
deployment, authenticated host identity/policy adapters, and the protected actuator remain
external trusted dependencies or assumptions. Conversely, the public client is not in the
enumerated narrow-core file list.

## Recommendations and claims not established by this inventory

The following are recommendations, not current-source facts:

1. In the paper, name SQLite as the concrete measured warden and replay-store backend;
   do not list PostgreSQL or another backend unless an implementation and evidence are
   added.
2. Describe transaction behavior with the exact SQLite settings above instead of applying
   an unsupported generic isolation label. `synchronous=FULL` still relies on the OS,
   filesystem, and device honoring durability requests.
3. State that executor replicas require one authoritative claim namespace. Do not claim
   cross-host replica safety or availability until a shared backend and failover test exist.
4. Describe a receipt as durably **claimed** before the physical effect, not atomically
   completed with it. The current verifier/claim transaction does not include the external
   actuator.
5. Treat raw seed-file loading as a mechanism, not a production key-management system.
   Production guidance should specify OS-protected secret storage, HSM/KMS integration, or
   an equivalent custody boundary.
6. Count the rollback anchor as effective only when operators place it in an independent
   rollback domain; merely using a second file beside the database does not satisfy that
   requirement.
7. Report the narrow-core LOC as an auditable implementation-source footprint and list the
   principal transitive dependencies separately; do not present 15,188 nonblank lines as a
   formally minimized or dependency-complete TCB.
