# LETS implementation inventory

- Schema: `lets.nsdi-implementation-inventory/v1`
- Revision: `a9f4ba810e1741f93ba204eb782b6c4e3d409a03`
- Working tree dirty: `True`

Counts are transparent physical/nonblank source-line counts, not semantic SLOC.

| Group | Files | Physical lines | Nonblank lines |
|---|---:|---:|---:|
| Whole LETS runtime | 34 | 28573 | 26738 |
| Narrow enforcement core | 18 | 16169 | 15188 |

## Verified implementation facts

- **python-version-range** — The released package supports Python >=3.11 and <3.15. (`pyproject.toml:10`)
- **sqlite-write-atomicity** — Warden and executor stores use explicit-autocommit SQLite connections, WAL, synchronous=FULL, and BEGIN IMMEDIATE write transactions. (`src/lets/storage/sqlite.py:288`, `src/lets/storage/sqlite.py:2002`, `src/lets/storage/sqlite.py:2007`, `src/lets/storage/sqlite.py:2052`, `src/lets/executor.py:285`, `src/lets/executor.py:292`, `src/lets/executor.py:300`, `src/lets/executor.py:1031`)
- **ed25519-key-format** — Receipts use PyNaCl Ed25519 with 32-byte raw seeds and public keys; key IDs bind the warden name to a SHA-256 public-key fingerprint prefix. (`src/lets/crypto.py:14`, `src/lets/crypto.py:38`, `src/lets/crypto.py:29`, `src/lets/crypto.py:30`)
- **canonical-wire-format** — Signed objects use compact, sorted UTF-8 canonical JSON over an integer-only subset; the strict decoder rejects duplicate keys and floating-point values. (`src/lets/canonical.py:58`, `src/lets/canonical.py:59`, `src/lets/canonical.py:84`, `src/lets/canonical.py:76`)
- **operation-identifiers** — Opaque operation identifiers use a validated kind prefix and UUID4 hex. (`src/lets/ids.py:19`)
- **clock-and-uncertainty** — Runtime time is time.time_ns(), and callers declare a non-negative uncertainty that is checked at authorization and receipt verification boundaries. (`src/lets/clock.py:23`, `src/lets/clock.py:35`, `src/lets/executor.py:1402`, `src/lets/service.py:484`)
- **executor-claim-store** — The concrete durable executor claim backend inventoried here is a local SQLite replay store with receipt-claim and per-lease watermark tables. (`src/lets/executor.py:151`, `src/lets/executor.py:357`, `src/lets/executor.py:372`)
- **rollback-anchors** — Warden and executor rollback anchors have file and process-isolated file implementations, and their documentation requires an independent rollback domain. (`src/lets/authority.py:308`, `src/lets/authority.py:465`, `src/lets/executor_authority.py:235`, `src/lets/executor_authority.py:300`, `src/lets/executor_authority.py:238`)

## Narrow enforcement-core files

- `src/lets/authority.py` — 1116 physical, 1037 nonblank
- `src/lets/authority_helper.py` — 176 physical, 154 nonblank
- `src/lets/canonical.py` — 124 physical, 102 nonblank
- `src/lets/clock.py` — 73 physical, 54 nonblank
- `src/lets/crypto.py` — 282 physical, 246 nonblank
- `src/lets/errors.py` — 170 physical, 134 nonblank
- `src/lets/executor.py` — 1473 physical, 1405 nonblank
- `src/lets/executor_authority.py` — 520 physical, 460 nonblank
- `src/lets/ids.py` — 64 physical, 44 nonblank
- `src/lets/invariants.py` — 82 physical, 64 nonblank
- `src/lets/manifest.py` — 604 physical, 559 nonblank
- `src/lets/models.py` — 687 physical, 614 nonblank
- `src/lets/policy.py` — 643 physical, 584 nonblank
- `src/lets/service.py` — 5193 physical, 5037 nonblank
- `src/lets/storage/__init__.py` — 31 physical, 29 nonblank
- `src/lets/storage/schema.py` — 1287 physical, 1272 nonblank
- `src/lets/storage/sqlite.py` — 3554 physical, 3326 nonblank
- `src/lets/vector.py` — 90 physical, 67 nonblank
