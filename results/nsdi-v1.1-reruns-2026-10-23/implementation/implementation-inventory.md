# LETS implementation inventory

- Schema: `lets.nsdi-implementation-inventory/v1`
- Revision: `b248f29012b4ff9231a041a6fc9eeea1565b3b85`
- Working tree dirty: `True`

Counts are transparent physical/nonblank source-line counts, not semantic SLOC.

| Group | Files | Physical lines | Nonblank lines |
|---|---:|---:|---:|
| Whole LETS runtime | 36 | 30887 | 29178 |
| Narrow enforcement core | 18 | 16670 | 15828 |

## Verified implementation facts

- **python-version-range** — The released package supports Python >=3.11 and <3.15. (`pyproject.toml:10`)
- **sqlite-write-atomicity** — Warden and executor stores use explicit-autocommit SQLite connections, WAL, synchronous=FULL, and BEGIN IMMEDIATE write transactions. (`src/lets/storage/sqlite.py:287`, `src/lets/storage/sqlite.py:1953`, `src/lets/storage/sqlite.py:1958`, `src/lets/storage/sqlite.py:1997`, `src/lets/executor.py:272`, `src/lets/executor.py:279`, `src/lets/executor.py:287`, `src/lets/executor.py:1012`)
- **ed25519-key-format** — Receipts use PyNaCl Ed25519 with 32-byte raw seeds and public keys; key IDs bind the warden name to a SHA-256 public-key fingerprint prefix. (`src/lets/crypto.py:17`, `src/lets/crypto.py:39`, `src/lets/crypto.py:30`, `src/lets/crypto.py:31`)
- **canonical-wire-format** — Signed objects use compact, sorted UTF-8 canonical JSON over an integer-only subset; the strict decoder rejects duplicate keys and floating-point values. (`src/lets/canonical.py:60`, `src/lets/canonical.py:61`, `src/lets/canonical.py:84`, `src/lets/canonical.py:76`)
- **operation-identifiers** — Opaque operation identifiers use a validated kind prefix and UUID4 hex. (`src/lets/ids.py:20`)
- **clock-and-uncertainty** — Runtime time is time.time_ns(), and callers declare a non-negative uncertainty that is checked at authorization and receipt verification boundaries. (`src/lets/clock.py:25`, `src/lets/clock.py:37`, `src/lets/executor.py:1362`, `src/lets/service.py:484`)
- **executor-claim-store** — The concrete durable executor claim backend inventoried here is a local SQLite replay store with receipt-claim and per-lease watermark tables. (`src/lets/executor.py:148`, `src/lets/executor.py:344`, `src/lets/executor.py:359`)
- **rollback-anchors** — Warden and executor rollback anchors have file and process-isolated file implementations, and their documentation requires an independent rollback domain. (`src/lets/authority.py:283`, `src/lets/authority.py:433`, `src/lets/executor_authority.py:224`, `src/lets/executor_authority.py:277`, `src/lets/executor_authority.py:223`)

## Narrow enforcement-core files

- `src/lets/authority.py` — 1061 physical, 998 nonblank
- `src/lets/authority_helper.py` — 179 physical, 157 nonblank
- `src/lets/canonical.py` — 115 physical, 98 nonblank
- `src/lets/clock.py` — 73 physical, 56 nonblank
- `src/lets/crypto.py` — 263 physical, 236 nonblank
- `src/lets/errors.py` — 163 physical, 130 nonblank
- `src/lets/executor.py` — 1433 physical, 1379 nonblank
- `src/lets/executor_authority.py` — 489 physical, 440 nonblank
- `src/lets/ids.py` — 53 physical, 39 nonblank
- `src/lets/invariants.py` — 65 physical, 53 nonblank
- `src/lets/manifest.py` — 605 physical, 561 nonblank
- `src/lets/models.py` — 779 physical, 702 nonblank
- `src/lets/policy.py` — 630 physical, 576 nonblank
- `src/lets/service.py` — 5790 physical, 5661 nonblank
- `src/lets/storage/__init__.py` — 34 physical, 32 nonblank
- `src/lets/storage/schema.py` — 1411 physical, 1395 nonblank
- `src/lets/storage/sqlite.py` — 3436 physical, 3246 nonblank
- `src/lets/vector.py` — 91 physical, 69 nonblank
