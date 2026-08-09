"""Independent protected-executor receipt verification and replay defense."""

from __future__ import annotations

import os
import secrets
import shutil
import sqlite3
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Protocol, Self

from lets.canonical import b64url_decode, b64url_encode, canonical_json
from lets.clock import Clock, SystemClock
from lets.crypto import PublicKeyRegistry
from lets.errors import (
    ClockUncertainError,
    PolicyError,
    ReplayError,
    SignatureError,
    StorageError,
    ValidationError,
)
from lets.executor_authority import (
    ExecutorAuthorityAnchor,
    ExecutorAuthorityCheckpoint,
    ExecutorReplayIdentity,
    FileExecutorAuthorityAnchor,
    ProcessFileExecutorAuthorityAnchor,
)
from lets.models import Receipt
from lets.vector import MAX_RESOURCE

_REPLAY_GC_BATCH = 128
_ZERO_HASH = bytes(32)


class ReceiptReplayStore(Protocol):
    def claim(
        self,
        receipt: Receipt,
        *,
        claimed_at_ns: int,
        clock_uncertainty_ns: int = 0,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ExecutorPolicy:
    audience: str
    tenant_id: str | None = None
    envelope_id: str | None = None
    config_epoch: int | None = None
    allowed_policy_digests: frozenset[str] = frozenset()
    allowed_machine_digests: frozenset[str] = frozenset()
    trusted_wardens: frozenset[str] = frozenset()
    max_clock_uncertainty_ns: int = 0

    def __post_init__(self) -> None:
        if not self.audience:
            raise ValueError("executor audience must not be empty")
        if self.config_epoch is not None and (
            isinstance(self.config_epoch, bool)
            or not isinstance(self.config_epoch, int)
            or self.config_epoch <= 0
            or self.config_epoch > MAX_RESOURCE
        ):
            raise ValidationError("executor config_epoch must be a positive signed 64-bit integer")
        if (
            isinstance(self.max_clock_uncertainty_ns, bool)
            or not isinstance(self.max_clock_uncertainty_ns, int)
            or self.max_clock_uncertainty_ns < 0
            or self.max_clock_uncertainty_ns > MAX_RESOURCE
        ):
            raise ValidationError(
                "executor clock uncertainty must be a non-negative signed 64-bit integer"
            )


def executor_policy_digest(policy: ExecutorPolicy) -> bytes:
    """Canonical fingerprint of the complete executor authorization policy."""

    return sha256(
        canonical_json(
            {
                "type": "lets.executor-policy/v1",
                "audience": policy.audience,
                "tenant_id": policy.tenant_id,
                "envelope_id": policy.envelope_id,
                "config_epoch": policy.config_epoch,
                "allowed_policy_digests": sorted(policy.allowed_policy_digests),
                "allowed_machine_digests": sorted(policy.allowed_machine_digests),
                "trusted_wardens": sorted(policy.trusted_wardens),
                "max_clock_uncertainty_ns": policy.max_clock_uncertainty_ns,
            }
        )
    ).digest()


def executor_replay_identity(
    policy: ExecutorPolicy, registry: PublicKeyRegistry
) -> ExecutorReplayIdentity:
    """Build the immutable replay/anchor identity admitted by a verifier."""

    if policy.tenant_id is None or policy.envelope_id is None or policy.config_epoch is None:
        raise ValidationError(
            "anchored executor policy must fix tenant, envelope, and configuration epoch"
        )
    return ExecutorReplayIdentity(
        audience=policy.audience,
        tenant_id=policy.tenant_id,
        envelope_id=policy.envelope_id,
        config_epoch=policy.config_epoch,
        executor_policy_sha256=executor_policy_digest(policy),
        trust_registry_sha256=registry.trust_digest(),
    )


@dataclass(frozen=True, slots=True)
class ExecutorReplayStatus:
    """Operator-facing capacity and monotonic-head snapshot."""

    path: str
    rollback_protected: bool
    authority_healthy: bool
    identity: ExecutorReplayIdentity | None
    claim_sequence: int
    clock_floor_ns: int | None
    live_claims: int
    live_watermarks: int
    database_bytes: int
    wal_bytes: int
    shared_memory_bytes: int
    filesystem_free_bytes: int | None


class SQLiteReceiptReplayStore:
    """Receipt replay authority with optional external rollback protection.

    Production callers must provide an :class:`ExecutorAuthorityAnchor`.  The
    unanchored mode survives ordinary restart but not restoration of older
    bytes, and is available only through the explicit ``allow_unanchored``
    development switch.
    """

    APPLICATION_ID = 0x4C455845
    SCHEMA_VERSION = 5

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        busy_timeout_ms: int = 5_000,
        authority_anchor: ExecutorAuthorityAnchor | None = None,
        allow_unanchored: bool = False,
        identity: ExecutorReplayIdentity | None = None,
        _create: bool = False,
    ) -> None:
        raw_path = os.fspath(path)
        if not raw_path or raw_path == ":memory:":
            raise ValueError("executor replay storage must be filesystem-backed")
        self.path = str(Path(raw_path).resolve())
        if busy_timeout_ms <= 0:
            raise ValueError("busy_timeout_ms must be positive")
        if authority_anchor is None and not allow_unanchored:
            raise ValidationError(
                "executor replay storage requires an external authority anchor; "
                "set allow_unanchored=True only for development"
            )
        if authority_anchor is not None and allow_unanchored:
            raise ValidationError(
                "allow_unanchored cannot be combined with an executor authority anchor"
            )
        if (
            isinstance(
                authority_anchor,
                (FileExecutorAuthorityAnchor, ProcessFileExecutorAuthorityAnchor),
            )
            and authority_anchor.path.parent == Path(self.path).parent
        ):
            raise ValidationError(
                "executor replay database and file authority anchor require different directories"
            )
        if _create and authority_anchor is not None and identity is None:
            raise ValidationError("anchored executor replay initialization requires an identity")
        if not _create and identity is not None:
            raise ValidationError("executor replay identity is read from existing storage")
        self._busy_timeout_ms = busy_timeout_ms
        self._authority_anchor = authority_anchor
        self._authority_faulted = False
        self._authority_transaction_lock = threading.Lock()
        self._identity: ExecutorReplayIdentity | None = identity
        self._anchored = authority_anchor is not None
        self._connect_path = self.path
        self._connect_uri = False
        reserved = False
        if _create:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError as exc:
                raise StorageError("executor replay database already exists") from exc
            else:
                os.close(descriptor)
                reserved = True
        else:
            self._connect_path = f"{Path(self.path).as_uri()}?mode=rw"
            self._connect_uri = True
        try:
            if _create:
                self._initialize()
            else:
                self._verify_existing()
            if self.integrity_check() != ("ok",):
                raise StorageError("executor replay database failed its integrity check")
            if self._anchored:
                self._reconcile_existing(initialize=_create)
        except sqlite3.Error as exc:
            if reserved:
                with suppress(OSError):
                    os.unlink(self.path)
            raise StorageError("executor replay SQLite admission failed") from exc
        except BaseException:
            if reserved:
                with suppress(OSError):
                    os.unlink(self.path)
            raise

    @classmethod
    def initialize(
        cls,
        path: str | os.PathLike[str],
        *,
        busy_timeout_ms: int = 5_000,
        authority_anchor: ExecutorAuthorityAnchor | None = None,
        identity: ExecutorReplayIdentity | None = None,
        allow_unanchored: bool = False,
    ) -> Self:
        """Create executor replay authority state exactly once."""

        return cls(
            path,
            busy_timeout_ms=busy_timeout_ms,
            authority_anchor=authority_anchor,
            identity=identity,
            allow_unanchored=allow_unanchored,
            _create=True,
        )

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self._connect_path,
                isolation_level=None,
                timeout=self._busy_timeout_ms / 1_000,
                cached_statements=128,
                uri=self._connect_uri,
            )
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as exc:
            raise StorageError(f"could not open executor replay database {self.path!r}") from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise StorageError(f"SQLite refused WAL mode for executor store: {mode!r}")
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
                    authority_mode TEXT NOT NULL CHECK (
                        authority_mode IN ('anchored', 'development')
                    ),
                    audience TEXT,
                    tenant_id TEXT,
                    envelope_id TEXT,
                    config_epoch INTEGER CHECK (
                        config_epoch IS NULL OR config_epoch > 0
                    ),
                    executor_policy_sha256 BLOB CHECK (
                        executor_policy_sha256 IS NULL
                        OR length(executor_policy_sha256) = 32
                    ),
                    trust_registry_sha256 BLOB CHECK (
                        trust_registry_sha256 IS NULL
                        OR length(trust_registry_sha256) = 32
                    ),
                    database_instance_id BLOB NOT NULL CHECK (
                        length(database_instance_id) = 32
                    ),
                    claim_sequence INTEGER NOT NULL CHECK (claim_sequence >= 0),
                    claim_digest BLOB NOT NULL CHECK (length(claim_digest) = 32),
                    clock_floor_ns INTEGER CHECK (
                        clock_floor_ns IS NULL OR clock_floor_ns >= 0
                    ),
                    CHECK (
                        (
                            audience IS NULL AND tenant_id IS NULL
                            AND envelope_id IS NULL AND config_epoch IS NULL
                            AND executor_policy_sha256 IS NULL
                            AND trust_registry_sha256 IS NULL
                        ) OR (
                            audience IS NOT NULL AND tenant_id IS NOT NULL
                            AND envelope_id IS NOT NULL AND config_epoch IS NOT NULL
                            AND executor_policy_sha256 IS NOT NULL
                            AND trust_registry_sha256 IS NOT NULL
                        )
                    ),
                    CHECK (
                        authority_mode = 'development'
                        OR (
                            audience IS NOT NULL AND tenant_id IS NOT NULL
                            AND envelope_id IS NOT NULL AND config_epoch IS NOT NULL
                            AND executor_policy_sha256 IS NOT NULL
                            AND trust_registry_sha256 IS NOT NULL
                        )
                    )
                ) STRICT;
                CREATE TABLE receipt_claims (
                    receipt_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    envelope_id TEXT NOT NULL,
                    warden_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    audience TEXT NOT NULL,
                    resulting_sequence INTEGER NOT NULL CHECK (resulting_sequence > 0),
                    nonce TEXT NOT NULL,
                    claimed_at_ns INTEGER NOT NULL CHECK (claimed_at_ns >= 0),
                    expires_at_ns INTEGER NOT NULL CHECK (expires_at_ns > claimed_at_ns),
                    UNIQUE (tenant_id, envelope_id, audience, nonce)
                ) STRICT;
                CREATE INDEX ix_receipt_claims_expiry
                    ON receipt_claims(expires_at_ns);
                CREATE TABLE lease_watermarks (
                    warden_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    audience TEXT NOT NULL,
                    last_sequence INTEGER NOT NULL CHECK (last_sequence > 0),
                    updated_at_ns INTEGER NOT NULL CHECK (updated_at_ns >= 0),
                    expires_at_ns INTEGER NOT NULL CHECK (expires_at_ns >= updated_at_ns),
                    PRIMARY KEY (warden_id, lease_id, audience)
                ) STRICT, WITHOUT ROWID;
                CREATE TABLE claim_history (
                    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
                    previous_digest BLOB NOT NULL CHECK (length(previous_digest) = 32),
                    claim_digest BLOB NOT NULL UNIQUE CHECK (length(claim_digest) = 32),
                    receipt_digest BLOB NOT NULL CHECK (length(receipt_digest) = 32),
                    receipt_id TEXT NOT NULL,
                    claimed_at_ns INTEGER NOT NULL CHECK (claimed_at_ns >= 0),
                    clock_floor_ns INTEGER NOT NULL CHECK (clock_floor_ns >= 0)
                ) STRICT;
                CREATE TRIGGER claim_history_chain_insert
                BEFORE INSERT ON claim_history
                BEGIN
                    SELECT CASE WHEN NEW.sequence != (
                        SELECT claim_sequence + 1 FROM metadata WHERE singleton = 1
                    ) THEN RAISE(ABORT, 'executor claim sequence is not contiguous') END;
                    SELECT CASE WHEN NEW.previous_digest != (
                        SELECT claim_digest FROM metadata WHERE singleton = 1
                    ) THEN RAISE(ABORT, 'executor claim previous digest does not match') END;
                END;
                CREATE TRIGGER claim_history_immutable_update
                BEFORE UPDATE ON claim_history
                BEGIN
                    SELECT RAISE(ABORT, 'executor claim history is append-only');
                END;
                CREATE TRIGGER claim_history_immutable_delete
                BEFORE DELETE ON claim_history
                BEGIN
                    SELECT RAISE(ABORT, 'executor claim history is append-only');
                END;
                CREATE TRIGGER metadata_authority_update
                BEFORE UPDATE ON metadata
                BEGIN
                    SELECT CASE WHEN
                        NEW.schema_version != OLD.schema_version
                        OR NEW.authority_mode != OLD.authority_mode
                        OR NEW.audience IS NOT OLD.audience
                        OR NEW.tenant_id IS NOT OLD.tenant_id
                        OR NEW.envelope_id IS NOT OLD.envelope_id
                        OR NEW.config_epoch IS NOT OLD.config_epoch
                        OR NEW.executor_policy_sha256 IS NOT OLD.executor_policy_sha256
                        OR NEW.trust_registry_sha256 IS NOT OLD.trust_registry_sha256
                        OR NEW.database_instance_id != OLD.database_instance_id
                    THEN RAISE(ABORT, 'executor authority identity is immutable') END;
                    SELECT CASE WHEN
                        OLD.clock_floor_ns IS NOT NULL
                        AND (
                            NEW.clock_floor_ns IS NULL
                            OR NEW.clock_floor_ns < OLD.clock_floor_ns
                        )
                    THEN RAISE(ABORT, 'executor clock floor cannot regress') END;
                    SELECT CASE WHEN NOT (
                        (
                            NEW.claim_sequence = OLD.claim_sequence
                            AND NEW.claim_digest = OLD.claim_digest
                        ) OR (
                            NEW.claim_sequence = OLD.claim_sequence + 1
                            AND EXISTS (
                                SELECT 1 FROM claim_history
                                WHERE sequence = NEW.claim_sequence
                                  AND previous_digest = OLD.claim_digest
                                  AND claim_digest = NEW.claim_digest
                            )
                        )
                    ) THEN RAISE(ABORT, 'executor claim head update is invalid') END;
                END;
                CREATE TRIGGER metadata_immutable_delete
                BEFORE DELETE ON metadata
                BEGIN
                    SELECT RAISE(ABORT, 'executor authority metadata is immutable');
                END;
                """
            )
            identity = self._identity
            connection.execute(
                """
                INSERT INTO metadata(
                    singleton, schema_version, authority_mode, audience, tenant_id,
                    envelope_id, config_epoch, executor_policy_sha256,
                    trust_registry_sha256, database_instance_id, claim_sequence,
                    claim_digest, clock_floor_ns
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, NULL)
                """,
                (
                    self.SCHEMA_VERSION,
                    "anchored" if self._anchored else "development",
                    None if identity is None else identity.audience,
                    None if identity is None else identity.tenant_id,
                    None if identity is None else identity.envelope_id,
                    None if identity is None else identity.config_epoch,
                    None if identity is None else identity.executor_policy_sha256,
                    None if identity is None else identity.trust_registry_sha256,
                    secrets.token_bytes(32),
                    _ZERO_HASH,
                ),
            )
            connection.execute(f"PRAGMA application_id={self.APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={self.SCHEMA_VERSION}")
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _verify_existing(self) -> None:
        connection = self._connect()
        try:
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if application_id != self.APPLICATION_ID:
                if application_id == 0 and user_version == 0:
                    raise StorageError(
                        "executor replay database is empty or has an incomplete schema"
                    )
                raise StorageError("executor replay database application identity is invalid")
            if user_version != self.SCHEMA_VERSION:
                raise StorageError(
                    f"executor replay schema {user_version} requires explicit migration to "
                    f"{self.SCHEMA_VERSION}; existing bytes were not modified"
                )
            tables = {
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_schema WHERE type = 'table'")
            }
            required = {"metadata", "receipt_claims", "lease_watermarks", "claim_history"}
            if not required.issubset(tables):
                raise StorageError("executor replay database is empty or has an incomplete schema")
            row = connection.execute(
                """
                SELECT schema_version, authority_mode, audience, tenant_id, envelope_id,
                       config_epoch, executor_policy_sha256, trust_registry_sha256,
                       database_instance_id, claim_sequence, claim_digest, clock_floor_ns
                FROM metadata WHERE singleton = 1
                """
            ).fetchone()
            if row is None:
                raise StorageError("executor replay database metadata is missing")
            version = int(row[0])
            if version != self.SCHEMA_VERSION:
                raise StorageError(
                    f"executor replay schema {version} requires explicit migration to "
                    f"{self.SCHEMA_VERSION}"
                )
            if any(
                not isinstance(item, bytes) or len(item) != 32 for item in (row[6], row[7])
            ) and any(item is not None for item in (row[6], row[7])):
                raise StorageError("executor replay policy or trust fingerprint is invalid")
            mode = str(row[1])
            if mode == "anchored":
                if self._authority_anchor is None:
                    raise StorageError(
                        "anchored executor replay storage cannot be opened without its authority "
                        "anchor"
                    )
                if not all(item is not None for item in row[2:8]):
                    raise StorageError("anchored executor replay identity is incomplete")
                self._identity = ExecutorReplayIdentity(
                    audience=str(row[2]),
                    tenant_id=str(row[3]),
                    envelope_id=str(row[4]),
                    config_epoch=int(row[5]),
                    executor_policy_sha256=bytes(row[6]),
                    trust_registry_sha256=bytes(row[7]),
                )
                self._anchored = True
            elif mode == "development":
                if self._authority_anchor is not None:
                    raise StorageError(
                        "development replay storage cannot be retroactively adopted by an anchor"
                    )
                if all(item is not None for item in row[2:8]):
                    self._identity = ExecutorReplayIdentity(
                        audience=str(row[2]),
                        tenant_id=str(row[3]),
                        envelope_id=str(row[4]),
                        config_epoch=int(row[5]),
                        executor_policy_sha256=bytes(row[6]),
                        trust_registry_sha256=bytes(row[7]),
                    )
                elif any(item is not None for item in row[2:8]):
                    raise StorageError("development executor replay identity is incomplete")
                self._anchored = False
            else:
                raise StorageError("executor replay authority mode is invalid")
            if not isinstance(row[8], bytes) or len(row[8]) != 32:
                raise StorageError("executor replay database instance identity is invalid")
            if int(row[9]) < 0 or not isinstance(row[10], bytes) or len(row[10]) != 32:
                raise StorageError("executor replay claim head is invalid")
            metadata_info = tuple(connection.execute("PRAGMA table_info(metadata)"))
            claims_info = tuple(connection.execute("PRAGMA table_info(receipt_claims)"))
            watermarks_info = tuple(connection.execute("PRAGMA table_info(lease_watermarks)"))
            history_info = tuple(connection.execute("PRAGMA table_info(claim_history)"))
            if (
                {str(item[1]) for item in metadata_info}
                != {
                    "singleton",
                    "schema_version",
                    "authority_mode",
                    "audience",
                    "tenant_id",
                    "envelope_id",
                    "config_epoch",
                    "executor_policy_sha256",
                    "trust_registry_sha256",
                    "database_instance_id",
                    "claim_sequence",
                    "claim_digest",
                    "clock_floor_ns",
                }
                or {str(item[1]) for item in claims_info}
                != {
                    "receipt_id",
                    "tenant_id",
                    "envelope_id",
                    "warden_id",
                    "lease_id",
                    "audience",
                    "resulting_sequence",
                    "nonce",
                    "claimed_at_ns",
                    "expires_at_ns",
                }
                or {str(item[1]) for item in watermarks_info}
                != {
                    "warden_id",
                    "lease_id",
                    "audience",
                    "last_sequence",
                    "updated_at_ns",
                    "expires_at_ns",
                }
                or {str(item[1]) for item in history_info}
                != {
                    "sequence",
                    "previous_digest",
                    "claim_digest",
                    "receipt_digest",
                    "receipt_id",
                    "claimed_at_ns",
                    "clock_floor_ns",
                }
            ):
                raise StorageError("executor replay database column shape is not supported")

            unique_claim_indexes: set[tuple[str, ...]] = set()
            for index in connection.execute("PRAGMA index_list(receipt_claims)"):
                if int(index[2]) == 1:
                    unique_claim_indexes.add(
                        tuple(
                            str(item[0])
                            for item in connection.execute(
                                "SELECT name FROM pragma_index_info(?) ORDER BY seqno",
                                (str(index[1]),),
                            )
                        )
                    )
            watermark_primary_key = tuple(
                name
                for _, name in sorted(
                    (int(item[5]), str(item[1])) for item in watermarks_info if int(item[5]) > 0
                )
            )
            expiry_index = tuple(
                str(item[2])
                for item in connection.execute("PRAGMA index_info(ix_receipt_claims_expiry)")
            )
            history_primary_key = tuple(
                name
                for _, name in sorted(
                    (int(item[5]), str(item[1])) for item in history_info if int(item[5]) > 0
                )
            )
            history_unique_indexes = {
                tuple(
                    str(item[2])
                    for item in connection.execute(
                        "SELECT * FROM pragma_index_info(?) ORDER BY seqno", (str(index[1]),)
                    )
                )
                for index in connection.execute("PRAGMA index_list(claim_history)")
                if int(index[2]) == 1
            }
            triggers = {
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='trigger'")
            }
            required_triggers = {
                "claim_history_chain_insert",
                "claim_history_immutable_update",
                "claim_history_immutable_delete",
                "metadata_authority_update",
                "metadata_immutable_delete",
            }
            if (
                ("tenant_id", "envelope_id", "audience", "nonce") not in unique_claim_indexes
                or ("receipt_id",) not in unique_claim_indexes
                or watermark_primary_key != ("warden_id", "lease_id", "audience")
                or expiry_index != ("expires_at_ns",)
                or history_primary_key != ("sequence",)
                or ("claim_digest",) not in history_unique_indexes
                or not required_triggers.issubset(triggers)
            ):
                raise StorageError("executor replay authority constraints or indexes are missing")
            journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
            if journal_mode.casefold() != "wal":
                raise StorageError("executor replay database must already use WAL journal mode")
            self._verify_claim_chain(
                connection,
                expected_sequence=int(row[9]),
                expected_digest=row[10],
            )
        finally:
            connection.close()

    @staticmethod
    def _verify_claim_chain(
        connection: sqlite3.Connection,
        *,
        expected_sequence: int,
        expected_digest: object,
    ) -> None:
        if not isinstance(expected_digest, bytes) or len(expected_digest) != 32:
            raise StorageError("executor replay metadata claim digest is malformed")
        sequence = 0
        previous = _ZERO_HASH
        for row in connection.execute(
            "SELECT sequence, previous_digest, claim_digest FROM claim_history ORDER BY sequence"
        ):
            sequence += 1
            prior = row[1]
            current = row[2]
            if (
                int(row[0]) != sequence
                or not isinstance(prior, bytes)
                or prior != previous
                or not isinstance(current, bytes)
                or len(current) != 32
            ):
                raise StorageError("executor replay claim history is not a contiguous hash chain")
            previous = current
        if sequence != expected_sequence or previous != expected_digest:
            raise StorageError("executor replay metadata does not match its claim history head")

    @property
    def identity(self) -> ExecutorReplayIdentity | None:
        """Return the fixed replay-policy identity, if this store has one."""

        return self._identity

    @property
    def rollback_protected(self) -> bool:
        """Whether successful claims are acknowledged by an external anchor."""

        return self._anchored and not self._authority_faulted

    def _authority_checkpoint(self, connection: sqlite3.Connection) -> ExecutorAuthorityCheckpoint:
        row = connection.execute(
            """
            SELECT schema_version, audience, tenant_id, envelope_id, config_epoch,
                   executor_policy_sha256, trust_registry_sha256,
                   database_instance_id, claim_sequence, claim_digest, clock_floor_ns
            FROM metadata WHERE singleton = 1
            """
        ).fetchone()
        if row is None:
            raise StorageError("executor replay authority metadata is missing")
        if self._identity is None:
            raise StorageError("anchored executor replay identity is missing")
        database_instance_id = row[7]
        claim_digest = row[9]
        if any(not isinstance(item, bytes) or len(item) != 32 for item in (row[5], row[6])):
            raise StorageError("executor replay policy or trust fingerprint is malformed")
        if not isinstance(database_instance_id, bytes) or len(database_instance_id) != 32:
            raise StorageError("executor replay database instance identity is malformed")
        if not isinstance(claim_digest, bytes) or len(claim_digest) != 32:
            raise StorageError("executor replay claim digest is malformed")
        stored_identity = ExecutorReplayIdentity(
            audience=str(row[1]),
            tenant_id=str(row[2]),
            envelope_id=str(row[3]),
            config_epoch=int(row[4]),
            executor_policy_sha256=bytes(row[5]),
            trust_registry_sha256=bytes(row[6]),
        )
        if stored_identity != self._identity:
            raise StorageError("executor replay identity changed after admission")
        return ExecutorAuthorityCheckpoint(
            identity=stored_identity,
            schema_version=int(row[0]),
            database_instance_id=database_instance_id,
            claim_sequence=int(row[8]),
            claim_digest=claim_digest,
            clock_floor_ns=None if row[10] is None else int(row[10]),
        )

    @staticmethod
    def _claim_digest_at(connection: sqlite3.Connection, sequence: int) -> bytes | None:
        row = connection.execute(
            "SELECT claim_digest FROM claim_history WHERE sequence = ?", (sequence,)
        ).fetchone()
        if row is None:
            return None
        value = row[0]
        if not isinstance(value, bytes) or len(value) != 32:
            raise StorageError("executor replay historical claim digest is malformed")
        return value

    def _reconcile_authority_anchor(
        self, connection: sqlite3.Connection, *, initialize: bool = False
    ) -> None:
        anchor = self._authority_anchor
        if anchor is None:
            return
        if self._authority_faulted:
            raise StorageError(
                "executor authority anchor previously faulted; restart after operator repair"
            )
        try:
            checkpoint = self._authority_checkpoint(connection)
            anchor.reconcile(
                checkpoint,
                claim_digest_at=lambda sequence: self._claim_digest_at(connection, sequence),
                initialize=initialize,
            )
        except StorageError:
            self._authority_faulted = True
            raise
        except Exception as exc:
            self._authority_faulted = True
            raise StorageError("executor authority anchor provider failed") from exc

    def _reconcile_existing(self, *, initialize: bool = False) -> None:
        with self._authority_transaction_lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._reconcile_authority_anchor(connection, initialize=initialize)
                connection.rollback()
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        with self._authority_transaction_lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._reconcile_authority_anchor(connection)
                yield connection
                connection.commit()
                if self._anchored:
                    # Reacquire the SQLite writer lock before publishing the
                    # committed head.  Another process may win the small
                    # COMMIT/BEGIN race; if so, this snapshot includes and
                    # publishes its extension too.  A separate cloned database
                    # is not locked and must still win the external CAS.
                    connection.execute("BEGIN IMMEDIATE")
                    self._reconcile_authority_anchor(connection)
                    connection.rollback()
            except sqlite3.IntegrityError as exc:
                if connection.in_transaction:
                    connection.rollback()
                raise ReplayError("receipt id or nonce has already been consumed") from exc
            except sqlite3.Error as exc:
                if connection.in_transaction:
                    connection.rollback()
                if (
                    getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL
                    or "full" in str(exc).casefold()
                ):
                    raise StorageError(
                        "executor replay storage is full; protected effects remain disabled"
                    ) from exc
                raise StorageError("executor replay SQLite claim transaction failed") from exc
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()

    def claim(
        self,
        receipt: Receipt,
        *,
        claimed_at_ns: int,
        clock_uncertainty_ns: int = 0,
    ) -> None:
        for name, value in (
            ("claimed_at_ns", claimed_at_ns),
            ("clock_uncertainty_ns", clock_uncertainty_ns),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or value > MAX_RESOURCE
            ):
                raise ClockUncertainError(f"executor {name} is invalid")
        if claimed_at_ns > MAX_RESOURCE - clock_uncertainty_ns:
            raise ClockUncertainError("executor clock interval exceeds signed 64-bit time")
        identity = self._identity
        if identity is not None and (
            receipt.executor_audience != identity.audience
            or receipt.tenant_id != identity.tenant_id
            or receipt.envelope_id != identity.envelope_id
            or receipt.config_epoch != identity.config_epoch
        ):
            raise PolicyError("receipt does not match the executor replay store identity")
        with self._write() as connection:
            floor = connection.execute(
                """
                SELECT clock_floor_ns, claim_sequence, claim_digest, database_instance_id
                FROM metadata WHERE singleton = 1
                """
            ).fetchone()
            if floor is None:
                raise StorageError("executor replay clock metadata is missing")
            prior_floor = floor[0]
            if prior_floor is not None and claimed_at_ns + clock_uncertainty_ns < int(prior_floor):
                raise ClockUncertainError(
                    "executor clock moved behind its durable floor beyond declared uncertainty"
                )
            next_floor = (
                claimed_at_ns if prior_floor is None else max(claimed_at_ns, int(prior_floor))
            )
            # Replay cleanup is deliberately bounded.  A protected effect must never
            # inherit an arbitrarily large write transaction merely because a long-
            # lived executor accumulated expired history.  Repeated claims converge;
            # operators may also run maintenance while preserving the same batch cap.
            connection.execute(
                """
                DELETE FROM receipt_claims
                WHERE receipt_id IN (
                    SELECT receipt_id
                    FROM receipt_claims
                    WHERE expires_at_ns <= ?
                    ORDER BY expires_at_ns, receipt_id
                    LIMIT ?
                )
                """,
                (claimed_at_ns, _REPLAY_GC_BATCH),
            )
            connection.execute(
                """
                DELETE FROM lease_watermarks
                WHERE (warden_id, lease_id, audience) IN (
                    SELECT warden_id, lease_id, audience
                    FROM lease_watermarks
                    WHERE expires_at_ns <= ?
                    ORDER BY expires_at_ns, warden_id, lease_id, audience
                    LIMIT ?
                )
                """,
                (claimed_at_ns, _REPLAY_GC_BATCH),
            )
            row = connection.execute(
                """
                SELECT last_sequence FROM lease_watermarks
                WHERE warden_id = ? AND lease_id = ? AND audience = ?
                """,
                (receipt.warden_id, receipt.lease_id, receipt.executor_audience),
            ).fetchone()
            if row is not None and receipt.resulting_sequence <= int(row[0]):
                raise ReplayError(
                    "receipt sequence does not advance the executor's lease watermark"
                )
            connection.execute(
                """
                INSERT INTO receipt_claims(
                    receipt_id, tenant_id, envelope_id, warden_id, lease_id, audience,
                    resulting_sequence, nonce, claimed_at_ns, expires_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.receipt_id,
                    receipt.tenant_id,
                    receipt.envelope_id,
                    receipt.warden_id,
                    receipt.lease_id,
                    receipt.executor_audience,
                    receipt.resulting_sequence,
                    receipt.nonce,
                    claimed_at_ns,
                    receipt.expires_at_ns,
                ),
            )
            connection.execute(
                """
                INSERT INTO lease_watermarks(
                    warden_id, lease_id, audience, last_sequence, updated_at_ns,
                    expires_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(warden_id, lease_id, audience) DO UPDATE SET
                    last_sequence = excluded.last_sequence,
                    updated_at_ns = excluded.updated_at_ns,
                    expires_at_ns = MAX(
                        lease_watermarks.expires_at_ns,
                        excluded.expires_at_ns
                    )
                """,
                (
                    receipt.warden_id,
                    receipt.lease_id,
                    receipt.executor_audience,
                    receipt.resulting_sequence,
                    claimed_at_ns,
                    receipt.expires_at_ns,
                ),
            )
            prior_sequence = int(floor[1])
            if prior_sequence >= MAX_RESOURCE:
                raise StorageError("executor claim sequence exhausted signed 64-bit authority")
            prior_digest = floor[2]
            database_instance_id = floor[3]
            if not isinstance(prior_digest, bytes) or len(prior_digest) != 32:
                raise StorageError("executor replay prior claim digest is malformed")
            if not isinstance(database_instance_id, bytes) or len(database_instance_id) != 32:
                raise StorageError("executor replay database identity is malformed")
            next_sequence = prior_sequence + 1
            receipt_digest = sha256(canonical_json(receipt.to_dict())).digest()
            event = {
                "type": "lets.executor-claim/v1",
                "database_instance_id": b64url_encode(database_instance_id),
                "sequence": next_sequence,
                "previous_digest": b64url_encode(prior_digest),
                "receipt_digest": b64url_encode(receipt_digest),
                "receipt_id": receipt.receipt_id,
                "tenant_id": receipt.tenant_id,
                "envelope_id": receipt.envelope_id,
                "warden_id": receipt.warden_id,
                "lease_id": receipt.lease_id,
                "audience": receipt.executor_audience,
                "resulting_sequence": receipt.resulting_sequence,
                "nonce": receipt.nonce,
                "claimed_at_ns": claimed_at_ns,
                "clock_uncertainty_ns": clock_uncertainty_ns,
                "clock_floor_ns": next_floor,
                "expires_at_ns": receipt.expires_at_ns,
            }
            claim_digest = sha256(prior_digest + canonical_json(event)).digest()
            connection.execute(
                """
                INSERT INTO claim_history(
                    sequence, previous_digest, claim_digest, receipt_digest,
                    receipt_id, claimed_at_ns, clock_floor_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    next_sequence,
                    prior_digest,
                    claim_digest,
                    receipt_digest,
                    receipt.receipt_id,
                    claimed_at_ns,
                    next_floor,
                ),
            )
            connection.execute(
                """
                UPDATE metadata
                SET clock_floor_ns = ?, claim_sequence = ?, claim_digest = ?
                WHERE singleton = 1
                """,
                (next_floor, next_sequence, claim_digest),
            )

    def checkpoint_wal(self) -> tuple[int, int, int]:
        """Synchronously truncate WAL before an operator-managed database copy.

        The returned tuple is SQLite's ``(busy, log_frames,
        checkpointed_frames)`` result.  A nonzero busy result fails closed.
        Anchor files are intentionally not copied with the database.
        """

        with self._authority_transaction_lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._reconcile_authority_anchor(connection)
                connection.rollback()
                row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if row is None:
                    raise StorageError("SQLite omitted its executor WAL checkpoint result")
                result = (int(row[0]), int(row[1]), int(row[2]))
                if result[0] != 0:
                    raise StorageError("executor replay WAL checkpoint remained busy")
                return result
            except sqlite3.Error as exc:
                if connection.in_transaction:
                    connection.rollback()
                raise StorageError("could not checkpoint executor replay WAL") from exc
            finally:
                connection.close()

    def status(self) -> ExecutorReplayStatus:
        """Return an explicit authority/capacity snapshot for health checks."""

        with self._authority_transaction_lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._reconcile_authority_anchor(connection)
                row = connection.execute(
                    """
                    SELECT claim_sequence, clock_floor_ns,
                           (SELECT COUNT(*) FROM receipt_claims),
                           (SELECT COUNT(*) FROM lease_watermarks)
                    FROM metadata WHERE singleton = 1
                    """
                ).fetchone()
                connection.rollback()
                if row is None:
                    raise StorageError("executor replay status metadata is missing")
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()
        sizes: list[int] = []
        for candidate in (self.path, f"{self.path}-wal", f"{self.path}-shm"):
            size = 0
            with suppress(OSError):
                size = os.path.getsize(candidate)
            sizes.append(size)
        filesystem_free: int | None = None
        with suppress(OSError):
            filesystem_free = shutil.disk_usage(Path(self.path).parent).free
        return ExecutorReplayStatus(
            path=self.path,
            rollback_protected=self.rollback_protected,
            authority_healthy=self._anchored and not self._authority_faulted,
            identity=self._identity,
            claim_sequence=int(row[0]),
            clock_floor_ns=None if row[1] is None else int(row[1]),
            live_claims=int(row[2]),
            live_watermarks=int(row[3]),
            database_bytes=sizes[0],
            wal_bytes=sizes[1],
            shared_memory_bytes=sizes[2],
            filesystem_free_bytes=filesystem_free,
        )

    def verify_authority_anchor(self) -> bool:
        """Reconcile the current head without accepting a new receipt."""

        if self._authority_anchor is None:
            raise StorageError("no executor authority anchor is configured")
        self._reconcile_existing()
        return True

    def integrity_check(self) -> tuple[str, ...]:
        try:
            connection = self._connect()
            try:
                return tuple(str(row[0]) for row in connection.execute("PRAGMA integrity_check"))
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise StorageError("could not verify executor replay database integrity") from exc


class ReceiptVerifier:
    """Fail-closed receipt verifier used by a protected executor boundary."""

    def __init__(
        self,
        registry: PublicKeyRegistry,
        replay_store: ReceiptReplayStore,
        policy: ExecutorPolicy,
        *,
        clock: Clock | None = None,
    ) -> None:
        if isinstance(replay_store, SQLiteReceiptReplayStore):
            identity = replay_store.identity
            if identity is not None and executor_replay_identity(policy, registry) != identity:
                raise ValidationError(
                    "executor policy and trust registry must exactly match the replay store "
                    "identity"
                )
        self._registry = registry
        self._replay_store = replay_store
        self.policy = policy
        self._clock = SystemClock() if clock is None else clock

    def _clock_interval(self) -> tuple[int, int]:
        uncertainty = self._clock.uncertainty_ns()
        policy = self.policy
        if (
            isinstance(uncertainty, bool)
            or not isinstance(uncertainty, int)
            or uncertainty < 0
            or uncertainty > policy.max_clock_uncertainty_ns
        ):
            raise ClockUncertainError("executor clock uncertainty exceeds policy")
        now_ns = self._clock.now_ns()
        if (
            isinstance(now_ns, bool)
            or not isinstance(now_ns, int)
            or now_ns < 0
            or now_ns > MAX_RESOURCE - uncertainty
        ):
            raise ClockUncertainError("executor clock time is invalid")
        return now_ns, uncertainty

    def _verify_at(self, receipt: Receipt, *, now_ns: int, uncertainty: int) -> None:
        policy = self.policy
        if receipt.executor_audience != policy.audience:
            raise PolicyError("receipt audience does not match this executor")
        if policy.tenant_id is not None and receipt.tenant_id != policy.tenant_id:
            raise PolicyError("receipt tenant is not accepted by this executor")
        if policy.envelope_id is not None and receipt.envelope_id != policy.envelope_id:
            raise PolicyError("receipt envelope is not accepted by this executor")
        if policy.config_epoch is not None and receipt.config_epoch != policy.config_epoch:
            raise PolicyError("receipt configuration epoch is not accepted")
        if (
            policy.allowed_policy_digests
            and receipt.policy_digest not in policy.allowed_policy_digests
        ):
            raise PolicyError("receipt policy digest is not accepted")
        if (
            policy.allowed_machine_digests
            and receipt.machine_digest not in policy.allowed_machine_digests
        ):
            raise PolicyError("receipt machine digest is not accepted")
        if policy.trusted_wardens and receipt.warden_id not in policy.trusted_wardens:
            raise PolicyError("receipt issuer is not accepted")

        if receipt.issued_at_ns > now_ns + uncertainty:
            raise PolicyError("receipt issuance is in the future")
        if now_ns + uncertainty >= receipt.expires_at_ns:
            raise PolicyError("receipt is expired or cannot be proven fresh")

        try:
            signature = b64url_decode(receipt.signature)
        except Exception as exc:
            raise SignatureError("receipt signature is malformed") from exc
        if not self._registry.verify(
            receipt.warden_id,
            receipt.key_id,
            canonical_json(receipt.unsigned_payload()),
            signature,
        ):
            raise SignatureError("receipt signature is invalid or untrusted")

    def verify(self, receipt: Receipt) -> None:
        now_ns, uncertainty = self._clock_interval()
        self._verify_at(receipt, now_ns=now_ns, uncertainty=uncertainty)

    def verify_and_claim(self, receipt: Receipt) -> None:
        now_ns, uncertainty = self._clock_interval()
        self._verify_at(receipt, now_ns=now_ns, uncertainty=uncertainty)
        self._replay_store.claim(
            receipt,
            claimed_at_ns=now_ns,
            clock_uncertainty_ns=uncertainty,
        )


def trusted_registry(signers: Iterable[tuple[str, str, bytes]]) -> PublicKeyRegistry:
    registry = PublicKeyRegistry()
    for warden_id, key_id, public_key in signers:
        registry.register(warden_id, key_id, public_key)
    return registry
