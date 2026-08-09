"""Independent protected-executor receipt verification and replay defense."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Self

from lets.canonical import b64url_decode, canonical_json
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
from lets.models import Receipt
from lets.vector import MAX_RESOURCE


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


class SQLiteReceiptReplayStore:
    """Crash-safe replay window plus per-lease high-water marks."""

    APPLICATION_ID = 0x4C455845
    SCHEMA_VERSION = 4

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        busy_timeout_ms: int = 5_000,
        _create: bool = False,
    ) -> None:
        raw_path = os.fspath(path)
        if not raw_path or raw_path == ":memory:":
            raise ValueError("executor replay storage must be filesystem-backed")
        self.path = str(Path(raw_path).resolve())
        if busy_timeout_ms <= 0:
            raise ValueError("busy_timeout_ms must be positive")
        self._busy_timeout_ms = busy_timeout_ms
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
    ) -> Self:
        """Create executor replay authority state exactly once."""

        return cls(path, busy_timeout_ms=busy_timeout_ms, _create=True)

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
                CREATE TABLE IF NOT EXISTS metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
                    clock_floor_ns INTEGER CHECK (
                        clock_floor_ns IS NULL OR clock_floor_ns >= 0
                    )
                ) STRICT;
                INSERT OR IGNORE INTO metadata(singleton, schema_version) VALUES (1, 4);
                CREATE TABLE IF NOT EXISTS receipt_claims (
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
                CREATE INDEX IF NOT EXISTS ix_receipt_claims_expiry
                    ON receipt_claims(expires_at_ns);
                CREATE TABLE IF NOT EXISTS lease_watermarks (
                    warden_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    audience TEXT NOT NULL,
                    last_sequence INTEGER NOT NULL CHECK (last_sequence > 0),
                    updated_at_ns INTEGER NOT NULL CHECK (updated_at_ns >= 0),
                    expires_at_ns INTEGER NOT NULL CHECK (expires_at_ns >= updated_at_ns),
                    PRIMARY KEY (warden_id, lease_id, audience)
                ) STRICT, WITHOUT ROWID;
                COMMIT;
                """
            )
            connection.execute(f"PRAGMA application_id={self.APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={self.SCHEMA_VERSION}")
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _verify_existing(self) -> None:
        connection = self._connect()
        try:
            tables = {
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_schema WHERE type = 'table'")
            }
            required = {"metadata", "receipt_claims", "lease_watermarks"}
            if not required.issubset(tables):
                raise StorageError("executor replay database is empty or has an incomplete schema")
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if application_id != self.APPLICATION_ID or user_version != self.SCHEMA_VERSION:
                raise StorageError("executor replay database identity or schema version is invalid")
            row = connection.execute(
                "SELECT schema_version FROM metadata WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise StorageError("executor replay database metadata is missing")
            version = int(row[0])
            if version != self.SCHEMA_VERSION:
                raise StorageError(
                    f"executor replay schema {version} requires explicit migration to "
                    f"{self.SCHEMA_VERSION}"
                )
            metadata_info = tuple(connection.execute("PRAGMA table_info(metadata)"))
            claims_info = tuple(connection.execute("PRAGMA table_info(receipt_claims)"))
            watermarks_info = tuple(connection.execute("PRAGMA table_info(lease_watermarks)"))
            if (
                {str(item[1]) for item in metadata_info}
                != {
                    "singleton",
                    "schema_version",
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
            if (
                ("tenant_id", "envelope_id", "audience", "nonce") not in unique_claim_indexes
                or ("receipt_id",) not in unique_claim_indexes
                or watermark_primary_key != ("warden_id", "lease_id", "audience")
                or expiry_index != ("expires_at_ns",)
            ):
                raise StorageError("executor replay uniqueness or expiry index is missing")
            journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
            if journal_mode.casefold() != "wal":
                raise StorageError("executor replay database must already use WAL journal mode")
        finally:
            connection.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.rollback()
            raise ReplayError("receipt id or nonce has already been consumed") from exc
        except Exception:
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
        with self._write() as connection:
            floor = connection.execute(
                "SELECT clock_floor_ns FROM metadata WHERE singleton = 1"
            ).fetchone()
            if floor is None:
                raise StorageError("executor replay clock metadata is missing")
            prior_floor = floor[0]
            if prior_floor is not None and claimed_at_ns + clock_uncertainty_ns < int(prior_floor):
                raise ClockUncertainError(
                    "executor clock moved behind its durable floor beyond declared uncertainty"
                )
            if prior_floor is None or claimed_at_ns > int(prior_floor):
                connection.execute(
                    "UPDATE metadata SET clock_floor_ns = ? WHERE singleton = 1",
                    (claimed_at_ns,),
                )
            connection.execute(
                "DELETE FROM receipt_claims WHERE expires_at_ns <= ?",
                (claimed_at_ns,),
            )
            connection.execute(
                "DELETE FROM lease_watermarks WHERE expires_at_ns <= ?",
                (claimed_at_ns,),
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
        self._registry = registry
        self._replay_store = replay_store
        self.policy = policy
        self._clock = SystemClock() if clock is None else clock

    def verify(self, receipt: Receipt) -> None:
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

        uncertainty = self._clock.uncertainty_ns()
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

    def verify_and_claim(self, receipt: Receipt) -> None:
        self.verify(receipt)
        self._replay_store.claim(
            receipt,
            claimed_at_ns=self._clock.now_ns(),
            clock_uncertainty_ns=self._clock.uncertainty_ns(),
        )


def trusted_registry(signers: Iterable[tuple[str, str, bytes]]) -> PublicKeyRegistry:
    registry = PublicKeyRegistry()
    for warden_id, key_id, public_key in signers:
        registry.register(warden_id, key_id, public_key)
    return registry
