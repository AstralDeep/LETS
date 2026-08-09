"""Durable audit outbox export with idempotent sink semantics."""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from lets.canonical import b64url_encode, strict_json_loads
from lets.errors import ConflictError, StorageError, ValidationError
from lets.ids import require_identifier, require_warden_id
from lets.storage import SQLiteStorage, audit_event_hash
from lets.vector import MAX_RESOURCE

_ARCHIVE_APPLICATION_ID = 0x4C455441  # ASCII "LETA"
_ARCHIVE_SCHEMA_VERSION = 2


def _integer(value: object, field: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    if value < 0 or (positive and value == 0) or value > MAX_RESOURCE:
        qualifier = "positive" if positive else "non-negative"
        raise ValidationError(f"{field} must be a {qualifier} signed 64-bit integer")
    return value


@dataclass(frozen=True, slots=True)
class AuditExportRecord:
    warden_id: str
    tenant_id: str
    envelope_id: str
    config_epoch: int
    database_instance_id: bytes
    sequence: int
    event_type: str
    entity_type: str | None
    entity_id: str | None
    previous_hash: bytes
    event_hash: bytes
    payload: bytes
    created_at_ns: int

    def __post_init__(self) -> None:
        require_warden_id(self.warden_id, field="audit export warden_id")
        require_identifier(self.tenant_id, field="audit export tenant_id")
        require_identifier(self.envelope_id, field="audit export envelope_id")
        _integer(self.config_epoch, "audit export config_epoch", positive=True)
        if not isinstance(self.database_instance_id, bytes) or len(self.database_instance_id) != 32:
            raise ValidationError("audit export database_instance_id must contain 32 bytes")
        _integer(self.sequence, "audit export sequence")
        require_identifier(self.event_type, field="audit export event_type")
        if self.entity_type is not None:
            require_identifier(self.entity_type, field="audit export entity_type")
        if self.entity_id is not None:
            require_identifier(self.entity_id, field="audit export entity_id")
        _integer(self.created_at_ns, "audit export created_at_ns")
        if not isinstance(self.previous_hash, bytes) or len(self.previous_hash) != 32:
            raise ValidationError("audit export previous_hash must contain 32 bytes")
        if not isinstance(self.event_hash, bytes) or len(self.event_hash) != 32:
            raise ValidationError("audit export event_hash must contain 32 bytes")
        if not isinstance(self.payload, bytes) or not self.payload:
            raise ValidationError("audit export payload must be non-empty bytes")
        try:
            decoded = strict_json_loads(self.payload)
        except (UnicodeError, ValueError) as exc:
            raise ValidationError("audit export payload is outside LETS-CJ/1") from exc
        if not isinstance(decoded, Mapping):
            raise ValidationError("audit export payload must be a JSON object")
        expected_hash = audit_event_hash(
            self.previous_hash,
            self.sequence,
            self.event_type,
            self.entity_type,
            self.entity_id,
            self.payload,
            self.created_at_ns,
        )
        if self.event_hash != expected_hash:
            raise ValidationError("audit export event_hash does not authenticate its record")

    def to_dict(self) -> dict[str, object]:
        return {
            "warden_id": self.warden_id,
            "tenant_id": self.tenant_id,
            "envelope_id": self.envelope_id,
            "config_epoch": self.config_epoch,
            "database_instance_id": b64url_encode(self.database_instance_id),
            "sequence": self.sequence,
            "event_type": self.event_type,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "previous_hash": b64url_encode(self.previous_hash),
            "event_hash": b64url_encode(self.event_hash),
            "payload": strict_json_loads(self.payload),
            "created_at_ns": self.created_at_ns,
        }


@dataclass(frozen=True, slots=True)
class AuditArchiveHead:
    sequence: int
    event_hash: bytes

    def __post_init__(self) -> None:
        _integer(self.sequence, "audit archive head sequence")
        if not isinstance(self.event_hash, bytes) or len(self.event_hash) != 32:
            raise ValidationError("audit archive head event_hash must contain 32 bytes")


class AuditSink(Protocol):
    """An idempotent, durable sink keyed by warden/envelope/sequence.

    Providers SHOULD return or raise within their documented deadline.  The
    exporter nevertheless enforces its own deadline so a defective remote sink
    cannot keep node readiness green or prevent process shutdown indefinitely.
    """

    def publish(self, record: AuditExportRecord) -> None: ...

    def head(
        self,
        *,
        warden_id: str,
        tenant_id: str,
        envelope_id: str,
        config_epoch: int,
        database_instance_id: bytes,
    ) -> AuditArchiveHead | None: ...


class SQLiteAuditSink:
    """Independent SQLite archive used by single-host and sidecar deployments."""

    def __init__(self, path: str | os.PathLike[str], *, _create: bool = False) -> None:
        self._path = Path(path).resolve()
        reserved = False
        if _create:
            if not self._path.parent.is_dir():
                raise StorageError("audit archive parent directory does not exist")
            try:
                descriptor = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError as exc:
                raise StorageError("audit archive already exists") from exc
            except OSError as exc:
                raise StorageError(f"could not reserve audit archive {self._path}") from exc
            else:
                os.close(descriptor)
                reserved = True
            connect_path = str(self._path)
            uri = False
        else:
            connect_path = f"{self._path.as_uri()}?mode=rw"
            uri = True
        try:
            connection = sqlite3.connect(connect_path, isolation_level=None, uri=uri)
        except sqlite3.Error as exc:
            if reserved:
                self._path.unlink(missing_ok=True)
            raise StorageError(f"could not open audit archive {self._path}") from exc
        try:
            connection.create_function("lets_audit_hash", 7, audit_event_hash, deterministic=True)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            if _create:
                mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0])
                if mode.casefold() != "wal":
                    raise StorageError("audit archive refused WAL mode")
            self._admit(connection, create=_create)
        except BaseException:
            if reserved:
                connection.close()
                self._path.unlink(missing_ok=True)
            raise
        finally:
            connection.close()

    @classmethod
    def initialize(cls, path: str | os.PathLike[str]) -> SQLiteAuditSink:
        return cls(path, _create=True)

    @property
    def path(self) -> Path:
        return self._path

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                f"{self._path.as_uri()}?mode=rw",
                timeout=5,
                isolation_level=None,
                uri=True,
            )
            connection.row_factory = sqlite3.Row
            connection.create_function("lets_audit_hash", 7, audit_event_hash, deterministic=True)
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA busy_timeout=5000")
            return connection
        except sqlite3.Error as exc:
            raise StorageError("could not connect to the audit archive") from exc

    @staticmethod
    def _admit(connection: sqlite3.Connection, *, create: bool) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        if version == 0:
            if not create:
                raise StorageError("audit archive is empty or uninitialized")
            existing = connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchone()
            if existing is not None:
                raise StorageError("unversioned non-empty audit archive")
            connection.executescript(
                """
                CREATE TABLE audit_records (
                    warden_id           TEXT NOT NULL,
                    tenant_id           TEXT NOT NULL,
                    envelope_id         TEXT NOT NULL,
                    config_epoch        INTEGER NOT NULL CHECK (config_epoch > 0),
                    database_instance_id BLOB NOT NULL CHECK (
                        typeof(database_instance_id)='blob'
                        AND length(database_instance_id)=32
                    ),
                    sequence            INTEGER NOT NULL CHECK (sequence >= 0),
                    event_type          TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 512),
                    entity_type         TEXT CHECK (
                        entity_type IS NULL OR length(entity_type) BETWEEN 1 AND 512
                    ),
                    entity_id           TEXT CHECK (
                        entity_id IS NULL OR length(entity_id) BETWEEN 1 AND 512
                    ),
                    previous_hash       BLOB NOT NULL CHECK (
                        typeof(previous_hash)='blob' AND length(previous_hash)=32
                    ),
                    event_hash          BLOB NOT NULL CHECK (
                        typeof(event_hash)='blob' AND length(event_hash)=32
                        AND event_hash=lets_audit_hash(
                            previous_hash, sequence, event_type, entity_type,
                            entity_id, payload, created_at_ns
                        )
                    ),
                    payload             BLOB NOT NULL CHECK (typeof(payload)='blob'),
                    created_at_ns       INTEGER NOT NULL CHECK (created_at_ns >= 0),
                    received_at_ns      INTEGER NOT NULL CHECK (received_at_ns >= 0),
                    PRIMARY KEY (
                        warden_id, tenant_id, envelope_id, config_epoch,
                        database_instance_id, sequence
                    )
                ) STRICT, WITHOUT ROWID;
                CREATE UNIQUE INDEX ux_audit_archive_hash
                ON audit_records(
                    warden_id, tenant_id, envelope_id, config_epoch,
                    database_instance_id, event_hash
                );
                CREATE TRIGGER audit_archive_immutable_update
                BEFORE UPDATE ON audit_records
                BEGIN SELECT RAISE(ABORT, 'audit archive is immutable'); END;
                CREATE TRIGGER audit_archive_immutable_delete
                BEFORE DELETE ON audit_records
                BEGIN SELECT RAISE(ABORT, 'audit archive is immutable'); END;
                """
            )
            connection.execute(f"PRAGMA application_id={_ARCHIVE_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={_ARCHIVE_SCHEMA_VERSION}")
            version = _ARCHIVE_SCHEMA_VERSION
            application_id = _ARCHIVE_APPLICATION_ID
        elif create:
            raise StorageError("audit archive already exists")
        if version != _ARCHIVE_SCHEMA_VERSION or application_id != _ARCHIVE_APPLICATION_ID:
            raise StorageError("audit archive identity or schema version is unsupported")
        journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
        if journal_mode.casefold() != "wal":
            raise StorageError("audit archive must use WAL journal mode")
        required = {
            "audit_records",
            "ux_audit_archive_hash",
            "audit_archive_immutable_update",
            "audit_archive_immutable_delete",
        }
        found = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE name IN (?, ?, ?, ?)", tuple(required)
            )
        }
        if found != required:
            raise StorageError("audit archive schema is incomplete")
        columns = {
            str(row[1]): (str(row[2]), int(row[5]))
            for row in connection.execute("PRAGMA table_info(audit_records)")
        }
        expected_columns = {
            "warden_id": ("TEXT", 1),
            "tenant_id": ("TEXT", 2),
            "envelope_id": ("TEXT", 3),
            "config_epoch": ("INTEGER", 4),
            "database_instance_id": ("BLOB", 5),
            "sequence": ("INTEGER", 6),
            "event_type": ("TEXT", 0),
            "entity_type": ("TEXT", 0),
            "entity_id": ("TEXT", 0),
            "previous_hash": ("BLOB", 0),
            "event_hash": ("BLOB", 0),
            "payload": ("BLOB", 0),
            "created_at_ns": ("INTEGER", 0),
            "received_at_ns": ("INTEGER", 0),
        }
        if columns != expected_columns:
            raise StorageError("audit archive columns or primary key are malformed")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise StorageError("audit archive integrity check failed")

    def publish(self, record: AuditExportRecord) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT event_type, entity_type, entity_id, previous_hash,
                       event_hash, payload, created_at_ns
                FROM audit_records
                WHERE warden_id=? AND tenant_id=? AND envelope_id=?
                  AND config_epoch=? AND database_instance_id=? AND sequence=?
                """,
                (
                    record.warden_id,
                    record.tenant_id,
                    record.envelope_id,
                    record.config_epoch,
                    record.database_instance_id,
                    record.sequence,
                ),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["event_type"]) != record.event_type
                    or existing["entity_type"] != record.entity_type
                    or existing["entity_id"] != record.entity_id
                    or bytes(existing["previous_hash"]) != record.previous_hash
                    or bytes(existing["event_hash"]) != record.event_hash
                    or bytes(existing["payload"]) != record.payload
                    or int(existing["created_at_ns"]) != record.created_at_ns
                ):
                    raise ConflictError("audit archive sequence is bound to different content")
                connection.rollback()
                return
            prior = connection.execute(
                """
                SELECT sequence, event_hash FROM audit_records
                WHERE warden_id=? AND tenant_id=? AND envelope_id=?
                  AND config_epoch=? AND database_instance_id=?
                ORDER BY sequence DESC LIMIT 1
                """,
                (
                    record.warden_id,
                    record.tenant_id,
                    record.envelope_id,
                    record.config_epoch,
                    record.database_instance_id,
                ),
            ).fetchone()
            expected_sequence = 0 if prior is None else int(prior["sequence"]) + 1
            expected_previous = bytes(32) if prior is None else bytes(prior["event_hash"])
            if record.sequence != expected_sequence or record.previous_hash != expected_previous:
                raise ConflictError("audit archive requires one contiguous hash-chain successor")
            connection.execute(
                """
                INSERT INTO audit_records(
                    warden_id, tenant_id, envelope_id, config_epoch,
                    database_instance_id, sequence, event_type, entity_type,
                    entity_id, previous_hash, event_hash, payload,
                    created_at_ns, received_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.warden_id,
                    record.tenant_id,
                    record.envelope_id,
                    record.config_epoch,
                    record.database_instance_id,
                    record.sequence,
                    record.event_type,
                    record.entity_type,
                    record.entity_id,
                    record.previous_hash,
                    record.event_hash,
                    record.payload,
                    record.created_at_ns,
                    time.time_ns(),
                ),
            )
            connection.commit()
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise StorageError("audit archive write failed") from exc
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def head(
        self,
        *,
        warden_id: str,
        tenant_id: str,
        envelope_id: str,
        config_epoch: int,
        database_instance_id: bytes,
    ) -> AuditArchiveHead | None:
        checked_warden = require_warden_id(warden_id, field="audit archive warden_id")
        checked_tenant = require_identifier(tenant_id, field="audit archive tenant_id")
        checked_envelope = require_identifier(envelope_id, field="audit archive envelope_id")
        checked_epoch = _integer(config_epoch, "audit archive config_epoch", positive=True)
        if not isinstance(database_instance_id, bytes) or len(database_instance_id) != 32:
            raise ValidationError("audit archive database_instance_id must contain 32 bytes")
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT sequence, event_hash FROM audit_records
                WHERE warden_id=? AND tenant_id=? AND envelope_id=?
                  AND config_epoch=? AND database_instance_id=?
                ORDER BY sequence DESC LIMIT 1
                """,
                (
                    checked_warden,
                    checked_tenant,
                    checked_envelope,
                    checked_epoch,
                    database_instance_id,
                ),
            ).fetchone()
            if row is None:
                return None
            return AuditArchiveHead(int(row["sequence"]), bytes(row["event_hash"]))
        finally:
            connection.close()

    def count(self) -> int:
        connection = self._connect()
        try:
            return int(connection.execute("SELECT COUNT(*) FROM audit_records").fetchone()[0])
        finally:
            connection.close()


class AuditExporter:
    """Retrying outbox worker; sink publish precedes local acknowledgement."""

    def __init__(
        self,
        store: SQLiteStorage,
        sink: AuditSink,
        *,
        batch_size: int = 64,
        retain_published: int = 256,
        poll_interval_s: float = 1.0,
        publish_timeout_s: float = 5.0,
        max_pending: int = 4096,
        max_stall_s: float = 15.0,
    ) -> None:
        self._store = store
        self._sink = sink
        self._batch_size = _integer(batch_size, "audit batch_size", positive=True)
        self._retain_published = _integer(retain_published, "retain_published")
        if (
            isinstance(poll_interval_s, bool)
            or not isinstance(poll_interval_s, (int, float))
            or poll_interval_s <= 0
            or poll_interval_s > 60
        ):
            raise ValidationError("audit poll_interval_s must be in (0, 60]")
        self._poll_interval_s = float(poll_interval_s)
        if (
            isinstance(publish_timeout_s, bool)
            or not isinstance(publish_timeout_s, (int, float))
            or publish_timeout_s <= 0
            or publish_timeout_s > 60
        ):
            raise ValidationError("audit publish_timeout_s must be in (0, 60]")
        if (
            isinstance(max_stall_s, bool)
            or not isinstance(max_stall_s, (int, float))
            or max_stall_s < publish_timeout_s
            or max_stall_s > 300
        ):
            raise ValidationError(
                "audit max_stall_s must be at least publish_timeout_s and at most 300"
            )
        self._publish_timeout_s = float(publish_timeout_s)
        self._max_pending = _integer(max_pending, "audit max_pending", positive=True)
        self._max_stall_s = float(max_stall_s)
        checkpoint = store.authority_checkpoint()
        self._database_instance_id = checkpoint.database_instance_id
        self._config_epoch = checkpoint.config_epoch
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._blocked_sink_call: threading.Thread | None = None
        self._status_lock = threading.Lock()
        self._last_error: str | None = None
        self._last_success_ns: int | None = None
        self._last_progress_monotonic = time.monotonic()
        self._archive_reconciled = False

    def _core_batch(
        self, archive_head: AuditArchiveHead | None
    ) -> tuple[AuditArchiveHead | None, list[AuditExportRecord]]:
        with self._store.read() as transaction:
            core = transaction.connection.execute(
                """
                SELECT sequence, event_hash FROM audit_log
                WHERE tenant_id=? AND envelope_id=?
                ORDER BY sequence DESC LIMIT 1
                """,
                (self._store.metadata.tenant_id, self._store.metadata.envelope_id),
            ).fetchone()
            core_head = (
                None
                if core is None
                else AuditArchiveHead(int(core["sequence"]), bytes(core["event_hash"]))
            )
            if archive_head is not None:
                if core_head is None or archive_head.sequence > core_head.sequence:
                    raise StorageError("audit archive is ahead of the authoritative audit log")
                historical = transaction.connection.execute(
                    """
                    SELECT event_hash FROM audit_log
                    WHERE tenant_id=? AND envelope_id=? AND sequence=?
                    """,
                    (
                        self._store.metadata.tenant_id,
                        self._store.metadata.envelope_id,
                        archive_head.sequence,
                    ),
                ).fetchone()
                if historical is None or bytes(historical["event_hash"]) != archive_head.event_hash:
                    raise StorageError("audit archive diverges from the authoritative audit log")
            after_sequence = -1 if archive_head is None else archive_head.sequence
            rows = transaction.connection.execute(
                """
                SELECT sequence, event_type, entity_type, entity_id, previous_hash,
                       event_hash, payload, created_at_ns
                FROM audit_log
                WHERE tenant_id=? AND envelope_id=? AND sequence>?
                ORDER BY sequence LIMIT ?
                """,
                (
                    self._store.metadata.tenant_id,
                    self._store.metadata.envelope_id,
                    after_sequence,
                    self._batch_size,
                ),
            ).fetchall()
        records = [
            AuditExportRecord(
                warden_id=self._store.metadata.warden_id,
                tenant_id=self._store.metadata.tenant_id,
                envelope_id=self._store.metadata.envelope_id,
                config_epoch=self._config_epoch,
                database_instance_id=self._database_instance_id,
                sequence=int(row["sequence"]),
                event_type=str(row["event_type"]),
                entity_type=(None if row["entity_type"] is None else str(row["entity_type"])),
                entity_id=None if row["entity_id"] is None else str(row["entity_id"]),
                previous_hash=bytes(row["previous_hash"]),
                event_hash=bytes(row["event_hash"]),
                payload=bytes(row["payload"]),
                created_at_ns=int(row["created_at_ns"]),
            )
            for row in rows
        ]
        return core_head, records

    def _acknowledge(self, record: AuditExportRecord) -> None:
        now_ns = time.time_ns()
        with self._store.capacity_recovery() as transaction:
            cursor = transaction.connection.execute(
                """
                UPDATE audit_outbox
                SET published_at_ns=?, attempts=attempts+1, last_error=NULL
                WHERE tenant_id=? AND envelope_id=? AND sequence=?
                  AND event_hash=? AND published_at_ns IS NULL
                """,
                (
                    now_ns,
                    record.tenant_id,
                    record.envelope_id,
                    record.sequence,
                    record.event_hash,
                ),
            )
            if cursor.rowcount not in (0, 1):
                raise StorageError("audit outbox acknowledgement affected multiple rows")
            published = transaction.connection.execute(
                """
                SELECT MAX(sequence) FROM audit_outbox
                WHERE tenant_id=? AND envelope_id=? AND published_at_ns IS NOT NULL
                """,
                (record.tenant_id, record.envelope_id),
            ).fetchone()[0]
            if published is not None:
                threshold = int(published) - self._retain_published + 1
                if threshold > 0:
                    transaction.connection.execute(
                        """
                        DELETE FROM audit_outbox
                        WHERE (tenant_id, envelope_id, sequence) IN (
                            SELECT tenant_id, envelope_id, sequence
                            FROM audit_outbox
                            WHERE tenant_id=? AND envelope_id=?
                              AND published_at_ns IS NOT NULL AND sequence < ?
                            ORDER BY sequence
                            LIMIT ?
                        )
                        """,
                        (
                            record.tenant_id,
                            record.envelope_id,
                            threshold,
                            self._batch_size,
                        ),
                    )

    def _acknowledge_archive_prefix(self, head: AuditArchiveHead) -> bool:
        """Repair a bounded sink-commit/local-ack prefix.

        A restored archive can be far ahead of local outbox acknowledgements.
        Updating or pruning that entire prefix in one emergency transaction can
        exhaust the reserved WAL headroom needed to recover.  Each call therefore
        touches at most one exporter batch and reports whether repair is complete.
        """

        now_ns = time.time_ns()
        with self._store.capacity_recovery() as transaction:
            mismatch = transaction.connection.execute(
                """
                SELECT 1 FROM audit_outbox AS outbox
                JOIN audit_log AS log
                  ON log.tenant_id=outbox.tenant_id
                 AND log.envelope_id=outbox.envelope_id
                 AND log.sequence=outbox.sequence
                WHERE outbox.tenant_id=? AND outbox.envelope_id=?
                  AND outbox.sequence<=? AND outbox.event_hash<>log.event_hash
                LIMIT 1
                """,
                (
                    self._store.metadata.tenant_id,
                    self._store.metadata.envelope_id,
                    head.sequence,
                ),
            ).fetchone()
            if mismatch is not None:
                raise StorageError("audit outbox diverges from its immutable audit log")
            transaction.connection.execute(
                """
                UPDATE audit_outbox
                SET published_at_ns=?, attempts=attempts+1, last_error=NULL
                WHERE (tenant_id, envelope_id, sequence) IN (
                    SELECT tenant_id, envelope_id, sequence
                    FROM audit_outbox
                    WHERE tenant_id=? AND envelope_id=? AND sequence<=?
                      AND published_at_ns IS NULL
                    ORDER BY sequence
                    LIMIT ?
                )
                """,
                (
                    now_ns,
                    self._store.metadata.tenant_id,
                    self._store.metadata.envelope_id,
                    head.sequence,
                    self._batch_size,
                ),
            )
            acknowledged = int(transaction.connection.execute("SELECT changes()").fetchone()[0])
            threshold = head.sequence - self._retain_published + 1
            prune_budget = max(0, self._batch_size - acknowledged)
            if threshold > 0 and prune_budget > 0:
                transaction.connection.execute(
                    """
                    DELETE FROM audit_outbox
                    WHERE (tenant_id, envelope_id, sequence) IN (
                        SELECT tenant_id, envelope_id, sequence
                        FROM audit_outbox
                        WHERE tenant_id=? AND envelope_id=?
                          AND published_at_ns IS NOT NULL AND sequence < ?
                        ORDER BY sequence
                        LIMIT ?
                    )
                    """,
                    (
                        self._store.metadata.tenant_id,
                        self._store.metadata.envelope_id,
                        threshold,
                        prune_budget,
                    ),
                )
            remaining = transaction.connection.execute(
                """
                SELECT 1 FROM audit_outbox
                WHERE tenant_id=? AND envelope_id=? AND sequence<=?
                  AND published_at_ns IS NULL
                LIMIT 1
                """,
                (
                    self._store.metadata.tenant_id,
                    self._store.metadata.envelope_id,
                    head.sequence,
                ),
            ).fetchone()
            retained = None
            if threshold > 0:
                retained = transaction.connection.execute(
                    """
                    SELECT 1 FROM audit_outbox
                    WHERE tenant_id=? AND envelope_id=?
                      AND published_at_ns IS NOT NULL AND sequence < ?
                    LIMIT 1
                    """,
                    (
                        self._store.metadata.tenant_id,
                        self._store.metadata.envelope_id,
                        threshold,
                    ),
                ).fetchone()
            return remaining is None and retained is None

    def _call_sink(self, operation: Callable[[], object]) -> object:
        blocked = self._blocked_sink_call
        if blocked is not None:
            if blocked.is_alive():
                raise StorageError("a prior audit sink operation remains blocked")
            self._blocked_sink_call = None

        completed = threading.Event()
        errors: list[Exception] = []
        results: list[object] = []

        def invoke() -> None:
            try:
                results.append(operation())
            except Exception as exc:
                errors.append(exc)
            finally:
                completed.set()

        thread = threading.Thread(
            target=invoke,
            name="lets-audit-sink-call",
            daemon=True,
        )
        thread.start()
        if not completed.wait(self._publish_timeout_s):
            self._blocked_sink_call = thread
            raise StorageError("audit sink operation exceeded its deadline")
        thread.join()
        if errors:
            raise errors[0]
        if len(results) != 1:
            raise StorageError("audit sink operation returned no result")
        return results[0]

    def _archive_head(self) -> AuditArchiveHead | None:
        result = self._call_sink(
            lambda: self._sink.head(
                warden_id=self._store.metadata.warden_id,
                tenant_id=self._store.metadata.tenant_id,
                envelope_id=self._store.metadata.envelope_id,
                config_epoch=self._config_epoch,
                database_instance_id=self._database_instance_id,
            )
        )
        if result is not None and not isinstance(result, AuditArchiveHead):
            raise StorageError("audit sink returned an invalid archive head")
        return result

    def _publish(self, record: AuditExportRecord) -> None:
        self._call_sink(lambda: self._sink.publish(record))

    def run_once(self) -> int:
        exported = 0
        last_exported_sequence: int | None = None
        try:
            archive_head = self._archive_head()
            core_head, records = self._core_batch(archive_head)
            archive_prefix_reconciled = True
            if archive_head is not None:
                archive_prefix_reconciled = self._acknowledge_archive_prefix(archive_head)
            with self._status_lock:
                self._archive_reconciled = archive_prefix_reconciled and not records
            if not archive_prefix_reconciled:
                return 0
            for record in records:
                if self._stop.is_set():
                    break
                self._publish(record)
                self._acknowledge(record)
                with self._status_lock:
                    self._last_error = None
                    self._last_success_ns = time.time_ns()
                    self._last_progress_monotonic = time.monotonic()
                exported += 1
                last_exported_sequence = record.sequence
            if archive_prefix_reconciled and (
                core_head is None
                or last_exported_sequence == core_head.sequence
                or (archive_head is not None and archive_head.sequence == core_head.sequence)
            ):
                with self._status_lock:
                    self._archive_reconciled = True
                    self._last_error = None
                    if not records:
                        self._last_progress_monotonic = time.monotonic()
        except Exception as exc:
            with self._status_lock:
                self._archive_reconciled = False
                blocked = self._blocked_sink_call
                if not (
                    blocked is not None and blocked.is_alive() and self._last_error is not None
                ):
                    self._last_error = f"{type(exc).__name__}: {exc}"
        return exported

    def _run(self) -> None:
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self._poll_interval_s)

    def start(self) -> None:
        if self._thread is not None:
            raise StorageError("audit exporter is already started")
        self._stop.clear()
        with self._status_lock:
            self._last_progress_monotonic = time.monotonic()
        self._thread = threading.Thread(target=self._run, name="lets-audit-exporter", daemon=True)
        self._thread.start()

    def stop(self, *, timeout_s: float = 10.0) -> None:
        thread = self._thread
        if thread is None:
            return
        self._stop.set()
        thread.join(timeout_s)
        if thread.is_alive():
            raise StorageError("audit exporter did not stop within its deadline")
        self._thread = None

    def status(self) -> dict[str, object]:
        thread = self._thread
        try:
            with self._store.read() as transaction:
                backlog = transaction.connection.execute(
                    """
                    SELECT COUNT(*), MIN(created_at_ns) FROM audit_outbox
                    WHERE tenant_id=? AND envelope_id=? AND published_at_ns IS NULL
                    """,
                    (self._store.metadata.tenant_id, self._store.metadata.envelope_id),
                ).fetchone()
            pending = int(backlog[0]) if backlog is not None else self._max_pending + 1
            oldest_pending_ns = None if backlog is None else backlog[1]
            oldest_pending_age_s = (
                None
                if oldest_pending_ns is None
                else max(0.0, (time.time_ns() - int(oldest_pending_ns)) / 1_000_000_000)
            )
            status_error: str | None = None
        except Exception as exc:
            pending = self._max_pending + 1
            oldest_pending_age_s = None
            status_error = f"{type(exc).__name__}: {exc}"
        with self._status_lock:
            last_error = self._last_error
            last_success_ns = self._last_success_ns
            stalled_for_s = max(0.0, time.monotonic() - self._last_progress_monotonic)
            archive_reconciled = self._archive_reconciled
        running = thread is not None and thread.is_alive()
        blocked = self._blocked_sink_call
        sink_call_blocked = blocked is not None and blocked.is_alive()
        healthy = (
            running
            and last_error is None
            and status_error is None
            and not sink_call_blocked
            and archive_reconciled
            and pending <= self._max_pending
            and (pending == 0 or stalled_for_s <= self._max_stall_s)
        )
        return {
            "running": running,
            "healthy": healthy,
            "pending": pending,
            "max_pending": self._max_pending,
            "oldest_pending_age_s": oldest_pending_age_s,
            "stalled_for_s": stalled_for_s,
            "max_stall_s": self._max_stall_s,
            "archive_reconciled": archive_reconciled,
            "publish_blocked": sink_call_blocked,
            "sink_call_blocked": sink_call_blocked,
            "publish_timeout_s": self._publish_timeout_s,
            "last_success_ns": last_success_ns,
            "last_error": last_error or status_error,
        }


__all__ = [
    "AuditArchiveHead",
    "AuditExportRecord",
    "AuditExporter",
    "AuditSink",
    "SQLiteAuditSink",
]
