"""Durable audit outbox export with idempotent sink semantics."""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from lets.canonical import b64url_encode, strict_json_loads
from lets.errors import ConflictError, StorageError, ValidationError
from lets.ids import require_identifier, require_warden_id
from lets.storage import SQLiteStorage
from lets.vector import MAX_RESOURCE

_ARCHIVE_APPLICATION_ID = 0x4C455441  # ASCII "LETA"
_ARCHIVE_SCHEMA_VERSION = 1


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
    sequence: int
    event_hash: bytes
    payload: bytes
    created_at_ns: int

    def __post_init__(self) -> None:
        require_warden_id(self.warden_id, field="audit export warden_id")
        require_identifier(self.tenant_id, field="audit export tenant_id")
        require_identifier(self.envelope_id, field="audit export envelope_id")
        _integer(self.sequence, "audit export sequence")
        _integer(self.created_at_ns, "audit export created_at_ns")
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

    def to_dict(self) -> dict[str, object]:
        return {
            "warden_id": self.warden_id,
            "tenant_id": self.tenant_id,
            "envelope_id": self.envelope_id,
            "sequence": self.sequence,
            "event_hash": b64url_encode(self.event_hash),
            "payload": strict_json_loads(self.payload),
            "created_at_ns": self.created_at_ns,
        }


class AuditSink(Protocol):
    """An idempotent, durable sink keyed by warden/envelope/sequence."""

    def publish(self, record: AuditExportRecord) -> None: ...


class SQLiteAuditSink:
    """Independent SQLite archive used by single-host and sidecar deployments."""

    def __init__(self, path: str | os.PathLike[str], *, _create: bool = False) -> None:
        self._path = Path(path).resolve()
        if _create:
            connect_path = str(self._path)
            uri = False
        else:
            connect_path = f"{self._path.as_uri()}?mode=rw"
            uri = True
        try:
            connection = sqlite3.connect(connect_path, isolation_level=None, uri=uri)
        except sqlite3.Error as exc:
            raise StorageError(f"could not open audit archive {self._path}") from exc
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            if _create:
                mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0])
                if mode.casefold() != "wal":
                    raise StorageError("audit archive refused WAL mode")
            self._admit(connection, create=_create)
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
                    warden_id     TEXT NOT NULL,
                    tenant_id     TEXT NOT NULL,
                    envelope_id   TEXT NOT NULL,
                    sequence      INTEGER NOT NULL CHECK (sequence >= 0),
                    event_hash    BLOB NOT NULL CHECK (
                        typeof(event_hash)='blob' AND length(event_hash)=32
                    ),
                    payload       BLOB NOT NULL CHECK (typeof(payload)='blob'),
                    created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
                    received_at_ns INTEGER NOT NULL CHECK (received_at_ns >= 0),
                    PRIMARY KEY (warden_id, tenant_id, envelope_id, sequence)
                ) STRICT, WITHOUT ROWID;
                CREATE UNIQUE INDEX ux_audit_archive_hash
                ON audit_records(warden_id, tenant_id, envelope_id, event_hash);
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
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise StorageError("audit archive integrity check failed")

    def publish(self, record: AuditExportRecord) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT event_hash, payload, created_at_ns FROM audit_records
                WHERE warden_id=? AND tenant_id=? AND envelope_id=? AND sequence=?
                """,
                (record.warden_id, record.tenant_id, record.envelope_id, record.sequence),
            ).fetchone()
            if existing is not None:
                if (
                    bytes(existing["event_hash"]) != record.event_hash
                    or bytes(existing["payload"]) != record.payload
                    or int(existing["created_at_ns"]) != record.created_at_ns
                ):
                    raise ConflictError("audit archive sequence is bound to different content")
                connection.rollback()
                return
            connection.execute(
                """
                INSERT INTO audit_records(
                    warden_id, tenant_id, envelope_id, sequence, event_hash,
                    payload, created_at_ns, received_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.warden_id,
                    record.tenant_id,
                    record.envelope_id,
                    record.sequence,
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
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_error: str | None = None
        self._last_success_ns: int | None = None

    def _pending(self) -> list[AuditExportRecord]:
        with self._store.read() as transaction:
            rows = transaction.connection.execute(
                """
                SELECT sequence, event_hash, payload, created_at_ns
                FROM audit_outbox
                WHERE tenant_id=? AND envelope_id=? AND published_at_ns IS NULL
                ORDER BY sequence LIMIT ?
                """,
                (
                    self._store.metadata.tenant_id,
                    self._store.metadata.envelope_id,
                    self._batch_size,
                ),
            ).fetchall()
        return [
            AuditExportRecord(
                warden_id=self._store.metadata.warden_id,
                tenant_id=self._store.metadata.tenant_id,
                envelope_id=self._store.metadata.envelope_id,
                sequence=int(row["sequence"]),
                event_hash=bytes(row["event_hash"]),
                payload=bytes(row["payload"]),
                created_at_ns=int(row["created_at_ns"]),
            )
            for row in rows
        ]

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
                        WHERE tenant_id=? AND envelope_id=? AND published_at_ns IS NOT NULL
                          AND sequence < ?
                        """,
                        (record.tenant_id, record.envelope_id, threshold),
                    )

    def run_once(self) -> int:
        exported = 0
        for record in self._pending():
            if self._stop.is_set():
                break
            try:
                self._sink.publish(record)
                self._acknowledge(record)
            except Exception as exc:
                self._last_error = f"{type(exc).__name__}: {exc}"
                break
            self._last_error = None
            self._last_success_ns = time.time_ns()
            exported += 1
        return exported

    def _run(self) -> None:
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self._poll_interval_s)

    def start(self) -> None:
        if self._thread is not None:
            raise StorageError("audit exporter is already started")
        self._stop.clear()
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
        return {
            "running": thread is not None and thread.is_alive(),
            "last_success_ns": self._last_success_ns,
            "last_error": self._last_error,
        }


__all__ = [
    "AuditExportRecord",
    "AuditExporter",
    "AuditSink",
    "SQLiteAuditSink",
]
