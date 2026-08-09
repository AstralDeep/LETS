"""Durable, transport-neutral SQLite storage for LETS wardens."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol, Self, TypeAlias, cast, runtime_checkable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from lets.authority import AuthorityAnchor, AuthorityCheckpoint
from lets.canonical import canonical_json
from lets.errors import (
    CapacityError,
    ConflictError,
    InvariantError,
    NotFoundError,
    StorageError,
    ValidationError,
)
from lets.ids import require_key_id, require_warden_id
from lets.policy import MAX_TRANSFER_GAP_WINDOW
from lets.storage.schema import (
    APPLICATION_ID,
    MIGRATIONS,
    REQUIRED_INDEXES,
    REQUIRED_TABLES,
    REQUIRED_TRIGGERS,
    SCHEMA_VERSION,
)
from lets.vector import (
    ResourceVector,
    add,
    less_than_or_equal,
    pack,
    subtract,
    unpack,
    vector,
    zero,
)

SQLiteScalar: TypeAlias = str | int | float | bytes | None
SQLParameters: TypeAlias = Sequence[SQLiteScalar] | Mapping[str, SQLiteScalar]
Record: TypeAlias = dict[str, Any]
PathLike: TypeAlias = str | os.PathLike[str]

_MAX_SQLITE_INTEGER = (1 << 63) - 1
_ZERO_AUDIT_HASH = bytes(32)
_DEFAULT_RECEIPT_TTL_NS = 1_000_000_000
_DEFAULT_TRANSFER_GAP_WINDOW = 64


def _identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 512:
        raise ValidationError(f"{name} must be a non-empty string of at most 512 characters")
    return value


def _nonnegative_integer(
    value: object,
    name: str,
    *,
    positive: bool = False,
    maximum: int = _MAX_SQLITE_INTEGER,
) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        comparator = "positive" if positive else "non-negative"
        raise ValidationError(f"{name} must be {comparator} and no greater than {maximum}")
    return value


def _blob(value: object, name: str, *, allow_empty: bool = True) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValidationError(f"{name} must be bytes")
    result = bytes(value)
    if not allow_empty and not result:
        raise ValidationError(f"{name} must not be empty")
    return result


def _json_blob(value: object) -> bytes:
    return value if isinstance(value, bytes) else canonical_json(value)


def _decode_json(value: object, name: str) -> Any:
    try:
        return json.loads(_blob(value, name).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StorageError(f"stored {name} is not valid UTF-8 JSON") from exc


def _framed_hash_part(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def audit_event_hash(
    previous_hash: bytes,
    sequence: int,
    event_type: str,
    entity_type: str | None,
    entity_id: str | None,
    payload: bytes,
    created_at_ns: int,
) -> bytes:
    """Hash an audit event with unambiguous, cross-runtime framing."""

    previous = _blob(previous_hash, "previous_hash")
    if len(previous) != 32:
        raise ValidationError("previous_hash must contain 32 bytes")
    checked_sequence = _nonnegative_integer(sequence, "sequence")
    checked_created_at = _nonnegative_integer(created_at_ns, "created_at_ns")
    event = _identifier(event_type, "event_type")
    if entity_type is not None:
        _identifier(entity_type, "entity_type")
    if entity_id is not None:
        _identifier(entity_id, "entity_id")
    body = _blob(payload, "payload")

    digest = sha256()
    digest.update(b"LETS-AUDIT-v1\x00")
    digest.update(previous)
    digest.update(checked_sequence.to_bytes(8, "big"))
    digest.update(checked_created_at.to_bytes(8, "big"))
    for item in (event, entity_type or "", entity_id or ""):
        digest.update(_framed_hash_part(item.encode("utf-8")))
    digest.update(_framed_hash_part(body))
    return digest.digest()


def _sqlite_vector_valid(value: object, dimensions: object) -> int:
    try:
        encoded = _blob(value, "resource vector")
        expected = None if dimensions is None else int(cast(int, dimensions))
        unpack(encoded, dimensions=expected)
    except (TypeError, ValueError, ValidationError):
        return 0
    return 1


def _sqlite_vector_dimensions(value: object) -> int:
    try:
        return len(unpack(_blob(value, "resource vector")))
    except (TypeError, ValueError, ValidationError):
        return -1


def _sqlite_vector_nonzero(value: object) -> int:
    try:
        return int(any(unpack(_blob(value, "resource vector"))))
    except (TypeError, ValueError, ValidationError):
        return 0


def _sqlite_vector_add(left: object, right: object) -> bytes | None:
    try:
        return pack(add(unpack(_blob(left, "left vector")), unpack(_blob(right, "right vector"))))
    except (TypeError, ValueError, ValidationError):
        return None


def _sqlite_vector_subtract(left: object, right: object) -> bytes | None:
    try:
        return pack(
            subtract(unpack(_blob(left, "left vector")), unpack(_blob(right, "right vector")))
        )
    except (TypeError, ValueError, ValidationError):
        return None


def _sqlite_audit_hash(
    previous_hash: object,
    sequence: object,
    event_type: object,
    entity_type: object,
    entity_id: object,
    payload: object,
    created_at_ns: object,
) -> bytes | None:
    try:
        return audit_event_hash(
            _blob(previous_hash, "previous_hash"),
            int(cast(int, sequence)),
            str(event_type),
            None if entity_type is None else str(entity_type),
            None if entity_id is None else str(entity_id),
            _blob(payload, "payload"),
            int(cast(int, created_at_ns)),
        )
    except (TypeError, ValueError, ValidationError):
        return None


def _register_functions(connection: sqlite3.Connection) -> None:
    connection.create_function("lets_vector_valid", 2, _sqlite_vector_valid, deterministic=True)
    connection.create_function(
        "lets_vector_dimensions", 1, _sqlite_vector_dimensions, deterministic=True
    )
    connection.create_function("lets_vector_nonzero", 1, _sqlite_vector_nonzero, deterministic=True)
    connection.create_function("lets_vector_add", 2, _sqlite_vector_add, deterministic=True)
    connection.create_function(
        "lets_vector_subtract", 2, _sqlite_vector_subtract, deterministic=True
    )
    connection.create_function("lets_audit_hash", 7, _sqlite_audit_hash, deterministic=True)


def _normalize_dimensions(value: object | None, count: int) -> tuple[Record, ...]:
    if value is None:
        return ()
    # Dataclasses and other canonicalizable objects are normalized by canonical_json.
    try:
        normalized = json.loads(canonical_json(value).decode("utf-8"))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValidationError("dimension_metadata must be canonically JSON serializable") from exc
    if not isinstance(normalized, list):
        raise ValidationError("dimension_metadata must be an ordered array")
    if normalized and len(normalized) != count:
        raise ValidationError(
            f"dimension_metadata must be empty or contain exactly {count} ordered entries"
        )
    output: list[Record] = []
    names: set[str] = set()
    for index, item in enumerate(normalized):
        if isinstance(item, str):
            record: Record = {"name": item}
        elif isinstance(item, dict):
            record = dict(item)
        else:
            raise ValidationError(f"dimension_metadata[{index}] must be a string or object")
        name = _identifier(record.get("name"), f"dimension_metadata[{index}].name")
        if name in names:
            raise ValidationError(f"duplicate resource dimension name: {name}")
        names.add(name)
        output.append(record)
    return tuple(output)


@dataclass(frozen=True, slots=True)
class StorageMetadata:
    schema_version: int
    warden_id: str
    signing_key_id: str
    signing_public_key_sha256: bytes
    tenant_id: str
    envelope_id: str
    config_epoch: int
    dimension_metadata: tuple[Record, ...]
    budget: ResourceVector
    initial_local_share: ResourceVector
    receipt_ttl_ns: int
    max_clock_uncertainty_ns: int
    transfer_gap_window: int
    config: Any
    created_at_ns: int

    @property
    def dimension_count(self) -> int:
        return len(self.budget)


@dataclass(frozen=True, slots=True)
class CapacitySnapshot:
    database_bytes: int
    filesystem_free_bytes: int | None
    page_size: int
    page_count: int
    free_pages: int
    max_page_count: int
    reserve_pages: int
    min_free_disk_bytes: int
    max_database_bytes: int | None
    prior_full_error: bool
    healthy: bool

    def to_dict(self) -> Record:
        return {
            "database_bytes": self.database_bytes,
            "filesystem_free_bytes": self.filesystem_free_bytes,
            "page_size": self.page_size,
            "page_count": self.page_count,
            "free_pages": self.free_pages,
            "max_page_count": self.max_page_count,
            "reserve_pages": self.reserve_pages,
            "min_free_disk_bytes": self.min_free_disk_bytes,
            "max_database_bytes": self.max_database_bytes,
            "prior_full_error": self.prior_full_error,
            "healthy": self.healthy,
        }


@dataclass(frozen=True, slots=True)
class AuditRecord:
    sequence: int
    event_type: str
    entity_type: str | None
    entity_id: str | None
    payload: bytes
    previous_hash: bytes
    event_hash: bytes
    created_at_ns: int


@runtime_checkable
class Transaction(Protocol):
    @property
    def connection(self) -> sqlite3.Connection: ...

    @property
    def metadata(self) -> StorageMetadata: ...

    @property
    def writable(self) -> bool: ...

    def execute(self, sql: str, parameters: SQLParameters = ()) -> sqlite3.Cursor: ...

    def fetch_one(self, sql: str, parameters: SQLParameters = ()) -> sqlite3.Row | None: ...

    def fetch_all(self, sql: str, parameters: SQLParameters = ()) -> list[sqlite3.Row]: ...


@runtime_checkable
class Storage(Protocol):
    @property
    def metadata(self) -> StorageMetadata: ...

    def transaction(self, *, write: bool = True) -> AbstractContextManager[Transaction]: ...

    def write(self) -> AbstractContextManager[Transaction]: ...

    def read(self) -> AbstractContextManager[Transaction]: ...

    def close(self) -> None: ...


class SQLiteTransaction:
    """One explicitly bounded SQLite transaction.

    Instances are created by :class:`SQLiteStorage`; callers must not retain one
    after its context manager exits.
    """

    __slots__ = ("_closed", "_connection", "_metadata", "_writable")

    def __init__(
        self,
        connection: sqlite3.Connection,
        metadata: StorageMetadata,
        *,
        writable: bool,
    ) -> None:
        self._connection = connection
        self._metadata = metadata
        self._writable = writable
        self._closed = False

    @property
    def connection(self) -> sqlite3.Connection:
        self._ensure_open()
        return self._connection

    @property
    def metadata(self) -> StorageMetadata:
        return self._metadata

    @property
    def writable(self) -> bool:
        return self._writable

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def tenant_id(self) -> str:
        return self._metadata.tenant_id

    @property
    def envelope_id(self) -> str:
        return self._metadata.envelope_id

    @property
    def scope(self) -> tuple[str, str]:
        return (self.tenant_id, self.envelope_id)

    def _ensure_open(self) -> None:
        if self._closed:
            raise StorageError("transaction is closed")

    def _ensure_write(self) -> None:
        self._ensure_open()
        if not self._writable:
            raise StorageError("write operation attempted in a read transaction")

    def execute(self, sql: str, parameters: SQLParameters = ()) -> sqlite3.Cursor:
        self._ensure_open()
        return self._connection.execute(sql, parameters)

    def executemany(self, sql: str, parameters: Sequence[SQLParameters]) -> sqlite3.Cursor:
        self._ensure_open()
        return self._connection.executemany(sql, parameters)

    def fetch_one(self, sql: str, parameters: SQLParameters = ()) -> sqlite3.Row | None:
        return cast(sqlite3.Row | None, self.execute(sql, parameters).fetchone())

    def fetch_all(self, sql: str, parameters: SQLParameters = ()) -> list[sqlite3.Row]:
        return self.execute(sql, parameters).fetchall()

    def scalar(self, sql: str, parameters: SQLParameters = ()) -> SQLiteScalar:
        row = self.fetch_one(sql, parameters)
        return None if row is None else cast(SQLiteScalar, row[0])

    def pack_vector(self, value: Sequence[int]) -> bytes:
        return pack(vector(value, dimensions=self._metadata.dimension_count))

    def unpack_vector(self, value: object) -> ResourceVector:
        return unpack(_blob(value, "resource vector"), dimensions=self._metadata.dimension_count)

    def _scoped_record(
        self, row: sqlite3.Row, *vectors: str, json_fields: Sequence[str] = ()
    ) -> Record:
        result = dict(row)
        for field in vectors:
            result[field] = self.unpack_vector(result[field])
        for field in json_fields:
            result[field] = _decode_json(result[field], field)
        return result

    # -- Envelope state -------------------------------------------------

    def get_warden_state(self) -> Record:
        row = self.fetch_one(
            """
            SELECT * FROM warden_state WHERE tenant_id = ? AND envelope_id = ?
            """,
            self.scope,
        )
        if row is None:
            raise StorageError("warden state row is missing")
        return self._scoped_record(
            row,
            "free_pool",
            "lease_residual",
            "consumed",
            "transferred_in",
            "transferred_out",
        )

    def update_warden_state(
        self,
        *,
        free_pool: Sequence[int] | None = None,
        consumed: Sequence[int] | None = None,
        transferred_in: Sequence[int] | None = None,
        transferred_out: Sequence[int] | None = None,
        updated_at_ns: int,
        expected_revision: int | None = None,
    ) -> int:
        self._ensure_write()
        timestamp = _nonnegative_integer(updated_at_ns, "updated_at_ns")
        updates: list[str] = []
        parameters: list[SQLiteScalar] = []
        for name, value in (
            ("free_pool", free_pool),
            ("consumed", consumed),
            ("transferred_in", transferred_in),
            ("transferred_out", transferred_out),
        ):
            if value is not None:
                updates.append(f"{name} = ?")
                parameters.append(self.pack_vector(value))
        updates.extend(("revision = revision + 1", "updated_at_ns = ?"))
        parameters.append(timestamp)
        # ``updates`` contains only the fixed column names enumerated above.
        query = (
            f"UPDATE warden_state SET {', '.join(updates)} "  # nosec B608
            "WHERE tenant_id = ? AND envelope_id = ?"
        )
        parameters.extend(self.scope)
        if expected_revision is not None:
            query += " AND revision = ?"
            parameters.append(_nonnegative_integer(expected_revision, "expected_revision"))
        cursor = self.execute(query, parameters)
        if cursor.rowcount != 1:
            raise ConflictError("warden state revision changed")
        revision = self.scalar(
            "SELECT revision FROM warden_state WHERE tenant_id = ? AND envelope_id = ?",
            self.scope,
        )
        return cast(int, revision)

    # -- Policies -------------------------------------------------------

    def insert_policy(
        self,
        *,
        policy_version: str,
        policy_digest: str,
        machine_digest: str,
        payload: object,
        created_at_ns: int,
        active: bool = False,
    ) -> None:
        self._ensure_write()
        if not isinstance(active, bool):
            raise ValidationError("active must be a boolean")
        now = _nonnegative_integer(created_at_ns, "created_at_ns")
        if active:
            self.execute(
                """
                UPDATE policies SET active = 0, retired_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ? AND active = 1
                """,
                (now, *self.scope),
            )
        self.execute(
            """
            INSERT INTO policies(
                tenant_id, envelope_id, policy_version, policy_digest, machine_digest,
                payload, active, created_at_ns, retired_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                *self.scope,
                _identifier(policy_version, "policy_version"),
                _identifier(policy_digest, "policy_digest"),
                _identifier(machine_digest, "machine_digest"),
                _json_blob(payload),
                int(active),
                now,
            ),
        )

    def activate_policy(self, policy_version: str, *, activated_at_ns: int) -> None:
        self._ensure_write()
        version = _identifier(policy_version, "policy_version")
        now = _nonnegative_integer(activated_at_ns, "activated_at_ns")
        exists = self.scalar(
            """
            SELECT 1 FROM policies
            WHERE tenant_id = ? AND envelope_id = ? AND policy_version = ?
            """,
            (*self.scope, version),
        )
        if exists is None:
            raise NotFoundError(f"policy not found: {version}")
        self.execute(
            """
            UPDATE policies SET active = 0, retired_at_ns = ?
            WHERE tenant_id = ? AND envelope_id = ? AND active = 1
            """,
            (now, *self.scope),
        )
        self.execute(
            """
            UPDATE policies SET active = 1, retired_at_ns = NULL
            WHERE tenant_id = ? AND envelope_id = ? AND policy_version = ?
            """,
            (*self.scope, version),
        )

    def get_policy(
        self,
        policy_version: str | None = None,
        *,
        policy_digest: str | None = None,
        active: bool = False,
    ) -> Record | None:
        selectors = sum(item is not None for item in (policy_version, policy_digest)) + int(active)
        if selectors != 1:
            raise ValidationError("select a policy by exactly one version, digest, or active flag")
        if policy_version is not None:
            row = self.fetch_one(
                """
                SELECT * FROM policies
                WHERE tenant_id = ? AND envelope_id = ? AND policy_version = ?
                """,
                (*self.scope, _identifier(policy_version, "policy_version")),
            )
        elif policy_digest is not None:
            row = self.fetch_one(
                """
                SELECT * FROM policies
                WHERE tenant_id = ? AND envelope_id = ? AND policy_digest = ?
                """,
                (*self.scope, _identifier(policy_digest, "policy_digest")),
            )
        else:
            row = self.fetch_one(
                """
                SELECT * FROM policies
                WHERE tenant_id = ? AND envelope_id = ? AND active = 1
                """,
                self.scope,
            )
        if row is None:
            return None
        result = dict(row)
        result["payload"] = _decode_json(result["payload"], "policy payload")
        result["active"] = bool(result["active"])
        return result

    # -- Leases ---------------------------------------------------------

    def insert_lease(self, lease: Mapping[str, Any]) -> None:
        self._ensure_write()

        def required(name: str) -> Any:
            try:
                return lease[name]
            except KeyError as exc:
                raise ValidationError(f"missing lease field: {name}") from exc

        issued_at = _nonnegative_integer(required("issued_at_ns"), "issued_at_ns")
        expires_at = _nonnegative_integer(required("expires_at_ns"), "expires_at_ns")
        if expires_at <= issued_at:
            raise ValidationError("expires_at_ns must be later than issued_at_ns")
        allocation = vector(required("allocation"), dimensions=self._metadata.dimension_count)
        residual = vector(required("residual"), dimensions=self._metadata.dimension_count)
        if not less_than_or_equal(residual, allocation):
            raise ValidationError("lease residual cannot exceed allocation")
        created_at = _nonnegative_integer(lease.get("created_at_ns", issued_at), "created_at_ns")
        updated_at = _nonnegative_integer(lease.get("updated_at_ns", created_at), "updated_at_ns")
        if updated_at < created_at:
            raise ValidationError("updated_at_ns must not precede created_at_ns")
        policy_version = _identifier(required("policy_version"), "policy_version")
        policy_digest = lease.get("policy_digest")
        if policy_digest is None:
            policy_digest = self.scalar(
                """
                SELECT policy_digest FROM policies
                WHERE tenant_id = ? AND envelope_id = ? AND policy_version = ?
                """,
                (*self.scope, policy_version),
            )
        self.execute(
            """
            INSERT INTO leases(
                tenant_id, envelope_id, lease_id, lineage_id, parent_id, subject_id,
                warden_id, allocation, residual, capabilities_json, machine_digest,
                ancestor_path_json, branch_epoch, config_epoch, issued_at_ns, expires_at_ns,
                key_id, signature, state, status, sequence, policy_version, policy_digest,
                created_at_ns, updated_at_ns
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                *self.scope,
                _identifier(required("lease_id"), "lease_id"),
                _identifier(required("lineage_id"), "lineage_id"),
                None
                if lease.get("parent_id") is None
                else _identifier(lease["parent_id"], "parent_id"),
                _identifier(required("subject_id"), "subject_id"),
                _identifier(lease.get("warden_id", self._metadata.warden_id), "warden_id"),
                pack(allocation),
                pack(residual),
                _json_blob(required("capabilities")),
                _identifier(required("machine_digest"), "machine_digest"),
                _json_blob(lease.get("ancestor_path", ())),
                _nonnegative_integer(lease.get("branch_epoch", 0), "branch_epoch"),
                _nonnegative_integer(
                    lease.get("config_epoch", self._metadata.config_epoch),
                    "config_epoch",
                    positive=True,
                ),
                issued_at,
                expires_at,
                _identifier(required("key_id"), "key_id"),
                _blob(required("signature"), "signature", allow_empty=False),
                _identifier(required("state"), "state"),
                _identifier(required("status"), "status"),
                _nonnegative_integer(lease.get("sequence", 0), "sequence"),
                policy_version,
                _identifier(policy_digest, "policy_digest"),
                created_at,
                updated_at,
            ),
        )

    def get_lease(self, lease_id: str) -> Record | None:
        row = self.fetch_one(
            """
            SELECT * FROM leases
            WHERE tenant_id = ? AND envelope_id = ? AND lease_id = ?
            """,
            (*self.scope, _identifier(lease_id, "lease_id")),
        )
        if row is None:
            return None
        return self._scoped_record(
            row,
            "allocation",
            "residual",
            json_fields=("capabilities_json", "ancestor_path_json"),
        )

    def update_lease_state(
        self,
        lease_id: str,
        *,
        residual: Sequence[int],
        state: str,
        status: str,
        sequence: int,
        updated_at_ns: int,
        issued_at_ns: int | None = None,
        expires_at_ns: int | None = None,
        signature: bytes | None = None,
        branch_epoch: int | None = None,
        expected_sequence: int | None = None,
    ) -> None:
        self._ensure_write()
        updates = ["residual = ?", "state = ?", "status = ?", "sequence = ?", "updated_at_ns = ?"]
        parameters: list[SQLiteScalar] = [
            self.pack_vector(residual),
            _identifier(state, "state"),
            _identifier(status, "status"),
            _nonnegative_integer(sequence, "sequence"),
            _nonnegative_integer(updated_at_ns, "updated_at_ns"),
        ]
        for column, value in (
            ("issued_at_ns", issued_at_ns),
            ("expires_at_ns", expires_at_ns),
            ("branch_epoch", branch_epoch),
        ):
            if value is not None:
                updates.append(f"{column} = ?")
                parameters.append(_nonnegative_integer(value, column))
        if signature is not None:
            updates.append("signature = ?")
            parameters.append(_blob(signature, "signature", allow_empty=False))
        # ``updates`` contains only fixed columns selected in this method.
        query = (
            f"UPDATE leases SET {', '.join(updates)} "  # nosec B608
            "WHERE tenant_id = ? AND envelope_id = ? AND lease_id = ?"
        )
        parameters.extend((*self.scope, _identifier(lease_id, "lease_id")))
        if expected_sequence is not None:
            query += " AND sequence = ?"
            parameters.append(_nonnegative_integer(expected_sequence, "expected_sequence"))
        cursor = self.execute(query, parameters)
        if cursor.rowcount != 1:
            if expected_sequence is not None:
                raise ConflictError("lease sequence changed")
            raise NotFoundError(f"lease not found: {lease_id}")

    # -- Idempotency ----------------------------------------------------

    def get_idempotency(
        self, scope: str, request_id: str, *, now_ns: int | None = None
    ) -> Record | None:
        checked_scope = _identifier(scope, "scope")
        parameters: list[SQLiteScalar] = [
            *self.scope,
            _identifier(request_id, "request_id"),
        ]
        if now_ns is not None:
            parameters.append(_nonnegative_integer(now_ns, "now_ns"))
            row = self.fetch_one(
                """
                SELECT * FROM idempotency
                WHERE tenant_id = ? AND envelope_id = ? AND request_id = ?
                  AND (expires_at_ns IS NULL OR expires_at_ns > ?)
                """,
                parameters,
            )
        else:
            row = self.fetch_one(
                """
                SELECT * FROM idempotency
                WHERE tenant_id = ? AND envelope_id = ? AND request_id = ?
                """,
                parameters,
            )
        if row is None:
            return None
        if row["scope"] != checked_scope:
            raise ConflictError(
                f"request_id {request_id!r} is already bound to scope {row['scope']!r}"
            )
        return dict(row)

    def put_idempotency(
        self,
        *,
        scope: str,
        request_id: str,
        fingerprint: bytes,
        response: bytes,
        status_code: int,
        created_at_ns: int,
        expires_at_ns: int | None = None,
    ) -> None:
        self._ensure_write()
        created = _nonnegative_integer(created_at_ns, "created_at_ns")
        expires = (
            None if expires_at_ns is None else _nonnegative_integer(expires_at_ns, "expires_at_ns")
        )
        if expires is not None and expires < created:
            raise ValidationError("expires_at_ns must not precede created_at_ns")
        code = _nonnegative_integer(status_code, "status_code")
        if not 100 <= code <= 599:
            raise ValidationError("status_code must be between 100 and 599")
        checked_scope = _identifier(scope, "scope")
        checked_request = _identifier(request_id, "request_id")
        existing = self.fetch_one(
            """
            SELECT scope FROM idempotency
            WHERE tenant_id = ? AND envelope_id = ? AND request_id = ?
            """,
            (*self.scope, checked_request),
        )
        if existing is not None:
            raise ConflictError(
                f"request_id {checked_request!r} is already bound to scope {existing['scope']!r}"
            )
        self.execute(
            """
            INSERT INTO idempotency(
                tenant_id, envelope_id, scope, request_id, fingerprint, response,
                status_code, created_at_ns, expires_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                *self.scope,
                checked_scope,
                checked_request,
                _blob(fingerprint, "fingerprint", allow_empty=False),
                _blob(response, "response"),
                code,
                created,
                expires,
            ),
        )

    def prune_idempotency(self, now_ns: int) -> int:
        self._ensure_write()
        cursor = self.execute(
            """
            DELETE FROM idempotency
            WHERE tenant_id = ? AND envelope_id = ?
              AND expires_at_ns IS NOT NULL AND expires_at_ns <= ?
            """,
            (*self.scope, _nonnegative_integer(now_ns, "now_ns")),
        )
        return cursor.rowcount

    # -- Receipts and revocations --------------------------------------

    def insert_receipt(self, receipt: Mapping[str, Any]) -> None:
        self._ensure_write()

        def required(name: str) -> Any:
            try:
                return receipt[name]
            except KeyError as exc:
                raise ValidationError(f"missing receipt field: {name}") from exc

        issued = _nonnegative_integer(required("issued_at_ns"), "issued_at_ns")
        expires = _nonnegative_integer(required("expires_at_ns"), "expires_at_ns")
        if expires <= issued:
            raise ValidationError("expires_at_ns must be later than issued_at_ns")
        columns = (
            "receipt_id",
            "request_id",
            "key_id",
            "policy_version",
            "policy_digest",
            "machine_digest",
            "lease_id",
            "lineage_id",
            "subject_id",
            "executor_audience",
            "transition_name",
            "source_state",
            "target_state",
        )
        checked = [_identifier(required(name), name) for name in columns]
        self.execute(
            """
            INSERT INTO receipts(
                tenant_id, envelope_id, receipt_id, request_id, warden_id, key_id,
                config_epoch, policy_version, policy_digest, machine_digest, lease_id,
                lineage_id, subject_id, executor_audience, transition_name, source_state,
                target_state, cost, resulting_sequence, evidence_digest, nonce, issued_at_ns,
                expires_at_ns, signature, payload
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                *self.scope,
                checked[0],
                checked[1],
                _identifier(receipt.get("warden_id", self._metadata.warden_id), "warden_id"),
                checked[2],
                _nonnegative_integer(
                    receipt.get("config_epoch", self._metadata.config_epoch),
                    "config_epoch",
                    positive=True,
                ),
                *checked[3:],
                self.pack_vector(required("cost")),
                _nonnegative_integer(
                    required("resulting_sequence"), "resulting_sequence", positive=True
                ),
                None
                if receipt.get("evidence_digest") is None
                else _identifier(receipt["evidence_digest"], "evidence_digest"),
                _identifier(required("nonce"), "nonce"),
                issued,
                expires,
                _blob(required("signature"), "signature", allow_empty=False),
                _json_blob(receipt.get("payload", receipt)),
            ),
        )

    def get_receipt(self, receipt_id: str) -> Record | None:
        row = self.fetch_one(
            """
            SELECT * FROM receipts
            WHERE tenant_id = ? AND envelope_id = ? AND receipt_id = ?
            """,
            (*self.scope, _identifier(receipt_id, "receipt_id")),
        )
        return None if row is None else self._scoped_record(row, "cost")

    def put_revocation(
        self,
        *,
        lineage_id: str,
        branch_lease_id: str,
        epoch: int,
        reason: str,
        key_id: str,
        issued_at_ns: int,
        observed_at_ns: int,
        source_warden: str,
        signature: bytes,
        payload: bytes | object,
        config_epoch: int | None = None,
    ) -> bool:
        self._ensure_write()
        key = (
            *self.scope,
            _identifier(lineage_id, "lineage_id"),
            _identifier(branch_lease_id, "branch_lease_id"),
        )
        existing = self.fetch_one(
            """
            SELECT epoch, payload FROM revocations
            WHERE tenant_id = ? AND envelope_id = ? AND lineage_id = ? AND branch_lease_id = ?
            """,
            key,
        )
        checked_epoch = _nonnegative_integer(epoch, "epoch", positive=True)
        encoded_payload = _json_blob(payload)
        if existing is not None and checked_epoch <= cast(int, existing["epoch"]):
            if (
                checked_epoch == existing["epoch"]
                and _blob(existing["payload"], "payload") != encoded_payload
            ):
                raise ConflictError("revocation epoch reused with a different payload")
            return False
        issued = _nonnegative_integer(issued_at_ns, "issued_at_ns")
        observed = _nonnegative_integer(observed_at_ns, "observed_at_ns")
        if observed < issued:
            raise ValidationError("observed_at_ns must not precede issued_at_ns")
        if not isinstance(reason, str) or not 1 <= len(reason) <= 1_000:
            raise ValidationError("reason must contain 1..1000 characters")
        values = (
            checked_epoch,
            _nonnegative_integer(
                self._metadata.config_epoch if config_epoch is None else config_epoch,
                "config_epoch",
                positive=True,
            ),
            observed,
            _identifier(source_warden, "source_warden"),
            reason,
            _identifier(key_id, "key_id"),
            issued,
            _blob(signature, "signature", allow_empty=False),
            encoded_payload,
        )
        if existing is None:
            self.execute(
                """
                INSERT INTO revocations(
                    tenant_id, envelope_id, lineage_id, branch_lease_id, epoch,
                    config_epoch, observed_at_ns, source_warden, reason, key_id,
                    issued_at_ns, signature, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (*key, *values),
            )
        else:
            self.execute(
                """
                UPDATE revocations
                SET epoch = ?, config_epoch = ?, observed_at_ns = ?,
                    source_warden = ?, reason = ?, key_id = ?, issued_at_ns = ?,
                    signature = ?, payload = ?
                WHERE tenant_id = ? AND envelope_id = ? AND lineage_id = ? AND branch_lease_id = ?
                """,
                (*values, *key),
            )
        return True

    def get_revocation(self, lineage_id: str, branch_lease_id: str) -> Record | None:
        row = self.fetch_one(
            """
            SELECT * FROM revocations
            WHERE tenant_id = ? AND envelope_id = ? AND lineage_id = ? AND branch_lease_id = ?
            """,
            (
                *self.scope,
                _identifier(lineage_id, "lineage_id"),
                _identifier(branch_lease_id, "branch_lease_id"),
            ),
        )
        return None if row is None else dict(row)

    # -- Transfer streams ----------------------------------------------

    def allocate_outgoing_sequence(
        self, target_warden: str, *, updated_at_ns: int, config_epoch: int | None = None
    ) -> int:
        self._ensure_write()
        target = _identifier(target_warden, "target_warden")
        now = _nonnegative_integer(updated_at_ns, "updated_at_ns")
        epoch = _nonnegative_integer(
            self._metadata.config_epoch if config_epoch is None else config_epoch,
            "config_epoch",
            positive=True,
        )
        row = self.fetch_one(
            """
            SELECT next_sequence, config_epoch FROM outgoing_transfer_streams
            WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
            """,
            (*self.scope, target),
        )
        if row is None:
            sequence = 1
            self.execute(
                """
                INSERT INTO outgoing_transfer_streams(
                    tenant_id, envelope_id, target_warden, config_epoch,
                    next_sequence, acked_through, updated_at_ns
                ) VALUES (?, ?, ?, ?, 2, 0, ?)
                """,
                (*self.scope, target, epoch, now),
            )
        else:
            if row["config_epoch"] != epoch:
                raise ConflictError("outgoing transfer stream config epoch mismatch")
            sequence = cast(int, row["next_sequence"])
            if sequence >= _MAX_SQLITE_INTEGER:
                raise ValidationError("outgoing transfer sequence exhausted")
            self.execute(
                """
                UPDATE outgoing_transfer_streams
                SET next_sequence = next_sequence + 1, updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
                """,
                (now, *self.scope, target),
            )
        return sequence

    def insert_outgoing_transfer(
        self,
        *,
        transfer_id: str,
        target_warden: str,
        sequence: int,
        amount: Sequence[int],
        policy_version: str,
        policy_digest: str,
        digest: str,
        key_id: str,
        signature: bytes,
        voucher_payload: bytes | object,
        prepared_at_ns: int,
        config_epoch: int | None = None,
    ) -> None:
        self._ensure_write()
        checked_amount = vector(amount, dimensions=self._metadata.dimension_count)
        if not any(checked_amount):
            raise ValidationError("outgoing transfer amount must contain a non-zero dimension")
        self.execute(
            """
            INSERT INTO outgoing_transfers(
                tenant_id, envelope_id, transfer_id, source_warden, target_warden,
                sequence, config_epoch, amount, policy_version, policy_digest, digest,
                key_id, signature, voucher_payload, status, prepared_at_ns,
                acknowledged_at_ns, ack_payload
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED', ?, NULL, NULL
            )
            """,
            (
                *self.scope,
                _identifier(transfer_id, "transfer_id"),
                self._metadata.warden_id,
                _identifier(target_warden, "target_warden"),
                _nonnegative_integer(sequence, "sequence", positive=True),
                _nonnegative_integer(
                    self._metadata.config_epoch if config_epoch is None else config_epoch,
                    "config_epoch",
                    positive=True,
                ),
                pack(checked_amount),
                _identifier(policy_version, "policy_version"),
                _identifier(policy_digest, "policy_digest"),
                _identifier(digest, "digest"),
                _identifier(key_id, "key_id"),
                _blob(signature, "signature", allow_empty=False),
                _json_blob(voucher_payload),
                _nonnegative_integer(prepared_at_ns, "prepared_at_ns"),
            ),
        )

    def acknowledge_outgoing_transfer(
        self,
        target_warden: str,
        sequence: int,
        *,
        acknowledged_at_ns: int,
        ack_payload: bytes,
    ) -> bool:
        self._ensure_write()
        target = _identifier(target_warden, "target_warden")
        checked_sequence = _nonnegative_integer(sequence, "sequence", positive=True)
        row = self.fetch_one(
            """
            SELECT status, ack_payload FROM outgoing_transfers
            WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ? AND sequence = ?
            """,
            (*self.scope, target, checked_sequence),
        )
        if row is None:
            stream = self.fetch_one(
                """
                SELECT compacted_through FROM outgoing_transfer_streams
                WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
                """,
                (*self.scope, target),
            )
            if stream is not None and checked_sequence <= stream["compacted_through"]:
                return False
            raise NotFoundError(f"outgoing transfer not found: {target}/{checked_sequence}")
        if row["status"] == "ACKNOWLEDGED":
            if _blob(row["ack_payload"], "ack_payload") != _blob(ack_payload, "ack_payload"):
                raise ConflictError("outgoing transfer acknowledgement payload changed")
            return False
        self.execute(
            """
            UPDATE outgoing_transfers
            SET status = 'ACKNOWLEDGED', acknowledged_at_ns = ?, ack_payload = ?
            WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ? AND sequence = ?
            """,
            (
                _nonnegative_integer(acknowledged_at_ns, "acknowledged_at_ns"),
                _blob(ack_payload, "ack_payload"),
                *self.scope,
                target,
                checked_sequence,
            ),
        )
        stream = self.fetch_one(
            """
            SELECT acked_through FROM outgoing_transfer_streams
            WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
            """,
            (*self.scope, target),
        )
        if stream is None:
            raise InvariantError("outgoing transfer stream disappeared during acknowledgement")
        watermark = cast(int, stream["acked_through"])
        rows = self.fetch_all(
            """
            SELECT sequence, status FROM outgoing_transfers
            WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
              AND sequence > ? ORDER BY sequence
            """,
            (*self.scope, target, watermark),
        )
        for next_row in rows:
            if next_row["sequence"] != watermark + 1 or next_row["status"] != "ACKNOWLEDGED":
                break
            watermark += 1
        self.execute(
            """
            UPDATE outgoing_transfer_streams SET acked_through = ?, updated_at_ns = ?
            WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
            """,
            (
                watermark,
                _nonnegative_integer(acknowledged_at_ns, "acknowledged_at_ns"),
                *self.scope,
                target,
            ),
        )
        return True

    def compact_outgoing_stream(
        self,
        target_warden: str,
        *,
        through: int,
        checkpoint_payload: bytes,
        updated_at_ns: int,
    ) -> int:
        """Persist a signed checkpoint before removing finalized voucher rows."""

        self._ensure_write()
        target = _identifier(target_warden, "target_warden")
        checked_through = _nonnegative_integer(through, "through", positive=True)
        checkpoint = _blob(checkpoint_payload, "checkpoint_payload", allow_empty=False)
        stream = self.fetch_one(
            """
            SELECT acked_through, compacted_through, checkpoint_payload
            FROM outgoing_transfer_streams
            WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
            """,
            (*self.scope, target),
        )
        if stream is None:
            raise NotFoundError(f"outgoing transfer stream not found: {target}")
        if checked_through < stream["compacted_through"]:
            raise ConflictError("outgoing checkpoint would move backward")
        if checked_through == stream["compacted_through"]:
            if _blob(stream["checkpoint_payload"], "checkpoint_payload") != checkpoint:
                raise ConflictError("outgoing checkpoint payload changed at the same watermark")
            return 0
        if checked_through > stream["acked_through"]:
            raise ConflictError("outgoing checkpoint exceeds acknowledged watermark")
        unfinalized = self.scalar(
            """
            SELECT COUNT(*) FROM outgoing_transfers
            WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
              AND sequence <= ? AND status NOT IN ('ACKNOWLEDGED', 'FINALIZED')
            """,
            (*self.scope, target, checked_through),
        )
        if cast(int, unfinalized) != 0:
            raise ConflictError("outgoing checkpoint covers an unfinalized transfer")
        self.execute(
            """
            UPDATE outgoing_transfer_streams
            SET compacted_through = ?, checkpoint_payload = ?, updated_at_ns = ?
            WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
            """,
            (
                checked_through,
                checkpoint,
                _nonnegative_integer(updated_at_ns, "updated_at_ns"),
                *self.scope,
                target,
            ),
        )
        cursor = self.execute(
            """
            DELETE FROM outgoing_transfers
            WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ? AND sequence <= ?
            """,
            (*self.scope, target, checked_through),
        )
        return cursor.rowcount

    def record_inbound_ack(
        self,
        *,
        transfer_id: str,
        source_warden: str,
        sequence: int,
        transfer_digest: str,
        contiguous_watermark: int | None,
        key_id: str,
        ack_payload: bytes,
        signature: bytes,
        accepted_at_ns: int,
        expires_at_ns: int | None = None,
        config_epoch: int | None = None,
    ) -> bool:
        """Record an accepted inbound sequence and maintain a bounded sparse set.

        Returns ``False`` for an already accepted sequence.  A duplicate whose
        acknowledgement is still retained must match the original digest.
        ``inbound_transfer_gaps`` stores accepted out-of-order sequences above
        the contiguous watermark, matching :class:`~lets.service.WardenService`.
        """

        self._ensure_write()
        source = _identifier(source_warden, "source_warden")
        checked_sequence = _nonnegative_integer(sequence, "sequence", positive=True)
        digest = _identifier(transfer_digest, "transfer_digest")
        accepted = _nonnegative_integer(accepted_at_ns, "accepted_at_ns")
        expires = (
            None if expires_at_ns is None else _nonnegative_integer(expires_at_ns, "expires_at_ns")
        )
        if expires is not None and expires < accepted:
            raise ValidationError("expires_at_ns must not precede accepted_at_ns")
        epoch = _nonnegative_integer(
            self._metadata.config_epoch if config_epoch is None else config_epoch,
            "config_epoch",
            positive=True,
        )
        stream = self.fetch_one(
            """
            SELECT * FROM inbound_transfer_streams
            WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
            """,
            (*self.scope, source),
        )
        if stream is None:
            new_stream = True
            contiguous = highest = 0
        else:
            new_stream = False
            if stream["config_epoch"] != epoch:
                raise ConflictError("inbound transfer stream config epoch mismatch")
            contiguous = cast(int, stream["contiguous_through"])
            highest = cast(int, stream["highest_seen"])

        previous = self.fetch_one(
            """
            SELECT transfer_digest FROM inbound_transfer_acks
            WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ? AND sequence = ?
            """,
            (*self.scope, source, checked_sequence),
        )
        if previous is not None:
            if previous["transfer_digest"] != digest:
                raise ConflictError("conflicting transfer digest for an accepted sequence")
            return False
        if checked_sequence <= contiguous:
            return False
        if checked_sequence - contiguous > self._metadata.transfer_gap_window:
            raise ValidationError("inbound transfer sequence exceeds the configured gap window")

        if new_stream:
            self.execute(
                """
                INSERT INTO inbound_transfer_streams(
                    tenant_id, envelope_id, source_warden, config_epoch,
                    contiguous_through, highest_seen, updated_at_ns
                ) VALUES (?, ?, ?, ?, 0, 0, ?)
                """,
                (*self.scope, source, epoch, accepted),
            )
        if checked_sequence > contiguous + 1:
            self.execute(
                """
                INSERT OR IGNORE INTO inbound_transfer_gaps(
                    tenant_id, envelope_id, source_warden, sequence, observed_at_ns
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (*self.scope, source, checked_sequence, accepted),
            )
            new_contiguous = contiguous
        else:
            new_contiguous = checked_sequence
            while True:
                accepted_next = self.scalar(
                    """
                    SELECT 1 FROM inbound_transfer_gaps
                    WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
                      AND sequence = ?
                    """,
                    (*self.scope, source, new_contiguous + 1),
                )
                if accepted_next is None:
                    break
                new_contiguous += 1
                self.execute(
                    """
                    DELETE FROM inbound_transfer_gaps
                    WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
                      AND sequence = ?
                    """,
                    (*self.scope, source, new_contiguous),
                )
        highest = max(highest, checked_sequence)
        if contiguous_watermark is not None:
            claimed_watermark = _nonnegative_integer(contiguous_watermark, "contiguous_watermark")
            if claimed_watermark != new_contiguous:
                raise ConflictError(
                    "signed acknowledgement watermark does not match inbound stream state"
                )
        self.execute(
            """
            INSERT INTO inbound_transfer_acks(
                tenant_id, envelope_id, transfer_id, source_warden, target_warden,
                sequence, config_epoch, transfer_digest, contiguous_watermark,
                key_id, ack_payload, signature, accepted_at_ns, expires_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                *self.scope,
                _identifier(transfer_id, "transfer_id"),
                source,
                self._metadata.warden_id,
                checked_sequence,
                epoch,
                digest,
                new_contiguous,
                _identifier(key_id, "key_id"),
                _blob(ack_payload, "ack_payload"),
                _blob(signature, "signature", allow_empty=False),
                accepted,
                expires,
            ),
        )
        self.execute(
            """
            UPDATE inbound_transfer_streams
            SET contiguous_through = ?, highest_seen = ?, updated_at_ns = ?
            WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
            """,
            (new_contiguous, highest, accepted, *self.scope, source),
        )
        return True

    def compact_inbound_stream(
        self,
        source_warden: str,
        *,
        through: int,
        checkpoint_payload: bytes,
        updated_at_ns: int,
    ) -> int:
        """Persist a verified source checkpoint before pruning acknowledgement rows."""

        self._ensure_write()
        source = _identifier(source_warden, "source_warden")
        checked_through = _nonnegative_integer(through, "through", positive=True)
        checkpoint = _blob(checkpoint_payload, "checkpoint_payload", allow_empty=False)
        stream = self.fetch_one(
            """
            SELECT contiguous_through, compacted_through, checkpoint_payload
            FROM inbound_transfer_streams
            WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
            """,
            (*self.scope, source),
        )
        if stream is None:
            raise NotFoundError(f"inbound transfer stream not found: {source}")
        if checked_through < stream["compacted_through"]:
            raise ConflictError("inbound checkpoint would move backward")
        if checked_through == stream["compacted_through"]:
            if _blob(stream["checkpoint_payload"], "checkpoint_payload") != checkpoint:
                raise ConflictError("inbound checkpoint payload changed at the same watermark")
            return 0
        if checked_through > stream["contiguous_through"]:
            raise ConflictError("inbound checkpoint exceeds contiguous watermark")
        self.execute(
            """
            UPDATE inbound_transfer_streams
            SET compacted_through = ?, checkpoint_payload = ?, updated_at_ns = ?
            WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
            """,
            (
                checked_through,
                checkpoint,
                _nonnegative_integer(updated_at_ns, "updated_at_ns"),
                *self.scope,
                source,
            ),
        )
        cursor = self.execute(
            """
            DELETE FROM inbound_transfer_acks
            WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ? AND sequence <= ?
            """,
            (*self.scope, source, checked_through),
        )
        return cursor.rowcount

    # -- Audit and outbox ----------------------------------------------

    def audit_sequence(self) -> int:
        value = self.scalar(
            """
            SELECT MAX(sequence) FROM audit_log
            WHERE tenant_id = ? AND envelope_id = ?
            """,
            self.scope,
        )
        return -1 if value is None else cast(int, value)

    def append_audit(
        self,
        event_type: str,
        payload: bytes | object,
        *,
        created_at_ns: int,
        entity_type: str | None = None,
        entity_id: str | None = None,
        publish: bool = True,
    ) -> AuditRecord:
        self._ensure_write()
        event = _identifier(event_type, "event_type")
        entity_kind = None if entity_type is None else _identifier(entity_type, "entity_type")
        entity = None if entity_id is None else _identifier(entity_id, "entity_id")
        body = payload if isinstance(payload, bytes) else canonical_json(payload)
        body = _blob(body, "payload")
        created = _nonnegative_integer(created_at_ns, "created_at_ns")
        last = self.fetch_one(
            """
            SELECT sequence, event_hash FROM audit_log
            WHERE tenant_id = ? AND envelope_id = ? ORDER BY sequence DESC LIMIT 1
            """,
            self.scope,
        )
        if last is None:
            sequence, previous = 0, _ZERO_AUDIT_HASH
        else:
            sequence = cast(int, last["sequence"]) + 1
            previous = _blob(last["event_hash"], "event_hash")
        event_hash = audit_event_hash(previous, sequence, event, entity_kind, entity, body, created)
        self.execute(
            """
            INSERT INTO audit_log(
                tenant_id, envelope_id, sequence, event_type, entity_type, entity_id,
                payload, previous_hash, event_hash, created_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                *self.scope,
                sequence,
                event,
                entity_kind,
                entity,
                body,
                previous,
                event_hash,
                created,
            ),
        )
        if publish:
            self.execute(
                """
                INSERT INTO audit_outbox(
                    tenant_id, envelope_id, sequence, event_hash, payload,
                    created_at_ns, published_at_ns, attempts, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, 0, NULL)
                """,
                (*self.scope, sequence, event_hash, body, created),
            )
        return AuditRecord(
            sequence, event, entity_kind, entity, body, previous, event_hash, created
        )

    def pending_outbox(self, *, limit: int = 100) -> list[Record]:
        checked_limit = _nonnegative_integer(limit, "limit", positive=True)
        return [
            dict(row)
            for row in self.fetch_all(
                """
                SELECT * FROM audit_outbox
                WHERE tenant_id = ? AND envelope_id = ? AND published_at_ns IS NULL
                ORDER BY sequence LIMIT ?
                """,
                (*self.scope, checked_limit),
            )
        ]

    def mark_outbox_published(self, sequence: int, *, published_at_ns: int) -> None:
        self._ensure_write()
        cursor = self.execute(
            """
            UPDATE audit_outbox SET published_at_ns = ?, attempts = attempts + 1, last_error = NULL
            WHERE tenant_id = ? AND envelope_id = ? AND sequence = ?
            """,
            (
                _nonnegative_integer(published_at_ns, "published_at_ns"),
                *self.scope,
                _nonnegative_integer(sequence, "sequence"),
            ),
        )
        if cursor.rowcount != 1:
            raise NotFoundError(f"audit outbox sequence not found: {sequence}")

    # -- Executor replay ------------------------------------------------

    def claim_executor_receipt(
        self,
        *,
        executor_audience: str,
        receipt_id: str,
        receipt_digest: str,
        consumed_at_ns: int,
        expires_at_ns: int,
        nonce: str | None = None,
    ) -> bool:
        self._ensure_write()
        executor = _identifier(executor_audience, "executor_audience")
        identifier = _identifier(receipt_id, "receipt_id")
        digest = _identifier(receipt_digest, "receipt_digest")
        consumed = _nonnegative_integer(consumed_at_ns, "consumed_at_ns")
        expires = _nonnegative_integer(expires_at_ns, "expires_at_ns")
        if expires < consumed:
            raise ValidationError("expires_at_ns must not precede consumed_at_ns")
        existing = self.fetch_one(
            """
            SELECT receipt_digest FROM executor_replay
            WHERE tenant_id = ? AND envelope_id = ?
              AND executor_audience = ? AND receipt_id = ?
            """,
            (*self.scope, executor, identifier),
        )
        if existing is not None:
            if existing["receipt_digest"] != digest:
                raise ConflictError("receipt identifier reused with a different digest")
            return False
        try:
            self.execute(
                """
                INSERT INTO executor_replay(
                    tenant_id, envelope_id, executor_audience, receipt_id, receipt_digest,
                    nonce, consumed_at_ns, expires_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *self.scope,
                    executor,
                    identifier,
                    digest,
                    None if nonce is None else _identifier(nonce, "nonce"),
                    consumed,
                    expires,
                ),
            )
        except sqlite3.IntegrityError as exc:
            if nonce is not None:
                raise ConflictError("executor nonce has already been consumed") from exc
            raise
        return True

    def prune_executor_replay(self, now_ns: int) -> int:
        self._ensure_write()
        cursor = self.execute(
            """
            DELETE FROM executor_replay
            WHERE tenant_id = ? AND envelope_id = ? AND expires_at_ns <= ?
            """,
            (*self.scope, _nonnegative_integer(now_ns, "now_ns")),
        )
        return cursor.rowcount

    def _mark_closed(self) -> None:
        self._closed = True


class SQLiteStorage:
    """One-envelope SQLite store with crash-safe write transactions."""

    def __init__(
        self,
        path: PathLike,
        warden_id: str,
        budget: Sequence[int],
        *,
        signing_key_id: str,
        signing_public_key: bytes,
        tenant_id: str = "default",
        envelope_id: str = "default",
        config_epoch: int = 1,
        dimension_metadata: object | None = None,
        initial_local_share: Sequence[int] | None = None,
        receipt_ttl_ns: int | None = None,
        max_clock_uncertainty_ns: int | None = None,
        transfer_gap_window: int | None = None,
        config: object | None = None,
        busy_timeout_ms: int = 5_000,
        authority_anchor: AuthorityAnchor | None = None,
        min_free_disk_bytes: int = 0,
        max_database_bytes: int | None = None,
        reserve_pages: int = 64,
        _create: bool = False,
        _migrate: bool = False,
    ) -> None:
        self._path = os.fspath(path)
        if not self._path:
            raise ValidationError("database path must not be empty")
        if self._path == ":memory:":
            raise ValidationError("durable storage requires a filesystem-backed SQLite database")
        self._uri = self._path.startswith("file:")
        if self._uri:
            parsed = urlsplit(self._path)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if _create:
                self._connect_path = self._path
            else:
                configured_mode = query.get("mode")
                if configured_mode not in (None, "rw"):
                    raise ValidationError("opening an existing LETS store requires SQLite mode=rw")
                query["mode"] = "rw"
                self._connect_path = urlunsplit(
                    (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
                )
            self._connect_uri = True
        elif _create:
            self._connect_path = self._path
            self._connect_uri = False
        else:
            self._connect_path = f"{Path(self._path).resolve().as_uri()}?mode=rw"
            self._connect_uri = True
        self._busy_timeout_ms = _nonnegative_integer(
            busy_timeout_ms, "busy_timeout_ms", positive=True
        )
        self._authority_anchor = authority_anchor
        self._authority_anchor_faulted = False
        self._authority_transaction_lock = threading.RLock()
        self._min_free_disk_bytes = _nonnegative_integer(min_free_disk_bytes, "min_free_disk_bytes")
        self._max_database_bytes = (
            None
            if max_database_bytes is None
            else _nonnegative_integer(max_database_bytes, "max_database_bytes", positive=True)
        )
        self._reserve_pages = _nonnegative_integer(reserve_pages, "reserve_pages", positive=True)
        self._capacity_faulted = False
        self._closed = False
        self._active: ContextVar[bool] = ContextVar(
            f"lets_sqlite_transaction_{id(self)}", default=False
        )

        checked_warden = require_warden_id(warden_id)
        checked_signing_key = require_key_id(signing_key_id, field="signing_key_id")
        checked_public_key = _blob(signing_public_key, "signing_public_key", allow_empty=False)
        if len(checked_public_key) != 32:
            raise ValidationError("signing_public_key must contain exactly 32 bytes")
        checked_tenant = _identifier(tenant_id, "tenant_id")
        checked_envelope = _identifier(envelope_id, "envelope_id")
        checked_budget = vector(budget)
        if len(checked_budget) > 256:
            raise ValidationError("LETS v1 envelopes support at most 256 resource dimensions")
        checked_share = vector(
            checked_budget if initial_local_share is None else initial_local_share,
            dimensions=len(checked_budget),
        )
        if not less_than_or_equal(checked_share, checked_budget):
            raise ValidationError("initial_local_share cannot exceed the configured budget")
        checked_dimensions = (
            None
            if dimension_metadata is None
            else _normalize_dimensions(dimension_metadata, len(checked_budget))
        )
        candidate = {
            "warden_id": checked_warden,
            "signing_key_id": checked_signing_key,
            "signing_public_key_sha256": sha256(checked_public_key).digest(),
            "tenant_id": checked_tenant,
            "envelope_id": checked_envelope,
            "config_epoch": _nonnegative_integer(config_epoch, "config_epoch", positive=True),
            "budget": checked_budget,
            "initial_local_share": checked_share,
            "dimension_metadata": checked_dimensions,
            "receipt_ttl_ns": (
                None
                if receipt_ttl_ns is None
                else _nonnegative_integer(receipt_ttl_ns, "receipt_ttl_ns", positive=True)
            ),
            "max_clock_uncertainty_ns": (
                None
                if max_clock_uncertainty_ns is None
                else _nonnegative_integer(max_clock_uncertainty_ns, "max_clock_uncertainty_ns")
            ),
            "transfer_gap_window": (
                None
                if transfer_gap_window is None
                else _nonnegative_integer(
                    transfer_gap_window,
                    "transfer_gap_window",
                    positive=True,
                    maximum=MAX_TRANSFER_GAP_WINDOW,
                )
            ),
            "config": config,
        }
        self._metadata = self._initialize(candidate, create=_create, migrate=_migrate)

    @classmethod
    def initialize(
        cls,
        path: PathLike,
        warden_id: str,
        budget: Sequence[int],
        **options: Any,
    ) -> Self:
        return cls(path, warden_id, budget, _create=True, **options)

    @classmethod
    def migrate(
        cls,
        path: PathLike,
        warden_id: str,
        budget: Sequence[int],
        **options: Any,
    ) -> Self:
        """Explicitly migrate an existing store after operator approval."""

        return cls(path, warden_id, budget, _migrate=True, **options)

    @property
    def path(self) -> str:
        return self._path

    @property
    def metadata(self) -> StorageMetadata:
        return self._metadata

    @property
    def schema_version(self) -> int:
        return self._metadata.schema_version

    @property
    def busy_timeout_s(self) -> float:
        """Maximum time a single SQLite operation waits for a conflicting writer."""

        return self._busy_timeout_ms / 1_000

    def _connect(self, *, set_wal: bool = False) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self._connect_path,
                timeout=self._busy_timeout_ms / 1_000,
                isolation_level=None,
                uri=self._connect_uri,
                cached_statements=256,
            )
            connection.row_factory = sqlite3.Row
            _register_functions(connection)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA wal_autocheckpoint = 1000")
            if set_wal:
                mode = cast(str, connection.execute("PRAGMA journal_mode = WAL").fetchone()[0])
                if mode.lower() != "wal":
                    raise StorageError(f"SQLite refused WAL mode (selected {mode!r})")
            self._restrict_file_permissions()
            return connection
        except sqlite3.Error as exc:
            raise StorageError(f"could not open SQLite database {self._path!r}") from exc

    def _restrict_file_permissions(self) -> None:
        """Best-effort POSIX protection for the DB and SQLite sidecars.

        Windows and container operators must provision equivalent directory/file ACLs.
        SQLite is durable storage, not encryption at rest.
        """

        if os.name == "nt" or self._uri:
            return
        for candidate in (self._path, f"{self._path}-wal", f"{self._path}-shm"):
            if os.path.isfile(candidate):
                with suppress(OSError):
                    os.chmod(candidate, 0o600)

    def _initialize(
        self,
        candidate: Mapping[str, Any],
        *,
        create: bool,
        migrate: bool,
    ) -> StorageMetadata:
        connection = self._connect(set_wal=create)
        try:
            connection.execute("BEGIN IMMEDIATE")
            version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
            application_id = cast(int, connection.execute("PRAGMA application_id").fetchone()[0])
            if version > SCHEMA_VERSION:
                message = (
                    f"database schema version {version} is newer than supported "
                    f"version {SCHEMA_VERSION}"
                )
                raise StorageError(message)
            if version == 0:
                if not create:
                    raise StorageError(
                        "database is empty or uninitialized; authority state must be created "
                        "only by explicit initialization"
                    )
                existing = connection.execute(
                    "SELECT name FROM sqlite_schema "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
                if existing:
                    raise StorageError(
                        "unversioned non-empty database; refusing destructive initialization"
                    )
                for target_version in range(1, SCHEMA_VERSION + 1):
                    for statement in MIGRATIONS[target_version]:
                        connection.execute(statement)
                self._insert_genesis(connection, candidate)
                connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif create:
                raise StorageError("database is already initialized; refusing to reinitialize it")
            elif version < SCHEMA_VERSION:
                if application_id != APPLICATION_ID:
                    raise StorageError("database application_id does not identify a LETS store")
                if not migrate:
                    raise StorageError(
                        f"database schema version {version} requires explicit migration to "
                        f"version {SCHEMA_VERSION}"
                    )
                for target_version in range(version + 1, SCHEMA_VERSION + 1):
                    for statement in MIGRATIONS[target_version]:
                        connection.execute(statement)
                    connection.execute(
                        "UPDATE database_metadata SET schema_version = ? WHERE singleton = 1",
                        (target_version,),
                    )
                    connection.execute(f"PRAGMA user_version = {target_version}")

            if version > 0 and application_id != APPLICATION_ID:
                raise StorageError("database application_id does not identify a LETS store")
            if not create:
                journal_mode = cast(str, connection.execute("PRAGMA journal_mode").fetchone()[0])
                if journal_mode.casefold() != "wal":
                    raise StorageError("existing LETS stores must already use WAL journal mode")

            self._verify_schema(connection)
            metadata = self._load_metadata(connection)
            self._verify_candidate(metadata, candidate)
            self._assert_local_conservation(connection, metadata, reconcile=True)
            connection.commit()
            self._reconcile_authority_anchor(
                connection,
                initialize=create,
                allow_schema_upgrade=migrate,
                metadata=metadata,
            )
            return metadata
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _insert_genesis(self, connection: sqlite3.Connection, candidate: Mapping[str, Any]) -> None:
        created_at_ns = time.time_ns()
        dimensions = candidate["dimension_metadata"]
        if dimensions is None:
            dimensions = _normalize_dimensions(None, len(candidate["budget"]))
        receipt_ttl = candidate["receipt_ttl_ns"] or _DEFAULT_RECEIPT_TTL_NS
        uncertainty = (
            0
            if candidate["max_clock_uncertainty_ns"] is None
            else candidate["max_clock_uncertainty_ns"]
        )
        gap_window = candidate["transfer_gap_window"] or _DEFAULT_TRANSFER_GAP_WINDOW
        extensions = {} if candidate["config"] is None else candidate["config"]
        configuration = {
            "tenant_id": candidate["tenant_id"],
            "envelope_id": candidate["envelope_id"],
            "config_epoch": candidate["config_epoch"],
            "budget": list(candidate["budget"]),
            "local_share": list(candidate["initial_local_share"]),
            "receipt_ttl_ns": receipt_ttl,
            "max_clock_uncertainty_ns": uncertainty,
            "transfer_gap_window": gap_window,
            "dimension_metadata": list(dimensions),
            "extensions": extensions,
        }
        connection.execute(
            """
            INSERT INTO database_metadata(
                singleton, schema_version, warden_id, signing_key_id,
                signing_public_key_sha256, created_at_ns
            ) VALUES (1, ?, ?, ?, ?, ?)
            """,
            (
                SCHEMA_VERSION,
                candidate["warden_id"],
                candidate["signing_key_id"],
                candidate["signing_public_key_sha256"],
                created_at_ns,
            ),
        )
        connection.execute(
            """
            INSERT INTO envelopes(
                tenant_id, envelope_id, singleton, config_epoch, dimension_count,
                dimension_metadata_json, budget, initial_local_share, receipt_ttl_ns,
                max_clock_uncertainty_ns, transfer_gap_window, config_json, created_at_ns
            ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                candidate["tenant_id"],
                candidate["envelope_id"],
                candidate["config_epoch"],
                len(candidate["budget"]),
                canonical_json(dimensions),
                pack(candidate["budget"]),
                pack(candidate["initial_local_share"]),
                receipt_ttl,
                uncertainty,
                gap_window,
                canonical_json(configuration),
                created_at_ns,
            ),
        )
        empty = pack(zero(len(candidate["budget"])))
        connection.execute(
            """
            INSERT INTO warden_state(
                tenant_id, envelope_id, free_pool, lease_residual, consumed,
                transferred_in, transferred_out, revision, updated_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (
                candidate["tenant_id"],
                candidate["envelope_id"],
                pack(candidate["initial_local_share"]),
                empty,
                empty,
                empty,
                empty,
                created_at_ns,
            ),
        )

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection) -> None:
        objects = connection.execute(
            "SELECT type, name FROM sqlite_schema WHERE type IN ('table', 'index', 'trigger')"
        ).fetchall()
        tables = {row["name"] for row in objects if row["type"] == "table"}
        indexes = {row["name"] for row in objects if row["type"] == "index"}
        triggers = {row["name"] for row in objects if row["type"] == "trigger"}
        missing_tables = REQUIRED_TABLES - tables
        missing_indexes = REQUIRED_INDEXES - indexes
        missing_triggers = REQUIRED_TRIGGERS - triggers
        if missing_tables or missing_indexes or missing_triggers:
            details = []
            if missing_tables:
                details.append(f"tables={sorted(missing_tables)}")
            if missing_indexes:
                details.append(f"indexes={sorted(missing_indexes)}")
            if missing_triggers:
                details.append(f"triggers={sorted(missing_triggers)}")
            raise StorageError("incomplete SQLite schema: " + ", ".join(details))
        metadata_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(database_metadata)")
        }
        if "key_seed" in metadata_columns:
            raise StorageError(
                "legacy database embeds a signing seed; export it securely and migrate to "
                "external signer storage before opening it with this runtime"
            )
        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_errors:
            raise StorageError("SQLite foreign-key integrity check failed")

    @staticmethod
    def _load_metadata(connection: sqlite3.Connection) -> StorageMetadata:
        database = connection.execute(
            "SELECT * FROM database_metadata WHERE singleton = 1"
        ).fetchone()
        envelope = connection.execute("SELECT * FROM envelopes WHERE singleton = 1").fetchone()
        if database is None or envelope is None:
            raise StorageError("database metadata is missing")
        version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
        if database["schema_version"] != version:
            raise StorageError("schema version metadata disagrees with PRAGMA user_version")
        dimension_count = cast(int, envelope["dimension_count"])
        budget = unpack(_blob(envelope["budget"], "budget"), dimensions=dimension_count)
        share = unpack(
            _blob(envelope["initial_local_share"], "initial_local_share"),
            dimensions=dimension_count,
        )
        raw_dimensions = _decode_json(
            envelope["dimension_metadata_json"], "dimension_metadata_json"
        )
        dimensions = _normalize_dimensions(raw_dimensions, dimension_count)
        return StorageMetadata(
            schema_version=version,
            warden_id=cast(str, database["warden_id"]),
            signing_key_id=cast(str, database["signing_key_id"]),
            signing_public_key_sha256=_blob(
                database["signing_public_key_sha256"],
                "signing_public_key_sha256",
                allow_empty=False,
            ),
            tenant_id=cast(str, envelope["tenant_id"]),
            envelope_id=cast(str, envelope["envelope_id"]),
            config_epoch=cast(int, envelope["config_epoch"]),
            dimension_metadata=dimensions,
            budget=budget,
            initial_local_share=share,
            receipt_ttl_ns=cast(int, envelope["receipt_ttl_ns"]),
            max_clock_uncertainty_ns=cast(int, envelope["max_clock_uncertainty_ns"]),
            transfer_gap_window=cast(int, envelope["transfer_gap_window"]),
            config=_decode_json(envelope["config_json"], "config_json"),
            created_at_ns=cast(int, database["created_at_ns"]),
        )

    @staticmethod
    def _verify_candidate(metadata: StorageMetadata, candidate: Mapping[str, Any]) -> None:
        comparisons = {
            "warden_id": (metadata.warden_id, candidate["warden_id"]),
            "signing_key_id": (
                metadata.signing_key_id,
                candidate["signing_key_id"],
            ),
            "signing_public_key_sha256": (
                metadata.signing_public_key_sha256,
                candidate["signing_public_key_sha256"],
            ),
            "tenant_id": (metadata.tenant_id, candidate["tenant_id"]),
            "envelope_id": (metadata.envelope_id, candidate["envelope_id"]),
            "config_epoch": (metadata.config_epoch, candidate["config_epoch"]),
            "budget": (metadata.budget, candidate["budget"]),
            "initial_local_share": (
                metadata.initial_local_share,
                candidate["initial_local_share"],
            ),
        }
        optional = {
            "dimension_metadata": (
                metadata.dimension_metadata,
                candidate["dimension_metadata"],
            ),
            "receipt_ttl_ns": (metadata.receipt_ttl_ns, candidate["receipt_ttl_ns"]),
            "max_clock_uncertainty_ns": (
                metadata.max_clock_uncertainty_ns,
                candidate["max_clock_uncertainty_ns"],
            ),
            "transfer_gap_window": (
                metadata.transfer_gap_window,
                candidate["transfer_gap_window"],
            ),
        }
        for field, (stored, requested) in comparisons.items():
            if stored != requested:
                raise StorageError(f"database metadata mismatch for {field}")
        for field, (stored, requested) in optional.items():
            if requested is not None and stored != requested:
                raise StorageError(f"database metadata mismatch for {field}")
        requested_extensions = {} if candidate["config"] is None else candidate["config"]
        requested_config = json.loads(canonical_json(requested_extensions).decode("utf-8"))
        stored_extensions = (
            metadata.config.get("extensions") if isinstance(metadata.config, dict) else None
        )
        if stored_extensions != requested_config:
            raise StorageError("database metadata mismatch for config")

    @staticmethod
    def _assert_local_conservation(
        connection: sqlite3.Connection,
        metadata: StorageMetadata,
        *,
        reconcile: bool,
    ) -> None:
        """Check the O(dimensions) ledger equation, optionally rebuilding the lease term.

        Lease triggers maintain ``warden_state.lease_residual``. Normal commits therefore
        avoid scanning a potentially large lease table. Startup reconciliation performs the
        full scan once so external/offline corruption of the aggregate cannot hide drift.
        """

        row = connection.execute(
            """
            SELECT free_pool, lease_residual, consumed, transferred_in, transferred_out
            FROM warden_state WHERE tenant_id = ? AND envelope_id = ?
            """,
            (metadata.tenant_id, metadata.envelope_id),
        ).fetchone()
        if row is None:
            raise InvariantError("warden state is missing from the conservation ledger")
        dimensions = metadata.dimension_count
        try:
            free_pool = unpack(_blob(row["free_pool"], "free_pool"), dimensions=dimensions)
            lease_residual = unpack(
                _blob(row["lease_residual"], "lease_residual"), dimensions=dimensions
            )
            consumed = unpack(_blob(row["consumed"], "consumed"), dimensions=dimensions)
            transferred_in = unpack(
                _blob(row["transferred_in"], "transferred_in"), dimensions=dimensions
            )
            transferred_out = unpack(
                _blob(row["transferred_out"], "transferred_out"), dimensions=dimensions
            )
            if reconcile:
                scanned_residual = zero(dimensions)
                for lease in connection.execute(
                    """
                    SELECT residual FROM leases
                    WHERE tenant_id = ? AND envelope_id = ?
                    """,
                    (metadata.tenant_id, metadata.envelope_id),
                ):
                    scanned_residual = add(
                        scanned_residual,
                        unpack(_blob(lease["residual"], "lease residual"), dimensions=dimensions),
                    )
                if scanned_residual != lease_residual:
                    raise InvariantError(
                        "stored lease-residual aggregate does not match durable lease rows"
                    )
            available = add(metadata.initial_local_share, transferred_in)
            accounted = add(
                add(free_pool, lease_residual),
                add(consumed, transferred_out),
            )
        except ValidationError as exc:
            raise InvariantError("conservation ledger contains an invalid vector") from exc
        if available != accounted:
            raise InvariantError(
                f"local conservation violated: available={available}, accounted={accounted}"
            )

    def _authority_checkpoint(
        self,
        connection: sqlite3.Connection,
        metadata: StorageMetadata | None = None,
    ) -> AuthorityCheckpoint:
        current = self._metadata if metadata is None else metadata
        state = connection.execute(
            """
            SELECT free_pool, lease_residual, consumed, transferred_in, transferred_out,
                   revision, clock_floor_ns
            FROM warden_state
            WHERE tenant_id = ? AND envelope_id = ?
            """,
            (current.tenant_id, current.envelope_id),
        ).fetchone()
        if state is None:
            raise StorageError("warden state is missing while computing the authority anchor")
        control = connection.execute(
            """
            SELECT mode, generation, reason, changed_at_ns, changed_by
            FROM runtime_control WHERE singleton = 1
            """
        ).fetchone()
        if control is None:
            raise StorageError("runtime control is missing while computing the authority anchor")
        instance = connection.execute(
            "SELECT instance_id FROM database_instance WHERE singleton = 1"
        ).fetchone()
        if instance is None:
            raise StorageError("database instance identity is missing")
        instance_id = _blob(
            instance["instance_id"], "database instance identity", allow_empty=False
        )
        if len(instance_id) != 32:
            raise StorageError("database instance identity must contain exactly 32 bytes")
        audit = connection.execute(
            """
            SELECT sequence, event_hash FROM audit_log
            WHERE tenant_id = ? AND envelope_id = ?
            ORDER BY sequence DESC LIMIT 1
            """,
            (current.tenant_id, current.envelope_id),
        ).fetchone()
        if audit is None:
            audit_sequence = -1
            audit_hash = _ZERO_AUDIT_HASH
        else:
            audit_sequence = cast(int, audit["sequence"])
            audit_hash = _blob(audit["event_hash"], "authority audit hash", allow_empty=False)
            if len(audit_hash) != 32:
                raise StorageError("authority audit hash must contain exactly 32 bytes")
        vector_fields = (
            "free_pool",
            "lease_residual",
            "consumed",
            "transferred_in",
            "transferred_out",
        )
        state_payload: dict[str, object] = {
            field: list(
                unpack(
                    _blob(state[field], f"authority {field}"),
                    dimensions=current.dimension_count,
                )
            )
            for field in vector_fields
        }
        state_payload["revision"] = cast(int, state["revision"])
        state_payload["clock_floor_ns"] = cast(int | None, state["clock_floor_ns"])
        state_payload["runtime_control"] = {
            "mode": cast(str, control["mode"]),
            "generation": cast(int, control["generation"]),
            "reason": cast(str, control["reason"]),
            "changed_at_ns": cast(int, control["changed_at_ns"]),
            "changed_by": cast(str, control["changed_by"]),
        }
        return AuthorityCheckpoint(
            warden_id=current.warden_id,
            tenant_id=current.tenant_id,
            envelope_id=current.envelope_id,
            config_epoch=current.config_epoch,
            schema_version=current.schema_version,
            signing_key_id=current.signing_key_id,
            signing_public_key_sha256=current.signing_public_key_sha256,
            database_instance_id=instance_id,
            audit_sequence=audit_sequence,
            audit_hash=audit_hash,
            state_revision=cast(int, state["revision"]),
            state_digest=sha256(canonical_json(state_payload)).digest(),
        )

    def _audit_hash_at(
        self,
        connection: sqlite3.Connection,
        sequence: int,
        metadata: StorageMetadata | None = None,
    ) -> bytes | None:
        current = self._metadata if metadata is None else metadata
        row = connection.execute(
            """
            SELECT event_hash FROM audit_log
            WHERE tenant_id = ? AND envelope_id = ? AND sequence = ?
            """,
            (current.tenant_id, current.envelope_id, sequence),
        ).fetchone()
        if row is None:
            return None
        digest = _blob(row["event_hash"], "historical authority audit hash", allow_empty=False)
        if len(digest) != 32:
            raise StorageError("historical authority audit hash must contain exactly 32 bytes")
        return digest

    def _reconcile_authority_anchor(
        self,
        connection: sqlite3.Connection,
        *,
        initialize: bool = False,
        allow_schema_upgrade: bool = False,
        metadata: StorageMetadata | None = None,
    ) -> None:
        anchor = self._authority_anchor
        if anchor is None:
            return
        if self._authority_anchor_faulted:
            raise StorageError("authority anchor previously faulted; restart after operator repair")
        try:
            checkpoint = self._authority_checkpoint(connection, metadata)
            anchor.reconcile(
                checkpoint,
                audit_hash_at=lambda sequence: self._audit_hash_at(connection, sequence, metadata),
                initialize=initialize,
                allow_schema_upgrade=allow_schema_upgrade,
            )
        except StorageError:
            self._authority_anchor_faulted = True
            raise
        except Exception as exc:
            self._authority_anchor_faulted = True
            raise StorageError("authority anchor provider failed") from exc

    def _database_size(self) -> int:
        if self._uri:
            return 0
        total = 0
        for candidate in (self._path, f"{self._path}-wal", f"{self._path}-shm"):
            with suppress(OSError):
                total += os.path.getsize(candidate)
        return total

    def _capacity_snapshot(self, connection: sqlite3.Connection) -> CapacitySnapshot:
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        free_pages = int(connection.execute("PRAGMA freelist_count").fetchone()[0])
        max_page_count = int(connection.execute("PRAGMA max_page_count").fetchone()[0])
        database_bytes = self._database_size()
        filesystem_free: int | None = None
        if not self._uri:
            try:
                filesystem_free = shutil.disk_usage(Path(self._path).resolve().parent).free
            except OSError:
                filesystem_free = None
        page_headroom = max(0, max_page_count - page_count) + free_pages
        healthy = (
            not self._capacity_faulted
            and page_headroom >= self._reserve_pages
            and (
                (filesystem_free is not None and filesystem_free >= self._min_free_disk_bytes)
                or self._min_free_disk_bytes == 0
            )
            and (
                self._max_database_bytes is None
                or database_bytes + self._reserve_pages * page_size <= self._max_database_bytes
            )
        )
        return CapacitySnapshot(
            database_bytes=database_bytes,
            filesystem_free_bytes=filesystem_free,
            page_size=page_size,
            page_count=page_count,
            free_pages=free_pages,
            max_page_count=max_page_count,
            reserve_pages=self._reserve_pages,
            min_free_disk_bytes=self._min_free_disk_bytes,
            max_database_bytes=self._max_database_bytes,
            prior_full_error=self._capacity_faulted,
            healthy=healthy,
        )

    def _require_write_capacity(self, connection: sqlite3.Connection) -> None:
        snapshot = self._capacity_snapshot(connection)
        if not snapshot.healthy:
            raise CapacityError(
                "storage capacity reserve is exhausted; authority writes are disabled"
            )

    @contextmanager
    def transaction(
        self, *, write: bool = True, capacity_recovery: bool = False
    ) -> Iterator[SQLiteTransaction]:
        if self._closed:
            raise StorageError("storage is closed")
        if self._active.get():
            raise StorageError("nested transactions on the same storage are not supported")
        token = self._active.set(True)
        connection: sqlite3.Connection | None = None
        transaction: SQLiteTransaction | None = None
        try:
            # Keep in-process readers, the peer dispatcher, and HTTP handlers behind
            # the post-COMMIT anchor CAS.  Consequently no signed result or outbox row
            # from a losing fork can be observed through this storage instance.
            with self._authority_transaction_lock:
                connection = self._connect()
                self._reconcile_authority_anchor(connection)
                if write and not capacity_recovery:
                    self._require_write_capacity(connection)
                if not write:
                    connection.execute("PRAGMA query_only = ON")
                connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                transaction = SQLiteTransaction(connection, self._metadata, writable=write)
                yield transaction
                if write:
                    # SQLite enforces immediate constraints on each statement and deferred
                    # constraints at COMMIT because every connection enables foreign_keys.
                    # A full foreign_key_check is O(database size), so it remains a startup
                    # and explicit diagnostic instead of running on every write.
                    try:
                        self._assert_local_conservation(connection, self._metadata, reconcile=False)
                    except InvariantError:
                        # If a malformed internal transaction violates both conservation and
                        # a deferred FK, preserve the FK failure that COMMIT would report.
                        # This diagnostic scan is restricted to the already-failing path; it
                        # never adds database-size work to a valid commit.
                        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                            raise sqlite3.IntegrityError("FOREIGN KEY constraint failed") from None
                        raise
                connection.commit()
                if write:
                    self._reconcile_authority_anchor(connection)
        except sqlite3.IntegrityError:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.Error as exc:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            if (
                getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL
                or "full" in str(exc).casefold()
            ):
                self._capacity_faulted = True
            raise StorageError("SQLite transaction failed") from exc
        except BaseException:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise
        finally:
            if transaction is not None:
                transaction._mark_closed()
            if connection is not None:
                connection.close()
            self._active.reset(token)

    def write(self) -> AbstractContextManager[SQLiteTransaction]:
        return self.transaction(write=True)

    def capacity_recovery(self) -> AbstractContextManager[SQLiteTransaction]:
        """A reserved write lane for bounded deletion/export bookkeeping only."""

        return self.transaction(write=True, capacity_recovery=True)

    def read(self) -> AbstractContextManager[SQLiteTransaction]:
        return self.transaction(write=False)

    def audit_sequence(self) -> int:
        with self.read() as transaction:
            return transaction.audit_sequence()

    @property
    def authority_anchor_enabled(self) -> bool:
        return self._authority_anchor is not None

    @property
    def authority_anchor_healthy(self) -> bool:
        return self._authority_anchor is not None and not self._authority_anchor_faulted

    def authority_checkpoint(self) -> AuthorityCheckpoint:
        """Return the current checkpoint for explicit external-anchor bootstrap."""

        with self.read() as transaction:
            return self._authority_checkpoint(transaction.connection)

    def verify_authority_anchor(self) -> bool:
        if self._authority_anchor is None:
            raise StorageError("no authority anchor is configured")
        with self.read():
            pass
        return True

    def capacity_snapshot(self) -> CapacitySnapshot:
        if self._closed:
            raise StorageError("storage is closed")
        connection = self._connect()
        try:
            return self._capacity_snapshot(connection)
        finally:
            connection.close()

    def clear_capacity_fault(self) -> CapacitySnapshot:
        """Clear a sticky SQLITE_FULL fault only after headroom is restored."""

        if self._closed:
            raise StorageError("storage is closed")
        connection = self._connect()
        try:
            self._capacity_faulted = False
            snapshot = self._capacity_snapshot(connection)
            if not snapshot.healthy:
                self._capacity_faulted = True
                raise CapacityError("storage capacity headroom has not been restored")
            return snapshot
        finally:
            connection.close()

    def pragma_integrity_check(self) -> tuple[str, ...]:
        with self.read() as transaction:
            rows = transaction.fetch_all("PRAGMA integrity_check")
            return tuple(cast(str, row[0]) for row in rows)

    def pragma_foreign_key_check(self) -> list[sqlite3.Row]:
        with self.read() as transaction:
            return transaction.fetch_all("PRAGMA foreign_key_check")

    def verify_conservation(self, *, reconcile: bool = True) -> bool:
        """Verify local conservation; full reconciliation is intended for diagnostics."""

        with self.read() as transaction:
            self._assert_local_conservation(
                transaction.connection,
                self._metadata,
                reconcile=reconcile,
            )
        return True

    def checkpoint(self, *, truncate: bool = False) -> tuple[int, int, int]:
        if self._closed:
            raise StorageError("storage is closed")
        if self._active.get():
            raise StorageError("cannot checkpoint during a transaction")
        connection = self._connect()
        try:
            mode = "TRUNCATE" if truncate else "PASSIVE"
            row = connection.execute(f"PRAGMA wal_checkpoint({mode})").fetchone()
            return cast(tuple[int, int, int], tuple(row))
        finally:
            connection.close()

    def close(self) -> None:
        if self._active.get():
            raise StorageError("cannot close storage during a transaction")
        self._closed = True

    def __enter__(self) -> Self:
        if self._closed:
            raise StorageError("storage is closed")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


SQLiteStore = SQLiteStorage

__all__ = [
    "AuditRecord",
    "CapacitySnapshot",
    "Record",
    "SQLiteScalar",
    "SQLiteStorage",
    "SQLiteStore",
    "SQLiteTransaction",
    "Storage",
    "StorageMetadata",
    "Transaction",
    "audit_event_hash",
]
