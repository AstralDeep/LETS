"""Bounded, cache-only production observation for a running warden."""

from __future__ import annotations

import json
import math
import secrets
import sqlite3
import threading
import time
from collections.abc import Mapping, Sequence
from hashlib import sha256
from typing import TYPE_CHECKING, Any, cast

from lets.audit import AuditExporter
from lets.authority import AuthorityCheckpoint
from lets.canonical import canonical_json
from lets.errors import InvariantError, SignatureError, StorageError, ValidationError
from lets.models import IdentityContext, InvariantSnapshot, RuntimeStatus
from lets.service import WardenService
from lets.storage import SQLiteStorage

if TYPE_CHECKING:
    from lets.peer import PeerDispatcher

OBSERVATION_SCHEMA = "lets.observation-snapshot/v1"
OBSERVATION_MAX_AGE_NS = 15_000_000_000
OBSERVATION_CAPTURE_INTERVAL_SECONDS = 2.0
OBSERVATION_ADMISSION_TIMEOUT_SECONDS = 25.0
OBSERVATION_SQL_TIMEOUT_SECONDS = 5.0
OBSERVATION_AUDIT_PAGE_SIZE = 256
OBSERVATION_AUDIT_PAGE_MAX_BYTES = 4 * 1024 * 1024
OBSERVATION_SNAPSHOT_MAX_BYTES = 16 * 1024
OBSERVATION_PROGRESS_CALLBACK_STEPS = 1_000
OBSERVATION_MAX_PROGRESS_CALLBACKS = 2_000
OBSERVATION_TERMINAL_FULL_TIMEOUT_SECONDS = 60.0
OBSERVATION_RECONCILE_ALLOWANCE_SECONDS = 30.0
_ZERO_HASH = bytes(32)


def _observation_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _decode_observation_json(value: bytes) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate observation key: {key}")
            result[key] = item
        return result

    def reject_constant(constant: str) -> object:
        raise ValueError(f"non-finite observation number: {constant}")

    return json.loads(
        value,
        object_pairs_hook=unique,
        parse_constant=reject_constant,
    )


def _hash_text(value: bytes | None) -> str | None:
    return None if value is None else f"sha256:{value.hex()}"


def _audit_row(row: sqlite3.Row) -> dict[str, object]:
    return {
        "sequence": int(row["sequence"]),
        "event_type": str(row["event_type"]),
        "entity_type": None if row["entity_type"] is None else str(row["entity_type"]),
        "entity_id": None if row["entity_id"] is None else str(row["entity_id"]),
        "payload": bytes(row["payload"]),
        "previous_hash": bytes(row["previous_hash"]),
        "event_hash": bytes(row["event_hash"]),
        "created_at_ns": int(row["created_at_ns"]),
    }


def _invariant_document(snapshot: InvariantSnapshot) -> dict[str, object]:
    return {
        "tenant_id": snapshot.tenant_id,
        "envelope_id": snapshot.envelope_id,
        "config_epoch": snapshot.config_epoch,
        "initial_share": list(snapshot.initial_share),
        "transferred_in": list(snapshot.transferred_in),
        "transferred_out": list(snapshot.transferred_out),
        "free_pool": list(snapshot.free_pool),
        "lease_residual": list(snapshot.lease_residual),
        "consumed": list(snapshot.consumed),
        "checked_at_ns": snapshot.checked_at_ns,
        "healthy": snapshot.healthy,
    }


class ObservationPublisher:
    """Publish immutable snapshots and serve them without authority admission."""

    def __init__(
        self,
        service: WardenService,
        store: SQLiteStorage,
        identity: IdentityContext,
        *,
        peer_dispatcher: PeerDispatcher,
        audit_exporter: AuditExporter | None,
        capture_interval_s: float = OBSERVATION_CAPTURE_INTERVAL_SECONDS,
        admission_timeout_s: float = OBSERVATION_ADMISSION_TIMEOUT_SECONDS,
        sql_timeout_s: float = OBSERVATION_SQL_TIMEOUT_SECONDS,
        max_age_ns: int = OBSERVATION_MAX_AGE_NS,
        audit_page_size: int = OBSERVATION_AUDIT_PAGE_SIZE,
    ) -> None:
        timing_bounds = (capture_interval_s, admission_timeout_s, sql_timeout_s)
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or value <= 0
            for value in timing_bounds
        ):
            raise ValueError("observation timing bounds must be positive")
        if (
            type(max_age_ns) is not int
            or max_age_ns <= 0
            or type(audit_page_size) is not int
            or not 1 <= audit_page_size <= 1_000
        ):
            raise ValueError("observation age and audit page bounds are invalid")
        self._service = service
        self._store = store
        self._identity = identity
        self._peer_dispatcher = peer_dispatcher
        self._audit_exporter = audit_exporter
        self._capture_interval_s = float(capture_interval_s)
        self._admission_timeout_s = float(admission_timeout_s)
        self._sql_timeout_s = float(sql_timeout_s)
        self._max_age_ns = max_age_ns
        self._audit_page_size = audit_page_size
        self._instance_id = secrets.token_hex(16)
        authority = store.authority_anchor_status()
        lifetime = authority.get("lifetime_id")
        if not isinstance(lifetime, str):
            raise StorageError("authority lifetime is unavailable for observation")
        self._lifetime_id = lifetime
        self._cache_lock = threading.Lock()
        self._wall_time_lock = threading.Lock()
        self._last_wall_time_ns = 0
        self._snapshot_bytes: bytes | None = None
        self._attempt_sequence = 0
        self._capture_in_progress = False
        self._last_attempt_monotonic_ns: int | None = None
        self._last_successful_attempt_sequence: int | None = None
        self._last_capture_error: str | None = None
        self._revision = 0
        self._audit_lock = threading.RLock()
        self._verified_sequence = -1
        self._verified_hash = _ZERO_HASH
        self._startup_full_verification_at_ns: int | None = None
        self._last_full_verification_at_ns: int | None = None
        self._audit_sticky_error: str | None = None
        self._schema_definition_sha256 = store.expected_schema_definition_digest()
        self._sweep_cursor_sequence = -1
        self._sweep_previous_hash = _ZERO_HASH
        self._sweep_target_sequence = -1
        self._sweep_target_hash = _ZERO_HASH
        self._sweep_last_completed_at_ns: int | None = None
        self._sweep_last_completed_head_sequence = -1
        self._sweep_last_completed_head_hash = _ZERO_HASH
        self._bootstrapped = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def instance_id(self) -> str:
        return self._instance_id

    def _ordered_wall_time_ns(self) -> int:
        """Clamp wall-clock rollback while monotonic fields retain exact age."""

        candidate = time.time_ns()
        if type(candidate) is not int or candidate < 0:
            raise StorageError("observation wall clock is invalid")
        with self._wall_time_lock:
            if candidate < self._last_wall_time_ns:
                return self._last_wall_time_ns
            self._last_wall_time_ns = candidate
            return candidate

    def _install_sql_bound(
        self,
        connection: sqlite3.Connection,
        *,
        absolute_deadline: float | None = None,
    ) -> None:
        deadline = time.monotonic() + self._sql_timeout_s
        if absolute_deadline is not None:
            deadline = min(deadline, absolute_deadline)
        callbacks = 0

        def progress() -> int:
            nonlocal callbacks
            callbacks += 1
            return int(
                callbacks > OBSERVATION_MAX_PROGRESS_CALLBACKS
                or time.monotonic() >= deadline
                or self._stop.is_set()
            )

        connection.set_progress_handler(progress, OBSERVATION_PROGRESS_CALLBACK_STEPS)

    @staticmethod
    def _clear_sql_bound(connection: sqlite3.Connection) -> None:
        connection.set_progress_handler(None, 0)

    def _audit_page(
        self,
        connection: sqlite3.Connection,
        *,
        after_sequence: int,
        through_sequence: int | None = None,
    ) -> tuple[int, bytes, bytes | None, list[dict[str, object]]]:
        head_row = connection.execute(
            """
            SELECT sequence, event_hash FROM audit_log
            WHERE tenant_id=? AND envelope_id=?
            ORDER BY sequence DESC LIMIT 1
            """,
            (self._store.metadata.tenant_id, self._store.metadata.envelope_id),
        ).fetchone()
        head_sequence = -1 if head_row is None else int(head_row[0])
        head_hash = _ZERO_HASH if head_row is None else bytes(head_row[1])
        boundary_hash: bytes | None = _ZERO_HASH if after_sequence == -1 else None
        if after_sequence >= 0:
            boundary = connection.execute(
                """
                SELECT event_hash FROM audit_log
                WHERE tenant_id=? AND envelope_id=? AND sequence=?
                """,
                (
                    self._store.metadata.tenant_id,
                    self._store.metadata.envelope_id,
                    after_sequence,
                ),
            ).fetchone()
            if boundary is not None:
                boundary_hash = bytes(boundary[0])
        selected_through = head_sequence if through_sequence is None else through_sequence
        if selected_through > head_sequence:
            raise InvariantError("audit page target is beyond the captured durable head")
        size_cursor = connection.execute(
            """
            SELECT sequence,
                   length(CAST(event_type AS BLOB)),
                   COALESCE(length(CAST(entity_type AS BLOB)), 0),
                   COALESCE(length(CAST(entity_id AS BLOB)), 0),
                   length(payload), length(previous_hash), length(event_hash)
            FROM audit_log
            WHERE tenant_id=? AND envelope_id=? AND sequence>? AND sequence<=?
            ORDER BY sequence LIMIT ?
            """,
            (
                self._store.metadata.tenant_id,
                self._store.metadata.envelope_id,
                after_sequence,
                selected_through,
                self._audit_page_size,
            ),
        )
        retained_through: int | None = None
        retained_bytes = 0
        while True:
            size_row = size_cursor.fetchone()
            if size_row is None:
                break
            # Include every copied variable field, fixed hashes/integers, and a
            # conservative per-row structural allowance in the byte admission.
            row_bytes = 64 + sum(int(size_row[index]) for index in range(1, 7))
            if row_bytes > OBSERVATION_AUDIT_PAGE_MAX_BYTES:
                raise StorageError("one audit row exceeds the observation byte bound")
            if (
                retained_through is not None
                and retained_bytes + row_bytes > OBSERVATION_AUDIT_PAGE_MAX_BYTES
            ):
                break
            retained_bytes += row_bytes
            retained_through = int(size_row[0])
        rows: list[dict[str, object]] = []
        if retained_through is not None:
            row_cursor = connection.execute(
                """
                SELECT sequence, event_type, entity_type, entity_id, payload,
                       previous_hash, event_hash, created_at_ns
                FROM audit_log
                WHERE tenant_id=? AND envelope_id=? AND sequence>? AND sequence<=?
                ORDER BY sequence
                """,
                (
                    self._store.metadata.tenant_id,
                    self._store.metadata.envelope_id,
                    after_sequence,
                    retained_through,
                ),
            )
            while True:
                row = row_cursor.fetchone()
                if row is None:
                    break
                rows.append(_audit_row(row))
        return head_sequence, head_hash, boundary_hash, rows

    def bootstrap_audit(self) -> None:
        """Perform one streaming complete scan before concurrent workers start."""

        if self._bootstrapped:
            raise RuntimeError("observation audit was already bootstrapped")
        verified_sequence, verified_hash = self._service.verify_audit_head(identity=self._identity)
        self._verified_sequence = verified_sequence
        self._verified_hash = verified_hash
        self._last_full_verification_at_ns = self._ordered_wall_time_ns()
        self._startup_full_verification_at_ns = self._last_full_verification_at_ns
        self._sweep_target_sequence = verified_sequence
        self._sweep_target_hash = verified_hash
        self._sweep_last_completed_at_ns = self._last_full_verification_at_ns
        self._sweep_last_completed_head_sequence = verified_sequence
        self._sweep_last_completed_head_hash = verified_hash
        self._bootstrapped = True

    def _durable_capture(self) -> dict[str, object]:
        with self._audit_lock:
            verified_sequence = self._verified_sequence
            sweep_after_sequence = self._sweep_cursor_sequence
            sweep_through_sequence = self._sweep_target_sequence
        capture_started_monotonic_ns = time.monotonic_ns()
        capture_deadline = (
            time.monotonic()
            + self._admission_timeout_s
            + self._store.busy_timeout_s
            + OBSERVATION_RECONCILE_ALLOWANCE_SECONDS
            + self._sql_timeout_s
        )
        with self._store.observation_read(
            timeout_s=self._admission_timeout_s,
            cancel_event=self._stop,
        ) as transaction:
            connection = transaction.connection
            if self._stop.is_set() or time.monotonic() >= capture_deadline:
                raise StorageError("observation capture exceeded its lifecycle bound")
            self._install_sql_bound(
                connection,
                absolute_deadline=capture_deadline,
            )
            try:
                captured_at_ns = self._ordered_wall_time_ns()
                captured_at_monotonic_ns = time.monotonic_ns()
                facts = self._service.observation_facts(
                    transaction,
                    identity=self._identity,
                )
                checked_at_ns = cast(int, facts["checked_at_ns"])
                capacity = self._store.observation_capacity(connection)
                schema_definition_sha256 = self._store.observation_schema_definition_digest(
                    connection
                )
                if schema_definition_sha256 != self._schema_definition_sha256:
                    raise InvariantError("captured SQLite schema definition digest changed")
                authority_checkpoint = self._store.observation_checkpoint(connection)
                captured_authority = self._store.authority_anchor_status()
                lease_rows = connection.execute(
                    "SELECT status, COUNT(*) FROM leases GROUP BY status ORDER BY status"
                ).fetchall()
                receipt_count = int(
                    connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
                )
                outgoing = connection.execute(
                    """
                    SELECT COUNT(*), COALESCE(MAX(acked_through), 0),
                           COALESCE(MAX(compacted_through), 0)
                    FROM outgoing_transfer_streams
                    """
                ).fetchone()
                incoming = connection.execute(
                    """
                    SELECT COUNT(*), COALESCE(MAX(contiguous_through), 0),
                           COALESCE(MAX(compacted_through), 0)
                    FROM inbound_transfer_streams
                    """
                ).fetchone()
                gap_count = int(
                    connection.execute("SELECT COUNT(*) FROM inbound_transfer_gaps").fetchone()[0]
                )
                in_flight = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM outgoing_transfers WHERE status='PREPARED'"
                    ).fetchone()[0]
                )
                outbox = connection.execute(
                    """
                    SELECT COUNT(*), MIN(created_at_ns) FROM audit_outbox
                    WHERE published_at_ns IS NULL
                    """
                ).fetchone()
                peer_durable = self._peer_dispatcher.durable_status(
                    connection,
                    now_ns=checked_at_ns,
                )
                exporter_durable = (
                    None
                    if self._audit_exporter is None
                    else self._audit_exporter.durable_status(
                        connection,
                        now_ns=checked_at_ns,
                    )
                )
                head_sequence, head_hash, boundary_hash, audit_rows = self._audit_page(
                    connection,
                    after_sequence=verified_sequence,
                )
                (
                    sweep_head_sequence,
                    sweep_head_hash,
                    sweep_boundary_hash,
                    sweep_rows,
                ) = self._audit_page(
                    connection,
                    after_sequence=sweep_after_sequence,
                    through_sequence=sweep_through_sequence,
                )
                if (
                    authority_checkpoint.audit_sequence != head_sequence
                    or authority_checkpoint.audit_hash != head_hash
                ):
                    raise InvariantError(
                        "captured authority checkpoint and durable audit head disagree"
                    )
            finally:
                self._clear_sql_bound(connection)
        return {
            "audit_rows": audit_rows,
            "boundary_hash": boundary_hash,
            "capture_started_monotonic_ns": capture_started_monotonic_ns,
            "capture_deadline": capture_deadline,
            "captured_at_monotonic_ns": captured_at_monotonic_ns,
            "captured_at_ns": captured_at_ns,
            "capacity": capacity.to_dict(),
            "authority_checkpoint": authority_checkpoint.to_dict(),
            "captured_authority": captured_authority,
            "exporter_durable": exporter_durable,
            "facts": facts,
            "head_hash": head_hash,
            "head_sequence": head_sequence,
            "schema_definition_sha256": schema_definition_sha256,
            "sweep_boundary_hash": sweep_boundary_hash,
            "sweep_head_hash": sweep_head_hash,
            "sweep_head_sequence": sweep_head_sequence,
            "sweep_rows": sweep_rows,
            "leases": {
                "total": sum(int(row[1]) for row in lease_rows),
                "by_status": {str(row[0]): int(row[1]) for row in lease_rows},
            },
            "outbox": {
                "unpublished_count": int(outbox[0]),
                "oldest_unpublished_age_ns": (
                    0 if outbox[1] is None else max(0, checked_at_ns - int(outbox[1]))
                ),
            },
            "peer_durable": peer_durable,
            "receipts": {"total": receipt_count},
            "transfers": {
                "outgoing_streams": int(outgoing[0]),
                "outgoing_acked_high_water": int(outgoing[1]),
                "outgoing_compacted_high_water": int(outgoing[2]),
                "incoming_streams": int(incoming[0]),
                "incoming_contiguous_high_water": int(incoming[1]),
                "incoming_compacted_high_water": int(incoming[2]),
                "inbound_gap_count": gap_count,
                "in_flight_count": in_flight,
            },
        }

    def _advance_audit_locked(self, captured: Mapping[str, object]) -> dict[str, object]:
        head_sequence = cast(int, captured["head_sequence"])
        head_hash = cast(bytes, captured["head_hash"])
        rows = cast(Sequence[Mapping[str, Any]], captured["audit_rows"])
        boundary_hash = cast(bytes | None, captured["boundary_hash"])
        if head_sequence < self._verified_sequence:
            raise StorageError("captured audit snapshot was superseded before publication")
        if self._audit_sticky_error is None:
            try:
                if boundary_hash != self._verified_hash:
                    raise InvariantError("audit incremental page boundary changed")
                if rows:
                    self._verified_sequence, self._verified_hash = self._service.verify_audit_rows(
                        rows,
                        tenant_id=self._store.metadata.tenant_id,
                        envelope_id=self._store.metadata.envelope_id,
                        expected_sequence=self._verified_sequence + 1,
                        expected_previous_hash=self._verified_hash,
                    )
                elif self._verified_sequence != head_sequence:
                    raise InvariantError("audit incremental page omitted an unverified head")
                if self._verified_sequence == head_sequence and self._verified_hash != head_hash:
                    raise InvariantError("audit verified hash does not match captured head")
                sweep_boundary = cast(bytes | None, captured["sweep_boundary_hash"])
                sweep_rows = cast(
                    Sequence[Mapping[str, Any]],
                    captured["sweep_rows"],
                )
                if sweep_boundary != self._sweep_previous_hash:
                    raise InvariantError("historical audit sweep page boundary changed")
                if sweep_rows:
                    self._sweep_cursor_sequence, self._sweep_previous_hash = (
                        self._service.verify_audit_rows(
                            sweep_rows,
                            tenant_id=self._store.metadata.tenant_id,
                            envelope_id=self._store.metadata.envelope_id,
                            expected_sequence=self._sweep_cursor_sequence + 1,
                            expected_previous_hash=self._sweep_previous_hash,
                        )
                    )
                elif self._sweep_cursor_sequence != self._sweep_target_sequence:
                    raise InvariantError("historical audit sweep omitted its target")
                if self._sweep_cursor_sequence == self._sweep_target_sequence:
                    if self._sweep_previous_hash != self._sweep_target_hash:
                        raise InvariantError("historical audit sweep target hash changed")
                    self._sweep_last_completed_at_ns = cast(int, captured["captured_at_ns"])
                    self._sweep_last_completed_head_sequence = self._sweep_target_sequence
                    self._sweep_last_completed_head_hash = self._sweep_target_hash
                    self._sweep_cursor_sequence = -1
                    self._sweep_previous_hash = _ZERO_HASH
                    self._sweep_target_sequence = cast(int, captured["sweep_head_sequence"])
                    self._sweep_target_hash = cast(bytes, captured["sweep_head_hash"])
            except BaseException as exc:
                self._audit_sticky_error = f"{type(exc).__module__}.{type(exc).__qualname__}"
        lag = max(0, head_sequence - self._verified_sequence)
        valid = (
            self._audit_sticky_error is None
            and lag == 0
            and self._verified_sequence == head_sequence
            and self._verified_hash == head_hash
        )
        return {
            "captured_head_hash": _hash_text(head_hash),
            "captured_head_sequence": head_sequence,
            "catching_up": not valid and self._audit_sticky_error is None,
            "error_type": self._audit_sticky_error,
            "lag": lag,
            "last_full_verification_at_ns": self._last_full_verification_at_ns,
            "page_size": self._audit_page_size,
            "schema_definition_sha256": captured["schema_definition_sha256"],
            "sticky_failure": self._audit_sticky_error is not None,
            "sweep_cursor_sequence": self._sweep_cursor_sequence,
            "sweep_last_completed_at_ns": self._sweep_last_completed_at_ns,
            "sweep_last_completed_head_hash": _hash_text(self._sweep_last_completed_head_hash),
            "sweep_last_completed_head_sequence": (self._sweep_last_completed_head_sequence),
            "sweep_target_sequence": self._sweep_target_sequence,
            "valid": valid,
            "verified_through_hash": _hash_text(self._verified_hash),
            "verified_through_sequence": self._verified_sequence,
        }

    def _advance_audit(self, captured: Mapping[str, object]) -> dict[str, object]:
        with self._audit_lock:
            return self._advance_audit_locked(captured)

    def _verify_terminal_checked(
        self,
        connection: sqlite3.Connection,
        checkpoint: AuthorityCheckpoint,
        full_verification: bool,
        fence_deadline: float,
    ) -> Mapping[str, object]:
        if type(full_verification) is not bool:
            raise ValueError("terminal audit verification mode must be a boolean")
        remaining = fence_deadline - time.monotonic()
        if not math.isfinite(fence_deadline) or remaining <= 0:
            raise ValueError("terminal audit verification deadline is invalid")
        if not self._audit_lock.acquire(timeout=remaining):
            raise StorageError("terminal audit verifier lock exceeded its time bound")
        try:
            return self._verify_terminal_locked(
                connection,
                checkpoint,
                full_verification,
                fence_deadline,
            )
        finally:
            self._audit_lock.release()

    def _verify_terminal_locked(
        self,
        connection: sqlite3.Connection,
        checkpoint: AuthorityCheckpoint,
        full_verification: bool,
        fence_deadline: float,
    ) -> Mapping[str, object]:
        """Verify the exact fenced audit head under terminal authority admission."""

        if type(full_verification) is not bool:
            raise ValueError("terminal audit verification mode must be a boolean")
        if not math.isfinite(fence_deadline) or fence_deadline <= time.monotonic():
            raise ValueError("terminal audit verification deadline is invalid")
        with self._audit_lock:
            if self._audit_sticky_error is not None:
                raise InvariantError("terminal audit verification is permanently faulted")
            schema_definition_sha256 = self._store.observation_schema_definition_digest(connection)
            if schema_definition_sha256 != self._schema_definition_sha256:
                raise InvariantError("terminal SQLite schema definition digest changed")
            if full_verification:
                verified_sequence = -1
                verified_hash = _ZERO_HASH
                absolute_deadline = min(
                    fence_deadline,
                    time.monotonic() + OBSERVATION_TERMINAL_FULL_TIMEOUT_SECONDS,
                )
            else:
                if self._verified_sequence > checkpoint.audit_sequence:
                    raise InvariantError("terminal audit checkpoint moved behind verified history")
                verified_sequence = self._verified_sequence
                verified_hash = self._verified_hash
                absolute_deadline = min(
                    fence_deadline,
                    time.monotonic() + self._sql_timeout_s,
                )
            while verified_sequence < checkpoint.audit_sequence:
                if time.monotonic() >= absolute_deadline:
                    raise StorageError("terminal audit verification exceeded its time bound")
                self._install_sql_bound(
                    connection,
                    absolute_deadline=absolute_deadline,
                )
                try:
                    captured_head, captured_hash, boundary_hash, rows = self._audit_page(
                        connection,
                        after_sequence=verified_sequence,
                        through_sequence=checkpoint.audit_sequence,
                    )
                finally:
                    self._clear_sql_bound(connection)
                if (
                    captured_head != checkpoint.audit_sequence
                    or captured_hash != checkpoint.audit_hash
                    or boundary_hash != verified_hash
                    or not rows
                ):
                    raise InvariantError("terminal audit page is not bound to the fenced head")
                try:
                    verified_sequence, verified_hash = self._service.verify_audit_rows(
                        rows,
                        tenant_id=self._store.metadata.tenant_id,
                        envelope_id=self._store.metadata.envelope_id,
                        expected_sequence=verified_sequence + 1,
                        expected_previous_hash=verified_hash,
                    )
                except (StorageError, TypeError, ValueError) as exc:
                    raise InvariantError("terminal audit row payload is malformed") from exc
                if time.monotonic() >= absolute_deadline:
                    raise StorageError("terminal audit verification exceeded its time bound")
            if (
                verified_sequence != checkpoint.audit_sequence
                or verified_hash != checkpoint.audit_hash
            ):
                raise InvariantError("terminal audit verification did not reach the fenced head")
            verified_at_ns = self._ordered_wall_time_ns()
            if time.monotonic() >= absolute_deadline:
                raise StorageError("terminal audit verification exceeded its time bound")
            checkpoint_document = checkpoint.to_dict()
            return {
                "schema": "lets.terminal-audit-proof/v1",
                "valid": True,
                "verification_mode": ("full" if full_verification else "trusted-startup-plus-tail"),
                "generation": self._instance_id,
                "lifetime_id": self._lifetime_id,
                "verified_at_ns": verified_at_ns,
                "verified_head_sequence": verified_sequence,
                "verified_head_hash": _hash_text(verified_hash),
                "authority_state_revision": checkpoint.state_revision,
                "authority_checkpoint_sha256": (
                    f"sha256:{sha256(canonical_json(checkpoint_document)).hexdigest()}"
                ),
                "database_instance_id": checkpoint_document["database_instance_id"],
                "schema_definition_sha256": schema_definition_sha256,
                "startup_full_verification_at_ns": self._startup_full_verification_at_ns,
            }

    def verify_terminal(
        self,
        connection: sqlite3.Connection,
        checkpoint: AuthorityCheckpoint,
        full_verification: bool,
        fence_deadline: float,
    ) -> Mapping[str, object]:
        """Fail the live cache closed if terminal verification cannot prove safety."""

        if not self._bootstrapped or self._startup_full_verification_at_ns is None:
            raise RuntimeError("observation audit bootstrap has not completed")

        try:
            return self._verify_terminal_checked(
                connection,
                checkpoint,
                full_verification,
                fence_deadline,
            )
        except BaseException as exc:
            error_type = f"{type(exc).__module__}.{type(exc).__qualname__}"
            if isinstance(exc, (InvariantError, SignatureError, ValidationError)):
                with self._audit_lock:
                    if self._audit_sticky_error is None:
                        self._audit_sticky_error = error_type
            with self._cache_lock:
                self._last_capture_error = error_type
            raise

    def capture_once(self) -> None:
        if not self._bootstrapped:
            raise RuntimeError("observation audit bootstrap has not completed")
        attempted_ns = time.monotonic_ns()
        with self._cache_lock:
            self._attempt_sequence += 1
            attempt_sequence = self._attempt_sequence
            self._capture_in_progress = True
            self._last_attempt_monotonic_ns = attempted_ns
        try:
            captured = self._durable_capture()
            audit = self._advance_audit(captured)
            if self._stop.is_set() or time.monotonic() >= cast(float, captured["capture_deadline"]):
                raise StorageError("observation capture exceeded its lifecycle bound")
            facts = cast(Mapping[str, object], captured["facts"])
            invariant = cast(InvariantSnapshot, facts["invariant"])
            runtime = cast(RuntimeStatus, facts["runtime"])
            capacity = cast(dict[str, object], captured["capacity"])
            peer_status = {
                **cast(dict[str, object], captured["peer_durable"]),
                **self._peer_dispatcher.volatile_status(),
            }
            if self._audit_exporter is None:
                exporter_status: dict[str, object] = {
                    "archive_reconciled": True,
                    "configured": False,
                    "healthy": True,
                    "last_error": None,
                    "last_success_ns": None,
                    "max_pending": 0,
                    "max_stall_s": 0.0,
                    "oldest_pending_age_s": None,
                    "pending": 0,
                    "publish_blocked": False,
                    "publish_timeout_s": 0.0,
                    "running": False,
                    "sink_call_blocked": False,
                    "stalled_for_s": 0.0,
                }
            else:
                exporter_status = self._audit_exporter.combine_status(
                    cast(Mapping[str, object], captured["exporter_durable"]),
                    self._audit_exporter.observation_volatile_status(),
                )
                exporter_status["configured"] = True
            published_at_ns = self._ordered_wall_time_ns()
            published_at_monotonic_ns = time.monotonic_ns()
            self._revision += 1
            invariant_document = _invariant_document(invariant)
            audit_valid = audit["valid"] is True
            core_healthy = (
                facts.get("core_healthy") is True
                and capacity.get("healthy") is True
                and audit_valid
            )
            eligible = core_healthy
            snapshot: dict[str, object] = {
                "schema": OBSERVATION_SCHEMA,
                "generation": self._instance_id,
                "lifetime_id": self._lifetime_id,
                "revision": self._revision,
                "capture_started_monotonic_ns": captured["capture_started_monotonic_ns"],
                "captured_at_ns": captured["captured_at_ns"],
                "captured_at_monotonic_ns": captured["captured_at_monotonic_ns"],
                "published_at_ns": published_at_ns,
                "published_at_monotonic_ns": published_at_monotonic_ns,
                "capture_duration_ns": (
                    published_at_monotonic_ns - cast(int, captured["capture_started_monotonic_ns"])
                ),
                "checked_at_ns": facts["checked_at_ns"],
                "max_age_ns": self._max_age_ns,
                "observation_eligible": eligible,
                "authority_checkpoint": captured["authority_checkpoint"],
                "captured_authority_anchor": captured["captured_authority"],
                "core_state_revision": cast(Mapping[str, object], captured["authority_checkpoint"])[
                    "state_revision"
                ],
                "database_instance_id": cast(
                    Mapping[str, object], captured["authority_checkpoint"]
                )["database_instance_id"],
                "clock_healthy": facts["clock_healthy"],
                "signing_key_healthy": facts["signing_key_healthy"],
                "sqlite_schema_sha256": captured["schema_definition_sha256"],
                "invariant_healthy": invariant.healthy,
                "invariant": invariant_document,
                "resources": {
                    key: invariant_document[key]
                    for key in (
                        "initial_share",
                        "transferred_in",
                        "transferred_out",
                        "free_pool",
                        "lease_residual",
                        "consumed",
                    )
                },
                "runtime": runtime.to_dict(),
                "storage_capacity": capacity,
                "leases": captured["leases"],
                "receipts": captured["receipts"],
                "transfers": captured["transfers"],
                "audit_outbox": captured["outbox"],
                "peer_dispatcher": peer_status,
                "audit_exporter": exporter_status,
                "audit_verification": audit,
            }
            snapshot["snapshot_id"] = f"sha256:{sha256(_observation_json(snapshot)).hexdigest()}"
            encoded = _observation_json(snapshot)
            if len(encoded) > OBSERVATION_SNAPSHOT_MAX_BYTES:
                raise StorageError("production observation snapshot exceeds its byte bound")
        except BaseException as exc:
            with self._cache_lock:
                self._capture_in_progress = False
                self._last_capture_error = f"{type(exc).__module__}.{type(exc).__qualname__}"
            raise
        with self._cache_lock:
            self._snapshot_bytes = encoded
            self._capture_in_progress = False
            self._last_capture_error = None
            self._last_successful_attempt_sequence = attempt_sequence

    def _run(self) -> None:
        while not self._stop.wait(self._capture_interval_s):
            try:
                self.capture_once()
            except Exception:
                # A failed bounded attempt relinquishes its reservation and backs
                # off for one normal interval.  This keeps a broken observer from
                # starving authority writers while the served cache fails closed.
                continue

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("observation publisher is already started")
        self._stop.clear()
        self.capture_once()
        self._thread = threading.Thread(
            target=self._run,
            name=f"lets-observation-{self._store.metadata.warden_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is None:
            return
        thread.join(
            self._admission_timeout_s
            + self._store.busy_timeout_s
            + OBSERVATION_RECONCILE_ALLOWANCE_SECONDS
            + self._sql_timeout_s
            + 5.0
        )
        exceeded_declared_bound = thread.is_alive()
        if exceeded_declared_bound:
            # A provider or SQLite primitive violated its declared bound. Never
            # let caller teardown close storage while this producer still owns
            # the authority lane; wait for ownership to return before escaping.
            while thread.is_alive():
                thread.join(1.0)
        self._thread = None
        if exceeded_declared_bound:
            raise RuntimeError("observation publisher exceeded its declared stop bound")

    def metrics_document(self) -> dict[str, object]:
        with self._cache_lock:
            encoded = self._snapshot_bytes
            attempt_sequence = self._attempt_sequence
            capture_in_progress = self._capture_in_progress
            last_error = self._last_capture_error
            last_attempt = self._last_attempt_monotonic_ns
            last_success = self._last_successful_attempt_sequence
        if encoded is None:
            raise StorageError("no production observation snapshot is available")
        decoded = _decode_observation_json(encoded)
        if not isinstance(decoded, dict):
            raise StorageError("cached production observation snapshot is malformed")
        document = cast(dict[str, object], decoded)
        now_monotonic_ns = time.monotonic_ns()
        captured_at = document.get("captured_at_monotonic_ns")
        if isinstance(captured_at, bool) or not isinstance(captured_at, int):
            raise StorageError("cached production observation time is malformed")
        age_ns = max(0, now_monotonic_ns - captured_at)
        current_authority = self._store.authority_anchor_status()
        current_lifetime = current_authority.get("lifetime_id")
        authority_healthy = (
            current_lifetime == self._lifetime_id
            and current_authority.get("healthy") is True
            and current_authority.get("admission_fenced") is False
        )
        fresh = (
            document.get("observation_eligible") is True
            and age_ns < self._max_age_ns
            and authority_healthy
            and last_error is None
        )
        exporter = document.get("audit_exporter")
        exporter_healthy = isinstance(exporter, dict) and exporter.get("healthy") is True
        peer = document.get("peer_dispatcher")
        peer_healthy = isinstance(peer, dict) and peer.get("healthy") is True
        service_ready = fresh
        document.update(
            {
                "age_ns": age_ns,
                "authority_anchor": current_authority,
                "capture_status": {
                    "attempt_sequence": attempt_sequence,
                    "capture_in_progress": capture_in_progress,
                    "last_attempt_monotonic_ns": last_attempt,
                    "last_error_type": last_error,
                    "last_successful_attempt_sequence": last_success,
                },
                "fresh": fresh,
                "ready": service_ready and exporter_healthy and peer_healthy,
                "served_at_monotonic_ns": now_monotonic_ns,
                "service_ready": service_ready,
            }
        )
        return document

    def ready(self) -> bool:
        try:
            return self.metrics_document().get("ready") is True
        except (StorageError, ValueError):
            return False


__all__ = [
    "OBSERVATION_ADMISSION_TIMEOUT_SECONDS",
    "OBSERVATION_AUDIT_PAGE_MAX_BYTES",
    "OBSERVATION_AUDIT_PAGE_SIZE",
    "OBSERVATION_CAPTURE_INTERVAL_SECONDS",
    "OBSERVATION_MAX_AGE_NS",
    "OBSERVATION_SCHEMA",
    "OBSERVATION_SNAPSHOT_MAX_BYTES",
    "OBSERVATION_TERMINAL_FULL_TIMEOUT_SECONDS",
    "ObservationPublisher",
]
