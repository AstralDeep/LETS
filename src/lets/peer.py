"""Durable at-least-once peer delivery for a running LETS warden."""

from __future__ import annotations

import math
import re
import threading
import time
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any, Protocol, cast

import httpx

from lets.canonical import strict_json_loads
from lets.client import PeerClient, RemoteUnavailableError, RetryPolicy
from lets.crypto import Ed25519Signer
from lets.errors import StorageError
from lets.ids import require_warden_id
from lets.models import IdentityContext
from lets.service import WardenService
from lets.storage import SQLiteStorage
from lets.timeouts import DEFAULT_PEER_REQUEST_TIMEOUT_SECONDS


class PeerTransport(Protocol):
    """Peer client whose ``close`` must interrupt any in-flight transport operation."""

    def accept_transfer(self, voucher: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def ingest_revocation(self, revocation: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def ingest_transfer_checkpoint(self, checkpoint: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def close(self) -> None: ...


ClientFactory = Callable[[str], PeerTransport]

MAX_PEER_RETRY_DELAY_SECONDS = 30.0
_EXCEPTION_CLASS = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]{0,63}\Z")


class PeerDispatcher:
    """Discover durable peer records and deliver them idempotently until acknowledged.

    Authority records remain in the warden database. ``peer_delivery_state`` stores only
    retry metadata, so a crash between the authoritative commit and discovery cannot lose work.
    """

    def __init__(
        self,
        service: WardenService,
        store: SQLiteStorage,
        signer: Ed25519Signer,
        peer_endpoints: Mapping[str, str],
        *,
        client_factory: ClientFactory | None = None,
        verify: bool | str = True,
        cert: str | tuple[str, str] | None = None,
        poll_interval_s: float = 0.25,
        request_timeout_s: float = DEFAULT_PEER_REQUEST_TIMEOUT_SECONDS,
        batch_size: int = 64,
        max_concurrency: int = 8,
    ) -> None:
        intervals = (poll_interval_s, request_timeout_s)
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
            for value in intervals
        ):
            raise ValueError("peer dispatcher intervals must be positive")
        if batch_size < 1 or batch_size > 1024:
            raise ValueError("peer dispatcher batch_size must be between 1 and 1024")
        if max_concurrency < 1 or max_concurrency > 64:
            raise ValueError("peer dispatcher max_concurrency must be between 1 and 64")
        self._service = service
        self._store = store
        self._signer = signer
        self._endpoints: dict[str, str] = {}
        for warden_id, endpoint in peer_endpoints.items():
            checked = require_warden_id(warden_id, field="peer endpoint warden_id")
            if checked == signer.warden_id:
                continue
            if not isinstance(endpoint, str) or not endpoint:
                raise ValueError(f"peer endpoint for {checked!r} must be a non-empty URI")
            self._endpoints[checked] = endpoint.rstrip("/")

        def default_factory(endpoint: str) -> PeerTransport:
            return PeerClient(
                endpoint,
                signer=signer,
                verify=verify,
                cert=cert,
                timeout=request_timeout_s,
                total_timeout_s=request_timeout_s,
                retry=RetryPolicy(max_attempts=1),
            )

        factory = default_factory if client_factory is None else client_factory
        self._clients = {warden: factory(endpoint) for warden, endpoint in self._endpoints.items()}
        self._identity = IdentityContext(
            subject_id=signer.warden_id,
            tenant_id=store.metadata.tenant_id,
            scopes=frozenset({"lets.peer", "lets.transfer"}),
            authentication_method="local-peer-dispatcher",
        )
        self._poll_interval_s = poll_interval_s
        self._request_timeout_s = request_timeout_s
        self._batch_size = batch_size
        self._max_concurrency = max_concurrency
        self._stop = threading.Event()
        self._run_lock = threading.Lock()
        self._status_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._last_cycle_ns: int | None = None
        self._last_error: str | None = None
        self._schedule_cursor: tuple[str, str, str] | None = None
        self._checkpoint_cursor: str | None = None

    @staticmethod
    def _exception_class(error: BaseException) -> str:
        """Return a bounded class token without serializing attacker-controlled text."""

        candidate = type(error).__name__
        return candidate if _EXCEPTION_CLASS.fullmatch(candidate) is not None else "UnknownError"

    @staticmethod
    def _stored_exception_class(value: object) -> str:
        """Sanitize both new class-only values and legacy ``Class: message`` rows."""

        if not isinstance(value, str):
            return "UnknownError"
        candidate = value.partition(":")[0].strip()
        return candidate if _EXCEPTION_CLASS.fullmatch(candidate) is not None else "UnknownError"

    @staticmethod
    def _stored_record_kind(value: object) -> str:
        return (
            value
            if isinstance(value, str) and value in {"checkpoint", "revocation", "transfer"}
            else "unknown"
        )

    @staticmethod
    def _stored_target_warden(value: object) -> str:
        try:
            return require_warden_id(cast(str, value), field="durable retry target_warden")
        except (TypeError, ValueError):
            return "unknown"

    def _record_status(
        self,
        *,
        error: str | None,
        cycle_ns: int | None = None,
    ) -> None:
        with self._status_lock:
            self._last_error = error
            if cycle_ns is not None:
                self._last_cycle_ns = cycle_ns

    def _record_cycle(self, cycle_ns: int) -> None:
        with self._status_lock:
            self._last_cycle_ns = cycle_ns

    @staticmethod
    def _object(payload: object, label: str) -> dict[str, Any]:
        decoded = strict_json_loads(cast(bytes | str, payload))
        if not isinstance(decoded, dict):
            raise ValueError(f"durable {label} payload is not a JSON object")
        return decoded

    def _record_attempt(
        self,
        kind: str,
        record_id: str,
        target: str,
        *,
        now_ns: int,
        error: Exception | None,
    ) -> None:
        with self._store.capacity_recovery() as transaction:
            connection = transaction.connection
            row = connection.execute(
                """
                SELECT attempts, superseded_at_ns FROM peer_delivery_state
                WHERE record_kind = ? AND record_id = ? AND target_warden = ?
                """,
                (kind, record_id, target),
            ).fetchone()
            if row is None:
                raise StorageError("durable peer delivery record disappeared")
            if row[1] is not None:
                return
            attempts = int(row[0]) + 1
            if error is None:
                delivered_at_ns = now_ns
                next_attempt_ns = 0
                message = None
            else:
                delivered_at_ns = None
                delay_ns = min(
                    int(MAX_PEER_RETRY_DELAY_SECONDS * 1_000_000_000),
                    250_000_000 * (2 ** min(attempts - 1, 7)),
                )
                next_attempt_ns = min((1 << 63) - 1, now_ns + delay_ns)
                message = self._exception_class(error)
                self._record_status(error=message)
            cursor = connection.execute(
                """
                UPDATE peer_delivery_state
                SET attempts = ?, next_attempt_ns = ?, last_attempt_ns = ?,
                    delivered_at_ns = ?, last_error = ?
                WHERE record_kind = ? AND record_id = ? AND target_warden = ?
                  AND superseded_at_ns IS NULL
                """,
                (
                    attempts,
                    next_attempt_ns,
                    now_ns,
                    delivered_at_ns,
                    message,
                    kind,
                    record_id,
                    target,
                ),
            )
            if cursor.rowcount != 1:
                raise StorageError("durable peer delivery update did not affect one record")
            if error is None:
                connection.execute(
                    """
                    INSERT INTO peer_delivery_counters(
                        record_kind, target_warden, delivered_count,
                        superseded_count, last_terminal_ns
                    ) VALUES (?, ?, 1, 0, ?)
                    ON CONFLICT(record_kind, target_warden) DO UPDATE SET
                        delivered_count = delivered_count + 1,
                        last_terminal_ns = excluded.last_terminal_ns
                    """,
                    (kind, target, now_ns),
                )

    def _prune_terminal(self) -> None:
        """Bound the outbox after its durable peer obligations are complete."""

        with self._store.capacity_recovery() as transaction:
            connection = transaction.connection
            # Prune at most one dispatcher batch per transaction.  Prefixes can be
            # arbitrarily long on a long-lived stream, and compaction must remain a
            # bounded recovery-lane write even when normal capacity is exhausted.
            connection.execute(
                """
                DELETE FROM peer_delivery_state
                WHERE (record_kind, record_id, target_warden) IN (
                    SELECT transfer.record_kind, transfer.record_id,
                           transfer.target_warden
                    FROM peer_delivery_state AS transfer
                    WHERE transfer.record_kind = 'transfer'
                      AND transfer.delivered_at_ns IS NOT NULL
                      AND EXISTS (
                          SELECT 1
                          FROM peer_delivery_state AS checkpoint
                          WHERE checkpoint.record_kind = 'checkpoint'
                            AND checkpoint.target_warden = transfer.target_warden
                            AND checkpoint.delivered_at_ns IS NOT NULL
                            AND checkpoint.stream_position >= transfer.stream_position
                      )
                    ORDER BY transfer.target_warden, transfer.stream_position,
                             transfer.record_id
                    LIMIT ?
                )
                """,
                (self._batch_size,),
            )
            removed = int(connection.execute("SELECT changes()").fetchone()[0])
            remaining = self._batch_size - removed
            if remaining <= 0:
                return
            connection.execute(
                """
                DELETE FROM peer_delivery_state
                WHERE (record_kind, record_id, target_warden) IN (
                    SELECT terminal.record_kind, terminal.record_id,
                           terminal.target_warden
                    FROM peer_delivery_state AS terminal
                    WHERE (
                        terminal.record_kind = 'revocation'
                        AND (
                            terminal.delivered_at_ns IS NOT NULL
                            OR terminal.superseded_at_ns IS NOT NULL
                        )
                    ) OR (
                        terminal.record_kind = 'checkpoint'
                        AND (
                            terminal.superseded_at_ns IS NOT NULL
                            OR (
                                terminal.delivered_at_ns IS NOT NULL
                                AND NOT EXISTS (
                                    SELECT 1
                                    FROM peer_delivery_state AS covered
                                    WHERE covered.record_kind = 'transfer'
                                      AND covered.target_warden = terminal.target_warden
                                      AND covered.delivered_at_ns IS NOT NULL
                                      AND covered.stream_position
                                          <= terminal.stream_position
                                )
                            )
                        )
                    )
                    ORDER BY terminal.record_kind, terminal.target_warden,
                             terminal.stream_position, terminal.record_id
                    LIMIT ?
                )
                """,
                (remaining,),
            )

    def _prune_compacted_transfer_history(self) -> None:
        """Finish physical checkpoint cleanup in bounded local batches.

        The signed stream checkpoint advances ``compacted_through`` atomically,
        while the first service call deletes at most one maintenance batch.  A
        peer need not resend an already accepted checkpoint merely to finish
        non-authoritative row cleanup, so the local dispatcher drains the
        remaining covered history under the same fixed write budget.
        """

        with self._store.capacity_recovery() as transaction:
            connection = transaction.connection
            connection.execute(
                """
                DELETE FROM outgoing_transfers
                WHERE (tenant_id, envelope_id, target_warden, sequence) IN (
                    SELECT transfer.tenant_id, transfer.envelope_id,
                           transfer.target_warden, transfer.sequence
                    FROM outgoing_transfers AS transfer
                    JOIN outgoing_transfer_streams AS stream
                      ON stream.tenant_id = transfer.tenant_id
                     AND stream.envelope_id = transfer.envelope_id
                     AND stream.target_warden = transfer.target_warden
                    WHERE transfer.sequence <= stream.compacted_through
                    ORDER BY transfer.target_warden, transfer.sequence
                    LIMIT ?
                )
                """,
                (self._batch_size,),
            )
            removed = int(connection.execute("SELECT changes()").fetchone()[0])
            remaining = self._batch_size - removed
            if remaining <= 0:
                return
            connection.execute(
                """
                DELETE FROM inbound_transfer_acks
                WHERE (tenant_id, envelope_id, source_warden, sequence) IN (
                    SELECT acknowledgement.tenant_id,
                           acknowledgement.envelope_id,
                           acknowledgement.source_warden,
                           acknowledgement.sequence
                    FROM inbound_transfer_acks AS acknowledgement
                    JOIN inbound_transfer_streams AS stream
                      ON stream.tenant_id = acknowledgement.tenant_id
                     AND stream.envelope_id = acknowledgement.envelope_id
                     AND stream.source_warden = acknowledgement.source_warden
                    WHERE acknowledgement.sequence <= stream.compacted_through
                    ORDER BY acknowledgement.source_warden,
                             acknowledgement.sequence
                    LIMIT ?
                )
                """,
                (remaining,),
            )

    def _pending_records(self) -> dict[str, list[tuple[str, str, str, bytes]]]:
        now_ns = time.time_ns()
        cursor = self._schedule_cursor or ("", "", "")
        with self._store.read() as transaction:
            connection = transaction.connection

            def fetch(
                comparison: str,
                boundary: tuple[str, str, str],
                limit: int,
            ) -> list[Any]:
                queries = {
                    ">": """
                        SELECT head.record_kind, head.record_id, head.target_warden,
                               head.ordering_key, state.payload
                        FROM peer_delivery_heads AS head
                        JOIN peer_delivery_state AS state
                          ON state.record_kind = head.record_kind
                         AND state.record_id = head.record_id
                         AND state.target_warden = head.target_warden
                        WHERE (head.target_warden, head.record_kind, head.ordering_key)
                                  > (?, ?, ?)
                          AND (state.next_attempt_ns = 0 OR state.next_attempt_ns <= ?)
                        ORDER BY head.target_warden, head.record_kind, head.ordering_key
                        LIMIT ?
                    """,
                    "<=": """
                        SELECT head.record_kind, head.record_id, head.target_warden,
                               head.ordering_key, state.payload
                        FROM peer_delivery_heads AS head
                        JOIN peer_delivery_state AS state
                          ON state.record_kind = head.record_kind
                         AND state.record_id = head.record_id
                         AND state.target_warden = head.target_warden
                        WHERE (head.target_warden, head.record_kind, head.ordering_key)
                                  <= (?, ?, ?)
                          AND (state.next_attempt_ns = 0 OR state.next_attempt_ns <= ?)
                        ORDER BY head.target_warden, head.record_kind, head.ordering_key
                        LIMIT ?
                    """,
                }
                try:
                    query = queries[comparison]
                except KeyError as exc:
                    raise AssertionError("invalid dispatcher cursor comparison") from exc
                return connection.execute(
                    query,
                    (*boundary, now_ns, limit),
                ).fetchall()

            rows = fetch(">", cursor, self._batch_size)
            if len(rows) < self._batch_size:
                rows.extend(fetch("<=", cursor, self._batch_size - len(rows)))
        if rows:
            last = rows[-1]
            self._schedule_cursor = (str(last[2]), str(last[0]), str(last[3]))
        grouped: dict[str, list[tuple[str, str, str, bytes]]] = defaultdict(list)
        for row in rows:
            grouped[str(row[2])].append((str(row[0]), str(row[1]), str(row[3]), bytes(row[4])))
        return dict(grouped)

    def _deliver_target(
        self,
        target: str,
        records: Sequence[tuple[str, str, str, bytes]],
    ) -> None:
        client = self._clients.get(target)
        if client is None:
            error = StorageError(f"no configured client exists for peer {target!r}")
            kind, record_id, _, _ = records[0]
            self._record_attempt(kind, record_id, target, now_ns=time.time_ns(), error=error)
            return
        for kind, record_id, _ordering_key, raw in records:
            if self._stop.is_set():
                return
            now_ns = time.time_ns()
            try:
                payload = self._object(raw, f"{kind} peer record")
                if kind == "transfer":
                    acknowledgement = client.accept_transfer(payload)
                    self._service.finalize_transfer(
                        identity=self._identity,
                        acknowledgement=acknowledgement,
                    )
                elif kind == "checkpoint":
                    client.ingest_transfer_checkpoint(payload)
                elif kind == "revocation":
                    client.ingest_revocation(payload)
                else:
                    raise StorageError(f"unknown durable peer record kind {kind!r}")
            except Exception as error:
                self._record_attempt(kind, record_id, target, now_ns=now_ns, error=error)
                # A network/server outage is peer-wide and is bounded to one
                # transport timeout per cycle. A signed semantic rejection is
                # stream-local; the SQL query selected only one head from each
                # stream, so unrelated streams may continue safely.
                if isinstance(error, (OSError, httpx.TransportError, RemoteUnavailableError)):
                    return
                continue
            else:
                self._record_attempt(kind, record_id, target, now_ns=now_ns, error=None)

    def _deliver_pending(self) -> None:
        grouped = self._pending_records()
        work = [
            partial(self._deliver_target, target, records) for target, records in grouped.items()
        ]
        for offset in range(0, len(work), self._max_concurrency):
            if self._stop.is_set():
                return
            chunk = work[offset : offset + self._max_concurrency]
            with ThreadPoolExecutor(
                max_workers=len(chunk),
                thread_name_prefix=f"lets-peer-{self._signer.warden_id}",
            ) as executor:
                futures = [executor.submit(operation) for operation in chunk]
                for future in futures:
                    try:
                        future.result()
                    except Exception as error:
                        self._record_status(error=self._exception_class(error))

    def _create_checkpoints(self) -> None:
        cursor = self._checkpoint_cursor or ""
        with self._store.read() as transaction:
            connection = transaction.connection

            def fetch(comparison: str, boundary: str, limit: int) -> list[Any]:
                queries = {
                    ">": """
                        SELECT target_warden, acked_through
                        FROM outgoing_transfer_streams AS stream
                        WHERE target_warden > ?
                          AND acked_through > compacted_through
                          AND NOT EXISTS (
                              SELECT 1
                              FROM outgoing_transfers AS transfer
                              LEFT JOIN peer_delivery_state AS delivery
                                ON delivery.record_kind = 'transfer'
                               AND delivery.record_id = transfer.transfer_id
                               AND delivery.target_warden = transfer.target_warden
                              WHERE transfer.tenant_id = stream.tenant_id
                                AND transfer.envelope_id = stream.envelope_id
                                AND transfer.target_warden = stream.target_warden
                                AND transfer.sequence <= stream.acked_through
                                AND (delivery.record_id IS NULL OR delivery.delivered_at_ns IS NULL)
                          )
                        ORDER BY target_warden
                        LIMIT ?
                    """,
                    "<=": """
                        SELECT target_warden, acked_through
                        FROM outgoing_transfer_streams AS stream
                        WHERE target_warden <= ?
                          AND acked_through > compacted_through
                          AND NOT EXISTS (
                              SELECT 1
                              FROM outgoing_transfers AS transfer
                              LEFT JOIN peer_delivery_state AS delivery
                                ON delivery.record_kind = 'transfer'
                               AND delivery.record_id = transfer.transfer_id
                               AND delivery.target_warden = transfer.target_warden
                              WHERE transfer.tenant_id = stream.tenant_id
                                AND transfer.envelope_id = stream.envelope_id
                                AND transfer.target_warden = stream.target_warden
                                AND transfer.sequence <= stream.acked_through
                                AND (delivery.record_id IS NULL OR delivery.delivered_at_ns IS NULL)
                          )
                        ORDER BY target_warden
                        LIMIT ?
                    """,
                }
                try:
                    query = queries[comparison]
                except KeyError as exc:
                    raise AssertionError("invalid checkpoint cursor comparison") from exc
                return connection.execute(
                    query,
                    (boundary, limit),
                ).fetchall()

            rows = fetch(">", cursor, self._batch_size)
            if len(rows) < self._batch_size:
                rows.extend(fetch("<=", cursor, self._batch_size - len(rows)))
        if rows:
            self._checkpoint_cursor = str(rows[-1][0])
        for row in rows:
            if self._stop.is_set():
                return
            try:
                self._service.create_transfer_checkpoint(
                    identity=self._identity,
                    target_warden=str(row[0]),
                    through_sequence=int(row[1]),
                )
            except Exception as error:
                self._record_status(error=self._exception_class(error))

    def run_once(self) -> None:
        """Run one bounded discovery and delivery cycle."""

        if not self._run_lock.acquire(blocking=False):
            return
        try:
            self._record_status(error=None)
            self._create_checkpoints()
            self._deliver_pending()
            self._prune_terminal()
            self._prune_compacted_transfer_history()
            self._record_cycle(time.time_ns())
        except Exception as error:
            self._record_status(
                error=self._exception_class(error),
                cycle_ns=time.time_ns(),
            )
        finally:
            self._run_lock.release()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self._poll_interval_s)

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("peer dispatcher is already started")
        self._thread = threading.Thread(
            target=self._run,
            name=f"lets-peer-dispatch-{self._signer.warden_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self, *, timeout_s: float | None = None) -> None:
        self._stop.set()
        # Closing first interrupts an HTTP response that is making slow incremental
        # progress; per-phase HTTP timeouts alone are not a wall-clock shutdown bound.
        for client in self._clients.values():
            try:
                client.close()
            except Exception as error:
                self._record_status(error=self._exception_class(error))
        if self._thread is not None:
            deadline = max(
                5.0,
                self._request_timeout_s + self._store.busy_timeout_s + self._poll_interval_s + 2.0,
            )
            self._thread.join(deadline if timeout_s is None else timeout_s)
            if self._thread.is_alive():
                raise RuntimeError("peer dispatcher did not stop within its deadline")
            self._thread = None

    def durable_status(
        self,
        connection: Any,
        *,
        now_ns: int,
    ) -> dict[str, object]:
        row = connection.execute(
            """
                SELECT
                    SUM(
                        CASE WHEN delivered_at_ns IS NULL AND superseded_at_ns IS NULL
                        THEN 1 ELSE 0 END
                    ),
                    SUM(
                        CASE WHEN delivered_at_ns IS NULL AND superseded_at_ns IS NULL
                                  AND last_error IS NOT NULL
                        THEN 1 ELSE 0 END
                    )
                FROM peer_delivery_state
                """
        ).fetchone()
        counters = connection.execute(
            """
                SELECT SUM(delivered_count), SUM(superseded_count)
                FROM peer_delivery_counters
                """
        ).fetchone()
        prepared = int(
            connection.execute(
                "SELECT COUNT(*) FROM outgoing_transfers WHERE status = 'PREPARED'"
            ).fetchone()[0]
        )
        retry_row = connection.execute(
            """
                SELECT attempts, next_attempt_ns, last_error, record_kind, target_warden
                FROM peer_delivery_state
                WHERE delivered_at_ns IS NULL
                  AND superseded_at_ns IS NULL
                  AND last_error IS NOT NULL
                ORDER BY created_at_ns, record_kind, record_id, target_warden
                LIMIT 1
                """
        ).fetchone()
        durable_retry: dict[str, object] | None = None
        if retry_row is not None:
            remaining_ns = max(0, int(retry_row[1]) - now_ns)
            delay_seconds = min(
                MAX_PEER_RETRY_DELAY_SECONDS,
                remaining_ns / 1_000_000_000,
            )
            durable_retry = {
                "attempt_count": max(0, int(retry_row[0])),
                "exception_class": self._stored_exception_class(retry_row[2]),
                "next_retry_delay_seconds": round(delay_seconds, 3),
                "record_kind": self._stored_record_kind(retry_row[3]),
                "target_warden": self._stored_target_warden(retry_row[4]),
            }
        return {
            "pending_records": 0 if row[0] is None else int(row[0]),
            "delivered_records": 0 if counters[0] is None else int(counters[0]),
            "superseded_records": 0 if counters[1] is None else int(counters[1]),
            "failed_records": 0 if row[1] is None else int(row[1]),
            "prepared_transfers": prepared,
            "durable_retry": durable_retry,
        }

    def volatile_status(self) -> dict[str, object]:
        with self._status_lock:
            thread = self._thread
            running = thread is not None and thread.is_alive()
            return {
                "configured_peers": len(self._clients),
                "healthy": (
                    running and self._last_cycle_ns is not None and self._last_error is None
                ),
                "last_cycle_ns": self._last_cycle_ns,
                "last_error": self._last_error,
                "running": running,
            }

    def status(self) -> dict[str, object]:
        now_ns = time.time_ns()
        with self._store.read() as transaction:
            durable = self.durable_status(transaction.connection, now_ns=now_ns)
        return {**durable, **self.volatile_status()}


__all__ = [
    "DEFAULT_PEER_REQUEST_TIMEOUT_SECONDS",
    "MAX_PEER_RETRY_DELAY_SECONDS",
    "PeerDispatcher",
    "PeerTransport",
]
