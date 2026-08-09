from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

import pytest

from lets.errors import CapacityError, ConflictError, InvariantError, StorageError, ValidationError
from lets.storage import SQLiteStorage
from lets.storage.schema import (
    APPLICATION_ID,
    REQUIRED_INDEXES,
    REQUIRED_TABLES,
    REQUIRED_TRIGGERS,
    SCHEMA_VERSION,
)
from lets.vector import pack

_SIGNING_KEY_ID = "test-signing-key"
_SIGNING_PUBLIC_KEY = bytes(range(32))


@pytest.fixture
def store(tmp_path: Path) -> Iterator[SQLiteStorage]:
    storage = SQLiteStorage.initialize(
        tmp_path / "warden.db",
        "warden-a",
        (100, 50),
        signing_key_id=_SIGNING_KEY_ID,
        signing_public_key=_SIGNING_PUBLIC_KEY,
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=3,
        dimension_metadata=(
            {"name": "network", "unit": "requests"},
            {"name": "energy", "unit": "joules"},
        ),
        initial_local_share=(60, 20),
        receipt_ttl_ns=1_000,
        max_clock_uncertainty_ns=5,
        transfer_gap_window=8,
    )
    yield storage
    storage.close()


def test_initializes_versioned_schema_and_required_pragmas(store: SQLiteStorage) -> None:
    assert store.schema_version == SCHEMA_VERSION
    assert store.metadata.warden_id == "warden-a"
    assert store.metadata.signing_key_id == _SIGNING_KEY_ID
    assert store.metadata.budget == (100, 50)
    assert store.metadata.initial_local_share == (60, 20)
    with store.read() as transaction:
        columns = {
            row[1] for row in transaction.connection.execute("PRAGMA table_info(database_metadata)")
        }
    assert "key_seed" not in columns

    with store.read() as transaction:
        connection = transaction.connection
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 5_000
        assert connection.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        rows = connection.execute(
            "SELECT type, name FROM sqlite_schema WHERE type IN ('table', 'index', 'trigger')"
        ).fetchall()
        tables = {row["name"] for row in rows if row["type"] == "table"}
        indexes = {row["name"] for row in rows if row["type"] == "index"}
        triggers = {row["name"] for row in rows if row["type"] == "trigger"}
    assert tables >= REQUIRED_TABLES
    assert indexes >= REQUIRED_INDEXES
    assert triggers >= REQUIRED_TRIGGERS
    assert store.pragma_integrity_check() == ("ok",)
    assert store.pragma_foreign_key_check() == []


def test_open_existing_fails_closed_without_recreating_authority_state(tmp_path: Path) -> None:
    missing = tmp_path / "missing.db"
    options = {
        "signing_key_id": _SIGNING_KEY_ID,
        "signing_public_key": _SIGNING_PUBLIC_KEY,
        "tenant_id": "tenant-a",
        "envelope_id": "envelope-a",
    }
    with pytest.raises(StorageError, match="could not open"):
        SQLiteStorage(missing, "warden-a", (10,), **options)
    assert not missing.exists()

    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    with pytest.raises(StorageError, match="empty or uninitialized"):
        SQLiteStorage(empty, "warden-a", (10,), **options)
    assert empty.read_bytes() == b""

    initialized = tmp_path / "initialized.db"
    created = SQLiteStorage.initialize(initialized, "warden-a", (10,), **options)
    created.close()
    with pytest.raises(StorageError, match="already initialized"):
        SQLiteStorage.initialize(initialized, "warden-a", (10,), **options)


def test_schema_v1_requires_explicit_transactional_migration(tmp_path: Path) -> None:
    path = tmp_path / "legacy-v1.db"
    options = {
        "signing_key_id": _SIGNING_KEY_ID,
        "signing_public_key": _SIGNING_PUBLIC_KEY,
        "tenant_id": "tenant-a",
        "envelope_id": "envelope-a",
    }
    current = SQLiteStorage.initialize(path, "warden-a", (10,), **options)
    current.close()

    # Construct the exact version boundary represented by the v1 schema: v2's
    # expand-only runtime-control objects are absent and both version markers agree.
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("DROP TRIGGER runtime_control_generation_monotonic")
        connection.execute("DROP TRIGGER runtime_control_no_delete")
        connection.execute("DROP TABLE runtime_control")
        connection.execute("DROP TRIGGER database_instance_immutable")
        connection.execute("DROP TRIGGER database_instance_no_delete")
        connection.execute("DROP TABLE database_instance")
        connection.execute("UPDATE database_metadata SET schema_version = 1 WHERE singleton = 1")
        connection.execute("PRAGMA user_version = 1")

    with pytest.raises(StorageError, match="requires explicit migration"):
        SQLiteStorage(path, "warden-a", (10,), **options)

    migrated = SQLiteStorage.migrate(path, "warden-a", (10,), **options)
    try:
        assert migrated.schema_version == SCHEMA_VERSION == 2
        with migrated.read() as transaction:
            row = transaction.connection.execute(
                "SELECT mode, generation FROM runtime_control WHERE singleton = 1"
            ).fetchone()
        assert tuple(row) == ("ACTIVE", 0)
    finally:
        migrated.close()


def test_capacity_reserve_fails_closed_before_sqlite_full(tmp_path: Path) -> None:
    path = tmp_path / "capacity.db"
    options = {
        "signing_key_id": _SIGNING_KEY_ID,
        "signing_public_key": _SIGNING_PUBLIC_KEY,
        "tenant_id": "tenant-a",
        "envelope_id": "envelope-a",
    }
    initialized = SQLiteStorage.initialize(path, "warden-a", (10,), **options)
    initialized.close()

    limited = SQLiteStorage(
        path,
        "warden-a",
        (10,),
        max_database_bytes=1,
        reserve_pages=8,
        **options,
    )
    try:
        snapshot = limited.capacity_snapshot()
        assert not snapshot.healthy
        assert snapshot.max_database_bytes == 1
        assert snapshot.database_bytes > snapshot.max_database_bytes
        with pytest.raises(CapacityError, match="reserve is exhausted"), limited.write():
            pass
        assert limited.pragma_integrity_check() == ("ok",)
        assert limited.verify_conservation()
    finally:
        limited.close()


def test_transaction_rolls_back_and_closes_handle(store: SQLiteStorage) -> None:
    with pytest.raises(RuntimeError, match="abort"), store.write() as transaction:
        transaction.put_idempotency(
            scope="issue",
            request_id="request-1",
            fingerprint=b"fingerprint",
            response=b"response",
            status_code=201,
            created_at_ns=10,
        )
        raise RuntimeError("abort")

    assert transaction.closed
    with pytest.raises(StorageError, match="closed"):
        transaction.fetch_one("SELECT 1")
    with store.read() as reader:
        assert reader.get_idempotency("issue", "request-1") is None


def test_idempotency_request_id_is_global_to_the_envelope(store: SQLiteStorage) -> None:
    with store.write() as transaction:
        transaction.put_idempotency(
            scope="issue",
            request_id="global-id",
            fingerprint=b"fingerprint",
            response=b"response",
            status_code=201,
            created_at_ns=10,
        )
    with store.read() as transaction, pytest.raises(ConflictError, match="bound to scope"):
        transaction.get_idempotency("authorize", "global-id")
    with store.write() as transaction, pytest.raises(ConflictError, match="bound to scope"):
        transaction.put_idempotency(
            scope="authorize",
            request_id="global-id",
            fingerprint=b"other",
            response=b"other",
            status_code=201,
            created_at_ns=11,
        )


def test_deferred_commit_failure_rolls_back_and_closes(store: SQLiteStorage) -> None:
    with store.write() as transaction:
        transaction.insert_policy(
            policy_version="v1",
            policy_digest="digest-1",
            machine_digest="machine-1",
            payload={},
            created_at_ns=1,
        )

    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"), store.write() as failed:
        failed.insert_lease(
            {
                "lease_id": "orphan",
                "lineage_id": "lineage",
                "parent_id": "missing-parent",
                "subject_id": "subject",
                "allocation": (1, 1),
                "residual": (1, 1),
                "capabilities": (),
                "machine_digest": "machine-1",
                "issued_at_ns": 1,
                "expires_at_ns": 2,
                "key_id": "key",
                "signature": b"signature",
                "state": "ready",
                "status": "ACTIVE",
                "policy_version": "v1",
                "policy_digest": "digest-1",
            }
        )

    assert failed.closed
    with store.read() as transaction:
        assert transaction.get_lease("orphan") is None


def test_nested_transactions_are_refused(store: SQLiteStorage) -> None:
    with store.write(), pytest.raises(StorageError, match="nested"), store.read():
        pass


def test_read_transaction_is_database_enforced_read_only(store: SQLiteStorage) -> None:
    with pytest.raises(StorageError, match="transaction failed"), store.read() as transaction:
        transaction.connection.execute("UPDATE warden_state SET revision = revision + 1")


def test_metadata_identity_persists_and_mismatches_are_refused(
    tmp_path: Path,
) -> None:
    path = tmp_path / "metadata.db"
    first = SQLiteStorage.initialize(
        path,
        "warden-a",
        (9,),
        signing_key_id=_SIGNING_KEY_ID,
        signing_public_key=_SIGNING_PUBLIC_KEY,
        tenant_id="t",
        envelope_id="e",
    )
    first.close()

    reopened = SQLiteStorage(
        path,
        "warden-a",
        (9,),
        signing_key_id=_SIGNING_KEY_ID,
        signing_public_key=_SIGNING_PUBLIC_KEY,
        tenant_id="t",
        envelope_id="e",
    )
    assert reopened.metadata.warden_id == "warden-a"
    reopened.close()

    with pytest.raises(StorageError, match="metadata mismatch"):
        SQLiteStorage(
            path,
            "warden-b",
            (9,),
            signing_key_id=_SIGNING_KEY_ID,
            signing_public_key=_SIGNING_PUBLIC_KEY,
            tenant_id="t",
            envelope_id="e",
        )
    with pytest.raises(StorageError, match="metadata mismatch"):
        SQLiteStorage(
            path,
            "warden-a",
            (10,),
            signing_key_id=_SIGNING_KEY_ID,
            signing_public_key=_SIGNING_PUBLIC_KEY,
            tenant_id="t",
            envelope_id="e",
        )
    with pytest.raises(StorageError, match="metadata mismatch"):
        SQLiteStorage(
            path,
            "warden-a",
            (9,),
            signing_key_id=_SIGNING_KEY_ID,
            signing_public_key=_SIGNING_PUBLIC_KEY,
            tenant_id="t",
            envelope_id="other",
        )
    with pytest.raises(StorageError, match="signing_key_id"):
        SQLiteStorage(
            path,
            "warden-a",
            (9,),
            signing_key_id="replacement-key",
            signing_public_key=_SIGNING_PUBLIC_KEY,
            tenant_id="t",
            envelope_id="e",
        )
    with pytest.raises(StorageError, match="signing_public_key_sha256"):
        SQLiteStorage(
            path,
            "warden-a",
            (9,),
            signing_key_id=_SIGNING_KEY_ID,
            signing_public_key=b"x" * 32,
            tenant_id="t",
            envelope_id="e",
        )


def test_service_and_database_reject_invalid_vectors(store: SQLiteStorage) -> None:
    with store.write() as transaction:
        with pytest.raises(ValidationError, match="dimension mismatch"):
            transaction.update_warden_state(free_pool=(1,), updated_at_ns=1)
        with pytest.raises(ValidationError, match="non-negative"):
            transaction.update_warden_state(free_pool=(-1, 0), updated_at_ns=1)
        with pytest.raises(sqlite3.IntegrityError):
            transaction.connection.execute(
                """
                UPDATE warden_state SET free_pool = ?
                WHERE tenant_id = ? AND envelope_id = ?
                """,
                (b"not-a-vector", *transaction.scope),
            )


def test_policy_lease_receipt_audit_and_replay_repositories(store: SQLiteStorage) -> None:
    policy_digest = "sha256:" + "1" * 64
    machine_digest = "sha256:" + "2" * 64
    with store.write() as transaction:
        transaction.insert_policy(
            policy_version="v1",
            policy_digest=policy_digest,
            machine_digest=machine_digest,
            payload={"policy_id": "policy-a"},
            active=True,
            created_at_ns=1,
        )
        transaction.insert_lease(
            {
                "lease_id": "lease-a",
                "lineage_id": "lineage-a",
                "subject_id": "agent-a",
                "allocation": (10, 4),
                "residual": (9, 3),
                "capabilities": ("move",),
                "machine_digest": machine_digest,
                "ancestor_path": (),
                "issued_at_ns": 2,
                "expires_at_ns": 100,
                "key_id": "key-a",
                "signature": b"lease-signature",
                "state": "ready",
                "status": "ACTIVE",
                "policy_version": "v1",
                "policy_digest": policy_digest,
            }
        )
        transaction.insert_receipt(
            {
                "receipt_id": "receipt-a",
                "request_id": "request-a",
                "key_id": "key-a",
                "policy_version": "v1",
                "policy_digest": policy_digest,
                "machine_digest": machine_digest,
                "lease_id": "lease-a",
                "lineage_id": "lineage-a",
                "subject_id": "agent-a",
                "executor_audience": "executor-a",
                "transition_name": "move",
                "source_state": "ready",
                "target_state": "done",
                "cost": (1, 1),
                "resulting_sequence": 1,
                "nonce": "nonce-a",
                "issued_at_ns": 3,
                "expires_at_ns": 4,
                "signature": b"receipt-signature",
            }
        )
        transaction.update_warden_state(
            free_pool=(50, 16),
            consumed=(1, 1),
            updated_at_ns=3,
        )
        audit = transaction.append_audit(
            "receipt.issued",
            {"receipt_id": "receipt-a"},
            entity_type="receipt",
            entity_id="receipt-a",
            created_at_ns=3,
        )
        assert audit.sequence == 0
        assert transaction.claim_executor_receipt(
            executor_audience="executor-a",
            receipt_id="receipt-a",
            receipt_digest="sha256:" + "3" * 64,
            nonce="nonce-a",
            consumed_at_ns=3,
            expires_at_ns=4,
        )
        assert not transaction.claim_executor_receipt(
            executor_audience="executor-a",
            receipt_id="receipt-a",
            receipt_digest="sha256:" + "3" * 64,
            nonce="nonce-a",
            consumed_at_ns=3,
            expires_at_ns=4,
        )

    with store.read() as transaction:
        policy = transaction.get_policy(active=True)
        lease = transaction.get_lease("lease-a")
        receipt = transaction.get_receipt("receipt-a")
        assert policy is not None and policy["policy_digest"] == policy_digest
        assert lease is not None and lease["residual"] == (9, 3)
        assert receipt is not None and receipt["cost"] == (1, 1)
        assert transaction.audit_sequence() == 0
        assert len(transaction.pending_outbox()) == 1


def test_revocations_are_strictly_monotonic(store: SQLiteStorage) -> None:
    with store.write() as transaction:
        assert transaction.put_revocation(
            lineage_id="lineage-a",
            branch_lease_id="lease-a",
            epoch=1,
            reason="test",
            key_id="key-a",
            issued_at_ns=1,
            observed_at_ns=1,
            source_warden="warden-a",
            signature=b"signature",
            payload={"epoch": 1},
        )
        assert not transaction.put_revocation(
            lineage_id="lineage-a",
            branch_lease_id="lease-a",
            epoch=1,
            reason="test",
            key_id="key-a",
            issued_at_ns=1,
            observed_at_ns=2,
            source_warden="warden-a",
            signature=b"signature",
            payload={"epoch": 1},
        )
        assert transaction.put_revocation(
            lineage_id="lineage-a",
            branch_lease_id="lease-a",
            epoch=2,
            reason="test",
            key_id="key-a",
            issued_at_ns=3,
            observed_at_ns=3,
            source_warden="warden-a",
            signature=b"signature",
            payload={"epoch": 2},
        )


def test_inbound_stream_tracks_gaps_duplicates_and_window(store: SQLiteStorage) -> None:
    def digest(sequence: int) -> str:
        return "sha256:" + f"{sequence:064x}"

    with store.write() as transaction:
        assert transaction.record_inbound_ack(
            transfer_id="transfer-2",
            source_warden="warden-b",
            sequence=2,
            transfer_digest=digest(2),
            contiguous_watermark=0,
            key_id="key-b",
            ack_payload=b"ack-2",
            signature=b"signature",
            accepted_at_ns=2,
        )
        gap = transaction.scalar(
            "SELECT sequence FROM inbound_transfer_gaps WHERE source_warden = 'warden-b'"
        )
        assert gap == 2
        assert transaction.record_inbound_ack(
            transfer_id="transfer-1",
            source_warden="warden-b",
            sequence=1,
            transfer_digest=digest(1),
            contiguous_watermark=2,
            key_id="key-b",
            ack_payload=b"ack-1",
            signature=b"signature",
            accepted_at_ns=3,
        )
        assert not transaction.record_inbound_ack(
            transfer_id="transfer-2",
            source_warden="warden-b",
            sequence=2,
            transfer_digest=digest(2),
            contiguous_watermark=2,
            key_id="key-b",
            ack_payload=b"ack-2",
            signature=b"signature",
            accepted_at_ns=4,
        )
        stream = transaction.fetch_one(
            "SELECT contiguous_through FROM inbound_transfer_streams WHERE source_warden = ?",
            ("warden-b",),
        )
        assert stream is not None and stream["contiguous_through"] == 2
        assert (
            transaction.compact_inbound_stream(
                "warden-b", through=2, checkpoint_payload=b"checkpoint-2", updated_at_ns=4
            )
            == 2
        )
        assert transaction.scalar("SELECT COUNT(*) FROM inbound_transfer_acks") == 0
        with pytest.raises(ValidationError, match="gap window"):
            transaction.record_inbound_ack(
                transfer_id="transfer-20",
                source_warden="warden-b",
                sequence=20,
                transfer_digest=digest(20),
                contiguous_watermark=None,
                key_id="key-b",
                ack_payload=b"ack-20",
                signature=b"signature",
                accepted_at_ns=5,
            )


def test_outgoing_transfer_persists_exact_signed_payload(store: SQLiteStorage) -> None:
    with store.write() as transaction:
        transaction.insert_policy(
            policy_version="v1",
            policy_digest="digest-1",
            machine_digest="machine-1",
            payload={},
            created_at_ns=1,
        )
        sequence = transaction.allocate_outgoing_sequence("warden-b", updated_at_ns=2)
        assert sequence == 1
        transaction.insert_outgoing_transfer(
            transfer_id="transfer-1",
            target_warden="warden-b",
            sequence=sequence,
            amount=(3, 2),
            policy_version="v1",
            policy_digest="digest-1",
            digest="voucher-digest",
            key_id="key-a",
            signature=b"signature",
            voucher_payload=b'{"type":"lets.transfer-voucher/v1"}',
            prepared_at_ns=2,
        )
        transaction.update_warden_state(
            free_pool=(57, 18),
            transferred_out=(3, 2),
            updated_at_ns=2,
        )
        row = transaction.fetch_one(
            "SELECT * FROM outgoing_transfers WHERE transfer_id = ?", ("transfer-1",)
        )
        assert row is not None
        assert row["source_warden"] == "warden-a"
        assert row["key_id"] == "key-a"
        assert row["voucher_payload"] == b'{"type":"lets.transfer-voucher/v1"}'
        assert transaction.acknowledge_outgoing_transfer(
            "warden-b", 1, acknowledged_at_ns=3, ack_payload=b"ack"
        )
        assert (
            transaction.compact_outgoing_stream(
                "warden-b", through=1, checkpoint_payload=b"checkpoint-1", updated_at_ns=4
            )
            == 1
        )
        assert transaction.scalar("SELECT COUNT(*) FROM outgoing_transfers") == 0


def test_concurrent_writers_are_serialized(tmp_path: Path) -> None:
    storage = SQLiteStorage.initialize(
        tmp_path / "concurrent.db",
        "warden-a",
        (100,),
        signing_key_id=_SIGNING_KEY_ID,
        signing_public_key=_SIGNING_PUBLIC_KEY,
        busy_timeout_ms=20_000,
    )

    def increment() -> None:
        for _ in range(15):
            with storage.write() as transaction:
                transaction.connection.execute(
                    "UPDATE warden_state SET revision = revision + 1, updated_at_ns = 1"
                )

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(increment) for _ in range(4)]
        for future in futures:
            future.result()

    with storage.read() as transaction:
        assert transaction.get_warden_state()["revision"] == 60
    storage.close()


def test_inconsistent_raw_write_is_rolled_back_at_commit(store: SQLiteStorage) -> None:
    with pytest.raises(InvariantError, match="conservation"), store.write() as transaction:
        transaction.connection.execute(
            """
            UPDATE warden_state SET free_pool = ?
            WHERE tenant_id = ? AND envelope_id = ?
            """,
            (pack((61, 20)), *transaction.scope),
        )

    with store.read() as transaction:
        state = transaction.get_warden_state()
        assert state["free_pool"] == (60, 20)
        assert state["lease_residual"] == (0, 0)
    assert store.verify_conservation()


def test_raw_policy_fk_cannot_mix_version_and_digest(store: SQLiteStorage) -> None:
    with store.write() as transaction:
        transaction.insert_policy(
            policy_version="v1",
            policy_digest="digest-1",
            machine_digest="machine-1",
            payload={},
            created_at_ns=1,
        )
        transaction.insert_policy(
            policy_version="v2",
            policy_digest="digest-2",
            machine_digest="machine-2",
            payload={},
            created_at_ns=1,
        )
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            transaction.connection.execute(
                """
                INSERT INTO leases(
                    tenant_id, envelope_id, lease_id, lineage_id, parent_id, subject_id,
                    warden_id, allocation, residual, capabilities_json, machine_digest,
                    ancestor_path_json, branch_epoch, config_epoch, issued_at_ns, expires_at_ns,
                    key_id, signature, state, status, sequence, policy_version, policy_digest,
                    created_at_ns, updated_at_ns
                ) VALUES (?, ?, 'lease', 'lineage', NULL, 'subject', 'warden-a', ?, ?,
                          X'5B5D', 'machine-1', X'5B5D', 0, 3, 1, 2, 'key', X'01',
                          'ready', 'ACTIVE', 0, 'v1', 'digest-2', 1, 1)
                """,
                (*transaction.scope, pack((1, 1)), pack((1, 1))),
            )
