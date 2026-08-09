from __future__ import annotations

import shutil
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path

import pytest

from lets.audit import AuditArchiveHead, AuditExporter, AuditExportRecord, SQLiteAuditSink
from lets.errors import ConflictError, StorageError
from lets.storage import SQLiteStorage, audit_event_hash

_KEY_ID = "warden-a-key"
_PUBLIC_KEY = bytes(range(32))


def _options() -> dict[str, object]:
    return {
        "signing_key_id": _KEY_ID,
        "signing_public_key": _PUBLIC_KEY,
        "tenant_id": "tenant-a",
        "envelope_id": "envelope-a",
        "initial_local_share": (10,),
    }


def _events(store: SQLiteStorage, count: int) -> None:
    for sequence in range(count):
        with store.write() as transaction:
            transaction.append_audit(
                "test.event",
                {"ordinal": sequence},
                entity_type="test",
                entity_id=f"event-{sequence}",
                created_at_ns=sequence,
            )


def _export_record(
    *,
    sequence: int = 0,
    previous_hash: bytes = bytes(32),
    payload: bytes = b'{"event":"one"}',
    config_epoch: int = 1,
    database_instance_id: bytes = b"i" * 32,
) -> AuditExportRecord:
    event_type = "test.event"
    created_at_ns = sequence + 1
    return AuditExportRecord(
        warden_id="warden-a",
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=config_epoch,
        database_instance_id=database_instance_id,
        sequence=sequence,
        event_type=event_type,
        entity_type="test",
        entity_id=f"event-{sequence}",
        previous_hash=previous_hash,
        event_hash=audit_event_hash(
            previous_hash,
            sequence,
            event_type,
            "test",
            f"event-{sequence}",
            payload,
            created_at_ns,
        ),
        payload=payload,
        created_at_ns=created_at_ns,
    )


def test_exporter_is_idempotent_and_bounds_published_outbox_rows(tmp_path: Path) -> None:
    store = SQLiteStorage.initialize(tmp_path / "warden.sqlite3", "warden-a", (10,), **_options())
    sink = SQLiteAuditSink.initialize(tmp_path / "archive.sqlite3")
    try:
        _events(store, 20)
        exporter = AuditExporter(store, sink, batch_size=64, retain_published=3)
        assert exporter.run_once() == 20
        assert exporter.run_once() == 0
        assert sink.count() == 20
        with store.read() as transaction:
            pending = transaction.connection.execute(
                "SELECT COUNT(*) FROM audit_outbox WHERE published_at_ns IS NULL"
            ).fetchone()[0]
            retained = transaction.connection.execute(
                "SELECT COUNT(*) FROM audit_outbox"
            ).fetchone()[0]
        assert pending == 0
        assert retained == 3

        reopened = SQLiteAuditSink(sink.path)
        assert reopened.count() == 20
    finally:
        store.close()


def test_sink_replay_is_idempotent_but_conflicting_sequence_fails(tmp_path: Path) -> None:
    sink = SQLiteAuditSink.initialize(tmp_path / "archive.sqlite3")
    record = _export_record()
    sink.publish(record)
    sink.publish(record)
    assert sink.count() == 1
    conflicting = _export_record(payload=b'{"event":"two"}')
    with pytest.raises(ConflictError, match="different content"):
        sink.publish(conflicting)


def test_export_failure_leaves_outbox_pending_for_retry(tmp_path: Path) -> None:
    class FailOnceSink:
        def __init__(self, delegate: SQLiteAuditSink) -> None:
            self.delegate = delegate
            self.failed = False

        def publish(self, record: AuditExportRecord) -> None:
            if not self.failed:
                self.failed = True
                raise StorageError("injected archive outage")
            self.delegate.publish(record)

        def head(self, **identity: object) -> AuditArchiveHead | None:
            return self.delegate.head(**identity)  # type: ignore[arg-type]

    store = SQLiteStorage.initialize(tmp_path / "warden.sqlite3", "warden-a", (10,), **_options())
    archive = SQLiteAuditSink.initialize(tmp_path / "archive.sqlite3")
    try:
        _events(store, 2)
        exporter = AuditExporter(store, FailOnceSink(archive), retain_published=0)
        assert exporter.run_once() == 0
        assert "injected archive outage" in str(exporter.status()["last_error"])
        with store.read() as transaction:
            assert (
                transaction.connection.execute(
                    "SELECT COUNT(*) FROM audit_outbox WHERE published_at_ns IS NULL"
                ).fetchone()[0]
                == 2
            )
        assert exporter.run_once() == 2
        assert archive.count() == 2
        with store.read() as transaction:
            assert (
                transaction.connection.execute("SELECT COUNT(*) FROM audit_outbox").fetchone()[0]
                == 0
            )
    finally:
        store.close()


def test_exporter_repairs_crash_after_sink_commit_before_local_ack(tmp_path: Path) -> None:
    class CrashAfterPublish(AuditExporter):
        def _acknowledge(self, _record: AuditExportRecord) -> None:
            raise StorageError("injected crash after sink commit")

    store = SQLiteStorage.initialize(tmp_path / "warden.sqlite3", "warden-a", (10,), **_options())
    archive = SQLiteAuditSink.initialize(tmp_path / "archive.sqlite3")
    try:
        _events(store, 1)
        failed = CrashAfterPublish(store, archive, retain_published=0)
        assert failed.run_once() == 0
        assert archive.count() == 1
        with store.read() as transaction:
            pending = transaction.connection.execute(
                "SELECT COUNT(*) FROM audit_outbox WHERE published_at_ns IS NULL"
            ).fetchone()[0]
        assert pending == 1

        recovered = AuditExporter(store, archive, retain_published=0)
        assert recovered.run_once() == 0
        with store.read() as transaction:
            assert (
                transaction.connection.execute("SELECT COUNT(*) FROM audit_outbox").fetchone()[0]
                == 0
            )
    finally:
        store.close()


def test_archive_prefix_repair_is_bounded_and_converges(tmp_path: Path) -> None:
    class LoseAllAcknowledgements(AuditExporter):
        def _acknowledge(self, _record: AuditExportRecord) -> None:
            return

    store = SQLiteStorage.initialize(tmp_path / "warden.sqlite3", "warden-a", (10,), **_options())
    archive = SQLiteAuditSink.initialize(tmp_path / "archive.sqlite3")
    try:
        _events(store, 10)
        failed = LoseAllAcknowledgements(store, archive, batch_size=16, retain_published=0)
        assert failed.run_once() == 10
        assert archive.count() == 10

        recovered = AuditExporter(store, archive, batch_size=3, retain_published=0)
        prior_pending = 10
        prior_total = 10
        for _ in range(8):
            assert recovered.run_once() == 0
            with store.read() as transaction:
                pending = int(
                    transaction.connection.execute(
                        "SELECT COUNT(*) FROM audit_outbox WHERE published_at_ns IS NULL"
                    ).fetchone()[0]
                )
                total = int(
                    transaction.connection.execute("SELECT COUNT(*) FROM audit_outbox").fetchone()[
                        0
                    ]
                )
            assert (prior_pending - pending) + (prior_total - total) <= 3
            prior_pending = pending
            prior_total = total
            if total:
                assert not recovered.status()["archive_reconciled"]
            else:
                break

        assert prior_total == 0
        assert recovered.status()["archive_reconciled"]
    finally:
        store.close()


def test_export_bookkeeping_uses_the_reserved_capacity_recovery_lane(tmp_path: Path) -> None:
    path = tmp_path / "warden.sqlite3"
    initial = SQLiteStorage.initialize(path, "warden-a", (10,), **_options())
    _events(initial, 1)
    capacity = initial.capacity_snapshot()
    initial.close()
    reserve_pages = 8
    limited = SQLiteStorage(
        path,
        "warden-a",
        (10,),
        max_database_bytes=(
            capacity.effective_database_bytes + (reserve_pages // 2) * capacity.page_size
        ),
        reserve_pages=reserve_pages,
        **_options(),
    )
    archive = SQLiteAuditSink.initialize(tmp_path / "archive.sqlite3")
    try:
        assert not limited.capacity_snapshot().healthy
        exporter = AuditExporter(limited, archive, retain_published=0)
        assert exporter.run_once() == 1
        assert archive.count() == 1
        with limited.read() as transaction:
            assert (
                transaction.connection.execute("SELECT COUNT(*) FROM audit_outbox").fetchone()[0]
                == 0
            )
    finally:
        limited.close()


def test_hung_sink_fails_readiness_status_and_cannot_block_exporter_shutdown(
    tmp_path: Path,
) -> None:
    class HungSink:
        def __init__(self) -> None:
            self.entered = threading.Event()
            self.release = threading.Event()

        def publish(self, _record: AuditExportRecord) -> None:
            self.entered.set()
            self.release.wait(10)

        def head(self, **_identity: object) -> AuditArchiveHead | None:
            return None

    store = SQLiteStorage.initialize(tmp_path / "warden.sqlite3", "warden-a", (10,), **_options())
    sink = HungSink()
    try:
        _events(store, 1)
        exporter = AuditExporter(
            store,
            sink,
            poll_interval_s=0.01,
            publish_timeout_s=0.05,
            max_stall_s=0.05,
        )
        exporter.start()
        assert sink.entered.wait(1)
        deadline = time.monotonic() + 1
        status = exporter.status()
        while status["last_error"] is None and time.monotonic() < deadline:
            time.sleep(0.01)
            status = exporter.status()
        assert not status["healthy"]
        assert status["publish_blocked"]
        assert status["pending"] == 1
        assert "deadline" in str(status["last_error"])
        started = time.monotonic()
        exporter.stop(timeout_s=0.5)
        assert time.monotonic() - started < 0.5
    finally:
        sink.release.set()
        store.close()


def test_exporter_detects_archive_rollback_and_backfills_from_immutable_core_log(
    tmp_path: Path,
) -> None:
    store = SQLiteStorage.initialize(tmp_path / "warden.sqlite3", "warden-a", (10,), **_options())
    archive_path = tmp_path / "archive.sqlite3"
    archive = SQLiteAuditSink.initialize(archive_path)
    stale_path = tmp_path / "archive-stale.sqlite3"
    try:
        _events(store, 5)
        assert AuditExporter(store, archive, retain_published=1).run_once() == 5
        with closing(sqlite3.connect(archive_path)) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        shutil.copy2(archive_path, stale_path)

        _events(store, 15)
        assert AuditExporter(store, archive, retain_published=1).run_once() == 15
        assert archive.count() == 20
        with closing(sqlite3.connect(archive_path)) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        for suffix in ("-wal", "-shm"):
            Path(f"{archive_path}{suffix}").unlink(missing_ok=True)
        shutil.copy2(stale_path, archive_path)

        restored = SQLiteAuditSink(archive_path)
        repair = AuditExporter(store, restored, retain_published=1)
        assert repair.run_once() == 15
        assert restored.count() == 20
        repair.start()
        try:
            deadline = time.monotonic() + 2
            while not repair.status()["healthy"] and time.monotonic() < deadline:
                time.sleep(0.01)
            assert repair.status()["archive_reconciled"]
            assert repair.status()["healthy"]
        finally:
            repair.stop()
    finally:
        store.close()


def test_archive_namespaces_audit_sequences_by_epoch_and_database_instance(
    tmp_path: Path,
) -> None:
    archive = SQLiteAuditSink.initialize(tmp_path / "archive.sqlite3")
    options_one = _options()
    first = SQLiteStorage.initialize(tmp_path / "one.sqlite3", "warden-a", (10,), **options_one)
    try:
        _events(first, 1)
        first_checkpoint = first.authority_checkpoint()
        assert AuditExporter(first, archive).run_once() == 1
    finally:
        first.close()

    options_two = _options()
    options_two["config_epoch"] = 2
    second = SQLiteStorage.initialize(tmp_path / "two.sqlite3", "warden-a", (10,), **options_two)
    try:
        _events(second, 1)
        second_checkpoint = second.authority_checkpoint()
        assert first_checkpoint.database_instance_id != second_checkpoint.database_instance_id
        assert AuditExporter(second, archive).run_once() == 1
        assert archive.count() == 2
        assert (
            archive.head(
                warden_id="warden-a",
                tenant_id="tenant-a",
                envelope_id="envelope-a",
                config_epoch=1,
                database_instance_id=first_checkpoint.database_instance_id,
            )
            is not None
        )
        assert (
            archive.head(
                warden_id="warden-a",
                tenant_id="tenant-a",
                envelope_id="envelope-a",
                config_epoch=2,
                database_instance_id=second_checkpoint.database_instance_id,
            )
            is not None
        )
    finally:
        second.close()
