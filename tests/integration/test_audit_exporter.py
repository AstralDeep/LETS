from __future__ import annotations

from pathlib import Path

import pytest

from lets.audit import AuditExporter, AuditExportRecord, SQLiteAuditSink
from lets.errors import ConflictError, StorageError
from lets.storage import SQLiteStorage

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
    record = AuditExportRecord(
        warden_id="warden-a",
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        sequence=0,
        event_hash=b"h" * 32,
        payload=b'{"event":"one"}',
        created_at_ns=1,
    )
    sink.publish(record)
    sink.publish(record)
    assert sink.count() == 1
    conflicting = AuditExportRecord(
        warden_id="warden-a",
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        sequence=0,
        event_hash=b"x" * 32,
        payload=b'{"event":"two"}',
        created_at_ns=1,
    )
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


def test_export_bookkeeping_uses_the_reserved_capacity_recovery_lane(tmp_path: Path) -> None:
    path = tmp_path / "warden.sqlite3"
    initial = SQLiteStorage.initialize(path, "warden-a", (10,), **_options())
    _events(initial, 1)
    initial.close()
    limited = SQLiteStorage(
        path,
        "warden-a",
        (10,),
        max_database_bytes=1,
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
