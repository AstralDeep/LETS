from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from contextlib import suppress
from pathlib import Path
from typing import NamedTuple

import pytest

import lets.storage.sqlite as sqlite_module
from lets.errors import CapacityError, StorageError
from lets.storage import SQLiteStorage


def _crash_process(database: str, *, commit: bool) -> subprocess.CompletedProcess[str]:
    operation = "context.__exit__(None, None, None)" if commit else "pass"
    code = f"""
import os
import sys
from lets.storage import SQLiteStorage

store = SQLiteStorage(
    sys.argv[1], 'warden-a', (10,),
    signing_key_id='test-key', signing_public_key=bytes(range(32)),
    tenant_id='tenant', envelope_id='envelope',
)
context = store.write()
transaction = context.__enter__()
transaction.put_idempotency(
    scope='crash', request_id={"committed" if commit else "uncommitted"!r},
    fingerprint=b'fingerprint', response=b'response', status_code=200, created_at_ns=1,
)
{operation}
os._exit(23)
"""
    return subprocess.run(
        [sys.executable, "-c", code, database],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )


def test_crash_reopen_discards_uncommitted_and_preserves_committed(tmp_path: Path) -> None:
    path = tmp_path / "crash.db"
    initial = SQLiteStorage.initialize(
        path,
        "warden-a",
        (10,),
        signing_key_id="test-key",
        signing_public_key=bytes(range(32)),
        tenant_id="tenant",
        envelope_id="envelope",
    )
    initial.close()

    crashed = _crash_process(str(path), commit=False)
    assert crashed.returncode == 23, crashed.stderr
    reopened = SQLiteStorage(
        path,
        "warden-a",
        (10,),
        signing_key_id="test-key",
        signing_public_key=bytes(range(32)),
        tenant_id="tenant",
        envelope_id="envelope",
    )
    with reopened.read() as transaction:
        assert transaction.get_idempotency("crash", "uncommitted") is None
    reopened.close()

    crashed_after_commit = _crash_process(str(path), commit=True)
    assert crashed_after_commit.returncode == 23, crashed_after_commit.stderr
    recovered = SQLiteStorage(
        path,
        "warden-a",
        (10,),
        signing_key_id="test-key",
        signing_public_key=bytes(range(32)),
        tenant_id="tenant",
        envelope_id="envelope",
    )
    assert recovered.metadata.warden_id == "warden-a"
    with recovered.read() as transaction:
        assert transaction.get_idempotency("crash", "committed") is not None
    assert recovered.pragma_integrity_check() == ("ok",)
    recovered.close()


def test_reopen_refuses_incomplete_versioned_schema(tmp_path: Path) -> None:
    path = tmp_path / "damaged.db"
    store = SQLiteStorage.initialize(
        path,
        "warden-a",
        (10,),
        signing_key_id="test-key",
        signing_public_key=bytes(range(32)),
    )
    store.close()

    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP INDEX ix_leases_expiry")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(StorageError, match="incomplete SQLite schema"):
        SQLiteStorage(
            path,
            "warden-a",
            (10,),
            signing_key_id="test-key",
            signing_public_key=bytes(range(32)),
        )


def test_sqlite_full_rolls_back_atomically_and_sticks_readiness_false(tmp_path: Path) -> None:
    path = tmp_path / "full.db"
    options = {
        "signing_key_id": "test-key",
        "signing_public_key": bytes(range(32)),
        "tenant_id": "tenant",
        "envelope_id": "envelope",
        "reserve_pages": 1,
    }
    store = SQLiteStorage.initialize(path, "warden-a", (10,), **options)
    try:
        with (
            pytest.raises(CapacityError, match="capacity limit"),
            store.write() as transaction,
        ):
            page_count = int(transaction.execute("PRAGMA page_count").fetchone()[0])
            selected = int(
                transaction.execute(f"PRAGMA max_page_count={page_count + 1}").fetchone()[0]
            )
            assert selected == page_count + 1
            transaction.put_idempotency(
                scope="capacity",
                request_id="oversized-write",
                fingerprint=b"fingerprint",
                response=b"x" * (1024 * 1024),
                status_code=200,
                created_at_ns=1,
            )
        with store.read() as transaction:
            assert transaction.get_idempotency("capacity", "oversized-write") is None
        faulted = store.capacity_snapshot()
        assert faulted.prior_full_error
        assert not faulted.healthy

        recovered = store.clear_capacity_fault()
        assert recovered.healthy
        assert store.pragma_integrity_check() == ("ok",)
        assert store.verify_conservation()
    finally:
        store.close()


def test_recovery_deletion_restores_capacity_by_crediting_reusable_pages(tmp_path: Path) -> None:
    path = tmp_path / "capacity-gc.db"
    options = {
        "signing_key_id": "test-key",
        "signing_public_key": bytes(range(32)),
        "tenant_id": "tenant",
        "envelope_id": "envelope",
    }
    initial = SQLiteStorage.initialize(path, "warden-a", (10,), **options)
    for index in range(500):
        with initial.write() as transaction:
            transaction.put_idempotency(
                scope="capacity-gc",
                request_id=f"request-{index}",
                fingerprint=b"fingerprint",
                response=b"x" * 4096,
                status_code=200,
                created_at_ns=index,
            )
    before = initial.capacity_snapshot()
    initial.close()

    reserve_pages = 8
    limit = before.effective_database_bytes + (reserve_pages // 2) * before.page_size
    limited = SQLiteStorage(
        path,
        "warden-a",
        (10,),
        max_database_bytes=limit,
        reserve_pages=reserve_pages,
        **options,
    )
    try:
        assert not limited.capacity_snapshot().healthy
        with pytest.raises(CapacityError), limited.write():
            pass
        with limited.capacity_recovery() as transaction:
            transaction.execute("DELETE FROM idempotency WHERE scope='capacity-gc'")
        limited.checkpoint(truncate=True)
        recovered = limited.capacity_snapshot()
        assert recovered.reusable_bytes > 0
        assert recovered.effective_database_bytes < before.effective_database_bytes
        assert recovered.healthy
        with limited.write() as transaction:
            transaction.put_idempotency(
                scope="capacity-gc",
                request_id="post-recovery",
                fingerprint=b"fingerprint",
                response=b"ok",
                status_code=200,
                created_at_ns=1_000,
            )
    finally:
        limited.close()


@pytest.mark.parametrize("recovery_lane", [False, True])
def test_one_transaction_cannot_overshoot_database_capacity_limit(
    tmp_path: Path, recovery_lane: bool
) -> None:
    path = tmp_path / f"overshoot-{recovery_lane}.db"
    options = {
        "signing_key_id": "test-key",
        "signing_public_key": bytes(range(32)),
        "tenant_id": "tenant",
        "envelope_id": "envelope",
        "reserve_pages": 1,
    }
    initialized = SQLiteStorage.initialize(path, "warden-a", (10,), **options)
    baseline = initialized.capacity_snapshot()
    initialized.close()
    limit = baseline.effective_database_bytes + 16 * baseline.page_size
    store = SQLiteStorage(
        path,
        "warden-a",
        (10,),
        max_database_bytes=limit,
        **options,
    )
    transaction_context = store.capacity_recovery if recovery_lane else store.write
    try:
        with pytest.raises(CapacityError), transaction_context() as transaction:
            transaction.put_idempotency(
                scope="capacity-overshoot",
                request_id="huge-response",
                fingerprint=b"fingerprint",
                response=b"x" * (1024 * 1024),
                status_code=200,
                created_at_ns=1,
            )
        with store.read() as transaction:
            assert transaction.get_idempotency("capacity-overshoot", "huge-response") is None
        assert store.capacity_snapshot().effective_database_bytes <= limit
    finally:
        store.close()


def test_every_connection_caps_main_pages_and_reserves_a_pinned_wal_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "wal-reserve.db"
    options = {
        "signing_key_id": "test-key",
        "signing_public_key": bytes(range(32)),
        "tenant_id": "tenant",
        "envelope_id": "envelope",
        "reserve_pages": 1,
    }
    initialized = SQLiteStorage.initialize(path, "warden-a", (10,), **options)
    baseline = initialized.capacity_snapshot()
    initialized.close()
    configured_pages = baseline.page_count + 32
    logical_limit = configured_pages * baseline.page_size
    store = SQLiteStorage(
        path,
        "warden-a",
        (10,),
        max_database_bytes=logical_limit,
        min_free_disk_bytes=1,
        **options,
    )

    class _Usage(NamedTuple):
        total: int
        used: int
        free: int

    try:
        store.checkpoint(truncate=True)
        snapshot = store.capacity_snapshot()
        assert snapshot.max_page_count == configured_pages
        with store.read() as transaction:
            assert int(transaction.execute("PRAGMA max_page_count").fetchone()[0]) == (
                configured_pages
            )

        reader = sqlite3.connect(path)
        try:
            reader.execute("BEGIN")
            reader.execute("SELECT COUNT(*) FROM idempotency").fetchone()
            initial_wal_bytes = 0
            with suppress(OSError):
                initial_wal_bytes = os.path.getsize(f"{path}-wal")

            def constrained_usage(_path: object) -> _Usage:
                wal_bytes = 0
                shared_memory_bytes = 0
                with suppress(OSError):
                    wal_bytes = os.path.getsize(f"{path}-wal")
                with suppress(OSError):
                    shared_memory_bytes = os.path.getsize(f"{path}-shm")
                frame_bytes = snapshot.page_size + 24
                existing_frames = (
                    0 if wal_bytes <= 32 else (wal_bytes - 32 + frame_bytes - 1) // frame_bytes
                )
                future_frames = existing_frames + configured_pages
                extra_frames = max(0, future_frames - 4_062)
                worst_shm = (1 + (extra_frames + 4_095) // 4_096) * 32_768
                required = (
                    1
                    + snapshot.remaining_main_growth_bytes
                    + snapshot.worst_case_transaction_wal_bytes
                    + max(0, worst_shm - shared_memory_bytes)
                )
                new_wal_bytes = max(0, wal_bytes - initial_wal_bytes)
                free = max(1, required + snapshot.page_size - new_wal_bytes)
                return _Usage(total=10 * required, used=0, free=free)

            monkeypatch.setattr(sqlite_module.shutil, "disk_usage", constrained_usage)
            with store.write() as transaction:
                transaction.put_idempotency(
                    scope="wal-reserve",
                    request_id="first",
                    fingerprint=b"fingerprint",
                    response=b"response",
                    status_code=200,
                    created_at_ns=1,
                )
            after_first = store.capacity_snapshot()
            assert after_first.wal_bytes > 0
            assert after_first.filesystem_free_bytes is not None
            assert after_first.filesystem_free_bytes >= after_first.min_free_disk_bytes
            assert not after_first.healthy
            with pytest.raises(CapacityError, match="reserve is exhausted"), store.write():
                pass
        finally:
            reader.rollback()
            reader.close()

        store.checkpoint(truncate=True)
        assert store.capacity_snapshot().healthy
        with store.write() as transaction:
            transaction.put_idempotency(
                scope="wal-reserve",
                request_id="second",
                fingerprint=b"fingerprint",
                response=b"response",
                status_code=200,
                created_at_ns=2,
            )
    finally:
        store.close()


def test_capacity_reserves_checkpoint_main_growth_and_wal_index_together(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "checkpoint-reserve.db"
    options = {
        "signing_key_id": "test-key",
        "signing_public_key": bytes(range(32)),
        "tenant_id": "tenant",
        "envelope_id": "envelope",
        "reserve_pages": 1,
    }
    initialized = SQLiteStorage.initialize(path, "warden-a", (10,), **options)
    baseline = initialized.capacity_snapshot()
    initialized.close()
    configured_pages = baseline.page_count + 64
    store = SQLiteStorage(
        path,
        "warden-a",
        (10,),
        max_database_bytes=configured_pages * baseline.page_size,
        min_free_disk_bytes=1,
        **options,
    )

    class _Usage(NamedTuple):
        total: int
        used: int
        free: int

    try:
        snapshot = store.capacity_snapshot()
        assert snapshot.remaining_main_growth_bytes == (
            configured_pages * snapshot.page_size - snapshot.main_database_bytes
        )
        assert snapshot.worst_case_shared_memory_bytes >= 32_768
        assert snapshot.required_filesystem_free_bytes == (
            snapshot.min_free_disk_bytes
            + snapshot.remaining_main_growth_bytes
            + snapshot.worst_case_transaction_wal_bytes
            + snapshot.additional_shared_memory_bytes
        )
        monkeypatch.setattr(
            sqlite_module.shutil,
            "disk_usage",
            lambda _path: _Usage(
                total=10 * snapshot.required_filesystem_free_bytes,
                used=0,
                free=snapshot.required_filesystem_free_bytes - 1,
            ),
        )
        assert not store.capacity_snapshot().healthy
        with pytest.raises(CapacityError, match="reserve is exhausted"), store.write():
            pass
    finally:
        store.close()
