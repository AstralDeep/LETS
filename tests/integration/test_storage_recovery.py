from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from lets.errors import StorageError
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
