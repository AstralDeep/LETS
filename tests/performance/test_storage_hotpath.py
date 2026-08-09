from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import StorageError
from lets.models import IdentityContext
from lets.service import WardenService
from lets.storage import SQLiteStorage

POLICY_DIGEST = "sha256:" + "1" * 64
MACHINE_DIGEST = "sha256:" + "2" * 64


def _store(path: Path, *, budget: int = 10) -> tuple[SQLiteStorage, Ed25519Signer]:
    signer = Ed25519Signer.generate("warden-performance")
    store = SQLiteStorage.initialize(
        path,
        signer.warden_id,
        (budget,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        initial_local_share=(budget,),
    )
    return store, signer


def _insert_policy(transaction: object) -> None:
    transaction.insert_policy(  # type: ignore[attr-defined]
        policy_version="v1",
        policy_digest=POLICY_DIGEST,
        machine_digest=MACHINE_DIGEST,
        payload={"policy_id": "performance-policy"},
        active=True,
        created_at_ns=1,
    )


def _insert_lease(
    transaction: object,
    signer: Ed25519Signer,
    lease_id: str,
    *,
    parent_id: str | None = None,
) -> None:
    transaction.insert_lease(  # type: ignore[attr-defined]
        {
            "lease_id": lease_id,
            "lineage_id": f"lineage-{lease_id}",
            "parent_id": parent_id,
            "subject_id": "agent",
            "allocation": (1,),
            "residual": (1,),
            "capabilities": ("step",),
            "machine_digest": MACHINE_DIGEST,
            "ancestor_path": (),
            "issued_at_ns": 2,
            "expires_at_ns": 100_000,
            "key_id": signer.key_id,
            "signature": b"signature",
            "state": "ready",
            "status": "ACTIVE",
            "policy_version": "v1",
            "policy_digest": POLICY_DIGEST,
        }
    )


def test_write_hot_path_uses_sqlite_enforcement_without_full_fk_scan(tmp_path: Path) -> None:
    store, _ = _store(tmp_path / "hotpath.sqlite3")
    statements: list[str] = []
    try:
        with store.write() as transaction:
            transaction.connection.set_trace_callback(statements.append)
            assert transaction.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            transaction.update_warden_state(updated_at_ns=2)
    finally:
        store.close()

    normalized = {" ".join(statement.upper().split()) for statement in statements}
    assert "PRAGMA FOREIGN_KEY_CHECK" not in normalized


def test_deferred_foreign_key_is_still_rejected_atomically_at_commit(tmp_path: Path) -> None:
    store, signer = _store(tmp_path / "deferred.sqlite3")
    try:
        with store.write() as transaction:
            _insert_policy(transaction)

        with (
            pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"),
            store.write() as transaction,
        ):
            _insert_lease(transaction, signer, "child", parent_id="missing-parent")
            transaction.update_warden_state(free_pool=(9,), updated_at_ns=2)

        with store.read() as transaction:
            assert transaction.get_lease("child") is None
            assert transaction.get_warden_state()["free_pool"] == (10,)
    finally:
        store.close()


def test_startup_full_fk_check_rejects_offline_corruption(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.sqlite3"
    store, signer = _store(path)
    with store.write() as transaction:
        _insert_policy(transaction)
        _insert_lease(transaction, signer, "root")
        transaction.update_warden_state(free_pool=(9,), updated_at_ns=2)
    store.close()

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 0
        connection.execute("DELETE FROM policies")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(StorageError, match="foreign-key integrity"):
        SQLiteStorage(
            path,
            signer.warden_id,
            (10,),
            signing_key_id=signer.key_id,
            signing_public_key=signer.public_key_bytes,
            tenant_id="tenant",
            envelope_id="envelope",
            initial_local_share=(10,),
        )


def test_invariant_snapshot_reads_trigger_maintained_aggregate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, signer = _store(tmp_path / "aggregate.sqlite3", budget=3)
    with store.write() as transaction:
        _insert_policy(transaction)
        for index in range(3):
            _insert_lease(transaction, signer, f"lease-{index}")
        transaction.update_warden_state(free_pool=(0,), updated_at_ns=2)
    registry = PublicKeyRegistry()
    registry.register_signer(signer)
    service = WardenService(
        store,
        signer=signer,
        clock=ManualClock(100),
        trust_registry=registry,
    )
    statements: list[str] = []
    original_connect = store._connect

    def traced_connect(*, set_wal: bool = False) -> sqlite3.Connection:
        connection = original_connect(set_wal=set_wal)
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(store, "_connect", traced_connect)
    try:
        snapshot = service.invariant_snapshot(
            identity=IdentityContext("auditor", "tenant", frozenset())
        )
    finally:
        store.close()

    assert snapshot.healthy
    assert snapshot.lease_residual == (3,)
    normalized = [" ".join(statement.upper().split()) for statement in statements]
    assert not any("SELECT RESIDUAL FROM LEASES" in statement for statement in normalized)
