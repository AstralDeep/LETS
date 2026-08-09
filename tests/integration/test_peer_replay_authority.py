from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from lets.authority import AuthorityCheckpoint, FileAuthorityAnchor
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer
from lets.errors import StorageError
from lets.service import WardenService
from lets.storage import SQLiteStorage


def _options(signer: Ed25519Signer, anchor: object) -> dict[str, object]:
    return {
        "signing_key_id": signer.key_id,
        "signing_public_key": signer.public_key_bytes,
        "tenant_id": "tenant-a",
        "envelope_id": "envelope-a",
        "config_epoch": 1,
        "initial_local_share": (10,),
        "receipt_ttl_ns": 1_000,
        "max_clock_uncertainty_ns": 0,
        "transfer_gap_window": 4,
        "authority_anchor": anchor,
    }


def _claim(service: WardenService) -> bool:
    return service.claim_peer_request(
        warden_id="warden-b",
        key_id="warden-b-key",
        nonce="peer-nonce-000000000001",
        timestamp_s=1_800_000_000,
        expires_at_s=1_800_000_030,
        now_s=1_800_000_000,
        clock_tolerance_s=30,
    )


def test_peer_nonce_claim_advances_anchor_and_stale_core_fails_closed(
    tmp_path: Path,
) -> None:
    database = tmp_path / "warden.sqlite3"
    stale = tmp_path / "stale-before-peer-claim.sqlite3"
    anchor_path = tmp_path / "independent" / "authority.json"
    signer = Ed25519Signer.generate("warden-a")
    clock = ManualClock(1_800_000_000_000_000_000, 0)
    store = SQLiteStorage.initialize(
        database,
        signer.warden_id,
        (10,),
        **_options(signer, FileAuthorityAnchor(anchor_path)),
    )
    initial = store.authority_checkpoint()
    store.checkpoint(truncate=True)
    shutil.copy2(database, stale)

    service = WardenService(store, signer=signer, clock=clock)
    assert _claim(service)
    assert not _claim(service)
    claimed = store.authority_checkpoint()
    assert claimed.audit_sequence == initial.audit_sequence + 1
    assert claimed.state_digest != initial.state_digest
    assert service.peer_replay_status()["revision"] == 1
    store.close()

    with pytest.raises(StorageError, match="older than its monotonic authority anchor"):
        SQLiteStorage(
            stale,
            signer.warden_id,
            (10,),
            **_options(signer, FileAuthorityAnchor(anchor_path)),
        )


def test_peer_claim_commit_before_anchor_fails_closed_then_reconciles(
    tmp_path: Path,
) -> None:
    class FailPostCommitOnce:
        def __init__(self, delegate: FileAuthorityAnchor) -> None:
            self.delegate = delegate
            self.calls = 0

        def reconcile(self, checkpoint: AuthorityCheckpoint, **options: Any) -> None:
            self.calls += 1
            # Fail only once the claimed nonce's signed audit record is present,
            # which is necessarily the post-COMMIT anchor CAS.
            if checkpoint.audit_sequence == 0:
                raise StorageError("injected replay-anchor outage")
            self.delegate.reconcile(checkpoint, **options)

        def read_current(self) -> AuthorityCheckpoint:
            return self.delegate.read_current()

    database = tmp_path / "warden.sqlite3"
    durable = FileAuthorityAnchor(tmp_path / "independent" / "authority.json")
    signer = Ed25519Signer.generate("warden-a")
    clock = ManualClock(1_800_000_000_000_000_000, 0)
    failing = FailPostCommitOnce(durable)
    store = SQLiteStorage.initialize(
        database,
        signer.warden_id,
        (10,),
        **_options(signer, failing),
    )
    service = WardenService(store, signer=signer, clock=clock)
    with pytest.raises(StorageError, match="injected replay-anchor outage"):
        _claim(service)
    assert not store.authority_anchor_healthy
    with pytest.raises(StorageError, match="previously faulted"):
        store.authority_checkpoint()
    store.close()

    recovered = SQLiteStorage(
        database,
        signer.warden_id,
        (10,),
        **_options(signer, durable),
    )
    try:
        recovered_service = WardenService(recovered, signer=signer, clock=clock)
        assert recovered_service.peer_replay_status()["revision"] == 1
        assert not _claim(recovered_service)
        assert recovered.verify_authority_anchor()
    finally:
        recovered.close()
