from __future__ import annotations

import shutil
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier, Lock

import pytest

from lets.canonical import b64url_encode, canonical_json
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ReplayError, StorageError, ValidationError
from lets.executor import (
    ExecutorPolicy,
    ReceiptVerifier,
    SQLiteReceiptReplayStore,
    executor_replay_identity,
)
from lets.executor_authority import (
    ExecutorAuthorityCheckpoint,
    ExecutorReplayIdentity,
    FileExecutorAuthorityAnchor,
    ProcessFileExecutorAuthorityAnchor,
)
from lets.models import Receipt

POLICY_DIGEST = "sha256:" + "1" * 64
MACHINE_DIGEST = "sha256:" + "2" * 64
AUDIENCE = "executor-a"
TENANT_ID = "tenant-a"
ENVELOPE_ID = "envelope-a"
CONFIG_EPOCH = 1


def _policy(signer: Ed25519Signer) -> ExecutorPolicy:
    return ExecutorPolicy(
        audience=AUDIENCE,
        tenant_id=TENANT_ID,
        envelope_id=ENVELOPE_ID,
        config_epoch=CONFIG_EPOCH,
        allowed_policy_digests=frozenset({POLICY_DIGEST}),
        allowed_machine_digests=frozenset({MACHINE_DIGEST}),
        trusted_wardens=frozenset({signer.warden_id}),
    )


def _registry(signer: Ed25519Signer) -> PublicKeyRegistry:
    registry = PublicKeyRegistry()
    registry.register_signer(signer)
    return registry


def _identity(signer: Ed25519Signer) -> ExecutorReplayIdentity:
    return executor_replay_identity(_policy(signer), _registry(signer))


def _receipt(
    signer: Ed25519Signer,
    *,
    receipt_id: str,
    nonce: str,
    lease_id: str = "lease-a",
    sequence: int = 1,
) -> Receipt:
    unsigned = Receipt(
        tenant_id=TENANT_ID,
        envelope_id=ENVELOPE_ID,
        config_epoch=CONFIG_EPOCH,
        receipt_id=receipt_id,
        request_id=f"request-{receipt_id}",
        warden_id=signer.warden_id,
        key_id=signer.key_id,
        policy_id="policy-a",
        policy_version="v1",
        policy_digest=POLICY_DIGEST,
        machine_digest=MACHINE_DIGEST,
        lease_id=lease_id,
        lineage_id="lineage-a",
        subject_id="subject-a",
        executor_audience=AUDIENCE,
        transition="run",
        source_state="ready",
        target_state="running",
        cost=(1,),
        resulting_sequence=sequence,
        evidence_digest=None,
        nonce=nonce,
        issued_at_ns=90,
        expires_at_ns=1_000,
    )
    return replace(
        unsigned,
        signature=b64url_encode(signer.sign(canonical_json(unsigned.unsigned_payload()))),
    )


def _verifier(store: SQLiteReceiptReplayStore, signer: Ed25519Signer) -> ReceiptVerifier:
    return ReceiptVerifier(
        _registry(signer),
        store,
        _policy(signer),
        clock=ManualClock(100),
    )


def _replace_database(source: Path, target: Path) -> None:
    for sidecar in (target.with_name(f"{target.name}-wal"), target.with_name(f"{target.name}-shm")):
        sidecar.unlink(missing_ok=True)
    shutil.copy2(source, target)


def test_process_anchor_rejects_stale_preclaim_database_restore(tmp_path: Path) -> None:
    state = tmp_path / "state"
    authority = tmp_path / "authority"
    state.mkdir()
    authority.mkdir()
    database = state / "executor.sqlite3"
    stale = tmp_path / "stale.sqlite3"
    anchor = ProcessFileExecutorAuthorityAnchor(authority / "executor.anchor")
    signer = Ed25519Signer.generate("warden-a")
    try:
        store = SQLiteReceiptReplayStore.initialize(
            database,
            authority_anchor=anchor,
            identity=_identity(signer),
        )
        assert store.checkpoint_wal()[0] == 0
        shutil.copy2(database, stale)

        receipt = _receipt(signer, receipt_id="receipt-a", nonce="nonce-a")
        _verifier(store, signer).verify_and_claim(receipt)
        assert store.status().claim_sequence == 1
        assert anchor.read_current().claim_sequence == 1
        assert store.checkpoint_wal()[0] == 0

        _replace_database(stale, database)
        with pytest.raises(StorageError, match="older than its monotonic authority anchor"):
            SQLiteReceiptReplayStore(database, authority_anchor=anchor)
    finally:
        anchor.close()


class _BarrierAnchor:
    def __init__(self, delegate: FileExecutorAuthorityAnchor) -> None:
        self.delegate = delegate
        self.barrier = Barrier(2)
        self.armed = False

    def reconcile(
        self,
        checkpoint: ExecutorAuthorityCheckpoint,
        *,
        claim_digest_at: Callable[[int], bytes | None],
        initialize: bool = False,
    ) -> None:
        synchronized = self.armed and not initialize and checkpoint.claim_sequence == 0
        if synchronized:
            self.barrier.wait(timeout=5)
        self.delegate.reconcile(
            checkpoint,
            claim_digest_at=claim_digest_at,
            initialize=initialize,
        )
        if synchronized:
            self.barrier.wait(timeout=5)

    def read_current(self) -> ExecutorAuthorityCheckpoint:
        return self.delegate.read_current()


def test_concurrent_cloned_databases_have_one_external_cas_winner(tmp_path: Path) -> None:
    authority = tmp_path / "authority"
    authority.mkdir()
    anchor_path = authority / "executor.anchor"
    anchor = _BarrierAnchor(FileExecutorAuthorityAnchor(anchor_path))
    first_path = tmp_path / "executor-a.sqlite3"
    second_path = tmp_path / "executor-b.sqlite3"
    signer = Ed25519Signer.generate("warden-a")
    first = SQLiteReceiptReplayStore.initialize(
        first_path,
        authority_anchor=anchor,
        identity=_identity(signer),
    )
    first.checkpoint_wal()
    shutil.copy2(first_path, second_path)
    second = SQLiteReceiptReplayStore(second_path, authority_anchor=anchor)
    contenders = (
        (first, _receipt(signer, receipt_id="receipt-a", nonce="nonce-a", lease_id="lease-a")),
        (
            second,
            _receipt(signer, receipt_id="receipt-b", nonce="nonce-b", lease_id="lease-b"),
        ),
    )
    anchor.armed = True

    def claim(item: tuple[SQLiteReceiptReplayStore, Receipt]) -> bool:
        try:
            _verifier(item[0], signer).verify_and_claim(item[1])
        except StorageError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(claim, contenders))
    assert sum(outcomes) == 1
    assert anchor.read_current().claim_sequence == 1

    winner_path = first_path if outcomes[0] else second_path
    loser_path = second_path if outcomes[0] else first_path
    assert SQLiteReceiptReplayStore(
        winner_path, authority_anchor=FileExecutorAuthorityAnchor(anchor_path)
    ).verify_authority_anchor()
    with pytest.raises(StorageError, match="diverges from its authority anchor"):
        SQLiteReceiptReplayStore(
            loser_path,
            authority_anchor=FileExecutorAuthorityAnchor(anchor_path),
        )


class _FailCommittedHeadOnce:
    def __init__(self, delegate: FileExecutorAuthorityAnchor) -> None:
        self.delegate = delegate
        self._lock = Lock()
        self.failed = False

    def reconcile(
        self,
        checkpoint: ExecutorAuthorityCheckpoint,
        *,
        claim_digest_at: Callable[[int], bytes | None],
        initialize: bool = False,
    ) -> None:
        with self._lock:
            if checkpoint.claim_sequence > 0 and not self.failed:
                self.failed = True
                raise StorageError("injected post-commit authority outage")
        self.delegate.reconcile(
            checkpoint,
            claim_digest_at=claim_digest_at,
            initialize=initialize,
        )

    def read_current(self) -> ExecutorAuthorityCheckpoint:
        return self.delegate.read_current()


def test_commit_before_anchor_failure_recovers_claim_without_reauthorizing(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "authority"
    authority.mkdir()
    durable = FileExecutorAuthorityAnchor(authority / "executor.anchor")
    failing = _FailCommittedHeadOnce(durable)
    database = tmp_path / "executor.sqlite3"
    signer = Ed25519Signer.generate("warden-a")
    store = SQLiteReceiptReplayStore.initialize(
        database,
        authority_anchor=failing,
        identity=_identity(signer),
    )
    receipt = _receipt(signer, receipt_id="receipt-a", nonce="nonce-a")

    with pytest.raises(StorageError, match="post-commit authority outage"):
        _verifier(store, signer).verify_and_claim(receipt)
    assert not store.rollback_protected
    assert durable.read_current().claim_sequence == 0

    recovered = SQLiteReceiptReplayStore(database, authority_anchor=durable)
    assert durable.read_current().claim_sequence == 1
    with pytest.raises(ReplayError):
        _verifier(recovered, signer).verify_and_claim(receipt)


def test_anchor_and_policy_identity_are_exact(tmp_path: Path) -> None:
    authority = tmp_path / "authority"
    authority.mkdir()
    anchor_path = authority / "executor.anchor"
    signer = Ed25519Signer.generate("warden-a")
    first = SQLiteReceiptReplayStore.initialize(
        tmp_path / "first.sqlite3",
        authority_anchor=FileExecutorAuthorityAnchor(anchor_path),
        identity=_identity(signer),
    )
    first.checkpoint_wal()
    with pytest.raises(StorageError, match="identity does not match"):
        SQLiteReceiptReplayStore.initialize(
            tmp_path / "different.sqlite3",
            authority_anchor=FileExecutorAuthorityAnchor(anchor_path),
            identity=_identity(signer),
        )

    registry = PublicKeyRegistry()
    registry.register_signer(signer)
    with pytest.raises(ValidationError, match="exactly match"):
        ReceiptVerifier(
            registry,
            first,
            ExecutorPolicy(
                audience=AUDIENCE,
                tenant_id="another-tenant",
                envelope_id=ENVELOPE_ID,
                config_epoch=CONFIG_EPOCH,
            ),
            clock=ManualClock(100),
        )

    widened = replace(
        _policy(signer),
        allowed_machine_digests=frozenset({MACHINE_DIGEST, "sha256:" + "3" * 64}),
    )
    with pytest.raises(ValidationError, match="exactly match"):
        ReceiptVerifier(registry, first, widened, clock=ManualClock(100))

    substituted = Ed25519Signer.generate(signer.warden_id)
    substituted_registry = PublicKeyRegistry()
    substituted_registry.register(
        signer.warden_id,
        signer.key_id,
        substituted.public_key_bytes,
    )
    with pytest.raises(ValidationError, match="exactly match"):
        ReceiptVerifier(
            substituted_registry,
            first,
            _policy(signer),
            clock=ManualClock(100),
        )


def test_unanchored_mode_is_never_implicit(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="allow_unanchored=True only for development"):
        SQLiteReceiptReplayStore.initialize(tmp_path / "executor.sqlite3")

    development = SQLiteReceiptReplayStore.initialize(
        tmp_path / "development.sqlite3",
        allow_unanchored=True,
    )
    assert not development.rollback_protected
    with pytest.raises(StorageError, match="retroactively adopted"):
        authority = tmp_path / "development-authority"
        authority.mkdir()
        SQLiteReceiptReplayStore(
            tmp_path / "development.sqlite3",
            authority_anchor=FileExecutorAuthorityAnchor(authority / "development.anchor"),
        )

    signer = Ed25519Signer.generate("warden-a")
    with pytest.raises(ValidationError, match="require different directories"):
        SQLiteReceiptReplayStore.initialize(
            tmp_path / "collocated.sqlite3",
            authority_anchor=ProcessFileExecutorAuthorityAnchor(tmp_path / "collocated.anchor"),
            identity=_identity(signer),
        )
