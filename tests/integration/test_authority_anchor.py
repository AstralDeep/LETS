from __future__ import annotations

import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

import lets.authority as authority_module
from lets.authority import AuthorityCheckpoint, FileAuthorityAnchor, ProcessFileAuthorityAnchor
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import StorageError
from lets.models import IdentityContext
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage
from lets.vector import pack

_KEY_ID = "warden-a-key"
_PUBLIC_KEY = bytes(range(32))


def _options(anchor: FileAuthorityAnchor | None = None) -> dict[str, object]:
    return {
        "signing_key_id": _KEY_ID,
        "signing_public_key": _PUBLIC_KEY,
        "tenant_id": "tenant-a",
        "envelope_id": "envelope-a",
        "config_epoch": 7,
        "initial_local_share": (10,),
        "authority_anchor": anchor,
    }


def _open(path: Path, anchor: FileAuthorityAnchor | None = None) -> SQLiteStorage:
    return SQLiteStorage(path, "warden-a", (10,), **_options(anchor))


def _consume_one(store: SQLiteStorage, event: str) -> None:
    with store.write() as transaction:
        transaction.execute(
            """
            UPDATE warden_state
            SET free_pool = ?, consumed = ?, revision = revision + 1, updated_at_ns = 10
            WHERE tenant_id = ? AND envelope_id = ?
            """,
            (pack((9,)), pack((1,)), "tenant-a", "envelope-a"),
        )
        transaction.append_audit(event, {"cost": [1]}, created_at_ns=10)


def _policy() -> PolicySpec:
    return PolicySpec(
        policy_id="anchor-policy",
        policy_version="v1",
        dimensions=(ResourceDimension("operations", "count"),),
        machine=MachineSpec(
            machine_id="worker",
            initial_state="ready",
            transitions=(TransitionSpec("act", "ready", "ready", (1,), "worker.act"),),
        ),
        max_lease_ttl_ns=10_000,
        receipt_ttl_ns=100,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=4,
    )


def test_file_anchor_tracks_commits_and_survives_reopen(tmp_path: Path) -> None:
    database = tmp_path / "warden.sqlite3"
    anchor = FileAuthorityAnchor(tmp_path / "monotonic" / "warden.anchor.json")
    store = SQLiteStorage.initialize(
        database,
        "warden-a",
        (10,),
        **_options(anchor),
    )
    initial = store.authority_checkpoint()
    assert initial.audit_sequence == -1
    assert anchor.path.exists()

    _consume_one(store, "consume")
    committed = store.authority_checkpoint()
    assert committed.audit_sequence == 0
    assert committed.state_revision == 1
    assert store.verify_authority_anchor()
    store.close()

    reopened = _open(database, FileAuthorityAnchor(anchor.path))
    try:
        assert reopened.authority_checkpoint() == committed
        assert reopened.authority_anchor_healthy
    finally:
        reopened.close()


def test_process_file_anchor_tracks_commits_and_survives_reopen(tmp_path: Path) -> None:
    database = tmp_path / "warden.sqlite3"
    anchor_path = tmp_path / "monotonic" / "warden.anchor.json"
    anchor = ProcessFileAuthorityAnchor(anchor_path)
    store = SQLiteStorage.initialize(database, "warden-a", (10,), **_options(anchor))
    _consume_one(store, "consume-through-helper")
    committed = store.authority_checkpoint()
    assert store.verify_authority_anchor()
    store.close()

    reopened_anchor = ProcessFileAuthorityAnchor(anchor_path)
    reopened = SQLiteStorage(
        database,
        "warden-a",
        (10,),
        **_options(reopened_anchor),
    )
    try:
        assert reopened.authority_checkpoint() == committed
        assert reopened.authority_anchor_healthy
    finally:
        reopened.close()
        reopened_anchor.close()
        anchor.close()


def test_process_file_anchor_enforces_one_total_io_deadline(tmp_path: Path) -> None:
    anchor = ProcessFileAuthorityAnchor(
        tmp_path / "anchor.json",
        timeout_s=0.05,
        helper_command=(sys.executable, "-c", "import time; time.sleep(10)"),
    )
    checkpoint = AuthorityCheckpoint(
        warden_id="warden-a",
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        schema_version=2,
        signing_key_id=_KEY_ID,
        signing_public_key_sha256=b"k" * 32,
        database_instance_id=b"i" * 32,
        audit_sequence=-1,
        audit_hash=bytes(32),
        state_revision=0,
        state_digest=b"s" * 32,
        clock_floor_ns=None,
    )
    started = time.monotonic()
    with pytest.raises(StorageError, match="exceeded its deadline"):
        anchor.reconcile(checkpoint, audit_hash_at=lambda _sequence: None, initialize=True)
    assert time.monotonic() - started < 1.0


def test_process_file_anchor_cas_allows_only_one_divergent_successor(tmp_path: Path) -> None:
    path = tmp_path / "anchor.json"
    initial = AuthorityCheckpoint(
        warden_id="warden-a",
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        schema_version=2,
        signing_key_id=_KEY_ID,
        signing_public_key_sha256=b"k" * 32,
        database_instance_id=b"i" * 32,
        audit_sequence=-1,
        audit_hash=bytes(32),
        state_revision=0,
        state_digest=b"s" * 32,
        clock_floor_ns=None,
    )
    initializing_anchor = ProcessFileAuthorityAnchor(path)
    initializing_anchor.reconcile(
        initial,
        audit_hash_at=lambda _sequence: None,
        initialize=True,
    )
    initializing_anchor.close()
    successors = (
        AuthorityCheckpoint(
            warden_id="warden-a",
            tenant_id="tenant-a",
            envelope_id="envelope-a",
            config_epoch=1,
            schema_version=2,
            signing_key_id=_KEY_ID,
            signing_public_key_sha256=b"k" * 32,
            database_instance_id=b"i" * 32,
            audit_sequence=0,
            audit_hash=digest * 32,
            state_revision=1,
            state_digest=digest.upper() * 32,
            clock_floor_ns=None,
        )
        for digest in (b"a", b"b")
    )
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    anchors = (ProcessFileAuthorityAnchor(path), ProcessFileAuthorityAnchor(path))

    def contend(candidate: AuthorityCheckpoint, anchor: ProcessFileAuthorityAnchor) -> None:
        barrier.wait(timeout=5)
        try:
            anchor.reconcile(
                candidate,
                audit_hash_at=lambda _sequence: bytes(32),
            )
        except StorageError as exc:
            outcomes.append(f"error:{exc}")
        else:
            outcomes.append("advanced")

    threads = tuple(
        threading.Thread(target=contend, args=(candidate, anchor))
        for candidate, anchor in zip(successors, anchors, strict=True)
    )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert outcomes.count("advanced") == 1
    assert sum("diverges" in outcome for outcome in outcomes) == 1
    for anchor in anchors:
        anchor.close()


def test_external_anchor_rejects_a_stale_but_internally_valid_backup(tmp_path: Path) -> None:
    database = tmp_path / "live.sqlite3"
    stale = tmp_path / "stale.sqlite3"
    anchor_path = tmp_path / "independent-anchor" / "warden.json"
    store = SQLiteStorage.initialize(
        database,
        "warden-a",
        (10,),
        **_options(FileAuthorityAnchor(anchor_path)),
    )
    store.checkpoint(truncate=True)
    store.close()
    shutil.copy2(database, stale)

    live = _open(database, FileAuthorityAnchor(anchor_path))
    _consume_one(live, "effect-authorized")
    assert live.authority_checkpoint().audit_sequence == 0
    live.close()

    # The stale copy remains a valid SQLite/LETS database and opens without the
    # independent witness, which is precisely the rollback hazard being fenced.
    unanchored = _open(stale)
    try:
        assert unanchored.pragma_integrity_check() == ("ok",)
        assert unanchored.authority_checkpoint().audit_sequence == -1
    finally:
        unanchored.close()

    with pytest.raises(StorageError, match="older than its monotonic authority anchor"):
        _open(stale, FileAuthorityAnchor(anchor_path))


def test_anchor_fences_a_second_database_copy_before_its_next_write(tmp_path: Path) -> None:
    original = tmp_path / "original.sqlite3"
    copy_a = tmp_path / "copy-a.sqlite3"
    copy_b = tmp_path / "copy-b.sqlite3"
    anchor_path = tmp_path / "anchor" / "warden.json"
    initialized = SQLiteStorage.initialize(
        original,
        "warden-a",
        (10,),
        **_options(FileAuthorityAnchor(anchor_path)),
    )
    initialized.checkpoint(truncate=True)
    initialized.close()
    shutil.copy2(original, copy_a)
    shutil.copy2(original, copy_b)

    first = _open(copy_a, FileAuthorityAnchor(anchor_path))
    second = _open(copy_b, FileAuthorityAnchor(anchor_path))
    try:
        _consume_one(first, "winning-branch")
        with (
            pytest.raises(StorageError, match="older than its monotonic authority anchor"),
            second.write(),
        ):
            pass
        assert not second.authority_anchor_healthy
    finally:
        first.close()
        second.close()


def test_anchor_rejects_divergence_at_the_same_audit_sequence(tmp_path: Path) -> None:
    anchor = FileAuthorityAnchor(tmp_path / "anchor.json")
    checkpoint = AuthorityCheckpoint(
        warden_id="warden-a",
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        schema_version=2,
        signing_key_id=_KEY_ID,
        signing_public_key_sha256=b"k" * 32,
        database_instance_id=b"i" * 32,
        audit_sequence=0,
        audit_hash=b"a" * 32,
        state_revision=1,
        state_digest=b"b" * 32,
        clock_floor_ns=None,
    )
    anchor.reconcile(checkpoint, audit_hash_at=lambda _sequence: None, initialize=True)
    divergent = AuthorityCheckpoint(
        warden_id="warden-a",
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        schema_version=2,
        signing_key_id=_KEY_ID,
        signing_public_key_sha256=b"k" * 32,
        database_instance_id=b"i" * 32,
        audit_sequence=0,
        audit_hash=b"c" * 32,
        state_revision=1,
        state_digest=b"b" * 32,
        clock_floor_ns=None,
    )
    with pytest.raises(StorageError, match="audit head diverges"):
        anchor.reconcile(divergent, audit_hash_at=lambda _sequence: None)


def test_failed_durable_anchor_publish_preserves_the_prior_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    anchor = FileAuthorityAnchor(tmp_path / "anchor.json")
    initial = AuthorityCheckpoint(
        warden_id="warden-a",
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        schema_version=2,
        signing_key_id=_KEY_ID,
        signing_public_key_sha256=b"k" * 32,
        database_instance_id=b"i" * 32,
        audit_sequence=-1,
        audit_hash=bytes(32),
        state_revision=0,
        state_digest=b"s" * 32,
        clock_floor_ns=None,
    )
    anchor.reconcile(initial, audit_hash_at=lambda _sequence: None, initialize=True)
    before = anchor.path.read_bytes()
    successor = AuthorityCheckpoint(
        warden_id=initial.warden_id,
        tenant_id=initial.tenant_id,
        envelope_id=initial.envelope_id,
        config_epoch=initial.config_epoch,
        schema_version=initial.schema_version,
        signing_key_id=initial.signing_key_id,
        signing_public_key_sha256=initial.signing_public_key_sha256,
        database_instance_id=initial.database_instance_id,
        audit_sequence=0,
        audit_hash=b"a" * 32,
        state_revision=1,
        state_digest=b"t" * 32,
        clock_floor_ns=None,
    )

    def fail_move(_source: str, _target: Path, *, exclusive: bool) -> None:
        del exclusive
        raise OSError("injected durable rename failure")

    monkeypatch.setattr(authority_module, "_durable_move", fail_move)
    with pytest.raises(StorageError, match="could not persist authority anchor"):
        anchor.reconcile(successor, audit_hash_at=lambda _sequence: bytes(32))
    assert anchor.path.read_bytes() == before
    assert anchor.read_current() == initial


def test_clock_floor_advances_without_false_fork_and_cannot_roll_back(tmp_path: Path) -> None:
    original = tmp_path / "warden.sqlite3"
    stale = tmp_path / "stale.sqlite3"
    anchor_path = tmp_path / "independent" / "anchor.json"
    store = SQLiteStorage.initialize(
        original,
        "warden-a",
        (10,),
        **_options(FileAuthorityAnchor(anchor_path)),
    )
    with store.write() as transaction:
        transaction.execute(
            "UPDATE warden_state SET clock_floor_ns=10 WHERE tenant_id=? AND envelope_id=?",
            ("tenant-a", "envelope-a"),
        )
    store.checkpoint(truncate=True)
    shutil.copy2(original, stale)
    with store.write() as transaction:
        transaction.execute(
            "UPDATE warden_state SET clock_floor_ns=20 WHERE tenant_id=? AND envelope_id=?",
            ("tenant-a", "envelope-a"),
        )
    assert store.authority_checkpoint().clock_floor_ns == 20
    assert store.authority_anchor_healthy
    store.close()

    with pytest.raises(StorageError, match="clock floor moved behind"):
        _open(stale, FileAuthorityAnchor(anchor_path))


def test_idempotent_service_retry_can_advance_anchored_clock_floor(tmp_path: Path) -> None:
    database = tmp_path / "warden.sqlite3"
    anchor_path = tmp_path / "independent" / "anchor.json"
    signer = Ed25519Signer.generate("warden-a")
    clock = ManualClock(1_000_000, 0)
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    options = {
        "signing_key_id": signer.key_id,
        "signing_public_key": signer.public_key_bytes,
        "tenant_id": "tenant-a",
        "envelope_id": "envelope-a",
        "config_epoch": 1,
        "initial_local_share": (10,),
        "receipt_ttl_ns": 100,
        "max_clock_uncertainty_ns": 0,
        "transfer_gap_window": 4,
        "authority_anchor": FileAuthorityAnchor(anchor_path),
    }
    store = SQLiteStorage.initialize(database, "warden-a", (10,), **options)
    service = WardenService(store, signer=signer, clock=clock, trust_registry=registry)
    policy = _policy()
    service.register_policy(policy)
    identity = IdentityContext(
        subject_id="agent-a",
        tenant_id="tenant-a",
        scopes=frozenset({"lets.lease.issue"}),
    )
    grant = service.issue_root(
        request_id="anchored-retry",
        identity=identity,
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        subject_id="agent-a",
        allocation=(5,),
        capabilities={"worker.act"},
        policy_digest=policy.digest,
        ttl_ns=1_000,
    )
    clock.advance(10)
    assert (
        service.issue_root(
            request_id="anchored-retry",
            identity=identity,
            tenant_id="tenant-a",
            envelope_id="envelope-a",
            subject_id="agent-a",
            allocation=(5,),
            capabilities={"worker.act"},
            policy_digest=policy.digest,
            ttl_ns=1_000,
        )
        == grant
    )
    assert store.authority_anchor_healthy
    assert store.authority_checkpoint().clock_floor_ns == clock.now_ns()
    store.close()

    reopened = SQLiteStorage(database, "warden-a", (10,), **options)
    try:
        assert reopened.verify_authority_anchor()
    finally:
        reopened.close()


def test_commit_anchor_crash_window_fails_closed_then_recovers_extension(
    tmp_path: Path,
) -> None:
    class FailPostCommitOnce:
        def __init__(self, delegate: FileAuthorityAnchor) -> None:
            self.delegate = delegate
            self.calls = 0

        def reconcile(self, checkpoint: AuthorityCheckpoint, **options: Any) -> None:
            self.calls += 1
            # initialize, then the transaction's pre-COMMIT check, then fail the
            # post-COMMIT CAS before the delegate can advance.
            if self.calls == 3:
                raise StorageError("injected anchor outage")
            self.delegate.reconcile(checkpoint, **options)

    database = tmp_path / "warden.sqlite3"
    durable = FileAuthorityAnchor(tmp_path / "independent" / "anchor.json")
    failing = FailPostCommitOnce(durable)
    store = SQLiteStorage.initialize(
        database,
        "warden-a",
        (10,),
        **_options(failing),
    )
    with pytest.raises(StorageError, match="injected anchor outage"):
        _consume_one(store, "committed-before-anchor-outage")
    assert not store.authority_anchor_healthy
    with pytest.raises(StorageError, match="previously faulted"):
        store.authority_checkpoint()
    store.close()

    # The local COMMIT is durable, but no result escaped the failed context.  On
    # restart the DB proves a contiguous extension of the independently retained
    # head, so the anchor advances rather than discarding a committed debit.
    recovered = _open(database, durable)
    try:
        assert recovered.authority_checkpoint().audit_sequence == 0
        assert recovered.authority_checkpoint().state_revision == 1
        assert recovered.verify_authority_anchor()
    finally:
        recovered.close()


def test_simultaneous_database_forks_use_one_linearizable_anchor_successor(
    tmp_path: Path,
) -> None:
    original = tmp_path / "original.sqlite3"
    left_path = tmp_path / "left.sqlite3"
    right_path = tmp_path / "right.sqlite3"
    anchor_path = tmp_path / "independent" / "anchor.json"
    initialized = SQLiteStorage.initialize(
        original,
        "warden-a",
        (10,),
        **_options(FileAuthorityAnchor(anchor_path)),
    )
    initialized.checkpoint(truncate=True)
    initialized.close()
    shutil.copy2(original, left_path)
    shutil.copy2(original, right_path)
    left = _open(left_path, FileAuthorityAnchor(anchor_path))
    right = _open(right_path, FileAuthorityAnchor(anchor_path))
    barrier = threading.Barrier(2)
    results: list[tuple[str, str]] = []
    result_lock = threading.Lock()

    def contend(name: str, store: SQLiteStorage) -> None:
        try:
            with store.write() as transaction:
                transaction.execute(
                    """
                    UPDATE warden_state
                    SET free_pool = ?, consumed = ?, revision = revision + 1,
                        updated_at_ns = 10
                    WHERE tenant_id = ? AND envelope_id = ?
                    """,
                    (pack((9,)), pack((1,)), "tenant-a", "envelope-a"),
                )
                transaction.append_audit(name, {"fork": name}, created_at_ns=10)
                barrier.wait(timeout=5)
        except StorageError as exc:
            outcome = (name, f"error:{exc}")
        else:
            outcome = (name, "committed-and-anchored")
        with result_lock:
            results.append(outcome)

    threads = (
        threading.Thread(target=contend, args=("left", left)),
        threading.Thread(target=contend, args=("right", right)),
    )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    left.close()
    right.close()

    assert sum(outcome == "committed-and-anchored" for _, outcome in results) == 1
    assert sum("diverges" in outcome for _, outcome in results) == 1
    reopen_outcomes: list[str] = []
    for path in (left_path, right_path):
        try:
            candidate = _open(path, FileAuthorityAnchor(anchor_path))
        except StorageError:
            reopen_outcomes.append("fenced")
        else:
            candidate.close()
            reopen_outcomes.append("winner")
    assert sorted(reopen_outcomes) == ["fenced", "winner"]
