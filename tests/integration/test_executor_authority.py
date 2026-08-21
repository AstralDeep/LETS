from __future__ import annotations

import shutil
import sys
import textwrap
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier, Lock

import pytest

import lets.executor as executor_module
import lets.executor_authority as executor_authority_module
from lets.canonical import b64url_encode, canonical_json
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import AuthorityAnchorTransportError, ReplayError, StorageError, ValidationError
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


@pytest.mark.parametrize("timeout_s", (float("nan"), float("inf"), float("-inf")))
@pytest.mark.parametrize(
    "anchor_type",
    (FileExecutorAuthorityAnchor, ProcessFileExecutorAuthorityAnchor),
)
def test_executor_file_anchors_reject_nonfinite_timeouts(
    tmp_path: Path,
    timeout_s: float,
    anchor_type: type[FileExecutorAuthorityAnchor] | type[ProcessFileExecutorAuthorityAnchor],
) -> None:
    with pytest.raises(ValidationError, match="timeout_s"):
        anchor_type(tmp_path / "executor.anchor", timeout_s=timeout_s)


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
        self.calls = 0

    def reconcile(
        self,
        checkpoint: ExecutorAuthorityCheckpoint,
        *,
        claim_digest_at: Callable[[int], bytes | None],
        initialize: bool = False,
    ) -> None:
        with self._lock:
            self.calls += 1
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


class _ScriptedExecutorAnchor:
    def __init__(
        self,
        delegate: FileExecutorAuthorityAnchor,
        failures: dict[int, StorageError],
        *,
        fail_after_delegate: frozenset[int] = frozenset(),
    ) -> None:
        self.delegate = delegate
        self.failures = failures
        self.fail_after_delegate = fail_after_delegate
        self.calls = 0
        self.confirm_calls = 0

    def reconcile(
        self,
        checkpoint: ExecutorAuthorityCheckpoint,
        *,
        claim_digest_at: Callable[[int], bytes | None],
        initialize: bool = False,
    ) -> None:
        self.calls += 1
        failure = self.failures.get(self.calls)
        if failure is not None and self.calls not in self.fail_after_delegate:
            raise failure
        self.delegate.reconcile(
            checkpoint,
            claim_digest_at=claim_digest_at,
            initialize=initialize,
        )
        if failure is not None:
            raise failure

    def confirm(self, checkpoint: ExecutorAuthorityCheckpoint) -> None:
        self.confirm_calls += 1
        with self.delegate._locked():
            if self.delegate._read_executor() != checkpoint:
                raise StorageError("injected executor confirmation mismatch")
            self.delegate._write_executor(checkpoint, exclusive=False)

    def read_current(self) -> ExecutorAuthorityCheckpoint:
        return self.delegate.read_current()


def _executor_transport_failure(
    *, operation: str, mutation_uncertain: bool
) -> AuthorityAnchorTransportError:
    return AuthorityAnchorTransportError(
        "bounded injected executor transport failure",
        reason="helper_eof",
        operation=operation,
        request_flushed=True,
        mutation_uncertain=mutation_uncertain,
        helper_pid=321,
        helper_exit_code=-9,
    )


def _malformed_executor_transport_failure() -> AuthorityAnchorTransportError:
    failure = AuthorityAnchorTransportError.__new__(AuthorityAnchorTransportError)
    Exception.__init__(failure, "untrusted executor provider detail")
    failure.reason = "semantic_divergence"
    failure.operation = "bogus"
    failure.request_flushed = 1
    failure.mutation_uncertain = "yes"
    failure.helper_pid = 1 << 40
    failure.helper_exit_code = -(1 << 40)
    return failure


@pytest.mark.parametrize("failure_call", [2, 3])
def test_executor_typed_transport_recovers_only_on_later_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_call: int,
) -> None:
    now = [10_000_000_000]
    monkeypatch.setattr(executor_module.time, "monotonic_ns", lambda: now[0])
    post_commit = failure_call == 3
    authority = tmp_path / "authority"
    authority.mkdir()
    durable = FileExecutorAuthorityAnchor(authority / "executor.anchor")
    failure = _executor_transport_failure(
        operation="compare-and-set" if post_commit else "read",
        mutation_uncertain=post_commit,
    )
    anchor = _ScriptedExecutorAnchor(
        durable,
        {failure_call: failure},
        fail_after_delegate=frozenset({failure_call}) if post_commit else frozenset(),
    )
    signer = Ed25519Signer.generate("warden-a")
    store = SQLiteReceiptReplayStore.initialize(
        tmp_path / "executor.sqlite3",
        authority_anchor=anchor,
        identity=_identity(signer),
    )
    first = _receipt(signer, receipt_id="receipt-a", nonce="nonce-a")
    effects = 0

    with pytest.raises(AuthorityAnchorTransportError):
        _verifier(store, signer).verify_and_claim(first)
        effects += 1
    assert effects == 0
    faulted = store.authority_status()
    assert faulted["state"] == "recoverable_transport_fault"
    assert faulted["transport_faults"] == 1
    assert faulted["transport_fault_episodes"] == 1
    assert faulted["transport_recovery_attempts"] == 0
    assert faulted["transport_recoveries"] == 0
    assert faulted["unresolved_transport_faults"] == 1
    assert faulted["permanent_faults"] == 0
    assert faulted["first_fault"] == {
        "reason": "helper_eof",
        "stage": "post_commit" if post_commit else "pre_begin",
        "operation": "compare-and-set" if post_commit else "read",
        "request_flushed": True,
        "mutation_uncertain": post_commit,
        "helper_pid": 321,
        "helper_exit_code": -9,
    }
    with pytest.raises(StorageError, match="cooldown"):
        _verifier(store, signer).verify_and_claim(first)
    assert anchor.calls == failure_call

    now[0] += 250_000_000
    if post_commit:
        with pytest.raises(ReplayError):
            _verifier(store, signer).verify_and_claim(first)
        assert effects == 0
        second = _receipt(
            signer,
            receipt_id="receipt-b",
            nonce="nonce-b",
            lease_id="lease-b",
            sequence=2,
        )
        _verifier(store, signer).verify_and_claim(second)
        effects += 1
        assert anchor.confirm_calls == 1
        assert store.status().claim_sequence == 2
    else:
        _verifier(store, signer).verify_and_claim(first)
        effects += 1
        assert anchor.confirm_calls == 0
        assert store.status().claim_sequence == 1
    assert effects == 1
    recovered = store.authority_status()
    assert recovered["state"] == "healthy"
    assert recovered["healthy"] is True
    assert recovered["transport_faults"] == 1
    assert recovered["transport_fault_episodes"] == 1
    assert recovered["transport_recovery_attempts"] == 1
    assert recovered["transport_recoveries"] == 1
    assert recovered["unresolved_transport_faults"] == 0
    assert recovered["permanent_faults"] == 0
    assert recovered["first_fault"] == faulted["first_fault"]


def test_executor_malformed_typed_failure_is_permanent_and_never_reprobed(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "authority"
    authority.mkdir()
    durable = FileExecutorAuthorityAnchor(authority / "executor.anchor")
    anchor = _ScriptedExecutorAnchor(
        durable,
        {2: _malformed_executor_transport_failure()},
    )
    signer = Ed25519Signer.generate("warden-a")
    store = SQLiteReceiptReplayStore.initialize(
        tmp_path / "executor.sqlite3",
        authority_anchor=anchor,
        identity=_identity(signer),
    )
    receipt = _receipt(signer, receipt_id="receipt-a", nonce="nonce-a")

    with pytest.raises(StorageError, match="malformed transport failure") as raised:
        _verifier(store, signer).verify_and_claim(receipt)
    assert "untrusted executor" not in str(raised.value)
    status = store.authority_status()
    assert status["state"] == "permanent_fault"
    assert status["fault_reason"] == "malformed_transport_error"
    assert status["permanent_faults"] == 1
    assert status["transport_faults"] == 0
    assert status["first_fault"] is None
    calls = anchor.calls
    with pytest.raises(StorageError, match="previously faulted permanently"):
        store.status()
    assert anchor.calls == calls


def test_process_executor_reconcile_and_confirm_pass_one_exact_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = tmp_path / "authority"
    authority.mkdir()
    anchor = ProcessFileExecutorAuthorityAnchor(
        authority / "executor.anchor",
        timeout_s=0.5,
    )
    now = 100.0

    def advancing_monotonic() -> float:
        nonlocal now
        current = now
        now += 0.01
        return current

    operations: list[tuple[str, float]] = []

    def invoke(request: dict[str, object], *, deadline: float) -> dict[str, object]:
        operation = str(request.get("operation"))
        operations.append((operation, deadline))
        return {"status": "missing" if operation == "read" else "ok"}

    monkeypatch.setattr(executor_authority_module.time, "monotonic", advancing_monotonic)
    monkeypatch.setattr(anchor, "_invoke", invoke)
    signer = Ed25519Signer.generate("warden-a")
    store = SQLiteReceiptReplayStore.initialize(
        tmp_path / "executor.sqlite3",
        authority_anchor=anchor,
        identity=_identity(signer),
    )
    assert store.rollback_protected
    assert operations == [
        ("read", 100.5),
        ("initialize", 100.5),
        ("confirm", 100.5),
    ]
    anchor.close()


def test_process_executor_rejects_checkpoint_decoded_after_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = tmp_path / "authority"
    authority.mkdir()
    anchor = ProcessFileExecutorAuthorityAnchor(
        authority / "executor.anchor",
        timeout_s=2.0,
    )
    signer = Ed25519Signer.generate("warden-a")
    SQLiteReceiptReplayStore.initialize(
        tmp_path / "executor.sqlite3",
        authority_anchor=anchor,
        identity=_identity(signer),
    )
    checkpoint = anchor.read_current()
    process_before = anchor._backend._process
    assert process_before is not None
    decode = anchor._executor_checkpoint

    real_monotonic = time.monotonic
    offset = [0.0]

    def controlled_monotonic() -> float:
        return real_monotonic() + offset[0]

    def delayed_checkpoint(response: dict[str, object]) -> ExecutorAuthorityCheckpoint:
        decoded = decode(response)
        offset[0] = 2.0
        return decoded

    monkeypatch.setattr(executor_authority_module.time, "monotonic", controlled_monotonic)
    monkeypatch.setattr(anchor, "_executor_checkpoint", delayed_checkpoint)
    anchor._timeout_s = 1.0
    with pytest.raises(AuthorityAnchorTransportError) as raised:
        anchor.read_current()
    assert raised.value.reason == "deadline"
    assert raised.value.operation == "read"
    assert raised.value.mutation_uncertain is False
    assert anchor._backend._reset_required.is_set()
    assert anchor._backend._process is process_before

    monkeypatch.setattr(anchor, "_executor_checkpoint", decode)
    offset[0] = 0.0
    anchor._timeout_s = 2.0
    assert anchor.read_current() == checkpoint
    assert anchor._backend._process is not process_before
    assert process_before.poll() is not None
    anchor.close()


def test_executor_startup_transport_preserves_durable_database_identity(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "authority"
    authority.mkdir()
    durable = FileExecutorAuthorityAnchor(authority / "executor.anchor")
    failing = _ScriptedExecutorAnchor(
        durable,
        {
            1: _executor_transport_failure(
                operation="initialize",
                mutation_uncertain=True,
            )
        },
        fail_after_delegate=frozenset({1}),
    )
    database = tmp_path / "executor.sqlite3"
    signer = Ed25519Signer.generate("warden-a")

    with pytest.raises(AuthorityAnchorTransportError):
        SQLiteReceiptReplayStore.initialize(
            database,
            authority_anchor=failing,
            identity=_identity(signer),
        )
    assert database.is_file()
    anchored = durable.read_current()

    reopened = SQLiteReceiptReplayStore(database, authority_anchor=durable)
    status = reopened.status()
    assert status.authority_checkpoint == anchored
    assert status.claim_sequence == 0


def test_process_executor_startup_confirm_lost_reply_preserves_and_reconfirms(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = tmp_path / "authority"
    authority.mkdir()
    anchor_path = authority / "executor.anchor"
    database = tmp_path / "executor.sqlite3"
    script = textwrap.dedent(
        """
        import sys
        from pathlib import Path
        from lets.authority_helper import _operate_executor, _respond
        from lets.canonical import strict_json_loads

        path = Path(sys.argv[sys.argv.index("--path") + 1])
        for line in sys.stdin.buffer:
            request = strict_json_loads(line)
            response = _operate_executor(path, request)
            if request.get("operation") == "confirm":
                raise SystemExit(0)
            _respond(response)
        """
    )
    signer = Ed25519Signer.generate("warden-a")
    failing = ProcessFileExecutorAuthorityAnchor(
        anchor_path,
        timeout_s=2.0,
        helper_command=(sys.executable, "-c", script),
    )
    with pytest.raises(AuthorityAnchorTransportError) as raised:
        SQLiteReceiptReplayStore.initialize(
            database,
            authority_anchor=failing,
            identity=_identity(signer),
        )
    assert raised.value.reason == "helper_eof"
    assert raised.value.operation == "confirm"
    assert raised.value.request_flushed is True
    assert raised.value.mutation_uncertain is True
    assert database.is_file()
    assert anchor_path.is_file()
    anchored = FileExecutorAuthorityAnchor(anchor_path).read_current()
    failing.close()

    fresh = ProcessFileExecutorAuthorityAnchor(anchor_path, timeout_s=2.0)
    operations: list[str] = []
    invoke = fresh._invoke

    def recording_invoke(
        request: dict[str, object],
        *,
        deadline: float,
    ) -> dict[str, object]:
        operations.append(str(request.get("operation")))
        return dict(invoke(request, deadline=deadline))

    monkeypatch.setattr(fresh, "_invoke", recording_invoke)
    reopened = SQLiteReceiptReplayStore(database, authority_anchor=fresh)
    assert operations == ["read", "confirm"]
    authority_status = reopened.authority_status()
    assert authority_status["state"] == "healthy"
    assert authority_status["transport_faults"] == 0
    assert authority_status["first_fault"] is None
    assert FileExecutorAuthorityAnchor(anchor_path).read_current() == anchored
    fresh.close()


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
    faulted = store.authority_status()
    assert faulted["state"] == "permanent_fault"
    assert faulted["transport_faults"] == 0
    assert faulted["permanent_faults"] == 1
    calls_after_fault = failing.calls
    with pytest.raises(StorageError, match="previously faulted permanently"):
        store.status()
    assert failing.calls == calls_after_fault
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
