from __future__ import annotations

import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Any, cast

import pytest

import lets.authority as authority_module
import lets.storage.sqlite as sqlite_module
from lets.authority import AuthorityCheckpoint, FileAuthorityAnchor, ProcessFileAuthorityAnchor
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import AuthorityAnchorTransportError, ConflictError, StorageError, ValidationError
from lets.models import IdentityContext
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage
from lets.vector import pack

_KEY_ID = "warden-a-key"
_PUBLIC_KEY = bytes(range(32))


@pytest.mark.parametrize("timeout_s", (float("nan"), float("inf"), float("-inf")))
@pytest.mark.parametrize("anchor_type", (FileAuthorityAnchor, ProcessFileAuthorityAnchor))
def test_file_authority_anchors_reject_nonfinite_timeouts(
    tmp_path: Path,
    timeout_s: float,
    anchor_type: type[FileAuthorityAnchor] | type[ProcessFileAuthorityAnchor],
) -> None:
    with pytest.raises(ValidationError, match="timeout_s"):
        anchor_type(tmp_path / "anchor.json", timeout_s=timeout_s)


def _transport_failure(
    *,
    operation: str = "read",
    request_flushed: bool = True,
    mutation_uncertain: bool = False,
) -> AuthorityAnchorTransportError:
    return AuthorityAnchorTransportError(
        "bounded injected transport failure",
        reason="helper_eof",
        operation=operation,
        request_flushed=request_flushed,
        mutation_uncertain=mutation_uncertain,
        helper_pid=123,
        helper_exit_code=-9,
    )


def _malformed_transport_failure() -> AuthorityAnchorTransportError:
    failure = AuthorityAnchorTransportError.__new__(AuthorityAnchorTransportError)
    Exception.__init__(failure, "untrusted provider detail")
    failure.reason = "semantic_divergence"
    failure.operation = "bogus"
    failure.request_flushed = 1
    failure.mutation_uncertain = "yes"
    failure.helper_pid = 1 << 40
    failure.helper_exit_code = -(1 << 40)
    return failure


class _ScriptedAnchor:
    def __init__(
        self,
        delegate: FileAuthorityAnchor,
        failures: dict[int, StorageError],
        *,
        fail_after_delegate: frozenset[int] = frozenset(),
    ) -> None:
        self.delegate = delegate
        self.failures = failures
        self.fail_after_delegate = fail_after_delegate
        self.calls = 0
        self.confirm_calls = 0

    def reconcile(self, checkpoint: AuthorityCheckpoint, **options: Any) -> None:
        self.calls += 1
        failure = self.failures.get(self.calls)
        if failure is not None and self.calls not in self.fail_after_delegate:
            raise failure
        self.delegate.reconcile(checkpoint, **options)
        if failure is not None:
            raise failure

    def confirm(self, checkpoint: AuthorityCheckpoint) -> None:
        self.confirm_calls += 1
        with self.delegate._locked():
            if self.delegate._read() != checkpoint:
                raise StorageError("injected confirmation mismatch")
            self.delegate._write(checkpoint, exclusive=False)


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
    class ConfirmingProcessAnchor(ProcessFileAuthorityAnchor):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            self.confirm_calls = 0

        def reconcile_and_confirm(
            self,
            checkpoint: AuthorityCheckpoint,
            *,
            audit_hash_at: Any,
            initialize: bool = False,
            allow_schema_upgrade: bool = False,
        ) -> None:
            self.confirm_calls += 1
            super().reconcile_and_confirm(
                checkpoint,
                audit_hash_at=audit_hash_at,
                initialize=initialize,
                allow_schema_upgrade=allow_schema_upgrade,
            )

    database = tmp_path / "warden.sqlite3"
    anchor_path = tmp_path / "monotonic" / "warden.anchor.json"
    anchor = ConfirmingProcessAnchor(anchor_path)
    store = SQLiteStorage.initialize(database, "warden-a", (10,), **_options(anchor))
    assert anchor.confirm_calls == 1
    _consume_one(store, "consume-through-helper")
    committed = store.authority_checkpoint()
    assert store.verify_authority_anchor()
    store.close()

    reopened_anchor = ConfirmingProcessAnchor(anchor_path)
    reopened = SQLiteStorage(
        database,
        "warden-a",
        (10,),
        **_options(reopened_anchor),
    )
    try:
        assert reopened_anchor.confirm_calls == 1
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
    with pytest.raises(AuthorityAnchorTransportError, match="exceeded its deadline") as raised:
        anchor.reconcile(checkpoint, audit_hash_at=lambda _sequence: None, initialize=True)
    assert raised.value.reason == "deadline"
    assert raised.value.operation == "read"
    assert raised.value.request_flushed is True
    assert raised.value.mutation_uncertain is False
    assert time.monotonic() - started < 1.0


def test_process_file_reconcile_and_confirm_share_one_absolute_deadline(tmp_path: Path) -> None:
    script = (
        "import json,sys,time;"
        "\nfor line in sys.stdin:"
        "\n r=json.loads(line);op=r['operation'];"
        "\n if op=='confirm': time.sleep(10);"
        "\n status='missing' if op=='read' else 'ok';"
        "\n print(json.dumps({'request_id':r['request_id'],'status':status}),flush=True)"
    )
    anchor = ProcessFileAuthorityAnchor(
        tmp_path / "anchor.json",
        timeout_s=0.5,
        helper_command=(sys.executable, "-c", script),
    )
    assert (
        anchor._invoke(
            {"operation": "read"},
            deadline=time.monotonic() + 2.0,
        )["status"]
        == "missing"
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
    with pytest.raises(AuthorityAnchorTransportError) as raised:
        anchor.reconcile_and_confirm(
            checkpoint,
            audit_hash_at=lambda _sequence: None,
            initialize=True,
        )
    assert raised.value.operation == "confirm"
    assert raised.value.reason == "deadline"
    assert raised.value.request_flushed is True
    assert raised.value.mutation_uncertain is True
    assert time.monotonic() - started < 1.5


def test_process_file_anchor_start_eof_and_process_lock_failures_are_typed(
    tmp_path: Path,
) -> None:
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
    missing = ProcessFileAuthorityAnchor(
        tmp_path / "missing.anchor",
        timeout_s=0.05,
        helper_command=(str(tmp_path / "does-not-exist"),),
    )
    with pytest.raises(AuthorityAnchorTransportError) as start_failure:
        missing.reconcile(checkpoint, audit_hash_at=lambda _sequence: None, initialize=True)
    assert start_failure.value.reason == "helper_start"
    assert start_failure.value.request_flushed is False
    assert start_failure.value.mutation_uncertain is False

    exited = ProcessFileAuthorityAnchor(
        tmp_path / "eof.anchor",
        timeout_s=0.25,
        helper_command=(sys.executable, "-c", "pass"),
    )
    with pytest.raises(AuthorityAnchorTransportError) as eof_failure:
        exited.reconcile(checkpoint, audit_hash_at=lambda _sequence: None, initialize=True)
    assert eof_failure.value.reason in {"helper_eof", "helper_pipe"}
    assert eof_failure.value.operation == "read"
    assert eof_failure.value.mutation_uncertain is False

    locked = ProcessFileAuthorityAnchor(tmp_path / "locked.anchor", timeout_s=0.05)
    assert locked._process_lock.acquire(timeout=1)
    try:
        with pytest.raises(AuthorityAnchorTransportError) as lock_failure:
            locked.reconcile(checkpoint, audit_hash_at=lambda _sequence: None, initialize=True)
    finally:
        locked._process_lock.release()
    assert lock_failure.value.reason == "process_lock_deadline"
    assert lock_failure.value.request_flushed is False
    assert lock_failure.value.mutation_uncertain is False


def test_process_file_anchor_bounds_and_cancels_helper_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "helper-read-request"
    script = (
        "import json,pathlib,sys;"
        "line=sys.stdin.readline();"
        f"p=pathlib.Path({str(marker)!r});"
        "p.write_text('requested') if line else None;"
        "r=json.loads(line) if line else None;"
        "print(json.dumps({'request_id':r['request_id'],'status':'missing'}),flush=True) "
        "if r else None"
    )
    anchor = ProcessFileAuthorityAnchor(
        tmp_path / "anchor.json",
        timeout_s=0.05,
        helper_command=(sys.executable, "-c", script),
    )
    real_popen = authority_module.subprocess.Popen
    entered = threading.Event()
    release = threading.Event()
    created: list[Any] = []
    calls = 0

    def delayed_popen(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            assert release.wait(timeout=2)
        process = real_popen(*args, **kwargs)
        created.append(process)
        return process

    monkeypatch.setattr(authority_module.subprocess, "Popen", delayed_popen)
    started = time.monotonic()
    with pytest.raises(AuthorityAnchorTransportError) as start_deadline:
        anchor.read_current()
    assert entered.is_set()
    assert start_deadline.value.reason == "helper_start_deadline"
    assert time.monotonic() - started < 0.15

    with pytest.raises(AuthorityAnchorTransportError) as still_spawning:
        anchor.read_current()
    assert still_spawning.value.reason == "helper_start_in_progress"
    assert calls == 1

    anchor.close()
    release.set()
    deadline = time.monotonic() + 2
    while (
        not created or created[0].poll() is None or anchor._spawn_attempt is not None
    ) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert created and created[0].poll() is not None
    assert anchor._spawn_attempt is None
    assert not marker.exists()

    anchor._timeout_s = 0.5
    with pytest.raises(StorageError, match="missing"):
        anchor.read_current()
    assert calls == 2
    anchor.close()


def test_process_file_anchor_sanitizes_unexpected_spawn_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anchor = ProcessFileAuthorityAnchor(tmp_path / "anchor.json", timeout_s=0.1)

    def fail_spawn(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("sensitive spawn detail")

    monkeypatch.setattr(authority_module.subprocess, "Popen", fail_spawn)
    with pytest.raises(AuthorityAnchorTransportError) as raised:
        anchor.read_current()
    assert raised.value.reason == "helper_start"
    assert raised.value.request_flushed is False
    assert raised.value.mutation_uncertain is False
    assert "sensitive" not in str(raised.value)
    anchor.close()


def test_process_file_anchor_rejects_stale_correlation_and_resets_helper(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "started-once"
    script = (
        "import json,pathlib,sys;"
        f"p=pathlib.Path({str(marker)!r});"
        "r=json.loads(sys.stdin.readline());"
        "first=not p.exists();p.touch();"
        "rid=('0'*32 if first else r['request_id']);"
        "print(json.dumps({'request_id':rid,'status':'missing'}),flush=True);"
        "sys.stdin.read()"
    )
    anchor = ProcessFileAuthorityAnchor(
        tmp_path / "anchor.json",
        timeout_s=0.5,
        helper_command=(sys.executable, "-c", script),
    )
    with pytest.raises(StorageError, match="correlation is invalid"):
        anchor.read_current()
    with pytest.raises(StorageError, match="missing"):
        anchor.read_current()
    anchor.close()


@pytest.mark.parametrize("operation", ["read", "confirm"])
def test_process_file_anchor_rejects_response_parsed_after_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    anchor = ProcessFileAuthorityAnchor(tmp_path / "anchor.json", timeout_s=0.5)
    assert (
        anchor._invoke({"operation": "read"}, deadline=time.monotonic() + 2.0)["status"]
        == "missing"
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
    request: dict[str, object] = {"operation": operation}
    if operation == "confirm":
        request["checkpoint"] = checkpoint.to_dict()
    decode = authority_module.strict_json_loads

    real_monotonic = time.monotonic
    offset = [0.0]

    def controlled_monotonic() -> float:
        return real_monotonic() + offset[0]

    def delayed_decode(value: bytes) -> Any:
        decoded = decode(value)
        offset[0] = 2.0
        return decoded

    monkeypatch.setattr(authority_module.time, "monotonic", controlled_monotonic)
    monkeypatch.setattr(authority_module, "strict_json_loads", delayed_decode)
    started = real_monotonic()
    with pytest.raises(AuthorityAnchorTransportError) as raised:
        anchor._invoke(request, deadline=controlled_monotonic() + 1.0)
    assert raised.value.reason == "deadline"
    assert raised.value.operation == operation
    assert raised.value.request_flushed is True
    assert raised.value.mutation_uncertain is (operation == "confirm")
    assert real_monotonic() - started < 0.5

    monkeypatch.setattr(authority_module, "strict_json_loads", decode)
    offset[0] = 0.0
    assert (
        anchor._invoke({"operation": "read"}, deadline=controlled_monotonic() + 2.0)["status"]
        == "missing"
    )
    anchor.close()


def test_process_file_anchor_rejects_checkpoint_decoded_after_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anchor = ProcessFileAuthorityAnchor(tmp_path / "anchor.json", timeout_s=0.5)
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
    anchor.reconcile(checkpoint, audit_hash_at=lambda _sequence: None, initialize=True)
    process_before = anchor._process
    assert process_before is not None
    decode = anchor._checkpoint

    real_monotonic = time.monotonic
    offset = [0.0]

    def controlled_monotonic() -> float:
        return real_monotonic() + offset[0]

    def delayed_checkpoint(response: dict[str, Any]) -> AuthorityCheckpoint:
        decoded = decode(response)
        offset[0] = 2.0
        return decoded

    monkeypatch.setattr(authority_module.time, "monotonic", controlled_monotonic)
    monkeypatch.setattr(anchor, "_checkpoint", delayed_checkpoint)
    anchor._timeout_s = 1.0
    with pytest.raises(AuthorityAnchorTransportError) as raised:
        anchor.read_current()
    assert raised.value.reason == "deadline"
    assert raised.value.operation == "read"
    assert raised.value.mutation_uncertain is False
    assert anchor._reset_required.is_set()
    assert anchor._process is process_before

    monkeypatch.setattr(anchor, "_checkpoint", decode)
    offset[0] = 0.0
    anchor._timeout_s = 2.0
    assert anchor.read_current() == checkpoint
    assert anchor._process is not process_before
    assert process_before.poll() is not None
    anchor.close()


@pytest.mark.parametrize("failure_call, expected_stage", [(2, "pre_begin"), (3, "post_commit")])
def test_core_transport_fault_recovers_once_after_cooldown_with_durable_counters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_call: int,
    expected_stage: str,
) -> None:
    now = [10_000_000_000]
    monkeypatch.setattr(sqlite_module.time, "monotonic_ns", lambda: now[0])
    database = tmp_path / "warden.sqlite3"
    durable = FileAuthorityAnchor(tmp_path / "independent" / "anchor.json")
    post_commit = failure_call == 3
    failure = _transport_failure(
        operation="compare-and-set" if post_commit else "read",
        mutation_uncertain=post_commit,
    )
    anchor = _ScriptedAnchor(
        durable,
        {failure_call: failure},
        fail_after_delegate=frozenset({failure_call}) if post_commit else frozenset(),
    )
    store = SQLiteStorage.initialize(database, "warden-a", (10,), **_options(anchor))
    with pytest.raises(AuthorityAnchorTransportError):
        _consume_one(store, f"{expected_stage}-transport-fault")
    faulted = store.authority_anchor_status()
    assert faulted["state"] == "recoverable_transport_fault"
    assert faulted["transport_faults"] == 1
    assert faulted["transport_fault_episodes"] == 1
    assert faulted["transport_recovery_attempts"] == 0
    assert faulted["transport_recoveries"] == 0
    assert faulted["unresolved_transport_faults"] == 1
    assert faulted["permanent_faults"] == 0
    assert faulted["fault_stage"] == expected_stage
    assert faulted["first_fault"] == {
        "reason": "helper_eof",
        "stage": expected_stage,
        "operation": "compare-and-set" if post_commit else "read",
        "request_flushed": True,
        "mutation_uncertain": post_commit,
        "helper_pid": 123,
        "helper_exit_code": -9,
    }
    with pytest.raises(StorageError, match="must be healthy"):
        store.fence_authority_admission(
            restart_id="restart-while-faulted",
            expected_lifetime_id=cast(str, faulted["lifetime_id"]),
        )
    assert store.authority_anchor_status()["admission_fenced"] is False
    calls_after_fault = anchor.calls
    with pytest.raises(StorageError, match="cooldown"):
        store.authority_checkpoint()
    assert anchor.calls == calls_after_fault

    now[0] += 250_000_000
    recovered_checkpoint = store.authority_checkpoint()
    assert recovered_checkpoint.audit_sequence == (0 if post_commit else -1)
    recovered = store.authority_anchor_status()
    assert recovered["state"] == "healthy"
    assert recovered["healthy"] is True
    assert recovered["transport_faults"] == 1
    assert recovered["transport_fault_episodes"] == 1
    assert recovered["transport_recovery_attempts"] == 1
    assert recovered["transport_recoveries"] == 1
    assert recovered["unresolved_transport_faults"] == 0
    assert recovered["permanent_faults"] == 0
    assert recovered["fault_stage"] is None
    assert recovered["fault_reason"] is None
    assert recovered["retry_not_before_monotonic_ns"] is None
    assert anchor.confirm_calls == int(post_commit)
    store.close()

    reopened_anchor = _ScriptedAnchor(durable, {})
    reopened = SQLiteStorage(database, "warden-a", (10,), **_options(reopened_anchor))
    try:
        persisted = reopened.authority_anchor_status()
        assert persisted["transport_faults"] == 0
        assert persisted["transport_recoveries"] == 0
        assert persisted["lifetime_id"] != recovered["lifetime_id"]
    finally:
        reopened.close()


def test_repeated_transport_failure_rearms_backoff_and_preserves_first_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [30_000_000_000]
    monkeypatch.setattr(sqlite_module.time, "monotonic_ns", lambda: now[0])
    durable = FileAuthorityAnchor(tmp_path / "independent" / "anchor.json")
    first = _transport_failure(operation="read", request_flushed=False)
    repeated = _transport_failure(operation="read")
    anchor = _ScriptedAnchor(durable, {2: first, 3: repeated})
    store = SQLiteStorage.initialize(
        tmp_path / "warden.sqlite3", "warden-a", (10,), **_options(anchor)
    )
    with pytest.raises(AuthorityAnchorTransportError):
        store.authority_checkpoint()
    initial_first_fault = store.authority_anchor_status()["first_fault"]
    now[0] += 250_000_000
    with pytest.raises(AuthorityAnchorTransportError):
        store.authority_checkpoint()
    repeated_status = store.authority_anchor_status()
    assert repeated_status["transport_faults"] == 2
    assert repeated_status["transport_fault_episodes"] == 1
    assert repeated_status["transport_recovery_attempts"] == 1
    assert repeated_status["transport_recoveries"] == 0
    assert repeated_status["first_fault"] == initial_first_fault
    calls = anchor.calls
    with pytest.raises(StorageError, match="cooldown"):
        store.authority_checkpoint()
    assert anchor.calls == calls
    now[0] += 500_000_000
    assert store.verify_authority_anchor()
    final = store.authority_anchor_status()
    assert final["transport_recovery_attempts"] == 2
    assert final["transport_recoveries"] == 1
    assert final["state"] == "healthy"
    store.close()


def test_non_transport_anchor_failure_is_permanent_and_never_reprobed(tmp_path: Path) -> None:
    durable = FileAuthorityAnchor(tmp_path / "independent" / "anchor.json")
    anchor = _ScriptedAnchor(durable, {2: StorageError("semantic divergence")})
    store = SQLiteStorage.initialize(
        tmp_path / "warden.sqlite3", "warden-a", (10,), **_options(anchor)
    )
    with pytest.raises(StorageError, match="semantic divergence"):
        store.authority_checkpoint()
    status = store.authority_anchor_status()
    assert status["state"] == "permanent_fault"
    assert status["permanent_faults"] == 1
    assert status["transport_faults"] == 0
    calls = anchor.calls
    with pytest.raises(StorageError, match="previously faulted"):
        store.authority_checkpoint()
    assert anchor.calls == calls
    store.close()


def test_malformed_typed_anchor_failure_is_permanent_and_never_reprobed(tmp_path: Path) -> None:
    durable = FileAuthorityAnchor(tmp_path / "independent" / "anchor.json")
    anchor = _ScriptedAnchor(durable, {2: _malformed_transport_failure()})
    store = SQLiteStorage.initialize(
        tmp_path / "warden.sqlite3", "warden-a", (10,), **_options(anchor)
    )
    with pytest.raises(StorageError, match="malformed transport failure") as raised:
        store.authority_checkpoint()
    assert "untrusted provider" not in str(raised.value)
    status = store.authority_anchor_status()
    assert status["state"] == "permanent_fault"
    assert status["fault_reason"] == "malformed_transport_error"
    assert status["permanent_faults"] == 1
    assert status["transport_faults"] == 0
    assert status["first_fault"] is None
    calls = anchor.calls
    with pytest.raises(StorageError, match="previously faulted"):
        store.authority_checkpoint()
    assert anchor.calls == calls
    store.close()


def test_authority_admission_fence_is_atomic_idempotent_and_terminal(tmp_path: Path) -> None:
    durable = FileAuthorityAnchor(tmp_path / "independent" / "anchor.json")
    anchor = _ScriptedAnchor(durable, {})
    store = SQLiteStorage.initialize(
        tmp_path / "warden.sqlite3", "warden-a", (10,), **_options(anchor)
    )
    lifetime = cast(str, store.authority_anchor_status()["lifetime_id"])
    with pytest.raises(ConflictError, match="lifetime does not match"):
        store.fence_authority_admission(
            restart_id="restart-wrong-lifetime",
            expected_lifetime_id="0" * 32,
        )
    assert store.verify_authority_anchor()
    calls = anchor.calls
    terminal = store.fence_authority_admission(
        restart_id="restart-0001",
        expected_lifetime_id=lifetime,
    )
    assert terminal["schema"] == "lets.authority-admission-fence/v1"
    assert terminal["restart_id"] == "restart-0001"
    assert terminal["warden_id"] == "warden-a"
    assert terminal["lifetime_id"] == lifetime
    status = cast(dict[str, object], terminal["authority_anchor"])
    assert status == store.authority_anchor_status()
    assert status["admission_fenced"] is True
    assert status["fence_id"] == "restart-0001"
    assert status["state"] == "healthy"
    assert status["unresolved_transport_faults"] == 0
    assert status["permanent_faults"] == 0
    assert anchor.calls == calls
    assert (
        store.fence_authority_admission(
            restart_id="restart-0001",
            expected_lifetime_id=lifetime,
        )
        == terminal
    )
    with pytest.raises(StorageError, match="admission is fenced"):
        store.authority_checkpoint()
    with pytest.raises(StorageError, match="admission is fenced"):
        store.capacity_snapshot()
    with pytest.raises(StorageError, match="admission is fenced"):
        store.clear_capacity_fault()
    with pytest.raises(StorageError, match="admission is fenced"):
        store.checkpoint()
    assert anchor.calls == calls
    with pytest.raises(ConflictError, match="already fenced"):
        store.fence_authority_admission(
            restart_id="restart-0002",
            expected_lifetime_id=lifetime,
        )
    with pytest.raises(ConflictError, match="already fenced"):
        store.fence_authority_admission(
            restart_id="restart-0001",
            expected_lifetime_id="0" * 32,
        )
    store.close()


def test_authority_fence_waits_for_active_work_then_rejects_queued_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class OrderedRLock:
        def __init__(self) -> None:
            self._condition = threading.Condition()
            self._next_ticket = 0
            self._serving = 0
            self._owner: int | None = None
            self._depth = 0

        def acquire(self) -> bool:
            identity = threading.get_ident()
            with self._condition:
                if self._owner == identity:
                    self._depth += 1
                    return True
                ticket = self._next_ticket
                self._next_ticket += 1
                self._condition.notify_all()
                self._condition.wait_for(
                    lambda: ticket == self._serving and self._owner is None,
                    timeout=5,
                )
                assert ticket == self._serving and self._owner is None
                self._owner = identity
                self._depth = 1
                return True

        def release(self) -> None:
            identity = threading.get_ident()
            with self._condition:
                assert self._owner == identity and self._depth > 0
                self._depth -= 1
                if self._depth == 0:
                    self._owner = None
                    self._serving += 1
                    self._condition.notify_all()

        def wait_for_tickets(self, count: int) -> None:
            with self._condition:
                assert self._condition.wait_for(
                    lambda: self._next_ticket >= count,
                    timeout=5,
                )

        def __enter__(self) -> OrderedRLock:
            self.acquire()
            return self

        def __exit__(self, *arguments: object) -> None:
            del arguments
            self.release()

    durable = FileAuthorityAnchor(tmp_path / "independent" / "anchor.json")
    anchor = _ScriptedAnchor(durable, {})
    store = SQLiteStorage.initialize(
        tmp_path / "warden.sqlite3", "warden-a", (10,), **_options(anchor)
    )
    ordered = OrderedRLock()
    store._authority_transaction_lock = cast(Any, ordered)
    lifetime = cast(str, store.authority_anchor_status()["lifetime_id"])
    active_entered = threading.Event()
    release_active = threading.Event()
    fence_result: list[dict[str, object]] = []
    queued_errors: list[BaseException] = []

    def active_transaction() -> None:
        with store.read():
            active_entered.set()
            assert release_active.wait(timeout=5)

    active = threading.Thread(target=active_transaction)
    active.start()
    assert active_entered.wait(timeout=5)

    connect_calls = 0
    original_connect = store._connect

    def counted_connect(*arguments: Any, **options: Any) -> Any:
        nonlocal connect_calls
        connect_calls += 1
        return original_connect(*arguments, **options)

    monkeypatch.setattr(store, "_connect", counted_connect)

    def fence() -> None:
        fence_result.append(
            store.fence_authority_admission(
                restart_id="restart-queued",
                expected_lifetime_id=lifetime,
            )
        )

    fence_thread = threading.Thread(target=fence)
    fence_thread.start()
    ordered.wait_for_tickets(3)

    def queued_transaction() -> None:
        try:
            with store.read():
                raise AssertionError("queued transaction unexpectedly entered")
        except BaseException as exc:
            queued_errors.append(exc)

    queued = threading.Thread(target=queued_transaction)
    queued.start()
    ordered.wait_for_tickets(4)
    assert not fence_result
    release_active.set()
    active.join(timeout=5)
    fence_thread.join(timeout=5)
    queued.join(timeout=5)
    assert not active.is_alive() and not fence_thread.is_alive() and not queued.is_alive()
    assert fence_result[0]["restart_id"] == "restart-queued"
    assert len(queued_errors) == 1
    assert isinstance(queued_errors[0], StorageError)
    assert "admission is fenced" in str(queued_errors[0])
    assert connect_calls == 0
    store.close()


def test_authority_fence_rejects_same_thread_active_transaction(tmp_path: Path) -> None:
    durable = FileAuthorityAnchor(tmp_path / "independent" / "anchor.json")
    store = SQLiteStorage.initialize(
        tmp_path / "warden.sqlite3",
        "warden-a",
        (10,),
        **_options(durable),
    )
    lifetime = cast(str, store.authority_anchor_status()["lifetime_id"])

    with store.write():
        with pytest.raises(StorageError, match="during a transaction"):
            store.fence_authority_admission(
                restart_id="restart-reentrant",
                expected_lifetime_id=lifetime,
            )
        assert store.authority_anchor_status()["admission_fenced"] is False

    terminal = store.fence_authority_admission(
        restart_id="restart-after-commit",
        expected_lifetime_id=lifetime,
    )
    assert cast(dict[str, object], terminal["authority_anchor"])["admission_fenced"] is True
    store.close()


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
