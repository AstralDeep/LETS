from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from jsonschema import Draft202012Validator

import lets.api as api_module
import lets.observation as observation_module
from lets.api import create_app
from lets.auth import StaticBearerAuthenticator
from lets.authority import FileAuthorityAnchor
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import SignatureError, StorageError
from lets.models import IdentityContext
from lets.observation import OBSERVATION_SNAPSHOT_MAX_BYTES, ObservationPublisher
from lets.peer import PeerDispatcher
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage


@dataclass(frozen=True)
class _ObservationStack:
    store: SQLiteStorage
    service: WardenService
    publisher: ObservationPublisher
    admin: IdentityContext


def _policy(policy_id: str) -> PolicySpec:
    return PolicySpec(
        policy_id=policy_id,
        policy_version=policy_id,
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


@pytest.fixture
def observation_stack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_ObservationStack]:
    signer = Ed25519Signer.generate("warden-a")
    registry = PublicKeyRegistry()
    registry.register_signer(signer)
    store = SQLiteStorage.initialize(
        tmp_path / "warden.sqlite3",
        "warden-a",
        (10,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="production-acceptance-tenant",
        envelope_id="production-acceptance-envelope",
        config_epoch=1,
        initial_local_share=(10,),
        receipt_ttl_ns=100,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=4,
        authority_anchor=FileAuthorityAnchor(tmp_path / "authority" / "anchor.json"),
    )
    service = WardenService(
        store,
        signer=signer,
        clock=ManualClock(1_000_000_000, 0),
        trust_registry=registry,
    )
    dispatcher = PeerDispatcher(service, store, signer, {})
    monkeypatch.setattr(
        dispatcher,
        "volatile_status",
        lambda: {
            "configured_peers": 0,
            "healthy": True,
            "last_cycle_ns": 1,
            "last_error": None,
            "running": True,
        },
    )
    metrics_identity = IdentityContext(
        "metrics",
        "production-acceptance-tenant",
        frozenset({"lets.admin", "lets.metrics.read"}),
    )
    publisher = ObservationPublisher(
        service,
        store,
        metrics_identity,
        peer_dispatcher=dispatcher,
        audit_exporter=None,
        capture_interval_s=0.05,
        admission_timeout_s=0.5,
        sql_timeout_s=0.5,
        audit_page_size=1,
    )
    admin = IdentityContext(
        "admin",
        "production-acceptance-tenant",
        frozenset({"lets.admin"}),
    )
    try:
        yield _ObservationStack(store, service, publisher, admin)
    finally:
        publisher.stop()
        store.close()


def test_terminal_verification_requires_bootstrap_before_fencing(
    observation_stack: _ObservationStack,
) -> None:
    store = observation_stack.store
    publisher = observation_stack.publisher
    lifetime = store.authority_anchor_status()["lifetime_id"]
    assert isinstance(lifetime, str)

    with pytest.raises(RuntimeError, match="bootstrap has not completed"):
        store.fence_authority_admission(
            restart_id="pre-bootstrap",
            expected_lifetime_id=lifetime,
            full_audit_verification=True,
            terminal_audit_verifier=publisher.verify_terminal,
        )
    assert store.authority_anchor_status()["admission_fenced"] is False

    publisher.bootstrap_audit()
    terminal = store.fence_authority_admission(
        restart_id="post-bootstrap",
        expected_lifetime_id=lifetime,
        full_audit_verification=True,
        terminal_audit_verifier=publisher.verify_terminal,
    )
    proof = terminal["terminal_audit_proof"]
    assert isinstance(proof, dict)
    assert proof["valid"] is True
    assert proof["verification_mode"] == "full"
    assert isinstance(proof["startup_full_verification_at_ns"], int)
    assert proof["verified_at_ns"] >= proof["startup_full_verification_at_ns"]
    assert (
        store.fence_authority_admission(
            restart_id="post-bootstrap",
            expected_lifetime_id=lifetime,
            full_audit_verification=True,
            terminal_audit_verifier=publisher.verify_terminal,
        )
        == terminal
    )


def test_wall_clock_rollback_preserves_valid_snapshot_and_terminal_order(
    observation_stack: _ObservationStack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ScriptedTime:
        def __init__(self) -> None:
            self._wall = iter((300, 200, 100, 50))

        def time_ns(self) -> int:
            return next(self._wall)

        @staticmethod
        def monotonic() -> float:
            return time.monotonic()

        @staticmethod
        def monotonic_ns() -> int:
            return time.monotonic_ns()

    monkeypatch.setattr(observation_module, "time", ScriptedTime())
    publisher = observation_stack.publisher
    store = observation_stack.store
    publisher.bootstrap_audit()
    publisher.capture_once()
    document = publisher.metrics_document()

    assert document["captured_at_ns"] == 300
    assert document["published_at_ns"] == 300
    assert document["fresh"] is True
    assert document["ready"] is True
    audit = document["audit_verification"]
    assert isinstance(audit, dict)
    assert audit["last_full_verification_at_ns"] == 300
    assert audit["sweep_last_completed_at_ns"] == 300

    lifetime = store.authority_anchor_status()["lifetime_id"]
    assert isinstance(lifetime, str)
    terminal = store.fence_authority_admission(
        restart_id="rollback-safe",
        expected_lifetime_id=lifetime,
        terminal_audit_verifier=publisher.verify_terminal,
    )
    proof = terminal["terminal_audit_proof"]
    assert isinstance(proof, dict)
    assert proof["startup_full_verification_at_ns"] == 300
    assert proof["verified_at_ns"] == 300


def test_cached_snapshot_is_bounded_isolated_and_independent_of_storage_admission(
    observation_stack: _ObservationStack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher = observation_stack.publisher
    publisher.bootstrap_audit()
    publisher.capture_once()
    encoded = publisher._snapshot_bytes
    assert encoded is not None
    assert len(encoded) <= OBSERVATION_SNAPSHOT_MAX_BYTES

    poisoned = publisher.metrics_document()
    invariant = poisoned["invariant"]
    assert isinstance(invariant, dict)
    invariant["tenant_id"] = "poisoned"
    assert publisher.metrics_document()["invariant"]["tenant_id"] == (
        "production-acceptance-tenant"
    )

    entered = threading.Event()
    release = threading.Event()

    def hold_transaction() -> None:
        with observation_stack.store.read():
            entered.set()
            assert release.wait(2.0)

    holder = threading.Thread(target=hold_transaction, daemon=True)
    holder.start()
    assert entered.wait(2.0)
    started = time.perf_counter()
    cached = publisher.metrics_document()
    elapsed = time.perf_counter() - started
    release.set()
    holder.join(2.0)
    assert not holder.is_alive()
    assert cached["fresh"] is True
    assert elapsed < 0.1

    original_capture = publisher._durable_capture

    def fail_capture() -> dict[str, object]:
        raise StorageError("bounded injected capture failure")

    monkeypatch.setattr(publisher, "_durable_capture", fail_capture)
    with pytest.raises(StorageError, match="bounded injected"):
        publisher.capture_once()
    failed = publisher.metrics_document()
    assert failed["fresh"] is False
    assert failed["ready"] is False
    assert failed["capture_status"]["last_error_type"].endswith("StorageError")

    monkeypatch.setattr(publisher, "_durable_capture", original_capture)
    publisher.capture_once()
    assert publisher.metrics_document()["ready"] is True


def test_freshness_boundary_is_exact_and_immediately_fail_closed(
    observation_stack: _ObservationStack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher = observation_stack.publisher
    publisher.bootstrap_audit()
    publisher.capture_once()
    captured = publisher.metrics_document()["captured_at_monotonic_ns"]
    assert isinstance(captured, int)

    class FixedMonotonic:
        value = captured

        @classmethod
        def monotonic_ns(cls) -> int:
            return cls.value

    monkeypatch.setattr(observation_module, "time", FixedMonotonic)
    FixedMonotonic.value = captured + publisher._max_age_ns - 1
    assert publisher.metrics_document()["fresh"] is True
    FixedMonotonic.value = captured + publisher._max_age_ns
    stale = publisher.metrics_document()
    assert stale["age_ns"] == stale["max_age_ns"]
    assert stale["fresh"] is False
    assert stale["ready"] is False


def test_terminal_lock_timeout_is_retryable_and_not_sticky(
    observation_stack: _ObservationStack,
) -> None:
    publisher = observation_stack.publisher
    publisher.bootstrap_audit()
    entered = threading.Event()
    release = threading.Event()

    def hold_verifier() -> None:
        with publisher._audit_lock:
            entered.set()
            assert release.wait(2.0)

    holder = threading.Thread(target=hold_verifier, daemon=True)
    holder.start()
    assert entered.wait(2.0)
    try:
        with observation_stack.store.observation_read(timeout_s=0.5) as transaction:
            checkpoint = observation_stack.store.observation_checkpoint(transaction.connection)
            with pytest.raises(StorageError, match="lock exceeded"):
                publisher.verify_terminal(
                    transaction.connection,
                    checkpoint,
                    False,
                    time.monotonic() + 0.05,
                )
    finally:
        release.set()
        holder.join(2.0)
    assert not holder.is_alive()
    assert publisher._audit_sticky_error is None

    with observation_stack.store.observation_read(timeout_s=0.5) as transaction:
        checkpoint = observation_stack.store.observation_checkpoint(transaction.connection)
        proof = publisher.verify_terminal(
            transaction.connection,
            checkpoint,
            False,
            time.monotonic() + 1.0,
        )
    assert proof["valid"] is True
    assert proof["verification_mode"] == "trusted-startup-plus-tail"


def test_observation_admission_preempts_normal_fifo_and_timeout_cleans_reservation(
    observation_stack: _ObservationStack,
) -> None:
    store = observation_stack.store
    holder_entered = threading.Event()
    holder_release = threading.Event()
    order: list[str] = []
    errors: list[BaseException] = []

    def hold_normal() -> None:
        with store.read():
            holder_entered.set()
            assert holder_release.wait(2.0)

    def enter_normal() -> None:
        try:
            with store.read():
                order.append("normal")
        except BaseException as exc:
            errors.append(exc)

    def enter_observation() -> None:
        try:
            with store.observation_read(timeout_s=1.0):
                order.append("observation")
        except BaseException as exc:
            errors.append(exc)

    holder = threading.Thread(target=hold_normal, daemon=True)
    normal = threading.Thread(target=enter_normal, daemon=True)
    observation = threading.Thread(target=enter_observation, daemon=True)
    holder.start()
    assert holder_entered.wait(2.0)
    normal.start()

    def wait_for_class(admission_class: int) -> None:
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            with store._authority_admission_condition:
                if admission_class in store._authority_admission_waiters.values():
                    return
            time.sleep(0.005)
        raise AssertionError(f"authority admission class {admission_class} was not queued")

    wait_for_class(0)
    observation.start()
    wait_for_class(1)
    holder_release.set()
    for thread in (holder, observation, normal):
        thread.join(2.0)
        assert not thread.is_alive()
    assert errors == []
    assert order == ["observation", "normal"]

    holder_entered.clear()
    holder_release.clear()
    holder = threading.Thread(target=hold_normal, daemon=True)
    holder.start()
    assert holder_entered.wait(2.0)
    with (
        pytest.raises(StorageError, match="admission timed out"),
        store.observation_read(timeout_s=0.02),
    ):
        raise AssertionError("timed-out observation unexpectedly entered")
    with store._authority_admission_condition:
        assert 1 not in store._authority_admission_waiters.values()
    holder_release.set()
    holder.join(2.0)
    assert not holder.is_alive()


def test_publisher_start_stop_relinquishes_lane_before_storage_close(
    observation_stack: _ObservationStack,
) -> None:
    publisher = observation_stack.publisher
    publisher.bootstrap_audit()
    publisher.start()
    assert publisher.metrics_document()["fresh"] is True
    publisher.stop()
    assert publisher._thread is None
    with observation_stack.store.read() as transaction:
        assert transaction.scalar("SELECT 1") == 1


def test_post_proof_fence_failure_does_not_advance_shared_audit_state(
    observation_stack: _ObservationStack,
) -> None:
    publisher = observation_stack.publisher
    service = observation_stack.service
    store = observation_stack.store
    publisher.bootstrap_audit()
    service.register_policy(_policy("post-proof-policy"), identity=observation_stack.admin)
    lifetime = store.authority_anchor_status()["lifetime_id"]
    assert isinstance(lifetime, str)

    def fail_after_proof(
        connection: Any,
        checkpoint: Any,
        full_verification: bool,
        deadline: float,
    ) -> dict[str, object]:
        proof = dict(
            publisher.verify_terminal(
                connection,
                checkpoint,
                full_verification,
                deadline,
            )
        )
        assert proof["valid"] is True
        raise StorageError("bounded injected post-proof fence failure")

    with pytest.raises(StorageError, match="post-proof fence failure"):
        store.fence_authority_admission(
            restart_id="post-proof-failure",
            expected_lifetime_id=lifetime,
            terminal_audit_verifier=fail_after_proof,
        )
    assert store.authority_anchor_status()["admission_fenced"] is False
    assert publisher._verified_sequence == -1
    assert publisher._audit_sticky_error is None

    publisher.capture_once()
    recovered = publisher.metrics_document()
    assert recovered["audit_verification"]["verified_through_sequence"] == 0
    assert recovered["audit_verification"]["sticky_failure"] is False
    assert recovered["ready"] is True
    terminal = store.fence_authority_admission(
        restart_id="post-proof-retry",
        expected_lifetime_id=lifetime,
        terminal_audit_verifier=publisher.verify_terminal,
    )
    assert terminal["terminal_audit_proof"]["valid"] is True


def test_historical_only_sweep_signature_failure_is_sticky(
    observation_stack: _ObservationStack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher = observation_stack.publisher
    service = observation_stack.service
    service.register_policy(_policy("historical-policy"), identity=observation_stack.admin)
    publisher.bootstrap_audit()

    def corrupt_historical_rows(*args: Any, **kwargs: Any) -> tuple[int, bytes]:
        raise SignatureError("bounded injected historical signature failure")

    monkeypatch.setattr(service, "verify_audit_rows", corrupt_historical_rows)
    publisher.capture_once()
    document = publisher.metrics_document()
    audit = document["audit_verification"]
    assert audit["verified_through_sequence"] == 0
    assert audit["captured_head_sequence"] == 0
    assert audit["sticky_failure"] is True
    assert audit["error_type"].endswith("SignatureError")
    assert document["ready"] is False


def test_incremental_audit_catchup_sweep_and_signature_failure_are_fail_closed(
    observation_stack: _ObservationStack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher = observation_stack.publisher
    service = observation_stack.service
    publisher.bootstrap_audit()
    service.register_policy(_policy("policy-a"), identity=observation_stack.admin)
    service.register_policy(_policy("policy-b"), identity=observation_stack.admin)

    publisher.capture_once()
    catching_up = publisher.metrics_document()
    audit = catching_up["audit_verification"]
    assert audit["catching_up"] is True
    assert audit["lag"] == 1
    assert catching_up["ready"] is False

    publisher.capture_once()
    caught_up = publisher.metrics_document()
    assert caught_up["audit_verification"]["valid"] is True
    assert caught_up["audit_verification"]["verified_through_sequence"] == 1
    publisher.capture_once()
    swept = publisher.metrics_document()["audit_verification"]
    assert swept["sweep_last_completed_head_sequence"] == 1

    service.register_policy(_policy("policy-c"), identity=observation_stack.admin)

    def corrupt_rows(*args: Any, **kwargs: Any) -> tuple[int, bytes]:
        raise SignatureError("bounded injected signature failure")

    monkeypatch.setattr(service, "verify_audit_rows", corrupt_rows)
    publisher.capture_once()
    failed = publisher.metrics_document()
    assert failed["audit_verification"]["sticky_failure"] is True
    assert failed["audit_verification"]["error_type"].endswith("SignatureError")
    assert failed["ready"] is False


def test_real_cached_api_document_matches_generated_openapi_without_threadpool(
    observation_stack: _ObservationStack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher = observation_stack.publisher
    publisher.bootstrap_audit()
    publisher.capture_once()

    async def cached_metrics() -> dict[str, object]:
        return publisher.metrics_document()

    async def cached_ready() -> bool:
        return publisher.ready()

    async def forbidden_threadpool(*args: object, **kwargs: object) -> object:
        raise AssertionError("cached production observation entered the shared threadpool")

    monkeypatch.setattr(api_module, "run_in_threadpool", forbidden_threadpool)
    metrics_identity = IdentityContext(
        "metrics",
        "production-acceptance-tenant",
        frozenset({"lets.metrics.read"}),
    )
    app = create_app(
        observation_stack.service,
        authenticator=StaticBearerAuthenticator.single("metrics-token", metrics_identity),
        readiness_check=cached_ready,
        metrics_provider=cached_metrics,
    )

    async def exercise() -> tuple[dict[str, object], dict[str, object]]:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
            ready = await client.get("/health/ready")
            assert ready.status_code == 200
            response = await client.get(
                "/v1/metrics",
                headers={"authorization": "Bearer metrics-token"},
            )
            assert response.status_code == 200
            return response.json(), app.openapi()

    metrics, openapi = asyncio.run(exercise())
    assert metrics["ready"] is True
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/ProductionMetricsSnapshot",
        "components": openapi["components"],
    }
    Draft202012Validator(schema).validate(metrics)
