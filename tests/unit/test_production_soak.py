from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import pytest

import deploy.production.acceptance.soak as soak_scenario
import deploy.production.run_soak as soak_runner
from deploy.production.acceptance.materialize import _nodes, acceptance_policy
from deploy.production.acceptance.soak import (
    NODES,
    TRANSFER_PAIRS,
    _bounded_audit_exporter,
    _health_sample,
    _is_converged,
    operation_plan,
    scheduled_transfer_pair,
)
from deploy.production.run_soak import (
    DEFAULT_RESTART_INTERVAL_SECONDS,
    Harness,
    ResourceBounds,
    SoakConfiguration,
    _canonical_digest,
    _expected_transfer_pair_counts,
    _next_restart_deadline,
    _preflight_zero,
    _restart_integrity,
    evaluate_health_cadence,
    evaluate_resource_bounds,
    evaluate_workload_result,
    may_start_chaos_episode,
    minimum_cycle_count,
    minimum_health_sample_count,
    validate_image_labels,
    validate_package_identity,
)

EXACT_IMAGE = "ghcr.io/astraldeep/lets@sha256:" + "a" * 64


def _configuration() -> SoakConfiguration:
    return SoakConfiguration(
        image=EXACT_IMAGE,
        duration_seconds=30,
        cycle_interval_seconds=0.1,
        health_interval_seconds=2,
        resource_interval_seconds=1,
        partition_interval_seconds=5,
        partition_duration_seconds=1,
        restart_interval_seconds=6,
        retry_timeout_seconds=30,
        convergence_timeout_seconds=60,
        transfer_every_cycles=2,
        executor_reopen_every_cycles=3,
        initial_share=10_000,
        seed=7,
        smoke=True,
    )


def _resource_node(*, rss: int, fds: int, database: int, audit: int) -> dict[str, object]:
    return {
        "audit": {
            "database_bytes": audit,
            "shared_memory_bytes": 32_768,
            "wal_bytes": 100_000,
        },
        "authority_anchor_bytes": 1_024,
        "container_init_pid": 100,
        "container_state": {"exit_code": 0, "oom_killed": False, "status": "running"},
        "core": {
            "database_bytes": database,
            "shared_memory_bytes": 32_768,
            "wal_bytes": 100_000,
        },
        "fd_count": fds,
        "init": {
            "cmdline": [
                "/sbin/docker-init",
                "--",
                "/usr/local/bin/lets",
                "--config",
                "/var/lib/lets/config.json",
                "serve",
            ],
            "pid": 1,
        },
        "process": {
            "cmdline": ["/usr/local/bin/python", "/usr/local/bin/lets", "serve"],
            "identity": "lets-serve",
            "pid": 7,
        },
        "restart_count": 0,
        "rss_bytes": rss,
        "signer_log_bytes": 10_000,
        "virtual_peak_bytes": rss * 2,
    }


def _sample(*, rss: int, fds: int, database: int, audit: int) -> dict[str, object]:
    return {
        "elapsed_seconds": 0.0,
        "nodes": {
            node: _resource_node(rss=rss, fds=fds, database=database, audit=audit) for node in NODES
        },
    }


def test_materializer_preserves_default_and_supports_large_soak_share(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert acceptance_policy().machine.transitions[0].name == "act"
    monkeypatch.delenv("LETS_ACCEPTANCE_INITIAL_SHARE", raising=False)
    assert {share for _, share, _, _ in _nodes()} == {(100,)}

    monkeypatch.setenv("LETS_ACCEPTANCE_INITIAL_SHARE", "250000")
    assert {share for _, share, _, _ in _nodes()} == {(250_000,)}

    monkeypatch.setenv("LETS_ACCEPTANCE_INITIAL_SHARE", "99")
    with pytest.raises(RuntimeError, match="between 100"):
        _nodes()


def test_soak_schedule_deterministically_covers_every_node_and_transfer_pair() -> None:
    plans = [operation_plan(index) for index in range(len(TRANSFER_PAIRS))]
    assert {plan["node"] for plan in plans} == set(NODES)
    assert {(plan["transfer_source"], plan["transfer_target"]) for plan in plans} == set(
        TRANSFER_PAIRS
    )
    assert plans == [operation_plan(index) for index in range(len(TRANSFER_PAIRS))]

    actual_filtered = [
        pair
        for cycle in range(3 * len(TRANSFER_PAIRS))
        if (pair := scheduled_transfer_pair(cycle, 3)) is not None
    ]
    assert actual_filtered == list(TRANSFER_PAIRS)


def test_configuration_requires_exact_digest_and_repeated_chaos_window() -> None:
    configuration = _configuration()
    configuration.validate()

    with pytest.raises(ValueError, match="exact name@sha256"):
        replace(configuration, image="ghcr.io/astraldeep/lets:latest").validate()
    with pytest.raises(ValueError, match="every warden"):
        replace(configuration, duration_seconds=10).validate()
    with pytest.raises(ValueError, match="at least 300"):
        replace(configuration, smoke=False).validate()
    assert DEFAULT_RESTART_INTERVAL_SECONDS == 900

    release = replace(
        configuration,
        duration_seconds=3_600,
        partition_interval_seconds=90,
        restart_interval_seconds=900,
        smoke=False,
    )
    release.validate()
    assert minimum_cycle_count(release) == 300
    assert minimum_health_sample_count(release) == 301
    assert may_start_chaos_episode(configuration, elapsed_s=19.99) is True
    assert may_start_chaos_episode(configuration, elapsed_s=20.0) is False
    assert may_start_chaos_episode(configuration, elapsed_s=30.0) is False
    assert _next_restart_deadline(prior_deadline=30, interval_s=30, completed_at=40) == 60
    assert _next_restart_deadline(prior_deadline=30, interval_s=30, completed_at=80) == 87.5


def test_workload_evaluation_enforces_exact_load_and_executor_relationships() -> None:
    configuration = _configuration()
    cycles = 3
    health_samples = [
        {
            "elapsed_seconds": elapsed,
            "nodes": {node: {"audit_exporter": {"max_stall_s": 15.0}} for node in NODES},
        }
        for elapsed in (5.0, 10.0, 20.0, 30.0)
    ]
    result: dict[str, Any] = {
        "audit_progress": {
            "bounded_progress": True,
            "catchup_sample_count": 1,
            "maximum_pending_by_node": {node: 5 for node in NODES},
            "sample_count": 4,
        },
        "counters": {
            "authorizations": 6,
            "closed": 3,
            "issued_roots": 3,
            "quiesced": 3,
            "renewed": 3,
            "resumed": 3,
            "transfers_prepared": 2,
        },
        "cycles": cycles,
        "duration_seconds": 30.0,
        "executor": {
            "claims": 6,
            "reopen_count": 1,
            "replay_rejections": 7,
            "status": {"claim_sequence": 6},
        },
        "health_sample_count": 4,
        "health_samples": health_samples,
        "latency": {"buckets_ms": {"overflow": 0}, "count": 3, "maximum_ms": 500},
        "request_retry_count": 2,
        "transfer_pair_counts": _expected_transfer_pair_counts(
            cycles=cycles,
            transfer_every_cycles=configuration.transfer_every_cycles,
        ),
    }
    evaluation = evaluate_workload_result(result, configuration)
    assert evaluation["passed"] is True
    assert evaluation["metrics"]["required_cycles"] == 3
    assert evaluation["metrics"]["required_health_samples"] == 4
    assert evaluation["metrics"]["health_cadence"]["maximum_gap_seconds"] == 10.0

    result["health_samples"] = [{**sample, "elapsed_seconds": 0.0} for sample in health_samples]
    cadence_failed = evaluate_workload_result(result, configuration)
    assert cadence_failed["passed"] is False
    assert "health_cadence" in cadence_failed["violations"]
    result["health_samples"] = health_samples

    result["counters"] = {**result["counters"], "closed": 2}
    result["request_retry_count"] = 25
    result["latency"] = {
        "buckets_ms": {"overflow": 1},
        "count": 3,
        "maximum_ms": 61_000,
    }
    failed = evaluate_workload_result(result, configuration)
    assert failed["passed"] is False
    assert set(failed["violations"]) >= {
        "counter_relationships",
        "cycle_latency_bounded",
        "retry_budget",
    }


def test_health_cadence_rejects_gaps_larger_than_the_exporter_stall_bound() -> None:
    samples = [
        {
            "elapsed_seconds": elapsed,
            "nodes": {node: {"audit_exporter": {"max_stall_s": 15.0}} for node in NODES},
        }
        for elapsed in (5.0, 10.0, 26.0, 30.0)
    ]
    result = evaluate_health_cadence(samples, duration_seconds=30.0)
    assert result["passed"] is False
    assert result["maximum_gap_seconds"] == 16.0


def test_resource_bounds_accept_bounded_growth_and_report_leaks() -> None:
    samples = [
        _sample(rss=64_000_000, fds=20, database=2_000_000, audit=1_000_000),
        _sample(rss=66_000_000, fds=22, database=3_000_000, audit=2_000_000),
    ]
    passed = evaluate_resource_bounds(samples, cycles=20, bounds=ResourceBounds())
    assert passed["passed"] is True
    assert passed["violations"] == []
    assert all(all(node["checks"].values()) for node in passed["measurements"].values())

    leaked = [
        samples[0],
        _sample(rss=700_000_000, fds=700, database=101 * 1024 * 1024, audit=80_000_000),
    ]
    failed = evaluate_resource_bounds(leaked, cycles=1, bounds=ResourceBounds())
    assert failed["passed"] is False
    assert any(item.endswith(":fd_count") for item in failed["violations"])
    assert any(item.endswith(":core_database") for item in failed["violations"])

    tini = _sample(rss=524_288, fds=3, database=2_000_000, audit=1_000_000)
    for node in NODES:
        tini["nodes"][node]["process"] = {
            "cmdline": ["/sbin/tini", "--"],
            "identity": "tini",
            "pid": 1,
        }
        tini["nodes"][node]["container_state"]["oom_killed"] = True
        tini["nodes"][node]["restart_count"] = 1
    invalid_process = evaluate_resource_bounds(
        [samples[0], tini], cycles=1, bounds=ResourceBounds()
    )
    assert invalid_process["passed"] is False
    assert all(f"{node}:runtime_process" in invalid_process["violations"] for node in NODES)
    assert all(f"{node}:container_integrity" in invalid_process["violations"] for node in NODES)


def test_convergence_rejects_in_flight_transfers_and_inbound_gaps() -> None:
    sample = {
        "nodes": {
            node: {
                "audit_exporter": {
                    "archive_reconciled": True,
                    "catching_up": False,
                    "healthy": True,
                    "pending": 0,
                    "running": True,
                },
                "audit_outbox": {"unpublished_count": 0},
                "peer_dispatcher": {
                    "configured_peers": 2,
                    "failed_records": 0,
                    "last_cycle_ns": 1,
                    "last_error": None,
                    "pending_records": 0,
                    "prepared_transfers": 0,
                },
                "ready": True,
                "service_ready": True,
                "transfers": {"in_flight_count": 0, "inbound_gap_count": 0},
            }
            for node in NODES
        }
    }
    assert _is_converged(sample) is True
    sample["nodes"]["warden-a"]["transfers"]["in_flight_count"] = 1
    assert _is_converged(sample) is False
    sample["nodes"]["warden-a"]["transfers"]["in_flight_count"] = 0
    sample["nodes"]["warden-b"]["transfers"]["inbound_gap_count"] = 2
    assert _is_converged(sample) is False
    sample["nodes"]["warden-b"]["transfers"]["inbound_gap_count"] = 0
    sample["nodes"]["warden-c"]["peer_dispatcher"]["failed_records"] = 1
    assert _is_converged(sample) is False
    sample["nodes"]["warden-c"]["peer_dispatcher"]["failed_records"] = 0
    sample["nodes"]["warden-c"]["peer_dispatcher"]["last_error"] = "checkpoint failed"
    assert _is_converged(sample) is False


def _audit_status(**overrides: object) -> dict[str, object]:
    status: dict[str, object] = {
        "archive_reconciled": False,
        "healthy": False,
        "last_error": None,
        "last_success_ns": 123,
        "max_pending": 4_096,
        "max_stall_s": 15.0,
        "oldest_pending_age_s": 2.558,
        "pending": 5,
        "publish_blocked": False,
        "running": True,
        "sink_call_blocked": False,
        "stalled_for_s": 0.005,
    }
    status.update(overrides)
    return status


def test_health_sample_accepts_only_bounded_audit_catchup() -> None:
    class FakeClient:
        @staticmethod
        def request(_method: str, _node: str, path: str) -> dict[str, Any]:
            if path == "/v1/invariants":
                return {
                    "consumed": [1],
                    "free_pool": [9],
                    "healthy": True,
                    "lease_residual": [0],
                    "transferred_in": [0],
                    "transferred_out": [0],
                }
            if path == "/v1/audit/verify":
                return {"valid": True}
            return {
                "audit_exporter": _audit_status(),
                "audit_outbox": {"unpublished_count": 5},
                "peer_dispatcher": {"pending_records": 0, "prepared_transfers": 0},
                "ready": False,
                "receipts": {"total": 1},
                "service_ready": True,
                "storage_capacity": {"healthy": True},
                "transfers": {"in_flight_count": 0, "inbound_gap_count": 0},
            }

    sample = _health_sample(FakeClient(), elapsed_s=2.75)  # type: ignore[arg-type]
    assert sample["audit_catchup_nodes"] == list(NODES)
    assert sample["nodes"]["warden-a"]["audit_exporter"]["pending"] == 5
    assert _is_converged(sample) is False


@pytest.mark.parametrize(
    ("service_ready", "ready", "match"),
    (
        (False, False, "core service is not ready"),
        (True, True, "inconsistent aggregate readiness"),
    ),
)
def test_health_sample_does_not_mask_core_or_aggregate_readiness_failures(
    service_ready: bool, ready: bool, match: str
) -> None:
    class FakeClient:
        @staticmethod
        def request(_method: str, _node: str, path: str) -> dict[str, Any]:
            if path == "/v1/invariants":
                return {"healthy": True}
            if path == "/v1/audit/verify":
                return {"valid": True}
            return {
                "audit_exporter": _audit_status(),
                "ready": ready,
                "service_ready": service_ready,
                "storage_capacity": {"healthy": True},
            }

    with pytest.raises(RuntimeError, match=match):
        _health_sample(FakeClient(), elapsed_s=1.0)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("overrides", "match"),
    (
        ({"last_error": "archive unavailable"}, "bounded progress"),
        ({"publish_blocked": True, "sink_call_blocked": True}, "bounded progress"),
        ({"pending": 4_097}, "bounded progress"),
        ({"stalled_for_s": 15.001}, "bounded progress"),
        ({"oldest_pending_age_s": 15.001}, "bounded progress"),
        ({"running": False}, "bounded progress"),
        ({"healthy": True}, "inconsistent"),
        (
            {
                "archive_reconciled": True,
                "healthy": True,
                "oldest_pending_age_s": None,
                "pending": 0,
                "stalled_for_s": 15.001,
            },
            "bounded progress",
        ),
    ),
)
def test_audit_catchup_rejects_errors_blocks_stalls_and_inconsistent_health(
    overrides: dict[str, object], match: str
) -> None:
    with pytest.raises(RuntimeError, match=match):
        _bounded_audit_exporter(_audit_status(**overrides), node="warden-a")


def test_workload_pause_acknowledges_and_preserves_health_cadence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    pause = tmp_path / "pause.json"
    acknowledgement = tmp_path / "pause-ack.json"
    pause.write_text('{"episode":4}\n', encoding="utf-8")
    monkeypatch.setattr(soak_scenario, "WORKLOAD_PAUSE", pause)
    monkeypatch.setattr(soak_scenario, "WORKLOAD_PAUSE_ACK", acknowledgement)
    monkeypatch.setattr(soak_scenario.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(
        soak_scenario,
        "_health_sample",
        lambda _client, *, elapsed_s: {"elapsed_seconds": elapsed_s},
    )
    monkeypatch.setattr(soak_scenario.time, "sleep", lambda _seconds: pause.unlink())
    samples: deque[dict[str, Any]] = deque(maxlen=512)
    next_health, count = soak_scenario._wait_if_paused(
        object(),  # type: ignore[arg-type]
        health_interval_seconds=10,
        health_samples=samples,
        next_health=99,
        started=50,
    )
    assert count == 1
    assert next_health == 110
    assert list(samples) == [{"elapsed_seconds": 50.0}]
    assert acknowledgement.read_text(encoding="utf-8") == ('{"episode": 4, "paused": true}\n')


def test_evidence_payload_digest_is_order_independent_and_content_bound() -> None:
    first = {"schema": "example/v1", "nested": {"b": 2, "a": 1}}
    reordered = {"nested": {"a": 1, "b": 2}, "schema": "example/v1"}
    assert _canonical_digest(first) == _canonical_digest(reordered)
    assert _canonical_digest(first) != _canonical_digest({**first, "passed": True})


def test_runtime_image_labels_must_match_source_commit_and_package_version() -> None:
    labels = {
        "org.opencontainers.image.revision": "f" * 40,
        "org.opencontainers.image.version": "1.0.0",
    }
    validate_image_labels(labels, expected_revision="f" * 40, expected_version="1.0.0")

    with pytest.raises(RuntimeError, match="source/package"):
        validate_image_labels(labels, expected_revision="e" * 40, expected_version="1.0.0")
    with pytest.raises(RuntimeError, match="source/package"):
        validate_image_labels(labels, expected_revision="f" * 40, expected_version="1.0.1")

    runtime = {node: {"lets_agent": "1.0.0"} for node in NODES}
    identity = validate_package_identity(
        host_version="1.0.0",
        image={"labels": labels},
        runtime_packages=runtime,
        workload={"package_version": "1.0.0"},
        verification={"package_version": "1.0.0"},
    )
    assert identity["passed"] is True
    runtime["warden-c"]["lets_agent"] = "0.9.9"
    with pytest.raises(RuntimeError, match="identities do not match"):
        validate_package_identity(
            host_version="1.0.0",
            image={"labels": labels},
            runtime_packages=runtime,
            workload={"package_version": "1.0.0"},
            verification={"package_version": "1.0.0"},
        )
    runtime["warden-c"]["lets_agent"] = "1.0.0"
    for workload_version, verifier_version in (
        ("0.9.9", "1.0.0"),
        ("1.0.0", "0.9.9"),
    ):
        with pytest.raises(RuntimeError, match="identities do not match"):
            validate_package_identity(
                host_version="1.0.0",
                image={"labels": labels},
                runtime_packages=runtime,
                workload={"package_version": workload_version},
                verification={"package_version": verifier_version},
            )


def test_cleanup_proves_project_containers_volumes_and_networks_are_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeHarness:
        def __init__(self) -> None:
            self.compose_calls: list[tuple[str, ...]] = []
            self.allowed_volumes: set[str] = set()

        def compose(self, *arguments: str, **_options: Any) -> str:
            self.compose_calls.append(arguments)
            return ""

    harness = FakeHarness()
    volume_snapshots: Iterator[set[str]] = iter((set(), set()))
    monkeypatch.setattr(soak_runner, "_project_volumes", lambda _harness: next(volume_snapshots))
    monkeypatch.setattr(soak_runner, "_project_containers", lambda _harness: set())
    monkeypatch.setattr(soak_runner, "_project_networks", lambda _harness: set())
    result = soak_runner._checked_down(harness)  # type: ignore[arg-type]
    assert result == {
        "performed": True,
        "remaining_containers": 0,
        "remaining_networks": 0,
        "remaining_volumes": 0,
    }
    assert harness.compose_calls == [("down", "--volumes", "--remove-orphans")]

    harness = FakeHarness()
    volume_snapshots = iter((set(), {"leftover-volume"}))
    monkeypatch.setattr(soak_runner, "_project_volumes", lambda _harness: next(volume_snapshots))
    with pytest.raises(RuntimeError, match="cleanup left project resources"):
        soak_runner._checked_down(harness)  # type: ignore[arg-type]


def test_unique_project_preflight_and_restart_integrity_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = Harness(_configuration())
    second = Harness(_configuration())
    assert first.project != second.project
    assert first.project in first.compose_command
    assert all(name.startswith(f"{first.project}_") for name in first.allowed_volumes)

    monkeypatch.setattr(soak_runner, "_project_volumes", lambda _harness: set())
    monkeypatch.setattr(soak_runner, "_project_containers", lambda _harness: set())
    monkeypatch.setattr(soak_runner, "_project_networks", lambda _harness: set())
    assert _preflight_zero(first) == {
        "containers": 0,
        "networks": 0,
        "passed": True,
        "volumes": 0,
    }
    monkeypatch.setattr(soak_runner, "_project_networks", lambda _harness: {"unexpected-network"})
    with pytest.raises(RuntimeError, match="not empty before startup"):
        _preflight_zero(first)

    class RestartHarness:
        configuration = _configuration()

        @staticmethod
        def state(_service: str) -> dict[str, Any]:
            return {"ExitCode": 0, "OOMKilled": False, "Status": "running"}

        @staticmethod
        def restart_count(_service: str) -> int:
            return 0

    restarts = [
        {"elapsed_seconds": 6.0, "service": "warden-a"},
        {"elapsed_seconds": 12.0, "service": "warden-b"},
        {"elapsed_seconds": 18.0, "service": "warden-c"},
    ]
    integrity = _restart_integrity(
        RestartHarness(),
        restarts,
        chaos_duration_seconds=30.0,  # type: ignore[arg-type]
    )
    assert integrity["all_wardens_sigkilled"] is True
    assert integrity["longest_sigkill_free_seconds"] == 12.0
    assert integrity["per_warden_lifetimes"] == {
        "warden-a": {
            "longest_seconds": 24.0,
            "passed": True,
            "planned_sigkill_seconds": [6.0],
            "segments_seconds": [6.0, 24.0],
        },
        "warden-b": {
            "longest_seconds": 18.0,
            "passed": True,
            "planned_sigkill_seconds": [12.0],
            "segments_seconds": [12.0, 18.0],
        },
        "warden-c": {
            "longest_seconds": 18.0,
            "passed": True,
            "planned_sigkill_seconds": [18.0],
            "segments_seconds": [18.0, 12.0],
        },
    }

    class RestartedHarness(RestartHarness):
        @staticmethod
        def restart_count(_service: str) -> int:
            return 1

    with pytest.raises(RuntimeError, match="unplanned automatic restart"):
        _restart_integrity(
            RestartedHarness(),  # type: ignore[arg-type]
            restarts,
            chaos_duration_seconds=30.0,
        )
