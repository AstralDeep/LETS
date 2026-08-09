from __future__ import annotations

import textwrap
from collections import deque
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import deploy.production.acceptance.soak as soak_scenario
import deploy.production.run_soak as soak_runner
from deploy.production.acceptance.materialize import _nodes, acceptance_policy
from deploy.production.acceptance.soak import (
    AUDIT_ERROR_MAX_BYTES,
    AUDIT_ERROR_SAMPLE_BUDGET,
    NODES,
    TRANSFER_PAIRS,
    AuditErrorBudget,
    _audit_progress_summary,
    _bounded_audit_exporter,
    _health_sample,
    _is_converged,
    _poll_audit_error_recovery,
    operation_plan,
    scheduled_transfer_pair,
)
from deploy.production.run_soak import (
    DEFAULT_RESTART_INTERVAL_SECONDS,
    Harness,
    ResourceBounds,
    SoakConfiguration,
    WorkloadExitedError,
    _bounded_text,
    _canonical_digest,
    _capture_failure_resource_sample,
    _expected_transfer_pair_counts,
    _next_restart_deadline,
    _pause_workload,
    _pre_sigkill_resource_checkpoint,
    _preflight_zero,
    _restart_integrity,
    evaluate_health_cadence,
    evaluate_resource_bounds,
    evaluate_workload_result,
    may_start_chaos_episode,
    minimum_cycle_count,
    minimum_health_sample_count,
    run_soak,
    validate_image_labels,
    validate_package_identity,
)

EXACT_IMAGE = "ghcr.io/astraldeep/lets@sha256:" + "a" * 64
TRANSIENT_BUSY_ERROR = (
    "StorageError: could not connect to the audit archive "
    "(sqlite_errorname=SQLITE_BUSY, sqlite_errorcode=5)"
)


def test_release_soak_evidence_verifier_compiles_with_regex_dependency() -> None:
    workflow = (Path(__file__).parents[2] / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )
    step = workflow.split(
        "      - name: Require sustained evidence to bind the exact candidate and source\n",
        maxsplit=1,
    )[1].split("      - name: Archive failed production-profile soak diagnostics\n", maxsplit=1)[0]
    embedded = step.split("          python - <<'PY'\n", maxsplit=1)[1].split(
        "\n          PY", maxsplit=1
    )[0]
    source = textwrap.dedent(embedded)
    assert "\nimport math\n" in f"\n{source}"
    assert "\nimport re\n" in f"\n{source}"
    compile(source, "release-soak-evidence.py", "exec")


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
        "cgroup": {
            "memory": {
                "current_bytes": rss + 10_000_000,
                "events": {
                    "high": 0,
                    "low": 0,
                    "max": 0,
                    "oom": 0,
                    "oom_group_kill": 0,
                    "oom_kill": 0,
                },
                "max_bytes": 1024 * 1024 * 1024,
                "peak_bytes": rss + 20_000_000,
            },
            "pids": {
                "current": 5,
                "events": {"max": 0},
                "max": 256,
                "peak": 12,
            },
            "swap": {
                "current_bytes": 0,
                "events": {"fail": 0, "high": 0, "max": 0},
                "max_bytes": 0,
                "peak_bytes": 0,
            },
            "version": 2,
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
            "error_evidence_complete": True,
            "error_recovery_passed": True,
            "error_sample_budget": 1,
            "error_sample_count": 0,
            "error_samples_by_node": {node: 0 for node in NODES},
            "maximum_pending_by_node": {node: 5 for node in NODES},
            "recorded_error_sample_count": 0,
            "recorded_error_samples_by_node": {node: 0 for node in NODES},
            "recorded_recovered_error_sample_count": 0,
            "recorded_unresolved_error_nodes": [],
            "recovered_error_sample_count": 0,
            "sample_count": 4,
            "unresolved_error_nodes": [],
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

    valid_audit_progress = dict(result["audit_progress"])
    result["audit_progress"] = {
        **valid_audit_progress,
        "error_sample_count": 1,
    }
    error_evidence_failed = evaluate_workload_result(result, configuration)
    assert error_evidence_failed["passed"] is False
    assert "audit_error_recovery" in error_evidence_failed["violations"]
    result["audit_progress"] = valid_audit_progress

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
    bounds = ResourceBounds()
    assert bounds.max_rss_bytes == 256 * 1024 * 1024
    assert bounds.max_rss_growth_bytes == 128 * 1024 * 1024
    assert bounds.max_cgroup_memory_peak_bytes == 768 * 1024 * 1024
    assert bounds.cgroup_memory_max_bytes == 1024 * 1024 * 1024
    assert bounds.cgroup_swap_max_bytes == 0
    assert bounds.max_cgroup_pids_peak == 192
    assert bounds.cgroup_pids_max == 256
    samples = [
        _sample(rss=64_000_000, fds=20, database=2_000_000, audit=1_000_000),
        _sample(rss=66_000_000, fds=22, database=3_000_000, audit=2_000_000),
    ]
    passed = evaluate_resource_bounds(samples, cycles=20, bounds=bounds)
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


@pytest.mark.parametrize(
    ("controller", "field", "value", "violation"),
    (
        ("memory", "peak_bytes", 769 * 1024 * 1024, "cgroup_memory_peak"),
        ("memory", "max_bytes", 2 * 1024 * 1024 * 1024, "cgroup_memory_limit"),
        ("swap", "current_bytes", 1, "cgroup_swap_usage"),
        ("swap", "peak_bytes", 1, "cgroup_swap_usage"),
        ("swap", "max_bytes", 1, "cgroup_swap_limit"),
        ("pids", "peak", 193, "cgroup_pids_peak"),
        ("pids", "max", 255, "cgroup_pids_limit"),
    ),
)
def test_resource_bounds_reject_cgroup_limit_and_usage_regressions(
    controller: str,
    field: str,
    value: int,
    violation: str,
) -> None:
    samples = [
        _sample(rss=64_000_000, fds=20, database=2_000_000, audit=1_000_000),
        _sample(rss=66_000_000, fds=22, database=3_000_000, audit=2_000_000),
    ]
    samples[1]["nodes"]["warden-a"]["cgroup"][controller][field] = value
    result = evaluate_resource_bounds(samples, cycles=20, bounds=ResourceBounds())
    assert result["passed"] is False
    assert f"warden-a:{violation}" in result["violations"]


@pytest.mark.parametrize(
    ("controller", "event", "violation"),
    (
        ("memory", "max", "cgroup_memory_events"),
        ("memory", "oom", "cgroup_memory_events"),
        ("memory", "oom_kill", "cgroup_memory_events"),
        ("swap", "max", "cgroup_swap_events"),
        ("swap", "fail", "cgroup_swap_events"),
        ("pids", "max", "cgroup_pids_events"),
    ),
)
def test_resource_bounds_reject_every_cgroup_exhaustion_counter(
    controller: str,
    event: str,
    violation: str,
) -> None:
    samples = [
        _sample(rss=64_000_000, fds=20, database=2_000_000, audit=1_000_000),
        _sample(rss=66_000_000, fds=22, database=3_000_000, audit=2_000_000),
    ]
    samples[1]["nodes"]["warden-b"]["cgroup"][controller]["events"][event] = 1
    result = evaluate_resource_bounds(samples, cycles=20, bounds=ResourceBounds())
    assert result["passed"] is False
    assert f"warden-b:{violation}" in result["violations"]


def test_resource_bounds_fail_closed_when_cgroup_v2_evidence_is_missing() -> None:
    samples = [
        _sample(rss=64_000_000, fds=20, database=2_000_000, audit=1_000_000),
        _sample(rss=66_000_000, fds=22, database=3_000_000, audit=2_000_000),
    ]
    del samples[1]["nodes"]["warden-c"]["cgroup"]
    result = evaluate_resource_bounds(samples, cycles=20, bounds=ResourceBounds())
    assert result["passed"] is False
    assert "warden-c:cgroup_probe" in result["violations"]


def test_pre_sigkill_checkpoint_is_sampled_and_evaluated_before_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    samples = [_sample(rss=64_000_000, fds=20, database=2_000_000, audit=1_000_000)]
    captured: dict[str, Any] = {}

    def fake_sample(
        _harness: object,
        *,
        elapsed_s: float,
        reason: str,
        planned_sigkill_service: str | None = None,
        command_timeout: float | None = None,
    ) -> dict[str, Any]:
        captured.update(
            command_timeout=command_timeout,
            elapsed_s=elapsed_s,
            reason=reason,
            service=planned_sigkill_service,
        )
        return _sample(rss=65_000_000, fds=21, database=2_100_000, audit=1_100_000)

    def fake_evaluate(
        actual: list[dict[str, Any]], *, cycles: int, bounds: ResourceBounds
    ) -> dict[str, Any]:
        captured.update(sample_count=len(actual), cycles=cycles, bounds=bounds)
        return {"passed": True, "violations": []}

    monkeypatch.setattr(soak_runner, "_resource_sample", fake_sample)
    monkeypatch.setattr(soak_runner, "evaluate_resource_bounds", fake_evaluate)
    checkpoint = _pre_sigkill_resource_checkpoint(
        object(),  # type: ignore[arg-type]
        service="warden-b",
        elapsed_s=12.5,
        samples=samples,
        configuration=_configuration(),
        bounds=ResourceBounds(),
    )
    assert captured["reason"] == "pre_sigkill"
    assert captured["service"] == "warden-b"
    assert captured["sample_count"] == 2
    assert checkpoint == {
        "evaluation_passed": True,
        "sample_index": 1,
        "sample_reason": "pre_sigkill",
        "service": "warden-b",
    }

    monkeypatch.setattr(
        soak_runner,
        "evaluate_resource_bounds",
        lambda *_args, **_kwargs: {"passed": False, "violations": ["warden-b:swap"]},
    )
    with pytest.raises(RuntimeError, match="pre-SIGKILL resource bounds failed"):
        _pre_sigkill_resource_checkpoint(
            object(),  # type: ignore[arg-type]
            service="warden-b",
            elapsed_s=13.0,
            samples=samples,
            configuration=_configuration(),
            bounds=ResourceBounds(),
        )


def test_failure_resource_capture_records_success_and_bounded_unavailability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    samples: list[dict[str, Any]] = []
    captured: dict[str, Any] = {}

    def fake_sample(
        _harness: object,
        *,
        elapsed_s: float,
        reason: str,
        planned_sigkill_service: str | None = None,
        command_timeout: float | None = None,
    ) -> dict[str, Any]:
        captured.update(
            command_timeout=command_timeout,
            elapsed_s=elapsed_s,
            reason=reason,
            service=planned_sigkill_service,
        )
        return _sample(rss=65_000_000, fds=21, database=2_100_000, audit=1_100_000)

    monkeypatch.setattr(soak_runner, "_resource_sample", fake_sample)
    result = _capture_failure_resource_sample(
        object(),  # type: ignore[arg-type]
        elapsed_s=19.25,
        samples=samples,
    )
    assert result == {"attempted": True, "captured": True, "sample_index": 0}
    assert captured == {
        "command_timeout": 5.0,
        "elapsed_s": 19.25,
        "reason": "failure",
        "service": None,
    }
    assert len(samples) == 1

    oversized = "probe unavailable: " + "x" * (soak_runner.FAILED_EVIDENCE_MAX_TEXT_BYTES * 2)
    monkeypatch.setattr(
        soak_runner,
        "_resource_sample",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(oversized)),
    )
    unavailable = _capture_failure_resource_sample(
        object(),  # type: ignore[arg-type]
        elapsed_s=20.0,
        samples=samples,
    )
    assert unavailable["attempted"] is True
    assert unavailable["captured"] is False
    assert "truncated to bounded tail" in unavailable["error"]
    assert len(unavailable["error"].encode("utf-8")) <= soak_runner.FAILED_EVIDENCE_MAX_TEXT_BYTES
    assert len(samples) == 1

    monkeypatch.setattr(
        soak_runner,
        "_resource_sample",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            soak_runner.subprocess.TimeoutExpired(["docker", "inspect"], 5.0)
        ),
    )
    timed_out = _capture_failure_resource_sample(
        object(),  # type: ignore[arg-type]
        elapsed_s=21.0,
        samples=samples,
    )
    assert timed_out["attempted"] is True
    assert timed_out["captured"] is False
    assert "timed out after 5.0 seconds" in timed_out["error"]
    assert len(samples) == 1


def test_failure_resource_capture_propagates_five_second_timeout_per_command() -> None:
    class Result:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    class TimedHarness:
        def __init__(self) -> None:
            self.container_calls: list[tuple[str, float]] = []
            self.exec_timeouts: list[float] = []
            self.state_calls: list[tuple[str, float]] = []
            self.restart_calls: list[tuple[str, float]] = []

        def container(self, service: str, *, timeout: float) -> str:
            self.container_calls.append((service, timeout))
            return f"container-{service}"

        def run(self, _arguments: list[str], *, timeout: float) -> Result:
            self.exec_timeouts.append(timeout)
            document = _resource_node(
                rss=65_000_000,
                fds=21,
                database=2_100_000,
                audit=1_100_000,
            )
            return Result(soak_runner.json.dumps(document))

        def container_state(self, container: str, *, timeout: float) -> dict[str, Any]:
            self.state_calls.append((container, timeout))
            return {"ExitCode": 0, "OOMKilled": False, "Pid": 100, "Status": "running"}

        def container_restart_count(self, container: str, *, timeout: float) -> int:
            self.restart_calls.append((container, timeout))
            return 0

    harness = TimedHarness()
    samples: list[dict[str, Any]] = []
    result = _capture_failure_resource_sample(
        harness,  # type: ignore[arg-type]
        elapsed_s=2.0,
        samples=samples,
    )
    assert result == {"attempted": True, "captured": True, "sample_index": 0}
    assert harness.container_calls == [(node, 5.0) for node in NODES]
    assert harness.exec_timeouts == [5.0, 5.0, 5.0]
    assert harness.state_calls == [(f"container-{node}", 5.0) for node in NODES]
    assert harness.restart_calls == [(f"container-{node}", 5.0) for node in NODES]
    assert (
        len(harness.container_calls)
        + len(harness.exec_timeouts)
        + len(harness.state_calls)
        + len(harness.restart_calls)
    ) * soak_runner.FAILURE_COMMAND_TIMEOUT_SECONDS == 60.0
    assert samples[0]["reason"] == "failure"
    assert set(samples[0]["nodes"]) == set(NODES)


def test_harness_inspection_helpers_propagate_explicit_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(_configuration())
    compose_timeouts: list[float] = []
    run_timeouts: list[float] = []

    def fake_compose(*_arguments: str, timeout: float, **_options: Any) -> str:
        compose_timeouts.append(timeout)
        return "container-warden-a"

    class Result:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    def fake_run(arguments: list[str], *, timeout: float, **_options: Any) -> Result:
        run_timeouts.append(timeout)
        if any(".RestartCount" in item for item in arguments):
            return Result("0")
        return Result('{"ExitCode":0,"OOMKilled":false,"Pid":100,"Status":"running"}')

    monkeypatch.setattr(harness, "compose", fake_compose)
    monkeypatch.setattr(harness, "run", fake_run)
    assert harness.state("warden-a", timeout=5.0)["Status"] == "running"
    assert harness.restart_count("warden-a", timeout=5.0) == 0
    assert harness.container_state("container-warden-a", timeout=5.0)["Pid"] == 100
    assert harness.container_restart_count("container-warden-a", timeout=5.0) == 0
    assert compose_timeouts == [5.0, 5.0]
    assert run_timeouts == [5.0, 5.0, 5.0, 5.0]


def test_convergence_rejects_in_flight_transfers_and_inbound_gaps() -> None:
    sample = {
        "nodes": {
            node: {
                "audit_exporter": {
                    "archive_reconciled": True,
                    "catching_up": False,
                    "healthy": True,
                    "last_error": None,
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
    sample["nodes"]["warden-c"]["peer_dispatcher"]["last_error"] = None
    sample["nodes"]["warden-a"]["audit_exporter"]["last_error"] = "archive failed"
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


def _clean_audit_status() -> dict[str, object]:
    return _audit_status(
        archive_reconciled=True,
        catching_up=False,
        healthy=True,
        last_error=None,
        oldest_pending_age_s=None,
        pending=0,
        stalled_for_s=0.1,
    )


def _audit_document(status: dict[str, object]) -> dict[str, object]:
    return {
        "audit_exporter": status,
        "audit_outbox": {"unpublished_count": 0 if status["pending"] == 0 else status["pending"]},
        "ready": status["healthy"],
        "service_ready": True,
    }


def _audit_health_sample(
    elapsed: float,
    *,
    error_nodes: tuple[str, ...] = (),
    recovered_nodes: tuple[str, ...] = (),
) -> dict[str, Any]:
    nodes: dict[str, Any] = {}
    recoveries: list[dict[str, Any]] = []
    for node in NODES:
        if node in error_nodes:
            status = _audit_status(
                last_error=TRANSIENT_BUSY_ERROR,
                oldest_pending_age_s=None,
                pending=0,
                stalled_for_s=5.0,
            )
        else:
            status = _clean_audit_status()
        nodes[node] = _audit_document(status)
        if node in recovered_nodes:
            recoveries.append(
                {
                    **_audit_document(_clean_audit_status()),
                    "elapsed_seconds": elapsed + 1.0,
                    "node": node,
                    "remaining_stall_window_seconds": 10.0,
                }
            )
    return {
        "audit_catchup_nodes": list(error_nodes),
        "audit_error_recoveries": recoveries,
        "elapsed_seconds": elapsed,
        "nodes": nodes,
    }


@pytest.mark.parametrize(
    "last_error",
    (
        TRANSIENT_BUSY_ERROR,
        (
            "StorageError: could not connect to the audit archive "
            "(sqlite_errorname=SQLITE_BUSY_RECOVERY, sqlite_errorcode=261)"
        ),
        (
            "StorageError: could not connect to the audit archive "
            "(sqlite_errorname=SQLITE_BUSY_SNAPSHOT, sqlite_errorcode=517)"
        ),
        (
            "StorageError: could not connect to the audit archive "
            "(sqlite_errorname=SQLITE_BUSY_TIMEOUT, sqlite_errorcode=773)"
        ),
    ),
)
def test_bounded_audit_exporter_accepts_exact_isolated_transient_status(
    last_error: str,
) -> None:
    result = _bounded_audit_exporter(
        _audit_status(
            last_error=last_error,
            oldest_pending_age_s=None,
            pending=0,
            stalled_for_s=5.114,
        ),
        node="warden-c",
    )
    assert result["catching_up"] is True
    assert result["last_success_ns"] == 123
    assert result["last_error"] == last_error


@pytest.mark.parametrize(
    ("overrides", "match"),
    (
        ({"last_error": ""}, "malformed bounded"),
        ({"last_error": " "}, "malformed bounded"),
        ({"last_error": 7}, "malformed bounded"),
        ({"last_error": "x" * (AUDIT_ERROR_MAX_BYTES + 1)}, "malformed bounded"),
        ({"last_error": "archive unavailable"}, "non-tolerable"),
        (
            {
                "last_error": (
                    "StorageError: could not connect to the audit archive "
                    "(sqlite_errorname=SQLITE_IOERR, sqlite_errorcode=10)"
                )
            },
            "non-tolerable",
        ),
        (
            {
                "last_error": (
                    "StorageError: audit archive write failed "
                    "(sqlite_errorname=SQLITE_BUSY, sqlite_errorcode=5)"
                )
            },
            "non-tolerable",
        ),
        (
            {
                "last_error": (
                    "StorageError: could not connect to the audit archive "
                    "(sqlite_errorname=SQLITE_BUSY, sqlite_errorcode=6)"
                )
            },
            "non-tolerable",
        ),
        (
            {
                "last_error": (
                    "StorageError: could not connect to the audit archive "
                    f"(sqlite_errorname=SQLITE_BUSY_{'A' * 53}, sqlite_errorcode=5)"
                )
            },
            "non-tolerable",
        ),
        ({"last_error": TRANSIENT_BUSY_ERROR, "last_success_ns": None}, "prior success"),
        (
            {"archive_reconciled": True, "last_error": TRANSIENT_BUSY_ERROR},
            "reconciled audit exporter error",
        ),
        ({"healthy": True, "last_error": TRANSIENT_BUSY_ERROR}, "inconsistent"),
    ),
)
def test_bounded_audit_exporter_rejects_malformed_or_inconsistent_errors(
    overrides: dict[str, object], match: str
) -> None:
    with pytest.raises(RuntimeError, match=match):
        _bounded_audit_exporter(_audit_status(**overrides), node="warden-a")


@pytest.mark.parametrize(
    ("recover_first", "second_node"),
    ((False, "warden-a"), (True, "warden-a"), (True, "warden-b")),
)
def test_audit_error_budget_rejects_repeated_or_cross_node_samples_live(
    recover_first: bool, second_node: str
) -> None:
    budget = AuditErrorBudget()
    budget.observe_error("warden-a")
    if recover_first:
        budget.mark_recovered("warden-a")
    with pytest.raises(RuntimeError, match="transient error budget exceeded"):
        budget.observe_error(second_node)


def test_health_sample_recovers_one_error_inside_only_the_remaining_stall_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.metrics_calls = {node: 0 for node in NODES}
            self.recovery_windows: list[float] = []

        def request(
            self,
            _method: str,
            node: str,
            path: str,
            *,
            retry_timeout_s: float | None = None,
        ) -> dict[str, Any]:
            if retry_timeout_s is not None:
                self.recovery_windows.append(retry_timeout_s)
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
            self.metrics_calls[node] += 1
            if node == "warden-a" and self.metrics_calls[node] == 1:
                status = _audit_status(
                    last_error=TRANSIENT_BUSY_ERROR,
                    oldest_pending_age_s=None,
                    pending=0,
                    stalled_for_s=5.0,
                )
            else:
                status = _clean_audit_status()
            return {
                **_audit_document(status),
                "peer_dispatcher": {},
                "receipts": {"total": 1},
                "storage_capacity": {"healthy": True},
                "transfers": {},
            }

    current = 100.0

    def monotonic() -> float:
        nonlocal current
        current += 0.1
        return current

    monkeypatch.setattr(soak_scenario.time, "monotonic", monotonic)
    client = FakeClient()
    budget = AuditErrorBudget()
    sample = _health_sample(
        client,  # type: ignore[arg-type]
        elapsed_s=20.0,
        audit_error_budget=budget,
    )
    assert budget.error_sample_count == AUDIT_ERROR_SAMPLE_BUDGET
    assert budget.recovered_error_sample_count == 1
    assert budget.unresolved_error_nodes == set()
    assert len(sample["audit_error_recoveries"]) == 1
    recovery = sample["audit_error_recoveries"][0]
    assert recovery["node"] == "warden-a"
    assert recovery["elapsed_seconds"] > sample["elapsed_seconds"]
    assert recovery["remaining_stall_window_seconds"] == 10.0
    assert client.recovery_windows and 0 < max(client.recovery_windows) <= 10.0
    summary = _audit_progress_summary([sample], audit_error_budget=budget)
    assert summary["bounded_progress"] is True
    assert summary["error_evidence_complete"] is True
    assert summary["error_sample_count"] == 1
    assert summary["recorded_error_sample_count"] == 1
    assert summary["recovered_error_sample_count"] == 1
    assert summary["unresolved_error_nodes"] == []


def test_audit_recovery_deadline_is_anchored_to_initial_metrics_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RecoveryClient:
        def __init__(self) -> None:
            self.retry_windows: list[float] = []

        def request(
            self,
            _method: str,
            _node: str,
            _path: str,
            *,
            retry_timeout_s: float | None = None,
        ) -> dict[str, Any]:
            assert retry_timeout_s is not None
            self.retry_windows.append(retry_timeout_s)
            return _audit_document(_clean_audit_status())

    current = 105.9

    def monotonic() -> float:
        nonlocal current
        current += 0.1
        return current

    monkeypatch.setattr(soak_scenario.time, "monotonic", monotonic)
    client = RecoveryClient()
    recovery = _poll_audit_error_recovery(
        client,  # type: ignore[arg-type]
        node="warden-a",
        initial_exporter=_audit_status(
            last_error=TRANSIENT_BUSY_ERROR,
            oldest_pending_age_s=None,
            pending=0,
            stalled_for_s=5.0,
        ),
        initial_elapsed_s=20.0,
        initial_observed_monotonic=100.0,
    )
    assert client.retry_windows == [pytest.approx(3.9)]
    assert recovery["elapsed_seconds"] == pytest.approx(26.2)
    assert recovery["remaining_stall_window_seconds"] == 10.0


def test_audit_recovery_rejects_clean_status_observed_after_original_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LateRecoveryClient:
        @staticmethod
        def request(
            _method: str,
            _node: str,
            _path: str,
            *,
            retry_timeout_s: float | None = None,
        ) -> dict[str, Any]:
            assert retry_timeout_s is not None
            return _audit_document(_clean_audit_status())

    current = 109.8

    def monotonic() -> float:
        nonlocal current
        current += 0.1
        return current

    monkeypatch.setattr(soak_scenario.time, "monotonic", monotonic)
    monkeypatch.setattr(soak_scenario.time, "sleep", lambda _seconds: None)
    with pytest.raises(RuntimeError, match=r"did not recover within its remaining 10\.000s"):
        _poll_audit_error_recovery(
            LateRecoveryClient(),  # type: ignore[arg-type]
            node="warden-a",
            initial_exporter=_audit_status(
                last_error=TRANSIENT_BUSY_ERROR,
                oldest_pending_age_s=None,
                pending=0,
                stalled_for_s=5.0,
            ),
            initial_elapsed_s=20.0,
            initial_observed_monotonic=100.0,
        )


def test_audit_recovery_rejects_persistent_busy_status_at_original_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PersistentErrorClient:
        calls = 0

        @classmethod
        def request(
            cls,
            _method: str,
            _node: str,
            _path: str,
            *,
            retry_timeout_s: float | None = None,
        ) -> dict[str, Any]:
            assert retry_timeout_s is not None
            cls.calls += 1
            return _audit_document(
                _audit_status(
                    last_error=TRANSIENT_BUSY_ERROR,
                    oldest_pending_age_s=None,
                    pending=0,
                    stalled_for_s=5.0,
                )
            )

    current = 100.0

    def monotonic() -> float:
        nonlocal current
        current += 1.0
        return current

    monkeypatch.setattr(soak_scenario.time, "monotonic", monotonic)
    monkeypatch.setattr(soak_scenario.time, "sleep", lambda _seconds: None)
    with pytest.raises(RuntimeError, match=r"did not recover within its remaining 10\.000s"):
        _poll_audit_error_recovery(
            PersistentErrorClient(),  # type: ignore[arg-type]
            node="warden-b",
            initial_exporter=_audit_status(
                last_error=TRANSIENT_BUSY_ERROR,
                oldest_pending_age_s=None,
                pending=0,
                stalled_for_s=5.0,
            ),
            initial_elapsed_s=20.0,
            initial_observed_monotonic=100.0,
        )
    assert PersistentErrorClient.calls > 1


def test_audit_recovery_rejects_malformed_followup_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MalformedRecoveryClient:
        @staticmethod
        def request(
            _method: str,
            _node: str,
            _path: str,
            *,
            retry_timeout_s: float | None = None,
        ) -> dict[str, Any]:
            assert retry_timeout_s is not None
            return _audit_document(_audit_status(last_error="archive unavailable"))

    monkeypatch.setattr(soak_scenario.time, "monotonic", lambda: 101.0)
    with pytest.raises(RuntimeError, match="non-tolerable audit exporter error"):
        _poll_audit_error_recovery(
            MalformedRecoveryClient(),  # type: ignore[arg-type]
            node="warden-c",
            initial_exporter=_audit_status(
                last_error=TRANSIENT_BUSY_ERROR,
                oldest_pending_age_s=None,
                pending=0,
                stalled_for_s=5.0,
            ),
            initial_elapsed_s=20.0,
            initial_observed_monotonic=100.0,
        )


@pytest.mark.parametrize(
    "samples",
    (
        [_audit_health_sample(0.0, error_nodes=("warden-a",))],
        [
            _audit_health_sample(
                0.0,
                error_nodes=("warden-a",),
                recovered_nodes=("warden-a",),
            ),
            _audit_health_sample(
                10.0,
                error_nodes=("warden-a",),
                recovered_nodes=("warden-a",),
            ),
        ],
        [
            _audit_health_sample(
                0.0,
                error_nodes=("warden-a",),
                recovered_nodes=("warden-a",),
            ),
            _audit_health_sample(
                10.0,
                error_nodes=("warden-b",),
                recovered_nodes=("warden-b",),
            ),
        ],
        [
            _audit_health_sample(
                0.0,
                error_nodes=("warden-a",),
                recovered_nodes=("warden-a",),
            ),
            _audit_health_sample(10.0),
            _audit_health_sample(
                20.0,
                error_nodes=("warden-a",),
                recovered_nodes=("warden-a",),
            ),
        ],
    ),
)
def test_audit_progress_summary_rejects_unresolved_repeated_and_cross_node_errors(
    samples: list[dict[str, Any]],
) -> None:
    summary = _audit_progress_summary(samples)
    assert summary["bounded_progress"] is False
    assert summary["error_recovery_passed"] is False


def test_audit_progress_summary_fails_when_retained_deque_erases_live_error() -> None:
    budget = AuditErrorBudget()
    budget.observe_error("warden-c")
    budget.mark_recovered("warden-c")
    summary = _audit_progress_summary([_audit_health_sample(20.0)], audit_error_budget=budget)
    assert summary["error_sample_count"] == 1
    assert summary["recorded_error_sample_count"] == 0
    assert summary["error_evidence_complete"] is False
    assert summary["bounded_progress"] is False


def test_audit_progress_summary_rejects_recovery_beyond_remaining_stall_window() -> None:
    sample = _audit_health_sample(
        0.0,
        error_nodes=("warden-b",),
        recovered_nodes=("warden-b",),
    )
    sample["audit_error_recoveries"][0]["elapsed_seconds"] = 10.01
    with pytest.raises(RuntimeError, match="invalid bounded warden-b audit recovery"):
        _audit_progress_summary([sample])


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


def _converged_health_response(path: str) -> dict[str, Any]:
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
        **_audit_document(_clean_audit_status()),
        "peer_dispatcher": {
            "configured_peers": 2,
            "failed_records": 0,
            "last_cycle_ns": 1,
            "last_error": None,
            "pending_records": 0,
            "prepared_transfers": 0,
        },
        "receipts": {"total": 1},
        "storage_capacity": {"healthy": True},
        "transfers": {"in_flight_count": 0, "inbound_gap_count": 0},
    }


def test_health_sample_threads_one_absolute_deadline_through_all_nine_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.deadlines: list[float | None] = []

        def request(
            self,
            _method: str,
            _node: str,
            path: str,
            *,
            deadline_monotonic: float | None = None,
        ) -> dict[str, Any]:
            self.deadlines.append(deadline_monotonic)
            return _converged_health_response(path)

    monkeypatch.setattr(soak_scenario.time, "monotonic", lambda: 90.0)
    client = FakeClient()
    sample = _health_sample(
        client,  # type: ignore[arg-type]
        elapsed_s=1.0,
        deadline=100.0,
    )
    assert _is_converged(sample) is True
    assert client.deadlines == [100.0] * 9


def test_settle_rejects_a_ninth_response_that_completes_after_shared_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = 0.0

    class FakeClient:
        def __init__(self, **_kwargs: Any) -> None:
            self.calls = 0
            self.deadlines: list[float | None] = []

        def request(
            self,
            _method: str,
            _node: str,
            path: str,
            *,
            deadline_monotonic: float | None = None,
        ) -> dict[str, Any]:
            nonlocal current
            self.calls += 1
            self.deadlines.append(deadline_monotonic)
            if self.calls == 9:
                current = 1.001
            return _converged_health_response(path)

    client = FakeClient()
    monkeypatch.setattr(soak_scenario, "_verified_manifest", lambda: None)
    monkeypatch.setattr(soak_scenario, "ClusterClient", lambda **_kwargs: client)
    monkeypatch.setattr(soak_scenario.time, "monotonic", lambda: current)
    monkeypatch.setattr(soak_scenario.time, "sleep", lambda _seconds: None)
    arguments = soak_scenario.argparse.Namespace(
        convergence_timeout_seconds=1.0,
        retry_timeout_seconds=1.0,
        seed=1,
    )
    with pytest.raises(RuntimeError, match="did not settle"):
        soak_scenario.wait_converged(arguments)
    assert client.calls == 9
    assert client.deadlines == [1.0] * 9


@pytest.mark.parametrize("probe_name", ("wait_converged", "verify_final"))
def test_settle_and_final_probes_reject_errors_outside_shared_budget(
    monkeypatch: pytest.MonkeyPatch,
    probe_name: str,
) -> None:
    class FakeClient:
        @staticmethod
        def request(
            _method: str,
            _node: str,
            path: str,
            **_kwargs: Any,
        ) -> dict[str, Any]:
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
            status = _audit_status(
                last_error=TRANSIENT_BUSY_ERROR,
                oldest_pending_age_s=None,
                pending=0,
                stalled_for_s=5.0,
            )
            return {
                **_audit_document(status),
                "peer_dispatcher": {},
                "receipts": {"total": 1},
                "storage_capacity": {"healthy": True},
                "transfers": {},
            }

    monkeypatch.setattr(soak_scenario, "_verified_manifest", lambda: None)
    monkeypatch.setattr(soak_scenario, "ClusterClient", lambda **_kwargs: FakeClient())
    arguments = soak_scenario.argparse.Namespace(
        convergence_timeout_seconds=1.0,
        retry_timeout_seconds=1.0,
        seed=1,
    )
    probe = getattr(soak_scenario, probe_name)
    with pytest.raises(RuntimeError, match="outside the shared workload error budget"):
        probe(arguments)


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
        lambda _client, *, elapsed_s, audit_error_budget=None: {"elapsed_seconds": elapsed_s},
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


def test_workload_pause_fails_immediately_with_exited_workload_diagnostics() -> None:
    class ExitedWorkload:
        @staticmethod
        def poll() -> int:
            return 23

        @staticmethod
        def communicate(*, timeout: float) -> tuple[str, str]:
            assert timeout == 1
            return ("workload stdout", "workload stderr")

    class UnusedHarness:
        def run(self, *_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("pause coordination must not run after workload exit")

    with pytest.raises(WorkloadExitedError, match="before partition pause 7") as captured:
        _pause_workload(
            UnusedHarness(),  # type: ignore[arg-type]
            7,
            ExitedWorkload(),  # type: ignore[arg-type]
        )
    assert captured.value.returncode == 23
    assert captured.value.stdout == "workload stdout"
    assert captured.value.stderr == "workload stderr"


def test_settle_cluster_uses_the_full_configured_convergence_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeHarness:
        configuration = replace(
            _configuration(),
            convergence_timeout_seconds=180.0,
            retry_timeout_seconds=30.0,
        )

        def __init__(self) -> None:
            self.arguments: tuple[str, ...] = ()
            self.timeout = 0.0

        def compose(self, *arguments: str, timeout: float) -> str:
            self.arguments = arguments
            self.timeout = timeout
            return ""

    harness = FakeHarness()
    monkeypatch.setattr(
        soak_runner,
        "_scenario_result",
        lambda _harness, _path: {"converged": True, "status": "passed"},
    )
    result = soak_runner._settle_cluster(harness, 7)  # type: ignore[arg-type]
    convergence_index = harness.arguments.index("--convergence-timeout-seconds")
    assert harness.arguments[convergence_index + 1] == "180.0"
    assert harness.timeout == 330.0
    assert result == {"converged": True, "status": "passed"}


def test_failed_soak_evidence_is_atomic_structured_bounded_and_rethrows(
    tmp_path: Any,
) -> None:
    output = tmp_path / "soak.json"
    output.write_text('{"passed":true}\n', encoding="utf-8")
    invalid = replace(_configuration(), image="mutable:latest")
    with pytest.raises(ValueError, match="exact name@sha256"):
        run_soak(invalid, output=output)

    evidence = soak_runner.json.loads(output.read_text(encoding="utf-8"))
    assert evidence["passed"] is False
    assert evidence["source"] == {"status": "not_captured"}
    assert evidence["image"] == {
        "configured_digest": "mutable:latest",
        "status": "not_inspected",
    }
    assert evidence["orchestration"]["preflight"] == {"status": "not_run"}
    assert evidence["resources"]["sample_count"] == 0
    assert evidence["resources"]["samples"] == []
    assert evidence["resources"]["failure_capture"] == {
        "attempted": False,
        "captured": False,
        "reason": "cluster was not started",
    }
    assert evidence["chaos"]["partition_count"] == 0
    assert evidence["chaos"]["restart_count"] == 0
    assert evidence["workload_status"] == {
        "host_cli_terminated": True,
        "return_code": None,
        "started": False,
        "state": "not_started",
        "stderr": "",
        "stdout": "",
    }
    assert evidence["error"]["type"] == "builtins.ValueError"
    assert evidence["orchestration"]["phase"] == "configuration"
    assert evidence["cleanup"] == {
        "performed": False,
        "reason": "cluster was not started",
    }
    payload_digest = evidence.pop("evidence_payload_sha256")
    assert payload_digest == _canonical_digest(evidence)

    oversized = "prefix" + "x" * (soak_runner.FAILED_EVIDENCE_MAX_TEXT_BYTES * 2)
    bounded = _bounded_text(oversized)
    assert "truncated to bounded tail" in bounded
    assert len(bounded.encode("utf-8")) <= soak_runner.FAILED_EVIDENCE_MAX_TEXT_BYTES

    multibyte = _bounded_text("😀" * 10_000)
    assert "truncated to bounded tail" in multibyte
    assert len(multibyte.encode("utf-8")) <= soak_runner.FAILED_EVIDENCE_MAX_TEXT_BYTES


def test_cleanup_failure_is_evidenced_without_masking_original_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    class OriginalError(RuntimeError):
        pass

    class CleanupError(RuntimeError):
        pass

    class Result:
        stdout = ""
        stderr = ""
        returncode = 0

    cleanup_order: list[str] = []

    class FakeHarness:
        project = "lets-production-soak-cleanup-test"
        workload_container = f"{project}-workload"

        def __init__(self) -> None:
            self.environment: dict[str, str] = {}
            self.log_timeouts: list[float] = []

        @staticmethod
        def run(arguments: list[str], **_kwargs: Any) -> Result:
            if arguments[:3] == ["docker", "container", "ls"]:
                cleanup_order.append("workload_container")
            return Result()

        def compose(self, *arguments: str, **options: Any) -> str:
            if arguments and arguments[0] == "up":
                raise OriginalError("cluster startup failed")
            if arguments and arguments[0] == "logs":
                self.log_timeouts.append(options["timeout"])
                return "bounded failure logs"
            return ""

    fake_harness = FakeHarness()
    monkeypatch.setattr(soak_runner, "Harness", lambda _configuration: fake_harness)
    monkeypatch.setattr(
        soak_runner,
        "_source_tree_digest",
        lambda _environment: {
            "dirty": True,
            "git_commit": "f" * 40,
            "status": "captured",
        },
    )
    monkeypatch.setattr(
        soak_runner,
        "_preflight_zero",
        lambda _harness: {"containers": 0, "networks": 0, "passed": True, "volumes": 0},
    )
    cleanup_timeouts: dict[str, float] = {}

    def fail_cleanup(
        _harness: object,
        *,
        probe_timeout: float,
        down_timeout: float,
    ) -> dict[str, Any]:
        cleanup_order.append("compose_down")
        cleanup_timeouts.update(probe=probe_timeout, down=down_timeout)
        raise CleanupError("cleanup proof failed")

    monkeypatch.setattr(soak_runner, "_checked_down", fail_cleanup)
    output = tmp_path / "cleanup-failure.json"
    with pytest.raises(OriginalError, match="cluster startup failed"):
        run_soak(_configuration(), output=output)

    evidence = soak_runner.json.loads(output.read_text(encoding="utf-8"))
    assert evidence["passed"] is False
    assert evidence["error"]["type"].endswith("OriginalError")
    assert evidence["error"]["message"] == "cluster startup failed"
    assert evidence["cleanup"] == {
        "error": "cleanup proof failed",
        "performed": False,
        "reason": "cleanup failed",
        "workload_container": {
            "attempted": True,
            "container_name": "lets-production-soak-cleanup-test-workload",
            "force_removed": False,
            "found": False,
            "labels_validated": False,
            "remaining": False,
        },
    }
    assert evidence["resources"]["failure_capture"]["attempted"] is True
    assert evidence["resources"]["failure_capture"]["captured"] is False
    assert evidence["orchestration"]["phase"] == "cluster_startup"
    assert fake_harness.log_timeouts == [10.0]
    assert cleanup_timeouts == {"probe": 5.0, "down": 30.0}
    assert cleanup_order == ["workload_container", "compose_down"]


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


def test_failed_workload_cleanup_refuses_an_active_host_cli_without_docker_calls() -> None:
    class FakeHarness:
        project = "lets-production-soak-active"
        workload_container = f"{project}-workload"

        @staticmethod
        def run(*_args: Any, **_kwargs: Any) -> None:
            pytest.fail("Docker must not be called while the host Compose CLI is active")

    result: dict[str, Any] = {}
    with pytest.raises(RuntimeError, match="host Compose CLI is still active"):
        soak_runner._remove_failed_workload_container(
            FakeHarness(),  # type: ignore[arg-type]
            host_cli_terminated=False,
            result=result,
        )
    assert result == {
        "attempted": False,
        "container_name": "lets-production-soak-active-workload",
        "force_removed": False,
        "found": False,
        "labels_validated": False,
        "remaining": False,
    }


def test_failed_workload_cleanup_records_absence_without_broad_deletion() -> None:
    class Result:
        stdout = ""

    class FakeHarness:
        project = "lets-production-soak-absent"
        workload_container = f"{project}-workload"

        def __init__(self) -> None:
            self.commands: list[tuple[str, ...]] = []

        def run(self, arguments: list[str], **_kwargs: Any) -> Result:
            self.commands.append(tuple(arguments))
            return Result()

    harness = FakeHarness()
    result = soak_runner._remove_failed_workload_container(
        harness,  # type: ignore[arg-type]
        host_cli_terminated=True,
    )
    assert result == {
        "attempted": True,
        "container_name": "lets-production-soak-absent-workload",
        "force_removed": False,
        "found": False,
        "labels_validated": False,
        "remaining": False,
    }
    assert len(harness.commands) == 1
    assert harness.commands[0][:4] == ("docker", "container", "ls", "--all")
    assert "name=^/lets-production-soak-absent-workload$" in harness.commands[0]
    assert not any("rm" in command for command in harness.commands)


def test_failed_workload_cleanup_validates_labels_removes_by_id_and_proves_absence() -> None:
    short_id = "a" * 12
    full_id = "a" * 64

    class Result:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    class FakeHarness:
        project = "lets-production-soak-valid"
        workload_container = f"{project}-workload"

        def __init__(self) -> None:
            self.commands: list[tuple[str, ...]] = []
            self.listings = iter((f"{short_id}\t{self.workload_container}\n", ""))

        def run(self, arguments: list[str], **_kwargs: Any) -> Result:
            command = tuple(arguments)
            self.commands.append(command)
            if command[2:4] == ("ls", "--all"):
                return Result(next(self.listings))
            if command[2] == "inspect":
                return Result(
                    soak_runner.json.dumps(
                        {
                            "Config": {
                                "Labels": {
                                    "com.docker.compose.oneoff": "True",
                                    "com.docker.compose.project": self.project,
                                    "com.docker.compose.service": "scenario",
                                }
                            },
                            "Id": full_id,
                            "Name": f"/{self.workload_container}",
                        }
                    )
                )
            assert command == ("docker", "container", "rm", "--force", full_id)
            return Result("")

    harness = FakeHarness()
    result = soak_runner._remove_failed_workload_container(
        harness,  # type: ignore[arg-type]
        host_cli_terminated=True,
    )
    assert result == {
        "attempted": True,
        "container_name": "lets-production-soak-valid-workload",
        "force_removed": True,
        "found": True,
        "labels_validated": True,
        "remaining": False,
    }
    assert [command[2] for command in harness.commands] == ["ls", "inspect", "rm", "ls"]


@pytest.mark.parametrize("mismatch", ("id", "name", "oneoff"))
def test_failed_workload_cleanup_refuses_identity_or_label_mismatch(mismatch: str) -> None:
    short_id = "a" * 12
    full_id = ("b" if mismatch == "id" else "a") * 64

    class Result:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    class FakeHarness:
        project = "lets-production-soak-mismatch"
        workload_container = f"{project}-workload"

        def __init__(self) -> None:
            self.commands: list[tuple[str, ...]] = []

        def run(self, arguments: list[str], **_kwargs: Any) -> Result:
            command = tuple(arguments)
            self.commands.append(command)
            if command[2] == "ls":
                return Result(f"{short_id}\t{self.workload_container}\n")
            assert command[2] == "inspect"
            return Result(
                soak_runner.json.dumps(
                    {
                        "Config": {
                            "Labels": {
                                "com.docker.compose.oneoff": (
                                    "False" if mismatch == "oneoff" else "True"
                                ),
                                "com.docker.compose.project": self.project,
                                "com.docker.compose.service": "scenario",
                            }
                        },
                        "Id": full_id,
                        "Name": (
                            "/replacement" if mismatch == "name" else f"/{self.workload_container}"
                        ),
                    }
                )
            )

    harness = FakeHarness()
    result: dict[str, Any] = {}
    with pytest.raises(RuntimeError, match="mismatched identity labels"):
        soak_runner._remove_failed_workload_container(
            harness,  # type: ignore[arg-type]
            host_cli_terminated=True,
            result=result,
        )
    assert result["found"] is True
    assert result["labels_validated"] is False
    assert result["force_removed"] is False
    assert result["remaining"] is True
    assert not any(command[2] == "rm" for command in harness.commands)


def test_failed_workload_cleanup_does_not_delete_a_name_race_replacement() -> None:
    original_short_id = "a" * 12
    original_full_id = "a" * 64
    replacement_short_id = "b" * 12

    class Result:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    class FakeHarness:
        project = "lets-production-soak-race"
        workload_container = f"{project}-workload"

        def __init__(self) -> None:
            self.commands: list[tuple[str, ...]] = []
            self.listings = iter(
                (
                    f"{original_short_id}\t{self.workload_container}\n",
                    f"{replacement_short_id}\t{self.workload_container}\n",
                )
            )

        def run(self, arguments: list[str], **_kwargs: Any) -> Result:
            command = tuple(arguments)
            self.commands.append(command)
            if command[2] == "ls":
                return Result(next(self.listings))
            if command[2] == "inspect":
                return Result(
                    soak_runner.json.dumps(
                        {
                            "Config": {
                                "Labels": {
                                    "com.docker.compose.oneoff": "True",
                                    "com.docker.compose.project": self.project,
                                    "com.docker.compose.service": "scenario",
                                }
                            },
                            "Id": original_full_id,
                            "Name": f"/{self.workload_container}",
                        }
                    )
                )
            assert command == ("docker", "container", "rm", "--force", original_full_id)
            return Result("")

    harness = FakeHarness()
    result: dict[str, Any] = {}
    with pytest.raises(RuntimeError, match="remained after forced removal"):
        soak_runner._remove_failed_workload_container(
            harness,  # type: ignore[arg-type]
            host_cli_terminated=True,
            result=result,
        )
    removals = [command for command in harness.commands if command[2] == "rm"]
    assert removals == [("docker", "container", "rm", "--force", original_full_id)]
    assert result["force_removed"] is True
    assert result["remaining"] is True


def test_cleanup_proves_project_containers_volumes_and_networks_are_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeHarness:
        def __init__(self) -> None:
            self.compose_calls: list[tuple[str, ...]] = []
            self.compose_timeouts: list[float] = []
            self.allowed_volumes: set[str] = set()

        def compose(self, *arguments: str, timeout: float, **_options: Any) -> str:
            self.compose_calls.append(arguments)
            self.compose_timeouts.append(timeout)
            return ""

    harness = FakeHarness()
    probe_timeouts: list[float] = []
    volume_snapshots: Iterator[set[str]] = iter((set(), set()))

    def volumes(_harness: object, *, timeout: float) -> set[str]:
        probe_timeouts.append(timeout)
        return next(volume_snapshots)

    def absent(_harness: object, *, timeout: float) -> set[str]:
        probe_timeouts.append(timeout)
        return set()

    monkeypatch.setattr(soak_runner, "_project_volumes", volumes)
    monkeypatch.setattr(soak_runner, "_project_containers", absent)
    monkeypatch.setattr(soak_runner, "_project_networks", absent)
    result = soak_runner._checked_down(harness)  # type: ignore[arg-type]
    assert result == {
        "performed": True,
        "remaining_containers": 0,
        "remaining_networks": 0,
        "remaining_volumes": 0,
    }
    assert harness.compose_calls == [("down", "--volumes", "--remove-orphans")]
    assert harness.compose_timeouts == [180]
    assert probe_timeouts == [600, 600, 600, 600]

    harness = FakeHarness()
    probe_timeouts = []
    volume_snapshots = iter((set(), set()))
    result = soak_runner._checked_down(  # type: ignore[arg-type]
        harness,
        probe_timeout=5,
        down_timeout=30,
    )
    assert result["performed"] is True
    assert harness.compose_timeouts == [30]
    assert probe_timeouts == [5, 5, 5, 5]

    harness = FakeHarness()
    volume_snapshots = iter((set(), {"leftover-volume"}))
    monkeypatch.setattr(soak_runner, "_project_volumes", volumes)
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
