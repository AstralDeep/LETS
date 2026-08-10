from __future__ import annotations

import base64
import hashlib
import json
import textwrap
import threading
import time
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
    ClusterClient,
    HealthSampler,
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
    _fence_restart_authority,
    _next_restart_deadline,
    _pause_workload,
    _pre_sigkill_resource_checkpoint,
    _preflight_zero,
    _restart_integrity,
    _wait_restart_acknowledgement,
    evaluate_authority_evidence,
    evaluate_health_cadence,
    evaluate_pause_evidence,
    evaluate_resource_bounds,
    evaluate_restart_evidence,
    evaluate_workload_result,
    may_start_chaos_episode,
    minimum_cycle_count,
    minimum_health_sample_count,
    run_soak,
    semantic_cycle_floor,
    validate_image_labels,
    validate_package_identity,
)

EXACT_IMAGE = "ghcr.io/astraldeep/lets@sha256:" + "a" * 64
TRANSIENT_BUSY_ERROR = (
    "StorageError: could not connect to the audit archive "
    "(sqlite_errorname=SQLITE_BUSY, sqlite_errorcode=5)"
)


def _core_authority_status(
    node: str = "warden-a",
    *,
    lifetime_id: str | None = None,
) -> dict[str, Any]:
    ordinal = NODES.index(node) + 1
    return {
        "admission_fenced": False,
        "enabled": True,
        "fault_reason": None,
        "fault_stage": None,
        "fence_id": None,
        "fenced_at_monotonic_ns": None,
        "first_fault": None,
        "healthy": True,
        "lifetime_id": lifetime_id or f"{ordinal:032x}",
        "namespace_process_id": 100 + ordinal,
        "permanent_faults": 0,
        "retry_not_before_monotonic_ns": None,
        "state": "healthy",
        "transport_fault_episodes": 0,
        "transport_faults": 0,
        "transport_recoveries": 0,
        "transport_recovery_attempts": 0,
        "unresolved_transport_faults": 0,
    }


def _executor_authority_status(
    lifetime_id: str,
    *,
    recovered_fault: bool = False,
) -> dict[str, Any]:
    first_fault = (
        {
            "helper_exit_code": None,
            "helper_pid": None,
            "mutation_uncertain": True,
            "operation": "compare-and-set",
            "reason": "helper_eof",
            "request_flushed": True,
            "stage": "post_commit",
        }
        if recovered_fault
        else None
    )
    count = int(recovered_fault)
    return {
        "enabled": True,
        "fault_reason": None,
        "fault_stage": None,
        "first_fault": first_fault,
        "healthy": True,
        "lifetime_id": lifetime_id,
        "permanent_faults": 0,
        "retry_not_before_monotonic_ns": None,
        "state": "healthy",
        "transport_fault_episodes": count,
        "transport_faults": count,
        "transport_recoveries": count,
        "transport_recovery_attempts": count,
        "unresolved_transport_faults": 0,
    }


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
    assert "\nimport base64\n" in f"\n{source}"
    assert "\nimport math\n" in f"\n{source}"
    assert "\nimport re\n" in f"\n{source}"
    compile(source, "release-soak-evidence.py", "exec")


def test_release_soak_evidence_verifier_executes_and_recomputes_digest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workflow = (Path(__file__).parents[2] / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )
    step = workflow.split(
        "      - name: Require sustained evidence to bind the exact candidate and source\n",
        maxsplit=1,
    )[1].split("      - name: Archive failed production-profile soak diagnostics\n", maxsplit=1)[0]
    source = textwrap.dedent(
        step.split("          python - <<'PY'\n", maxsplit=1)[1].split(
            "\n          PY",
            maxsplit=1,
        )[0]
    )
    evidence = {
        "configuration": {},
        "evidence_payload_sha256": "sha256:" + "0" * 64,
        "image": {},
        "passed": False,
        "source": {},
        "workload": {},
    }
    evidence_path = tmp_path / "results" / "generated" / "production-profile-soak.json"
    evidence_path.parent.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("EXPECTED_IMAGE", EXACT_IMAGE)
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(SystemExit, match="evidence payload digest is invalid"):
        exec(compile(source, "release-soak-evidence.py", "exec"), {})

    canonical = dict(evidence)
    canonical.pop("evidence_payload_sha256")
    evidence["evidence_payload_sha256"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                canonical,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
    )
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(SystemExit) as failure:
        exec(compile(source, "release-soak-evidence.py", "exec"), {})
    assert "evidence payload digest is invalid" not in str(failure.value)

    for malformed_root in ("null", "false", '"not-an-object"'):
        evidence_path.write_text(malformed_root, encoding="utf-8")
        with pytest.raises(SystemExit, match="evidence root is malformed"):
            exec(compile(source, "release-soak-evidence.py", "exec"), {})

    for malformed_fields in (
        {"chaos": None, "orchestration": "invalid"},
        {"resources": False, "verification": None},
        {
            "workload_evaluation": {
                "checks": False,
                "metrics": None,
                "passed": False,
            }
        },
        {"configuration": {"duration_seconds": False}},
    ):
        malformed = {**evidence, **malformed_fields}
        malformed.pop("evidence_payload_sha256", None)
        malformed["evidence_payload_sha256"] = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    malformed,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
        )
        evidence_path.write_text(json.dumps(malformed), encoding="utf-8")
        with pytest.raises(SystemExit):
            exec(compile(source, "release-soak-evidence.py", "exec"), {})

    evidence_path.write_text('{"passed":false,"passed":true}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        exec(compile(source, "release-soak-evidence.py", "exec"), {})

    evidence_path.write_text('{"duration_seconds":NaN}', encoding="utf-8")
    with pytest.raises(ValueError, match="non-finite JSON number"):
        exec(compile(source, "release-soak-evidence.py", "exec"), {})


def test_release_workflow_independently_rejects_forged_authority_raw_evidence() -> None:
    workflow = (Path(__file__).parents[2] / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )
    embedded = workflow.split(
        "      - name: Require sustained evidence to bind the exact candidate and source\n",
        maxsplit=1,
    )[1].split("      - name: Archive failed production-profile soak diagnostics\n", maxsplit=1)[0]
    source = textwrap.dedent(
        embedded.split("          python - <<'PY'\n", maxsplit=1)[1].split(
            "\n          PY", maxsplit=1
        )[0]
    )
    verifier = source.split("# BEGIN RAW AUTHORITY EVIDENCE VERIFIER\n", maxsplit=1)[1].split(
        "# END RAW AUTHORITY EVIDENCE VERIFIER", maxsplit=1
    )[0]
    workload, restarts, verification = _authority_evidence_fixture(_configuration())
    summary = evaluate_authority_evidence(workload, restarts, verification)

    def run(
        raw_workload: dict[str, Any],
        *,
        raw_summary: dict[str, Any] = summary,
        raw_verification: dict[str, Any] = verification,
    ) -> list[str]:
        failures: list[str] = []

        def required_mapping(value: object, label: str) -> dict[str, Any]:
            if isinstance(value, dict):
                return value
            failures.append(f"{label} is malformed")
            return {}

        namespace = {
            "authority_summary": raw_summary,
            "configuration": {
                "executor_reopen_every_cycles": (_configuration().executor_reopen_every_cycles),
                "seed": _configuration().seed,
            },
            "cycle_metrics_valid": True,
            "cycles": raw_workload["cycles"],
            "evidence": {"authority_evaluation": raw_summary},
            "expected_nodes": set(NODES),
            "failures": failures,
            "base64": base64,
            "close_number": lambda left, right, tolerance=0.002: (
                soak_runner._finite_number(left)
                and soak_runner._finite_number(right)
                and abs(float(left) - float(right)) <= tolerance
            ),
            "finite_number": soak_runner._finite_number,
            "final_nodes": raw_verification["final_health"]["nodes"],
            "health_samples": raw_workload["health_samples"],
            "re": soak_runner.re,
            "required_mapping": required_mapping,
            "restarts": restarts,
            "verification": raw_verification,
            "workload": raw_workload,
        }
        exec(compile(verifier, "release-authority-evidence.py", "exec"), namespace)
        return failures

    assert run(workload) == []
    forged = json.loads(json.dumps(workload))
    forged["executor"]["transport_recovery_events"][0]["original_transport_error"]["reason"] = (
        "semantic_divergence"
    )
    assert run(forged) == ["soak authority lifetime and recovery budget is not raw-bound"]

    forged_checkpoint = json.loads(json.dumps(workload))
    forged_checkpoint["executor"]["terminal_statuses"][0]["status"]["anchor"]["schema_version"] = 4
    assert run(forged_checkpoint) == [
        "soak authority lifetime and recovery budget is not raw-bound"
    ]

    rolled_back_floor = json.loads(json.dumps(workload))
    rolled_back_floor["executor"]["terminal_statuses"][1]["status"]["anchor"]["clock_floor_ns"] = 1
    assert run(rolled_back_floor) == [
        "soak authority lifetime and recovery budget is not raw-bound"
    ]

    forged_identity_workload = json.loads(json.dumps(workload))
    forged_identity_verification = json.loads(json.dumps(verification))
    for terminal in forged_identity_workload["executor"]["terminal_statuses"]:
        terminal["status"]["anchor"]["audience"] = "forged-executor"
    forged_identity_verification["executor"]["terminal_status"]["status"]["anchor"]["audience"] = (
        "forged-executor"
    )
    assert run(
        forged_identity_workload,
        raw_verification=forged_identity_verification,
    ) == ["soak authority lifetime and recovery budget is not raw-bound"]

    forged_summary = {**summary, "executor_lifetime_count": 99}
    assert run(workload, raw_summary=forged_summary) == [
        "soak authority lifetime and recovery budget is not raw-bound"
    ]

    forged_verification = json.loads(json.dumps(verification))
    forged_verification["terminal_capture"]["deadline_monotonic_seconds"] += 1
    assert run(workload, raw_verification=forged_verification) == [
        "soak authority lifetime and recovery budget is not raw-bound"
    ]

    forged_verification = json.loads(json.dumps(verification))
    forged_verification["executor"].pop("integrity")
    assert run(workload, raw_verification=forged_verification) == [
        "soak authority lifetime and recovery budget is not raw-bound"
    ]

    for field_name in ("anchor_claim_sequence", "claim_sequence"):
        forged_verification = json.loads(json.dumps(verification))
        forged_verification["executor"][field_name] = float(
            forged_verification["executor"][field_name]
        )
        assert run(workload, raw_verification=forged_verification) == [
            "soak authority lifetime and recovery budget is not raw-bound"
        ]

    forged_ordinal = json.loads(json.dumps(workload))
    forged_ordinal["executor"]["transport_recovery_events"][0]["ordinal"] = False
    assert run(forged_ordinal) == ["soak authority lifetime and recovery budget is not raw-bound"]

    forged_terminal = json.loads(json.dumps(workload))
    forged_terminal["executor"]["terminal_statuses"][0]["ordinal"] = 0.0
    assert run(forged_terminal) == ["soak authority lifetime and recovery budget is not raw-bound"]

    forged_fence = json.loads(json.dumps(verification))
    forged_fence["terminal_authority_fences"]["warden-a"]["namespace_process_id"] = float(
        forged_fence["terminal_authority_fences"]["warden-a"]["namespace_process_id"]
    )
    assert run(workload, raw_verification=forged_fence) == [
        "soak authority lifetime and recovery budget is not raw-bound"
    ]

    forged_summary = json.loads(json.dumps(summary))
    forged_summary["core_lifetime_count"] = float(forged_summary["core_lifetime_count"])
    forged_summary["global_counters"]["permanent_faults"] = False
    assert run(workload, raw_summary=forged_summary) == [
        "soak authority lifetime and recovery budget is not raw-bound"
    ]


def test_cluster_client_retains_typed_retry_code_and_request_correlation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Tokens:
        @staticmethod
        def issue() -> str:
            return "bounded-test-token"

    class Response:
        def __init__(
            self,
            status_code: int,
            document: dict[str, Any],
            *,
            request_id: str,
        ) -> None:
            self.status_code = status_code
            self._document = document
            self.headers = {"x-request-id": request_id}

        def json(self) -> dict[str, Any]:
            return self._document

    responses = [
        Response(
            503,
            {"code": "authority_anchor_transport_error"},
            request_id="server-correlation-1",
        ),
        Response(200, {"ok": True}, request_id="server-correlation-2"),
    ]

    class HttpClient:
        def __init__(self, **_options: Any) -> None:
            pass

        def __enter__(self) -> HttpClient:
            return self

        def __exit__(self, *_arguments: Any) -> None:
            return None

        @staticmethod
        def request(*_arguments: Any, **_options: Any) -> Response:
            return responses.pop(0)

    client = ClusterClient.__new__(ClusterClient)
    client._tokens = Tokens()  # type: ignore[assignment]
    client._tls = None  # type: ignore[assignment]
    client._retry_timeout_s = 2.0
    client._abort_event = None
    client.retry_count = 0
    client._retry_scope_first_error = None
    client._retry_scope_last_error = None
    monkeypatch.setattr(soak_scenario.httpx, "Client", HttpClient)
    monkeypatch.setattr(soak_scenario.time, "sleep", lambda _seconds: None)

    client.begin_retry_scope()
    assert client.request(
        "POST",
        "warden-a",
        "/v1/leases/lease-a/transitions",
        body={"request_id": "request-correlation-1"},
    ) == {"ok": True}
    assert client.retry_count == 1
    retry_error = client.retry_scope()["first_error"]
    assert retry_error is not None
    assert "code:authority_anchor_transport_error" in retry_error
    assert "path:/v1/leases/lease-a/transitions" in retry_error
    assert "request:request-correlation-1" in retry_error
    assert "response:server-correlation-1" in retry_error


def _configuration() -> SoakConfiguration:
    return SoakConfiguration(
        image=EXACT_IMAGE,
        duration_seconds=120,
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


def _timed_health_samples(
    *,
    duration_seconds: float = 30.0,
    interval_seconds: float = 2.0,
) -> list[dict[str, Any]]:
    schedule: list[float] = []
    due = 0.0
    while due < duration_seconds:
        schedule.append(due)
        due += interval_seconds
    schedule.append(duration_seconds)
    return [
        {
            "audit_catchup_nodes": [],
            "audit_error_recoveries": [],
            "completed_elapsed_seconds": scheduled + 0.3,
            "deadline_elapsed_seconds": scheduled + 15.0,
            "deadline_missed": False,
            "elapsed_seconds": scheduled,
            "nodes": {
                node: {
                    "audit_exporter": {"max_stall_s": 15.0},
                    "authority_anchor": _core_authority_status(node),
                    "observation": {
                        "completed_elapsed_seconds": scheduled + 0.2,
                        "metrics_observed_elapsed_seconds": scheduled + 0.1,
                        "request_retries": 0,
                        "started_elapsed_seconds": scheduled + 0.01,
                    },
                }
                for node in NODES
            },
            "planned_unavailable_nodes": [],
            "schedule_index": index,
            "scheduled_elapsed_seconds": scheduled,
            "started_elapsed_seconds": scheduled,
        }
        for index, scheduled in enumerate(schedule)
    ]


def _valid_workload_result(
    configuration: SoakConfiguration,
    *,
    cycles: int = 11,
) -> dict[str, Any]:
    samples = _timed_health_samples(
        duration_seconds=configuration.duration_seconds,
        interval_seconds=configuration.health_interval_seconds,
    )
    expected_transfers = (
        cycles + configuration.transfer_every_cycles - 1
    ) // configuration.transfer_every_cycles
    expected_reopens = cycles // configuration.executor_reopen_every_cycles
    return {
        "active_workload_seconds": configuration.duration_seconds,
        "audit_progress": {
            "bounded_progress": True,
            "catchup_sample_count": 0,
            "error_evidence_complete": True,
            "error_recovery_passed": True,
            "error_sample_budget": 1,
            "error_sample_count": 0,
            "error_samples_by_node": {node: 0 for node in NODES},
            "maximum_pending_by_node": {node: 0 for node in NODES},
            "recorded_error_sample_count": 0,
            "recorded_error_samples_by_node": {node: 0 for node in NODES},
            "recorded_recovered_error_sample_count": 0,
            "recorded_unresolved_error_nodes": [],
            "recovered_error_sample_count": 0,
            "sample_count": len(samples),
            "unresolved_error_nodes": [],
        },
        "counters": {
            "authorizations": 2 * cycles - 1,
            "closed": cycles,
            "executor_failed_closed": 1,
            "executor_faulting_calls": 1,
            "issued_receipts": 2 * cycles,
            "issued_roots": cycles,
            "quiesced": cycles,
            "renewed": cycles,
            "resumed": cycles,
            "transfers_prepared": expected_transfers,
        },
        "configuration": {
            "cycle_interval_seconds": configuration.cycle_interval_seconds,
            "duration_seconds": configuration.duration_seconds,
            "executor_reopen_every_cycles": (configuration.executor_reopen_every_cycles),
            "health_interval_seconds": configuration.health_interval_seconds,
            "retry_timeout_seconds": configuration.retry_timeout_seconds,
            "seed": configuration.seed,
            "transfer_every_cycles": configuration.transfer_every_cycles,
        },
        "cycles": cycles,
        "duration_seconds": configuration.duration_seconds,
        "executor": {
            "claims": 2 * cycles,
            "reopen_count": expected_reopens,
            "replay_rejections": 2 * cycles + expected_reopens,
            "status": {"claim_sequence": 2 * cycles},
        },
        "health_monitor": {
            "actual_sample_count": len(samples),
            "audit_error_budget_instances": 1,
            "deadline_miss_count": 0,
            "expected_sample_count": len(samples),
            "interval_seconds": configuration.health_interval_seconds,
            "joined": True,
            "request_retry_count": 0,
            "retained_sample_count": len(samples),
            "samples_truncated": 0,
            "schedule": "absolute_monotonic",
            "status": "passed",
        },
        "health_sample_count": len(samples),
        "health_samples": samples,
        "latency": {"buckets_ms": {"overflow": 0}, "count": cycles, "maximum_ms": 500},
        "measurement_window_seconds": configuration.duration_seconds,
        "pause_interval_count": 0,
        "pause_intervals": [],
        "paused_workload_seconds": 0.0,
        "request_retry_count": 0,
        "run_id": "unit-workload-run",
        "schema": "lets.production-profile-soak-workload/v2",
        "started_monotonic_seconds": 100.0,
        "status": "passed",
        "transfer_pair_counts": _expected_transfer_pair_counts(
            cycles=cycles,
            transfer_every_cycles=configuration.transfer_every_cycles,
        ),
    }


def _workload_start(
    result: dict[str, Any],
    configuration: SoakConfiguration,
) -> dict[str, Any]:
    return {
        "cycle_interval_seconds": configuration.cycle_interval_seconds,
        "duration_seconds": configuration.duration_seconds,
        "executor_reopen_every_cycles": configuration.executor_reopen_every_cycles,
        "health_interval_seconds": configuration.health_interval_seconds,
        "host_received_monotonic_seconds": 999.0,
        "host_wait_started_monotonic_seconds": 998.0,
        "retry_timeout_seconds": configuration.retry_timeout_seconds,
        "run_id": result["run_id"],
        "schema": "lets.production-profile-soak-workload-start/v1",
        "seed": configuration.seed,
        "started_monotonic_seconds": result["started_monotonic_seconds"],
        "transfer_every_cycles": configuration.transfer_every_cycles,
    }


def _authority_evidence_fixture(
    configuration: SoakConfiguration,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    workload = _valid_workload_result(configuration)
    cycles = int(workload["cycles"])
    issued = 2 * cycles
    executor = workload["executor"]
    reopen_count = int(executor["reopen_count"])
    recovered_authority = _executor_authority_status("e" * 32, recovered_fault=True)
    faulted_authority = {
        **recovered_authority,
        "fault_reason": "helper_eof",
        "fault_stage": "post_commit",
        "healthy": False,
        "retry_not_before_monotonic_ns": 123,
        "state": "recoverable_transport_fault",
        "transport_recoveries": 0,
        "transport_recovery_attempts": 0,
        "unresolved_transport_faults": 1,
    }

    executor_checkpoint = {
        "audience": "production-soak-executor",
        "claim_digest": "A" * 43,
        "claim_sequence": issued,
        "clock_floor_ns": 123,
        "config_epoch": 1,
        "database_instance_id": "A" * 43,
        "envelope_id": "production-acceptance-envelope",
        "executor_policy_sha256": "A" * 43,
        "format": "LETS-EXECUTOR-AUTHORITY-ANCHOR/1",
        "schema_version": 5,
        "tenant_id": "production-acceptance-tenant",
        "trust_registry_sha256": "A" * 43,
    }

    def status(authority: dict[str, Any], *, claim_sequence: int) -> dict[str, Any]:
        checkpoint = {**executor_checkpoint, "claim_sequence": claim_sequence}
        return {
            "anchor": checkpoint,
            "authority_anchor": authority,
            "authority_healthy": True,
            "claim_sequence": claim_sequence,
            "database_bytes": 4096,
            "integrity": ["ok"],
            "live_claims": claim_sequence,
            "live_watermarks": claim_sequence,
            "rollback_protected": True,
            "shared_memory_bytes": 0,
            "wal_bytes": 0,
        }

    workload_terminals = []
    for ordinal in range(reopen_count + 1):
        authority = (
            recovered_authority
            if ordinal == 0
            else _executor_authority_status(f"{0xE0 + ordinal:032x}")
        )
        claim_sequence = (
            2 * configuration.executor_reopen_every_cycles * (ordinal + 1)
            if ordinal < reopen_count
            else issued
        )
        snapshot = status(authority, claim_sequence=claim_sequence)
        workload_terminals.append(
            {
                "lifetime_id": authority["lifetime_id"],
                "ordinal": ordinal,
                "source": "workload",
                "status": snapshot,
            }
        )
    executor.update(
        {
            "status": workload_terminals[-1]["status"],
            "terminal_statuses": workload_terminals,
            "transport_recovery_events": [
                {
                    "durable_claim_outcome": "burned_before_response",
                    "faulted_authority_anchor": faulted_authority,
                    "faulting_call_effect_executed": False,
                    "ordinal": 0,
                    "original_call_raised": True,
                    "original_transport_error": {
                        key: recovered_authority["first_fault"][key]
                        for key in (
                            "helper_exit_code",
                            "helper_pid",
                            "mutation_uncertain",
                            "operation",
                            "reason",
                            "request_flushed",
                        )
                    },
                    "phase": "primary_claim",
                    "primary_returned": False,
                    "protected_effect_executed_after_recovery": False,
                    "receipt_id": "receipt-1",
                    "recovered_authority_anchor": recovered_authority,
                    "retry_outcome": "replay_rejected",
                }
            ],
        }
    )
    final_executor_authority = _executor_authority_status("f" * 32)
    final_executor_status = status(final_executor_authority, claim_sequence=issued)
    core_fences: dict[str, Any] = {}
    for node in NODES:
        prior = _core_authority_status(node)
        fence_id = f"final-verification-7-{node}"
        authority = {
            **prior,
            "admission_fenced": True,
            "fence_id": fence_id,
            "fenced_at_monotonic_ns": 1_000 + NODES.index(node),
        }
        core_fences[node] = {
            "authority_anchor": authority,
            "fenced_at_monotonic_ns": authority["fenced_at_monotonic_ns"],
            "lifetime_id": authority["lifetime_id"],
            "namespace_process_id": authority["namespace_process_id"],
            "restart_id": fence_id,
            "schema": "lets.authority-admission-fence/v1",
            "warden_id": node,
        }
    verification = {
        "executor": {
            "anchor_claim_sequence": issued,
            "authority_anchor": final_executor_authority,
            "authority_healthy": True,
            "claim_sequence": issued,
            "database_bytes": 4096,
            "integrity": ["ok"],
            "rollback_protected": True,
            "terminal_status": {
                "lifetime_id": final_executor_authority["lifetime_id"],
                "ordinal": len(workload_terminals),
                "source": "final_verification",
                "status": final_executor_status,
            },
            "wal_bytes": 0,
        },
        "final_health": {
            "nodes": {node: {"authority_anchor": _core_authority_status(node)} for node in NODES}
        },
        "schema": "lets.production-profile-soak-verification/v1",
        "status": "passed",
        "terminal_capture": {
            "completed_monotonic_seconds": 2.0,
            "deadline_monotonic_seconds": 91.0,
            "started_monotonic_seconds": 1.0,
        },
        "terminal_authority_fences": core_fences,
    }
    return workload, [], verification


def _chaos_started() -> float:
    return 1_000.0


def _chaos_completed() -> float:
    return 1_120.0


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
    with pytest.raises(ValueError, match="partition episodes"):
        replace(configuration, duration_seconds=10).validate()
    with pytest.raises(ValueError, match="at least 300"):
        replace(configuration, smoke=False).validate()
    assert DEFAULT_RESTART_INTERVAL_SECONDS == 900

    release = replace(
        configuration,
        duration_seconds=3_600,
        partition_interval_seconds=90,
        restart_interval_seconds=900,
        retry_timeout_seconds=90,
        smoke=False,
    )
    release.validate()
    assert semantic_cycle_floor(release) == 36
    assert minimum_cycle_count(release) == 240
    assert minimum_health_sample_count(release) == 1_801
    assert soak_runner.chaos_start_shutdown_margin_seconds(release) == 150.0
    assert may_start_chaos_episode(release, elapsed_s=3_449.999) is True
    assert may_start_chaos_episode(release, elapsed_s=3_450.0) is False
    assert may_start_chaos_episode(configuration, elapsed_s=29.99) is True
    assert may_start_chaos_episode(configuration, elapsed_s=30.0) is False
    assert may_start_chaos_episode(configuration, elapsed_s=90.0) is False
    assert _next_restart_deadline(prior_deadline=30, interval_s=30, completed_at=40) == 60
    assert _next_restart_deadline(prior_deadline=30, interval_s=30, completed_at=80) == 87.5


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("duration_seconds", float("nan")),
        ("duration_seconds", float("inf")),
        ("health_interval_seconds", float("nan")),
        ("health_interval_seconds", float("inf")),
    ),
)
def test_configuration_rejects_nonfinite_schedule_values(
    field: str,
    value: float,
) -> None:
    with pytest.raises(ValueError, match="positive"):
        replace(_configuration(), **{field: value}).validate()

    with pytest.raises(Exception, match="positive"):
        soak_runner._positive_float(str(value))


def test_configuration_rejects_exactly_impossible_chaos_boundaries() -> None:
    configuration = _configuration()
    restart_boundary = (
        3 * configuration.restart_interval_seconds
        + soak_runner.chaos_start_shutdown_margin_seconds(configuration)
    )
    with pytest.raises(ValueError, match="SIGKILL episode"):
        replace(configuration, duration_seconds=restart_boundary).validate()

    partition_boundary = (
        2 * configuration.partition_interval_seconds
        + configuration.partition_duration_seconds
        + soak_runner.chaos_start_shutdown_margin_seconds(configuration)
    )
    with pytest.raises(ValueError, match="partition episodes"):
        replace(configuration, duration_seconds=partition_boundary).validate()


def test_workload_evaluation_enforces_exact_load_and_executor_relationships() -> None:
    configuration = _configuration()
    result = _valid_workload_result(configuration)
    evaluation = evaluate_workload_result(
        result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=_chaos_started(),
        partitions=[],
        restarts=[],
        workload_start=_workload_start(result, configuration),
    )
    assert evaluation["passed"] is True
    assert evaluation["metrics"]["required_cycles"] == 11
    assert evaluation["metrics"]["required_health_samples"] == 61
    assert evaluation["metrics"]["health_cadence"]["maximum_gap_seconds"] == 2.0

    valid_audit_progress = dict(result["audit_progress"])
    result["audit_progress"] = {
        **valid_audit_progress,
        "error_sample_count": 1,
    }
    error_evidence_failed = evaluate_workload_result(
        result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=_chaos_started(),
        partitions=[],
        restarts=[],
        workload_start=_workload_start(result, configuration),
    )
    assert error_evidence_failed["passed"] is False
    assert "audit_error_recovery" in error_evidence_failed["violations"]
    result["audit_progress"] = valid_audit_progress

    health_samples = result["health_samples"]
    result["health_samples"] = [
        {**sample, "scheduled_elapsed_seconds": 0.0} for sample in health_samples
    ]
    cadence_failed = evaluate_workload_result(
        result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=_chaos_started(),
        partitions=[],
        restarts=[],
        workload_start=_workload_start(result, configuration),
    )
    assert cadence_failed["passed"] is False
    assert "health_cadence" in cadence_failed["violations"]
    result["health_samples"] = health_samples

    result["counters"] = {**result["counters"], "closed": 10}
    result["request_retry_count"] = 45
    result["latency"] = {
        "buckets_ms": {"overflow": 1},
        "count": 11,
        "maximum_ms": 61_000,
    }
    failed = evaluate_workload_result(
        result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=_chaos_started(),
        partitions=[],
        restarts=[],
        workload_start=_workload_start(result, configuration),
    )
    assert failed["passed"] is False
    assert set(failed["violations"]) >= {
        "counter_relationships",
        "cycle_latency_bounded",
        "retry_budget",
    }


@pytest.mark.parametrize(
    ("target", "field", "value", "violation"),
    (
        ("counters", "closed", True, "counter_relationships"),
        ("counters", "closed", 1.0, "counter_relationships"),
        ("executor", "claims", 24.0, "executor_claims"),
        ("executor", "reopen_count", True, "executor_reopens"),
        ("executor", "replay_rejections", 28.0, "executor_replay_rejections"),
        ("executor_status", "claim_sequence", 24.0, "executor_claim_sequence"),
        ("pairs", "warden-a->warden-b", 1.0, "transfer_pair_rotation"),
    ),
)
def test_workload_evaluator_rejects_type_loose_integer_evidence(
    target: str,
    field: str,
    value: object,
    violation: str,
) -> None:
    configuration = _configuration()
    result = _valid_workload_result(configuration)
    if target == "executor_status":
        result["executor"]["status"][field] = value
    elif target == "pairs":
        result["transfer_pair_counts"][field] = value
    else:
        result[target][field] = value
    evaluation = evaluate_workload_result(
        result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=_chaos_started(),
        partitions=[],
        restarts=[],
        workload_start=_workload_start(result, configuration),
    )
    assert evaluation["passed"] is False
    assert violation in evaluation["violations"]


def test_authority_evaluator_reconstructs_and_adversarially_gates_global_budget() -> None:
    workload, restarts, verification = _authority_evidence_fixture(_configuration())
    result = evaluate_authority_evidence(workload, restarts, verification)
    assert result["passed"] is True
    assert result["global_counters"] == {
        "permanent_faults": 0,
        "transport_fault_episodes": 1,
        "transport_faults": 1,
        "transport_recoveries": 1,
        "transport_recovery_attempts": 1,
    }

    event = workload["executor"]["transport_recovery_events"][0]
    event["faulted_authority_anchor"]["transport_faults"] = 2
    assert evaluate_authority_evidence(workload, restarts, verification)["passed"] is False
    event["faulted_authority_anchor"]["transport_faults"] = 1
    event["original_transport_error"]["reason"] = "semantic_divergence"
    assert evaluate_authority_evidence(workload, restarts, verification)["passed"] is False
    event["original_transport_error"]["reason"] = "helper_eof"
    verification["terminal_authority_fences"]["warden-a"]["lifetime_id"] = "0" * 32
    assert evaluate_authority_evidence(workload, restarts, verification)["passed"] is False


def test_authority_evaluator_rejects_executor_checkpoint_and_reopen_head_rollback() -> None:
    workload, restarts, verification = _authority_evidence_fixture(_configuration())
    workload["executor"]["terminal_statuses"][1]["status"]["anchor"]["clock_floor_ns"] = 1
    assert evaluate_authority_evidence(workload, restarts, verification)["passed"] is False

    workload, restarts, verification = _authority_evidence_fixture(_configuration())
    first = workload["executor"]["terminal_statuses"][0]["status"]
    first["claim_sequence"] = 2 * workload["cycles"]
    first["anchor"]["claim_sequence"] = 2 * workload["cycles"]
    assert evaluate_authority_evidence(workload, restarts, verification)["passed"] is False

    workload, restarts, verification = _authority_evidence_fixture(_configuration())
    for terminal in workload["executor"]["terminal_statuses"]:
        terminal["status"]["anchor"]["tenant_id"] = "forged-tenant"
    verification["executor"]["terminal_status"]["status"]["anchor"]["tenant_id"] = "forged-tenant"
    assert evaluate_authority_evidence(workload, restarts, verification)["passed"] is False

    for field_name in ("anchor_claim_sequence", "claim_sequence"):
        workload, restarts, verification = _authority_evidence_fixture(_configuration())
        verification["executor"][field_name] = float(verification["executor"][field_name])
        assert evaluate_authority_evidence(workload, restarts, verification)["passed"] is False

    workload, restarts, verification = _authority_evidence_fixture(_configuration())
    workload["executor"]["transport_recovery_events"][0]["ordinal"] = False
    assert evaluate_authority_evidence(workload, restarts, verification)["passed"] is False

    workload, restarts, verification = _authority_evidence_fixture(_configuration())
    workload["executor"]["terminal_statuses"][0]["ordinal"] = 0.0
    assert evaluate_authority_evidence(workload, restarts, verification)["passed"] is False

    workload, restarts, verification = _authority_evidence_fixture(_configuration())
    verification["terminal_authority_fences"]["warden-a"]["fenced_at_monotonic_ns"] = 1_000.0
    assert evaluate_authority_evidence(workload, restarts, verification)["passed"] is False


def test_authority_evaluator_requires_replacement_snapshot_terminal_lower_bound() -> None:
    workload, _, verification = _authority_evidence_fixture(_configuration())
    restart = _restart_record()
    old = restart["authority_fence"]["prior_authority_anchor"]
    new = restart["new_authority_anchor"]
    samples = workload["health_samples"]
    midpoint = len(samples) // 2
    for index, sample in enumerate(samples):
        sample["nodes"]["warden-a"]["authority_anchor"] = old if index < midpoint else new
    fence_id = "final-verification-7-warden-a"
    final_authority = {
        **new,
        "admission_fenced": True,
        "fence_id": fence_id,
        "fenced_at_monotonic_ns": 9_999,
    }
    verification["terminal_authority_fences"]["warden-a"] = {
        "authority_anchor": final_authority,
        "fenced_at_monotonic_ns": 9_999,
        "lifetime_id": new["lifetime_id"],
        "namespace_process_id": new["namespace_process_id"],
        "restart_id": fence_id,
        "schema": "lets.authority-admission-fence/v1",
        "warden_id": "warden-a",
    }
    verification["final_health"]["nodes"]["warden-a"]["authority_anchor"] = new
    assert evaluate_authority_evidence(workload, [restart], verification)["passed"] is True

    first_fault = _executor_authority_status("a" * 32, recovered_fault=True)["first_fault"]
    new.update(
        {
            "first_fault": first_fault,
            "transport_fault_episodes": 1,
            "transport_faults": 1,
            "transport_recoveries": 1,
            "transport_recovery_attempts": 1,
        }
    )
    restart["workload_coordination"]["completed"]["recovery_acknowledgement"][
        "recovered_authority_anchor"
    ] = new
    assert evaluate_authority_evidence(workload, [restart], verification)["passed"] is False


@pytest.mark.parametrize(
    ("mutation", "violation"),
    (
        ({"schema": "lets.production-profile-soak-workload/v1"}, "workload_identity"),
        ({"status": "failed"}, "workload_identity"),
    ),
)
def test_workload_evaluation_rejects_wrong_envelope_identity(
    mutation: dict[str, Any],
    violation: str,
) -> None:
    configuration = _configuration()
    result = _valid_workload_result(configuration)
    result.update(mutation)
    evaluation = evaluate_workload_result(
        result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=_chaos_started(),
        partitions=[],
        restarts=[],
        workload_start=_workload_start(result, configuration),
    )
    assert evaluation["passed"] is False
    assert violation in evaluation["violations"]


def test_workload_start_handshake_rejects_origin_shift() -> None:
    configuration = _configuration()
    result = _valid_workload_result(configuration)
    workload_start = _workload_start(result, configuration)
    result["started_monotonic_seconds"] = 110.0
    evaluation = evaluate_workload_result(
        result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=_chaos_started(),
        partitions=[],
        restarts=[],
        workload_start=workload_start,
    )
    assert evaluation["passed"] is False
    assert "workload_identity" in evaluation["violations"]
    assert "pause_partition_binding" in evaluation["violations"]


def test_health_cadence_rejects_gaps_larger_than_the_exporter_stall_bound() -> None:
    samples = _timed_health_samples(duration_seconds=30.0, interval_seconds=10.0)
    samples[2]["nodes"]["warden-b"]["observation"].update(
        {
            "completed_elapsed_seconds": 26.1,
            "metrics_observed_elapsed_seconds": 26.0,
        }
    )
    samples[2]["completed_elapsed_seconds"] = 26.2
    result = evaluate_health_cadence(
        samples,
        duration_seconds=30.0,
        interval_seconds=10.0,
        restart_evidence={
            "bindings": {},
            "passed": True,
            "windows_by_node": {node: [] for node in NODES},
        },
    )
    assert result["passed"] is False
    assert result["maximum_gap_seconds"] == 15.9


def _restart_record(*, service: str = "warden-a", episode: int = 0) -> dict[str, Any]:
    restart_id = f"restart-{episode}-{service}"
    prior_authority = _core_authority_status(
        service,
        lifetime_id=f"{10 + episode:032x}",
    )
    recovered_authority = _core_authority_status(
        service,
        lifetime_id=f"{100 + episode:032x}",
    )
    recovered_authority["namespace_process_id"] = 200 + episode
    terminal_authority = {
        **prior_authority,
        "admission_fenced": True,
        "fence_id": restart_id,
        "fenced_at_monotonic_ns": 12_500_000_000 + episode,
    }
    armed = {
        "armed_monotonic_seconds": 110.0,
        "episode": episode,
        "restart_id": restart_id,
        "service": service,
        "state": "armed",
    }
    completed = {
        **armed,
        "completed_monotonic_seconds": 125.0,
        "expected_recovered_authority_identity": {
            "lifetime_id": recovered_authority["lifetime_id"],
            "namespace_process_id": recovered_authority["namespace_process_id"],
        },
        "state": "completed",
    }
    acknowledgement = {
        key: armed[key] for key in ("armed_monotonic_seconds", "episode", "restart_id", "service")
    } | {
        "acknowledged_monotonic_seconds": 111.0,
        "prior_authority_anchor": prior_authority,
    }
    recovery = {
        **acknowledgement,
        "completed_monotonic_seconds": 125.0,
        "recovered_authority_anchor": recovered_authority,
        "recovered_monotonic_seconds": 126.0,
    }
    return {
        "authority_fence": {
            "host_container_id": "a" * 64,
            "host_exec_attempts": 1,
            "host_pid": 101,
            "prior_authority_anchor": prior_authority,
            "result": {
                "node": service,
                "request_retry_count": 0,
                "schema": "lets.production-profile-authority-fence/v1",
                "status": "passed",
                "terminal": {
                    "authority_anchor": terminal_authority,
                    "fenced_at_monotonic_ns": terminal_authority["fenced_at_monotonic_ns"],
                    "lifetime_id": prior_authority["lifetime_id"],
                    "namespace_process_id": prior_authority["namespace_process_id"],
                    "restart_id": restart_id,
                    "schema": "lets.authority-admission-fence/v1",
                    "warden_id": service,
                },
            },
        },
        "host_operation_completed_monotonic_seconds": 1_010.0,
        "host_operation_started_monotonic_seconds": 1_002.0,
        "new_authority_anchor": recovered_authority,
        "new_container_id": "b" * 64,
        "new_pid": 202,
        "planned_exit_code": 137,
        "prior_container_id": "a" * 64,
        "prior_pid": 101,
        "service": service,
        "signal": "SIGKILL",
        "workload_coordination": {
            "armed": {
                "acknowledgement": acknowledgement,
                "host_armed_started_monotonic_seconds": 1_000.0,
                "host_monitor_acknowledged_monotonic_seconds": 1_001.0,
                "marker": armed,
            },
            "completed": {
                "host_completed_marker_monotonic_seconds": 1_011.0,
                "host_monitor_recovered_monotonic_seconds": 1_012.0,
                "marker": completed,
                "recovery_acknowledgement": recovery,
            },
        },
    }


def test_restart_authority_fence_recovers_late_first_output_with_unique_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    restart = _restart_record()
    armed = restart["workload_coordination"]["armed"]
    valid_result = restart["authority_fence"]["result"]

    class Clock:
        value = 100.0

        @classmethod
        def monotonic(cls) -> float:
            return cls.value

        @classmethod
        def sleep(cls, seconds: float) -> None:
            cls.value += seconds

    class Workload:
        @staticmethod
        def poll() -> None:
            return None

    class FakeHarness:
        configuration = _configuration()
        workload_container = "workload"

        def __init__(self) -> None:
            self.exec_count = 0
            self.output_paths: list[str] = []

        def run(
            self,
            command: list[str],
            *,
            check: bool = True,
            timeout: float,
        ) -> Any:
            del check
            Clock.value += min(0.05, timeout)
            if "fence-authority" in command:
                self.exec_count += 1
                output_path = command[command.index("--output") + 1]
                self.output_paths.append(output_path)
                if self.exec_count < 3:
                    raise soak_runner.subprocess.TimeoutExpired(command, timeout)
                return soak_runner.subprocess.CompletedProcess(command, 0, "", "")
            script = command[-1]
            if self.exec_count >= 3 and repr(self.output_paths[0]) in script:
                return soak_runner.subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps(valid_result),
                    "",
                )
            return soak_runner.subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setattr(soak_runner.time, "monotonic", Clock.monotonic)
    monkeypatch.setattr(soak_runner.time, "sleep", Clock.sleep)
    harness = FakeHarness()
    attempt_evidence: dict[str, Any] = {}
    result = _fence_restart_authority(
        harness,  # type: ignore[arg-type]
        service="warden-a",
        armed=armed,
        prior_identity={"container_id": "a" * 64, "host_pid": 101},
        deadline_monotonic=130.0,
        attempt_evidence=attempt_evidence,
        workload=Workload(),  # type: ignore[arg-type]
    )

    assert result["host_exec_attempts"] == 3
    assert result["result"] == valid_result
    assert attempt_evidence["resolved"] is True
    assert attempt_evidence["resolved_attempt"] == 1
    assert len(attempt_evidence["attempts"]) == 3
    assert len(set(harness.output_paths)) == 3
    assert attempt_evidence["attempts"][0]["exec_error_type"].endswith("TimeoutExpired")
    assert attempt_evidence["attempts"][0]["last_read"]["outcome"] == "valid"


def test_restart_authority_fence_rejects_extra_fields_and_closes_attempt_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    restart = _restart_record()
    armed = restart["workload_coordination"]["armed"]
    malformed = {**restart["authority_fence"]["result"], "extra": "forged"}

    class Clock:
        value = 200.0

        @classmethod
        def monotonic(cls) -> float:
            return cls.value

        @classmethod
        def sleep(cls, seconds: float) -> None:
            cls.value += seconds

    class Workload:
        @staticmethod
        def poll() -> None:
            return None

    class FakeHarness:
        configuration = _configuration()
        workload_container = "workload"

        def run(
            self,
            command: list[str],
            *,
            check: bool = True,
            timeout: float,
        ) -> Any:
            del check
            Clock.value += min(0.4, timeout)
            if "fence-authority" in command:
                return soak_runner.subprocess.CompletedProcess(command, 0, "", "")
            return soak_runner.subprocess.CompletedProcess(
                command,
                0,
                json.dumps(malformed),
                "",
            )

    monkeypatch.setattr(soak_runner.time, "monotonic", Clock.monotonic)
    monkeypatch.setattr(soak_runner.time, "sleep", Clock.sleep)
    attempt_evidence: dict[str, Any] = {}
    with pytest.raises(RuntimeError, match="response remained unresolved"):
        _fence_restart_authority(
            FakeHarness(),  # type: ignore[arg-type]
            service="warden-a",
            armed=armed,
            prior_identity={"container_id": "a" * 64, "host_pid": 101},
            deadline_monotonic=204.0,
            attempt_evidence=attempt_evidence,
            workload=Workload(),  # type: ignore[arg-type]
        )

    assert attempt_evidence["resolved"] is False
    assert attempt_evidence["status"] == "unresolved"
    assert attempt_evidence["completed_monotonic_seconds"] >= 204.0
    assert len(attempt_evidence["attempts"]) >= 2
    assert all(
        attempt["last_read"]["outcome"] == "invalid_response"
        for attempt in attempt_evidence["attempts"]
        if attempt["last_read"] is not None
    )


def _pause_binding(
    result: dict[str, Any],
    *,
    configuration: SoakConfiguration,
) -> list[dict[str, Any]]:
    pause = {
        "duration_seconds": 15.0,
        "episode": 0,
        "measurement_clipped_duration_seconds": 15.0,
        "observed_elapsed_seconds": 5.0,
        "observed_monotonic_seconds": 105.0,
        "pause_id": "pause-0",
        "requested_monotonic_seconds": 104.0,
        "resumed_elapsed_seconds": 20.0,
        "resumed_monotonic_seconds": 120.0,
    }
    result.update(
        {
            "active_workload_seconds": configuration.duration_seconds - 15.0,
            "pause_interval_count": 1,
            "pause_intervals": [pause],
            "paused_workload_seconds": 15.0,
        }
    )
    marker = {
        "episode": 0,
        "pause_id": "pause-0",
        "requested_monotonic_seconds": 104.0,
    }
    acknowledgement = {
        **marker,
        "observed_monotonic_seconds": 105.0,
        "paused": True,
    }
    return [
        {
            "disabled_monotonic_seconds": 1_002.0,
            "episode": 0,
            "restored_monotonic_seconds": 1_011.0,
            "workload_coordination": {
                **marker,
                "acknowledgement": acknowledgement,
                "authorized_end": {
                    **marker,
                    "authorized_end_monotonic_seconds": 119.0,
                    "host_boundary_completed_monotonic_seconds": 1_011.5,
                    "host_boundary_started_monotonic_seconds": 1_011.0,
                },
                "authorized_start": {
                    **marker,
                    "authorized_start_monotonic_seconds": 106.0,
                    "host_boundary_completed_monotonic_seconds": 1_001.75,
                    "host_boundary_started_monotonic_seconds": 1_001.5,
                },
                "host_acknowledged_monotonic_seconds": 1_001.0,
                "host_pause_duration_seconds": 11.0,
                "host_request_started_monotonic_seconds": 1_000.0,
                "host_resume_completed_monotonic_seconds": 1_012.5,
                "host_resume_started_monotonic_seconds": 1_012.0,
                "marker": marker,
                "workload_resume_requested_monotonic_seconds": 119.5,
            },
        }
    ]


def test_pause_evidence_uses_exact_token_bound_workload_clock_bridge() -> None:
    configuration = _configuration()
    result = _valid_workload_result(configuration)
    partitions = _pause_binding(result, configuration=configuration)
    evidence = evaluate_pause_evidence(
        result,
        configuration=configuration,
        partitions=partitions,
        workload_start=_workload_start(result, configuration),
    )
    assert evidence["passed"] is True
    assert evidence["authorized_paused_seconds"] == 11.0
    assert evidence["active_workload_seconds"] == 109.0

    partitions[0]["workload_coordination"]["pause_id"] = "swapped-token"
    assert (
        evaluate_pause_evidence(
            result,
            configuration=configuration,
            partitions=partitions,
            workload_start=_workload_start(result, configuration),
        )["passed"]
        is False
    )


def test_pause_evidence_recomputes_measurement_edge_and_rejects_forged_active_time() -> None:
    configuration = _configuration()
    result = _valid_workload_result(configuration)
    partitions = _pause_binding(result, configuration=configuration)
    result["pause_intervals"][0]["measurement_clipped_duration_seconds"] = 20.0
    assert (
        evaluate_pause_evidence(
            result,
            configuration=configuration,
            partitions=partitions,
            workload_start=_workload_start(result, configuration),
        )["passed"]
        is False
    )
    result["pause_intervals"][0]["measurement_clipped_duration_seconds"] = 15.0
    result["active_workload_seconds"] = 1.0
    assert (
        evaluate_pause_evidence(
            result,
            configuration=configuration,
            partitions=partitions,
            workload_start=_workload_start(result, configuration),
        )["passed"]
        is False
    )


def test_pause_evidence_rejects_a_marker_before_the_workload_origin() -> None:
    configuration = _configuration()
    result = _valid_workload_result(configuration)
    partitions = _pause_binding(result, configuration=configuration)
    pause = result["pause_intervals"][0]
    coordination = partitions[0]["workload_coordination"]
    pause["requested_monotonic_seconds"] = 99.0
    coordination["requested_monotonic_seconds"] = 99.0
    for document in (
        coordination["marker"],
        coordination["acknowledgement"],
        coordination["authorized_start"],
        coordination["authorized_end"],
    ):
        document["requested_monotonic_seconds"] = 99.0

    assert (
        evaluate_pause_evidence(
            result,
            configuration=configuration,
            partitions=partitions,
            workload_start=_workload_start(result, configuration),
        )["passed"]
        is False
    )


def test_workload_evaluator_rejects_chaos_before_startup_or_pause_request() -> None:
    configuration = _configuration()
    result = _valid_workload_result(configuration)
    workload_start = _workload_start(result, configuration)
    partitions = _pause_binding(result, configuration=configuration)
    valid = evaluate_workload_result(
        result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=_chaos_started(),
        partitions=partitions,
        restarts=[],
        workload_start=workload_start,
    )
    assert valid["passed"] is True

    early_start = evaluate_workload_result(
        result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=998.5,
        partitions=partitions,
        restarts=[],
        workload_start=workload_start,
    )
    assert "chaos_start_binding" in early_start["violations"]

    partitions[0]["workload_coordination"]["host_request_started_monotonic_seconds"] = 999.5
    early_pause = evaluate_workload_result(
        result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=_chaos_started(),
        partitions=partitions,
        restarts=[],
        workload_start=workload_start,
    )
    assert "chaos_start_binding" in early_pause["violations"]


def test_restart_evidence_requires_exact_ack_lifecycle_and_bounded_recovery() -> None:
    restart = _restart_record()
    evidence = evaluate_restart_evidence([restart], workload_started_monotonic=100.0)
    assert evidence["passed"] is True
    assert evidence["windows_by_node"]["warden-a"] == [
        {
            "end_elapsed_seconds": 25.0,
            "episode": 0,
            "restart_id": "restart-0-warden-a",
            "service": "warden-a",
            "start_elapsed_seconds": 11.0,
        }
    ]

    restart["workload_coordination"]["armed"]["acknowledgement"]["restart_id"] = "stale"
    assert evaluate_restart_evidence([restart], workload_started_monotonic=100.0)["passed"] is False

    restart = _restart_record()
    coordination = restart["workload_coordination"]
    for document in (
        coordination["armed"]["marker"],
        coordination["armed"]["acknowledgement"],
        coordination["completed"]["marker"],
        coordination["completed"]["recovery_acknowledgement"],
    ):
        document["episode"] = 0.0
    assert evaluate_restart_evidence([restart], workload_started_monotonic=100.0)["passed"] is False


def test_restart_evidence_rejects_pre_origin_and_overlapping_host_operations() -> None:
    pre_origin = _restart_record()
    coordination = pre_origin["workload_coordination"]
    for document in (
        coordination["armed"]["marker"],
        coordination["armed"]["acknowledgement"],
        coordination["completed"]["marker"],
        coordination["completed"]["recovery_acknowledgement"],
    ):
        document["armed_monotonic_seconds"] = 99.0
    assert (
        evaluate_restart_evidence([pre_origin], workload_started_monotonic=100.0)["passed"] is False
    )

    first = _restart_record()
    second = _restart_record(service="warden-b", episode=1)
    second_coordination = second["workload_coordination"]
    for document in (
        second_coordination["armed"]["marker"],
        second_coordination["armed"]["acknowledgement"],
        second_coordination["completed"]["marker"],
        second_coordination["completed"]["recovery_acknowledgement"],
    ):
        document["armed_monotonic_seconds"] = 140.0
    second_coordination["armed"]["acknowledgement"]["acknowledged_monotonic_seconds"] = 141.0
    second_coordination["completed"]["marker"]["completed_monotonic_seconds"] = 155.0
    second_coordination["completed"]["recovery_acknowledgement"].update(
        {
            "acknowledged_monotonic_seconds": 141.0,
            "completed_monotonic_seconds": 155.0,
            "recovered_monotonic_seconds": 156.0,
        }
    )
    second.update(
        {
            "host_operation_completed_monotonic_seconds": 1_009.0,
            "host_operation_started_monotonic_seconds": 1_005.0,
        }
    )
    second_coordination["armed"].update(
        {
            "host_armed_started_monotonic_seconds": 1_003.0,
            "host_monitor_acknowledged_monotonic_seconds": 1_004.0,
        }
    )
    second_coordination["completed"].update(
        {
            "host_completed_marker_monotonic_seconds": 1_010.0,
            "host_monitor_recovered_monotonic_seconds": 1_011.0,
        }
    )
    evidence = evaluate_restart_evidence(
        [first, second],
        workload_started_monotonic=100.0,
    )
    assert evidence == {
        "passed": False,
        "reason": "host restart operations overlap globally",
    }


def test_planned_unavailable_is_per_node_and_must_overlap_exact_restart_window() -> None:
    restart = _restart_record()
    restart_evidence = evaluate_restart_evidence(
        [restart],
        workload_started_monotonic=100.0,
    )
    samples = _timed_health_samples(duration_seconds=30.0, interval_seconds=10.0)
    armed_marker = restart["workload_coordination"]["armed"]["marker"]
    samples[1]["completed_elapsed_seconds"] = 11.3
    samples[1]["nodes"]["warden-a"] = {
        "observation": {
            "completed_elapsed_seconds": 11.2,
            "metrics_observed_elapsed_seconds": None,
            "request_retries": 1,
            "started_elapsed_seconds": 10.01,
        },
        "planned_unavailable": armed_marker,
    }
    samples[1]["planned_unavailable_nodes"] = ["warden-a"]
    assert (
        evaluate_health_cadence(
            samples,
            duration_seconds=30.0,
            interval_seconds=10.0,
            restart_evidence=restart_evidence,
        )["passed"]
        is True
    )

    samples[1]["nodes"]["warden-a"]["planned_unavailable"] = restart["workload_coordination"][
        "completed"
    ]["marker"]
    assert (
        evaluate_health_cadence(
            samples,
            duration_seconds=30.0,
            interval_seconds=10.0,
            restart_evidence=restart_evidence,
        )["passed"]
        is False
    )
    samples[1]["nodes"]["warden-a"]["planned_unavailable"] = armed_marker

    samples[0]["nodes"]["warden-a"] = samples[1]["nodes"]["warden-a"]
    samples[0]["planned_unavailable_nodes"] = ["warden-a"]
    assert (
        evaluate_health_cadence(
            samples,
            duration_seconds=30.0,
            interval_seconds=10.0,
            restart_evidence=restart_evidence,
        )["passed"]
        is False
    )


@pytest.mark.parametrize(
    ("field", "value", "violation"),
    (
        ("samples_truncated", 1, "health_monitor"),
        ("deadline_miss_count", 1, "health_monitor"),
        ("audit_error_budget_instances", 2, "health_monitor"),
    ),
)
def test_workload_evaluator_rejects_truncated_missed_or_multiple_budget_monitors(
    field: str,
    value: int,
    violation: str,
) -> None:
    configuration = _configuration()
    result = _valid_workload_result(configuration)
    result["health_monitor"][field] = value
    evaluation = evaluate_workload_result(
        result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=_chaos_started(),
        partitions=[],
        restarts=[],
        workload_start=_workload_start(result, configuration),
    )
    assert evaluation["passed"] is False
    assert violation in evaluation["violations"]


def test_workload_evaluator_recomputes_raw_health_retry_total() -> None:
    configuration = _configuration()
    result = _valid_workload_result(configuration)
    result["health_samples"][0]["nodes"]["warden-a"]["observation"]["request_retries"] = 1
    evaluation = evaluate_workload_result(
        result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=_chaos_started(),
        partitions=[],
        restarts=[],
        workload_start=_workload_start(result, configuration),
    )
    assert evaluation["passed"] is False
    assert "health_monitor" in evaluation["violations"]
    assert evaluation["metrics"]["raw_health_request_retries"] == 1


def test_active_time_throughput_floor_passes_and_fails_at_exact_boundary() -> None:
    configuration = replace(
        _configuration(),
        duration_seconds=180.0,
        partition_interval_seconds=30.0,
        restart_interval_seconds=20.0,
    )
    configuration.validate()
    result = _valid_workload_result(configuration, cycles=12)
    passed = evaluate_workload_result(
        result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=_chaos_started(),
        partitions=[],
        restarts=[],
        workload_start=_workload_start(result, configuration),
    )
    assert passed["passed"] is True
    assert passed["metrics"]["active_time_cycle_floor"] == 12

    failed_result = _valid_workload_result(configuration, cycles=11)
    failed = evaluate_workload_result(
        failed_result,
        configuration,
        chaos_completed_monotonic=_chaos_completed(),
        chaos_started_monotonic=_chaos_started(),
        partitions=[],
        restarts=[],
        workload_start=_workload_start(failed_result, configuration),
    )
    assert failed["passed"] is False
    assert "minimum_cycles" in failed["violations"]


def test_independent_sampler_is_not_starved_by_a_long_inline_workload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        retry_count = 0

        def __init__(self, **_kwargs: Any) -> None:
            pass

    def sample(
        _client: object,
        *,
        elapsed_s: float,
        observation_origin_monotonic: float,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        observed = time.monotonic() - observation_origin_monotonic
        return {
            "audit_catchup_nodes": [],
            "audit_error_recoveries": [],
            "elapsed_seconds": elapsed_s,
            "nodes": {
                node: {
                    "audit_exporter": {"max_stall_s": 15.0},
                    "observation": {
                        "completed_elapsed_seconds": observed,
                        "metrics_observed_elapsed_seconds": observed,
                        "request_retries": 0,
                        "started_elapsed_seconds": observed,
                    },
                }
                for node in NODES
            },
            "planned_unavailable_nodes": [],
        }

    monkeypatch.setattr(soak_scenario, "ClusterClient", FakeClient)
    monkeypatch.setattr(soak_scenario, "_health_sample", sample)
    started = time.monotonic()
    sampler = HealthSampler(
        started_monotonic=started,
        interval_seconds=0.02,
        retry_timeout_seconds=1.0,
        seed=1,
        failure_event=threading.Event(),
    )
    sampler.start()
    time.sleep(0.075)
    ended = time.monotonic()
    sampler.finish(workload_ended_monotonic=ended)
    monitor = sampler.result(workload_ended_monotonic=ended)
    assert monitor["health_monitor"]["actual_sample_count"] >= 4
    scheduled = [item["scheduled_elapsed_seconds"] for item in monitor["samples"]]
    assert scheduled[:4] == pytest.approx([0.0, 0.02, 0.04, 0.06], abs=0.005)


def test_monitor_error_sets_abort_and_retains_structured_failure_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        retry_count = 0

        def __init__(self, **_kwargs: Any) -> None:
            pass

    monkeypatch.setattr(soak_scenario, "ClusterClient", FakeClient)
    monkeypatch.setattr(
        soak_scenario,
        "_health_sample",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("injected monitor")),
    )
    failure_event = threading.Event()
    started = time.monotonic()
    sampler = HealthSampler(
        started_monotonic=started,
        interval_seconds=0.02,
        retry_timeout_seconds=1.0,
        seed=2,
        failure_event=failure_event,
    )
    sampler.start()
    assert failure_event.wait(1.0) is True
    sampler.cancel()
    with pytest.raises(RuntimeError, match="injected monitor"):
        sampler.raise_if_failed()
    snapshot = sampler.failure_snapshot(workload_ended_monotonic=time.monotonic())
    assert snapshot["health_monitor"]["status"] == "failed"
    assert snapshot["health_monitor"]["joined"] is True
    assert snapshot["health_monitor"]["samples_truncated"] == 0
    assert snapshot["health_monitor"]["attempted_sample_count"] == 1
    assert snapshot["health_monitor"]["expected_sample_count"] >= 1
    assert snapshot["health_monitor"]["failure_schedule"] == {
        "deadline_elapsed_seconds": pytest.approx(15.0, abs=0.01),
        "schedule_index": 0,
        "scheduled_elapsed_seconds": 0.0,
        "started_elapsed_seconds": pytest.approx(0.0, abs=0.01),
    }


def test_monitor_join_timeout_is_structured_and_daemonized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        retry_count = 0

        def __init__(self, **_kwargs: Any) -> None:
            pass

    class StuckThread:
        daemon = True
        ident = 1

        def is_alive(self) -> bool:
            return True

        def join(self, timeout: float | None = None) -> None:
            assert timeout is not None

    monkeypatch.setattr(soak_scenario, "ClusterClient", FakeClient)
    started = time.monotonic()
    sampler = HealthSampler(
        started_monotonic=started,
        interval_seconds=1.0,
        retry_timeout_seconds=1.0,
        seed=3,
        failure_event=threading.Event(),
    )
    sampler._thread = StuckThread()  # type: ignore[assignment]
    sampler._current_schedule = {  # type: ignore[attr-defined]
        "deadline_elapsed_seconds": 15.0,
        "schedule_index": 0,
        "scheduled_elapsed_seconds": 0.0,
        "started_elapsed_seconds": 0.0,
    }
    with pytest.raises(RuntimeError, match="did not join"):
        sampler.finish(workload_ended_monotonic=started + 1.0)
    snapshot = sampler.failure_snapshot(workload_ended_monotonic=started + 1.0)
    assert snapshot["health_monitor"]["joined"] is False
    assert snapshot["health_monitor"]["failure_schedule"]["schedule_index"] == 0


def test_planned_restart_live_window_expires_only_before_completion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker_path = tmp_path / "restart.json"
    acknowledgement_path = tmp_path / "restart-ack.json"
    marker = {
        "armed_monotonic_seconds": 100.0,
        "episode": 0,
        "restart_id": "restart-0-warden-a",
        "service": "warden-a",
        "state": "armed",
    }
    acknowledgement = {
        **{
            key: marker[key]
            for key in (
                "armed_monotonic_seconds",
                "episode",
                "restart_id",
                "service",
            )
        },
        "acknowledged_monotonic_seconds": 111.0,
    }
    marker_path.write_text(soak_scenario.json.dumps(marker), encoding="utf-8")
    acknowledgement_path.write_text(
        soak_scenario.json.dumps(acknowledgement),
        encoding="utf-8",
    )
    monkeypatch.setattr(soak_scenario, "WORKLOAD_RESTART", marker_path)
    monkeypatch.setattr(soak_scenario, "WORKLOAD_RESTART_ACK", acknowledgement_path)
    monkeypatch.setattr(soak_scenario.time, "monotonic", lambda: 141.001)
    with pytest.raises(RuntimeError, match="live 30s"):
        soak_scenario._planned_restart_window(
            "warden-a",
            observation_started_monotonic=140.0,
            prior_authority_anchor=_core_authority_status("warden-a"),
        )

    completed = {
        **marker,
        "completed_monotonic_seconds": 141.0,
        "state": "completed",
    }
    marker_path.write_text(soak_scenario.json.dumps(completed), encoding="utf-8")
    monkeypatch.setattr(soak_scenario.time, "monotonic", lambda: 141.5)
    assert (
        soak_scenario._planned_restart_window(
            "warden-a",
            observation_started_monotonic=140.0,
        )
        == completed
    )


def test_restart_deadline_accepts_ack_after_a_post_arm_live_observation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FakeClient:
        def __init__(self, **_kwargs: Any) -> None:
            pass

    marker_path = tmp_path / "restart.json"
    acknowledgement_path = tmp_path / "restart-ack.json"
    marker = {
        "armed_monotonic_seconds": 104.0,
        "completed_monotonic_seconds": 120.0,
        "episode": 0,
        "restart_id": "restart-0-warden-a",
        "service": "warden-a",
        "state": "completed",
    }
    acknowledgement = {
        "acknowledged_monotonic_seconds": 106.0,
        "armed_monotonic_seconds": 104.0,
        "episode": 0,
        "restart_id": "restart-0-warden-a",
        "service": "warden-a",
    }
    marker_path.write_text(soak_scenario.json.dumps(marker), encoding="utf-8")
    acknowledgement_path.write_text(
        soak_scenario.json.dumps(acknowledgement),
        encoding="utf-8",
    )
    monkeypatch.setattr(soak_scenario, "ClusterClient", FakeClient)
    monkeypatch.setattr(soak_scenario, "WORKLOAD_RESTART", marker_path)
    monkeypatch.setattr(soak_scenario, "WORKLOAD_RESTART_ACK", acknowledgement_path)
    sampler = HealthSampler(
        started_monotonic=100.0,
        interval_seconds=10.0,
        retry_timeout_seconds=1.0,
        seed=3,
        failure_event=threading.Event(),
    )
    sampler._last_observed_monotonic = {"warden-a": 105.0}  # type: ignore[attr-defined]

    assert sampler._deadline_for(120.0) == 135.0  # type: ignore[attr-defined]


def test_restart_ack_wait_and_host_operations_use_hard_deadlines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Clock:
        current = 0.0

        @classmethod
        def monotonic(cls) -> float:
            cls.current += 5.0
            return cls.current

    class Process:
        @staticmethod
        def poll() -> None:
            return None

    class Result:
        returncode = 0
        stdout = ""

    class AckHarness:
        workload_container = "workload"

        @staticmethod
        def run(*_args: Any, **_kwargs: Any) -> Result:
            return Result()

    marker = {
        "armed_monotonic_seconds": 100.0,
        "episode": 0,
        "restart_id": "restart-0-warden-a",
        "service": "warden-a",
        "state": "armed",
    }
    monkeypatch.setattr(soak_runner.time, "monotonic", Clock.monotonic)
    monkeypatch.setattr(soak_runner.time, "sleep", lambda _seconds: None)
    with pytest.raises(RuntimeError, match="did not provide exact restart"):
        _wait_restart_acknowledgement(
            AckHarness(),  # type: ignore[arg-type]
            marker=marker,
            required_field="acknowledged_monotonic_seconds",
            workload=Process(),  # type: ignore[arg-type]
        )

    with pytest.raises(RuntimeError, match="began after its 30s"):
        soak_runner._restart(
            object(),  # type: ignore[arg-type]
            "warden-a",
            armed={},
            completion_deadline_monotonic=Clock.current - 1.0,
            elapsed_s=0.0,
            workload=Process(),  # type: ignore[arg-type]
        )


def test_wait_healthy_propagates_remaining_deadline_to_inspect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Clock:
        current = 100.0

        @classmethod
        def monotonic(cls) -> float:
            cls.current += 0.1
            return cls.current

    harness = object.__new__(Harness)
    timeouts: list[float] = []

    def state(_service: str, *, timeout: float) -> dict[str, Any]:
        timeouts.append(timeout)
        return {"Health": {"Status": "healthy"}, "Status": "running"}

    harness.state = state  # type: ignore[method-assign]
    monkeypatch.setattr(soak_runner.time, "monotonic", Clock.monotonic)
    harness.wait_healthy("warden-a", timeout_s=2.0)
    assert len(timeouts) == 1
    assert 0 < timeouts[0] <= 2.0


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
        return {
            **_sample(
                rss=65_000_000,
                fds=21,
                database=2_100_000,
                audit=1_100_000,
            ),
            "host_observed_monotonic_seconds": 1_001.0,
        }

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
        "host_observed_monotonic_seconds": 1_001.0,
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
            if path == "/v1/maintenance/authority-status":
                return _core_authority_status(node)
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
                "authority_anchor": _core_authority_status(node),
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
            if path == "/v1/maintenance/authority-status":
                return _core_authority_status(_node)
            return {
                "audit_exporter": _audit_status(),
                "audit_outbox": {"unpublished_count": 5},
                "authority_anchor": _core_authority_status(_node),
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
    if path == "/v1/maintenance/authority-status":
        return _core_authority_status()
    return {
        **_audit_document(_clean_audit_status()),
        "authority_anchor": _core_authority_status(),
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


def test_health_sample_threads_one_absolute_deadline_through_all_twelve_requests(
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
    assert client.deadlines == [100.0] * 12


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
            if self.calls == 12:
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
    assert client.calls == 12
    assert client.deadlines == [1.0] * 12


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
            if path == "/v1/maintenance/authority-status":
                return _core_authority_status(_node)
            status = _audit_status(
                last_error=TRANSIENT_BUSY_ERROR,
                oldest_pending_age_s=None,
                pending=0,
                stalled_for_s=5.0,
            )
            return {
                **_audit_document(status),
                "authority_anchor": _core_authority_status(_node),
                "peer_dispatcher": {},
                "receipts": {"total": 1},
                "storage_capacity": {"healthy": True},
                "transfers": {},
            }

    monkeypatch.setattr(soak_scenario, "_verified_manifest", lambda: None)
    monkeypatch.setattr(soak_scenario, "ClusterClient", lambda **_kwargs: FakeClient())
    if probe_name == "verify_final":
        monkeypatch.setattr(
            soak_scenario,
            "_object",
            lambda _path: {"executor": {"status": {}, "terminal_statuses": [{}]}},
        )
    arguments = soak_scenario.argparse.Namespace(
        convergence_timeout_seconds=1.0,
        retry_timeout_seconds=1.0,
        seed=1,
    )
    probe = getattr(soak_scenario, probe_name)
    with pytest.raises(RuntimeError, match="outside the shared workload error budget"):
        probe(arguments)


def test_final_verification_retains_typed_executor_startup_admission_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    database = tmp_path / "executor.sqlite3"
    anchor_path = tmp_path / "executor.anchor"
    database.write_bytes(b"database")
    anchor_path.write_bytes(b"anchor")
    final_sample = {"nodes": {node: {} for node in NODES}}
    close_calls: list[bool] = []

    class FakeClient:
        retry_count = 0

        def __init__(self, **_options: Any) -> None:
            pass

    class FakeAnchor:
        def __init__(self, *_arguments: Any, **_options: Any) -> None:
            pass

        @staticmethod
        def close() -> None:
            close_calls.append(True)

    def fail_store(*_arguments: Any, **_options: Any) -> None:
        raise soak_scenario.AuthorityAnchorTransportError(
            "raw helper detail must not escape",
            reason="helper_eof",
            operation="confirm",
            request_flushed=True,
            mutation_uncertain=True,
            helper_pid=321,
            helper_exit_code=-9,
        )

    monkeypatch.setattr(soak_scenario, "_verified_manifest", lambda: None)
    monkeypatch.setattr(
        soak_scenario,
        "_object",
        lambda _path: {
            "executor": {
                "status": {"claim_sequence": 1},
                "terminal_statuses": [{"lifetime_id": "a" * 32}],
            }
        },
    )
    monkeypatch.setattr(soak_scenario, "ClusterClient", FakeClient)
    monkeypatch.setattr(soak_scenario, "_health_sample", lambda *_args, **_kwargs: final_sample)
    monkeypatch.setattr(soak_scenario, "_is_converged", lambda _sample: True)
    monkeypatch.setattr(soak_scenario, "_validate_conservation", lambda _sample: {"balanced": True})
    monkeypatch.setattr(soak_scenario, "ProcessFileExecutorAuthorityAnchor", FakeAnchor)
    monkeypatch.setattr(soak_scenario, "SQLiteReceiptReplayStore", fail_store)
    monkeypatch.setattr(soak_scenario, "EXECUTOR_DATABASE", database)
    monkeypatch.setattr(soak_scenario, "EXECUTOR_ANCHOR", anchor_path)
    monkeypatch.setattr(soak_scenario.metadata, "version", lambda _name: "1.0.5")
    arguments = soak_scenario.argparse.Namespace(
        convergence_timeout_seconds=1.0,
        retry_timeout_seconds=1.0,
        seed=7,
    )

    with pytest.raises(soak_scenario.WorkloadMonitorError) as raised:
        soak_scenario.verify_final(arguments)
    executor = raised.value.result["executor"]
    assert executor == {
        "admission_error": {
            "helper_exit_code": -9,
            "helper_pid": 321,
            "mutation_uncertain": True,
            "operation": "confirm",
            "reason": "helper_eof",
            "request_flushed": True,
        },
        "anchor_preserved": True,
        "database_preserved": True,
        "pending_transport_fault": None,
        "phase": "final_verification_startup",
    }
    assert close_calls == [True]
    assert "raw helper detail" not in str(raised.value)


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
            if path == "/v1/maintenance/authority-status":
                return _core_authority_status(_node)
            return {
                "audit_exporter": _audit_status(),
                "authority_anchor": _core_authority_status(_node),
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


def test_workload_pause_acknowledges_and_records_exact_interval(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    pause = tmp_path / "pause.json"
    acknowledgement = tmp_path / "pause-ack.json"
    pause.write_text(
        '{"episode":4,"pause_id":"pause-4","requested_monotonic_seconds":90.0}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(soak_scenario, "WORKLOAD_PAUSE", pause)
    monkeypatch.setattr(soak_scenario, "WORKLOAD_PAUSE_ACK", acknowledgement)
    monkeypatch.setattr(soak_scenario.time, "monotonic", lambda: 100.0)

    class ResumeEvent:
        @staticmethod
        def wait(_timeout: float) -> bool:
            pause.unlink()
            return False

    interval = soak_scenario._wait_if_paused(
        failure_event=ResumeEvent(),  # type: ignore[arg-type]
        raise_monitor_error=lambda: None,
        started=50,
    )
    assert interval == {
        "duration_seconds": 0.0,
        "episode": 4,
        "observed_elapsed_seconds": 50.0,
        "observed_monotonic_seconds": 100.0,
        "pause_id": "pause-4",
        "requested_monotonic_seconds": 90.0,
        "resumed_elapsed_seconds": 50.0,
        "resumed_monotonic_seconds": 100.0,
    }
    assert soak_scenario.json.loads(acknowledgement.read_text(encoding="utf-8")) == {
        "episode": 4,
        "observed_monotonic_seconds": 100.0,
        "pause_id": "pause-4",
        "paused": True,
        "requested_monotonic_seconds": 90.0,
    }


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
        {
            "host_operation_completed_monotonic_seconds": 1_007.0,
            "host_operation_started_monotonic_seconds": 1_006.0,
            "service": "warden-a",
        },
        {
            "host_operation_completed_monotonic_seconds": 1_013.0,
            "host_operation_started_monotonic_seconds": 1_012.0,
            "service": "warden-b",
        },
        {
            "host_operation_completed_monotonic_seconds": 1_019.0,
            "host_operation_started_monotonic_seconds": 1_018.0,
            "service": "warden-c",
        },
    ]
    integrity = _restart_integrity(
        RestartHarness(),
        restarts,
        chaos_completed_monotonic_seconds=1_030.0,
        chaos_started_monotonic_seconds=1_000.0,
    )
    assert integrity["all_wardens_sigkilled"] is True
    assert integrity["longest_sigkill_free_seconds"] == 11.0
    assert integrity["per_warden_lifetimes"] == {
        "warden-a": {
            "longest_seconds": 23.0,
            "passed": True,
            "planned_sigkill_seconds": [6.0],
            "segments_seconds": [6.0, 23.0],
        },
        "warden-b": {
            "longest_seconds": 17.0,
            "passed": True,
            "planned_sigkill_seconds": [12.0],
            "segments_seconds": [12.0, 17.0],
        },
        "warden-c": {
            "longest_seconds": 18.0,
            "passed": True,
            "planned_sigkill_seconds": [18.0],
            "segments_seconds": [18.0, 11.0],
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
            chaos_completed_monotonic_seconds=1_030.0,
            chaos_started_monotonic_seconds=1_000.0,
        )
