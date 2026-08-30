from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import math
import os
import re
import runpy
import shutil
import sqlite3
import subprocess
from collections.abc import Callable
from contextlib import closing
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from deploy.production import check_build_context, healthcheck, stage_config, validate

REPOSITORY = Path(__file__).resolve().parents[2]
PRODUCTION = REPOSITORY / "deploy" / "production"
PINNED_ACTION = re.compile(r"^\s*-?\s*uses:\s*[^\s@]+@[0-9a-f]{40}(?:\s+#.*)?$")


def _release_soak_verifier_script() -> str:
    workflow = (REPOSITORY / ".github/workflows/release.yml").read_text(encoding="utf-8")
    step = workflow.split(
        "- name: Require sustained evidence to bind the exact candidate and source",
        maxsplit=1,
    )[1]
    body = step.split("python - <<'PY'\n", maxsplit=1)[1].split("\n          PY", maxsplit=1)[0]
    return (
        "\n".join(
            line[10:] if line.startswith("          ") else line for line in body.splitlines()
        )
        + "\n"
    )


def _release_soak_verifier_namespace() -> dict[str, Any]:
    """Load only the workflow's independent verifier helpers into empty globals."""

    tree = ast.parse(_release_soak_verifier_script())
    assignments = {
        "authority_counter_fields",
        "core_authority_fields",
        "core_checkpoint_fields",
        "core_checkpoint_stable_fields",
        "executor_authority_fields",
        "executor_checkpoint_fields",
        "first_fault_fields",
        "observation_document_fields",
        "observation_dynamic_fields",
        "observation_immutable_fields",
        "observation_timing_fields",
        "success_workload_fields",
        "terminal_audit_proof_fields",
        "transport_operations",
        "transport_reasons",
    }
    functions = {
        "core_checkpoint_extends",
        "finite_number",
        "sha256_json",
        "valid_authority",
        "valid_audit_exporter_projection",
        "valid_audit_exporter_status",
        "valid_bounded_integer",
        "valid_capacity_status",
        "valid_core_checkpoint",
        "valid_digest",
        "valid_identifier",
        "valid_leases_status",
        "valid_observation_document",
        "valid_observation_progression",
        "valid_observation_snapshot",
        "valid_observation_timing",
        "valid_outbox_status",
        "valid_peer_status",
        "valid_receipts_status",
        "valid_resource_vector",
        "valid_retry_scope",
        "valid_runtime_status",
        "valid_sample_request_budget",
        "valid_sha256",
        "valid_success_workload_artifact",
        "valid_terminal_fence",
        "valid_transfers_status",
    }
    selected: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            selected.append(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in functions:
                selected.append(node)
        elif isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id in assignments for target in node.targets
        ):
            selected.append(node)
    namespace: dict[str, Any] = {}
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
            "release-soak-verifier-helpers",
            "exec",
        ),
        namespace,
    )
    assert functions <= namespace.keys()
    assert assignments <= namespace.keys()
    return namespace


def _release_authority(*, lifetime: str = "a" * 32, fenced: bool = False) -> dict[str, Any]:
    return {
        "admission_fenced": fenced,
        "enabled": True,
        "fault_reason": None,
        "fault_stage": None,
        "fence_id": "restart-0" if fenced else None,
        "fenced_at_monotonic_ns": 900 if fenced else None,
        "first_fault": None,
        "healthy": True,
        "lifetime_id": lifetime,
        "namespace_process_id": 17,
        "permanent_faults": 0,
        "retry_not_before_monotonic_ns": None,
        "state": "healthy",
        "transport_fault_episodes": 0,
        "transport_faults": 0,
        "transport_recoveries": 0,
        "transport_recovery_attempts": 0,
        "unresolved_transport_faults": 0,
    }


def _release_checkpoint(*, revision: int = 1) -> dict[str, Any]:
    digest = base64.urlsafe_b64encode(bytes(32)).decode("ascii").rstrip("=")
    return {
        "audit_hash": digest,
        "audit_sequence": revision - 1,
        "clock_floor_ns": revision,
        "config_epoch": 1,
        "database_instance_id": digest,
        "envelope_id": "production-acceptance-envelope",
        "format": "LETS-AUTHORITY-ANCHOR/1",
        "schema_version": 2,
        "signing_key_id": "production-key",
        "signing_public_key_sha256": digest,
        "state_digest": digest,
        "state_revision": revision,
        "tenant_id": "production-acceptance-tenant",
        "warden_id": "warden-a",
    }


def _release_observation(
    namespace: dict[str, Any],
    *,
    revision: int = 1,
    lifetime: str = "a" * 32,
    generation: str = "b" * 32,
) -> dict[str, Any]:
    checkpoint = _release_checkpoint(revision=revision)
    authority = _release_authority(lifetime=lifetime)
    audit_hash = "sha256:" + bytes(32).hex()
    schema_digest = "sha256:" + "1" * 64
    invariant = {
        "checked_at_ns": 100 + revision,
        "config_epoch": 1,
        "consumed": [0],
        "envelope_id": "production-acceptance-envelope",
        "free_pool": [10],
        "healthy": True,
        "initial_share": [10],
        "lease_residual": [0],
        "tenant_id": "production-acceptance-tenant",
        "transferred_in": [0],
        "transferred_out": [0],
    }
    snapshot: dict[str, Any] = {
        "age_ns": 5,
        "audit_exporter": {
            "archive_reconciled": True,
            "configured": True,
            "healthy": True,
            "last_error": None,
            "last_success_ns": 50,
            "max_pending": 4_096,
            "max_stall_s": 40.0,
            "oldest_pending_age_s": None,
            "pending": 0,
            "publish_blocked": False,
            "publish_timeout_s": 5.0,
            "running": True,
            "sink_call_blocked": False,
            "stalled_for_s": 0.0,
        },
        "audit_outbox": {"oldest_unpublished_age_ns": 0, "unpublished_count": 0},
        "audit_verification": {
            "captured_head_hash": audit_hash,
            "captured_head_sequence": revision - 1,
            "catching_up": False,
            "error_type": None,
            "lag": 0,
            "last_full_verification_at_ns": 10,
            "page_size": 256,
            "schema_definition_sha256": schema_digest,
            "sticky_failure": False,
            "sweep_cursor_sequence": revision - 1,
            "sweep_last_completed_at_ns": 50,
            "sweep_last_completed_head_hash": audit_hash,
            "sweep_last_completed_head_sequence": revision - 1,
            "sweep_target_sequence": revision - 1,
            "valid": True,
            "verified_through_hash": audit_hash,
            "verified_through_sequence": revision - 1,
        },
        "authority_anchor": authority,
        "authority_checkpoint": checkpoint,
        "capture_duration_ns": 2,
        "capture_started_monotonic_ns": 100,
        "capture_status": {
            "attempt_sequence": revision,
            "capture_in_progress": False,
            "last_attempt_monotonic_ns": 100,
            "last_error_type": None,
            "last_successful_attempt_sequence": revision,
        },
        "captured_at_monotonic_ns": 101,
        "captured_at_ns": 100,
        "captured_authority_anchor": copy.deepcopy(authority),
        "checked_at_ns": 100 + revision,
        "clock_healthy": True,
        "core_state_revision": revision,
        "database_instance_id": checkpoint["database_instance_id"],
        "fresh": True,
        "generation": generation,
        "invariant": invariant,
        "invariant_healthy": True,
        "leases": {"by_status": {}, "total": 0},
        "lifetime_id": lifetime,
        "max_age_ns": 15_000_000_000,
        "observation_eligible": True,
        "peer_dispatcher": {
            "configured_peers": 2,
            "delivered_records": 0,
            "durable_retry": None,
            "failed_records": 0,
            "healthy": True,
            "last_cycle_ns": 90,
            "last_error": None,
            "pending_records": 0,
            "prepared_transfers": 0,
            "running": True,
            "superseded_records": 0,
        },
        "published_at_monotonic_ns": 102,
        "published_at_ns": 102,
        "ready": True,
        "receipts": {"total": 0},
        "resources": {
            name: copy.deepcopy(invariant[name])
            for name in (
                "consumed",
                "free_pool",
                "initial_share",
                "lease_residual",
                "transferred_in",
                "transferred_out",
            )
        },
        "revision": revision,
        "runtime": {
            "changed_at_ns": 1,
            "changed_by": "test",
            "generation": 1,
            "mode": "ACTIVE",
            "reason": "test",
        },
        "schema": "lets.observation-snapshot/v1",
        "served_at_monotonic_ns": 106,
        "service_ready": True,
        "signing_key_healthy": True,
        "snapshot_id": "",
        "sqlite_schema_sha256": schema_digest,
        "storage_capacity": {
            "additional_shared_memory_bytes": 0,
            "database_bytes": 16_384,
            "effective_database_bytes": 12_288,
            "filesystem_free_bytes": 1_000_000,
            "free_pages": 1,
            "healthy": True,
            "logical_live_bytes": 12_288,
            "main_database_bytes": 16_384,
            "max_database_bytes": None,
            "max_page_count": 4,
            "min_free_disk_bytes": 0,
            "page_count": 4,
            "page_size": 4_096,
            "prior_full_error": False,
            "remaining_main_growth_bytes": 0,
            "required_filesystem_free_bytes": 4_096,
            "reserve_pages": 1,
            "reusable_bytes": 4_096,
            "shared_memory_bytes": 0,
            "wal_bytes": 0,
            "worst_case_shared_memory_bytes": 0,
            "worst_case_transaction_wal_bytes": 0,
        },
        "transfers": {
            "in_flight_count": 0,
            "inbound_gap_count": 0,
            "incoming_compacted_high_water": 0,
            "incoming_contiguous_high_water": 0,
            "incoming_streams": 0,
            "outgoing_acked_high_water": 0,
            "outgoing_compacted_high_water": 0,
            "outgoing_streams": 0,
        },
    }
    immutable = {
        key: value
        for key, value in snapshot.items()
        if key not in namespace["observation_dynamic_fields"] and key != "snapshot_id"
    }
    snapshot["snapshot_id"] = namespace["sha256_json"](immutable)
    return snapshot


def _reseal_release_observation(namespace: dict[str, Any], snapshot: dict[str, Any]) -> None:
    immutable = {
        key: value
        for key, value in snapshot.items()
        if key not in namespace["observation_dynamic_fields"] and key != "snapshot_id"
    }
    snapshot["snapshot_id"] = namespace["sha256_json"](immutable)


def _forge_oversized_release_resources(snapshot: dict[str, Any]) -> None:
    maximum = 1 << 80
    for target in (snapshot["invariant"], snapshot["resources"]):
        target["initial_share"] = [maximum]
        target["transferred_in"] = [0]
        target["free_pool"] = [maximum]
        target["lease_residual"] = [0]
        target["consumed"] = [0]
        target["transferred_out"] = [0]


def _release_observation_document(
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    invariant = snapshot["invariant"]
    summary_fields = {
        "consumed",
        "free_pool",
        "healthy",
        "lease_residual",
        "transferred_in",
        "transferred_out",
    }
    return {
        "audit_exporter": {
            key: copy.deepcopy(snapshot["audit_exporter"][key])
            for key in (
                "archive_reconciled",
                "healthy",
                "last_error",
                "last_success_ns",
                "max_pending",
                "max_stall_s",
                "oldest_pending_age_s",
                "pending",
                "publish_blocked",
                "running",
                "sink_call_blocked",
                "stalled_for_s",
            )
        }
        | {"catching_up": snapshot["audit_exporter"]["healthy"] is False},
        "audit_outbox": copy.deepcopy(snapshot["audit_outbox"]),
        "authority_anchor": copy.deepcopy(snapshot["authority_anchor"]),
        "invariant": {name: copy.deepcopy(invariant[name]) for name in summary_fields},
        "observation": {
            "completed_elapsed_seconds": 1.2,
            "metrics_observed_elapsed_seconds": 1.1,
            "request_count": 1,
            "request_path": "/v1/metrics",
            "request_retries": 0,
            "retry_errors": {"first_error": None, "last_error": None},
            "started_elapsed_seconds": 1.0,
        },
        "observation_generation": snapshot["generation"],
        "observation_revision": snapshot["revision"],
        "observation_snapshot": snapshot,
        "observation_snapshot_id": snapshot["snapshot_id"],
        "peer_dispatcher": copy.deepcopy(snapshot["peer_dispatcher"]),
        "ready": snapshot["ready"],
        "receipts": copy.deepcopy(snapshot["receipts"]),
        "service_ready": snapshot["service_ready"],
        "storage_capacity": copy.deepcopy(snapshot["storage_capacity"]),
        "transfers": copy.deepcopy(snapshot["transfers"]),
    }


def _release_terminal_fence(
    namespace: dict[str, Any],
    prior: dict[str, Any],
    *,
    full: bool,
) -> dict[str, Any]:
    checkpoint = copy.deepcopy(prior["authority_checkpoint"])
    authority = _release_authority(lifetime=str(prior["lifetime_id"]), fenced=True)
    proof = {
        "authority_checkpoint_sha256": namespace["sha256_json"](checkpoint),
        "authority_state_revision": checkpoint["state_revision"],
        "database_instance_id": checkpoint["database_instance_id"],
        "generation": prior["generation"],
        "lifetime_id": prior["lifetime_id"],
        "schema": "lets.terminal-audit-proof/v1",
        "schema_definition_sha256": prior["sqlite_schema_sha256"],
        "startup_full_verification_at_ns": prior["audit_verification"][
            "last_full_verification_at_ns"
        ],
        "valid": True,
        "verification_mode": "full" if full else "trusted-startup-plus-tail",
        "verified_at_ns": 20,
        "verified_head_hash": "sha256:" + bytes(32).hex(),
        "verified_head_sequence": checkpoint["audit_sequence"],
    }
    return {
        "authority_anchor": authority,
        "authority_checkpoint": checkpoint,
        "fenced_at_monotonic_ns": 900,
        "lifetime_id": prior["lifetime_id"],
        "namespace_process_id": authority["namespace_process_id"],
        "restart_id": "restart-0",
        "schema": "lets.authority-admission-fence/v1",
        "terminal_audit_proof": proof,
        "warden_id": "warden-a",
    }


def _release_success_workload_artifact(namespace: dict[str, Any]) -> dict[str, Any]:
    workload = {name: None for name in namespace["success_workload_fields"]}
    workload.update(
        {
            "artifact_revision": 1,
            "journal_revision": 2,
            "schema": "lets.production-profile-soak-workload/v2",
            "status": "passed",
        }
    )
    payload = dict(workload)
    payload.pop("artifact_payload_sha256")
    workload["artifact_payload_sha256"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
    )
    return workload


@pytest.fixture(autouse=True)
def _model_independent_production_filesystems(monkeypatch: pytest.MonkeyPatch) -> None:
    original = validate._storage_device
    original_mount = validate._storage_mount
    modeled_devices = {
        "state": 10_001,
        "authority": 10_002,
        "audit": 10_003,
        "backup": 10_004,
    }

    def storage_device(path: Path) -> int:
        return modeled_devices.get(path.name, original(path))

    def storage_mount(path: Path) -> validate.StorageMount:
        device = modeled_devices.get(path.name)
        if device is None:
            return original_mount(path)
        mount_point = PurePosixPath(path.as_posix())
        return validate.StorageMount(
            mount_id=device,
            device=f"0:{device}",
            root=PurePosixPath("/"),
            mount_point=mount_point,
            filesystem_type="ext4",
            source=f"/dev/lets-{path.name}",
            has_descendant_mount=False,
        )

    monkeypatch.setattr(validate, "_storage_device", storage_device)
    monkeypatch.setattr(validate, "_storage_device_numbers", lambda device: (0, device))
    monkeypatch.setattr(validate, "_storage_mount", storage_mount)


def test_runtime_image_is_pinned_nonroot_and_root_owned() -> None:
    dockerfile = (REPOSITORY / "Dockerfile").read_text(encoding="utf-8")
    from_lines = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
    internal_stages: set[str] = set()
    external_lines: list[str] = []
    for line in from_lines:
        fields = line.split()
        if fields[1] not in internal_stages:
            external_lines.append(line)
        if len(fields) >= 4 and fields[-2].casefold() == "as":
            internal_stages.add(fields[-1])

    assert from_lines
    assert all(re.search(r"@sha256:[0-9a-f]{64}(?:\s+AS\s+\w+)?$", line) for line in external_lines)
    assert "COPY --from=builder --chown=0:0 /app/.venv /app/.venv" in dockerfile
    assert "COPY --chown=0:0" in dockerfile
    assert "chmod -R a-w /app" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "python:3.14-alpine@sha256:" in dockerfile
    assert "apk add --no-cache --upgrade libcrypto3=3.5.8-r0 libssl3=3.5.8-r0" in dockerfile
    assert "apk add --no-cache openssl=3.5.8-r0" in dockerfile
    assert "/usr/local/lib/python3.14/site-packages/pip" in dockerfile
    assert "/sbin/nologin" in dockerfile
    assert "org.opencontainers.image.revision" in dockerfile
    assert "ARG SOURCE_DATE_EPOCH=0" in dockerfile
    assert "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" in dockerfile
    assert "lets_agent-*.dist-info/uv_cache.json" in dockerfile
    assert "find /app/.venv -exec touch -h -d" in dockerfile
    assert "find /app -exec touch -h -d" in dockerfile
    assert re.search(r"^\s*(?:COPY|ADD)\s+[.]\s", dockerfile, re.MULTILINE) is None
    runtime_stage = dockerfile.split(" AS runtime", 1)[1].split("FROM runtime", 1)[0]
    assert "bootstrap_cluster.py" not in runtime_stage
    assert "start_warden.py" not in runtime_stage


def test_opt_in_production_acceptance_requires_real_mtls_and_external_provider() -> None:
    compose = (PRODUCTION / "acceptance-compose.yaml").read_text(encoding="utf-8")
    scenario = (PRODUCTION / "acceptance" / "scenario.py").read_text(encoding="utf-8")
    runner = (PRODUCTION / "run_acceptance.py").read_text(encoding="utf-8")

    assert compose.count("--production") == 1
    for argument in ("--tls-cert", "--tls-key", "--client-ca", "--peer-ca", "--peer-cert"):
        assert argument in compose
    assert compose.count("/var/lib/lets-authority") >= 6
    assert compose.count("/var/lib/lets-audit") >= 6
    assert compose.count("subpath: config.json") == 3
    assert "/var/lib/lets-executor" in compose
    assert "/var/lib/lets-executor-authority" in compose
    assert compose.count("LETS_PRODUCTION_ACCEPTANCE_IMAGE") == 3
    assert '"read_only_config": True' in runner
    assert '"audit_archive": archive' in runner
    assert "apk add --no-cache openssl >/dev/null" not in compose
    assert "network_mode: none" in compose.split("  materials:", 1)[1].split("  init-a:", 1)[0]
    assert "cap_add: [CHOWN, FOWNER]" in compose
    assert "--backlog" in compose
    assert '--peer-request-timeout-seconds\n  - "60"' in compose
    assert "stop_grace_period: 120s" in compose
    assert "max-size: 10m" in compose
    assert "nofile:" in compose
    assert compose.count("mem_limit: 1g") == 1
    assert compose.count("memswap_limit: 1g") == 1
    assert "generic-production" in scenario
    assert "_sqlite_wal_reset_safe" in scenario
    assert "ProcessFileExecutorAuthorityAnchor" in scenario
    assert "SQLiteReceiptReplayStore.initialize" in scenario
    assert "duplicate_receipt_rejected_after_reopen" in scenario
    assert "stale_database_restore_rejected" in scenario
    assert "expired JWT" in scenario
    assert "untrusted client certificate" in scenario
    assert "SIGKILL" in runner
    assert '"a_to_b"' in runner and '"b_to_a"' in runner
    assert '"tree_digest": source_tree_digest' in runner
    assert '"runtime_image_digest": candidate_image' in runner
    assert "configured_images != {candidate_image}" in runner
    assert 'executor = _scenario("executor")' in runner
    assert '"executor": executor' in runner
    assert 'host.get("Memory") != 1024 * 1024 * 1024' in runner
    assert 'host.get("MemorySwap") != 1024 * 1024 * 1024' in runner


def test_build_context_policy_rejects_secret_like_tracked_paths() -> None:
    assert check_build_context.is_sensitive_path("operator/.env")
    assert check_build_context.is_sensitive_path("nested/secrets/identity.json")
    assert check_build_context.is_sensitive_path("tls/server.key")
    assert check_build_context.is_sensitive_path("id_ed25519")
    assert check_build_context.is_sensitive_path("gcp/service-account-prod.json")
    assert not check_build_context.is_sensitive_path("deploy/production/.env.example")
    assert check_build_context.find_violations(REPOSITORY) == ()


def test_dependabot_tracks_python_actions_and_pinned_container_bases() -> None:
    configuration = (REPOSITORY / ".github/dependabot.yml").read_text(encoding="utf-8")

    for ecosystem in ("uv", "github-actions", "docker"):
        assert f"package-ecosystem: {ecosystem}" in configuration
    assert configuration.count("interval: weekly") == 3


def test_production_compose_is_fail_closed_and_hardened() -> None:
    compose = (PRODUCTION / "compose.yaml").read_text(encoding="utf-8")
    example_environment = (PRODUCTION / ".env.example").read_text(encoding="utf-8")

    assert "${LETS_IMAGE:?" in compose
    assert "${LETS_RUNTIME_PROVIDER:?" in compose
    assert "${LETS_CONFIG_FILE:?" in compose
    assert "--production" in compose
    assert "--runtime-provider" in compose
    assert "--limit-concurrency" in compose
    assert "${LETS_LIMIT_CONCURRENCY:-64}" in compose
    assert "--backlog" in compose
    assert "${LETS_BACKLOG:-128}" in compose
    assert "--request-body-timeout" in compose
    assert "${LETS_REQUEST_BODY_TIMEOUT_SECONDS:-30}" in compose
    assert "LETS_REQUEST_BODY_TIMEOUT_SECONDS=30" in example_environment
    assert "--peer-request-timeout-seconds" in compose
    assert "${LETS_PEER_REQUEST_TIMEOUT_SECONDS:-60}" in compose
    assert "LETS_PEER_REQUEST_TIMEOUT_SECONDS=60" in example_environment
    assert "--timeout-graceful-shutdown" in compose
    assert "stop_grace_period: 120s" in compose
    assert 40 + 10 + (60 + 5 + 0.25 + 2) < 120
    assert "${LETS_HEALTH_START_PERIOD_SECONDS:-600}s" in compose
    assert 'mem_limit: "${LETS_MEMORY_LIMIT:-1g}"' in compose
    assert 'memswap_limit: "${LETS_MEMORY_LIMIT:-1g}"' in compose
    assert "allow-insecure" not in compose
    assert "read_only: true" in compose
    assert "cap_drop: [ALL]" in compose
    assert "no-new-privileges:true" in compose
    assert 'user: "10001:10001"' in compose
    assert "/var/lib/lets-authority" in compose
    assert "/var/lib/lets-audit" in compose
    assert "/var/lib/lets-backup" not in compose
    assert "/etc/lets/trust" in compose
    assert "create_host_path: false" in compose
    assert compose.count("propagation: rprivate") == compose.count("create_host_path: false")
    assert "LETS_BOOTSTRAP_TOKEN" not in compose
    assert "lets-acceptance-token" not in compose
    assert "http://" not in compose
    assert compose.count('file: "${LETS_') == 6
    for audit_setting in (
        "LETS_AUDIT_STORAGE_BOUNDARY",
        "LETS_AUDIT_CAPACITY_BYTES",
        "LETS_AUDIT_EXPECTED_DAILY_BYTES",
        "LETS_AUDIT_FORECAST_DAYS",
        "LETS_AUDIT_MIN_FREE_BYTES",
    ):
        assert f"{audit_setting}=" in example_environment
    for domain_setting in (
        "LETS_STATE_ROLLBACK_DOMAIN",
        "LETS_AUTHORITY_STORAGE_BOUNDARY",
        "LETS_AUTHORITY_ROLLBACK_DOMAIN",
        "LETS_AUDIT_ROLLBACK_DOMAIN",
        "LETS_BACKUP_STORAGE_BOUNDARY",
        "LETS_BACKUP_ROLLBACK_DOMAIN",
    ):
        assert f"{domain_setting}=" in example_environment


def test_provisioning_compose_does_not_expose_the_runtime_config_or_network() -> None:
    compose = (PRODUCTION / "provision-compose.yaml").read_text(encoding="utf-8")

    assert "network_mode: none" in compose
    assert "LETS_CONFIG_FILE" not in compose
    assert "/var/lib/lets/config.json" not in compose
    assert 'user: "10001:10001"' in compose
    assert "read_only: true" in compose
    assert "cap_drop: [ALL]" in compose
    assert "no-new-privileges:true" in compose
    assert compose.count("propagation: rprivate") == compose.count("create_host_path: false")


def test_maintenance_compose_is_networkless_and_owns_backup_access() -> None:
    compose = (PRODUCTION / "maintenance-compose.yaml").read_text(encoding="utf-8")

    assert "network_mode: none" in compose
    assert "/var/lib/lets-backup" in compose
    assert "/var/lib/lets/config.json" in compose
    assert 'user: "10001:10001"' in compose
    assert "read_only: true" in compose
    assert "cap_drop: [ALL]" in compose
    assert "no-new-privileges:true" in compose
    assert compose.count("propagation: rprivate") == compose.count("create_host_path: false")
    assert 'restart: "no"' in compose
    assert "ports:" not in compose


def _production_environment(tmp_path: Path) -> dict[str, str]:
    directories = {}
    for name in ("state", "authority", "audit", "backup", "trust"):
        path = tmp_path / name
        path.mkdir()
        directories[name] = str(path.resolve())
    trust = Path(directories["trust"])
    (trust / "manifest.json").write_text("{}\n", encoding="utf-8")
    (trust / "identity-keys.json").write_text("{}\n", encoding="utf-8")
    with (
        closing(sqlite3.connect(Path(directories["state"]) / "warden.sqlite3")) as connection,
        connection,
    ):
        connection.execute("CREATE TABLE production_validation_probe(value INTEGER)")
    files = {}
    for name in ("tls-cert", "tls-key", "client-ca", "peer-ca", "peer-cert", "peer-key"):
        path = tmp_path / f"{name}.pem"
        path.write_text("test-only-placeholder\n", encoding="utf-8")
        path.chmod(0o600)
        files[name] = str(path.resolve())
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "allow_insecure_manifest": False,
                "bootstrap_identities": [],
                "database": "/var/lib/lets/warden.sqlite3",
                "manifest": "/etc/lets/trust/manifest.json",
                "manifest_digest": "sha256:" + "a" * 64,
                "operator_trust": {},
                "max_database_bytes": 16_777_216,
                "min_free_disk_bytes": 1_048_576,
                "reserve_pages": 64,
                "runtime": {"provider": "example-provider", "options": {}},
                "version": 1,
                "warden_id": "warden-a",
                "tenant_id": "tenant-a",
                "envelope_id": "envelope-a",
            }
        ),
        encoding="utf-8",
    )
    config.chmod(0o444)
    return {
        "LETS_IMAGE": f"ghcr.io/example/lets@sha256:{'a' * 64}",
        "LETS_RUNTIME_PROVIDER": "example-provider",
        "LETS_PEER_REQUEST_TIMEOUT_SECONDS": "60",
        "LETS_SERVER_NAME": "warden-a.example.test",
        "LETS_STATE_DIR": directories["state"],
        "LETS_AUTHORITY_DIR": directories["authority"],
        "LETS_AUDIT_DIR": directories["audit"],
        "LETS_BACKUP_DIR": directories["backup"],
        "LETS_TRUST_DIR": directories["trust"],
        "LETS_CONFIG_FILE": str(config.resolve()),
        "LETS_STATE_STORAGE_BOUNDARY": "enforced-quota",
        "LETS_STATE_ROLLBACK_DOMAIN": "zfs://state-pool/warden-a",
        "LETS_STATE_CAPACITY_BYTES": "41943040",
        "LETS_AUTHORITY_STORAGE_BOUNDARY": "fenced-filesystem",
        "LETS_AUTHORITY_ROLLBACK_DOMAIN": "zfs://authority-pool/warden-a",
        "LETS_AUDIT_STORAGE_BOUNDARY": "dedicated-filesystem",
        "LETS_AUDIT_ROLLBACK_DOMAIN": "zfs://audit-pool/warden-a",
        "LETS_AUDIT_CAPACITY_BYTES": "16777216",
        "LETS_AUDIT_EXPECTED_DAILY_BYTES": "1024",
        "LETS_AUDIT_FORECAST_DAYS": "30",
        "LETS_AUDIT_MIN_FREE_BYTES": "1048576",
        "LETS_BACKUP_STORAGE_BOUNDARY": "dedicated-filesystem",
        "LETS_BACKUP_ROLLBACK_DOMAIN": "zfs://backup-pool/warden-a",
        "LETS_TLS_CERT_FILE": files["tls-cert"],
        "LETS_TLS_KEY_FILE": files["tls-key"],
        "LETS_CLIENT_CA_FILE": files["client-ca"],
        "LETS_PEER_CA_FILE": files["peer-ca"],
        "LETS_PEER_CERT_FILE": files["peer-cert"],
        "LETS_PEER_KEY_FILE": files["peer-key"],
    }


def _generic_options() -> dict[str, str]:
    return {
        "audit_archive_path": "/var/lib/lets-audit/audit.sqlite3",
        "authority_anchor_path": "/var/lib/lets-authority/warden.anchor.json",
        "identity_audience": "lets-api",
        "identity_issuer": "https://identity.example",
        "identity_keys_file": "/etc/lets/trust/identity-keys.json",
        "signer_command_json": '["/usr/local/bin/lets-hsm-sign"]',
        "signer_key_id": "warden-key",
        "signer_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }


def _rewrite_config(environment: dict[str, str], document: dict[str, object]) -> None:
    config = Path(environment["LETS_CONFIG_FILE"])
    config.chmod(0o600)
    config.write_text(json.dumps(document), encoding="utf-8")
    config.chmod(0o444)


def test_production_environment_validation(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    assert validate.validate_environment(environment) == ()

    environment["LETS_IMAGE"] = "ghcr.io/example/lets:latest"
    environment["LETS_AUTHORITY_DIR"] = environment["LETS_STATE_DIR"]
    environment["LETS_TIMEOUT_GRACEFUL_SHUTDOWN"] = "45"
    environment["LETS_HEALTH_START_PERIOD_SECONDS"] = "30"
    environment["LETS_STATE_STORAGE_BOUNDARY"] = "shared-directory"
    environment["LETS_STATE_CAPACITY_BYTES"] = "1"
    environment["LETS_SERVER_NAME"] = "https://unsafe.example"
    environment["LETS_BIND_ADDRESS"] = "all-interfaces"
    environment["LETS_CPUS"] = "0"
    environment["LETS_MEMORY_LIMIT"] = "0"
    environment["LETS_BACKLOG"] = "0"
    environment["LETS_REQUEST_BODY_TIMEOUT_SECONDS"] = "0"
    environment["LETS_PEER_REQUEST_TIMEOUT_SECONDS"] = "29"
    errors = validate.validate_environment(environment)
    assert any("immutable" in error for error in errors)
    assert any("distinct non-nested paths" in error for error in errors)
    assert any("GRACEFUL_SHUTDOWN" in error for error in errors)
    assert any("HEALTH_START_PERIOD" in error for error in errors)
    assert any("LETS_STATE_STORAGE_BOUNDARY" in error for error in errors)
    assert any("worst-case WAL" in error for error in errors)
    assert any("LETS_SERVER_NAME" in error for error in errors)
    assert any("LETS_BIND_ADDRESS" in error for error in errors)
    assert any("LETS_CPUS" in error for error in errors)
    assert any("LETS_MEMORY_LIMIT" in error for error in errors)
    assert any("LETS_BACKLOG" in error for error in errors)
    assert any("LETS_REQUEST_BODY_TIMEOUT_SECONDS" in error for error in errors)
    assert any("LETS_PEER_REQUEST_TIMEOUT_SECONDS" in error for error in errors)


def test_production_environment_rejects_shared_or_undeclared_rollback_domains(
    tmp_path: Path,
) -> None:
    environment = _production_environment(tmp_path)
    environment["LETS_AUTHORITY_ROLLBACK_DOMAIN"] = environment["LETS_STATE_ROLLBACK_DOMAIN"]
    environment["LETS_BACKUP_STORAGE_BOUNDARY"] = "shared-directory"
    environment.pop("LETS_AUDIT_ROLLBACK_DOMAIN")

    errors = validate.validate_environment(environment)

    assert any("independent rollback domains" in error for error in errors)
    assert any("LETS_BACKUP_STORAGE_BOUNDARY" in error for error in errors)
    assert any("LETS_AUDIT_ROLLBACK_DOMAIN" in error for error in errors)


def test_production_environment_rejects_one_filesystem_for_all_domains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _production_environment(tmp_path)
    monkeypatch.setattr(validate, "_storage_device", lambda _path: 42)

    errors = validate.validate_environment(environment)

    assert sum("distinct mounted filesystems" in error for error in errors) == 3


def test_mountinfo_parser_tracks_exact_and_nested_mounts() -> None:
    observations = validate._parse_mountinfo(
        "41 1 8:1 / /srv/lets\\040state rw - ext4 /dev/state rw\n"
        "42 41 8:2 / /srv/lets\\040state/nested rw - ext4 /dev/nested rw\n"
    )

    assert observations[0].mount_point == PurePosixPath("/srv/lets state")
    assert observations[0].has_descendant_mount is True
    assert observations[1].has_descendant_mount is False


def test_production_environment_rejects_fallback_or_remote_mounts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _production_environment(tmp_path)
    modeled_mount = validate._storage_mount

    def unsafe_mount(path: Path) -> validate.StorageMount:
        observation = modeled_mount(path)
        if path.name == "authority":
            return replace(
                observation,
                mount_point=PurePosixPath(path.parent.as_posix()),
                has_descendant_mount=True,
            )
        if path.name == "audit":
            return replace(observation, filesystem_type="nfs4")
        return observation

    monkeypatch.setattr(validate, "_storage_mount", unsafe_mount)

    errors = validate.validate_environment(environment)

    assert any("LETS_AUTHORITY_DIR must be the exact mountpoint" in error for error in errors)
    assert any(
        "LETS_AUTHORITY_DIR must not contain nested mountpoints" in error for error in errors
    )
    assert any("LETS_AUDIT_DIR uses unsupported production filesystem" in error for error in errors)


@pytest.mark.parametrize("value", ['"/safe/path"', "/safe/path # comment", "$UNSAFE/path"])
def test_environment_file_parser_rejects_ambiguous_compose_syntax(
    tmp_path: Path,
    value: str,
) -> None:
    environment = tmp_path / "production.env"
    environment.write_text(f"LETS_STATE_DIR={value}\n", encoding="utf-8")

    with pytest.raises(ValueError):
        validate.load_environment(environment)


def test_production_environment_rejects_impossible_page_reserve(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    document = json.loads(Path(environment["LETS_CONFIG_FILE"]).read_text(encoding="utf-8"))
    document["reserve_pages"] = 4097
    _rewrite_config(environment, document)

    errors = validate.validate_environment(environment)

    assert any("reserve_pages exceeds" in error for error in errors)


def test_production_environment_accounts_for_existing_wal_growth(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    database = Path(environment["LETS_STATE_DIR"]) / "warden.sqlite3"
    page_size = 4096
    with database.with_name(f"{database.name}-wal").open("wb") as stream:
        stream.truncate(32 + 5_000 * (page_size + 24))

    errors = validate.validate_environment(environment)

    assert any("LETS_STATE_CAPACITY_BYTES is below" in error for error in errors)


def test_production_environment_requires_audit_lifecycle_capacity(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    environment["LETS_AUDIT_CAPACITY_BYTES"] = "1"

    errors = validate.validate_environment(environment)

    assert any("lifecycle forecast" in error for error in errors)


def test_generic_provider_rejects_interpreter_or_mutable_signer_code(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    environment["LETS_RUNTIME_PROVIDER"] = "generic-production"
    document = json.loads(Path(environment["LETS_CONFIG_FILE"]).read_text(encoding="utf-8"))
    options = _generic_options()
    options["signer_command_json"] = '["/bin/sh","/var/lib/lets/evil.sh"]'
    document["runtime"] = {"provider": "generic-production", "options": options}
    _rewrite_config(environment, document)

    errors = validate.validate_environment(environment)

    assert any("dedicated helper" in error for error in errors)
    assert any("writable or ephemeral mounts" in error for error in errors)


def test_production_environment_rejects_linked_security_input(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    original = Path(environment["LETS_TLS_KEY_FILE"])
    linked = tmp_path / "linked-server-key.pem"
    try:
        os.link(original, linked)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")
    environment["LETS_TLS_KEY_FILE"] = str(linked.resolve())

    errors = validate.validate_environment(environment)

    assert any("must not be hard linked" in error for error in errors)


def test_production_environment_requires_mapped_immutable_trust_files(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    manifest = Path(environment["LETS_TRUST_DIR"]) / "manifest.json"
    manifest.unlink()

    errors = validate.validate_environment(environment)

    assert any("manifest.json" in error or "manifest" in error for error in errors)


def test_production_environment_rejects_symlinked_security_path(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    target = tmp_path / "operator-owned-key.pem"
    target.write_text("test-only-placeholder\n", encoding="utf-8")
    target.chmod(0o600)
    linked = tmp_path / "symlinked-server-key.pem"
    try:
        linked.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")
    environment["LETS_TLS_KEY_FILE"] = str(linked.absolute())

    errors = validate.validate_environment(environment)

    assert any("symbolic links or reparse points" in error for error in errors)


def test_runtime_image_validation_executes_the_loaded_sqlite_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.extend(command)
        return subprocess.CompletedProcess(command, 0, "3.53.2\n", "")

    monkeypatch.setattr("deploy.production.validate.subprocess.run", run)
    image = f"ghcr.io/example/lets@sha256:{'a' * 64}"

    assert validate.validate_runtime_image(image) == "3.53.2"
    assert observed[0:2] == ["docker", "run"]
    assert image in observed
    assert "--network" in observed and "none" in observed
    assert "--read-only" in observed
    assert "--pids-limit" in observed and "64" in observed
    assert "--memory" in observed and "256m" in observed
    assert "--cpus" in observed and "1.0" in observed
    assert "_require_production_sqlite" in observed[-1]

    observed.clear()
    assert (
        validate.validate_runtime_image(
            image,
            provider="generic-production",
            signer_executable="/usr/local/bin/lets-hsm-sign",
        )
        == "3.53.2"
    )
    assert observed[-2:] == ["generic-production", "/usr/local/bin/lets-hsm-sign"]
    assert "runtime provider is missing" in observed[-3]


def test_runtime_image_validation_fences_a_timed_out_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[1] == "run":
            raise subprocess.TimeoutExpired(command, 180)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("deploy.production.validate.subprocess.run", run)
    image = f"ghcr.io/example/lets@sha256:{'a' * 64}"

    with pytest.raises(ValueError, match="timed out and was fenced"):
        validate.validate_runtime_image(image)

    assert commands[1][:3] == ["docker", "rm", "--force"]
    assert commands[1][3] in commands[0]


def test_production_environment_rejects_inputs_inside_writable_domains(
    tmp_path: Path,
) -> None:
    environment = _production_environment(tmp_path)
    unsafe_key = Path(environment["LETS_STATE_DIR"]) / "runtime-writable-key.pem"
    unsafe_key.write_text("unsafe\n", encoding="utf-8")
    unsafe_key.chmod(0o600)
    environment["LETS_TLS_KEY_FILE"] = str(unsafe_key.resolve())

    errors = validate.validate_environment(environment)

    assert any(
        "LETS_TLS_KEY_FILE must be outside runtime-writable LETS_STATE_DIR" in error
        for error in errors
    )


def test_generic_provider_paths_are_bound_to_separate_production_mounts(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    environment["LETS_RUNTIME_PROVIDER"] = "generic-production"
    config = Path(environment["LETS_CONFIG_FILE"])
    document = json.loads(config.read_text(encoding="utf-8"))
    document["runtime"] = {"provider": "generic-production", "options": _generic_options()}
    config.chmod(0o600)
    config.write_text(json.dumps(document), encoding="utf-8")
    config.chmod(0o444)
    assert validate.validate_environment(environment) == ()

    document["runtime"]["options"].update(
        {
            "authority_anchor_path": "/var/lib/lets/anchor.json",
            "audit_archive_path": "/var/lib/lets/audit.sqlite3",
            "identity_keys_file": "/etc/lets/trust/../mutable/identity-keys.json",
            "signer_command_json": '["/run/operator-controlled/sign"]',
        }
    )
    config.chmod(0o600)
    config.write_text(json.dumps(document), encoding="utf-8")
    config.chmod(0o444)

    errors = validate.validate_environment(environment)

    for field in (
        "authority_anchor_path",
        "audit_archive_path",
        "identity_keys_file",
        "signer executable",
    ):
        assert any(field in error for error in errors)


def test_generic_provider_peer_timeout_floor_matches_runtime_admission(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    environment["LETS_RUNTIME_PROVIDER"] = "generic-production"
    document = json.loads(Path(environment["LETS_CONFIG_FILE"]).read_text(encoding="utf-8"))
    document["peer_endpoints"] = {"warden-b": "https://warden-b.example"}
    document["runtime"] = {"provider": "generic-production", "options": _generic_options()}
    _rewrite_config(environment, document)

    environment["LETS_PEER_REQUEST_TIMEOUT_SECONDS"] = "54"
    errors = validate.validate_environment(environment)
    assert any("provider safety bound (55 seconds)" in error for error in errors)

    for admitted in ("55", "60"):
        environment["LETS_PEER_REQUEST_TIMEOUT_SECONDS"] = admitted
        assert validate.validate_environment(environment) == ()

    options = document["runtime"]["options"]
    assert isinstance(options, dict)
    options.update({"authority_timeout_s": "4", "signer_timeout_s": "4"})
    _rewrite_config(environment, document)
    environment["LETS_PEER_REQUEST_TIMEOUT_SECONDS"] = "46"
    errors = validate.validate_environment(environment)
    assert any("provider safety bound (47 seconds)" in error for error in errors)
    environment["LETS_PEER_REQUEST_TIMEOUT_SECONDS"] = "47"
    assert validate.validate_environment(environment) == ()

    for invalid in ("NaN", "Infinity", "60.5"):
        environment["LETS_PEER_REQUEST_TIMEOUT_SECONDS"] = invalid
        errors = validate.validate_environment(environment)
        assert errors
        assert any("must be an integer" in error for error in errors)


def test_production_compose_renders_when_docker_compose_is_available(tmp_path: Path) -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is not installed")
    version = subprocess.run(
        [docker, "compose", "version"],
        check=False,
        capture_output=True,
        text=True,
    )
    if version.returncode != 0:
        pytest.skip("Docker Compose plugin is not available")

    environment = os.environ.copy()
    environment.update(_production_environment(tmp_path))
    rendered = subprocess.run(
        [
            docker,
            "compose",
            "-f",
            str(PRODUCTION / "compose.yaml"),
            "config",
            "--format",
            "json",
        ],
        cwd=REPOSITORY,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    document = json.loads(rendered.stdout)
    warden = document["services"]["warden"]
    assert warden["image"] == environment["LETS_IMAGE"]
    assert warden["user"] == "10001:10001"
    assert warden["read_only"] is True
    assert warden["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in warden["security_opt"]
    assert warden["healthcheck"]["start_period"] == "10m0s"
    assert "--production" in warden["command"]
    assert "--allow-insecure-http" not in warden["command"]
    assert len(warden["secrets"]) == 6
    targets = {mount["target"] for mount in warden["volumes"]}
    assert targets == {
        "/var/lib/lets",
        "/var/lib/lets/config.json",
        "/var/lib/lets-authority",
        "/var/lib/lets-audit",
        "/etc/lets/trust",
    }

    for compose_name, service_name, expected_targets in (
        (
            "maintenance-compose.yaml",
            "maintenance",
            {
                "/var/lib/lets",
                "/var/lib/lets/config.json",
                "/var/lib/lets-authority",
                "/var/lib/lets-audit",
                "/var/lib/lets-backup",
                "/etc/lets/trust",
            },
        ),
        (
            "provision-compose.yaml",
            "provision",
            {
                "/var/lib/lets",
                "/var/lib/lets-authority",
                "/var/lib/lets-audit",
                "/etc/lets/trust",
            },
        ),
    ):
        rendered = subprocess.run(
            [
                docker,
                "compose",
                "-f",
                str(PRODUCTION / compose_name),
                "config",
                "--format",
                "json",
            ],
            cwd=REPOSITORY,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        service = json.loads(rendered.stdout)["services"][service_name]
        assert service["network_mode"] == "none"
        assert service["user"] == "10001:10001"
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert {mount["target"] for mount in service["volumes"]} == expected_targets


def test_stage_config_moves_runtime_configuration_outside_writable_state(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    protected = tmp_path / "protected"
    state.mkdir()
    protected.mkdir()
    (state / "warden.sqlite3").write_bytes(b"test-database")
    (state / "peer-replay.sqlite3").write_bytes(b"test-replay-database")
    source = state / "config.json"
    source.write_text(
        json.dumps(
            {
                "allow_insecure_manifest": False,
                "bootstrap_identities": [],
                "database": "warden.sqlite3",
                "manifest": "/etc/lets/trust/manifest.json",
                "manifest_digest": "sha256:" + "a" * 64,
                "operator_trust": {},
                "replay_database": "peer-replay.sqlite3",
                "runtime": {
                    "provider": "generic-production",
                    "options": _generic_options(),
                },
                "version": 1,
                "warden_id": "warden-a",
                "tenant_id": "tenant-a",
                "envelope_id": "envelope-a",
            }
        ),
        encoding="utf-8",
    )
    destination = protected / "config.json"

    staged = stage_config.stage_config(source.resolve(), destination.resolve())

    document = json.loads(staged.read_text(encoding="utf-8"))
    assert document["database"] == "/var/lib/lets/warden.sqlite3"
    assert document["replay_database"] == "/var/lib/lets/peer-replay.sqlite3"
    if os.name != "nt":
        assert staged.stat().st_mode & 0o222 == 0
    with pytest.raises(ValueError, match="already exists"):
        stage_config.stage_config(source.resolve(), destination.resolve())


def test_healthcheck_requires_exact_ready_document() -> None:
    assert healthcheck.build_request("warden.example").startswith(b"GET /health/ready HTTP/1.1")
    assert b"Host: [2001:db8::1]\r\n" in healthcheck.build_request("2001:db8::1")
    assert healthcheck.is_ready_response(
        b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"status":"ready"}'
    )
    assert not healthcheck.is_ready_response(
        b'HTTP/1.1 503 Service Unavailable\r\n\r\n{"status":"ready"}'
    )
    assert not healthcheck.is_ready_response(b'HTTP/1.1 200 OK\r\n\r\n{"status":"live"}')


@pytest.mark.parametrize("workflow", ["security.yml", "release.yml"])
def test_supply_chain_workflow_uses_only_pinned_actions(workflow: str) -> None:
    text = (REPOSITORY / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    uses = [line for line in text.splitlines() if "uses:" in line]

    assert uses
    assert all(PINNED_ACTION.fullmatch(line) for line in uses)
    assert "runs-on: ubuntu-latest" not in text
    assert "continue-on-error" not in text


def test_security_workflow_has_fatal_scans_sboms_and_package_smoke() -> None:
    workflow = (REPOSITORY / ".github/workflows/security.yml").read_text(encoding="utf-8")

    for required in (
        "bandit==1.9.4",
        "pip-audit==2.10.1",
        "cyclonedx-bom==7.3.1",
        "twine==7.0.0",
        "syft-version: v1.50.0",
        "version: v0.73.0",
        "exit-code: 1",
        "--read-only",
        "--cap-drop ALL",
        ".github/tools/actionlint_1.7.12_linux_amd64.tar.gz",
        "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
        "moby/buildkit:buildx-stable-1@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec",
        "_require_production_sqlite",
    ):
        assert required in workflow
    assert "rhysd/actionlint@sha256:" not in workflow
    assert "docker run --rm --volume" not in workflow
    assert 'timeout --signal=KILL 30s "$RUNNER_TEMP/actionlint" -shellcheck= -pyflakes=' in workflow
    assert workflow.count("--constraint requirements-audit.txt") == 2

    actionlint_archive = REPOSITORY / ".github/tools/actionlint_1.7.12_linux_amd64.tar.gz"
    assert actionlint_archive.is_file()
    assert (
        hashlib.sha256(actionlint_archive.read_bytes()).hexdigest()
        == "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
    )


def test_release_soak_verifier_full_heredoc_smokes_with_empty_globals(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    script = _release_soak_verifier_script()
    evidence = tmp_path / "results" / "generated" / "production-profile-soak.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("EXPECTED_IMAGE", "ghcr.io/example/lets@sha256:" + "1" * 64)
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)

    with pytest.raises(SystemExit, match="soak evidence payload digest is invalid"):
        exec(compile(script, "release-soak-verifier", "exec"), {})


def test_release_soak_verifier_rejects_oversized_evidence_before_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    script = _release_soak_verifier_script()
    evidence = tmp_path / "results" / "generated" / "production-profile-soak.json"
    evidence.parent.mkdir(parents=True)
    with evidence.open("wb") as stream:
        stream.seek(80 * 1024 * 1024)
        stream.write(b"\0")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("EXPECTED_IMAGE", "ghcr.io/example/lets@sha256:" + "1" * 64)
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)

    with pytest.raises(SystemExit, match="exceeds the 80 MiB host retention bound"):
        exec(compile(script, "release-soak-verifier", "exec"), {})


def test_release_soak_verifier_reconstructs_exact_two_stage_restarts() -> None:
    soak_tests = runpy.run_path(str(REPOSITORY / "tests" / "unit" / "test_production_soak.py"))
    run_soak = runpy.run_path(str(PRODUCTION / "run_soak.py"))
    script = _release_soak_verifier_script()
    block = script.split("# BEGIN RAW RESTART EVIDENCE VERIFIER", maxsplit=1)[1].split(
        "# END RAW RESTART EVIDENCE VERIFIER", maxsplit=1
    )[0]
    nodes = ("warden-a", "warden-b", "warden-c")
    restarts: list[dict[str, Any]] = []
    for episode, service in enumerate(nodes):
        restart = soak_tests["_restart_record"](service=service, episode=episode)
        host_validated = restart["authority_fence"]["host_validated_monotonic_seconds"]
        host_armed = restart["workload_coordination"]["armed"][
            "host_armed_started_monotonic_seconds"
        ]
        restart.update(
            {
                "completed_at_seconds": 110.0 + 20.0 * episode,
                "elapsed_seconds": 103.0 + 20.0 * episode,
                "resource_checkpoint": {},
            }
        )
        read = {
            "completed_monotonic_seconds": host_validated,
            "error_type": None,
            "outcome": "valid",
            "returncode": 0,
        }
        restart_id = restart["workload_coordination"]["armed"]["marker"]["restart_id"]
        restart["authority_fence_attempt"] = {
            "attempts": [
                {
                    "exec_completed_monotonic_seconds": host_validated - 0.2,
                    "exec_error_type": None,
                    "exec_returncode": 0,
                    "exec_started_monotonic_seconds": host_validated - 0.5,
                    "exec_timeout_seconds": 95.0,
                    "first_read": copy.deepcopy(read),
                    "last_read": copy.deepcopy(read),
                    "ordinal": 1,
                    "output_path": (f"/scenario/authority-fence-{episode:06d}-attempt-1.json"),
                    "read_count": 1,
                }
            ],
            "completed_monotonic_seconds": host_validated,
            "deadline_monotonic_seconds": host_armed + 110.0,
            "episode": episode,
            "expected_lifetime_id": restart["authority_fence"]["prior_authority_anchor"][
                "lifetime_id"
            ],
            "post_spacing_seconds": 26.75,
            "resolved": True,
            "resolved_attempt": 1,
            "restart_id": restart_id,
            "service": service,
            "started_monotonic_seconds": host_validated - 0.8,
            "status": "resolved",
        }
        restarts.append(restart)
    intervals = []
    for restart in restarts:
        interval = soak_tests["_restart_quiescence_interval"](restart)
        interval["measurement_clipped_start_elapsed_seconds"] = interval["observed_elapsed_seconds"]
        interval["measurement_clipped_end_elapsed_seconds"] = interval["resumed_elapsed_seconds"]
        intervals.append(interval)
    metrics = run_soak["evaluate_restart_evidence"](
        restarts,
        measurement_window_seconds=120.0,
        restart_quiescence_intervals=copy.deepcopy(intervals),
        workload_started_monotonic=100.0,
    )
    finite_number = run_soak["_finite_number"]

    def verify(
        raw_restarts: list[dict[str, Any]],
        raw_intervals: list[dict[str, Any]],
        claimed_metrics: dict[str, Any],
        *,
        interval_count: object = 3,
    ) -> dict[str, Any]:
        namespace: dict[str, Any] = {
            "canonical_digest": run_soak["_canonical_digest"],
            "chaos_completed": 1_200.0,
            "chaos_started": 900.0,
            "close_number": lambda left, right: (
                finite_number(left)
                and finite_number(right)
                and math.isclose(float(left), float(right), rel_tol=0.0, abs_tol=0.002)
            ),
            "expected_nodes": set(nodes),
            "failures": [],
            "finite_number": finite_number,
            "configured_duration": 120.0,
            "math": math,
            "re": re,
            "restarts": raw_restarts,
            "workload": {
                "restart_quiescence_interval_count": interval_count,
                "restart_quiescence_intervals": raw_intervals,
            },
            "workload_identity_valid": True,
            "workload_metrics": {"restart_evidence": claimed_metrics},
            "workload_start": {"started_monotonic_seconds": 100.0},
        }
        exec(compile(block, "release-raw-restart-verifier", "exec"), namespace)
        return namespace

    baseline = verify(copy.deepcopy(restarts), copy.deepcopy(intervals), copy.deepcopy(metrics))
    assert baseline["raw_restart_valid"] is True
    assert baseline["restart_bindings"] == metrics["bindings"]
    assert baseline["restart_windows"] == metrics["windows_by_node"]
    assert baseline["failures"] == []

    terminal_namespace = _release_soak_verifier_namespace()
    first_restart = restarts[0]
    first_ack = first_restart["workload_coordination"]["armed"]["acknowledgement"]
    compact_prior = copy.deepcopy(first_ack["prior_observation"])
    first_terminal = first_restart["authority_fence"]["result"]["terminal"]
    assert terminal_namespace["valid_terminal_fence"](
        first_terminal,
        node="warden-a",
        restart_id=first_ack["restart_id"],
        expected_lifetime=first_ack["prior_authority_anchor"]["lifetime_id"],
        prior_authority=first_ack["prior_authority_anchor"],
        prior_observation=compact_prior,
        full_audit_verification=False,
    )
    compact_prior["lifetime_id"] = "f" * 32
    assert not terminal_namespace["valid_terminal_fence"](
        first_terminal,
        node="warden-a",
        restart_id=first_ack["restart_id"],
        expected_lifetime=first_ack["prior_authority_anchor"]["lifetime_id"],
        prior_authority=first_ack["prior_authority_anchor"],
        prior_observation=compact_prior,
        full_audit_verification=False,
    )

    def reseal_target_binding(restart: dict[str, Any]) -> None:
        target_identity = {
            "container_id": restart["prior_container_id"],
            "host_pid": restart["prior_pid"],
            "oom_killed": False,
            "restart_count": restart["restart_counts"]["prior"],
            "state": {
                "OOMKilled": False,
                "Pid": restart["prior_pid"],
                "Status": "running",
            },
            "status": "running",
        }
        acknowledgement = restart["workload_coordination"]["armed"]["acknowledgement"]
        acknowledgement["target_identity_sha256"] = run_soak["_canonical_digest"](target_identity)
        acknowledgement_payload = dict(acknowledgement)
        acknowledgement_payload.pop("coordination_payload_sha256")
        acknowledgement["coordination_payload_sha256"] = run_soak["_canonical_digest"](
            acknowledgement_payload
        )
        recovery = restart["workload_coordination"]["completed"]["recovery_acknowledgement"]
        for key, value in acknowledgement.items():
            if key not in {"coordination_payload_sha256", "coordination_revision"}:
                recovery[key] = copy.deepcopy(value)
        recovery_payload = dict(recovery)
        recovery_payload.pop("coordination_payload_sha256")
        recovery["coordination_payload_sha256"] = run_soak["_canonical_digest"](recovery_payload)

    forged_cases: list[
        tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], object]
    ] = []
    for mutation in range(13):
        forged_restarts = copy.deepcopy(restarts)
        forged_intervals = copy.deepcopy(intervals)
        forged_metrics = copy.deepcopy(metrics)
        interval_count: object = 3
        if mutation == 0:
            restart_id = next(iter(forged_metrics["bindings"]))
            forged_metrics["bindings"][restart_id]["start_elapsed_seconds"] += 2.0
        elif mutation == 1:
            restart_id = next(iter(forged_metrics["bindings"]))
            forged_metrics["bindings"][restart_id].pop("prior_authority_anchor")
        elif mutation == 2:
            forged_metrics["binding_count"] = 3.0
        elif mutation == 3:
            interval_count = 3.0
        elif mutation == 4:
            forged_restarts[0]["planned_exit_code"] = 137.0
        elif mutation == 5:
            forged_restarts[0]["authority_fence_attempt"]["attempts"][0]["last_read"][
                "returncode"
            ] = True
        elif mutation == 6:
            forged_restarts[0]["prior_container_id"] = "a" * 12
            forged_restarts[0]["new_container_id"] = "b" * 12
            forged_restarts[0]["authority_fence"]["host_container_id"] = "a" * 12
            reseal_target_binding(forged_restarts[0])
        elif mutation == 7:
            forged_restarts[0]["prior_pid"] = 2**80
            forged_restarts[0]["new_pid"] = 2**80 + 1
            forged_restarts[0]["authority_fence"]["host_pid"] = 2**80
            reseal_target_binding(forged_restarts[0])
        elif mutation == 8:
            forged_restarts[0]["workload_coordination"]["quiescence"].pop(
                "resume_requested_monotonic_seconds"
            )
        elif mutation == 9:
            forged_restarts[0]["workload_coordination"]["quiescence"][
                "resume_requested_monotonic_seconds"
            ] += 0.001
        elif mutation == 10:
            forged_restarts[0]["workload_coordination"]["quiescence"]["unexpected"] = True
        elif mutation == 11:
            forged_intervals[0]["measurement_clipped_duration_seconds"] += 1.0
        else:
            forged_intervals[0]["observed_elapsed_seconds"] = -1.0
        forged_cases.append((forged_restarts, forged_intervals, forged_metrics, interval_count))

    for forged_restarts, forged_intervals, forged_metrics, interval_count in forged_cases:
        rejected = verify(
            forged_restarts,
            forged_intervals,
            forged_metrics,
            interval_count=interval_count,
        )
        assert rejected["raw_restart_valid"] is False
        assert rejected["failures"] == ["soak restart cadence exclusions are not raw-bound"]


def test_release_soak_verifier_reconstructs_combined_pause_budget() -> None:
    soak_tests = runpy.run_path(str(REPOSITORY / "tests" / "unit" / "test_production_soak.py"))
    run_soak = runpy.run_path(str(PRODUCTION / "run_soak.py"))
    script = _release_soak_verifier_script()
    block = script.split("# END RAW RESTART EVIDENCE VERIFIER", maxsplit=1)[1].split(
        'transfer_every = configuration.get("transfer_every_cycles")',
        maxsplit=1,
    )[0]
    configuration = soak_tests["_configuration"]()
    workload = soak_tests["_valid_workload_result"](configuration)
    partitions = soak_tests["_pause_binding"](workload, configuration=configuration)
    restart = soak_tests["_restart_record"](service="warden-b", episode=1)
    restart_interval = soak_tests["_restart_quiescence_interval"](restart)
    restart_seconds = restart_interval["measurement_clipped_duration_seconds"]
    workload["restart_quiescence_interval_count"] = 1
    workload["restart_quiescence_intervals"] = [restart_interval]
    workload["paused_workload_seconds"] += restart_seconds
    workload["active_workload_seconds"] -= restart_seconds
    restart_evidence = {
        "passed": True,
        "workload_quiesced_seconds": restart_seconds,
    }
    pause_metrics = run_soak["evaluate_pause_evidence"](
        workload,
        configuration=configuration,
        partitions=partitions,
        restart_evidence=restart_evidence,
        workload_start=soak_tests["_workload_start"](workload, configuration),
    )
    assert pause_metrics["passed"] is True

    def verify(
        raw_workload: dict[str, Any],
        raw_partitions: list[dict[str, Any]],
        raw_pause_metrics: dict[str, Any],
        raw_restart_intervals: list[dict[str, Any]],
    ) -> dict[str, Any]:
        finite_number = run_soak["_finite_number"]
        namespace: dict[str, Any] = {
            "chaos_completed": 1_200.0,
            "chaos_started": 900.0,
            "close_number": lambda left, right: (
                finite_number(left)
                and finite_number(right)
                and math.isclose(float(left), float(right), rel_tol=0.0, abs_tol=0.002)
            ),
            "configuration": {"duration_seconds": configuration.duration_seconds},
            "configured_duration": configuration.duration_seconds,
            "failures": [],
            "finite_number": finite_number,
            "math": math,
            "partitions": raw_partitions,
            "raw_restart_valid": True,
            "restart_quiesced_seconds": restart_seconds,
            "restart_quiescence_intervals": raw_restart_intervals,
            "workload": raw_workload,
            "workload_identity_valid": True,
            "workload_metrics": {"pause_evidence": raw_pause_metrics},
            "workload_start": soak_tests["_workload_start"](raw_workload, configuration),
        }
        exec(compile(block, "release-raw-pause-verifier", "exec"), namespace)
        return namespace

    baseline = verify(
        copy.deepcopy(workload),
        copy.deepcopy(partitions),
        copy.deepcopy(pause_metrics),
        [copy.deepcopy(restart_interval)],
    )
    assert baseline["raw_pause_valid"] is True
    assert baseline["failures"] == []

    tolerated = copy.deepcopy(pause_metrics)
    tolerated["bindings"][0]["workload_clipped_pause_seconds"] += 0.001
    assert (
        verify(
            copy.deepcopy(workload),
            copy.deepcopy(partitions),
            tolerated,
            [copy.deepcopy(restart_interval)],
        )["raw_pause_valid"]
        is True
    )

    for mutation in ("missing_resume", "divergent_resume", "forged_binding", "overlap"):
        forged_workload = copy.deepcopy(workload)
        forged_partitions = copy.deepcopy(partitions)
        forged_metrics = copy.deepcopy(pause_metrics)
        forged_restart_intervals = [copy.deepcopy(restart_interval)]
        if mutation == "missing_resume":
            forged_partitions[0]["workload_coordination"].pop("resume_requested_monotonic_seconds")
        elif mutation == "divergent_resume":
            forged_partitions[0]["workload_coordination"]["resume_requested_monotonic_seconds"] += (
                0.001
            )
        elif mutation == "forged_binding":
            forged_metrics["bindings"][0]["workload_clipped_pause_seconds"] += 0.01
        else:
            forged_restart_intervals[0]["observed_monotonic_seconds"] = 110.0
            forged_restart_intervals[0]["resumed_monotonic_seconds"] = 130.0
        rejected = verify(
            forged_workload,
            forged_partitions,
            forged_metrics,
            forged_restart_intervals,
        )
        assert rejected["raw_pause_valid"] is False
        assert rejected["failures"] == [
            "soak pause intervals or active-time denominator are not raw-bound"
        ]


def test_release_soak_verifier_requires_exact_planned_fence_wrapper() -> None:
    authority_block = (
        _release_soak_verifier_script()
        .split("# BEGIN RAW AUTHORITY EVIDENCE VERIFIER", maxsplit=1)[1]
        .split("# END RAW AUTHORITY EVIDENCE VERIFIER", maxsplit=1)[0]
    )
    tree = ast.parse(authority_block)
    wrapper_fields: set[str] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == "fence_wrapper_fields"
            for target in node.targets
        ):
            wrapper_fields = ast.literal_eval(node.value)
            break

    assert wrapper_fields == {
        "host_container_id",
        "host_exec_attempts",
        "host_pid",
        "host_validated_monotonic_seconds",
        "prior_authority_anchor",
        "result",
    }


def test_release_soak_verifier_accepts_armed_health_attempt_inside_restart_window() -> None:
    soak_tests = runpy.run_path(str(REPOSITORY / "tests" / "unit" / "test_production_soak.py"))
    run_soak = runpy.run_path(str(PRODUCTION / "run_soak.py"))
    restart = soak_tests["_restart_record"]()
    restart_evidence = soak_tests["_evaluate_restart_records"]([restart])
    samples = soak_tests["_timed_health_samples"](
        duration_seconds=30.0,
        interval_seconds=10.0,
    )
    armed_marker = restart["workload_coordination"]["armed"]["marker"]
    samples[1]["completed_elapsed_seconds"] = 11.3
    samples[1]["nodes"]["warden-a"] = {
        "observation": {
            "completed_elapsed_seconds": 11.2,
            "metrics_observed_elapsed_seconds": None,
            "request_count": 0,
            "request_path": "/v1/metrics",
            "request_retries": 0,
            "retry_errors": {"first_error": None, "last_error": None},
            "started_elapsed_seconds": 11.0,
        },
        "planned_unavailable": armed_marker,
    }
    samples[1]["planned_unavailable_nodes"] = ["warden-a"]
    cadence = run_soak["evaluate_health_cadence"](
        samples,
        duration_seconds=30.0,
        interval_seconds=10.0,
        restart_evidence=restart_evidence,
    )
    assert cadence["passed"] is True
    assert (
        restart_evidence["bindings"][armed_marker["restart_id"]]["start_elapsed_seconds"]
        < samples[1]["nodes"]["warden-a"]["observation"]["started_elapsed_seconds"]
    )

    monitor = {
        "actual_sample_count": len(samples),
        "audit_error_budget_instances": 1,
        "deadline_miss_count": 0,
        "expected_sample_count": len(samples),
        "interval_seconds": 10.0,
        "joined": True,
        "request_retry_count": 0,
        "retained_sample_count": len(samples),
        "samples_truncated": 0,
        "schedule": "absolute_monotonic",
        "status": "passed",
    }
    workload = {
        "duration_seconds": 30.0,
        "health_monitor": monitor,
        "health_sample_count": len(samples),
        "health_samples": samples,
    }
    workflow = _release_soak_verifier_script()
    health_block = (
        "health_samples_value = workload.get"
        + workflow.split(
            "health_samples_value = workload.get",
            maxsplit=1,
        )[1].split("raw_error_evidence_valid =", maxsplit=1)[0]
    )
    finite_number = run_soak["_finite_number"]
    namespace: dict[str, Any] = {
        "close_number": lambda left, right, tolerance=0.002: (
            finite_number(left)
            and finite_number(right)
            and math.isclose(
                float(left),
                float(right),
                rel_tol=0.0,
                abs_tol=tolerance,
            )
        ),
        "configuration": {"health_interval_seconds": 10.0},
        "expected_nodes": {"warden-a", "warden-b", "warden-c"},
        "failures": [],
        "finite_number": finite_number,
        "math": math,
        "raw_restart_valid": True,
        "restart_bindings": restart_evidence["bindings"],
        "restart_windows": restart_evidence["windows_by_node"],
        "workload": workload,
        "workload_metrics": {
            "actual_health_request_retries": 0,
            "actual_health_samples": len(samples),
            "health_cadence": cadence,
            "raw_health_request_retries": 0,
            "required_health_samples": len(samples),
        },
    }
    exec(compile(health_block, "release-raw-health-verifier", "exec"), namespace)

    assert namespace["raw_health_valid"] is True
    assert namespace["failures"] == []


def test_release_soak_verifier_accepts_exact_observation_and_terminal_proofs() -> None:
    namespace = _release_soak_verifier_namespace()
    snapshot = _release_observation(namespace)
    document = _release_observation_document(snapshot)

    assert namespace["valid_observation_snapshot"](snapshot, node="warden-a") is True
    assert namespace["valid_observation_document"](document, node="warden-a") is True
    for full in (False, True):
        terminal = _release_terminal_fence(namespace, snapshot, full=full)
        assert (
            namespace["valid_terminal_fence"](
                terminal,
                node="warden-a",
                restart_id="restart-0",
                expected_lifetime=snapshot["lifetime_id"],
                prior_authority=snapshot["authority_anchor"],
                prior_observation=snapshot,
                full_audit_verification=full,
            )
            is True
        )
    compact_prior = {
        "audit_verification": {
            "last_full_verification_at_ns": snapshot["audit_verification"][
                "last_full_verification_at_ns"
            ]
        },
        "authority_checkpoint": snapshot["authority_checkpoint"],
        "generation": snapshot["generation"],
        "lifetime_id": snapshot["lifetime_id"],
        "sqlite_schema_sha256": snapshot["sqlite_schema_sha256"],
    }
    tail = _release_terminal_fence(namespace, snapshot, full=False)
    assert (
        namespace["valid_terminal_fence"](
            tail,
            node="warden-a",
            restart_id="restart-0",
            expected_lifetime=snapshot["lifetime_id"],
            prior_authority=snapshot["authority_anchor"],
            prior_observation=compact_prior,
            full_audit_verification=False,
        )
        is True
    )
    assert (
        namespace["valid_terminal_fence"](
            tail,
            node="warden-a",
            restart_id="restart-0",
            expected_lifetime=snapshot["lifetime_id"],
            prior_authority=snapshot["authority_anchor"],
            prior_observation=compact_prior,
            full_audit_verification=True,
        )
        is False
    )


@pytest.mark.parametrize(
    ("mutation", "reseal"),
    (
        (lambda value: value.__setitem__("schema", "wrong"), True),
        (lambda value: value.__setitem__("revision", True), True),
        (lambda value: value.__setitem__("revision", 1.0), True),
        (lambda value: value.__setitem__("revision", 1 << 80), True),
        (lambda value: value.pop("runtime"), True),
        (lambda value: value.__setitem__("extra", None), True),
        (lambda value: value.__setitem__("snapshot_id", "sha256:" + "0" * 64), False),
        (lambda value: value.__setitem__("fresh", False), False),
        (lambda value: value.__setitem__("age_ns", 15_000_000_000), False),
        (
            lambda value: value["authority_checkpoint"].__setitem__("state_revision", 99),
            True,
        ),
        (
            lambda value: value["audit_verification"].__setitem__(
                "schema_definition_sha256", "sha256:" + "2" * 64
            ),
            True,
        ),
        (
            lambda value: value["runtime"].__setitem__("reason", "x" * (21 * 1024)),
            True,
        ),
        (lambda value: value.__setitem__("runtime", {"bogus": "accepted"}), True),
        (
            lambda value: value.__setitem__("storage_capacity", {"bogus": "accepted"}),
            True,
        ),
        (lambda value: value.__setitem__("leases", {"bogus": "accepted"}), True),
        (lambda value: value.__setitem__("receipts", {"bogus": "accepted"}), True),
        (lambda value: value.__setitem__("transfers", {"bogus": "accepted"}), True),
        (lambda value: value.__setitem__("audit_outbox", {"bogus": "accepted"}), True),
        (
            lambda value: value.__setitem__("peer_dispatcher", {"bogus": "accepted"}),
            True,
        ),
        (
            lambda value: value.__setitem__("audit_exporter", {"bogus": "accepted"}),
            True,
        ),
        (_forge_oversized_release_resources, True),
        (
            lambda value: value["storage_capacity"].__setitem__(
                "database_bytes", value["storage_capacity"]["database_bytes"] + 1
            ),
            True,
        ),
        (
            lambda value: value["audit_verification"].__setitem__("lag", False),
            True,
        ),
    ),
)
def test_release_soak_verifier_rejects_observation_mutations(
    mutation: Callable[[dict[str, Any]], object],
    reseal: bool,
) -> None:
    namespace = _release_soak_verifier_namespace()
    snapshot = _release_observation(namespace)
    mutation(snapshot)
    if reseal:
        _reseal_release_observation(namespace, snapshot)

    assert namespace["valid_observation_snapshot"](snapshot, node="warden-a") is False


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value["observation"].__setitem__("request_count", True),
        lambda value: value["observation"].__setitem__("request_count", 2),
        lambda value: value["observation"].__setitem__("request_path", "/v1/ready"),
        lambda value: value["observation"].pop("retry_errors"),
        lambda value: value.__setitem__("extra", None),
        lambda value: value.__setitem__("observation_snapshot_id", "sha256:" + "0" * 64),
    ),
)
def test_release_soak_verifier_rejects_sampler_or_summary_mutations(
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    namespace = _release_soak_verifier_namespace()
    document = _release_observation_document(_release_observation(namespace))
    mutation(document)

    assert namespace["valid_observation_document"](document, node="warden-a") is False


def test_release_soak_verifier_requires_exact_producer_audit_exporter_projection() -> None:
    namespace = _release_soak_verifier_namespace()
    snapshot = _release_observation(namespace)
    document = _release_observation_document(snapshot)

    assert namespace["valid_observation_document"](document, node="warden-a") is True

    raw_exporter = copy.deepcopy(snapshot["audit_exporter"])
    document["audit_exporter"] = raw_exporter
    assert namespace["valid_observation_document"](document, node="warden-a") is False

    document = _release_observation_document(snapshot)
    document["audit_exporter"]["catching_up"] = True
    assert namespace["valid_observation_document"](document, node="warden-a") is False


def test_release_soak_verifier_accepts_only_consistent_bounded_audit_catchup() -> None:
    namespace = _release_soak_verifier_namespace()
    snapshot = _release_observation(namespace)
    catchup = {
        "archive_reconciled": False,
        "healthy": False,
        "last_error": None,
        "last_success_ns": 50,
        "oldest_pending_age_s": 2.0,
        "pending": 5,
        "stalled_for_s": 0.1,
    }
    snapshot["audit_exporter"].update(catchup)
    snapshot["audit_outbox"] = {
        "oldest_unpublished_age_ns": 2_000_000_000,
        "unpublished_count": 5,
    }
    snapshot["ready"] = False
    _reseal_release_observation(namespace, snapshot)

    assert namespace["valid_audit_exporter_status"](snapshot["audit_exporter"]) is True
    assert namespace["valid_observation_snapshot"](snapshot, node="warden-a") is True
    assert (
        namespace["valid_observation_document"](
            _release_observation_document(snapshot),
            node="warden-a",
        )
        is True
    )

    inconsistent_clean = copy.deepcopy(snapshot["audit_exporter"])
    inconsistent_clean.update({"archive_reconciled": True, "healthy": False})
    assert namespace["valid_audit_exporter_status"](inconsistent_clean) is False

    inconsistent_fault = copy.deepcopy(snapshot["audit_exporter"])
    inconsistent_fault.update(
        {
            "archive_reconciled": True,
            "healthy": False,
            "last_error": "StorageError:sqlite_busy",
        }
    )
    assert namespace["valid_audit_exporter_status"](inconsistent_fault) is False


def test_release_soak_verifier_accepts_exact_transient_peer_partition() -> None:
    namespace = _release_soak_verifier_namespace()
    snapshot = _release_observation(namespace)
    retry = {
        "attempt_count": 7,
        "exception_class": "ConnectError",
        "next_retry_delay_seconds": 15.486,
        "record_kind": "transfer",
        "target_warden": "warden-b",
    }
    transient = {
        "durable_retry": retry,
        "failed_records": 1,
        "healthy": False,
        "last_error": "ConnectError",
        "pending_records": 1,
        "prepared_transfers": 1,
    }
    snapshot["peer_dispatcher"].update(transient)
    snapshot["ready"] = False
    _reseal_release_observation(namespace, snapshot)

    assert (
        namespace["valid_peer_status"](
            snapshot["peer_dispatcher"],
            node="warden-a",
            published_at_ns=snapshot["published_at_ns"],
        )
        is True
    )
    assert namespace["valid_observation_snapshot"](snapshot, node="warden-a") is True

    for mutation in (
        lambda value: value.__setitem__("durable_retry", None),
        lambda value: value.__setitem__("healthy", True),
        lambda value: value.__setitem__("last_error", "ConnectError: secret"),
        lambda value: value.__setitem__("pending_records", 0),
        lambda value: value["durable_retry"].__setitem__("attempt_count", 0),
        lambda value: value["durable_retry"].__setitem__("next_retry_delay_seconds", 30.001),
        lambda value: value["durable_retry"].__setitem__("record_kind", "unknown"),
        lambda value: value["durable_retry"].__setitem__("target_warden", "warden-a"),
    ):
        forged = copy.deepcopy(snapshot)
        mutation(forged["peer_dispatcher"])
        _reseal_release_observation(namespace, forged)
        assert namespace["valid_observation_snapshot"](forged, node="warden-a") is False


def test_release_soak_verifier_accepts_volatile_peer_error_with_cleared_durable_retry() -> None:
    namespace = _release_soak_verifier_namespace()
    snapshot = _release_observation(namespace)
    transient = {
        "durable_retry": None,
        "failed_records": 0,
        "healthy": False,
        "last_error": "ConnectError",
        "pending_records": 1,
        "prepared_transfers": 1,
    }
    snapshot["peer_dispatcher"].update(transient)
    snapshot["ready"] = False
    _reseal_release_observation(namespace, snapshot)

    assert (
        namespace["valid_peer_status"](
            snapshot["peer_dispatcher"],
            node="warden-a",
            published_at_ns=snapshot["published_at_ns"],
        )
        is True
    )
    assert namespace["valid_observation_snapshot"](snapshot, node="warden-a") is True

    retry = {
        "attempt_count": 7,
        "exception_class": "ConnectError",
        "next_retry_delay_seconds": 15.486,
        "record_kind": "transfer",
        "target_warden": "warden-b",
    }
    for mutation in (
        lambda value: value.__setitem__("failed_records", 1),
        lambda value: value.__setitem__("durable_retry", copy.deepcopy(retry)),
        lambda value: value.__setitem__("healthy", True),
        lambda value: value.__setitem__("last_error", "ConnectError: secret"),
    ):
        forged = copy.deepcopy(snapshot)
        mutation(forged["peer_dispatcher"])
        _reseal_release_observation(namespace, forged)
        assert namespace["valid_observation_snapshot"](forged, node="warden-a") is False


def test_release_soak_verifier_accepts_pre_first_cycle_peer_startup() -> None:
    namespace = _release_soak_verifier_namespace()
    snapshot = _release_observation(namespace)
    startup = {
        "durable_retry": None,
        "failed_records": 0,
        "healthy": False,
        "last_cycle_ns": None,
        "last_error": None,
        "pending_records": 1,
        "prepared_transfers": 1,
    }
    snapshot["peer_dispatcher"].update(startup)
    snapshot["ready"] = False
    _reseal_release_observation(namespace, snapshot)

    assert (
        namespace["valid_peer_status"](
            snapshot["peer_dispatcher"],
            node="warden-a",
            published_at_ns=snapshot["published_at_ns"],
        )
        is True
    )
    assert namespace["valid_observation_snapshot"](snapshot, node="warden-a") is True

    for mutation in (
        lambda value: value.__setitem__("healthy", True),
        lambda value: value.__setitem__("last_cycle_ns", 0),
        lambda value: value.__setitem__("last_cycle_ns", 90),
        lambda value: value.__setitem__("running", False),
    ):
        forged = copy.deepcopy(snapshot)
        mutation(forged["peer_dispatcher"])
        _reseal_release_observation(namespace, forged)
        assert namespace["valid_observation_snapshot"](forged, node="warden-a") is False


def test_release_soak_verifier_accepts_exporter_error_before_first_success() -> None:
    namespace = _release_soak_verifier_namespace()
    snapshot = _release_observation(namespace)
    faulted = copy.deepcopy(snapshot["audit_exporter"])
    faulted.update(
        {
            "archive_reconciled": False,
            "healthy": False,
            "last_error": "StorageError:sqlite_busy",
            "last_success_ns": None,
        }
    )

    assert namespace["valid_audit_exporter_status"](faulted) is True

    for mutation in (
        lambda value: value.__setitem__("healthy", True),
        lambda value: value.__setitem__("archive_reconciled", True),
        lambda value: value.__setitem__("last_success_ns", 0),
        lambda value: value.__setitem__(
            "last_error",
            "StorageError: could not connect to the audit archive "
            "(sqlite_errorname=SQLITE_BUSY, sqlite_errorcode=5)",
        ),
    ):
        forged = copy.deepcopy(faulted)
        mutation(forged)
        assert namespace["valid_audit_exporter_status"](forged) is False


def test_release_soak_verifier_enforces_observation_lineage() -> None:
    namespace = _release_soak_verifier_namespace()
    first = _release_observation(namespace, revision=1)
    second = _release_observation(namespace, revision=2)
    progression = namespace["valid_observation_progression"]

    assert progression(first, second, allow_same_snapshot=False) is True
    assert progression(second, second, allow_same_snapshot=True) is True
    assert progression(second, second, allow_same_snapshot=False) is False

    reused_revision = copy.deepcopy(second)
    reused_revision["snapshot_id"] = "sha256:" + "9" * 64
    assert progression(second, reused_revision, allow_same_snapshot=True) is False

    changed_lifetime = _release_observation(
        namespace,
        revision=1,
        lifetime="c" * 32,
        generation=str(first["generation"]),
    )
    assert progression(first, changed_lifetime, allow_same_snapshot=False) is False

    changed_digest = _release_observation(namespace, revision=2)
    changed_digest["authority_checkpoint"]["state_revision"] = 1
    changed_digest["authority_checkpoint"]["state_digest"] = (
        base64.urlsafe_b64encode(bytes([1]) * 32).decode("ascii").rstrip("=")
    )
    changed_digest["core_state_revision"] = 1
    _reseal_release_observation(namespace, changed_digest)
    assert progression(first, changed_digest, allow_same_snapshot=False) is True

    diverged_at_same_audit_head = copy.deepcopy(changed_digest)
    diverged_at_same_audit_head["authority_checkpoint"]["audit_sequence"] = first[
        "authority_checkpoint"
    ]["audit_sequence"]
    diverged_at_same_audit_head["authority_checkpoint"]["audit_hash"] = first[
        "authority_checkpoint"
    ]["audit_hash"]
    _reseal_release_observation(namespace, diverged_at_same_audit_head)
    assert progression(first, diverged_at_same_audit_head, allow_same_snapshot=False) is False


def test_release_soak_verifier_enforces_three_single_requests_per_normal_sample() -> None:
    budget = _release_soak_verifier_namespace()["valid_sample_request_budget"]

    assert budget(3, 0) is True
    assert budget(2, 1) is True
    assert budget(3, 1) is True
    for request_total, planned_count in (
        (2, 0),
        (4, 0),
        (1, 1),
        (4, 1),
        (True, 0),
        (3.0, 0),
        (3, True),
    ):
        assert budget(request_total, planned_count) is False


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value["terminal_audit_proof"].__setitem__("valid", 1),
        lambda value: value["terminal_audit_proof"].__setitem__("verified_at_ns", 20.0),
        lambda value: value["terminal_audit_proof"].pop("authority_checkpoint_sha256"),
        lambda value: value["terminal_audit_proof"].__setitem__("extra", None),
        lambda value: value["terminal_audit_proof"].__setitem__(
            "verified_head_hash", "sha256:" + "f" * 64
        ),
        lambda value: value["authority_checkpoint"].__setitem__("state_revision", True),
    ),
)
def test_release_soak_verifier_rejects_terminal_proof_mutations(
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    namespace = _release_soak_verifier_namespace()
    snapshot = _release_observation(namespace)
    terminal = _release_terminal_fence(namespace, snapshot, full=False)
    mutation(terminal)

    assert (
        namespace["valid_terminal_fence"](
            terminal,
            node="warden-a",
            restart_id="restart-0",
            expected_lifetime=snapshot["lifetime_id"],
            prior_authority=snapshot["authority_anchor"],
            prior_observation=snapshot,
            full_audit_verification=False,
        )
        is False
    )


@pytest.mark.parametrize(
    ("mutation", "reseal"),
    (
        (lambda value: value.__setitem__("artifact_revision", True), True),
        (lambda value: value.__setitem__("journal_revision", 2.0), True),
        (lambda value: value.__setitem__("journal_compact", True), True),
        (lambda value: value.__setitem__("status", "failed"), True),
        (lambda value: value.__setitem__("schema", "wrong"), True),
        (
            lambda value: value.__setitem__("artifact_payload_sha256", "sha256:" + "0" * 64),
            False,
        ),
    ),
)
def test_release_soak_verifier_rejects_success_artifact_mutations(
    mutation: Callable[[dict[str, Any]], object],
    reseal: bool,
) -> None:
    namespace = _release_soak_verifier_namespace()
    workload = _release_success_workload_artifact(namespace)
    assert namespace["valid_success_workload_artifact"](workload) is True

    mutation(workload)
    if reseal:
        resealed = dict(workload)
        resealed.pop("artifact_payload_sha256", None)
        workload["artifact_payload_sha256"] = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    resealed,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
        )
    assert namespace["valid_success_workload_artifact"](workload) is False


def test_release_soak_verifier_reserves_success_artifact_trailing_newline() -> None:
    namespace = _release_soak_verifier_namespace()
    workload = _release_success_workload_artifact(namespace)
    real_json = namespace["json"]

    class OversizedBytes:
        def __len__(self) -> int:
            return 64 * 1024 * 1024

    class OversizedText:
        def encode(self, _encoding: str) -> OversizedBytes:
            return OversizedBytes()

    class SizeModel:
        @staticmethod
        def dumps(value: object, **options: object) -> object:
            if isinstance(value, dict) and "artifact_payload_sha256" in value:
                return OversizedText()
            return real_json.dumps(value, **options)

    namespace["json"] = SizeModel
    assert namespace["valid_success_workload_artifact"](workload) is False


def test_release_workflow_verifies_and_keyless_signs_before_release() -> None:
    workflow = (REPOSITORY / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "if: github.event.deleted == false" in workflow
    assert "Require a GitHub-verified annotated tag" in workflow
    assert "Require a verified commit and successful push gates" in workflow
    assert "actions: read" in workflow
    assert "for required, expected_path in required_workflows.items()" in workflow
    assert 'run.get("head_sha") == os.environ["GITHUB_SHA"]' in workflow
    assert 'latest.get("conclusion") != "success"' in workflow
    assert "release commit is not GitHub-verified" in workflow
    assert "Perform two clean reproducible builds" in workflow
    assert "Record deterministic image metadata" in workflow
    assert 'epoch="$(git show -s --format=%ct "$GITHUB_SHA")"' in workflow
    assert "SOURCE_DATE_EPOCH: ${{ steps.build-metadata.outputs.epoch }}" in workflow
    assert "SOURCE_DATE_EPOCH=${{ steps.build-metadata.outputs.epoch }}" in workflow
    assert "digest: ${{ steps.candidate.outputs.digest }}" in workflow
    assert "Resume an already promoted candidate without rebuilding" in workflow
    assert "existing immutable release tags resolve to different digests" in workflow
    assert 'manifest.get("digest") != expected_digest' in workflow
    assert '"org.opencontainers.image.revision": os.environ["GITHUB_SHA"]' in workflow
    assert "actions/attest" not in workflow
    assert "gh attestation verify" not in workflow
    assert "attestations: write" not in workflow
    assert workflow.count("id-token: write") == 3
    assert workflow.count("cosign-release: v3.1.3") == 3
    assert workflow.count("--type slsaprovenance1") == 3
    assert workflow.count('--certificate-identity "$workflow_identity"') >= 6
    assert (
        workflow.count("--certificate-oidc-issuer https://token.actions.githubusercontent.com") >= 6
    )
    assert workflow.count('--certificate-github-workflow-sha "$GITHUB_SHA"') >= 6
    assert workflow.count('"_type": "https://in-toto.io/Statement/v0.1"') == 3
    assert '"predicateType": "https://slsa.dev/provenance/v1"' in workflow
    assert (
        '"buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"'
        in workflow
    )
    assert '"candidate": f"{os.environ[\'IMAGE_NAME\']}@' in workflow
    assert '"gitCommit": os.environ["GITHUB_SHA"]' in workflow
    assert '"created": os.environ["EXPECTED_CREATED"]' in workflow
    assert '"version": os.environ["EXPECTED_VERSION"]' in workflow
    assert "resumed image lacks the exact signed candidate provenance" in workflow
    assert "new image lacks the exact signed candidate provenance" in workflow
    assert workflow.count("if: steps.resume.outputs.build_required == 'true'") == 2
    assert 'digest="${RESUMED_DIGEST:-$BUILT_DIGEST}"' in workflow
    assert "lets-deployment-$version.tar.gz" in workflow
    assert "deploy/production/maintenance-compose.yaml" in workflow
    assert "examples/runtime_provider.py" in workflow
    assert "git archive --format=tar" in workflow
    assert "git log -1 --format=%ct HEAD --" in workflow
    assert 'test -n "$SOURCE_DATE_EPOCH"' in workflow
    assert '--mtime="@$SOURCE_DATE_EPOCH"' in workflow
    assert '"HEAD^{tree}" --' in workflow
    assert "gzip -n" in workflow
    assert 'archive_contents="$(mktemp)"' in workflow
    assert '> "$archive_contents"' in workflow
    assert "grep -q '/deploy/production/compose.yaml$' \"$archive_contents\"" in workflow
    assert "grep -q '/examples/runtime_provider.py$' \"$archive_contents\"" in workflow
    assert "| grep -q '/deploy/production/compose.yaml$'" not in workflow
    assert "sha256sum --check RELEASE_SHA256SUMS" in workflow
    assert "uv pip sync --python .release-smoke/bin/python requirements-release.txt" in workflow
    assert 'uv pip install --python .release-smoke/bin/python --no-deps "$wheel"' in workflow
    assert "uv pip check --python .release-smoke/bin/python" in workflow
    assert "--requirement requirements-release.txt" in workflow
    assert 'sysconfig.get_paths()["purelib"]' not in workflow
    assert '--path "$site_packages"' not in workflow
    assert workflow.index("uv pip sync --python") < workflow.index("uv pip install --python")
    assert workflow.index("uv pip install --python") < workflow.index("uv pip check --python")
    assert workflow.index("uv pip check --python") < workflow.index("pip-audit --strict")
    assert workflow.index("pip-audit --strict") < workflow.index("cyclonedx-py environment")
    assert "sqlite-runtime-versions.txt" in workflow
    assert workflow.count("_require_production_sqlite") >= 1
    assert "outputs: type=registry,rewrite-timestamp=true" in workflow
    assert "provenance: false" in workflow
    assert "sbom: false" in workflow
    assert "Keyless-attest and verify exact candidate build provenance" in workflow
    assert "cosign attest --yes" in workflow
    assert "--predicate candidate-provenance.json" in workflow
    assert "cosign sign --yes" in workflow
    assert "cosign verify \\" in workflow
    assert "Run the mTLS production-profile acceptance" in workflow
    assert "release-production-acceptance-${{ needs.verify.outputs.version }}" in workflow
    assert "Run the one-hour production-profile soak against the exact candidate" in workflow
    assert "release-production-soak-${{ needs.verify.outputs.version }}" in workflow
    assert "--duration-seconds 3600" in workflow
    assert 'source.get("git_commit") != os.environ["GITHUB_SHA"]' in workflow
    assert 'source.get("dirty") is not False' in workflow
    assert 'workload_evaluation.get("passed") is not True' in workflow
    assert 'get("health_cadence") is not True' in workflow
    assert "required_cycles = max(semantic_cycle_floor, active_time_cycle_floor)" in workflow
    assert 'workload_metrics.get("required_cycles") == required_cycles' in workflow
    assert 'monitor.get("request_retry_count") == raw_health_retries' in workflow
    assert "expected_release_configuration = {" in workflow
    assert "type(configuration.get(name)) is not type(expected)" in workflow
    assert "right[0] < left[1]" in workflow
    assert 'float(armed_marker["armed_monotonic_seconds"]) < float(' in workflow
    assert "<= requested\n                      <= observed" in workflow
    assert 'float(exporter["max_stall_s"])' not in workflow
    assert 'close_number(exporter.get("max_stall_s"), 40.0, 0.0)' in workflow
    assert "len(pair_counts) != 6" in workflow
    assert 'get("durably_pending_observed") is not True' in workflow
    assert 'get("all_wardens_sigkilled") is not True' in workflow
    assert '"cgroup_memory_max_bytes": 1024 * 1024 * 1024' in workflow
    assert '"cgroup_swap_max_bytes": 0' in workflow
    assert '"max_cgroup_memory_peak_bytes": 768 * 1024 * 1024' in workflow
    assert '"max_rss_bytes": 256 * 1024 * 1024' in workflow
    assert '"max_rss_growth_bytes": 128 * 1024 * 1024' in workflow
    assert 'checkpoint.get("evaluation_passed") is not True' in workflow
    assert 'sample.get("reason") != "pre_sigkill"' in workflow
    assert "if: ${{ always() && (failure() || cancelled()) }}" in workflow
    assert (
        "diagnostic-production-soak-${{ needs.verify.outputs.version }}-"
        "${{ github.run_id }}-${{ github.run_attempt }}" in workflow
    )
    assert workflow.count("release-production-soak-${{ needs.verify.outputs.version }}") == 1
    assert 'package_identity.get("passed") is not True' in workflow
    assert 'cleanup.get("remaining_containers") != 0' in workflow
    assert (
        "tonistiigi/binfmt@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0"
        in workflow
    )
    assert (
        "moby/buildkit:buildx-stable-1@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec"
        in workflow
    )
    assert "needs: [verify, package, image-candidate]" in workflow
    assert (
        "needs: [verify, package, image-candidate, production-acceptance, production-soak]"
        in workflow
    )
    assert "needs: [verify, package, production-acceptance, production-soak, image]" in workflow
    assert "candidate-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}" in workflow
    assert "LETS_PRODUCTION_ACCEPTANCE_IMAGE" in workflow
    assert 'evidence.get("runtime_image_digest")' in workflow
    assert workflow.count("flavor: latest=false") == 2
    assert "type=semver,pattern={{major}}.{{minor}}" not in workflow
    assert "type=raw,value=latest" not in workflow
    assert "release tag must resolve to the current main commit" in workflow
    assert "lets.__version__ does not match package version" in workflow
    assert '"ci": ".github/workflows/ci.yml"' in workflow
    assert '"security": ".github/workflows/security.yml"' in workflow
    assert 'key=lambda run: (run.get("id", 0), run.get("run_attempt", 0))' in workflow
    assert "refusing to move existing release image tag" in workflow
    assert (
        workflow.count(
            "image-ref: ${{ env.IMAGE_NAME }}@${{ needs.image-candidate.outputs.digest }}"
        )
        == 2
    )
    assert "already resolves to the verified candidate digest" in workflow
    assert "release tag did not resolve to the verified candidate" in workflow
    assert "could not prove that release image tag is absent" in workflow
    assert workflow.count("--format '{{.Manifest.Digest}}'") == 3
    assert "merge-multiple: true" not in workflow
    assert 'f"release-package-{version}"' in workflow
    assert 'f"release-production-acceptance-{version}"' in workflow
    assert 'f"release-production-soak-{version}"' in workflow
    assert 'f"release-image-{version}"' in workflow
    assert "release asset name collision" in workflow
    assert "release asset is empty" in workflow
    assert "if len(artifacts) != 15:" in workflow
    assert 'signature_name = f"{checksum_name}.sigstore.json"' in workflow
    assert "path.name not in {checksum_name, signature_name}" in workflow
    assert 'test "$(find release-assets -maxdepth 1 -type f | wc -l)" -eq 17' in workflow
    assert "anchore/sbom-action/download-syft@aa80c8c5bd439a416a62804f2151ab38c671a638" in workflow
    assert "syft-version: v1.50.0" in workflow
    assert "--from registry" in workflow
    assert '--platform "$platform"' in workflow
    assert workflow.index("Verify both candidate architectures are present") < workflow.index(
        "Require patched SQLite in both exact published architectures"
    )
    sqlite_step = workflow.split(
        "- name: Require patched SQLite in both exact published architectures", maxsplit=1
    )[1].split("- name: Scan the exact published amd64 candidate", maxsplit=1)[0]
    assert "steps.manifest.outputs.amd64_digest" in sqlite_step
    assert "steps.manifest.outputs.arm64_digest" in sqlite_step
    assert '"$IMAGE_NAME@$child_digest"' in sqlite_step
    assert "needs.image-candidate.outputs.digest" not in sqlite_step
    assert '"schema": "lets.container-sbom-index/v1"' in workflow
    assert 'metadata.get("manifestDigest") != child_digest' in workflow
    assert 'image_ref not in (metadata.get("repoDigests") or [])' in workflow
    assert "Keyless-attest and verify each SPDX SBOM against its child manifest" in workflow
    assert "AMD64_DIGEST: ${{ steps.manifest.outputs.amd64_digest }}" in workflow
    assert "ARM64_DIGEST: ${{ steps.manifest.outputs.arm64_digest }}" in workflow
    assert workflow.count("--type spdxjson") == 2
    assert '"predicateType": "https://spdx.dev/Document"' in workflow
    assert "child manifest lacks its exact signed SPDX SBOM" in workflow
    assert "lets-container.spdx.json" not in workflow
    assert "Keyless-sign and verify the complete release checksum manifest" in workflow
    assert "cosign sign-blob --yes" in workflow
    assert '--bundle "$bundle"' in workflow
    assert "cosign verify-blob" in workflow
    assert workflow.count('"RELEASE_SHA256SUMS.sigstore.json"') >= 2
    assert "existing GitHub release has duplicate Sigstore bundles" in workflow
    assert "existing GitHub release has an invalid draft state" in workflow
    assert 'is_draft = state.get("draft")' in workflow
    assert 'is_draft = state.get("isDraft")' not in workflow
    assert '"reuse" if is_draft is False and matching else "retain"' in workflow
    assert "reused the existing release's verified Sigstore bundle" in workflow
    assert "retained the freshly signed bundle for a draft or bundle-free release" in workflow
    assert "could not prove that an existing release bundle is absent" in workflow
    assert 'mv "$remote_bundle" "$bundle"' in workflow
    assert "final release asset allowlist mismatch" in workflow
    assert workflow.index("cosign sign-blob --yes") < workflow.index('release_state="$(mktemp)"')
    assert workflow.index('test -s "$remote_bundle"') < workflow.index(
        'mv "$remote_bundle" "$bundle"'
    )
    assert workflow.index('--bundle "$remote_bundle"') < workflow.index(
        'mv "$remote_bundle" "$bundle"'
    )
    assert "Publish or safely resume the immutable GitHub release" in workflow
    assert "Extract exact compatibility, migration, and rollback release notes" in workflow
    assert '"### Compatibility, migration, and rollback"' in workflow
    assert "--notes-file release-notes.md" in workflow
    assert "published GitHub release has the wrong lifecycle notes" in workflow
    assert "--generate-notes" not in workflow
    assert '"repos/$GITHUB_REPOSITORY/immutable-releases"' not in workflow
    assert "release tag moved before publication" in workflow
    assert "GitHub release did not become immutable within its deadline" in workflow
    assert "mutable release was returned to draft" in workflow
    assert 'gh release verify "$GITHUB_REF_NAME"' in workflow
    assert workflow.count("X-GitHub-Api-Version: 2026-03-10") >= 1
    assert 'gh release create "$GITHUB_REF_NAME"' in workflow
    assert "--draft" in workflow
    assert 'gh release upload "$GITHUB_REF_NAME" release-assets/*' in workflow
    assert "--clobber" in workflow
    assert 'gh release edit "$GITHUB_REF_NAME"' in workflow
    assert "--draft=false" in workflow
    assert "GitHub release asset digest mismatch" in workflow
    assert "published GitHub release already has the exact verified asset set" in workflow
    assert "could not prove that the GitHub release is absent" in workflow
    for required_asset in (
        'f"lets-deployment-{version}.tar.gz"',
        'f"lets_agent-{version}-py3-none-any.whl"',
        'f"lets_agent-{version}.tar.gz"',
        '"RELEASE_SHA256SUMS"',
        '"RELEASE_SHA256SUMS.sigstore.json"',
        '"production-profile-acceptance.json"',
        '"production-profile-soak.json"',
        '"image-digest.txt"',
        '"image-manifest.json"',
        '"lets-container-amd64.spdx.json"',
        '"lets-container-arm64.spdx.json"',
        '"lets-container-sbom-index.json"',
        '"sqlite-runtime-versions.txt"',
        '"trivy-amd64.txt"',
        '"trivy-arm64.txt"',
    ):
        assert required_asset in workflow
    assert "Promote the verified digest to immutable release tags" in workflow
    assert workflow.index("Publish the multi-architecture release candidate") < workflow.index(
        "Keyless-attest and verify exact candidate build provenance"
    )
    assert workflow.index(
        "Resume an already promoted candidate without rebuilding"
    ) < workflow.index("Publish the multi-architecture release candidate")
    assert workflow.index(
        "Keyless-attest and verify exact candidate build provenance"
    ) < workflow.index("Run the mTLS production-profile acceptance against the exact candidate")
    assert workflow.index(
        "Run the mTLS production-profile acceptance against the exact candidate"
    ) < workflow.index("Scan the exact published amd64 candidate with Trivy")
    assert workflow.index("Verify both candidate architectures are present") < workflow.index(
        "Generate and validate one SPDX SBOM per published architecture"
    )
    assert workflow.index(
        "Generate and validate one SPDX SBOM per published architecture"
    ) < workflow.index("Keyless-attest and verify each SPDX SBOM against its child manifest")
    assert workflow.index(
        "Keyless-attest and verify each SPDX SBOM against its child manifest"
    ) < workflow.index("Promote the verified digest to immutable release tags")
    assert workflow.index("Keyless-sign and verify the exact image digest") < workflow.index(
        "Promote the verified digest to immutable release tags"
    )
    assert workflow.index("Promote the verified digest to immutable release tags") < workflow.index(
        "Publish or safely resume the immutable GitHub release"
    )
    assert workflow.index(
        "Keyless-sign and verify the complete release checksum manifest"
    ) < workflow.index("Publish or safely resume the immutable GitHub release")
