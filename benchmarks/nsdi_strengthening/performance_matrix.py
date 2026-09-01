"""Measure LETS durable-path cost across delay, concurrency, and storage matrices.

The runner deliberately stays below any host integration.  Enforce-mode samples
exercise the real :class:`SQLiteStorage`, :class:`WardenService`,
:class:`ReceiptVerifier`, and :class:`SQLiteReceiptReplayStore`; off-mode samples
execute the identical synthetic actuator without an authorization or claim.

Each measured worker owns an independent lease while all workers in a trial
share one warden database and one executor replay database.  Raw observations
are retained so every reported percentile can be independently recomputed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import io
import json
import math
import os
import platform
import re
import shutil
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal

from lets.authority import FileAuthorityAnchor, ProcessFileAuthorityAnchor
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.executor import (
    ExecutorPolicy,
    ReceiptVerifier,
    SQLiteReceiptReplayStore,
    executor_replay_identity,
)
from lets.executor_authority import (
    FileExecutorAuthorityAnchor,
    ProcessFileExecutorAuthorityAnchor,
)
from lets.models import IdentityContext
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage

RESULT_SCHEMA = "lets.nsdi-performance-matrix/v1"
DEFAULT_DELAYS_MS = (0.0, 1.0, 10.0, 100.0, 1_000.0)
DEFAULT_WORKERS = (1, 2, 4, 8, 16)
BENCHMARK_CLOCK_NS = 1_000_000_000_000_000
OUTPUT_JSON = "performance-matrix.json"
OUTPUT_CSV = "performance-matrix-samples.csv"
OUTPUT_MARKDOWN = "performance-matrix.md"
AnchorMode = Literal["unanchored", "file", "process-file"]
Mode = Literal["off", "enforce"]


@dataclass(frozen=True, slots=True)
class MatrixConfiguration:
    trials: int = 10
    operations: int = 1_000
    warmup_per_worker: int = 100
    delays_ms: tuple[float, ...] = DEFAULT_DELAYS_MS
    workers: tuple[int, ...] = DEFAULT_WORKERS
    anchor_mode: AnchorMode = "file"


@dataclass(frozen=True, slots=True)
class OperationSample:
    worker_id: int
    operation_index: int
    lease_id: str
    warden_ns: int
    claim_ns: int
    application_ns: int
    unattributed_ns: int
    end_to_end_ns: int


@dataclass(slots=True)
class _TrialRig:
    service: WardenService
    storage: SQLiteStorage
    verifier: ReceiptVerifier
    replay_store: SQLiteReceiptReplayStore
    identities: tuple[IdentityContext, ...]
    lease_ids: tuple[str, ...]
    warden_anchor: object | None
    executor_anchor: object | None

    def close(self) -> None:
        self.storage.close()
        for anchor in (self.executor_anchor, self.warden_anchor):
            close = getattr(anchor, "close", None)
            if callable(close):
                close()


def _policy() -> PolicySpec:
    return PolicySpec(
        policy_id="nsdi-performance-policy",
        policy_version="v1",
        dimensions=(ResourceDimension("operations", "count"),),
        machine=MachineSpec(
            machine_id="nsdi-performance-worker",
            initial_state="ready",
            transitions=(
                TransitionSpec(
                    "step",
                    "ready",
                    "ready",
                    (1,),
                    "benchmark.step",
                ),
            ),
        ),
        max_lease_ttl_ns=1_000_000_000_000_000_000,
        receipt_ttl_ns=60_000_000_000,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=64,
    )


def _identity(subject: str, *scopes: str) -> IdentityContext:
    return IdentityContext(subject, "nsdi-performance", frozenset(scopes))


def _split_operations(operations: int, workers: int) -> tuple[int, ...]:
    quotient, remainder = divmod(operations, workers)
    return tuple(quotient + (1 if worker < remainder else 0) for worker in range(workers))


def _anchors(
    root: Path,
    mode: AnchorMode,
) -> tuple[object | None, object | None]:
    if mode == "unanchored":
        return None, None
    authority = root / "authority"
    authority.mkdir()
    if mode == "file":
        return (
            FileAuthorityAnchor(authority / "warden.anchor"),
            FileExecutorAuthorityAnchor(authority / "executor.anchor"),
        )
    return (
        ProcessFileAuthorityAnchor(authority / "warden.anchor"),
        ProcessFileExecutorAuthorityAnchor(authority / "executor.anchor"),
    )


def _build_trial_rig(
    root: Path,
    *,
    operation_counts: Sequence[int],
    warmup_per_worker: int,
    anchor_mode: AnchorMode,
) -> _TrialRig:
    policy = _policy()
    clock = ManualClock(BENCHMARK_CLOCK_NS)
    signer = Ed25519Signer.generate("warden-performance")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    total_allocation = sum(operation_counts) + warmup_per_worker * len(operation_counts)
    warden_anchor, executor_anchor = _anchors(root, anchor_mode)
    storage = SQLiteStorage.initialize(
        root / "warden.sqlite3",
        signer.warden_id,
        (total_allocation,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="nsdi-performance",
        envelope_id="performance-envelope",
        initial_local_share=(total_allocation,),
        receipt_ttl_ns=policy.receipt_ttl_ns,
        transfer_gap_window=policy.transfer_gap_window,
        authority_anchor=warden_anchor,
    )
    service = WardenService(storage, signer=signer, clock=clock, trust_registry=registry)
    service.register_policy(policy)
    identities: list[IdentityContext] = []
    lease_ids: list[str] = []
    for worker, measured in enumerate(operation_counts):
        identity = _identity(f"worker-{worker}", "lets.lease.issue")
        grant = service.issue_root(
            request_id=f"root-{worker}",
            identity=identity,
            tenant_id="nsdi-performance",
            envelope_id="performance-envelope",
            subject_id=f"worker-{worker}",
            allocation=(measured + warmup_per_worker,),
            capabilities={"benchmark.step"},
            policy_digest=policy.digest,
            ttl_ns=1_000_000_000_000_000,
        )
        identities.append(identity)
        lease_ids.append(grant.lease_id)

    executor_policy = ExecutorPolicy(
        audience="performance-executor",
        tenant_id="nsdi-performance",
        envelope_id="performance-envelope",
        config_epoch=1,
        allowed_policy_digests=frozenset({policy.digest}),
        allowed_machine_digests=frozenset({policy.machine.digest}),
        trusted_wardens=frozenset({signer.warden_id}),
        max_clock_uncertainty_ns=0,
    )
    replay = SQLiteReceiptReplayStore.initialize(
        root / "executor.sqlite3",
        authority_anchor=executor_anchor,
        identity=(
            None if executor_anchor is None else executor_replay_identity(executor_policy, registry)
        ),
        allow_unanchored=executor_anchor is None,
    )
    verifier = ReceiptVerifier(registry, replay, executor_policy, clock=clock)
    return _TrialRig(
        service=service,
        storage=storage,
        verifier=verifier,
        replay_store=replay,
        identities=tuple(identities),
        lease_ids=tuple(lease_ids),
        warden_anchor=warden_anchor,
        executor_anchor=executor_anchor,
    )


def _execute_operation(
    rig: _TrialRig,
    *,
    mode: Mode,
    worker_id: int,
    sequence: int,
    operation_index: int,
    delay_ms: float,
    prefix: str,
) -> OperationSample:
    started = time.perf_counter_ns()
    warden_ns = 0
    claim_ns = 0
    if mode == "enforce":
        warden_started = time.perf_counter_ns()
        receipt = rig.service.authorize(
            request_id=f"{prefix}-request-{worker_id}-{sequence}",
            identity=rig.identities[worker_id],
            lease_id=rig.lease_ids[worker_id],
            transition="step",
            audience="performance-executor",
            nonce=f"{prefix}-nonce-{worker_id}-{sequence}-0000000000000000",
            expected_state="ready",
            expected_sequence=sequence,
        )
        warden_ns = time.perf_counter_ns() - warden_started
        claim_started = time.perf_counter_ns()
        rig.verifier.verify_and_claim(receipt)
        claim_ns = time.perf_counter_ns() - claim_started

    application_started = time.perf_counter_ns()
    if delay_ms:
        time.sleep(delay_ms / 1_000)
    application_ns = time.perf_counter_ns() - application_started
    end_to_end_ns = time.perf_counter_ns() - started
    attributed = warden_ns + claim_ns + application_ns
    return OperationSample(
        worker_id=worker_id,
        operation_index=operation_index,
        lease_id=rig.lease_ids[worker_id],
        warden_ns=warden_ns,
        claim_ns=claim_ns,
        application_ns=application_ns,
        unattributed_ns=max(0, end_to_end_ns - attributed),
        end_to_end_ns=end_to_end_ns,
    )


def _nearest_rank(values: Sequence[int | float], percentile: float) -> int | float:
    if not values:
        raise ValueError("at least one sample is required")
    ordered = sorted(values)
    rank = max(1, math.ceil(len(ordered) * percentile))
    return ordered[min(rank - 1, len(ordered) - 1)]


def _summary(values: Sequence[int]) -> dict[str, int]:
    if not values:
        raise ValueError("at least one latency sample is required")
    return {
        "minimum": min(values),
        "p50": int(_nearest_rank(values, 0.50)),
        "mean": int(statistics.fmean(values)),
        "p95": int(_nearest_rank(values, 0.95)),
        "p99": int(_nearest_rank(values, 0.99)),
        "maximum": max(values),
    }


def _throughput_summary(values: Sequence[float]) -> dict[str, float]:
    if not values:
        raise ValueError("at least one throughput sample is required")
    return {
        "minimum": min(values),
        "p50": float(_nearest_rank(values, 0.50)),
        "mean": statistics.fmean(values),
        "p95": float(_nearest_rank(values, 0.95)),
        "p99": float(_nearest_rank(values, 0.99)),
        "maximum": max(values),
    }


def _latency_summaries(samples: Sequence[OperationSample]) -> dict[str, dict[str, int]]:
    return {
        name: _summary([int(getattr(sample, name)) for sample in samples])
        for name in (
            "warden_ns",
            "claim_ns",
            "application_ns",
            "unattributed_ns",
            "end_to_end_ns",
        )
    }


def _run_trial(
    storage_root: Path,
    *,
    storage_id: str,
    mode: Mode,
    delay_ms: float,
    workers: int,
    trial_index: int,
    operations: int,
    warmup_per_worker: int,
    anchor_mode: AnchorMode,
) -> dict[str, Any]:
    operation_counts = _split_operations(operations, workers)
    with TemporaryDirectory(prefix="lets-nsdi-performance-", dir=storage_root) as temporary:
        root = Path(temporary)
        rig = _build_trial_rig(
            root,
            operation_counts=operation_counts,
            warmup_per_worker=warmup_per_worker,
            anchor_mode=anchor_mode,
        )
        try:
            start_holder = [0]
            barrier = threading.Barrier(
                workers + 1,
                action=lambda: start_holder.__setitem__(0, time.perf_counter_ns()),
            )
            prefix = f"t{trial_index}-{mode[0]}-d{str(delay_ms).replace('.', '_')}-c{workers}"

            def run_worker(worker_id: int) -> tuple[list[OperationSample], int]:
                for sequence in range(warmup_per_worker):
                    if mode == "enforce":
                        _execute_operation(
                            rig,
                            mode=mode,
                            worker_id=worker_id,
                            sequence=sequence,
                            operation_index=-1,
                            delay_ms=0,
                            prefix=f"{prefix}-warmup",
                        )
                barrier.wait()
                samples = [
                    _execute_operation(
                        rig,
                        mode=mode,
                        worker_id=worker_id,
                        sequence=warmup_per_worker + local_index,
                        operation_index=local_index,
                        delay_ms=delay_ms,
                        prefix=prefix,
                    )
                    for local_index in range(operation_counts[worker_id])
                ]
                return samples, time.perf_counter_ns()

            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(run_worker, worker) for worker in range(workers)]
                barrier.wait()
                completed = [future.result() for future in futures]
            samples = [
                sample for worker_samples, _finished in completed for sample in worker_samples
            ]
            finished_ns = max(finished for _worker_samples, finished in completed)
            wall_time_ns = finished_ns - start_holder[0]
            conservation = rig.service.invariant_snapshot(
                identity=_identity("performance-auditor")
            ).healthy
            replay_status = rig.replay_store.status()
            return {
                "storage_id": storage_id,
                "mode": mode,
                "delay_ms": delay_ms,
                "workers": workers,
                "trial_index": trial_index,
                "operations": len(samples),
                "warmup_per_worker": warmup_per_worker,
                "wall_time_ns": wall_time_ns,
                "throughput_ops_per_second": len(samples) * 1_000_000_000 / wall_time_ns,
                "latency_ns": _latency_summaries(samples),
                "worker_lease_ids": list(rig.lease_ids),
                "conservation_healthy": conservation,
                "executor_rollback_protected": replay_status.rollback_protected,
                "independent_rollback_domain_established": False,
                "samples": [asdict(sample) for sample in samples],
            }
        finally:
            rig.close()


def _command(
    arguments: Sequence[str],
    *,
    cwd: Path,
) -> str | None:
    try:
        completed = subprocess.run(
            list(arguments),
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip()


def _sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _git_identity(root: Path) -> dict[str, object]:
    status = _command(("git", "status", "--porcelain=v1", "--untracked-files=all"), cwd=root)
    diff = _command(("git", "diff", "--binary", "HEAD"), cwd=root)
    return {
        "revision": _command(("git", "rev-parse", "HEAD"), cwd=root),
        "tree": _command(("git", "rev-parse", "HEAD^{tree}"), cwd=root),
        "describe": _command(("git", "describe", "--tags", "--always", "--dirty"), cwd=root),
        "dirty": None if status is None else bool(status),
        "status_sha256": None if status is None else hashlib.sha256(status.encode()).hexdigest(),
        "tracked_diff_sha256": (
            None if diff is None else hashlib.sha256(diff.encode()).hexdigest()
        ),
    }


def _storage_probe(root: Path) -> dict[str, object]:
    resolved = root.resolve(strict=True)
    stat = resolved.stat()
    usage = shutil.disk_usage(resolved)
    result: dict[str, object] = {
        "path": str(resolved),
        "device_id": stat.st_dev,
        "total_bytes": usage.total,
        "free_bytes_at_start": usage.free,
        "platform_probe": None,
    }
    if os.name == "nt":
        drive = resolved.drive
        if re.fullmatch(r"[A-Za-z]:", drive):
            drive_letter = drive[0].upper()
            script = (
                f"$volume=Get-Volume -DriveLetter '{drive_letter}';"
                f"$disk=Get-Partition -DriveLetter '{drive_letter}'|Get-Disk;"
                f"[pscustomobject]@{{drive='{drive_letter}';"
                "filesystem=$volume.FileSystem;"
                "volume_label=$volume.FileSystemLabel;disk_number=$disk.Number;"
                "disk_model=$disk.FriendlyName;bus_type=[string]$disk.BusType;"
                "disk_size_bytes=$disk.Size}|ConvertTo-Json -Compress"
            )
            raw = _command(
                ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script),
                cwd=resolved,
            )
        else:
            raw = None
    else:
        raw = _command(
            ("findmnt", "--json", "--target", str(resolved), "--output", "SOURCE,FSTYPE,TARGET"),
            cwd=resolved,
        )
    if raw:
        try:
            result["platform_probe"] = json.loads(raw)
        except json.JSONDecodeError:
            result["platform_probe"] = {"raw": raw}
    return result


def _environment(root: Path) -> dict[str, object]:
    package_versions: dict[str, str | None] = {}
    for distribution in ("lets-agent", "PyNaCl"):
        try:
            package_versions[distribution] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            package_versions[distribution] = None
    return {
        "captured_at": datetime.now(UTC).isoformat(),
        "python": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_count": os.cpu_count(),
        "sqlite": sqlite3.sqlite_version,
        "package_versions": package_versions,
        "git": _git_identity(root),
        "input_hashes": {
            "pyproject.toml": _sha256_file(root / "pyproject.toml"),
            "uv.lock": _sha256_file(root / "uv.lock"),
            "performance_matrix.py": _sha256_file(Path(__file__).resolve()),
        },
    }


def _validate_configuration(configuration: MatrixConfiguration) -> None:
    if configuration.trials <= 0:
        raise ValueError("trials must be positive")
    if configuration.operations <= 0:
        raise ValueError("operations must be positive")
    if configuration.warmup_per_worker < 0:
        raise ValueError("warmup_per_worker must be non-negative")
    if not configuration.delays_ms or len(set(configuration.delays_ms)) != len(
        configuration.delays_ms
    ):
        raise ValueError("delays_ms must be non-empty and unique")
    if any(not math.isfinite(value) or value < 0 for value in configuration.delays_ms):
        raise ValueError("delays_ms must contain finite non-negative values")
    if not configuration.workers or len(set(configuration.workers)) != len(configuration.workers):
        raise ValueError("workers must be non-empty and unique")
    if any(type(value) is not int or value <= 0 for value in configuration.workers):
        raise ValueError("workers must contain positive integers")
    if configuration.operations < max(configuration.workers):
        raise ValueError("operations must be at least the largest worker count")
    if configuration.anchor_mode not in {"unanchored", "file", "process-file"}:
        raise ValueError("invalid anchor_mode")


def _aggregate(trials: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, float, int], list[Mapping[str, Any]]] = {}
    for trial in trials:
        key = (
            str(trial["storage_id"]),
            str(trial["mode"]),
            float(trial["delay_ms"]),
            int(trial["workers"]),
        )
        grouped.setdefault(key, []).append(trial)
    aggregates: list[dict[str, Any]] = []
    for (storage_id, mode, delay_ms, workers), members in sorted(grouped.items()):
        raw = [sample for member in members for sample in member["samples"]]
        aggregates.append(
            {
                "storage_id": storage_id,
                "mode": mode,
                "delay_ms": delay_ms,
                "workers": workers,
                "trial_count": len(members),
                "operations": len(raw),
                "throughput_ops_per_second": _throughput_summary(
                    [float(member["throughput_ops_per_second"]) for member in members]
                ),
                "latency_ns": {
                    field: _summary([int(sample[field]) for sample in raw])
                    for field in (
                        "warden_ns",
                        "claim_ns",
                        "application_ns",
                        "unattributed_ns",
                        "end_to_end_ns",
                    )
                },
            }
        )
    return aggregates


def run_matrix(
    storage_roots: Sequence[Path],
    configuration: MatrixConfiguration,
) -> dict[str, Any]:
    """Execute a complete matrix and return a JSON-serializable evidence document."""

    _validate_configuration(configuration)
    if not storage_roots:
        raise ValueError("at least one storage root is required")
    roots: list[Path] = []
    for candidate in storage_roots:
        candidate.mkdir(parents=True, exist_ok=True)
        resolved = candidate.resolve(strict=True)
        if not resolved.is_dir():
            raise ValueError(f"storage root is not a directory: {resolved}")
        roots.append(resolved)
    if len(set(roots)) != len(roots):
        raise ValueError("storage roots must be unique")

    repository = Path(__file__).resolve().parents[2]
    storage = [
        {"storage_id": f"storage-{index}", **_storage_probe(root)}
        for index, root in enumerate(roots)
    ]
    trials: list[dict[str, Any]] = []
    for storage_entry, storage_root in zip(storage, roots, strict=True):
        for delay_ms in configuration.delays_ms:
            for workers in configuration.workers:
                for trial_index in range(configuration.trials):
                    modes: tuple[Mode, Mode] = (
                        ("off", "enforce") if trial_index % 2 == 0 else ("enforce", "off")
                    )
                    for mode in modes:
                        trials.append(
                            _run_trial(
                                storage_root,
                                storage_id=str(storage_entry["storage_id"]),
                                mode=mode,
                                delay_ms=delay_ms,
                                workers=workers,
                                trial_index=trial_index,
                                operations=configuration.operations,
                                warmup_per_worker=configuration.warmup_per_worker,
                                anchor_mode=configuration.anchor_mode,
                            )
                        )
    return {
        "schema": RESULT_SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": _environment(repository),
        "configuration": {
            **asdict(configuration),
            "storage_roots": [str(root) for root in roots],
            "durability": "SQLite WAL, synchronous=FULL, one transaction per debit/claim",
            "percentile_method": "nearest-rank",
            "warmup_application_delay_ms": 0,
            "mode_order": "alternates by paired trial",
            "anchor_topology": (
                "Anchor files are distinct from the SQLite files but live below the same "
                "ephemeral storage root; this benchmark does not establish an independent "
                "rollback failure domain."
            ),
        },
        "storage": storage,
        "trials": trials,
        "aggregates": _aggregate(trials),
    }


def _markdown(result: Mapping[str, Any]) -> str:
    environment = result["environment"]
    lines = [
        "# LETS performance matrix",
        "",
        f"- Schema: `{result['schema']}`",
        f"- Generated: `{result['generated_at']}`",
        f"- Revision: `{environment['git']['revision']}`",
        f"- Python: `{str(environment['python']).splitlines()[0]}`",
        f"- SQLite: `{environment['sqlite']}`",
        "",
        "All latency columns are nearest-rank percentiles over retained raw operations. "
        "Throughput columns summarize per-trial achieved throughput.",
        "Configured anchors use distinct files in the same ephemeral storage root; these "
        "measurements do not establish independent rollback failure domains.",
        "",
        "| Storage | Mode | Delay ms | Workers | Ops | Throughput p50 | E2E p50 ms | "
        "E2E p95 ms | E2E p99 ms | Warden p50 ms | Claim p50 ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in result["aggregates"]:
        latency = item["latency_ns"]
        lines.append(
            "| {storage_id} | {mode} | {delay_ms:g} | {workers} | {operations} | "
            "{throughput:.2f} | {p50:.3f} | {p95:.3f} | {p99:.3f} | "
            "{warden:.3f} | {claim:.3f} |".format(
                **item,
                throughput=item["throughput_ops_per_second"]["p50"],
                p50=latency["end_to_end_ns"]["p50"] / 1_000_000,
                p95=latency["end_to_end_ns"]["p95"] / 1_000_000,
                p99=latency["end_to_end_ns"]["p99"] / 1_000_000,
                warden=latency["warden_ns"]["p50"] / 1_000_000,
                claim=latency["claim_ns"]["p50"] / 1_000_000,
            )
        )
    lines.extend(("", "Raw samples are in `performance-matrix-samples.csv` and the JSON file."))
    return "\n".join(lines) + "\n"


def _csv_text(result: Mapping[str, Any]) -> str:
    stream = io.StringIO(newline="")
    fields = (
        "storage_id",
        "mode",
        "delay_ms",
        "workers",
        "trial_index",
        "worker_id",
        "operation_index",
        "lease_id",
        "warden_ns",
        "claim_ns",
        "application_ns",
        "unattributed_ns",
        "end_to_end_ns",
    )
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for trial in result["trials"]:
        common = {field: trial[field] for field in fields[:5]}
        for sample in trial["samples"]:
            writer.writerow({**common, **sample})
    return stream.getvalue()


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_outputs(
    result: Mapping[str, Any],
    output: Path,
    *,
    overwrite: bool = False,
) -> tuple[Path, Path, Path]:
    """Write JSON, raw CSV, and Markdown, refusing replacement by default."""

    targets = (output / OUTPUT_JSON, output / OUTPUT_CSV, output / OUTPUT_MARKDOWN)
    existing = [path for path in targets if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing evidence: {existing[0]}")
    output.mkdir(parents=True, exist_ok=True)
    _atomic_write(targets[0], json.dumps(result, indent=2, sort_keys=True) + "\n")
    _atomic_write(targets[1], _csv_text(result))
    _atomic_write(targets[2], _markdown(result))
    return targets


def _float_list(value: str) -> tuple[float, ...]:
    try:
        parsed = tuple(float(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected comma-separated numbers") from exc
    if not parsed:
        raise argparse.ArgumentTypeError("expected at least one number")
    return parsed


def _integer_list(value: str) -> tuple[int, ...]:
    try:
        parsed = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected comma-separated integers") from exc
    if not parsed:
        raise argparse.ArgumentTypeError("expected at least one integer")
    return parsed


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--operations", type=int, default=1_000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--delays-ms", type=_float_list, default=DEFAULT_DELAYS_MS)
    parser.add_argument("--workers", type=_integer_list, default=DEFAULT_WORKERS)
    parser.add_argument(
        "--anchor-mode",
        choices=("unanchored", "file", "process-file"),
        default="file",
    )
    parser.add_argument(
        "--storage-root",
        action="append",
        type=Path,
        dest="storage_roots",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/results/nsdi-strengthening/performance"),
    )
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> None:
    arguments = _arguments()
    storage_roots = arguments.storage_roots or [
        Path("benchmarks/results/nsdi-strengthening/storage")
    ]
    configuration = MatrixConfiguration(
        trials=arguments.trials,
        operations=arguments.operations,
        warmup_per_worker=arguments.warmup,
        delays_ms=arguments.delays_ms,
        workers=arguments.workers,
        anchor_mode=arguments.anchor_mode,
    )
    result = run_matrix(storage_roots, configuration)
    paths = write_outputs(result, arguments.output, overwrite=arguments.overwrite)
    print(json.dumps({"json": str(paths[0]), "csv": str(paths[1]), "markdown": str(paths[2])}))


if __name__ == "__main__":
    main()
