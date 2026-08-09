"""Run LETS microbenchmarks without installing anything outside ``.venv``.

The production measurements exercise the public service and executor APIs with
their default SQLite ``WAL``/``synchronous=FULL`` durability.  The SQLite-only
diagnostics intentionally compare batching and ``synchronous=NORMAL``; they are
labelled non-production because neither changes LETS runtime semantics or
defaults.
"""

from __future__ import annotations

import argparse
import cProfile
import csv
import io
import json
import os
import platform
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from lets.canonical import b64url_encode, canonical_json
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.models import IdentityContext, Receipt
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage

RESULT_SCHEMA = "lets.benchmark-result/v1"
BENCHMARK_CLOCK_NS = 1_000_000_000_000_000


@dataclass(frozen=True, slots=True)
class LatencySummary:
    minimum: int
    median: int
    mean: int
    p95: int
    p99: int
    maximum: int


def _percentile(sorted_values: Sequence[int], percentile: float) -> int:
    """Return a nearest-rank percentile for a non-empty sorted sequence."""

    rank = max(1, (len(sorted_values) * int(percentile * 100) + 99) // 100)
    return sorted_values[min(rank - 1, len(sorted_values) - 1)]


def _latencies(values: Sequence[int]) -> LatencySummary:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("at least one latency sample is required")
    return LatencySummary(
        minimum=ordered[0],
        median=int(statistics.median(ordered)),
        mean=int(statistics.fmean(ordered)),
        p95=_percentile(ordered, 0.95),
        p99=_percentile(ordered, 0.99),
        maximum=ordered[-1],
    )


def _measurement(
    name: str,
    values: Sequence[int],
    wall_ns: int,
    *,
    durability: str,
    production_semantics: bool = True,
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    operations = len(values)
    return {
        "name": name,
        "operations": operations,
        "wall_time_ns": wall_ns,
        "throughput_ops_per_second": operations * 1_000_000_000 / wall_ns,
        "latency_ns": asdict(_latencies(values)),
        "durability": durability,
        "production_semantics": production_semantics,
        "notes": list(notes),
    }


def _policy() -> PolicySpec:
    return PolicySpec(
        policy_id="benchmark-policy",
        policy_version="v1",
        dimensions=(ResourceDimension("operations", "count"),),
        machine=MachineSpec(
            machine_id="benchmark-worker",
            initial_state="ready",
            transitions=(TransitionSpec("step", "ready", "ready", (1,), "benchmark.step"),),
        ),
        max_lease_ttl_ns=1_000_000_000_000_000_000,
        receipt_ttl_ns=60_000_000_000,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=64,
    )


def _identity(subject: str, *scopes: str) -> IdentityContext:
    return IdentityContext(subject, "benchmark", frozenset(scopes))


def _service(
    path: Path,
    warden_id: str,
    *,
    budget: int,
    share: int,
    clock: ManualClock,
    registry: PublicKeyRegistry,
) -> tuple[SQLiteStorage, WardenService]:
    signer = Ed25519Signer.generate(warden_id)
    store = SQLiteStorage.initialize(
        path,
        warden_id,
        (budget,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="benchmark",
        envelope_id="benchmark-envelope",
        initial_local_share=(share,),
        receipt_ttl_ns=60_000_000_000,
        transfer_gap_window=64,
    )
    registry.register_signer(signer)
    return store, WardenService(store, signer=signer, clock=clock, trust_registry=registry)


def _time_calls(calls: Iterable[Callable[[], object]]) -> tuple[list[int], int]:
    samples: list[int] = []
    wall_start = time.perf_counter_ns()
    for call in calls:
        start = time.perf_counter_ns()
        call()
        samples.append(time.perf_counter_ns() - start)
    return samples, time.perf_counter_ns() - wall_start


def _authorize_benchmark(directory: Path, iterations: int, warmup: int) -> dict[str, Any]:
    total = iterations + warmup
    clock = ManualClock(BENCHMARK_CLOCK_NS)
    registry = PublicKeyRegistry(clock=clock)
    store, service = _service(
        directory / "authorize.sqlite3",
        "warden-authorize",
        budget=total + 8,
        share=total + 8,
        clock=clock,
        registry=registry,
    )
    try:
        policy = _policy()
        service.register_policy(policy)
        identity = _identity("benchmark-agent", "lets.lease.issue")
        grant = service.issue_root(
            request_id="benchmark-authorize-root",
            identity=identity,
            tenant_id="benchmark",
            envelope_id="benchmark-envelope",
            subject_id="benchmark-agent",
            allocation=(total,),
            capabilities={"benchmark.step"},
            policy_digest=policy.digest,
            ttl_ns=1_000_000_000_000_000,
        )

        def authorize(index: int) -> None:
            service.authorize(
                request_id=f"benchmark-authorize-{index:012d}",
                identity=identity,
                lease_id=grant.lease_id,
                transition="step",
                audience="benchmark-executor",
                nonce=f"benchmark-nonce-{index:012d}",
                expected_sequence=index,
            )

        for index in range(warmup):
            authorize(index)
        calls = (lambda index=index: authorize(index) for index in range(warmup, total))
        samples, wall_ns = _time_calls(calls)
        result = _measurement(
            "warden.authorize.full_fsync",
            samples,
            wall_ns,
            durability="SQLite WAL, synchronous=FULL, one transaction per authorization",
            notes=("Includes validation, policy evaluation, Ed25519 signing, audit, and commit.",),
        )
        result["conservation_healthy"] = service.invariant_snapshot(
            identity=_identity("benchmark-auditor")
        ).healthy
        return result
    finally:
        store.close()


def _transfer_benchmarks(directory: Path, iterations: int, warmup: int) -> list[dict[str, Any]]:
    total = iterations + warmup
    clock = ManualClock(BENCHMARK_CLOCK_NS)
    registry = PublicKeyRegistry(clock=clock)
    source_store, source = _service(
        directory / "transfer-source.sqlite3",
        "warden-source",
        budget=total + 8,
        share=total + 8,
        clock=clock,
        registry=registry,
    )
    target_store, target = _service(
        directory / "transfer-target.sqlite3",
        "warden-target",
        budget=total + 8,
        share=0,
        clock=clock,
        registry=registry,
    )
    try:
        policy = _policy()
        digest = source.register_policy(policy)
        target.register_policy(policy)
        source_identity = _identity("warden-source")
        target_identity = _identity("warden-target")
        measured: list[tuple[int, int, int]] = []
        wall_start = time.perf_counter_ns()
        for index in range(total):
            start = time.perf_counter_ns()
            voucher = source.prepare_transfer(
                request_id=f"benchmark-transfer-{index:012d}",
                identity=source_identity,
                tenant_id="benchmark",
                envelope_id="benchmark-envelope",
                target_warden="warden-target",
                amount=(1,),
                policy_digest=digest,
            )
            prepared = time.perf_counter_ns()
            acknowledgement = target.accept_transfer(
                identity=target_identity,
                voucher=voucher,
            )
            accepted = time.perf_counter_ns()
            source.finalize_transfer(
                identity=source_identity,
                acknowledgement=acknowledgement,
            )
            finalized = time.perf_counter_ns()
            if index >= warmup:
                measured.append((prepared - start, accepted - prepared, finalized - accepted))
        wall_ns = time.perf_counter_ns() - wall_start
        # Remove warm-up time from throughput by using the sum of measured stage durations.
        measured_wall_ns = sum(sum(stage) for stage in measured)
        names = ("prepare", "accept", "finalize")
        results = [
            _measurement(
                f"transfer.{name}.full_fsync",
                [row[position] for row in measured],
                sum(row[position] for row in measured),
                durability="SQLite WAL, synchronous=FULL, one transaction per stage",
                notes=(
                    "Ed25519 signing is included."
                    if name != "finalize"
                    else "Peer signature verification is included.",
                ),
            )
            for position, name in enumerate(names)
        ]
        results.append(
            _measurement(
                "transfer.round_trip.full_fsync",
                [sum(row) for row in measured],
                measured_wall_ns,
                durability="Three SQLite WAL synchronous=FULL transactions across two stores",
                notes=(
                    "In-process protocol path; excludes HTTP and network transport latency.",
                    f"Raw loop including warm-up took {wall_ns} ns.",
                ),
            )
        )
        results[-1]["source_conservation_healthy"] = source.invariant_snapshot(
            identity=source_identity
        ).healthy
        results[-1]["target_conservation_healthy"] = target.invariant_snapshot(
            identity=target_identity
        ).healthy
        return results
    finally:
        source_store.close()
        target_store.close()


def _receipt(
    signer: Ed25519Signer,
    *,
    index: int,
    policy_digest: str,
    machine_digest: str,
) -> Receipt:
    unsigned = Receipt(
        tenant_id="benchmark",
        envelope_id="benchmark-envelope",
        config_epoch=1,
        receipt_id=f"receipt-{index:012d}",
        request_id=f"request-{index:012d}",
        warden_id=signer.warden_id,
        key_id=signer.key_id,
        policy_id="benchmark-policy",
        policy_version="v1",
        policy_digest=policy_digest,
        machine_digest=machine_digest,
        lease_id=f"lease-{index:012d}",
        lineage_id=f"lineage-{index:012d}",
        subject_id="benchmark-agent",
        executor_audience="benchmark-executor",
        transition="step",
        source_state="ready",
        target_state="ready",
        cost=(1,),
        resulting_sequence=1,
        evidence_digest=None,
        nonce=f"executor-nonce-{index:012d}",
        issued_at_ns=BENCHMARK_CLOCK_NS - 1,
        expires_at_ns=BENCHMARK_CLOCK_NS + 60_000_000_000,
    )
    return replace(
        unsigned,
        signature=b64url_encode(signer.sign(canonical_json(unsigned.unsigned_payload()))),
    )


def _executor_benchmarks(directory: Path, iterations: int, warmup: int) -> list[dict[str, Any]]:
    total = iterations + warmup
    clock = ManualClock(BENCHMARK_CLOCK_NS)
    signer = Ed25519Signer.generate("warden-executor-source")
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    policy = _policy()
    verifier = ReceiptVerifier(
        registry,
        SQLiteReceiptReplayStore.initialize(
            directory / "executor-replay.sqlite3",
            allow_unanchored=True,
        ),
        ExecutorPolicy(
            audience="benchmark-executor",
            tenant_id="benchmark",
            envelope_id="benchmark-envelope",
            config_epoch=1,
            allowed_policy_digests=frozenset({policy.digest}),
            allowed_machine_digests=frozenset({policy.machine.digest}),
            trusted_wardens=frozenset({signer.warden_id}),
        ),
        clock=clock,
    )
    receipts = [
        _receipt(
            signer,
            index=index,
            policy_digest=policy.digest,
            machine_digest=policy.machine.digest,
        )
        for index in range(total)
    ]

    for receipt in receipts[:warmup]:
        verifier.verify(receipt)
    verify_calls = (
        lambda receipt=receipt: verifier.verify(receipt) for receipt in receipts[warmup:]
    )
    verify_samples, verify_wall = _time_calls(verify_calls)

    # Claims use every receipt exactly once; the warm-up claims are intentionally durable too.
    for receipt in receipts[:warmup]:
        verifier.verify_and_claim(receipt)
    claim_calls = (
        lambda receipt=receipt: verifier.verify_and_claim(receipt) for receipt in receipts[warmup:]
    )
    claim_samples, claim_wall = _time_calls(claim_calls)
    return [
        _measurement(
            "executor.verify.signature_only",
            verify_samples,
            verify_wall,
            durability="No write; Ed25519 and policy/time validation only",
        ),
        _measurement(
            "executor.verify_and_claim.full_fsync",
            claim_samples,
            claim_wall,
            durability="SQLite WAL, synchronous=FULL, one replay claim transaction per receipt",
            notes=(
                "Includes verification, expiry pruning, nonce claim, and lease watermark update.",
            ),
        ),
    ]


def _concurrent_benchmark(
    directory: Path,
    iterations: int,
    warmup: int,
    workers: int,
) -> dict[str, Any]:
    per_worker = max(1, iterations // workers)
    measured_operations = per_worker * workers
    total_per_worker = per_worker + warmup
    budget = total_per_worker * workers + workers + 8
    clock = ManualClock(BENCHMARK_CLOCK_NS)
    registry = PublicKeyRegistry(clock=clock)
    store, service = _service(
        directory / "contention.sqlite3",
        "warden-contention",
        budget=budget,
        share=budget,
        clock=clock,
        registry=registry,
    )
    try:
        policy = _policy()
        service.register_policy(policy)
        leases = []
        identities = []
        for worker in range(workers):
            identity = _identity(f"worker-{worker}", "lets.lease.issue")
            identities.append(identity)
            leases.append(
                service.issue_root(
                    request_id=f"contention-root-{worker}",
                    identity=identity,
                    tenant_id="benchmark",
                    envelope_id="benchmark-envelope",
                    subject_id=f"worker-{worker}",
                    allocation=(total_per_worker,),
                    capabilities={"benchmark.step"},
                    policy_digest=policy.digest,
                    ttl_ns=1_000_000_000_000_000,
                )
            )

        barrier = threading.Barrier(workers + 1)

        def run_worker(worker: int) -> list[int]:
            identity = identities[worker]
            lease = leases[worker]
            for index in range(warmup):
                service.authorize(
                    request_id=f"contention-warmup-{worker}-{index:08d}",
                    identity=identity,
                    lease_id=lease.lease_id,
                    transition="step",
                    audience="benchmark-executor",
                    nonce=f"contention-warmup-nonce-{worker}-{index:08d}",
                    expected_sequence=index,
                )
            barrier.wait()
            values = []
            for index in range(warmup, total_per_worker):
                start = time.perf_counter_ns()
                service.authorize(
                    request_id=f"contention-{worker}-{index:08d}",
                    identity=identity,
                    lease_id=lease.lease_id,
                    transition="step",
                    audience="benchmark-executor",
                    nonce=f"contention-nonce-{worker}-{index:08d}",
                    expected_sequence=index,
                )
                values.append(time.perf_counter_ns() - start)
            return values

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(run_worker, worker) for worker in range(workers)]
            start = time.perf_counter_ns()
            barrier.wait()
            samples = [sample for future in futures for sample in future.result()]
            wall_ns = time.perf_counter_ns() - start
        result = _measurement(
            "warden.authorize.concurrent_contention.full_fsync",
            samples,
            wall_ns,
            durability="SQLite WAL, synchronous=FULL, one transaction per authorization",
            notes=(
                f"{workers} threads use independent leases in one warden database.",
                "Latency includes SQLite writer-lock wait time.",
            ),
        )
        result["requested_operations"] = iterations
        result["measured_operations"] = measured_operations
        result["workers"] = workers
        result["conservation_healthy"] = service.invariant_snapshot(
            identity=_identity("benchmark-auditor")
        ).healthy
        return result
    finally:
        store.close()


def _sqlite_diagnostic(
    path: Path,
    *,
    iterations: int,
    synchronous: str,
    batch: bool,
) -> dict[str, Any]:
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(f"PRAGMA synchronous={synchronous}")
        connection.execute("CREATE TABLE events(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)")
        samples: list[int] = []
        wall_start = time.perf_counter_ns()
        if batch:
            start = time.perf_counter_ns()
            connection.execute("BEGIN IMMEDIATE")
            connection.executemany(
                "INSERT INTO events(payload) VALUES (?)",
                ((b"benchmark",) for _ in range(iterations)),
            )
            connection.commit()
            elapsed = time.perf_counter_ns() - start
            samples = [max(1, elapsed // iterations)] * iterations
        else:
            for _ in range(iterations):
                start = time.perf_counter_ns()
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("INSERT INTO events(payload) VALUES (?)", (b"benchmark",))
                connection.commit()
                samples.append(time.perf_counter_ns() - start)
        wall_ns = time.perf_counter_ns() - wall_start
        mode = str(connection.execute("PRAGMA synchronous").fetchone()[0])
        result = _measurement(
            f"diagnostic.sqlite.{synchronous.lower()}.{'batch' if batch else 'per_commit'}",
            samples,
            wall_ns,
            durability=(
                f"Raw SQLite WAL synchronous={synchronous}; "
                f"{'one batch' if batch else 'one commit per row'}"
            ),
            production_semantics=False,
            notes=(
                "Diagnostic only: bypasses LETS validation, signatures, audit, and service API.",
                "NORMAL and batching are not production LETS defaults.",
            ),
        )
        result["sqlite_synchronous_numeric"] = mode
        return result
    finally:
        connection.close()


def _git_revision(root: Path) -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _git_dirty(root: Path) -> bool | None:
    try:
        return bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )
    except (OSError, subprocess.CalledProcessError):
        return None


def _environment(root: Path) -> dict[str, Any]:
    return {
        "python": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_count": os.cpu_count(),
        "sqlite": sqlite3.sqlite_version,
        "git_revision": _git_revision(root),
        "git_worktree_dirty": _git_dirty(root),
        "working_directory": str(root),
    }


def run_benchmarks(
    workspace: Path,
    *,
    iterations: int,
    warmup: int,
    workers: int,
    include_diagnostics: bool = True,
) -> dict[str, Any]:
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    if warmup < 0:
        raise ValueError("warmup must be non-negative")
    if workers <= 0:
        raise ValueError("workers must be positive")
    root = Path(__file__).resolve().parents[1]
    workspace.mkdir(parents=True, exist_ok=True)
    production: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    with TemporaryDirectory(prefix="lets-benchmark-", dir=workspace) as temporary:
        directory = Path(temporary)
        production.append(_authorize_benchmark(directory, iterations, warmup))
        production.extend(_transfer_benchmarks(directory, iterations, warmup))
        production.extend(_executor_benchmarks(directory, iterations, warmup))
        production.append(_concurrent_benchmark(directory, iterations, warmup, workers))
        if include_diagnostics:
            diagnostic_iterations = max(10, iterations)
            diagnostics.extend(
                (
                    _sqlite_diagnostic(
                        directory / "diagnostic-full.sqlite3",
                        iterations=diagnostic_iterations,
                        synchronous="FULL",
                        batch=False,
                    ),
                    _sqlite_diagnostic(
                        directory / "diagnostic-full-batch.sqlite3",
                        iterations=diagnostic_iterations,
                        synchronous="FULL",
                        batch=True,
                    ),
                    _sqlite_diagnostic(
                        directory / "diagnostic-normal.sqlite3",
                        iterations=diagnostic_iterations,
                        synchronous="NORMAL",
                        batch=False,
                    ),
                )
            )
    return {
        "schema": RESULT_SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": _environment(root),
        "configuration": {
            "iterations": iterations,
            "warmup": warmup,
            "workers": workers,
            "production_storage": "SQLite WAL synchronous=FULL",
        },
        "production_results": production,
        "non_production_diagnostics": diagnostics,
    }


def write_results(result: dict[str, Any], output: Path) -> tuple[Path, Path]:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    csv_path = output.with_suffix(".csv")
    rows = [*result["production_results"], *result["non_production_diagnostics"]]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "name",
                "production_semantics",
                "operations",
                "throughput_ops_per_second",
                "minimum_ns",
                "median_ns",
                "mean_ns",
                "p95_ns",
                "p99_ns",
                "maximum_ns",
                "wall_time_ns",
                "durability",
            ),
        )
        writer.writeheader()
        for row in rows:
            latency = row["latency_ns"]
            writer.writerow(
                {
                    "name": row["name"],
                    "production_semantics": row["production_semantics"],
                    "operations": row["operations"],
                    "throughput_ops_per_second": row["throughput_ops_per_second"],
                    "minimum_ns": latency["minimum"],
                    "median_ns": latency["median"],
                    "mean_ns": latency["mean"],
                    "p95_ns": latency["p95"],
                    "p99_ns": latency["p99"],
                    "maximum_ns": latency["maximum"],
                    "wall_time_ns": row["wall_time_ns"],
                    "durability": row["durability"],
                }
            )
    return output, csv_path


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--workers", type=int, default=min(4, os.cpu_count() or 1))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/results/latest.json"),
    )
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--no-diagnostics", action="store_true")
    return parser.parse_args()


def main() -> None:
    arguments = _arguments()
    workspace = Path("benchmarks/results")
    profiler = cProfile.Profile() if arguments.profile is not None else None
    if profiler is not None:
        profiler.enable()
    result = run_benchmarks(
        workspace,
        iterations=arguments.iterations,
        warmup=arguments.warmup,
        workers=arguments.workers,
        include_diagnostics=not arguments.no_diagnostics,
    )
    if profiler is not None:
        profiler.disable()
        arguments.profile.parent.mkdir(parents=True, exist_ok=True)
        profiler.dump_stats(arguments.profile)
        stream = io.StringIO()
        import pstats

        pstats.Stats(profiler, stream=stream).strip_dirs().sort_stats("cumulative").print_stats(30)
        result["profile_summary"] = stream.getvalue()
        result["profile_path"] = str(arguments.profile)
    json_path, csv_path = write_results(result, arguments.output)
    print(json.dumps({"json": str(json_path), "csv": str(csv_path)}, sort_keys=True))


if __name__ == "__main__":
    main()
