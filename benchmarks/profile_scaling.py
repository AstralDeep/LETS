"""Measure LETS authorization and integrity-scan scaling by database size."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from benchmarks.run import BENCHMARK_CLOCK_NS, _environment, _identity, _policy, _service
from lets.clock import ManualClock
from lets.crypto import PublicKeyRegistry


def _summary(samples: list[int]) -> dict[str, int]:
    ordered = sorted(samples)
    return {
        "minimum": ordered[0],
        "median": int(statistics.median(ordered)),
        "mean": int(statistics.fmean(ordered)),
        "p95": ordered[max(0, (len(ordered) * 95 + 99) // 100 - 1)],
        "maximum": ordered[-1],
    }


def profile_scaling(workspace: Path, counts: tuple[int, ...]) -> dict[str, Any]:
    if not counts or any(count <= 0 for count in counts) or tuple(sorted(set(counts))) != counts:
        raise ValueError("counts must be unique positive integers in ascending order")
    workspace.mkdir(parents=True, exist_ok=True)
    clock = ManualClock(BENCHMARK_CLOCK_NS)
    registry = PublicKeyRegistry(clock=clock)
    observations: list[dict[str, Any]] = []
    with TemporaryDirectory(prefix="lets-scaling-", dir=workspace) as temporary:
        store, service = _service(
            Path(temporary) / "scaling.sqlite3",
            "warden-scaling",
            budget=counts[-1] + 8,
            share=counts[-1] + 8,
            clock=clock,
            registry=registry,
        )
        try:
            policy = _policy()
            service.register_policy(policy)
            identity = _identity("scaling-agent", "lets.lease.issue")
            grant = service.issue_root(
                request_id="scaling-root",
                identity=identity,
                tenant_id="benchmark",
                envelope_id="benchmark-envelope",
                subject_id="scaling-agent",
                allocation=(counts[-1],),
                capabilities={"benchmark.step"},
                policy_digest=policy.digest,
                ttl_ns=1_000_000_000_000_000,
            )
            previous = 0
            for target in counts:
                authorizations: list[int] = []
                for index in range(previous, target):
                    start = time.perf_counter_ns()
                    service.authorize(
                        request_id=f"scaling-authorize-{index:012d}",
                        identity=identity,
                        lease_id=grant.lease_id,
                        transition="step",
                        audience="scaling-executor",
                        nonce=f"scaling-nonce-{index:012d}",
                        expected_sequence=index,
                    )
                    authorizations.append(time.perf_counter_ns() - start)
                previous = target
                with store.read() as transaction:
                    connection = transaction.connection
                    scans = []
                    for _ in range(30):
                        start = time.perf_counter_ns()
                        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
                        scans.append(time.perf_counter_ns() - start)
                        if violations:
                            raise RuntimeError("benchmark database has foreign-key violations")
                    counts_by_table = {
                        table: int(
                            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                        )
                        for table in (
                            "leases",
                            "receipts",
                            "idempotency",
                            "audit_log",
                            "audit_outbox",
                        )
                    }
                observations.append(
                    {
                        "receipt_rows": target,
                        "rows": counts_by_table,
                        "authorize_full_fsync_latency_ns": _summary(authorizations),
                        "explicit_foreign_key_check_latency_ns": _summary(scans),
                    }
                )
        finally:
            store.close()
    return {
        "schema": "lets.storage-scaling-profile/v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": _environment(Path(__file__).resolve().parents[1]),
        "counts": list(counts),
        "durability": "SQLite WAL synchronous=FULL",
        "foreign_key_enforcement": (
            "PRAGMA foreign_keys=ON on every connection; full foreign_key_check is diagnostic"
        ),
        "observations": observations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--counts", type=int, nargs="+", default=(10, 100, 500, 1_000))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/results/scaling.json"),
    )
    arguments = parser.parse_args()
    result = profile_scaling(Path("benchmarks/results"), tuple(arguments.counts))
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": str(arguments.output)}, sort_keys=True))


if __name__ == "__main__":
    main()
