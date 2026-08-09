"""A/B test an experimental SQLite keeper connection without changing LETS."""

from __future__ import annotations

import argparse
import json
import sqlite3
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from benchmarks.run import BENCHMARK_CLOCK_NS, _environment, _identity, _policy, _service
from lets.clock import ManualClock
from lets.crypto import PublicKeyRegistry


def _case(
    directory: Path,
    *,
    anchor: bool,
    trial: int,
    iterations: int,
    warmup: int,
) -> dict[str, Any]:
    total = iterations + warmup
    clock = ManualClock(BENCHMARK_CLOCK_NS)
    registry = PublicKeyRegistry(clock=clock)
    store, service = _service(
        directory / f"anchor-{trial}-{anchor}.sqlite3",
        f"warden-anchor-{trial}-{anchor}",
        budget=total + 8,
        share=total + 8,
        clock=clock,
        registry=registry,
    )
    keeper: sqlite3.Connection | None = None
    try:
        policy = _policy()
        service.register_policy(policy)
        identity = _identity("anchor-agent", "lets.lease.issue")
        grant = service.issue_root(
            request_id="anchor-root",
            identity=identity,
            tenant_id="benchmark",
            envelope_id="benchmark-envelope",
            subject_id="anchor-agent",
            allocation=(total,),
            capabilities={"benchmark.step"},
            policy_digest=policy.digest,
            ttl_ns=1_000_000_000_000_000,
        )
        if anchor:
            keeper = sqlite3.connect(store.path, isolation_level=None, cached_statements=256)
            keeper.execute("PRAGMA foreign_keys=ON")
            keeper.execute("PRAGMA busy_timeout=5000")
            keeper.execute("PRAGMA synchronous=FULL")
            keeper.execute("PRAGMA wal_autocheckpoint=1000")

        def authorize(index: int) -> None:
            service.authorize(
                request_id=f"anchor-authorize-{index:012d}",
                identity=identity,
                lease_id=grant.lease_id,
                transition="step",
                audience="anchor-executor",
                nonce=f"anchor-nonce-{index:012d}",
                expected_sequence=index,
            )

        for index in range(warmup):
            authorize(index)
        samples = []
        wall_start = time.perf_counter_ns()
        for index in range(warmup, total):
            start = time.perf_counter_ns()
            authorize(index)
            samples.append(time.perf_counter_ns() - start)
        wall_ns = time.perf_counter_ns() - wall_start
        samples.sort()
        return {
            "anchor": anchor,
            "trial": trial,
            "operations": iterations,
            "median_latency_ns": int(statistics.median(samples)),
            "p95_latency_ns": samples[max(0, (len(samples) * 95 + 99) // 100 - 1)],
            "throughput_ops_per_second": iterations * 1_000_000_000 / wall_ns,
            "conservation_healthy": service.invariant_snapshot(
                identity=_identity("anchor-auditor")
            ).healthy,
        }
    finally:
        if keeper is not None:
            keeper.close()
        store.close()


def profile_anchor(
    workspace: Path,
    *,
    trials: int,
    iterations: int,
    warmup: int,
) -> dict[str, Any]:
    if trials <= 0 or iterations <= 0 or warmup < 0:
        raise ValueError("trials/iterations must be positive and warmup non-negative")
    workspace.mkdir(parents=True, exist_ok=True)
    cases = []
    with TemporaryDirectory(prefix="lets-anchor-", dir=workspace) as temporary:
        directory = Path(temporary)
        for trial in range(trials):
            order = (True, False) if trial % 2 == 0 else (False, True)
            for anchor in order:
                cases.append(
                    _case(
                        directory,
                        anchor=anchor,
                        trial=trial,
                        iterations=iterations,
                        warmup=warmup,
                    )
                )
    medians = {
        str(anchor).lower(): int(
            statistics.median(
                case["median_latency_ns"] for case in cases if case["anchor"] is anchor
            )
        )
        for anchor in (False, True)
    }
    baseline = medians["false"]
    experimental = medians["true"]
    return {
        "schema": "lets.sqlite-anchor-experiment/v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": _environment(Path(__file__).resolve().parents[1]),
        "configuration": {
            "trials": trials,
            "iterations_per_case": iterations,
            "warmup_per_case": warmup,
            "durability": "SQLite WAL synchronous=FULL in both cases",
            "trial_order": "alternating to reduce order bias",
        },
        "cases": cases,
        "median_of_trial_medians_ns": medians,
        "experimental_to_baseline_latency_ratio": experimental / baseline,
        "decision": (
            "reject_keeper_connection"
            if experimental >= baseline * 0.98
            else "candidate_for_implementation"
        ),
        "notes": [
            "The experimental anchor is read-capable but performs no queries or writes.",
            "Each LETS operation still uses its own connection and FULL commit.",
            "No source/runtime change is made by this experiment.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=4)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/results/anchor.json"),
    )
    arguments = parser.parse_args()
    result = profile_anchor(
        Path("benchmarks/results"),
        trials=arguments.trials,
        iterations=arguments.iterations,
        warmup=arguments.warmup,
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": str(arguments.output), "decision": result["decision"]}))


if __name__ == "__main__":
    main()
