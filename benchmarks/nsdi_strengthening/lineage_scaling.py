"""Measure lineage depth/branching costs with disclosed bounded tree shapes."""

from __future__ import annotations

import argparse
import csv
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import PolicyError
from lets.models import IdentityContext
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage

from .common import (
    environment_identity,
    latency_summary,
    source_identity,
    utc_now,
    write_json,
    write_text,
)

SCHEMA = "lets.lineage-scaling/v1"
CLOCK_NS = 1_900_000_000_000_000_000


def _policy() -> PolicySpec:
    return PolicySpec(
        policy_id="lineage-policy",
        policy_version="v1",
        dimensions=(ResourceDimension("actions", "count"),),
        machine=MachineSpec(
            machine_id="lineage-worker",
            initial_state="ready",
            transitions=(TransitionSpec("act", "ready", "ready", (1,), "lineage.act"),),
        ),
        max_lease_ttl_ns=1_000_000_000_000_000_000,
        receipt_ttl_ns=60_000_000_000,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=8,
    )


def _tree_nodes(depth: int, branching: int) -> int:
    return depth + 1 if branching == 1 else (branching ** (depth + 1) - 1) // (branching - 1)


def _file_bytes(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    for label, candidate in (
        ("database", path),
        ("wal", Path(f"{path}-wal")),
        ("shared_memory", Path(f"{path}-shm")),
    ):
        try:
            values[f"{label}_bytes"] = candidate.stat().st_size
        except OSError:
            values[f"{label}_bytes"] = 0
    values["total_bytes"] = sum(values.values())
    return values


def _run_cell(
    directory: Path,
    *,
    shape: Literal["spine_fanout", "complete_tree"],
    depth: int,
    branching: int,
    max_workers: int,
) -> dict[str, object]:
    if depth <= 0 or branching <= 0:
        raise ValueError("depth and branching must be positive")
    leaves_expected = depth * (branching - 1) + 1 if shape == "spine_fanout" else branching**depth
    node_count_expected = (
        1 + depth * branching if shape == "spine_fanout" else _tree_nodes(depth, branching)
    )
    budget = leaves_expected
    tenant = f"lineage-{shape.replace('_', '-')}"
    envelope = f"lineage-d{depth}-b{branching}"
    warden = f"warden-d{depth}-b{branching}-{shape.replace('_', '-')}"
    path = directory / f"{shape}-d{depth}-b{branching}.sqlite3"
    signer = Ed25519Signer.generate(warden)
    clock = ManualClock(CLOCK_NS)
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    policy = _policy()
    identity = IdentityContext("lineage-admin", tenant, frozenset({"lets.admin"}))
    options: dict[str, object] = {
        "signing_key_id": signer.key_id,
        "signing_public_key": signer.public_key_bytes,
        "tenant_id": tenant,
        "envelope_id": envelope,
        "initial_local_share": (budget,),
        "receipt_ttl_ns": policy.receipt_ttl_ns,
        "max_clock_uncertainty_ns": 0,
        "transfer_gap_window": policy.transfer_gap_window,
    }
    store = SQLiteStorage.initialize(path, warden, (budget,), **options)
    service = WardenService(store, signer=signer, clock=clock, trust_registry=registry)
    service.register_policy(policy)
    grant = service.issue_root(
        request_id="lineage-root",
        identity=identity,
        tenant_id=tenant,
        envelope_id=envelope,
        subject_id="root",
        allocation=(budget,),
        capabilities={"lineage.act"},
        policy_digest=policy.digest,
        ttl_ns=1_000_000_000_000_000,
    )
    sequences = {grant.lease_id: 0}
    leaves: list[str] = []
    spawn_samples: list[int] = []
    spawned = 0

    def spawn(parent_id: str, allocation: int, level: int, ordinal: int) -> str:
        nonlocal spawned
        started = time.perf_counter_ns()
        child = service.spawn(
            request_id=f"spawn-{level:02d}-{spawned:06d}",
            identity=identity,
            parent_id=parent_id,
            subject_id=f"node-{level:02d}-{spawned:06d}",
            allocation=(allocation,),
            capabilities={"lineage.act"},
            ttl_ns=1_000_000_000_000_000,
            policy_digest=policy.digest,
            expected_sequence=sequences[parent_id],
        )
        spawn_samples.append(time.perf_counter_ns() - started)
        spawned += 1
        sequences[parent_id] += 1
        sequences[child.lease_id] = 0
        del ordinal
        return child.lease_id

    if shape == "spine_fanout":
        spine = grant.lease_id
        for level in range(1, depth + 1):
            for ordinal in range(max(0, branching - 1)):
                leaves.append(spawn(spine, 1, level, ordinal))
            remaining = (depth - level) * (branching - 1) + 1
            spine = spawn(spine, remaining, level, branching - 1)
        leaves.append(spine)
    else:
        frontier = [grant.lease_id]
        for level in range(1, depth + 1):
            allocation = branching ** (depth - level)
            next_frontier: list[str] = []
            for parent_id in frontier:
                for ordinal in range(branching):
                    next_frontier.append(spawn(parent_id, allocation, level, ordinal))
            frontier = next_frontier
        leaves = frontier

    if len(leaves) != leaves_expected or spawned + 1 != node_count_expected:
        raise AssertionError("constructed tree shape differs from declared size")

    def authorize(item: tuple[int, str]) -> int:
        index, lease_id = item
        started = time.perf_counter_ns()
        service.authorize(
            request_id=f"authorize-{index:08d}",
            identity=identity,
            lease_id=lease_id,
            transition="act",
            audience="lineage-executor",
            nonce=f"lineage-nonce-{index:012d}",
            expected_state="ready",
            expected_sequence=0,
        )
        return time.perf_counter_ns() - started

    workers = min(max_workers, len(leaves))
    wall_started = time.perf_counter_ns()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        authorize_samples = list(executor.map(authorize, enumerate(leaves)))
    authorize_wall_ns = time.perf_counter_ns() - wall_started
    live_sizes = _file_bytes(path)
    with store.read() as transaction:
        connection = transaction.connection
        table_counts = {
            table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in ("leases", "receipts", "audit_log")
        }
    invariant = service.invariant_snapshot(identity=identity)
    if not invariant.healthy or invariant.consumed != (leaves_expected,):
        raise AssertionError("lineage cell failed conservation or consumption check")
    store.checkpoint(truncate=True)
    checkpointed_sizes = _file_bytes(path)
    store.close()

    reopen_started = time.perf_counter_ns()
    reopened = SQLiteStorage(path, warden, (budget,), **options)
    recovered = WardenService(reopened, signer=signer, clock=clock, trust_registry=registry)
    recovery_snapshot = recovered.invariant_snapshot(identity=identity)
    reopen_ns = time.perf_counter_ns() - reopen_started
    integrity = reopened.pragma_integrity_check()
    reopened.close()
    if not recovery_snapshot.healthy or integrity != ("ok",):
        raise AssertionError("lineage cell did not reopen cleanly")

    return {
        "status": "passed",
        "shape": shape,
        "depth": depth,
        "branching_factor": branching,
        "nodes": node_count_expected,
        "leaves_authorized": leaves_expected,
        "concurrent_workers": workers,
        "spawn_samples_ns": spawn_samples,
        "authorize_samples_ns": authorize_samples,
        "spawn_latency_ns": latency_summary(spawn_samples),
        "authorize_latency_ns": latency_summary(authorize_samples),
        "authorize_wall_ns": authorize_wall_ns,
        "authorize_throughput_ops_per_second": (
            len(authorize_samples) * 1_000_000_000 / authorize_wall_ns
        ),
        "state_sizes_live": live_sizes,
        "state_sizes_after_checkpoint": checkpointed_sizes,
        "table_rows": table_counts,
        "reopen_latency_ns": reopen_ns,
        "reopen_integrity": list(integrity),
        "final_accounting": {
            "initial_share": list(invariant.initial_share),
            "free_pool": list(invariant.free_pool),
            "lease_residual": list(invariant.lease_residual),
            "consumed": list(invariant.consumed),
            "healthy": invariant.healthy,
        },
    }


def _depth_limit_probe(directory: Path) -> dict[str, object]:
    depth_limit = 64
    budget = 1
    tenant = "lineage-depth-limit"
    envelope = "lineage-depth-limit"
    warden = "warden-depth-limit"
    signer = Ed25519Signer.generate(warden)
    clock = ManualClock(CLOCK_NS)
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    policy = _policy()
    identity = IdentityContext("depth-admin", tenant, frozenset({"lets.admin"}))
    path = directory / "depth-limit.sqlite3"
    store = SQLiteStorage.initialize(
        path,
        warden,
        (budget,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id=tenant,
        envelope_id=envelope,
        initial_local_share=(budget,),
        receipt_ttl_ns=policy.receipt_ttl_ns,
        max_clock_uncertainty_ns=policy.max_clock_uncertainty_ns,
        transfer_gap_window=policy.transfer_gap_window,
    )
    try:
        service = WardenService(store, signer=signer, clock=clock, trust_registry=registry)
        service.register_policy(policy)
        root = service.issue_root(
            request_id="depth-root",
            identity=identity,
            tenant_id=tenant,
            envelope_id=envelope,
            subject_id="depth-root",
            allocation=(1,),
            capabilities={"lineage.act"},
            policy_digest=policy.digest,
            ttl_ns=1_000_000_000_000_000,
        )
        parent = root.lease_id
        for level in range(1, depth_limit + 1):
            child = service.spawn(
                request_id=f"depth-{level:03d}",
                identity=identity,
                parent_id=parent,
                subject_id=f"depth-node-{level:03d}",
                allocation=(1,),
                capabilities={"lineage.act"},
                ttl_ns=1_000_000_000_000_000,
                policy_digest=policy.digest,
                expected_sequence=0,
            )
            parent = child.lease_id
        denied_code = None
        try:
            service.spawn(
                request_id="depth-065",
                identity=identity,
                parent_id=parent,
                subject_id="depth-node-065",
                allocation=(1,),
                capabilities={"lineage.act"},
                ttl_ns=1_000_000_000_000_000,
                policy_digest=policy.digest,
                expected_sequence=0,
            )
        except PolicyError as exc:
            denied_code = exc.code
        if denied_code != "policy_denied":
            raise AssertionError("lineage depth 65 was not rejected")
        return {
            "maximum_accepted_depth": depth_limit,
            "next_depth": depth_limit + 1,
            "next_depth_rejected": True,
            "error_code": denied_code,
        }
    finally:
        store.close()


def run_lineage_scaling(
    workspace: Path,
    *,
    depths: tuple[int, ...] = (1, 2, 4, 8),
    branching_factors: tuple[int, ...] = (1, 2, 4, 8),
    complete_node_cap: int = 5_000,
    max_workers: int = 16,
    include_depth_limit_probe: bool = True,
) -> dict[str, object]:
    if not depths or not branching_factors or complete_node_cap <= 0 or max_workers <= 0:
        raise ValueError("lineage configuration values must be positive")
    workspace.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    with TemporaryDirectory(prefix="lineage-scaling-", dir=workspace) as temporary:
        directory = Path(temporary)
        for depth in depths:
            for branching in branching_factors:
                rows.append(
                    _run_cell(
                        directory,
                        shape="spine_fanout",
                        depth=depth,
                        branching=branching,
                        max_workers=max_workers,
                    )
                )
                nodes = _tree_nodes(depth, branching)
                if nodes > complete_node_cap:
                    rows.append(
                        {
                            "status": "skipped_node_cap",
                            "shape": "complete_tree",
                            "depth": depth,
                            "branching_factor": branching,
                            "nodes": nodes,
                            "leaves_authorized": branching**depth,
                            "complete_node_cap": complete_node_cap,
                        }
                    )
                else:
                    rows.append(
                        _run_cell(
                            directory,
                            shape="complete_tree",
                            depth=depth,
                            branching=branching,
                            max_workers=max_workers,
                        )
                    )
        depth_probe = _depth_limit_probe(directory) if include_depth_limit_probe else None
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "source": source_identity(),
        "environment": environment_identity(),
        "configuration": {
            "depths": list(depths),
            "branching_factors": list(branching_factors),
            "complete_node_cap": complete_node_cap,
            "max_workers": max_workers,
            "spine_fanout_definition": (
                "At every level one child continues the spine and b-1 siblings remain leaves; "
                "nodes=1+d*b. This covers all requested depth/fanout cells without implying a "
                "complete b^d tree."
            ),
        },
        "rows": rows,
        "depth_limit_probe": depth_probe,
    }


def _markdown(result: dict[str, object]) -> str:
    lines = [
        "# Lineage depth and branching results",
        "",
        "All 16 depth/fanout combinations use the disclosed spine-and-fanout shape. Complete "
        "trees are also run when their calculated node count is at most the configured cap; "
        "larger cells are explicitly skipped.",
        "",
        "| Shape | Depth | Branch | Nodes | Leaves/actions | Spawn p50 (ms) | Auth p50 (ms) | "
        "Auth p95 (ms) | Throughput (ops/s) | DB after checkpoint (KiB) | Reopen (ms) | Status |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for row in result["rows"]:
        if row["status"] != "passed":
            lines.append(
                f"| {row['shape']} | {row['depth']} | {row['branching_factor']} | "
                f"{row['nodes']} | {row['leaves_authorized']} | — | — | — | — | — | — | "
                f"{row['status']} |"
            )
            continue
        lines.append(
            f"| {row['shape']} | {row['depth']} | {row['branching_factor']} | "
            f"{row['nodes']} | {row['leaves_authorized']} | "
            f"{row['spawn_latency_ns']['p50_ns'] / 1_000_000:.3f} | "
            f"{row['authorize_latency_ns']['p50_ns'] / 1_000_000:.3f} | "
            f"{row['authorize_latency_ns']['p95_ns'] / 1_000_000:.3f} | "
            f"{row['authorize_throughput_ops_per_second']:.1f} | "
            f"{row['state_sizes_after_checkpoint']['total_bytes'] / 1024:.1f} | "
            f"{row['reopen_latency_ns'] / 1_000_000:.3f} | passed |"
        )
    probe = result.get("depth_limit_probe")
    if probe:
        lines.extend(
            [
                "",
                "## Runtime lineage-depth boundary",
                "",
                f"A chain at depth {probe['maximum_accepted_depth']} was accepted; depth "
                f"{probe['next_depth']} was rejected with `{probe['error_code']}`.",
            ]
        )
    return "\n".join(lines)


def _write_csv(result: dict[str, object], path: Path, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing evidence: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = (
        "shape",
        "depth",
        "branching_factor",
        "nodes",
        "leaves_authorized",
        "status",
        "spawn_p50_ns",
        "spawn_p95_ns",
        "authorize_p50_ns",
        "authorize_p95_ns",
        "authorize_p99_ns",
        "authorize_throughput_ops_per_second",
        "state_bytes_after_checkpoint",
        "reopen_latency_ns",
    )
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in result["rows"]:
            passed = row["status"] == "passed"
            writer.writerow(
                {
                    "shape": row["shape"],
                    "depth": row["depth"],
                    "branching_factor": row["branching_factor"],
                    "nodes": row["nodes"],
                    "leaves_authorized": row["leaves_authorized"],
                    "status": row["status"],
                    "spawn_p50_ns": row["spawn_latency_ns"]["p50_ns"] if passed else "",
                    "spawn_p95_ns": row["spawn_latency_ns"]["p95_ns"] if passed else "",
                    "authorize_p50_ns": (row["authorize_latency_ns"]["p50_ns"] if passed else ""),
                    "authorize_p95_ns": (row["authorize_latency_ns"]["p95_ns"] if passed else ""),
                    "authorize_p99_ns": (row["authorize_latency_ns"]["p99_ns"] if passed else ""),
                    "authorize_throughput_ops_per_second": (
                        row["authorize_throughput_ops_per_second"] if passed else ""
                    ),
                    "state_bytes_after_checkpoint": (
                        row["state_sizes_after_checkpoint"]["total_bytes"] if passed else ""
                    ),
                    "reopen_latency_ns": row["reopen_latency_ns"] if passed else "",
                }
            )


def write_outputs(result: dict[str, object], output_dir: Path, *, overwrite: bool) -> None:
    write_json(output_dir / "lineage-scaling.json", result, overwrite=overwrite)
    _write_csv(result, output_dir / "lineage-scaling.csv", overwrite=overwrite)
    write_text(output_dir / "LINEAGE-RESULTS.md", _markdown(result), overwrite=overwrite)


def _positive_tuple(values: list[int]) -> tuple[int, ...]:
    if not values or any(value <= 0 for value in values):
        raise argparse.ArgumentTypeError("values must be positive integers")
    return tuple(values)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/nsdi-strengthening-2026-08-31/lineage"),
    )
    parser.add_argument("--workspace", type=Path, default=Path("benchmarks/results"))
    parser.add_argument("--depths", type=int, nargs="+", default=[1, 2, 4, 8])
    parser.add_argument("--branching", type=int, nargs="+", default=[1, 2, 4, 8])
    parser.add_argument("--complete-node-cap", type=int, default=5_000)
    parser.add_argument("--max-workers", type=int, default=16)
    parser.add_argument("--skip-depth-limit-probe", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> None:
    arguments = _arguments()
    depths = _positive_tuple(arguments.depths)
    branching = _positive_tuple(arguments.branching)
    result = run_lineage_scaling(
        arguments.workspace,
        depths=depths,
        branching_factors=branching,
        complete_node_cap=arguments.complete_node_cap,
        max_workers=arguments.max_workers,
        include_depth_limit_probe=not arguments.skip_depth_limit_probe,
    )
    write_outputs(result, arguments.output_dir, overwrite=arguments.overwrite)
    print(json.dumps({"status": "passed", "output_dir": str(arguments.output_dir)}))


if __name__ == "__main__":
    main()
