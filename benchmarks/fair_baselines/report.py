"""Summarizes one or more E1 grids into headline metrics: pooled completion with seed-bootstrap
intervals, pre-break authorization latency, stranded budget, the safety totals, and the lease-tree
refresh costs of the LETS delegation variants, read through
analysis.py from the controller's run files (regenerating the flat CSVs with controller.assemble
when they are absent).
"""

from __future__ import annotations

import argparse
import statistics
import sys
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from benchmarks.fair_baselines.analysis import (
    NS_PER_S,
    GridData,
    RequestRow,
    load_grid,
    per_site_rows,
    pooled_bootstrap_ci,
    quantile,
    summary_rows,
    tree_builds,
)
from benchmarks.fair_baselines.common import (
    SystemSpec,
    resolve_topology,
    site_links,
    topology_order,
)
from benchmarks.fair_baselines.controller import assemble
from benchmarks.nsdi_strengthening.common import write_json, write_text

ROW_ORDER = (
    "lets",
    "lets-tree",
    "lets-anchored",
    "lets-anchored-restore",
    "lets-restore",
    "static-quota",
    "central-noretry",
    "central-retry",
    "raft-quorum",
)
ROW_LABELS = {
    "lets": "LETS",
    "lets-tree": "LETS, delegation tree",
    "lets-anchored": "LETS, rollback anchors",
    "lets-anchored-restore": "LETS, rollback anchors, stale restore",
    "lets-restore": "LETS, no anchors, stale restore",
    "static-quota": "Static per-site quotas",
    "central-noretry": "Central counter, no retry",
    "central-retry": "Central counter, retry",
    "raft-quorum": "Raft quorum counter",
}
LETS_GROUPS = frozenset(
    {"lets", "lets-tree", "lets-anchored", "lets-anchored-restore", "lets-restore"}
)


@dataclass(frozen=True, slots=True)
class CompletionCell:
    completion: float
    ci_low: float
    ci_high: float
    seeds: int

    @property
    def width_points(self) -> float:
        return 100 * (self.ci_high - self.ci_low)


@dataclass(frozen=True, slots=True)
class GridReduction:
    label: str
    load: float
    theta: float
    topologies: tuple[str, ...]
    systems: tuple[str, ...]
    completion: dict[str, dict[str, CompletionCell]]
    pre_break_p50_ms: dict[str, float]
    pre_break_s: float
    stranded_topology: str | None
    stranded_peak_units: dict[str, int]
    stranded_unit_seconds: dict[str, float]
    run_system_pairs: int
    max_authorized: int
    envelope: int
    all_safety_ok: bool
    all_effects_match: bool
    delegation: dict[str, dict[str, float | None]]


def row_key(system: str) -> str:
    spec = SystemSpec.parse(system)
    if spec.kind == "lets":
        if spec.restore_site is not None:
            return "lets-anchored-restore" if spec.anchored else "lets-restore"
        if spec.anchored:
            return "lets-anchored"
        return "lets-tree" if spec.delegates else "lets"
    if spec.kind != "central":
        return spec.kind
    return "central-retry" if spec.retry else "central-noretry"


def row_label(key: str, members: Sequence[str]) -> str:
    label = ROW_LABELS[key]
    if key != "lets-tree":
        return label
    shapes = sorted({(SystemSpec.parse(m).depth, SystemSpec.parse(m).fanout) for m in members})
    if len(shapes) != 1:
        return f"{label}s"
    depth, fanout = shapes[0]
    return f"{label} (depth {depth}, fanout {fanout})"


def delegation_costs(
    grid: GridData, load: float, theta: float
) -> dict[str, dict[str, float | None]]:
    meta = {row["run_id"]: row for row in grid.runs}
    selected: dict[str, list[tuple[str, int, float, bool, int]]] = defaultdict(list)
    for build in tree_builds(grid.events):
        row = meta.get(build.run_id)
        if row is None or float(row["load"]) != load or float(row["theta"]) != theta:
            continue
        selected[build.system].append(
            (build.run_id, build.operations, build.seconds, build.refresh, build.leases)
        )
    costs: dict[str, dict[str, float | None]] = {}
    for system, builds in sorted(selected.items()):
        runs = len({run_id for run_id, *_ in builds})
        refreshes = [(ops, seconds) for _, ops, seconds, refresh, _ in builds if refresh]
        initial = [leases for _, _, _, refresh, leases in builds if not refresh]
        costs[system] = {
            "leases_per_tree": statistics.fmean(initial) if initial else 0.0,
            "lease_ops_per_run": sum(ops for _, ops, *_ in builds) / runs,
            "refreshes_per_run": len(refreshes) / runs,
            "refresh_ops_mean": statistics.fmean(ops for ops, _ in refreshes)
            if refreshes
            else None,
            "refresh_ms_p50": quantile([seconds * 1000 for _, seconds in refreshes], 0.5),
            "refresh_ms_p95": quantile([seconds * 1000 for _, seconds in refreshes], 0.95),
        }
    return costs


def pooled_completion(
    rows: Sequence[RequestRow], load: float, theta: float
) -> dict[str, dict[str, CompletionCell]]:
    per_run: dict[tuple[str, str, int], list[int]] = defaultdict(lambda: [0, 0])
    for row in rows:
        if row.load != load or row.theta != theta:
            continue
        counts = per_run[(row.topology, row.system, row.seed)]
        counts[1] += 1
        counts[0] += row.outcome == "authorized"
    pairs: dict[tuple[str, str], list[tuple[int, int]]] = defaultdict(list)
    for (topology, system, _seed), (authorized, total) in sorted(per_run.items()):
        pairs[(topology, system)].append((authorized, total))
    result: dict[str, dict[str, CompletionCell]] = defaultdict(dict)
    for (topology, system), values in pairs.items():
        mean, low, high = pooled_bootstrap_ci(values)
        result[topology][system] = CompletionCell(mean, low, high, len(values))
    return dict(result)


def pre_break_latency_p50(rows: Sequence[RequestRow], pre_break_s: float) -> dict[str, float]:
    limit = int(pre_break_s * NS_PER_S)
    samples: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        if (
            row.outcome == "authorized"
            and row.t_auth_ns is not None
            and row.arrival_offset_ns < limit
        ):
            samples[row.system].append(row.t_auth_ns / 1_000_000)
    return {system: statistics.median(values) for system, values in sorted(samples.items())}


def isolating_topology(topologies: Sequence[str], sites: Sequence[str]) -> str | None:
    if not sites:
        return None
    first = sites[0]
    expected = frozenset(link for link in site_links(sites) if first in link)
    for name in topologies:
        topology = resolve_topology(name, sites)
        if topology.flap_period_s is None and topology.cut_links == expected:
            return name
    return None


def reduce_grid(label: str, grid: GridData, load: float, theta: float) -> GridReduction:
    requests = grid.requests
    systems = tuple(sorted({row.system for row in requests}, key=_system_rank))
    topologies = tuple(topology_order([row.topology for row in requests]))
    completion = pooled_completion(requests, load, theta)
    stranded_topology = isolating_topology(topologies, grid.sites)
    peaks: dict[str, int] = {}
    unit_seconds: dict[str, float] = {}
    if stranded_topology is not None:
        table = per_site_rows(requests, grid.events, grid.faults, grid.runs, grid.messages)
        for row in summary_rows(table):
            if (
                row["topology"] == stranded_topology
                and float(str(row["load"])) == load
                and float(str(row["theta"])) == theta
            ):
                peaks[str(row["system"])] = int(str(row["stranded_peak_units"]))
                unit_seconds[str(row["system"])] = float(str(row["stranded_unit_seconds_mean"]))
    authorized = [int(row["authorized"]) for row in grid.runs]
    return GridReduction(
        label=label,
        load=load,
        theta=theta,
        topologies=topologies,
        systems=systems,
        completion=completion,
        pre_break_p50_ms=pre_break_latency_p50(requests, grid.pre_break_s),
        pre_break_s=grid.pre_break_s,
        stranded_topology=stranded_topology,
        stranded_peak_units=peaks,
        stranded_unit_seconds=unit_seconds,
        run_system_pairs=len(grid.runs),
        max_authorized=max(authorized, default=0),
        envelope=grid.envelope,
        all_safety_ok=all(row["safety_ok"] == "True" for row in grid.runs),
        all_effects_match=all(row["effects"] == row["authorized"] for row in grid.runs),
        delegation=delegation_costs(grid, load, theta),
    )


def _system_rank(system: str) -> tuple[int, str]:
    return ROW_ORDER.index(row_key(system)), system


def _range(values: Sequence[float], digits: int) -> str:
    if not values:
        return "n/a"
    low, high = min(values), max(values)
    if f"{low:.{digits}f}" == f"{high:.{digits}f}":
        return f"{low:.{digits}f}"
    return f"{low:.{digits}f} to {high:.{digits}f}"


def _latency(values: Sequence[float]) -> str:
    if not values:
        return "n/a"
    digits = 1 if max(values) < 10 else 0
    return _range(values, digits)


def _number(value: float | None, digits: int) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def widest_intervals(reductions: Sequence[GridReduction]) -> dict[str, dict[str, object]]:
    widest: dict[str, tuple[float, str, str, str]] = {}
    for reduction in reductions:
        for topology, cells in reduction.completion.items():
            for system, cell in cells.items():
                key = row_key(system)
                group = key if key in LETS_GROUPS else "baselines"
                candidate = (cell.width_points, reduction.label, topology, system)
                if group not in widest or candidate > widest[group]:
                    widest[group] = candidate
    return {
        group: {"width_points": width, "grid": grid, "topology": topology, "system": system}
        for group, (width, grid, topology, system) in sorted(widest.items())
    }


def markdown(reductions: Sequence[GridReduction]) -> str:
    lines = ["# E1 grid report", ""]
    for reduction in reductions:
        lines.append(
            f"## {reduction.label}: completion at {reduction.load:g}x load, "
            f"theta={reduction.theta:g}"
        )
        lines.append("")
        header = ["System", *reduction.topologies, "t_auth p50 (ms)"]
        if reduction.stranded_topology is not None:
            header.append(f"Stranded unit-s ({reduction.stranded_topology})")
        lines.append("| " + " | ".join(header) + " |")
        lines.append("|" + "---|" * len(header))
        for key in ROW_ORDER:
            members = [system for system in reduction.systems if row_key(system) == key]
            if not members:
                continue
            cells = [row_label(key, members)]
            for topology in reduction.topologies:
                values = [
                    reduction.completion.get(topology, {})[system].completion
                    for system in members
                    if system in reduction.completion.get(topology, {})
                ]
                cells.append(_range(values, 2))
            cells.append(
                _latency(
                    [
                        reduction.pre_break_p50_ms[system]
                        for system in members
                        if system in reduction.pre_break_p50_ms
                    ]
                )
            )
            if reduction.stranded_topology is not None:
                cells.append(
                    _range(
                        [
                            reduction.stranded_unit_seconds[system]
                            for system in members
                            if system in reduction.stranded_unit_seconds
                        ],
                        0,
                    )
                )
            lines.append("| " + " | ".join(cells) + " |")
        lines.append("")
        lines.append(
            f"Completion is authorized requests divided by all requests, pooled over the seeds of "
            f"each cell; the latency column is the median over authorized requests that arrived "
            f"in the first {reduction.pre_break_s:g} s of every run in the grid; stranded "
            f"unit-seconds are the mean over seeds. Safety: {reduction.run_system_pairs} "
            f"run-system pairs, maximum authorized {reduction.max_authorized} of "
            f"{reduction.envelope} units, every safety check "
            f"{'passed' if reduction.all_safety_ok else 'FAILED'}, effects "
            f"{'equal' if reduction.all_effects_match else 'DIFFER FROM'} authorized counts."
        )
        lines.append("")
        if reduction.delegation:
            lines.append("### Lease-tree costs")
            lines.append("")
            lines.append(
                "| System | Leases per site tree | Lease ops / run | Refreshes / run | "
                "Ops / refresh | Refresh p50 / p95 (ms) |"
            )
            lines.append("|---|---:|---:|---:|---:|---|")
            for system, cost in reduction.delegation.items():
                lines.append(
                    f"| {system} | {_number(cost['leases_per_tree'], 1)} | "
                    f"{_number(cost['lease_ops_per_run'], 1)} | "
                    f"{_number(cost['refreshes_per_run'], 2)} | "
                    f"{_number(cost['refresh_ops_mean'], 1)} | "
                    f"{_number(cost['refresh_ms_p50'], 1)} / {_number(cost['refresh_ms_p95'], 1)} |"
                )
            lines.append("")
            lines.append(
                "A refresh closes every live lease of a site's tree and rebuilds it from the "
                "refreshed root; lease operations are issue, spawn, and close calls, and the "
                "times are measured at the site over the runs at this load and skew."
            )
            lines.append("")
        lines.append("### 95% seed-bootstrap intervals")
        lines.append("")
        lines.append(
            "| Topology | System | Completion | CI low | CI high | Width (points) | Seeds |"
        )
        lines.append("|---|---|---|---|---|---|---|")
        for topology in reduction.topologies:
            for system in reduction.systems:
                cell = reduction.completion.get(topology, {}).get(system)
                if cell is None:
                    continue
                lines.append(
                    f"| {topology} | {system} | {cell.completion:.3f} | {cell.ci_low:.3f} | "
                    f"{cell.ci_high:.3f} | {cell.width_points:.1f} | {cell.seeds} |"
                )
        lines.append("")
    widest = widest_intervals(reductions)
    lines.append("## Widest completion intervals")
    lines.append("")
    for group, entry in widest.items():
        lines.append(
            f"- {group}: {float(str(entry['width_points'])):.1f} percentage points "
            f"({entry['grid']}, {entry['topology']}, {entry['system']})"
        )
    lines.append("")
    return "\n".join(lines)


def payload(reductions: Sequence[GridReduction]) -> dict[str, object]:
    grids = []
    for reduction in reductions:
        record = asdict(reduction)
        record["completion"] = {
            topology: {
                system: {**asdict(cell), "width_points": cell.width_points}
                for system, cell in cells.items()
            }
            for topology, cells in reduction.completion.items()
        }
        grids.append(record)
    return {
        "schema": "lets.fair-baselines-report/v1",
        "grids": grids,
        "widest_intervals": widest_intervals(reductions),
    }


def load_or_assemble(output_dir: Path) -> GridData:
    if not (output_dir / "requests.csv").exists():
        assemble(output_dir)
    return load_grid(output_dir)


def _grid_argument(value: str) -> tuple[str, Path]:
    label, separator, path = value.partition("=")
    if not separator or not label or not path:
        raise argparse.ArgumentTypeError("expected LABEL=PATH")
    return label, Path(path)


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--grid",
        action="append",
        required=True,
        type=_grid_argument,
        help="LABEL=PATH of a controller output directory; repeat per grid",
    )
    parser.add_argument("--load", type=float, default=0.7)
    parser.add_argument("--theta", type=float, default=1.0)
    parser.add_argument("--write", type=Path, required=True, help="directory for the outputs")
    parser.add_argument("--basename", default="report")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    reductions = [
        reduce_grid(label, load_or_assemble(path), arguments.load, arguments.theta)
        for label, path in arguments.grid
    ]
    text = markdown(reductions)
    write_text(arguments.write / f"{arguments.basename}.md", text, overwrite=True)
    write_json(arguments.write / f"{arguments.basename}.json", payload(reductions), overwrite=True)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
