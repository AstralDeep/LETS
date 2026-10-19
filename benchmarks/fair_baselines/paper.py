"""Reduces one or more E1 grids to the numbers the paper's partition table reports: pooled
completion with seed-bootstrap intervals, pre-break authorization latency, stranded budget, and
the safety totals, read through analysis.py from the controller's run files (regenerating the
flat CSVs with controller.assemble when they are absent).
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
    summary_rows,
)
from benchmarks.fair_baselines.common import (
    SystemSpec,
    resolve_topology,
    site_links,
    topology_order,
)
from benchmarks.fair_baselines.controller import assemble
from benchmarks.nsdi_strengthening.common import write_json, write_text

ROW_ORDER = ("lets", "static-quota", "central-noretry", "central-retry", "raft-quorum")
ROW_LABELS = {
    "lets": "LETS",
    "static-quota": "Static per-site quotas",
    "central-noretry": "Central counter, no retry",
    "central-retry": "Central counter, retry",
    "raft-quorum": "Raft quorum counter",
}


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


def row_key(system: str) -> str:
    spec = SystemSpec.parse(system)
    if spec.kind != "central":
        return spec.kind
    return "central-retry" if spec.retry else "central-noretry"


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


def widest_intervals(reductions: Sequence[GridReduction]) -> dict[str, dict[str, object]]:
    widest: dict[str, tuple[float, str, str, str]] = {}
    for reduction in reductions:
        for topology, cells in reduction.completion.items():
            for system, cell in cells.items():
                group = "lets" if system == "lets" else "baselines"
                candidate = (cell.width_points, reduction.label, topology, system)
                if group not in widest or candidate > widest[group]:
                    widest[group] = candidate
    return {
        group: {"width_points": width, "grid": grid, "topology": topology, "system": system}
        for group, (width, grid, topology, system) in sorted(widest.items())
    }


def markdown(reductions: Sequence[GridReduction]) -> str:
    lines = ["# Partition-study numbers", ""]
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
            cells = [ROW_LABELS[key]]
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
        "schema": "lets.fair-baselines-paper/v1",
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
    parser.add_argument("--basename", default="paper-table")
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
