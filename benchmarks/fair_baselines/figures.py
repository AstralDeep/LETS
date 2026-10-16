"""Figure script for E1: renders the time-to-authorization CDF panel with one column per topology
present and the per-topology completion bars with seed-bootstrap confidence intervals from the
controller's requests.csv, using the aggregates in analysis.py.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from benchmarks.fair_baselines.analysis import (
    RequestRow,
    authorization_cdf,
    bootstrap_ci,
    completion_by_seed,
    load_requests,
)
from benchmarks.fair_baselines.common import SystemSpec, is_flapping, topology_order


def save_figure(fig: object, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.suffix.lower() == ".svg":
        buffer = io.StringIO()
        fig.savefig(buffer, format="svg")  # type: ignore[attr-defined]
        output.write_text(buffer.getvalue(), encoding="utf-8", newline="\n")
    else:
        fig.savefig(output)  # type: ignore[attr-defined]
    plt.close(fig)  # type: ignore[arg-type]


PALETTE = {
    "lets": "#1b6ca8",
    "static-quota": "#7a7a7a",
    "raft-quorum": "#c9452a",
}
NORETRY_COLOR = "#8c6d1f"
RETRY_COLORS = ("#2e8b57", "#3cb371", "#66cdaa", "#1f7a4d", "#52b788", "#95d5b2", "#0b5d3b")
KIND_ORDER = {"lets": 0, "static-quota": 1, "raft-quorum": 2, "central": 3}


def _systems(rows: Sequence[RequestRow]) -> list[str]:
    present = {row.system for row in rows}
    roster = sorted({row.site for row in rows})

    def rank(name: str) -> tuple[int, int, int, str]:
        spec = SystemSpec.parse(name)
        host = roster.index(spec.host) if spec.host in roster else len(roster)
        return KIND_ORDER.get(spec.kind, 9), 0 if not spec.retry else 1, host, name

    return sorted(present, key=rank)


def _palette(systems: Sequence[str]) -> dict[str, str]:
    colors: dict[str, str] = {}
    retry_index = 0
    for name in systems:
        spec = SystemSpec.parse(name)
        if spec.kind == "central" and not spec.retry:
            colors[name] = NORETRY_COLOR
        elif spec.kind == "central":
            colors[name] = RETRY_COLORS[retry_index % len(RETRY_COLORS)]
            retry_index += 1
        else:
            colors[name] = PALETTE.get(name, "#444444")
    return colors


def _style(system: str) -> str:
    spec = SystemSpec.parse(system)
    if spec.kind != "central":
        return "-"
    return "--" if spec.retry else ":"


def cdf_panel(
    rows: Sequence[RequestRow],
    topologies: Sequence[str],
    load: float,
    theta: float,
    output: Path,
    *,
    title: str | None = None,
) -> Path:
    selected = [row for row in rows if row.load == load and row.theta == theta]
    systems = _systems(selected)
    colors = _palette(systems)
    fig, axes = plt.subplots(1, len(topologies), figsize=(4.2 * len(topologies), 3.6), sharey=True)
    if len(topologies) == 1:
        axes = [axes]
    for axis, topology in zip(axes, topologies, strict=True):
        subset = [row for row in selected if row.topology == topology]
        deadline = max((row.deadline_ns for row in subset), default=0) / 1e9
        for system in systems:
            xs, ys = authorization_cdf(row for row in subset if row.system == system)
            if not xs:
                continue
            xs.append(deadline)
            ys.append(ys[-1])
            axis.step(
                xs,
                ys,
                where="post",
                label=system,
                color=colors[system],
                linestyle=_style(system),
                linewidth=1.6,
            )
        axis.set_title(topology)
        axis.set_xlabel("time to authorization (s)")
        axis.set_xlim(0, deadline if deadline else None)
        axis.set_ylim(0, 1.02)
        axis.grid(True, alpha=0.3)
    axes[0].set_ylabel("fraction of requests authorized")
    handles, labels = axes[-1].get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="lower center", ncol=min(4, len(labels)), fontsize=8, frameon=False
    )
    fig.suptitle(title or f"Time to authorization, load {load:g}x envelope, Zipf θ={theta:g}")
    fig.tight_layout(rect=(0, 0.12, 1, 1))
    save_figure(fig, output)
    return output


def completion_chart(
    rows: Sequence[RequestRow],
    topologies: Sequence[str],
    theta: float,
    output: Path,
) -> Path:
    loads = sorted({row.load for row in rows})
    systems = _systems(rows)
    colors = _palette(systems)
    completions = completion_by_seed(row for row in rows if row.theta == theta)
    fig, axes = plt.subplots(1, len(loads), figsize=(5.5 * len(loads), 3.8), sharey=True)
    if len(loads) == 1:
        axes = [axes]
    width = 0.8 / max(1, len(systems))
    for axis, load in zip(axes, loads, strict=True):
        for offset, system in enumerate(systems):
            means, lows, highs = [], [], []
            for topology in topologies:
                values = completions.get(((topology, load, theta, "equal"), system)) or [
                    value
                    for (cell, name), seeds in completions.items()
                    if cell[0] == topology and cell[1] == load and name == system
                    for value in seeds
                ]
                if values:
                    mean, low, high = bootstrap_ci(values)
                else:
                    mean = low = high = 0.0
                means.append(mean)
                lows.append(mean - low)
                highs.append(high - mean)
            positions = [
                index + (offset - len(systems) / 2 + 0.5) * width
                for index in range(len(topologies))
            ]
            axis.bar(
                positions,
                means,
                width=width,
                yerr=[lows, highs],
                label=system,
                color=colors[system],
                capsize=2,
                error_kw={"linewidth": 0.8},
            )
        axis.set_xticks(range(len(topologies)))
        axis.set_xticklabels(topologies, rotation=20 if len(topologies) > 4 else 0)
        axis.set_title(f"offered load {load:g}x envelope")
        axis.set_ylim(0, 1.05)
        axis.grid(True, axis="y", alpha=0.3)
    axes[0].set_ylabel("completions by deadline (fraction)")
    handles, labels = axes[-1].get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="lower center", ncol=min(4, len(labels)), fontsize=8, frameon=False
    )
    fig.suptitle(f"Completions by deadline with 95% seed-bootstrap CIs, Zipf θ={theta:g}")
    fig.tight_layout(rect=(0, 0.12, 1, 1))
    save_figure(fig, output)
    return output


def render_all(output_dir: Path, figure_dir: Path, formats: Sequence[str]) -> list[Path]:
    rows = load_requests(output_dir / "requests.csv")
    if not rows:
        raise ValueError("requests.csv has no rows")
    thetas = sorted({row.theta for row in rows})
    loads = sorted({row.load for row in rows})
    present = topology_order([row.topology for row in rows])
    topologies_present = [name for name in present if not is_flapping(name)]
    flapping = [name for name in present if is_flapping(name)]
    written = []
    by_count: dict[float, int] = defaultdict(int)
    for row in rows:
        by_count[row.theta] += 1
    for theta in thetas:
        for load in loads:
            for extension in formats:
                if topologies_present:
                    written.append(
                        cdf_panel(
                            rows,
                            topologies_present,
                            load,
                            theta,
                            figure_dir / f"cdf-panel-L{load:g}-T{theta:g}.{extension}",
                        )
                    )
                if flapping:
                    written.append(
                        cdf_panel(
                            rows,
                            flapping,
                            load,
                            theta,
                            figure_dir / f"cdf-flapping-L{load:g}-T{theta:g}.{extension}",
                        )
                    )
        for extension in formats:
            written.append(
                completion_chart(
                    rows,
                    [*topologies_present, *flapping],
                    theta,
                    figure_dir / f"completions-T{theta:g}.{extension}",
                )
            )
    return written


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="controller output directory")
    parser.add_argument("--figures", type=Path, default=None, help="figure directory")
    parser.add_argument("--formats", nargs="+", default=["svg", "pdf"])
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    figure_dir = arguments.figures or (arguments.output / "figures")
    written = render_all(arguments.output, figure_dir, arguments.formats)
    print(json.dumps({"figures": [str(path) for path in written]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
