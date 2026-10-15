"""Figure script for E1: renders the topology x time-to-authorization CDF panel and the
completion bar chart with seed-bootstrap confidence intervals from the controller's requests.csv,
using the aggregates in analysis.py.
"""

from __future__ import annotations

import argparse
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
from benchmarks.fair_baselines.common import STATIC_TOPOLOGIES

PALETTE = {
    "lets": "#1b6ca8",
    "static-quota": "#7a7a7a",
    "raft-quorum": "#c9452a",
    "central-noretry@s2": "#8c6d1f",
    "central-retry@s1": "#2e8b57",
    "central-retry@s2": "#3cb371",
    "central-retry@s3": "#66cdaa",
}
STYLES = {
    "central-noretry@s2": ":",
    "central-retry@s1": "--",
    "central-retry@s2": "--",
    "central-retry@s3": "--",
}


def _color(system: str) -> str:
    return PALETTE.get(system, "#444444")


def _systems(rows: Sequence[RequestRow]) -> list[str]:
    order = list(PALETTE)
    present = {row.system for row in rows}
    return [name for name in order if name in present] + sorted(present - set(order))


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
                color=_color(system),
                linestyle=STYLES.get(system, "-"),
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
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output)
    plt.close(fig)
    return output


def completion_chart(
    rows: Sequence[RequestRow],
    topologies: Sequence[str],
    theta: float,
    output: Path,
) -> Path:
    loads = sorted({row.load for row in rows})
    systems = _systems(rows)
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
                color=_color(system),
                capsize=2,
                error_kw={"linewidth": 0.8},
            )
        axis.set_xticks(range(len(topologies)))
        axis.set_xticklabels(topologies)
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
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output)
    plt.close(fig)
    return output


def render_all(output_dir: Path, figure_dir: Path, formats: Sequence[str]) -> list[Path]:
    rows = load_requests(output_dir / "requests.csv")
    if not rows:
        raise ValueError("requests.csv has no rows")
    thetas = sorted({row.theta for row in rows})
    loads = sorted({row.load for row in rows})
    topologies_present = [
        name for name in STATIC_TOPOLOGIES if any(r.topology == name for r in rows)
    ]
    flapping = sorted({row.topology for row in rows} - set(STATIC_TOPOLOGIES))
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
