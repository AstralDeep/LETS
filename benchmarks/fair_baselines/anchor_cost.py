"""Measures what rollback anchors add to one LETS authorization on a quiet host: paired, order-
alternating trials of the systems.py LetsSystem with and without process-file anchors, timing the
warden debit and the executor claim of every call, written as JSON evidence beside the E1 grids.
"""

from __future__ import annotations

import argparse
import json
import platform
import shlex
import statistics
import time
from collections.abc import Sequence
from pathlib import Path

from benchmarks.fair_baselines.systems import AnchorSettings, LetsSystem, PeerTransport
from benchmarks.nsdi_strengthening.common import write_json
from lets.crypto import Ed25519Signer

SCHEMA = "lets.fair-baselines.anchor-cost/v1"
CONFIGS = ("unanchored", "anchored")


def quantile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    position = fraction * (len(ordered) - 1)
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def summarize(values: Sequence[float]) -> dict[str, float]:
    return {
        "n": len(values),
        "p50": quantile(values, 0.5),
        "p95": quantile(values, 0.95),
        "mean": statistics.fmean(values),
    }


def run_trial(
    config: str,
    trial: int,
    state_root: Path,
    anchor: AnchorSettings,
    calls: int,
    warmup: int,
    site: str,
) -> list[dict[str, int]]:
    signer = Ed25519Signer.generate(site)
    events: list[tuple[str, str, int, str]] = []

    def sink(system: str, kind: str, value: int, detail: str) -> None:
        events.append((system, kind, value, detail))

    state_dir = state_root / f"trial-{trial:02d}" / config
    state_dir.mkdir(parents=True)
    transport = PeerTransport(site, "anchor-cost-token-0123456789", {}, 0.5)
    system = LetsSystem(
        f"lets-{config}",
        site,
        state_dir,
        warmup + calls,
        warmup + calls,
        signer.seed_bytes,
        {site: (signer.key_id, signer.public_key_bytes)},
        transport,
        sink,
        anchor=anchor if config == "anchored" else None,
    )
    try:
        for index in range(warmup + calls):
            decision = system.take(f"{config}-{trial}-{index}")
            if not decision.authorized:
                raise RuntimeError(f"{config} call {index} was refused: {decision.reason}")
    finally:
        system.close()
    costs = []
    for _, kind, value, detail in events:
        if kind != "auth_cost":
            continue
        fields = dict(token.split("=", 1) for token in detail.split())
        costs.append(
            {
                "total_us": value,
                "warden_us": int(fields["warden_us"]),
                "executor_us": int(fields["executor_us"]),
            }
        )
    return costs[warmup:]


def measure(
    state_root: Path, anchor: AnchorSettings, trials: int, calls: int, warmup: int, site: str
) -> dict[str, object]:
    samples: dict[str, list[dict[str, int]]] = {config: [] for config in CONFIGS}
    order_log = []
    for trial in range(trials):
        order = CONFIGS if trial % 2 == 0 else tuple(reversed(CONFIGS))
        order_log.append(list(order))
        for config in order:
            for sample in run_trial(config, trial, state_root, anchor, calls, warmup, site):
                samples[config].append({"trial": trial, **sample})
    summary = {
        config: {
            part: summarize([sample[part] / 1000 for sample in rows])
            for part in ("total_us", "warden_us", "executor_us")
        }
        for config, rows in samples.items()
    }
    added = {
        part: summary["anchored"][part]["p50"] - summary["unanchored"][part]["p50"]
        for part in ("total_us", "warden_us", "executor_us")
    }
    return {
        "schema": SCHEMA,
        "site": site,
        "host": {"system": platform.system(), "release": platform.release()},
        "python": platform.python_version(),
        "anchor_root": str(anchor.root),
        "anchor_helper": list(anchor.helper),
        "trials": trials,
        "calls_per_trial": calls,
        "warmup_per_trial": warmup,
        "trial_order": order_log,
        "summary_ms": summary,
        "anchor_added_p50_ms": added,
        "samples": samples,
        "finished_at_epoch_s": time.time(),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--anchor-root", type=Path, required=True)
    parser.add_argument("--anchor-helper", default="")
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--calls", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.trials < 2 or arguments.calls < 1 or arguments.warmup < 0:
        parser.error("need at least two trials, one call, and a non-negative warmup")
    anchor = AnchorSettings(arguments.anchor_root, tuple(shlex.split(arguments.anchor_helper)))
    result = measure(
        arguments.state_root,
        anchor,
        arguments.trials,
        arguments.calls,
        arguments.warmup,
        arguments.site,
    )
    write_json(arguments.output, result)
    print(
        json.dumps({"site": arguments.site, "anchor_added_p50_ms": result["anchor_added_p50_ms"]})
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
