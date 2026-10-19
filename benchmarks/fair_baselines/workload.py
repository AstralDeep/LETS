"""Deterministic randomized demand for E1: Poisson arrivals over the run's arrival window with a
Zipf site skew whose rank order is the run's site roster, derived from the run seed so every site
and every system in a run sees the same request sequence (common.py supplies the configuration,
site_agent.py consumes the plan).
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass

from benchmarks.fair_baselines.common import RunConfig, zipf_weights

NS_PER_S = 1_000_000_000


@dataclass(frozen=True, slots=True)
class Arrival:
    index: int
    site: str
    offset_ns: int

    @property
    def request_id(self) -> str:
        return f"r{self.index:05d}"


def arrival_plan(config: RunConfig) -> tuple[Arrival, ...]:
    expected = config.load * config.envelope
    rate_per_ns = expected / (config.arrival_window_s * NS_PER_S)
    weights = zipf_weights(config.theta, len(config.sites))
    generator = random.Random(f"{config.run_id}:{config.seed}:{config.load}:{config.theta}")
    arrivals: list[Arrival] = []
    clock = 0.0
    window_ns = config.arrival_window_s * NS_PER_S
    while True:
        clock += generator.expovariate(rate_per_ns)
        if clock >= window_ns:
            break
        site = generator.choices(config.sites, weights=weights, k=1)[0]
        arrivals.append(Arrival(len(arrivals), site, int(clock)))
    return tuple(arrivals)


def site_demand(plan: Sequence[Arrival], sites: Sequence[str]) -> dict[str, int]:
    counts = dict.fromkeys(sites, 0)
    for arrival in plan:
        counts[arrival.site] += 1
    return counts
