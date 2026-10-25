"""Offline metrics for E1 from the controller's CSVs: completion rates with seed-level bootstrap
CIs, time-to-authorization distributions with censored timeouts, stranded capacity reconstructed
from free-unit and waiting events against the fault timeline, message counts, the per-site
results table, and the delegation-tree build costs from tree_build events; report.py summarizes
the same aggregates per grid.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from benchmarks.fair_baselines.common import (
    DEFAULT_SITES,
    SystemSpec,
    resolve_topology,
    site_links,
)
from benchmarks.fair_baselines.controller import read_run, run_files
from benchmarks.nsdi_strengthening.common import write_text

NS_PER_S = 1_000_000_000
CellKey = tuple[str, float, float, str]


@dataclass(frozen=True, slots=True)
class RequestRow:
    run_id: str
    topology: str
    load: float
    theta: float
    seed: int
    placement: str
    system: str
    site: str
    outcome: str
    arrival_offset_ns: int
    t_auth_ns: int | None
    deadline_ns: int
    messages: int

    @property
    def cell(self) -> CellKey:
        return (self.topology, self.load, self.theta, self.placement)


def _optional_int(value: str) -> int | None:
    return None if value in ("", "None") else int(value)


def load_requests(path: Path) -> list[RequestRow]:
    rows = []
    with path.open(encoding="utf-8", newline="") as stream:
        for raw in csv.DictReader(stream):
            rows.append(
                RequestRow(
                    raw["run_id"],
                    raw["topology"],
                    float(raw["load"]),
                    float(raw["theta"]),
                    int(raw["seed"]),
                    raw["placement"],
                    raw["system"],
                    raw["site"],
                    raw["outcome"],
                    int(raw["arrival_offset_ns"]),
                    _optional_int(raw["t_auth_ns"]),
                    int(raw["deadline_ns"]),
                    int(raw["messages"]),
                )
            )
    return rows


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def bootstrap_ci(
    values: Sequence[float], *, resamples: int = 2000, seed: int = 7, level: float = 0.95
) -> tuple[float, float, float]:
    if not values:
        raise ValueError("bootstrap needs at least one value")
    mean = statistics.fmean(values)
    if len(values) == 1:
        return mean, mean, mean
    generator = random.Random(seed)
    means = sorted(
        statistics.fmean(generator.choices(values, k=len(values))) for _ in range(resamples)
    )
    lower_index = math.floor((1 - level) / 2 * (resamples - 1))
    upper_index = math.ceil((1 + level) / 2 * (resamples - 1))
    return mean, means[lower_index], means[upper_index]


def pooled_bootstrap_ci(
    pairs: Sequence[tuple[int, int]], *, resamples: int = 2000, seed: int = 7, level: float = 0.95
) -> tuple[float, float, float]:
    if not pairs or sum(total for _, total in pairs) == 0:
        raise ValueError("pooled bootstrap needs at least one request")

    def pooled(sample: Sequence[tuple[int, int]]) -> float:
        total = sum(count for _, count in sample)
        return sum(authorized for authorized, _ in sample) / total if total else 0.0

    mean = pooled(pairs)
    if len(pairs) == 1:
        return mean, mean, mean
    generator = random.Random(seed)
    ratios = sorted(pooled(generator.choices(pairs, k=len(pairs))) for _ in range(resamples))
    lower_index = math.floor((1 - level) / 2 * (resamples - 1))
    upper_index = math.ceil((1 + level) / 2 * (resamples - 1))
    return mean, ratios[lower_index], ratios[upper_index]


def completion_by_seed(rows: Iterable[RequestRow]) -> dict[tuple[CellKey, str], list[float]]:
    per_run: dict[tuple[CellKey, str, int], list[int]] = defaultdict(lambda: [0, 0])
    for row in rows:
        counts = per_run[(row.cell, row.system, row.seed)]
        counts[1] += 1
        if row.outcome == "authorized":
            counts[0] += 1
    result: dict[tuple[CellKey, str], list[float]] = defaultdict(list)
    for (cell, system, _seed), (authorized, total) in sorted(per_run.items()):
        result[(cell, system)].append(authorized / total if total else 0.0)
    return result


def authorization_cdf(rows: Iterable[RequestRow]) -> tuple[list[float], list[float]]:
    times = []
    total = 0
    for row in rows:
        total += 1
        if row.outcome == "authorized" and row.t_auth_ns is not None:
            times.append(row.t_auth_ns / NS_PER_S)
    if total == 0:
        return [], []
    times.sort()
    xs = [0.0]
    ys = [0.0]
    for index, value in enumerate(times, start=1):
        xs.append(value)
        ys.append(index / total)
    return xs, ys


def quantile(values: Sequence[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return ordered[position]


@dataclass
class LinkState:
    cuts: list[tuple[float, float, frozenset[str]]]

    def link_up(self, link: frozenset[str], offset_s: float) -> bool:
        return not any(start <= offset_s < end for start, end, cut in self.cuts if cut == link)


def link_states(faults: Sequence[Mapping[str, str]]) -> dict[str, LinkState]:
    per_run: dict[str, list[tuple[float, str, frozenset[frozenset[str]]]]] = defaultdict(list)
    for fault in faults:
        if fault["kind"] not in {"cut", "heal"}:
            continue
        links = frozenset(frozenset(label.split("-")) for label in fault["link"].split(","))
        per_run[fault["run_id"]].append((float(fault["returned_offset_s"]), fault["kind"], links))
    states: dict[str, LinkState] = {}
    for run_id, events in per_run.items():
        events.sort()
        open_cuts: dict[frozenset[str], float] = {}
        intervals: list[tuple[float, float, frozenset[str]]] = []
        for offset, kind, links in events:
            for link in links:
                if kind == "cut":
                    open_cuts.setdefault(link, offset)
                elif link in open_cuts:
                    intervals.append((open_cuts.pop(link), offset, link))
        for link, start in open_cuts.items():
            intervals.append((start, math.inf, link))
        states[run_id] = LinkState(intervals)
    return states


def _majority_reachable(site: str, state: LinkState, offset_s: float, sites: Sequence[str]) -> bool:
    reachable = sum(
        1 for other in sites if other != site and state.link_up(frozenset({site, other}), offset_s)
    )
    return 2 * (reachable + 1) > len(sites)


def pool_usable(
    spec: SystemSpec,
    waiting_site: str,
    pool: str,
    state: LinkState,
    t: float,
    sites: Sequence[str] = DEFAULT_SITES,
) -> bool:
    if spec.kind == "static-quota":
        return waiting_site == pool
    if spec.kind in {"lets", "central"}:
        return waiting_site == pool or state.link_up(frozenset({waiting_site, pool}), t)
    return _majority_reachable(waiting_site, state, t, sites)


@dataclass(frozen=True, slots=True)
class StrandedSummary:
    peak_units: int
    unit_seconds: float


def _step_value(samples: Sequence[tuple[float, int]], t: float, initial: int) -> int:
    value = initial
    for offset, sample in samples:
        if offset > t:
            break
        value = sample
    return value


def stranded_capacity(
    system: str,
    events: Sequence[Mapping[str, str]],
    state: LinkState,
    shares: Mapping[str, int],
    envelope: int,
    end_s: float,
    step_s: float = 0.1,
    sites: Sequence[str] | None = None,
) -> StrandedSummary:
    roster = tuple(sites) if sites is not None else tuple(shares) or DEFAULT_SITES
    spec = SystemSpec.parse(system)
    free_samples: dict[str, list[tuple[float, int]]] = defaultdict(list)
    waiting_samples: dict[str, list[tuple[float, int]]] = defaultdict(list)
    for event in events:
        if event["system"] != system:
            continue
        offset = int(event["offset_ns"]) / NS_PER_S
        if event["kind"] == "free":
            key = event["site"] if spec.kind in {"static-quota", "lets"} else "pool"
            free_samples[key].append((offset, int(event["value"])))
        elif event["kind"] == "waiting":
            waiting_samples[event["site"]].append((offset, int(event["value"])))
    for samples in (*free_samples.values(), *waiting_samples.values()):
        samples.sort()
    if spec.kind in {"static-quota", "lets"}:
        pools = {site: shares[site] for site in roster}
    else:
        pools = {"pool": envelope}
    peak = 0
    unit_seconds = 0.0
    steps = math.ceil(end_s / step_s)
    for index in range(steps):
        t = index * step_s
        waiting = [site for site in roster if _step_value(waiting_samples.get(site, ()), t, 0) > 0]
        if not waiting:
            continue
        stranded = 0
        for pool, initial in pools.items():
            free = _step_value(free_samples.get(pool, ()), t, initial)
            if free <= 0:
                continue
            location = pool if pool in roster else (spec.host or "pool")
            if spec.kind == "central":
                usable = any(
                    pool_usable(spec, site, location, state, t, roster) for site in waiting
                )
            else:
                usable = any(pool_usable(spec, site, pool, state, t, roster) for site in waiting)
            if not usable:
                stranded += free
        peak = max(peak, stranded)
        unit_seconds += stranded * step_s
    return StrandedSummary(peak, unit_seconds)


def per_site_rows(
    requests: Sequence[RequestRow],
    events: Sequence[Mapping[str, str]],
    faults: Sequence[Mapping[str, str]],
    runs: Sequence[Mapping[str, str]],
    messages: Sequence[Mapping[str, str]] = (),
) -> list[dict[str, object]]:
    states = link_states(faults)
    site_messages: dict[tuple[str, str, str], int] = {}
    for row in messages:
        site_messages[(row["run_id"], row["system"], row["site"])] = int(row["messages"])
    run_meta = {row["run_id"]: row for row in runs}
    events_by_run: dict[str, list[Mapping[str, str]]] = defaultdict(list)
    for event in events:
        events_by_run[event["run_id"]].append(event)
    stranded_cache: dict[tuple[str, str], StrandedSummary] = {}
    grouped: dict[tuple[CellKey, str, str], list[RequestRow]] = defaultdict(list)
    seeds: dict[tuple[CellKey, str], set[int]] = defaultdict(set)
    for row in requests:
        grouped[(row.cell, row.system, row.site)].append(row)
        seeds[(row.cell, row.system)].add(row.seed)
    table = []
    for (cell, system, site), rows in sorted(grouped.items()):
        meta = run_meta[rows[0].run_id]
        shares = json.loads(meta.get("shares", "{}") or "{}")
        sites = tuple(json.loads(meta.get("sites", "[]") or "[]")) or tuple(shares) or DEFAULT_SITES
        envelope = int(meta["envelope"])
        stranded_values = []
        for run_id in sorted({row.run_id for row in rows}):
            key = (run_id, system)
            if key not in stranded_cache:
                end_s = (
                    max((int(event["offset_ns"]) for event in events_by_run[run_id]), default=0)
                    / NS_PER_S
                )
                stranded_cache[key] = stranded_capacity(
                    system,
                    events_by_run[run_id],
                    states.get(run_id, LinkState([])),
                    shares,
                    envelope,
                    end_s,
                    sites=sites,
                )
            stranded_values.append(stranded_cache[key])
        times = [row.t_auth_ns / NS_PER_S for row in rows if row.t_auth_ns is not None]
        completions = completion_by_seed(rows)[(cell, system)]
        mean, lower, upper = bootstrap_ci(completions)
        count_seeds = len(seeds[(cell, system)])
        table.append(
            {
                "topology": cell[0],
                "load": cell[1],
                "theta": cell[2],
                "placement": cell[3],
                "system": system,
                "site": site,
                "seeds": count_seeds,
                "share": shares.get(site),
                "requests_per_run": len(rows) / count_seeds,
                "authorized_per_run": sum(1 for r in rows if r.outcome == "authorized")
                / count_seeds,
                "denied_per_run": sum(1 for r in rows if r.outcome == "denied") / count_seeds,
                "timeout_per_run": sum(1 for r in rows if r.outcome == "timeout") / count_seeds,
                "completion_mean": mean,
                "completion_ci_low": lower,
                "completion_ci_high": upper,
                "t_auth_p50_s": quantile(times, 0.5),
                "t_auth_p95_s": quantile(times, 0.95),
                "censored_fraction": 1 - len(times) / len(rows),
                "stranded_peak_units": max(value.peak_units for value in stranded_values),
                "stranded_unit_seconds_mean": statistics.fmean(
                    value.unit_seconds for value in stranded_values
                ),
                "messages_per_run": sum(
                    site_messages.get((run_id, system, site), 0)
                    for run_id in {row.run_id for row in rows}
                )
                / count_seeds,
                "client_messages_per_run": sum(r.messages for r in rows) / count_seeds,
            }
        )
    return table


def _fmt(value: object, digits: int = 2) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def per_site_markdown(table: Sequence[Mapping[str, object]], title: str) -> str:
    lines = [
        f"# {title}",
        "",
        "Per-site results aggregated over seeds. `A/D/T` are mean authorized, denied, and "
        "timed-out requests per run at that site; completion is the per-run fraction of the "
        "site's requests authorized by their deadline with a 95% seed-bootstrap CI; "
        "time-to-authorization quantiles are over authorized requests only (timeouts are "
        "censored, see the censored column); stranded capacity is reconstructed from free-unit "
        "and waiting events against the fault timeline; messages are application messages sent "
        "from that site per run.",
        "",
        "| Topology | Load | θ | System | Site | Share | N/run | A/D/T per run | Completion "
        "[95% CI] | t_auth p50 / p95 (s) | Censored | Stranded peak / unit·s | Msgs/run |",
        "|---|---:|---:|---|---|---:|---:|---:|---|---:|---:|---:|---:|",
    ]
    for row in table:
        lines.append(
            f"| {row['topology']} | {row['load']:g} | {row['theta']:g} | {row['system']} | "
            f"{row['site']} | {_fmt(row['share'])} | {_fmt(row['requests_per_run'], 1)} | "
            f"{_fmt(row['authorized_per_run'], 1)}/{_fmt(row['denied_per_run'], 1)}/"
            f"{_fmt(row['timeout_per_run'], 1)} | {_fmt(row['completion_mean'])} "
            f"[{_fmt(row['completion_ci_low'])}, {_fmt(row['completion_ci_high'])}] | "
            f"{_fmt(row['t_auth_p50_s'], 3)} / {_fmt(row['t_auth_p95_s'], 3)} | "
            f"{_fmt(row['censored_fraction'])} | {row['stranded_peak_units']} / "
            f"{_fmt(row['stranded_unit_seconds_mean'], 1)} | {_fmt(row['messages_per_run'], 1)} |"
        )
    return "\n".join(lines)


def per_site_csv(table: Sequence[Mapping[str, object]]) -> str:
    if not table:
        return ""
    import io

    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(table[0].keys()), lineterminator="\n")
    writer.writeheader()
    for row in table:
        writer.writerow(row)
    return output.getvalue()


def summary_rows(table: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[object, ...], list[Mapping[str, object]]] = defaultdict(list)
    for row in table:
        grouped[
            (row["topology"], row["load"], row["theta"], row["placement"], row["system"])
        ].append(row)
    summary = []
    for key, rows in sorted(grouped.items()):
        requests = sum(float(row["requests_per_run"]) for row in rows)  # type: ignore[arg-type]
        authorized = sum(float(row["authorized_per_run"]) for row in rows)  # type: ignore[arg-type]
        summary.append(
            {
                "topology": key[0],
                "load": key[1],
                "theta": key[2],
                "placement": key[3],
                "system": key[4],
                "requests_per_run": requests,
                "authorized_per_run": authorized,
                "completion": authorized / requests if requests else 0.0,
                "stranded_peak_units": max(int(row["stranded_peak_units"]) for row in rows),  # type: ignore[call-overload]
                "stranded_unit_seconds_mean": max(
                    float(row["stranded_unit_seconds_mean"])
                    for row in rows  # type: ignore[arg-type]
                ),
                "messages_per_run": sum(float(row["messages_per_run"]) for row in rows),  # type: ignore[arg-type]
            }
        )
    return summary


@dataclass(frozen=True, slots=True)
class TreeBuild:
    run_id: str
    system: str
    site: str
    offset_s: float
    reason: str
    operations: int
    leases: int
    leaves: int
    seconds: float

    @property
    def refresh(self) -> bool:
        return self.reason != "initial"


def tree_builds(events: Iterable[Mapping[str, str]]) -> list[TreeBuild]:
    builds = []
    for event in events:
        if event["kind"] != "tree_build":
            continue
        reason, _, rest = event["detail"].partition(" ")
        fields = dict(token.split("=", 1) for token in rest.split())
        builds.append(
            TreeBuild(
                event["run_id"],
                event["system"],
                event["site"],
                int(event["offset_ns"]) / NS_PER_S,
                reason,
                int(event["value"]),
                int(fields["leases"]),
                int(fields["leaves"]),
                int(fields["us"]) / 1_000_000,
            )
        )
    return builds


def _ms(builds: Sequence[TreeBuild], fraction: float) -> float | None:
    return quantile([build.seconds * 1000 for build in builds], fraction)


def delegation_rows(
    events: Sequence[Mapping[str, str]], runs: Sequence[Mapping[str, str]]
) -> list[dict[str, object]]:
    run_meta = {row["run_id"]: row for row in runs}
    grouped: dict[tuple[str, float, float, str, str], list[TreeBuild]] = defaultdict(list)
    for build in tree_builds(events):
        meta = run_meta.get(build.run_id)
        if meta is None:
            continue
        key = (
            meta["topology"],
            float(meta["load"]),
            float(meta["theta"]),
            meta["placement"],
            build.system,
        )
        grouped[key].append(build)
    table = []
    for key, builds in sorted(grouped.items()):
        spec = SystemSpec.parse(key[4])
        count_runs = len({build.run_id for build in builds})
        initial = [build for build in builds if not build.refresh]
        refresh = [build for build in builds if build.refresh]
        table.append(
            {
                "topology": key[0],
                "load": key[1],
                "theta": key[2],
                "placement": key[3],
                "system": key[4],
                "depth": spec.depth,
                "fanout": spec.fanout,
                "runs": count_runs,
                "leases_per_tree": statistics.fmean(build.leases for build in initial)
                if initial
                else 0.0,
                "leaves_per_tree": statistics.fmean(build.leaves for build in initial)
                if initial
                else 0.0,
                "initial_ops_per_site": statistics.fmean(build.operations for build in initial)
                if initial
                else 0.0,
                "initial_ms_p50": _ms(initial, 0.5),
                "refreshes_per_run": len(refresh) / count_runs,
                "refresh_ops_mean": statistics.fmean(build.operations for build in refresh)
                if refresh
                else None,
                "refresh_ms_p50": _ms(refresh, 0.5),
                "refresh_ms_p95": _ms(refresh, 0.95),
                "refresh_ms_max": _ms(refresh, 1.0),
                "lease_ops_per_run": sum(build.operations for build in builds) / count_runs,
                "build_ms_per_run": sum(build.seconds for build in builds) * 1000 / count_runs,
            }
        )
    return table


def delegation_markdown(table: Sequence[Mapping[str, object]], title: str) -> str:
    lines = [
        f"# {title}",
        "",
        "Lease-tree build costs per cell and LETS system, from the `tree_build` events. A build "
        "is the issue of a site's root lease plus the spawn of every child down to the leaves; a "
        "refresh is the close of every live lease in the tree followed by a new build, which is "
        "how an exhausted tree takes up transferred budget (`in-*`) or releases units for an "
        "outgoing transfer (`out-*`). Lease operations count issue, spawn, and close calls to "
        "the warden; times are wall-clock at the site. A depth of 0 is the one-lease system.",
        "",
        "| Topology | Load | θ | System | Depth | Fanout | Runs | Leases / tree | Leaves / tree "
        "| Initial ops / site | Initial p50 (ms) | Refreshes / run | Ops / refresh "
        "| Refresh p50 / p95 / max (ms) | Lease ops / run | Build ms / run |",
        "|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|",
    ]
    for row in table:
        lines.append(
            f"| {row['topology']} | {row['load']:g} | {row['theta']:g} | {row['system']} | "
            f"{row['depth']} | {row['fanout']} | {row['runs']} | "
            f"{_fmt(row['leases_per_tree'], 1)} | {_fmt(row['leaves_per_tree'], 1)} | "
            f"{_fmt(row['initial_ops_per_site'], 1)} | {_fmt(row['initial_ms_p50'], 1)} | "
            f"{_fmt(row['refreshes_per_run'], 2)} | {_fmt(row['refresh_ops_mean'], 1)} | "
            f"{_fmt(row['refresh_ms_p50'], 1)} / {_fmt(row['refresh_ms_p95'], 1)} / "
            f"{_fmt(row['refresh_ms_max'], 1)} | {_fmt(row['lease_ops_per_run'], 1)} | "
            f"{_fmt(row['build_ms_per_run'], 1)} |"
        )
    return "\n".join(lines)


def topology_description(name: str, sites: Sequence[str] = DEFAULT_SITES) -> str:
    topology = resolve_topology(name, sites)
    labels = sorted("-".join(sorted(link)) for link in topology.cut_links)
    if topology.flap_period_s is not None:
        return f"{name}: link(s) {', '.join(labels)} toggle every {topology.flap_period_s:g} s"
    intact = sorted(
        "-".join(sorted(link)) for link in site_links(sites) if link not in topology.cut_links
    )
    return f"{name}: cut {', '.join(labels)}; intact {', '.join(intact) or 'none'}"


@dataclass(frozen=True, slots=True)
class GridData:
    requests: list[RequestRow]
    events: list[dict[str, str]]
    faults: list[dict[str, str]]
    runs: list[dict[str, str]]
    messages: list[dict[str, str]]
    sites: tuple[str, ...]
    envelope: int
    pre_break_s: float


def load_grid(output: Path) -> GridData:
    requests = load_requests(output / "requests.csv")
    events = load_csv(output / "events.csv")
    faults = load_csv(output / "faults.csv")
    runs = load_csv(output / "runs.csv")
    messages = load_csv(output / "messages.csv")
    shares_by_run: dict[str, str] = {}
    sites_by_run: dict[str, str] = {}
    rosters: set[tuple[str, ...]] = set()
    envelopes: set[int] = set()
    pre_breaks: set[float] = set()
    for path in run_files(output):
        payload = read_run(path)
        config = payload.get("config", {})
        sites = tuple(config.get("sites", DEFAULT_SITES))
        rosters.add(sites)
        if "envelope" in config:
            envelopes.add(int(config["envelope"]))
        if "pre_s" in config:
            pre_breaks.add(float(config["pre_s"]))
        shares_by_run[payload["run_id"]] = json.dumps(
            next(iter(payload["configured"].values()))["shares"]
            if payload.get("configured")
            else {}
        )
        sites_by_run[payload["run_id"]] = json.dumps(list(sites))
    if len(rosters) > 1 or len(envelopes) > 1 or len(pre_breaks) > 1:
        raise ValueError(f"{output}: runs disagree on roster, envelope, or pre-break length")
    for row in runs:
        row["shares"] = shares_by_run.get(row["run_id"], "{}")
        row["sites"] = sites_by_run.get(row["run_id"], "[]")
    return GridData(
        requests,
        events,
        faults,
        runs,
        messages,
        next(iter(rosters), tuple(DEFAULT_SITES)),
        next(iter(envelopes), 0),
        next(iter(pre_breaks), 0.0),
    )


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="controller output directory")
    parser.add_argument("--title", default="E1 fair-baseline family: per-site results")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    output: Path = arguments.output
    grid = load_grid(output)
    table = per_site_rows(grid.requests, grid.events, grid.faults, grid.runs, grid.messages)
    write_text(output / "per-site.md", per_site_markdown(table, arguments.title), overwrite=True)
    write_text(output / "per-site.csv", per_site_csv(table), overwrite=True)
    write_text(output / "summary.csv", per_site_csv(summary_rows(table)), overwrite=True)
    delegation = delegation_rows(grid.events, grid.runs)
    if delegation:
        write_text(
            output / "delegation.md",
            delegation_markdown(delegation, f"{arguments.title}: lease-tree build costs"),
            overwrite=True,
        )
        write_text(output / "delegation.csv", per_site_csv(delegation), overwrite=True)
    print(json.dumps({"rows": len(table), "delegation_rows": len(delegation)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
