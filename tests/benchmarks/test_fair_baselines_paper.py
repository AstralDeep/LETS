"""Tests for benchmarks/fair_baselines/paper.py on a synthetic three-site grid written as the
controller's CSVs plus minimal run files: pooled completion with seed-bootstrap intervals,
pre-break latency, the isolating topology and its stranded budget, safety totals, widest
intervals, the Markdown and JSON outputs, and the assemble fallback.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from benchmarks.fair_baselines import paper
from benchmarks.fair_baselines.analysis import GridData, RequestRow, pooled_bootstrap_ci
from benchmarks.fair_baselines.controller import (
    EVENT_FIELDS,
    FAULT_FIELDS,
    MESSAGE_FIELDS,
    REQUEST_FIELDS,
    RUN_FIELDS,
)

SITES = ("s1", "s2", "s3")
SYSTEMS = ("lets", "static-quota", "central-noretry@s2", "central-retry@s1", "raft-quorum")


def _row(
    topology: str,
    system: str,
    site: str,
    seed: int,
    index: int,
    outcome: str,
    t_auth_ns: int | None,
) -> RequestRow:
    return RequestRow(
        run_id=f"{topology}-L0.7-T1-equal-S{seed:03d}",
        topology=topology,
        load=0.7,
        theta=1.0,
        seed=seed,
        placement="equal",
        system=system,
        site=site,
        outcome=outcome,
        arrival_offset_ns=index * 2_000_000_000,
        t_auth_ns=t_auth_ns,
        deadline_ns=20_000_000_000,
        messages=1,
    )


def _requests() -> list[RequestRow]:
    rows = []
    for topology in ("split-s1", "bridge-s3"):
        for seed in (1, 2):
            for system in SYSTEMS:
                for index in range(4):
                    approved = system == "lets" or index < 3 or topology == "bridge-s3"
                    latency = 10_000_000 if system == "static-quota" else 20_000_000 * (index + 1)
                    rows.append(
                        _row(
                            topology,
                            system,
                            SITES[index % 3],
                            seed,
                            index,
                            "authorized" if approved else "timeout",
                            latency if approved else None,
                        )
                    )
    return rows


def _write_csv(path: Path, fields: tuple[str, ...], rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _write_grid(output: Path) -> None:
    (output / "runs").mkdir(parents=True)
    requests = _requests()
    _write_csv(
        output / "requests.csv",
        REQUEST_FIELDS,
        [
            {
                "run_id": row.run_id,
                "topology": row.topology,
                "load": row.load,
                "theta": row.theta,
                "seed": row.seed,
                "placement": row.placement,
                "system": row.system,
                "site": row.site,
                "index": index,
                "request_id": f"r{index:05d}",
                "planned_offset_ns": row.arrival_offset_ns,
                "arrival_offset_ns": row.arrival_offset_ns,
                "outcome": row.outcome,
                "reason": row.outcome,
                "t_auth_ns": "" if row.t_auth_ns is None else row.t_auth_ns,
                "attempts": 1,
                "messages": row.messages,
                "deadline_ns": row.deadline_ns,
            }
            for index, row in enumerate(requests)
        ],
    )
    run_ids = sorted({row.run_id for row in requests})
    events = []
    faults = []
    runs = []
    messages = []
    for run_id in run_ids:
        topology, _, seed = run_id.partition("-L0.7-T1-equal-S")
        for system in SYSTEMS:
            events.append(
                {
                    "run_id": run_id,
                    "system": system,
                    "site": "s1",
                    "offset_ns": 6_000_000_000,
                    "kind": "waiting",
                    "value": 1,
                    "detail": "",
                }
            )
            events.append(
                {
                    "run_id": run_id,
                    "system": system,
                    "site": "s1",
                    "offset_ns": 8_000_000_000,
                    "kind": "waiting",
                    "value": 0,
                    "detail": "",
                }
            )
            authorized = sum(
                1
                for row in requests
                if row.run_id == run_id and row.system == system and row.outcome == "authorized"
            )
            runs.append(
                {
                    "run_id": run_id,
                    "topology": topology,
                    "load": 0.7,
                    "theta": 1.0,
                    "seed": int(seed),
                    "placement": "equal",
                    "envelope": 30,
                    "cluster": "test",
                    "status": "passed",
                    "start_wall_ns": 0,
                    "plan_size": 4,
                    "system": system,
                    "authorized": authorized,
                    "denied": 0,
                    "timeout": 4 - authorized,
                    "effects": authorized,
                    "safety_margin": 30 - authorized,
                    "safety_ok": True,
                    "messages": 4,
                    "dropped_packets": 0,
                }
            )
            for site in SITES:
                messages.append(
                    {
                        "run_id": run_id,
                        "topology": topology,
                        "load": 0.7,
                        "theta": 1.0,
                        "seed": int(seed),
                        "placement": "equal",
                        "system": system,
                        "site": site,
                        "messages": 1,
                    }
                )
        links = "s1-s2,s1-s3" if topology == "split-s1" else "s1-s2"
        for kind, offset in (("cut", 5.0), ("heal", 35.0)):
            faults.append(
                {
                    "run_id": run_id,
                    "scheduled_offset_s": offset,
                    "kind": kind,
                    "link": links,
                    "site": "s1",
                    "command": "",
                    "ok": True,
                    "sent_offset_s": offset,
                    "returned_offset_s": offset,
                }
            )
        (output / "runs" / f"{run_id}.json").write_text(
            json.dumps(
                {
                    "run_id": run_id,
                    "config": {"sites": list(SITES), "envelope": 30, "pre_s": 5.0},
                    "configured": {"s1": {"shares": {"s1": 10, "s2": 10, "s3": 10}}},
                }
            ),
            encoding="utf-8",
        )
    _write_csv(output / "events.csv", EVENT_FIELDS, events)
    _write_csv(output / "faults.csv", FAULT_FIELDS, faults)
    _write_csv(output / "runs.csv", RUN_FIELDS, runs)
    _write_csv(output / "messages.csv", MESSAGE_FIELDS, messages)


def test_pooled_bootstrap_matches_pooled_ratio_and_rejects_empty() -> None:
    mean, low, high = pooled_bootstrap_ci([(3, 4), (4, 4), (2, 4)], resamples=400)
    assert abs(mean - 0.75) < 1e-9 and low <= mean <= high
    assert pooled_bootstrap_ci([(1, 2)]) == (0.5, 0.5, 0.5)
    with pytest.raises(ValueError):
        pooled_bootstrap_ci([])
    with pytest.raises(ValueError):
        pooled_bootstrap_ci([(0, 0)])


def test_reduce_grid_computes_every_table_column(tmp_path: Path) -> None:
    _write_grid(tmp_path)
    grid = paper.load_or_assemble(tmp_path)
    assert isinstance(grid, GridData) and grid.pre_break_s == 5.0 and grid.envelope == 30
    reduction = paper.reduce_grid("synthetic", grid, 0.7, 1.0)
    assert reduction.topologies == ("split-s1", "bridge-s3")
    assert reduction.systems == SYSTEMS
    assert reduction.stranded_topology == "split-s1"
    lets = reduction.completion["split-s1"]["lets"]
    assert lets.completion == 1.0 and lets.ci_low == 1.0 and lets.width_points == 0.0
    static = reduction.completion["split-s1"]["static-quota"]
    assert abs(static.completion - 0.75) < 1e-9 and static.seeds == 2
    assert reduction.completion["bridge-s3"]["raft-quorum"].completion == 1.0
    assert reduction.pre_break_p50_ms["static-quota"] == 10.0
    assert reduction.pre_break_p50_ms["lets"] == 40.0
    assert reduction.stranded_peak_units["static-quota"] == 20
    assert reduction.stranded_unit_seconds["lets"] >= 0.0
    assert reduction.run_system_pairs == 20 and reduction.max_authorized == 4
    assert reduction.all_safety_ok and reduction.all_effects_match
    widest = paper.widest_intervals([reduction])
    assert widest["lets"]["width_points"] == 0.0
    assert widest["baselines"]["topology"] == "split-s1"
    assert paper.isolating_topology(("bridge-s3",), SITES) is None
    assert paper.isolating_topology(("split-s1",), ()) is None
    assert paper.row_key("central-retry@s1") == "central-retry"
    assert paper.row_key("central-noretry@s2") == "central-noretry"
    assert paper.row_key("raft-quorum") == "raft-quorum"


def test_main_writes_markdown_and_json_and_assembles_when_csvs_are_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    grid = tmp_path / "grid"
    _write_grid(grid)
    out = tmp_path / "out"
    assert paper.main(["--grid", f"synthetic={grid}", "--write", str(out)]) == 0
    text = (out / "paper-table.md").read_text(encoding="utf-8")
    assert "| LETS | 1.00 | 1.00 | 40 |" in text
    assert "| Static per-site quotas | 0.75 | 1.00 | 10 | 40 |" in text
    assert "Central counter, no retry" in text and "Central counter, retry" in text
    assert "20 run-system pairs, maximum authorized 4 of 30 units" in text
    assert "every safety check passed, effects equal authorized counts" in text
    assert "## Widest completion intervals" in text
    payload = json.loads((out / "paper-table.json").read_text(encoding="utf-8"))
    assert payload["schema"] == "lets.fair-baselines-paper/v1"
    assert payload["grids"][0]["completion"]["split-s1"]["lets"]["width_points"] == 0.0
    assert set(payload["widest_intervals"]) == {"baselines", "lets"}
    assert paper._range([], 2) == "n/a" and paper._latency([]) == "n/a"
    assert paper._range([0.5, 0.5004], 2) == "0.50" and paper._latency([4.6, 46.0]) == "5 to 46"
    (grid / "requests.csv").unlink()
    calls: list[Path] = []

    def fake_assemble(output_dir: Path) -> dict[str, int]:
        calls.append(output_dir)
        (grid / "requests.csv").write_text(
            ",".join(REQUEST_FIELDS) + "\n", encoding="utf-8", newline="\n"
        )
        return {"runs": 0}

    monkeypatch.setattr(paper, "assemble", fake_assemble)
    assert paper.load_or_assemble(grid).requests == [] and calls == [grid]
    with pytest.raises(SystemExit):
        paper.main(["--grid", "nolabel", "--write", str(out)])
