from __future__ import annotations

import csv
import json
from pathlib import Path

from benchmarks.run import RESULT_SCHEMA, run_benchmarks, write_results


def test_benchmark_harness_smoke_preserves_production_durability(tmp_path: Path) -> None:
    result = run_benchmarks(
        tmp_path / "workspace",
        iterations=2,
        warmup=0,
        workers=2,
        include_diagnostics=False,
    )

    assert result["schema"] == RESULT_SCHEMA
    assert result["non_production_diagnostics"] == []
    assert result["production_results"]
    for measurement in result["production_results"]:
        assert measurement["production_semantics"] is True
        assert measurement["operations"] > 0
        assert measurement["throughput_ops_per_second"] > 0
        assert measurement["latency_ns"]["minimum"] > 0
        if "full_fsync" in measurement["name"]:
            assert "synchronous=FULL" in measurement["durability"]
        if "conservation_healthy" in measurement:
            assert measurement["conservation_healthy"] is True

    json_path, csv_path = write_results(result, tmp_path / "result.json")
    assert json.loads(json_path.read_text(encoding="utf-8"))["schema"] == RESULT_SCHEMA
    assert csv_path.read_text(encoding="utf-8").startswith("name,production_semantics")


def test_sqlite_comparisons_are_explicitly_non_production(tmp_path: Path) -> None:
    result = run_benchmarks(
        tmp_path / "workspace",
        iterations=1,
        warmup=0,
        workers=1,
        include_diagnostics=True,
    )

    diagnostics = result["non_production_diagnostics"]
    assert {item["name"] for item in diagnostics} == {
        "diagnostic.sqlite.full.batch",
        "diagnostic.sqlite.full.per_commit",
        "diagnostic.sqlite.normal.per_commit",
    }
    assert all(item["production_semantics"] is False for item in diagnostics)
    assert all("bypasses LETS" in item["notes"][0] for item in diagnostics)


def test_reviewed_baseline_is_machine_readable() -> None:
    root = Path(__file__).resolve().parents[2]
    baseline = json.loads(
        (root / "benchmarks/baselines/windows10-python314.json").read_text(encoding="utf-8")
    )
    assert baseline["schema"] == "lets.reviewed-benchmark-baseline/v1"
    assert baseline["method"]["production_storage"].endswith("one atomic transaction per stage")
    assert baseline["keeper_connection_experiment"]["decision"] == ("reject_keeper_connection")
    assert all(
        item["before"]["median_ns"] > 0 and item["after"]["median_ns"] > 0
        for item in baseline["production_comparison"]
    )

    with (root / "benchmarks/baselines/windows10-python314.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))
    assert rows
    assert {row["production_semantics"] for row in rows} == {"true"}
