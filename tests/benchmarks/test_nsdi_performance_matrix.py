from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from benchmarks.nsdi_strengthening.performance_matrix import (
    OUTPUT_CSV,
    OUTPUT_JSON,
    OUTPUT_MARKDOWN,
    RESULT_SCHEMA,
    MatrixConfiguration,
    run_matrix,
    write_outputs,
)


def test_real_durable_matrix_retains_exclusive_raw_samples(tmp_path: Path) -> None:
    result = run_matrix(
        [tmp_path / "storage"],
        MatrixConfiguration(
            trials=1,
            operations=2,
            warmup_per_worker=0,
            delays_ms=(0.0,),
            workers=(2,),
            anchor_mode="file",
        ),
    )

    assert result["schema"] == RESULT_SCHEMA
    assert len(result["trials"]) == 2
    by_mode = {trial["mode"]: trial for trial in result["trials"]}
    assert set(by_mode) == {"off", "enforce"}
    assert len(set(by_mode["enforce"]["worker_lease_ids"])) == 2
    assert by_mode["enforce"]["conservation_healthy"] is True
    assert by_mode["enforce"]["executor_rollback_protected"] is True
    assert by_mode["enforce"]["independent_rollback_domain_established"] is False

    for sample in by_mode["off"]["samples"]:
        assert sample["warden_ns"] == 0
        assert sample["claim_ns"] == 0
        assert sample["application_ns"] >= 0
        assert sample["end_to_end_ns"] >= sample["application_ns"]
    for sample in by_mode["enforce"]["samples"]:
        assert sample["warden_ns"] > 0
        assert sample["claim_ns"] > 0
        assert sample["application_ns"] >= 0
        assert sample["end_to_end_ns"] >= (
            sample["warden_ns"] + sample["claim_ns"] + sample["application_ns"]
        )

    assert len(result["aggregates"]) == 2
    for aggregate in result["aggregates"]:
        assert aggregate["operations"] == 2
        assert aggregate["latency_ns"]["end_to_end_ns"]["p99"] > 0
        assert aggregate["throughput_ops_per_second"]["p50"] > 0


def test_performance_outputs_are_complete_and_refuse_overwrite(tmp_path: Path) -> None:
    result = run_matrix(
        [tmp_path / "storage"],
        MatrixConfiguration(
            trials=1,
            operations=1,
            warmup_per_worker=0,
            delays_ms=(0.0,),
            workers=(1,),
            anchor_mode="unanchored",
        ),
    )
    output = tmp_path / "output"
    paths = write_outputs(result, output)

    assert paths == (
        output / OUTPUT_JSON,
        output / OUTPUT_CSV,
        output / OUTPUT_MARKDOWN,
    )
    assert json.loads(paths[0].read_text(encoding="utf-8"))["schema"] == RESULT_SCHEMA
    with paths[1].open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert {row["mode"] for row in rows} == {"off", "enforce"}
    assert paths[2].read_text(encoding="utf-8").startswith("# LETS performance matrix")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_outputs(result, output)
    write_outputs(result, output, overwrite=True)


def test_matrix_rejects_worker_counts_larger_than_operation_count(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least the largest worker count"):
        run_matrix(
            [tmp_path / "storage"],
            MatrixConfiguration(operations=1, workers=(2,), delays_ms=(0.0,)),
        )
