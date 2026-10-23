"""Tests for benchmarks/fair_baselines/anchor_cost.py: a small paired run with and without
process-file anchors that writes the per-call warden and executor timings and their summary.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.fair_baselines.anchor_cost import main, quantile, summarize


def test_quantile_and_summary_interpolate() -> None:
    assert quantile([4.0, 1.0, 3.0, 2.0], 0.5) == 2.5
    assert quantile([7.0], 0.95) == 7.0
    assert summarize([1.0, 2.0, 3.0]) == {"n": 3, "p50": 2.0, "p95": 2.9, "mean": 2.0}


def test_paired_trials_time_both_configurations(tmp_path: Path) -> None:
    anchors = tmp_path / "anchors"
    anchors.mkdir()
    output = tmp_path / "cost.json"
    assert (
        main(
            [
                "--site",
                "s1",
                "--state-root",
                str(tmp_path / "state"),
                "--anchor-root",
                str(anchors),
                "--trials",
                "2",
                "--calls",
                "3",
                "--warmup",
                "1",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["trial_order"] == [["unanchored", "anchored"], ["anchored", "unanchored"]]
    for config in ("unanchored", "anchored"):
        rows = result["samples"][config]
        assert len(rows) == 6 and {row["trial"] for row in rows} == {0, 1}
        assert all(row["total_us"] >= row["warden_us"] + row["executor_us"] for row in rows)
        assert result["summary_ms"][config]["warden_us"]["n"] == 6
    assert set(result["anchor_added_p50_ms"]) == {"total_us", "warden_us", "executor_us"}
    assert len(list(anchors.glob("*.anchor"))) == 4


def test_main_rejects_too_few_trials(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(
            [
                "--site",
                "s1",
                "--state-root",
                str(tmp_path),
                "--anchor-root",
                str(tmp_path),
                "--trials",
                "1",
                "--output",
                str(tmp_path / "x.json"),
            ]
        )
