from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from benchmarks.nsdi_strengthening.distributed_partition import (
    SCHEMA,
    _schedule,
    run_experiment,
    write_outputs,
)


def test_weighted_schedule_is_deterministic_and_exact() -> None:
    balanced = _schedule(300, (1, 1, 1))
    skewed = _schedule(300, (70, 15, 15))

    assert [balanced.count(site) for site in ("site-a", "site-b", "site-c")] == [
        100,
        100,
        100,
    ]
    assert [skewed.count(site) for site in ("site-a", "site-b", "site-c")] == [
        210,
        45,
        45,
    ]
    assert balanced == _schedule(300, (1, 1, 1))
    assert skewed == _schedule(300, (70, 15, 15))


def test_real_partition_matrix_preserves_scope_and_expected_tradeoff(
    tmp_path: Path,
) -> None:
    result = run_experiment(tmp_path / "workspace")

    assert result["schema"] == SCHEMA
    assert result["topology"]["independent_warden_databases"] is True
    assert result["topology"]["independent_executor_claim_databases"] is True
    assert result["topology"]["independent_hosts"] is False
    runs = {(run["scenario"], run["scheme"]): run for run in result["runs"]}

    balanced_lets = runs[("balanced_equal_shares", "lets")]["summary"]
    balanced_central = runs[("balanced_equal_shares", "centralized_counter")]["summary"]
    assert (balanced_lets["authorized"], balanced_lets["denied"]) == (300, 0)
    assert (balanced_central["authorized"], balanced_central["denied"]) == (250, 50)

    skewed_lets = runs[("skew_equal_shares", "lets")]
    assert (skewed_lets["summary"]["authorized"], skewed_lets["summary"]["denied"]) == (
        253,
        47,
    )
    assert skewed_lets["summary"]["remote_spendable_at_first_exhaustion"] == 157
    assert sum(transfer["amount"] for transfer in skewed_lets["recovery_transfers"]) == 63
    assert all(transfer["accepted_once"] for transfer in skewed_lets["recovery_transfers"])
    assert all(transfer["finalized"] for transfer in skewed_lets["recovery_transfers"])

    placed_lets = runs[("skew_demand_placed_shares", "lets")]["summary"]
    assert (placed_lets["authorized"], placed_lets["denied"]) == (300, 0)
    for run in result["runs"]:
        if run["scheme"] == "lets":
            assert run["summary"]["conservation_healthy"] is True
            assert run["summary"]["final_aggregate"]["healthy"] is True
        else:
            assert run["summary"]["counter_identity_healthy"] is True

    output = tmp_path / "output"
    write_outputs(result, output, overwrite=False)
    assert (
        json.loads((output / "partition-results.json").read_text(encoding="utf-8"))["schema"]
        == SCHEMA
    )
    with (output / "partition-events.csv").open(newline="", encoding="utf-8") as handle:
        assert len(list(csv.DictReader(handle))) == 1_800
    assert (
        (output / "partition-skew-equal-shares.svg").read_text(encoding="utf-8").startswith("<svg")
    )
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_outputs(result, output, overwrite=False)


def test_partition_matrix_rejects_misleading_scaled_inputs(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="multiple of 300"):
        run_experiment(tmp_path, total_requests=30, partition_start=6, partition_end=21)
