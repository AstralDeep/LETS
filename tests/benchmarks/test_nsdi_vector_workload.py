from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from benchmarks.nsdi_strengthening.vector_workload import (
    BUDGET,
    SCHEMA,
    run_vector_workload,
    vector_policy,
    write_outputs,
)


def test_policy_contains_heterogeneous_multidimensional_costs() -> None:
    policy = vector_policy()
    costs = {transition.name: transition.cost for transition in policy.machine.transitions}

    assert tuple(dimension.id for dimension in policy.dimensions) == ("read", "system")
    assert costs["inspect_configuration"] == (1, 0)
    assert costs["restart_service"] == (0, 3)
    assert costs["rotate_credential"] == (1, 5)


def test_real_vector_workload_conserves_each_dimension_and_retains_debit(
    tmp_path: Path,
) -> None:
    result = run_vector_workload(tmp_path / "workspace")

    assert result["schema"] == SCHEMA
    assert result["final"]["conserved"] == list(BUDGET)
    assert result["final"]["identity_holds"] is True
    assert result["final"]["spendable_bound_holds"] is True
    assert result["final"]["local_invariants_healthy"] is True
    assert result["final"]["transferred_in"] == [4, 10]
    assert result["final"]["transferred_out"] == [4, 10]
    assert all(result["checks"].values())

    receipts = result["receipt_accounting"]
    assert receipts["issued_receipts"] == 12
    assert receipts["claimed_receipts"] == 11
    assert receipts["unclaimed_cost"] == [0, 3]
    assert receipts["authority_refunded_after_expiry"] is False


def test_vector_outputs_are_complete_and_refuse_overwrite(tmp_path: Path) -> None:
    result = run_vector_workload(tmp_path / "workspace")
    output = tmp_path / "output"
    write_outputs(result, output, overwrite=False)

    assert (
        json.loads((output / "vector-workload.json").read_text(encoding="utf-8"))["schema"]
        == SCHEMA
    )
    with (output / "vector-transitions.csv").open(newline="", encoding="utf-8") as handle:
        assert len(list(csv.DictReader(handle))) == len(result["operations"])
    assert (
        (output / "VECTOR-RESULTS.md")
        .read_text(encoding="utf-8")
        .startswith("# Resource-vector and debit/claim results")
    )
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_outputs(result, output, overwrite=False)
