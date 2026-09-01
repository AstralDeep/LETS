from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from benchmarks.nsdi_strengthening.lineage_scaling import (
    SCHEMA,
    _tree_nodes,
    run_lineage_scaling,
    write_outputs,
)


def test_tree_node_count_handles_spines_and_complete_trees() -> None:
    assert _tree_nodes(8, 1) == 9
    assert _tree_nodes(2, 2) == 7
    assert _tree_nodes(4, 8) == 4_681


def test_real_lineage_probe_measures_declared_shapes_and_depth_limit(
    tmp_path: Path,
) -> None:
    result = run_lineage_scaling(
        tmp_path,
        depths=(2,),
        branching_factors=(2,),
        complete_node_cap=10,
        max_workers=2,
    )

    assert result["schema"] == SCHEMA
    rows = {row["shape"]: row for row in result["rows"]}
    assert rows["spine_fanout"]["nodes"] == 5
    assert rows["spine_fanout"]["leaves_authorized"] == 3
    assert rows["complete_tree"]["nodes"] == 7
    assert rows["complete_tree"]["leaves_authorized"] == 4
    for row in rows.values():
        assert row["status"] == "passed"
        assert row["final_accounting"]["healthy"] is True
        assert row["final_accounting"]["consumed"] == [row["leaves_authorized"]]
        assert row["reopen_integrity"] == ["ok"]

    assert result["depth_limit_probe"] == {
        "maximum_accepted_depth": 64,
        "next_depth": 65,
        "next_depth_rejected": True,
        "error_code": "policy_denied",
    }


def test_outputs_are_machine_readable_and_refuse_accidental_overwrite(
    tmp_path: Path,
) -> None:
    result = run_lineage_scaling(
        tmp_path / "workspace",
        depths=(1,),
        branching_factors=(1,),
        complete_node_cap=10,
        max_workers=1,
        include_depth_limit_probe=False,
    )
    output = tmp_path / "output"
    write_outputs(result, output, overwrite=False)

    assert (
        json.loads((output / "lineage-scaling.json").read_text(encoding="utf-8"))["schema"]
        == SCHEMA
    )
    with (output / "lineage-scaling.csv").open(newline="", encoding="utf-8") as handle:
        assert len(list(csv.DictReader(handle))) == 2
    assert (
        (output / "LINEAGE-RESULTS.md")
        .read_text(encoding="utf-8")
        .startswith("# Lineage depth and branching results")
    )

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_outputs(result, output, overwrite=False)
    write_outputs(result, output, overwrite=True)
