import json
from pathlib import Path

import pytest

from formal.vector_model_checker import (
    ACTION_COSTS,
    Bounds,
    main,
    run_suite,
)


def test_baseline_covers_vector_actions_and_preserves_invariants() -> None:
    result = run_suite()
    baseline = result["baseline"]

    assert result["success"] is True
    assert baseline["passed"] is True
    assert result["action_costs"] == {
        "inspect_configuration": [1, 0],
        "restart_service": [0, 3],
        "rotate_credential": [1, 5],
    }
    assert {item.cost for item in ACTION_COSTS} == {(1, 0), (0, 3), (1, 5)}
    assert baseline["action_counts"]["spawn"] > 0
    assert baseline["action_counts"]["prepare_transfer"] > 0
    assert baseline["action_counts"]["accept_transfer"] > 0
    for action in (
        "inspect_configuration",
        "restart_service",
        "rotate_credential",
    ):
        assert baseline["action_counts"][f"authorize:{action}"] > 0
    assert isinstance(baseline["frontier_exhausted"], bool)
    assert baseline["termination"] in {"frontier_exhausted", "depth_limit"}


def test_cross_dimension_mutant_has_shortest_counterexample() -> None:
    mutant = run_suite()["mutant"]

    assert mutant["killed"] is True
    assert mutant["passed"] is False
    assert mutant["violated_property"] == "per_dimension_conservation"
    assert mutant["counterexample_depth"] == len(mutant["shortest_trace"]) == 2
    assert mutant["shortest_trace"][0]["action"].startswith("issue_root")
    assert mutant["shortest_trace"][-1]["action"].startswith("MUTANT_cross_dimension_debit")


def test_small_depth_records_an_unexhausted_frontier() -> None:
    baseline = run_suite(Bounds(max_depth=1))["baseline"]

    assert baseline["termination"] == "depth_limit"
    assert baseline["frontier_exhausted"] is False
    assert baseline["cutoff_states"] > 0
    assert baseline["unseen_successors_at_cutoff"] > 0


def test_cli_writes_json_and_markdown_and_refuses_silent_overwrite(
    tmp_path: Path,
) -> None:
    json_path = tmp_path / "vector.json"
    markdown_path = tmp_path / "vector.md"
    args = [
        "--max-depth",
        "4",
        "--json-out",
        str(json_path),
        "--markdown-out",
        str(markdown_path),
    ]

    assert main(args) == 0
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["success"] is True
    assert "Two-dimensional bounded model-checking results" in markdown_path.read_text(
        encoding="utf-8"
    )
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        main(args)
    assert main([*args, "--overwrite"]) == 0
