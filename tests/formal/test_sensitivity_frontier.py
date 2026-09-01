from __future__ import annotations

import json
from pathlib import Path

import pytest

from formal.model_checker import Bounds
from formal.sensitivity_frontier import (
    MUTANTS,
    analyze_frontier,
    analyze_sensitivity_suite,
    main,
)


def test_frontier_reports_shortest_depth_counts_and_unseen_cutoff() -> None:
    result = analyze_frontier(
        Bounds(
            initial_shares=(1, 1),
            max_leases=1,
            max_transfers=1,
            max_receipts=1,
            max_depth=1,
        )
    )

    assert result["passed"] is True
    assert result["termination"] == "depth_limit"
    assert result["frontier_exhausted"] is False
    assert result["states_by_shortest_depth"]["0"] == 1
    assert result["states_by_shortest_depth"]["1"] > 0
    assert result["cutoff_states"] == result["states_by_shortest_depth"]["1"]
    assert result["transitions_by_source_shortest_depth"]["0"] > 0
    assert result["cutoff_probe_transitions"] > 0
    assert result["unseen_successors_at_cutoff"] > 0
    assert sum(result["states_by_shortest_depth"].values()) == result["states_checked"]


def test_frontier_explicitly_reports_exhaustion() -> None:
    result = analyze_frontier(
        Bounds(
            initial_shares=(0, 0),
            max_leases=1,
            max_transfers=1,
            max_receipts=1,
            max_depth=2,
        )
    )

    assert result["passed"] is True
    assert result["termination"] == "frontier_exhausted"
    assert result["frontier_exhausted"] is True
    assert result["states_by_shortest_depth"] == {"0": 1}
    assert result["cutoff_states"] == 0
    assert result["unseen_successors_at_cutoff"] == 0


def test_sensitivity_baseline_passes_and_every_isolated_mutant_is_killed() -> None:
    result = analyze_sensitivity_suite(timeout_seconds=30)

    assert result["baseline_passed"] is True
    assert result["all_mutants_killed"] is True
    assert result["passed"] is True
    assert result["baseline"]["violated_property"] is None

    expected = {mutant.mutant_id: mutant.expected_property for mutant in MUTANTS}
    observed = {item["mutant_id"]: item for item in result["mutants"]}
    assert observed.keys() == expected.keys()
    for mutant_id, expected_property in expected.items():
        item = observed[mutant_id]
        assert item["killed"] is True
        assert item["expected_property_killed"] is True
        assert item["violated_property"] == expected_property
        assert item["counterexample_depth"] == len(item["trace"])
        assert item["counterexample_depth"] > 0
        assert item["states_checked"] > 0
        assert item["transitions_checked"] > 0
        assert item["model_digest"].startswith("sha256:")
        assert item["analyzer_digest"].startswith("sha256:")


def test_cli_all_writes_json_and_markdown_and_refuses_silent_overwrite(
    tmp_path: Path,
) -> None:
    output = tmp_path / "frontier.json"
    markdown = tmp_path / "frontier.md"
    arguments = [
        "--mode",
        "all",
        "--shares",
        "0",
        "0",
        "--depth",
        "2",
        "--leases",
        "1",
        "--transfers",
        "1",
        "--receipts",
        "1",
        "--output",
        str(output),
        "--markdown-output",
        str(markdown),
    ]

    assert main(arguments) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    rendered = markdown.read_text(encoding="utf-8")
    assert payload["frontier"]["frontier_exhausted"] is True
    assert payload["sensitivity"]["baseline_passed"] is True
    assert payload["sensitivity"]["all_mutants_killed"] is True
    assert "## Frontier" in rendered
    assert "## Mutation sensitivity" in rendered

    with pytest.raises(FileExistsError, match="without --overwrite"):
        main(arguments)

    assert main([*arguments, "--overwrite"]) == 0


def test_cli_returns_nonzero_when_the_bound_cannot_kill_every_mutant(
    tmp_path: Path,
) -> None:
    output = tmp_path / "shallow.json"

    exit_code = main(
        [
            "--mode",
            "sensitivity",
            "--sensitivity-depth",
            "1",
            "--output",
            str(output),
        ]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["sensitivity"]["baseline_passed"] is True
    assert payload["sensitivity"]["all_mutants_killed"] is False
    assert exit_code == 1
