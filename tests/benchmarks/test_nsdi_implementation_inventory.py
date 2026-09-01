from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.nsdi_strengthening.implementation_inventory import (
    NARROW_CORE,
    OUTPUT_JSON,
    OUTPUT_MARKDOWN,
    RESULT_SCHEMA,
    generate_inventory,
    write_outputs,
)


def test_inventory_counts_exact_files_and_verifies_facts() -> None:
    root = Path(__file__).resolve().parents[2]
    inventory = generate_inventory(root)

    assert inventory["schema"] == RESULT_SCHEMA
    whole = inventory["groups"]["whole_runtime"]
    narrow = inventory["groups"]["narrow_enforcement_core"]
    assert whole["file_count"] >= narrow["file_count"] == len(NARROW_CORE)
    assert whole["physical_lines"] >= narrow["physical_lines"] > 0
    assert whole["nonblank_lines"] >= narrow["nonblank_lines"] > 0
    assert [record["path"] for record in narrow["files"]] == list(NARROW_CORE)
    assert all(len(record["sha256"]) == 64 for record in whole["files"])
    assert inventory["facts"]
    assert all(fact["verified"] is True for fact in inventory["facts"])
    assert all(evidence["matches"] for fact in inventory["facts"] for evidence in fact["evidence"])


def test_inventory_outputs_are_readable_and_refuse_overwrite(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    inventory = generate_inventory(root)
    output = tmp_path / "inventory"
    paths = write_outputs(inventory, output)

    assert paths == (output / OUTPUT_JSON, output / OUTPUT_MARKDOWN)
    assert json.loads(paths[0].read_text(encoding="utf-8"))["schema"] == RESULT_SCHEMA
    markdown = paths[1].read_text(encoding="utf-8")
    assert markdown.startswith("# LETS implementation inventory")
    assert "Narrow enforcement core" in markdown

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_outputs(inventory, output)
    write_outputs(inventory, output, overwrite=True)
