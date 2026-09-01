from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import lets
from benchmarks.nsdi_strengthening.matched_host_path import (
    EXPECTED_ASTRALDEEP_COMMIT,
    EXPECTED_COMPONENTS,
    OUTPUT_CSV,
    OUTPUT_JSON,
    OUTPUT_MARKDOWN,
    BenchmarkRefusal,
    _authority_helper_command,
    _exclusive,
    _harness_repository_identity,
    _summary,
    _validate_composition_document,
    write_outputs,
)


def _document() -> dict[str, object]:
    return {
        "format": "lets.nsdi-matched-host-path/v1",
        "claim": "replacement-current-composition-not-historical-reproduction",
        "configuration": {"trials": 1, "operations": 1, "warmups": 0},
        "environment": {
            "astraldeep": {"revision": EXPECTED_ASTRALDEEP_COMMIT},
            "components": EXPECTED_COMPONENTS,
        },
        "scope": {
            "historical_artifact_available": False,
            "included": [],
            "excluded": [],
        },
        "trials": [
            {
                "trial": 0,
                "order_ordinal": 0,
                "mode": "enforce",
                "summary_ns": {
                    "end_to_end_ns": {
                        "minimum": 100,
                        "p50": 100,
                        "mean": 100,
                        "p95": 100,
                        "p99": 100,
                        "maximum": 100,
                    }
                },
                "samples": [
                    {
                        "format": "lets.nsdi-matched-host-path-sample/v1",
                        "mode": "enforce",
                        "operation_index": 0,
                        "result": 1,
                        "timing_ns": {"end_to_end_ns": 100, "application_ns": 1},
                        "exclusive_ns": {"host_dispatch_framework_ns": 99},
                        "span_counts": {"end_to_end_ns": 1},
                    }
                ],
            }
        ],
    }


def test_exclusive_decomposition_subtracts_only_nested_spans() -> None:
    values = {
        "end_to_end_ns": 1_000,
        "host_runtime_resolver_ns": 10,
        "host_plane_transaction_ns": 20,
        "host_context_policy_ns": 30,
        "host_gateway_inclusive_ns": 400,
        "warden_request_inclusive_ns": 300,
        "warden_transaction_ns": 250,
        "warden_signing_serialization_ns": 50,
        "coordinator_prepare_ns": 5,
        "coordinator_receipt_ns": 5,
        "audit_ns": 10,
        "executor_claim_invoke_inclusive_ns": 500,
        "executor_gateway_inclusive_ns": 400,
        "executor_verifier_inclusive_ns": 300,
        "executor_verify_ns": 25,
        "replay_claim_ns": 250,
        "replay_transaction_ns": 225,
        "rollback_anchor_claim_ns": 125,
        "executor_replay_status_inclusive_ns": 80,
        "rollback_anchor_status_ns": 60,
        "coordinator_claim_ns": 10,
        "coordinator_outcome_ns": 10,
        "application_ns": 5,
    }

    result = _exclusive(values)

    assert result["warden_transaction_exclusive_ns"] == 200
    assert result["warden_request_adapter_ns"] == 50
    assert result["host_gateway_other_ns"] == 80
    assert result["executor_replay_transaction_exclusive_ns"] == 100
    assert result["executor_replay_claim_overhead_ns"] == 25
    assert result["executor_verifier_overhead_ns"] == 25
    assert result["executor_replay_status_exclusive_ns"] == 20
    assert result["rollback_anchor_claim_exclusive_ns"] == 125
    assert result["rollback_anchor_status_exclusive_ns"] == 60
    assert result["receipt_handoff_host_validation_ns"] == 10
    assert result["executor_bookkeeping_ns"] == 85
    assert result["host_dispatch_framework_ns"] == 40
    assert sum(result.values()) == values["end_to_end_ns"]


def test_summary_uses_median_and_nearest_rank_tails() -> None:
    result = _summary((1, 2, 100, 200))

    assert result["p50"] == 51
    assert result["p95"] == 200


def test_composition_validation_requires_current_reference_pins() -> None:
    document = {
        "components": {
            "astral-plane": {"commit": EXPECTED_COMPONENTS["astral-plane"]},
            "lets": {
                "commit": EXPECTED_COMPONENTS["lets"],
                "ref": "v1.0.11",
            },
        }
    }
    assert _validate_composition_document(document) is document

    document["components"]["lets"]["commit"] = "0" * 40  # type: ignore[index]
    with pytest.raises(BenchmarkRefusal, match="lets pin"):
        _validate_composition_document(document)


def test_standalone_harness_records_source_identity_without_git(tmp_path: Path) -> None:
    source = tmp_path / "one" / "two" / "matched_host_path.py"
    source.parent.mkdir(parents=True)
    source.write_text("standalone benchmark\n", encoding="utf-8")

    identity = _harness_repository_identity(source)

    assert identity["available"] is False
    assert identity["reason"] == "standalone-source-upload"
    assert len(str(identity["benchmark_sha256"])) == 64


def test_authority_helper_launches_from_exact_source_without_installed_package(
    tmp_path: Path,
) -> None:
    command = _authority_helper_command(SimpleNamespace(lets_package=lets))

    completed = subprocess.run(
        (*command, "--path", str(tmp_path / "executor.anchor")),
        input=b"",
        capture_output=True,
        check=False,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")


def test_outputs_are_raw_labeled_and_refuse_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "matched"

    paths = write_outputs(_document(), output, overwrite=False)

    assert paths == (
        output / OUTPUT_JSON,
        output / OUTPUT_CSV,
        output / OUTPUT_MARKDOWN,
    )
    payload = json.loads((output / OUTPUT_JSON).read_text(encoding="utf-8"))
    assert payload["claim"] == "replacement-current-composition-not-historical-reproduction"
    csv_text = (output / OUTPUT_CSV).read_text(encoding="utf-8")
    assert "end_to_end_ns" in csv_text
    markdown = (output / OUTPUT_MARKDOWN).read_text(encoding="utf-8")
    assert "not an exact" in markdown
    assert "74.778 ms" in markdown

    with pytest.raises(BenchmarkRefusal, match="overwrite"):
        write_outputs(_document(), output, overwrite=False)
    write_outputs(_document(), output, overwrite=True)


def test_outputs_refuse_unexpected_files_even_with_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "matched"
    output.mkdir()
    (output / "foreign.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(BenchmarkRefusal, match="unexpected"):
        write_outputs(_document(), output, overwrite=True)
