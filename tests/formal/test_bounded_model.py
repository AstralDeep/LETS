from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import formal.run_tlc as tlc_runner
from formal.model_checker import Bounds, check_model

ROOT = Path(__file__).resolve().parents[2]


def test_three_warden_bounded_model_preserves_invariants() -> None:
    result = check_model(
        Bounds(
            initial_shares=(1, 1, 1),
            max_leases=3,
            max_transfers=2,
            max_receipts=2,
            max_depth=9,
        )
    )
    evidence = json.loads(
        (ROOT / "formal" / "evidence" / "bounded-check.json").read_text(encoding="utf-8")
    )

    assert result.passed
    assert result.violations == ()
    assert result.states_checked == evidence["states_checked"] == 101_245
    assert result.transitions_checked == evidence["transitions_checked"] == 318_558
    assert result.self_loops_checked == evidence["self_loops_checked"] == 66_072
    assert result.maximum_depth_reached == evidence["maximum_depth_reached"] == 9
    assert result.model_digest == evidence["model_digest"]


def test_duplicate_credit_mutation_produces_conservation_counterexample() -> None:
    result = check_model(
        Bounds(
            initial_shares=(1, 1, 1),
            max_leases=1,
            max_transfers=1,
            max_receipts=1,
            max_depth=4,
        ),
        duplicate_credit_fault=True,
    )

    assert not result.passed
    violation = result.violations[0]
    assert violation.invariant == "global_conservation"
    assert any(action.startswith("duplicate_accept") for action in violation.trace)


def test_tlc_evidence_is_bound_to_the_checked_spec_and_configuration() -> None:
    evidence = json.loads(
        (ROOT / "formal" / "evidence" / "tlc-check.json").read_text(encoding="utf-8")
    )
    tool = json.loads((ROOT / "formal" / "tlc-tool.json").read_text(encoding="utf-8"))

    assert evidence["passed"] is True
    assert evidence["states_left_on_queue"] == 0
    assert evidence["distinct_states"] == 6_776
    assert evidence["tla2tools_jar_sha256"] == tool["sha256"]
    assert evidence["tla2tools_jar_bytes"] == tool["bytes"]
    assert evidence["tla2tools_release"] == tool["release"]
    assert evidence["tlc_version"] == tool["version"]
    assert "-metadir ../results/generated/formal/" in evidence["tlc_command"]
    assert tool["url"].startswith("https://github.com/tlaplus/tlaplus/releases/download/")
    for name, evidence_field in (("LETS.tla", "spec_sha256"), ("LETS.cfg", "config_sha256")):
        digest = hashlib.sha256((ROOT / "formal" / name).read_bytes()).hexdigest()
        assert digest == evidence[evidence_field]


def test_tlc_runner_fails_clearly_without_java(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tlc_runner.shutil, "which", lambda _name: None)

    with pytest.raises(RuntimeError, match="Java 11 or newer"):
        tlc_runner.run_tlc(
            meta_directory=Path("results/generated/formal/not-created"),
            evidence_output=Path("results/generated/formal/not-created.json"),
        )


def test_tlc_runner_rejects_output_outside_generated_evidence() -> None:
    with pytest.raises(ValueError, match="below results/generated/formal"):
        tlc_runner._generated_path(Path("formal/LETS.tla"), "test path")
