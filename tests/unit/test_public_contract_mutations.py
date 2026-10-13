"""Test the bounded public-contract mutation runner's fail-closed evidence classification.
Import, collection, skip, missing-test, and survivor results cannot count as assertion kills.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import check_public_contract_mutations as gate
from scripts.check_public_contract_mutations import classify_result


@pytest.mark.parametrize(
    ("returncode", "body", "mutated", "expected"),
    [
        (0, "", False, "passed"),
        (0, "", True, "survived"),
        (1, '<failure message="Failed: DID NOT RAISE SignatureError"/>', True, "killed"),
        (1, '<failure message="AssertionError: removed export"/>', True, "killed"),
        (1, '<failure message="ImportError: missing dependency"/>', True, "invalid"),
        (1, '<failure message="SyntaxError: invalid syntax"/>', True, "invalid"),
        (1, '<failure message="RuntimeError: disconnected"/>', True, "invalid"),
        (2, '<error message="ImportError"/>', True, "invalid"),
        (0, '<skipped message="disabled"/>', True, "invalid"),
        (1, '<failure message="AssertionError"/>', False, "invalid"),
        (2, '<failure message="AssertionError"/>', True, "invalid"),
    ],
)
def test_mutation_classifier_requires_assertion_failure(
    tmp_path: Path, returncode: int, body: str, mutated: bool, expected: str
) -> None:
    report = tmp_path / "report.xml"
    report.write_text(
        f'<testsuites><testsuite><testcase name="target">{body}</testcase></testsuite></testsuites>'
    )
    status, _ = classify_result(returncode, report, ("target",), mutated=mutated)
    assert status == expected


@pytest.mark.parametrize(
    "cases",
    ["", '<testcase name="other"/>', '<testcase name="target"/><testcase name="target"/>'],
)
def test_mutation_classifier_requires_exact_focused_tests(tmp_path: Path, cases: str) -> None:
    report = tmp_path / "report.xml"
    report.write_text(f"<testsuites><testsuite>{cases}</testsuite></testsuites>")
    status, _ = classify_result(0, report, ("target",), mutated=True)
    assert status == "invalid"


@pytest.mark.parametrize("content", [None, "broken XML"])
def test_mutation_classifier_requires_readable_evidence(
    tmp_path: Path, content: str | None
) -> None:
    report = tmp_path / "report.xml"
    if content is not None:
        report.write_text(content)
    status, _ = classify_result(1, report, ("target",), mutated=True)
    assert status == "invalid"


def test_real_mutation_gate_kills_all_guards_without_changing_sources(tmp_path: Path) -> None:
    sources = {mutation.path for mutation in gate.MUTATIONS}
    before = {path: (gate.ROOT / "src" / path).read_bytes() for path in sources}
    receipt = gate.qualify(tmp_path / "receipt.json")
    assert receipt["status"] == "passed"
    assert receipt["baseline"]["status"] == "passed"
    assert len(receipt["mutations"]) == 5
    assert all(row["status"] == "killed" for row in receipt["mutations"])
    assert before == {path: (gate.ROOT / "src" / path).read_bytes() for path in sources}


@pytest.mark.parametrize("baseline_status", ["invalid", "survived"])
def test_mutation_gate_requires_passing_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, baseline_status: str
) -> None:
    monkeypatch.setattr(gate, "run_focused", lambda *args, **kwargs: (baseline_status, {}))
    receipt = gate.qualify(tmp_path / "receipt.json")
    assert receipt["status"] == "failed"
    assert receipt["mutations"] == []


def test_mutation_gate_requires_unique_guard_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gate, "run_focused", lambda *args, **kwargs: ("passed", {}))
    monkeypatch.setattr(
        gate, "MUTATIONS", (gate.Mutation("missing", "lets/executor.py", "absent guard", "", ()),)
    )
    receipt = gate.qualify(tmp_path / "receipt.json")
    assert receipt["status"] == "failed"
    assert receipt["mutations"][0]["status"] == "invalid"


@pytest.mark.parametrize("status", ["survived", "invalid"])
def test_mutation_gate_rejects_survivors_and_invalid_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    monkeypatch.setattr(
        gate,
        "run_focused",
        lambda *args, **kwargs: (status if kwargs["mutated"] else "passed", {}),
    )
    monkeypatch.setattr(gate, "MUTATIONS", (gate.MUTATIONS[0],))
    assert gate.qualify(tmp_path / "receipt.json")["status"] == "failed"


def test_focused_execution_timeout_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def timeout(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired("focused-test", 60)

    monkeypatch.setattr(gate.subprocess, "run", timeout)
    status, _ = gate.run_focused(tmp_path, tmp_path / "receipt", ("test_target",), mutated=True)
    assert status == "invalid"


def test_failed_source_bootstrap_cannot_reuse_a_prior_mutation_failure(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "receipt"
    report = output.with_suffix(".xml")
    report.write_text(
        '<testsuites><testsuite><testcase name="test_target">'
        '<failure message="AssertionError: prior mutation"/>'
        "</testcase></testsuite></testsuites>"
    )
    output.with_suffix(".log").write_text("prior execution")
    assert classify_result(1, report, ("test_target",), mutated=True)[0] == "killed"
    status, details = gate.run_focused(source, output, ("test_target",), mutated=True)
    assert status == "invalid", details
    assert not report.exists()
    log = output.with_suffix(".log").read_text()
    assert "prior execution" not in log
    assert "Traceback" in log


@pytest.mark.parametrize(("status", "exit_code"), [("passed", 0), ("failed", 1)])
def test_mutation_cli_preserves_gate_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str, exit_code: int
) -> None:
    output = tmp_path / "receipt.json"
    monkeypatch.setattr(sys, "argv", ["mutation-gate", "--output", str(output)])
    monkeypatch.setattr(gate, "qualify", lambda path: {"status": status})
    assert gate.main() == exit_code
    assert json.loads(output.read_text()) == {"status": status}
