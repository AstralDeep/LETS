from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from benchmarks.nsdi_strengthening import rollback_matrix


def _junit(path: Path, *, tests: int, failures: int = 0) -> None:
    path.write_text(
        (
            '<?xml version="1.0" encoding="utf-8"?>'
            f'<testsuites><testsuite tests="{tests}" failures="{failures}" '
            'errors="0" skipped="0" time="0.25"/></testsuites>'
        ),
        encoding="utf-8",
    )


def _fake_git_state() -> dict[str, object]:
    return {
        "branch": "main",
        "captured_before_evidence_write": True,
        "commit": "a" * 40,
        "dirty": False,
        "status_sha256": "sha256:" + "0" * 64,
    }


def _install_successful_pytest(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    commands: list[list[str]] = []

    def run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
        commands.append(command)
        junit = Path(command[command.index("--junitxml") + 1])
        _junit(junit, tests=len(rollback_matrix.TEST_NODE_IDS))
        return subprocess.CompletedProcess(command, 0, b"complete stdout\n", b"complete stderr\n")

    monkeypatch.setattr(rollback_matrix, "_run_pytest", run)
    monkeypatch.setattr(rollback_matrix, "_git_state", _fake_git_state)
    return commands


def test_requirement_mapping_is_complete_honest_and_uses_exact_selectors() -> None:
    selected = set(rollback_matrix.TEST_NODE_IDS)
    mapped: set[str] = set()
    stale_anchor = None
    for requirement in rollback_matrix.REQUIREMENT_TO_TESTS:
        node_ids = tuple(requirement["test_node_ids"])
        assert set(node_ids) <= selected
        mapped.update(node_ids)
        if requirement["requirement_id"] == "review-8.stale-anchor-replacement":
            stale_anchor = requirement
    assert mapped == selected
    assert len(selected) == len(rollback_matrix.TEST_NODE_IDS)
    assert stale_anchor is not None
    assert stale_anchor["coverage"] == "assumption-boundary-not-directly-tested"
    assert stale_anchor["test_node_ids"] == ()


def test_success_bundle_captures_exact_command_logs_junit_and_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands = _install_successful_pytest(monkeypatch)
    output = tmp_path / "evidence"

    assert rollback_matrix.run_evidence(output) == 0
    assert len(commands) == 1
    command = commands[0]
    assert command[:3] == [rollback_matrix.sys.executable, "-m", "pytest"]
    assert command[-len(rollback_matrix.TEST_NODE_IDS) :] == list(rollback_matrix.TEST_NODE_IDS)
    assert "--junitxml" in command

    assert (output / rollback_matrix.STDOUT_NAME).read_bytes() == b"complete stdout\n"
    assert (output / rollback_matrix.STDERR_NAME).read_bytes() == b"complete stderr\n"
    summary = json.loads((output / rollback_matrix.SUMMARY_NAME).read_text(encoding="utf-8"))
    assert summary["schema"] == rollback_matrix.SCHEMA
    assert summary["passed"] is True
    assert summary["pytest_returncode"] == 0
    assert summary["git"]["commit"] == "a" * 40
    assert summary["environment"]["python_executable"] == rollback_matrix.sys.executable
    assert summary["selected_test_node_ids"] == list(rollback_matrix.TEST_NODE_IDS)
    assert summary["junit"]["tests"] == len(rollback_matrix.TEST_NODE_IDS)
    assert summary["artifacts"]["stdout"]["bytes"] == len(b"complete stdout\n")
    assert len(summary["requirement_to_test_mapping"]) == len(rollback_matrix.REQUIREMENT_TO_TESTS)


def test_existing_evidence_is_refused_before_pytest_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "evidence"
    output.mkdir()
    prior = output / rollback_matrix.SUMMARY_NAME
    prior.write_text("do not replace", encoding="utf-8")
    monkeypatch.setattr(rollback_matrix, "_git_state", _fake_git_state)

    def unexpected(_command: list[str]) -> Any:
        pytest.fail("pytest ran despite an existing evidence conflict")

    monkeypatch.setattr(rollback_matrix, "_run_pytest", unexpected)
    with pytest.raises(rollback_matrix.EvidenceError, match="without --overwrite"):
        rollback_matrix.run_evidence(output)
    assert prior.read_text(encoding="utf-8") == "do not replace"


def test_explicit_overwrite_replaces_only_known_evidence_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_successful_pytest(monkeypatch)
    output = tmp_path / "evidence"
    output.mkdir()
    for name in rollback_matrix.EVIDENCE_NAMES:
        (output / name).write_text("old", encoding="utf-8")
    unrelated = output / "operator-notes.txt"
    unrelated.write_text("keep", encoding="utf-8")

    assert rollback_matrix.run_evidence(output, overwrite=True) == 0
    assert json.loads((output / rollback_matrix.SUMMARY_NAME).read_text())["passed"] is True
    assert unrelated.read_text(encoding="utf-8") == "keep"


def test_pytest_failure_is_retained_and_returns_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rollback_matrix, "_git_state", _fake_git_state)

    def fail(command: list[str]) -> subprocess.CompletedProcess[bytes]:
        junit = Path(command[command.index("--junitxml") + 1])
        _junit(junit, tests=len(rollback_matrix.TEST_NODE_IDS), failures=1)
        return subprocess.CompletedProcess(command, 1, b"failure stdout\n", b"failure stderr\n")

    monkeypatch.setattr(rollback_matrix, "_run_pytest", fail)
    output = tmp_path / "failed"
    assert rollback_matrix.run_evidence(output) == 1
    summary = json.loads((output / rollback_matrix.SUMMARY_NAME).read_text(encoding="utf-8"))
    assert summary["passed"] is False
    assert summary["pytest_returncode"] == 1
    assert summary["junit"]["failures"] == 1
    assert (output / rollback_matrix.STDOUT_NAME).read_bytes() == b"failure stdout\n"
    assert (output / rollback_matrix.STDERR_NAME).read_bytes() == b"failure stderr\n"


def test_junit_failure_cannot_be_hidden_by_zero_process_returncode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rollback_matrix, "_git_state", _fake_git_state)

    def inconsistent(command: list[str]) -> subprocess.CompletedProcess[bytes]:
        junit = Path(command[command.index("--junitxml") + 1])
        _junit(junit, tests=len(rollback_matrix.TEST_NODE_IDS), failures=1)
        return subprocess.CompletedProcess(command, 0, b"stdout\n", b"")

    monkeypatch.setattr(rollback_matrix, "_run_pytest", inconsistent)
    output = tmp_path / "inconsistent"
    assert rollback_matrix.run_evidence(output) == 1
    summary = json.loads((output / rollback_matrix.SUMMARY_NAME).read_text(encoding="utf-8"))
    assert summary["passed"] is False
    assert summary["runner_error"] == "JUnit reported 1 failed tests"


def test_cli_requires_output_dir_and_reports_conflict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "evidence"
    output.mkdir()
    (output / rollback_matrix.JUNIT_NAME).write_text("existing", encoding="utf-8")
    monkeypatch.setattr(rollback_matrix, "_git_state", _fake_git_state)
    assert rollback_matrix.main(["--output-dir", str(output)]) == 2
