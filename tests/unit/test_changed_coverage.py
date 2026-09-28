"""Tests scripts/check_changed_coverage.py, the recorder behind the changed-coverage step in
.github/workflows/ci.yml: exact-threshold pass and fail decisions, the explicit not-applicable
outcome with its compared revisions and changed paths, and fail-closed report rejection.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import check_changed_coverage as recorder

COMPARE = "origin/main"
DIFF_NAME = "origin/main...HEAD, staged and unstaged changes"


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        [
            "git",
            "-c",
            "user.name=LETS Test",
            "-c",
            "user.email=lets-test@example.invalid",
            *arguments,
        ],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _repository(tmp_path: Path) -> tuple[Path, str, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--initial-branch=main")
    _write(repository / "src/lets/runtime.py", "VALUE = 1\n")
    _write(repository / "README.md", "base\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "base")
    base = _git(repository, "rev-parse", "HEAD")
    _git(repository, "update-ref", "refs/remotes/origin/main", base)
    _write(repository / "src/lets/runtime.py", "VALUE = 2\n")
    _write(repository / "docs/guide.md", "guide\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "candidate")
    return repository, base, _git(repository, "rev-parse", "HEAD")


def _report(
    path: Path,
    *,
    lines: object = 0,
    violations: object = 0,
    measured: object = None,
    diff_name: object = DIFF_NAME,
) -> Path:
    document = {
        "diff_name": diff_name,
        "num_changed_lines": 3,
        "report_name": "XML",
        "src_stats": {} if measured is None else measured,
        "total_num_lines": lines,
        "total_num_violations": violations,
        "total_percent_covered": 100,
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _run(repository: Path, report: Path, *extra: str) -> tuple[int, Path]:
    output = repository.parent / "decision.json"
    status = recorder.main(
        [
            "--report",
            str(report),
            "--compare-branch",
            COMPARE,
            "--fail-under",
            "90",
            "--output",
            str(output),
            "--repository",
            str(repository),
            *extra,
        ]
    )
    return status, output


def test_unmeasurable_diff_records_explicit_not_applicable_decision(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repository, base, candidate = _repository(tmp_path)
    _write(repository / "README.md", "unstaged\n")
    _write(repository / "docs/staged.md", "staged\n")
    _git(repository, "add", "docs/staged.md")

    status, output = _run(repository, _report(tmp_path / "report.json"))

    decision = json.loads(output.read_text(encoding="utf-8"))
    assert status == 0
    assert decision == {
        "base_sha": base,
        "candidate_sha": candidate,
        "changed_paths": ["README.md", "docs/guide.md", "docs/staged.md", "src/lets/runtime.py"],
        "compare_branch": COMPARE,
        "covered_percent": None,
        "fail_under": 90,
        "measured_lines": 0,
        "measured_paths": [],
        "reason": "the diff has no executable lines in the measured packages",
        "schema": "lets.changed-coverage-decision/v1",
        "status": "not-applicable",
        "uncovered_lines": 0,
    }
    assert json.loads(capsys.readouterr().out) == decision


def test_coverage_exactly_at_threshold_passes(tmp_path: Path) -> None:
    repository, _, _ = _repository(tmp_path)
    report = _report(
        tmp_path / "report.json",
        lines=10,
        violations=1,
        measured={"src/lets/runtime.py": {"percent_covered": 90.0}},
    )

    status, output = _run(repository, report)

    decision = json.loads(output.read_text(encoding="utf-8"))
    assert status == 0
    assert decision["status"] == "pass"
    assert decision["covered_percent"] == 90.0
    assert decision["measured_paths"] == ["src/lets/runtime.py"]


@pytest.mark.parametrize(("lines", "violations"), [(10, 2), (1000, 101)])
def test_measurable_coverage_below_threshold_fails_with_a_recorded_decision(
    tmp_path: Path, lines: int, violations: int
) -> None:
    repository, _, _ = _repository(tmp_path)
    report = _report(
        tmp_path / "report.json",
        lines=lines,
        violations=violations,
        measured={"src/lets/runtime.py": {}},
    )

    status, output = _run(repository, report)

    decision = json.loads(output.read_text(encoding="utf-8"))
    assert status == 1
    assert decision["status"] == "fail"
    assert decision["reason"] == "changed-line coverage is below 90%"
    assert decision["covered_percent"] < 90


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"diff_name": "origin/main..HEAD"}, "compares"),
        ({"lines": -1}, "total_num_lines"),
        ({"lines": True}, "total_num_lines"),
        ({"lines": 2, "violations": 3, "measured": {"src/lets/runtime.py": {}}}, "more uncovered"),
        ({"lines": 2, "measured": []}, "src_stats"),
        ({"lines": 2}, "disagree"),
        ({"measured": {"src/lets/runtime.py": {}}}, "disagree"),
        ({"lines": 2, "measured": {"src/lets/other.py": {}}}, "outside the diff"),
    ],
)
def test_inconsistent_or_mismatched_reports_fail_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    fields: dict[str, object],
    message: str,
) -> None:
    repository, _, _ = _repository(tmp_path)
    report = _report(tmp_path / "report.json", **fields)

    status, output = _run(repository, report)

    assert status == 1
    assert not output.exists()
    assert message in capsys.readouterr().err


@pytest.mark.parametrize("content", ["[]", "{not json", None])
def test_unreadable_or_non_object_reports_fail_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str | None
) -> None:
    repository, _, _ = _repository(tmp_path)
    report = tmp_path / "report.json"
    if content is not None:
        report.write_text(content, encoding="utf-8")

    status, output = _run(repository, report)

    assert status == 1
    assert not output.exists()
    assert "changed-coverage decision failed" in capsys.readouterr().err


def test_missing_compare_branch_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repository, _, _ = _repository(tmp_path)
    _git(repository, "update-ref", "-d", "refs/remotes/origin/main")

    status, output = _run(repository, _report(tmp_path / "report.json"))

    assert status == 1
    assert not output.exists()
    assert "git merge-base" in capsys.readouterr().err


@pytest.mark.parametrize("threshold", ["0", "101", "ninety"])
def test_threshold_must_be_an_integer_percentage(tmp_path: Path, threshold: str) -> None:
    with pytest.raises(SystemExit) as raised:
        recorder.main(
            [
                "--report",
                str(tmp_path / "report.json"),
                "--compare-branch",
                COMPARE,
                "--fail-under",
                threshold,
                "--output",
                str(tmp_path / "decision.json"),
            ]
        )

    assert raised.value.code == 2
