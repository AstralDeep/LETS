"""Tests scripts/check_changed_coverage.py, the recorder behind the changed-coverage step in
.github/workflows/ci.yml: base-commit validation, exact-threshold pass and fail decisions, the
explicit not-applicable outcome naming both revisions, and fail-closed report rejection.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import check_changed_coverage as recorder


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
    _write(repository / "src/lets/runtime.py", "VALUE = 2\n")
    _write(repository / "docs/guide.md", "guide\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "candidate")
    return repository, base, _git(repository, "rev-parse", "HEAD")


def _report(
    path: Path,
    base: str,
    *,
    lines: object = 0,
    violations: object = 0,
    measured: object = None,
    diff_name: object = None,
) -> Path:
    document = {
        "diff_name": f"{base}..HEAD, staged and unstaged changes"
        if diff_name is None
        else diff_name,
        "num_changed_lines": 3,
        "report_name": "XML",
        "src_stats": {} if measured is None else measured,
        "total_num_lines": lines,
        "total_num_violations": violations,
        "total_percent_covered": 100,
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _run(repository: Path, report: Path, base: str) -> tuple[int, Path]:
    output = repository.parent / "decision.json"
    status = recorder.main(
        [
            "--report",
            str(report),
            "--base-sha",
            base,
            "--fail-under",
            "90",
            "--output",
            str(output),
            "--repository",
            str(repository),
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

    status, output = _run(repository, _report(tmp_path / "report.json", base), base)

    decision = json.loads(output.read_text(encoding="utf-8"))
    assert status == 0
    assert decision == {
        "base_sha": base,
        "candidate_sha": candidate,
        "changed_paths": ["README.md", "docs/guide.md", "docs/staged.md", "src/lets/runtime.py"],
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


def test_diff_is_the_exact_range_from_the_base_commit(tmp_path: Path) -> None:
    repository, _, _ = _repository(tmp_path)
    middle = _git(repository, "rev-parse", "HEAD")
    _write(repository / "src/lets/extra.py", "EXTRA = 1\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "pushed")

    status, output = _run(repository, _report(tmp_path / "report.json", middle), middle)

    decision = json.loads(output.read_text(encoding="utf-8"))
    assert status == 0
    assert decision["base_sha"] == middle
    assert decision["changed_paths"] == ["src/lets/extra.py"]


def test_coverage_exactly_at_threshold_passes(tmp_path: Path) -> None:
    repository, base, _ = _repository(tmp_path)
    report = _report(
        tmp_path / "report.json",
        base,
        lines=10,
        violations=1,
        measured={"src/lets/runtime.py": {"percent_covered": 90.0}},
    )

    status, output = _run(repository, report, base)

    decision = json.loads(output.read_text(encoding="utf-8"))
    assert status == 0
    assert decision["status"] == "pass"
    assert decision["covered_percent"] == 90.0
    assert decision["measured_paths"] == ["src/lets/runtime.py"]


@pytest.mark.parametrize(("lines", "violations"), [(10, 2), (1000, 101)])
def test_measurable_coverage_below_threshold_fails_with_a_recorded_decision(
    tmp_path: Path, lines: int, violations: int
) -> None:
    repository, base, candidate = _repository(tmp_path)
    report = _report(
        tmp_path / "report.json",
        base,
        lines=lines,
        violations=violations,
        measured={"src/lets/runtime.py": {}},
    )

    status, output = _run(repository, report, base)

    decision = json.loads(output.read_text(encoding="utf-8"))
    assert status == 1
    assert decision["status"] == "fail"
    assert decision["reason"] == "changed-line coverage is below 90%"
    assert decision["covered_percent"] < 90
    assert (decision["base_sha"], decision["candidate_sha"]) == (base, candidate)


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"diff_name": "origin/main...HEAD, staged and unstaged changes"}, "compares"),
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
    repository, base, _ = _repository(tmp_path)
    report = _report(tmp_path / "report.json", base, **fields)

    status, output = _run(repository, report, base)

    assert status == 1
    assert not output.exists()
    assert message in capsys.readouterr().err


@pytest.mark.parametrize("content", ["[]", "{not json", None])
def test_unreadable_or_non_object_reports_fail_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str | None
) -> None:
    repository, base, _ = _repository(tmp_path)
    report = tmp_path / "report.json"
    if content is not None:
        report.write_text(content, encoding="utf-8")

    status, output = _run(repository, report, base)

    assert status == 1
    assert not output.exists()
    assert "changed-coverage decision failed" in capsys.readouterr().err


@pytest.mark.parametrize(
    "base",
    ["", "origin/main", "0" * 40, "A" * 40, "a" * 39, "a" * 41],
    ids=["empty", "branch-name", "all-zero", "uppercase", "short", "long"],
)
def test_base_must_be_a_forty_hex_non_zero_sha(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], base: str
) -> None:
    repository, valid_base, _ = _repository(tmp_path)

    status, output = _run(repository, _report(tmp_path / "report.json", valid_base), base)

    assert status == 1
    assert not output.exists()
    assert "40-hex commit SHA" in capsys.readouterr().err


def test_base_commit_absent_from_the_checkout_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repository, _, _ = _repository(tmp_path)
    absent = "1" * 40

    status, output = _run(repository, _report(tmp_path / "report.json", absent), absent)

    assert status == 1
    assert not output.exists()
    assert "is not in this checkout" in capsys.readouterr().err


def test_base_revision_must_be_a_commit_not_a_tag_object(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repository, _, _ = _repository(tmp_path)
    _git(repository, "tag", "-a", "fixture", "-m", "annotated")
    tag_object = _git(repository, "rev-parse", "refs/tags/fixture")

    status, output = _run(repository, _report(tmp_path / "report.json", tag_object), tag_object)

    assert status == 1
    assert not output.exists()
    assert "is not a commit" in capsys.readouterr().err


@pytest.mark.parametrize("threshold", ["0", "101", "ninety"])
def test_threshold_must_be_an_integer_percentage(tmp_path: Path, threshold: str) -> None:
    with pytest.raises(SystemExit) as raised:
        recorder.main(
            [
                "--report",
                str(tmp_path / "report.json"),
                "--base-sha",
                "a" * 40,
                "--fail-under",
                threshold,
                "--output",
                str(tmp_path / "decision.json"),
            ]
        )

    assert raised.value.code == 2
