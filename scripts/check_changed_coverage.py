"""Turns the JSON report of the hash-locked diff-cover run in .github/workflows/ci.yml into a
recorded changed-line coverage decision against one validated base commit: pass or fail against
the threshold, or an explicit not-applicable outcome naming both revisions and changed paths.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

DECISION_SCHEMA = "lets.changed-coverage-decision/v1"
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
_ZERO_SHA = "0" * 40


class CoverageDecisionError(RuntimeError):
    pass


@dataclass(frozen=True)
class CoverageReport:
    measured_lines: int
    uncovered_lines: int
    measured_paths: tuple[str, ...]


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise CoverageDecisionError(f"git {' '.join(arguments)} failed: {completed.stderr.strip()}")
    return completed.stdout


def base_revision(repository: Path, value: str) -> str:
    if _COMMIT_SHA.fullmatch(value) is None or value == _ZERO_SHA:
        raise CoverageDecisionError(
            f"base revision {value!r} is not a 40-hex commit SHA other than the all-zero SHA"
        )
    try:
        resolved = _git(repository, "rev-parse", "--verify", f"{value}^{{commit}}").strip()
    except CoverageDecisionError as error:
        raise CoverageDecisionError(f"base commit {value} is not in this checkout") from error
    if resolved != value:
        raise CoverageDecisionError(f"base revision {value} is not a commit")
    return value


def changed_paths(repository: Path, base_sha: str) -> list[str]:
    paths: set[str] = set()
    for arguments in (
        ("diff", "--name-only", "-z", f"{base_sha}..HEAD"),
        ("diff", "--name-only", "-z", "--cached"),
        ("diff", "--name-only", "-z"),
    ):
        paths.update(path for path in _git(repository, *arguments).split("\0") if path)
    return sorted(paths)


def _count(report: Mapping[str, object], key: str) -> int:
    value = report.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CoverageDecisionError(f"diff-cover report {key} is not a non-negative integer")
    return value


def load_report(path: Path, base_sha: str) -> CoverageReport:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CoverageDecisionError(f"diff-cover report is unreadable: {error}") from error
    if not isinstance(report, dict):
        raise CoverageDecisionError("diff-cover report is not a JSON object")
    expected_diff = f"{base_sha}..HEAD, staged and unstaged changes"
    if report.get("diff_name") != expected_diff:
        raise CoverageDecisionError(
            f"diff-cover report compares {report.get('diff_name')!r}, not {expected_diff!r}"
        )
    measured_lines = _count(report, "total_num_lines")
    uncovered_lines = _count(report, "total_num_violations")
    if uncovered_lines > measured_lines:
        raise CoverageDecisionError("diff-cover report has more uncovered than measured lines")
    measured = report.get("src_stats")
    if not isinstance(measured, dict):
        raise CoverageDecisionError("diff-cover report src_stats is not an object")
    if (measured_lines == 0) != (not measured):
        raise CoverageDecisionError("diff-cover report totals disagree with its measured files")
    return CoverageReport(measured_lines, uncovered_lines, tuple(sorted(measured)))


def decide(
    report: CoverageReport,
    *,
    fail_under: int,
    base_sha: str,
    candidate_sha: str,
    changed: Sequence[str],
) -> dict[str, object]:
    unexpected = sorted(set(report.measured_paths) - set(changed))
    if unexpected:
        raise CoverageDecisionError(f"diff-cover measured paths outside the diff: {unexpected}")
    decision: dict[str, object] = {
        "base_sha": base_sha,
        "candidate_sha": candidate_sha,
        "changed_paths": list(changed),
        "fail_under": fail_under,
        "measured_lines": report.measured_lines,
        "measured_paths": list(report.measured_paths),
        "schema": DECISION_SCHEMA,
        "uncovered_lines": report.uncovered_lines,
    }
    if report.measured_lines == 0:
        decision.update(
            covered_percent=None,
            reason="the diff has no executable lines in the measured packages",
            status="not-applicable",
        )
        return decision
    measured, uncovered = report.measured_lines, report.uncovered_lines
    covered = Fraction(100 * (measured - uncovered), measured)
    passed = covered >= fail_under
    decision.update(
        covered_percent=round(float(covered), 2),
        reason=f"changed-line coverage is {'at or above' if passed else 'below'} {fail_under}%",
        status="pass" if passed else "fail",
    )
    return decision


def _threshold(value: str) -> int:
    try:
        threshold = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("threshold must be an integer percentage") from error
    if not 1 <= threshold <= 100:
        raise argparse.ArgumentTypeError("threshold must be between 1 and 100")
    return threshold


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Record the changed-line coverage decision from a diff-cover JSON report against a "
            "base commit, including an explicit not-applicable outcome."
        )
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--fail-under", type=_threshold, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path("."))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        base_sha = base_revision(arguments.repository, arguments.base_sha)
        report = load_report(arguments.report, base_sha)
        candidate_sha = _git(arguments.repository, "rev-parse", "HEAD").strip()
        decision = decide(
            report,
            fail_under=arguments.fail_under,
            base_sha=base_sha,
            candidate_sha=candidate_sha,
            changed=changed_paths(arguments.repository, base_sha),
        )
    except CoverageDecisionError as error:
        print(f"changed-coverage decision failed: {error}", file=sys.stderr)
        return 1
    document = json.dumps(decision, indent=2, sort_keys=True) + "\n"
    arguments.output.write_text(document, encoding="utf-8", newline="\n")
    sys.stdout.write(document)
    return 1 if decision["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
