import re
import tomllib
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
PYPROJECT_PATH = ROOT / "pyproject.toml"
LOCK_PATH = ROOT / "uv.lock"

CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_UV_ACTION = "astral-sh/setup-uv@ae62891fec2bb8e7d6c99fc78c9fec3a63790f8d"
UPLOAD_ACTION = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
APPROVED_ACTIONS = {
    "actions/checkout": CHECKOUT_ACTION.partition("@")[2],
    "astral-sh/setup-uv": SETUP_UV_ACTION.partition("@")[2],
    "actions/upload-artifact": UPLOAD_ACTION.partition("@")[2],
}
EXPECTED_ACTIONS = Counter(
    {
        CHECKOUT_ACTION: 3,
        SETUP_UV_ACTION: 3,
        UPLOAD_ACTION: 1,
    }
)
EXPECTED_JOBS = {"quality", "test", "distributed-acceptance", "required"}
EXPECTED_TRIGGERS = {"push", "pull_request", "workflow_dispatch"}
EXPECTED_MATRIX = {
    ("ubuntu-latest", "3.11"),
    ("ubuntu-latest", "3.12"),
    ("ubuntu-latest", "3.13"),
    ("ubuntu-latest", "3.14"),
    ("windows-latest", "3.11"),
    ("windows-latest", "3.14"),
}
REQUIRED_NEEDS = {"quality", "test", "distributed-acceptance"}


def _top_level_block(text: str, key: str) -> str:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*$", text)
    assert match is not None, key
    following = text[match.end() :]
    boundary = re.search(r"(?m)^\S[^\n]*:\s*(?:#.*)?$", following)
    return following[: boundary.start()] if boundary is not None else following


def _job_blocks(text: str) -> dict[str, str]:
    jobs = _top_level_block(text, "jobs")
    matches = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", jobs))
    assert matches
    return {
        match.group(1): jobs[match.end() : matches[index + 1].start()]
        if index + 1 < len(matches)
        else jobs[match.end() :]
        for index, match in enumerate(matches)
    }


def _assert_ci_contract(text: str) -> None:
    triggers = _top_level_block(text, "on")
    trigger_names = set(re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$", triggers))
    assert trigger_names == EXPECTED_TRIGGERS
    push = re.search(r"(?ms)^  push:\s*\n(?P<body>(?: {4}.*\n?)*)", triggers)
    assert push is not None and re.search(r"(?m)^    branches: \[main\]$", push["body"])

    permissions = _top_level_block(text, "permissions")
    permission_pairs = dict(re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\s*(\S+)\s*$", permissions))
    assert permission_pairs == {"contents": "read"}
    assert "continue-on-error:" not in text

    jobs = _job_blocks(text)
    assert set(jobs) == EXPECTED_JOBS
    for job_name in ("quality", "test", "distributed-acceptance"):
        block = jobs[job_name]
        assert block.count(CHECKOUT_ACTION) == 1
        assert block.count("fetch-depth: 0") == 1

    anchor_command = (
        "python -m benchmarks.astraldeep.check_version_disposition verify-anchor --repository ."
    )
    for job_name in ("quality", "test"):
        block = jobs[job_name]
        assert block.count(anchor_command) == 1
        assert block.index(anchor_command) < block.index("uv sync --all-extras --frozen")
        assert block.index(anchor_command) < block.index('pytest -m "not e2e"')

    matrix = set(re.findall(r'(?m)^ {10}- os: ([^\s]+)\n {12}python: "([0-9.]+)"$', jobs["test"]))
    assert matrix == EXPECTED_MATRIX

    quality = jobs["quality"]
    assert "--cov=lets" in quality
    assert "--cov=benchmarks.astraldeep" in quality
    assert "--cov-report=xml:coverage.xml" in quality
    changed_coverage = next(
        (line.strip() for line in quality.splitlines() if "diff-cover coverage.xml" in line),
        None,
    )
    assert changed_coverage is not None
    assert "--compare-branch origin/main" in changed_coverage
    threshold = re.search(r"--fail-under=([0-9]+)", changed_coverage)
    assert threshold is not None and int(threshold.group(1)) >= 90
    assert "--omit" not in changed_coverage

    required = jobs["required"]
    assert re.search(r"(?m)^    if: \$\{\{ always\(\) \}\}$", required)
    needs = set(re.findall(r"(?m)^      - ([A-Za-z0-9_-]+)$", required))
    assert needs == REQUIRED_NEEDS
    for dependency in REQUIRED_NEEDS:
        assert required.count(f"needs.{dependency}.result") == 1
    assert required.count("== 'success'") == len(REQUIRED_NEEDS)


def _assert_approved_actions(text: str) -> None:
    actions = re.findall(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)", text)
    assert actions
    for action in actions:
        repository, separator, sha = action.rpartition("@")
        assert separator and re.fullmatch(r"[0-9a-f]{40}", sha), action
        assert APPROVED_ACTIONS.get(repository) == sha, action
    assert Counter(actions) == EXPECTED_ACTIONS


def test_ci_uses_only_exact_approved_action_commits() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    _assert_approved_actions(text)
    _assert_ci_contract(text)


def test_ci_rejects_valid_shape_unapproved_action_commit() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    mutated = text.replace(SETUP_UV_ACTION, f"astral-sh/setup-uv@{'0' * 40}", 1)
    assert mutated != text

    with pytest.raises(AssertionError):
        _assert_approved_actions(mutated)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("  pull_request:\n", "  pull_request-disabled:\n"),
        ("  contents: read\n", "  contents: write\n"),
        ("fetch-depth: 0", "fetch-depth: 1"),
        (
            "python -m benchmarks.astraldeep.check_version_disposition "
            "verify-anchor --repository .",
            "python -c 'pass'",
        ),
        ('          - os: ubuntu-latest\n            python: "3.13"', ""),
        ("--fail-under=90", "--fail-under=89"),
        ("needs.test.result", "needs.quality.result"),
    ],
    ids=[
        "pull-request-trigger",
        "read-only-authority",
        "complete-history",
        "signed-anchor-preflight",
        "supported-matrix",
        "changed-coverage-threshold",
        "aggregate-dependency",
    ],
)
def test_ci_contract_rejects_gate_weakening(old: str, new: str) -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    mutated = text.replace(old, new, 1)
    assert mutated != text

    with pytest.raises(AssertionError):
        _assert_ci_contract(mutated)


def test_changed_coverage_tooling_is_locked_and_ci_only() -> None:
    pyproject = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    runtime = pyproject["project"]["dependencies"]
    development = pyproject["project"]["optional-dependencies"]["dev"]

    assert not any(requirement.startswith("diff-cover") for requirement in runtime)
    assert [requirement for requirement in development if requirement.startswith("diff-cover")] == [
        "diff-cover>=9.7,<10"
    ]
    assert re.search(r'(?m)^name = "diff-cover"$', LOCK_PATH.read_text(encoding="utf-8"))


def test_changed_benchmark_modules_have_no_coverage_suppressions() -> None:
    modules = sorted((ROOT / "benchmarks" / "astraldeep").glob("*.py"))
    assert modules
    for module in modules:
        text = module.read_text(encoding="utf-8")
        assert "pragma: no cover" not in text
        assert "coverage: ignore" not in text
