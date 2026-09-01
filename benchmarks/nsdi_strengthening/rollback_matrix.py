"""Run and retain the focused LETS rollback/clone evidence matrix.

This runner deliberately invokes existing tests without changing LETS runtime
behavior.  It records the exact selectors, environment, Git state, JUnit XML,
and complete pytest stdout/stderr in an operator-selected output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = "lets.nsdi-rollback-clone-evidence/v1"
ROOT = Path(__file__).resolve().parents[2]

SUMMARY_NAME = "rollback-matrix.summary.json"
JUNIT_NAME = "rollback-matrix.junit.xml"
STDOUT_NAME = "rollback-matrix.stdout.log"
STDERR_NAME = "rollback-matrix.stderr.log"
EVIDENCE_NAMES = (JUNIT_NAME, STDOUT_NAME, STDERR_NAME, SUMMARY_NAME)

TEST_NODE_IDS = (
    "tests/integration/test_authority_anchor.py::"
    "test_external_anchor_rejects_a_stale_but_internally_valid_backup",
    "tests/integration/test_authority_anchor.py::"
    "test_anchor_fences_a_second_database_copy_before_its_next_write",
    "tests/integration/test_authority_anchor.py::"
    "test_commit_anchor_crash_window_fails_closed_then_recovers_extension",
    "tests/integration/test_authority_anchor.py::"
    "test_simultaneous_database_forks_use_one_linearizable_anchor_successor",
    "tests/integration/test_executor_authority.py::"
    "test_process_anchor_rejects_stale_preclaim_database_restore",
    "tests/integration/test_executor_authority.py::"
    "test_concurrent_cloned_databases_have_one_external_cas_winner",
    "tests/integration/test_executor_authority.py::"
    "test_process_executor_startup_confirm_lost_reply_preserves_and_reconfirms",
    "tests/integration/test_executor_authority.py::"
    "test_commit_before_anchor_failure_recovers_claim_without_reauthorizing",
    "tests/integration/test_backup_restore_fencing.py::"
    "test_stale_recovery_bundle_is_fenced_before_live_files_are_replaced",
    "tests/unit/test_cli_recovery.py::"
    "test_server_holds_same_process_lock_as_recovery_for_its_full_lifetime",
)

REQUIREMENT_TO_TESTS: tuple[Mapping[str, object], ...] = (
    {
        "requirement_id": "review-8.warden-stale-snapshot",
        "description": (
            "A stale but internally valid warden database is rejected by the live anchor."
        ),
        "coverage": "direct",
        "test_node_ids": (TEST_NODE_IDS[0], TEST_NODE_IDS[8]),
    },
    {
        "requirement_id": "review-8.warden-clone",
        "description": "Two warden database copies cannot both advance one authority lineage.",
        "coverage": "direct-local-process",
        "test_node_ids": (TEST_NODE_IDS[1], TEST_NODE_IDS[3]),
    },
    {
        "requirement_id": "review-8.executor-stale-claim-store",
        "description": "Restoring a pre-claim executor database behind its anchor fails closed.",
        "coverage": "direct",
        "test_node_ids": (TEST_NODE_IDS[4],),
    },
    {
        "requirement_id": "review-8.executor-clone",
        "description": "Concurrent executor database clones have exactly one external-CAS winner.",
        "coverage": "direct-local-process",
        "test_node_ids": (TEST_NODE_IDS[5],),
    },
    {
        "requirement_id": "review-8.commit-response-loss",
        "description": (
            "Post-commit anchor/confirmation failures recover the committed head without "
            "reauthorizing or replaying the protected effect."
        ),
        "coverage": "direct-fault-injection",
        "test_node_ids": (TEST_NODE_IDS[2], TEST_NODE_IDS[6], TEST_NODE_IDS[7]),
    },
    {
        "requirement_id": "review-8.same-state-process-exclusion",
        "description": "Serving and recovery cannot concurrently own one node state directory.",
        "coverage": "direct-local-process",
        "test_node_ids": (TEST_NODE_IDS[9],),
    },
    {
        "requirement_id": "review-8.stale-anchor-replacement",
        "description": (
            "Replacing or jointly rolling back the independent anchor is an infrastructure "
            "assumption, not a property established by the selected file-anchor tests."
        ),
        "coverage": "assumption-boundary-not-directly-tested",
        "test_node_ids": (),
    },
)

LIMITATIONS = (
    "The selected clone races execute inside local pytest processes, not on independent hosts.",
    "The file-anchor implementation requires an independently administered non-rollback domain.",
    "Joint rollback of a database and its independent anchor is outside the LETS threat model.",
    (
        "A database ahead of a stale anchor may safely prove a contiguous extension and repair it "
        "forward."
    ),
)


class EvidenceError(RuntimeError):
    """The runner could not produce a complete evidence bundle."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _artifact(path: Path) -> dict[str, object]:
    value = path.read_bytes()
    return {
        "bytes": len(value),
        "file": path.name,
        "sha256": _sha256_bytes(value),
    }


def _git(arguments: Sequence[str]) -> bytes:
    process = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise EvidenceError(f"git {' '.join(arguments)} failed: {detail}")
    return process.stdout


def _git_state() -> dict[str, object]:
    commit = _git(("rev-parse", "--verify", "HEAD")).decode().strip()
    branch = _git(("rev-parse", "--abbrev-ref", "HEAD")).decode().strip()
    status = _git(("status", "--porcelain=v1", "--untracked-files=all"))
    return {
        "branch": branch,
        "captured_before_evidence_write": True,
        "commit": commit,
        "dirty": bool(status),
        "status_sha256": _sha256_bytes(status),
    }


def _platform_state() -> dict[str, object]:
    return {
        "machine": platform.machine(),
        "operating_system": platform.system(),
        "operating_system_release": platform.release(),
        "operating_system_version": platform.version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python_executable": sys.executable,
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_version_detail": sys.version,
    }


def _junit_counts(path: Path) -> dict[str, object]:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise EvidenceError("pytest did not produce readable JUnit XML") from exc
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    if not suites:
        raise EvidenceError("pytest JUnit XML contains no test suite")
    counts: dict[str, int | float] = {
        "errors": 0,
        "failures": 0,
        "skipped": 0,
        "tests": 0,
        "time_seconds": 0.0,
    }
    for suite in suites:
        for name in ("errors", "failures", "skipped", "tests"):
            counts[name] = int(counts[name]) + int(suite.attrib.get(name, "0"))
        counts["time_seconds"] = float(counts["time_seconds"]) + float(
            suite.attrib.get("time", "0")
        )
    return counts


def _run_pytest(command: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        list(command),
        cwd=ROOT,
        check=False,
        capture_output=True,
    )


def _has_path(path: Path) -> bool:
    return os.path.lexists(path)


def _prepare_output(output_dir: Path, *, overwrite: bool) -> None:
    if _has_path(output_dir) and not output_dir.is_dir():
        raise EvidenceError(f"output path is not a directory: {output_dir}")
    conflicts = [name for name in EVIDENCE_NAMES if _has_path(output_dir / name)]
    if conflicts and not overwrite:
        raise EvidenceError(
            "refusing to overwrite existing evidence files without --overwrite: "
            + ", ".join(conflicts)
        )
    directories = [name for name in conflicts if (output_dir / name).is_dir()]
    if directories:
        raise EvidenceError("evidence target is a directory: " + ", ".join(directories))
    output_dir.mkdir(parents=True, exist_ok=True)


def _publish(source: Path, target: Path, *, overwrite: bool) -> None:
    if overwrite:
        os.replace(source, target)
        return
    try:
        with target.open("xb") as destination, source.open("rb") as staged:
            shutil.copyfileobj(staged, destination)
            destination.flush()
            os.fsync(destination.fileno())
    except FileExistsError as exc:
        raise EvidenceError(f"evidence target appeared during publication: {target}") from exc
    source.unlink()


def _mapping_document() -> list[dict[str, object]]:
    return [
        {
            **entry,
            "test_node_ids": list(entry["test_node_ids"]),
        }
        for entry in REQUIREMENT_TO_TESTS
    ]


def run_evidence(output_dir: Path, *, overwrite: bool = False) -> int:
    """Run the matrix, publish its evidence, and return a process exit code."""

    output_dir = output_dir.resolve()
    git_state = _git_state()
    _prepare_output(output_dir, overwrite=overwrite)
    started_at = _utc_now()
    started_monotonic = time.monotonic()
    staging = Path(tempfile.mkdtemp(prefix=".rollback-matrix-", dir=output_dir))
    try:
        junit = staging / JUNIT_NAME
        stdout = staging / STDOUT_NAME
        stderr = staging / STDERR_NAME
        pytest_temp = staging / "pytest-temp"
        command = [
            sys.executable,
            "-m",
            "pytest",
            "--color=no",
            "-vv",
            "--tb=long",
            "-p",
            "no:cacheprovider",
            "--junitxml",
            str(junit),
            "--basetemp",
            str(pytest_temp),
            *TEST_NODE_IDS,
        ]
        runner_error: str | None = None
        try:
            process = _run_pytest(command)
            stdout.write_bytes(process.stdout)
            stderr.write_bytes(process.stderr)
            returncode = process.returncode
        except OSError as exc:
            stdout.write_bytes(b"")
            stderr.write_bytes(f"{type(exc).__name__}: {exc}\n".encode())
            returncode = 2
            runner_error = f"could not start pytest: {type(exc).__name__}"

        junit_counts: dict[str, object] | None = None
        if junit.is_file():
            try:
                junit_counts = _junit_counts(junit)
            except EvidenceError as exc:
                runner_error = str(exc)
                returncode = returncode or 1
        else:
            runner_error = runner_error or "pytest did not create JUnit XML"
            returncode = returncode or 1

        if junit_counts is not None and int(junit_counts["tests"]) != len(TEST_NODE_IDS):
            runner_error = (
                f"JUnit reported {junit_counts['tests']} tests; expected {len(TEST_NODE_IDS)}"
            )
            returncode = returncode or 1
        if junit_counts is not None:
            failed_tests = int(junit_counts["failures"]) + int(junit_counts["errors"])
            if failed_tests:
                runner_error = runner_error or f"JUnit reported {failed_tests} failed tests"
                returncode = returncode or 1

        completed_at = _utc_now()
        artifacts: dict[str, object] = {
            "stdout": _artifact(stdout),
            "stderr": _artifact(stderr),
        }
        if junit.is_file():
            artifacts["junit"] = _artifact(junit)
        passed = returncode == 0 and runner_error is None
        summary: dict[str, Any] = {
            "artifacts": artifacts,
            "command": command,
            "completed_at": completed_at,
            "duration_seconds": round(time.monotonic() - started_monotonic, 6),
            "environment": _platform_state(),
            "git": git_state,
            "junit": junit_counts,
            "limitations": list(LIMITATIONS),
            "passed": passed,
            "pytest_returncode": process.returncode if "process" in locals() else None,
            "repository_root": str(ROOT),
            "requirement_to_test_mapping": _mapping_document(),
            "runner_error": runner_error,
            "schema": SCHEMA,
            "selected_test_node_ids": list(TEST_NODE_IDS),
            "started_at": started_at,
        }
        summary_path = staging / SUMMARY_NAME
        summary_path.write_text(
            json.dumps(summary, allow_nan=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        for name in (JUNIT_NAME, STDOUT_NAME, STDERR_NAME, SUMMARY_NAME):
            source = staging / name
            if source.is_file():
                _publish(source, output_dir / name, overwrite=overwrite)

        return 0 if passed else (returncode if 0 < returncode < 256 else 1)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace only the four known rollback-matrix evidence files",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _arguments(arguments)
    try:
        return run_evidence(parsed.output_dir, overwrite=parsed.overwrite)
    except EvidenceError as exc:
        print(f"rollback-matrix: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
