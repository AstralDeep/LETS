"""Run a bounded set of removed-authority guards against focused public acceptance tests.
Disposable source copies and JUnit receipts distinguish assertion kills from broken test execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TEST_PATH = ROOT / "tests/integration/test_public_contract_acceptance.py"


@dataclass(frozen=True)
class Mutation:
    name: str
    path: str
    before: str
    after: str
    tests: tuple[str, ...]


MUTATIONS = (
    Mutation(
        "executor-audience-check-removed",
        "lets/executor.py",
        "        if receipt.executor_audience != policy.audience:\n"
        '            raise PolicyError("receipt audience does not match this executor")\n',
        "",
        ("test_executor_rejects_wrong_audience",),
    ),
    Mutation(
        "executor-signature-verification-removed",
        "lets/executor.py",
        "        if not self._registry.verify(\n"
        "            receipt.warden_id,\n"
        "            receipt.key_id,\n"
        "            canonical_json(receipt.unsigned_payload()),\n"
        "            signature,\n"
        "        ):\n",
        "        if False:\n",
        ("test_executor_rejects_unsigned_receipt", "test_executor_rejects_tampered_receipt"),
    ),
    Mutation(
        "executor-durable-claim-removed",
        "lets/executor.py",
        "        self._replay_store.claim(\n"
        "            receipt,\n"
        "            claimed_at_ns=now_ns,\n"
        "            clock_uncertainty_ns=uncertainty,\n"
        "        )\n",
        "        return\n",
        ("test_public_receipt_claim_survives_fresh_instance_and_process",),
    ),
    Mutation(
        "client-canonical-audience-check-removed",
        "lets/client.py",
        '        if "executor_audience" not in payload or "audience" in payload:\n'
        '            raise ValueError("transition requests require canonical executor_audience")\n',
        "",
        ("test_public_client_rejects_noncanonical_audience_before_transport",),
    ),
    Mutation(
        "released-audience-binding-export-removed",
        "lets/integrations/__init__.py",
        "from lets.integrations.a2a import A2ATaskProfile, AudienceBinding, TaskLedger\n",
        "from lets.integrations.a2a import A2ATaskProfile, TaskLedger\n",
        ("test_released_public_exports_remain_available",),
    ),
)


def classify_result(
    returncode: int, report: Path, expected: tuple[str, ...], *, mutated: bool
) -> tuple[str, dict[str, Any]]:
    try:
        cases = ET.parse(report).findall(".//testcase")
    except (OSError, ET.ParseError) as exc:
        return "invalid", {"reason": f"missing or invalid JUnit receipt: {exc}"}
    names = [case.attrib.get("name", "") for case in cases]
    failures = [
        {"test": case.attrib.get("name"), "message": failure.attrib.get("message", "")}
        for case in cases
        for failure in case.findall("failure")
    ]
    result: dict[str, Any] = {"returncode": returncode, "tests": names, "failures": failures}
    if (
        set(names) != set(expected)
        or len(names) != len(expected)
        or any(case.find("error") is not None or case.find("skipped") is not None for case in cases)
    ):
        return "invalid", {**result, "reason": "missing, extra, skipped, or errored focused tests"}
    if not mutated:
        return ("passed" if returncode == 0 and not failures else "invalid"), result
    if returncode == 0 and not failures:
        return "survived", result
    assertion_failures = all(
        failure["message"].startswith(("AssertionError", "Failed: DID NOT RAISE"))
        for failure in failures
    )
    if returncode == 1 and failures and assertion_failures:
        return "killed", result
    return "invalid", {**result, "reason": "execution failures do not demonstrate guard detection"}


def run_focused(
    source: Path, output: Path, tests: tuple[str, ...], *, mutated: bool
) -> tuple[str, dict[str, Any]]:
    for suffix in (".xml", ".log"):
        output.with_suffix(suffix).unlink(missing_ok=True)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(source)
    env.pop("PYTEST_ADDOPTS", None)
    command = [
        sys.executable,
        "-c",
        "import pathlib, sys, lets; "
        "assert pathlib.Path(lets.__file__).resolve().parent == "
        "pathlib.Path(sys.argv[1]).resolve(); "
        "import pytest; raise SystemExit(pytest.main(sys.argv[2:]))",
        str(source / "lets"),
        "-c",
        str(ROOT / "pyproject.toml"),
        "-o",
        "addopts=",
        "--strict-config",
        "--strict-markers",
        "-p",
        "no:cacheprovider",
        "-q",
        "--tb=short",
        f"--junitxml={output.with_suffix('.xml')}",
        *(f"{TEST_PATH}::{name}" for name in tests),
    ]
    try:
        completed = subprocess.run(
            command, cwd=ROOT, env=env, capture_output=True, text=True, check=False, timeout=60
        )
    except subprocess.TimeoutExpired:
        return "invalid", {"reason": "focused execution exceeded its fixed execution budget"}
    output.with_suffix(".log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
    return classify_result(completed.returncode, output.with_suffix(".xml"), tests, mutated=mutated)


def qualify(output: Path) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    evidence = output.parent / f"{output.stem}-details"
    evidence.mkdir(exist_ok=True)
    tests = tuple(sorted({test for mutation in MUTATIONS for test in mutation.tests}))
    result: dict[str, Any] = {
        "schema": "lets.public-contract-mutations/v1",
        "test_sha256": hashlib.sha256(TEST_PATH.read_bytes()).hexdigest(),
        "fixture_sha256": hashlib.sha256(
            (ROOT / "tests/fixtures/public-receipt-v1.json").read_bytes()
        ).hexdigest(),
        "mutations": [],
    }
    with tempfile.TemporaryDirectory(prefix="lets-public-contract-") as temporary:
        workspace = Path(temporary)
        source = workspace / "baseline"
        shutil.copytree(ROOT / "src", source, ignore=shutil.ignore_patterns("__pycache__"))
        status, baseline = run_focused(source, evidence / "baseline", tests, mutated=False)
        result["baseline"] = {"status": status, **baseline}
        if status != "passed":
            result["status"] = "failed"
            return result
        for mutation in MUTATIONS:
            copied = workspace / mutation.name
            shutil.copytree(source, copied)
            path = copied / mutation.path
            original = path.read_text(encoding="utf-8")
            record: dict[str, Any] = {
                "name": mutation.name,
                "path": f"src/{mutation.path}",
                "original_sha256": hashlib.sha256(original.encode()).hexdigest(),
            }
            if original.count(mutation.before) != 1:
                record.update(status="invalid", reason="guard must match exactly once")
            else:
                changed = original.replace(mutation.before, mutation.after, 1)
                path.write_text(changed, encoding="utf-8")
                status, details = run_focused(
                    copied, evidence / mutation.name, mutation.tests, mutated=True
                )
                record.update(
                    status=status,
                    mutated_sha256=hashlib.sha256(changed.encode()).hexdigest(),
                    **details,
                )
            result["mutations"].append(record)
    result["status"] = (
        "passed"
        if all(record["status"] == "killed" for record in result["mutations"])
        else "failed"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    result = qualify(arguments.output)
    arguments.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
