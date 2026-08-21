from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from benchmarks.astraldeep import aggregate_case_study as aggregate
from benchmarks.astraldeep import capture_environment as capture
from benchmarks.astraldeep import check_version_disposition as versioning
from benchmarks.astraldeep import run_case_study as runner

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_SHA256 = "616b1c778b7d834c724047513becbc705e0c2cacfa334d82ecd214920591f3dc"


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _initialize_repository(root: Path, label: str) -> str:
    root.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    _git(root, "config", "user.name", "Case Study Test")
    _git(root, "config", "user.email", "case-study-test@example.invalid")
    (root / "identity.txt").write_text(f"{label}\n", encoding="utf-8")
    _git(root, "add", "identity.txt")
    _git(root, "commit", "--quiet", "-m", f"initialize {label}")
    return _git(root, "rev-parse", "HEAD")


def _execution_identity(
    *,
    deep_commit: str = "a" * 40,
    plane_commit: str = "b" * 40,
    lets_commit: str = versioning.BASELINE_COMMIT,
) -> dict[str, object]:
    return {
        "format": runner.EXECUTION_IDENTITY_FORMAT,
        "astraldeep": {
            "commit": deep_commit,
            "driver_relative_path": runner.DRIVER_RELATIVE_PATH,
            "driver_sha256": "1" * 64,
        },
        "interpreter": {
            "implementation": "CPython",
            "version": "3.11.9",
            "executable_sha256": "2" * 64,
        },
        "imports": {
            "astralplane": {
                "component_commit": plane_commit,
                "file_count": 42,
                "tree_sha256": "3" * 64,
            },
            "lets": {
                "component_commit": lets_commit,
                "file_count": 24,
                "tree_sha256": "4" * 64,
                "release": "v1.0.10",
            },
        },
    }


def _driver_result(
    scenario: runner.Scenario,
    execution_identity: Mapping[str, object] | None = None,
) -> dict[str, object]:
    lifecycle = scenario.category == "lifecycle"
    denied = scenario.expected_effect == "deny"
    if lifecycle or denied:
        physical_effects = 0
    elif scenario.category == "parallel-dispatch":
        physical_effects = scenario.parallelism
    elif scenario.category == "recursive-dispatch":
        physical_effects = scenario.recursion_depth + 1
    else:
        physical_effects = 1
    lets_requests = 0 if scenario.mode == "off" else 1
    post_revocation = scenario.category == "post-revocation-effect"
    if scenario.mode == "enforce" and not lifecycle and not denied:
        receipts_issued = physical_effects
        receipts_claimed = physical_effects
    elif scenario.mode == "shadow" and not lifecycle and not post_revocation:
        receipts_issued = 1
        receipts_claimed = 0
    else:
        receipts_issued = 0
        receipts_claimed = 0
    return {
        "format": runner.RESULT_FORMAT,
        "scenario_id": scenario.scenario_id,
        "mode": scenario.mode,
        "category": scenario.category,
        "status": "passed",
        "execution_identity": copy.deepcopy(execution_identity or _execution_identity()),
        "observations": {
            "astral_decision": (
                "not-applicable" if lifecycle else "denied" if denied else "allowed"
            ),
            "lets_requests": lets_requests,
            "receipts_issued": receipts_issued,
            "receipts_claimed": receipts_claimed,
            "physical_effects": physical_effects,
            "denied_effects": 1 if denied else 0,
            "unreceipted_governed_effects": 0,
            "budget_conserved": True,
            "sequence_monotonic": True,
            "lifecycle_converged": lifecycle or post_revocation,
            "lifecycle_state": (
                scenario.expected_lifecycle_state
                if lifecycle
                else "revoked"
                if post_revocation
                else None
            ),
            "denial_code": runner._FAULT_DENIAL_CODES.get(scenario.category) if denied else None,
            "scope_binding": (
                None
                if lifecycle
                else {
                    "scope": scenario.scope or "tools:execute",
                    "capability": runner.ASTRAL_SCOPE_BINDINGS[scenario.scope or "tools:execute"][
                        0
                    ],
                    "transition": runner.ASTRAL_SCOPE_BINDINGS[scenario.scope or "tools:execute"][
                        1
                    ],
                    "resource_dimension": runner.ASTRAL_SCOPE_BINDINGS[
                        scenario.scope or "tools:execute"
                    ][2],
                    "checks": (0 if scenario.mode == "off" or post_revocation else lets_requests),
                }
            ),
        },
        "measurements": [
            {
                "name": "lifecycle_convergence" if lifecycle else "authorization_latency",
                "unit": "ns",
                "samples": [1, 2, 3],
                "exclusions": [],
            }
        ],
    }


def _run(
    root: Path,
    *,
    mode: str = "enforce",
    evidence_class: str = "astral-integration",
    execution_identity: Mapping[str, object] | None = None,
) -> dict[str, object]:
    identity = dict(execution_identity or _execution_identity())

    def fake_driver(**kwargs: object) -> tuple[int, bytes, bytes, str, str]:
        scenario = kwargs["scenario"]
        assert isinstance(scenario, runner.Scenario)
        payload = runner.canonical_json_bytes(_driver_result(scenario, identity)) + b"\n"
        now = runner._timestamp()
        return 0, payload, b"", now, now

    with (
        patch.object(runner, "capture_execution_identity", return_value=identity),
        patch.object(runner, "_canonical_interpreter", return_value=Path(sys.executable)),
        patch.object(runner, "_run_driver", side_effect=fake_driver),
    ):
        return runner.run_case_study(
            mode=mode,
            evidence_class=evidence_class,
            astraldeep_root=root.parent,
            output_root=root,
            timeout_seconds=5,
        )


def _repositories(root: Path) -> tuple[dict[str, Path], dict[str, str]]:
    paths: dict[str, Path] = {}
    revisions: dict[str, str] = {}
    for name in capture.REPOSITORY_KEYS:
        path = root / name
        paths[name] = path
        revisions[name] = _initialize_repository(path, name)
    return paths, revisions


def _composition(revisions: Mapping[str, str]) -> dict[str, object]:
    return {
        "format": "astral.composition/v1",
        "components": {
            "astral-projection": {"commit": revisions["astral-projection"]},
            "astral-plane": {"commit": revisions["astral-plane"]},
            "astral-primitives": {"commit": revisions["astral-primitives"]},
            "lets": {"commit": versioning.BASELINE_COMMIT, "ref": "v1.0.10"},
        },
        "compatibility": {"lets": {"release": "v1.0.10"}},
    }


def _runtime_identities() -> dict[str, object]:
    return {
        "format": capture.RUNTIME_IDENTITIES_FORMAT,
        "lets_release": "v1.0.10",
        "policy_digest": f"sha256:{'1' * 64}",
        "machine_digest": f"sha256:{'2' * 64}",
        "config_epoch": 7,
        "scope_profile": "astral.tools/v1",
        "api_version": "v1",
        "receipt_wire_type": "lets.receipt/v1",
        "warden_topology": "single-local-test-warden",
    }


@pytest.fixture(scope="module")
def captured_bundle(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    tmp_path = tmp_path_factory.mktemp("astraldeep-case-study")
    evidence_root = tmp_path / "evidence"
    repository_paths, revisions = _repositories(tmp_path / "repositories")
    composition_payload = json.dumps(_composition(revisions), indent=2, sort_keys=True) + "\n"
    canonical_composition = repository_paths["astraldeep"] / capture.COMPOSITION_RELATIVE_PATH
    canonical_composition.parent.mkdir(parents=True)
    canonical_composition.write_text(composition_payload, encoding="utf-8")
    _git(repository_paths["astraldeep"], "add", capture.COMPOSITION_RELATIVE_PATH)
    _git(
        repository_paths["astraldeep"],
        "commit",
        "--quiet",
        "-m",
        "track canonical composition",
    )
    revisions["astraldeep"] = _git(repository_paths["astraldeep"], "rev-parse", "HEAD")
    execution_identity = _execution_identity(
        deep_commit=revisions["astraldeep"],
        plane_commit=revisions["astral-plane"],
    )
    run = _run(evidence_root, execution_identity=execution_identity)
    composition_path = tmp_path / "composition.json"
    composition_path.write_text(composition_payload, encoding="utf-8")
    runtime_path = tmp_path / "runtime.json"
    capture.write_canonical_json_exclusive(runtime_path, _runtime_identities())
    manifest_path = evidence_root / "manifest.json"
    with patch.object(runner, "capture_execution_identity", return_value=execution_identity):
        bundle = capture.capture_case_study_evidence(
            run_manifest_path=evidence_root / "run.json",
            composition_path=composition_path,
            runtime_identities_path=runtime_path,
            repository_paths=repository_paths,
            output_path=manifest_path,
            additional_environment={"database_version": "17", "parallel_workers": 4},
            notes="Synthetic public conformance workload.",
        )
    return {
        "bundle": bundle,
        "root": evidence_root,
        "manifest": manifest_path,
        "repositories": repository_paths,
        "revisions": revisions,
        "composition_payload": composition_path.read_bytes(),
        "composition_path": canonical_composition,
        "runtime_path": runtime_path,
        "run": run,
    }


def _disposition(candidate_repository: Path, runtime_paths: list[str]) -> dict[str, object]:
    candidate_commit = _git(candidate_repository, "rev-parse", "HEAD")
    candidate_tree = _git(candidate_repository, "show", "-s", "--format=%T", "HEAD")
    integration_paths = [] if runtime_paths else ["benchmarks/astraldeep/run_case_study.py"]
    changed_paths = sorted([*runtime_paths, *integration_paths])
    return {
        "format": versioning.DISPOSITION_FORMAT,
        "baseline": {
            "release": "v1.0.10",
            "tag_object": versioning.BASELINE_TAG_OBJECT,
            "commit": versioning.BASELINE_COMMIT,
            "tree": versioning.BASELINE_TREE,
            "signature_verified": True,
        },
        "candidate": {"commit": candidate_commit, "tree": candidate_tree, "clean": True},
        "comparison": {
            "method": "immutable-git-tree-diff/v1",
            "comparator_sha256": capture.sha256_file(Path(versioning.__file__)),
            "release_anchor_sha256": "3" * 64,
            "baseline_runtime_tree": "4" * 40,
            "candidate_runtime_tree": "4" * 40,
            "baseline_protocol_tree": "5" * 40,
            "candidate_protocol_tree": "5" * 40,
            "changed_paths": changed_paths,
            "runtime_or_wire_paths": runtime_paths,
            "integration_only_paths": integration_paths,
        },
        "disposition": "successor-required" if runtime_paths else "unchanged-runtime",
        "reason": (
            "candidate runtime or wire inputs differ from signed v1.0.10"
            if runtime_paths
            else "candidate changes do not alter signed v1.0.10 runtime or wire inputs"
        ),
        "generated_at": "2026-08-14T12:00:00Z",
    }


def _release_anchor(path: Path) -> Path:
    capture.write_canonical_json_exclusive(
        path,
        {
            "letsReleaseAnchor": {
                "version": "v1.0.10",
                "tagObject": versioning.BASELINE_TAG_OBJECT,
                "peeledCommit": versioning.BASELINE_COMMIT,
                "tree": versioning.BASELINE_TREE,
                "signature": {
                    "verified": True,
                    "scheme": "ssh-ed25519",
                    "keyFingerprint": versioning.BASELINE_SIGNER_FINGERPRINT,
                    "commandExitCode": 0,
                },
            }
        },
    )
    return path


@contextmanager
def _candidate_clone(tmp_path: Path) -> Iterator[Path]:
    candidate = tmp_path / "candidate"
    subprocess.run(
        ["git", "clone", "--quiet", str(REPOSITORY_ROOT), str(candidate)],
        check=True,
    )
    _git(candidate, "config", "user.name", "Case Study Test")
    _git(candidate, "config", "user.email", "case-study-test@example.invalid")
    yield candidate


def _copied_bundle(
    captured_bundle: Mapping[str, Any], tmp_path: Path
) -> tuple[dict[str, Any], Path]:
    root = tmp_path / "evidence"
    shutil.copytree(captured_bundle["root"], root)
    return copy.deepcopy(captured_bundle["bundle"]), root


def _replace_artifact_record(
    bundle: dict[str, Any], root: Path, relative_path: str, kind: str
) -> None:
    replacement = capture.artifact_record(root, relative_path, kind)
    artifacts = bundle["artifacts"]
    for index, artifact in enumerate(artifacts):
        if artifact["relative_path"] == relative_path:
            artifacts[index] = replacement
            return
    raise AssertionError(f"missing test artifact {relative_path}")


def _rewrite_retained_run(bundle: dict[str, Any], root: Path, run: Mapping[str, object]) -> None:
    record = next(
        artifact for artifact in bundle["artifacts"] if artifact["kind"] == "case-study-run"
    )
    relative_path = str(record["relative_path"])
    path = root.joinpath(*Path(relative_path).parts)
    path.write_bytes(capture.canonical_json_bytes(run) + b"\n")
    _replace_artifact_record(bundle, root, relative_path, "case-study-run")


def test_standalone_schema_is_byte_identified() -> None:
    schema = REPOSITORY_ROOT / "benchmarks/astraldeep/case-study-evidence.schema.json"
    assert hashlib.sha256(schema.read_bytes()).hexdigest() == SCHEMA_SHA256


def test_scenario_matrix_covers_every_required_behavior() -> None:
    scenarios = runner.build_scenarios("enforce")
    assert len(scenarios) == 19
    assert {item.scope for item in scenarios if item.category == "scope"} == set(
        runner.ASTRAL_TOOL_SCOPES
    )
    assert {item.lifecycle_event for item in scenarios if item.category == "lifecycle"} == set(
        runner.LIFECYCLE_EVENTS
    )
    assert {item.category for item in scenarios}.issuperset(
        {"parallel-dispatch", "recursive-dispatch", *runner.FAULT_SCENARIOS}
    )
    assert runner.build_scenarios("off")[0].expected_lets_behavior == "off"
    assert runner.build_scenarios("shadow")[0].expected_lets_behavior == "evaluate"


def test_driver_revision_requires_canonical_tracked_file_and_clean_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "deep"
    _initialize_repository(root, "deep")
    driver = root / runner.DRIVER_RELATIVE_PATH
    driver.parent.mkdir(parents=True)
    driver.write_text("raise SystemExit(0)\n", encoding="utf-8")
    _git(root, "add", runner.DRIVER_RELATIVE_PATH)
    _git(root, "commit", "--quiet", "-m", "track canonical driver")
    assert runner._clean_repository_commit(root) == _git(root, "rev-parse", "HEAD")

    (root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(capture.EvidenceError, match="dirty"):
        runner._clean_repository_commit(root)

    missing = tmp_path / "missing-driver"
    _initialize_repository(missing, "missing-driver")
    with pytest.raises(capture.EvidenceError):
        runner._clean_repository_commit(missing)


def test_canonical_interpreter_is_fixed_to_deep_virtualenv(tmp_path: Path) -> None:
    relative = (
        Path(".venv/Scripts/python.exe") if runner.os.name == "nt" else Path(".venv/bin/python")
    )
    executable = tmp_path / relative
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"canonical interpreter placeholder")
    assert runner._canonical_interpreter(tmp_path) == executable.resolve(strict=True)

    executable.unlink()
    with pytest.raises(capture.EvidenceError, match="interpreter is missing"):
        runner._canonical_interpreter(tmp_path)


@pytest.mark.parametrize("mode", runner.MODES)
def test_runner_executes_complete_single_mode_matrix(tmp_path: Path, mode: str) -> None:
    run = _run(tmp_path / mode, mode=mode)
    assert run["status"] == "passed"
    assert len(run["commands"]) == 19
    assert len(run["measurements"]) == 19
    assert all(command["exit_code"] == 0 for command in run["commands"])
    if mode == "off":
        assert all(command["id"].startswith("off-") for command in run["commands"])


def test_runner_rejects_unreceipted_enforced_effect() -> None:
    scenario = runner.build_scenarios("enforce")[0]
    identity = _execution_identity()
    result = _driver_result(scenario)
    result["observations"]["receipts_claimed"] = 0  # type: ignore[index]
    with pytest.raises(capture.EvidenceError, match="one receipt per effect"):
        runner._validate_result(result, scenario, identity)

    conserved = _driver_result(scenario)
    conserved["observations"]["budget_conserved"] = False  # type: ignore[index]
    with pytest.raises(capture.EvidenceError, match="authority conservation"):
        runner._validate_result(conserved, scenario, identity)

    parallel = next(
        item for item in runner.build_scenarios("enforce") if item.category == "parallel-dispatch"
    )
    incomplete = _driver_result(parallel)
    incomplete["observations"]["physical_effects"] = 1  # type: ignore[index]
    incomplete["observations"]["receipts_issued"] = 1  # type: ignore[index]
    incomplete["observations"]["receipts_claimed"] = 1  # type: ignore[index]
    with pytest.raises(capture.EvidenceError, match="every branch"):
        runner._validate_result(incomplete, parallel, identity)


def test_runner_rejects_fabricated_identity_scope_and_revocation_evidence() -> None:
    identity = _execution_identity()
    scope = runner.build_scenarios("enforce")[0]
    forged_identity = _driver_result(scope, identity)
    forged_identity["execution_identity"]["astraldeep"]["driver_sha256"] = "9" * 64  # type: ignore[index]
    with pytest.raises(capture.EvidenceError, match="execution identity"):
        runner._validate_result(forged_identity, scope, identity)

    wrong_scope = _driver_result(scope, identity)
    wrong_scope["observations"]["scope_binding"]["transition"] = "tool_execute"  # type: ignore[index]
    with pytest.raises(capture.EvidenceError, match="exact scope mapping"):
        runner._validate_result(wrong_scope, scope, identity)

    revoked = next(
        scenario
        for scenario in runner.build_scenarios("enforce")
        if scenario.category == "post-revocation-effect"
    )
    for field, value in (
        ("lifecycle_converged", False),
        ("lifecycle_state", "active"),
        ("denial_code", "unrelated_denial"),
    ):
        malformed = _driver_result(revoked, identity)
        malformed["observations"][field] = value  # type: ignore[index]
        with pytest.raises(capture.EvidenceError):
            runner._validate_result(malformed, revoked, identity)


def test_child_environment_is_minimal_and_drops_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CASE_STUDY_SECRET_TOKEN", "must-not-reach-child")
    environment = runner._child_environment()
    assert "CASE_STUDY_SECRET_TOKEN" not in environment
    assert set(environment).issubset(
        runner._CHILD_ENV_KEYS
        | {
            "PYTHONDONTWRITEBYTECODE",
            "PYTHONHASHSEED",
            "PYTHONIOENCODING",
            "PYTHONNOUSERSITE",
            "PYTHONUTF8",
        }
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b"[]",
        b'{"duplicate":1,"duplicate":2}',
        b'{"not_finite":NaN}',
    ],
)
def test_driver_result_parser_rejects_noncanonical_payloads(payload: bytes) -> None:
    with pytest.raises(capture.EvidenceError):
        runner._strict_result(payload)


def test_driver_result_parser_enforces_output_bound() -> None:
    with pytest.raises(capture.EvidenceError, match="bounded result size"):
        runner._strict_result(b"x" * (runner._MAX_DRIVER_OUTPUT_BYTES + 1))


def test_driver_result_parser_requires_exact_canonical_bytes() -> None:
    scenario = runner.build_scenarios("enforce")[0]
    result = _driver_result(scenario)
    canonical = runner.canonical_json_bytes(result) + b"\n"
    assert runner._strict_result(canonical) == result
    for payload in (
        runner.canonical_json_bytes(result),
        canonical + b"\n",
        json.dumps(result, indent=2, sort_keys=False).encode("utf-8") + b"\n",
    ):
        with pytest.raises(capture.EvidenceError, match="not canonical JSON"):
            runner._strict_result(payload)


def test_real_driver_boundary_covers_success_timeout_and_execution_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = runner.build_scenarios("off")[0]
    echo_driver = tmp_path / runner.DRIVER_RELATIVE_PATH
    echo_driver.parent.mkdir(parents=True)
    monkeypatch.setenv("CASE_STUDY_SECRET_TOKEN", "must-not-reach-child")
    echo_driver.write_text(
        "import os\nimport sys\n"
        "assert 'CASE_STUDY_SECRET_TOKEN' not in os.environ\n"
        "request = sys.stdin.read()\nsys.stdout.write(request)\n"
        "sys.stderr.write('public diagnostic\\n')\n",
        encoding="utf-8",
    )
    exit_code, stdout, stderr, started, finished = runner._run_driver(
        astraldeep_root=tmp_path,
        interpreter=Path(sys.executable),
        scenario=scenario,
        timeout_seconds=5,
    )
    assert exit_code == 0
    assert json.loads(stdout)["scenario_id"] == scenario.scenario_id
    assert stderr.decode("utf-8").splitlines() == ["public diagnostic"]
    assert started <= finished

    echo_driver.write_text("import time\ntime.sleep(2)\n", encoding="utf-8")
    exit_code, *_ = runner._run_driver(
        astraldeep_root=tmp_path,
        interpreter=Path(sys.executable),
        scenario=scenario,
        timeout_seconds=0.01,
    )
    assert exit_code == 124

    echo_driver.write_text(
        "import sys\nsys.stdout.buffer.write(b'x' * (2 * 1024 * 1024 + 1))\n",
        encoding="utf-8",
    )
    with pytest.raises(capture.EvidenceError, match="2 MiB per-stream bound"):
        runner._run_driver(
            astraldeep_root=tmp_path,
            interpreter=Path(sys.executable),
            scenario=scenario,
            timeout_seconds=5,
        )

    def fail_popen(*_args: object, **_kwargs: object) -> None:
        raise OSError("synthetic execution failure")

    monkeypatch.setattr(runner.subprocess, "Popen", fail_popen)
    with pytest.raises(capture.EvidenceError, match="could not be executed"):
        runner._run_driver(
            astraldeep_root=tmp_path,
            interpreter=Path(sys.executable),
            scenario=scenario,
            timeout_seconds=1,
        )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"evidence_class": "unknown"}, "evidence class"),
        ({"mode": "unknown"}, "mode"),
        ({"timeout_seconds": 0}, "timeout"),
    ],
)
def test_runner_input_validation_fails_before_creating_output(
    tmp_path: Path, kwargs: dict[str, object], message: str
) -> None:
    arguments: dict[str, object] = {
        "mode": "enforce",
        "evidence_class": "astral-integration",
        "astraldeep_root": tmp_path,
        "output_root": tmp_path / "output",
        "timeout_seconds": 5,
    }
    arguments.update(kwargs)
    with pytest.raises(capture.EvidenceError, match=message):
        runner.run_case_study(**arguments)  # type: ignore[arg-type]
    assert not (tmp_path / "output").exists()


def test_runner_refuses_secret_before_retaining_driver_stdout(tmp_path: Path) -> None:
    def secret_driver(*args: object, **kwargs: object) -> tuple[int, bytes, bytes, str, str]:
        del args
        scenario = kwargs["scenario"]
        assert isinstance(scenario, runner.Scenario)
        result = _driver_result(scenario)
        result["api_token"] = "not-retainable"
        now = runner._timestamp()
        return 0, runner.canonical_json_bytes(result) + b"\n", b"", now, now

    output = tmp_path / "secret-run"
    with (
        patch.object(runner, "capture_execution_identity", return_value=_execution_identity()),
        patch.object(runner, "_canonical_interpreter", return_value=Path(sys.executable)),
        patch.object(runner, "_run_driver", side_effect=secret_driver),
        pytest.raises(capture.EvidenceError, match="pre-retention sanitization"),
    ):
        runner.run_case_study(
            mode="enforce",
            evidence_class="astral-integration",
            astraldeep_root=tmp_path,
            output_root=output,
        )
    assert not list(output.glob("raw/commands/*.stdout.json"))


def test_capture_binds_exact_revisions_and_raw_composition_digest(
    captured_bundle: dict[str, Any],
) -> None:
    bundle = captured_bundle["bundle"]
    assert bundle["repositories"] == captured_bundle["revisions"]
    assert (
        bundle["composition_sha256"]
        == hashlib.sha256(captured_bundle["composition_payload"]).hexdigest()
    )
    assert bundle["sanitization"]["findings"] == 0
    capture.validate_evidence_bundle(bundle, captured_bundle["root"])


def test_capture_recomputes_execution_identity_and_binds_deep_composition(
    captured_bundle: dict[str, Any],
    tmp_path: Path,
) -> None:
    root = tmp_path / "evidence"
    shutil.copytree(captured_bundle["root"], root)
    expected_identity = captured_bundle["bundle"]["execution_identity"]
    forged_identity = copy.deepcopy(expected_identity)
    forged_identity["astraldeep"]["driver_sha256"] = "9" * 64
    with (
        patch.object(
            runner,
            "capture_execution_identity",
            return_value=forged_identity,
        ),
        pytest.raises(capture.EvidenceError, match="execution identity does not match"),
    ):
        capture.capture_case_study_evidence(
            run_manifest_path=root / "run.json",
            composition_path=captured_bundle["composition_path"],
            runtime_identities_path=captured_bundle["runtime_path"],
            repository_paths=captured_bundle["repositories"],
            output_path=root / "recaptured.json",
        )

    changed_composition = tmp_path / "changed-composition.json"
    changed_composition.write_bytes(captured_bundle["composition_payload"] + b"\n")
    with (
        patch.object(
            runner,
            "capture_execution_identity",
            return_value=expected_identity,
        ),
        pytest.raises(capture.EvidenceError, match="composition bytes do not match"),
    ):
        capture.capture_case_study_evidence(
            run_manifest_path=root / "run.json",
            composition_path=changed_composition,
            runtime_identities_path=captured_bundle["runtime_path"],
            repository_paths=captured_bundle["repositories"],
            output_path=root / "recaptured.json",
        )


def test_semantic_validation_rejects_missing_and_duplicate_artifacts(
    captured_bundle: dict[str, Any],
) -> None:
    missing = copy.deepcopy(captured_bundle["bundle"])
    missing["artifacts"][0]["relative_path"] = "raw/missing.txt"
    with pytest.raises(capture.EvidenceError, match="missing or escapes"):
        capture.validate_evidence_bundle(missing, captured_bundle["root"])

    duplicate = copy.deepcopy(captured_bundle["bundle"])
    duplicate["artifacts"].append(copy.deepcopy(duplicate["artifacts"][0]))
    with pytest.raises(capture.EvidenceError, match="unique case-insensitively"):
        capture.validate_evidence_bundle(duplicate, captured_bundle["root"])


def test_semantic_validation_rejects_broken_references_and_ordered_time(
    captured_bundle: dict[str, Any],
) -> None:
    broken = copy.deepcopy(captured_bundle["bundle"])
    broken["measurements"][0]["source_artifact"] = "raw/not-retained.json"
    with pytest.raises(capture.EvidenceError, match="unretained"):
        capture.validate_evidence_bundle(broken, captured_bundle["root"])

    unordered = copy.deepcopy(captured_bundle["bundle"])
    unordered["commands"][0]["started_at"] = "2026-08-14T12:00:00Z"
    unordered["commands"][0]["finished_at"] = "2026-08-14T12:00:00Z"
    unordered["commands"][1]["started_at"] = "2026-08-14T11:00:00Z"
    unordered["commands"][1]["finished_at"] = "2026-08-14T11:00:00Z"
    with pytest.raises(capture.EvidenceError, match="ordered by start"):
        capture.validate_evidence_bundle(unordered, captured_bundle["root"])


def test_semantic_validation_recomputes_canonical_digest_fields(
    captured_bundle: dict[str, Any],
) -> None:
    changed = copy.deepcopy(captured_bundle["bundle"])
    changed["composition_sha256"] = "0" * 64
    with pytest.raises(capture.EvidenceError, match="composition_sha256"):
        capture.validate_evidence_bundle(changed, captured_bundle["root"])


def test_semantic_validation_derives_summaries_from_retained_samples(
    captured_bundle: dict[str, Any],
) -> None:
    changed = copy.deepcopy(captured_bundle["bundle"])
    changed["measurements"][0]["summary"]["p99"] = 999
    with pytest.raises(capture.EvidenceError, match="derive from retained raw samples"):
        capture.validate_evidence_bundle(changed, captured_bundle["root"])


def test_semantic_validation_replays_retained_effect_and_receipt_invariants(
    captured_bundle: dict[str, Any], tmp_path: Path
) -> None:
    bundle, root = _copied_bundle(captured_bundle, tmp_path)
    command = bundle["commands"][0]
    command_id = str(command["id"])
    result_relative = f"raw/commands/{command_id}.stdout.json"
    result_path = root.joinpath(*Path(result_relative).parts)
    result = capture.read_json_object(result_path)
    result["observations"]["receipts_claimed"] = 0
    result_path.write_bytes(capture.canonical_json_bytes(result) + b"\n")
    _replace_artifact_record(bundle, root, result_relative, "command-stdout")
    result_digest = capture.sha256_file(result_path)
    command["stdout_sha256"] = result_digest

    run_record = next(
        artifact for artifact in bundle["artifacts"] if artifact["kind"] == "case-study-run"
    )
    run_path = root.joinpath(*Path(str(run_record["relative_path"])).parts)
    run = capture.read_json_object(run_path)
    run["commands"][0]["stdout_sha256"] = result_digest
    run_artifact = next(
        artifact for artifact in run["artifacts"] if artifact["relative_path"] == result_relative
    )
    replacement = capture.artifact_record(root, result_relative, "command-stdout")
    run_artifact.clear()
    run_artifact.update(replacement)
    _rewrite_retained_run(bundle, root, run)

    with pytest.raises(capture.EvidenceError, match="violates scenario semantics"):
        capture.validate_evidence_bundle(bundle, root)


def test_semantic_validation_rejects_noncanonical_retained_stdout(
    captured_bundle: dict[str, Any], tmp_path: Path
) -> None:
    bundle, root = _copied_bundle(captured_bundle, tmp_path)
    command = bundle["commands"][0]
    command_id = str(command["id"])
    result_relative = f"raw/commands/{command_id}.stdout.json"
    result_path = root.joinpath(*Path(result_relative).parts)
    result = capture.read_json_object(result_path)
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _replace_artifact_record(bundle, root, result_relative, "command-stdout")
    result_digest = capture.sha256_file(result_path)
    command["stdout_sha256"] = result_digest

    run_record = next(
        artifact for artifact in bundle["artifacts"] if artifact["kind"] == "case-study-run"
    )
    run_path = root.joinpath(*Path(str(run_record["relative_path"])).parts)
    run = capture.read_json_object(run_path)
    run["commands"][0]["stdout_sha256"] = result_digest
    run_artifact = next(
        artifact for artifact in run["artifacts"] if artifact["relative_path"] == result_relative
    )
    replacement = capture.artifact_record(root, result_relative, "command-stdout")
    run_artifact.clear()
    run_artifact.update(replacement)
    _rewrite_retained_run(bundle, root, run)

    with pytest.raises(capture.EvidenceError, match="result is inconsistent"):
        capture.validate_evidence_bundle(bundle, root)


def test_run_and_bundle_require_fixed_driver_argv(
    captured_bundle: dict[str, Any],
) -> None:
    run = copy.deepcopy(captured_bundle["run"])
    run["commands"][0]["argv"] = ["python", "untracked-driver.py"]
    with pytest.raises(capture.EvidenceError, match="canonical driver argv"):
        capture._validate_run_for_capture(run)

    bundle = copy.deepcopy(captured_bundle["bundle"])
    bundle["commands"][0]["argv"] = ["python", "untracked-driver.py"]
    with pytest.raises(capture.EvidenceError, match="schema rejected"):
        capture.validate_evidence_bundle(bundle, captured_bundle["root"])


def test_semantic_validation_binds_success_and_run_envelope(
    captured_bundle: dict[str, Any], tmp_path: Path
) -> None:
    failed = copy.deepcopy(captured_bundle["bundle"])
    failed["commands"][0]["exit_code"] = 1
    with pytest.raises(capture.EvidenceError, match="did not complete successfully"):
        capture.validate_evidence_bundle(failed, captured_bundle["root"])

    bundle, root = _copied_bundle(captured_bundle, tmp_path)
    run_record = next(
        artifact for artifact in bundle["artifacts"] if artifact["kind"] == "case-study-run"
    )
    run_path = root.joinpath(*Path(str(run_record["relative_path"])).parts)
    run = capture.read_json_object(run_path)
    run["started_at"] = "2999-01-01T00:00:00Z"
    run["finished_at"] = "2999-01-01T00:00:01Z"
    _rewrite_retained_run(bundle, root, run)
    with pytest.raises(capture.EvidenceError, match="started after its first retained command"):
        capture.validate_evidence_bundle(bundle, root)


def test_semantic_validation_binds_run_artifact_records_and_order(
    captured_bundle: dict[str, Any], tmp_path: Path
) -> None:
    unordered = copy.deepcopy(captured_bundle["bundle"])
    unordered["artifacts"].reverse()
    with pytest.raises(capture.EvidenceError, match="canonically ordered"):
        capture.validate_evidence_bundle(unordered, captured_bundle["root"])

    bundle, root = _copied_bundle(captured_bundle, tmp_path)
    run_record = next(
        artifact for artifact in bundle["artifacts"] if artifact["kind"] == "case-study-run"
    )
    run_path = root.joinpath(*Path(str(run_record["relative_path"])).parts)
    run = capture.read_json_object(run_path)
    run["artifacts"][0]["kind"] = "mismatched-run-kind"
    _rewrite_retained_run(bundle, root, run)
    with pytest.raises(capture.EvidenceError, match="differs from its run manifest"):
        capture.validate_evidence_bundle(bundle, root)


@pytest.mark.parametrize(
    "value",
    [
        {"api_token": "redacted"},
        {"note": "patient_name=Example"},
        {"note": "person@example.org"},
        {"note": "C:/Users/real-person/result.json"},
    ],
)
def test_public_scanner_rejects_secret_credentials_and_phi(value: object) -> None:
    assert capture.scan_public_value(value)


def test_capture_rejects_missing_or_dirty_repository_inputs(tmp_path: Path) -> None:
    paths, _ = _repositories(tmp_path / "repositories")
    (paths["astraldeep"] / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(capture.EvidenceError, match="dirty"):
        capture.capture_repository_revisions(paths)
    del paths["lets"]
    with pytest.raises(capture.EvidenceError, match="all five"):
        capture.capture_repository_revisions(paths)


def test_strict_json_and_exclusive_records_fail_closed(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"key":1,"key":2}', encoding="utf-8")
    with pytest.raises(capture.EvidenceError, match="strict JSON"):
        capture.read_json_object(duplicate)
    scalar = tmp_path / "scalar.json"
    scalar.write_text("[]", encoding="utf-8")
    with pytest.raises(capture.EvidenceError, match="JSON object"):
        capture.read_json_object(scalar)
    record = tmp_path / "record.json"
    capture.write_canonical_json_exclusive(record, {"value": 1})
    with pytest.raises(capture.EvidenceError, match="refusing to replace"):
        capture.write_canonical_json_exclusive(record, {"value": 2})


def test_cli_output_guards_require_the_dedicated_ignored_result_root(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _initialize_repository(repository, "guard")
    (repository / ".gitignore").write_text("/results/astraldeep-case-study/\n", encoding="utf-8")
    output = repository / "results/astraldeep-case-study/integration/manifest.json"
    assert runner._is_ignored_output(repository, output)
    assert capture._is_ignored_case_study_path(repository, output)
    assert versioning._is_ignored(repository, output)
    assert not runner._is_ignored_output(repository, repository / "paper/submission/result.json")


def test_cli_entrypoints_preserve_fail_closed_status_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "run"
    monkeypatch.setattr(runner, "_is_ignored_output", lambda *args: True)
    monkeypatch.setattr(runner, "run_case_study", lambda **kwargs: {"status": "passed"})
    runner_argv = [
        "--mode",
        "enforce",
        "--evidence-class",
        "astral-integration",
        "--astraldeep-root",
        str(tmp_path),
        "--output",
        str(output),
    ]
    assert runner.main(runner_argv) == 0
    monkeypatch.setattr(runner, "run_case_study", lambda **kwargs: {"status": "failed"})
    assert runner.main(runner_argv) == 1

    monkeypatch.setattr(capture, "_is_ignored_case_study_path", lambda *args: True)
    monkeypatch.setattr(capture, "capture_case_study_evidence", lambda **kwargs: {})
    capture_argv = [
        "--run-manifest",
        str(tmp_path / "run.json"),
        "--composition",
        str(tmp_path / "composition.json"),
        "--runtime-identities",
        str(tmp_path / "runtime.json"),
        "--output",
        str(tmp_path / "manifest.json"),
    ]
    for name in capture.REPOSITORY_KEYS:
        capture_argv.extend(("--repository", f"{name}={tmp_path / name}"))
    assert capture.main(capture_argv) == 0

    repository = tmp_path / "lets-cli"
    _initialize_repository(repository, "lets-cli")
    disposition = _disposition(repository, [])
    monkeypatch.setattr(versioning, "_is_ignored", lambda *args: True)
    monkeypatch.setattr(
        versioning,
        "compare_version_disposition",
        lambda **kwargs: disposition,
    )
    disposition_output = tmp_path / "version-disposition.json"
    assert (
        versioning.main(
            [
                "compare",
                "--repository",
                str(repository),
                "--release-anchor",
                str(tmp_path / "anchor.json"),
                "--output",
                str(disposition_output),
            ]
        )
        == 0
    )
    monkeypatch.setattr(versioning, "gate_paper_result_finalization", lambda **kwargs: False)
    gate_argv = [
        "gate",
        "--repository",
        str(repository),
        "--disposition",
        str(disposition_output),
        "--readiness-output",
        str(tmp_path / "ready.json"),
        "--handoff-output",
        str(tmp_path / "handoff.json"),
    ]
    assert versioning.main(gate_argv) == 3


def test_baseline_and_integration_classes_cannot_be_mixed(tmp_path: Path) -> None:
    with pytest.raises(capture.EvidenceError, match="only run with mode off"):
        runner.run_case_study(
            mode="shadow",
            evidence_class="release-baseline",
            astraldeep_root=tmp_path,
            output_root=tmp_path / "mixed",
        )


def test_schema_refuses_to_relabel_enforced_integration_as_release_baseline(
    captured_bundle: dict[str, Any],
) -> None:
    mixed = copy.deepcopy(captured_bundle["bundle"])
    mixed["evidence_class"] = "release-baseline"
    with pytest.raises(capture.EvidenceError, match="schema rejected"):
        capture.validate_evidence_bundle(mixed, captured_bundle["root"])


def test_signed_v1010_comparison_classifies_integration_only_and_runtime_changes(
    tmp_path: Path,
) -> None:
    anchor = _release_anchor(tmp_path / "anchor.json")
    with _candidate_clone(tmp_path) as candidate:
        unchanged = versioning.compare_version_disposition(
            repository=candidate,
            release_anchor_path=anchor,
        )
        versioning.validate_disposition(unchanged)
        assert unchanged["disposition"] == "unchanged-runtime"
        assert unchanged["comparison"]["runtime_or_wire_paths"] == []

        runtime_source = candidate / "src/lets/__init__.py"
        runtime_source.write_text(
            runtime_source.read_text(encoding="utf-8") + "\n# successor-required test\n",
            encoding="utf-8",
        )
        with pytest.raises(capture.EvidenceError, match="dirty"):
            versioning.compare_version_disposition(
                repository=candidate,
                release_anchor_path=anchor,
            )
        _git(candidate, "add", "src/lets/__init__.py")
        _git(candidate, "commit", "--quiet", "-m", "test runtime change")
        changed = versioning.compare_version_disposition(
            repository=candidate,
            release_anchor_path=anchor,
        )
        versioning.validate_disposition(changed)
        assert changed["disposition"] == "successor-required"
        assert changed["comparison"]["runtime_or_wire_paths"] == ["src/lets/__init__.py"]


def test_version_disposition_validation_rejects_inconsistent_records(tmp_path: Path) -> None:
    repository = tmp_path / "lets"
    _initialize_repository(repository, "lets")
    valid = _disposition(repository, [])
    mutations: list[dict[str, object]] = []

    bad_baseline = copy.deepcopy(valid)
    bad_baseline["baseline"]["signature_verified"] = False  # type: ignore[index]
    mutations.append(bad_baseline)
    bad_candidate = copy.deepcopy(valid)
    bad_candidate["candidate"]["clean"] = False  # type: ignore[index]
    mutations.append(bad_candidate)
    bad_method = copy.deepcopy(valid)
    bad_method["comparison"]["method"] = "untrusted"  # type: ignore[index]
    mutations.append(bad_method)
    bad_partition = copy.deepcopy(valid)
    bad_partition["comparison"]["runtime_or_wire_paths"] = [  # type: ignore[index]
        "src/lets/client.py"
    ]
    mutations.append(bad_partition)
    bad_outcome = copy.deepcopy(valid)
    bad_outcome["disposition"] = "successor-required"
    mutations.append(bad_outcome)
    bad_reason = copy.deepcopy(valid)
    bad_reason["reason"] = ""
    mutations.append(bad_reason)
    bad_timestamp = copy.deepcopy(valid)
    bad_timestamp["generated_at"] = "not-a-timestamp"
    mutations.append(bad_timestamp)

    for document in mutations:
        with pytest.raises(capture.EvidenceError):
            versioning.validate_disposition(document)
    with pytest.raises(capture.EvidenceError, match="release anchor"):
        versioning._release_anchor({"letsReleaseAnchor": {}})


def test_current_candidate_validation_recomputes_signed_tree_comparison(
    tmp_path: Path,
) -> None:
    anchor = _release_anchor(tmp_path / "anchor.json")
    with _candidate_clone(tmp_path) as candidate:
        disposition = versioning.compare_version_disposition(
            repository=candidate,
            release_anchor_path=anchor,
        )
        versioning._validate_current_candidate(candidate, disposition)

        stale = copy.deepcopy(disposition)
        stale["comparison"]["changed_paths"] = ["docs/forged-path.md"]
        stale["comparison"]["integration_only_paths"] = ["docs/forged-path.md"]
        versioning.validate_disposition(stale)
        with pytest.raises(capture.EvidenceError, match="no longer matches"):
            versioning._validate_current_candidate(candidate, stale)

        wrong_tree = copy.deepcopy(disposition)
        wrong_tree["candidate"]["tree"] = "0" * 40
        with pytest.raises(capture.EvidenceError, match="candidate tree changed"):
            versioning._validate_current_candidate(candidate, wrong_tree)


def test_successor_gate_blocks_finalization_and_emits_separate_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "lets"
    _initialize_repository(repository, "lets")
    disposition = _disposition(repository, ["src/lets/client.py"])
    disposition_path = tmp_path / "version-disposition.json"
    capture.write_canonical_json_exclusive(disposition_path, disposition)
    monkeypatch.setattr(versioning, "_validate_current_candidate", lambda *args: None)
    readiness = tmp_path / "paper-ready.json"
    handoff = tmp_path / "successor-handoff.json"
    assert not versioning.gate_paper_result_finalization(
        repository=repository,
        disposition_path=disposition_path,
        evidence_manifest_path=None,
        readiness_output=readiness,
        handoff_output=handoff,
    )
    assert not readiness.exists()
    handoff_document = capture.read_json_object(handoff)
    assert handoff_document["status"] == "successor-release-required"
    assert handoff_document["runtime_or_wire_paths"] == ["src/lets/client.py"]
    assert len(handoff_document["handoff_id"]) == 24
    assert handoff_document["disposition_sha256"] == capture.sha256_file(disposition_path)


def test_finalization_gate_rejects_missing_evidence_and_manuscript_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "lets"
    _initialize_repository(repository, "lets")
    disposition_path = tmp_path / "version-disposition.json"
    capture.write_canonical_json_exclusive(disposition_path, _disposition(repository, []))
    monkeypatch.setattr(versioning, "_validate_current_candidate", lambda *args: None)
    with pytest.raises(capture.EvidenceError, match="validated evidence bundle"):
        versioning.gate_paper_result_finalization(
            repository=repository,
            disposition_path=disposition_path,
            evidence_manifest_path=None,
            readiness_output=tmp_path / "ready.json",
            handoff_output=tmp_path / "handoff.json",
        )
    with pytest.raises(capture.EvidenceError, match="separate from manuscript"):
        versioning.gate_paper_result_finalization(
            repository=repository,
            disposition_path=disposition_path,
            evidence_manifest_path=None,
            readiness_output=repository / "paper/submission/ready.json",
            handoff_output=tmp_path / "handoff.json",
        )


def test_unchanged_runtime_gate_requires_matching_validated_integration_bundle(
    captured_bundle: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = captured_bundle["repositories"]["lets"]
    disposition = _disposition(repository, [])
    disposition_path = tmp_path / "version-disposition.json"
    capture.write_canonical_json_exclusive(disposition_path, disposition)
    monkeypatch.setattr(versioning, "_validate_current_candidate", lambda *args: None)
    readiness = tmp_path / "paper-ready.json"
    handoff = tmp_path / "successor-handoff.json"
    assert versioning.gate_paper_result_finalization(
        repository=repository,
        disposition_path=disposition_path,
        evidence_manifest_path=captured_bundle["manifest"],
        readiness_output=readiness,
        handoff_output=handoff,
    )
    assert capture.read_json_object(readiness)["status"] == (
        "ready-for-local-paper-result-finalization"
    )
    assert capture.read_json_object(readiness)["lets_runtime_commit"] == (
        versioning.BASELINE_COMMIT
    )
    assert not handoff.exists()


def test_unchanged_runtime_gate_rejects_nonbaseline_composition_pin(
    captured_bundle: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, root = _copied_bundle(captured_bundle, tmp_path)
    composition_record = next(
        artifact for artifact in bundle["artifacts"] if artifact["kind"] == "composition-manifest"
    )
    composition_relative = str(composition_record["relative_path"])
    composition_path = root.joinpath(*Path(composition_relative).parts)
    composition = capture.read_json_object(composition_path)
    composition["components"]["lets"]["commit"] = "6" * 40
    composition_path.write_bytes(capture.canonical_json_bytes(composition) + b"\n")
    bundle["composition_sha256"] = capture.sha256_file(composition_path)
    _replace_artifact_record(
        bundle,
        root,
        composition_relative,
        "composition-manifest",
    )
    manifest = root / "manifest.json"
    manifest.write_bytes(capture.canonical_json_bytes(bundle) + b"\n")

    repository = captured_bundle["repositories"]["lets"]
    disposition_path = tmp_path / "version-disposition.json"
    capture.write_canonical_json_exclusive(disposition_path, _disposition(repository, []))
    monkeypatch.setattr(versioning, "_validate_current_candidate", lambda *args: None)
    with pytest.raises(capture.EvidenceError, match="execution imports"):
        versioning.gate_paper_result_finalization(
            repository=repository,
            disposition_path=disposition_path,
            evidence_manifest_path=manifest,
            readiness_output=tmp_path / "ready.json",
            handoff_output=tmp_path / "handoff.json",
        )


@pytest.fixture(scope="module")
def aggregate_bundle(
    captured_bundle: dict[str, Any], tmp_path_factory: pytest.TempPathFactory
) -> dict[str, Path]:
    workspace = tmp_path_factory.mktemp("astraldeep-case-study-aggregate")
    root = workspace / "results" / "astraldeep-case-study"
    runtime_path = root / "runtime-identities.json"
    runtime_path.parent.mkdir(parents=True)
    runtime_path.write_bytes(captured_bundle["runtime_path"].read_bytes())
    execution_identity = captured_bundle["bundle"]["execution_identity"]
    modes = {
        "off": (root / "baseline" / "off", "release-baseline"),
        "shadow": (root / "integration" / "shadow", "astral-integration"),
        "enforce": (root / "integration" / "enforce", "astral-integration"),
    }
    manifests: dict[str, Path] = {}
    for mode, (mode_root, evidence_class) in modes.items():
        mode_root.parent.mkdir(parents=True, exist_ok=True)
        _run(
            mode_root,
            mode=mode,
            evidence_class=evidence_class,
            execution_identity=execution_identity,
        )
        manifest = mode_root / "manifest.json"
        with patch.object(runner, "capture_execution_identity", return_value=execution_identity):
            capture.capture_case_study_evidence(
                run_manifest_path=mode_root / "run.json",
                composition_path=captured_bundle["composition_path"],
                runtime_identities_path=runtime_path,
                repository_paths=captured_bundle["repositories"],
                output_path=manifest,
                additional_environment={"database_version": "17", "parallel_workers": 4},
                notes="Synthetic public aggregate conformance workload.",
            )
        manifests[mode] = manifest

    disposition_path = root / "version-disposition.json"
    disposition = _disposition(captured_bundle["repositories"]["lets"], [])
    capture.write_canonical_json_exclusive(disposition_path, disposition)
    readiness_path = root / "paper-readiness.json"
    capture.write_canonical_json_exclusive(
        readiness_path,
        {
            "format": versioning.READINESS_FORMAT,
            "status": "ready-for-local-paper-result-finalization",
            "lets_release": versioning.BASELINE_RELEASE,
            "lets_runtime_commit": versioning.BASELINE_COMMIT,
            "lets_tooling_commit": disposition["candidate"]["commit"],
            "disposition_sha256": capture.sha256_file(disposition_path),
            "evidence_manifest_sha256": capture.sha256_file(manifests["enforce"]),
            "created_at": aggregate._timestamp(),
        },
    )

    alternate_runtime = copy.deepcopy(_runtime_identities())
    alternate_runtime["machine_digest"] = f"sha256:{'9' * 64}"
    alternate_runtime_path = workspace / "alternate-runtime.json"
    capture.write_canonical_json_exclusive(alternate_runtime_path, alternate_runtime)
    alternate_shadow = workspace / "alternate-shadow"
    _run(
        alternate_shadow,
        mode="shadow",
        evidence_class="astral-integration",
        execution_identity=execution_identity,
    )
    with patch.object(runner, "capture_execution_identity", return_value=execution_identity):
        capture.capture_case_study_evidence(
            run_manifest_path=alternate_shadow / "run.json",
            composition_path=captured_bundle["composition_path"],
            runtime_identities_path=alternate_runtime_path,
            repository_paths=captured_bundle["repositories"],
            output_path=alternate_shadow / "manifest.json",
            additional_environment={"database_version": "17", "parallel_workers": 4},
            notes="Synthetic public aggregate conformance workload.",
        )
    return {"root": root, "alternate_shadow": alternate_shadow}


def _copy_aggregate_root(aggregate_bundle: Mapping[str, Path], tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "results" / "astraldeep-case-study"
    shutil.copytree(aggregate_bundle["root"], root)
    alternate = tmp_path / "alternate-shadow"
    shutil.copytree(aggregate_bundle["alternate_shadow"], alternate)
    return root, alternate


def test_cross_mode_aggregate_creates_digest_bound_descriptive_outputs(
    aggregate_bundle: dict[str, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _ = _copy_aggregate_root(aggregate_bundle, tmp_path)
    monkeypatch.setattr(aggregate, "_validate_historical_candidate", lambda *args: None)
    manifest, summary = aggregate.aggregate_case_study(root)

    assert manifest["status"] == "validated"
    assert summary["status"] == "validated"
    assert summary["totals"]["scenario_count"] == 57
    assert summary["totals"]["command_count"] == 57
    assert summary["modes"]["off"]["comparison_role"] == "flag-off-control"
    assert summary["modes"]["shadow"]["comparison_role"] == "shadow-observation"
    assert summary["modes"]["enforce"]["comparison_role"] == "enforced-treatment"
    assert summary["measurement_coverage"]["recovery_time_included"] is False
    assert summary["runtime_identity_quality"]["authenticated_runtime_identity_supported"] is False
    assert summary["statistical_limits"]["publication_inference_supported"] is False
    assert summary["evidence_scope"]["reproduction_attestation_included"] is False
    assert summary["evidence_scope"]["distinct_historical_release_reference_included"] is False
    assert len(summary["modes"]["enforce"]["scenario_outcomes"]) == 19
    assert summary["modes"]["enforce"]["invariants"]["zero_unreceipted_governed_effects"]
    assert summary["modes"]["enforce"]["cohort_metrics"]
    assert manifest["summary"]["sha256"] == capture.sha256_file(root / "summary.json")
    assert manifest["inputs"]["enforce_manifest"]["sha256"] == capture.sha256_file(
        root / "integration" / "enforce" / "manifest.json"
    )
    assert (root / "manifest.json").read_bytes() == (capture.canonical_json_bytes(manifest) + b"\n")
    assert (root / "summary.json").read_bytes() == (capture.canonical_json_bytes(summary) + b"\n")
    assert not (root / "reproduction.json").exists()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "regular retained file"),
        ("extra", "exact retained file set"),
        ("noncanonical", "not canonical JSON"),
    ],
)
def test_cross_mode_aggregate_rejects_missing_extra_and_noncanonical_inputs(
    aggregate_bundle: dict[str, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    message: str,
) -> None:
    root, _ = _copy_aggregate_root(aggregate_bundle, tmp_path)
    shadow_manifest = root / "integration" / "shadow" / "manifest.json"
    if mutation == "missing":
        shadow_manifest.unlink()
    elif mutation == "extra":
        (root / "integration" / "shadow" / "unlisted.json").write_text("{}\n", encoding="utf-8")
    else:
        document = capture.read_json_object(shadow_manifest)
        shadow_manifest.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    monkeypatch.setattr(aggregate, "_validate_historical_candidate", lambda *args: None)
    with pytest.raises(capture.EvidenceError, match=message):
        aggregate.aggregate_case_study(root)
    assert not (root / "manifest.json").exists()
    assert not (root / "summary.json").exists()


def test_cross_mode_aggregate_rejects_individually_valid_mixed_identity(
    aggregate_bundle: dict[str, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, alternate_shadow = _copy_aggregate_root(aggregate_bundle, tmp_path)
    shadow = root / "integration" / "shadow"
    shutil.rmtree(shadow)
    shutil.copytree(alternate_shadow, shadow)
    monkeypatch.setattr(aggregate, "_validate_historical_candidate", lambda *args: None)
    with pytest.raises(capture.EvidenceError, match="mix shared machine_digest"):
        aggregate.aggregate_case_study(root)


def test_cross_mode_aggregate_rejects_stale_readiness_binding(
    aggregate_bundle: dict[str, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _ = _copy_aggregate_root(aggregate_bundle, tmp_path)
    readiness_path = root / "paper-readiness.json"
    readiness = capture.read_json_object(readiness_path)
    readiness["evidence_manifest_sha256"] = "0" * 64
    readiness_path.write_bytes(capture.canonical_json_bytes(readiness) + b"\n")
    monkeypatch.setattr(aggregate, "_validate_historical_candidate", lambda *args: None)
    with pytest.raises(capture.EvidenceError, match="stale or bound to the wrong evidence"):
        aggregate.aggregate_case_study(root)


def test_cross_mode_aggregate_never_replaces_existing_output(
    aggregate_bundle: dict[str, Path], tmp_path: Path
) -> None:
    root, _ = _copy_aggregate_root(aggregate_bundle, tmp_path)
    marker = b"retained\n"
    (root / "summary.json").write_bytes(marker)
    with pytest.raises(capture.EvidenceError, match="refusing to replace"):
        aggregate.aggregate_case_study(root)
    assert (root / "summary.json").read_bytes() == marker
    assert not (root / "manifest.json").exists()


def test_cross_mode_aggregate_recomputes_historical_disposition_snapshot(
    captured_bundle: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = captured_bundle["repositories"]["lets"]
    disposition = _disposition(repository, [])
    candidate = disposition["candidate"]
    monkeypatch.setattr(versioning, "_validate_repository_anchor", lambda *args: None)
    monkeypatch.setattr(versioning, "_git", lambda *args: candidate["tree"])
    observed = copy.deepcopy(disposition["comparison"])
    observed["changed_paths"] = ["benchmarks/astraldeep/forged.py"]
    observed["integration_only_paths"] = ["benchmarks/astraldeep/forged.py"]
    monkeypatch.setattr(versioning, "_comparison_snapshot", lambda *args: observed)
    with pytest.raises(capture.EvidenceError, match="changed_paths no longer matches"):
        aggregate._validate_historical_candidate(repository, disposition)


def test_cross_mode_aggregate_cli_rejects_noncanonical_root(tmp_path: Path) -> None:
    assert aggregate.main(["--evidence-root", str(tmp_path)]) == 2
    assert not (tmp_path / "manifest.json").exists()


def test_cross_mode_aggregate_pair_rollback_never_removes_preexisting_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path = tmp_path / "manifest.json"
    summary_path = tmp_path / "summary.json"
    marker = b"preexisting\n"
    manifest_path.write_bytes(marker)
    real_open = aggregate.os.open

    def guarded_open(path: Path, flags: int, mode: int) -> int:
        if Path(path) == manifest_path:
            raise PermissionError("simulated locked pre-existing manifest")
        return real_open(path, flags, mode)

    monkeypatch.setattr(aggregate.os, "open", guarded_open)
    with pytest.raises(capture.EvidenceError, match="could not create"):
        aggregate._write_pair_exclusive(
            manifest_path,
            {"format": "test"},
            summary_path,
            {"format": "test"},
        )
    assert manifest_path.read_bytes() == marker
    assert not summary_path.exists()


def test_cross_mode_aggregate_final_revalidation_detects_concurrent_leaf_change(
    aggregate_bundle: dict[str, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _ = _copy_aggregate_root(aggregate_bundle, tmp_path)
    monkeypatch.setattr(aggregate, "_validate_historical_candidate", lambda *args: None)
    original = aggregate._mode_summary

    def mutate_after_summary(
        mode: str, manifest_path: Path, document: Mapping[str, object]
    ) -> dict[str, object]:
        summary = original(mode, manifest_path, document)
        if mode == "enforce":
            target = manifest_path.parent / "raw" / "commands" / ("enforce-scope-read.stderr.txt")
            target.write_bytes(b"changed after summary\n")
        return summary

    monkeypatch.setattr(aggregate, "_mode_summary", mutate_after_summary)
    with pytest.raises(capture.EvidenceError, match="digest mismatch"):
        aggregate.aggregate_case_study(root)
    assert not (root / "manifest.json").exists()
    assert not (root / "summary.json").exists()


def test_cross_mode_aggregate_schema_matches_runtime_digest_and_path_contracts(
    aggregate_bundle: dict[str, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _ = _copy_aggregate_root(aggregate_bundle, tmp_path)
    monkeypatch.setattr(aggregate, "_validate_historical_candidate", lambda *args: None)
    manifest, summary = aggregate.build_aggregate_documents(root)

    bare_digest = copy.deepcopy(summary)
    bare_digest["runtime_identities"]["policy_digest"] = "1" * 64
    capture._schema_validate(bare_digest, aggregate.AGGREGATE_SCHEMA)

    invalid_epoch = copy.deepcopy(summary)
    invalid_epoch["runtime_identities"]["config_epoch"] = 0
    with pytest.raises(capture.EvidenceError, match="schema rejected"):
        capture._schema_validate(invalid_epoch, aggregate.AGGREGATE_SCHEMA)

    traversal = copy.deepcopy(manifest)
    traversal["inputs"]["off_manifest"]["relative_path"] = "x/../../secret"
    with pytest.raises(capture.EvidenceError, match="schema rejected"):
        capture._schema_validate(traversal, aggregate.AGGREGATE_SCHEMA)

    swapped = copy.deepcopy(manifest)
    swapped["inputs"]["off_manifest"]["relative_path"] = "integration/shadow/manifest.json"
    with pytest.raises(capture.EvidenceError, match="schema rejected"):
        capture._schema_validate(swapped, aggregate.AGGREGATE_SCHEMA)
