"""Run the fixed Astral/LETS case-study matrix through the exact Deep driver.

The driver is an exact-composition AstralDeep test entrypoint.  It receives one
canonical JSON scenario on stdin and returns one bounded JSON result on stdout.
This repository stays standalone: the tracked harness imports no AstralDeep
implementation and stores no manuscript or generated result in Git.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import statistics
import subprocess
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.astraldeep.capture_environment import (
    RUN_FORMAT,
    EvidenceError,
    artifact_record,
    canonical_json_bytes,
    read_json_object,
    scan_public_text,
    scan_public_value,
    sha256_file,
    write_canonical_json_exclusive,
)

SCENARIO_FORMAT = "lets.astraldeep-case-study-scenario/v1"
RESULT_FORMAT = "lets.astraldeep-case-study-result/v1"
EXECUTION_IDENTITY_FORMAT = "lets.astraldeep-execution-identity/v1"
DRIVER_RELATIVE_PATH = "backend/tests/lets_case_study_driver.py"
COMPOSITION_RELATIVE_PATH = "config/astral-composition.json"
PUBLIC_DRIVER_ARGV = ("python", DRIVER_RELATIVE_PATH)
ASTRAL_TOOL_SCOPES = (
    "tools:read",
    "tools:write",
    "tools:search",
    "tools:system",
    "tools:files",
    "tools:execute",
)
ASTRAL_SCOPE_BINDINGS = {
    "tools:read": ("astral.tools.read", "tool_read", 0),
    "tools:write": ("astral.tools.write", "tool_write", 1),
    "tools:search": ("astral.tools.search", "tool_search", 2),
    "tools:system": ("astral.tools.system", "tool_system", 3),
    "tools:files": ("astral.tools.files", "tool_files", 4),
    "tools:execute": ("astral.tools.execute", "tool_execute", 5),
}
MODES = ("off", "shadow", "enforce")
LIFECYCLE_EVENTS = (
    "provision",
    "spawn",
    "renew",
    "quiesce",
    "resume",
    "close",
    "revoke",
)
FAULT_SCENARIOS = (
    "warden-outage",
    "receipt-replay",
    "budget-exhaustion",
    "post-revocation-effect",
)
_RESULT_KEYS = {
    "format",
    "scenario_id",
    "mode",
    "category",
    "status",
    "execution_identity",
    "observations",
    "measurements",
}
_OBSERVATION_KEYS = {
    "astral_decision",
    "lets_requests",
    "receipts_issued",
    "receipts_claimed",
    "physical_effects",
    "denied_effects",
    "unreceipted_governed_effects",
    "budget_conserved",
    "sequence_monotonic",
    "lifecycle_converged",
    "lifecycle_state",
    "denial_code",
    "scope_binding",
}
_MEASUREMENT_KEYS = {"name", "unit", "samples", "exclusions"}
_PUBLIC_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_. -]{0,99}\Z")
_MAX_DRIVER_OUTPUT_BYTES = 2 * 1024 * 1024
_SOURCE_SUFFIXES = frozenset({".py", ".pyi"})
_FAULT_DENIAL_CODES = {
    "warden-outage": "warden_unavailable",
    "receipt-replay": "receipt_replayed",
    "budget-exhaustion": "budget_exhausted",
    "post-revocation-effect": "binding_unavailable",
}
_CHILD_ENV_KEYS = frozenset(
    {
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    }
)


@dataclass(frozen=True, slots=True)
class Scenario:
    scenario_id: str
    mode: str
    category: str
    scope: str | None = None
    lifecycle_event: str | None = None
    parallelism: int = 1
    recursion_depth: int = 0
    expected_effect: str = "none"
    expected_lets_behavior: str = "off"
    expected_lifecycle_state: str | None = None

    def to_request(self) -> dict[str, object]:
        return {"format": SCENARIO_FORMAT, **asdict(self)}


def build_scenarios(mode: str) -> tuple[Scenario, ...]:
    """Return the deterministic six-scope, lifecycle, dispatch, and fault matrix."""

    if mode not in MODES:
        raise EvidenceError(f"unsupported case-study mode {mode!r}")
    lets_behavior = {"off": "off", "shadow": "evaluate", "enforce": "enforce"}[mode]
    scenarios: list[Scenario] = []
    for scope in ASTRAL_TOOL_SCOPES:
        scenarios.append(
            Scenario(
                scenario_id=f"{mode}-scope-{scope.removeprefix('tools:')}",
                mode=mode,
                category="scope",
                scope=scope,
                expected_effect="execute",
                expected_lets_behavior=lets_behavior,
            )
        )
    lifecycle_targets = {
        "provision": "active",
        "spawn": "active",
        "renew": "active",
        "quiesce": "quiescent",
        "resume": "active",
        "close": "closed",
        "revoke": "revoked",
    }
    for event in LIFECYCLE_EVENTS:
        scenarios.append(
            Scenario(
                scenario_id=f"{mode}-lifecycle-{event}",
                mode=mode,
                category="lifecycle",
                lifecycle_event=event,
                expected_lets_behavior=lets_behavior,
                expected_lifecycle_state=lifecycle_targets[event],
            )
        )
    scenarios.extend(
        (
            Scenario(
                scenario_id=f"{mode}-parallel-dispatch",
                mode=mode,
                category="parallel-dispatch",
                scope="tools:execute",
                parallelism=4,
                expected_effect="execute",
                expected_lets_behavior=lets_behavior,
            ),
            Scenario(
                scenario_id=f"{mode}-recursive-dispatch",
                mode=mode,
                category="recursive-dispatch",
                scope="tools:execute",
                recursion_depth=3,
                expected_effect="execute",
                expected_lets_behavior=lets_behavior,
            ),
        )
    )
    for fault in FAULT_SCENARIOS:
        scenarios.append(
            Scenario(
                scenario_id=f"{mode}-{fault}",
                mode=mode,
                category=fault,
                scope="tools:execute",
                expected_effect="deny" if mode == "enforce" else "execute",
                expected_lets_behavior=lets_behavior,
            )
        )
    return tuple(scenarios)


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _git(repository: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise EvidenceError("could not inspect the exact AstralDeep driver revision") from exc
    if completed.returncode != 0:
        raise EvidenceError("could not inspect the exact AstralDeep driver revision")
    return completed.stdout.strip()


def _source_tree_identity(root: Path) -> dict[str, object]:
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise EvidenceError("an exact imported source tree is unavailable") from exc
    records: list[dict[str, str]] = []
    try:
        candidates = sorted(
            (
                path
                for path in resolved.rglob("*")
                if path.is_file() and path.suffix in _SOURCE_SUFFIXES
            ),
            key=lambda path: path.relative_to(resolved).as_posix(),
        )
        for path in candidates:
            if path.is_symlink():
                raise EvidenceError("an imported source tree contains a symbolic link")
            records.append(
                {
                    "relative_path": path.relative_to(resolved).as_posix(),
                    "sha256": sha256_file(path),
                }
            )
    except OSError as exc:
        raise EvidenceError("an exact imported source tree is unavailable") from exc
    if not records:
        raise EvidenceError("an exact imported source tree contains no Python sources")
    return {
        "file_count": len(records),
        "tree_sha256": hashlib.sha256(canonical_json_bytes(records)).hexdigest(),
    }


def _clean_repository_commit(repository: Path) -> str:
    root = Path(_git(repository, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if root != repository.resolve(strict=True):
        raise EvidenceError("AstralDeep root is not the canonical Git worktree root")
    status = _git(
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    if status:
        raise EvidenceError("AstralDeep driver revision is dirty")
    commit = _git(repository, "rev-parse", "--verify", "HEAD")
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise EvidenceError("AstralDeep driver revision is not one exact commit")
    tracked_driver = _git(
        repository,
        "ls-files",
        "--error-unmatch",
        "--",
        DRIVER_RELATIVE_PATH,
    )
    if tracked_driver != DRIVER_RELATIVE_PATH:
        raise EvidenceError("canonical AstralDeep driver is not tracked exactly once")
    return commit


def _component_identity(
    *,
    astraldeep_root: Path,
    component_name: str,
    source_relative: str,
    component: Mapping[str, object],
    include_release: bool = False,
) -> dict[str, object]:
    commit = component.get("commit")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise EvidenceError(f"composition {component_name} pin is not one exact commit")
    component_root = astraldeep_root / "components" / component_name
    observed_commit = _git(component_root, "rev-parse", "--verify", "HEAD")
    if observed_commit != commit:
        raise EvidenceError(f"checked-out {component_name} does not match its composition pin")
    if _git(component_root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise EvidenceError(f"checked-out {component_name} source tree is dirty")
    identity = {
        "component_commit": commit,
        **_source_tree_identity(component_root / source_relative),
    }
    if include_release:
        release = component.get("ref")
        if (
            not isinstance(release, str)
            or re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", release) is None
        ):
            raise EvidenceError("composition LETS release identity is invalid")
        identity["release"] = release
    return identity


def _canonical_interpreter(astraldeep_root: Path) -> Path:
    relative = Path(".venv/Scripts/python.exe") if os.name == "nt" else Path(".venv/bin/python")
    try:
        executable = (astraldeep_root / relative).resolve(strict=True)
    except OSError as exc:
        raise EvidenceError(
            "canonical AstralDeep virtual-environment interpreter is missing"
        ) from exc
    if not executable.is_file():
        raise EvidenceError("canonical AstralDeep interpreter is not a regular file")
    return executable


def _interpreter_identity(executable: Path) -> dict[str, object]:
    probe = (
        "import json,platform;"
        "print(json.dumps([platform.python_implementation(),platform.python_version()],"
        "separators=(',',':')))"
    )
    try:
        completed = subprocess.run(
            [str(executable), "-I", "-c", probe],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            env=_child_environment(),
            timeout=30,
        )
        values = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("canonical AstralDeep interpreter identity is unavailable") from exc
    if (
        completed.returncode != 0
        or not isinstance(values, list)
        or len(values) != 2
        or any(not isinstance(value, str) or not value for value in values)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", values[1]) is None
    ):
        raise EvidenceError("canonical AstralDeep interpreter identity is invalid")
    return {
        "implementation": values[0],
        "version": values[1],
        "executable_sha256": sha256_file(executable),
    }


def capture_execution_identity(astraldeep_root: Path) -> dict[str, object]:
    """Bind the only accepted driver and imported runtime trees without paths."""

    try:
        root = astraldeep_root.resolve(strict=True)
        driver_path = (root / DRIVER_RELATIVE_PATH).resolve(strict=True)
    except OSError as exc:
        raise EvidenceError("canonical AstralDeep driver inputs are unavailable") from exc
    try:
        driver_path.relative_to(root)
    except ValueError as exc:
        raise EvidenceError("canonical AstralDeep driver escapes its worktree") from exc
    commit = _clean_repository_commit(root)
    composition = read_json_object(root / COMPOSITION_RELATIVE_PATH)
    components = composition.get("components")
    if not isinstance(components, Mapping):
        raise EvidenceError("AstralDeep composition has no component map")
    plane = components.get("astral-plane")
    lets = components.get("lets")
    if not isinstance(plane, Mapping) or not isinstance(lets, Mapping):
        raise EvidenceError("AstralDeep composition lacks Plane or LETS")
    executable = _canonical_interpreter(root)
    return {
        "format": EXECUTION_IDENTITY_FORMAT,
        "astraldeep": {
            "commit": commit,
            "driver_relative_path": DRIVER_RELATIVE_PATH,
            "driver_sha256": sha256_file(driver_path),
        },
        "interpreter": _interpreter_identity(executable),
        "imports": {
            "astralplane": _component_identity(
                astraldeep_root=root,
                component_name="AstralPlane",
                source_relative="src/astralplane",
                component=plane,
            ),
            "lets": _component_identity(
                astraldeep_root=root,
                component_name="LETS",
                source_relative="src/lets",
                component=lets,
                include_release=True,
            ),
        },
    }


def _child_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if key.upper() in _CHILD_ENV_KEYS
    }
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
        }
    )
    return environment


def _strict_result(payload: bytes) -> dict[str, Any]:
    if len(payload) > _MAX_DRIVER_OUTPUT_BYTES:
        raise EvidenceError("driver stdout exceeded the bounded result size")

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON value {value!r}")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise EvidenceError("driver stdout is not one strict UTF-8 JSON result") from exc
    if not isinstance(document, dict):
        raise EvidenceError("driver stdout result must be an object")
    if payload != canonical_json_bytes(document) + b"\n":
        raise EvidenceError("driver stdout is not canonical JSON followed by one newline")
    return document


def _integer(observations: Mapping[str, object], field: str) -> int:
    value = observations.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EvidenceError(f"driver observation {field} must be a non-negative integer")
    return value


def _validate_result(
    result: Mapping[str, object],
    scenario: Scenario,
    execution_identity: Mapping[str, object],
) -> None:
    if set(result) != _RESULT_KEYS:
        raise EvidenceError(f"driver result for {scenario.scenario_id} has undeclared fields")
    expected_header = {
        "format": RESULT_FORMAT,
        "scenario_id": scenario.scenario_id,
        "mode": scenario.mode,
        "category": scenario.category,
        "status": "passed",
    }
    for field, expected in expected_header.items():
        if result.get(field) != expected:
            raise EvidenceError(
                f"driver result {field} does not match scenario {scenario.scenario_id}"
            )
    observed_identity = result.get("execution_identity")
    if not isinstance(observed_identity, Mapping) or dict(observed_identity) != dict(
        execution_identity
    ):
        raise EvidenceError(f"driver execution identity for {scenario.scenario_id} is not exact")
    observations = result.get("observations")
    if not isinstance(observations, Mapping) or set(observations) != _OBSERVATION_KEYS:
        raise EvidenceError(f"driver observations for {scenario.scenario_id} are malformed")
    decision = observations.get("astral_decision")
    if decision not in {"allowed", "denied", "not-applicable"}:
        raise EvidenceError(f"driver decision for {scenario.scenario_id} is invalid")
    lets_requests = _integer(observations, "lets_requests")
    receipts_issued = _integer(observations, "receipts_issued")
    receipts_claimed = _integer(observations, "receipts_claimed")
    physical_effects = _integer(observations, "physical_effects")
    denied_effects = _integer(observations, "denied_effects")
    unreceipted = _integer(observations, "unreceipted_governed_effects")
    budget_conserved = observations.get("budget_conserved")
    sequence_monotonic = observations.get("sequence_monotonic")
    converged = observations.get("lifecycle_converged")
    lifecycle_state = observations.get("lifecycle_state")
    denial_code = observations.get("denial_code")
    scope_binding = observations.get("scope_binding")
    if (
        not isinstance(budget_conserved, bool)
        or not isinstance(sequence_monotonic, bool)
        or not isinstance(converged, bool)
        or (lifecycle_state is not None and not isinstance(lifecycle_state, str))
        or (denial_code is not None and not isinstance(denial_code, str))
    ):
        raise EvidenceError(
            f"driver convergence or denial record for {scenario.scenario_id} is invalid"
        )
    if not budget_conserved or not sequence_monotonic:
        raise EvidenceError(f"scenario {scenario.scenario_id} violated authority conservation")
    if unreceipted != 0:
        raise EvidenceError(
            f"scenario {scenario.scenario_id} observed an unreceipted governed effect"
        )
    if receipts_claimed > receipts_issued:
        raise EvidenceError(
            f"scenario {scenario.scenario_id} claimed more receipts than were issued"
        )

    if scenario.mode == "off":
        if any((lets_requests, receipts_issued, receipts_claimed)):
            raise EvidenceError(f"flag-off scenario {scenario.scenario_id} made a LETS call")
    elif lets_requests < 1:
        raise EvidenceError(f"enabled scenario {scenario.scenario_id} made no LETS request")
    if scenario.mode == "shadow" and receipts_claimed:
        raise EvidenceError(
            f"shadow scenario {scenario.scenario_id} claimed an enforcement receipt"
        )

    if scenario.category == "lifecycle":
        if scope_binding is not None:
            raise EvidenceError(
                f"lifecycle scenario {scenario.scenario_id} reported a tool-scope mapping"
            )
    else:
        if not isinstance(scope_binding, Mapping) or set(scope_binding) != {
            "scope",
            "capability",
            "transition",
            "resource_dimension",
            "checks",
        }:
            raise EvidenceError(
                f"scenario {scenario.scenario_id} returned a malformed scope mapping"
            )
        scope = scenario.scope or "tools:execute"
        capability, transition, dimension = ASTRAL_SCOPE_BINDINGS[scope]
        checks = scope_binding.get("checks")
        if (
            scope_binding.get("scope") != scope
            or scope_binding.get("capability") != capability
            or scope_binding.get("transition") != transition
            or scope_binding.get("resource_dimension") != dimension
            or type(checks) is not int
            or checks < 0
        ):
            raise EvidenceError(
                f"scenario {scenario.scenario_id} did not observe its exact scope mapping"
            )
        expected_checks = (
            0
            if scenario.mode == "off" or scenario.category == "post-revocation-effect"
            else lets_requests
        )
        if checks != expected_checks:
            raise EvidenceError(
                f"scenario {scenario.scenario_id} did not verify every scope mapping request"
            )

    if scenario.category == "post-revocation-effect" and (
        not converged or lifecycle_state != "revoked"
    ):
        raise EvidenceError(
            f"post-revocation scenario {scenario.scenario_id} lacks a causal revoked state"
        )

    if scenario.category == "lifecycle":
        if (
            decision != "not-applicable"
            or not converged
            or lifecycle_state != scenario.expected_lifecycle_state
            or physical_effects
            or denied_effects
        ):
            raise EvidenceError(
                f"lifecycle scenario {scenario.scenario_id} did not converge cleanly"
            )
    elif scenario.expected_effect == "deny":
        if (
            decision != "denied"
            or physical_effects
            or denied_effects < 1
            or denial_code != _FAULT_DENIAL_CODES.get(scenario.category)
        ):
            raise EvidenceError(f"enforced fault scenario {scenario.scenario_id} did not deny")
    else:
        if decision != "allowed" or physical_effects < 1 or denied_effects:
            raise EvidenceError(
                f"scenario {scenario.scenario_id} did not execute its expected effect"
            )
        if scenario.mode == "enforce" and receipts_claimed != physical_effects:
            raise EvidenceError(
                f"enforced scenario {scenario.scenario_id} did not claim one receipt per effect"
            )
        if scenario.category == "parallel-dispatch" and physical_effects != scenario.parallelism:
            raise EvidenceError(
                f"parallel scenario {scenario.scenario_id} did not execute every branch"
            )
        if (
            scenario.category == "recursive-dispatch"
            and physical_effects != scenario.recursion_depth + 1
        ):
            raise EvidenceError(
                f"recursive scenario {scenario.scenario_id} did not execute every depth"
            )

    measurements = result.get("measurements")
    if not isinstance(measurements, list) or not measurements:
        raise EvidenceError(f"scenario {scenario.scenario_id} returned no measurements")
    for measurement in measurements:
        if not isinstance(measurement, Mapping) or set(measurement) != _MEASUREMENT_KEYS:
            raise EvidenceError(f"scenario {scenario.scenario_id} returned a malformed measurement")
        name = measurement.get("name")
        unit = measurement.get("unit")
        samples = measurement.get("samples")
        exclusions = measurement.get("exclusions")
        if not isinstance(name, str) or _PUBLIC_NAME.fullmatch(name) is None:
            raise EvidenceError(
                f"scenario {scenario.scenario_id} returned an invalid measurement name"
            )
        if not isinstance(unit, str) or not unit or len(unit) > 50:
            raise EvidenceError(f"scenario {scenario.scenario_id} returned an invalid unit")
        if not isinstance(samples, list) or not samples or len(samples) > 100_000:
            raise EvidenceError(f"scenario {scenario.scenario_id} returned invalid samples")
        if any(
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            for value in samples
        ):
            raise EvidenceError(f"scenario {scenario.scenario_id} returned non-finite samples")
        if not isinstance(exclusions, list) or any(
            not isinstance(item, str) for item in exclusions
        ):
            raise EvidenceError(f"scenario {scenario.scenario_id} returned invalid exclusions")


def _percentile(ordered: Sequence[float], percentage: int) -> float:
    rank = max(1, math.ceil(len(ordered) * percentage / 100))
    return ordered[min(rank - 1, len(ordered) - 1)]


def _measurements(
    result: Mapping[str, object], scenario: Scenario, source_artifact: str
) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    raw_measurements = result["measurements"]
    assert isinstance(raw_measurements, list)
    for raw in raw_measurements:
        assert isinstance(raw, Mapping)
        samples = [float(value) for value in raw["samples"]]
        ordered = sorted(samples)
        summary = {
            "minimum": ordered[0],
            "p50": _percentile(ordered, 50),
            "p95": _percentile(ordered, 95),
            "p99": _percentile(ordered, 99),
            "maximum": ordered[-1],
            "mean": statistics.fmean(ordered),
        }
        measurement: dict[str, object] = {
            "name": f"{scenario.scenario_id}.{raw['name']}",
            "unit": raw["unit"],
            "sample_count": len(samples),
            "summary": summary,
            "source_artifact": source_artifact,
        }
        exclusions = raw["exclusions"]
        if exclusions:
            measurement["exclusions"] = exclusions
        output.append(measurement)
    return output


def _run_driver(
    *,
    astraldeep_root: Path,
    interpreter: Path,
    scenario: Scenario,
    timeout_seconds: float,
) -> tuple[int, bytes, bytes, str, str]:
    request = canonical_json_bytes(scenario.to_request()) + b"\n"
    started = _timestamp()
    try:
        process = subprocess.Popen(
            [str(interpreter), DRIVER_RELATIVE_PATH],
            cwd=astraldeep_root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_child_environment(),
        )
    except OSError as exc:
        raise EvidenceError("case-study driver could not be executed") from exc

    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    output_overflow = threading.Event()
    reader_errors: list[OSError] = []

    def drain(stream: Any, target: bytearray) -> None:
        try:
            while chunk := stream.read(64 * 1024):
                remaining = _MAX_DRIVER_OUTPUT_BYTES - len(target)
                if remaining > 0:
                    target.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    output_overflow.set()
        except OSError as exc:
            reader_errors.append(exc)
        finally:
            stream.close()

    assert process.stdout is not None and process.stderr is not None
    readers = (
        threading.Thread(target=drain, args=(process.stdout, stdout_buffer), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr_buffer), daemon=True),
    )
    for reader in readers:
        reader.start()
    assert process.stdin is not None
    try:
        process.stdin.write(request)
        process.stdin.close()
    except BrokenPipeError:
        process.stdin.close()

    try:
        process.wait(timeout=timeout_seconds)
        exit_code = process.returncode
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        exit_code = 124
    for reader in readers:
        reader.join(timeout=5)
    finished = _timestamp()
    if any(reader.is_alive() for reader in readers) or reader_errors:
        raise EvidenceError("case-study driver output could not be read completely")
    if output_overflow.is_set():
        raise EvidenceError("case-study driver output exceeded the 2 MiB per-stream bound")
    stdout_payload = bytes(stdout_buffer)
    stderr_payload = bytes(stderr_buffer)
    try:
        stdout_text = stdout_payload.decode("utf-8")
        stderr_text = stderr_payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError("case-study driver output is not UTF-8") from exc
    findings = scan_public_text(stdout_text, location=f"driver.{scenario.scenario_id}.stdout")
    findings.extend(scan_public_text(stderr_text, location=f"driver.{scenario.scenario_id}.stderr"))
    if findings:
        raise EvidenceError(f"driver output failed pre-retention sanitization: {findings[0]}")
    return exit_code, stdout_payload, stderr_payload, started, finished


def run_case_study(
    *,
    mode: str,
    evidence_class: str,
    astraldeep_root: Path,
    output_root: Path,
    timeout_seconds: float = 120.0,
) -> dict[str, object]:
    """Execute one single-mode matrix and retain bounded raw evidence."""

    if evidence_class not in {"release-baseline", "astral-integration"}:
        raise EvidenceError("evidence class must be release-baseline or astral-integration")
    if mode not in MODES:
        raise EvidenceError("case-study mode must be off, shadow, or enforce")
    if evidence_class == "release-baseline" and mode != "off":
        raise EvidenceError("release-baseline evidence can only run with mode off")
    if timeout_seconds <= 0 or timeout_seconds > 600:
        raise EvidenceError(
            "per-scenario timeout must be greater than zero and at most 600 seconds"
        )
    execution_identity = capture_execution_identity(astraldeep_root)
    astraldeep_root = astraldeep_root.resolve(strict=True)
    interpreter = _canonical_interpreter(astraldeep_root)
    try:
        output_root.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise EvidenceError("refusing to replace or append to an existing case-study run") from exc
    except OSError as exc:
        raise EvidenceError("could not create the case-study output root") from exc

    started_at = _timestamp()
    commands: list[dict[str, object]] = []
    artifacts: list[dict[str, object]] = []
    measurements: list[dict[str, object]] = []
    passed = True
    for scenario in build_scenarios(mode):
        command_id = scenario.scenario_id
        request_path = output_root / "raw" / "scenarios" / f"{command_id}.request.json"
        write_canonical_json_exclusive(request_path, scenario.to_request())
        artifacts.append(
            artifact_record(
                output_root,
                f"raw/scenarios/{command_id}.request.json",
                "scenario-request",
            )
        )
        exit_code, stdout_payload, stderr_payload, started, finished = _run_driver(
            astraldeep_root=astraldeep_root,
            interpreter=interpreter,
            scenario=scenario,
            timeout_seconds=timeout_seconds,
        )
        parsed_result: dict[str, Any] | None = None
        result_error = False
        if exit_code == 0:
            try:
                parsed_result = _strict_result(stdout_payload)
            except EvidenceError:
                result_error = True
            if parsed_result is not None:
                findings = scan_public_value(parsed_result, location=f"driver.{command_id}.stdout")
                if findings:
                    raise EvidenceError(
                        f"driver output failed pre-retention sanitization: {findings[0]}"
                    )
                try:
                    _validate_result(parsed_result, scenario, execution_identity)
                except EvidenceError:
                    result_error = True
        stdout_relative = f"raw/commands/{command_id}.stdout.json"
        stderr_relative = f"raw/commands/{command_id}.stderr.txt"
        stdout_path = output_root.joinpath(*stdout_relative.split("/"))
        stderr_path = output_root.joinpath(*stderr_relative.split("/"))
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with stdout_path.open("xb") as stream:
                stream.write(stdout_payload)
            with stderr_path.open("xb") as stream:
                stream.write(stderr_payload)
        except (FileExistsError, OSError) as exc:
            raise EvidenceError(f"could not retain unique driver output for {command_id}") from exc
        stdout_record = artifact_record(output_root, stdout_relative, "command-stdout")
        stderr_record = artifact_record(output_root, stderr_relative, "command-stderr")
        artifacts.extend((stdout_record, stderr_record))
        command = {
            "id": command_id,
            "argv": list(PUBLIC_DRIVER_ARGV),
            "exit_code": exit_code,
            "started_at": started,
            "finished_at": finished,
            "stdout_sha256": stdout_record["sha256"],
            "stderr_sha256": stderr_record["sha256"],
        }
        commands.append(command)
        if exit_code != 0 or result_error:
            passed = False
            continue
        assert parsed_result is not None
        measurements.extend(_measurements(parsed_result, scenario, stdout_relative))

    if capture_execution_identity(astraldeep_root) != execution_identity:
        raise EvidenceError("AstralDeep execution identity changed during the case-study run")
    finished_at = _timestamp()
    run: dict[str, object] = {
        "format": RUN_FORMAT,
        "evidence_class": evidence_class,
        "mode": mode,
        "status": "passed" if passed else "failed",
        "execution_identity": execution_identity,
        "commands": commands,
        "artifacts": sorted(artifacts, key=lambda item: str(item["relative_path"])),
        "measurements": measurements,
        "started_at": started_at,
        "finished_at": finished_at,
    }
    write_canonical_json_exclusive(output_root / "run.json", run)
    return run


def _is_ignored_output(repository_root: Path, output_root: Path) -> bool:
    try:
        relative = output_root.resolve().relative_to(repository_root.resolve())
    except ValueError:
        return False
    if tuple(part.casefold() for part in relative.parts[:2]) != (
        "results",
        "astraldeep-case-study",
    ):
        return False
    result = subprocess.run(
        ["git", "-C", str(repository_root), "check-ignore", "--quiet", "--", relative.as_posix()],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument(
        "--evidence-class",
        required=True,
        choices=("release-baseline", "astral-integration"),
    )
    parser.add_argument("--astraldeep-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    repository_root = Path(__file__).resolve().parents[2]
    if not _is_ignored_output(repository_root, arguments.output):
        print(
            "case-study runner refused: --output must be beneath the Git-ignored "
            "results/astraldeep-case-study root",
            file=sys.stderr,
        )
        return 2
    try:
        run = run_case_study(
            mode=arguments.mode,
            evidence_class=arguments.evidence_class,
            astraldeep_root=arguments.astraldeep_root,
            output_root=arguments.output,
            timeout_seconds=arguments.timeout_seconds,
        )
    except EvidenceError as exc:
        print(f"case-study runner refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"run": str(arguments.output / "run.json"), "status": run["status"]}))
    return 0 if run["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
