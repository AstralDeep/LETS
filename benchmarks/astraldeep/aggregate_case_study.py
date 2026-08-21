"""Validate and aggregate the complete three-mode AstralDeep case study.

The per-mode evidence bundles remain the authority for raw measurements.  This
module adds a digest-linked, cross-mode index and a descriptive summary without
claiming manuscript reproduction or inferential statistical support.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import stat
import statistics
import sys
from collections import Counter
from collections.abc import Mapping
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from benchmarks.astraldeep import capture_environment as capture
from benchmarks.astraldeep import check_version_disposition as versioning

AGGREGATE_FORMAT = "lets.astraldeep-case-study-aggregate/v1"
SUMMARY_FORMAT = "lets.astraldeep-case-study-summary/v1"
AGGREGATE_SCHEMA = Path(__file__).with_name("case-study-aggregate.schema.json")
EXPECTED_INPUTS = {
    "off_manifest": ("baseline/off/manifest.json", "mode-manifest"),
    "shadow_manifest": ("integration/shadow/manifest.json", "mode-manifest"),
    "enforce_manifest": ("integration/enforce/manifest.json", "mode-manifest"),
    "runtime_identities": ("runtime-identities.json", "runtime-identities"),
    "version_disposition": ("version-disposition.json", "version-disposition"),
    "paper_readiness": ("paper-readiness.json", "paper-readiness"),
}
EXPECTED_MODES = {
    "off": ("off_manifest", "release-baseline"),
    "shadow": ("shadow_manifest", "astral-integration"),
    "enforce": ("enforce_manifest", "astral-integration"),
}
_EXPECTED_ROOT_ENTRIES = {
    "baseline",
    "integration",
    "runtime-identities.json",
    "version-disposition.json",
    "paper-readiness.json",
}
_EXPECTED_BASELINE_ENTRIES = {"off"}
_EXPECTED_INTEGRATION_ENTRIES = {"shadow", "enforce"}
_READINESS_FIELDS = {
    "format",
    "status",
    "lets_release",
    "lets_runtime_commit",
    "lets_tooling_commit",
    "disposition_sha256",
    "evidence_manifest_sha256",
    "created_at",
}
_SHARED_FIELDS = (
    "repositories",
    "composition_sha256",
    "lets_release",
    "policy_digest",
    "machine_digest",
    "config_epoch",
    "scope_profile",
    "execution_identity",
    "environment",
    "sanitization",
)


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise capture.EvidenceError(f"could not inspect aggregate input {path.name}") from exc
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _require_regular_file(path: Path, label: str) -> None:
    if not path.exists() or not path.is_file() or _is_reparse_point(path):
        raise capture.EvidenceError(f"aggregate {label} must be a regular retained file")


def _read_canonical(path: Path, label: str) -> dict[str, Any]:
    _require_regular_file(path, label)
    document = capture.read_json_object(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise capture.EvidenceError(f"could not read aggregate {label}") from exc
    if raw != capture.canonical_json_bytes(document) + b"\n":
        raise capture.EvidenceError(f"aggregate {label} is not canonical JSON")
    return document


def _read_strict(path: Path, label: str) -> dict[str, Any]:
    _require_regular_file(path, label)
    return capture.read_json_object(path)


def _relative(root: Path, path: Path) -> str:
    try:
        relative = path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise capture.EvidenceError("aggregate input escaped its evidence root") from exc
    return PurePosixPath(*relative.parts).as_posix()


def _file_record(root: Path, path: Path, kind: str) -> dict[str, object]:
    _require_regular_file(path, kind)
    return {
        "kind": kind,
        "relative_path": _relative(root, path),
        "sha256": capture.sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _directory_entries(path: Path) -> set[str]:
    try:
        entries = list(path.iterdir())
    except OSError as exc:
        raise capture.EvidenceError(f"could not inventory aggregate directory {path.name}") from exc
    for entry in entries:
        if _is_reparse_point(entry):
            raise capture.EvidenceError(
                f"aggregate evidence contains a reparse point: {entry.name}"
            )
    return {entry.name for entry in entries}


def _validate_root_layout(root: Path) -> None:
    if not root.exists() or not root.is_dir() or _is_reparse_point(root):
        raise capture.EvidenceError("aggregate evidence root must be a regular directory")
    if (root / "manifest.json").exists() or (root / "summary.json").exists():
        raise capture.EvidenceError("refusing to replace retained aggregate evidence")
    if _directory_entries(root) != _EXPECTED_ROOT_ENTRIES:
        raise capture.EvidenceError(
            "aggregate evidence root contains missing or unexpected entries"
        )
    if _directory_entries(root / "baseline") != _EXPECTED_BASELINE_ENTRIES:
        raise capture.EvidenceError("aggregate baseline directory is incomplete or mixed")
    if _directory_entries(root / "integration") != _EXPECTED_INTEGRATION_ENTRIES:
        raise capture.EvidenceError("aggregate integration directory is incomplete or mixed")


def _inventory_files(root: Path) -> set[str]:
    resolved_root = root.resolve(strict=True)
    observed: set[str] = set()
    casefolded: set[str] = set()
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in [*directories, *files]:
            candidate = current_path / name
            if _is_reparse_point(candidate):
                raise capture.EvidenceError(
                    f"aggregate mode bundle contains a reparse point: {name}"
                )
            try:
                candidate.resolve(strict=True).relative_to(resolved_root)
            except (OSError, ValueError) as exc:
                raise capture.EvidenceError("aggregate mode bundle escaped its root") from exc
        for name in files:
            candidate = current_path / name
            relative = PurePosixPath(*candidate.relative_to(root).parts).as_posix()
            folded = relative.casefold()
            if folded in casefolded:
                raise capture.EvidenceError(
                    "aggregate mode bundle paths must be unique case-insensitively"
                )
            casefolded.add(folded)
            observed.add(relative)
    return observed


def _validate_exact_artifact_coverage(manifest_path: Path, document: Mapping[str, object]) -> None:
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list):
        raise capture.EvidenceError("aggregate mode manifest artifacts are malformed")
    expected = {"manifest.json"}
    for artifact in artifacts:
        if not isinstance(artifact, Mapping) or not isinstance(artifact.get("relative_path"), str):
            raise capture.EvidenceError("aggregate mode artifact record is malformed")
        expected.add(str(artifact["relative_path"]))
    observed = _inventory_files(manifest_path.parent)
    if observed != expected:
        raise capture.EvidenceError(
            "aggregate mode manifest does not cover its exact retained file set"
        )


def _single_artifact_path(manifest_path: Path, document: Mapping[str, object], kind: str) -> Path:
    artifacts = document.get("artifacts")
    matches = [
        artifact
        for artifact in artifacts
        if isinstance(artifacts, list)
        if isinstance(artifact, Mapping) and artifact.get("kind") == kind
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("relative_path"), str):
        raise capture.EvidenceError(f"aggregate mode bundle lacks one {kind} artifact")
    relative = PurePosixPath(str(matches[0]["relative_path"]))
    return manifest_path.parent.joinpath(*relative.parts)


def _validate_mode_documents(
    root: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, Path]]:
    documents: dict[str, dict[str, Any]] = {}
    paths: dict[str, Path] = {}
    for mode, (input_key, evidence_class) in EXPECTED_MODES.items():
        relative_path, _ = EXPECTED_INPUTS[input_key]
        path = root.joinpath(*PurePosixPath(relative_path).parts)
        document = _read_canonical(path, f"{mode} manifest")
        capture.validate_evidence_bundle(document, path.parent)
        _validate_exact_artifact_coverage(path, document)
        if document.get("mode") != mode or document.get("evidence_class") != evidence_class:
            raise capture.EvidenceError(f"aggregate {mode} evidence is mislabeled")
        documents[mode] = document
        paths[mode] = path
    baseline = documents["off"]
    for field in _SHARED_FIELDS:
        if any(document.get(field) != baseline.get(field) for document in documents.values()):
            raise capture.EvidenceError(f"aggregate mode bundles mix shared {field} identities")
    for kind in ("composition-manifest", "runtime-identities", "repository-revisions"):
        baseline_path = _single_artifact_path(paths["off"], baseline, kind)
        baseline_bytes = baseline_path.read_bytes()
        for mode in ("shadow", "enforce"):
            candidate_path = _single_artifact_path(paths[mode], documents[mode], kind)
            if candidate_path.read_bytes() != baseline_bytes:
                raise capture.EvidenceError(f"aggregate mode bundles mix retained {kind} bytes")
    return documents, paths


def _validate_runtime_identity_input(
    root: Path, documents: Mapping[str, Mapping[str, object]], paths: Mapping[str, Path]
) -> tuple[dict[str, Any], Path]:
    relative_path, _ = EXPECTED_INPUTS["runtime_identities"]
    path = root.joinpath(*PurePosixPath(relative_path).parts)
    runtime = _read_strict(path, "runtime identities")
    capture._validate_runtime_identities(runtime)
    for mode, document in documents.items():
        retained_path = _single_artifact_path(paths[mode], document, "runtime-identities")
        retained_runtime = _read_canonical(retained_path, f"{mode} retained runtime identities")
        if retained_runtime != runtime:
            raise capture.EvidenceError(
                f"aggregate top-level runtime identities differ from {mode} evidence"
            )
    return runtime, path


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise capture.EvidenceError(f"aggregate {label} is not an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise capture.EvidenceError(f"aggregate {label} is not an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise capture.EvidenceError(f"aggregate {label} must include a UTC offset")
    return parsed


def _validate_disposition_and_readiness(
    root: Path,
    documents: Mapping[str, Mapping[str, object]],
    paths: Mapping[str, Path],
) -> tuple[dict[str, Any], Path, dict[str, Any], Path]:
    disposition_relative, _ = EXPECTED_INPUTS["version_disposition"]
    disposition_path = root.joinpath(*PurePosixPath(disposition_relative).parts)
    disposition = _read_canonical(disposition_path, "version disposition")
    versioning.validate_disposition(disposition)
    _validate_historical_candidate(Path(__file__).resolve().parents[2], disposition)
    if disposition.get("disposition") != "unchanged-runtime":
        raise capture.EvidenceError(
            "aggregate evidence requires an unchanged-runtime version disposition"
        )
    repositories = documents["off"].get("repositories")
    candidate = disposition.get("candidate")
    if (
        not isinstance(repositories, Mapping)
        or not isinstance(candidate, Mapping)
        or candidate.get("commit") != repositories.get("lets")
    ):
        raise capture.EvidenceError(
            "aggregate version disposition is stale for the measured LETS tooling revision"
        )

    readiness_relative, _ = EXPECTED_INPUTS["paper_readiness"]
    readiness_path = root.joinpath(*PurePosixPath(readiness_relative).parts)
    readiness = _read_canonical(readiness_path, "paper readiness")
    if set(readiness) != _READINESS_FIELDS:
        raise capture.EvidenceError("aggregate paper readiness record is malformed")
    enforce_sha = capture.sha256_file(paths["enforce"])
    expected = {
        "format": versioning.READINESS_FORMAT,
        "status": "ready-for-local-paper-result-finalization",
        "lets_release": versioning.BASELINE_RELEASE,
        "lets_runtime_commit": versioning.BASELINE_COMMIT,
        "lets_tooling_commit": candidate["commit"],
        "disposition_sha256": capture.sha256_file(disposition_path),
        "evidence_manifest_sha256": enforce_sha,
    }
    if any(readiness.get(field) != value for field, value in expected.items()):
        raise capture.EvidenceError(
            "aggregate paper readiness record is stale or bound to the wrong evidence"
        )
    readiness_time = _parse_timestamp(readiness.get("created_at"), "readiness created_at")
    disposition_time = _parse_timestamp(disposition.get("generated_at"), "disposition generated_at")
    reproduction_times = [
        _parse_timestamp(document.get("reproduced_at"), f"{mode} reproduced_at")
        for mode, document in documents.items()
    ]
    if readiness_time < max(disposition_time, *reproduction_times):
        raise capture.EvidenceError("aggregate paper readiness predates its bound evidence")
    versioning._validate_evidence_runtime_pin(documents["enforce"], paths["enforce"])
    return disposition, disposition_path, readiness, readiness_path


def _validate_historical_candidate(repository: Path, disposition: Mapping[str, object]) -> None:
    """Recompute a retained candidate's exact tree partition without requiring HEAD."""

    candidate = disposition.get("candidate")
    comparison = disposition.get("comparison")
    if not isinstance(candidate, Mapping) or not isinstance(comparison, Mapping):
        raise capture.EvidenceError("aggregate version disposition sections are malformed")
    versioning._validate_repository_anchor(repository, {"version": versioning.BASELINE_RELEASE})
    candidate_commit = str(candidate.get("commit"))
    try:
        observed_tree = versioning._git(repository, "show", "-s", "--format=%T", candidate_commit)
    except capture.EvidenceError as exc:
        raise capture.EvidenceError(
            "aggregate version disposition candidate is unavailable"
        ) from exc
    if observed_tree != candidate.get("tree"):
        raise capture.EvidenceError("aggregate version disposition candidate tree is stale")
    if comparison.get("comparator_sha256") != capture.sha256_file(Path(versioning.__file__)):
        raise capture.EvidenceError("aggregate version disposition comparator is stale")
    observed = versioning._comparison_snapshot(repository, observed_tree)
    for field, value in observed.items():
        if comparison.get(field) != value:
            raise capture.EvidenceError(
                f"aggregate version disposition {field} no longer matches its candidate"
            )


def _measurement_summary(measurement: Mapping[str, object]) -> dict[str, object]:
    sample_count = measurement.get("sample_count")
    if type(sample_count) is not int or sample_count < 1:
        raise capture.EvidenceError("aggregate measurement sample count is invalid")
    record = copy.deepcopy(dict(measurement))
    record["statistical_limits"] = {
        "single_sample": sample_count == 1,
        "p95_tail_resolution_supported": sample_count >= 20,
        "p99_tail_resolution_supported": sample_count >= 100,
        "inferential_claim_supported": False,
        "interpretation": "empirical-descriptive-only",
    }
    return record


def _percentile(ordered: list[float], percentage: int) -> float:
    rank = max(1, math.ceil(len(ordered) * percentage / 100))
    return ordered[min(rank - 1, len(ordered) - 1)]


def _scenario_outcomes(
    manifest_path: Path, document: Mapping[str, object]
) -> list[dict[str, object]]:
    commands = document.get("commands")
    if not isinstance(commands, list):
        raise capture.EvidenceError("aggregate mode commands are malformed")
    outcomes: list[dict[str, object]] = []
    for command in commands:
        if not isinstance(command, Mapping) or not isinstance(command.get("id"), str):
            raise capture.EvidenceError("aggregate command is malformed")
        command_id = str(command["id"])
        result_path = manifest_path.parent / "raw" / "commands" / f"{command_id}.stdout.json"
        result = _read_canonical(result_path, f"{command_id} result")
        observations = result.get("observations")
        if not isinstance(observations, Mapping):
            raise capture.EvidenceError(f"aggregate {command_id} observations are malformed")
        scope_binding = observations.get("scope_binding")
        outcome = {
            "scenario_id": command_id,
            "category": result.get("category"),
            "status": result.get("status"),
            "astral_decision": observations.get("astral_decision"),
            "denial_code": observations.get("denial_code"),
            "lets_requests": observations.get("lets_requests"),
            "receipts_issued": observations.get("receipts_issued"),
            "receipts_claimed": observations.get("receipts_claimed"),
            "physical_effects": observations.get("physical_effects"),
            "denied_effects": observations.get("denied_effects"),
            "unreceipted_governed_effects": observations.get("unreceipted_governed_effects"),
            "budget_conserved": observations.get("budget_conserved"),
            "sequence_monotonic": observations.get("sequence_monotonic"),
            "lifecycle_converged": observations.get("lifecycle_converged"),
            "lifecycle_state": observations.get("lifecycle_state"),
            "scope": scope_binding.get("scope") if isinstance(scope_binding, Mapping) else None,
        }
        outcomes.append(outcome)
    return outcomes


def _cohort_metrics(manifest_path: Path, document: Mapping[str, object]) -> list[dict[str, object]]:
    commands = document.get("commands")
    if not isinstance(commands, list):
        raise capture.EvidenceError("aggregate cohort commands are malformed")
    groups: dict[tuple[str, str], dict[str, object]] = {}
    for command in commands:
        if not isinstance(command, Mapping) or not isinstance(command.get("id"), str):
            raise capture.EvidenceError("aggregate cohort command is malformed")
        command_id = str(command["id"])
        result_path = manifest_path.parent / "raw" / "commands" / f"{command_id}.stdout.json"
        result = _read_canonical(result_path, f"{command_id} cohort result")
        raw_measurements = result.get("measurements")
        if not isinstance(raw_measurements, list):
            raise capture.EvidenceError("aggregate cohort measurements are malformed")
        seen_names: set[str] = set()
        for raw in raw_measurements:
            if not isinstance(raw, Mapping):
                raise capture.EvidenceError("aggregate cohort measurement is malformed")
            name = raw.get("name")
            unit = raw.get("unit")
            samples = raw.get("samples")
            if (
                not isinstance(name, str)
                or not isinstance(unit, str)
                or not isinstance(samples, list)
                or not samples
                or name in seen_names
            ):
                raise capture.EvidenceError(
                    f"aggregate {command_id} cohort measurement is malformed or duplicate"
                )
            seen_names.add(name)
            numeric_samples = [float(value) for value in samples]
            if any(not math.isfinite(value) or value < 0 for value in numeric_samples):
                raise capture.EvidenceError(
                    f"aggregate {command_id} cohort measurement is negative or non-finite"
                )
            group = groups.setdefault((name, unit), {"samples": [], "scenario_ids": []})
            group["samples"].extend(numeric_samples)  # type: ignore[union-attr]
            group["scenario_ids"].append(command_id)  # type: ignore[union-attr]
    output: list[dict[str, object]] = []
    for (name, unit), group in sorted(groups.items()):
        samples = sorted(float(value) for value in group["samples"])  # type: ignore[union-attr]
        scenario_ids = list(group["scenario_ids"])  # type: ignore[arg-type]

        output.append(
            {
                "name": name,
                "unit": unit,
                "cohort": "all-mode-scenarios-reporting-this-metric",
                "scenario_ids": scenario_ids,
                "source_measurement_count": len(scenario_ids),
                "sample_count": len(samples),
                "summary": {
                    "minimum": samples[0],
                    "p50": _percentile(samples, 50),
                    "p95": _percentile(samples, 95),
                    "p99": _percentile(samples, 99),
                    "maximum": samples[-1],
                    "mean": statistics.fmean(samples),
                },
                "statistical_limits": {
                    "p95_tail_resolution_supported": len(samples) >= 20,
                    "p99_tail_resolution_supported": len(samples) >= 100,
                    "inferential_claim_supported": False,
                    "interpretation": "heterogeneous-scenario-descriptive-only",
                },
            }
        )
    return output


def _counter(values: list[object]) -> dict[str, int]:
    return {
        ("null" if key is None else str(key)): count
        for key, count in sorted(Counter(values).items(), key=lambda item: str(item[0]))
    }


def _mode_summary(
    mode: str, manifest_path: Path, document: Mapping[str, object]
) -> dict[str, object]:
    measurements_raw = document.get("measurements")
    artifacts = document.get("artifacts")
    commands = document.get("commands")
    sanitization = document.get("sanitization")
    if (
        not isinstance(measurements_raw, list)
        or not isinstance(artifacts, list)
        or not isinstance(commands, list)
        or not isinstance(sanitization, Mapping)
    ):
        raise capture.EvidenceError(f"aggregate {mode} mode sections are malformed")
    measurements = [
        _measurement_summary(item) for item in measurements_raw if isinstance(item, Mapping)
    ]
    if len(measurements) != len(measurements_raw):
        raise capture.EvidenceError(f"aggregate {mode} measurements are malformed")
    outcomes = _scenario_outcomes(manifest_path, document)
    cohort_metrics = _cohort_metrics(manifest_path, document)
    observations = {
        key: sum(int(outcome[key]) for outcome in outcomes)
        for key in (
            "lets_requests",
            "receipts_issued",
            "receipts_claimed",
            "physical_effects",
            "denied_effects",
            "unreceipted_governed_effects",
        )
    }
    observations["decision_counts"] = _counter([outcome["astral_decision"] for outcome in outcomes])
    observations["denial_reason_counts"] = _counter(
        [outcome["denial_code"] for outcome in outcomes if outcome["denial_code"] is not None]
    )
    observations["lifecycle_state_counts"] = _counter(
        [outcome["lifecycle_state"] for outcome in outcomes]
    )
    sample_distribution = Counter(int(item["sample_count"]) for item in measurements)
    lifecycle = [outcome for outcome in outcomes if outcome["category"] == "lifecycle"]
    post_revocation = [
        outcome for outcome in outcomes if outcome["category"] == "post-revocation-effect"
    ]
    return {
        "evidence_class": document.get("evidence_class"),
        "comparison_role": {
            "off": "flag-off-control",
            "shadow": "shadow-observation",
            "enforce": "enforced-treatment",
        }[mode],
        "scenario_count": len(outcomes),
        "command_count": len(commands),
        "retained_artifact_count": len(artifacts),
        "measurement_count": len(measurements),
        "sample_count": sum(int(item["sample_count"]) for item in measurements),
        "measurement_sample_count_distribution": [
            {"sample_count": sample_count, "measurement_count": count}
            for sample_count, count in sorted(sample_distribution.items())
        ],
        "observations": observations,
        "invariants": {
            "scenario_semantics_revalidated": True,
            "complete_ordered_matrix": len(outcomes) == 19,
            "all_scenarios_passed": all(outcome["status"] == "passed" for outcome in outcomes),
            "all_budgets_conserved": all(
                outcome["budget_conserved"] is True for outcome in outcomes
            ),
            "all_sequences_monotonic": all(
                outcome["sequence_monotonic"] is True for outcome in outcomes
            ),
            "zero_unreceipted_governed_effects": observations["unreceipted_governed_effects"] == 0,
            "lifecycle_events_converged": bool(lifecycle)
            and all(outcome["lifecycle_converged"] is True for outcome in lifecycle),
            "post_revocation_causally_revoked": len(post_revocation) == 1
            and post_revocation[0]["lifecycle_converged"] is True
            and post_revocation[0]["lifecycle_state"] == "revoked",
            "zero_sanitization_findings": sanitization.get("findings") == 0,
        },
        "scenario_outcomes": outcomes,
        "measurements": measurements,
        "cohort_metrics": cohort_metrics,
    }


def _input_records(
    root: Path,
    paths: Mapping[str, Path],
    runtime_path: Path,
    disposition_path: Path,
    readiness_path: Path,
) -> dict[str, dict[str, object]]:
    file_paths = {
        "off_manifest": paths["off"],
        "shadow_manifest": paths["shadow"],
        "enforce_manifest": paths["enforce"],
        "runtime_identities": runtime_path,
        "version_disposition": disposition_path,
        "paper_readiness": readiness_path,
    }
    return {
        key: _file_record(root, file_paths[key], EXPECTED_INPUTS[key][1]) for key in EXPECTED_INPUTS
    }


def _statistical_limits(mode_summaries: Mapping[str, Mapping[str, object]]) -> dict[str, object]:
    measurements = [
        measurement
        for mode in mode_summaries.values()
        for measurement in mode["measurements"]  # type: ignore[index]
    ]
    sample_counts = [int(measurement["sample_count"]) for measurement in measurements]
    return {
        "measurement_count": len(measurements),
        "minimum_sample_count": min(sample_counts),
        "maximum_sample_count": max(sample_counts),
        "single_sample_measurement_count": sum(count == 1 for count in sample_counts),
        "p95_tail_resolution_measurement_count": sum(count >= 20 for count in sample_counts),
        "p99_tail_resolution_measurement_count": sum(count >= 100 for count in sample_counts),
        "all_percentiles_descriptive_only": True,
        "inferential_statistics_present": False,
        "publication_inference_supported": False,
        "limitation": (
            "Recorded percentiles are empirical descriptions of retained samples; "
            "the aggregate supplies no confidence interval, repeated-run inference, "
            "or population-level performance claim."
        ),
    }


def _measurement_coverage(
    mode_summaries: Mapping[str, Mapping[str, object]],
) -> dict[str, bool]:
    names = {
        str(measurement["name"]).rsplit(".", 1)[-1]
        for mode in mode_summaries.values()
        for measurement in mode["measurements"]  # type: ignore[index]
    }
    return {
        "authorization_latency_included": "authorization_latency" in names,
        "end_to_end_latency_included": "end_to_end_latency" in names,
        "throughput_included": "throughput" in names,
        "storage_growth_included": "storage_growth" in names,
        "refusal_latency_included": "refusal_latency" in names,
        "lifecycle_convergence_included": "lifecycle_convergence" in names,
        "recovery_time_included": "recovery_time" in names,
    }


def _runtime_identity_quality(runtime: Mapping[str, object]) -> dict[str, object]:
    def placeholder(field: str) -> bool:
        value = str(runtime.get(field, "")).removeprefix("sha256:")
        return len(value) == 64 and len(set(value)) == 1

    policy_placeholder = placeholder("policy_digest")
    machine_placeholder = placeholder("machine_digest")
    return {
        "policy_digest_placeholder_pattern": policy_placeholder,
        "machine_digest_placeholder_pattern": machine_placeholder,
        "authenticated_runtime_identity_supported": not (policy_placeholder or machine_placeholder),
        "limitation": (
            "Repeated single-nibble digests are treated as placeholder-pattern identities; "
            "they bind the retained run consistently but do not establish authenticated "
            "deployment trust identity."
        ),
    }


def _revalidate_final_inputs(
    root: Path,
    documents: Mapping[str, Mapping[str, object]],
    paths: Mapping[str, Path],
    inputs: Mapping[str, Mapping[str, object]],
) -> None:
    """Close the summary-construction window by rehashing every retained leaf."""

    _validate_root_layout(root)
    for mode, original in documents.items():
        current = _read_canonical(paths[mode], f"final {mode} manifest")
        if current != original:
            raise capture.EvidenceError(
                f"aggregate {mode} manifest changed during summary construction"
            )
        capture.validate_evidence_bundle(current, paths[mode].parent)
        _validate_exact_artifact_coverage(paths[mode], current)
    for key, record in inputs.items():
        relative_path = record.get("relative_path")
        kind = record.get("kind")
        if not isinstance(relative_path, str) or not isinstance(kind, str):
            raise capture.EvidenceError("aggregate final input record is malformed")
        path = root.joinpath(*PurePosixPath(relative_path).parts)
        if _file_record(root, path, kind) != dict(record):
            raise capture.EvidenceError(f"aggregate {key} changed during summary construction")


def build_aggregate_documents(root: Path) -> tuple[dict[str, object], dict[str, object]]:
    """Return validated manifest and summary documents without writing them."""

    if _is_reparse_point(root):
        raise capture.EvidenceError("aggregate evidence root must not be a reparse point")
    root = root.resolve(strict=True)
    _validate_root_layout(root)
    documents, paths = _validate_mode_documents(root)
    runtime, runtime_path = _validate_runtime_identity_input(root, documents, paths)
    disposition, disposition_path, readiness, readiness_path = _validate_disposition_and_readiness(
        root, documents, paths
    )
    inputs = _input_records(root, paths, runtime_path, disposition_path, readiness_path)
    mode_summaries = {
        mode: _mode_summary(mode, paths[mode], documents[mode]) for mode in EXPECTED_MODES
    }
    statistical_limits = _statistical_limits(mode_summaries)
    generated_at = _timestamp()
    shared = documents["off"]
    study_id = "sha256:" + capture.canonical_json_sha256(
        {
            "composition_sha256": shared["composition_sha256"],
            "repositories": shared["repositories"],
            "runtime_identities": runtime,
            "inputs": inputs,
        }
    )
    totals = {
        "mode_count": len(mode_summaries),
        "scenario_count": sum(int(mode["scenario_count"]) for mode in mode_summaries.values()),
        "command_count": sum(int(mode["command_count"]) for mode in mode_summaries.values()),
        "retained_artifact_count": sum(
            int(mode["retained_artifact_count"]) for mode in mode_summaries.values()
        ),
        "measurement_count": sum(
            int(mode["measurement_count"]) for mode in mode_summaries.values()
        ),
        "cohort_metric_count": sum(
            len(mode["cohort_metrics"])  # type: ignore[arg-type]
            for mode in mode_summaries.values()
        ),
        "sample_count": sum(int(mode["sample_count"]) for mode in mode_summaries.values()),
        "sanitization_findings": sum(
            int(doc["sanitization"]["findings"])  # type: ignore[index]
            for doc in documents.values()
        ),
    }
    summary: dict[str, object] = {
        "format": SUMMARY_FORMAT,
        "status": "validated",
        "study_id": study_id,
        "generated_at": generated_at,
        "aggregator_sha256": capture.sha256_file(Path(__file__)),
        "aggregate_schema_sha256": capture.sha256_file(AGGREGATE_SCHEMA),
        "composition_sha256": shared["composition_sha256"],
        "lets_release": shared["lets_release"],
        "repositories": copy.deepcopy(shared["repositories"]),
        "runtime_identities": copy.deepcopy(runtime),
        "inputs": copy.deepcopy(inputs),
        "totals": totals,
        "cross_mode_invariants": {
            "complete_mode_set": set(mode_summaries) == set(EXPECTED_MODES),
            "shared_identity_exact": True,
            "canonical_evidence_records": True,
            "exact_artifact_coverage": True,
            "all_commands_passed": all(
                mode["invariants"]["all_scenarios_passed"]  # type: ignore[index]
                for mode in mode_summaries.values()
            ),
            "off_no_lets_requests": mode_summaries["off"]["observations"][  # type: ignore[index]
                "lets_requests"
            ]
            == 0,
            "shadow_no_receipt_claims": mode_summaries["shadow"]["observations"][  # type: ignore[index]
                "receipts_claimed"
            ]
            == 0,
            "enforce_zero_unreceipted_governed_effects": mode_summaries["enforce"][  # type: ignore[index]
                "observations"
            ]["unreceipted_governed_effects"]
            == 0,
            "unchanged_runtime_disposition": disposition["disposition"] == "unchanged-runtime",
            "readiness_bound_to_enforce_manifest": readiness["evidence_manifest_sha256"]
            == inputs["enforce_manifest"]["sha256"],
        },
        "modes": mode_summaries,
        "measurement_coverage": _measurement_coverage(mode_summaries),
        "runtime_identity_quality": _runtime_identity_quality(runtime),
        "statistical_limits": statistical_limits,
        "evidence_scope": {
            "historical_v1_0_10_release_results_included": False,
            "manuscript_checks_included": False,
            "reproduction_attestation_included": False,
            "distinct_historical_release_reference_included": False,
            "readiness_interpretation": "successor-version-gate-only",
        },
    }
    summary_payload = capture.canonical_json_bytes(summary) + b"\n"
    manifest: dict[str, object] = {
        "format": AGGREGATE_FORMAT,
        "status": "validated",
        "study_id": study_id,
        "generated_at": generated_at,
        "aggregator_sha256": summary["aggregator_sha256"],
        "aggregate_schema_sha256": summary["aggregate_schema_sha256"],
        "composition_sha256": summary["composition_sha256"],
        "lets_release": summary["lets_release"],
        "repositories": copy.deepcopy(summary["repositories"]),
        "inputs": copy.deepcopy(inputs),
        "summary": {
            "kind": "aggregate-summary",
            "relative_path": "summary.json",
            "sha256": hashlib.sha256(summary_payload).hexdigest(),
            "bytes": len(summary_payload),
        },
        "mode_counts": {
            mode: {
                "scenario_count": mode_summary["scenario_count"],
                "measurement_count": mode_summary["measurement_count"],
                "cohort_metric_count": len(mode_summary["cohort_metrics"]),  # type: ignore[arg-type]
                "sample_count": mode_summary["sample_count"],
            }
            for mode, mode_summary in mode_summaries.items()
        },
        "version_disposition": disposition["disposition"],
        "paper_readiness_status": readiness["status"],
        "statistical_limits": copy.deepcopy(statistical_limits),
        "evidence_scope": copy.deepcopy(summary["evidence_scope"]),
    }
    for document in (summary, manifest):
        capture._schema_validate(document, AGGREGATE_SCHEMA)
        findings = capture.scan_public_value(document, location="aggregate")
        if findings:
            raise capture.EvidenceError(
                f"aggregate public output failed secret/PHI sanitization: {findings[0]}"
            )
    _revalidate_final_inputs(root, documents, paths, inputs)
    return manifest, summary


def _write_pair_exclusive(
    manifest_path: Path,
    manifest: Mapping[str, object],
    summary_path: Path,
    summary: Mapping[str, object],
) -> None:
    payloads = {
        summary_path: capture.canonical_json_bytes(summary) + b"\n",
        manifest_path: capture.canonical_json_bytes(manifest) + b"\n",
    }
    descriptors: dict[Path, int] = {}
    created: set[Path] = set()
    try:
        for path in payloads:
            descriptors[path] = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.add(path)
        for path, payload in payloads.items():
            descriptor = descriptors.pop(path)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
    except FileExistsError as exc:
        for descriptor in descriptors.values():
            os.close(descriptor)
        for path in created:
            with suppress(OSError):
                path.unlink()
        raise capture.EvidenceError("refusing to replace retained aggregate evidence") from exc
    except OSError as exc:
        for descriptor in descriptors.values():
            os.close(descriptor)
        for path in created:
            with suppress(OSError):
                path.unlink()
        raise capture.EvidenceError("could not create aggregate evidence atomically") from exc


def aggregate_case_study(root: Path) -> tuple[dict[str, object], dict[str, object]]:
    """Validate the root and exclusively create its aggregate manifest and summary."""

    manifest, summary = build_aggregate_documents(root)
    root = root.resolve(strict=True)
    _write_pair_exclusive(root / "manifest.json", manifest, root / "summary.json", summary)
    return manifest, summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    repository = Path(__file__).resolve().parents[2]
    expected_root = (repository / "results" / "astraldeep-case-study").resolve()
    if arguments.evidence_root.resolve() != expected_root:
        print(
            "case-study aggregation refused: --evidence-root must be the dedicated "
            "results/astraldeep-case-study directory",
            file=sys.stderr,
        )
        return 2
    if not all(
        capture._is_ignored_case_study_path(repository, expected_root / name)
        for name in ("manifest.json", "summary.json")
    ):
        print(
            "case-study aggregation refused: aggregate outputs must be Git-ignored",
            file=sys.stderr,
        )
        return 2
    try:
        manifest, _ = aggregate_case_study(expected_root)
    except (capture.EvidenceError, OSError) as exc:
        print(f"case-study aggregation refused: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "manifest": str(expected_root / "manifest.json"),
                "status": manifest["status"],
                "summary": str(expected_root / "summary.json"),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
