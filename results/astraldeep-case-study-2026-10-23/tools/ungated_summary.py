"""Builds the cross-mode case-study summary with the tracked aggregate code from
benchmarks/astraldeep/aggregate_case_study.py, skipping only its v1.0.11
version-disposition and readiness binding, and writes it as canonical JSON.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from benchmarks.astraldeep import aggregate_case_study as aggregate
from benchmarks.astraldeep import capture_environment as capture

UNGATED_FORMAT = "lets.astraldeep-case-study-ungated-summary/v1"


def build(root: Path, disposition: dict[str, object]) -> dict[str, object]:
    documents, paths = aggregate._validate_mode_documents(root)
    runtime, runtime_path = aggregate._validate_runtime_identity_input(root, documents, paths)
    modes = {
        mode: aggregate._mode_summary(mode, paths[mode], documents[mode])
        for mode in aggregate.EXPECTED_MODES
    }
    inputs = {
        "off_manifest": aggregate._file_record(root, paths["off"], "mode-manifest"),
        "shadow_manifest": aggregate._file_record(root, paths["shadow"], "mode-manifest"),
        "enforce_manifest": aggregate._file_record(root, paths["enforce"], "mode-manifest"),
        "runtime_identities": aggregate._file_record(root, runtime_path, "runtime-identities"),
    }
    shared = documents["off"]
    summary: dict[str, object] = {
        "format": UNGATED_FORMAT,
        "status": "validated-without-release-gate",
        "generated_at": aggregate._timestamp(),
        "aggregator_sha256": capture.sha256_file(Path(aggregate.__file__)),
        "composition_sha256": shared["composition_sha256"],
        "lets_release": shared["lets_release"],
        "repositories": shared["repositories"],
        "execution_identity": shared["execution_identity"],
        "runtime_identities": runtime,
        "inputs": inputs,
        "release_gate": {
            "gated_aggregate_created": False,
            "version_disposition": disposition.get("disposition"),
            "baseline_release": "v1.0.11",
            "reason": (
                "The tracked aggregate requires an unchanged-runtime disposition against "
                "signed v1.0.11; the measured runtime is the composition's v1.1.0 pin, "
                "whose runtime differs from v1.0.11, so the gate refuses by design."
            ),
        },
        "cross_mode_invariants": {
            "all_commands_passed": all(
                mode["invariants"]["all_scenarios_passed"] for mode in modes.values()
            ),
            "off_no_lets_requests": modes["off"]["observations"]["lets_requests"] == 0,
            "shadow_no_receipt_claims": modes["shadow"]["observations"]["receipts_claimed"] == 0,
            "enforce_zero_unreceipted_governed_effects": modes["enforce"]["observations"][
                "unreceipted_governed_effects"
            ]
            == 0,
        },
        "modes": modes,
        "measurement_coverage": aggregate._measurement_coverage(modes),
        "runtime_identity_quality": aggregate._runtime_identity_quality(runtime),
        "statistical_limits": aggregate._statistical_limits(modes),
    }
    findings = capture.scan_public_value(summary, location="ungated_summary")
    if findings:
        raise capture.EvidenceError(f"summary failed sanitization: {findings[0]}")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    root = arguments.evidence_root.resolve(strict=True)
    disposition = capture.read_json_object(root / "version-disposition.json")
    try:
        summary = build(root, disposition)
    except capture.EvidenceError as exc:
        print(f"ungated summary refused: {exc}", file=sys.stderr)
        return 2
    capture.write_canonical_json_exclusive(arguments.output, summary)
    print(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
