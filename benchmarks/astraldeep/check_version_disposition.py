"""Compare LETS to signed v1.0.10 and gate case-study result finalization.

``compare`` writes an evidence-backed disposition from a clean candidate tree.
``gate`` creates a readiness record only for unchanged runtime semantics and a
validated integration bundle.  A runtime/wire change instead creates a
separate defect/release handoff and exits non-zero; the v1.0.10 ref is never
modified by this tool.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from benchmarks.astraldeep.capture_environment import (
    BASELINE_RELEASE,
    EvidenceError,
    canonical_json_sha256,
    read_json_object,
    sha256_file,
    validate_evidence_bundle,
    write_canonical_json_exclusive,
)

DISPOSITION_FORMAT = "lets.astraldeep-version-disposition/v1"
HANDOFF_FORMAT = "lets.astraldeep-successor-release-handoff/v1"
READINESS_FORMAT = "lets.astraldeep-paper-result-readiness/v1"
BASELINE_TAG_OBJECT = "5ed575066a0c61a51dc55278fa7412f60772fac7"
BASELINE_COMMIT = "82dbe4f5ddf410cc86778784bb612440725ec66d"
BASELINE_TREE = "16f6034c26e0d538eaf94867ed8dce166dc9f447"
BASELINE_SIGNER_FINGERPRINT = "SHA256:5KasB4SV3tUn6UHrxeFR3ZmQ9faDA4Uq6blCa06ShRw"
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_RUNTIME_ROOTS = ("src/lets/", "protocol/")
_RUNTIME_FILES = frozenset({"pyproject.toml", "uv.lock", "Dockerfile", "compose.yaml"})
_DEPLOY_SUFFIXES = frozenset({".py", ".yaml", ".yml", ".toml", ".json"})


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _git(repository: Path, *arguments: str) -> str:
    environment = os.environ.copy()
    environment.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"})
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.DEVNULL,
            timeout=10,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvidenceError("local Git comparison could not execute") from exc
    if result.returncode != 0:
        raise EvidenceError("local Git comparison failed closed")
    return result.stdout.strip()


def _release_anchor(document: Mapping[str, object]) -> Mapping[str, object]:
    anchor = document.get("letsReleaseAnchor", document)
    if not isinstance(anchor, Mapping):
        raise EvidenceError("release anchor is malformed")
    signature = anchor.get("signature")
    if not isinstance(signature, Mapping):
        raise EvidenceError("release anchor has no verified signature record")
    expected = {
        "version": BASELINE_RELEASE,
        "tagObject": BASELINE_TAG_OBJECT,
        "peeledCommit": BASELINE_COMMIT,
        "tree": BASELINE_TREE,
    }
    if any(anchor.get(field) != value for field, value in expected.items()):
        raise EvidenceError("release anchor does not identify immutable signed v1.0.10")
    if (
        signature.get("verified") is not True
        or signature.get("scheme") != "ssh-ed25519"
        or signature.get("commandExitCode") != 0
        or signature.get("keyFingerprint") != BASELINE_SIGNER_FINGERPRINT
    ):
        raise EvidenceError("release anchor signature was not trust-verified")
    return anchor


def _validate_repository_anchor(repository: Path, anchor: Mapping[str, object]) -> None:
    if _git(repository, "rev-parse", "--is-inside-work-tree") != "true":
        raise EvidenceError("LETS comparison root is not a Git worktree")
    if _git(repository, "rev-parse", "refs/tags/v1.0.10") != BASELINE_TAG_OBJECT:
        raise EvidenceError("local v1.0.10 tag object does not match the trusted anchor")
    if _git(repository, "cat-file", "-t", BASELINE_TAG_OBJECT) != "tag":
        raise EvidenceError("local v1.0.10 is not an annotated tag")
    if _git(repository, "rev-parse", "refs/tags/v1.0.10^{}") != BASELINE_COMMIT:
        raise EvidenceError("local v1.0.10 peeled commit does not match the trusted anchor")
    if _git(repository, "show", "-s", "--format=%T", BASELINE_COMMIT) != BASELINE_TREE:
        raise EvidenceError("local v1.0.10 tree does not match the trusted anchor")
    tag_payload = _git(repository, "cat-file", "-p", BASELINE_TAG_OBJECT)
    if "-----BEGIN SSH SIGNATURE-----" not in tag_payload:
        raise EvidenceError("local v1.0.10 tag has no embedded SSH signature")
    if anchor.get("version") != BASELINE_RELEASE:
        raise EvidenceError("release anchor version changed during validation")


def _canonical_path(value: str) -> str:
    pure = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise EvidenceError("Git tree comparison returned a non-canonical path")
    return pure.as_posix()


def _is_runtime_or_wire_path(path: str) -> bool:
    if path in _RUNTIME_FILES or path.startswith(_RUNTIME_ROOTS):
        return True
    if path.startswith("deploy/evidence/"):
        return False
    return path.startswith("deploy/") and PurePosixPath(path).suffix.lower() in _DEPLOY_SUFFIXES


def _candidate_tree_entry(repository: Path, tree: str, relative_path: str) -> str:
    try:
        value = _git(repository, "rev-parse", f"{tree}:{relative_path}")
    except EvidenceError:
        return "0" * 40
    if _SHA1.fullmatch(value) is None:
        raise EvidenceError("candidate runtime tree entry is invalid")
    return value


def _comparison_snapshot(repository: Path, candidate_tree: str) -> dict[str, object]:
    changed_output = _git(
        repository,
        "diff",
        "--name-only",
        "-z",
        "--no-renames",
        BASELINE_TREE,
        candidate_tree,
        "--",
    )
    changed_paths = sorted({_canonical_path(line) for line in changed_output.split("\0") if line})
    runtime_paths = [path for path in changed_paths if _is_runtime_or_wire_path(path)]
    runtime_set = set(runtime_paths)
    return {
        "baseline_runtime_tree": _git(repository, "rev-parse", f"{BASELINE_TREE}:src/lets"),
        "candidate_runtime_tree": _candidate_tree_entry(repository, candidate_tree, "src/lets"),
        "baseline_protocol_tree": _git(repository, "rev-parse", f"{BASELINE_TREE}:protocol"),
        "candidate_protocol_tree": _candidate_tree_entry(repository, candidate_tree, "protocol"),
        "changed_paths": changed_paths,
        "runtime_or_wire_paths": runtime_paths,
        "integration_only_paths": [path for path in changed_paths if path not in runtime_set],
    }


def compare_version_disposition(
    *, repository: Path, release_anchor_path: Path
) -> dict[str, object]:
    """Return an immutable-tag/tree comparison for one clean candidate commit."""

    try:
        repository = repository.resolve(strict=True)
    except OSError as exc:
        raise EvidenceError("LETS comparison repository does not exist") from exc
    anchor_document = read_json_object(release_anchor_path)
    anchor = _release_anchor(anchor_document)
    _validate_repository_anchor(repository, anchor)
    if _git(
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise EvidenceError("LETS candidate tree is dirty; version disposition would be stale")
    candidate_commit = _git(repository, "rev-parse", "--verify", "HEAD^{commit}")
    candidate_tree = _git(repository, "show", "-s", "--format=%T", candidate_commit)
    if _SHA1.fullmatch(candidate_commit) is None or _SHA1.fullmatch(candidate_tree) is None:
        raise EvidenceError("LETS candidate did not resolve to an exact commit and tree")
    snapshot = _comparison_snapshot(repository, candidate_tree)
    runtime_paths = snapshot["runtime_or_wire_paths"]
    assert isinstance(runtime_paths, list)
    disposition = "successor-required" if runtime_paths else "unchanged-runtime"
    source_digest = sha256_file(Path(__file__))
    return {
        "format": DISPOSITION_FORMAT,
        "baseline": {
            "release": BASELINE_RELEASE,
            "tag_object": BASELINE_TAG_OBJECT,
            "commit": BASELINE_COMMIT,
            "tree": BASELINE_TREE,
            "signature_verified": True,
        },
        "candidate": {
            "commit": candidate_commit,
            "tree": candidate_tree,
            "clean": True,
        },
        "comparison": {
            "method": "immutable-git-tree-diff/v1",
            "comparator_sha256": source_digest,
            "release_anchor_sha256": sha256_file(release_anchor_path),
            **snapshot,
        },
        "disposition": disposition,
        "reason": (
            "candidate runtime or wire inputs differ from signed v1.0.10"
            if runtime_paths
            else "candidate changes do not alter signed v1.0.10 runtime or wire inputs"
        ),
        "generated_at": _timestamp(),
    }


def validate_disposition(document: Mapping[str, object]) -> None:
    required = {
        "format",
        "baseline",
        "candidate",
        "comparison",
        "disposition",
        "reason",
        "generated_at",
    }
    if set(document) != required or document.get("format") != DISPOSITION_FORMAT:
        raise EvidenceError("version disposition is malformed")
    baseline = document.get("baseline")
    candidate = document.get("candidate")
    comparison = document.get("comparison")
    if (
        not isinstance(baseline, Mapping)
        or not isinstance(candidate, Mapping)
        or not isinstance(comparison, Mapping)
    ):
        raise EvidenceError("version disposition sections are malformed")
    expected_baseline = {
        "release": BASELINE_RELEASE,
        "tag_object": BASELINE_TAG_OBJECT,
        "commit": BASELINE_COMMIT,
        "tree": BASELINE_TREE,
        "signature_verified": True,
    }
    if dict(baseline) != expected_baseline:
        raise EvidenceError("version disposition baseline is not immutable signed v1.0.10")
    if set(candidate) != {"commit", "tree", "clean"} or candidate.get("clean") is not True:
        raise EvidenceError("version disposition candidate is not an exact clean tree")
    if any(_SHA1.fullmatch(str(candidate.get(field))) is None for field in ("commit", "tree")):
        raise EvidenceError("version disposition candidate identity is invalid")
    required_comparison = {
        "method",
        "comparator_sha256",
        "release_anchor_sha256",
        "baseline_runtime_tree",
        "candidate_runtime_tree",
        "baseline_protocol_tree",
        "candidate_protocol_tree",
        "changed_paths",
        "runtime_or_wire_paths",
        "integration_only_paths",
    }
    if (
        set(comparison) != required_comparison
        or comparison.get("method") != "immutable-git-tree-diff/v1"
    ):
        raise EvidenceError("version disposition comparison is malformed")
    for field in (
        "comparator_sha256",
        "release_anchor_sha256",
    ):
        value = comparison.get(field)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise EvidenceError(f"version disposition {field} is invalid")
    for field in (
        "baseline_runtime_tree",
        "candidate_runtime_tree",
        "baseline_protocol_tree",
        "candidate_protocol_tree",
    ):
        if _SHA1.fullmatch(str(comparison.get(field))) is None:
            raise EvidenceError(f"version disposition {field} is invalid")
    path_lists: dict[str, list[str]] = {}
    for field in ("changed_paths", "runtime_or_wire_paths", "integration_only_paths"):
        values = comparison.get(field)
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise EvidenceError(f"version disposition {field} is invalid")
        canonical = [_canonical_path(value) for value in values]
        if canonical != sorted(set(canonical)):
            raise EvidenceError(f"version disposition {field} is not canonical and unique")
        path_lists[field] = canonical
    runtime = set(path_lists["runtime_or_wire_paths"])
    integration = set(path_lists["integration_only_paths"])
    if runtime & integration or runtime | integration != set(path_lists["changed_paths"]):
        raise EvidenceError("version disposition path partitions are inconsistent")
    if any(not _is_runtime_or_wire_path(path) for path in runtime) or any(
        _is_runtime_or_wire_path(path) for path in integration
    ):
        raise EvidenceError("version disposition path classification is inconsistent")
    expected = "successor-required" if runtime else "unchanged-runtime"
    if document.get("disposition") != expected:
        raise EvidenceError("version disposition does not follow its runtime diff")
    if not runtime and (
        comparison["baseline_runtime_tree"] != comparison["candidate_runtime_tree"]
        or comparison["baseline_protocol_tree"] != comparison["candidate_protocol_tree"]
    ):
        raise EvidenceError("unchanged-runtime disposition has changed runtime tree identities")
    if not isinstance(document.get("reason"), str) or not document["reason"]:
        raise EvidenceError("version disposition has no rationale")
    expected_reason = (
        "candidate runtime or wire inputs differ from signed v1.0.10"
        if runtime
        else "candidate changes do not alter signed v1.0.10 runtime or wire inputs"
    )
    if document["reason"] != expected_reason:
        raise EvidenceError("version disposition rationale is inconsistent")
    generated_at = document.get("generated_at")
    if not isinstance(generated_at, str):
        raise EvidenceError("version disposition generated_at is not an RFC 3339 timestamp")
    try:
        parsed_generated_at = datetime.fromisoformat(
            generated_at[:-1] + "+00:00" if generated_at.endswith("Z") else generated_at
        )
    except ValueError as exc:
        raise EvidenceError(
            "version disposition generated_at is not an RFC 3339 timestamp"
        ) from exc
    if parsed_generated_at.tzinfo is None or parsed_generated_at.utcoffset() is None:
        raise EvidenceError("version disposition generated_at must include a UTC offset")


def _validate_current_candidate(repository: Path, document: Mapping[str, object]) -> None:
    candidate = document["candidate"]
    comparison = document["comparison"]
    assert isinstance(candidate, Mapping)
    assert isinstance(comparison, Mapping)
    _validate_repository_anchor(repository, {"version": BASELINE_RELEASE})
    if _git(
        repository, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"
    ):
        raise EvidenceError("LETS candidate changed after version disposition capture")
    current_commit = _git(repository, "rev-parse", "--verify", "HEAD^{commit}")
    if current_commit != candidate["commit"]:
        raise EvidenceError("LETS HEAD changed after version disposition capture")
    current_tree = _git(repository, "show", "-s", "--format=%T", current_commit)
    if current_tree != candidate["tree"]:
        raise EvidenceError("LETS candidate tree changed after version disposition capture")
    if sha256_file(Path(__file__)) != document["comparison"]["comparator_sha256"]:  # type: ignore[index]
        raise EvidenceError("version comparator changed after disposition capture")
    snapshot = _comparison_snapshot(repository, current_tree)
    for field, observed in snapshot.items():
        if comparison.get(field) != observed:
            raise EvidenceError(f"version disposition {field} no longer matches the candidate tree")


def _paths_are_distinct(*paths: Path) -> None:
    normalized = [os.path.normcase(str(path.resolve())) for path in paths]
    if len(set(normalized)) != len(normalized):
        raise EvidenceError("readiness, handoff, disposition, and evidence paths must be distinct")


def _reject_manuscript_output(repository: Path, *paths: Path) -> None:
    manuscript_root = (repository / "paper").resolve()
    for path in paths:
        try:
            path.resolve().relative_to(manuscript_root)
        except ValueError:
            continue
        raise EvidenceError("version gate outputs must remain separate from manuscript state")


def _validate_evidence_runtime_pin(
    evidence: Mapping[str, object], evidence_manifest_path: Path
) -> None:
    artifacts = evidence.get("artifacts")
    if not isinstance(artifacts, list):
        raise EvidenceError("validated evidence has no retained composition manifest")
    matches = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, Mapping) and artifact.get("kind") == "composition-manifest"
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("relative_path"), str):
        raise EvidenceError("validated evidence has no unique composition manifest")
    relative_path = PurePosixPath(str(matches[0]["relative_path"]))
    composition = read_json_object(evidence_manifest_path.parent.joinpath(*relative_path.parts))
    components = composition.get("components")
    lets_component = components.get("lets") if isinstance(components, Mapping) else None
    if (
        not isinstance(lets_component, Mapping)
        or lets_component.get("ref") != BASELINE_RELEASE
        or lets_component.get("commit") != BASELINE_COMMIT
    ):
        raise EvidenceError(
            "unchanged-runtime finalization requires the exact signed v1.0.10 runtime pin"
        )


def gate_paper_result_finalization(
    *,
    repository: Path,
    disposition_path: Path,
    evidence_manifest_path: Path | None,
    readiness_output: Path,
    handoff_output: Path,
) -> bool:
    """Return true only after creating a validated finalization readiness record."""

    disposition = read_json_object(disposition_path)
    validate_disposition(disposition)
    repository = repository.resolve(strict=True)
    _validate_current_candidate(repository, disposition)
    paths = [disposition_path, readiness_output, handoff_output]
    if evidence_manifest_path is not None:
        paths.append(evidence_manifest_path)
    _paths_are_distinct(*paths)
    _reject_manuscript_output(repository, readiness_output, handoff_output)
    if readiness_output.exists():
        raise EvidenceError("refusing to trust or replace a pre-existing readiness marker")

    if disposition["disposition"] == "successor-required":
        comparison = disposition["comparison"]
        candidate = disposition["candidate"]
        assert isinstance(comparison, Mapping) and isinstance(candidate, Mapping)
        handoff_basis = {
            "baseline_release": BASELINE_RELEASE,
            "candidate_commit": candidate["commit"],
            "runtime_or_wire_paths": comparison["runtime_or_wire_paths"],
        }
        handoff = {
            "format": HANDOFF_FORMAT,
            "handoff_id": canonical_json_sha256(handoff_basis)[:24],
            "status": "successor-release-required",
            "baseline_release": BASELINE_RELEASE,
            "candidate_commit": candidate["commit"],
            "runtime_or_wire_paths": comparison["runtime_or_wire_paths"],
            "disposition_sha256": sha256_file(disposition_path),
            "required_actions": [
                "review and fix the separately identified LETS runtime or wire change",
                "create and verify a successor LETS release without altering v1.0.10",
                "update the exact Astral composition pin and version disposition",
                "rerun every affected case-study experiment from clean exact revisions",
                "finalize paper results only from the replacement validated evidence bundle",
            ],
            "created_at": _timestamp(),
        }
        write_canonical_json_exclusive(handoff_output, handoff)
        return False

    if handoff_output.exists():
        raise EvidenceError("an unresolved successor-release handoff still exists")
    if evidence_manifest_path is None:
        raise EvidenceError("unchanged-runtime finalization requires a validated evidence bundle")
    evidence = read_json_object(evidence_manifest_path)
    validate_evidence_bundle(evidence, evidence_manifest_path.parent)
    if evidence.get("evidence_class") != "astral-integration":
        raise EvidenceError("paper result finalization refuses release-baseline evidence")
    if evidence.get("lets_release") != BASELINE_RELEASE:
        raise EvidenceError("unchanged-runtime disposition does not match the evidence release")
    _validate_evidence_runtime_pin(evidence, evidence_manifest_path)
    repositories = evidence.get("repositories")
    candidate = disposition["candidate"]
    assert isinstance(candidate, Mapping)
    if not isinstance(repositories, Mapping) or repositories.get("lets") != candidate.get("commit"):
        raise EvidenceError(
            "evidence was not captured from the disposition's LETS tooling revision"
        )
    readiness = {
        "format": READINESS_FORMAT,
        "status": "ready-for-local-paper-result-finalization",
        "lets_release": BASELINE_RELEASE,
        "lets_runtime_commit": BASELINE_COMMIT,
        "lets_tooling_commit": candidate["commit"],
        "disposition_sha256": sha256_file(disposition_path),
        "evidence_manifest_sha256": sha256_file(evidence_manifest_path),
        "created_at": _timestamp(),
    }
    write_canonical_json_exclusive(readiness_output, readiness)
    return True


def _is_ignored(repository: Path, path: Path) -> bool:
    try:
        relative = path.resolve().relative_to(repository.resolve())
    except ValueError:
        return False
    if tuple(part.casefold() for part in relative.parts[:2]) != (
        "results",
        "astraldeep-case-study",
    ):
        return False
    result = subprocess.run(
        ["git", "-C", str(repository), "check-ignore", "--quiet", "--", relative.as_posix()],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    compare = subparsers.add_parser("compare", help="compare a clean candidate to signed v1.0.10")
    compare.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    compare.add_argument("--release-anchor", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)
    gate = subparsers.add_parser("gate", help="gate local paper-result finalization")
    gate.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    gate.add_argument("--disposition", type=Path, required=True)
    gate.add_argument("--evidence-manifest", type=Path)
    gate.add_argument("--readiness-output", type=Path, required=True)
    gate.add_argument("--handoff-output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    repository = arguments.repository.resolve()
    try:
        if arguments.command == "compare":
            if not _is_ignored(repository, arguments.output):
                raise EvidenceError("version disposition output must be Git-ignored")
            disposition = compare_version_disposition(
                repository=repository,
                release_anchor_path=arguments.release_anchor,
            )
            validate_disposition(disposition)
            write_canonical_json_exclusive(arguments.output, disposition)
            print(f"version disposition created: {disposition['disposition']}")
            return 0
        if not _is_ignored(repository, arguments.readiness_output) or not _is_ignored(
            repository, arguments.handoff_output
        ):
            raise EvidenceError("gate outputs must be Git-ignored")
        ready = gate_paper_result_finalization(
            repository=repository,
            disposition_path=arguments.disposition,
            evidence_manifest_path=arguments.evidence_manifest,
            readiness_output=arguments.readiness_output,
            handoff_output=arguments.handoff_output,
        )
        if ready:
            print("validated integration evidence is ready for local paper result finalization")
            return 0
        print(
            "paper result finalization blocked; successor-release handoff created", file=sys.stderr
        )
        return 3
    except (EvidenceError, OSError) as exc:
        print(f"version disposition gate refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
