"""Fail-closed preparation and finalization for a clean evidence campaign.

The remote runners intentionally own credential handling.  This module has no
credential option and never copies a credential file into an evidence bundle.
It prepares a new ignored (or out-of-tree) staging directory, then binds the
finished artifacts, exact source commit, and paper inputs with deterministic
manifests.
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

CAMPAIGN_PREFLIGHT_NAME = "CAMPAIGN-PREFLIGHT.json"
SOURCE_MANIFEST_NAME = "SOURCE-MANIFEST.json"
PAPER_INPUT_MANIFEST_NAME = "PAPER-INPUT-MANIFEST.json"
MANIFEST_NAME = "MANIFEST.json"

CAMPAIGN_SCHEMA = "lets.nsdi-clean-evidence-campaign/v1"
SOURCE_MANIFEST_SCHEMA = "lets.nsdi-source-manifest/v1"
EVIDENCE_MANIFEST_SCHEMA = "lets.evidence-manifest/v1"

_FULL_COMMIT = re.compile(r"[0-9a-fA-F]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CAMPAIGN_BINDING = re.compile(r"results/nsdi-strengthening-\d{4}-\d{2}-\d{2}/MANIFEST\.json")
_CAMPAIGN_BINDING_PREFIX = "% Evidence campaign manifest: "
_SOURCE_PATTERNS = (
    "Dockerfile",
    "benchmarks/nsdi_strengthening/*",
    "compose.yaml",
    "deploy/run_acceptance.py",
    "formal/sensitivity_frontier.py",
    "formal/vector_model_checker.py",
    "pyproject.toml",
    "tests/benchmarks/test_evidence_campaign.py",
    "tests/benchmarks/test_nsdi_*.py",
    "tests/benchmarks/test_remote_*.py",
    "tests/benchmarks/test_rollback_matrix.py",
    "tests/e2e/**",
    "tests/formal/test_sensitivity_frontier.py",
    "tests/formal/test_vector_model_checker.py",
    "uv.lock",
)
_REQUIRED_SOURCE_FILES = frozenset(
    {
        "benchmarks/nsdi_strengthening/evidence_campaign.py",
        "Dockerfile",
        "compose.yaml",
        "deploy/run_acceptance.py",
        "pyproject.toml",
        "tests/e2e/test_compose_cluster.py",
        "tests/e2e/test_production_profile.py",
        "uv.lock",
    }
)
_PAPER_EXCLUDED_DIRECTORIES = frozenset({"__pycache__", ".pytest_cache", ".ruff_cache", "build"})
_PAPER_EXCLUDED_ENDINGS = (
    ".aux",
    ".bbl",
    ".bcf",
    ".blg",
    ".fdb_latexmk",
    ".fls",
    ".log",
    ".nav",
    ".out",
    ".pyc",
    ".run.xml",
    ".snm",
    ".synctex.gz",
    ".toc",
    ".vrb",
)
_ALLOWED_EVIDENCE_ENDINGS = (
    ".csv",
    ".gz",
    ".json",
    ".log",
    ".md",
    ".pdf",
    ".png",
    ".svg",
    ".xml",
    ".zip",
)
_SENSITIVE_NAME = re.compile(
    r"(^|[._-])(credential|credentials|password|passwd|private[._-]?key|"
    r"secret|secrets|servers?|token|tokens)([._-]|$)",
    re.IGNORECASE,
)
_SENSITIVE_ENDINGS = (".env", ".key", ".p12", ".pem", ".pfx", ".token")
_LOCAL_PROVENANCE_PATHS = frozenset(
    {
        ("environment", "git"),
        ("git",),
        ("source",),
        ("source", "controller_git"),
    }
)
_PRIVACY_FLAGS = frozenset(
    {
        "addresses_retained",
        "credentials_retained",
        "home_paths_retained",
        "raw_addresses_retained",
        "raw_usernames_retained",
        "secrets_retained",
        "secrets_retained_in_result",
        "usernames_retained",
    }
)
_REQUIRED_ARTIFACTS = frozenset(
    {
        "distributed/PARTITION-RESULTS.md",
        "distributed/partition-events.csv",
        "distributed/partition-results.json",
        "distributed/partition-skew-equal-shares.svg",
        "docker/docker-acceptance.json",
        "docker/docker-compose.log",
        "docker/DOCKER-ACCEPTANCE.md",
        "docker/scenario-evidence.json",
        "formal/VECTOR-MODEL-RESULTS.md",
        "formal/sensitivity-frontier.json",
        "formal/sensitivity-frontier.md",
        "formal/vector-model.json",
        "implementation/implementation-inventory.json",
        "implementation/implementation-inventory.md",
        "lineage/LINEAGE-RESULTS.md",
        "lineage/lineage-scaling.csv",
        "lineage/lineage-scaling.json",
        "performance/performance-matrix-samples.csv",
        "performance/performance-matrix.json",
        "performance/performance-matrix.md",
        "raw/final-full-suite.xml",
        "remote/cluster-inventory.json",
        "remote/matched-host/matched-host-path-samples.csv",
        "remote/matched-host/matched-host-path.json.gz",
        "remote/matched-host/matched-host-path.md",
        "remote/matched-host/remote-matched-host-manifest.json",
        "remote/three-host-linux-per-site-timeline.svg",
        "remote/three-host-linux-phase-end.csv",
        "remote/three-host-linux-phase-end.md",
        "remote/three-host-linux-report.md",
        "remote/three-host-linux-result.json",
        "remote/three-host-linux-timeline.csv",
        "remote/three-host-linux-timeline.svg",
        "rollback/rollback-matrix.junit.xml",
        "rollback/rollback-matrix.stderr.log",
        "rollback/rollback-matrix.stdout.log",
        "rollback/rollback-matrix.summary.json",
        "vector/VECTOR-RESULTS.md",
        "vector/vector-transitions.csv",
        "vector/vector-workload.json",
    }
)
_REQUIRED_PAPER_INPUTS = frozenset(
    {
        "evaluation-strengthened.tex",
        "evidence.tex",
        "figures/control-gap.pdf",
        "figures/fonts/GUST-FONT-LICENSE.txt",
        "figures/fonts/qhvb.afm",
        "figures/fonts/qhvb.pfb",
        "figures/fonts/qhvr.afm",
        "figures/fonts/qhvr.pfb",
        "figures/generate_partition_progress_figure.py",
        "figures/three-endpoint-progress-comparison.pdf",
        "figures/trusted-effect-path.pdf",
        "latexmkrc",
        "main.tex",
        "manuscript.tex",
        "paper-anon.tex",
        "paper-arxiv.tex",
        "paper-nsdi27.tex",
        "references.bib",
        "usenix-2020-09.sty",
    }
)


class CampaignError(RuntimeError):
    """Raised when a clean evidence campaign invariant is not satisfied."""


@dataclass(frozen=True)
class GitIdentity:
    commit: str
    tree: str
    branch: str | None


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(repository: Path, *arguments: str, allow_failure: bool = False) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CampaignError("unable to execute Git for campaign verification") from error
    if completed.returncode:
        if allow_failure:
            return None
        command = " ".join(arguments[:2])
        raise CampaignError(f"Git verification failed while running: git {command}")
    return completed.stdout.strip()


def _committed_file(repository: Path, commit: str, relative: str) -> bytes:
    """Read a file from the committed tree, never from an uncommitted worktree."""

    try:
        completed = subprocess.run(
            ["git", "show", f"{commit}:{relative}"],
            cwd=repository,
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CampaignError("unable to read a committed campaign source") from error
    if completed.returncode:
        raise CampaignError(f"required committed campaign source is absent: {relative}")
    return completed.stdout


def _repository_root(repository: Path) -> Path:
    requested = repository.resolve(strict=True)
    if not requested.is_dir():
        raise CampaignError(f"repository is not a directory: {requested}")
    discovered = _git(requested, "rev-parse", "--show-toplevel")
    assert discovered is not None
    return Path(discovered).resolve(strict=True)


def _expected_commit(value: str) -> str:
    if _FULL_COMMIT.fullmatch(value) is None:
        raise CampaignError("expected commit must be a complete 40-character Git object ID")
    return value.lower()


def _clean_git_identity(repository: Path, expected_commit: str) -> GitIdentity:
    expected = _expected_commit(expected_commit)
    resolved = _git(repository, "rev-parse", "--verify", f"{expected}^{{commit}}")
    head = _git(repository, "rev-parse", "--verify", "HEAD^{commit}")
    if resolved is None or resolved.lower() != expected:
        raise CampaignError("expected commit does not resolve to that exact commit object")
    if head is None or head.lower() != expected:
        raise CampaignError("repository HEAD does not match the expected commit")
    status = _git(
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    if status:
        # Do not echo paths: an accidentally untracked credential filename must
        # not be copied into campaign diagnostics.
        raise CampaignError("repository index and worktree must be completely clean")
    tree = _git(repository, "rev-parse", "--verify", "HEAD^{tree}")
    branch = _git(repository, "branch", "--show-current")
    assert tree is not None
    return GitIdentity(commit=expected, tree=tree.lower(), branch=branch or None)


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _validate_staging_location(repository: Path, staging_root: Path) -> Path:
    staging = staging_root.resolve(strict=False)
    if staging == repository or staging in repository.parents:
        raise CampaignError("staging root cannot be the repository or one of its parents")
    if _is_within(staging, repository):
        relative_marker = (staging / CAMPAIGN_PREFLIGHT_NAME).relative_to(repository)
        if relative_marker.parts[0] == ".git":
            raise CampaignError("staging root cannot be inside the Git metadata directory")
        ignored = _git(
            repository,
            "check-ignore",
            "--quiet",
            "--no-index",
            "--",
            relative_marker.as_posix(),
            allow_failure=True,
        )
        if ignored is None:
            raise CampaignError(
                "in-repository staging root must be ignored so evidence writes "
                "cannot dirty the measured checkout"
            )
    return staging


def _write_new(path: Path, content: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(content)
    except FileExistsError as error:
        raise CampaignError(f"refusing to overwrite existing campaign file: {path.name}") from error


def preflight_campaign(*, repository: Path, staging_root: Path, expected_commit: str) -> Path:
    """Create a new clean-campaign staging root and immutable preflight record."""

    root = _repository_root(repository)
    identity = _clean_git_identity(root, expected_commit)
    staging = _validate_staging_location(root, staging_root)
    if staging.exists():
        raise CampaignError("staging root already exists; refusing to alter a prior campaign")
    staging.parent.mkdir(parents=True, exist_ok=True)
    try:
        staging.mkdir()
    except FileExistsError as error:
        raise CampaignError("staging root appeared during preflight; refusing to use it") from error
    record = {
        "git": {
            "commit": identity.commit,
            "dirty": False,
            "tree": identity.tree,
        },
        "purpose": "bind a clean exact checkout before evidence is written",
        "schema": CAMPAIGN_SCHEMA,
    }
    marker = staging / CAMPAIGN_PREFLIGHT_NAME
    _write_new(marker, _json_bytes(record))
    _clean_git_identity(root, expected_commit)
    return marker


def compress_matched_host_result(
    *, repository: Path, staging_root: Path, expected_commit: str
) -> Path:
    """Losslessly replace the large retained matched-host JSON with deterministic gzip."""

    root = _repository_root(repository)
    identity = _clean_git_identity(root, expected_commit)
    staging = staging_root.resolve(strict=True)
    _validate_staging_location(root, staging)
    _read_preflight(staging, identity)
    raw = staging / "remote/matched-host/matched-host-path.json"
    target = raw.with_suffix(".json.gz")
    if target.exists():
        raise CampaignError("refusing to overwrite an existing matched-host JSON archive")
    content = _read_regular_file(raw)
    try:
        parsed = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CampaignError("matched-host result is not valid UTF-8 JSON") from error
    if not isinstance(parsed, dict):
        raise CampaignError("matched-host result JSON is not an object")
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, compresslevel=9, mtime=0) as stream:
        stream.write(content)
    compressed = buffer.getvalue()
    if gzip.decompress(compressed) != content:
        raise CampaignError("deterministic matched-host compression did not round trip")
    _write_new(target, compressed)
    raw.unlink()
    _clean_git_identity(root, expected_commit)
    return target


def _read_regular_file(path: Path) -> bytes:
    if path.is_symlink():
        raise CampaignError(f"symbolic links are not permitted in campaign inputs: {path.name}")
    if not path.is_file():
        raise CampaignError(f"campaign input is not a regular file: {path.name}")
    before = path.stat()
    content = path.read_bytes()
    after = path.stat()
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity or len(content) != after.st_size:
        raise CampaignError(f"campaign input changed while it was being read: {path.name}")
    return content


def _file_entry(relative: str, content: bytes) -> dict[str, object]:
    return {"bytes": len(content), "path": relative, "sha256": _sha256(content)}


def _tracked_source_paths(repository: Path) -> list[str]:
    output = _git(repository, "ls-tree", "-r", "--name-only", "HEAD")
    assert output is not None
    selected = sorted(
        path
        for path in output.splitlines()
        if any(fnmatch.fnmatchcase(path, pattern) for pattern in _SOURCE_PATTERNS)
    )
    missing = sorted(_REQUIRED_SOURCE_FILES.difference(selected))
    if missing:
        raise CampaignError("required clean-campaign source files are absent from HEAD")
    return selected


def _source_manifest(repository: Path, identity: GitIdentity) -> dict[str, object]:
    entries = []
    for relative in _tracked_source_paths(repository):
        content = _read_regular_file(repository.joinpath(*relative.split("/")))
        entries.append(_file_entry(relative, content))
    return {
        "controller_only_dependencies": [
            {
                "declaration": "campaign RUNBOOK.md (not part of the project uv.lock)",
                "name": "paramiko",
                "scope": "remote orchestration only",
                "version": "4.0.0",
            }
        ],
        "files": entries,
        "git": {
            "branch": identity.branch,
            "commit": identity.commit,
            "dirty": False,
            "tracked_diff": "",
            "tree": identity.tree,
        },
        "purpose": "bind evidence sources to an exact clean Git commit",
        "schema": SOURCE_MANIFEST_SCHEMA,
    }


def _paper_manifest(repository: Path, paper_input_root: Path) -> dict[str, object]:
    paper = paper_input_root.resolve(strict=True)
    if not paper.is_dir():
        raise CampaignError(f"paper input root is not a directory: {paper}")
    if not _is_within(paper, repository) or paper == repository:
        raise CampaignError("paper input root must be a directory within the repository")
    entries = []
    for path in sorted(paper.rglob("*")):
        relative_path = path.relative_to(paper)
        if path.is_symlink():
            raise CampaignError(
                f"symbolic links are not permitted in paper inputs: {relative_path.as_posix()}"
            )
        if not path.is_file():
            continue
        if _PAPER_EXCLUDED_DIRECTORIES.intersection(relative_path.parts):
            continue
        if path.name.lower().endswith(_PAPER_EXCLUDED_ENDINGS):
            continue
        _reject_sensitive_path(relative_path)
        content = _read_regular_file(path)
        entries.append(_file_entry(relative_path.as_posix(), content))
    if not entries:
        raise CampaignError("paper input root contains no stable input files")
    retained_paths = {str(entry["path"]) for entry in entries}
    missing = sorted(_REQUIRED_PAPER_INPUTS.difference(retained_paths))
    if missing:
        raise CampaignError("paper input dependency closure is incomplete: " + ", ".join(missing))
    return {
        "files": entries,
        "purpose": "content snapshot of the paper inputs bound to this evidence campaign",
        "schema": EVIDENCE_MANIFEST_SCHEMA,
        "source_directory": paper.relative_to(repository).as_posix(),
    }


def _validated_campaign_binding(value: str) -> str:
    if _CAMPAIGN_BINDING.fullmatch(value) is None:
        raise CampaignError(
            "campaign binding must be a repository-relative "
            "results/nsdi-strengthening-YYYY-MM-DD/MANIFEST.json path"
        )
    return value


def _validate_paper_campaign_binding(paper_input_root: Path, campaign_binding: str) -> None:
    """Require one unambiguous paper-to-campaign seal and no author TODOs."""

    expected = _validated_campaign_binding(campaign_binding)
    evidence_path = paper_input_root.resolve(strict=True) / "evidence.tex"
    try:
        evidence = _read_regular_file(evidence_path).decode("utf-8")
    except UnicodeDecodeError as error:
        raise CampaignError("paper evidence.tex is not valid UTF-8") from error
    marker = _CAMPAIGN_BINDING_PREFIX + expected
    marker_lines = [line.strip() for line in evidence.splitlines() if line.strip() == marker]
    if len(marker_lines) != 1:
        raise CampaignError(
            "paper evidence.tex must contain exactly one campaign binding marker: " + marker
        )
    referenced = set(_CAMPAIGN_BINDING.findall(evidence))
    if referenced != {expected}:
        raise CampaignError("paper evidence.tex retains a different evidence-bundle reference")

    for tex_path in sorted(paper_input_root.resolve(strict=True).rglob("*.tex")):
        relative = tex_path.relative_to(paper_input_root.resolve(strict=True))
        if _PAPER_EXCLUDED_DIRECTORIES.intersection(relative.parts):
            continue
        try:
            content = _read_regular_file(tex_path).decode("utf-8")
        except UnicodeDecodeError as error:
            raise CampaignError("paper TeX input is not valid UTF-8") from error
        if re.search(r"TODO\s*\(\s*author\s*\)", content, flags=re.IGNORECASE):
            raise CampaignError("paper inputs retain a TODO(author) submission decision")


def _validate_evidence_path(relative: Path) -> None:
    rendered = relative.as_posix()
    _reject_sensitive_path(relative)
    if not rendered.lower().endswith(_ALLOWED_EVIDENCE_ENDINGS):
        raise CampaignError(f"unsupported file type in staged evidence root: {rendered}")


def _reject_sensitive_path(relative: Path) -> None:
    rendered = relative.as_posix().lower()
    lowered_parts = tuple(part.lower() for part in relative.parts)
    if any(_SENSITIVE_NAME.search(part) for part in lowered_parts) or rendered.endswith(
        _SENSITIVE_ENDINGS
    ):
        raise CampaignError("credential-like files are forbidden in campaign inputs")


def _walk_mappings(
    value: object, path: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], dict[str, object]]]:
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            yield from _walk_mappings(child, (*path, str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_mappings(child, (*path, str(index)))


def _validate_json_provenance(relative: str, content: bytes, expected_commit: str) -> None:
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CampaignError(f"staged JSON is not valid UTF-8 JSON: {relative}") from error
    for path, mapping in _walk_mappings(document):
        if "dirty" in mapping and mapping["dirty"] is not False:
            raise CampaignError(f"dirty source provenance retained in staged JSON: {relative}")
        if path in _LOCAL_PROVENANCE_PATHS:
            if path == ("source",) and isinstance(mapping.get("controller_git"), dict):
                continue
            observed = mapping.get("commit", mapping.get("git_commit", mapping.get("revision")))
            if observed != expected_commit:
                raise CampaignError(
                    f"staged JSON local provenance is absent or does not match the "
                    f"campaign commit: {relative}"
                )
        for flag in _PRIVACY_FLAGS.intersection(mapping):
            if mapping[flag] is not False:
                raise CampaignError(f"unsafe privacy flag retained in staged JSON: {relative}")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CampaignError(message)


def _json_artifact(artifacts: dict[str, bytes], relative: str) -> dict[str, object]:
    try:
        value = json.loads(artifacts[relative])
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CampaignError(f"required campaign JSON is invalid: {relative}") from error
    if not isinstance(value, dict):
        raise CampaignError(f"required campaign JSON is not an object: {relative}")
    return value


def _require_schema(document: dict[str, object], schema: str, relative: str) -> None:
    _require(
        document.get("schema") == schema, f"unexpected schema in required artifact: {relative}"
    )


def _assertions_passed(value: object) -> bool:
    return isinstance(value, dict) and value.get("passed") is True and value.get("failures") == []


def _is_nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _validate_three_host_scenario(scenario: dict[str, object]) -> tuple[str, str]:
    expected_specs: dict[tuple[str, str], dict[str, object]] = {
        ("equal", "equal"): {
            "name": "equal-placement-equal-workload",
            "shares": {"s1": 10, "s2": 10, "s3": 10},
            "phase_counts": {
                "normal": {"s1": 2, "s2": 2, "s3": 2},
                "partition": {"s1": 3, "s2": 3, "s3": 3},
                "recovery": {"s1": 1, "s2": 1, "s3": 1},
            },
            "transfer": ("s2", "s1", 1),
        },
        ("equal", "70-percent-s1"): {
            "name": "equal-placement-skew70-workload",
            "shares": {"s1": 10, "s2": 10, "s3": 10},
            "phase_counts": {
                "normal": {"s1": 4, "s2": 1, "s3": 1},
                "partition": {"s1": 7, "s2": 1, "s3": 1},
                "recovery": {"s1": 3, "s2": 1, "s3": 1},
            },
            "transfer": ("s2", "s1", 3),
        },
        ("70-percent-s1", "equal"): {
            "name": "skew70-placement-equal-workload",
            "shares": {"s1": 21, "s2": 4, "s3": 5},
            "phase_counts": {
                "normal": {"s1": 2, "s2": 2, "s3": 2},
                "partition": {"s1": 3, "s2": 3, "s3": 3},
                "recovery": {"s1": 1, "s2": 1, "s3": 1},
            },
            "transfer": ("s1", "s2", 2),
        },
        ("70-percent-s1", "70-percent-s1"): {
            "name": "skew70-placement-skew70-workload",
            "shares": {"s1": 21, "s2": 4, "s3": 5},
            "phase_counts": {
                "normal": {"s1": 4, "s2": 1, "s3": 1},
                "partition": {"s1": 7, "s2": 1, "s3": 1},
                "recovery": {"s1": 3, "s2": 1, "s3": 1},
            },
            "transfer": ("s2", "s1", 1),
        },
    }
    key = (str(scenario.get("placement")), str(scenario.get("workload")))
    _require(key in expected_specs, "remote matrix contains an unknown factorial cell")
    spec = expected_specs[key]
    _require(scenario.get("name") == spec["name"], "remote scenario name does not match its cell")
    _require(scenario.get("shares") == spec["shares"], "remote scenario shares are not canonical")
    _require(
        scenario.get("phase_counts") == spec["phase_counts"],
        "remote scenario schedule is not canonical",
    )

    snapshots = scenario.get("final_snapshots")
    _require(
        isinstance(snapshots, list) and len(snapshots) == 3, "remote final snapshots are absent"
    )
    assert isinstance(snapshots, list)
    by_alias: dict[str, dict[str, object]] = {}
    accounting_fields = (
        "initial_share",
        "transferred_in",
        "transferred_out",
        "free_pool",
        "lease_residual",
        "consumed",
    )
    for snapshot in snapshots:
        _require(isinstance(snapshot, dict), "remote final snapshot is malformed")
        assert isinstance(snapshot, dict)
        alias = snapshot.get("alias")
        _require(alias in {"s1", "s2", "s3"}, "remote final snapshot alias is invalid")
        assert isinstance(alias, str)
        _require(alias not in by_alias, "remote final snapshots contain a duplicate site")
        _require(
            all(_is_nonnegative_integer(snapshot.get(field)) for field in accounting_fields),
            "remote final snapshot accounting is malformed",
        )
        _require(snapshot.get("healthy") is True, "remote final local invariant is unhealthy")
        _require(
            int(snapshot["initial_share"]) + int(snapshot["transferred_in"])
            == int(snapshot["transferred_out"])
            + int(snapshot["free_pool"])
            + int(snapshot["lease_residual"])
            + int(snapshot["consumed"]),
            "remote final local conservation identity failed",
        )
        by_alias[alias] = snapshot
    _require(set(by_alias) == {"s1", "s2", "s3"}, "remote final snapshots omit a site")

    aggregate = scenario.get("aggregate_final")
    _require(isinstance(aggregate, dict), "remote aggregate accounting is absent")
    assert isinstance(aggregate, dict)
    for field in accounting_fields:
        _require(
            _is_nonnegative_integer(aggregate.get(field))
            and aggregate[field] == sum(int(snapshot[field]) for snapshot in snapshots),
            "remote aggregate accounting does not equal the site snapshots",
        )
    _require(
        aggregate["initial_share"] + aggregate["transferred_in"]
        == aggregate["transferred_out"]
        + aggregate["free_pool"]
        + aggregate["lease_residual"]
        + aggregate["consumed"]
        and aggregate.get("conservation_holds") is True
        and aggregate.get("all_local_invariants_healthy") is True,
        "remote aggregate conservation failed",
    )
    _require(
        aggregate["initial_share"] == sum(int(value) for value in spec["shares"].values()),
        "remote aggregate does not match the configured authority shares",
    )
    _require(
        aggregate["consumed"] == sum(int(snapshot.get("authorized", -1)) for snapshot in snapshots),
        "remote debit total does not match authorized operations",
    )

    recovery = scenario.get("recovery")
    transfer = recovery.get("transfer") if isinstance(recovery, dict) else None
    _require(isinstance(transfer, dict), "remote recovery transfer is absent")
    assert isinstance(transfer, dict)
    source_alias, target_alias, amount = spec["transfer"]
    _require(
        transfer.get("source") == source_alias
        and transfer.get("target") == target_alias
        and transfer.get("amount") == amount
        and transfer.get("sequence") == 1
        and transfer.get("delivered") is True
        and transfer.get("finalized") is True
        and transfer.get("transport") == "controller_paramiko_two_ssh_session_relay",
        "remote recovery transfer does not match the fixed scenario",
    )
    _require(
        aggregate["transferred_in"] == amount
        and aggregate["transferred_out"] == amount
        and by_alias[str(source_alias)]["transferred_out"] == amount
        and by_alias[str(target_alias)]["transferred_in"] == amount,
        "remote transfer is not reflected in final accounting",
    )

    phase_counts = spec["phase_counts"]
    assert isinstance(phase_counts, dict)
    expected_events = [
        (phase, alias)
        for phase in ("normal", "partition", "recovery")
        for alias in ("s1", "s2", "s3")
        for _ in range(int(phase_counts[phase][alias]))
    ]
    timeline = scenario.get("timeline")
    _require(isinstance(timeline, list), "remote scenario timeline is absent")
    assert isinstance(timeline, list)
    observed_events = [
        (event.get("phase"), event.get("site")) for event in timeline if isinstance(event, dict)
    ]
    _require(
        len(observed_events) == len(timeline)
        and sorted(observed_events) == sorted(expected_events)
        and [event.get("step") for event in timeline if isinstance(event, dict)]
        == list(range(len(timeline))),
        "remote timeline does not match the fixed schedule",
    )

    baseline = scenario.get("central_baseline_summary")
    _require(isinstance(baseline, dict), "remote central baseline summary is absent")
    assert isinstance(baseline, dict)
    total_attempts = len(expected_events)
    _require(
        _is_nonnegative_integer(baseline.get("authorized"))
        and _is_nonnegative_integer(baseline.get("denied"))
        and baseline["authorized"] + baseline["denied"] == total_attempts,
        "remote central baseline did not execute the fixed schedule",
    )
    return key


def _validate_q1_outputs(artifacts: dict[str, bytes], result: dict[str, object]) -> None:
    try:
        from .remote_three_host import (
            per_site_timeline_svg,
            phase_end_csv,
            phase_end_markdown,
            report_markdown,
            timeline_csv,
            timeline_svg,
        )

        renderers = {
            "remote/three-host-linux-report.md": report_markdown,
            "remote/three-host-linux-timeline.csv": timeline_csv,
            "remote/three-host-linux-timeline.svg": timeline_svg,
            "remote/three-host-linux-per-site-timeline.svg": per_site_timeline_svg,
            "remote/three-host-linux-phase-end.csv": phase_end_csv,
            "remote/three-host-linux-phase-end.md": phase_end_markdown,
        }
        for relative, renderer in renderers.items():
            expected = (renderer(result).rstrip() + "\n").encode("utf-8")
            _require(
                artifacts.get(relative) == expected,
                f"derived Q1 artifact does not match the retained raw result: {relative}",
            )
    except CampaignError:
        raise
    except Exception as error:
        raise CampaignError("unable to deterministically render retained Q1 evidence") from error


def _validate_remote_artifacts(
    artifacts: dict[str, bytes], repository: Path, identity: GitIdentity
) -> None:
    inventory_path = "remote/cluster-inventory.json"
    inventory = _json_artifact(artifacts, inventory_path)
    _require_schema(inventory, "lets.remote-cluster-inventory/v1", inventory_path)
    servers = inventory.get("servers")
    _require(
        isinstance(servers, list) and len(servers) == 3, "remote inventory must contain 3 sites"
    )
    assert isinstance(servers, list)
    aliases: list[object] = []
    addresses: list[object] = []
    host_keys: list[object] = []
    for server in servers:
        _require(isinstance(server, dict), "remote inventory contains a malformed site")
        assert isinstance(server, dict)
        aliases.append(server.get("alias"))
        addresses.append(server.get("address_sha256"))
        host_keys.append(server.get("host_key_sha256"))
        for check in (
            "connected",
            "home_absolute",
            "home_normalized",
            "home_owned",
            "inventory_ok",
            "login_matches_credential",
        ):
            _require(server.get(check) is True, f"remote inventory site failed {check}")
    _require(aliases == ["s1", "s2", "s3"], "remote inventory aliases are incomplete")
    _require(
        len(set(addresses)) == 3 and None not in addresses, "remote addresses are not distinct"
    )
    _require(
        len(set(host_keys)) == 3 and None not in host_keys, "remote host keys are not distinct"
    )

    result_path = "remote/three-host-linux-result.json"
    result = _json_artifact(artifacts, result_path)
    _require_schema(result, "lets.three-host-linux-experiment/v1", result_path)
    _require(result.get("status") == "passed", "three-site remote experiment did not pass")
    _require(_assertions_passed(result.get("assertions")), "remote assertions did not pass")
    source = result.get("source")
    _require(
        isinstance(source, dict)
        and source.get("commit") == identity.commit
        and source.get("tree") == identity.tree
        and isinstance(source.get("archive_sha256"), str)
        and _SHA256.fullmatch(str(source["archive_sha256"])) is not None,
        "remote result is not bound to the campaign commit and tree",
    )
    controller_path = "benchmarks/nsdi_strengthening/remote_three_host.py"
    agent_path = "benchmarks/nsdi_strengthening/remote_three_host_agent.py"
    controller_source = _committed_file(repository, identity.commit, controller_path)
    agent_source = _committed_file(repository, identity.commit, agent_path)
    harness = result.get("harness")
    _require(
        isinstance(harness, dict)
        and harness.get("controller_path") == controller_path
        and harness.get("agent_path") == agent_path
        and harness.get("controller_sha256") == _sha256(controller_source)
        and harness.get("agent_sha256") == _sha256(agent_source)
        and harness.get("sha256") == _sha256(controller_source + b"\x00" + agent_source),
        "remote harness hashes do not match the committed controller and agent",
    )
    _require(
        result.get("secrets_retained_in_result") is False
        and result.get("home_scoped_runtime_secrets_removed_after_each_scenario") is True
        and result.get("raw_addresses_retained") is False
        and result.get("raw_usernames_retained") is False,
        "remote result privacy or credential-cleanup contract failed",
    )

    host_evidence = result.get("host_evidence")
    _require(isinstance(host_evidence, dict), "remote host identity evidence is absent")
    assert isinstance(host_evidence, dict)
    _require(
        host_evidence.get("aliases") == aliases
        and host_evidence.get("address_sha256") == addresses
        and host_evidence.get("ssh_host_key_sha256") == host_keys
        and host_evidence.get("distinct_address_hashes") == 3
        and host_evidence.get("distinct_ssh_host_keys") == 3,
        "remote host evidence does not match the accepted inventory",
    )
    try:
        salt = base64.b64decode(str(host_evidence.get("identity_hash_salt_b64")), validate=True)
    except (ValueError, TypeError) as error:
        raise CampaignError("remote identity salt is malformed") from error
    _require(len(salt) == 32, "remote identity salt is malformed")
    boot_identities = host_evidence.get("linux_boot_identity")
    _require(
        isinstance(boot_identities, list) and len(boot_identities) == 3,
        "remote Linux boot identity evidence is incomplete",
    )
    assert isinstance(boot_identities, list)
    identity_fields = tuple(
        f"{name}{suffix}_sha256"
        for name in ("machine_id", "boot_id", "hostname")
        for suffix in ("", "_salted")
    )
    for expected_alias, boot_identity in zip(aliases, boot_identities, strict=True):
        _require(isinstance(boot_identity, dict), "remote Linux boot identity is malformed")
        assert isinstance(boot_identity, dict)
        _require(
            boot_identity.get("alias") == expected_alias
            and isinstance(boot_identity.get("kernel"), str)
            and bool(str(boot_identity["kernel"]).strip())
            and all(
                isinstance(boot_identity.get(field), str)
                and _SHA256.fullmatch(str(boot_identity[field])) is not None
                for field in identity_fields
            ),
            "remote Linux boot identity is malformed",
        )
    _require(
        len({str(item["boot_id_sha256"]) for item in boot_identities}) == 3
        and len({str(item["boot_id_salted_sha256"]) for item in boot_identities}) == 3,
        "remote Linux boot identities are not distinct",
    )

    _require(
        result.get("scenario_matrix")
        == {
            "design": "full-factorial-2x2",
            "placements": ["equal", "70-percent-s1"],
            "workloads": ["equal", "70-percent-s1"],
        },
        "remote scenario matrix declaration is not the exact 2x2 design",
    )
    scenarios = result.get("scenarios")
    _require(isinstance(scenarios, list) and len(scenarios) == 4, "remote matrix is incomplete")
    assert isinstance(scenarios, list)
    scenario_keys: set[tuple[str, str]] = set()
    for scenario in scenarios:
        _require(isinstance(scenario, dict), "remote matrix contains a malformed scenario")
        assert isinstance(scenario, dict)
        _require(scenario.get("status") == "passed", "remote scenario did not pass")
        _require(
            _assertions_passed(scenario.get("assertions")),
            "remote scenario assertions did not pass",
        )
        scenario_keys.add(_validate_three_host_scenario(scenario))
    _require(
        scenario_keys
        == {
            ("equal", "equal"),
            ("equal", "70-percent-s1"),
            ("70-percent-s1", "equal"),
            ("70-percent-s1", "70-percent-s1"),
        },
        "remote matrix is not the exact full-factorial scenario set",
    )
    _validate_q1_outputs(artifacts, result)

    matched_path = "remote/matched-host/remote-matched-host-manifest.json"
    matched = _json_artifact(artifacts, matched_path)
    _require_schema(matched, "lets.remote-matched-host/v1", matched_path)
    _require(matched.get("status") == "passed", "matched-host benchmark did not pass")
    _require("recovery" not in matched, "matched-host evidence must be a fresh benchmark run")
    _require(isinstance(matched.get("commands"), list), "matched-host fresh command log is absent")
    remote_source = matched.get("remote_source")
    _require(
        isinstance(remote_source, dict) and remote_source.get("clean") is True,
        "matched-host remote source was not clean",
    )
    matched_source = matched.get("source")
    controller = matched_source.get("controller_git") if isinstance(matched_source, dict) else None
    _require(
        isinstance(controller, dict)
        and controller.get("dirty") is False
        and controller.get("commit") == identity.commit,
        "matched-host controller source was not the clean campaign commit",
    )
    orchestrator_source = _committed_file(
        repository,
        identity.commit,
        "benchmarks/nsdi_strengthening/remote_matched_host.py",
    )
    benchmark_source = _committed_file(
        repository,
        identity.commit,
        "benchmarks/nsdi_strengthening/matched_host_path.py",
    )
    _require(
        isinstance(matched_source, dict)
        and matched_source.get("orchestrator_sha256") == _sha256(orchestrator_source)
        and matched_source.get("benchmark_sha256") == _sha256(benchmark_source),
        "matched-host harness hashes do not match the committed orchestrator and benchmark",
    )
    privacy = matched.get("privacy")
    _require(
        isinstance(privacy, dict) and privacy and all(value is False for value in privacy.values()),
        "matched-host privacy contract did not pass",
    )
    configuration = matched.get("configuration")
    _require(
        configuration == {"operations_per_mode": 1000, "trials": 10, "warmups": 100},
        "matched-host benchmark configuration is incomplete",
    )
    declared = matched.get("artifacts")
    _require(isinstance(declared, dict), "matched-host artifact digests are absent")
    assert isinstance(declared, dict)
    for name in ("matched-host-path-samples.csv", "matched-host-path.md"):
        metadata = declared.get(name)
        relative = f"remote/matched-host/{name}"
        _require(isinstance(metadata, dict), f"matched-host manifest omits {name}")
        assert isinstance(metadata, dict)
        _require(
            metadata.get("retained_sanitized_sha256") == _sha256(artifacts[relative]),
            f"matched-host retained digest does not match {name}",
        )
    json_metadata = declared.get("matched-host-path.json")
    _require(isinstance(json_metadata, dict), "matched-host manifest omits matched-host-path.json")
    compressed = artifacts["remote/matched-host/matched-host-path.json.gz"]
    _require(
        len(compressed) >= 10
        and compressed[:2] == b"\x1f\x8b"
        and compressed[3] & 0x08 == 0
        and compressed[4:8] == b"\0\0\0\0",
        "matched-host JSON archive is not deterministic gzip with mtime 0 and no filename",
    )
    try:
        decompressed = gzip.decompress(compressed)
        json.loads(decompressed)
    except (gzip.BadGzipFile, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CampaignError("matched-host JSON archive is invalid") from error
    assert isinstance(json_metadata, dict)
    _require(
        json_metadata.get("retained_sanitized_sha256") == _sha256(decompressed),
        "matched-host decompressed JSON digest does not match its manifest",
    )
    _validate_json_provenance(
        "remote/matched-host/matched-host-path.json.gz (decompressed)",
        decompressed,
        identity.commit,
    )


def _validate_distributed(document: dict[str, object]) -> None:
    _require_schema(document, "lets.partition-comparison/v1", "distributed/partition-results.json")
    expected_scenarios = {
        "balanced_equal_shares",
        "skew_demand_placed_shares",
        "skew_equal_shares",
    }
    runs = document.get("runs")
    _require(isinstance(runs, list) and len(runs) == 6, "distributed matrix is incomplete")
    assert isinstance(runs, list)
    observed: set[tuple[object, object]] = set()
    for run in runs:
        _require(isinstance(run, dict), "distributed matrix contains a malformed run")
        assert isinstance(run, dict)
        scheme = run.get("scheme")
        scenario = run.get("scenario")
        observed.add((scheme, scenario))
        summary = run.get("summary")
        _require(isinstance(summary, dict), "distributed run has no summary")
        assert isinstance(summary, dict)
        if scheme == "lets":
            final = summary.get("final_aggregate")
            _require(
                summary.get("conservation_healthy") is True
                and isinstance(final, dict)
                and final.get("healthy") is True,
                "distributed LETS run failed conservation",
            )
        elif scheme == "centralized_counter":
            _require(
                summary.get("counter_identity_healthy") is True,
                "distributed central counter identity failed",
            )
        else:
            raise CampaignError("distributed matrix contains an unknown scheme")
    expected = {
        (scheme, scenario)
        for scheme in ("lets", "centralized_counter")
        for scenario in expected_scenarios
    }
    _require(observed == expected, "distributed scenario coverage is incomplete")


def _validate_vector(document: dict[str, object]) -> None:
    _require_schema(document, "lets.vector-workload/v1", "vector/vector-workload.json")
    checks = document.get("checks")
    _require(
        isinstance(checks, dict) and checks and all(value is True for value in checks.values()),
        "vector workload checks did not all pass",
    )
    final = document.get("final")
    _require(
        isinstance(final, dict)
        and final.get("identity_holds") is True
        and final.get("local_invariants_healthy") is True
        and final.get("spendable_bound_holds") is True,
        "vector workload final invariants did not pass",
    )


def _validate_lineage(document: dict[str, object]) -> None:
    _require_schema(document, "lets.lineage-scaling/v1", "lineage/lineage-scaling.json")
    configuration = document.get("configuration")
    _require(
        isinstance(configuration, dict)
        and configuration.get("depths") == [1, 2, 4, 8]
        and configuration.get("branching_factors") == [1, 2, 4, 8],
        "lineage grid configuration is incomplete",
    )
    rows = document.get("rows")
    _require(isinstance(rows, list) and len(rows) == 32, "lineage grid is incomplete")
    assert isinstance(rows, list)
    combinations: set[tuple[object, object, object]] = set()
    for row in rows:
        _require(isinstance(row, dict), "lineage grid contains a malformed row")
        assert isinstance(row, dict)
        combinations.add((row.get("shape"), row.get("depth"), row.get("branching_factor")))
        status = row.get("status")
        _require(status in {"passed", "skipped_node_cap"}, "lineage row failed")
        if status == "passed":
            accounting = row.get("final_accounting")
            _require(
                isinstance(accounting, dict)
                and accounting.get("healthy") is True
                and row.get("reopen_integrity") == ["ok"],
                "lineage row invariants did not pass",
            )
    _require(len(combinations) == 32, "lineage grid contains duplicate cells")
    probe = document.get("depth_limit_probe")
    _require(
        isinstance(probe, dict)
        and probe.get("maximum_accepted_depth") == 64
        and probe.get("next_depth") == 65
        and probe.get("next_depth_rejected") is True,
        "lineage depth-limit probe did not pass",
    )


def _validate_formal(vector: dict[str, object], frontier: dict[str, object]) -> None:
    _require(vector.get("schema_version") == 1, "unexpected vector model schema")
    baseline = vector.get("baseline")
    mutant = vector.get("mutant")
    _require(
        vector.get("success") is True
        and isinstance(baseline, dict)
        and baseline.get("passed") is True
        and isinstance(mutant, dict)
        and mutant.get("killed") is True,
        "vector model checker did not pass",
    )
    _require_schema(frontier, "lets.formal-sensitivity-frontier/v1", "formal frontier")
    frontier_result = frontier.get("frontier")
    sensitivity = frontier.get("sensitivity")
    _require(
        frontier.get("success") is True
        and isinstance(frontier_result, dict)
        and frontier_result.get("passed") is True
        and isinstance(sensitivity, dict)
        and sensitivity.get("passed") is True
        and sensitivity.get("baseline_passed") is True
        and sensitivity.get("all_mutants_killed") is True,
        "formal sensitivity checks did not pass",
    )


def _validate_performance(document: dict[str, object]) -> None:
    _require_schema(document, "lets.nsdi-performance-matrix/v1", "performance matrix")
    configuration = document.get("configuration")
    storage = document.get("storage")
    _require(isinstance(configuration, dict), "performance configuration is absent")
    assert isinstance(configuration, dict)
    _require(
        configuration.get("delays_ms") == [0.0, 1.0, 10.0, 100.0, 1000.0]
        and configuration.get("workers") == [1, 2, 4, 8, 16]
        and configuration.get("mode_order") == "alternates by paired trial"
        and configuration.get("trials") == 2
        and isinstance(storage, list)
        and len(storage) == 2,
        "performance matrix configuration is incomplete",
    )
    trials = document.get("trials")
    aggregates = document.get("aggregates")
    _require(
        isinstance(trials, list) and len(trials) == 200,
        "performance trial matrix is incomplete",
    )
    _require(
        isinstance(aggregates, list) and len(aggregates) == 100,
        "performance aggregate matrix is incomplete",
    )
    assert isinstance(trials, list)
    _require(
        all(
            isinstance(trial, dict)
            and trial.get("conservation_healthy") is True
            and trial.get("executor_rollback_protected") is True
            for trial in trials
        ),
        "performance trial safety checks did not all pass",
    )
    storage_ids = {
        storage_item.get("storage_id") for storage_item in storage if isinstance(storage_item, dict)
    }
    _require(
        len(storage_ids) == 2 and None not in storage_ids, "performance storage IDs are invalid"
    )
    expected_trial_keys = {
        (storage_id, delay, workers, mode, trial_index)
        for storage_id in storage_ids
        for delay in (0.0, 1.0, 10.0, 100.0, 1000.0)
        for workers in (1, 2, 4, 8, 16)
        for mode in ("off", "enforce")
        for trial_index in (0, 1)
    }
    trial_keys = {
        (
            trial.get("storage_id"),
            trial.get("delay_ms"),
            trial.get("workers"),
            trial.get("mode"),
            trial.get("trial_index"),
        )
        for trial in trials
        if isinstance(trial, dict)
    }
    _require(trial_keys == expected_trial_keys, "performance trial grid is not exact")
    assert isinstance(aggregates, list)
    expected_aggregate_keys = {key[:-1] for key in expected_trial_keys}
    aggregate_keys = {
        (
            aggregate.get("storage_id"),
            aggregate.get("delay_ms"),
            aggregate.get("workers"),
            aggregate.get("mode"),
        )
        for aggregate in aggregates
        if isinstance(aggregate, dict)
    }
    _require(aggregate_keys == expected_aggregate_keys, "performance aggregate grid is not exact")


def _validate_junit(content: bytes, *, minimum_tests: int, label: str) -> None:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as error:
        raise CampaignError(f"{label} is not valid JUnit XML") from error
    suites = [root] if root.tag.endswith("testsuite") else list(root.findall("./testsuite"))
    try:
        tests = sum(int(suite.attrib["tests"]) for suite in suites)
        errors = sum(int(suite.attrib.get("errors", "0")) for suite in suites)
        failures = sum(int(suite.attrib.get("failures", "0")) for suite in suites)
    except (KeyError, ValueError) as error:
        raise CampaignError(f"{label} has malformed JUnit totals") from error
    _require(
        bool(suites) and tests >= minimum_tests and errors == 0 and failures == 0,
        f"{label} is incomplete or failing",
    )


def _validate_rollback(document: dict[str, object], junit: bytes) -> None:
    _require_schema(document, "lets.nsdi-rollback-clone-evidence/v1", "rollback summary")
    summary = document.get("junit")
    selected = document.get("selected_test_node_ids")
    _require(
        document.get("passed") is True
        and document.get("pytest_returncode") == 0
        and document.get("runner_error") is None
        and isinstance(summary, dict)
        and summary.get("errors") == 0
        and summary.get("failures") == 0
        and isinstance(selected, list)
        and len(selected) >= 10
        and summary.get("tests") == len(selected),
        "rollback matrix did not pass its complete selected suite",
    )
    _validate_junit(junit, minimum_tests=10, label="rollback matrix")


def _validate_implementation(document: dict[str, object]) -> None:
    _require_schema(document, "lets.nsdi-implementation-inventory/v1", "implementation inventory")
    facts = document.get("facts")
    groups = document.get("groups")
    _require(
        isinstance(facts, list)
        and len(facts) >= 8
        and all(isinstance(fact, dict) and fact.get("verified") is True for fact in facts),
        "implementation inventory facts were not all verified",
    )
    _require(
        isinstance(groups, dict) and {"narrow_enforcement_core", "whole_runtime"}.issubset(groups),
        "implementation inventory source groups are incomplete",
    )


def _validate_docker(
    document: dict[str, object], scenario: dict[str, object], expected_commit: str
) -> None:
    _require_schema(document, "lets.acceptance-evidence/v2", "Docker acceptance")
    source = document.get("source")
    source_after = document.get("source_after")
    for identity in (source, source_after):
        _require(
            isinstance(identity, dict)
            and identity.get("dirty") is False
            and identity.get("git_commit") == expected_commit,
            "Docker acceptance source is not the clean campaign commit",
        )
    _require(
        document.get("passed") is True
        and document.get("pytest_exit_code") == 0
        and document.get("source_stable") is True,
        "Docker acceptance did not pass with stable source",
    )
    _require(document.get("scenario") == scenario, "Docker scenario evidence does not match")


def _validate_required_campaign(
    artifacts: dict[str, bytes], repository: Path, identity: GitIdentity
) -> None:
    missing = sorted(_REQUIRED_ARTIFACTS.difference(artifacts))
    if missing:
        raise CampaignError("required campaign artifacts are missing: " + ", ".join(missing))
    _validate_remote_artifacts(artifacts, repository, identity)
    _validate_distributed(_json_artifact(artifacts, "distributed/partition-results.json"))
    _validate_vector(_json_artifact(artifacts, "vector/vector-workload.json"))
    _validate_lineage(_json_artifact(artifacts, "lineage/lineage-scaling.json"))
    _validate_formal(
        _json_artifact(artifacts, "formal/vector-model.json"),
        _json_artifact(artifacts, "formal/sensitivity-frontier.json"),
    )
    _validate_performance(_json_artifact(artifacts, "performance/performance-matrix.json"))
    _validate_rollback(
        _json_artifact(artifacts, "rollback/rollback-matrix.summary.json"),
        artifacts["rollback/rollback-matrix.junit.xml"],
    )
    _validate_implementation(
        _json_artifact(artifacts, "implementation/implementation-inventory.json")
    )
    _validate_junit(
        artifacts["raw/final-full-suite.xml"], minimum_tests=800, label="full test suite"
    )
    _validate_docker(
        _json_artifact(artifacts, "docker/docker-acceptance.json"),
        _json_artifact(artifacts, "docker/scenario-evidence.json"),
        identity.commit,
    )


def _staged_artifacts(
    staging_root: Path,
    repository: Path,
    identity: GitIdentity,
    *,
    allowed_manifests: dict[str, bytes] | None = None,
) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    reserved = {
        MANIFEST_NAME,
        PAPER_INPUT_MANIFEST_NAME,
        SOURCE_MANIFEST_NAME,
    }
    for name in reserved:
        manifest_path = staging_root / name
        if not manifest_path.exists():
            continue
        if allowed_manifests is None or name not in allowed_manifests:
            raise CampaignError(f"refusing to overwrite existing campaign manifest: {name}")
        if _read_regular_file(manifest_path) != allowed_manifests[name]:
            raise CampaignError(f"campaign manifest changed while finalizing: {name}")
    entries = []
    artifacts: dict[str, bytes] = {}
    for path in sorted(staging_root.rglob("*")):
        relative_path = path.relative_to(staging_root)
        if path.is_symlink():
            raise CampaignError(
                f"symbolic links are not permitted in staged evidence: {relative_path.as_posix()}"
            )
        if not path.is_file():
            continue
        relative = relative_path.as_posix()
        if relative in reserved:
            continue
        _validate_evidence_path(relative_path)
        content = _read_regular_file(path)
        if path.suffix.lower() == ".json" and relative != CAMPAIGN_PREFLIGHT_NAME:
            _validate_json_provenance(relative, content, identity.commit)
        entries.append(_file_entry(relative, content))
        artifacts[relative] = content
    observed = set(artifacts).difference({CAMPAIGN_PREFLIGHT_NAME})
    if observed != _REQUIRED_ARTIFACTS:
        missing = sorted(_REQUIRED_ARTIFACTS.difference(observed))
        unexpected = sorted(observed.difference(_REQUIRED_ARTIFACTS))
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        raise CampaignError("staged artifact set is not exact (" + "; ".join(details) + ")")
    _validate_required_campaign(artifacts, repository, identity)
    return entries, artifacts


def _read_preflight(staging_root: Path, identity: GitIdentity) -> None:
    marker = staging_root / CAMPAIGN_PREFLIGHT_NAME
    try:
        document = json.loads(_read_regular_file(marker))
    except FileNotFoundError as error:
        raise CampaignError("staging root has no clean-campaign preflight record") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CampaignError("clean-campaign preflight record is invalid") from error
    expected: dict[str, object] = {
        "git": {
            "commit": identity.commit,
            "dirty": False,
            "tree": identity.tree,
        },
        "purpose": "bind a clean exact checkout before evidence is written",
        "schema": CAMPAIGN_SCHEMA,
    }
    if document != expected:
        raise CampaignError("clean-campaign preflight record does not match this campaign")


def _render_campaign_manifests(
    *,
    repository: Path,
    staging_root: Path,
    paper_input_root: Path,
    identity: GitIdentity,
    campaign_binding: str,
    allowed_manifests: dict[str, bytes] | None = None,
) -> tuple[bytes, bytes, bytes]:
    current_identity = _clean_git_identity(repository, identity.commit)
    _require(current_identity == identity, "campaign Git identity changed while finalizing")
    _read_preflight(staging_root, identity)
    _validate_paper_campaign_binding(paper_input_root, campaign_binding)
    source_bytes = _json_bytes(_source_manifest(repository, identity))
    paper_bytes = _json_bytes(_paper_manifest(repository, paper_input_root))
    evidence_entries, _ = _staged_artifacts(
        staging_root,
        repository,
        identity,
        allowed_manifests=allowed_manifests,
    )
    evidence_entries.extend(
        [
            _file_entry(PAPER_INPUT_MANIFEST_NAME, paper_bytes),
            _file_entry(SOURCE_MANIFEST_NAME, source_bytes),
        ]
    )
    top_level_bytes = _json_bytes(
        {
            "files": sorted(evidence_entries, key=lambda entry: str(entry["path"])),
            "schema": EVIDENCE_MANIFEST_SCHEMA,
        }
    )
    return source_bytes, paper_bytes, top_level_bytes


def _remove_created_campaign_file(path: Path, expected_content: bytes) -> None:
    """Remove only a file created by this finalization attempt and still unchanged."""

    try:
        if _read_regular_file(path) == expected_content:
            path.unlink()
    except (FileNotFoundError, CampaignError, OSError):
        pass


def finalize_campaign(
    *,
    repository: Path,
    staging_root: Path,
    paper_input_root: Path,
    expected_commit: str,
    campaign_binding: str,
) -> tuple[Path, Path, Path]:
    """Validate and seal staged evidence without modifying a prior bundle."""

    root = _repository_root(repository)
    expected = _expected_commit(expected_commit)
    identity = _clean_git_identity(root, expected)
    staging = staging_root.resolve(strict=True)
    if not staging.is_dir():
        raise CampaignError(f"staging root is not a directory: {staging}")
    _validate_staging_location(root, staging)
    _read_preflight(staging, identity)

    paper_root = paper_input_root
    if not paper_root.is_absolute():
        paper_root = root / paper_root
    binding = _validated_campaign_binding(campaign_binding)
    rendered = _render_campaign_manifests(
        repository=root,
        staging_root=staging,
        paper_input_root=paper_root,
        identity=identity,
        campaign_binding=binding,
    )
    # Re-read every source, paper, and evidence input before materializing any
    # manifest.  This catches drift during the first complete validation pass.
    _require(
        _render_campaign_manifests(
            repository=root,
            staging_root=staging,
            paper_input_root=paper_root,
            identity=identity,
            campaign_binding=binding,
        )
        == rendered,
        "campaign inputs changed while finalizing",
    )
    source_bytes, paper_bytes, top_level_bytes = rendered
    source_path = staging / SOURCE_MANIFEST_NAME
    paper_path = staging / PAPER_INPUT_MANIFEST_NAME
    manifest_path = staging / MANIFEST_NAME
    created: list[tuple[Path, bytes]] = []
    try:
        _write_new(source_path, source_bytes)
        created.append((source_path, source_bytes))
        _write_new(paper_path, paper_bytes)
        created.append((paper_path, paper_bytes))
        allowed = {
            SOURCE_MANIFEST_NAME: source_bytes,
            PAPER_INPUT_MANIFEST_NAME: paper_bytes,
        }
        _require(
            _render_campaign_manifests(
                repository=root,
                staging_root=staging,
                paper_input_root=paper_root,
                identity=identity,
                campaign_binding=binding,
                allowed_manifests=allowed,
            )
            == rendered,
            "campaign inputs changed before the final seal",
        )
        # MANIFEST.json is published last and is the only seal consumers trust.
        _write_new(manifest_path, top_level_bytes)
        created.append((manifest_path, top_level_bytes))
        allowed[MANIFEST_NAME] = top_level_bytes
        _require(
            _render_campaign_manifests(
                repository=root,
                staging_root=staging,
                paper_input_root=paper_root,
                identity=identity,
                campaign_binding=binding,
                allowed_manifests=allowed,
            )
            == rendered,
            "campaign inputs changed after the final seal",
        )
    except BaseException:
        # A failed attempt must not leave a valid-looking MANIFEST.json (or
        # partial companion manifests) behind.
        for path, content in reversed(created):
            _remove_created_campaign_file(path, content)
        raise
    return source_path, paper_path, manifest_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare or deterministically finalize a clean NSDI evidence campaign."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "compress-matched-host", "finalize"):
        command = subparsers.add_parser(name)
        command.add_argument("--repository", type=Path, default=Path("."))
        command.add_argument("--staging-root", type=Path, required=True)
        command.add_argument("--expected-commit", required=True)
        if name == "finalize":
            command.add_argument("--paper-input-root", type=Path, default=Path("paper/submission"))
            command.add_argument("--campaign-binding", required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    try:
        if options.command == "preflight":
            marker = preflight_campaign(
                repository=options.repository,
                staging_root=options.staging_root,
                expected_commit=options.expected_commit,
            )
            print(f"clean campaign staging root prepared: {marker.parent}")
        elif options.command == "compress-matched-host":
            output = compress_matched_host_result(
                repository=options.repository,
                staging_root=options.staging_root,
                expected_commit=options.expected_commit,
            )
            print(f"deterministic matched-host archive created: {output}")
        else:
            outputs = finalize_campaign(
                repository=options.repository,
                staging_root=options.staging_root,
                paper_input_root=options.paper_input_root,
                expected_commit=options.expected_commit,
                campaign_binding=options.campaign_binding,
            )
            print("clean campaign manifests finalized:")
            for output in outputs:
                print(output)
    except (CampaignError, FileNotFoundError, NotADirectoryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
