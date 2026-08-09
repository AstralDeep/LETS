"""Build, run, evidence, and stop the real multi-node acceptance cluster."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "lets-acceptance"
ALLOWED_VOLUMES = {
    f"{PROJECT}_cluster-config",
    f"{PROJECT}_operator-data",
    f"{PROJECT}_warden-a-data",
    f"{PROJECT}_warden-b-data",
    f"{PROJECT}_warden-c-data",
}
COMPOSE = ("docker", "compose", "--project-directory", str(ROOT))
RESULTS = ROOT / "results" / "generated"
SCENARIO_EVIDENCE = RESULTS / "scenario-evidence.json"
TRACKED_SUMMARY = ROOT / "deploy" / "evidence" / "acceptance-2026-08-09.md"
NODES = {
    "warden-a": "http://127.0.0.1:18741",
    "warden-b": "http://127.0.0.1:18742",
    "warden-c": "http://127.0.0.1:18743",
}
SOURCE_DIGEST_DOMAIN = b"LETS repository source tree v1\0"
RUNTIME_INPUT_DIGEST_DOMAIN = b"LETS runtime and acceptance inputs v1\0"
RUNTIME_INPUT_FILES = frozenset(
    {
        ".dockerignore",
        ".gitattributes",
        ".gitignore",
        ".python-version",
        "Dockerfile",
        "LICENSE",
        "NOTICE",
        "README.md",
        "compose.yaml",
        "pyproject.toml",
        "uv.lock",
    }
)
RUNTIME_INPUT_PREFIXES = ("protocol/", "src/", "tests/e2e/")


def _run(
    arguments: list[str] | tuple[str, ...],
    *,
    check: bool = True,
    timeout: float = 300,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(arguments),
        cwd=ROOT,
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=environment,
    )


def _compose(*arguments: str, check: bool = True, timeout: float = 300) -> str:
    process = _run([*COMPOSE, *arguments], check=check, timeout=timeout)
    return process.stdout.strip()


def _nul_items(output: str) -> list[str]:
    return [item for item in output.split("\0") if item]


def _digest_source_paths(source_paths: list[str], *, domain: bytes) -> str:
    digest = hashlib.sha256(domain)
    for git_path in source_paths:
        relative = PurePosixPath(git_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("git returned a path outside the repository")
        path_bytes = relative.as_posix().encode("utf-8", errors="surrogateescape")
        local_path = ROOT.joinpath(*relative.parts)
        if local_path.is_symlink():
            kind = b"symlink"
            content = os.readlink(local_path).encode("utf-8", errors="surrogateescape")
        elif local_path.is_file():
            kind = b"file"
            content = local_path.read_bytes()
        elif not local_path.exists():
            kind = b"missing"
            content = b""
        else:
            raise RuntimeError(f"git-visible source is not a file: {relative.as_posix()}")
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(kind).to_bytes(1, "big"))
        digest.update(kind)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"


def _is_runtime_input(git_path: str) -> bool:
    if git_path in RUNTIME_INPUT_FILES:
        return True
    if git_path.startswith(RUNTIME_INPUT_PREFIXES):
        return True
    relative = PurePosixPath(git_path)
    return relative.parent == PurePosixPath("deploy") and relative.suffix == ".py"


def _source_provenance() -> dict[str, Any]:
    """Describe and hash the exact Git-visible worktree without exposing paths."""

    commit = _run(["git", "rev-parse", "--verify", "HEAD"]).stdout.strip()
    git_ref = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    commit_time = _run(["git", "show", "-s", "--format=%cI", "HEAD"]).stdout.strip()
    status = _run(
        [
            "git",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ]
    ).stdout
    staged = _nul_items(_run(["git", "diff", "--cached", "--name-only", "-z", "--"]).stdout)
    unstaged = _nul_items(_run(["git", "diff", "--name-only", "-z", "--"]).stdout)
    untracked = _nul_items(_run(["git", "ls-files", "--others", "--exclude-standard", "-z"]).stdout)
    source_paths = _nul_items(
        _run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]).stdout
    )
    source_paths = sorted(
        set(source_paths), key=lambda item: item.encode("utf-8", errors="surrogateescape")
    )
    runtime_input_paths = [path for path in source_paths if _is_runtime_input(path)]
    if not runtime_input_paths:
        raise RuntimeError("no Git-visible runtime or acceptance inputs were found")

    return {
        "git_commit": commit,
        "git_ref": git_ref,
        "git_commit_time": commit_time,
        "dirty": bool(status),
        "staged_file_count": len(staged),
        "unstaged_file_count": len(unstaged),
        "untracked_file_count": len(untracked),
        "git_status_sha256": (
            "sha256:" + hashlib.sha256(status.encode("utf-8", errors="surrogateescape")).hexdigest()
        ),
        "source_file_count": len(source_paths),
        "source_sha256": _digest_source_paths(source_paths, domain=SOURCE_DIGEST_DOMAIN),
        "source_digest_algorithm": "LETS repository source tree v1",
        "runtime_input_file_count": len(runtime_input_paths),
        "runtime_input_sha256": _digest_source_paths(
            runtime_input_paths,
            domain=RUNTIME_INPUT_DIGEST_DOMAIN,
        ),
        "runtime_input_digest_algorithm": "LETS runtime and acceptance inputs v1",
        "runtime_input_selection": {
            "exact_files": sorted(RUNTIME_INPUT_FILES),
            "directory_prefixes": list(RUNTIME_INPUT_PREFIXES),
            "deploy_rule": "deploy/*.py",
        },
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _redact_sensitive_text(value: str) -> str:
    token = os.environ.get("LETS_BOOTSTRAP_TOKEN")
    if token:
        return value.replace(token, "[REDACTED LETS_BOOTSTRAP_TOKEN]")
    return value


def _existing_project_volumes() -> set[str]:
    output = _run(
        [
            "docker",
            "volume",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
            "--format",
            "{{.Name}}",
        ]
    ).stdout
    return {line.strip() for line in output.splitlines() if line.strip()}


def _fresh_start() -> None:
    existing = _existing_project_volumes()
    unexpected = existing - ALLOWED_VOLUMES
    if unexpected:
        raise RuntimeError(f"refusing to remove unexpected Docker volumes: {sorted(unexpected)}")
    _compose("down", "--volumes", "--remove-orphans", timeout=120)
    _compose("up", "-d", "--build", timeout=600)


def _wait_proxy_init() -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        container_id = _compose("ps", "-a", "-q", "proxy-init", check=False)
        if container_id:
            raw = _run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{json .State}}",
                    container_id,
                ]
            ).stdout
            state = json.loads(raw)
            if state.get("Status") == "exited":
                if state.get("ExitCode") != 0:
                    raise RuntimeError("Toxiproxy configuration service failed")
                return
        time.sleep(0.25)
    raise RuntimeError("Toxiproxy configuration did not complete")


def _wait_nodes() -> None:
    deadline = time.monotonic() + 90
    pending = set(NODES)
    while pending and time.monotonic() < deadline:
        for warden_id in tuple(pending):
            try:
                with urllib.request.urlopen(
                    f"{NODES[warden_id]}/health/ready", timeout=2
                ) as response:
                    if response.status == 200:
                        pending.remove(warden_id)
            except OSError:
                pass
        if pending:
            time.sleep(0.25)
    if pending:
        raise RuntimeError(f"wardens did not become ready: {sorted(pending)}")


def _get_json(url: str, *, authenticated: bool = False) -> dict[str, Any]:
    headers: dict[str, str] = {}
    if authenticated:
        token = os.environ.get("LETS_BOOTSTRAP_TOKEN", "lets-acceptance-token-change-me-2026")
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=5) as response:
        decoded = json.loads(response.read())
    if not isinstance(decoded, dict):
        raise RuntimeError(f"{url} did not return a JSON object")
    return decoded


def _container_state(service: str) -> dict[str, Any]:
    container_id = _compose("ps", "-q", service)
    decoded = json.loads(
        _run(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .State}}",
                container_id,
            ]
        ).stdout
    )
    if not isinstance(decoded, dict):
        raise RuntimeError(f"could not inspect {service}")
    return decoded


def _container_image_id(service: str) -> str:
    container_id = _compose("ps", "-q", service)
    image_id = _run(["docker", "inspect", "--format", "{{.Image}}", container_id]).stdout.strip()
    if not image_id.startswith("sha256:"):
        raise RuntimeError(f"{service} did not resolve to a content-addressed image ID")
    return image_id


def _image_evidence(image_id: str) -> dict[str, Any]:
    raw = _run(["docker", "image", "inspect", "--format", "{{json .}}", image_id]).stdout
    decoded = json.loads(raw)
    if not isinstance(decoded, dict) or decoded.get("Id") != image_id:
        raise RuntimeError(f"Docker image inspection did not resolve {image_id}")

    repo_digests = decoded.get("RepoDigests") or []
    repo_tags = decoded.get("RepoTags") or []
    if not isinstance(repo_digests, list) or not all(
        isinstance(item, str) for item in repo_digests
    ):
        raise RuntimeError(f"Docker returned malformed repository digests for {image_id}")
    if not isinstance(repo_tags, list) or not all(isinstance(item, str) for item in repo_tags):
        raise RuntimeError(f"Docker returned malformed repository tags for {image_id}")
    return {
        "image_id": image_id,
        "repo_digests": sorted(repo_digests),
        "repo_tags": sorted(repo_tags),
        "created": decoded.get("Created"),
        "os": decoded.get("Os"),
        "architecture": decoded.get("Architecture"),
        "variant": decoded.get("Variant"),
        "size_bytes": decoded.get("Size"),
    }


def _container_python_version(service: str) -> str:
    process = _run([*COMPOSE, "exec", "-T", service, "python", "--version"])
    return (process.stdout or process.stderr).strip()


def _cluster_report() -> dict[str, Any]:
    process = _run(
        [
            *COMPOSE,
            "exec",
            "-T",
            "warden-a",
            "python",
            "-c",
            "import pathlib; print(pathlib.Path('/cluster/bootstrap-report.json').read_text())",
        ]
    )
    decoded = json.loads(process.stdout)
    if not isinstance(decoded, dict):
        raise RuntimeError("bootstrap report is malformed")
    return decoded


def _manifest_digest(
    *,
    bootstrap: dict[str, Any],
    nodes: dict[str, Any],
    scenario: dict[str, Any] | None,
) -> str:
    candidates: list[Any] = [bootstrap.get("manifest_digest")]
    if scenario is not None:
        scenario_nodes = scenario.get("nodes")
        if isinstance(scenario_nodes, dict):
            candidates.append(scenario_nodes.get("manifest_digest"))
    for node in nodes.values():
        candidates.append(node.get("info", {}).get("metadata", {}).get("manifest_digest"))
    manifest_digests = {candidate for candidate in candidates if candidate is not None}
    if len(manifest_digests) != 1:
        raise RuntimeError(f"acceptance nodes disagree on manifest digest: {manifest_digests}")
    manifest_digest = manifest_digests.pop()
    if not isinstance(manifest_digest, str) or len(manifest_digest) != 71:
        raise RuntimeError("acceptance manifest digest is malformed")
    algorithm, separator, hex_digest = manifest_digest.partition(":")
    if (
        algorithm != "sha256"
        or separator != ":"
        or any(character not in "0123456789abcdef" for character in hex_digest)
    ):
        raise RuntimeError("acceptance manifest digest is not a lowercase SHA-256 digest")
    return manifest_digest


def _render_tracked_summary(evidence: dict[str, Any]) -> str:
    """Render curated evidence without logs or per-run identities."""

    source = evidence["source"]
    tools = evidence["tools"]
    images = evidence["images"]
    runtime_image = images["lets_runtime"]
    toxiproxy_image = images["toxiproxy"]
    bootstrap = evidence["bootstrap"]
    scenario = evidence["scenario"]
    reordered = scenario["reordered_transfer"]
    partition = scenario["partition"]
    restart = scenario["restart_recovery"]
    dispatcher = scenario["dispatcher_convergence"]
    executor = scenario["independent_executor"]
    conservation = scenario["conservation"]
    node_evidence = scenario["nodes"]
    toxiproxy_digests = toxiproxy_image["repo_digests"]
    toxiproxy_digest = toxiproxy_digests[0] if toxiproxy_digests else "not reported"
    dirty_label = "dirty" if source["dirty"] else "clean"
    process_count = len(set(node_evidence["distinct_process_ids"]))
    key_count = len(set(node_evidence["distinct_key_ids"].values()))
    local_receipt_count = len(partition["local_progress_receipts"])
    replay_result = f"{reordered['exact_http_replay_status']} {reordered['exact_http_replay_code']}"
    restart_replay_result = (
        f"{restart['exact_http_replay_status_after_restart']} "
        f"{restart['exact_http_replay_code_after_restart']}"
    )
    replay_integrity = json.dumps(executor["replay_store_integrity"], separators=(",", ":"))
    transferred_in = json.dumps(conservation["transferred_in"], separators=(",", ":"))
    transferred_out = json.dumps(conservation["transferred_out"], separators=(",", ":"))
    conserved = json.dumps(conservation["free_plus_residual_plus_consumed"], separators=(",", ":"))
    initial_budget = json.dumps(conservation["initial_budget"], separators=(",", ":"))

    return f"""# LETS distributed acceptance — 2026-08-09

This is the sanitized, runner-generated summary of the latest successful local
three-node Docker Compose acceptance. The authoritative machine-readable record
and container log are written to ignored paths under `results/generated/`.
This summary deliberately omits bearer credentials, full logs, process IDs,
public-key identifiers, receipt identifiers, and host filesystem paths.

## Provenance

- Evidence schema: `{evidence["schema"]}`.
- Started `{evidence["started_at"]}`; completed `{evidence["completed_at"]}`.
- Total evidence-bound duration: `{evidence["duration_seconds"]}` seconds;
  pytest scenario duration: `{evidence["pytest_duration_seconds"]}` seconds.
- Git commit `{source["git_commit"]}` on `{source["git_ref"]}`; worktree was
  `{dirty_label}` with {source["staged_file_count"]} staged,
  {source["unstaged_file_count"]} unstaged, and
  {source["untracked_file_count"]} non-ignored untracked files.
- The {source["source_file_count"]}-file source snapshot was stable before and
  after the acceptance scenario. Its deterministic digest was
  `{source["source_sha256"]}`; the path-redacted status digest was
  `{source["git_status_sha256"]}`.
- The non-circular runtime/acceptance-input set contained
  {source["runtime_input_file_count"]} files and had deterministic digest
  `{source["runtime_input_sha256"]}`. That explicit set covers container build
  inputs, top-level deployment programs, protocol artifacts, and `tests/e2e`,
  while excluding this derived evidence summary and paper prose.
- Compose digest: `{evidence["compose"]["file_sha256"]}`.
- Runtime image content ID: `{runtime_image["image_id"]}`.
- Toxiproxy image content ID: `{toxiproxy_image["image_id"]}`; pulled repository
  digest: `{toxiproxy_digest}`.
- Signed manifest digest: `{evidence["manifest_digest"]}`; policy digest:
  `{bootstrap["policy_digest"]}`.
- Tools: {tools["uv"]}; {tools["git"]}; {tools["pytest"]};
  {tools["docker_client"]}; server {tools["docker_server"]};
  {tools["docker_compose"]}.

The runner records both complete source snapshots in the JSON evidence and
compares them before it writes evidence outputs. A source change during the
cluster run makes the command fail even when pytest succeeds.

## Result

- Pytest exit code `{evidence["pytest_exit_code"]}`; overall evidence status:
  `passed={str(evidence["passed"]).lower()}`.
- {process_count} distinct container processes used {key_count} distinct
  Ed25519 signing keys and one signed manifest.
- Transfer sequence {reordered["sent_sequence_first"]} arrived before missing
  sequence {reordered["missing_sequence"]}; the contiguous watermark stayed at
  {reordered["contiguous_watermark"]}. Exact signed HTTP replay was rejected
  with `{replay_result}`.
- Both directed peer links were disabled. The durable source outbox retained
  {partition["durable_peer_delivery"]["pending_records"]} pending records and
  {partition["durable_peer_delivery"]["prepared_transfers"]} prepared transfers,
  while the partitioned wardens issued {local_receipt_count} valid local receipts.
- The target was stopped with `{restart["signal"]}` and restarted with a new
  process while its signing key stayed stable. Exact transport replay remained
  rejected with `{restart_replay_result}` and application-level duplicate
  acceptance returned the original acknowledgement.
- After link restoration, the production dispatcher automatically accepted and
  finalized both transfers, delivered the checkpoint, reached compacted high
  water {dispatcher["source_compacted_high_water"]} on the source and
  {dispatcher["target_compacted_high_water"]} on the target, and converged to
  {dispatcher["source_peer_dispatcher"]["pending_records"]} pending records and
  {dispatcher["source_peer_dispatcher"]["prepared_transfers"]} prepared transfers.
- An independent executor verified a signed receipt, durably claimed it in its
  own SQLite replay store, rejected it after reopening that store, and reported
  integrity `{replay_integrity}`.
- Aggregate transfer counters were `{transferred_in}` in and `{transferred_out}`
  out. Across all wardens, `free_pool + lease_residual + consumed` was
  `{conserved}` against initial budget `{initial_budget}`; every local invariant
  and signed audit chain was healthy.

The runner stopped all acceptance containers and removed the Compose network
in its `finally` block. It preserves the five named volumes for inspection; a
future run validates those exact names before removing them for a clean start.
"""


def _write_evidence(
    *,
    pytest_process: subprocess.CompletedProcess[str],
    pytest_duration_seconds: float,
    source: dict[str, Any],
    started_at: datetime,
    started_monotonic: float,
) -> bool:
    RESULTS.mkdir(parents=True, exist_ok=True)
    scenario: dict[str, Any] | None = None
    if SCENARIO_EVIDENCE.exists():
        decoded = json.loads(SCENARIO_EVIDENCE.read_text(encoding="utf-8"))
        if not isinstance(decoded, dict):
            raise RuntimeError("scenario evidence is malformed")
        scenario = decoded
    pytest_passed = pytest_process.returncode == 0
    if pytest_passed and scenario is None:
        raise RuntimeError("passing acceptance emitted no structured scenario evidence")
    (RESULTS / "docker-compose.log").write_text(
        _redact_sensitive_text(_compose("logs", "--no-color", check=False)),
        encoding="utf-8",
    )
    nodes: dict[str, Any] = {}
    for warden_id, base_url in NODES.items():
        nodes[warden_id] = {
            "container_state": _container_state(warden_id),
            "container_image_id": _container_image_id(warden_id),
            "container_python": _container_python_version(warden_id),
            "info": _get_json(f"{base_url}/v1/info"),
            "keys": _get_json(f"{base_url}/v1/keys"),
            "invariants": _get_json(f"{base_url}/v1/invariants", authenticated=True),
            "audit": _get_json(f"{base_url}/v1/audit/verify", authenticated=True),
        }

    runtime_image_ids = {node["container_image_id"] for node in nodes.values()}
    if len(runtime_image_ids) != 1:
        raise RuntimeError(f"warden runtime image IDs disagree: {runtime_image_ids}")
    runtime_image_id = runtime_image_ids.pop()
    toxiproxy_image_id = _container_image_id("toxiproxy")
    images = {
        "lets_runtime": _image_evidence(runtime_image_id),
        "toxiproxy": _image_evidence(toxiproxy_image_id),
    }
    bootstrap = _cluster_report()
    manifest_digest = _manifest_digest(
        bootstrap=bootstrap,
        nodes=nodes,
        scenario=scenario,
    )
    tools = {
        "uv": _run(["uv", "--version"]).stdout.strip(),
        "git": _run(["git", "--version"]).stdout.strip(),
        "pytest": _run([sys.executable, "-m", "pytest", "--version"]).stdout.strip(),
        "docker_client": _run(["docker", "--version"]).stdout.strip(),
        "docker_server": _run(
            ["docker", "version", "--format", "{{.Server.Version}}"]
        ).stdout.strip(),
        "docker_compose": _run(["docker", "compose", "version"]).stdout.strip(),
    }
    compose_evidence = {
        "file": "compose.yaml",
        "file_sha256": _sha256_file(ROOT / "compose.yaml"),
        "declared_images": sorted(set(_compose("config", "--images").splitlines())),
    }
    source_after = _source_provenance()
    source_stable = source_after == source
    completed_at = datetime.now(UTC)
    evidence_passed = pytest_passed and source_stable
    evidence: dict[str, Any] = {
        "schema": "lets.acceptance-evidence/v2",
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
        "duration_seconds": round(time.monotonic() - started_monotonic, 3),
        "pytest_duration_seconds": round(pytest_duration_seconds, 3),
        "passed": evidence_passed,
        "source_stable": source_stable,
        "source": source,
        "source_after": source_after,
        "provenance_boundary": "before acceptance evidence outputs are written",
        "command": f"{Path(sys.executable).name} deploy/run_acceptance.py",
        "host": {
            "python": sys.version,
            "python_implementation": platform.python_implementation(),
            "operating_system": platform.system(),
            "operating_system_release": platform.release(),
            "machine": platform.machine(),
        },
        "tools": tools,
        "compose": compose_evidence,
        "images": images,
        "manifest_digest": manifest_digest,
        "pytest_exit_code": pytest_process.returncode,
        "pytest_output": _redact_sensitive_text(pytest_process.stdout + pytest_process.stderr),
        "bootstrap": bootstrap,
        "scenario": scenario,
        "nodes": nodes,
    }
    evidence_path = RESULTS / "docker-acceptance.json"
    temporary_path = evidence_path.with_suffix(".json.tmp")
    temporary_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary_path, evidence_path)
    if evidence_passed:
        summary_temporary_path = TRACKED_SUMMARY.with_suffix(".md.tmp")
        summary_temporary_path.write_text(
            _render_tracked_summary(evidence),
            encoding="utf-8",
        )
        os.replace(summary_temporary_path, TRACKED_SUMMARY)
    return source_stable


def main() -> int:
    if not (ROOT / ".venv").is_dir():
        raise RuntimeError("run `uv sync --all-extras --frozen` before acceptance")
    started_at = datetime.now(UTC)
    started_monotonic = time.monotonic()
    source = _source_provenance()
    pytest_process = subprocess.CompletedProcess[str]([], 1, "", "not started")
    pytest_duration_seconds = 0.0
    started = False
    try:
        started = True
        _fresh_start()
        _wait_proxy_init()
        _wait_nodes()
        RESULTS.mkdir(parents=True, exist_ok=True)
        SCENARIO_EVIDENCE.unlink(missing_ok=True)
        environment = dict(os.environ)
        environment["LETS_RUN_DOCKER_E2E"] = "1"
        environment["LETS_E2E_SCENARIO_EVIDENCE"] = str(SCENARIO_EVIDENCE)
        pytest_started = time.monotonic()
        pytest_process = _run(
            [sys.executable, "-m", "pytest", "tests/e2e", "-vv"],
            check=False,
            timeout=300,
            environment=environment,
        )
        pytest_duration_seconds = time.monotonic() - pytest_started
        print(pytest_process.stdout, end="")
        print(pytest_process.stderr, end="", file=sys.stderr)
        source_stable = _write_evidence(
            pytest_process=pytest_process,
            pytest_duration_seconds=pytest_duration_seconds,
            source=source,
            started_at=started_at,
            started_monotonic=started_monotonic,
        )
        if pytest_process.returncode == 0 and not source_stable:
            print(
                "acceptance source changed while the cluster was running; evidence is invalid",
                file=sys.stderr,
            )
            return 2
        return pytest_process.returncode
    finally:
        if started:
            _compose("down", "--remove-orphans", check=False, timeout=120)


if __name__ == "__main__":
    raise SystemExit(main())
