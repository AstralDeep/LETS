from __future__ import annotations

import gzip
import hashlib
import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

import benchmarks.nsdi_strengthening.evidence_campaign as evidence_campaign
from benchmarks.nsdi_strengthening.evidence_campaign import (
    _REQUIRED_ARTIFACTS,
    CAMPAIGN_PREFLIGHT_NAME,
    MANIFEST_NAME,
    PAPER_INPUT_MANIFEST_NAME,
    SOURCE_MANIFEST_NAME,
    CampaignError,
    compress_matched_host_result,
    finalize_campaign,
    preflight_campaign,
)
from benchmarks.nsdi_strengthening.remote_three_host import (
    per_site_timeline_svg,
    phase_end_csv,
    phase_end_markdown,
    report_markdown,
    timeline_csv,
    timeline_svg,
)

CAMPAIGN_BINDING = "results/nsdi-strengthening-2026-09-02/MANIFEST.json"
REAL_RESULT_TEMPLATE = (
    Path(__file__).parents[2]
    / "results/nsdi-strengthening-2026-08-31/remote/three-host-linux-result.json"
)


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _clean_repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--initial-branch=main")
    _write(repository / ".gitignore", "paper/submission/\nstaging/\n")
    _write(
        repository / "benchmarks/nsdi_strengthening/evidence_campaign.py",
        '"""campaign source"""\n',
    )
    _write(repository / "benchmarks/nsdi_strengthening/harness.py", "VALUE = 1\n")
    _write(repository / "benchmarks/nsdi_strengthening/matched_host_path.py", "BENCHMARK = 1\n")
    _write(
        repository / "benchmarks/nsdi_strengthening/remote_matched_host.py",
        "ORCHESTRATOR = 1\n",
    )
    _write(repository / "benchmarks/nsdi_strengthening/remote_three_host.py", "CONTROLLER = 1\n")
    _write(repository / "benchmarks/nsdi_strengthening/remote_three_host_agent.py", "AGENT = 1\n")
    _write(repository / "Dockerfile", "FROM scratch\n")
    _write(repository / "compose.yaml", "services: {}\n")
    _write(repository / "deploy/run_acceptance.py", "PASS = True\n")
    _write(repository / "formal/sensitivity_frontier.py", "VALUE = 2\n")
    _write(repository / "formal/vector_model_checker.py", "VALUE = 3\n")
    _write(repository / "tests/benchmarks/test_evidence_campaign.py", "def test_ok(): pass\n")
    _write(repository / "tests/benchmarks/test_nsdi_example.py", "def test_ok(): pass\n")
    _write(repository / "tests/e2e/test_compose_cluster.py", "def test_ok(): pass\n")
    _write(repository / "tests/e2e/test_production_profile.py", "def test_ok(): pass\n")
    _write(repository / "tests/formal/test_vector_model_checker.py", "def test_ok(): pass\n")
    _write(repository / "pyproject.toml", "[project]\nname = 'campaign-test'\n")
    _write(repository / "uv.lock", "version = 1\n")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Campaign Test",
        "-c",
        "user.email=campaign@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    _write(repository / "paper/submission/main.tex", "paper input\n")
    _write(repository / "paper/submission/figures/plot.svg", "<svg/>\n")
    for relative in (
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
        "manuscript.tex",
        "paper-anon.tex",
        "paper-arxiv.tex",
        "paper-nsdi27.tex",
        "references.bib",
        "usenix-2020-09.sty",
    ):
        _write(repository / "paper/submission" / relative, f"paper input: {relative}\n")
    _write(
        repository / "paper/submission/evidence.tex",
        f"% Evidence campaign manifest: {CAMPAIGN_BINDING}\n",
    )
    _write(repository / "paper/submission/build/paper.log", "excluded output\n")
    _write(repository / "paper/submission/figures/__pycache__/plot.pyc", "excluded cache\n")
    commit = _git(repository, "rev-parse", "HEAD")
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""
    return repository, commit


def _add_complete_campaign(staging_root: Path, repository: Path, commit: str) -> None:
    matched_json = b'{"schema":"matched-host-result"}\n'
    matched_csv = b"mode,value\nenforce,1\n"
    matched_markdown = b"# Matched host\n"
    scenario = {"schema": "lets.acceptance-scenario/v1"}
    distributed_runs = []
    for scheme in ("lets", "centralized_counter"):
        for name in (
            "balanced_equal_shares",
            "skew_demand_placed_shares",
            "skew_equal_shares",
        ):
            summary = (
                {"conservation_healthy": True, "final_aggregate": {"healthy": True}}
                if scheme == "lets"
                else {"counter_identity_healthy": True}
            )
            distributed_runs.append({"scenario": name, "scheme": scheme, "summary": summary})
    lineage_rows = [
        {
            "branching_factor": branch,
            "depth": depth,
            "final_accounting": {"healthy": True},
            "reopen_integrity": ["ok"],
            "shape": shape,
            "status": "passed",
        }
        for depth in (1, 2, 4, 8)
        for branch in (1, 2, 4, 8)
        for shape in ("spine_fanout", "complete_tree")
    ]
    storage_ids = ("storage-0", "storage-1")
    performance_trials = [
        {
            "conservation_healthy": True,
            "delay_ms": delay,
            "executor_rollback_protected": True,
            "mode": mode,
            "storage_id": storage_id,
            "trial_index": trial_index,
            "workers": workers,
        }
        for storage_id in storage_ids
        for delay in (0.0, 1.0, 10.0, 100.0, 1000.0)
        for workers in (1, 2, 4, 8, 16)
        for mode in ("off", "enforce")
        for trial_index in (0, 1)
    ]
    performance_aggregates = [
        {
            "delay_ms": delay,
            "mode": mode,
            "storage_id": storage_id,
            "workers": workers,
        }
        for storage_id in storage_ids
        for delay in (0.0, 1.0, 10.0, 100.0, 1000.0)
        for workers in (1, 2, 4, 8, 16)
        for mode in ("off", "enforce")
    ]
    remote_result = deepcopy(json.loads(REAL_RESULT_TEMPLATE.read_text(encoding="utf-8")))
    tree = _git(repository, "rev-parse", "HEAD^{tree}")
    controller = (repository / "benchmarks/nsdi_strengthening/remote_three_host.py").read_bytes()
    agent = (repository / "benchmarks/nsdi_strengthening/remote_three_host_agent.py").read_bytes()
    matched_orchestrator = (
        repository / "benchmarks/nsdi_strengthening/remote_matched_host.py"
    ).read_bytes()
    matched_benchmark = (
        repository / "benchmarks/nsdi_strengthening/matched_host_path.py"
    ).read_bytes()
    remote_result["source"] = {
        "archive_sha256": "a" * 64,
        "commit": commit,
        "tree": tree,
    }
    remote_result["harness"] = {
        "agent_path": "benchmarks/nsdi_strengthening/remote_three_host_agent.py",
        "agent_sha256": hashlib.sha256(agent).hexdigest(),
        "controller_path": "benchmarks/nsdi_strengthening/remote_three_host.py",
        "controller_sha256": hashlib.sha256(controller).hexdigest(),
        "sha256": hashlib.sha256(controller + b"\x00" + agent).hexdigest(),
    }
    remote_result["host_evidence"]["address_sha256"] = [
        f"address-{alias}" for alias in ("s1", "s2", "s3")
    ]
    remote_result["host_evidence"]["ssh_host_key_sha256"] = [
        f"host-key-{alias}" for alias in ("s1", "s2", "s3")
    ]
    documents: dict[str, object] = {
        "distributed/partition-results.json": {
            "runs": distributed_runs,
            "schema": "lets.partition-comparison/v1",
            "source": {"commit": commit, "dirty": False},
        },
        "docker/docker-acceptance.json": {
            "passed": True,
            "pytest_exit_code": 0,
            "scenario": scenario,
            "schema": "lets.acceptance-evidence/v2",
            "source": {"dirty": False, "git_commit": commit},
            "source_after": {"dirty": False, "git_commit": commit},
            "source_stable": True,
        },
        "docker/scenario-evidence.json": scenario,
        "formal/sensitivity-frontier.json": {
            "frontier": {"passed": True},
            "schema": "lets.formal-sensitivity-frontier/v1",
            "sensitivity": {
                "all_mutants_killed": True,
                "baseline_passed": True,
                "passed": True,
            },
            "success": True,
        },
        "formal/vector-model.json": {
            "baseline": {"passed": True},
            "mutant": {"killed": True},
            "schema_version": 1,
            "success": True,
        },
        "implementation/implementation-inventory.json": {
            "facts": [{"verified": True} for _ in range(8)],
            "git": {"dirty": False, "revision": commit},
            "groups": {"narrow_enforcement_core": {}, "whole_runtime": {}},
            "schema": "lets.nsdi-implementation-inventory/v1",
        },
        "lineage/lineage-scaling.json": {
            "configuration": {
                "branching_factors": [1, 2, 4, 8],
                "depths": [1, 2, 4, 8],
            },
            "depth_limit_probe": {
                "maximum_accepted_depth": 64,
                "next_depth": 65,
                "next_depth_rejected": True,
            },
            "rows": lineage_rows,
            "schema": "lets.lineage-scaling/v1",
            "source": {"commit": commit, "dirty": False},
        },
        "performance/performance-matrix.json": {
            "aggregates": performance_aggregates,
            "configuration": {
                "delays_ms": [0.0, 1.0, 10.0, 100.0, 1000.0],
                "mode_order": "alternates by paired trial",
                "trials": 2,
                "workers": [1, 2, 4, 8, 16],
            },
            "environment": {"git": {"dirty": False, "revision": commit}},
            "schema": "lets.nsdi-performance-matrix/v1",
            "storage": [{"storage_id": storage_id} for storage_id in storage_ids],
            "trials": performance_trials,
        },
        "remote/cluster-inventory.json": {
            "addresses_retained": False,
            "schema": "lets.remote-cluster-inventory/v1",
            "secrets_retained": False,
            "servers": [
                {
                    "address_sha256": f"address-{alias}",
                    "alias": alias,
                    "connected": True,
                    "home_absolute": True,
                    "home_normalized": True,
                    "home_owned": True,
                    "host_key_sha256": f"host-key-{alias}",
                    "inventory_ok": True,
                    "login_matches_credential": True,
                }
                for alias in ("s1", "s2", "s3")
            ],
            "usernames_retained": False,
        },
        "remote/matched-host/remote-matched-host-manifest.json": {
            "artifacts": {
                "matched-host-path-samples.csv": {
                    "retained_sanitized_sha256": hashlib.sha256(matched_csv).hexdigest()
                },
                "matched-host-path.json": {
                    "retained_sanitized_sha256": hashlib.sha256(matched_json).hexdigest()
                },
                "matched-host-path.md": {
                    "retained_sanitized_sha256": hashlib.sha256(matched_markdown).hexdigest()
                },
            },
            "commands": ["fresh benchmark"],
            "configuration": {"operations_per_mode": 1000, "trials": 10, "warmups": 100},
            "privacy": {
                "addresses_retained": False,
                "credentials_retained": False,
                "home_paths_retained": False,
                "usernames_retained": False,
            },
            "remote_source": {"clean": True},
            "schema": "lets.remote-matched-host/v1",
            "source": {
                "benchmark_sha256": hashlib.sha256(matched_benchmark).hexdigest(),
                "controller_git": {"commit": commit, "dirty": False},
                "orchestrator_sha256": hashlib.sha256(matched_orchestrator).hexdigest(),
            },
            "status": "passed",
        },
        "remote/three-host-linux-result.json": remote_result,
        "rollback/rollback-matrix.summary.json": {
            "git": {"commit": commit, "dirty": False},
            "junit": {"errors": 0, "failures": 0, "tests": 10},
            "passed": True,
            "pytest_returncode": 0,
            "runner_error": None,
            "schema": "lets.nsdi-rollback-clone-evidence/v1",
            "selected_test_node_ids": [f"test-{index}" for index in range(10)],
        },
        "vector/vector-workload.json": {
            "checks": {"conservation": True, "replay": True},
            "final": {
                "identity_holds": True,
                "local_invariants_healthy": True,
                "spendable_bound_holds": True,
            },
            "schema": "lets.vector-workload/v1",
            "source": {"commit": commit, "dirty": False},
        },
    }
    q1_outputs = {
        "remote/three-host-linux-report.md": report_markdown(remote_result),
        "remote/three-host-linux-timeline.csv": timeline_csv(remote_result),
        "remote/three-host-linux-timeline.svg": timeline_svg(remote_result),
        "remote/three-host-linux-per-site-timeline.svg": per_site_timeline_svg(remote_result),
        "remote/three-host-linux-phase-end.csv": phase_end_csv(remote_result),
        "remote/three-host-linux-phase-end.md": phase_end_markdown(remote_result),
    }
    for relative in _REQUIRED_ARTIFACTS:
        path = staging_root.joinpath(*relative.split("/"))
        if relative == "remote/matched-host/matched-host-path.json.gz":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(gzip.compress(matched_json, compresslevel=9, mtime=0))
        elif relative == "remote/matched-host/matched-host-path-samples.csv":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(matched_csv)
        elif relative == "remote/matched-host/matched-host-path.md":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(matched_markdown)
        elif relative == "rollback/rollback-matrix.junit.xml":
            _write(path, '<testsuites><testsuite tests="10" errors="0" failures="0"/></testsuites>')
        elif relative == "raw/final-full-suite.xml":
            _write(
                path, '<testsuites><testsuite tests="800" errors="0" failures="0"/></testsuites>'
            )
        elif relative in documents:
            _write(path, json.dumps(documents[relative]))
        elif relative in q1_outputs:
            _write(path, q1_outputs[relative].rstrip() + "\n")
        else:
            _write(path, f"artifact: {relative}\n")


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_preflight_and_finalize_create_deterministic_manifests(tmp_path: Path) -> None:
    repository, commit = _clean_repository(tmp_path)

    rendered_manifests = []
    for name in ("first", "second"):
        staging = repository / "staging" / name
        marker = preflight_campaign(
            repository=repository,
            staging_root=staging,
            expected_commit=commit,
        )
        assert marker == staging / CAMPAIGN_PREFLIGHT_NAME
        _add_complete_campaign(staging, repository, commit)
        outputs = finalize_campaign(
            repository=repository,
            staging_root=staging,
            paper_input_root=Path("paper/submission"),
            expected_commit=commit,
            campaign_binding=CAMPAIGN_BINDING,
        )
        rendered_manifests.append(tuple(path.read_bytes() for path in outputs))

        source = _load(staging / SOURCE_MANIFEST_NAME)
        assert source["schema"] == "lets.nsdi-source-manifest/v1"
        assert source["git"]["commit"] == commit
        assert source["git"]["dirty"] is False
        source_paths = [entry["path"] for entry in source["files"]]
        assert source_paths == sorted(source_paths)
        assert "benchmarks/nsdi_strengthening/evidence_campaign.py" in source_paths
        assert "Dockerfile" in source_paths
        assert "compose.yaml" in source_paths
        assert "deploy/run_acceptance.py" in source_paths
        assert "tests/e2e/test_compose_cluster.py" in source_paths
        assert "tests/e2e/test_production_profile.py" in source_paths

        paper = _load(staging / PAPER_INPUT_MANIFEST_NAME)
        assert paper["source_directory"] == "paper/submission"
        paper_paths = {entry["path"] for entry in paper["files"]}
        assert "evaluation-strengthened.tex" in paper_paths
        assert "figures/generate_partition_progress_figure.py" in paper_paths
        assert "figures/three-endpoint-progress-comparison.pdf" in paper_paths
        assert "build/paper.log" not in paper_paths
        assert "figures/__pycache__/plot.pyc" not in paper_paths

        manifest = _load(staging / MANIFEST_NAME)
        manifest_paths = [entry["path"] for entry in manifest["files"]]
        assert manifest_paths == sorted(manifest_paths)
        assert MANIFEST_NAME not in manifest_paths
        assert manifest_paths == sorted(
            [
                CAMPAIGN_PREFLIGHT_NAME,
                PAPER_INPUT_MANIFEST_NAME,
                SOURCE_MANIFEST_NAME,
                *_REQUIRED_ARTIFACTS,
            ]
        )
        for entry in manifest["files"]:
            artifact = staging.joinpath(*entry["path"].split("/"))
            content = artifact.read_bytes()
            assert entry["bytes"] == len(content)
            assert entry["sha256"] == hashlib.sha256(content).hexdigest()

    assert rendered_manifests[0] == rendered_manifests[1]
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""


def test_preflight_requires_a_clean_worktree_without_creating_staging(tmp_path: Path) -> None:
    repository, commit = _clean_repository(tmp_path)
    _write(repository / "untracked.txt", "not clean\n")
    staging = repository / "staging" / "dirty"

    with pytest.raises(CampaignError, match="completely clean"):
        preflight_campaign(
            repository=repository,
            staging_root=staging,
            expected_commit=commit,
        )

    assert not staging.exists()


def test_preflight_requires_a_full_exact_commit(tmp_path: Path) -> None:
    repository, commit = _clean_repository(tmp_path)

    with pytest.raises(CampaignError, match="complete 40-character"):
        preflight_campaign(
            repository=repository,
            staging_root=repository / "staging/short",
            expected_commit=commit[:12],
        )
    with pytest.raises(CampaignError, match="Git verification failed"):
        preflight_campaign(
            repository=repository,
            staging_root=repository / "staging/wrong",
            expected_commit="0" * 40,
        )


def test_preflight_rejects_a_real_commit_that_is_not_head(tmp_path: Path) -> None:
    repository, prior_commit = _clean_repository(tmp_path)
    _write(repository / "benchmarks/nsdi_strengthening/harness.py", "VALUE = 4\n")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Campaign Test",
        "-c",
        "user.email=campaign@example.invalid",
        "commit",
        "-m",
        "second fixture commit",
    )

    with pytest.raises(CampaignError, match="HEAD does not match"):
        preflight_campaign(
            repository=repository,
            staging_root=repository / "staging/not-head",
            expected_commit=prior_commit,
        )


def test_preflight_preserves_an_existing_campaign_root(tmp_path: Path) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "staging/prior"
    _write(staging / "sentinel.json", "{}\n")

    with pytest.raises(CampaignError, match="prior campaign"):
        preflight_campaign(
            repository=repository,
            staging_root=staging,
            expected_commit=commit,
        )

    assert (staging / "sentinel.json").read_text(encoding="utf-8") == "{}\n"


def test_preflight_rejects_an_unignored_in_repository_root(tmp_path: Path) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "not-ignored/campaign"

    with pytest.raises(CampaignError, match="must be ignored"):
        preflight_campaign(
            repository=repository,
            staging_root=staging,
            expected_commit=commit,
        )

    assert not staging.exists()


def test_matched_host_compression_is_deterministic_and_lossless(tmp_path: Path) -> None:
    repository, commit = _clean_repository(tmp_path)
    compressed_payloads = []
    raw_content = b'{"schema":"matched-host-result","value":1}\n'
    for name in ("first", "second"):
        staging = repository / "staging" / name
        preflight_campaign(repository=repository, staging_root=staging, expected_commit=commit)
        raw = staging / "remote/matched-host/matched-host-path.json"
        raw.parent.mkdir(parents=True)
        raw.write_bytes(raw_content)

        archive = compress_matched_host_result(
            repository=repository,
            staging_root=staging,
            expected_commit=commit,
        )

        assert archive.name == "matched-host-path.json.gz"
        assert not raw.exists()
        compressed = archive.read_bytes()
        assert compressed[3] & 0x08 == 0
        assert compressed[4:8] == b"\0\0\0\0"
        assert gzip.decompress(compressed) == raw_content
        compressed_payloads.append(compressed)
    assert compressed_payloads[0] == compressed_payloads[1]


def test_finalize_rechecks_clean_checkout_and_writes_nothing(tmp_path: Path) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "staging/campaign"
    preflight_campaign(repository=repository, staging_root=staging, expected_commit=commit)
    _add_complete_campaign(staging, repository, commit)
    _write(repository / "untracked-after-preflight.txt", "dirty\n")

    with pytest.raises(CampaignError, match="completely clean"):
        finalize_campaign(
            repository=repository,
            staging_root=staging,
            paper_input_root=repository / "paper/submission",
            expected_commit=commit,
            campaign_binding=CAMPAIGN_BINDING,
        )

    assert not (staging / SOURCE_MANIFEST_NAME).exists()
    assert not (staging / PAPER_INPUT_MANIFEST_NAME).exists()
    assert not (staging / MANIFEST_NAME).exists()


def test_finalize_requires_the_exact_campaign_artifact_set(tmp_path: Path) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "staging/campaign"
    preflight_campaign(repository=repository, staging_root=staging, expected_commit=commit)
    _write(staging / "notes.md", "not part of the campaign contract\n")

    with pytest.raises(CampaignError, match="artifact set is not exact"):
        finalize_campaign(
            repository=repository,
            staging_root=staging,
            paper_input_root=repository / "paper/submission",
            expected_commit=commit,
            campaign_binding=CAMPAIGN_BINDING,
        )


@pytest.mark.parametrize(
    "relative,mutation,error",
    [
        (
            "remote/matched-host/remote-matched-host-manifest.json",
            lambda document: document.update({"recovery": {"benchmark_rerun": False}}),
            "fresh benchmark",
        ),
        (
            "docker/docker-acceptance.json",
            lambda document: document.update({"source_stable": False}),
            "stable source",
        ),
        (
            "performance/performance-matrix.json",
            lambda document: document["configuration"].update(  # type: ignore[index,union-attr]
                {"mode_order": ["off", "enforce"]}
            ),
            "configuration is incomplete",
        ),
        (
            "performance/performance-matrix.json",
            lambda document: document["trials"][0].update(  # type: ignore[index,union-attr]
                {"trial_index": 9}
            ),
            "trial grid is not exact",
        ),
    ],
)
def test_finalize_rejects_failed_required_success_contracts(
    tmp_path: Path, relative: str, mutation: object, error: str
) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "staging/campaign"
    preflight_campaign(repository=repository, staging_root=staging, expected_commit=commit)
    _add_complete_campaign(staging, repository, commit)
    path = staging.joinpath(*relative.split("/"))
    document = _load(path)
    mutation(document)  # type: ignore[operator]
    _write(path, json.dumps(document))

    with pytest.raises(CampaignError, match=error):
        finalize_campaign(
            repository=repository,
            staging_root=staging,
            paper_input_root=repository / "paper/submission",
            expected_commit=commit,
            campaign_binding=CAMPAIGN_BINDING,
        )


@pytest.mark.parametrize("field", ["orchestrator_sha256", "benchmark_sha256"])
def test_finalize_rejects_uncommitted_matched_host_harness(tmp_path: Path, field: str) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "staging/campaign"
    preflight_campaign(repository=repository, staging_root=staging, expected_commit=commit)
    _add_complete_campaign(staging, repository, commit)
    manifest_path = staging / "remote/matched-host/remote-matched-host-manifest.json"
    manifest = _load(manifest_path)
    manifest["source"][field] = "0" * 64  # type: ignore[index]
    _write(manifest_path, json.dumps(manifest))

    with pytest.raises(CampaignError, match="committed orchestrator and benchmark"):
        finalize_campaign(
            repository=repository,
            staging_root=staging,
            paper_input_root=repository / "paper/submission",
            expected_commit=commit,
            campaign_binding=CAMPAIGN_BINDING,
        )


def test_finalize_rejects_dirty_provenance_inside_matched_host_archive(tmp_path: Path) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "staging/campaign"
    preflight_campaign(repository=repository, staging_root=staging, expected_commit=commit)
    _add_complete_campaign(staging, repository, commit)
    archive_path = staging / "remote/matched-host/matched-host-path.json.gz"
    payload = json.loads(gzip.decompress(archive_path.read_bytes()))
    payload["metadata"] = {"dirty": True}
    decompressed = (json.dumps(payload, sort_keys=True) + "\n").encode()
    archive_path.write_bytes(gzip.compress(decompressed, compresslevel=9, mtime=0))
    manifest_path = staging / "remote/matched-host/remote-matched-host-manifest.json"
    manifest = _load(manifest_path)
    manifest["artifacts"]["matched-host-path.json"]["retained_sanitized_sha256"] = (  # type: ignore[index]
        hashlib.sha256(decompressed).hexdigest()
    )
    _write(manifest_path, json.dumps(manifest))

    with pytest.raises(CampaignError, match="dirty source provenance"):
        finalize_campaign(
            repository=repository,
            staging_root=staging,
            paper_input_root=repository / "paper/submission",
            expected_commit=commit,
            campaign_binding=CAMPAIGN_BINDING,
        )


@pytest.mark.parametrize(
    "document,error",
    [
        ({"source": {"commit": "COMMIT", "dirty": True}}, "dirty source provenance"),
        ({"metadata": {"dirty": True}}, "dirty source provenance"),
        ({"source": {"commit": "0" * 40, "dirty": False}}, "campaign commit"),
        ({"source": {"dirty": False}}, "local provenance is absent"),
        ({"raw_addresses_retained": True}, "unsafe privacy flag"),
    ],
)
def test_finalize_rejects_unsafe_or_mismatched_json_provenance(
    tmp_path: Path, document: dict[str, object], error: str
) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "staging/campaign"
    preflight_campaign(repository=repository, staging_root=staging, expected_commit=commit)
    rendered = json.dumps(document).replace("COMMIT", commit)
    _write(staging / "result.json", rendered)

    with pytest.raises(CampaignError, match=error):
        finalize_campaign(
            repository=repository,
            staging_root=staging,
            paper_input_root=repository / "paper/submission",
            expected_commit=commit,
            campaign_binding=CAMPAIGN_BINDING,
        )

    assert not (staging / MANIFEST_NAME).exists()


def test_finalize_rejects_credential_file_without_manifesting_it(tmp_path: Path) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "staging/campaign"
    preflight_campaign(repository=repository, staging_root=staging, expected_commit=commit)
    _write(staging / "Test_Servers.txt", "s1_password=do-not-read\n")

    with pytest.raises(CampaignError, match="credential-like"):
        finalize_campaign(
            repository=repository,
            staging_root=staging,
            paper_input_root=repository / "paper/submission",
            expected_commit=commit,
            campaign_binding=CAMPAIGN_BINDING,
        )

    assert not (staging / MANIFEST_NAME).exists()


def test_finalize_never_overwrites_an_existing_manifest(tmp_path: Path) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "staging/campaign"
    preflight_campaign(repository=repository, staging_root=staging, expected_commit=commit)
    _add_complete_campaign(staging, repository, commit)
    _write(staging / SOURCE_MANIFEST_NAME, "prior manifest\n")

    with pytest.raises(CampaignError, match="refusing to overwrite"):
        finalize_campaign(
            repository=repository,
            staging_root=staging,
            paper_input_root=repository / "paper/submission",
            expected_commit=commit,
            campaign_binding=CAMPAIGN_BINDING,
        )

    assert (staging / SOURCE_MANIFEST_NAME).read_text(encoding="utf-8") == "prior manifest\n"
    assert not (staging / MANIFEST_NAME).exists()


def _set_duplicate_boot_identity(document: dict[str, object]) -> None:
    identities = document["host_evidence"]["linux_boot_identity"]  # type: ignore[index]
    identities[1]["boot_id_sha256"] = identities[0]["boot_id_sha256"]  # type: ignore[index]


def _set_duplicate_scenario_cell(document: dict[str, object]) -> None:
    scenarios = document["scenarios"]  # type: ignore[assignment]
    scenarios[1]["workload"] = "equal"  # type: ignore[index]


def _break_aggregate_conservation(document: dict[str, object]) -> None:
    scenarios = document["scenarios"]  # type: ignore[assignment]
    scenarios[0]["aggregate_final"]["free_pool"] += 1  # type: ignore[index,operator]


def _break_recovery_transfer(document: dict[str, object]) -> None:
    scenarios = document["scenarios"]  # type: ignore[assignment]
    scenarios[0]["recovery"]["transfer"]["amount"] += 1  # type: ignore[index,operator]


@pytest.mark.parametrize(
    "mutation,error",
    [
        (
            lambda document: document["source"].update({"tree": "0" * 40}),  # type: ignore[index,union-attr]
            "campaign commit and tree",
        ),
        (
            lambda document: document["harness"].update(  # type: ignore[index,union-attr]
                {"controller_sha256": "0" * 64}
            ),
            "committed controller and agent",
        ),
        (_set_duplicate_boot_identity, "boot identities are not distinct"),
        (_set_duplicate_scenario_cell, "scenario name does not match"),
        (_break_aggregate_conservation, "aggregate accounting does not equal"),
        (_break_recovery_transfer, "transfer does not match"),
    ],
)
def test_finalize_rejects_false_three_host_claims(
    tmp_path: Path, mutation: object, error: str
) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "staging/campaign"
    preflight_campaign(repository=repository, staging_root=staging, expected_commit=commit)
    _add_complete_campaign(staging, repository, commit)
    result_path = staging / "remote/three-host-linux-result.json"
    result = _load(result_path)
    mutation(result)  # type: ignore[operator]
    _write(result_path, json.dumps(result))

    with pytest.raises(CampaignError, match=error):
        finalize_campaign(
            repository=repository,
            staging_root=staging,
            paper_input_root=repository / "paper/submission",
            expected_commit=commit,
            campaign_binding=CAMPAIGN_BINDING,
        )

    assert not (staging / MANIFEST_NAME).exists()


def test_finalize_rejects_noncanonical_q1_derived_output(tmp_path: Path) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "staging/campaign"
    preflight_campaign(repository=repository, staging_root=staging, expected_commit=commit)
    _add_complete_campaign(staging, repository, commit)
    _write(staging / "remote/three-host-linux-report.md", "stale report\n")

    with pytest.raises(CampaignError, match="derived Q1 artifact"):
        finalize_campaign(
            repository=repository,
            staging_root=staging,
            paper_input_root=repository / "paper/submission",
            expected_commit=commit,
            campaign_binding=CAMPAIGN_BINDING,
        )


@pytest.mark.parametrize(
    "paper_edit,binding,error",
    [
        (
            lambda paper: _write(
                paper / "evidence.tex",
                "% Evidence campaign manifest: "
                "results/nsdi-strengthening-2026-08-31/MANIFEST.json\n",
            ),
            CAMPAIGN_BINDING,
            "campaign binding marker",
        ),
        (
            lambda paper: _write(
                paper / "evaluation-strengthened.tex",
                "TODO(author): decide whether evidence is clean\n",
            ),
            CAMPAIGN_BINDING,
            r"TODO\(author\)",
        ),
    ],
)
def test_finalize_rejects_unbound_or_unresolved_paper(
    tmp_path: Path, paper_edit: object, binding: str, error: str
) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "staging/campaign"
    preflight_campaign(repository=repository, staging_root=staging, expected_commit=commit)
    paper_edit(repository / "paper/submission")  # type: ignore[operator]

    with pytest.raises(CampaignError, match=error):
        finalize_campaign(
            repository=repository,
            staging_root=staging,
            paper_input_root=repository / "paper/submission",
            expected_commit=commit,
            campaign_binding=binding,
        )


def test_finalize_removes_the_seal_if_inputs_change_after_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, commit = _clean_repository(tmp_path)
    staging = repository / "staging/campaign"
    preflight_campaign(repository=repository, staging_root=staging, expected_commit=commit)
    _add_complete_campaign(staging, repository, commit)
    original = evidence_campaign._render_campaign_manifests
    calls = 0

    def render_with_late_drift(**kwargs: object) -> tuple[bytes, bytes, bytes]:
        nonlocal calls
        calls += 1
        if calls == 4:
            _write(staging / "docker/docker-compose.log", "changed after seal\n")
        return original(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(evidence_campaign, "_render_campaign_manifests", render_with_late_drift)
    with pytest.raises(CampaignError, match="changed after the final seal"):
        finalize_campaign(
            repository=repository,
            staging_root=staging,
            paper_input_root=repository / "paper/submission",
            expected_commit=commit,
            campaign_binding=CAMPAIGN_BINDING,
        )

    assert not (staging / SOURCE_MANIFEST_NAME).exists()
    assert not (staging / PAPER_INPUT_MANIFEST_NAME).exists()
    assert not (staging / MANIFEST_NAME).exists()
