from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import deploy.run_acceptance as acceptance


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )


def test_source_provenance_hashes_git_visible_content_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init")
    (repository / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    (repository / "src").mkdir()
    (repository / "src" / "runtime.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repository / "deploy" / "evidence").mkdir(parents=True)
    summary = repository / "deploy" / "evidence" / "summary.md"
    summary.write_text("derived one\n", encoding="utf-8")
    _git(
        repository,
        "add",
        ".gitignore",
        "tracked.txt",
        "src/runtime.py",
        "deploy/evidence/summary.md",
    )
    _git(
        repository,
        "-c",
        "user.name=LETS Test",
        "-c",
        "user.email=lets-test@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    (repository / "visible.txt").write_text("first\n", encoding="utf-8")
    (repository / ".env").write_text("ignored secret one\n", encoding="utf-8")
    monkeypatch.setattr(acceptance, "ROOT", repository)

    first = acceptance._source_provenance()
    second = acceptance._source_provenance()
    assert first == second
    assert first["dirty"] is True
    assert first["untracked_file_count"] == 1
    assert first["source_file_count"] == 5
    assert first["runtime_input_file_count"] == 2
    assert "visible.txt" not in json.dumps(first)

    (repository / ".env").write_text("ignored secret two\n", encoding="utf-8")
    ignored_change = acceptance._source_provenance()
    assert ignored_change == first

    (repository / "visible.txt").write_text("second\n", encoding="utf-8")
    visible_change = acceptance._source_provenance()
    assert visible_change["source_sha256"] != first["source_sha256"]
    assert visible_change["git_status_sha256"] == first["git_status_sha256"]
    assert visible_change["runtime_input_sha256"] == first["runtime_input_sha256"]

    summary.write_text("derived two\n", encoding="utf-8")
    summary_change = acceptance._source_provenance()
    assert summary_change["source_sha256"] != visible_change["source_sha256"]
    assert summary_change["runtime_input_sha256"] == first["runtime_input_sha256"]

    (repository / "src" / "runtime.py").write_text("VALUE = 2\n", encoding="utf-8")
    runtime_change = acceptance._source_provenance()
    assert runtime_change["runtime_input_sha256"] != first["runtime_input_sha256"]


def test_manifest_digest_requires_all_evidence_to_agree() -> None:
    digest = "sha256:" + ("a" * 64)
    nodes = {
        "warden-a": {"info": {"metadata": {"manifest_digest": digest}}},
        "warden-b": {"info": {"metadata": {"manifest_digest": digest}}},
    }
    assert (
        acceptance._manifest_digest(
            bootstrap={"manifest_digest": digest},
            nodes=nodes,
            scenario={"nodes": {"manifest_digest": digest}},
        )
        == digest
    )


def test_retained_text_redacts_supplied_bootstrap_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "release-only-bootstrap-token-value"
    monkeypatch.setenv("LETS_BOOTSTRAP_TOKEN", token)
    retained = acceptance._redact_sensitive_text(f"before {token} after")
    assert token not in retained
    assert "[REDACTED LETS_BOOTSTRAP_TOKEN]" in retained


def test_evidence_start_date_uses_recorded_timestamp_in_utc() -> None:
    evidence = {"started_at": "2026-09-03T00:14:15.926832+00:00"}
    assert acceptance._evidence_start_date(evidence) == "2026-09-03"


@pytest.mark.parametrize("started_at", [None, "", "2026-09-03", "not-a-timestamp"])
def test_evidence_start_date_rejects_missing_or_invalid_timestamp(
    started_at: object,
) -> None:
    evidence = {"started_at": started_at}
    with pytest.raises(RuntimeError, match="started_at"):
        acceptance._evidence_start_date(evidence)
